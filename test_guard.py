#!/usr/bin/python3
"""Bounded integration probes; no project tests/builds or external services."""
import importlib.util
import json
import os
from pathlib import Path
import shlex
import signal
import select
import pty
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager
from unittest import mock
from audit import events_newest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('guard', HERE / 'guard.py')
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


def prepare(command, **extra):
    payload = {'tool_name': 'Bash', 'tool_input': {'command': command},
               'cwd': str(guard.ROOT), 'session_id': 'integration-tests',
               'tool_use_id': 'direct-' + str(time.time_ns()), **extra}
    proc = subprocess.run([sys.executable, str(HERE / 'guard.py'), 'hook'],
                          input=json.dumps(payload), text=True, capture_output=True, timeout=8)
    data = json.loads(proc.stdout)['hookSpecificOutput']
    if data['permissionDecision'] != 'allow':
        raise AssertionError(data)
    cmd = data['updatedInput']['command']
    return cmd, shlex.split(cmd)[4]


def execute(command, *, shell='/bin/bash', cwd=None, env=None, timeout=25, stdin=''):
    cmd, job = prepare(command)
    e = {**os.environ, 'CODEX_GUARD_MEMORY_MAX': str(128*1024**2),
         'CODEX_GUARD_RUNTIME_SECONDS': '12', 'CODEX_GUARD_CPU_PERCENT': '100',
         'CODEX_GUARD_TASKS_MAX': '32', **(env or {})}
    result = subprocess.run([shell, '-c', cmd], cwd=cwd or guard.ROOT, env=e,
                            input=stdin, text=True, capture_output=True, timeout=timeout)
    records = list(reversed(list(events_newest(guard.STATE))))
    return result, [r for r in records if r.get('id') == job]


def wait_finish(job, state=None, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for row in events_newest(state or guard.STATE):
            if row.get('id') == job and row['event'] == 'finish':
                return row
        time.sleep(0.05)
    raise AssertionError(f'No persisted finish for {job}')


class Integration(unittest.TestCase):
    def test_01_shell_cwd_environment_and_quote(self):
        for shell in ('/bin/bash', '/bin/zsh'):
            with self.subTest(shell=shell):
                r, log = execute("printf '%s\\n' \"$PWD\" \"$GUARD_QUOTE\"; printf 'err-marker\\n' >&2; exit 7",
                                 shell=shell, cwd='/tmp', env={'GUARD_QUOTE': 'spaces $HOME `literal` "quotes"\nsecond line'})
                self.assertEqual(r.returncode, 7, r.stderr)
                self.assertEqual(r.stdout, '/tmp\nspaces $HOME `literal` "quotes"\nsecond line\n')
                self.assertIn('err-marker', r.stderr)
                self.assertTrue(any(x['event'] == 'finish' for x in log), log)
                self.assertEqual(log[-1]['event'], 'return')
                self.assertIsNotNone(log[-1]['memory_peak_bytes'])

    def test_02_cgroup_actual_limits(self):
        command = "python3 -c " + shlex.quote("from pathlib import Path; import json; cg=Path('/sys/fs/cgroup'+next(x[3:] for x in Path('/proc/self/cgroup').read_text().splitlines() if x.startswith('0::'))); print(json.dumps({k:(cg/k).read_text().strip() for k in ['memory.max','memory.swap.max','memory.oom.group','pids.max','cpu.max']}))")
        r, logs = execute(command)
        self.assertEqual(r.returncode, 0, r.stderr)
        v=json.loads(r.stdout)
        self.assertEqual(v['memory.max'], str(128*1024**2))
        self.assertEqual(v['memory.swap.max'], '0')
        self.assertEqual(v['memory.oom.group'], '1')
        self.assertEqual(v['pids.max'], '32')
        self.assertEqual(v['cpu.max'], '100000 100000')
        ready = next(x for x in logs if x['event'] == 'ready')
        self.assertIn('io_active', ready['effective'])

    def test_03_memory_oom(self):
        # Finite 192MiB allocation, safe even if the 128MiB guard were broken.
        r, logs = execute("/usr/bin/python3 -c 'x=bytearray(192*1024*1024); print(\"SHOULD_NOT_REACH\")'")
        self.assertEqual(r.returncode, 137, r.stderr)
        self.assertNotIn('SHOULD_NOT_REACH', r.stdout)
        self.assertEqual(logs[-1]['result'], 'oom-kill')

    def test_04_timeout_and_detached_descendant(self):
        r, logs = execute("/usr/bin/python3 -c 'import subprocess,time; p=subprocess.Popen([\"/usr/bin/sleep\",\"20\"],start_new_session=True); print(p.pid,flush=True); time.sleep(20)'", env={'CODEX_GUARD_RUNTIME_SECONDS':'1'})
        self.assertEqual(r.returncode, 124, r.stderr)
        pid=int(r.stdout.strip())
        self.assertFalse(Path(f'/proc/{pid}').exists(), f'Detached child {pid} survived')
        self.assertEqual(logs[-1]['result'], 'timeout')

    def test_05_background_child_cleanup(self):
        r, logs = execute("/usr/bin/python3 -c 'import subprocess; p=subprocess.Popen([\"/usr/bin/sleep\",\"20\"],start_new_session=True); print(p.pid,flush=True)'")
        self.assertEqual(r.returncode, 0, r.stderr)
        pid=int(r.stdout.strip())
        self.assertFalse(Path(f'/proc/{pid}').exists(), f'Background child {pid} survived')

    def test_06_process_limit(self):
        r, logs = execute(f'/usr/bin/python3 {HERE}/probes.py pids')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('PIDS_BLOCKED True', r.stdout)

    def test_07_cpu_throttling(self):
        r, logs = execute(f'/usr/bin/python3 {HERE}/probes.py cpu', env={'CODEX_GUARD_CPU_PERCENT':'50'})
        self.assertEqual(r.returncode, 0, r.stderr)
        cpu = float(r.stdout.split()[1])
        self.assertLess(cpu, 1.35, r.stdout)

    def test_08_legacy_scope_preserves_cgroup(self):
        r, logs = execute("systemd-run --user --scope --quiet -p MemoryMax=96M -p MemoryHigh=80M -p MemorySwapMax=0 /usr/bin/cat /proc/self/cgroup")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(logs[-1]['unit'], r.stdout)
        self.assertTrue(any(x['event']=='nested_scope' for x in logs), logs)

    def test_09_external_scope_wrapper(self):
        with tempfile.TemporaryDirectory(prefix='resguard-wrapper-test-') as tmp:
            wrapper = Path(tmp) / 'limited-command.sh'
            wrapper.write_text('#!/bin/sh\nexec systemd-run --user --scope --quiet '
                               '-p MemoryMax=96M -p MemoryHigh=80M '
                               '-p MemorySwapMax=0 "$@"\n')
            wrapper.chmod(0o700)
            r, logs = execute(shlex.quote(str(wrapper)) + ' /usr/bin/cat /proc/self/cgroup')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(logs[-1]['unit'], r.stdout)
        self.assertTrue(any(x['event']=='nested_scope' for x in logs), logs)

    def test_10_stdin_and_umask(self):
        r, _ = execute("read -r line; printf '%s\\n' \"$line\"; umask", stdin='input $literal\n')
        self.assertEqual(r.returncode, 0, r.stderr)
        current = os.umask(0o022)
        os.umask(current)
        self.assertEqual(r.stdout.splitlines(), ['input $literal', f'{current:04o}'])

    def test_11_runner_sigkill(self):
        cmd, job=prepare(f'/usr/bin/python3 {HERE}/probes.py timeout')
        env={**os.environ,'CODEX_GUARD_MEMORY_MAX':str(128*1024**2),'CODEX_GUARD_RUNTIME_SECONDS':'12'}
        proc=subprocess.Popen(['/bin/bash','-c',cmd],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        line=proc.stdout.readline()
        self.assertIn('DETACHED_PID', line)
        pid=int(line.split()[1])
        proc.kill()
        proc.communicate(timeout=6)
        self.assertFalse(Path(f'/proc/{pid}').exists())
        wait_finish(job)

    def tty_execute(self, mode, *, send=None, kill_without_drain=False):
        cmd, job=prepare(f'/usr/bin/python3 {HERE}/probes.py {mode}')
        master, slave=pty.openpty()
        env={**os.environ,'CODEX_GUARD_MEMORY_MAX':str(128*1024**2),'CODEX_GUARD_RUNTIME_SECONDS':'12'}
        proc=subprocess.Popen(['/bin/bash','-c',cmd],env=env,stdin=slave,stdout=slave,stderr=slave)
        os.close(slave)
        data=b''
        try:
            if kill_without_drain:
                # The finite 1MiB probe fills the PTY while nothing consumes
                # it. Do not drain even a byte until cleanup has been logged.
                self.assertTrue(select.select([master], [], [], 4)[0],
                                'PTY output never became ready')
                time.sleep(0.2)
                self.assertIsNone(proc.poll(), 'Runner exited before cancellation')
                proc.kill()
                finish_deadline = time.monotonic() + 5
                finished = False
                while time.monotonic() < finish_deadline:
                    rows = [json.loads(x) for x in (guard.STATE/'events.jsonl').read_text().splitlines()]
                    if any(x.get('id') == job and x['event'] == 'finish' for x in rows):
                        finished = True
                        break
                    time.sleep(0.05)
                self.assertTrue(finished,
                                'Cleanup depended on draining the blocked PTY output')
            deadline=time.monotonic()+6
            sent=False
            while time.monotonic()<deadline:
                if select.select([master],[],[],0.1)[0]:
                    try:
                        chunk=os.read(master,65536)
                    except OSError:
                        break
                    if not chunk:break
                    data+=chunk
                    if send and b'TTY_OK' in data and not sent:
                        os.write(master,send)
                        sent=True
                if proc.poll() is not None and not select.select([master],[],[],0)[0]:break
            proc.wait(timeout=2)
        finally:
            if proc.poll() is None:proc.kill()
            os.close(master)
        return proc.returncode,data.decode(errors='replace'),job

    def test_12_pty_input_and_controlling_terminal(self):
        rc,output,job=self.tty_execute('interactive',send=b'hello interactive\n')
        self.assertEqual(rc,0,output)
        self.assertIn('TTY_OK True True',output)
        self.assertIn('INPUT hello interactive',output)

    def test_13_pty_background_cleanup(self):
        rc,output,job=self.tty_execute('background')
        self.assertEqual(rc,0,output)
        pid=int(output.split('BACKGROUND_PID ')[1].split()[0])
        self.assertFalse(Path(f'/proc/{pid}').exists())

    def test_14_pty_backpressure_cancel(self):
        rc,output,job=self.tty_execute('output',kill_without_drain=True)
        self.assertEqual(rc,-signal.SIGKILL)

    def test_15_trampoline_malformed_input_denies(self):
        p=subprocess.run([sys.executable,str(HERE/'hook.py')],input='broken json',text=True,capture_output=True,timeout=6)
        self.assertEqual(json.loads(p.stdout)['hookSpecificOutput']['permissionDecision'],'deny')

    def test_16_rapid_start_jobs(self):
        for n in range(10):
            r, logs=execute(f'printf "STARTED_{n}\\n"')
            self.assertEqual(r.returncode,0,r.stderr)
            self.assertEqual(r.stdout,f'STARTED_{n}\n')

    def test_17_simultaneous_shared_budget(self):
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=3) as pool:
            results=list(pool.map(lambda _: execute('/usr/bin/cat /proc/self/cgroup; /usr/bin/sleep 0.3'), range(3)))
        units=[]
        for r,logs in results:
            self.assertEqual(r.returncode,0,r.stderr)
            self.assertIn('/'+guard.SLICE+'/',r.stdout)
            units.append(logs[-1]['unit'])
        self.assertEqual(len(set(units)),3)

    def test_18_lower_overrides_cannot_raise_policy(self):
        r, logs=execute('/usr/bin/true',env={'CODEX_GUARD_MEMORY_MAX':str(100*1024**3), 'CODEX_GUARD_CPU_PERCENT':'10000'})
        self.assertEqual(r.returncode,0,r.stderr)
        launch=next(x for x in logs if x['event']=='launch')
        self.assertEqual(launch['limits']['memory_max'],guard.load_policy()['memory_max'])
        self.assertEqual(launch['limits']['cpu_percent'],guard.load_policy()['cpu_percent'])

    def test_19_shared_slice_uses_aggregate_limits(self):
        r, logs = execute('/usr/bin/cat /proc/self/cgroup')
        self.assertEqual(r.returncode, 0, r.stderr)
        unit = logs[-1]['unit']
        command_cgroup = next(x[3:] for x in r.stdout.splitlines() if x.startswith('0::'))
        group = Path('/sys/fs/cgroup' + command_cgroup).parent
        policy = guard.load_policy()
        aggregate = guard.aggregate_policy(policy)
        self.assertEqual((group/'memory.max').read_text().strip(), str(aggregate['memory_max']))
        self.assertEqual((group/'memory.high').read_text().strip(), str(aggregate['memory_high']))
        self.assertEqual((group/'pids.max').read_text().strip(), str(aggregate['tasks_max']))
        self.assertEqual((group/'cpu.max').read_text().split()[0],
                         str(aggregate['cpu_percent'] * 1000))
        self.assertIn(unit, r.stdout)

    def test_20_aggregate_policy_contract(self):
        base = dict(guard.load_policy())
        legacy = {k: v for k, v in base.items() if not k.startswith('aggregate_')}
        aggregate = guard.aggregate_policy(legacy)
        for name in ('memory_max', 'memory_high', 'tasks_max', 'cpu_percent',
                     'io_read_bytes_per_second', 'io_write_bytes_per_second'):
            self.assertEqual(aggregate[name], legacy[name])

        explicit = dict(legacy, aggregate_memory_max=legacy['memory_max'] * 2,
                        aggregate_memory_high=legacy['memory_high'] * 2,
                        aggregate_tasks_max=legacy['tasks_max'] * 2,
                        aggregate_cpu_percent=legacy['cpu_percent'] * 2,
                        aggregate_io_read_bytes_per_second=legacy['io_read_bytes_per_second'] * 2,
                        aggregate_io_write_bytes_per_second=legacy['io_write_bytes_per_second'] * 2)
        with mock.patch.dict(os.environ, {
                'CODEX_GUARD_MEMORY_MAX': str(legacy['memory_max']//2),
                'CODEX_GUARD_CPU_PERCENT': str(max(1, legacy['cpu_percent']//2)),
                'CODEX_GUARD_TASKS_MAX': str(max(1, legacy['tasks_max']//2))}):
            lowered = guard.lower_limits(explicit)
        self.assertLess(lowered['memory_max'], explicit['memory_max'])
        self.assertEqual(guard.aggregate_policy(lowered)['memory_max'],
                         explicit['aggregate_memory_max'])
        self.assertEqual(guard.aggregate_policy(lowered)['cpu_percent'],
                         explicit['aggregate_cpu_percent'])
        self.assertEqual(guard.aggregate_policy(lowered)['tasks_max'],
                         explicit['aggregate_tasks_max'])

        too_small_max = legacy['memory_max'] - 1
        with tempfile.TemporaryDirectory(prefix='resguard-policy-test-') as directory:
            policy = Path(directory)/'policy.json'
            with mock.patch.object(guard, 'POLICY', policy):
                for invalid, message in (
                        (dict(explicit, aggregate_memory_high=explicit['aggregate_memory_max']+1),
                         'aggregate_memory_high'),
                        (dict(explicit, aggregate_memory_max=too_small_max,
                              aggregate_memory_high=min(legacy['memory_high'], too_small_max)),
                         'aggregate_memory_max is lower')):
                    policy.write_text(json.dumps(invalid))
                    with self.assertRaisesRegex(ValueError, message):
                        guard.load_policy()


class FinalAccounting(unittest.TestCase):
    """Real systemd regressions with isolated state and finite sleeping helpers."""

    @contextmanager
    def fixture(self, delay=0, deadline=30, return_failure=False, skip_logger=False,
                finish_failure=False):
        original = HERE
        with tempfile.TemporaryDirectory(prefix='resguard-accounting-test-') as directory:
            root = Path(directory)
            state = root / 'state'
            source = (original / 'guard.py').read_text()
            source = source.replace("STATE = ACCOUNT_HOME / '.local/state/resguard'",
                                    f'STATE = Path({str(state)!r})')
            source = source.replace('LOG_TIMEOUT_SECONDS = 30',
                                    f'LOG_TIMEOUT_SECONDS = {deadline}')
            source = source.replace('def collect(job):\n',
                                    f'def collect(job):\n    time.sleep({delay!r})\n')
            if skip_logger:
                for trigger in ('OnSuccess', 'OnFailure'):
                    source = source.replace(f"        ('{trigger}', d.Array([audit_unit], signature='s')),\n", '')
            if return_failure or finish_failure:
                failing_kind = 'return' if return_failure else 'finish'
                source = source.replace('def event(kind, *, _nonblocking=False, **data):\n',
                    "def event(kind, *, _nonblocking=False, **data):\n"
                    f"    if kind == {failing_kind!r}:\n        raise OSError('fixture audit write failed')\n")
            (root / 'guard.py').write_text(source)
            (root / 'audit.py').write_text((original / 'audit.py').read_text())
            with mock.patch(__name__ + '.HERE', root), mock.patch.object(guard, 'STATE', state):
                yield root, state

    def test_slow_accounting_preserves_success_and_failure(self):
        with self.fixture(delay=4.2):
            for code in (0, 7):
                with self.subTest(code=code):
                    started = time.monotonic()
                    result, rows = execute(f'printf "WORK_DONE\\n"; exit {code}')
                    self.assertGreaterEqual(time.monotonic() - started, 4.2)
                    self.assertEqual(result.returncode, code, result.stderr)
                    self.assertEqual(result.stdout, 'WORK_DONE\n')
                    self.assertNotIn('Worker stopped', result.stderr)
                    self.assertEqual(rows[-1]['audit_result'], 'success')
                    finish = next(r for r in rows if r['event'] == 'finish')
                    self.assertEqual(finish['exit_status'], code)

    def test_logger_timeout_does_not_replace_command_result(self):
        with self.fixture(delay=5, deadline=1) as (_, state):
            for code in (0, 7):
                with self.subTest(code=code):
                    result, rows = execute(f'exit {code}')
                    self.assertEqual(result.returncode, code, result.stderr)
                    self.assertIn('final accounting timeout', result.stderr)
                    self.assertIn(f'workload exit {code} preserved', result.stderr)
                    self.assertFalse(any(r['event'] == 'finish' for r in rows))
                    launch = next(r for r in rows if r['event'] == 'launch')
                    self.assertTrue((state / 'pending' / (launch['id'] + '.json')).exists())

    def test_return_audit_write_failure_keeps_workload_exit(self):
        with self.fixture(return_failure=True):
            result, rows = execute('exit 7')
            self.assertEqual(result.returncode, 7, result.stderr)
            self.assertIn('return audit unavailable', result.stderr)
            self.assertTrue(any(r['event'] == 'finish' for r in rows))

    def test_final_audit_write_failure_keeps_workload_exit_and_metadata(self):
        with self.fixture(finish_failure=True) as (_, state):
            result, rows = execute('exit 7')
            self.assertEqual(result.returncode, 7, result.stderr)
            self.assertIn('final accounting exit-code', result.stderr)
            self.assertTrue(any(r['event'] == 'error' and r['mode'] == 'collect' for r in rows))
            job = next(r['id'] for r in rows if r['event'] == 'launch')
            self.assertTrue((state/'pending'/(job+'.json')).exists())

    def test_unstarted_logger_wait_is_bounded(self):
        with self.fixture(deadline=1, skip_logger=True) as (_, state):
            result, rows = execute('true', timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('final accounting accounting-deadline', result.stderr)
            self.assertFalse(any(r['event'] == 'finish' for r in rows))
            job = next(r['id'] for r in rows if r['event'] == 'launch')
            self.assertTrue((state/'pending'/(job+'.json')).exists())

    def test_runner_death_during_slow_accounting_keeps_stats(self):
        with self.fixture(delay=4.2) as (_, state):
            cmd, job = prepare('printf "DONE\\n"')
            proc = subprocess.Popen(['/bin/bash', '-c', cmd], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
            try:
                self.assertTrue(select.select([proc.stdout], [], [], 4)[0])
                self.assertEqual(proc.stdout.readline(), 'DONE\n')
                bus, mgr = guard.connection()
                try:
                    deadline = time.monotonic() + 3
                    while time.monotonic() < deadline:
                        w = guard.properties(bus, mgr, 'resguard-'+job+'.service', guard.UNIT_IF)
                        a = guard.properties(bus, mgr, 'resguardlog-'+job+'.service', guard.UNIT_IF)
                        if w['ActiveState'] == 'inactive' and a['ActiveState'] == 'activating':
                            break
                        time.sleep(0.025)
                    self.assertEqual(w['ActiveState'], 'inactive')
                    self.assertEqual(a['ActiveState'], 'activating')
                finally:
                    bus.close()
                proc.kill()
                proc.communicate(timeout=6)
                finish = wait_finish(job, state, timeout=10)
                self.assertEqual(finish['result'], 'success')
                self.assertIsNotNone(finish['memory_peak_bytes'])
                self.assertFalse((state / 'pending' / (job + '.json')).exists())
                # Dependency references retain statistics, not completed units forever.
                bus, mgr = guard.connection()
                try:
                    deadline = time.monotonic() + 3
                    names = [finish['unit'], finish['audit_unit']]
                    while time.monotonic() < deadline:
                        remaining = []
                        for unit in names:
                            try:
                                mgr.GetUnit(unit)
                                remaining.append(unit)
                            except Exception as exc:
                                self.assertEqual(exc.get_dbus_name(), 'org.freedesktop.systemd1.NoSuchUnit')
                        if not remaining:
                            break
                        time.sleep(0.05)
                    self.assertFalse(remaining, remaining)
                finally:
                    bus.close()
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate(timeout=6)

    def test_logger_is_independently_capped_and_stop_grace_unchanged(self):
        with self.fixture(delay=2):
            cmd, job = prepare('true')
            proc = subprocess.Popen(['/bin/bash', '-c', cmd], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
            bus, mgr = guard.connection()
            try:
                unit = 'resguard-' + job + '.service'
                logger = 'resguardlog-' + job + '.service'
                deadline = time.monotonic() + 4
                while time.monotonic() < deadline:
                    try:
                        props = guard.properties(bus, mgr, logger, guard.UNIT_IF)
                        if props['ActiveState'] == 'activating':
                            break
                    except Exception:
                        pass
                    time.sleep(0.025)
                cg = str(guard.properties(bus, mgr, logger, guard.SERVICE_IF)['ControlGroup'])
                self.assertIn('/'+guard.LOG_SLICE+'/', cg)
                self.assertNotIn('/resguard.slice/', cg)
                service = guard.properties(bus, mgr, unit, guard.SERVICE_IF)
                self.assertEqual(int(service['TimeoutStopUSec']), 3000000)
                self.assertFalse(service.get('ExecStopPostEx', service.get('ExecStopPost')))
                for group, memory, quota, tasks in (
                        (Path('/sys/fs/cgroup' + cg), 64*1024**2, '25000 100000', '8'),
                        (Path('/sys/fs/cgroup' + cg).parent, 256*1024**2, '100000 100000', '64')):
                    self.assertEqual((group/'memory.max').read_text().strip(), str(memory))
                    self.assertEqual((group/'memory.swap.max').read_text().strip(), '0')
                    self.assertEqual((group/'cpu.max').read_text().strip(), quota)
                    self.assertEqual((group/'pids.max').read_text().strip(), tasks)
                out, err = proc.communicate(timeout=8)
                self.assertEqual(proc.returncode, 0, err)
            finally:
                bus.close()
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate(timeout=6)

    def test_real_runtime_timeout_even_when_command_handles_term(self):
        # A genuine deadline must NOT become success just because a TERM handler exits0.
        result, rows = execute("trap 'exit 0' TERM; while :; do sleep 0.1; done",
                               env={'CODEX_GUARD_RUNTIME_SECONDS': '1'})
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertEqual(rows[-1]['result'], 'timeout')

    def test_stubborn_background_cleanup_keeps_timeout(self):
        command = "/usr/bin/python3 -c " + shlex.quote(
            "import os,signal,time; pid=os.fork(); "
            "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
            "print(pid,flush=True) if pid else None; "
            "time.sleep(0.2) if pid else time.sleep(12)")
        result, rows = execute(command)
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertFalse(Path('/proc/' + result.stdout.strip()).exists())
        self.assertEqual(rows[-1]['result'], 'timeout')


class FailureContracts(unittest.TestCase):
    """Exercise failure paths without replacing the installed hook or policy."""

    @staticmethod
    def hook_module():
        spec = importlib.util.spec_from_file_location('guard_hook_contract_test', HERE/'hook.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def assert_unavailable(self, result):
        h = result['hookSpecificOutput']
        self.assertEqual(h['hookEventName'], 'PreToolUse')
        self.assertEqual(h['permissionDecision'], 'deny')
        self.assertIn('resguard unavailable', h['permissionDecisionReason'])
        self.assertNotIn('updatedInput', h)

    def test_legacy_finalize_accepts_pre_upgrade_request(self):
        with tempfile.TemporaryDirectory(prefix='resguard-legacy-finalize-') as directory:
            request = Path(directory)/'old-job.json'
            request.write_text(json.dumps({'id': 'old-job', 'unit': 'old.service',
                                           'session_id': 'legacy-test'}))
            bus, mgr = mock.Mock(), mock.Mock()
            stats = {'result': 'success', 'exit_code_kind': 1, 'exit_status': 0}
            with mock.patch.object(guard, 'pending', return_value=request), \
                 mock.patch.object(guard, 'connection', return_value=(bus, mgr)), \
                 mock.patch.object(guard, 'measurements', return_value=stats), \
                 mock.patch.object(guard, 'event') as record, \
                 mock.patch.dict(os.environ, {'SERVICE_RESULT': 'success',
                     'EXIT_CODE': 'exited', 'EXIT_STATUS': '0'}):
                self.assertEqual(guard.finalize('old-job'), 0)
                self.assertEqual(record.call_args.args, ('finish',))
                self.assertEqual(record.call_args.kwargs['session_id'], 'legacy-test')
                self.assertFalse(request.exists())
                bus.close.assert_called_once()

    def test_nonblocking_secondary_audit_does_not_wait_for_lock(self):
        import fcntl
        with tempfile.TemporaryDirectory(prefix='resguard-log-lock-test-') as directory:
            state = Path(directory)
            with (state/'log.lock').open('a') as lock, mock.patch.object(guard, 'STATE', state):
                fcntl.flock(lock, fcntl.LOCK_EX)
                with self.assertRaises(BlockingIOError):
                    guard.event('return', _nonblocking=True, id='fixture')

    def test_trampoline_valid_child_results(self):
        hook = self.hook_module()
        results = [
            {'hookSpecificOutput': {'hookEventName': 'PreToolUse',
             'permissionDecision': 'allow', 'updatedInput': {'command': 'exec /safe/runner job'}}},
            {'hookSpecificOutput': {'hookEventName': 'PreToolUse',
             'permissionDecision': 'deny', 'permissionDecisionReason': 'Expected policy refusal'}},
        ]
        for expected in results:
            with self.subTest(decision=expected['hookSpecificOutput']['permissionDecision']):
                completed = subprocess.CompletedProcess([], 0, json.dumps(expected).encode(), b'')
                with mock.patch.object(hook.subprocess, 'run', return_value=completed):
                    self.assertEqual(hook.guarded_result(b'{}'), expected)

    def test_trampoline_rejects_malformed_child_output(self):
        hook = self.hook_module()
        bad_results = [
            {}, [],
            {'hookSpecificOutput': {'permissionDecision': 'allow',
             'updatedInput': {'command': 'exec /safe/runner job'}}},
            {'hookSpecificOutput': {'hookEventName': 'PostToolUse',
             'permissionDecision': 'allow', 'updatedInput': {'command': 'exec /safe/runner job'}}},
            {'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'ask'}},
            {'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'allow'}},
            {'hookSpecificOutput': {'hookEventName': 'PreToolUse',
             'permissionDecision': 'allow', 'updatedInput': {'command': ''}}},
            {'hookSpecificOutput': {'hookEventName': 'PreToolUse',
             'permissionDecision': 'allow', 'updatedInput': {'command': 'exec\0broken'}}},
            {'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny'}},
            {'hookSpecificOutput': {'hookEventName': 'PreToolUse',
             'permissionDecision': 'deny', 'permissionDecisionReason': 42}},
            {'hookSpecificOutput': {'hookEventName': 'PreToolUse',
             'permissionDecision': 'deny', 'permissionDecisionReason': ''}},
            {'hookSpecificOutput': {'hookEventName': 'PreToolUse',
             'permissionDecision': 'deny', 'permissionDecisionReason': ' \n '}},
        ]
        outputs = [b'not json', b'{'] + [json.dumps(value).encode() for value in bad_results]
        for output in outputs:
            with self.subTest(output=output):
                completed = subprocess.CompletedProcess([], 0, output, b'')
                with mock.patch.object(hook.subprocess, 'run', return_value=completed):
                    self.assert_unavailable(hook.guarded_result(b'{}'))

    def test_trampoline_rejects_child_failure_and_timeout(self):
        hook = self.hook_module()
        with mock.patch.object(hook.subprocess, 'run',
                               return_value=subprocess.CompletedProcess([], 1, b'{}', b'failed')):
            self.assert_unavailable(hook.guarded_result(b'{}'))
        for error in (subprocess.TimeoutExpired(['guard.py', 'hook'], 4),
                      OSError('Cannot execute guard process')):
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(hook.subprocess, 'run', side_effect=error):
                    self.assert_unavailable(hook.guarded_result(b'{}'))

    def test_trampoline_does_not_forward_unsupported_control_fields(self):
        # Codex rejects these control combinations and then continues the raw
        # call. The trampoline must deny them or emit only canonical fields.
        hook = self.hook_module()
        valid_allow = {'hookSpecificOutput': {'hookEventName': 'PreToolUse',
                       'permissionDecision': 'allow',
                       'updatedInput': {'command': 'exec /safe/runner job'}}}
        outputs = [
            dict(valid_allow, **{'continue': False}),
            dict(valid_allow, stopReason='Unsupported stop field'),
            dict(valid_allow, suppressOutput=True),
            {'hookSpecificOutput': {'hookEventName': 'PreToolUse',
             'permissionDecision': 'deny', 'permissionDecisionReason': 'Policy refusal',
             'updatedInput': {'command': 'exec /safe/runner job'}}},
        ]
        for output in outputs:
            with self.subTest(output=output):
                completed = subprocess.CompletedProcess([], 0, json.dumps(output).encode(), b'')
                with mock.patch.object(hook.subprocess, 'run', return_value=completed):
                    result = hook.guarded_result(b'{}')
                self.assertEqual(set(result), {'hookSpecificOutput'})
                h = result['hookSpecificOutput']
                if h['permissionDecision'] == 'allow':
                    self.assertEqual(h, valid_allow['hookSpecificOutput'])
                else:
                    self.assertEqual(set(h), {'hookEventName', 'permissionDecision',
                                              'permissionDecisionReason'})
                    self.assertEqual(h['hookEventName'], 'PreToolUse')
                    self.assertEqual(h['permissionDecision'], 'deny')
                    self.assertIsInstance(h['permissionDecisionReason'], str)
                    self.assertTrue(h['permissionDecisionReason'])

    def test_tighter_worker_io_uses_baseline_parent_policy(self):
        # This checks the policy validator with fixture files, not host I/O
        # enforcement. Kernel I/O remains unavailable until io is delegated.
        base = dict(guard.load_policy(), require_io=True, io_device='/dev/null',
                    memory_max=128*1024**2, memory_high=96*1024**2,
                    tasks_max=32, cpu_percent=100,
                    aggregate_memory_max=256*1024**2,
                    aggregate_memory_high=192*1024**2,
                    aggregate_tasks_max=64, aggregate_cpu_percent=200,
                    io_read_bytes_per_second=65536, io_write_bytes_per_second=32768)
        job_policy = dict(base, memory_max=64*1024**2, memory_high=48*1024**2,
                          tasks_max=16, cpu_percent=50,
                          io_read_bytes_per_second=4096, io_write_bytes_per_second=2048)
        device = os.stat('/dev/null').st_rdev
        devno = f'{os.major(device)}:{os.minor(device)}'
        with tempfile.TemporaryDirectory(prefix='codex-guard-io-contract-') as directory:
            parent = Path(directory)/guard.SLICE
            cg = parent/'guard-contract.service'
            cg.mkdir(parents=True)
            aggregate = guard.aggregate_policy(base)
            for path, policy in ((parent, aggregate), (cg, job_policy)):
                values = {'memory.max': policy['memory_max'], 'memory.high': policy['memory_high'],
                          'memory.swap.max': 0, 'memory.oom.group': 1, 'pids.max': policy['tasks_max'],
                          'cpu.max': f'{policy["cpu_percent"]*1000} 100000',
                          'io.max': f'{devno} rbps={policy["io_read_bytes_per_second"]} '
                                    f'wbps={policy["io_write_bytes_per_second"]} riops=max wiops=max'}
                for name, value in values.items():
                    (path/name).write_text(str(value))
            req = {'id': 'fixture-job', 'unit': cg.name, 'limits': job_policy,
                   'aggregate_limits': aggregate}
            with mock.patch.object(guard, 'current_cgroup', return_value=cg), \
                 mock.patch.object(guard, 'load_policy', return_value=base), \
                 mock.patch.object(guard, 'event'):
                self.assertTrue(guard.check_limits(req)['io_active'])
                (parent/'memory.high').write_text(str(aggregate['memory_high']-1))
                with self.assertRaisesRegex(RuntimeError, 'Aggregate memory.high'):
                    guard.check_limits(req)
                (parent/'memory.high').write_text(str(aggregate['memory_high']))
                (cg/'io.max').write_text(f'{devno} rbps=4096 wbps=max')
                with self.assertRaisesRegex(RuntimeError, 'io controller'):
                    guard.check_limits(req)
                (cg/'io.max').write_text(f'{devno} rbps=4096 wbps=2048')
                (parent/'io.max').write_text(f'{devno} rbps=65537 wbps=32768')
                with self.assertRaisesRegex(RuntimeError, 'io controller'):
                    guard.check_limits(req)


if __name__ == '__main__':
    unittest.main(verbosity=2)
