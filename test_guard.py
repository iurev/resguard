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
from unittest import mock

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
    records = [json.loads(line) for line in (guard.STATE/'events.jsonl').read_text().splitlines()]
    return result, [r for r in records if r.get('id') == job]


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
        logs=[json.loads(x) for x in (guard.STATE/'events.jsonl').read_text().splitlines()]
        self.assertTrue(any(x.get('id')==job and x['event']=='finish' for x in logs))

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
            for path, policy in ((parent, base), (cg, job_policy)):
                values = {'memory.max': policy['memory_max'], 'memory.high': policy['memory_high'],
                          'memory.swap.max': 0, 'memory.oom.group': 1, 'pids.max': policy['tasks_max'],
                          'cpu.max': f'{policy["cpu_percent"]*1000} 100000',
                          'io.max': f'{devno} rbps={policy["io_read_bytes_per_second"]} '
                                    f'wbps={policy["io_write_bytes_per_second"]} riops=max wiops=max'}
                for name, value in values.items():
                    (path/name).write_text(str(value))
            req = {'id': 'fixture-job', 'unit': cg.name, 'limits': job_policy}
            with mock.patch.object(guard, 'current_cgroup', return_value=cg), \
                 mock.patch.object(guard, 'load_policy', return_value=base), \
                 mock.patch.object(guard, 'event'):
                self.assertTrue(guard.check_limits(req)['io_active'])
                (cg/'io.max').write_text(f'{devno} rbps=4096 wbps=max')
                with self.assertRaisesRegex(RuntimeError, 'io controller'):
                    guard.check_limits(req)
                (cg/'io.max').write_text(f'{devno} rbps=4096 wbps=2048')
                (parent/'io.max').write_text(f'{devno} rbps=65537 wbps=32768')
                with self.assertRaisesRegex(RuntimeError, 'io controller'):
                    guard.check_limits(req)


if __name__ == '__main__':
    unittest.main(verbosity=2)
