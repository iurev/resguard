#!/usr/bin/python3
"""resguard: user-wide shell hook and cgroup runner. Requires Linux, systemd and python-dbus.

The hook only rewrites input. The runner creates the unit BEFORE executing the
original shell text. The worker supervises the command; systemd owns cleanup.
No subprocess command classification and no eval in the hook/runner.
"""
import argparse
import datetime
import fcntl
import json
import os
from pathlib import Path
import pwd
import pty
import re
import select
import shlex
import signal
import subprocess
import sys
import termios
import threading
import time
import tty
import uuid

from audit import archive_log

HERE = Path(__file__).resolve().parent
ACCOUNT_HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)
ROOT = ACCOUNT_HOME  # Default diagnostic/test cwd; never the source checkout.
POLICY = ACCOUNT_HOME / '.config/resguard/policy.json'
STATE = ACCOUNT_HOME / '.local/state/resguard'
SLICE = 'resguard.slice'
# No hyphen: resguard-log.slice would be a CHILD of the workload slice.
LOG_SLICE = 'resguardlog.slice'
LOG_TIMEOUT_SECONDS = 30
PREFIX = 'resguard-'
PYTHON = '/usr/bin/python3'
MAX_LOG = 10 * 1024 * 1024
UNIT_IF = 'org.freedesktop.systemd1.Unit'
SERVICE_IF = 'org.freedesktop.systemd1.Service'


def setup_state():
    os.umask(0o077)
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    (STATE / 'pending').mkdir(exist_ok=True, mode=0o700)


def event(kind, *, _nonblocking=False, **data):
    setup_state()
    record = dict(time=datetime.datetime.now(datetime.timezone.utc).isoformat(), event=kind, **data)
    # One inter-process lock also protects rotation. All command/resource
    # metadata is retained indefinitely, but not stdout/stderr/environment.
    # Command text is private (0600). Archives are never automatically deleted.
    with (STATE / 'log.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | (fcntl.LOCK_NB if _nonblocking else 0))
        path = STATE / 'events.jsonl'
        if path.exists() and path.stat().st_size >= MAX_LOG:
            archive_log(path)
        with path.open('a') as out:
            out.write(json.dumps(record, ensure_ascii=True) + '\n')


def pending(job):
    if not re.fullmatch('[0-9a-f]{32}', job):
        raise ValueError('Invalid guard job ID')
    return STATE / 'pending' / (job + '.json')


def load_policy():
    p = json.loads(POLICY.read_text())
    for name, value in p.items():
        if name not in ('io_device', 'require_io') and (type(value) is not int or value <= 0):
            raise ValueError(f'Invalid positive policy value: {name}')
    if p['memory_high'] > p['memory_max']:
        raise ValueError('memory_high exceeds memory_max')
    aggregate = aggregate_policy(p)
    if aggregate['memory_high'] > aggregate['memory_max']:
        raise ValueError('aggregate_memory_high exceeds aggregate_memory_max')
    for name in ('memory_max', 'memory_high', 'tasks_max', 'cpu_percent'):
        if aggregate[name] < p[name]:
            raise ValueError(f'aggregate_{name} is lower than per-command {name}')
    if type(p['require_io']) is not bool:
        raise ValueError('require_io must be a boolean')
    return p


def aggregate_policy(p):
    """Return shared-slice limits, preserving old policies as safe defaults."""
    aggregate = p.copy()
    for name in ('memory_max', 'memory_high', 'tasks_max', 'cpu_percent',
                 'io_read_bytes_per_second', 'io_write_bytes_per_second'):
        aggregate[name] = p.get('aggregate_' + name, p[name])
    return aggregate


def lower_limits(p):
    p = p.copy()
    # Optional tighter budgets for probes/small jobs. Environment cannot raise
    # policy ceilings. Values are bytes, seconds, percent, and task counts.
    for name in ('memory_max', 'memory_high', 'runtime_seconds', 'cpu_percent', 'tasks_max',
                 'io_read_bytes_per_second', 'io_write_bytes_per_second'):
        v = os.environ.get('CODEX_GUARD_' + name.upper())
        if v is not None:
            n = int(v)
            if n <= 0:
                raise ValueError(f'Invalid tighter limit {name}')
            p[name] = min(p[name], n)
    p['memory_high'] = min(p['memory_high'], p['memory_max'])
    return p


def hook():
    payload = json.load(sys.stdin)
    if payload.get('tool_name') != 'Bash':
        print('{}')
        return 0
    command = payload.get('tool_input', {}).get('command')
    if not isinstance(command, str) or not command or '\0' in command:
        raise ValueError('Bash hook did not receive a valid command')
    load_policy()  # A bad policy blocks before returning an executable rewrite.
    setup_state()
    # Cancelled hook requests never reach the runner. Bound their retention.
    sweep = STATE / 'pending-sweep'
    if not sweep.exists() or time.time() - sweep.stat().st_mtime > 3600:
        for item in (STATE / 'pending').glob('*.json'):
            try:
                if time.time() - item.stat().st_mtime > 86400:
                    # Keep launched jobs whose final audit could not be written.
                    # Only abandoned hook requests are safe to sweep.
                    if 'unit' not in json.loads(item.read_text()):
                        item.unlink(missing_ok=True)
            except FileNotFoundError:
                pass
        sweep.touch()
    job = uuid.uuid4().hex
    req = dict(id=job, session_id=payload.get('session_id'),
               tool_use_id=payload.get('tool_use_id'), hook_cwd=payload.get('cwd'),
               command=command, submitted_at=time.time())
    with pending(job).open('x') as out:
        json.dump(req, out)
    event('hook', **req)
    # $0 is the actual selected shell (including explicitly selected bash/zsh).
    # Actual cwd and environment are taken later, inside the shell tool context.
    rewritten = f'exec {PYTHON} {shlex.quote(str(HERE / "guard.py"))} run {job} --shell "$0"'
    print(json.dumps({'hookSpecificOutput': {
        'hookEventName': 'PreToolUse', 'permissionDecision': 'allow',
        'updatedInput': {'command': rewritten}}}))
    return 0


def connection():
    import dbus
    # Explicitly use this UID's manager, never an agent-supplied D-Bus address.
    bus = dbus.bus.BusConnection(f'unix:path=/run/user/{os.getuid()}/bus')
    mgr = dbus.Interface(bus.get_object('org.freedesktop.systemd1', '/org/freedesktop/systemd1'),
                         'org.freedesktop.systemd1.Manager')
    return bus, mgr


def properties(bus, mgr, unit, iface):
    import dbus
    obj = bus.get_object('org.freedesktop.systemd1', mgr.GetUnit(unit))
    return dbus.Interface(obj, 'org.freedesktop.DBus.Properties').GetAll(iface)


def resource_properties(p):
    import dbus as d
    return [
        ('MemoryAccounting', True), ('IOAccounting', True), ('TasksAccounting', True),
        ('MemoryMax', d.UInt64(p['memory_max'])),
        ('MemoryHigh', d.UInt64(p['memory_high'])), ('MemorySwapMax', d.UInt64(0)),
        ('TasksMax', d.UInt64(p['tasks_max'])),
        ('CPUQuotaPerSecUSec', d.UInt64(p['cpu_percent'] * 10000)),
        ('CPUQuotaPeriodUSec', d.UInt64(100000)), ('CPUWeight', d.UInt64(10)),
        ('IOWeight', d.UInt64(10)),
        ('IOReadBandwidthMax', d.Array([(p['io_device'], d.UInt64(p['io_read_bytes_per_second']))], signature='(st)')),
        ('IOWriteBandwidthMax', d.Array([(p['io_device'], d.UInt64(p['io_write_bytes_per_second']))], signature='(st)')),
    ]


def ensure_slice(bus, mgr, p):
    import dbus as d
    # Concurrent launches share one policy budget. No caps on Codex's group.
    aggregate = aggregate_policy(p)
    with (STATE / 'slice.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            mgr.StartTransientUnit(SLICE, 'fail', resource_properties(aggregate) + [
                ('Description', 'resguard user-wide Codex command budget'), ('AddRef', True)],
                d.Array([], signature='(sa(sv))'))
        except d.DBusException as exc:
            if exc.get_dbus_name() != 'org.freedesktop.systemd1.UnitExists':
                raise
            mgr.RefUnit(SLICE)
            mgr.SetUnitProperties(SLICE, True, resource_properties(aggregate))


def measurements(bus, mgr, unit):
    v = properties(bus, mgr, unit, SERVICE_IF)
    result = {'result': str(v.get('Result', 'unknown')),
              'exit_code_kind': int(v.get('ExecMainCode', 0)),
              'exit_status': int(v.get('ExecMainStatus', 0))}
    for prop, key in [('CPUUsageNSec', 'cpu_ns'), ('MemoryPeak', 'memory_peak_bytes'),
                      ('MemorySwapPeak', 'swap_peak_bytes'), ('IOReadBytes', 'io_read_bytes'),
                      ('IOWriteBytes', 'io_write_bytes')]:
        n = int(v.get(prop, 2**64-1))
        result[key] = None if n == 2**64-1 else n
    start, end = int(v.get('ExecMainStartTimestampMonotonic', 0)), int(v.get('ExecMainExitTimestampMonotonic', 0))
    result['duration_seconds'] = (end-start)/1e6 if start and end >= start else None
    return result


def accounting_resources(aggregate=False):
    import dbus as d
    return [
        ('MemoryAccounting', True), ('TasksAccounting', True),
        ('MemoryMax', d.UInt64((256 if aggregate else 64) * 1024**2)),
        ('MemorySwapMax', d.UInt64(0)),
        ('TasksMax', d.UInt64(64 if aggregate else 8)),
        ('CPUQuotaPerSecUSec', d.UInt64(1000000 if aggregate else 250000)),
        ('CPUQuotaPeriodUSec', d.UInt64(100000)),
    ]


def ensure_accounting_slice(mgr):
    import dbus as d
    with (STATE / 'slice.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            mgr.StartTransientUnit(LOG_SLICE, 'fail', accounting_resources(True) + [
                ('Description', 'resguard bounded final accounting'), ('AddRef', True)],
                d.Array([], signature='(sa(sv))'))
        except d.DBusException as exc:
            if exc.get_dbus_name() != 'org.freedesktop.systemd1.UnitExists':
                raise
            mgr.RefUnit(LOG_SLICE)
            mgr.SetUnitProperties(LOG_SLICE, True, accounting_resources(True))


def accounting_properties(req):
    import dbus as d
    argv = [PYTHON, str(HERE / 'guard.py'), 'collect', req['id']]
    return accounting_resources() + [
        ('Description', f'resguard accounting {req["id"]}'),
        ('Slice', LOG_SLICE), ('Type', 'oneshot'), ('AddRef', True),
        ('CollectMode', 'inactive-or-failed'),
        # This dependency also retains workload statistics while accounting runs.
        ('After', d.Array([req['unit']], signature='s')),
        ('TimeoutStartUSec', d.UInt64(LOG_TIMEOUT_SECONDS * 1000000)),
        ('TimeoutStopUSec', d.UInt64(3000000)),
        ('KillMode', 'control-group'), ('OOMPolicy', 'kill'),
        ('LimitCORE', d.UInt64(0)), ('LimitCORESoft', d.UInt64(0)),
        ('UMask', d.UInt32(0o077)),
        ('StandardInput', 'null'), ('StandardOutput', 'journal'),
        ('StandardError', 'journal'),
        ('ExecStartEx', d.Array([(PYTHON, argv, ['no-env-expand'])], signature='(sasas)')),
    ]


def current_cgroup():
    path = next(line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines()
                if line.startswith('0::'))
    return Path('/sys/fs/cgroup' + path)


def check_limits(req):
    p = req['limits']
    cg = current_cgroup()
    if cg.name != req['unit'] or cg.parent.name != SLICE:
        raise RuntimeError(f'Worker is outside its expected cgroup: {cg}')
    actual = {}
    for name, desired in [('memory.max', p['memory_max']), ('memory.high', p['memory_high']),
                          ('memory.swap.max', 0), ('pids.max', p['tasks_max'])]:
        actual[name] = (cg / name).read_text().strip()
        if actual[name] == 'max' or int(actual[name]) > desired:
            raise RuntimeError(f'{name} not enforced: {actual[name]} > {desired}')
    actual['memory.oom.group'] = (cg / 'memory.oom.group').read_text().strip()
    if actual['memory.oom.group'] != '1':
        raise RuntimeError('Group OOM kill is not enabled')
    actual['cpu.max'] = (cg / 'cpu.max').read_text().strip()
    # Validate the aggregate budget, not merely one job's limits.
    # New launchers snapshot this with the command request so a later policy
    # edit cannot make a running worker validate against unrelated values.
    # The fallback keeps pre-upgrade pending requests compatible.
    aggregate = req.get('aggregate_limits', aggregate_policy(load_policy()))
    for name, desired in [('memory.max', aggregate['memory_max']),
                          ('memory.high', aggregate['memory_high']), ('memory.swap.max', 0),
                          ('pids.max', aggregate['tasks_max'])]:
        v = (cg.parent / name).read_text().strip()
        if v == 'max' or int(v) != desired:
            raise RuntimeError(f'Aggregate {name} is {v}, expected {desired}')
    for group, policy, exact in ((cg, p, False), (cg.parent, aggregate, True)):
        quota, period = (group/'cpu.max').read_text().split()
        ratio = None if quota == 'max' else int(quota) / int(period)
        desired = policy['cpu_percent'] / 100
        if ratio is None or (ratio != desired if exact else ratio > desired):
            raise RuntimeError(f'CPU quota not enforced in {group}')
    actual['io.max'] = (cg / 'io.max').read_text().strip() if (cg/'io.max').exists() else None
    device = os.stat(p['io_device']).st_rdev
    devno = f'{os.major(device)}:{os.minor(device)}'

    def io_enforced(group, policy):
        if not (group/'io.max').exists():
            return False
        for row in (group/'io.max').read_text().splitlines():
            fields = row.split()
            if fields and fields[0] == devno:
                vals = dict(x.split('=') for x in fields[1:])
                return all(vals.get(k, 'max') != 'max' and
                           0 < int(vals[k]) <= policy[prop] for k, prop in
                           [('rbps', 'io_read_bytes_per_second'), ('wbps', 'io_write_bytes_per_second')])
        return False

    actual['io_active'] = io_enforced(cg, p) and io_enforced(cg.parent, aggregate)
    if p['require_io'] and not actual['io_active']:
        raise RuntimeError('io controller is not delegated; administrator setup required')
    event('ready', id=req['id'], unit=req['unit'], cgroup=str(cg), effective=actual)
    return actual


def exit_status(m):
    if m['result'] == 'timeout':
        return 124
    if m['result'] == 'oom-kill':
        return 137
    if m['exit_code_kind'] == 1:
        return m['exit_status']
    if m['exit_code_kind'] in (2, 3):
        return 128 + m['exit_status']
    return 125


def run(job, shell):
    import dbus as d
    from dbus.mainloop.glib import DBusGMainLoop
    from gi.repository import GLib
    original_umask = os.umask(0o077)
    setup_state()
    req = json.loads(pending(job).read_text())
    base = load_policy()
    p = lower_limits(base)
    aggregate = aggregate_policy(base)
    # Preserve the shell tool's selection; fail closed for unsupported shells.
    resolved = Path(shell) if shell.startswith('/') else Path('/bin') / shell
    if resolved.name not in ('bash', 'zsh', 'sh', 'dash') or not resolved.is_file():
        raise ValueError(f'Unsupported shell {shell!r}; use bash or zsh')
    unit = PREFIX + job + '.service'
    audit_unit = 'resguardlog-' + job + '.service'
    req.update(unit=unit, audit_unit=audit_unit, cwd=os.getcwd(), shell=str(resolved),
               limits=p, aggregate_limits=aggregate, runner_pid=os.getpid())
    pending(job).write_text(json.dumps(req))
    event('launch', **req)
    DBusGMainLoop(set_as_default=True)
    bus, mgr = connection()
    ensure_slice(bus, mgr, base)
    ensure_accounting_slice(mgr)
    loop = GLib.MainLoop()
    final = {}
    audit_final = {}
    audit_deadline = None
    poll_source = None
    started = False
    start_finished = False

    def check_state(*unused):
        nonlocal audit_deadline, poll_source
        if not started or not start_finished:
            return
        try:
            state = str(properties(bus, mgr, unit, UNIT_IF)['ActiveState'])
            if state in ('inactive', 'failed'):
                m = measurements(bus, mgr, unit)
                if state == 'inactive' and not m['exit_code_kind'] and m['result'] == 'success':
                    return  # StartTransientUnit has queued, not yet executed, the start job.
                final.update(m)
                if audit_deadline is None:
                    audit_deadline = time.monotonic() + LOG_TIMEOUT_SECONDS + 8
                    poll_source = GLib.timeout_add(250, poll_state)
                # Logging has its own deadline and cannot alter the workload
                # result. Wait for its bounded outcome to make failures visible.
                audit_state = str(properties(bus, mgr, audit_unit, UNIT_IF)['ActiveState'])
                a = measurements(bus, mgr, audit_unit)
                if audit_state in ('inactive', 'failed') and (
                        a['exit_code_kind'] or a['result'] != 'success'):
                    audit_final.update(a)
                    loop.quit()
                elif time.monotonic() >= audit_deadline:
                    audit_final['result'] = 'accounting-deadline'
                    loop.quit()
        except d.DBusException:
            loop.quit()

    def poll_state():
        # Poll only during bounded accounting, never for the workload lifetime.
        check_state()
        return True

    mgr.Subscribe()
    receiver = bus.add_signal_receiver(check_state, signal_name='PropertiesChanged',
                                       dbus_interface='org.freedesktop.DBus.Properties')

    def job_removed(number, path, name, result):
        nonlocal start_finished
        if str(name) != unit or str(path) != str(start_job):
            return
        start_finished = True
        if str(result) != 'done':
            final.update(measurements(bus, mgr, unit))
            final['result'] = 'start-' + str(result)
            loop.quit()
        else:
            check_state()

    job_receiver = bus.add_signal_receiver(job_removed, signal_name='JobRemoved',
                                           dbus_interface='org.freedesktop.systemd1.Manager')
    parent_fd = os.pidfd_open(os.getpid())
    environment_fd = os.memfd_create('codex-guard-environment', os.MFD_CLOEXEC)
    environment_bytes = json.dumps(dict(os.environ)).encode()
    os.write(environment_fd, environment_bytes)
    os.lseek(environment_fd, 0, os.SEEK_SET)
    start_job = None
    # FD passing keeps stdin/stdout streaming and avoids buffering unlimited
    # output in the runner. ExecStartEx disables systemd's $VAR substitution.
    argv = [PYTHON, str(HERE / 'guard.py'), 'worker', job, '--shell', str(resolved)]
    props = resource_properties(p) + [
        ('Description', f'Codex command {job}'), ('Slice', SLICE),
        ('Type', 'exec'), ('AddRef', True), ('CollectMode', 'inactive-or-failed'),
        ('OOMPolicy', 'kill'), ('KillMode', 'control-group'),
        ('LimitCORE', d.UInt64(0)), ('LimitCORESoft', d.UInt64(0)),
        ('RuntimeMaxUSec', d.UInt64(p['runtime_seconds'] * 1000000)),
        ('TimeoutStopUSec', d.UInt64(p['stop_seconds'] * 1000000)),
        ('WorkingDirectory', os.getcwd()), ('UMask', d.UInt32(original_umask)),
        ('StandardInputFileDescriptor', d.types.UnixFd(0)),
        ('StandardOutputFileDescriptor', d.types.UnixFd(1)),
        ('StandardErrorFileDescriptor', d.types.UnixFd(2)),
        ('ExtraFileDescriptors', d.Array([(d.types.UnixFd(parent_fd), 'guard-parent'),
                                         (d.types.UnixFd(environment_fd), 'guard-environment')], signature='(hs)')),
        ('ExecStartEx', d.Array([(PYTHON, argv, ['no-env-expand'])], signature='(sasas)')),
        ('OnSuccess', d.Array([audit_unit], signature='s')),
        ('OnFailure', d.Array([audit_unit], signature='s')),
    ]

    def cancel(signum, frame):
        # Cleanup must not depend on available log storage.
        mgr.StopUnit(unit, 'replace')
        try:
            event('cancel', id=job, signal=signum)
        except Exception:
            pass

    def resize(signum, frame):
        try:
            mgr.KillUnit(unit, 'main', int(signal.SIGWINCH))
        except d.DBusException:
            pass  # The short-lived worker may already have exited.

    old_handlers = {}
    try:
        # Load the handler in the same transaction, before the workload starts.
        # It still runs if this outer runner is killed or its terminal disappears.
        auxiliary = d.Array([(audit_unit, accounting_properties(req))], signature='(sa(sv))')
        start_job = mgr.StartTransientUnit(unit, 'fail', props, auxiliary)
        started = True
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            old_handlers[sig] = signal.signal(sig, cancel)
        old_handlers[signal.SIGWINCH] = signal.signal(signal.SIGWINCH, resize)
        check_state()
        if not audit_final and not final.get('result', '').startswith('start-'):
            loop.run()
        if not final:
            raise RuntimeError('Lost systemd service result')
        rc = exit_status(final)
        audit_result = audit_final.get('result', 'unavailable')
        # The finish record is authoritative. Never wait on a stalled logger's
        # lock here, or turn a secondary audit-write failure into command125.
        if audit_result == 'success':
            try:
                event('return', _nonblocking=True, id=job, unit=unit, returned_exit=rc,
                      audit_unit=audit_unit, audit_result=audit_result, **final)
            except Exception as exc:
                print(f'[resguard] WARNING: return audit unavailable ({type(exc).__name__}); '
                      'workload exit preserved; see the final accounting record.', file=sys.stderr)
        # Always make duration and kill reason available in the shell result.
        print(f'\n[resguard] id={job} result={final["result"]} exit={rc} '
              f'wall={final["duration_seconds"]}s cpu_ns={final["cpu_ns"]} '
              f'peak_bytes={final["memory_peak_bytes"]}', file=sys.stderr, flush=True)
        if final['result'] in ('oom-kill', 'timeout'):
            print('[resguard] Worker stopped; retry a smaller task or lower concurrency.', file=sys.stderr)
        if audit_result != 'success':
            print(f'[resguard] WARNING: final accounting {audit_result}; workload exit '
                  f'{rc} preserved. Metadata retained; inspect journal for {audit_unit}.',
                  file=sys.stderr, flush=True)
        return rc
    finally:
        if poll_source is not None:
            GLib.source_remove(poll_source)
        for sig, old in old_handlers.items():
            signal.signal(sig, old)
        receiver.remove()
        job_receiver.remove()
        os.close(parent_fd)
        os.close(environment_fd)
        if started:
            if not final:
                mgr.StopUnit(unit, 'replace')
            mgr.UnrefUnit(unit)
            mgr.UnrefUnit(audit_unit)
        mgr.UnrefUnit(LOG_SLICE)
        mgr.UnrefUnit(SLICE)
        bus.close()


def worker(job, shell):
    original_umask = os.umask(0o077)
    req = json.loads(pending(job).read_text())
    check_limits(req)
    # pidfd identity survives PID reuse. Parent loss is event-driven, even when
    # the outer command transport is killed with SIGKILL by Codex cancellation.
    names = os.environ.pop('LISTEN_FDNAMES', '').split(':')
    parent_fd = 3 + names.index('guard-parent')
    env_fd = 3 + names.index('guard-environment')
    os.set_inheritable(parent_fd, False)
    with os.fdopen(env_fd) as inp:
        environment = json.load(inp)
    os.environ.clear()
    os.environ.update(environment)
    os.environ['CODEX_RESOURCE_JOB'] = job
    os.environ['CODEX_RESOURCE_UNIT'] = req['unit']
    if select.select([parent_fd], [], [], 0)[0]:
        return 125
    os.environ['PATH'] = str(HERE / 'bin') + ':' + os.environ.get('PATH', '/usr/bin:/bin')
    os.umask(original_umask)
    if os.isatty(0) and os.isatty(1):
        return tty_worker(req, shell, parent_fd)
    child = subprocess.Popen([shell, '-c', req['command']])
    child_fd = os.pidfd_open(child.pid)
    ready, _, _ = select.select([parent_fd, child_fd], [], [])
    if parent_fd in ready:
        # Exiting the service's main process makes systemd kill its descendants.
        # Do not make this path wait for logging, storage or another D-Bus call.
        return 125
    rc = child.wait()
    return rc if rc >= 0 else 128-rc


def tty_worker(req, shell, parent_fd):
    saved = termios.tcgetattr(0)
    child_pid, master = pty.fork()
    if child_pid == 0:
        os.execve(shell, [shell, '-c', req['command']], os.environ)
    child_fd = os.pidfd_open(child_pid)

    def resize(*unused):
        try:
            size = fcntl.ioctl(0, termios.TIOCGWINSZ, b'\0'*8)
            fcntl.ioctl(master, termios.TIOCSWINSZ, size)
        except OSError:
            pass

    def write_all(fd, data):
        while data:
            data = data[os.write(fd, data):]

    resize()
    signal.signal(signal.SIGWINCH, resize)
    tty.setraw(0)

    def parent_gone():
        # Keep cancellation responsive even when the PTY forwarder is blocked
        # by output backpressure. This thread sleeps in the kernel on one FD.
        select.select([parent_fd], [], [])
        # Terminate the *worker*, not just this thread. KillMode=control-group
        # cleans descendants and ExecStopPost records exit 125. Logging here
        # could block on a full/broken filesystem and prevent cleanup.
        os._exit(125)

    threading.Thread(target=parent_gone, daemon=True).start()
    readers = [0, master, child_fd]
    try:
        while True:
            ready, _, _ = select.select(readers, [], [])
            if master in ready:
                try:
                    data = os.read(master, 65536)
                except OSError:
                    data = b''
                if not data:
                    break
                write_all(1, data)
            if 0 in ready:
                data = os.read(0, 65536)
                if data:
                    write_all(master, data)
                else:
                    readers.remove(0)
            if child_fd in ready:
                # Descendants can keep the PTY open after the shell exits.
                # Drain available output only, then let systemd kill leftovers.
                for _ in range(16):
                    if not select.select([master], [], [], 0)[0]:
                        break
                    try:
                        data = os.read(master, 65536)
                    except OSError:
                        break
                    if not data:
                        break
                    write_all(1, data)
                break
        _, status = os.waitpid(child_pid, 0)
        rc = os.waitstatus_to_exitcode(status)
        return rc if rc >= 0 else 128-rc
    finally:
        termios.tcsetattr(0, termios.TCSANOW, saved)
        os.close(master)
        os.close(child_fd)


def parse_size(value, base=1024):
    m = re.fullmatch(r'(\d+)([KMGT]?)', value)
    if not m:
        raise ValueError(f'Unsupported resource size {value!r}')
    return int(m[1]) * base ** ('KMGT'.index(m[2]) + 1 if m[2] else 0)


def physical_device(path):
    dev = os.stat(path).st_rdev
    sysdev = Path(f'/sys/dev/block/{os.major(dev)}:{os.minor(dev)}').resolve()
    if (sysdev / 'partition').exists():
        return (sysdev.parent / 'dev').read_text().strip()
    return f'{os.major(dev)}:{os.minor(dev)}'


def nested_scope(argv):
    """Compatibility for existing tests.md/GitNexus scope wrappers.

    Tighten the CURRENT service and exec the payload in it. Never migrate into
    a sibling scope, which would defeat aggregate accounting and cleanup.
    """
    original_umask = os.umask(0o077)
    job = os.environ.get('CODEX_RESOURCE_JOB', '')
    req = json.loads(pending(job).read_text())
    check_limits(req)
    changes = {}
    flags = set()
    while argv and argv[0].startswith('-'):
        arg = argv.pop(0)
        if arg == '--':
            break
        if arg in ('--user', '--scope', '--quiet', '-q'):
            flags.add(arg)
            continue
        if arg in ('-p', '--property') and argv:
            prop = argv.pop(0)
        elif arg.startswith('--property='):
            prop = arg.split('=', 1)[1]
        else:
            raise ValueError('Inside the guard only foreground --user --scope resource wrappers are supported')
        name, value = prop.split('=', 1)
        if name in ('MemoryMax', 'MemoryHigh', 'MemorySwapMax'):
            changes[name] = parse_size(value)
        elif name in ('CPUQuota',):
            changes['CPUQuotaPerSecUSec'] = int(float(value.rstrip('%')) * 10000)
        elif name == 'IOWeight':
            changes[name] = int(value)
        elif name in ('IOReadBandwidthMax', 'IOWriteBandwidthMax'):
            dev, val = value.split()
            if physical_device(dev) != physical_device(req['limits']['io_device']):
                raise ValueError('Nested wrapper requested an unconfigured I/O device')
            changes[name] = (req['limits']['io_device'], parse_size(val, base=1000))
        else:
            raise ValueError(f'Unsupported nested scope property {name}')
    if not {'--user', '--scope'}.issubset(flags) or not argv:
        raise ValueError('Run foreground commands directly; separate systemd services escape command accounting')
    import dbus as d
    bus, mgr = connection()
    with (STATE / 'slice.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        actual = properties(bus, mgr, req['unit'], SERVICE_IF)
        updates = []
        for name, requested in changes.items():
            if isinstance(requested, tuple):
                dev, size = requested
                existing = dict((os.path.realpath(str(k)), int(v)) for k, v in actual[name])
                policy_field = 'io_read_bytes_per_second' if name == 'IOReadBandwidthMax' else 'io_write_bytes_per_second'
                size = min(size, existing.get(os.path.realpath(dev), req['limits'][policy_field]), req['limits'][policy_field])
                updates.append((name, d.Array([(dev, d.UInt64(size))], signature='(st)')))
            else:
                updates.append((name, d.UInt64(min(requested, int(actual[name])))))
        mgr.SetUnitProperties(req['unit'], True, updates)
    event('nested_scope', id=job, unit=req['unit'], command=argv,
          note='Tightened existing service; no cgroup migration')
    bus.close()
    os.umask(original_umask)
    os.execvpe(argv[0], argv, os.environ)


def finalize(job):
    # Compatibility for already-running units created by older installations.
    # New jobs use collect() in a separate service, never ExecStopPost.
    req = json.loads(pending(job).read_text())
    bus, mgr = connection()
    m = measurements(bus, mgr, req['unit'])
    m['result'] = os.environ.get('SERVICE_RESULT', m['result'])
    event('finish', id=job, unit=req['unit'], session_id=req['session_id'],
          service_exit_code=os.environ.get('EXIT_CODE'),
          service_exit_status=os.environ.get('EXIT_STATUS'), **m)
    bus.close()
    pending(job).unlink(missing_ok=True)
    return 0


def collect(job):
    req = json.loads(pending(job).read_text())
    cg = current_cgroup()
    if cg.name != req['audit_unit'] or cg.parent.name != LOG_SLICE:
        raise RuntimeError('Final accounting is not in its independent cgroup')
    # systemd may omit MONITOR_* when a handler has multiple trigger
    # dependencies (including both success and failure). The retained source
    # unit's properties are authoritative; do not depend on those variables.
    if os.environ.get('MONITOR_UNIT', req['unit']) != req['unit']:
        raise RuntimeError('Unexpected final accounting trigger')
    bus, mgr = connection()
    try:
        m = measurements(bus, mgr, req['unit'])
        if str(properties(bus, mgr, req['unit'], UNIT_IF)['ActiveState']) not in ('inactive', 'failed'):
            raise RuntimeError('Accounting started before workload cleanup completed')
        status = str(m['exit_status'])
        if m['exit_code_kind'] in (2, 3):
            status = signal.Signals(m['exit_status']).name.removeprefix('SIG')
        event('finish', id=job, unit=req['unit'], session_id=req['session_id'],
              audit_unit=req['audit_unit'],
              service_exit_code={1: 'exited', 2: 'killed', 3: 'dumped'}.get(m['exit_code_kind']),
              service_exit_status=status, **m)
        pending(job).unlink(missing_ok=True)
    finally:
        bus.close()
    return 0


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'nested-scope':
        try:
            nested_scope(sys.argv[2:])
        except Exception as exc:
            print(f'[resguard] nested systemd-run refused: {exc}', file=sys.stderr)
            return 125
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['hook', 'run', 'worker', 'finalize', 'collect', 'logs'])
    parser.add_argument('job', nargs='?')
    parser.add_argument('--shell', default='/bin/bash')
    args = parser.parse_args()
    try:
        if args.mode == 'hook':
            return hook()
        if args.mode == 'logs':
            print(STATE / 'events.jsonl')
            return 0
        return {'run': lambda: run(args.job, args.shell),
                'worker': lambda: worker(args.job, args.shell),
                'finalize': lambda: finalize(args.job),
                'collect': lambda: collect(args.job)}[args.mode]()
    except Exception as exc:
        reason = f'resguard {args.mode} failed: {type(exc).__name__}: {exc}'
        try:
            event('error', id=args.job, mode=args.mode, reason=reason)
        except Exception:
            pass
        if args.mode == 'hook':
            print(json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse',
                  'permissionDecision': 'deny', 'permissionDecisionReason': reason}}))
            return 0
        print(reason, file=sys.stderr)
        return 125


if __name__ == '__main__':
    sys.exit(main())
