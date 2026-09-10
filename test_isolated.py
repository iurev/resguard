#!/usr/bin/python3
"""Run the finite suite with private state and its own 512MiB workload budget.

Copies source to a private temporary directory; never changes installed policy,
state, hooks, existing services, or their budgets. The harness is separately
capped at 128MiB/one CPU. Tests still create real systemd/cgroup jobs.
"""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import uuid

import guard


def main():
    with tempfile.TemporaryDirectory(prefix='resguard-isolated-suite-') as directory:
        root = Path(directory)
        state = root / 'state'
        state.mkdir(mode=0o700)
        policy = dict(guard.load_policy(), memory_max=512*1024**2,
                      memory_high=512*1024**2, cpu_percent=100, tasks_max=128,
                      aggregate_memory_max=512*1024**2,
                      aggregate_memory_high=512*1024**2,
                      aggregate_cpu_percent=100, aggregate_tasks_max=128)
        policy_path = root / 'policy.json'
        policy_path.write_text(json.dumps(policy))
        for name in ('guard.py', 'audit.py', 'hook.py', 'probes.py', 'report.py',
                     'test_audit.py', 'test_guard.py', 'test_pty_resize.py'):
            shutil.copy2(guard.HERE/name, root/name)
        shutil.copytree(guard.HERE/'bin', root/'bin')
        source = (root/'guard.py').read_text()
        source = source.replace("STATE = ACCOUNT_HOME / '.local/state/resguard'",
                                f'STATE = Path({str(state)!r})')
        source = source.replace("POLICY = ACCOUNT_HOME / '.config/resguard/policy.json'",
                                f'POLICY = Path({str(policy_path)!r})')
        token = uuid.uuid4().hex
        source = source.replace("SLICE = 'resguard.slice'",
                                f"SLICE = 'resguardtest{token}.slice'")
        source = source.replace("LOG_SLICE = 'resguardlog.slice'",
                                f"LOG_SLICE = 'resguardlogtest{token}.slice'")
        (root/'guard.py').write_text(source)
        # FinalAccounting creates additional isolated copies and must replace
        # this fixture's STATE line, not an account-specific hardcoded default.
        tests = (root/'test_guard.py').read_text()
        tests = tests.replace('source.replace("STATE = ACCOUNT_HOME / \'.local/state/resguard\'",',
                              f'source.replace({f"STATE = Path({str(state)!r})"!r},')
        (root/'test_guard.py').write_text(tests)
        selected = sys.argv[1:] or ['test_audit.py', 'test_guard.py', 'test_pty_resize.py']
        for name in selected:
            if name not in ('test_audit.py', 'test_guard.py', 'test_pty_resize.py'):
                raise ValueError('Unknown test module')
            print('ISOLATED', name, flush=True)
            # Explicit executable: this is a separately bounded verification
            # harness, not an attempt to migrate production commands away from
            # their resource policy through the compatibility PATH shim.
            argv = ['/usr/bin/systemd-run', '--user', '--wait', '--pipe', '--collect',
                    '--quiet', '--service-type=exec', '-p', 'MemoryMax=128M',
                    '-p', 'MemorySwapMax=0', '-p', 'CPUQuota=100%', '-p', 'TasksMax=32',
                    '-p', 'RuntimeMaxSec=300', '-p', 'TimeoutStopSec=3',
                    '/usr/bin/python3', '-B', str(root/name)]
            result = subprocess.run(argv, stdin=subprocess.DEVNULL, timeout=310)
            if result.returncode:
                return result.returncode
        return 0


if __name__ == '__main__':
    sys.exit(main())
