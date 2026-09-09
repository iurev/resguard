#!/usr/bin/python3
"""Inspect resguard installation and private command resource records."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

import guard


def status():
    from codex_hooks import list_hooks
    policy = guard.load_policy()
    data = list_hooks([os.getcwd()])[0]
    command = '/usr/bin/python3 '+shlex.quote(str(guard.HERE/'hook.py'))
    matches = [h for h in data['hooks'] if h.get('eventName') == 'preToolUse'
               and h.get('command') == command]
    active = len(matches) == 1 and matches[0]['enabled'] and matches[0]['trustStatus'] == 'trusted'
    manager = Path(f'/sys/fs/cgroup/user.slice/user-{os.getuid()}.slice/user@{os.getuid()}.service')
    controllers = (manager/'cgroup.controllers').read_text().strip()
    print(json.dumps({'name': 'resguard', 'user': guard.ACCOUNT_HOME.name,
        'runtime': str(guard.HERE), 'policy_file': str(guard.POLICY),
        'log_file': str(guard.STATE/'events.jsonl'), 'checked_cwd': os.getcwd(),
        'log_retention': 'indefinite', 'log_archive': str(guard.STATE/'archive'),
        'hook_enabled_and_trusted': active, 'hook_matches': len(matches),
        'hook_sources': [h['sourcePath'] for h in matches],
        'delegated_controllers': controllers, 'io_delegated': 'io' in controllers.split(),
        'policy': policy, 'codex_resource_cap': False,
        'warnings': data.get('warnings', []), 'errors': data.get('errors', [])}, indent=2))
    return 0 if active and not data.get('errors') else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('status', help='Check hook discovery/trust for the current directory')
    sub.add_parser('logs', help='Print the private JSONL log path')
    report = sub.add_parser('report', help='Summarize recent guarded commands')
    report.add_argument('--last', type=int, default=20)
    sub.add_parser('test', help='Run finite resource and terminal integration tests')
    args = parser.parse_args()
    if args.action == 'status':
        return status()
    if args.action == 'logs':
        print(guard.STATE/'events.jsonl')
        return 0
    if args.action == 'report':
        if args.last <= 0:
            parser.error('--last must be positive')
        from report import recent
        guard.setup_state()
        recent(args.last)
        return 0
    for name in ('test_audit.py', 'test_guard.py', 'test_pty_resize.py'):
        result = subprocess.run(['/usr/bin/python3', str(guard.HERE/name)])
        if result.returncode:
            return result.returncode
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        print(f'resguard: {exc}', file=sys.stderr)
        sys.exit(1)
