#!/usr/bin/python3
"""Check real CLI evidence, excluding the model's own success/failure claims."""
import argparse
import json
from pathlib import Path
import re

import guard


def verify(session, interactive):
    # Run immediately after a live test, before log rotation/PID reuse.
    rows = [json.loads(line) for line in (guard.STATE/'events.jsonl').read_text().splitlines()]
    launches = [r for r in rows if r.get('session_id') == session and r['event'] == 'launch']
    expected = [0, 0] if interactive else [0, 137, 124, 0, 0, 0, 0]
    assert len(launches) == len(expected), (len(launches), expected)
    for launch, code in zip(launches, expected):
        events = {r['event']: r for r in rows if r.get('id') == launch['id']}
        assert {'hook', 'ready', 'finish', 'return'} <= events.keys(), events.keys()
        assert events['return']['returned_exit'] == code, events['return']
        actual = events['ready']['effective']
        assert actual['memory.max'] == str(128*1024**2), actual
        assert actual['memory.swap.max'] == '0', actual
        assert actual['pids.max'] == '32', actual
        assert actual['cpu.max'] == '100000 100000', actual
        assert events['return']['memory_peak_bytes'] is not None
        assert not Path(events['ready']['cgroup']).exists(), 'Finished job cgroup survived'
    sessions = guard.ACCOUNT_HOME / '.codex/sessions'
    paths = list(sessions.rglob('*'+session+'*.jsonl'))
    assert len(paths) == 1, paths
    outputs = []
    for line in paths[0].read_text().splitlines():
        row = json.loads(line)
        p = row.get('payload', {})
        if row.get('type') == 'response_item' and p.get('type') in ('custom_tool_call_output', 'function_call_output'):
            outputs.append(json.dumps(p.get('output', ''), ensure_ascii=True))
    evidence = '\n'.join(outputs)
    markers = ['TTY_OK True True', 'INPUT hello-from-codex', 'AFTER_INTERACTIVE_OK'] if interactive else [
        'PROBE_NORMAL', 'MEMORY_PROBE_START', 'DETACHED_PID', 'PIDS_BLOCKED True',
        'BACKGROUND_PID', 'AFTER_FAILURES_OK']
    for marker in markers:
        assert marker in evidence, f'Missing actual tool output: {marker}'
    assert 'UNEXPECTED_ALLOCATION_SUCCESS' not in evidence
    for pid in re.findall(r'(?:DETACHED_PID|BACKGROUND_PID) (\d+)', evidence):
        assert not Path('/proc/'+pid).exists(), f'Fixture descendant remains: {pid}'
    print(f'PASS: {session}: {len(launches)} guarded jobs, exits {expected}; '
          'kernel readbacks, final metrics, cleanup and actual tool outputs verified.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('session')
    parser.add_argument('--interactive', action='store_true')
    args = parser.parse_args()
    verify(args.session, args.interactive)
