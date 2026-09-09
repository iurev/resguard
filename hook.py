#!/usr/bin/python3
"""Keep explicit denial available when the larger runner breaks or hangs."""
import json
from pathlib import Path
import subprocess
import sys

def validate_result(result):
    h = result['hookSpecificOutput']
    if h['hookEventName'] != 'PreToolUse':
        raise ValueError('Invalid hook event')
    if h['permissionDecision'] not in ('allow', 'deny'):
        raise ValueError('Invalid guard decision')
    if h['permissionDecision'] == 'allow':
        cmd = h['updatedInput']['command']
        if not isinstance(cmd, str) or not cmd or '\0' in cmd:
            raise ValueError('Missing or invalid command rewrite')
    elif not isinstance(h.get('permissionDecisionReason'), str) or not h['permissionDecisionReason'].strip():
        raise ValueError('Missing denial reason')
    # Forward only fields our native hook contract allows. Extra control fields
    # from a broken implementation can make Codex reject the whole response.
    clean = {'hookEventName': 'PreToolUse', 'permissionDecision': h['permissionDecision']}
    if h['permissionDecision'] == 'allow':
        clean['updatedInput'] = {'command': cmd}
    else:
        clean['permissionDecisionReason'] = h['permissionDecisionReason']
    return {'hookSpecificOutput': clean}


def guarded_result(payload):
    try:
        if len(payload) > 1024 * 1024:
            raise ValueError('Hook request exceeds 1MiB')
        run = subprocess.run(['/usr/bin/python3', str(Path(__file__).with_name('guard.py')), 'hook'],
                             input=payload, capture_output=True, timeout=4)
        if run.returncode:
            raise RuntimeError('Guard process exited unsuccessfully')
        return validate_result(json.loads(run.stdout))
    except Exception as exc:
        return {'hookSpecificOutput': {'hookEventName': 'PreToolUse',
                'permissionDecision': 'deny',
                'permissionDecisionReason': f'resguard unavailable; command was not executed: {exc}'}}


def main():
    print(json.dumps(guarded_result(sys.stdin.buffer.read(1024 * 1024 + 1))))


if __name__ == '__main__':
    main()
