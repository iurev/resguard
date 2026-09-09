#!/usr/bin/python3
"""Run real dangerous-mode Codex against finite fixtures, preserving transcripts."""
import argparse
import datetime
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import guard

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--interactive', action='store_true')
parser.add_argument('--cwd', default='/tmp')
args = parser.parse_args()
interactive_only = args.interactive
guard.setup_state()
stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
outpath = guard.STATE / f'live-codex-{stamp}.jsonl'
probe = str(HERE / 'probes.py')
prompt = f'''This is a user-authorized bounded integration test of an installed resource hook.
Run these EXACT commands as separate exec_command calls, in order, without adding wrappers.
No project tests, edits, repairs, retries, external services or subagents. Failures are expected.
1. /usr/bin/python3 {probe} normal
2. /usr/bin/python3 {probe} memory
3. /usr/bin/python3 {probe} timeout
4. /usr/bin/python3 {probe} pids
5. systemd-run --user --scope --quiet -p MemoryMax=96M -p MemoryHigh=80M -p MemorySwapMax=0 /usr/bin/cat /proc/self/cgroup
6. /usr/bin/python3 {probe} background
7. printf 'AFTER_FAILURES_OK\\n'
After each yielded call, poll until completion. Continue after expected OOM/timeouts.
Finally report actual output markers and exit status for each command; mention any failure honestly.
'''
if interactive_only:
    prompt = f'''This is a user-authorized bounded test of the installed resource hook.
Execute /usr/bin/python3 {probe} interactive using exec_command with tty=true and
yield_time_ms=1000. When it prints TTY_OK, immediately use write_stdin to send
hello-from-codex followed by a real newline. Poll to completion. Then execute
printf 'AFTER_INTERACTIVE_OK\\n'; pwd
and report actual output and exit statuses.
No project tests, edits, repairs, retries, external services or subagents.
'''
argv = ['codex', 'exec', '-C', args.cwd,
        '--dangerously-bypass-approvals-and-sandbox', '--skip-git-repo-check', '--json',
        '-c', 'model_reasoning_effort="low"', prompt]
env = {**os.environ, 'CODEX_GUARD_MEMORY_MAX': str(128*1024**2),
       'CODEX_GUARD_RUNTIME_SECONDS': '30' if interactive_only else '4', 'CODEX_GUARD_TASKS_MAX': '32',
       'CODEX_GUARD_CPU_PERCENT': '100'}
print('Transcript:', outpath, flush=True)
with outpath.open('x') as out:
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, env=env)
    for line in proc.stdout:
        out.write(line); out.flush()
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            print(line.rstrip(), flush=True)
            continue
        if item.get('type') == 'item.completed':
            value = item.get('item', {})
            if value.get('type') == 'command_execution':
                print('COMMAND', value.get('exit_code'), value.get('aggregated_output','')[-1200:], flush=True)
            elif value.get('type') == 'agent_message':
                print(value.get('text',''), flush=True)
        elif item.get('type') in ('thread.started','turn.completed','turn.failed'):
            print(line.rstrip(), flush=True)
    sys.exit(proc.wait())
