#!/usr/bin/python3
"""Read private rotated audit logs; never infer success from a hook event alone."""
import argparse
import json

import guard
from audit import events_newest


def recent_jobs(last):
    jobs = {}
    waiting_for_start = set()
    rows = events_newest(guard.STATE)
    try:
        for row in rows:
            job = row.get('id')
            kind = row.get('event')
            if not job or kind not in ('hook', 'launch', 'ready', 'finish', 'return', 'error'):
                continue
            if job not in jobs:
                if len(jobs) == last:
                    continue
                jobs[job] = {}
                waiting_for_start.add(job)
            jobs[job].setdefault(kind, row)  # Keep newest occurrence of each event.
            if kind == 'hook':
                waiting_for_start.discard(job)
            if len(jobs) == last and not waiting_for_start:
                break
    finally:
        rows.close()
    return list(reversed(jobs.items()))


def recent(last):
    jobs = recent_jobs(last)
    print('job          exit result             wall_s  cpu_s  peak_MiB io       command')
    for job, events in jobs:
        result = events.get('return', events.get('finish', {}))
        ready = events.get('ready', {}).get('effective', {})
        launch = events.get('launch', events.get('hook', {}))
        outcome = result.get('result', 'error' if 'error' in events else 'unfinished')
        rc = result.get('returned_exit', result.get('exit_status', '-'))
        def number(key, scale=1):
            value = result.get(key)
            return f'{value / scale:.2f}' if value is not None else '-'
        io = 'active' if ready.get('io_active') else 'OFF' if ready else 'unknown'
        # JSON escaping prevents command-embedded terminal control sequences.
        command = json.dumps(launch.get('command', ''), ensure_ascii=True)[:160]
        print(f'{job[:12]} {str(rc):>4} {outcome:<18} '
              f'{number("duration_seconds"):>6} {number("cpu_ns", 1e9):>6} '
              f'{number("memory_peak_bytes", 1024**2):>9} {io:<8} {command}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--last', type=int, default=20)
    args = parser.parse_args()
    if args.last <= 0:
        parser.error('--last must be positive')
    guard.setup_state()
    recent(args.last)
