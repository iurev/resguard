#!/usr/bin/python3
"""Independent, finite integration probe for PTY resize forwarding."""
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import shlex
import signal
import struct
import subprocess
import termios
import time
import unittest


HERE = Path(__file__).resolve().parent


def guarded_command(command):
    result = subprocess.run(
        ['/usr/bin/python3', str(HERE / 'hook.py')],
        input=json.dumps({'tool_name': 'Bash', 'tool_input': {'command': command},
                          'cwd': str(HERE.parent.parent),
                          'session_id': 'independent-pty-review',
                          'tool_use_id': str(time.time_ns())}),
        capture_output=True, text=True, timeout=8)
    output = json.loads(result.stdout)['hookSpecificOutput']
    if output['permissionDecision'] != 'allow':
        raise AssertionError(output)
    return output['updatedInput']['command']


def read_until(fd, marker, limit_seconds=4):
    output = bytearray()
    deadline = time.monotonic() + limit_seconds
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], max(0, deadline-time.monotonic()))
        if not ready:
            break
        try:
            data = os.read(fd, 65536)
        except OSError:
            break
        if not data:
            break
        output.extend(data)
        if marker in output:
            return bytes(output)
        if len(output) > 1024*1024:
            raise AssertionError('Unexpectedly large output')
    raise AssertionError(f'Missing {marker!r}; received {bytes(output)!r}')


class PTYReview(unittest.TestCase):
    def test_resize_reaches_inner_foreground_process(self):
        # Independent hard bounds: payload sleeps at most five seconds, while
        # the service additionally has an eight-second runtime deadline.
        payload = '''import os,signal,time
def report(*args):
    size=os.get_terminal_size(0)
    print(f"SIZE:{size.columns}:{size.lines}",flush=True)
signal.signal(signal.SIGWINCH,report)
report()
time.sleep(5)
'''
        command = guarded_command('exec /usr/bin/python3 -u -c ' + shlex.quote(payload))
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
        env = {**os.environ, 'CODEX_GUARD_MEMORY_MAX': str(128*1024**2),
               'CODEX_GUARD_RUNTIME_SECONDS': '8', 'CODEX_GUARD_CPU_PERCENT': '100',
               'CODEX_GUARD_TASKS_MAX': '32'}
        proc = subprocess.Popen(['/bin/bash', '-c', command], stdin=slave,
                                stdout=slave, stderr=slave, start_new_session=True,
                                cwd=HERE.parent.parent, env=env)
        os.close(slave)
        try:
            read_until(master, b'SIZE:80:24')
            for rows, columns in ((41, 132), (30, 96)):
                fcntl.ioctl(master, termios.TIOCSWINSZ,
                            struct.pack('HHHH', rows, columns, 0, 0))
                # The external terminal transport sends this signal to runner.
                # Worker must receive forwarding and resize its separate PTY.
                os.kill(proc.pid, signal.SIGWINCH)
                read_until(master, f'SIZE:{columns}:{rows}'.encode(), 2)
            self.assertEqual(proc.wait(timeout=7), 0)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=4)
            os.close(master)


if __name__ == '__main__':
    unittest.main(verbosity=2)
