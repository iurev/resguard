#!/usr/bin/python3
"""Finite test payloads. Resource probes refuse to run outside a small cgroup."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def cgroup():
    path = next(x[3:] for x in Path('/proc/self/cgroup').read_text().splitlines() if x.startswith('0::'))
    return Path('/sys/fs/cgroup' + path)


def small_guard():
    cg = cgroup()
    assert cg.name.startswith('resguard-'), f'Probe refused outside guard: {cg}'
    assert int((cg/'memory.max').read_text()) <= 256 * 1024**2, 'Probe requires a small test budget'
    assert (cg/'memory.swap.max').read_text().strip() == '0'
    return cg


mode = sys.argv[1]
if mode == 'normal':
    print('PROBE_NORMAL', os.getcwd(), flush=True)
    print(cgroup(), flush=True)
elif mode == 'memory':
    small_guard()
    print('MEMORY_PROBE_START', flush=True)
    data = bytearray(192 * 1024**2)
    print('UNEXPECTED_ALLOCATION_SUCCESS', len(data), flush=True)
elif mode == 'timeout':
    small_guard()
    child = subprocess.Popen(['/usr/bin/sleep', '10'], start_new_session=True)
    print('DETACHED_PID', child.pid, flush=True)
    time.sleep(10)
elif mode == 'pids':
    small_guard()
    children = []
    blocked = False
    try:
        for _ in range(40):
            children.append(subprocess.Popen(['/usr/bin/sleep', '1']))
    except OSError:
        blocked = True
    print('PIDS_BLOCKED', blocked, 'created', len(children), flush=True)
    for child in children:
        child.wait()
    assert blocked, 'Task limit was not reached by the finite 40-process probe'
elif mode == 'cpu':
    small_guard()
    start, cpu_start = time.monotonic(), time.process_time()
    while time.monotonic() - start < 2:
        sum(range(500))
    print('CPU_PROBE', time.process_time()-cpu_start, 'wall', time.monotonic()-start, flush=True)
elif mode == 'interactive':
    with open('/dev/tty') as terminal:
        print('TTY_OK', os.isatty(0), os.isatty(1), flush=True)
    print('INPUT', input(), flush=True)
elif mode == 'background':
    small_guard()
    child = subprocess.Popen(['/usr/bin/sleep', '10'], start_new_session=True)
    print('BACKGROUND_PID', child.pid, flush=True)
elif mode == 'output':
    small_guard()
    os.write(1, b'x' * 1024 * 1024)
    time.sleep(10)
else:
    raise ValueError(mode)
