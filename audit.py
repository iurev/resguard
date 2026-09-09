"""Permanent audit archives and bounded-memory reverse reading."""
import fcntl
import json
import os
import uuid


def archive_path(directory, number):
    return directory / f'events-{number:012d}.jsonl'


def sequence(directory):
    try:
        value = int((directory / 'sequence').read_text())
        if value < 0:
            raise ValueError('Negative audit archive sequence')
        return value
    except FileNotFoundError:
        # Also handles an imported archive directory without its sequence file.
        return max((int(p.stem.split('-')[1]) for p in directory.glob('events-[0-9]*.jsonl')), default=0)


def archive_log(path):
    """Caller must hold log.lock exclusively. Never delete an older archive."""
    directory = path.parent / 'archive'
    directory.mkdir(mode=0o700, exist_ok=True)
    number = sequence(directory) + 1
    while archive_path(directory, number).exists():
        number += 1
    temporary = directory / ('.sequence-' + uuid.uuid4().hex)
    try:
        with temporary.open('x') as out:
            out.write(str(number) + '\n')
        # Publish the index before renaming. An interrupted rotation may leave
        # a gap, but neither reuses a filename nor discards the current log.
        temporary.replace(directory / 'sequence')
        path.rename(archive_path(directory, number))
    finally:
        temporary.unlink(missing_ok=True)


def reverse_rows(inp, end):
    """Read JSONL backwards in fixed-size chunks, never a whole history file."""
    tail = b''
    while end:
        start = max(0, end - 65536)
        inp.seek(start)
        block = inp.read(end - start) + tail
        lines = block.split(b'\n')
        tail = lines.pop(0)
        for line in reversed(lines):
            try:
                value = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if isinstance(value, dict):
                yield value
        end = start
    if tail:
        try:
            value = json.loads(tail)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return
        if isinstance(value, dict):
            yield value


def events_newest(state):
    """Snapshot under the lock, then read without blocking command log writers.

    Opening the active file before releasing the lock keeps its inode readable
    if a writer rotates it. The captured size/sequence exclude subsequent writes
    and rotations, so a report neither duplicates nor misses snapshot records.
    """
    current = None
    with (state / 'log.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_SH)
        last = sequence(state / 'archive')
        try:
            current = (state / 'events.jsonl').open('rb')
            end = os.fstat(current.fileno()).st_size
        except FileNotFoundError:
            pass
    if current is not None:
        with current:
            yield from reverse_rows(current, end)
    for number in range(last, 0, -1):
        path = archive_path(state / 'archive', number)
        try:
            inp = path.open('rb')
        except FileNotFoundError:
            continue  # An interrupted rotation can leave a sequence gap.
        with inp:
            yield from reverse_rows(inp, os.fstat(inp.fileno()).st_size)
    # Retain and read pre-upgrade rotations too. New writers never touch them.
    for number in (1, 2, 3):
        try:
            inp = (state / f'events.jsonl.{number}').open('rb')
        except FileNotFoundError:
            continue
        with inp:
            yield from reverse_rows(inp, os.fstat(inp.fileno()).st_size)
