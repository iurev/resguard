#!/usr/bin/python3
"""Small isolated retention tests; never rotate/delete the user's real logs."""
import fcntl
import io
import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import audit
import guard
import report


def concurrent_writer(prefix):
    for index in range(25):
        guard.event('probe', id=f'{prefix}-{index}', padding='x'*200)


class Retention(unittest.TestCase):
    def setUp(self):
        self.saved_umask = os.umask(0o077)
        self.temp = tempfile.TemporaryDirectory(prefix='resguard-audit-test-')
        self.state = Path(self.temp.name)
        self.state_patch = mock.patch.object(guard, 'STATE', self.state)
        self.limit_patch = mock.patch.object(guard, 'MAX_LOG', 256)
        self.state_patch.start()
        self.limit_patch.start()

    def tearDown(self):
        self.limit_patch.stop()
        self.state_patch.stop()
        self.temp.cleanup()
        os.umask(self.saved_umask)

    def test_keeps_every_rotation_and_legacy_file(self):
        legacy = {}
        for number in (1, 2, 3):
            path = self.state/f'events.jsonl.{number}'
            text = json.dumps({'event':'legacy', 'id':f'old-{number}'})+'\n'
            path.write_text(text)
            legacy[path] = text
        for index in range(16):
            guard.event('probe', id=str(index), padding='x'*300)
        self.assertEqual(len(list((self.state/'archive').glob('events-*.jsonl'))), 15)
        rows = list(audit.events_newest(self.state))
        self.assertEqual([r['id'] for r in rows],
                         [str(n) for n in range(15,-1,-1)]+['old-1','old-2','old-3'])
        for path, text in legacy.items():
            self.assertEqual(path.read_text(), text)
        self.assertEqual((self.state/'archive').stat().st_mode & 0o777, 0o700)
        for path in (self.state/'archive').glob('events-*.jsonl'):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_multiple_process_writers_do_not_lose_records(self):
        ctx = multiprocessing.get_context('fork')
        workers = [ctx.Process(target=concurrent_writer, args=(n,)) for n in range(4)]
        try:
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=5)
                self.assertEqual(worker.exitcode, 0)
        finally:
            for worker in workers:
                if worker.is_alive():
                    worker.kill()
                    worker.join()
        rows = list(audit.events_newest(self.state))
        self.assertEqual(len(rows), 100)
        self.assertEqual({r['id'] for r in rows}, {f'{n}-{i}' for n in range(4) for i in range(25)})

    def test_recent_report_reassembles_jobs_across_archives(self):
        for n in range(8):
            guard.event('hook', id=str(n), command=f'command-{n}', padding='x'*300)
            guard.event('launch', id=str(n), command=f'command-{n}')
        for n in range(8):
            guard.event('return', id=str(n), result='success', returned_exit=0)
        jobs = report.recent_jobs(2)
        self.assertEqual([job for job, _ in jobs], ['6','7'])
        for job, events in jobs:
            self.assertEqual(set(events), {'hook','launch','return'})
            self.assertEqual(events['launch']['command'], f'command-{job}')

    def test_reader_snapshot_survives_rotation_without_blocking_writer(self):
        with mock.patch.object(guard, 'MAX_LOG', 1024*1024):
            guard.event('probe', id='first')
            guard.event('probe', id='second')
        reader = audit.events_newest(self.state)
        try:
            self.assertEqual(next(reader)['id'], 'second')
            with (self.state/'log.lock').open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(lock, fcntl.LOCK_UN)
            with mock.patch.object(guard, 'MAX_LOG', 1):
                guard.event('probe', id='later')
            self.assertEqual([r['id'] for r in reader], ['first'])
            self.assertEqual([r['id'] for r in audit.events_newest(self.state)],
                             ['later','second','first'])
        finally:
            reader.close()

    def test_reverse_reader_handles_large_unicode_and_partial_lines(self):
        first = {'id':'first','text':'\u2603'*70000}
        second = {'id':'second'}
        content = (json.dumps(first,ensure_ascii=False)+'\n'+json.dumps(second)+'\n{partial').encode()
        self.assertEqual(list(audit.reverse_rows(io.BytesIO(content),len(content))),[second,first])

    def test_sequence_gap_and_missing_index_preserve_existing_archives(self):
        guard.event('probe', id='old', padding='x'*300)
        guard.event('probe', id='current')
        index = self.state/'archive/sequence'
        index.write_text('5\n')  # Interrupted rotation can reserve unused numbers.
        self.assertEqual([r['id'] for r in audit.events_newest(self.state)], ['current','old'])
        index.unlink()  # Simulate importing archives without their index.
        self.assertEqual([r['id'] for r in audit.events_newest(self.state)], ['current','old'])

    def test_recent_report_stops_after_requested_jobs(self):
        visited = []
        closed = []
        def rows():
            try:
                for n in range(10000):
                    for kind in ('return','hook'):
                        visited.append(n)
                        yield {'id':str(n),'event':kind}
            finally:
                closed.append(True)
        with mock.patch.object(report, 'events_newest', side_effect=lambda _: rows()):
            self.assertEqual(len(report.recent_jobs(2)),2)
        self.assertEqual(len(visited),4)
        self.assertEqual(closed,[True])


if __name__ == '__main__':
    unittest.main(verbosity=2)
