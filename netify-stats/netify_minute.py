"""Bounded device-minute projection of already-accounted LAN byte deltas.

This is a short-lived chart index, never another source of traffic totals. No
application/domain dimensions or second capture are retained here.
"""
from collections import Counter
import sqlite3
import time

RETENTION_MINUTES = 120
MAX_ROWS = 32768
MAX_PENDING = 2048
MAX_COUNTER = (1 << 63) - 1
HEARTBEAT_GAP = 15


class MinuteSeries:
    def __init__(self, db):
        self.db = db
        self.pending = {}
        self.coverage = {}
        self.counters = Counter()
        self.error = ''
        self.sequence = 0
        self.marker = None
        self.previous = None
        self.cutoff = None
        self.last_prune = None
        db.execute('''CREATE TABLE IF NOT EXISTS device_minutes (
            bucket INTEGER NOT NULL,
            device_id INTEGER NOT NULL REFERENCES traffic_devices(id) ON DELETE CASCADE,
            upload INTEGER NOT NULL CHECK(upload>=0),
            download INTEGER NOT NULL CHECK(download>=0),
            PRIMARY KEY(bucket,device_id)) WITHOUT ROWID''')
        db.execute('CREATE INDEX IF NOT EXISTS device_minutes_device ON device_minutes(device_id,bucket)')
        db.execute('''CREATE TABLE IF NOT EXISTS minute_coverage (
            bucket INTEGER PRIMARY KEY, mask INTEGER NOT NULL, fault INTEGER NOT NULL)''')
        # A rollback removes this marker too. In-memory deltas must not survive
        # the transaction that held their corresponding hourly records.
        db.execute('CREATE TEMP TABLE IF NOT EXISTS minute_transaction (id INTEGER PRIMARY KEY, token INTEGER)')

    def _fault(self, bucket):
        if self.cutoff is not None and bucket < self.cutoff:
            return
        mask, _fault = self.coverage.get(bucket, (0, 0))
        self.coverage[bucket] = (mask, 1)

    def note_gap(self, timestamp, reason):
        self._fault(int(timestamp) // 60 * 60)
        self.counters[reason] += 1

    def _buffer(self, timestamp, device_id, upload, download):
        bucket = int(timestamp) // 60 * 60
        if self.cutoff is not None and bucket < self.cutoff:
            return False
        if (type(device_id) is not int or device_id <= 0 or type(upload) is not int
                or type(download) is not int or not -MAX_COUNTER <= upload <= MAX_COUNTER
                or not -MAX_COUNTER <= download <= MAX_COUNTER):
            self.counters['invalid_deltas'] += 1
            self._fault(bucket)
            return False
        if not upload and not download:
            return True
        key = bucket, device_id
        if key not in self.pending and len(self.pending) >= MAX_PENDING:
            self.counters['buffer_drops'] += 1
            self._fault(bucket)
            return False
        if not self.pending:
            self.sequence += 1
            self.marker = self.sequence
            self.db.execute('INSERT OR REPLACE INTO temp.minute_transaction VALUES (1,?)', (self.marker,))
        prior = self.pending.get(key, (0, 0))
        values = prior[0] + upload, prior[1] + download
        if not -MAX_COUNTER <= values[0] <= MAX_COUNTER or not -MAX_COUNTER <= values[1] <= MAX_COUNTER:
            self.counters['invalid_deltas'] += 1
            self._fault(bucket)
            return False
        self.pending[key] = values
        return True

    def add(self, timestamp, device_id, upload, download):
        if upload < 0 or download < 0:
            raise ValueError('Minute observations must be nonnegative')
        return self._buffer(timestamp, device_id, upload, download)

    def correct(self, timestamp, device_id, upload):
        if type(upload) is not int or upload < 0:
            raise ValueError('Minute correction must be nonnegative')
        key = int(timestamp) // 60 * 60, device_id
        if key not in self.pending and len(self.pending) >= MAX_PENDING:
            # Known duplicate bytes must not survive just because new positive
            # samples filled the buffer. Flush the bounded batch in the same
            # transaction before admitting its correction.
            self.flush(max(int(timestamp), max(bucket for bucket, _ in self.pending)))
        return self._buffer(timestamp, device_id, -upload, 0)

    def reset_pending(self, reason='transaction_rollback'):
        for bucket, _device_id in self.pending:
            self._fault(bucket)
        self.counters['discarded_batches'] += bool(self.pending)
        self.pending.clear()
        self.marker = None
        self.error = reason
        self.last_prune = None

    def heartbeat(self, now, connected):
        """Record actually observed seconds, not a fabricated zero-filled gap."""
        now = int(now)
        previous = self.previous
        self.previous = now, bool(connected)
        if previous is None:
            return
        start, was_connected = previous
        if now < start:
            self._fault(now // 60 * 60)
            self.counters['clock_gaps'] += 1
            return
        if not was_connected or not connected:
            return
        if now - start > HEARTBEAT_GAP:
            self._fault(now // 60 * 60)
            self.counters['heartbeat_gaps'] += 1
            return
        while start < now:
            bucket = start // 60 * 60
            until = min(now, bucket + 60)
            mask = ((1 << (until - start)) - 1) << (start - bucket)
            prior, fault = self.coverage.get(bucket, (0, 0))
            self.coverage[bucket] = (prior | mask, fault)
            start = until

    def prune_hours(self, buckets):
        """Mirror removed hourly data before a dictionary ID can be reused."""
        buckets = set(buckets)
        if not buckets:
            return
        for key in tuple(self.pending):
            if key[0] // 3600 * 3600 in buckets:
                self.pending.pop(key)
                self._fault(key[0])
        for bucket in buckets:
            self.db.execute('DELETE FROM device_minutes WHERE bucket>=? AND bucket<?', (bucket, bucket + 3600))
            self.db.execute('UPDATE minute_coverage SET fault=1 WHERE bucket>=? AND bucket<?', (bucket, bucket + 3600))

    def flush(self, now=None):
        """Flush with the collector's current transaction, without committing it."""
        now = int(time.time()) if now is None else int(now)
        current = now // 60 * 60
        self.cutoff = (now // 60 - RETENTION_MINUTES + 1) * 60
        if self.pending:
            row = self.db.execute('SELECT token FROM temp.minute_transaction WHERE id=1').fetchone()
            if row is None or row[0] != self.marker:
                self.reset_pending()
        pending, coverage = self.pending, self.coverage
        # Keep pending ownership explicit: failed flushes never replay a
        # partially applied batch on a later iteration.
        self.pending, self.coverage, self.marker = {}, {}, None
        self.db.execute('SAVEPOINT minute_flush')
        try:
            for (bucket, device_id), (upload, download) in pending.items():
                if not self.cutoff <= bucket <= current:
                    continue
                if upload >= 0 and download >= 0:
                    # A dictionary removed after an unrelated transaction
                    # failure must never be recreated by the projection.
                    self.db.execute('''INSERT INTO device_minutes
                        SELECT ?,id,?,? FROM traffic_devices WHERE id=?
                        ON CONFLICT(bucket,device_id) DO UPDATE SET
                        upload=upload+excluded.upload,download=download+excluded.download''',
                        (bucket, upload, download, device_id))
                else:
                    # Corrections never resurrect pruned rows or subtract
                    # another bucket. An insufficient surviving row is a gap.
                    changed = self.db.execute('''UPDATE device_minutes
                        SET upload=upload+?,download=download+?
                        WHERE bucket=? AND device_id=? AND upload>=? AND download>=?''',
                        (upload, download, bucket, device_id, max(0, -upload), max(0, -download))).rowcount
                    if not changed:
                        mask, _ = coverage.get(bucket, (0, 0))
                        coverage[bucket] = mask, 1
                        self.counters['correction_gaps'] += 1
            self.db.executemany('''INSERT INTO minute_coverage VALUES (?,?,?)
                ON CONFLICT(bucket) DO UPDATE SET mask=mask|excluded.mask,fault=MAX(fault,excluded.fault)''',
                ((bucket, mask, fault) for bucket, (mask, fault) in coverage.items() if self.cutoff <= bucket <= current))
            if current != self.last_prune:
                self.db.execute('DELETE FROM device_minutes WHERE bucket<? OR bucket>?', (self.cutoff, current))
                self.db.execute('DELETE FROM minute_coverage WHERE bucket<? OR bucket>?', (self.cutoff, current))
                self.last_prune = current
            count = self.db.execute('SELECT COUNT(*) FROM device_minutes').fetchone()[0]
            while count > MAX_ROWS:
                oldest = self.db.execute('SELECT MIN(bucket) FROM device_minutes').fetchone()[0]
                removed = self.db.execute('DELETE FROM device_minutes WHERE bucket=?', (oldest,)).rowcount
                self.db.execute('''INSERT INTO minute_coverage VALUES (?,0,1)
                    ON CONFLICT(bucket) DO UPDATE SET fault=1''', (oldest,))
                count -= removed
                self.counters['pruned_rows'] += removed
            self.db.execute('RELEASE minute_flush')
        except Exception:
            if self.db.in_transaction:
                self.db.execute('ROLLBACK TO minute_flush')
                self.db.execute('RELEASE minute_flush')
            for bucket, _device_id in pending:
                self._fault(bucket)
            self.counters['discarded_batches'] += bool(pending)
            self.error = 'minute_flush_failed'
            raise


def query_series(db, start, end, device=''):
    """Read at most two hours. Missing collection is distinct from zero bytes."""
    end = int(end)
    last = end // 60 * 60
    start = max(0, int(start) // 60 * 60, last - (RETENTION_MINUTES - 1) * 60)
    result = {'available': False, 'timeline': [], 'resolution_seconds': 60,
              'range_start': start, 'range_end': end}
    tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE name IN ('device_minutes','minute_coverage')")}
    if tables != {'device_minutes', 'minute_coverage'}:
        return result
    result['available'] = True
    where, args = 'bucket>=? AND bucket<=?', [start, last]
    if device:
        where += ' AND device_id IN (SELECT id FROM traffic_devices WHERE mac=? OR ip=?)'
        args.extend((device, device))
    totals = {bucket: (upload, download) for bucket, upload, download in db.execute(
        'SELECT bucket,SUM(upload),SUM(download) FROM device_minutes WHERE ' + where + ' GROUP BY bucket', args)}
    coverage = {bucket: (mask, fault) for bucket, mask, fault in db.execute(
        'SELECT bucket,mask,fault FROM minute_coverage WHERE bucket>=? AND bucket<=?', (start, last))}
    for bucket in range(start, last + 1, 60):
        mask, fault = coverage.get(bucket, (0, 0))
        expected_seconds = min(60, max(0, end - bucket))
        expected = (1 << expected_seconds) - 1
        has_bytes = bucket in totals
        if not has_bytes and (not mask or fault):
            state, upload, download = 'missing', None, None
        else:
            state = 'complete' if expected and mask & expected == expected and not fault else 'partial'
            upload, download = totals.get(bucket, (0, 0))
        result['timeline'].append({'bucket': bucket, 'upload': upload, 'download': download,
                                   'coverage': state, 'covered': state != 'missing'})
    return result
