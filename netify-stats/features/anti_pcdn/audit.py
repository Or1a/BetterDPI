"""Bounded local journal for automatic connection decisions and kernel hits."""
from collections import OrderedDict, deque
import json
import os
import secrets


MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_PENDING_BYTES = 64 * 1024
MAX_RECORD_BYTES = 1536
MAX_CONNECTIONS = 512
MAX_PENDING = 256
DEFAULT_DIRECTORY = '/tmp/betterdpi-anti-pcdn'

IDENTITY_FIELDS = ('id', 'ct_id', 'group', 'mac', 'ip', 'peer', 'sport', 'dport', 'proto')
EVIDENCE_FIELDS = ('score', 'upload', 'download', 'connection_upload_bytes', 'observed_seconds',
                   'evidence_source', 'detection_path', 'required_upload_bytes', 'upload_observations',
                   'metrics', 'history_metrics')
COHORT_FIELDS = ('serving_peers', 'peers', 'upload', 'download', 'upload_minutes',
                 'distributed_upload', 'networks', 'active_observations')


class AutoJournal:
    def __init__(self, directory):
        if directory == '/var/run/betterdpi-anti-pcdn':
            directory = DEFAULT_DIRECTORY  # Older collectors can keep their status path.
        self.path = os.path.join(directory, 'auto-actions.jsonl')
        self.session = secrets.token_hex(6)
        self.pending = deque()
        self.pending_bytes = 0
        self.seen = OrderedDict()
        self.written = self.dropped = 0
        self.error = ''

    def record(self, kind, wall, row, **fields):
        if kind == 'deferred' and (self.pending_bytes >= MAX_PENDING_BYTES // 2 or len(self.pending) >= MAX_PENDING // 2):
            self.dropped += 1
            return False
        record = {key: row[key] for key in IDENTITY_FIELDS if key in row}
        record.update(schema=1, session=self.session, timestamp=round(wall, 3), kind=kind, **fields)
        if 'chain' in row:
            record['lease'] = row['chain']
        try:
            line = (json.dumps(record, separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8')
        except (ValueError, TypeError) as exc:
            self.error = str(exc)[:200]
            self.dropped += 1
            return False
        if (len(line) > MAX_RECORD_BYTES or self.pending_bytes + len(line) > MAX_PENDING_BYTES
                or len(self.pending) >= MAX_PENDING):
            self.dropped += 1
            return False
        self.pending.append(line)
        self.pending_bytes += len(line)
        return True

    def decision(self, row, wall, kind, reason, **fields):
        key = row['id'], row.get('ct_id')
        previous = self.seen.get(key)
        state = kind, reason
        if (kind == 'deferred' and not fields.get('lease') and previous and previous[0] == state
                and 0 <= wall - previous[1] < 60):
            return
        evidence = {name: row[name] for name in EVIDENCE_FIELDS if name in row}
        for name in ('metrics', 'history_metrics'):
            if name in evidence:
                values = evidence[name]
                evidence[name] = {key: values[key] for key in COHORT_FIELDS if key in values}
        if self.record(kind, wall, row, reason=reason, **evidence, **fields):
            self.seen[key] = (state, wall)
            self.seen.move_to_end(key)
            if len(self.seen) > MAX_CONNECTIONS:
                self.seen.popitem(last=False)

    def flush(self):
        if not self.pending:
            return
        try:
            os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
            try:
                size = os.stat(self.path, follow_symlinks=False).st_size
            except FileNotFoundError:
                size = 0
            if size + self.pending_bytes > MAX_FILE_BYTES:
                os.replace(self.path, self.path + '.1')
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'ab', buffering=0) as handle:
                os.fchmod(handle.fileno(), 0o600)
                batch = b''.join(self.pending)
                written = handle.write(batch)
                if written != len(batch):
                    os.ftruncate(handle.fileno(), os.fstat(handle.fileno()).st_size - written)
                    raise OSError('short audit write')
            self.written += len(self.pending)
            self.pending.clear()
            self.pending_bytes = 0
            self.error = ''
        except OSError as exc:
            self.error = str(exc)[:200]

    def status(self):
        return dict(path=self.path, session=self.session, written=self.written, dropped=self.dropped,
                    pending=len(self.pending), pending_bytes=self.pending_bytes, error=self.error,
                    max_file_bytes=2 * MAX_FILE_BYTES, max_pending_bytes=MAX_PENDING_BYTES)
