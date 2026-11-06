"""Local, bounded shadow decisions. No firewall, socket or traffic-writer calls."""
from collections import OrderedDict, deque
import json
import os

from .scoring import FANOUT_WATCH_PEERS, SCORING_REVISION, PROTECTED_GUARDS

MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_RECORD_BYTES = 4096
MAX_RECENT = 20
MAX_GROUPS = 512
MAX_PER_EVALUATION = 8
MAX_PENDING = 512
REPEAT_SECONDS = 300
CHANGE_SECONDS = 30


class ObservationJournal:
    def __init__(self, directory):
        self.path = os.path.join(directory, 'observations.jsonl')
        self.recent = deque(maxlen=MAX_RECENT)
        self.seen = OrderedDict()
        self.pending = OrderedDict()
        self.error = ''
        self.written = 0
        self.protected = 0
        self.deferred = 0
        self.dropped = 0
        self.last_now = None

    def _append(self, record):
        payload = (json.dumps(record, separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8')
        if len(payload) > MAX_RECORD_BYTES:
            raise ValueError('Observation record exceeds the size limit.')
        os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
        try:
            size = os.stat(self.path).st_size
        except FileNotFoundError:
            size = 0
        if size + len(payload) > MAX_FILE_BYTES:
            os.replace(self.path, self.path + '.1')
        descriptor = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(descriptor, 'ab') as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(payload)

    def record(self, rows, settings, now, wall, coverage):
        """Fast proposals per connection; other samples per behavior group.

        A would_block entry is a scoring proposal, not a claim that kernel
        enforcement was checked. Protected/allowed transports never become
        proposals. Below-threshold uploads and high-fanout-only observations
        remain useful labelled examples, with their guards preserved.
        """
        if self.last_now is not None and now < self.last_now:
            self.seen.clear()
        self.last_now = now
        self.protected = sum(bool(PROTECTED_GUARDS.intersection(row.get('guards', ()))) for row in rows)
        groups = set()
        def material(row):
            minimum = 32 * 1024 if row.get('evidence_source') == 'conntrack_fast' and row.get('detection_path') == 'returning_peer' else 64 * 1024
            return row.get('upload', 0) >= minimum and 'not_uploading' not in row.get('guards', ())

        def priority(row):
            # A download-heavy/watch-only or locally incomplete member must
            # not hide another member's valid proposal in the same group.
            if not material(row):
                return 3
            if row['score'] >= settings['threshold']:
                return 1 if row.get('guards') else 0
            return 2

        for row in sorted(rows, key=priority):
            guards = list(row.get('guards', []))
            if PROTECTED_GUARDS.intersection(guards):
                continue
            uploading = material(row)
            if not uploading and row.get('metrics', {}).get('peers', 0) < FANOUT_WATCH_PEERS:
                continue
            if not uploading and 'not_uploading' not in guards:
                guards.append('not_uploading')
            threshold_met = row['score'] >= settings['threshold']
            connection_proposal = (row.get('evidence_source') == 'conntrack_fast'
                                   and uploading and threshold_met and not guards)
            # A representative group sample can hide a short-lived connection
            # that already qualified. Record each actionable fast identity;
            # retain the global write/cache/file limits and repeat debounce.
            key = ((row.get('group'), row['id'], row.get('ct_id')) if connection_proposal
                   else row.get('group') or row['id'])
            if key in groups:
                continue
            groups.add(key)
            outcome = ('below_threshold' if not threshold_met else
                       'evidence_incomplete' if guards else 'would_block')
            signature = (outcome, row['score'], tuple(sorted(guards)), settings['threshold'],
                         tuple(sorted(settings['weights'].items())), row.get('detection_path'))
            previous = self.seen.get(key)
            if previous is not None:
                stamp, prior = previous
                # Never debounce a change in eligibility: a valid proposal can
                # last just one evaluation before a source gap invalidates it.
                # Rate-limit only repeated decisions and their feature updates.
                if outcome == prior[0] and now - stamp < (
                        REPEAT_SECONDS if signature == prior else CHANGE_SECONDS):
                    continue
            event = (key, signature)
            if event in self.pending:
                continue
            if len(self.pending) >= MAX_PENDING:
                self.dropped += 1
                continue
            record = {field: row[field] for field in (
                'id', 'group', 'mac', 'ip', 'peer', 'sport', 'dport', 'proto',
                'protocol', 'host', 'interface', 'score', 'device_score', 'reasons',
                'guards', 'wait_seconds', 'upload', 'download', 'metrics',
                'evidence_source', 'observed_seconds', 'connection_upload_bytes',
                'connection_download_bytes', 'detection_path', 'aggregation',
                'history_metrics', 'required_upload_bytes') if field in row}
            record.update(schema=1, timestamp=wall, mode='observe', outcome=outcome,
                          sample_scope='connection' if connection_proposal else 'group',
                          engine_revision=coverage.get('engine_revision', 1),
                          score_revision=SCORING_REVISION,
                          sample_type='upload' if uploading else 'fanout_watch', guards=sorted(guards),
                          executed=False, enforcement_checked=False,
                          threshold=settings['threshold'], weights=dict(settings['weights']),
                          proposed_ban_seconds=settings['ban_seconds'],
                          coverage={name: coverage[name] for name in (
                              'global_wait_seconds', 'unresolved_metadata', 'last_gap',
                              'last_gap_scope', 'resources', 'execution_readiness') if name in coverage})
            try:
                payload = json.dumps(record, separators=(',', ':'), allow_nan=False)
                if len(payload.encode('utf-8')) + 1 > MAX_RECORD_BYTES:
                    raise ValueError('Observation record exceeds the size limit.')
                # Detach nested metrics: throttling must preserve the original
                # decision/time even when that short-lived flow has ended.
                self.pending[event] = json.loads(payload)
            except (ValueError, TypeError) as exc:
                self.error = str(exc)[:256]
                self.dropped += 1
                continue
            self.seen[key] = (now, signature)
            self.seen.move_to_end(key)
            if len(self.seen) > MAX_GROUPS:
                self.seen.popitem(last=False)
        self.deferred += max(0, len(self.pending) - MAX_PER_EVALUATION)
        self.flush()

    def flush(self):
        for event, record in list(self.pending.items())[:MAX_PER_EVALUATION]:
            try:
                self._append(record)
            except (OSError, ValueError, TypeError) as exc:
                # Keep the bounded queue for retry; never claim a failed write
                # succeeded or require the original connection to stay alive.
                self.error = str(exc)[:256]
                return
            self.error = ''
            self.pending.pop(event)
            self.recent.append(record)
            self.written += 1

    def status(self):
        return dict(recent=list(self.recent), written=self.written,
                    score_revision=SCORING_REVISION,
                    protected_connections=self.protected, deferred=self.deferred,
                    pending=len(self.pending), dropped=self.dropped, max_pending=MAX_PENDING,
                    error=self.error, max_bytes=2 * MAX_FILE_BYTES,
                    path=self.path, reboot_persistent=False)
