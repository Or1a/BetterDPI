"""Independent, read-only kernel byte evidence for early distribution signals.

Only Netify-attributed LAN tuples are considered. Initial counters are baselines,
not traffic. Each incarnation uses its kernel ID; neither socket replay nor late
Netify counters enter this ledger. A rolling lookback is not a waiting period.
"""
from collections import Counter, deque
import math
import hashlib
import json
import os
import socket
import time

from . import conntrack
from .config import CONFIG_PATH, domain_matches
from .scoring import KIB, MIB, REVOKING_GUARDS, fast_score
from .history import DistributionHistory, peer_key

POLL_SECONDS = 1
WINDOW = 60
MAX_TRACKED = 2048
MAX_SAMPLES = 65536
MAX_POLL_GAP = 3
EXCLUDED = REVOKING_GUARDS | {'suppressed'}


def metadata_index(rows):
    """Both sampling and execution rechecks reject ambiguous LAN tuples."""
    indexed = {}
    for row in rows:
        identity = conntrack.flow_tuple(row)
        indexed[identity] = None if identity in indexed else row
    return indexed


class FastObserver:
    def __init__(self, settings, reader=conntrack.counter_snapshot, runtime_dir=None,
                 router_macs=(), clock=time.monotonic, wall=time.time):
        self.settings, self.reader = settings, reader
        self.entries, self.rows, self.holds = {}, [], {}
        self.last_poll = None
        self.error = ''
        self.counters = Counter()
        self.sample_count = 0
        self.matched = self.unattributed = 0
        self.history = DistributionHistory()
        self.last_success = None
        self.read_failed = False
        self.failures = Counter()
        self.last_read_ms = self.max_read_ms = 0
        self.clock, self.wall = clock, wall
        self.checkpoint_path = os.path.join(runtime_dir, 'distribution-history.json') if runtime_dir else None
        self.checkpoint_error = ''
        self.last_checkpoint = clock()
        self.restored = False
        try:
            config_stat = os.stat(CONFIG_PATH)
            config_revision = (config_stat.st_ino, config_stat.st_mtime_ns, config_stat.st_size)
        except OSError:
            config_revision = None
        # Any saved configuration change (including disable/re-enable) starts
        # fresh history. A collector restart with unchanged settings may resume.
        self.policy = hashlib.sha256(json.dumps([settings, sorted(router_macs), config_revision],
                                               sort_keys=True).encode()).hexdigest()
        try:
            with open('/proc/sys/kernel/random/boot_id', encoding='ascii') as stream:
                self.boot = stream.read(128).strip()
        except OSError:
            self.boot = ''
        if self.checkpoint_path:
            try:
                self.restored = self.history.restore(self.checkpoint_path, clock(), wall(), self.boot, self.policy)
            except FileNotFoundError:
                pass
            except (OSError, ValueError, TypeError) as exc:
                self.checkpoint_error = str(exc)[:240]

    @staticmethod
    def cohort(row):
        return row.get('cohort') or row['group']

    def revoke_history(self, row):
        cohort = self.cohort(row)
        keys = self.history.revoke_scope(row.get('scope', cohort), row['peer'])
        self.history.revoke(cohort, row['peer'])
        return keys | {(cohort, row['peer'])}

    def checkpoint(self, now, force=False):
        if not self.checkpoint_path or not force and now - self.last_checkpoint < 30:
            return
        self.last_checkpoint = now
        try:
            self.history.save(self.checkpoint_path, now, self.wall(), self.boot, self.policy)
            self.checkpoint_error = ''
        except (OSError, ValueError, TypeError) as exc:
            self.checkpoint_error = str(exc)[:240]

    def reset(self, reason='source_gap'):
        self.entries.clear()
        self.rows = []
        self.sample_count = 0
        self.last_poll = None
        self.last_success = None
        if reason in ('disabled', 'manual_release', 'invalid_clock'):
            self.history.clear()
        self.counters['resets'] += 1
        self.error = str(reason)[:240]

    def poll(self, metadata, now):
        if not self.settings['enabled']:
            self.reset('disabled')
            return
        if not math.isfinite(now):
            self.reset('invalid_clock')
            return
        if self.last_poll is not None and now < self.last_poll:
            self.reset('invalid_clock')
        if self.last_success is not None and now - self.last_success > MAX_POLL_GAP:
            self.reset('counter_poll_gap')
            self.counters['long_gaps'] += 1
        started = self.clock()
        try:
            records = self.reader()
        except (OSError, ValueError, AttributeError) as exc:
            # A failed dump never proposes actions. Keep the last complete
            # cursor briefly: a subsequent full cumulative snapshot can recover
            # ALL directions without losing already validated history.
            code = getattr(exc, 'code', 'read_timeout' if isinstance(exc, (TimeoutError, socket.timeout))
                           else 'unavailable' if isinstance(exc, OSError) else 'invalid_snapshot')
            self.failures[code if code in ('read_timeout', 'decode_timeout', 'unavailable', 'invalid_snapshot') else 'invalid_snapshot'] += 1
            self.counters['read_failures'] += 1
            self.read_failed = True
            self.rows = []
            self.error = str(exc)[:240]
        else:
            try:
                self._update(records, metadata, now)
            except (ValueError, KeyError, TypeError) as exc:
                self.reset(str(exc))
                self.counters['invalid_updates'] += 1
            else:
                if self.read_failed:
                    self.counters['recovered_reads'] += 1
                self.read_failed = False
                self.error = ''
                self.last_success = now
        self.last_read_ms = round(max(0, self.clock() - started) * 1000, 2)
        self.max_read_ms = max(self.max_read_ms, self.last_read_ms)
        self.last_poll = now
        self.checkpoint(now)

    def _update(self, records, metadata, now):
        indexed = metadata_index(metadata)
        revoked, protected_scopes, scopes = set(), set(), {}
        for row in metadata:
            scope = row.get('scope', self.cohort(row))
            scopes[self.cohort(row)] = scope
            if EXCLUDED.intersection(row['guards']):
                protected_scopes.add((scope, row['peer']))
                revoked.update(self.revoke_history(row))
        self.holds = {key: expiry for key, expiry in self.holds.items() if expiry > now}
        touched, matched, updates = set(), 0, []
        historical = self.history.summaries(now)
        for record in records:
            identity = record['tuple']
            row = indexed.get(identity)
            inbound = False
            if identity not in indexed:
                row = indexed.get(record.get('reply'))
                inbound = row is not None
            key = (record['id'], identity)
            if record.get('excluded'):
                old = self.entries.pop(key, None)
                for source in (old['row'] if old else None, row):
                    if source is not None:
                        protected_scopes.add((source.get('scope', self.cohort(source)), source['peer']))
                        revoked.update(self.revoke_history(source))
                self.counters['kernel_exclusions'] += 1
                matched += int(row is not None)
                continue
            if row is None:
                continue
            row = dict(row)
            matched += 1
            if EXCLUDED.intersection(row['guards']) or row['id'] in self.holds:
                old = self.entries.pop(key, None)
                for source in (old['row'] if old else None, row):
                    if source is not None:
                        protected_scopes.add((source.get('scope', self.cohort(source)), source['peer']))
                        revoked.update(self.revoke_history(source))
                continue
            if row.get('closed') and key not in self.entries:
                continue
            # A purge may precede the last kernel sample. Keep BOTH directions
            # through the final counter, but never propose a closed connection.
            if not row.get('closed'):
                touched.add(key)
            current = (record['upload'], record['download'])
            if inbound:
                current = current[::-1]
            if any(type(value) is not int or not 0 <= value < 1 << 63 for value in current):
                raise ValueError('invalid kernel byte counter')
            entry = self.entries.get(key)
            changed_cohort = entry is not None and self.cohort(entry['row']) != self.cohort(row)
            if changed_cohort:
                revoked.add((self.cohort(entry['row']), entry['row']['peer']))
                self.history.revoke(self.cohort(entry['row']), entry['row']['peer'])
            if entry is None or entry['row']['birth'] != row['birth'] or entry['row']['id'] != row['id'] or changed_cohort:
                if entry is None and len(self.entries) >= MAX_TRACKED:
                    raise ValueError('fast connection capacity')
                learned = historical.get(self.cohort(row), {})
                returning = learned.get('ready', False) and row['peer'] in learned.get('qualified', ())
                self.entries[key] = dict(row=row, total=current, samples=deque(), first=now,
                                         last=now, observed=-math.inf, present=True, returning=returning)
                self.counters['baselines'] += 1
                continue
            previous = entry['total']
            entry.update(row=row, total=current, last=now, present=True)
            if any(value < old for value, old in zip(current, previous)):
                # Counter rollback invalidates this incarnation, including
                # earlier positive evidence, rather than inventing a wrap.
                entry['samples'].clear()
                revoked.add((self.cohort(row), row['peer']))
                self.history.revoke(self.cohort(row), row['peer'])
                entry['first'], entry['observed'] = now, -math.inf
                entry['returning'] = False
                self.counters['counter_resets'] += 1
                continue
            up, down = (value - old for value, old in zip(current, previous))
            if up or down:
                entry['samples'].append((now, up, down))
                updates.append((self.cohort(row), row['peer'], up, down))
                if up:
                    entry['observed'] = now
                self.counters['increments'] += 1
        for key, entry in list(self.entries.items()):
            identity = conntrack.flow_tuple(entry['row'])
            row = indexed.get(identity)
            if (identity in indexed and row is None
                    or row is not None and EXCLUDED.intersection(row['guards'])):
                self.history.revoke(self.cohort(entry['row']), entry['row']['peer'])
                revoked.add((self.cohort(entry['row']), entry['row']['peer']))
                del self.entries[key]
                continue
            entry['present'] = key in touched
            while entry['samples'] and entry['samples'][0][0] <= now - WINDOW:
                entry['samples'].popleft()
            if not entry['present'] and now - entry['last'] > WINDOW:
                del self.entries[key]
        self.sample_count = sum(len(entry['samples']) for entry in self.entries.values())
        if self.sample_count > MAX_SAMPLES:
            raise ValueError('fast sample capacity')
        self.history.record([update for update in updates if update[:2] not in revoked
                             and (scopes.get(update[0], update[0]), update[1]) not in protected_scopes], now, scopes)
        self.matched, self.unattributed = matched, len(records) - matched
        self.counters['snapshots'] += 1
        # Candidate evaluation runs once, after pending protection updates have
        # been consumed. Sampling itself does not need to build another score.
        self.rows = []

    def _candidates(self, now):
        groups, rows = {}, []
        history = self.history.summaries(now)
        for key, entry in self.entries.items():
            if not entry['samples']:
                continue
            groups.setdefault(self.cohort(entry['row']), []).append((key, entry))
        for cohort, members in groups.items():
            peers, stamps, own = {}, set(), {}
            upload = download = 0
            for key, entry in members:
                up = sum(sample[1] for sample in entry['samples'])
                down = sum(sample[2] for sample in entry['samples'])
                own[key] = (up, down)
                peer = peers.setdefault(peer_key(entry['row']['peer']), [0, 0])
                peer[0] += up
                peer[1] += down
                upload += up
                download += down
                stamps.update(sample[0] for sample in entry['samples'] if sample[1])
            serving = sum(up >= 128 * KIB and up >= 4 * max(down, 1) for up, down in peers.values())
            metrics = dict(peers=len(peers), serving_peers=serving, upload=upload,
                           download=download, upload_minutes=0, active_observations=len(stamps))
            # This conjunction is mandatory even if the user lowers the score
            # threshold. A single upload, fanout or handshake flood cannot pass.
            burst = serving >= 8 and upload >= 2 * MIB and upload >= 4 * max(download, 1) and len(stamps) >= 3
            learned = history.get(cohort, {})
            if not burst and not learned.get('ready'):
                continue
            for key, entry in members:
                up, down = own[key]
                upload_checks = sum(sample[1] > 0 for sample in entry['samples'])
                returning = entry['returning'] and entry['row']['peer'] in learned.get('qualified', ())
                minimum = 128 * KIB if burst else (32 * KIB if returning else 512 * KIB)
                if (not entry['present'] or entry['observed'] != now or up < minimum
                        or up < 4 * max(down, 1) or not burst and upload_checks < 2):
                    continue
                row = dict(entry['row'])
                hint = domain_matches(row.get('host'), self.settings['pcdn_domains'])
                value, reasons = fast_score(self.settings['weights'], hint, historical=not burst)
                threshold = value >= self.settings['threshold']
                row.update(group=cohort, score=value, device_score=value, reasons=reasons, guards=[],
                           threshold_met=threshold, wait_seconds=0,
                           decision='block' if threshold and self.settings['mode'] == 'auto' else 'observe',
                           last_observed=now, upload=up, download=down, metrics=metrics,
                           evidence_source='conntrack_fast', ct_id=key[0],
                           detection_path='burst' if burst else 'returning_peer' if returning else 'rotating_peers',
                           aggregation='cross_port', required_upload_bytes=minimum,
                           history_metrics={name: learned.get(name, 0) for name in (
                               'peers', 'serving_peers', 'networks', 'upload', 'download', 'serving_upload',
                               'serving_download', 'distributed_upload', 'active_observations')},
                           observed_seconds=round(now - entry['first'], 3),
                           connection_upload_bytes=entry['total'][0],
                           connection_download_bytes=entry['total'][1])
                rows.append(row)
        return sorted(rows, key=lambda row: (-row['score'], -row['upload'], row['id']))

    def candidates(self, now, metadata=None):
        if self.error or self.last_success is None or not 0 <= now - self.last_success <= 1.5:
            return []
        if metadata is not None:
            # A protection/identity update between the kernel poll and this
            # evaluation revokes both its candidate and its group contribution.
            current = {row['id']: row for row in metadata}
            by_tuple = metadata_index(metadata)
            for row in metadata:
                if EXCLUDED.intersection(row['guards']):
                    self.revoke_history(row)
            for key, entry in list(self.entries.items()):
                identity = conntrack.flow_tuple(entry['row'])
                latest = by_tuple.get(identity)
                if (identity in by_tuple and latest is None
                        or latest is not None and EXCLUDED.intersection(latest['guards'])):
                    self.revoke_history(entry['row'])
                    del self.entries[key]
                    continue
                row = current.get(entry['row']['id'])
                if row is None:
                    entry['present'] = False
                elif (conntrack.flow_tuple(row) != identity or row['birth'] != entry['row']['birth']
                      or EXCLUDED.intersection(row['guards'])):
                    self.revoke_history(entry['row'])
                    del self.entries[key]
                elif self.cohort(row) != self.cohort(entry['row']):
                    self.history.revoke(self.cohort(entry['row']), entry['row']['peer'])
                    del self.entries[key]
                else:
                    entry['row'] = row
                    if row.get('closed'):
                        entry['present'] = False
        self.rows = self._candidates(self.last_success)
        return self.rows

    def suppress(self, row, until):
        # Discard blocked-period counters, then baseline immediately at expiry.
        # An extra full-window hold would permit another minute of real uploads
        # even though this independent ledger can prove fresh post-expiry bytes.
        self.holds[row['id']] = until
        # Bound retry holds independently of kernel lease capacity.
        if len(self.holds) > MAX_TRACKED:
            self.holds.pop(next(iter(self.holds)))
        self.entries = {key: entry for key, entry in self.entries.items()
                        if entry['row']['id'] != row['id']}
        self.rows = [entry for entry in self.rows if entry['id'] != row['id']]

    def status(self, now=None):
        now = (self.last_poll or 0) if now is None else now
        return dict(revision=3, poll_seconds=POLL_SECONDS, window_seconds=WINDOW,
                    min_upload_bytes=2 * MIB, min_serving_peers=8,
                    min_peer_upload_bytes=128 * KIB, tracked=len(self.entries),
                    matched=self.matched, unattributed=self.unattributed,
                    samples=self.sample_count, candidates=len(self.rows),
                    error=self.error, counters=dict(self.counters),
                    failure_reasons=dict(self.failures), last_read_ms=self.last_read_ms,
                    max_read_ms=self.max_read_ms, history=self.history.status(now),
                    history_restored=self.restored, checkpoint_error=self.checkpoint_error,
                    evidence_source='conntrack_fast')
