"""Bounded cross-port distribution evidence; never a device/IP block list."""
from collections import Counter, deque
import ipaddress
import json
import math
import os
import re
import tempfile

from .scoring import KIB, MIB

WINDOW = 1800
BUCKET = 60
MAX_PEERS = 4096
MAX_BUCKETS = 65536
MAX_COHORT_PEERS = 512
MAX_COHORT_BUCKETS = 8192
MAX_FILE_BYTES = 8 * MIB


def peer_key(peer):
    """Conservative receiver diversity, not a claim of physical host identity."""
    address = ipaddress.ip_address(peer)
    return str(ipaddress.ip_network('%s/64' % address, strict=False)) if address.version == 6 else str(address)


class DistributionHistory:
    def __init__(self):
        self.peers, self.progress, self.owners = {}, {}, {}
        self.counters = Counter()
        self.error = ''
        self.last_bucket = None

    def clear(self):
        self.peers.clear()
        self.progress.clear()
        self.owners.clear()
        self.last_bucket = None

    def prune(self, now):
        bucket = math.floor(now / BUCKET) * BUCKET
        if bucket == self.last_bucket:
            return
        self.last_bucket = bucket
        cutoff = bucket - WINDOW + BUCKET
        for key, samples in list(self.peers.items()):
            while samples and samples[0][0] < cutoff:
                samples.popleft()
            if not samples:
                del self.peers[key]
        cohorts = {key[0] for key in self.peers}
        self.owners = {key: value for key, value in self.owners.items() if key in cohorts}
        self.progress = {key: deque((stamp for stamp in stamps if stamp >= cutoff), maxlen=3)
                         for key, stamps in self.progress.items() if key in cohorts}

    def record(self, updates, now, scopes=None):
        """Commit only complete, validated snapshot increments, including downloads."""
        self.prune(now)
        bucket = math.floor(now / BUCKET) * BUCKET
        combined = {}
        for cohort, peer, up, down in updates:
            values = combined.setdefault((cohort, peer), [0, 0])
            values[0] += up
            values[1] += down
        self.error = ''
        grouped = {}
        for key, values in combined.items():
            grouped.setdefault(key[0], {})[key] = values
        keys_by_cohort = {}
        for key in self.peers:
            keys_by_cohort.setdefault(key[0], set()).add(key)
        buckets = sum(len(samples) for samples in self.peers.values())
        # Existing cohorts get their complete counter updates before new ones.
        # On exhaustion discard the affected cohort, never negative-only bytes
        # or every other client's previously verified history.
        for cohort in sorted(grouped, key=lambda value: (value not in keys_by_cohort, value)):
            changes = grouped[cohort]
            keys = keys_by_cohort.get(cohort, set())
            cohort_buckets = sum(len(self.peers[key]) for key in keys)
            extra = sum(key not in self.peers for key in changes)
            extra_buckets = sum(key not in self.peers or self.peers[key][-1][0] != bucket for key in changes)
            if (len(self.peers)+extra > MAX_PEERS or buckets+extra_buckets > MAX_BUCKETS
                    or len(keys)+extra > MAX_COHORT_PEERS or cohort_buckets+extra_buckets > MAX_COHORT_BUCKETS):
                for key in keys:
                    del self.peers[key]
                self.progress.pop(cohort, None)
                self.owners.pop(cohort, None)
                buckets -= cohort_buckets
                self.counters['capacity_resets'] += 1
                self.error = 'distribution history cohort capacity'
                continue
            self.owners[cohort] = (scopes or {}).get(cohort, cohort)
            buckets += extra_buckets
            for key, (up, down) in changes.items():
                samples = self.peers.setdefault(key, deque())
                if not samples or samples[-1][0] != bucket:
                    samples.append([bucket, 0, 0])
                samples[-1][1] += up
                samples[-1][2] += down
                if up:
                    stamps = self.progress.setdefault(cohort, deque(maxlen=3))
                    if not stamps or stamps[-1] != now:
                        stamps.append(now)

    def revoke(self, cohort, peer):
        if self.peers.pop((cohort, peer), None) is not None:
            self.progress.pop(cohort, None)
            if not any(key[0] == cohort for key in self.peers):
                self.owners.pop(cohort, None)
            self.counters['revoked_peers'] += 1

    def revoke_scope(self, scope, peer):
        """Late protection also revokes a retired flow's old classification."""
        keys = {(cohort, peer) for cohort, owner in self.owners.items() if owner == scope}
        for cohort, address in keys:
            self.revoke(cohort, address)
        return keys

    def summaries(self, now):
        self.prune(now)
        result, receivers = {}, {}
        for (cohort, peer), samples in self.peers.items():
            up, down = sum(s[1] for s in samples), sum(s[2] for s in samples)
            row = result.setdefault(cohort, dict(peers=0, upload=0, download=0, serving_peers=0,
                                                serving_upload=0, serving_download=0,
                                                distributed_upload=0, networks=set(), qualified=set()))
            row['peers'] += 1
            row['upload'] += up
            row['download'] += down
            receiver = receivers.setdefault((cohort, peer_key(peer)), dict(upload=0, download=0, qualified=set()))
            receiver['upload'] += up
            receiver['download'] += down
            if up >= 128 * KIB and up >= 4 * max(down, 1):
                receiver['qualified'].add(peer)
        for (cohort, identity), receiver in receivers.items():
            up, down = receiver['upload'], receiver['download']
            row = result[cohort]
            if up >= 128 * KIB and up >= 4 * max(down, 1):
                address = ipaddress.ip_address(identity.split('/')[0])
                row['networks'].add(str(ipaddress.ip_network('%s/%s' % (address, 24 if address.version == 4 else 48), strict=False)))
                row['serving_peers'] += 1
                row['serving_upload'] += up
                row['serving_download'] += down
                row['distributed_upload'] += min(up, 512 * KIB)
                # A qualified IPv6 prefix does not make a previously unseen
                # address eligible for the returning-peer byte discount.
                row['qualified'].update(receiver['qualified'])
        for cohort, row in result.items():
            row['networks'] = len(row['networks'])
            row['active_observations'] = len(self.progress.get(cohort, ()))
            row['ready'] = (row['serving_peers'] >= 4 and row['networks'] >= 3
                            and row['distributed_upload'] >= 2 * MIB
                            and row['active_observations'] >= 3)
        return result

    def status(self, now):
        rows = self.summaries(now)
        return dict(window_seconds=WINDOW, peers=len(self.peers), cohorts=len(rows),
                    qualified_cohorts=sum(row['ready'] for row in rows.values()),
                    min_serving_peers=4, min_networks=3, min_distributed_upload_bytes=2 * MIB,
                    max_peer_contribution_bytes=512 * KIB,
                    max_cohort_peers=MAX_COHORT_PEERS, max_cohort_buckets=MAX_COHORT_BUCKETS,
                    counters=dict(self.counters), error=self.error)

    def save(self, path, now, wall, boot, policy):
        self.prune(now)
        cohorts = {cohort for cohort, _peer in self.peers}
        payload = json.dumps(dict(schema=2, boot=boot, policy=policy, offset=wall-now,
                                  peers=[[cohort, peer, list(samples)] for (cohort, peer), samples in self.peers.items()],
                                  owners={key: value for key, value in self.owners.items() if key in cohorts},
                                  progress={key: list(stamps) for key, stamps in self.progress.items()}),
                             separators=(',', ':'), allow_nan=False).encode()
        if len(payload) > MAX_FILE_BYTES:
            raise ValueError('distribution checkpoint size limit')
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix='.distribution-', dir=os.path.dirname(path))
        try:
            with os.fdopen(fd, 'wb') as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(payload)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def restore(self, path, now, wall, boot, policy):
        with open(path, 'rb') as stream:
            payload = stream.read(MAX_FILE_BYTES + 1)
        if len(payload) > MAX_FILE_BYTES:
            raise ValueError('distribution checkpoint size limit')
        value = json.loads(payload)
        if (not isinstance(value, dict) or value.get('schema') != 2 or not boot
                or value.get('boot') != boot or value.get('policy') != policy):
            return False
        offset = value.get('offset')
        if type(offset) not in (float, int) or not math.isfinite(offset) or abs(offset - (wall-now)) > 5:
            return False
        rows, progress = value.get('peers'), value.get('progress')
        if not isinstance(rows, list) or len(rows) > MAX_PEERS or not isinstance(progress, dict) or len(progress) > MAX_PEERS:
            raise ValueError('invalid distribution checkpoint')
        peers, ticks, count = {}, {}, 0
        cohort_peers, cohort_buckets = Counter(), Counter()
        for item in rows:
            if not isinstance(item, list) or len(item) != 3:
                raise ValueError('invalid distribution peer')
            cohort, peer, samples = item
            address = ipaddress.ip_address(peer)
            if (not isinstance(cohort, str) or not re.fullmatch('[a-f0-9]{24}', cohort)
                    or not address.is_global or address.is_multicast or not isinstance(samples, list)
                    or not 1 <= len(samples) <= WINDOW // BUCKET + 1 or (cohort, peer) in peers):
                raise ValueError('invalid distribution identity')
            prior = -math.inf
            for sample in samples:
                if (not isinstance(sample, list) or len(sample) != 3
                        or any(type(v) is not int or not 0 <= v < 1 << 63 for v in sample)
                        or sample[0] <= prior or sample[0] > now or sample[0] % BUCKET):
                    raise ValueError('invalid distribution sample')
                prior = sample[0]
            count += len(samples)
            cohort_peers[cohort] += 1
            cohort_buckets[cohort] += len(samples)
            if (count > MAX_BUCKETS or cohort_peers[cohort] > MAX_COHORT_PEERS
                    or cohort_buckets[cohort] > MAX_COHORT_BUCKETS):
                raise ValueError('distribution checkpoint bucket limit')
            peers[(cohort, peer)] = deque(samples)
        for key, stamps in progress.items():
            if (not re.fullmatch('[a-f0-9]{24}', key) or not isinstance(stamps, list) or len(stamps) > 3
                    or any(type(v) not in (int, float) or not math.isfinite(v) or not 0 <= v <= now for v in stamps)
                    or stamps != sorted(set(stamps))):
                raise ValueError('invalid distribution progress')
            ticks[key] = deque(stamps, maxlen=3)
        owners = value.get('owners')
        if (not isinstance(owners, dict) or set(owners) != {cohort for cohort, _peer in peers}
                or any(not isinstance(owner, str) or not re.fullmatch('[a-f0-9]{24}', owner) for owner in owners.values())):
            raise ValueError('invalid distribution owners')
        self.peers, self.progress, self.owners = peers, ticks, owners
        self.last_bucket = None
        self.prune(now)
        return True
