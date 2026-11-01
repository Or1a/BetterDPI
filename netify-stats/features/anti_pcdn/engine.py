"""One-point, bounded Netify observer. No database, packet capture or I/O.

Netify's local/other bytes are increments; total_bytes is a cumulative cursor.
Only fresh, contiguous increments enter short windows. Metadata and socket
reconnect snapshots never count as traffic. Loss invalidates action eligibility
for a complete window rather than treating missing traffic as a measured zero.
"""
from collections import Counter, deque
from dataclasses import dataclass, field
import hashlib
import ipaddress
import math
import re
import time

from .config import domain_matches, normalize_domain, validate
from .scoring import KIB, MIB, score

WINDOW = 300
SHORT_WINDOW = 60
BUCKET = 10
MAX_DELAY = 15
MAX_INTERVAL = 60
RETENTION = WINDOW + MAX_INTERVAL
MAX_FLOWS = 2048
MAX_GROUPS = 512
MAX_GROUP_FLOWS = 64
MAX_DEVICE_GROUPS = 32
MAX_SAMPLES = 16384
MAX_IGNORED = 4096
MAX_HOLDS = 512
MAX_COUNTER = (1 << 63) - 1
_MAC = re.compile(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}')
_VPN = frozenset(('wireguard', 'openvpn', 'ipsec', 'ipsecvpn', 'ike', 'isakmp',
                  'esp', 'ah', 'pptp', 'l2tp', 'sstp', 'tailscale', 'zerotier'))
_GENERIC = frozenset(('', 'unknown', 'unclassified', 'tcp', 'udp'))


def _integer(value, minimum=0, maximum=MAX_COUNTER):
    return type(value) is int and minimum <= value <= maximum


def _identifier(parts):
    return hashlib.sha256(repr(parts).encode('utf-8')).hexdigest()[:24]


def _protocol_key(value):
    return re.sub(r'[^a-z0-9]', '', value.casefold())


@dataclass
class _Flow:
    key: tuple
    group: tuple
    birth: int
    mac: str
    ip: str
    peer: str
    sport: int
    dport: int
    proto: int
    protocol: str
    host: str
    created: float
    touched: float
    guards: set = field(default_factory=set)
    total: object = None
    seen: object = None
    last_observed: float = -math.inf
    closed: bool = False
    suppressed_until: float = -math.inf
    valid_after: float = -math.inf
    allow_hint: bool = False
    samples: deque = field(default_factory=deque)


@dataclass
class _Group:
    key: tuple
    since: float
    valid_after: float
    members: set = field(default_factory=set)


class Engine:
    def __init__(self, settings, now=time.monotonic, router_macs=()):
        self.settings = validate(settings)
        self._clock = now if callable(now) else time.monotonic
        started = float(now() if callable(now) else now)
        self._last_now = started
        self._last_sweep = started
        self._offset = None
        self._incomplete_until = started + WINDOW
        self._router_macs = {mac.lower() for mac in router_macs}
        self.flows = {}
        self.tuples = {}
        self.groups = {}
        self.ignored = {}
        self.holds = {}
        self._sample_count = 0
        self.counters = Counter()

    def _tick(self, now):
        if not isinstance(now, (int, float)) or not math.isfinite(now):
            self.counters['invalid_clock'] += 1
            return False
        if now < self._last_now:
            # Monotonic rollback is a different time domain: keep cursors, clear
            # temporal evidence, and require a new full observation window.
            self.counters['clock_gaps'] += 1
            self._incomplete_until = now + WINDOW
            for flow in self.flows.values():
                flow.samples.clear()
                flow.last_observed = -math.inf
                flow.touched = now
                if flow.suppressed_until > self._last_now:
                    flow.suppressed_until = now + flow.suppressed_until - self._last_now
                flow.valid_after = max(now + WINDOW, flow.suppressed_until + WINDOW)
            self._sample_count = 0
            for group in self.groups.values():
                group.since = now
                group.valid_after = now + WINDOW
            self.holds = {key: now + max(0, expiry - self._last_now)
                          for key, expiry in self.holds.items()}
            self._last_sweep = now
            self._offset = None
        self._last_now = now
        if now - self._last_sweep >= BUCKET:
            self._sweep(now)
        return True

    def gap(self, now, reason='source_gap'):
        if self._tick(now):
            self._incomplete_until = max(self._incomplete_until, now + WINDOW)
            self.counters['gaps'] += 1
            # A bounded diagnostic value, never a dynamically growing key.
            self.last_gap = str(reason)[:120]

    def _invalidate(self, group, now, counter):
        self.counters[counter] += 1
        group.valid_after = max(group.valid_after, now + WINDOW)

    def _prune_samples(self, flow, now):
        while flow.samples and flow.samples[0][0] < now - WINDOW - BUCKET:
            flow.samples.popleft()
            self._sample_count -= 1

    def _remove(self, key):
        flow = self.flows.pop(key)
        self._sample_count -= len(flow.samples)
        self.groups[flow.group].members.discard(key)
        identity = self._tuple(flow)
        if self.tuples.get(identity) == key:
            del self.tuples[identity]

    def _sweep(self, now):
        self._last_sweep = now
        for key, flow in list(self.flows.items()):
            self._prune_samples(flow, now)
            if now - flow.touched > RETENTION:
                self._remove(key)
        for key, group in list(self.groups.items()):
            if not group.members and now >= group.valid_after:
                del self.groups[key]
        for key, expiry in list(self.ignored.items()):
            if expiry < now:
                del self.ignored[key]
        for key, expiry in list(self.holds.items()):
            if expiry + WINDOW < now:
                del self.holds[key]

    def _ignore(self, key, now):
        if key in self.flows:
            flow = self.flows[key]
            self._invalidate(self.groups[flow.group], now, 'attribution_changes')
            # Keep its cursor as a tombstone; later metadata of the same birth
            # must not turn previously ignored bytes into a new first report.
            flow.closed = True
        if key in self.ignored or len(self.ignored) < MAX_IGNORED:
            self.ignored[key] = now + RETENTION
        else:
            self.gap(now, 'exclusion_capacity')
            self.counters['capacity_drops'] += 1
        self.counters['ignored_events'] += 1

    def observe(self, message, now=None, wall=None):
        if not self.settings['enabled']:
            return
        now = self._clock() if now is None else now
        wall = time.time() if wall is None else wall
        if not self._tick(now):
            return
        if not isinstance(wall, (int, float)) or not math.isfinite(wall):
            self.gap(now, 'invalid_wall_clock')
            return
        offset = wall - now
        if self._offset is not None and abs(offset - self._offset) > 5:
            self.gap(now, 'wall_clock_jump')
            self.counters['clock_gaps'] += 1
        self._offset = offset
        if not isinstance(message, dict):
            self.counters['invalid_events'] += 1
            return
        kind = message.get('type')
        if kind not in ('flow', 'flow_stats', 'flow_purge'):
            return
        # Both sides of this check are intentional: truthy strings and WAN
        # events may never enter the same device-level behavior ledger.
        if message.get('internal') is not True or message.get('interface') != self.settings['interface']:
            self.counters['ignored_events'] += 1
            return
        raw = message.get('flow')
        if not isinstance(raw, dict):
            self.counters['invalid_events'] += 1
            return
        digest = raw.get('digest')
        if not isinstance(digest, str) or not 1 <= len(digest) <= 128:
            self.counters['invalid_events'] += 1
            return
        key = (message['interface'], digest)
        if kind == 'flow':
            self._metadata(key, raw, now)
        elif key in self.ignored:
            self.ignored[key] = now + RETENTION
            self.counters['ignored_events'] += 1
        elif key not in self.flows:
            self.counters['missing_metadata'] += 1
            self.gap(now, 'missing_metadata')
        else:
            self._stats(self.flows[key], raw, now, wall, kind == 'flow_purge')

    def _metadata(self, key, raw, now):
        mac = raw.get('local_mac')
        birth = raw.get('first_seen_at')
        if (not isinstance(mac, str) or _MAC.fullmatch(mac.lower()) is None
                or mac.lower() == '00:00:00:00:00:00' or int(mac[:2], 16) & 1
                or mac.lower() in self._router_macs or raw.get('other_type') != 'remote'):
            self._ignore(key, now)
            return
        mac = mac.lower()
        try:
            local = ipaddress.ip_address(raw.get('local_ip'))
            remote = ipaddress.ip_address(raw.get('other_ip'))
        except ValueError:
            self._ignore(key, now)
            return
        if (local.version != remote.version or local.is_loopback or local.is_unspecified
                or local.is_multicast or not remote.is_global or remote.is_multicast):
            self._ignore(key, now)
            return
        if (not _integer(birth, 1) or not _integer(raw.get('ip_protocol'))
                or raw.get('ip_protocol') not in (6, 17)
                or not _integer(raw.get('local_port'), 1, 65535)
                or not _integer(raw.get('other_port'), 1, 65535)):
            self.counters['invalid_events'] += 1
            self._ignore(key, now)
            return
        group_key = (key[0], mac, str(local), raw['ip_protocol'], raw['local_port'])
        identity = (mac, str(local), str(remote), raw['local_port'], raw['other_port'], raw['ip_protocol'])
        tuple_key = (key[0],) + identity
        old = self.flows.get(key)
        reused_identity = False
        if old is not None:
            if birth < old.birth:
                self.counters['old_metadata'] += 1
                return
            if birth == old.birth:
                if identity != (old.mac, old.ip, old.peer, old.sport, old.dport, old.proto):
                    old.guards.add('identity_changed')
                    self._invalidate(self.groups[old.group], now, 'attribution_changes')
                    return
                self._enrich(old, raw)
                return
            self._remove(key)
            reused_identity = True
            self.counters['birth_changes'] += 1
        alias = self.flows.get(self.tuples.get(tuple_key))
        if alias is not None:
            if birth <= alias.birth:
                # A different source digest for the same connection must not
                # become a second byte ledger. Older identities are tombstones.
                self._ignore(key, now)
                self.counters['duplicate_identities'] += 1
                return
            alias.closed = True
            self._sample_count -= len(alias.samples)
            alias.samples.clear()
            reused_identity = True
            self.counters['birth_changes'] += 1
        if key in self.ignored:
            del self.ignored[key]
        if len(self.flows) >= MAX_FLOWS:
            self.counters['capacity_drops'] += 1
            if group_key in self.groups:
                self.groups[group_key].valid_after = max(self.groups[group_key].valid_after, now + WINDOW)
            self._ignore(key, now)
            return
        group = self.groups.get(group_key)
        if group is None:
            if (len(self.groups) >= MAX_GROUPS or
                    sum(key_[1] == mac for key_ in self.groups) >= MAX_DEVICE_GROUPS):
                self.counters['capacity_drops'] += 1
                # A known omitted local port cannot contaminate evidence for
                # another port/device. Remember it so its stats are not later
                # mistaken for unattributable source loss.
                self._ignore(key, now)
                return
            group = self.groups[group_key] = _Group(group_key, now, now + WINDOW)
        if len(group.members) >= MAX_GROUP_FLOWS:
            self._invalidate(group, now, 'capacity_drops')
            self._ignore(key, now)
            return
        flow = _Flow(key, group_key, birth, *identity, '', '', now, now)
        flow.suppressed_until = self.holds.get(self._tuple(flow), -math.inf)
        flow.valid_after = flow.suppressed_until + WINDOW
        if reused_identity:
            flow.valid_after = max(flow.valid_after, now + WINDOW)
        self._enrich(flow, raw)
        self.flows[key] = flow
        self.tuples[tuple_key] = key
        group.members.add(key)

    def _enrich(self, flow, raw):
        # DNS association is sufficient to honor an explicit opt-out, never
        # sufficient to add PCDN points or extend a hint to other connections.
        if any(domain_matches(raw.get(name), self.settings['allow_domains'])
               for name in ('host_server_name', 'dns_host_name')):
            flow.allow_hint = True
        protocol = raw.get('detected_protocol_name')
        if isinstance(protocol, str) and len(protocol) <= 128:
            if _protocol_key(flow.protocol) in _GENERIC or _protocol_key(protocol) not in _GENERIC:
                flow.protocol = protocol
            if _protocol_key(protocol) in _VPN:
                flow.guards.add('protected_transport')
        application = raw.get('detected_application_name')
        if isinstance(application, str) and _protocol_key(application) in _VPN:
            flow.guards.add('protected_transport')
        if raw.get('proxy') is True or raw.get('attribution') in ('proxy', 'tunnel', 'redirect'):
            flow.guards.add('unsupported_proxy')
        if raw.get('shared_transport') is True:
            flow.guards.add('shared_transport')
        host = raw.get('host_server_name')
        if isinstance(host, str) and host:
            try:
                host = normalize_domain(host)
            except ValueError:
                return
            if flow.host and flow.host != host:
                flow.guards.add('shared_transport')
            flow.host = host

    def _stats(self, flow, raw, now, wall, closed):
        group = self.groups[flow.group]
        up, down, total, seen = (raw.get(field) for field in
                                 ('local_bytes', 'other_bytes', 'total_bytes', 'last_seen_at'))
        if (not all(_integer(value) for value in (up, down, total, seen))
                or up + down > MAX_COUNTER or seen < flow.birth):
            self._invalidate(group, now, 'invalid_events')
            return
        # Stats may also carry birth. It is an identity guard, never a source
        # from which to reconstruct missing metadata.
        birth = raw.get('first_seen_at', flow.birth)
        if birth != flow.birth:
            self._invalidate(group, now, 'identity_mismatches')
            return
        if flow.total is not None and total == flow.total:
            self.counters['duplicates'] += 1
            if closed and (flow.seen is None or seen >= flow.seen):
                flow.closed = True
            return
        if (flow.closed or (flow.total is not None and total < flow.total)
                or (flow.seen is not None and seen < flow.seen)):
            self._invalidate(group, now, 'regressions')
            return
        previous_total, previous_seen = flow.total, flow.seen
        # Advance even on a rejected increment so it cannot be replayed after
        # a loss, blocked interval, or delay as a fresh first sample.
        flow.total, flow.seen, flow.touched = total, seen, now
        flow.closed = closed
        if ((previous_total is None and total < up + down)
                or (previous_total is not None and total - previous_total != up + down)):
            self._invalidate(group, now, 'counter_gaps')
            return
        age = wall - seen / 1000
        start_seen = flow.birth if previous_seen is None else previous_seen
        interval = (seen - start_seen) / 1000
        if age > MAX_DELAY or age < -5 or interval > MAX_INTERVAL:
            self._invalidate(group, now, 'delayed_events')
            return
        if now < flow.suppressed_until:
            self.counters['suppressed_events'] += 1
            return
        if up + down == 0:
            return
        end = min(now, now - age)
        start = end - interval
        # Do not let an interval crossing the blocked period reintroduce its
        # retries. All its bytes are omitted conservatively.
        if start < flow.suppressed_until:
            self.counters['suppressed_events'] += 1
            return
        if not self._sample(flow, start, end, up, down, now):
            self._invalidate(group, now, 'sample_drops')
            return
        flow.last_observed = now
        self.counters['accepted_events'] += 1

    def _sample(self, flow, start, end, up, down, now):
        self._prune_samples(flow, now)
        # Each report touches at most eight 10-second buckets. Allocation is
        # proportional to the measured interval, not to arrival time; old
        # intervals are rejected above rather than creating artificial bursts.
        start_tick, end_tick = round(start * 1000), round(end * 1000)
        if end_tick <= start_tick:
            pieces = [(math.floor(end / BUCKET) * BUCKET, up, down)]
        else:
            width = BUCKET * 1000
            first = (start_tick // width) * width
            pieces, assigned_up, assigned_down = [], 0, 0
            bucket = first
            while bucket < end_tick:
                elapsed = min(end_tick, bucket + width) - start_tick
                duration = end_tick - start_tick
                # Integer division conserves every byte even above 2**53;
                # floating-point proportions can otherwise round upward.
                next_up, next_down = up * elapsed // duration, down * elapsed // duration
                pieces.append((bucket // 1000, next_up - assigned_up, next_down - assigned_down))
                assigned_up, assigned_down = next_up, next_down
                bucket += width
        existing = {sample[0]: sample for sample in flow.samples}
        required = sum(bucket not in existing for bucket, _, _ in pieces)
        if self._sample_count + required > MAX_SAMPLES:
            return False
        for bucket, upload, download in pieces:
            if bucket in existing:
                existing[bucket][1] += upload
                existing[bucket][2] += download
            else:
                sample = [bucket, upload, download]
                flow.samples.append(sample)
                existing[bucket] = sample
                self._sample_count += 1
        return True

    def _allowlisted(self, flow):
        return (flow.allow_hint or flow.mac in self.settings['allow_devices'] or
                domain_matches(flow.host, self.settings['allow_domains']))

    def _metrics(self, group, now):
        peers, minutes, own = {}, Counter(), {}
        upload = download = 0
        complete_minute = math.floor(now / 60) * 60
        for key in group.members:
            flow = self.flows[key]
            up = down = 0
            eligible = (not flow.guards and not self._allowlisted(flow)
                        and now >= flow.suppressed_until)
            for bucket, sample_up, sample_down in flow.samples:
                # Exclude boundary-straddling buckets instead of overclaiming
                # out-of-window bytes. At most ten seconds are undercounted.
                if bucket >= now - SHORT_WINDOW:
                    up += sample_up
                    down += sample_down
                minute = math.floor(bucket / 60) * 60
                if (eligible and minute >= max(complete_minute - WINDOW, group.since)
                        and minute < complete_minute):
                    minutes[minute] += sample_up
            own[key] = (up, down)
            if eligible and up + down:
                upload += up
                download += down
                peers[flow.peer] = peers.get(flow.peer, 0) + up
        return {'peers': len(peers),
                'serving_peers': sum(value >= 64 * KIB for value in peers.values()),
                'upload': upload, 'download': download,
                'upload_minutes': sum(value >= MIB for value in minutes.values())}, own

    def candidates(self, now=None):
        if not self.settings['enabled']:
            return []
        now = self._clock() if now is None else now
        if not self._tick(now):
            return []
        rows = []
        for group in self.groups.values():
            metrics, own = self._metrics(group, now)
            for key in group.members:
                flow = self.flows[key]
                if flow.closed or not 0 <= now - flow.last_observed <= MAX_DELAY:
                    continue
                up, down = own[key]
                value, reasons = score(metrics,
                                       domain_matches(flow.host, self.settings['pcdn_domains']),
                                       self.settings['weights'])
                guards = set(flow.guards)
                if self._allowlisted(flow):
                    guards.add('allowlisted')
                if now < group.since + WINDOW:
                    guards.add('warming_up')
                if now < max(self._incomplete_until, group.valid_after, flow.valid_after):
                    guards.add('incomplete_window')
                if now < flow.suppressed_until:
                    guards.add('suppressed')
                if up < 64 * KIB or up < 3 * max(down, 1):
                    guards.add('not_uploading')
                threshold_met = value >= self.settings['threshold']
                rows.append({
                    'id': _identifier((flow.key, flow.birth)),
                    'group': _identifier(group.key),
                    'score': value, 'reasons': reasons, 'guards': sorted(guards),
                    'threshold_met': threshold_met,
                    'decision': 'block' if (self.settings['mode'] == 'auto' and threshold_met
                                            and not guards) else 'observe',
                    'mac': flow.mac, 'ip': flow.ip, 'peer': flow.peer,
                    'sport': flow.sport, 'dport': flow.dport, 'proto': flow.proto,
                    'protocol': flow.protocol or ('TCP' if flow.proto == 6 else 'UDP'),
                    'host': flow.host, 'interface': flow.key[0], 'birth': flow.birth,
                    'last_observed': flow.last_observed, 'upload': up, 'download': down,
                    'metrics': dict(metrics),
                })
        return sorted(rows, key=lambda row: (-row['score'], -row['upload'], row['id']))

    def suppress(self, row, until):
        """Remove only the blocked tuple's evidence; retries cannot renew it.

        Other members retain their independently observed traffic. A tuple hold
        survives changes of Netify digest/birth through lease expiry plus the
        fresh-window requirement, so identity churn cannot resurrect retries.
        """
        if not isinstance(row, dict) or not isinstance(until, (int, float)) or not math.isfinite(until):
            return
        for flow in self.flows.values():
            if _identifier((flow.key, flow.birth)) != row.get('id'):
                continue
            flow.suppressed_until = max(flow.suppressed_until, until)
            flow.valid_after = flow.suppressed_until + WINDOW
            self._sample_count -= len(flow.samples)
            flow.samples.clear()
            flow.last_observed = -math.inf
            key = self._tuple(flow)
            if key in self.holds or len(self.holds) < MAX_HOLDS:
                self.holds[key] = flow.suppressed_until
            else:
                self._incomplete_until = max(self._incomplete_until, until + WINDOW)
                self.counters['capacity_drops'] += 1
            self.counters['suppressions'] += 1
            return

    @staticmethod
    def _tuple(flow):
        return (flow.key[0], flow.mac, flow.ip, flow.peer, flow.sport, flow.dport, flow.proto)
