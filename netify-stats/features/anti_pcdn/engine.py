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
from .scoring import KIB, MIB, REVOKING_GUARDS, score
from .history import peer_key

WINDOW = 300
SHORT_WINDOW = 60
BUCKET = 10
MAX_DELAY = 15
MAX_INTERVAL = 60
RETENTION = WINDOW + MAX_INTERVAL
MAX_FLOWS = 2048
MAX_GROUPS = 512
# Every retained identity already shares MAX_FLOWS/MAX_SAMPLES. A separate
# 64-identity veto counted old/closed connections and disabled whole groups
# even when all their observed evidence fit within the global budgets.
MAX_GROUP_FLOWS = MAX_FLOWS
MAX_CLOSED_CURSORS = 4096
MAX_DEVICE_GROUPS = 32
MAX_SAMPLES = 16384
MAX_IGNORED = 4096
MAX_HOLDS = 512
MAX_RECOVERY = 256
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
    next_promotion: float = 0
    recovered: bool = False
    application: str = ''


@dataclass
class _Group:
    key: tuple
    since: float
    valid_after: float
    members: set = field(default_factory=set)
    last_active: float = -math.inf


@dataclass
class _ClosedCursor:
    birth: int
    total: object
    seen: object
    expires: float
    identity: tuple
    group: tuple


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
        self.closed_cursors = {}
        self.closed_tuples = {}
        self.groups = {}
        # All identities keep their cursor; only material upload groups obtain
        # a full scoring window. Browser ports do not consume those slots.
        self.members = {}
        self.missing = {}
        self.ignored = {}
        self.holds = {}
        self._sample_count = 0
        self.counters = Counter()
        self.last_gap = ''
        self.last_gap_at = None
        self.last_gap_scope = ''
        self.device_rows = []
        self.last_candidate_count = 0

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
                flow.next_promotion = now
                if flow.suppressed_until > self._last_now:
                    flow.suppressed_until = now + flow.suppressed_until - self._last_now
                flow.valid_after = max(now + WINDOW, flow.suppressed_until + WINDOW)
            self._sample_count = 0
            self.missing.clear()
            self.closed_cursors.clear()
            self.closed_tuples.clear()
            for group in self.groups.values():
                group.since = now
                group.valid_after = now + WINDOW
                group.last_active = now
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
            self.last_gap_at, self.last_gap_scope = now, 'global'

    def _group_gap(self, key, now, reason):
        expiry = now + WINDOW
        group = self.groups.get(key)
        if group is not None:
            group.valid_after = max(group.valid_after, expiry)
        # Inactive groups cannot authorize actions. Promotion always requires
        # another full window, so their losses need no separate growing cache.
        self.last_gap, self.last_gap_at, self.last_gap_scope = reason, now, 'group'

    def _missing(self, key, raw, now):
        self.counters['missing_metadata'] += 1
        total, seen = raw.get('total_bytes'), raw.get('last_seen_at')
        prior = self.missing.get(key)
        if (prior is not None and _integer(total) and _integer(seen, 1)
                and prior[2:] == (total, seen) and prior[1] == raw.get('first_seen_at')):
            self.counters['duplicate_missing_events'] += 1
            return
        if key in self.missing or len(self.missing) < MAX_RECOVERY:
            if key not in self.missing:
                self.counters['gaps'] += 1
            birth = raw.get('first_seen_at')
            self.missing[key] = (now, birth if _integer(birth, 1) else None,
                                 total if _integer(total) else None,
                                 seen if _integer(seen, 1) else None)
            self.last_gap, self.last_gap_at, self.last_gap_scope = 'missing_metadata', now, 'unresolved'
        else:
            self.counters['recovery_capacity'] += 1
            self.gap(now, 'recovery_capacity')

    def _resolve_missing(self, key, group=None):
        lost = self.missing.pop(key, None)
        if lost is not None:
            self.counters['metadata_resolved'] += 1
            if group is not None:
                self._group_gap(group, lost[0], 'missing_metadata')

    def _invalidate_flow(self, flow, now, counter):
        self.counters[counter] += 1
        flow.valid_after = max(flow.valid_after, now + WINDOW)
        self._group_gap(flow.group, now, counter)

    def _prune_samples(self, flow, now):
        window = WINDOW if flow.group in self.groups else SHORT_WINDOW
        while flow.samples and flow.samples[0][0] < now - window - BUCKET:
            flow.samples.popleft()
            self._sample_count -= 1

    def _remove(self, key):
        flow = self.flows.pop(key)
        self._sample_count -= len(flow.samples)
        members = self.members[flow.group]
        members.discard(key)
        if not members:
            self.members.pop(flow.group)
        identity = self._tuple(flow)
        if self.tuples.get(identity) == key:
            del self.tuples[identity]

    def _archive_incarnation(self, flow):
        # A legitimate new incarnation is not a missing traffic report. Keep
        # the old, already-observed samples until normal expiry so replacing
        # its live digest cannot erase download evidence or restart the group.
        old_key = flow.key
        history_key = old_key[:2] + (flow.birth,)
        del self.flows[old_key]
        flow.key, flow.closed = history_key, True
        self.flows[history_key] = flow
        members = self.members[flow.group]
        members.remove(old_key)
        members.add(history_key)
        identity = self._tuple(flow)
        if self.tuples.get(identity) == old_key:
            self.tuples[identity] = history_key
        self.counters['incarnations_retained'] += 1

    def _drop_closed_cursor(self, key):
        cursor = self.closed_cursors.pop(key)
        if self.closed_tuples.get(cursor.identity) == key:
            del self.closed_tuples[cursor.identity]

    def _retire_closed(self, flow):
        if len(self.closed_cursors) >= MAX_CLOSED_CURSORS:
            self.counters['closed_cursor_capacity'] += 1
            return
        identity = self._tuple(flow)
        self.closed_cursors[flow.key] = _ClosedCursor(
            flow.birth, flow.total, flow.seen, flow.touched + RETENTION, identity, flow.group)
        prior = self.closed_cursors.get(self.closed_tuples.get(identity))
        if prior is None or prior.birth <= flow.birth:
            self.closed_tuples[identity] = flow.key
        self._remove(flow.key)
        self.counters['closed_identities_compacted'] += 1

    def _sweep(self, now):
        self._last_sweep = now
        for key, cursor in list(self.closed_cursors.items()):
            if cursor.expires < now:
                self._drop_closed_cursor(key)
        for key, flow in list(self.flows.items()):
            self._prune_samples(flow, now)
            if now - flow.touched > RETENTION:
                self._remove(key)
            elif flow.closed and not flow.samples:
                # Keep replay protection, but stop a completed empty identity
                # occupying a live observation slot for another five minutes.
                self._retire_closed(flow)
        for key, group in list(self.groups.items()):
            # Keep a full window through brief pauses. Churning the slot after
            # only a short pause discards the very history being measured.
            active_upload = any(not self.flows[member].closed and
                                sum(sample[1] for sample in self.flows[member].samples
                                    if sample[0] >= now - SHORT_WINDOW) >= 64 * KIB
                                for member in group.members)
            if active_upload:
                group.last_active = now
            if not group.members or now - group.last_active > WINDOW:
                del self.groups[key]
                self.counters['groups_reclaimed'] += 1
        for key, request in list(self.missing.items()):
            if request[0] + WINDOW <= now:
                del self.missing[key]
        for key, (expiry, _group) in list(self.ignored.items()):
            if expiry < now:
                del self.ignored[key]
        for key, expiry in list(self.holds.items()):
            if expiry + WINDOW < now:
                del self.holds[key]

    def _ignore(self, key, now, group=None):
        self._resolve_missing(key)
        if key in self.flows:
            flow = self.flows[key]
            self._invalidate_flow(flow, now, 'attribution_changes')
            flow.guards.add('identity_changed')
            # Keep its cursor as a tombstone; later metadata of the same birth
            # must not turn previously ignored bytes into a new first report.
            flow.closed = True
            group = flow.group
        if key in self.ignored or len(self.ignored) < MAX_IGNORED:
            self.ignored[key] = (now + RETENTION, group)
        else:
            self.counters['capacity_drops'] += 1
            self.counters['exclusion_capacity'] += 1
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
        if kind not in ('flow', 'flow_stats', 'flow_purge', 'flow_seed'):
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
        if kind == 'flow_seed':
            self.seed(key, raw, now, wall)
        elif kind == 'flow':
            self._metadata(key, raw, now)
        elif key in self.closed_cursors:
            cursor = self.closed_cursors[key]
            if raw.get('first_seen_at', cursor.birth) != cursor.birth:
                # A new birth without metadata may belong to another group.
                # Recover its attribution rather than trusting the old cursor.
                if not self._irrelevant_delta(raw, wall):
                    self._missing(key, raw, now)
            elif _integer(raw.get('total_bytes')) and raw['total_bytes'] == cursor.total:
                self.counters['duplicates'] += 1
            else:
                self.counters['closed_cursor_conflicts'] += 1
                self._group_gap(cursor.group, now, 'closed_cursor_conflicts')
        elif key not in self.flows and self._irrelevant_delta(raw, wall):
            if kind == 'flow_purge' and key in self.ignored and self.ignored[key][1] is None:
                del self.ignored[key]
                self.counters['excluded_identities_released'] += 1
        elif key in self.ignored:
            _expiry, group = self.ignored[key]
            self.ignored[key] = (now + RETENTION, group)
            if group is not None:
                self._group_gap(group, now, 'omitted_flow')
            self.counters['ignored_events'] += 1
            if kind == 'flow_purge' and group is None:
                del self.ignored[key]
                self.counters['excluded_identities_released'] += 1
        elif key not in self.flows:
            self._missing(key, raw, now)
        else:
            self._stats(self.flows[key], raw, now, wall, kind == 'flow_purge')

    def _irrelevant_delta(self, raw, wall):
        up, down, seen = (raw.get(name) for name in ('local_bytes', 'other_bytes', 'last_seen_at'))
        # Do not resolve an earlier real loss. These messages merely add no
        # new missing evidence and must not keep extending its quarantine.
        if not _integer(up) or not _integer(down):
            return False
        if up + down == 0:
            self.counters['zero_delta_events'] += 1
            return True
        if _integer(seen, 1) and seen < (wall - RETENTION - BUCKET) * 1000:
            self.counters['expired_delta_events'] += 1
            return True
        return False

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
        self._resolve_missing(key, group_key)
        identity = (mac, str(local), str(remote), raw['local_port'], raw['other_port'], raw['ip_protocol'])
        tuple_key = (key[0],) + identity
        closed = self.closed_cursors.get(key)
        if closed is not None:
            if birth <= closed.birth:
                self.counters['closed_metadata'] += 1
                return
            self._drop_closed_cursor(key)
        alias_closed = self.closed_cursors.get(self.closed_tuples.get(tuple_key))
        if alias_closed is not None and birth <= alias_closed.birth:
            self._ignore(key, now)
            self.counters['duplicate_identities'] += 1
            return
        old = self.flows.get(key)
        reused_identity = False
        if old is not None:
            if birth < old.birth:
                self.counters['old_metadata'] += 1
                return
            if birth == old.birth:
                if identity != (old.mac, old.ip, old.peer, old.sport, old.dport, old.proto):
                    old.guards.add('identity_changed')
                    self._invalidate_flow(old, now, 'attribution_changes')
                    return
                self._enrich(old, raw)
                return
            self._archive_incarnation(old)
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
            reused_identity = True
            self.counters['birth_changes'] += 1
        if key in self.ignored:
            del self.ignored[key]
        if len(self.flows) >= MAX_FLOWS:
            self.counters['capacity_drops'] += 1
            self.counters['flow_capacity'] += 1
            self._group_gap(group_key, now, 'flow_capacity')
            self._ignore(key, now, group_key)
            return
        flow = _Flow(key, group_key, birth, *identity, '', '', now, now)
        flow.suppressed_until = self.holds.get(self._tuple(flow), -math.inf)
        flow.valid_after = flow.suppressed_until + WINDOW
        if reused_identity:
            flow.valid_after = max(flow.valid_after, now + WINDOW)
        self._enrich(flow, raw)
        self.flows[key] = flow
        self.tuples[tuple_key] = key
        self.members.setdefault(group_key, set()).add(key)
        group = self.groups.get(group_key)
        if group is not None:
            group.members = self.members[group_key]

    def _activate(self, flow, now):
        group = self.groups.get(flow.group)
        if group is not None or now < flow.next_promotion:
            return group
        if flow.closed or flow.guards or self._allowlisted(flow):
            return None
        upload = sum(sample[1] for sample in flow.samples if sample[0] >= now - SHORT_WINDOW)
        if upload < 64 * KIB:
            return None
        flow.next_promotion = now + BUCKET
        members = self.members[flow.group]
        reason = ('group_capacity' if len(self.groups) >= MAX_GROUPS else
                  'device_group_capacity' if sum(key[1] == flow.mac for key in self.groups) >= MAX_DEVICE_GROUPS else '')
        if reason:
            self.counters['capacity_drops'] += 1
            self.counters[reason] += 1
            self._group_gap(flow.group, now, reason)
            return None
        first = min(self.flows[member].created for member in members)
        group = _Group(flow.group, first, now + WINDOW, members, last_active=now)
        self.groups[flow.group] = group
        self.counters['groups_activated'] += 1
        return group

    def seed(self, key, raw, now, wall):
        """Recover requested identity/baseline only; never replay export bytes."""
        request = self.missing.get(key)
        if request is None:
            return
        birth, total, seen = (raw.get(name) for name in ('first_seen_at', 'total_bytes', 'last_seen_at'))
        if (not _integer(birth, 1) or not _integer(total) or not _integer(seen, birth)
                or seen > (wall + 5) * 1000 or request[1] is not None and request[1] != birth):
            self.counters['recovery_rejected'] += 1
            return
        self._metadata(key, raw, now)
        flow = self.flows.get(key)
        if flow is not None and flow.birth == birth and flow.total is None:
            flow.total, flow.seen, flow.touched = total, seen, now
            flow.valid_after = now + WINDOW
            flow.recovered = True
            self._group_gap(flow.group, now, 'metadata_recovered')
            self.counters['metadata_recovered'] += 1

    def _protect(self, flow, raw):
        # DNS association is sufficient to honor an explicit opt-out, never
        # sufficient to add PCDN points or extend a hint to other connections.
        if any(domain_matches(raw.get(name), self.settings['allow_domains'])
               for name in ('host_server_name', 'dns_host_name')):
            flow.allow_hint = True
        for name in ('detected_protocol_name', 'detected_application_name'):
            value = raw.get(name)
            if isinstance(value, str) and len(value) <= 128 and _protocol_key(value) in _VPN:
                flow.guards.add('protected_transport')
        if raw.get('proxy') is True or raw.get('attribution') in ('proxy', 'tunnel', 'redirect'):
            flow.guards.add('unsupported_proxy')
        if raw.get('shared_transport') is True:
            flow.guards.add('shared_transport')

    def _enrich(self, flow, raw):
        self._protect(flow, raw)
        protocol = raw.get('detected_protocol_name')
        if isinstance(protocol, str) and len(protocol) <= 128:
            if _protocol_key(flow.protocol) in _GENERIC or _protocol_key(protocol) not in _GENERIC:
                flow.protocol = protocol
        application = raw.get('detected_application_name')
        if isinstance(application, str) and len(application) <= 128:
            if _protocol_key(flow.application) in _GENERIC or _protocol_key(application) not in _GENERIC:
                flow.application = application
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
        # Protection may arrive without usable counters. A rejected byte report
        # must not discard a valid opt-out for the same flow incarnation.
        if raw.get('first_seen_at', flow.birth) != flow.birth:
            flow.guards.add('identity_changed')
            self._invalidate_flow(flow, now, 'identity_mismatches')
            return
        self._protect(flow, raw)
        up, down, total, seen = (raw.get(field) for field in
                                 ('local_bytes', 'other_bytes', 'total_bytes', 'last_seen_at'))
        if (not all(_integer(value) for value in (up, down, total, seen))
                or up + down > MAX_COUNTER or seen < flow.birth):
            self._invalidate_flow(flow, now, 'invalid_events')
            return
        # Classification can arrive with stats, even a repeated/zero report.
        # Apply protections only after validating this incarnation's identity.
        self._enrich(flow, raw)
        if flow.total is not None and total == flow.total:
            self.counters['duplicates'] += 1
            if closed and (flow.seen is None or seen >= flow.seen):
                flow.closed = True
            return
        if flow.recovered and flow.total is not None and total < flow.total and seen <= flow.seen:
            self.counters['recovery_overlap'] += 1
            return
        if (flow.closed or (flow.total is not None and total < flow.total)
                or (flow.seen is not None and seen < flow.seen)):
            self._invalidate_flow(flow, now, 'regressions')
            return
        previous_total, previous_seen = flow.total, flow.seen
        # Advance even on a rejected increment so it cannot be replayed after
        # a loss, blocked interval, or delay as a fresh first sample.
        flow.total, flow.seen, flow.touched = total, seen, now
        flow.closed = closed
        if ((previous_total is None and total < up + down)
                or (previous_total is not None and total - previous_total != up + down)):
            self._invalidate_flow(flow, now, 'counter_gaps')
            return
        if up + down == 0:
            self.counters['zero_delta_events'] += 1
            return
        age = wall - seen / 1000
        start_seen = flow.birth if previous_seen is None else previous_seen
        interval = (seen - start_seen) / 1000
        if age > MAX_DELAY or age < -5 or interval > MAX_INTERVAL:
            self._invalidate_flow(flow, now, 'delayed_events')
            return
        if now < flow.suppressed_until:
            self.counters['suppressed_events'] += 1
            return
        end = min(now, now - age)
        start = end - interval
        # Do not let an interval crossing the blocked period reintroduce its
        # retries. All its bytes are omitted conservatively.
        if start < flow.suppressed_until:
            self.counters['suppressed_events'] += 1
            return
        if not self._sample(flow, start, end, up, down, now):
            self._invalidate_flow(flow, now, 'sample_drops')
            return
        flow.last_observed = now
        self._activate(flow, now)
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

    def _metrics(self, group, now, cache=None):
        # Device and port views reuse one pass over each flow's bounded samples.
        # The cache exists only during this evaluation, never on the input path.
        cache = {} if cache is None else cache
        peers, minutes, own = {}, Counter(), {}
        upload = download = 0
        complete_minute = math.floor(now / 60) * 60
        oldest_minute = max(complete_minute - WINDOW, group.since)
        recent = now - SHORT_WINDOW
        for key in group.members:
            flow = self.flows[key]
            if key not in cache:
                up = down = 0
                per_minute = {}
                allowed = self._allowlisted(flow)
                eligible = not flow.guards and not allowed and now >= flow.suppressed_until
                for bucket, sample_up, sample_down in flow.samples:
                    if bucket >= recent:
                        up += sample_up
                        down += sample_down
                    minute = bucket // 60 * 60
                    if eligible and complete_minute - WINDOW <= minute < complete_minute:
                        per_minute[minute] = per_minute.get(minute, 0) + sample_up
                cache[key] = up, down, per_minute, eligible, allowed
            up, down, per_minute, eligible, _allowed = cache[key]
            for minute, sample_up in per_minute.items():
                if minute >= oldest_minute:
                    minutes[minute] += sample_up
            own[key] = (up, down)
            if eligible and up + down:
                upload += up
                download += down
                values = peers.setdefault(peer_key(flow.peer), [0, 0])
                values[0] += up
                values[1] += down
        return {'peers': len(peers),
                'serving_peers': sum(up >= 64 * KIB and up >= 3 * max(down, 1)
                                     for up, down in peers.values()),
                'upload': upload, 'download': download,
                'upload_minutes': sum(value >= MIB for value in minutes.values())}, own

    def _global_until(self):
        return max(self._incomplete_until,
                   max((request[0] + WINDOW for request in self.missing.values()), default=0))

    def coverage(self, now):
        """Bounded, explicit resource/coverage diagnostics; no packet history."""
        return {
            'engine_revision': 5,
            'global_wait_seconds': round(max(0, self._global_until() - now), 1),
            'unresolved_metadata': len(self.missing),
            'last_gap': self.last_gap, 'last_gap_scope': self.last_gap_scope,
            'last_gap_age_seconds': None if self.last_gap_at is None else round(max(0, now - self.last_gap_at), 1),
            'resources': {
                'flow_identities': {'used': len(self.flows), 'limit': MAX_FLOWS},
                'closed_cursors': {'used': len(self.closed_cursors), 'limit': MAX_CLOSED_CURSORS},
                'active_groups': {'used': len(self.groups), 'limit': MAX_GROUPS},
                'samples': {'used': self._sample_count, 'limit': MAX_SAMPLES},
                'ignored_identities': {'used': len(self.ignored), 'limit': MAX_IGNORED},
                'recovery_requests': {'used': len(self.missing), 'limit': MAX_RECOVERY},
            },
            'per_device_group_limit': MAX_DEVICE_GROUPS,
            'group_flow_limit': MAX_GROUP_FLOWS,
            'candidate_count': self.last_candidate_count,
        }

    def candidates(self, now=None):
        if not self.settings['enabled']:
            return []
        now = self._clock() if now is None else now
        if not self._tick(now):
            return []
        rows, cohorts, metrics_cache = [], {}, {}
        global_until = self._global_until()
        for key, flow in self.flows.items():
            cohort = flow.group[:-1]
            cohorts.setdefault(cohort, set()).add(key)
        device_metrics, device_rows = {}, []
        for key, members in cohorts.items():
            first = min(self.flows[member].created for member in members)
            summary, _ = self._metrics(_Group(key, first, first + WINDOW, members), now, metrics_cache)
            value, reasons = score(summary, False, self.settings['weights'])
            wait_until = max(global_until, first + WINDOW,
                             max(self.flows[member].valid_after for member in members),
                             max((self.groups[self.flows[member].group].valid_after
                                  for member in members if self.flows[member].group in self.groups), default=0))
            # Short-only histories cannot substantiate a complete five-minute
            # device view. This view never authorizes a firewall action.
            complete = now >= wait_until and all(
                self.flows[member].group in self.groups for member in members
                if self.flows[member].samples)
            device_metrics[key] = value
            if summary['upload'] or summary['download']:
                device_rows.append({'id': _identifier(key), 'mac': key[1], 'ip': key[2],
                                    'proto': key[3], 'score': value, 'reasons': reasons,
                                    'metrics': summary, 'complete': complete,
                                    'observation_only': True,
                                    'ports': len({self.flows[member].sport for member in members}),
                                    'wait_seconds': round(max(0, wait_until - now), 1)})
        self.device_rows = sorted(device_rows, key=lambda row: (-row['score'], -row['metrics']['upload'], row['id']))[:20]
        for key, members in self.members.items():
            group = self.groups.get(key)
            if group is None:
                first = min(self.flows[member].created for member in members)
                group = _Group(key, first, first + WINDOW, members)
            metrics, own = self._metrics(group, now, metrics_cache)
            group_id = _identifier(group.key)
            base_score, base_reasons = score(metrics, False, self.settings['weights'])
            for member in members:
                flow = self.flows[member]
                if flow.closed or not 0 <= now - flow.last_observed <= MAX_DELAY:
                    continue
                up, down = own[member]
                value, reasons = base_score, base_reasons
                if self.settings['pcdn_domains'] and domain_matches(flow.host, self.settings['pcdn_domains']):
                    value, reasons = score(metrics, True, self.settings['weights'])
                guards = set(flow.guards)
                if metrics_cache[member][4]:
                    guards.add('allowlisted')
                if now < group.since + WINDOW:
                    guards.add('warming_up')
                wait_until = max(global_until, group.valid_after, flow.valid_after)
                if now < wait_until:
                    guards.add('incomplete_window')
                if key not in self.groups:
                    guards.add('short_window_only')
                if now < flow.suppressed_until:
                    guards.add('suppressed')
                if up < 64 * KIB or up < 3 * max(down, 1):
                    guards.add('not_uploading')
                threshold_met = value >= self.settings['threshold']
                rows.append({
                    'id': _identifier((flow.key, flow.birth)),
                    'group': group_id,
                    'score': value, 'reasons': reasons, 'guards': sorted(guards),
                    'device_score': device_metrics.get(key[:-1], 0),
                    'wait_seconds': round(max(0, wait_until - now), 1),
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
        self.last_candidate_count = len(rows)
        return sorted(rows, key=lambda row: (-max(row['score'], row['device_score']), -row['score'], -row['upload'], row['id']))

    def fast_metadata(self, now):
        """Identity/protection only; Netify byte totals never enter fast scoring."""
        rows = []
        for flow in self.flows.values():
            if self.tuples.get(self._tuple(flow)) != flow.key:
                continue
            guards = set(flow.guards)
            if self._allowlisted(flow):
                guards.add('allowlisted')
            if now < flow.suppressed_until:
                guards.add('suppressed')
            # Ports identify actions, not behavior cohorts. Keep independently
            # identified applications/hosts apart to avoid lending a P2P score
            # to an unrelated upload by the same client. Unclassified traffic
            # still needs all independent distribution and current-flow gates.
            application = _protocol_key(flow.application)
            label = (('application', application) if application not in _GENERIC else
                     ('host', flow.host) if flow.host else ('protocol', _protocol_key(flow.protocol)))
            cohort = _identifier((flow.key[0], flow.mac, flow.proto, label))
            rows.append(dict(id=_identifier((flow.key, flow.birth)), group=_identifier(flow.group),
                             cohort=cohort, application=flow.application,
                             scope=_identifier((flow.key[0], flow.mac, flow.proto)),
                             interface=flow.key[0], mac=flow.mac, ip=flow.ip, peer=flow.peer,
                             sport=flow.sport, dport=flow.dport, proto=flow.proto,
                             protocol=flow.protocol or ('TCP' if flow.proto == 6 else 'UDP'),
                             host=flow.host, birth=flow.birth, guards=sorted(guards), closed=flow.closed))
        return rows

    def protection_update(self, key):
        """O(1) lookup after consuming a report, including malformed counters."""
        flow = self.flows.get(key)
        if flow is None:
            return None
        guards = set(flow.guards) & REVOKING_GUARDS
        if self._allowlisted(flow):
            guards.add('allowlisted')
        if not guards:
            return None
        return dict(id=_identifier((flow.key, flow.birth)), guards=sorted(guards),
                    interface=flow.key[0], mac=flow.mac, ip=flow.ip, peer=flow.peer,
                    sport=flow.sport, dport=flow.dport, proto=flow.proto)

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
