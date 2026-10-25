"""Independent WAN evidence ledger. Never contributes bytes to device totals."""
from collections import OrderedDict
import ipaddress
import hashlib
import time

from netify_classify import PROTOCOL_LOOKUP

CATEGORIES = ('forwarded', 'proxy', 'tunnel', 'router', 'unattributed')
PROXY_PROCESSES = frozenset(('clash', 'mihomo', 'sing-box', 'xray', 'v2ray',
                            'trojan', 'ss-local', 'ss-redir'))
TUNNEL_PROCESSES = frozenset(('tailscaled', 'openvpn', 'charon', 'strongswan'))
METADATA_LIMIT = 1024
CURSOR_LIMIT = 32768
MAX_REPORT_AGE = 2*3600


def create_schema(db):
    db.execute('''CREATE TABLE IF NOT EXISTS wan_hourly (
        bucket INTEGER NOT NULL,interface TEXT NOT NULL,category TEXT NOT NULL,
        evidence TEXT NOT NULL,device TEXT NOT NULL,peer TEXT NOT NULL,protocol TEXT NOT NULL,
        upload INTEGER NOT NULL,download INTEGER NOT NULL,events INTEGER NOT NULL,
        reported_seen INTEGER NOT NULL,
        PRIMARY KEY(bucket,interface,category,evidence,device,peer,protocol)) WITHOUT ROWID''')
    db.execute('''CREATE TABLE IF NOT EXISTS wan_archive (
        interface TEXT NOT NULL,category TEXT NOT NULL,evidence TEXT NOT NULL,
        device TEXT NOT NULL,protocol TEXT NOT NULL,upload INTEGER NOT NULL,
        download INTEGER NOT NULL,events INTEGER NOT NULL,
        first_bucket INTEGER NOT NULL,last_bucket INTEGER NOT NULL,
        PRIMARY KEY(interface,category,evidence,device,protocol)) WITHOUT ROWID''')
    db.execute('CREATE INDEX IF NOT EXISTS wan_archive_oldest ON wan_archive(last_bucket)')


def _counter(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**63-1:
        raise ValueError('Invalid WAN byte counter')
    return value


def _ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ''


class WanAccounting:
    def __init__(self, db, attribution):
        self.db, self.attribution = db, attribution
        self.metadata = OrderedDict()
        self.cursor_count = 0
        self.evicted = {}
        self.last_guard_hour = 0
        self.stats = dict(events=0, duplicates=0, counter_regressions=0,
                          overlapping_events=0, missing_delta_bytes=0,
                          no_cumulative_events=0, metadata_evictions=0,
                          cursor_evictions=0, capacity_omitted_events=0, stale_events=0, clock_events=0, delayed_events=0, max_report_delay_seconds=0, last_event=0)
        # The collector already uses file-backed TEMP and a 256 KiB page cache.
        db.execute('''CREATE TEMP TABLE wan_cursors (
            interface TEXT NOT NULL,digest TEXT NOT NULL,birth INTEGER NOT NULL,
            total INTEGER NOT NULL,updated INTEGER NOT NULL,
            PRIMARY KEY(interface,digest)) WITHOUT ROWID''')
        db.execute('CREATE INDEX temp.wan_cursor_age ON wan_cursors(updated)')

    def evicted_identity(self, interface, digest, now, mark=False):
        # Four hourly Bloom filters have no false negatives for evicted guards
        # within the accepted report window. Expired reports are rejected
        # separately, so memory remains bounded without allowing old replays.
        # False positives omit traffic rather than inflate it.
        hour = max(now//3600, self.last_guard_hour)
        self.last_guard_hour = hour
        for old in tuple(self.evicted):
            if old < hour-3:
                del self.evicted[old]
        raw = hashlib.blake2b((interface+'\0'+digest).encode(),digest_size=12).digest()
        positions = [int.from_bytes(raw[i:i+4],'little') % (8*65536) for i in (0,4,8)]
        seen = any(all(bits[p//8] & (1 << (p%8)) for p in positions) for bits in self.evicted.values())
        if mark:
            if hour not in self.evicted:
                self.evicted[hour] = bytearray(65536)
            bits = self.evicted[hour]
            for position in positions:
                bits[position//8] |= 1 << (position%8)
        return seen

    def update_metadata(self, message):
        self.attribution.want_egress = True
        flow = message.get('flow') or {}
        key = message.get('interface', ''), flow.get('digest')
        if not isinstance(key[1], str) or not key[1] or len(key[1]) > 128:
            return
        # Metadata and JSON snapshots contain no new accounting event.
        kept = {}
        for field in ('local_ip','other_ip','other_type','detected_protocol_name'):
            value = flow.get(field)
            if isinstance(value, str) and len(value) <= 128:
                kept[field] = value
        for field in ('ip_protocol','local_port','other_port','first_seen_at'):
            value = flow.get(field)
            if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 2**63-1:
                kept[field] = value
        old = self.metadata.get(key, {})
        if old.get('first_seen_at') and kept.get('first_seen_at') and kept['first_seen_at'] < old['first_seen_at']:
            return
        if old.get('first_seen_at') == kept.get('first_seen_at'):
            generic = ('', 'unknown', 'unclassified', 'tcp', 'udp')
            if (old.get('detected_protocol_name','').strip().casefold() not in generic
                    and kept.get('detected_protocol_name','').strip().casefold() in generic):
                kept.pop('detected_protocol_name',None)
            old.update(kept)
            kept = old
        self.metadata[key] = kept
        self.metadata.move_to_end(key)
        if len(self.metadata) > METADATA_LIMIT:
            self.metadata.popitem(last=False)
            self.stats['metadata_evictions'] += 1

    def classify(self, metadata):
        if not metadata:
            return 'unattributed', 'missing_metadata', '', '', ''
        peer = _ip(metadata.get('other_ip', ''))
        protocol = metadata.get('detected_protocol_name', '')
        if metadata.get('other_type') != 'remote':
            return 'unattributed', 'direction_unconfirmed', '', peer, protocol
        owner, client = self.attribution.egress_lookup(metadata)
        if PROTOCOL_LOOKUP.get(protocol.strip().casefold()) == 'vpn' or metadata.get('ip_protocol') in (50, 51):
            return 'tunnel', 'observed_vpn_protocol', client[1] if client else '', peer, protocol
        if owner:
            category = 'proxy' if owner in PROXY_PROCESSES else 'tunnel' if owner in TUNNEL_PROCESSES else 'router'
            return category, 'socket:'+owner, '', peer, protocol
        if client:
            return 'forwarded', 'conntrack_lan_tuple', client[1], peer, protocol
        return 'unattributed', 'ownership_unconfirmed', '', peer, protocol

    def add_stats(self, message, now=None):
        self.attribution.want_egress = True
        flow = message.get('flow') or {}
        interface, digest = message.get('interface', ''), flow.get('digest')
        if not isinstance(interface, str) or not interface or len(interface) > 64 or not isinstance(digest, str) or not digest or len(digest) > 128:
            raise ValueError('Invalid WAN event identity')
        upload, download = _counter(flow.get('local_bytes', 0)), _counter(flow.get('other_bytes', 0))
        if upload+download == 0:
            return
        now = int(time.time()) if now is None else now
        metadata = self.metadata.get((interface,digest), {})
        if metadata:
            self.metadata.move_to_end((interface,digest))
        birth = metadata.get('first_seen_at', 0)
        report_seen = flow.get('last_seen_at')
        if not isinstance(report_seen,int) or isinstance(report_seen,bool) or report_seen < 0 or report_seen > (now+5)*1000:
            self.stats['clock_events'] += 1
            return
        if report_seen < (now-MAX_REPORT_AGE)*1000:
            self.stats['stale_events'] += 1
            return
        if birth and isinstance(report_seen, int) and not isinstance(report_seen, bool) and report_seen < birth:
            self.stats['counter_regressions'] += 1
            return
        cumulative = flow.get('total_bytes')
        previous = None
        gap = 0
        if cumulative is not None:
            cumulative = _counter(cumulative)
            if cumulative < upload+download:
                raise ValueError('WAN delta exceeds cumulative bytes')
            previous = self.db.execute('SELECT birth,total FROM temp.wan_cursors WHERE interface=? AND digest=?',
                                       (interface,digest)).fetchone()
            if previous is None and self.evicted_identity(interface,digest,now):
                self.stats['capacity_omitted_events'] += 1
                return
            if previous:
                old_birth, old_total = previous
                if birth and old_birth and birth < old_birth:
                    self.stats['counter_regressions'] += 1
                    return
                new_connection = birth and old_birth and birth > old_birth
                if not new_connection:
                    if cumulative == old_total:
                        self.stats['duplicates'] += 1
                        return
                    if cumulative < old_total:
                        self.stats['counter_regressions'] += 1
                        return
                    delta = cumulative-old_total
                    if delta < upload+download:
                        # Do not guess the direction of an overlapping part.
                        self.stats['overlapping_events'] += 1
                        return
                    gap = delta-upload-download
        else:
            # Unsupported event formats cannot be checked for replay safely.
            # Prefer a visible omission to potentially inflating WAN totals.
            self.stats['no_cumulative_events'] += 1
            return
        category,evidence,device,peer,protocol = self.classify(metadata)
        seen = flow.get('last_seen_at', 0)
        seen = seen//1000 if isinstance(seen,int) and not isinstance(seen,bool) and 0 <= seen <= 2**63-1 else 0
        # Atomically advance the duplicate guard only when the ledger write
        # succeeds. Do not use this table to amend or synthesize LAN counters.
        if not self.db.in_transaction:
            self.db.execute('BEGIN IMMEDIATE')
        self.db.execute('SAVEPOINT wan_delta')
        try:
            self.db.execute('''INSERT INTO wan_hourly VALUES (?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(bucket,interface,category,evidence,device,peer,protocol) DO UPDATE SET
                upload=upload+excluded.upload,download=download+excluded.download,
                events=events+1,reported_seen=MAX(reported_seen,excluded.reported_seen)''',
                (now//3600*3600,interface,category,evidence,device,peer,protocol,upload,download,1,seen))
            if cumulative is not None:
                if previous is None and self.cursor_count >= CURSOR_LIMIT:
                    for old_interface, old_digest in self.db.execute(
                            'SELECT interface,digest FROM temp.wan_cursors ORDER BY updated LIMIT 256'):
                        self.evicted_identity(old_interface,old_digest,now,mark=True)
                    removed = self.db.execute('''DELETE FROM temp.wan_cursors WHERE (interface,digest) IN (
                        SELECT interface,digest FROM temp.wan_cursors ORDER BY updated LIMIT 256)''').rowcount
                    self.cursor_count -= removed
                    self.stats['cursor_evictions'] += removed
                self.db.execute('''INSERT INTO temp.wan_cursors VALUES (?,?,?,?,?)
                    ON CONFLICT(interface,digest) DO UPDATE SET birth=MAX(birth,excluded.birth),
                    total=excluded.total,updated=excluded.updated''', (interface,digest,birth,cumulative,now))
                if previous is None:
                    self.cursor_count += 1
            self.db.execute('RELEASE wan_delta')
        except Exception:
            if self.db.in_transaction:
                self.db.execute('ROLLBACK TO wan_delta')
                self.db.execute('RELEASE wan_delta')
            self.cursor_count = self.db.execute('SELECT COUNT(*) FROM temp.wan_cursors').fetchone()[0]
            raise
        self.stats['missing_delta_bytes'] += gap
        delay = max(0, now-report_seen//1000)
        self.stats['max_report_delay_seconds'] = max(self.stats['max_report_delay_seconds'],delay)
        self.stats['delayed_events'] += int(delay > 30)
        self.stats['events'] += 1
        self.stats['last_event'] = max(self.stats['last_event'], now)
        # Keep bounded metadata through purge so a repeated final event keeps
        # the same incarnation. LRU eviction is reported, never hidden.


def query_wan(db, start, end, now):
    if not db.execute("SELECT 1 FROM sqlite_master WHERE name='wan_hourly'").fetchone():
        return []
    where, args = 'bucket>=?', [start]
    if end is not None:
        where += ' AND bucket<=?'
        args.append(end)
    result = {}
    def add(interface,category,evidence,device,peer,protocol,up,down,events,archived=False):
        item = result.setdefault(interface, dict(name=interface,upload=0,download=0,events=0,
            categories={key:dict(upload=0,download=0) for key in CATEGORIES}, details=[], archived=False,
            direction_unconfirmed_bytes=0))
        item['upload'] += up
        item['download'] += down
        item['events'] += events
        counts = item['categories'][category]
        counts['upload'] += up
        counts['download'] += down
        item['archived'] |= archived
        if evidence in ('missing_metadata','direction_unconfirmed'):
            item['direction_unconfirmed_bytes'] += up+down
        item['details'].append(dict(category=category,evidence=evidence,device=device,peer=peer,
                                   protocol=protocol,upload=up,download=down,archived=archived))
        # Keep only the top 10 evidence samples, not a full Python endpoint map.
        item['details'].sort(key=lambda r:(-r['upload']-r['download'],r['peer'],r['category']))
        del item['details'][10:]
    for row in db.execute('''SELECT interface,category,evidence,device,peer,protocol,
        SUM(upload),SUM(download),SUM(events) FROM wan_hourly WHERE '''+where+
        ' GROUP BY interface,category,evidence,device,peer,protocol', args):
        add(*row)
    if start == 0 and end is None:
        for row in db.execute("SELECT interface,category,evidence,device,'',protocol,upload,download,events FROM wan_archive"):
            add(*row,archived=True)
    for item in result.values():
        # Hourly evidence is useful for locating short bursts; archived history
        # is intentionally excluded because no dates can be reconstructed.
        hours = db.execute('''SELECT w.bucket,w.upload,w.download,k.upload,k.download,w.uncertain FROM (
            SELECT bucket,SUM(upload) upload,SUM(download) download,
                SUM(CASE WHEN evidence IN ('missing_metadata','direction_unconfirmed') THEN upload+download ELSE 0 END) uncertain
            FROM wan_hourly WHERE '''+where+
            ' AND interface=? GROUP BY bucket) w LEFT JOIN interface_hourly k ON k.bucket=w.bucket AND k.name=? '
            'ORDER BY w.bucket DESC LIMIT 168', args+[item['name'],item['name']])
        item['hours'] = []
        for bucket,up,down,kup,kdown,uncertain in hours:
            hour = dict(bucket=bucket,upload=up,download=down)
            if kup is not None and not uncertain:
                hour.update(interface_upload=kup,interface_download=kdown,
                            residual_upload=kup-up,residual_download=kdown-down)
            item['hours'].append(hour)
        item['hours'].reverse()
    return [result[name] for name in sorted(result)]
