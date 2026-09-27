#!/usr/bin/python3
import json
import os
import signal
import socket
import sqlite3
import time
import glob
import select
import sys
from collections import OrderedDict

sys.path.insert(0, '/usr/lib/netify-stats')
from netify_accounting import InterfaceAccounting
from netify_storage import compact_schema, record_hourly, StoragePolicy
from netify_proxy import RedirectMap


SOCKET_PATH = "/var/run/netifyd/netifyd.sock"
DATA_DIR = "/tmp/netify-stats"
DB_PATH = os.path.join(DATA_DIR, "stats.db")
RUNTIME_DIR = "/var/run/netify-stats"
STATUS_PATH = os.path.join(RUNTIME_DIR, "status.json")
EXPORT_PATH = '/var/run/netifyd/sink-request.json'
PENDING_LIMIT = 4096
PENDING_TTL = 60


class Collector:
    def __init__(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        os.makedirs(RUNTIME_DIR, exist_ok=True)
        self.db = sqlite3.connect(DB_PATH, timeout=30)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("PRAGMA busy_timeout=30000")
        self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS hourly (
                bucket INTEGER NOT NULL,
                mac TEXT NOT NULL,
                ip TEXT NOT NULL,
                application TEXT NOT NULL,
                protocol TEXT NOT NULL,
                host TEXT NOT NULL,
                upload INTEGER NOT NULL DEFAULT 0,
                download INTEGER NOT NULL DEFAULT 0,
                flows INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (bucket, mac, ip, application, protocol, host)
            )
            """
        )
        self.db.commit()
        self.db.execute('CREATE TABLE IF NOT EXISTS device_latest (mac TEXT PRIMARY KEY, ip TEXT, seen INTEGER)')
        self.db.commit()
        self.flows = {}
        self.proxy = RedirectMap()
        self.proxy_upload = 0
        self.proxy_download = 0
        self.accounting = InterfaceAccounting(self.db)
        compact_schema(self.db)
        self.storage = StoragePolicy(self.db, DB_PATH)
        self.excluded = set()
        # Global arrival order handles bounded retention; per-flow indexes let
        # recovery touch only that flow's events, not every other queued event.
        self.pending_stats = OrderedDict()
        self.pending_by_digest = {}
        self.pending_sequence = 0
        self.waiting_metadata = OrderedDict()
        # Short-lived TCP candidates allow a late REDIRECT map to correct
        # counters already recorded for the original leg.
        self.original_candidates = OrderedDict()
        self.missing_metadata = 0
        self.recovered_stats = 0
        self.unattributed_upload = 0
        self.unattributed_download = 0
        self.export_error = ''
        self.export_stamp = None
        self.export_checked = set()
        self.seen = {}
        self.seen_latest = 0
        self.running = True
        self.events = 0
        self.upload = 0
        self.download = 0
        self.connected = False
        self.last_error = ""
        self.last_event = 0
        self.invalid_messages = 0
        self.last_commit = time.monotonic()
        self.local_macs = set()
        for path in glob.glob('/sys/class/net/*/address'):
            try:
                with open(path) as handle:
                    self.local_macs.add(handle.read().strip().lower())
            except OSError:
                pass

    def normalize_metadata(self, message):
        flow = message.get("flow") or {}
        digest = flow.get("digest")
        if not digest:
            return None, None
        if not message.get("internal", False):
            return digest, None
        redirect = self.proxy.lookup(flow)
        if flow.get("other_type") != "remote" and redirect is None:
            return digest, None
        client_side = not redirect or redirect['local_client']
        mac = (flow.get("local_mac" if client_side else "other_mac") or "").lower()
        ip = flow.get("local_ip" if client_side else "other_ip") or ""
        if not mac or mac == "00:00:00:00:00:00":
            return digest, None
        application = flow.get("detected_application_name") or "Unknown"
        protocol = flow.get("detected_protocol_name") or "Unknown"
        host = flow.get("host_server_name") or flow.get("dns_host_name") or (redirect['remote'] if redirect else flow.get("other_ip")) or "Unknown"
        return digest, {
            "mac": mac,
            "ip": ip,
            "application": application,
            "protocol": protocol,
            "host": host.lower(),
            "redirect": redirect,
            # An original TCP leg can precede its conntrack REDIRECT entry.
            # Retain only its tuple so counters can re-check attribution when
            # they arrive; the first export must not permanently classify it.
            "proxy_probe": {key: flow.get(key) for key in (
                'ip_protocol', 'local_ip', 'local_port', 'other_ip', 'other_port')}
                if redirect is None and flow.get('ip_protocol') == 6 else None,
        }

    def update_metadata(self, message):
        if message.get('internal') is False:
            return
        digest, metadata = self.normalize_metadata(message)
        if not digest:
            return
        digest = (message.get('interface', ''), digest)
        if metadata is None or metadata['mac'] in self.local_macs:
            self.flows.pop(digest, None)
            flow = message.get('flow') or {}
            if metadata is None and self.proxy.is_candidate(flow, self.local_macs):
                # Conntrack may not yet be in the cached snapshot. Let the
                # bounded pending queue retry both endpoint orientations. Keep
                # metadata so a newer conntrack snapshot can resolve it even
                # before Netify writes another export.
                self.excluded.discard(digest)
                first_seen = self.waiting_metadata.get(digest, (int(time.time()),))[0]
                kept_flow = {key: flow[key] for key in (
                    'digest', 'ip_protocol', 'local_ip', 'local_port', 'local_mac',
                    'other_ip', 'other_port', 'other_mac', 'other_type',
                    'detected_application_name', 'detected_protocol_name',
                    'host_server_name', 'dns_host_name') if key in flow}
                self.waiting_metadata[digest] = (first_seen, {
                    'interface': digest[0], 'internal': True, 'flow': kept_flow})
                while len(self.waiting_metadata) > PENDING_LIMIT:
                    self.waiting_metadata.popitem(last=False)
                return
            self.waiting_metadata.pop(digest, None)
            self.excluded.add(digest)
            self.replay_pending(digest)
            return
        self.waiting_metadata.pop(digest, None)
        self.excluded.discard(digest)
        old = self.flows.get(digest, {})
        for key, value in metadata.items():
            if value and value != "Unknown":
                old[key] = value
            elif key not in old:
                old[key] = value
        self.flows[digest] = old
        probe = old.get('proxy_probe')
        if probe and all(probe.get(key) is not None for key in (
                'ip_protocol', 'local_ip', 'local_port', 'other_ip', 'other_port')):
            identity = (probe['ip_protocol'], probe['local_ip'],
                        probe['local_port'], probe['other_ip'], probe['other_port'])
            key = (digest[0], identity)
            candidate = self.original_candidates.get(key)
            if candidate is None or candidate['digest'] != digest:
                candidate = {'digest': digest, 'entries': {}, 'last': int(time.time())}
            candidate['last'] = int(time.time())
            self.original_candidates[key] = candidate
            self.original_candidates.move_to_end(key)
            self.expire_original_candidates()
        if old.get('redirect'):
            self.reconcile_original(digest[0], old['redirect']['connection'])
        self.replay_pending(digest)

    def expire_original_candidates(self):
        cutoff = int(time.time()) - PENDING_TTL
        while self.original_candidates:
            key, candidate = next(iter(self.original_candidates.items()))
            if len(self.original_candidates) <= PENDING_LIMIT and candidate['last'] >= cutoff:
                break
            self.original_candidates.popitem(last=False)

    def reconcile_original(self, interface, connection):
        self.expire_original_candidates()
        candidate = self.original_candidates.pop((interface, connection), None)
        if candidate is None:
            return
        original = self.flows.get(candidate['digest'])
        if original:
            # A subsequent socket delta must use the now-known mapping too.
            original['redirect'] = {'role': 'original', 'local_client': True,
                                    'connection': connection}
            original['proxy_probe'] = None
        for row, (upload, flow_inc) in candidate['entries'].items():
            bucket = row[0]
            seen = self.seen.setdefault(bucket, set())
            connection_key = (interface, connection)
            duplicate_flow = flow_inc if connection_key in seen else 0
            seen.add(connection_key)
            if upload or duplicate_flow:
                record_hourly(self.db, (*row, -upload, 0, -duplicate_flow))
                self.upload -= upload

    def pop_pending(self, sequence):
        item = self.pending_stats.pop(sequence)
        key = (item[1].get('interface', ''), item[1]['flow']['digest'])
        sequences = self.pending_by_digest[key]
        sequences.pop(sequence)
        if not sequences:
            del self.pending_by_digest[key]
        return item

    def replay_pending(self, digest):
        # Copy just this flow's index because replay can consume a final purge.
        for sequence in tuple(self.pending_by_digest.get(digest, ())):
            received, pending = self.pop_pending(sequence)
            self.add_stats(pending, received, retry=True)

    def queue_pending(self, message, now, upload, download):
        if len(self.pending_stats) >= PENDING_LIMIT:
            sequence = next(iter(self.pending_stats))
            self.discard_pending(self.pop_pending(sequence))
        key = (message.get('interface', ''), message['flow']['digest'])
        self.pending_sequence += 1
        sequence = self.pending_sequence
        # Socket/export metadata and counters are unrelated to replay. Retain
        # only the delta fields, keeping the queue's memory use predictable.
        pending = {'type': message.get('type'), 'interface': key[0],
                   'internal': True, 'flow': {'digest': key[1],
                   'local_bytes': upload, 'other_bytes': download}}
        self.pending_stats[sequence] = (now, pending)
        self.pending_by_digest.setdefault(key, {})[sequence] = None

    def add_stats(self, message, received_at=None, retry=False):
        flow = message.get("flow") or {}
        if message.get('internal') is False:
            return
        digest = (message.get('interface', ''), flow.get("digest"))
        meta = self.flows.get(digest)
        upload = max(0, int(flow.get("local_bytes") or 0))
        download = max(0, int(flow.get("other_bytes") or 0))
        now = int(time.time()) if received_at is None else received_at
        if digest in self.excluded:
            if message.get('type') == 'flow_purge':
                self.excluded.discard(digest)
            return
        if upload == 0 and download == 0:
            if message.get("type") == "flow_purge":
                if not retry and digest in self.pending_by_digest:
                    # Keep the end marker behind earlier deltas. Recovery must
                    # not leave a completed flow in the active metadata cache.
                    self.queue_pending(message, now, upload, download)
                self.flows.pop(digest, None)
                if retry or digest not in self.pending_by_digest:
                    self.waiting_metadata.pop(digest, None)
            return
        if not meta:
            if not retry:
                self.missing_metadata += 1
                self.queue_pending(message, now, upload, download)
            return
        if meta.get('proxy_probe'):
            late_redirect = self.proxy.lookup(meta['proxy_probe'])
            if late_redirect:
                self.reconcile_original(digest[0], late_redirect['connection'])
                meta['redirect'] = late_redirect
                meta['proxy_probe'] = None
        redirect = meta.get('redirect')
        if redirect:
            # REDIRECT is captured before destination translation on replies
            # and after translation on requests. Use exactly one leg per
            # direction; never add the WAN tunnel or both NAT aliases.
            if not redirect['local_client']:
                upload, download = download, upload
            if redirect['role'] == 'original':
                upload = 0
            else:
                download = 0
            self.proxy_upload += upload
            self.proxy_download += download
        if retry:
            self.recovered_stats += 1
        self.db.execute('''INSERT INTO device_latest VALUES (?,?,?) ON CONFLICT(mac)
            DO UPDATE SET ip=excluded.ip, seen=excluded.seen
            WHERE excluded.seen >= device_latest.seen''', (meta['mac'], meta['ip'], now))
        bucket = now - (now % 3600)
        # Recovery can interleave the previous hour with current events. Keep
        # both sets during the bounded replay window instead of clearing the
        # current set every time an older event arrives.
        self.seen_latest = max(self.seen_latest, now)
        oldest = (self.seen_latest - PENDING_TTL) // 3600 * 3600
        for old_bucket in tuple(self.seen):
            if old_bucket < oldest:
                del self.seen[old_bucket]
        seen = self.seen.setdefault(bucket, set())
        seen_key = (message.get('interface', ''), redirect['connection']) if redirect else digest
        flow_inc = 0 if seen_key in seen else 1
        seen.add(seen_key)
        if not redirect and meta.get('proxy_probe'):
            probe = meta['proxy_probe']
            identity = (probe['ip_protocol'], probe['local_ip'], probe['local_port'],
                        probe['other_ip'], probe['other_port'])
            candidate = self.original_candidates.get((digest[0], identity))
            if candidate and candidate['digest'] == digest:
                candidate['last'] = now
                self.original_candidates.move_to_end((digest[0], identity))
                row = (bucket, meta['mac'], meta['ip'], meta['application'],
                       meta['protocol'], meta['host'])
                previous_upload, previous_flow = candidate['entries'].get(row, (0, 0))
                candidate['entries'][row] = (previous_upload + upload,
                                             previous_flow + flow_inc)
        record_hourly(self.db,
            (
                bucket,
                meta["mac"],
                meta["ip"],
                meta["application"],
                meta["protocol"],
                meta["host"],
                upload,
                download,
                flow_inc,
            ),
        )
        self.events += 1
        self.upload += upload
        self.download += download
        self.last_event = max(self.last_event, now)
        if message.get("type") == "flow_purge":
            self.flows.pop(digest, None)

    def discard_pending(self, item):
        flow = item[1]['flow']
        self.unattributed_upload += max(0, int(flow.get('local_bytes') or 0))
        self.unattributed_download += max(0, int(flow.get('other_bytes') or 0))

    def recover_metadata(self):
        # Read metadata only: export counters overlap socket deltas and MUST NOT be added.
        now = int(time.time())
        # Expire before recovery so an old export cannot resurrect deltas after
        # their replay window. Scan once per maintenance tick, not per flow.
        for sequence, (received, _) in tuple(self.pending_stats.items()):
            if now - received >= PENDING_TTL:
                self.discard_pending(self.pop_pending(sequence))
        for key, (received, message) in tuple(self.waiting_metadata.items()):
            if now - received >= PENDING_TTL:
                self.waiting_metadata.pop(key, None)
            elif key in self.pending_by_digest:
                self.update_metadata(message)
        if not self.pending_stats:
            self.export_error = ''
            self.export_checked.clear()
            return
        try:
            stat = os.stat(EXPORT_PATH)
            stamp = (stat.st_mtime_ns, stat.st_size)
            if stamp != self.export_stamp:
                self.export_checked.clear()
            needed = set(self.pending_by_digest)
            self.export_checked.intersection_update(needed)
            if needed - self.export_checked:
                with open(EXPORT_PATH) as handle:
                    export = json.load(handle)
                for iface, flows in export.get('flows', {}).items():
                    if export.get('interfaces', {}).get(iface, {}).get('role') != 'LAN':
                        continue
                    for flow in flows:
                        if (iface, flow.get('digest')) in needed:
                            self.update_metadata({'interface': iface, 'internal': True, 'flow': flow})
                self.export_checked.update(needed)
                self.export_stamp = stamp
            self.export_error = ''
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            self.export_error = str(exc)

    def write_status(self):
        temp = STATUS_PATH + ".tmp"
        status = {
            "connected": self.connected,
            "events": self.events,
            "invalid_messages": self.invalid_messages,
            "missing_metadata": self.missing_metadata,
            "recovered_stats": self.recovered_stats,
            "pending_stats": len(self.pending_stats),
            "unattributed_upload": self.unattributed_upload,
            "unattributed_download": self.unattributed_download,
            "export_error": self.export_error,
            "interface_error": self.accounting.error,
            "proxy_error": self.proxy.error,
            "proxy_upload": self.proxy_upload,
            "proxy_download": self.proxy_download,
            "storage": self.storage.status(),
            "upload": self.upload,
            "download": self.download,
            "active_metadata": len(self.flows),
            "last_event": self.last_event,
            "last_error": self.last_error,
            "database": DB_PATH,
            "timestamp": int(time.time()),
        }
        with open(temp, "w", encoding="utf-8") as handle:
            json.dump(status, handle, separators=(",", ":"))
        os.replace(temp, STATUS_PATH)

    def maintenance(self):
        now_mono = time.monotonic()
        if now_mono - self.last_commit >= 3:
            self.recover_metadata()
            self.accounting.sample(int(time.time()))
            self.db.commit()
            self.storage.maintain()
            self.write_status()
            self.last_commit = now_mono

    def handle(self, message):
        msg_type = message.get("type")
        if msg_type == "flow":
            self.update_metadata(message)
        elif msg_type in ("flow_stats", "flow_purge"):
            self.add_stats(message)
        self.maintenance()

    def connect_and_read(self):
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(30)
        try:
            client.connect(SOCKET_PATH)
        except Exception:
            client.close()
            raise
        client.settimeout(None)
        self.connected = True
        self.last_error = ""
        self.write_status()
        self.flows.clear()
        self.excluded.clear()
        self.export_stamp = None
        pending = b''
        with client:
            while self.running:
                ready, _, _ = select.select([client], [], [], 1)
                self.maintenance()
                if not ready:
                    continue
                chunk = client.recv(65536)
                if not chunk:
                    break
                pending += chunk
                if len(pending) > 8 * 1024 * 1024:
                    raise ValueError('Netify socket message exceeds 8 MiB')
                lines = pending.split(b'\n')
                pending = lines.pop()
                for line in lines:
                    if not self.running:
                        break
                    self.read_message(line)
        if not self.running:
            return
        raise ConnectionError("Netifyd socket closed")

    def read_message(self, line):
        try:
            message = json.loads(line)
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            return
        if not isinstance(message, dict) or set(message.keys()) == {"length"}:
            return
        flow = message.get('flow')
        if message.get('type') in ('flow', 'flow_stats', 'flow_purge'):
            if not isinstance(message.get('interface', ''), str):
                self.invalid_messages += 1
                return
            if not isinstance(flow, dict) or not isinstance(flow.get('digest'), str):
                self.invalid_messages += 1
                return
            if any(flow.get(key) is not None and not isinstance(flow[key], str)
                   for key in ('local_mac', 'other_mac', 'local_ip', 'detected_application_name', 'detected_protocol_name', 'host_server_name', 'dns_host_name', 'other_ip')):
                self.invalid_messages += 1
                return
        try:
            self.handle(message)
        except (ValueError, TypeError, OverflowError):
            self.invalid_messages += 1

    def run(self):
        self.write_status()
        while self.running:
            try:
                self.connect_and_read()
            except Exception as exc:
                self.connected = False
                self.last_error = str(exc)
                self.db.commit()
                self.write_status()
                if self.running:
                    self.maintenance()
                    time.sleep(2)
        self.db.commit()
        self.connected = False
        self.write_status()
        self.db.close()


if __name__ == "__main__":
    collector = Collector()

    def stop(_signum, _frame):
        collector.running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    collector.run()
