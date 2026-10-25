"""Independent kernel interface accounting; never mixed into DPI rankings."""
import json
import re
import socket
import struct
import time
from pathlib import Path
import netify_storage

NET_ROOT = Path('/sys/class/net')
TUNNEL_PREFIX = 'tunnel/'  # '/' is forbidden in real Linux interface names.
TUNNEL_KINDS = frozenset(('wireguard', 'tun', 'gre', 'gretap', 'ip6gre',
                          'ip6gretap', 'ipip', 'sit', 'ip6tnl', 'vti', 'vti6',
                          'xfrm', 'vxlan', 'geneve'))
TUNNEL_DISCOVERY_INTERVAL = 30
TUNNEL_LIMIT = 64


def _attributes(data):
    offset = 0
    while offset + 4 <= len(data):
        length, kind = struct.unpack_from('=HH', data, offset)
        if length < 4 or offset + length > len(data):
            raise ValueError('Invalid link attributes')
        yield kind & 0x3fff, data[offset+4:offset+length]
        offset += (length+3) & ~3


def _tunnel_link(payload):
    if len(payload) < 16:
        raise ValueError('Invalid link information')
    index = struct.unpack_from('=i', payload, 4)[0]
    name = kind = ''
    for attribute, value in _attributes(payload[16:]):
        if attribute == 3:  # IFLA_IFNAME
            name = value.rstrip(b'\0').decode('ascii', errors='replace')
        elif attribute == 18:  # IFLA_LINKINFO
            for nested, data in _attributes(value):
                if nested == 1:  # IFLA_INFO_KIND: kernel type, never a name guess.
                    kind = data.rstrip(b'\0').decode('ascii', errors='strict')
    if kind in TUNNEL_KINDS and index > 0 and re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}', name):
        return name, (kind, index)
    return None


def discover_tunnels():
    """Read kernel link types once per 30 seconds; no subprocess or probing.

    Bound both the dump size and total wait, and reject partial/interrupted
    dumps. Arbitrary tun-like interface names do not prove a tunnel type.
    """
    found = {}
    sequence = 1
    deadline = time.monotonic()+.1
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as client:
        client.settimeout(.1)
        client.bind((0, 0))
        body = struct.pack('=BBHiII', socket.AF_UNSPEC, 0, 0, 0, 0, 0)
        request = struct.pack('=IHHII', 16+len(body), 18, 0x301, sequence, 0)+body
        client.sendto(request, (0, 0))  # RTM_GETLINK / NLM_F_REQUEST|DUMP
        for _ in range(128):
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Tunnel link discovery timed out')
            client.settimeout(remaining)
            data, _, flags, address = client.recvmsg(65536)
            if flags & socket.MSG_TRUNC:
                raise ValueError('Tunnel link discovery was truncated')
            if address[0] != 0:
                continue
            offset = 0
            while offset+16 <= len(data):
                length, kind, flags, seq, _ = struct.unpack_from('=IHHII', data, offset)
                if length < 16 or offset+length > len(data):
                    raise ValueError('Invalid link message')
                payload = data[offset+16:offset+length]
                offset += (length+3) & ~3
                if seq != sequence:
                    continue
                if flags & 0x10:  # NLM_F_DUMP_INTR
                    raise ValueError('Tunnel links changed during discovery')
                if kind == 3:  # NLMSG_DONE
                    if len(payload) >= 4 and struct.unpack_from('=i',payload)[0]:
                        raise OSError('Tunnel link discovery failed')
                    return found
                if kind == 2:  # NLMSG_ERROR
                    raise OSError('Tunnel link discovery failed')
                if kind == 16:  # RTM_NEWLINK
                    link = _tunnel_link(payload)
                    if link:
                        found[link[0]] = link[1]
                        if len(found) > TUNNEL_LIMIT:
                            raise ValueError('Too many tunnel interfaces to meter')
    raise ValueError('Tunnel link discovery did not finish')


def split_interface_history(rows):
    interfaces, tunnels = [], []
    for row in rows:
        if row['name'].startswith(TUNNEL_PREFIX):
            _, kind, name = row['name'].split('/', 2)
            tunnels.append(dict(row, name=name, kind=kind))
        else:
            interfaces.append(row)
    return interfaces, tunnels


def active_interfaces():
    selected = selected_interface()
    return [selected] if selected else []


def interface_choices():
    if not NET_ROOT.exists():
        return []
    return sorted(p.name for p in NET_ROOT.iterdir()
                  if re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}', p.name)
                  and p.name not in ('.', '..'))


def selected_interface():
    try:
        value = json.loads(Path(netify_storage.CONFIG_PATH).read_text()).get('interface', '')
    except FileNotFoundError:
        return ''
    if not isinstance(value, str) or (value and (
            not re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}', value) or value in ('.', '..'))):
        raise ValueError('Invalid interface setting')
    return value


def save_interface(value):
    if not isinstance(value, str) or (value and value not in interface_choices()):
        raise ValueError('Select an interface that exists on this device.')
    netify_storage.update_settings({'interface': value})
    return {'interface': value}


class InterfaceAccounting:
    def __init__(self, db):
        self.db = db
        self.error = ''
        self.tunnel_error = ''
        self.tunnels = {}
        self.last_discovery = float('-inf')
        db.execute('''CREATE TABLE IF NOT EXISTS interface_baseline (
            name TEXT PRIMARY KEY, identity TEXT, download INTEGER, upload INTEGER, sampled INTEGER)''')
        db.execute('''CREATE TABLE IF NOT EXISTS interface_hourly (
            bucket INTEGER, name TEXT, download INTEGER, upload INTEGER,
            since INTEGER, until INTEGER, resets INTEGER DEFAULT 0,
            PRIMARY KEY(bucket,name))''')

    def record(self, name, identity, download, upload, now):
        if min(download, upload) < 0:
            raise ValueError('Negative interface counter')
        previous = self.db.execute('SELECT identity,download,upload,sampled FROM interface_baseline WHERE name=?', (name,)).fetchone()
        if previous:
            reset = identity != previous[0] or download < previous[1] or upload < previous[2]
            # A replaced/reset interface starts a fresh baseline. Do not invent
            # bytes across the missing interval or count a pre-existing lifetime.
            down, up = (0, 0) if reset else (download-previous[1], upload-previous[2])
            self.db.execute('''INSERT INTO interface_hourly VALUES (?,?,?,?,?,?,?)
                ON CONFLICT(bucket,name) DO UPDATE SET download=download+excluded.download,
                upload=upload+excluded.upload, since=MIN(since,excluded.since),
                until=MAX(until,excluded.until), resets=resets+excluded.resets''',
                (now//3600*3600, name, down, up, min(previous[3], now), now, int(reset)))
        self.db.execute('INSERT OR REPLACE INTO interface_baseline VALUES (?,?,?,?,?)',
                        (name, identity, download, upload, now))

    def sample(self, now):
        tunnel_errors = []
        monotonic = time.monotonic()
        if monotonic-self.last_discovery >= TUNNEL_DISCOVERY_INTERVAL:
            self.last_discovery = monotonic
            try:
                self.tunnels = discover_tunnels()
                self.tunnel_error = ''
            except (OSError, ValueError, AttributeError) as exc:
                self.tunnels = {}
                self.tunnel_error = str(exc)
        # Retain discovery errors until a successful rescan, not just one tick.
        discovery_error = self.tunnel_error
        try:
            boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            interfaces = active_interfaces()
            sources = {name: (name, None) for name in interfaces}
            sources.update({TUNNEL_PREFIX+kind+'/'+name: (name, index)
                            for name, (kind, index) in self.tunnels.items()})
            # The same table retains independent meters, never their sum. Keys
            # survive seven-day compaction and pause/resume baseline clearing.
            for (name,) in self.db.execute('SELECT name FROM interface_baseline').fetchall():
                if name not in sources:
                    self.db.execute('DELETE FROM interface_baseline WHERE name=?', (name,))
            errors, readings = [], {}
            for key, (name, expected_index) in sources.items():
                is_tunnel = key.startswith(TUNNEL_PREFIX)
                try:
                    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}', name) or name in ('.', '..'):
                        raise ValueError('Invalid interface name')
                    if name not in readings:
                        base = NET_ROOT / name
                        index = int((base/'ifindex').read_text())
                        down = int((base/'statistics/rx_bytes').read_text())
                        up = int((base/'statistics/tx_bytes').read_text())
                        # Detect recreation during the two counter reads too.
                        if index != int((base/'ifindex').read_text()):
                            raise ValueError('Interface changed while reading counters')
                        readings[name] = index, down, up
                    index, down, up = readings[name]
                    if expected_index is not None and expected_index != index:
                        raise ValueError('Tunnel interface changed; waiting for rediscovery')
                    self.record(key, boot+':'+str(index), down, up, now)
                except (OSError, ValueError) as exc:
                    self.db.execute('DELETE FROM interface_baseline WHERE name=?', (key,))
                    (tunnel_errors if is_tunnel else errors).append(name+': '+str(exc))
            self.error = '; '.join(errors)
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            self.error = str(exc)
        self.tunnel_error = discovery_error
        self.tunnel_sample_error = '; '.join(tunnel_errors)
