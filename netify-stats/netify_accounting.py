"""Independent kernel interface accounting; never mixed into DPI rankings."""
import json
import re
from pathlib import Path
import netify_storage

NET_ROOT = Path('/sys/class/net')


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
        try:
            boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            interfaces = active_interfaces()
            # Keep history but discard inactive baselines: returning to an
            # interface must not include traffic from its unmonitored period.
            for (name,) in self.db.execute('SELECT name FROM interface_baseline').fetchall():
                if name not in interfaces:
                    self.db.execute('DELETE FROM interface_baseline WHERE name=?', (name,))
            if not interfaces:
                self.error = ''
                return
            errors = []
            for name in interfaces:
                if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}', name) or name in ('.', '..'):
                    errors.append('Invalid interface name')
                    continue
                try:
                    base = NET_ROOT / name
                    identity = boot + ':' + (base/'ifindex').read_text().strip()
                    down = int((base/'statistics/rx_bytes').read_text())
                    up = int((base/'statistics/tx_bytes').read_text())
                    self.record(name, identity, down, up, now)
                except (OSError, ValueError) as exc:
                    self.db.execute('DELETE FROM interface_baseline WHERE name=?', (name,))
                    errors.append(name + ': ' + str(exc))
            self.error = '; '.join(errors)
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            self.error = str(exc)
