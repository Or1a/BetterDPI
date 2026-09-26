"""Compact SQLite schema and user-controlled, oldest-hour-first retention."""
import json
import os
import sqlite3
import time
import tempfile
import fcntl

CONFIG_PATH = '/etc/netify-stats.json'
MIB = 1024*1024


def read_limit():
    try:
        with open(CONFIG_PATH) as handle:
            value = json.load(handle).get('max_storage_mib', 0)
        return validate_limit(value)
    except FileNotFoundError:
        return 0


def validate_limit(value):
    if isinstance(value, bool) or not isinstance(value, int) or not (value == 0 or 4 <= value <= 4096):
        raise ValueError('Capacity must be 0 (unlimited) or an integer from 4 to 4096 MiB')
    return value


def save_limit(value):
    value = validate_limit(value)
    update_settings({'max_storage_mib':value})
    return {'max_storage_mib':value}


def read_enabled():
    try:
        with open(CONFIG_PATH) as handle:
            value = json.load(handle).get('enabled', True)
        if not isinstance(value, bool):
            raise ValueError('Invalid enabled setting')
        return value
    except FileNotFoundError:
        return True


def update_settings(changes, deadline=None):
    deadline = time.monotonic()+5 if deadline is None else deadline
    with open(CONFIG_PATH+'.lock', 'a') as lock:
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError('Settings are being saved. Please try again.')
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                time.sleep(min(.05, max(0, deadline-time.monotonic())))
        try:
            with open(CONFIG_PATH) as handle:
                values = json.load(handle)
        except FileNotFoundError:
            values = {}
        values.update(changes)
        _save_settings(values)


def _save_settings(values):
    descriptor, temporary = tempfile.mkstemp(prefix='.netify-stats-', dir=os.path.dirname(CONFIG_PATH))
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
            json.dump(values, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, CONFIG_PATH)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def footprint(path):
    sizes = {}
    for name, suffix in (('database_bytes',''),('wal_bytes','-wal'),('shm_bytes','-shm')):
        try:
            sizes[name] = os.path.getsize(path+suffix)
        except FileNotFoundError:
            sizes[name] = 0
    sizes['used_bytes'] = sum(sizes.values())
    return sizes


def settings(path):
    result = footprint(path)
    try:
        result.update(max_storage_mib=read_limit(), error='')
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        result.update(max_storage_mib=0, error=str(exc))
    return result


def compact_schema(db):
    # Low-cardinality dimensions share IDs; host strings remain verbatim.
    # A compatibility view preserves the original nine-column read interface.
    db.commit()
    kind = db.execute("SELECT type FROM sqlite_master WHERE name='hourly'").fetchone()[0]
    changed = kind != 'view'
    if changed:
        with db:
            db.execute('BEGIN IMMEDIATE')
            before = db.execute('SELECT COUNT(*),SUM(upload),SUM(download),SUM(flows) FROM hourly').fetchone()
            db.execute('CREATE TABLE traffic_devices (id INTEGER PRIMARY KEY,mac TEXT NOT NULL,ip TEXT NOT NULL,UNIQUE(mac,ip))')
            db.execute('CREATE TABLE traffic_apps (id INTEGER PRIMARY KEY,value TEXT NOT NULL UNIQUE)')
            db.execute('CREATE TABLE traffic_protocols (id INTEGER PRIMARY KEY,value TEXT NOT NULL UNIQUE)')
            db.execute('''CREATE TABLE hourly_data (
                bucket INTEGER NOT NULL,device_id INTEGER NOT NULL REFERENCES traffic_devices(id),
                app_id INTEGER NOT NULL REFERENCES traffic_apps(id),
                protocol_id INTEGER NOT NULL REFERENCES traffic_protocols(id),host TEXT NOT NULL,
                upload INTEGER NOT NULL,download INTEGER NOT NULL,flows INTEGER NOT NULL,
                PRIMARY KEY(bucket,device_id,app_id,protocol_id,host)) WITHOUT ROWID''')
            db.execute('INSERT INTO traffic_devices(mac,ip) SELECT DISTINCT mac,ip FROM hourly')
            db.execute('INSERT INTO traffic_apps(value) SELECT DISTINCT application FROM hourly')
            db.execute('INSERT INTO traffic_protocols(value) SELECT DISTINCT protocol FROM hourly')
            db.execute('''INSERT INTO hourly_data SELECT h.bucket,d.id,a.id,p.id,h.host,h.upload,h.download,h.flows
                FROM hourly h JOIN traffic_devices d ON h.mac=d.mac AND h.ip=d.ip
                JOIN traffic_apps a ON h.application=a.value JOIN traffic_protocols p ON h.protocol=p.value''')
            after = db.execute('SELECT COUNT(*),SUM(upload),SUM(download),SUM(flows) FROM hourly_data').fetchone()
            if before != after:
                raise sqlite3.IntegrityError('Statistics migration verification failed; original data was preserved.')
            db.execute('DROP TABLE hourly')
            db.execute('''CREATE VIEW hourly AS SELECT h.bucket,d.mac,d.ip,a.value application,
                p.value protocol,h.host,h.upload,h.download,h.flows FROM hourly_data h
                JOIN traffic_devices d ON d.id=h.device_id JOIN traffic_apps a ON a.id=h.app_id
                JOIN traffic_protocols p ON p.id=h.protocol_id''')
            db.execute('''CREATE TRIGGER hourly_insert INSTEAD OF INSERT ON hourly BEGIN
                INSERT OR IGNORE INTO traffic_devices(mac,ip) VALUES (NEW.mac,NEW.ip);
                INSERT OR IGNORE INTO traffic_apps(value) VALUES (NEW.application);
                INSERT OR IGNORE INTO traffic_protocols(value) VALUES (NEW.protocol);
                INSERT INTO hourly_data VALUES (NEW.bucket,
                    (SELECT id FROM traffic_devices WHERE mac=NEW.mac AND ip=NEW.ip),
                    (SELECT id FROM traffic_apps WHERE value=NEW.application),
                    (SELECT id FROM traffic_protocols WHERE value=NEW.protocol),
                    NEW.host,NEW.upload,NEW.download,NEW.flows)
                ON CONFLICT(bucket,device_id,app_id,protocol_id,host) DO UPDATE SET
                    upload=upload+excluded.upload, download=download+excluded.download, flows=flows+excluded.flows;
                END''')
            db.execute('PRAGMA user_version=2')
    db.commit()
    if changed or db.execute('PRAGMA auto_vacuum').fetchone()[0] != 2:
        db.execute('PRAGMA auto_vacuum=INCREMENTAL')
        db.execute('VACUUM')
    db.execute('PRAGMA wal_autocheckpoint=64')
    db.execute('PRAGMA journal_size_limit=262144')
    db.execute('PRAGMA cache_size=-1024')
    db.execute('PRAGMA foreign_keys=ON')


def record_hourly(db, values):
    # The view trigger resolves dimensions inside SQLite without retaining stale
    # ID caches after retention cleanup, and accumulates only this event's delta.
    db.execute('INSERT INTO hourly VALUES (?,?,?,?,?,?,?,?,?)', values)


def prune_dimensions(db):
    for table, column in (('traffic_devices','device_id'),('traffic_apps','app_id'),('traffic_protocols','protocol_id')):
        db.execute('DELETE FROM %s WHERE id NOT IN (SELECT %s FROM hourly_data)' % (table,column))


class StoragePolicy:
    def __init__(self, db, path):
        self.db, self.path = db, path
        self.error = ''
        self.last_pruned = 0
        self.pruned_hours = 0
        self.last_checkpoint = float('-inf')
        self.limit = 0

    def checkpoint(self):
        timeout = self.db.execute('PRAGMA busy_timeout').fetchone()[0]
        try:
            self.db.execute('PRAGMA busy_timeout=50')
            return self.db.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0]
        finally:
            self.db.execute('PRAGMA busy_timeout=%d' % timeout)

    def maintain(self):
        try:
            self.limit = read_limit()
            used = footprint(self.path)['used_bytes']
            over = self.limit and used > self.limit*MIB
            if not over and time.monotonic()-self.last_checkpoint < 60:
                self.error = ''
                return
            # A long-lived reader can pin WAL pages. Never delete extra history
            # merely because those log bytes cannot be reclaimed yet.
            self.db.commit()
            busy = self.checkpoint()
            if busy:
                self.error = 'Storage cleanup is waiting for active queries to finish.'
                return
            self.last_checkpoint = time.monotonic()
            if self.limit and footprint(self.path)['used_bytes'] > self.limit*MIB:
                prune_dimensions(self.db)
                target = int(self.limit*MIB*0.85) - 32768
                page_size = self.db.execute('PRAGMA page_size').fetchone()[0]
                removed = 0
                # Bound synchronous reclamation work; large reductions continue
                # on subsequent maintenance ticks after dictionary GC.
                for _ in range(16):
                    live = (self.db.execute('PRAGMA page_count').fetchone()[0] - self.db.execute('PRAGMA freelist_count').fetchone()[0])*page_size
                    if live <= target:
                        break
                    oldest = self.db.execute('SELECT MIN(bucket) FROM (SELECT MIN(bucket) bucket FROM hourly_data UNION ALL SELECT MIN(bucket) FROM interface_hourly)').fetchone()[0]
                    if oldest is None:
                        break
                    self.db.execute('DELETE FROM hourly_data WHERE bucket=?', (oldest,))
                    self.db.execute('DELETE FROM interface_hourly WHERE bucket=?', (oldest,))
                    removed += 1
                if removed:
                    prune_dimensions(self.db)
                    # Dimensions were just pruned. Do not rejoin every retained
                    # traffic row merely to find the small set of active MACs.
                    self.db.execute('DELETE FROM device_latest WHERE mac NOT IN (SELECT mac FROM traffic_devices)')
                    self.last_pruned = int(time.time())
                    self.pruned_hours += removed
                self.db.execute('PRAGMA incremental_vacuum').fetchall()
                self.db.commit()
                self.checkpoint()
            self.error = ''
            if self.limit and footprint(self.path)['used_bytes'] > self.limit*MIB:
                self.error = 'Storage cleanup is not finished; oldest hours will continue to be removed.'
        except (OSError, ValueError, TypeError, AttributeError, sqlite3.Error) as exc:
            self.db.rollback()
            self.error = str(exc)

    def status(self):
        return dict(footprint(self.path), max_storage_mib=self.limit,
                    last_pruned=self.last_pruned, pruned_hours=self.pruned_hours,
                    error=self.error)
