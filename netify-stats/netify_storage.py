"""Compact SQLite storage, seven-day details and cumulative history."""
import json
import os
import sqlite3
import time
import tempfile
import fcntl
import re
import hashlib
from collections import OrderedDict
from functools import lru_cache

CONFIG_PATH = '/etc/netify-stats.json'
MIB = 1024*1024
GC_BATCH_SIZE = 256
VACUUM_PAGES_PER_TICK = 128
MAINTENANCE_BUDGET_SECONDS = .05
DETAIL_RETENTION_SECONDS = 7*24*3600
ARCHIVE_BATCH_SIZE = 256


def read_settings_snapshot():
    """Read each setting once; invalid fields must not hide valid history."""
    try:
        with open(CONFIG_PATH, encoding='utf-8') as handle:
            values = json.load(handle)
    except FileNotFoundError:
        values = {}
    except (OSError, ValueError) as exc:
        result = settings_snapshot(None)
        result['config_error'] = result['storage_error'] = str(exc)
        return result
    return settings_snapshot(values)


def settings_snapshot(values):
    """Validate a read or a proposed update without replacing invalid fields."""
    result = {'enabled': None, 'interface': None, 'max_storage_mib': None,
              'config_error': '', 'storage_error': ''}
    if not isinstance(values, dict):
        result['config_error'] = result['storage_error'] = 'Settings must be a JSON object.'
        return result
    errors = []
    enabled = values.get('enabled', True)
    if isinstance(enabled, bool):
        result['enabled'] = enabled
    else:
        errors.append('Invalid enabled setting')
    interface = values.get('interface', '')
    if isinstance(interface, str) and (not interface or (
            re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}', interface) and interface not in ('.', '..'))):
        result['interface'] = interface
    else:
        errors.append('Invalid interface setting')
    try:
        result['max_storage_mib'] = validate_limit(values.get('max_storage_mib', 0))
    except ValueError as exc:
        result['storage_error'] = str(exc)
        errors.append(str(exc))
    result['config_error'] = '; '.join(errors)
    return result


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


def update_settings(changes, deadline=None, validate=None):
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
        if not isinstance(values, dict):
            raise ValueError('Settings must be a JSON object.')
        values.update(changes)
        if validate is not None:
            validate(values)
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


def _fingerprint(db, source):
    """Verify every raw value during migration without retaining rows in RAM."""
    digest = hashlib.sha256()
    totals = [0, 0, 0, 0]
    for row in db.execute('SELECT * FROM (%s) ORDER BY bucket,mac,ip,application,protocol,host' % source):
        digest.update(json.dumps(tuple(row), separators=(',', ':')).encode())
        totals[0] += 1
        for index, value in enumerate(row[-3:], 1):
            totals[index] += value
    return tuple(totals), digest.digest()


def _hourly_view(table):
    return '''SELECT h.bucket,d.mac,d.ip,a.value application,p.value protocol,
        names.value host,h.upload,h.download,h.flows FROM %s h
        JOIN traffic_devices d ON d.id=h.device_id JOIN traffic_apps a ON a.id=h.app_id
        JOIN traffic_protocols p ON p.id=h.protocol_id JOIN traffic_hosts names ON names.id=h.host_id''' % table


def _host_key(value):
    # This is only an index bucket, never an identity: every lookup also
    # compares the complete original string, including when hashes collide.
    return hashlib.blake2b(value.encode('utf-8'), digest_size=8).digest()


def compact_schema(db):
    # All repeated strings, including hosts, live in dictionaries. The integer
    # primary key keeps both the main table and secondary indexes compact.
    # The compatibility view still exposes the original raw nine columns.
    db.commit()
    # Each writer registers its own small cache. Read-only clients need no
    # function because the hash is an ordinary stored column, not generated.
    cached_host_key = lru_cache(maxsize=256)(_host_key)
    db.create_function('netify_host_key', 1,
                       lambda value: cached_host_key(value) if len(value) <= 253 else _host_key(value),
                       deterministic=True)
    if db.execute('PRAGMA user_version').fetchone()[0] > 4:
        raise sqlite3.DatabaseError('Unsupported statistics schema version')
    kind = db.execute("SELECT type FROM sqlite_master WHERE name='hourly'").fetchone()[0]
    columns = {row[1] for row in db.execute('PRAGMA table_info(hourly_data)')}
    changed = kind != 'view' or 'host_id' not in columns
    if changed:
        with db:
            db.execute('BEGIN IMMEDIATE')
            # A v2 view uses INNER JOINs and can hide orphan child records in
            # a damaged database. Refuse migration before fingerprinting that
            # view rather than silently discard those hidden records.
            if kind == 'view' and db.execute('PRAGMA foreign_key_check').fetchone():
                raise sqlite3.IntegrityError('Statistics foreign-key integrity check failed; original data was preserved.')
            before = _fingerprint(db, 'SELECT * FROM hourly')
            if kind != 'view':
                db.execute('CREATE TABLE traffic_devices (id INTEGER PRIMARY KEY,mac TEXT NOT NULL,ip TEXT NOT NULL,UNIQUE(mac,ip))')
                db.execute('CREATE TABLE traffic_apps (id INTEGER PRIMARY KEY,value TEXT NOT NULL UNIQUE)')
                db.execute('CREATE TABLE traffic_protocols (id INTEGER PRIMARY KEY,value TEXT NOT NULL UNIQUE)')
                db.execute('INSERT INTO traffic_devices(mac,ip) SELECT DISTINCT mac,ip FROM hourly')
                db.execute('INSERT INTO traffic_apps(value) SELECT DISTINCT application FROM hourly')
                db.execute('INSERT INTO traffic_protocols(value) SELECT DISTINCT protocol FROM hourly')
            db.execute('CREATE TABLE traffic_hosts (id INTEGER PRIMARY KEY,value TEXT NOT NULL,lookup_hash BLOB NOT NULL)')
            db.execute('CREATE INDEX traffic_host_lookup ON traffic_hosts(lookup_hash)')
            db.execute('INSERT INTO traffic_hosts(value,lookup_hash) SELECT DISTINCT host,netify_host_key(host) FROM hourly')
            db.execute('''CREATE TABLE hourly_data_v3 (
                bucket INTEGER NOT NULL,device_id INTEGER NOT NULL REFERENCES traffic_devices(id),
                app_id INTEGER NOT NULL REFERENCES traffic_apps(id),
                protocol_id INTEGER NOT NULL REFERENCES traffic_protocols(id),
                host_id INTEGER NOT NULL REFERENCES traffic_hosts(id),
                upload INTEGER NOT NULL,download INTEGER NOT NULL,flows INTEGER NOT NULL,
                PRIMARY KEY(bucket,device_id,app_id,protocol_id,host_id)) WITHOUT ROWID''')
            db.execute('''INSERT INTO hourly_data_v3 SELECT h.bucket,d.id,a.id,p.id,n.id,h.upload,h.download,h.flows
                FROM hourly h JOIN traffic_devices d ON h.mac=d.mac AND h.ip=d.ip
                JOIN traffic_apps a ON h.application=a.value JOIN traffic_protocols p ON h.protocol=p.value
                JOIN traffic_hosts n ON n.lookup_hash=netify_host_key(h.host) AND n.value=h.host''')
            if before != _fingerprint(db, _hourly_view('hourly_data_v3')):
                raise sqlite3.IntegrityError('Statistics migration verification failed; original data was preserved.')
            if kind == 'view':
                db.execute('DROP VIEW hourly')
                db.execute('DROP TABLE hourly_data')
            else:
                db.execute('DROP TABLE hourly')
            db.execute('ALTER TABLE hourly_data_v3 RENAME TO hourly_data')
            db.execute('CREATE VIEW hourly AS ' + _hourly_view('hourly_data'))
            db.execute('''CREATE TRIGGER hourly_insert INSTEAD OF INSERT ON hourly BEGIN
                INSERT OR IGNORE INTO traffic_devices(mac,ip) VALUES (NEW.mac,NEW.ip);
                INSERT OR IGNORE INTO traffic_apps(value) VALUES (NEW.application);
                INSERT OR IGNORE INTO traffic_protocols(value) VALUES (NEW.protocol);
                INSERT INTO traffic_hosts(value,lookup_hash) SELECT NEW.host,netify_host_key(NEW.host)
                    WHERE NOT EXISTS (SELECT 1 FROM traffic_hosts
                        WHERE lookup_hash=netify_host_key(NEW.host) AND value=NEW.host);
                INSERT INTO hourly_data VALUES (NEW.bucket,
                    (SELECT id FROM traffic_devices WHERE mac=NEW.mac AND ip=NEW.ip),
                    (SELECT id FROM traffic_apps WHERE value=NEW.application),
                    (SELECT id FROM traffic_protocols WHERE value=NEW.protocol),
                    (SELECT id FROM traffic_hosts WHERE lookup_hash=netify_host_key(NEW.host)
                        AND value=NEW.host),NEW.upload,NEW.download,NEW.flows)
                ON CONFLICT(bucket,device_id,app_id,protocol_id,host_id) DO UPDATE SET
                    upload=upload+excluded.upload, download=download+excluded.download, flows=flows+excluded.flows;
                END''')
            db.execute('PRAGMA user_version=3')
    # These high-cardinality dimensions need indexes for both device filtering
    # and parent-row FK checks during GC. App/protocol dictionaries stay small.
    db.execute('CREATE INDEX IF NOT EXISTS hourly_device_bucket ON hourly_data(device_id,bucket)')
    db.execute('CREATE INDEX IF NOT EXISTS hourly_host ON hourly_data(host_id)')
    # Cumulative history has no host or hourly key. Keep the resolved app ID,
    # so deleting domain evidence never turns a recognized app into Unknown.
    db.execute('''CREATE TABLE IF NOT EXISTS traffic_archive (
        device_id INTEGER NOT NULL REFERENCES traffic_devices(id),
        application TEXT NOT NULL,protocol_id INTEGER NOT NULL REFERENCES traffic_protocols(id),
        upload INTEGER NOT NULL,download INTEGER NOT NULL,flows INTEGER NOT NULL,
        first_bucket INTEGER NOT NULL,last_bucket INTEGER NOT NULL,
        PRIMARY KEY(device_id,application,protocol_id)) WITHOUT ROWID''')
    db.execute('CREATE INDEX IF NOT EXISTS archive_oldest ON traffic_archive(last_bucket)')
    db.execute('''CREATE TABLE IF NOT EXISTS interface_archive (
        name TEXT PRIMARY KEY,download INTEGER NOT NULL,upload INTEGER NOT NULL,
        since INTEGER NOT NULL,until INTEGER NOT NULL,resets INTEGER NOT NULL,
        first_bucket INTEGER NOT NULL,last_bucket INTEGER NOT NULL) WITHOUT ROWID''')
    db.execute('PRAGMA user_version=4')
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


class HourlyWriter:
    """Bounded writer-local dimension IDs; clear after every retention/GC tick."""
    def __init__(self, db, maxsize=1024):
        self.db = db
        self.maxsize = maxsize
        self.cache = OrderedDict()

    def clear_cache(self):
        self.cache.clear()

    def write(self, values):
        try:
            self._write(values)
        except Exception:
            # SQLite aborts the failed statement; errors such as SQLITE_FULL
            # may roll back the transaction too. Never retain IDs from an
            # uncertain transaction, including dimensions rolled back after
            # a Python validation/encoding error. Preserve earlier valid rows.
            self.clear_cache()
            raise

    def _write(self, values):
        # Hold the writer transaction before SELECT/INSERT pairs: the compact
        # host lookup is deliberately nonunique because collisions are valid.
        if not self.db.in_transaction:
            self.db.execute('BEGIN IMMEDIATE')
        created = False

        def before_insert():
            nonlocal created
            if not created:
                self.db.execute('SAVEPOINT hourly_dimensions')
                created = True

        try:
            dimensions = (
                self._dimension('device', tuple(values[1:3]), before_insert),
                self._dimension('app', (values[3],), before_insert),
                self._dimension('protocol', (values[4],), before_insert),
                self._dimension('host', (values[5],), before_insert),
            )
            self.db.execute('''INSERT INTO hourly_data VALUES (?,?,?,?,?,?,?,?)
                ON CONFLICT(bucket,device_id,app_id,protocol_id,host_id) DO UPDATE SET
                upload=upload+excluded.upload,download=download+excluded.download,flows=flows+excluded.flows''',
                (values[0], *dimensions, *values[6:]))
            if created:
                self.db.execute('RELEASE hourly_dimensions')
        except Exception:
            if created and self.db.in_transaction:
                self.db.execute('ROLLBACK TO hourly_dimensions')
                self.db.execute('RELEASE hourly_dimensions')
            raise

    def _dimension(self, kind, values, before_insert):
        # Cache each dimension independently: 100 devices and 6 domains need
        # around 108 entries, not 600 combinations that would thrash an LRU.
        key = (kind, *values)
        identity = self.cache.get(key)
        if identity is not None:
            self.cache.move_to_end(key)
            return identity
        if kind == 'device':
            table, columns, where, args = 'traffic_devices', 'mac,ip', 'mac=? AND ip=?', values
        elif kind == 'host':
            table, columns = 'traffic_hosts', 'lookup_hash,value'
            where, args = 'lookup_hash=? AND value=?', (_host_key(values[0]), values[0])
        else:
            table = 'traffic_apps' if kind == 'app' else 'traffic_protocols'
            columns, where, args = 'value', 'value=?', values
        row = self.db.execute('SELECT id FROM '+table+' WHERE '+where, args).fetchone()
        if row is None:
            before_insert()
            identity = self.db.execute('INSERT INTO '+table+'('+columns+') VALUES ('+
                                       ','.join('?' for _ in args)+')', args).lastrowid
        else:
            identity = row[0]
        # Keep unexpected oversized metadata out of this optimization cache;
        # raw records still retain their complete original values.
        if self.maxsize > 0 and all(isinstance(value, str) for value in values) and sum(map(len, values)) <= 1024:
            self.cache[key] = identity
            if len(self.cache) > self.maxsize:
                self.cache.popitem(last=False)
        return identity


def correct_hourly(db, row, upload=0, flows=0):
    """Subtract a late proxy correction only from a still-retained row.

    Unlike record_hourly, this never inserts dimensions or resurrects an hour
    deleted by retention. A present row with insufficient counters indicates a
    duplicate/invalid correction, which must not silently create negative data.
    """
    if len(row) != 6 or any(isinstance(value, bool) or not isinstance(value, int)
                           or value < 0 for value in (upload, flows)):
        raise ValueError('Invalid hourly correction')
    where = '''bucket=? AND device_id=(SELECT id FROM traffic_devices WHERE mac=? AND ip=?)
        AND app_id=(SELECT id FROM traffic_apps WHERE value=?)
        AND protocol_id=(SELECT id FROM traffic_protocols WHERE value=?)
        AND host_id=(SELECT id FROM traffic_hosts WHERE lookup_hash=netify_host_key(?) AND value=?)'''
    key = (*row, row[-1])
    changed = db.execute('UPDATE hourly_data SET upload=upload-?,flows=flows-? WHERE ' +
                         where + ' AND upload>=? AND flows>=?',
                         (upload, flows, *key, upload, flows)).rowcount
    if not changed and db.execute('SELECT 1 FROM hourly_data WHERE ' + where, key).fetchone():
        raise sqlite3.IntegrityError('Hourly correction exceeds retained counters')
    return bool(changed)


def prune_dimensions(db, limit=GC_BATCH_SIZE, deadline=None):
    """Bound dictionary cleanup alongside the compact device/host FK indexes.

    The time budget is checked between statements: an individual SQLite scan
    may take longer. Foreign-key enforcement stays enabled throughout cleanup.
    """
    removed = 0
    for table, column in (('traffic_devices','device_id'),('traffic_apps','app_id'),
                          ('traffic_protocols','protocol_id'),('traffic_hosts','host_id')):
        if removed >= limit or (removed and deadline is not None and time.monotonic() >= deadline):
            return {'removed': removed, 'complete': False}
        references = 'SELECT %s FROM hourly_data' % column
        if column in ('device_id', 'protocol_id'):
            references += ' UNION SELECT %s FROM traffic_archive' % column
        candidates = db.execute('SELECT id FROM %s WHERE id NOT IN (%s) LIMIT ?' %
                                (table, references), (limit-removed+1,)).fetchall()
        for (identity,) in candidates:
            # Always permit one deletion: even a slow candidate scan must
            # make forward progress rather than repeat forever each tick.
            if removed >= limit or (removed and deadline is not None and time.monotonic() >= deadline):
                return {'removed': removed, 'complete': False}
            db.execute('DELETE FROM %s WHERE id=?' % table, (identity,))
            removed += 1
    return {'removed': removed, 'complete': True}


class StoragePolicy:
    def __init__(self, db, path, archive_guard=None):
        self.db, self.path = db, path
        self.archive_guard = archive_guard
        self.error = ''
        self.last_pruned = 0
        self.pruned_hours = 0
        self.last_checkpoint = float('-inf')
        self.limit = 0
        self._pruned_buckets = set()
        # Revisit orphan dimensions after restart too, including leftovers
        # from an interrupted cleanup that already fell below the size cap.
        self.cleanup_pending = True
        self.archive_pending = True
        self.last_archive_check = float('-inf')
        self._archive_classifier = None

    def take_pruned_buckets(self):
        """Drain committed evictions so collector dedup/correction state agrees."""
        if not self._pruned_buckets:
            return ()
        buckets = self._pruned_buckets
        self._pruned_buckets = set()
        return buckets

    def checkpoint(self):
        timeout = self.db.execute('PRAGMA busy_timeout').fetchone()[0]
        try:
            self.db.execute('PRAGMA busy_timeout=50')
            return self.db.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0]
        finally:
            self.db.execute('PRAGMA busy_timeout=%d' % timeout)

    def release_archive_classifier(self):
        if self._archive_classifier is not None:
            # The LRU wraps a bound method, creating a self-reference. Break
            # it so a router releases the rule dictionary immediately instead
            # of waiting for cyclic garbage collection after each hourly job.
            del self._archive_classifier._classify_domain
            self._archive_classifier = None

    def archive(self, now=None):
        """Move a bounded batch atomically; a crash cannot double-count bytes.

        Caller commits collection first. A partially processed hour remains
        in hourly_data and is revisited on the next tick. Only complete hours
        notify the collector that its correction/dedup state can be discarded.
        """
        now = int(time.time()) if now is None else now
        cutoff = now//3600*3600 - DETAIL_RETENTION_SECONDS
        if self.archive_guard is not None:
            protected = self.archive_guard()
            if protected is not None:
                cutoff = min(cutoff, protected)
        deadline = time.monotonic() + MAINTENANCE_BUDGET_SECONDS
        buckets = set()
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            rows = self.db.execute('''SELECT h.bucket,h.device_id,h.app_id,h.protocol_id,h.host_id,
                h.upload,h.download,h.flows,a.value,p.value,n.value
                FROM (SELECT * FROM hourly_data WHERE bucket<? ORDER BY
                    bucket,device_id,app_id,protocol_id,host_id LIMIT ?) h
                JOIN traffic_apps a ON a.id=h.app_id
                JOIN traffic_protocols p ON p.id=h.protocol_id
                JOIN traffic_hosts n ON n.id=h.host_id''',
                (cutoff, ARCHIVE_BATCH_SIZE)).fetchall()
            if rows and self._archive_classifier is None:
                from netify_classify import Classifier
                self._archive_classifier = Classifier()
                # The collector does not need the query process's large cache.
                self._archive_classifier._classify_domain = lru_cache(maxsize=256)(
                    self._archive_classifier._classify_domain.__wrapped__)
            classifier = self._archive_classifier
            if rows and classifier.error:
                self.release_archive_classifier()  # Retry after the rules file is repaired.
                raise ValueError('History compaction requires readable classification rules: ' + classifier.error)
            processed = 0
            for bucket, device, native, protocol, host, up, down, flows, app, proto, domain in rows:
                resolved = classifier.classify(app, domain, proto)
                if resolved.startswith('domain:'):
                    resolved = 'archive:domain'
                self.db.execute('''INSERT INTO traffic_archive VALUES (?,?,?,?,?,?,?,?)
                    ON CONFLICT(device_id,application,protocol_id) DO UPDATE SET
                    upload=upload+excluded.upload,download=download+excluded.download,
                    flows=flows+excluded.flows,first_bucket=MIN(first_bucket,excluded.first_bucket),
                    last_bucket=MAX(last_bucket,excluded.last_bucket)''',
                    (device,resolved,protocol,up,down,flows,bucket,bucket))
                self.db.execute('''DELETE FROM hourly_data WHERE bucket=? AND device_id=?
                    AND app_id=? AND protocol_id=? AND host_id=?''',
                    (bucket,device,native,protocol,host))
                buckets.add(bucket)
                processed += 1
                # Domain samples are deliberately not retained in the archive.
                classifier.app_sources.clear()
                classifier.app_evidence.clear()
                classifier.evidence_truncated.clear()
                if time.monotonic() >= deadline:
                    break
            # Interface counters are independent from DPI counters. Bound these
            # too, and never reset the live interface sampling baseline.
            interfaces = self.db.execute('''SELECT * FROM interface_hourly
                WHERE bucket<? ORDER BY bucket,name LIMIT ?''', (cutoff, ARCHIVE_BATCH_SIZE)).fetchall()
            for bucket, name, down, up, since, until, resets in interfaces:
                self.db.execute('''INSERT INTO interface_archive VALUES (?,?,?,?,?,?,?,?)
                    ON CONFLICT(name) DO UPDATE SET download=download+excluded.download,
                    upload=upload+excluded.upload,since=MIN(since,excluded.since),
                    until=MAX(until,excluded.until),resets=resets+excluded.resets,
                    first_bucket=MIN(first_bucket,excluded.first_bucket),
                    last_bucket=MAX(last_bucket,excluded.last_bucket)''',
                    (name,down,up,since,until,resets,bucket,bucket))
                self.db.execute('DELETE FROM interface_hourly WHERE bucket=? AND name=?', (bucket,name))
                buckets.add(bucket)
                if time.monotonic() >= deadline:
                    break
            complete = {bucket for bucket in buckets if not self.db.execute(
                'SELECT 1 FROM hourly_data WHERE bucket=? LIMIT 1', (bucket,)).fetchone()}
            pending = any(self.db.execute('SELECT 1 FROM '+table+' WHERE bucket<? LIMIT 1',
                                         (cutoff,)).fetchone()
                          for table in ('hourly_data','interface_hourly'))
        # Publish only after the transaction committed successfully.
        self._pruned_buckets.update(complete)
        self.archive_pending = pending
        self.last_archive_check = time.monotonic()
        if buckets:
            self.cleanup_pending = True
        if not pending:
            self.release_archive_classifier()
        return processed

    def maintain(self):
        try:
            self.limit = read_limit()
            self.db.commit()
            if self.archive_pending or time.monotonic()-self.last_archive_check >= 60:
                self.archive()
            used = footprint(self.path)['used_bytes']
            over = self.limit and used > self.limit*MIB
            if not over and not self.cleanup_pending and time.monotonic()-self.last_checkpoint < 60:
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
            over = bool(self.limit and footprint(self.path)['used_bytes'] > self.limit*MIB)
            if over or self.cleanup_pending:
                deadline = time.monotonic() + MAINTENANCE_BUDGET_SECONDS
                garbage = prune_dimensions(self.db, deadline=deadline)
                dimensions_removed = garbage['removed']
                target = int(self.limit*MIB*0.85) - 32768
                page_size = self.db.execute('PRAGMA page_size').fetchone()[0]
                removed = 0
                removed_buckets = set()
                # Bound synchronous reclamation work; large reductions continue
                # on subsequent maintenance ticks after dictionary GC.
                for _ in range(16):
                    # Reclaim orphan dimensions first; their still-occupied
                    # pages must not cause unnecessary deletion of history.
                    if self.archive_pending or not over or not garbage['complete'] or (removed and time.monotonic() >= deadline):
                        break
                    live = (self.db.execute('PRAGMA page_count').fetchone()[0] - self.db.execute('PRAGMA freelist_count').fetchone()[0])*page_size
                    if live <= target:
                        break
                    # Cumulative entries cannot be split back into hours.
                    # Under an explicit capacity cap, evict the oldest summary
                    # first; avoid dropping recent details to keep old totals.
                    archived = self.db.execute('''SELECT last_bucket,0,device_id,application,protocol_id
                        FROM traffic_archive UNION ALL SELECT last_bucket,1,0,name,0
                        FROM interface_archive ORDER BY 1 LIMIT 1''').fetchone()
                    if archived is not None:
                        _, kind, identity, app, protocol = archived
                        if kind:
                            self.db.execute('DELETE FROM interface_archive WHERE name=?', (app,))
                        else:
                            self.db.execute('DELETE FROM traffic_archive WHERE device_id=? AND application=? AND protocol_id=?',
                                            (identity,app,protocol))
                        garbage = prune_dimensions(self.db, limit=GC_BATCH_SIZE-dimensions_removed, deadline=deadline)
                        dimensions_removed += garbage['removed']
                        if time.monotonic() >= deadline:
                            break
                        continue
                    oldest = self.db.execute('SELECT MIN(bucket) FROM (SELECT MIN(bucket) bucket FROM hourly_data UNION ALL SELECT MIN(bucket) FROM interface_hourly)').fetchone()[0]
                    if oldest is None:
                        break
                    self.db.execute('DELETE FROM hourly_data WHERE bucket=?', (oldest,))
                    self.db.execute('DELETE FROM interface_hourly WHERE bucket=?', (oldest,))
                    removed += 1
                    removed_buckets.add(oldest)
                    # Host dictionaries can occupy more space than the rows
                    # just removed. Finish reclaiming those orphan entries
                    # before deciding whether another hour really must go.
                    garbage = prune_dimensions(self.db, limit=GC_BATCH_SIZE-dimensions_removed, deadline=deadline)
                    dimensions_removed += garbage['removed']
                if removed or dimensions_removed:
                    # Dimensions were just pruned. Do not rejoin every retained
                    # traffic row merely to find the small set of active MACs.
                    self.db.execute('DELETE FROM device_latest WHERE mac NOT IN (SELECT mac FROM traffic_devices)')
                self.db.execute('PRAGMA incremental_vacuum(%d)' % VACUUM_PAGES_PER_TICK).fetchall()
                pending = not garbage['complete'] or self.db.execute('PRAGMA freelist_count').fetchone()[0] > 0
                self.db.commit()
                self.cleanup_pending = pending
                if removed:
                    self.last_pruned = int(time.time())
                    self.pruned_hours += removed
                    self._pruned_buckets.update(removed_buckets)
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
                    cleanup_pending=self.cleanup_pending, archive_pending=self.archive_pending,
                    detail_retention_seconds=DETAIL_RETENTION_SECONDS,
                    error=self.error)
