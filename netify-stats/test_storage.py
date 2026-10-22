import hashlib
import json
import os
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

import netify_storage as storage
from netify_accounting import InterfaceAccounting


def original_schema(db):
    db.execute('''CREATE TABLE hourly (bucket INTEGER, mac TEXT, ip TEXT,
        application TEXT, protocol TEXT, host TEXT, upload INTEGER, download INTEGER, flows INTEGER,
        PRIMARY KEY(bucket,mac,ip,application,protocol,host))''')
    for key in ('mac','host','application'):
        name = 'app' if key == 'application' else key
        db.execute('CREATE INDEX hourly_%s_bucket ON hourly(%s,bucket)' % (name,key))
    db.execute('CREATE TABLE device_latest(mac TEXT PRIMARY KEY,ip TEXT,seen INTEGER)')
    InterfaceAccounting(db)
    db.commit()


def make_version_two(db):
    """Frozen deployed schema fixture, before domains became a dictionary."""
    db.execute('CREATE TABLE traffic_devices (id INTEGER PRIMARY KEY,mac TEXT,ip TEXT,UNIQUE(mac,ip))')
    db.execute('CREATE TABLE traffic_apps (id INTEGER PRIMARY KEY,value TEXT UNIQUE)')
    db.execute('CREATE TABLE traffic_protocols (id INTEGER PRIMARY KEY,value TEXT UNIQUE)')
    db.execute('''CREATE TABLE hourly_data (
        bucket INTEGER NOT NULL,device_id INTEGER NOT NULL REFERENCES traffic_devices(id),
        app_id INTEGER NOT NULL REFERENCES traffic_apps(id),
        protocol_id INTEGER NOT NULL REFERENCES traffic_protocols(id),host TEXT NOT NULL,
        upload INTEGER NOT NULL,download INTEGER NOT NULL,flows INTEGER NOT NULL,
        PRIMARY KEY(bucket,device_id,app_id,protocol_id,host)) WITHOUT ROWID''')
    db.execute('INSERT INTO traffic_devices(mac,ip) SELECT DISTINCT mac,ip FROM hourly ORDER BY mac DESC,ip DESC')
    db.execute('INSERT INTO traffic_apps(value) SELECT DISTINCT application FROM hourly ORDER BY application DESC')
    db.execute('INSERT INTO traffic_protocols(value) SELECT DISTINCT protocol FROM hourly')
    db.execute('''INSERT INTO hourly_data SELECT h.bucket,d.id,a.id,p.id,h.host,h.upload,h.download,h.flows
        FROM hourly h JOIN traffic_devices d ON d.mac=h.mac AND d.ip=h.ip
        JOIN traffic_apps a ON a.value=h.application JOIN traffic_protocols p ON p.value=h.protocol''')
    db.execute('DROP TABLE hourly')
    db.execute('''CREATE VIEW hourly AS SELECT h.bucket,d.mac,d.ip,a.value application,
        p.value protocol,h.host,h.upload,h.download,h.flows FROM hourly_data h
        JOIN traffic_devices d ON d.id=h.device_id JOIN traffic_apps a ON a.id=h.app_id
        JOIN traffic_protocols p ON p.id=h.protocol_id''')
    db.execute('PRAGMA user_version=2')
    db.commit()


def checksum(db):
    digest = hashlib.sha256()
    for row in db.execute('SELECT * FROM hourly ORDER BY bucket,mac,ip,application,protocol,host'):
        digest.update(json.dumps(row, separators=(',',':')).encode())
    return digest.hexdigest()


class StorageTests(unittest.TestCase):
    def test_v2_migration_verifies_raw_values_and_rolls_back_on_mismatch(self):
        with sqlite3.connect(':memory:') as db:
            original_schema(db)
            db.executemany('INSERT INTO hourly VALUES (?,?,?,?,?,?,?,?,?)', [
                (bucket,'mac','ip','native','TLS',host,5,10,1)
                for bucket in (3600,7200) for host in ('Case.Example.', '例子.example', 'quote".example')])
            make_version_two(db)
            before = checksum(db)
            actual_view = storage._hourly_view
            with patch.object(storage, '_hourly_view', side_effect=lambda table:
                              actual_view(table).replace('names.value host', "names.value || '.changed' host")):
                with self.assertRaisesRegex(sqlite3.IntegrityError, 'migration verification'):
                    storage.compact_schema(db)
            self.assertEqual(checksum(db), before)
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 2)
            self.assertIsNone(db.execute("SELECT 1 FROM sqlite_master WHERE name='traffic_hosts'").fetchone())
            self.assertIsNone(db.execute("SELECT 1 FROM sqlite_master WHERE name='hourly_data_v3'").fetchone())
            storage.compact_schema(db)
            self.assertEqual(checksum(db), before)
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 3)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM traffic_hosts').fetchone()[0], 3)
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(), [])
            for column, index in (('device_id','hourly_device_bucket'), ('host_id','hourly_host')):
                plan = ' '.join(row[3] for row in db.execute('EXPLAIN QUERY PLAN SELECT 1 FROM hourly_data WHERE '+column+'=1'))
                self.assertIn(index, plan)
            storage.compact_schema(db)
            self.assertEqual(checksum(db), before)

    def test_migration_rejects_orphan_rows_hidden_by_a_damaged_v2_view(self):
        with sqlite3.connect(':memory:') as db:
            original_schema(db)
            db.execute('INSERT INTO hourly VALUES (0,"m","i","a","p","h",1,2,1)')
            make_version_two(db)
            # Simulate a prior writer that did not enable FK enforcement.
            db.execute('INSERT INTO hourly_data VALUES (3600,999,1,1,"hidden",3,4,1)')
            db.commit()
            self.assertEqual(db.execute('SELECT COUNT(*) FROM hourly').fetchone()[0], 1)
            with self.assertRaisesRegex(sqlite3.IntegrityError, 'foreign-key integrity'):
                storage.compact_schema(db)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM hourly_data').fetchone()[0], 2)
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 2)

    def test_host_hash_collisions_keep_exact_identity_and_readers_need_no_function(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(storage, '_host_key', return_value=b'forced!!'):
            path = directory+'/stats.db'
            db = sqlite3.connect(path)
            original_schema(db)
            rows = [(3600,'mac','ip','App','TLS',host,10,20,1)
                    for host in ('one.example','two.example','three.example')]
            db.executemany('INSERT INTO hourly VALUES (?,?,?,?,?,?,?,?,?)', rows)
            make_version_two(db)
            before = checksum(db)
            storage.compact_schema(db)
            self.assertEqual(checksum(db), before)
            writer = storage.HourlyWriter(db)
            writer.write(rows[0])
            writer.write(rows[1])
            writer.write(rows[0])  # Direct numeric cache hit.
            self.assertTrue(storage.correct_hourly(db, rows[1][:6], upload=5))
            expected = [('one.example',30,60,3),('three.example',10,20,1),('two.example',15,40,2)]
            self.assertEqual(db.execute('SELECT host,upload,download,flows FROM hourly ORDER BY host').fetchall(), expected)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM traffic_hosts').fetchone()[0],3)
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(), [])
            db.commit()
            db.close()
            reader = sqlite3.connect('file:'+path+'?mode=ro',uri=True)
            self.assertEqual(reader.execute('SELECT host,upload,download,flows FROM hourly ORDER BY host').fetchall(), expected)
            reader.close()
            # Every restarted writer registers the same stable hash function.
            db = sqlite3.connect(path)
            storage.compact_schema(db)
            storage.HourlyWriter(db).write(rows[2])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM traffic_hosts').fetchone()[0],3)
            db.close()

    def test_hourly_writer_cache_is_bounded_and_rebuilds_after_dimension_gc(self):
        with sqlite3.connect(':memory:') as db:
            original_schema(db)
            storage.compact_schema(db)
            writer = storage.HourlyWriter(db,maxsize=2)
            for index in range(5):
                writer.write((0,'mac'+str(index),'ip','App','TLS','host'+str(index),10,20,1))
            self.assertEqual(len(writer.cache),2)
            old = (0,'mac4','ip','App','TLS','host4',10,20,1)
            db.execute('DELETE FROM hourly_data')
            while not storage.prune_dimensions(db)['complete']:
                pass
            replacement = (3600,'other','ip','Other','QUIC','other.example',100,200,1)
            storage.record_hourly(db,replacement)
            writer.clear_cache()
            writer.write(old)
            writer.write(old)
            self.assertEqual(db.execute('SELECT mac,upload,download,flows FROM hourly ORDER BY mac').fetchall(),
                             [('mac4',20,40,2),('other',100,200,1)])
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(), [])
            before = checksum(db)
            with self.assertRaises(OverflowError):
                writer.write((*old[:6], 1 << 100, 0, 0))
            self.assertEqual(len(writer.cache),0)
            self.assertEqual(checksum(db),before)
            # A failed cache hit clears uncertain IDs without dropping prior
            # valid writes in the collector's current transaction.
            writer.write(old)
            self.assertEqual(db.execute('SELECT upload FROM hourly WHERE mac="mac4"').fetchone()[0],30)
            db.execute("""CREATE TRIGGER reject_test_write BEFORE INSERT ON hourly_data
                WHEN NEW.upload=999 BEGIN SELECT RAISE(ABORT,'simulated write failure'); END""")
            before = checksum(db)
            with self.assertRaises(sqlite3.IntegrityError):
                writer.write((*old[:6],999,0,0))
            self.assertEqual(len(writer.cache),0)
            self.assertEqual(checksum(db),before)
            tables = ('traffic_devices','traffic_apps','traffic_protocols','traffic_hosts')
            dimensions = [db.execute('SELECT * FROM '+table).fetchall() for table in tables]
            with self.assertRaises(sqlite3.IntegrityError):
                writer.write((3600,'rejected','new-ip','Rejected','Rejected','rejected.example',999,0,0))
            self.assertEqual(len(writer.cache),0)
            self.assertEqual(checksum(db),before)
            self.assertEqual([db.execute('SELECT * FROM '+table).fetchall() for table in tables],dimensions)
            db.execute('DROP TRIGGER reject_test_write')
            oversized = (3600,'m','i','A','P','x'*2048,1,2,1)
            writer.clear_cache()
            writer.write(oversized)
            self.assertFalse(any(key[0] == 'host' and len(key[1]) > 1024 for key in writer.cache))
            self.assertEqual(db.execute('SELECT LENGTH(host) FROM hourly WHERE mac="m"').fetchone()[0],2048)

    def test_writer_encoding_failure_cannot_reuse_rolled_back_dimension_ids(self):
        with sqlite3.connect(':memory:') as db:
            original_schema(db)
            storage.compact_schema(db)
            writer = storage.HourlyWriter(db)
            with self.assertRaises(UnicodeEncodeError):
                writer.write((0,'alice','ip','alice-app','TLS','bad\ud800',1,2,1))
            self.assertEqual(len(writer.cache),0)
            writer.write((0,'bob','ip','bob-app','QUIC','bob.example',3,4,1))
            writer.write((0,'alice','ip','alice-app','TLS','alice.example',5,6,1))
            self.assertEqual(db.execute('SELECT mac,application,protocol,host,upload FROM hourly ORDER BY mac').fetchall(),
                             [('alice','alice-app','TLS','alice.example',5),('bob','bob-app','QUIC','bob.example',3)])
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(),[])

    def test_writer_caches_dimensions_across_many_distinct_combinations(self):
        with sqlite3.connect(':memory:') as db:
            original_schema(db)
            storage.compact_schema(db)
            writer = storage.HourlyWriter(db)
            rows = [(0,'mac'+str(device),'ip','App','TLS','host'+str(host),1,2,1)
                    for device in range(100) for host in range(6)]
            for row in rows:
                writer.write(row)
            self.assertEqual(len(writer.cache),108)
            statements = []
            db.set_trace_callback(statements.append)
            for row in rows:
                writer.write(row)
            db.set_trace_callback(None)
            self.assertFalse(any(sql.lstrip().upper().startswith('SELECT') for sql in statements))
            self.assertEqual(db.execute('SELECT COUNT(*),SUM(upload),SUM(download),SUM(flows) FROM hourly_data').fetchone(),
                             (600,1200,2400,1200))

    def test_dictionary_reuse_preserves_identity_after_eviction_and_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = directory+'/stats.db'
            db = sqlite3.connect(path)
            original_schema(db)
            storage.compact_schema(db)
            storage.record_hourly(db,(0,'old-mac','old-ip','Old','TLS','old.example',1,2,1))
            db.execute('DELETE FROM hourly_data')
            storage.prune_dimensions(db)
            expected = (3600,'new-mac','new-ip','New','QUIC','new.example',12,23,2)
            storage.record_hourly(db,expected[:-3]+(5,10,1))
            storage.record_hourly(db,expected[:-3]+(7,13,1))
            db.commit();db.close()
            db = sqlite3.connect(path)
            storage.compact_schema(db)
            self.assertEqual(db.execute('SELECT * FROM hourly').fetchone(),expected)
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(),[])
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute('DELETE FROM traffic_devices')
            db.close()

    def test_compaction_retains_every_row_and_byte(self):
        with tempfile.TemporaryDirectory() as directory:
            path = directory+'/stats.db'
            db = sqlite3.connect(path)
            original_schema(db)
            db.executemany('INSERT INTO hourly VALUES (?,?,?,?,?,?,?,?,?)',
                ((i//100*3600,'aa:bb:cc:dd:ee:ff','10.1.1.2','Unknown','TLS','long-service-name-%d.example.com'%i,i,i*2,1) for i in range(8000)))
            db.commit()
            old_size = os.path.getsize(path)
            before = checksum(db)
            storage.compact_schema(db)
            self.assertEqual(checksum(db), before)
            self.assertLess(os.path.getsize(path), old_size*0.6)
            self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0],'ok')
            self.assertEqual(db.execute('PRAGMA auto_vacuum').fetchone()[0],2)
            storage.compact_schema(db)
            self.assertEqual(checksum(db),before)
            db.close()

    def test_capacity_evicts_old_hours_and_reclaims_real_file_space(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(storage,'CONFIG_PATH',directory+'/settings.json'):
            path = directory+'/stats.db'
            db = sqlite3.connect(path)
            original_schema(db)
            storage.compact_schema(db)
            db.execute('PRAGMA journal_mode=WAL')
            db.executemany('INSERT INTO hourly VALUES (?,?,?,?,?,?,?,?,?)',
                ((i//1000*3600,'mac','ip','Unknown','TLS',str(i)+'x'*180+'.example',10,20,1) for i in range(25000)))
            storage.record_hourly(db,(0,'evicted-mac','old-ip','Unknown','TLS','old.example',1,2,1))
            db.executemany('INSERT INTO device_latest VALUES (?,?,?)',
                [('mac','ip',1),('evicted-mac','old-ip',1)])
            db.commit()
            policy = storage.StoragePolicy(db,path)
            storage.save_limit(0)
            policy.maintain()
            self.assertEqual(db.execute('SELECT COUNT(*) FROM hourly').fetchone()[0],25001)
            storage.save_limit(4)
            # Slow scans with no orphan dimensions must still allow one
            # oldest-hour deletion even after the cooperative deadline.
            with patch.object(storage, 'MAINTENANCE_BUDGET_SECONDS', 0):
                policy.maintain()
            self.assertLess(db.execute('SELECT COUNT(*) FROM hourly').fetchone()[0],25001)
            # Reclamation is deliberately spread over maintenance ticks.
            # Once rows are freed, subsequent ticks must reclaim those pages
            # rather than remove more retained hours just to shrink the file.
            retained_counts = []
            with patch.object(storage, 'MAINTENANCE_BUDGET_SECONDS', 10):
                for _ in range(256):
                    previous_count = db.execute('SELECT COUNT(*) FROM hourly').fetchone()[0]
                    live_bytes = (db.execute('PRAGMA page_count').fetchone()[0] -
                                  db.execute('PRAGMA freelist_count').fetchone()[0])*db.execute('PRAGMA page_size').fetchone()[0]
                    policy.maintain()
                    current_count = db.execute('SELECT COUNT(*) FROM hourly').fetchone()[0]
                    retained_counts.append(current_count)
                    if live_bytes <= int(4*storage.MIB*.85)-32768:
                        self.assertEqual(current_count, previous_count)
                    if not policy.error:
                        break
            self.assertEqual(policy.error,'')
            self.assertLessEqual(storage.footprint(path)['used_bytes'],4*storage.MIB)
            self.assertGreater(db.execute('SELECT MIN(bucket) FROM hourly').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT MAX(bucket) FROM hourly').fetchone()[0],24*3600)
            self.assertEqual(db.execute('SELECT SUM(download),SUM(upload) FROM hourly').fetchone(),
                tuple(v*db.execute('SELECT COUNT(*) FROM hourly').fetchone()[0] for v in (20,10)))
            self.assertGreater(policy.pruned_hours,0)
            self.assertEqual(db.execute('SELECT mac FROM device_latest').fetchall(),[('mac',)])
            self.assertEqual(storage.read_limit(),4)
            self.assertGreater(len(retained_counts),1)
            db.close()

    def test_late_correction_never_recreates_pruned_history_or_dimensions(self):
        with sqlite3.connect(':memory:') as db:
            original_schema(db)
            storage.compact_schema(db)
            row = (3600,'old-mac','old-ip','Old','TLS','old.example')
            storage.record_hourly(db, (*row, 100, 200, 1))
            self.assertTrue(storage.correct_hourly(db, row, upload=25))
            self.assertEqual(db.execute('SELECT upload,download,flows FROM hourly').fetchone(), (75,200,1))
            self.assertTrue(storage.correct_hourly(db, row))
            with self.assertRaises(sqlite3.IntegrityError):
                storage.correct_hourly(db, row, upload=76)
            self.assertEqual(db.execute('SELECT upload FROM hourly').fetchone()[0], 75)
            db.execute('DELETE FROM hourly_data WHERE bucket=3600')
            storage.prune_dimensions(db)
            # IDs may now be reused by unrelated dimensions.
            new_row = (7200,'new-mac','new-ip','New','QUIC','new.example',5,6,1)
            storage.record_hourly(db, new_row)
            before = checksum(db)
            self.assertFalse(storage.correct_hourly(db, row, upload=75, flows=1))
            self.assertEqual(checksum(db), before)
            self.assertEqual(db.execute('SELECT * FROM hourly').fetchall(), [new_row])
            self.assertEqual(db.execute('SELECT mac FROM traffic_devices').fetchall(), [('new-mac',)])
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(), [])

    def test_dimension_cleanup_progresses_in_bounded_batches_with_foreign_keys(self):
        with sqlite3.connect(':memory:') as db:
            original_schema(db)
            storage.compact_schema(db)
            storage.record_hourly(db, (0,'kept','ip','Kept','TLS','kept.example',1,2,1))
            for table, columns, rows in (
                    ('traffic_devices', 'mac,ip', [('unused', str(i)) for i in range(500)]),
                    ('traffic_apps', 'value', [('unused%d'%i,) for i in range(10)]),
                    ('traffic_protocols', 'value', [('unused%d'%i,) for i in range(10)])):
                db.executemany('INSERT INTO %s(%s) VALUES (%s)' %
                               (table, columns, ','.join('?' for _ in rows[0])), rows)
            before = checksum(db)
            first = storage.prune_dimensions(db)
            self.assertEqual(first, {'removed': storage.GC_BATCH_SIZE, 'complete': False})
            self.assertEqual(db.execute('PRAGMA foreign_keys').fetchone()[0], 1)
            total_removed = first['removed']
            for _ in range(20):
                result = storage.prune_dimensions(db, limit=64)
                self.assertLessEqual(result['removed'], 64)
                total_removed += result['removed']
                if result['complete']:
                    break
            self.assertTrue(result['complete'])
            self.assertEqual(total_removed, 520)
            self.assertEqual(checksum(db), before)
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(), [])
            # An expensive initial scan must not starve cleanup forever.
            db.execute("INSERT INTO traffic_apps(value) VALUES ('late-orphan')")
            result = storage.prune_dimensions(db, deadline=0)
            self.assertEqual(result['removed'], 1)

    def test_retention_notifications_and_counters_only_include_committed_deletions(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(storage, 'read_limit', return_value=4):
            path = directory+'/stats.db'
            db = sqlite3.connect(path)
            original_schema(db)
            storage.compact_schema(db)
            db.executemany('INSERT INTO hourly VALUES (?,?,?,?,?,?,?,?,?)',
                ((i//9000*3600,'mac','ip','Unknown','TLS',str(i)+'x'*180+'.example',1,2,1) for i in range(18000)))
            db.commit()
            self.assertGreater(storage.footprint(path)['used_bytes'],4*storage.MIB)
            before = checksum(db)
            policy = storage.StoragePolicy(db,path)
            real_prune = storage.prune_dimensions
            calls = 0
            def fail_after_hour_deleted(*args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError('simulated cleanup failure')
                return real_prune(*args, **kwargs)
            with patch.object(storage, 'prune_dimensions', side_effect=fail_after_hour_deleted):
                policy.maintain()
            self.assertEqual(policy.error, 'simulated cleanup failure')
            self.assertEqual(policy.take_pruned_buckets(), ())
            self.assertEqual((policy.pruned_hours, policy.last_pruned), (0,0))
            self.assertEqual(checksum(db), before)
            policy.maintain()
            self.assertEqual(policy.take_pruned_buckets(), {0})
            self.assertEqual(policy.take_pruned_buckets(), ())
            self.assertEqual(policy.pruned_hours, 1)
            self.assertEqual(db.execute('SELECT DISTINCT bucket FROM hourly').fetchall(), [(3600,)])
            db.close()

    def test_pending_dictionary_cleanup_continues_below_capacity_and_after_restart(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(storage, 'read_limit', return_value=4):
            path = directory+'/stats.db'
            db = sqlite3.connect(path)
            original_schema(db)
            storage.compact_schema(db)
            kept = (3600,'kept','ip','App','TLS','kept.example',10,20,1)
            storage.record_hourly(db, kept)
            db.executemany('INSERT INTO traffic_hosts(value,lookup_hash) SELECT ?,netify_host_key(?)',
                           ((str(i)+'.unused.example',)*2 for i in range(700)))
            db.commit()
            self.assertLess(storage.footprint(path)['used_bytes'],4*storage.MIB)
            policy = storage.StoragePolicy(db,path)
            policy.maintain()
            self.assertTrue(policy.cleanup_pending)
            self.assertEqual(policy.error, '')
            self.assertGreater(db.execute('SELECT COUNT(*) FROM traffic_hosts').fetchone()[0], 1)
            # A fresh policy must discover and finish unfinished GC even when
            # capacity is disabled, without deleting any live traffic.
            policy = storage.StoragePolicy(db,path)
            with patch.object(storage, 'read_limit', return_value=0):
                for _ in range(20):
                    policy.maintain()
                    self.assertEqual(db.execute('SELECT * FROM hourly').fetchall(), [kept])
                    if not policy.cleanup_pending:
                        break
            self.assertFalse(policy.cleanup_pending)
            self.assertEqual(db.execute('SELECT value FROM traffic_hosts').fetchall(), [('kept.example',)])
            self.assertEqual(policy.take_pruned_buckets(), ())
            db.close()

    def test_settings_snapshot_preserves_valid_fields_when_another_is_invalid(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(storage,'CONFIG_PATH',directory+'/settings.json'):
            snapshot = storage.read_settings_snapshot()
            self.assertEqual((snapshot['enabled'],snapshot['interface'],snapshot['max_storage_mib']), (True,'',0))
            self.assertEqual(snapshot['config_error'], '')
            cases = [
                ({'enabled':'true','interface':'wan','max_storage_mib':16}, (None,'wan',16)),
                ({'enabled':False,'interface':42,'max_storage_mib':16}, (False,None,16)),
                ({'enabled':True,'interface':'wan','max_storage_mib':'16'}, (True,'wan',None)),
            ]
            for values, expected in cases:
                with open(storage.CONFIG_PATH,'w') as handle:
                    json.dump(values,handle)
                result = storage.read_settings_snapshot()
                self.assertEqual((result['enabled'],result['interface'],result['max_storage_mib']), expected)
                self.assertTrue(result['config_error'])
            for malformed in ('{broken', '[]', 'null'):
                with open(storage.CONFIG_PATH,'w') as handle:
                    handle.write(malformed)
                result = storage.read_settings_snapshot()
                self.assertTrue(result['config_error'])
                self.assertEqual((result['enabled'],result['interface'],result['max_storage_mib']), (None,None,None))

    def test_validation_and_atomic_settings(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(storage,'CONFIG_PATH',directory+'/settings.json'):
            self.assertEqual(storage.read_limit(),0)
            for value in (-1,1,3,4097,True,'16',16.5,None):
                with self.assertRaises(ValueError):
                    storage.save_limit(value)
            storage.save_limit(32)
            self.assertEqual(storage.read_limit(),32)
            self.assertEqual(os.stat(storage.CONFIG_PATH).st_mode & 0o777,0o600)
            self.assertEqual(set(os.listdir(directory)),{'settings.json','settings.json.lock'})
            storage.update_settings({'enabled':False})
            storage.save_limit(16)
            self.assertFalse(storage.read_enabled())
            storage.update_settings({'enabled':True})
            self.assertEqual(storage.read_limit(),16)
            with open(storage.CONFIG_PATH) as handle:
                before = handle.read()
            def validate(values):
                error = storage.settings_snapshot(values)['config_error']
                if error:
                    raise ValueError(error)
            with self.assertRaises(ValueError):
                storage.update_settings({'interface':42}, validate=validate)
            with open(storage.CONFIG_PATH) as handle:
                self.assertEqual(handle.read(),before)

    def test_reader_blocks_reclamation_without_deleting_history(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(storage,'CONFIG_PATH',directory+'/settings.json'):
            path = directory+'/stats.db'
            db = sqlite3.connect(path)
            original_schema(db)
            storage.compact_schema(db)
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('INSERT INTO hourly VALUES (0,"m","i","a","p","h",1,2,1)')
            db.commit()
            reader = sqlite3.connect(path)
            reader.execute('BEGIN')
            reader.execute('SELECT * FROM hourly').fetchall()
            storage.record_hourly(db, (0,'m','i','a','p','h',1,0,0))
            db.commit()
            storage.save_limit(4)
            policy = storage.StoragePolicy(db,path)
            before = time.monotonic()
            policy.maintain()
            self.assertLess(time.monotonic()-before,1)
            self.assertTrue(policy.error)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM hourly').fetchone()[0],1)
            reader.close()
            policy.maintain()
            self.assertEqual(policy.error,'')
            db.close()


if __name__ == '__main__':
    unittest.main()
