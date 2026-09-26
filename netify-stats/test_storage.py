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


def checksum(db):
    digest = hashlib.sha256()
    for row in db.execute('SELECT * FROM hourly ORDER BY bucket,mac,ip,application,protocol,host'):
        digest.update(json.dumps(row, separators=(',',':')).encode())
    return digest.hexdigest()


class StorageTests(unittest.TestCase):
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
            policy.maintain()
            self.assertEqual(policy.error,'')
            self.assertLessEqual(storage.footprint(path)['used_bytes'],4*storage.MIB)
            self.assertGreater(db.execute('SELECT MIN(bucket) FROM hourly').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT MAX(bucket) FROM hourly').fetchone()[0],24*3600)
            self.assertEqual(db.execute('SELECT SUM(download),SUM(upload) FROM hourly').fetchone(),
                tuple(v*db.execute('SELECT COUNT(*) FROM hourly').fetchone()[0] for v in (20,10)))
            self.assertGreater(policy.pruned_hours,0)
            self.assertEqual(db.execute('SELECT mac FROM device_latest').fetchall(),[('mac',)])
            self.assertEqual(storage.read_limit(),4)
            db.close()

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
