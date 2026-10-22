"""Classification, compact/legacy aggregation and failed-read cleanup checks."""
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from netify_classify import Classifier
from netify_query import aggregate
import netify_rpc as rpc
import netify_storage as storage
import netify_control as control
from netify_storage import compact_schema


RULES = Path(__file__).parent / 'rules/community-rules.json'


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


class QueryTest(unittest.TestCase):
    def create_history(self, path):
        db = sqlite3.connect(path)
        db.execute('''CREATE TABLE hourly (
            bucket INTEGER,mac TEXT,ip TEXT,application TEXT,protocol TEXT,host TEXT,
            upload INTEGER,download INTEGER,flows INTEGER,
            PRIMARY KEY(bucket,mac,ip,application,protocol,host)) WITHOUT ROWID''')
        db.executemany('INSERT INTO hourly VALUES (?,?,?,?,?,?,?,?,?)', [
            (bucket, 'mac', '192.0.2.2', 'netify.test', 'TLS', 'example.com', value, value*2, 1)
            for bucket, value in ((3600, 10), (7200, 20), (10800, 30))])
        db.execute('''CREATE TABLE interface_hourly (
            bucket INTEGER,name TEXT,download INTEGER,upload INTEGER,
            since INTEGER,until INTEGER,resets INTEGER DEFAULT 0,PRIMARY KEY(bucket,name))''')
        db.executemany('INSERT INTO interface_hourly VALUES (?,?,?,?,?,?,?)', [
            (bucket, 'wan', value*2, value, bucket, bucket+1, 0)
            for bucket, value in ((3600, 100), (7200, 200), (10800, 300))])
        db.commit()
        return db

    def test_bad_settings_preserve_history_and_expose_unknown_values(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'settings.json'
            path = str(Path(directory) / 'stats.db')
            self.create_history(path).close()
            cases = [
                ('{broken', None, None, None),
                ('[]', None, None, None),
                ('{"enabled":"true","interface":"wan","max_storage_mib":16}', None, 'wan', 16),
                ('{"enabled":false,"interface":42,"max_storage_mib":16}', False, None, 16),
                ('{"enabled":true,"interface":"wan","max_storage_mib":"16"}', True, 'wan', None),
            ]
            with patch.object(storage, 'CONFIG_PATH', str(config)), \
                    patch.object(rpc, 'DB_PATH', path), \
                    patch.object(control, 'runtime_state', return_value=(False, False)), \
                    patch.object(rpc.time, 'time', return_value=14401):
                for document, enabled, interface, limit in cases:
                    with self.subTest(document=document):
                        config.write_text(document)
                        result = rpc.query_summary({})
                        self.assertEqual(result['total']['download'], 120)
                        self.assertTrue(result['config_error'])
                        self.assertEqual(result['enabled'], enabled)
                        self.assertEqual(result['selected_interface'], interface)
                        self.assertEqual(result['storage']['max_storage_mib'], limit)
                        if enabled is None:
                            self.assertEqual(result['control']['actual_state'], 'unknown')
                            self.assertFalse(result['control']['applied'])
                        self.assertEqual(config.read_text(), document)
                config.write_text('{"enabled":false,"interface":"wan","max_storage_mib":16}')
                result = rpc.query_summary({})
                self.assertEqual(result['config_error'], '')
                self.assertTrue(result['control']['applied'])
                self.assertEqual(result['active_interfaces'], ['wan'])

    def test_clock_rollback_uses_consistent_ranges_for_history_and_interfaces(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'stats.db')
            db = self.create_history(path)
            with patch.object(rpc, 'DB_PATH', path), \
                    patch.object(storage, 'CONFIG_PATH', str(Path(directory) / 'absent.json')), \
                    patch.object(rpc.time, 'time', return_value=7201):
                for compact in (False, True):
                    with self.subTest(compact=compact):
                        if compact:
                            compact_schema(db)
                        all_data = rpc.query_summary({'expanded': '["netify.test"]'})
                        recent = rpc.query_summary({'hours': 1, 'expanded': '["netify.test"]'})
                        self.assertTrue(all_data['clock_anomaly'])
                        self.assertTrue(recent['clock_anomaly'])
                        self.assertTrue(all_data['clock_warning'])
                        self.assertEqual(all_data['total']['download'], 120)
                        self.assertEqual(recent['total']['download'], 60)
                        self.assertEqual(all_data['interfaces'][0]['download'], 1200)
                        self.assertEqual(recent['interfaces'][0]['download'], 600)
                        self.assertEqual(all_data['range_end'], 10800)
                        self.assertEqual(recent['range_end'], 7201)
                        for result in (all_data, recent):
                            self.assertEqual(sum(row['download'] for row in result['timeline']),
                                             result['total']['download'])
                            app = result['applications'][0]
                            self.assertEqual(app['download'], result['total']['download'])
                            self.assertEqual(app['devices'][0]['download'], app['download'])
                            self.assertLessEqual(len(result['timeline']), 24)
                with patch.object(rpc.time, 'time', return_value=14401):
                    self.assertFalse(rpc.query_summary({})['clock_anomaly'])
            db.close()

    def test_all_history_with_only_future_buckets_keeps_timeline_bytes(self):
        with sqlite3.connect(':memory:') as db:
            db.execute('''CREATE TABLE hourly (
                bucket INTEGER,mac TEXT,ip TEXT,application TEXT,protocol TEXT,host TEXT,
                upload INTEGER,download INTEGER,flows INTEGER)''')
            db.execute('INSERT INTO hourly VALUES (?,?,?,?,?,?,?,?,?)',
                       (10800, 'mac', 'ip', 'netify.test', 'TLS', 'example.com', 10, 20, 1))
            result = aggregate(db, 0, '', 7201, Classifier(RULES), {}, {},
                               1, 1, 'total', 'desc', [])
            self.assertEqual(result['timeline'], [{'bucket': 10800, 'download': 20, 'upload': 10}])
            bounded = aggregate(db, 3600, '', 7201, Classifier(RULES), {}, {},
                                1, 1, 'total', 'desc', [], end=7200)
            self.assertEqual(bounded['total']['download'], 0)
            self.assertEqual(bounded['timeline'], [])

    def test_domain_cache_keeps_native_and_ip_semantics(self):
        classifier = Classifier(RULES)
        cases = {
            '1.2.3.4': 'Unknown',
            '001.2.3.4': 'domain:001.2.3.4',
            '256.2.3.4': 'domain:256.2.3.4',
            '1.2.3.4.example': 'domain:1.2.3.4.example',
            '2001:db8::1': 'Unknown',
            '::ffff:192.0.2.1': 'Unknown',
            'not a.domain': 'Unknown',
            '': 'Unknown',
            ' CHATGPT.COM. ': 'community:openai',
        }
        for host, expected in cases.items():
            self.assertEqual(classifier.classify('Unknown', host), expected)
            self.assertEqual(classifier.classify('netify.native', host), 'netify.native')
        classifier.classify('Unclassified', 'chatgpt.com')
        self.assertEqual(classifier._classify_domain.cache_info().currsize, 4)
        self.assertEqual(classifier._classify_domain.cache_info().hits, 1)

    def test_invalid_rule_document_preserves_native_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'rules.json'
            for document in ([], None, 'wrong', {'schema': 1}):
                path.write_text(json.dumps(document))
                classifier = Classifier(path)
                self.assertTrue(classifier.error)
                self.assertEqual(classifier.classify('netify.native', 'example.com'), 'netify.native')
                self.assertEqual(classifier.classify('Unknown', 'example.com'), 'domain:example.com')

    def test_legacy_v2_and_v3_hour_device_grouping_agree(self):
        with sqlite3.connect(':memory:') as db:
            db.execute('''CREATE TABLE hourly (
                bucket INTEGER,mac TEXT,ip TEXT,application TEXT,protocol TEXT,host TEXT,
                upload INTEGER,download INTEGER,flows INTEGER,
                PRIMARY KEY(bucket,mac,ip,application,protocol,host)) WITHOUT ROWID''')
            rows = []
            for hour in (3600, 7200, 14400):
                for device in range(13):
                    rows.append((hour, 'mac%02d' % device, 'old-ip', 'Unknown', 'TLS',
                                 'chatgpt.com', hour + device, device + 1, 1))
                    rows.append((hour, 'mac%02d' % device, 'new-ip', 'netify.test', 'TLS',
                                 'host%d.example' % device, 10, 30, 1))
            db.executemany('INSERT INTO hourly VALUES (?,?,?,?,?,?,?,?,?)', rows)
            params = [(0, '', 1, 'total', 'desc'), (7200, '', 2, 'upload', 'asc'),
                      (0, 'mac02', 1, 'download', 'desc'), (0, 'old-ip', 1, 'flows', 'asc')]

            def results():
                return [aggregate(db, start, device, 18000, Classifier(RULES), {}, {}, 1, page,
                                  metric, direction, ['community:openai', 'netify.test'])
                        for start, device, page, metric, direction in params]

            original = results()
            make_version_two(db)
            self.assertEqual(results(), original)
            compact_schema(db)
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 3)
            self.assertIn('host_id', {row[1] for row in db.execute('PRAGMA table_info(hourly_data)')})
            self.assertEqual(results(), original)
            for result in original:
                for metric in ('upload', 'download'):
                    self.assertEqual(sum(row[metric] for row in result['timeline']), result['total'][metric])
                for app in result['applications']:
                    self.assertEqual(sum(row['download'] for row in app['devices']), app['download'])
                    self.assertLessEqual(len(app['hosts']), 5)
                    self.assertEqual(app['source_type'], 'community' if app['id'].startswith('community:') else 'native')
                    self.assertIn('name_i18n', app)
                    self.assertIsInstance(app['source_names'], list)

    def test_v3_shared_hosts_keep_native_and_supplemental_groups_separate(self):
        with sqlite3.connect(':memory:') as db:
            db.execute('''CREATE TABLE hourly (
                bucket INTEGER,mac TEXT,ip TEXT,application TEXT,protocol TEXT,host TEXT,
                upload INTEGER,download INTEGER,flows INTEGER,
                PRIMARY KEY(bucket,mac,ip,application,protocol,host)) WITHOUT ROWID''')
            rows = [
                (3600, 'one', '192.0.2.1', 'Unknown', 'TLS', 'chatgpt.com', 10, 20, 1),
                (7200, 'one', '192.0.2.1', 'Unclassified', 'QUIC', 'chatgpt.com', 30, 40, 1),
                (7200, 'two', '192.0.2.2', 'netify.native', 'TLS', 'chatgpt.com', 50, 60, 1),
                (10800, 'two', '192.0.2.2', 'Unknown', 'TLS', 'api.openai.com', 70, 80, 1),
                (10800, 'two', '192.0.2.2', 'Unknown', 'TLS', '1.2.3.4', 90, 100, 1),
            ]
            db.executemany('INSERT INTO hourly VALUES (?,?,?,?,?,?,?,?,?)', rows)

            def query(device='', end=None):
                return aggregate(db, 0, device, 14400, Classifier(RULES), {}, {}, 1, 1,
                                 'total', 'desc', ['community:openai', 'netify.native', 'Unknown'], end=end)

            before = [query(), query('one'), query(end=7200)]
            compact_schema(db)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM traffic_hosts').fetchone()[0], 3)
            self.assertEqual([query(), query('one'), query(end=7200)], before)
            apps = {item['id']: item for item in query()['applications']}
            self.assertEqual(apps['community:openai']['download'], 140)
            self.assertEqual(apps['community:openai']['hosts'], [
                {'name': 'api.openai.com', 'upload': 70, 'download': 80, 'flows': 1},
                {'name': 'chatgpt.com', 'upload': 40, 'download': 60, 'flows': 2},
            ])
            self.assertEqual(apps['netify.native']['download'], 60)

    def test_failed_query_closes_snapshot_even_with_retained_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'stats.db')
            db = sqlite3.connect(path)
            db.execute('CREATE TABLE hourly (bucket INTEGER)')
            db.commit()
            with patch.object(rpc, 'DB_PATH', path), \
                    patch.object(rpc.sqlite3, 'connect', return_value=db), \
                    patch.object(rpc, 'aggregate', side_effect=RuntimeError('query failed')):
                with self.assertRaisesRegex(RuntimeError, 'query failed'):
                    rpc.query_summary({})
            with self.assertRaises(sqlite3.ProgrammingError):
                db.execute('SELECT 1')


if __name__ == '__main__':
    unittest.main()
