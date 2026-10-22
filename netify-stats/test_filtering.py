"""Filtered reports must agree across rankings, totals, details and time buckets."""
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from netify_classify import Classifier
from netify_query import aggregate, normalize_filters
import netify_rpc as rpc
import netify_storage as storage
from netify_storage import compact_schema
from test_query import make_version_two

RULES = Path(__file__).parent / 'rules/community-rules.json'


def history(db):
    db.execute('''CREATE TABLE hourly (bucket INTEGER,mac TEXT,ip TEXT,application TEXT,
        protocol TEXT,host TEXT,upload INTEGER,download INTEGER,flows INTEGER,
        PRIMARY KEY(bucket,mac,ip,application,protocol,host)) WITHOUT ROWID''')
    rows = [
        (3600, 'a', '192.0.2.2', 'Unknown', 'TLS', 'chatgpt.com', 10, 20, 1),
        (7200, 'b', '192.0.2.3', 'Unknown', 'QUIC', 'api.openai.com', 30, 60, 2),
        (10800, 'a', '192.0.2.4', 'Unknown', 'TLS', 'unmatched.example', 40, 80, 3),
        (3600, 'a', '192.0.2.2', 'Unknown', 'TLS', '192.0.2.9', 50, 100, 4),
        (7200, 'b', '192.0.2.3', 'Unknown', 'TLS', '', 60, 120, 5),
        (7200, 'b', '192.0.2.3', 'Unknown', 'Unknown', '', 70, 140, 6),
        (7200, 'a', '192.0.2.4', 'netify.video-player', 'TLS', 'mixed.example', 80, 160, 7),
        (7200, 'a', '192.0.2.4', 'Unknown', 'TLS', 'www.weixin.qq.com', 90, 180, 8),
    ]
    rows += [(3600, 'b', '192.0.2.3', 'native.%02d' % index, 'HTTP', 'small.example', 1, 2, 1)
             for index in range(12)]
    db.executemany('INSERT INTO hourly VALUES (?,?,?,?,?,?,?,?,?)', rows)
    db.commit()
    return rows


class FilteringTest(unittest.TestCase):
    def query(self, db, **kwargs):
        options = dict(start=0, device='', now=14401, classifier=Classifier(RULES),
                       names={'a': 'Living room', '192.0.2.3': 'Laptop'},
                       latest_ips={'a': '192.0.2.4'}, app_page=1, device_page=1,
                       sort_key='total', direction='desc', expanded=[])
        options.update(kwargs)
        return aggregate(db, **options)

    def assert_consistent(self, result):
        for field in ('upload', 'download', 'flows'):
            self.assertEqual(sum(row[field] for row in result['classification_coverage'].values()),
                             result['total'][field])
            self.assertEqual(sum(row[field] for row in result['devices']), result['total'][field])
        for field in ('upload', 'download'):
            self.assertEqual(sum(row[field] for row in result['timeline']), result['total'][field])
        for app in result['applications']:
            if app['devices']:
                for field in ('upload', 'download', 'flows'):
                    self.assertEqual(sum(row[field] for row in app['devices']), app[field])

    def test_filters_apply_before_pagination_and_preserve_schema_parity(self):
        with sqlite3.connect(':memory:') as db:
            rows = history(db)
            cases = [
                ({'identification': 'protocol', 'expanded': ['protocol:tls']}, 110),
                ({'identification': 'unknown'}, 70),
                ({'identification': 'domain'}, 40),
                ({'search': ' OPENAI ', 'expanded': ['community:openai']}, 40),
                ({'search': 'ChAtGpT.CoM', 'expanded': ['community:openai']}, 10),
                ({'search': 'Video Player'}, 80),
                ({'search': '腾讯'}, 90),
                ({'application': 'community:openai', 'expanded': ['community:openai']}, 40),
                ({'application': 'community:openai', 'device': 'b', 'end': 7200}, 30),
                ({'application': 'community:openai', 'device': 'a', 'start': 7200}, 0),
                ({'identification': 'unknown', 'search': 'OPENAI'}, 0),
                ({'search': 'native.', 'app_page': 2}, 12),
                ({'search': "%_' OR 1=1 --"}, 0),
                ({'search': 'nothing matches'}, 0),
            ]
            reference = None
            for schema in (1, 2, 3):
                if schema == 2:
                    make_version_two(db)
                elif schema == 3:
                    compact_schema(db)
                results = []
                for options, upload in cases:
                    with self.subTest(schema=schema, options=options):
                        result = self.query(db, **options)
                        results.append(result)
                        self.assertEqual(result['total']['upload'], upload)
                        self.assert_consistent(result)
                        self.assertEqual(db.execute("SELECT COUNT(*) FROM sqlite_temp_master WHERE name='netify_selected_groups'").fetchone()[0], 0)
                        if options.get('app_page') == 2:
                            self.assertEqual(result['app_count'], 12)
                            self.assertEqual(len(result['applications']), 2)
                        self.assertEqual(result['device_choices'], [
                            {'mac': 'a', 'name': 'Living room', 'ip': '192.0.2.4'},
                            {'mac': 'b', 'name': 'Laptop', 'ip': '192.0.2.3'}])
                if reference is None:
                    reference = results
                else:
                    self.assertEqual(results, reference)
                # A filtered request must not affect later unfiltered requests.
                self.assertEqual(self.query(db)['total']['upload'], sum(row[6] for row in rows))
                self.assertEqual(sorted(map(tuple, db.execute('SELECT * FROM hourly'))), sorted(rows))

    def test_translated_application_names_search_without_rewriting_labels(self):
        with sqlite3.connect(':memory:') as db:
            history(db)
            for host, value in (('360buyimg.com', 21), ('huawei.com', 22),
                                ('bilibili.com', 23), ('shop.example', 24)):
                db.execute('INSERT INTO hourly VALUES (?,?,?,?,?,?,?,?,?)',
                           (3600, 'a', '192.0.2.2', 'Unknown', 'TLS', host, value, value*2, 1))
            compact_schema(db)
            for search, label, upload in (
                    ('JD.com', '京东', 21), ('京東', '京东', 21), ('華為', '华为', 22),
                    ('嗶哩嗶哩', '哔哩哔哩', 23), ('淘寶', '淘宝', 24), ('騰訊', '腾讯', 90)):
                with self.subTest(search=search):
                    classifier = Classifier(RULES)
                    classifier.rules['exact']['shop.example'] = ['taobao']
                    result = self.query(db, search=search, classifier=classifier)
                    self.assertEqual(result['total']['upload'], upload)
                    self.assertEqual([app['name'] for app in result['applications']], [label])
                    self.assert_consistent(result)

    def test_all_matching_and_empty_filters_keep_time_and_device_scope(self):
        with sqlite3.connect(':memory:') as db:
            history(db)
            compact_schema(db)
            # Check complete and partial matches under time/device scope.
            options = dict(device='b', start=7200, end=7200)
            before = self.query(db, **options)
            # App IDs are not enough: each host must match for this shortcut.
            all_data = self.query(db, search='Unknown', device='b', start=7200, end=7200,
                                  identification='unknown')
            self.assertEqual(all_data['total']['upload'], 70)
            all_native = self.query(db, application='netify.video-player', device='a',
                                    start=7200, end=7200)
            self.assertEqual(all_native['total']['upload'], 80)
            only_time = self.query(db, identification='domain', device='a', start=10800)
            self.assertEqual(only_time['total']['upload'], 40)
            self.assertEqual(only_time, self.query(db, device='a', start=10800))
            for result in (all_data, all_native, only_time):
                self.assert_consistent(result)
            empty = self.query(db, application='missing-application', **options)
            self.assertEqual(empty['total'], {'upload': 0, 'download': 0, 'flows': 0})
            self.assertEqual(empty['timeline'], [])
            self.assertEqual(empty['devices'], [])
            self.assertEqual(empty['device_choices'], before['device_choices'])

    def test_search_evidence_only_describes_matched_traffic(self):
        with sqlite3.connect(':memory:') as db:
            history(db)
            compact_schema(db)
            selected = self.query(db, search='CHATGPT.COM', expanded=['community:openai'])['applications'][0]
            self.assertEqual([host['name'] for host in selected['hosts']], ['chatgpt.com'])
            self.assertEqual({item['matched_domain'] for item in selected['classification_evidence']}, {'chatgpt.com'})
            selected = self.query(db, search='192.0.2.9', expanded=['protocol:tls'])['applications'][0]
            self.assertEqual(selected['upload'], 50)
            reasons = {item['reason'] for item in selected['classification_evidence']}
            self.assertEqual(reasons, {'ip_literal', 'protocol'})
            self.assertNotIn('missing_host', reasons)

    def test_legacy_null_dimensions_match_without_disappearing(self):
        with sqlite3.connect(':memory:') as db:
            db.execute('CREATE TABLE hourly (bucket,mac,ip,application,protocol,host,upload,download,flows)')
            db.execute('INSERT INTO hourly VALUES (3600,"a","192.0.2.2",NULL,NULL,NULL,1,2,1)')
            db.execute('INSERT INTO hourly VALUES (3600,"a","192.0.2.2","native.test","TLS","known.example",10,20,1)')
            result = self.query(db, identification='unknown')
            self.assertEqual(result['total'], {'upload': 1, 'download': 2, 'flows': 1})
            self.assert_consistent(result)

    def test_temp_selection_is_bounded_in_parameters_and_cleans_up_on_failure(self):
        with sqlite3.connect(':memory:') as db:
            history(db)
            db.executemany('INSERT INTO hourly VALUES (?,?,?,?,?,?,?,?,?)', [
                (3600, 'a', '192.0.2.2', 'Unknown', 'TLS', 'host%d.unique.example' % index, 1, 2, 1)
                for index in range(1200)])
            compact_schema(db)
            old_limit = db.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 100)
            try:
                result = self.query(db, identification='domain')
                self.assertEqual(result['total']['upload'], 1240)
                self.assertEqual(result['app_count'], 1201)
                classifier = Classifier(RULES)
                original = classifier.classify
                count = 0
                def failing(*args):
                    nonlocal count
                    count += 1
                    if count == 300:
                        raise RuntimeError('classification failed')
                    return original(*args)
                classifier.classify = failing
                with self.assertRaisesRegex(RuntimeError, 'classification failed'):
                    self.query(db, identification='domain', classifier=classifier)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM sqlite_temp_master WHERE name='netify_selected_groups'").fetchone()[0], 0)
                self.assertEqual(db.execute('PRAGMA temp.cache_size').fetchone()[0], -256)
            finally:
                db.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, old_limit)

    def test_rpc_filters_work_on_read_only_history_and_normalize_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'stats.db')
            with sqlite3.connect(path) as db:
                history(db)
                compact_schema(db)
            with patch.object(rpc, 'DB_PATH', path), \
                    patch.object(storage, 'CONFIG_PATH', str(Path(directory) / 'absent.json')), \
                    patch.object(rpc, 'Classifier', side_effect=lambda: Classifier(RULES)), \
                    patch.object(rpc.time, 'time', return_value=14401):
                result = rpc.query_summary({'identification': 'application', 'search': ' OpenAI ', 'application': 'community:openai'})
                self.assertEqual(result['search'], 'OpenAI')
                self.assertEqual(result['identification'], 'application')
                self.assertEqual(result['application'], 'community:openai')
                self.assertEqual(result['total']['upload'], 40)
                invalid = rpc.query_summary({'identification': ['protocol'], 'search': 123, 'application': {}})
                self.assertEqual((invalid['identification'], invalid['search'], invalid['application']), ('', '', ''))
                self.assertEqual(invalid['total']['upload'], 442)
            with sqlite3.connect(path) as db:
                self.assertFalse(db.execute("SELECT name FROM sqlite_master WHERE name='netify_selected_groups'").fetchall())
            self.assertEqual(normalize_filters('all', ' a ', None), ('', 'a', ''))
            self.assertEqual(tuple(map(len, normalize_filters('', 's'*300, 'a'*1000))), (0, 128, 512))

    def test_unfiltered_requests_do_not_create_scratch_tables(self):
        with sqlite3.connect(':memory:') as db:
            history(db)
            compact_schema(db)
            statements = []
            db.set_trace_callback(statements.append)
            self.query(db)
            self.assertFalse(any('TEMP' in sql.upper() for sql in statements))


if __name__ == '__main__':
    unittest.main()
