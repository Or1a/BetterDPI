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
from netify_storage import compact_schema


RULES = Path(__file__).parent / 'rules/community-rules.json'


class QueryTest(unittest.TestCase):
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

    def test_compact_and_legacy_hour_device_grouping_agree(self):
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
            classifier = Classifier(RULES)
            params = [(0, '', 1, 'total', 'desc'), (7200, '', 2, 'upload', 'asc'),
                      (0, 'mac02', 1, 'download', 'desc'), (0, 'old-ip', 1, 'flows', 'asc')]

            def results():
                return [aggregate(db, start, device, 18000, classifier, {}, {}, 1, page,
                                  metric, direction, ['community:openai', 'netify.test'])
                        for start, device, page, metric, direction in params]

            original = results()
            compact_schema(db)
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
