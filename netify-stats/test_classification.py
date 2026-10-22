"""Recognition coverage must improve without inventing application identities."""
from pathlib import Path
import sqlite3
import tempfile
import unittest

from build_rules import REVIEWED_DLC_SERVICES, add_reviewed_dlc
from netify_classify import Classifier, PROTOCOL_ALIASES
from netify_query import aggregate
from netify_storage import compact_schema
from test_query import make_version_two

RULES = Path(__file__).parent / 'rules/community-rules.json'


class ClassificationTest(unittest.TestCase):
    def test_expanded_domains_match_services_without_matching_lookalikes(self):
        classifier = Classifier(RULES)
        cases = {'api.kimi.com': 'kimi', 'moonshot.ai': 'kimi',
                 'qwen.ai': 'qwen', 'chatglm.cn': 'zhipu', 'minimax.io': 'minimax',
                 'midjourney.com': 'midjourney', 'ollama.com': 'ollama',
                 'api.mistral.ai': 'mistral', 'openrouter.ai': 'openrouter',
                 'lmstudio.ai': 'lmstudio', 'dify.ai': 'dify', 'klingai.com': 'kling'}
        for host, tag in cases.items():
            with self.subTest(host=host):
                self.assertEqual(classifier.classify('Unknown', host, 'TLS'), 'community:' + tag)
                self.assertEqual(classifier.classify('netify.native', host, 'TLS'), 'netify.native')
                self.assertEqual(classifier.classify('Unknown', host + '.evil.example', 'TLS'),
                                 'domain:' + host + '.evil.example')
        self.assertEqual(classifier.classify('Unknown', 'notkimi.com', 'TLS'), 'domain:notkimi.com')

    def test_reviewed_category_import_is_explicit_and_preserves_conflicts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'data').mkdir()
            for filename, services in REVIEWED_DLC_SERVICES.items():
                domains = [domain for _, values in services.values() for domain in values]
                (root / 'data' / filename).write_text('\n'.join(domains + [
                    'unreviewed.example', 'include:parent', 'regexp:.*', 'cloudfront.net']))
            suffix = {'kimi.com': {'old', 'ambiguous'}, 'protected.ollama.com': {'tenant'}}
            exact = {'mistral.ai': {'exact-owner'}}
            added = add_reviewed_dlc(root, exact, suffix, {})
            self.assertEqual(suffix['kimi.com'], {'old', 'ambiguous'})
            self.assertNotIn('ollama.com', suffix)
            self.assertEqual(exact['mistral.ai'], {'exact-owner'})
            self.assertNotIn('unreviewed.example', suffix)
            self.assertNotIn('cloudfront.net', suffix)
            self.assertEqual(suffix['openrouter.ai'], {'openrouter'})
            self.assertEqual(added['openrouter.ai'], 'category-ai-!cn')
            path = root / 'data/category-ai-!cn'
            path.write_text(path.read_text().replace('openrouter.ai', 'removed.example'))
            with self.assertRaisesRegex(ValueError, 'reviewed domain missing'):
                add_reviewed_dlc(root, {}, {}, {})

    def test_observed_protocol_fallback_does_not_claim_application_identity(self):
        classifier = Classifier(RULES)
        for category, aliases in PROTOCOL_ALIASES.items():
            for alias in aliases:
                with self.subTest(alias=alias):
                    key = classifier.classify(' unknown ', '192.0.2.1', alias.upper())
                    self.assertEqual(key, 'protocol:' + category)
                    detail = classifier.describe_metadata(key)
                    self.assertEqual(detail['identification_level'], 'protocol')
                    self.assertFalse(detail['application_identified'])
                    self.assertLessEqual(len(detail['classification_evidence']), 5)
        for protocol in ('Unknown', 'Unclassified', 'tcp/443', 'probably youtube', '', None, 443):
            self.assertEqual(classifier.classify('Unknown', '192.0.2.1', protocol), 'Unknown')
        self.assertEqual(classifier.classify('Unknown', 'unmatched.example', 'TLS'), 'domain:unmatched.example')
        self.assertEqual(classifier.classify('native.app', '192.0.2.1', 'DNS'), 'native.app')
        classifier.rules['suffix']['shared.example'] = ['one', 'two']
        self.assertEqual(classifier.classify('Unknown', 'shared.example', 'HTTP'), 'domain:shared.example')
        for index in range(1000):
            classifier.classify('Unknown', '198.18.%d.%d' % (index // 256, index % 256),
                                'unrecognized-protocol-%d' % index)
        self.assertLessEqual(len(classifier._fallbacks), 64)
        self.assertLessEqual(len(classifier.app_evidence), len(PROTOCOL_ALIASES) + 1)
        # Rules unavailable does not prevent categorizing an observed protocol.
        with tempfile.TemporaryDirectory() as directory:
            missing = Classifier(Path(directory) / 'absent.json')
            self.assertTrue(missing.error)
            self.assertEqual(missing.classify('Unknown', '2001:db8::1', 'WireGuard'), 'protocol:vpn')

    def test_shared_infrastructure_is_not_counted_as_an_identified_app(self):
        classifier = Classifier(RULES)
        for host, provider in (('tenant.cloudfront.net', 'aws'), ('bucket.s3.amazonaws.com', 'aws'),
                               ('tenant.workers.dev', 'cloudflare'), ('tenant.azurewebsites.net', 'azure'),
                               ('tenant.akamaized.net', 'akamai'), ('tenant.myqcloud.com', 'qcloud')):
            with self.subTest(host=host):
                key = classifier.classify('Unknown', host, 'TLS')
                self.assertEqual(key, 'infrastructure:' + provider)
                detail = classifier.describe_metadata(key)
                self.assertEqual(detail['identification_level'], 'domain')
                self.assertFalse(detail['application_identified'])
                self.assertEqual(detail['classification_evidence'][0]['reason'], 'infrastructure')
        classifier.rules['exact']['known.cloudfront.net'] = ['specific-service']
        self.assertEqual(classifier.classify('Unknown', 'known.cloudfront.net'), 'community:specific-service')
        self.assertEqual(classifier.classify('netify.video', 'tenant.cloudfront.net'), 'netify.video')

    def test_protocol_groups_and_coverage_preserve_totals_across_schemas(self):
        with sqlite3.connect(':memory:') as db:
            db.execute('''CREATE TABLE hourly (bucket INTEGER,mac TEXT,ip TEXT,application TEXT,
                protocol TEXT,host TEXT,upload INTEGER,download INTEGER,flows INTEGER,
                PRIMARY KEY(bucket,mac,ip,application,protocol,host)) WITHOUT ROWID''')
            rows = [(3600, mac, '192.0.2.2', native, protocol, host, value, value*2, 1)
                    for mac, value in (('a', 10), ('b', 20))
                    for native, protocol, host in (
                        ('Unknown', 'TLS', '192.0.2.1'), ('Unknown', 'DNS', '192.0.2.1'),
                        ('Unknown', 'QUIC', 'Unknown'), ('Unknown', 'Unknown', '192.0.2.1'),
                        ('Unknown', 'TLS', 'unmatched.example'), ('Unknown', 'TLS', 'api.kimi.com'),
                        ('Unknown', 'TLS', 'tenant.cloudfront.net'))]
            # More than a ranked page: coverage must include hidden rows too.
            rows += [(3600, 'a', '192.0.2.2', 'native.%d' % i, 'TLS', 'known.example', 1, 2, 1)
                     for i in range(12)]
            db.executemany('INSERT INTO hourly VALUES (?,?,?,?,?,?,?,?,?)', rows)
            db.commit()
            responses = []
            for schema in (1, 2, 3):
                if schema == 2:
                    make_version_two(db)
                elif schema == 3:
                    compact_schema(db)
                result = aggregate(db, 0, '', 7201, Classifier(RULES), {}, {},
                                   1, 1, 'total', 'desc', ['protocol:tls', 'protocol:dns'])
                responses.append(result)
                coverage = result['classification_coverage']
                self.assertEqual({key: value['upload'] for key, value in coverage.items()},
                                 {'application': 42, 'domain': 60, 'protocol': 90, 'unknown': 30})
                for field in ('upload', 'download', 'flows'):
                    self.assertEqual(sum(group[field] for group in coverage.values()), result['total'][field])
                for key in ('protocol:tls', 'protocol:dns'):
                    app = next(app for app in result['applications'] if app['id'] == key)
                    self.assertEqual(app['upload'], 30)
                    self.assertEqual({device['mac']: device['upload'] for device in app['devices']}, {'a': 10, 'b': 20})
                filtered = aggregate(db, 0, 'b', 7201, Classifier(RULES), {}, {},
                                     1, 1, 'total', 'desc', [], end=3600)
                self.assertEqual(filtered['classification_coverage']['protocol']['upload'], 60)
                empty = aggregate(db, 7200, '', 10800, Classifier(RULES), {}, {},
                                  1, 1, 'total', 'desc', [])
                self.assertTrue(all(group['upload'] == 0 for group in empty['classification_coverage'].values()))
            self.assertEqual(responses[0], responses[1])
            self.assertEqual(responses[1], responses[2])
            self.assertEqual(sorted(map(tuple, db.execute('SELECT * FROM hourly'))), sorted(rows))


if __name__ == '__main__':
    unittest.main()
