"""Guard conservative supplemental matching and rule-source attribution."""
import json
from pathlib import Path
import tempfile
import unittest

from build_rules import NEXTDNS_ALLOWLIST, add_nextdns, source_revision
from netify_classify import APP_NAME_MSGIDS, Classifier


RULES = Path(__file__).parent / 'rules/community-rules.json'


class RulesTest(unittest.TestCase):
    def fixture(self, directory):
        source = Path(directory)
        (source / 'services').mkdir()
        for service, (_, domains) in NEXTDNS_ALLOWLIST.items():
            (source / 'services' / service).write_text('\n'.join(domains) +
                '\nshared.example\n_thing._tcp.local\nxboxlive.xom\nads.example\n')
        return source

    def test_supplements_require_allowlist_and_keep_existing_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.fixture(directory)
            exact = {'9gag.com': {'original'}, 'protected.9cache.com': {'original'}}
            suffix = {'tinder.com': {'one', 'two'}}
            extra = add_nextdns(source, exact, suffix, {})
            self.assertEqual(exact['9gag.com'], {'original'})
            self.assertNotIn('9gag.com', extra)
            self.assertNotIn('9cache.com', extra)
            self.assertEqual(suffix['tinder.com'], {'one', 'two'})
            self.assertNotIn('tinder.com', extra)
            self.assertNotIn('shared.example', suffix)
            self.assertNotIn('ads.example', suffix)
            self.assertNotIn('xboxlive.xom', suffix)
            self.assertNotIn('_thing._tcp.local', suffix)
            self.assertEqual(suffix['sc-prod.net'], {'snap'})

    def test_missing_reviewed_domain_requires_new_review(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.fixture(directory)
            (source / 'services' / '9gag').write_text('9gag.com\n')
            with self.assertRaisesRegex(ValueError, 'reviewed domain missing'):
                add_nextdns(source, {}, {}, {})
            with self.assertRaises(ValueError):
                source_revision(source, 'main')

    def test_source_tooltip_uses_observed_matches_and_native_stays_first(self):
        classifier = Classifier(RULES)
        self.assertEqual(classifier.error, '')
        native = classifier.classify('netify.native', '9gag.com')
        self.assertEqual(native, 'netify.native')
        self.assertEqual(classifier.describe(native)[1], 'Netify 原生识别')
        app = classifier.classify('Unknown', 'api.bereal.com')
        self.assertEqual(app, 'community:bereal')
        self.assertEqual(classifier.describe(app)[1], '社区域名规则（NextDNS services）')
        hits = classifier._classify_domain.cache_info().hits
        self.assertEqual(classifier.classify('Unclassified', 'API.BEREAL.COM.'), app)
        self.assertEqual(classifier._classify_domain.cache_info().hits, hits + 1)
        self.assertEqual(classifier.describe(app)[1], '社区域名规则（NextDNS services）')
        app = classifier.classify('Unknown', 'pinterest.com')
        self.assertEqual(classifier.describe(app)[1], '社区域名规则（DLC）')
        self.assertEqual(classifier.classify('Unknown', 'pinterest.biz'), app)
        self.assertEqual(classifier.describe(app)[1], '社区域名规则（DLC / NextDNS services）')
        self.assertEqual(classifier.describe_metadata(app), {
            'name_i18n': '', 'source_type': 'community',
            'source_names': ['DLC', 'NextDNS services'],
        })
        self.assertEqual(classifier.classify('Unknown', 'bereal.com.evil.example'),
                         'domain:bereal.com.evil.example')
        self.assertEqual(classifier.classify('Unknown', 'notbereal.com'), 'domain:notbereal.com')
        sources = {source['id']: source for source in classifier.rules['sources']}
        self.assertEqual(sources['nextdns-services']['license'], 'MIT')
        self.assertTrue((RULES.parent / sources['nextdns-services']['license_file']).is_file())

    def test_translation_metadata_preserves_labels_and_application_identity(self):
        classifier = Classifier(RULES)
        labels_before = dict(classifier.rules['labels'])
        localized_tags = {tag for tag, name in labels_before.items() if not name.isascii()}
        self.assertEqual(localized_tags, set(APP_NAME_MSGIDS))
        for tag in localized_tags:
            key = 'community:' + tag
            metadata = classifier.describe_metadata(key)
            self.assertEqual(metadata['source_type'], 'community')
            self.assertTrue(metadata['name_i18n'].isascii())
            self.assertTrue(metadata['name_i18n'])
            self.assertEqual(classifier.describe(key)[0], labels_before[tag])
        self.assertEqual(classifier.rules['labels'], labels_before)
        self.assertEqual(classifier.classify('Unknown', 'v95-aw-cold.douyinvod.com'), 'community:douyin')
        self.assertEqual(classifier.describe_metadata('Unknown'), {
            'name_i18n': 'Unknown destination', 'source_type': 'unknown', 'source_names': [],
        })
        self.assertEqual(classifier.describe_metadata('domain:example.com'), {
            'name_i18n': '', 'source_type': 'domain', 'source_names': [],
        })
        self.assertEqual(classifier.describe_metadata('netify.native'), {
            'name_i18n': '', 'source_type': 'native', 'source_names': [],
        })

    def test_malformed_provenance_falls_back_without_interrupting_summary(self):
        rules = json.loads(RULES.read_text())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bad.json'
            rules['default_rule_source'] = []
            path.write_text(json.dumps(rules))
            classifier = Classifier(path)
            self.assertTrue(classifier.error)
            self.assertEqual(classifier.classify('Unknown', 'bereal.com'), 'domain:bereal.com')


if __name__ == '__main__':
    unittest.main()
