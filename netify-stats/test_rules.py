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
            'classification_evidence': [
                {'reason': 'community', 'matched_domain': 'pinterest.biz', 'rule_type': 'suffix',
                 'source_id': 'nextdns-services', 'source_name': 'NextDNS services'},
                {'reason': 'community', 'matched_domain': 'pinterest.com', 'rule_type': 'suffix',
                 'source_id': 'dlc', 'source_name': 'DLC'},
            ],
            'classification_evidence_truncated': False,
            'identification_level': 'application', 'application_identified': True,
            'detection_reason': 'community_rule',
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
            'classification_evidence': [], 'classification_evidence_truncated': False,
            'identification_level': 'unknown', 'application_identified': False,
            'detection_reason': 'insufficient_metadata',
        })
        self.assertEqual(classifier.describe_metadata('domain:example.com'), {
            'name_i18n': '', 'source_type': 'domain', 'source_names': [],
            'classification_evidence': [{'reason': 'unmatched_domain'}],
            'classification_evidence_truncated': False,
            'identification_level': 'domain', 'application_identified': False,
            'detection_reason': 'unmatched_domain',
        })
        self.assertEqual(classifier.describe_metadata('netify.native'), {
            'name_i18n': '', 'source_type': 'native', 'source_names': [],
            'classification_evidence': [{'reason': 'native'}],
            'classification_evidence_truncated': False,
            'identification_level': 'application', 'application_identified': True,
            'detection_reason': 'native_app',
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
            self.assertEqual(classifier.describe_metadata('domain:bereal.com')['classification_evidence'],
                             [{'reason': 'rules_unavailable'}])

    def test_evidence_explains_exact_suffix_and_ambiguous_matches(self):
        classifier = Classifier(RULES)
        classifier.rules['exact']['specific.service.example'] = ['specific']
        classifier.rules['exact']['shared.service.example'] = ['one', 'two']
        classifier.rules['suffix']['service.example'] = ['parent']
        for host, expected, rule_type, matched in (
                ('SPECIFIC.SERVICE.EXAMPLE.', 'community:specific', 'exact', 'specific.service.example'),
                ('api.service.example', 'community:parent', 'suffix', 'service.example'),
                ('shared.service.example', 'domain:shared.service.example', 'exact', 'shared.service.example')):
            self.assertEqual(classifier.classify('Unknown', host), expected)
            evidence = classifier.describe_metadata(expected)['classification_evidence'][0]
            self.assertEqual((evidence['rule_type'], evidence['matched_domain']), (rule_type, matched))
            self.assertEqual((evidence['source_id'], evidence['source_name']), ('dlc', 'DLC'))
            if expected.startswith('domain:'):
                self.assertEqual(evidence['reason'], 'ambiguous')
                self.assertEqual(evidence['candidates'], ['one', 'two'])
                self.assertEqual(evidence['candidate_count'], 2)
            else:
                self.assertEqual(evidence['reason'], 'community')
        before = classifier._classify_domain.cache_info()
        self.assertEqual(classifier.classify('netify.native', 'shared.service.example'), 'netify.native')
        self.assertEqual(classifier.describe_metadata('netify.native')['classification_evidence'],
                         [{'reason': 'native'}])
        self.assertEqual(classifier._classify_domain.cache_info(), before)

    def test_community_evidence_is_deduplicated_and_bounded(self):
        classifier = Classifier(RULES)
        for index in range(8):
            classifier.rules['suffix'][f'service{index}.example'] = ['service']
        for index in range(8):
            for child in range(20):
                self.assertEqual(classifier.classify('Unknown', f'api{child}.service{index}.example'),
                                 'community:service')
        metadata = classifier.describe_metadata('community:service')
        self.assertEqual(len(metadata['classification_evidence']), 5)
        self.assertTrue(metadata['classification_evidence_truncated'])
        self.assertEqual(len({item['matched_domain'] for item in metadata['classification_evidence']}), 5)
        self.assertEqual(len(classifier.app_evidence['community:service']), 5)
        # Cache hits should not create duplicate observations or retain an
        # unbounded per-host evidence map alongside the domain lookup cache.
        for _ in range(10):
            classifier.classify('Unknown', 'api0.service0.example')
        self.assertEqual(classifier.describe_metadata('community:service'), metadata)
        metadata['classification_evidence'][0]['matched_domain'] = 'changed.example'
        self.assertNotIn('changed.example', [item['matched_domain'] for item in
                         classifier.describe_metadata('community:service')['classification_evidence']])

    def test_unknown_reasons_do_not_retain_raw_addresses_or_invalid_hosts(self):
        classifier = Classifier(RULES)
        for host in ('', 'Unknown', '192.0.2.1', '2001:db8::1', '::ffff:192.0.2.1',
                     'bad:address', '2001:db8::1\x00', 'not a.hostname', 'a' * 254):
            self.assertEqual(classifier.classify('Unknown', host), 'Unknown')
        self.assertEqual(classifier.describe_metadata('Unknown')['classification_evidence'], [
            {'reason': 'invalid_host'}, {'reason': 'ip_literal'}, {'reason': 'missing_host'}])
        for index in range(1000):
            host = f'unmatched{index}.example'
            self.assertEqual(classifier.classify('Unknown', host), 'domain:' + host)
        self.assertEqual(set(classifier.app_evidence), {'Unknown'})
        self.assertEqual(classifier.describe_metadata('domain:unmatched999.example')['classification_evidence'],
                         [{'reason': 'unmatched_domain'}])

    def test_evidence_samples_do_not_depend_on_sql_scan_order(self):
        outputs = []
        for order in (range(8), reversed(range(8)), (3, 7, 1, 6, 0, 5, 2, 4)):
            classifier = Classifier(RULES)
            for index in range(8):
                classifier.rules['suffix'][f'service{index}.example'] = ['service']
            for index in order:
                classifier.classify('Unknown', f'api.service{index}.example')
            outputs.append(classifier.describe_metadata('community:service'))
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(outputs[0], outputs[2])
        self.assertTrue(outputs[0]['classification_evidence_truncated'])

    def test_ambiguous_candidate_payload_is_bounded_and_independent(self):
        classifier = Classifier(RULES)
        candidates = [f'app{index}' for index in range(8)]
        classifier.rules['suffix']['shared.example'] = candidates
        app = classifier.classify('Unknown', 'api.shared.example')
        self.assertEqual(app, 'domain:api.shared.example')
        evidence = classifier.describe_metadata(app)['classification_evidence'][0]
        self.assertEqual(evidence['candidate_count'], 8)
        self.assertEqual(evidence['candidates'], candidates[:5])
        evidence['candidates'].append('changed')
        self.assertEqual(classifier.describe_metadata(app)['classification_evidence'][0]['candidates'],
                         candidates[:5])


if __name__ == '__main__':
    unittest.main()
