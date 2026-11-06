"""Shadow decisions must be useful evidence without becoming enforcement."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / 'features'))
from anti_pcdn import observation
from anti_pcdn.config import DEFAULTS
from anti_pcdn.observation import ObservationJournal
from anti_pcdn.runtime import Worker
from test_anti_pcdn_engine import Stream, BASE
from test_anti_pcdn_runtime import FakeFirewall


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.journal = ObservationJournal(self.directory.name)
        self.settings = dict(copy.deepcopy(DEFAULTS), enabled=True)

    def row(self, **fields):
        result = dict(id='a' * 24, group='b' * 24, mac='02:11:22:33:44:55',
                      ip='192.0.2.2', peer='198.51.100.2', sport=40000, dport=443,
                      proto=17, protocol='QUIC', score=80, decision='observe',
                      upload=128 * 1024, download=1024, guards=[],
                      reasons=[dict(id='sustained', points=20)],
                      metrics=dict(upload=8 * 1024 * 1024, download=1024,
                                   peers=20, serving_peers=10, upload_minutes=4))
        result.update(fields)
        return result

    def record(self, rows, now=1000):
        self.journal.record(rows, self.settings, now, BASE + now, {})

    def records(self, path=None):
        return [json.loads(line) for line in Path(path or self.journal.path).read_text().splitlines()]

    def test_observe_decision_is_independent_of_enforcement_and_keeps_features(self):
        self.record([self.row()])
        row = self.records()[0]
        self.assertEqual(row['outcome'], 'would_block')
        self.assertFalse(row['executed'])
        self.assertFalse(row['enforcement_checked'])
        self.assertEqual(row['metrics']['upload_minutes'], 4)
        self.assertEqual(row['threshold'], 80)
        self.assertEqual(row['weights'], DEFAULTS['weights'])
        self.assertEqual(os.stat(self.journal.path).st_mode & 0o777, 0o600)

    def test_guarded_and_low_score_uploads_are_not_reported_as_would_block(self):
        self.record([self.row(guards=['incomplete_window'])])
        self.record([self.row(group='other', score=60, guards=['short_window_only'])])
        self.record([self.row(group='zero', score=0)])
        self.assertEqual([r['outcome'] for r in self.records()],
                         ['evidence_incomplete', 'below_threshold', 'below_threshold'])

    def test_vpn_proxy_shared_and_allowlisted_connections_never_become_proposals(self):
        for guard in ('protected_transport', 'unsupported_proxy', 'shared_transport', 'allowlisted'):
            self.record([self.row(score=100, guards=[guard])])
        self.assertFalse(Path(self.journal.path).exists())
        self.assertEqual(self.journal.protected, 1)
        self.record([self.row(guards=['not_uploading']), self.row(upload=1)])
        self.assertEqual(self.journal.written, 0)

    def test_group_dedup_periodic_refresh_and_changed_decisions(self):
        self.record([self.row(), self.row(id='c' * 24)])
        self.record([self.row()], now=1010)
        self.assertEqual(len(self.records()), 1)
        self.record([self.row(guards=['incomplete_window'])], now=1020)
        self.assertEqual(len(self.records()), 2)
        self.record([self.row(guards=['incomplete_window'])], now=1030)
        self.assertEqual(len(self.records()), 2)
        self.record([self.row(guards=['incomplete_window'])], now=1330)
        self.assertEqual(len(self.records()), 3)
        # A monotonic reset does not suppress records indefinitely.
        self.record([self.row()], now=0)
        self.assertEqual(len(self.records()), 4)

    def test_returning_peer_small_upload_proposal_is_recorded(self):
        self.record([self.row(upload=32*1024, evidence_source='conntrack_fast',
                              detection_path='returning_peer', required_upload_bytes=32*1024)])
        self.assertEqual(self.records()[0]['outcome'], 'would_block')
        self.assertEqual(self.records()[0]['detection_path'], 'returning_peer')

    def test_fast_proposals_record_each_connection_with_bounded_deferred_writes(self):
        rows = [self.row(id='flow-%d' % index, ct_id=index, evidence_source='conntrack_fast')
                for index in range(10)]
        self.record(rows)
        self.assertEqual(len(self.records()), 8)
        self.record(rows, now=1001)
        records = self.records()
        self.assertEqual(len(records), 10)
        self.assertEqual(len({row['id'] for row in records}), 10)
        self.assertTrue(all(row['sample_scope'] == 'connection' for row in records))
        self.record(rows, now=1002)
        self.assertEqual(len(self.records()), 10)

    def test_brief_connections_survive_write_throttling_with_original_time(self):
        rows = [self.row(id='brief-%d' % index, ct_id=index, evidence_source='conntrack_fast')
                for index in range(12)]
        self.record(rows)
        self.assertEqual(len(self.records()), 8)
        self.record([], now=1001)
        self.assertEqual(len(self.records()), 12)
        self.assertTrue(all(row['timestamp'] == BASE+1000 for row in self.records()))

    def test_pending_records_are_bounded_and_keep_detached_metrics(self):
        rows = [self.row(group=str(index)) for index in range(12)]
        with patch.object(observation, 'MAX_PENDING', 10):
            self.record(rows)
        self.assertEqual(self.journal.dropped, 2)
        self.assertEqual(len(self.journal.pending), 2)
        rows[8]['metrics']['upload'] = 1
        self.record([], now=1001)
        self.assertEqual(len(self.records()), 10)
        self.assertEqual(self.records()[8]['metrics']['upload'], 8*1024*1024)

    def test_high_fanout_without_material_upload_is_logged_as_watch_only(self):
        row = self.row(upload=1024, score=40, guards=['not_uploading'],
                       metrics=dict(peers=80, serving_peers=0, upload_minutes=0))
        self.record([row])
        record = self.records()[0]
        self.assertEqual(record['outcome'], 'below_threshold')
        self.assertEqual(record['sample_type'], 'fanout_watch')
        self.assertEqual(record['score_revision'], 5)
        self.assertIn('not_uploading', record['guards'])
        # Even a low configured threshold cannot turn watch-only into a proposal.
        self.settings['threshold'] = 1
        self.record([dict(row, guards=[])], now=1010)
        self.assertEqual(self.records()[-1]['outcome'], 'evidence_incomplete')
        self.assertIn('not_uploading', self.records()[-1]['guards'])
        self.assertEqual(row['guards'], ['not_uploading'])
        self.record([dict(row, group='small', metrics=dict(peers=39))], now=1020)
        self.assertEqual(len(self.records()), 2)

    def test_eligible_member_is_not_hidden_by_watch_or_guarded_members(self):
        watch = self.row(id='watch', score=95, upload=8*1024*1024, guards=['not_uploading'],
                         metrics=dict(peers=80, serving_peers=20, upload_minutes=5))
        guarded = self.row(id='guarded', score=95, upload=1024*1024, guards=['incomplete_window'])
        eligible = self.row(id='eligible')
        self.record([watch, guarded, eligible])
        self.assertEqual(len(self.records()), 1)
        self.assertEqual(self.records()[0]['id'], 'eligible')
        self.assertEqual(self.records()[0]['outcome'], 'would_block')
        self.assertEqual(self.records()[0]['sample_type'], 'upload')

    def test_high_fanout_watch_never_records_protected_connections(self):
        for guard in ('protected_transport', 'unsupported_proxy', 'shared_transport', 'allowlisted'):
            self.record([self.row(upload=1024, score=100, guards=[guard], metrics=dict(peers=1000))])
        self.assertEqual(self.journal.written, 0)

    def test_real_high_fanout_observation_records_without_firewall_calls(self):
        stream = Stream(mode='observe', weights=dict(DEFAULTS['weights'], fanout=40, domain=5))
        stream.populate(count=80, up=100, down=100)
        firewall = FakeFirewall()
        worker = Worker(stream.engine.settings, runtime_dir=self.directory.name,
                        engine=stream.engine, firewall=firewall, clock=lambda: 330,
                        wall=lambda: BASE + 330)
        worker.applied_generation = 0
        worker.connected = True
        worker.evaluate(330)
        record = worker.observations.recent[0]
        self.assertEqual(record['score'], 40)
        self.assertEqual(record['sample_type'], 'fanout_watch')
        self.assertEqual(record['outcome'], 'below_threshold')
        self.assertFalse(firewall.calls)
        self.assertFalse(firewall.leases)

    def test_brief_eligibility_transitions_are_recorded_within_the_cooldown(self):
        # Universal synthetic identities: the transition rule must not depend
        # on a particular device, port, peer, domain or score above threshold.
        rows = [self.row(group=str(i), mac='02:11:22:33:44:%02x' % i,
                         sport=40000 + i, peer='198.51.100.%d' % (i + 1))
                for i in range(3)]
        self.record([dict(row, score=60) for row in rows], now=1000)
        self.record(rows, now=1010)
        self.record([dict(row, guards=['incomplete_window']) for row in rows], now=1020)
        self.record([dict(row, score=60) for row in rows], now=1030)
        for row in rows:
            self.assertEqual([entry['outcome'] for entry in self.records() if entry['group'] == row['group']],
                             ['below_threshold', 'would_block', 'evidence_incomplete', 'below_threshold'])

    def test_feature_changes_with_the_same_decision_still_obey_cooldown(self):
        self.record([self.row(score=60)], now=1000)
        self.record([self.row(score=65)], now=1010)
        self.record([self.row(score=65)], now=1030)
        self.assertEqual([row['score'] for row in self.records()], [60, 65])

    def test_rotation_restart_and_memory_limits(self):
        with patch.object(observation, 'MAX_FILE_BYTES', 2000), \
                patch.object(observation, 'MAX_GROUPS', 4):
            for i in range(30):
                self.record([self.row(group=str(i))], now=1000 + i)
            self.assertLessEqual(len(self.journal.seen), 4)
            self.assertEqual(len(self.journal.recent), observation.MAX_RECENT)
            for suffix in ('', '.1'):
                self.assertLessEqual(Path(self.journal.path + suffix).stat().st_size, 2000)
            before = self.records()
            journal = ObservationJournal(self.directory.name)
            self.assertEqual(self.records(), before)
            journal.record([self.row()], self.settings, 1400, BASE + 1400, {})
            self.assertEqual(self.records()[-1]['outcome'], 'would_block')

    def test_per_evaluation_budget_defers_without_claiming_success(self):
        rows = [self.row(group=str(i)) for i in range(12)]
        self.record(rows)
        self.assertEqual(self.journal.written, observation.MAX_PER_EVALUATION)
        self.assertEqual(self.journal.deferred, 4)
        self.record(rows, now=1010)
        self.assertEqual(self.journal.written, 12)

    def test_io_failure_does_not_escape_or_create_success_and_retries(self):
        with patch.object(self.journal, '_append', side_effect=OSError('disk full')):
            self.record([self.row()])
        self.assertEqual(self.journal.written, 0)
        self.assertFalse(self.journal.recent)
        self.assertEqual(self.journal.error, 'disk full')
        self.record([self.row()], now=1010)
        self.assertEqual(self.journal.written, 1)
        self.assertEqual(self.journal.error, '')

    def test_real_engine_records_shadow_block_without_firewall_install_or_suppression(self):
        stream = Stream(mode='observe')
        stream.populate()
        firewall = FakeFirewall()
        worker = Worker(stream.engine.settings, runtime_dir=self.directory.name,
                        engine=stream.engine, firewall=firewall, clock=lambda: 330,
                        wall=lambda: BASE + 330)
        worker.applied_generation = 0
        worker.connected = True
        # Observe mode needs neither kernel support nor successful cleanup to log.
        worker.cleanup_ready = False
        worker.evaluate(330)
        worker.publish(330)
        self.assertFalse(firewall.calls)
        self.assertFalse(firewall.leases)
        self.assertTrue(all(flow.suppressed_until == float('-inf') for flow in stream.engine.flows.values()))
        status = json.loads(Path(self.directory.name, 'status.json').read_text())
        self.assertEqual(status['observations']['score_revision'], 5)
        self.assertEqual(status['observations']['recent'][0]['outcome'], 'would_block')
        worker.connected = False
        worker.evaluate(1000)
        self.assertEqual(worker.observations.written, 1)

    def test_real_vpn_flows_are_not_logged_even_with_low_threshold(self):
        stream = Stream(mode='observe', threshold=1)
        rows = stream.populate(detected_protocol_name='WireGuard')
        self.record(rows)
        self.assertFalse(Path(self.journal.path).exists())


if __name__ == '__main__':
    unittest.main()
