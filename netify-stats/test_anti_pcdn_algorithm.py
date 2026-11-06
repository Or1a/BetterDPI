"""Whole-pipeline safety regressions with synthetic, universal identities."""
import copy
import os
import struct
import tempfile
import unittest
from unittest.mock import patch

from test_anti_pcdn_fast import Scenario
from test_anti_pcdn_history import PEERS
import test_anti_pcdn_history as history_tests
import test_anti_pcdn_firewall as firewall_tests
from test_anti_pcdn_engine import Stream, BASE
from test_anti_pcdn_runtime import FakeFirewall
from test_anti_pcdn_firewall import conntrack_payload, ROW
from anti_pcdn import conntrack as ct
from anti_pcdn.fast import FastObserver
from anti_pcdn.runtime import Worker
from anti_pcdn.scoring import KIB, MIB
from anti_pcdn import history


class AlgorithmTests(unittest.TestCase):
    def test_ambiguous_tuple_at_execution_recheck_cannot_keep_a_proposal(self):
        scenario = Scenario()
        self.assertTrue(scenario.burst())
        metadata = copy.deepcopy(scenario.metadata)
        duplicate = dict(metadata[0], id='f'*24)
        metadata.append(duplicate)
        rows = scenario.observer.candidates(3, metadata)
        self.assertFalse(any(row['id'] in (metadata[0]['id'], duplicate['id']) for row in rows))
        self.assertNotIn((metadata[0]['cohort'], metadata[0]['peer']), scenario.observer.history.peers)

    def test_closed_connection_final_download_is_not_lost(self):
        scenario = Scenario()
        scenario.burst()
        first = scenario.metadata[0]
        first['closed'] = True
        scenario.records[0]['download'] += 2*MIB
        scenario.poll(4)
        samples = scenario.observer.history.peers[(first['cohort'], first['peer'])]
        self.assertGreaterEqual(sum(sample[2] for sample in samples), 2*MIB)

    def returning(self):
        scenario = Scenario(1)
        row = scenario.metadata[0]
        row['peer'] = PEERS[0]
        scenario.records[0]['tuple'] = ct.flow_tuple(row)
        for now in (1, 2, 3):
            scenario.observer.history.record([(row['cohort'], peer, 180*KIB, KIB)
                                              for peer in PEERS + ['15.5.0.1']], now)
        scenario.poll(4)
        self.assertTrue(next(iter(scenario.observer.entries.values()))['returning'])
        return scenario

    def test_revoked_peer_cannot_keep_the_returning_peer_discount(self):
        scenario = self.returning()
        row = scenario.metadata[0]
        scenario.observer.history.revoke(row['cohort'], row['peer'])
        scenario.poll(5, up=16*KIB)
        scenario.poll(6, up=16*KIB)
        self.assertFalse(scenario.poll(7, up=16*KIB))

    def test_counter_rollback_revokes_returning_eligibility(self):
        scenario = self.returning()
        scenario.poll(5, up=16*KIB)
        scenario.records[0]['upload'] = 0
        scenario.poll(6)
        self.assertFalse(next(iter(scenario.observer.entries.values()))['returning'])

    def test_protection_is_accepted_even_when_the_byte_report_is_invalid(self):
        for protection in ({'detected_protocol_name': 'WireGuard'},
                           {'dns_host_name': 'allowed.example'}, {'proxy': True}):
            with self.subTest(protection=protection):
                stream = Stream(allow_domains=['allowed.example'])
                stream.metadata()
                stream.engine.observe(dict(type='flow_stats', internal=True, interface='br-lan',
                                           flow=dict(digest='0', **protection)), 1, BASE+1)
                row = stream.engine.fast_metadata(1)[0]
                self.assertTrue(set(row['guards']) & {'protected_transport', 'allowlisted', 'unsupported_proxy'})

    def test_late_vpn_classification_releases_an_existing_lease_during_consumption(self):
        scenario = Scenario()
        scenario.burst()
        firewall = FakeFirewall()
        tick = [3]
        with tempfile.TemporaryDirectory() as directory:
            worker = Worker(scenario.settings, engine=scenario.stream.engine, firewall=firewall,
                            runtime_dir=directory, clock=lambda: tick[0], wall=lambda: BASE+tick[0])
            worker.connected = worker.cleanup_ready = True
            worker.applied_generation = 0
            worker.fast = scenario.observer
            worker.evaluate(3)
            lease = next(iter(firewall.leases.values()))
            number = int(lease['peer'].rsplit('.', 1)[1])-1
            tick[0] = 4
            worker.submit(dict(type='flow_stats', internal=True, interface='br-lan',
                               flow=dict(digest=str(number), detected_protocol_name='WireGuard')))
            worker.consume(worker.queue.get_nowait())
            self.assertNotIn(lease['id'], firewall.leases)

    def test_exact_identity_check_rejects_a_new_conntrack_mark(self):
        identity = ct.flow_tuple(ROW)
        payload = conntrack_payload(identity) + ct.attribute(8, struct.pack('!I', 1))
        with self.assertRaises(ct.IdentityError):
            ct.decode_conntrack(payload, identity)

    def test_ipv6_aliases_in_one_subnet_cannot_be_eight_receiving_peers(self):
        scenario = Scenario()
        for index, row in enumerate(scenario.metadata):
            row.update(ip='fd00::2', peer='2606:4700:10:20::%x' % (index+1))
            scenario.records[index]['tuple'] = ct.flow_tuple(row)
        self.assertFalse(scenario.burst())

    def test_late_protection_revokes_history_after_live_cursor_has_retired(self):
        scenario, _rows = history_tests.CrossPortTests().serial()
        row = scenario.metadata[0]
        scenario.records = scenario.records[1:]
        for stamp in range(213, 275):
            scenario.poll(stamp)
        self.assertFalse(any(entry['row']['id'] == row['id'] for entry in scenario.observer.entries.values()))
        old_cohort = row['cohort']
        row.update(cohort='b'*24, guards=['protected_transport'])
        scenario.poll(275)
        self.assertNotIn((old_cohort, row['peer']), scenario.observer.history.peers)

    def test_history_capacity_isolated_to_the_affected_cohort(self):
        ledger = history_tests.learned()
        with patch.object(history, 'MAX_PEERS', 4):
            ledger.record([('b'*24, '15.1.0.1', KIB, KIB)], 4)
        self.assertTrue(ledger.summaries(4)[history_tests.COHORT]['ready'])
        with patch.object(history, 'MAX_COHORT_PEERS', 4):
            ledger.record([(history_tests.COHORT, '15.1.0.1', KIB, MIB)], 5)
        self.assertFalse(ledger.peers)

    def test_ipv6_history_caps_each_prefix_and_keeps_negative_evidence(self):
        ledger = history.DistributionHistory()
        peers = ['2606:4700:1:1::1', '2606:4700:1:1::2', '2606:4700:2:1::1', '2606:4700:3:1::1']
        for now in (1, 2, 3):
            ledger.record([(history_tests.COHORT, peer, 256*KIB, KIB) for peer in peers], now)
        row = ledger.summaries(3)[history_tests.COHORT]
        self.assertEqual(row['serving_peers'], 3)
        self.assertEqual(row['distributed_upload'], 1536*KIB)
        self.assertFalse(row['ready'])
        ledger.record([(history_tests.COHORT, '2606:4700:1:1::3', 0, 2*MIB)], 4)
        self.assertEqual(ledger.summaries(4)[history_tests.COHORT]['serving_peers'], 2)

    def test_platform_inspection_never_installs_a_table_or_connection_rule(self):
        harness = firewall_tests.FirewallTests()
        harness.setUp()
        harness.nft.document['nftables'].append({'rule': {'expr': [{'tproxy': {'port': 123}}]}})
        result = harness.firewall.inspect(100)
        self.assertFalse(result['supported'])
        self.assertTrue(result['read_only'])
        self.assertFalse(result['connection_checks_complete'])
        self.assertTrue(all('-j' in args and data is None for args, data in harness.nft.calls))
        calls = len(harness.nft.calls)
        harness.firewall.inspect(101)
        self.assertEqual(len(harness.nft.calls), calls)

    def test_mark_guards_remain_on_each_live_kernel_lease(self):
        harness = firewall_tests.FirewallTests()
        harness.setUp()
        self.assertIsNotNone(harness.install())
        rules = [line for _args, script in harness.nft.calls if script
                 for line in script.splitlines() if 'counter drop' in line]
        self.assertEqual(len(rules), 2)
        self.assertTrue(all('meta mark 0 ct mark 0 counter drop' in rule for rule in rules))

    def test_global_observation_loss_removes_existing_feature_leases(self):
        scenario = Scenario()
        scenario.burst()
        firewall = FakeFirewall()
        with tempfile.TemporaryDirectory() as directory:
            worker = Worker(scenario.settings, engine=scenario.stream.engine, firewall=firewall,
                            runtime_dir=directory, clock=lambda: 3, wall=lambda: BASE+3)
            worker.connected = worker.cleanup_ready = True
            worker.applied_generation = 0
            worker.fast = scenario.observer
            worker.evaluate(3)
            self.assertTrue(firewall.leases)
            worker.connected = False
            worker.gap('source_disconnected')
            worker.evaluate(4)
            self.assertFalse(firewall.leases)

    def test_download_acknowledgements_do_not_lend_a_distribution_score_to_one_upload(self):
        stream = Stream(weights=dict(fanout=40, serving_peers=20, sustained=20, upload_ratio=15, domain=5), threshold=75)
        for number in range(80):
            stream.metadata(number)
        for now in range(10, 331, 10):
            for number in range(80):
                stream.event(number, now, up=MIB if number == 0 else 64*KIB,
                             down=KIB if number == 0 else 8*MIB)
        rows = stream.engine.candidates(330)
        self.assertEqual(rows[0]['metrics']['serving_peers'], 1)
        self.assertTrue(all(row['decision'] == 'observe' for row in rows))

    def test_normal_path_also_deduplicates_ipv6_prefixes(self):
        stream = Stream()
        for number in range(20):
            stream.metadata(number, local_ip='fd00::2', other_ip='2606:4700:10:20::%x' % (number+1))
        for now in range(10, 331, 10):
            for number in range(20):
                stream.event(number, now)
        rows = stream.engine.candidates(330)
        self.assertEqual(rows[0]['metrics']['peers'], 1)
        self.assertTrue(all(row['decision'] == 'observe' for row in rows))

    def test_expired_fast_lease_rebaselines_without_a_free_upload_minute(self):
        scenario = Scenario()
        row = scenario.burst()[0]
        scenario.observer.suppress(row, 10)
        for now in range(4, 10):
            scenario.poll(now, up=MIB)
        self.assertFalse(any(candidate['id'] == row['id'] for candidate in scenario.poll(10, up=MIB)))
        scenario.poll(11, up=96*KIB)
        rows = scenario.poll(12, up=96*KIB)
        returned = next(candidate for candidate in rows if candidate['id'] == row['id'])
        self.assertEqual(returned['upload'], 192*KIB)

    def test_lease_release_failure_falls_back_to_owned_feature_cleanup(self):
        scenario = Scenario()
        scenario.burst()
        firewall = FakeFirewall()
        with tempfile.TemporaryDirectory() as directory:
            worker = Worker(scenario.settings, engine=scenario.stream.engine, firewall=firewall,
                            runtime_dir=directory, clock=lambda: 3, wall=lambda: BASE+3)
            worker.connected = worker.cleanup_ready = True
            worker.applied_generation = 0
            worker.fast = scenario.observer
            worker.evaluate(3)
            row = dict(next(iter(firewall.leases.values())), guards=['allowlisted'])
            firewall.release = lambda *_: False
            self.assertFalse(worker.revoke_protected(4, [row]))
            self.assertFalse(firewall.leases)


if __name__ == '__main__':
    unittest.main()
