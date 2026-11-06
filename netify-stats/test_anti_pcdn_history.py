"""Cross-port and rotating-peer regressions; synthetic, not an accuracy claim."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_anti_pcdn_fast import Scenario
import test_anti_pcdn_fast as fast_tests
from test_anti_pcdn_engine import Stream
from anti_pcdn import conntrack as ct, history
from anti_pcdn.history import DistributionHistory
from anti_pcdn.scoring import KIB, MIB

COHORT = 'a' * 24
PEERS = ['11.1.0.1', '12.2.0.1', '13.3.0.1', '14.4.0.1']


def learned():
    result = DistributionHistory()
    for stamp in (1, 2, 3):
        result.record([(COHORT, peer, 180*KIB, KIB) for peer in PEERS], stamp)
    return result


class HistoryTests(unittest.TestCase):
    def test_ready_without_waiting_and_expires_with_both_directions(self):
        ledger = learned()
        self.assertTrue(ledger.summaries(3)[COHORT]['ready'])
        ledger.record([(COHORT, PEERS[0], 0, MIB)], 4)
        self.assertFalse(ledger.summaries(4)[COHORT]['ready'])
        self.assertFalse(ledger.summaries(1801))

    def test_one_large_upload_small_peers_and_one_cloud_network_do_not_qualify(self):
        ledger = DistributionHistory()
        for stamp in (1, 2, 3):
            ledger.record([(COHORT, peer, 10*MIB if i == 0 else 64*KIB, 1)
                           for i, peer in enumerate(PEERS)], stamp)
        self.assertFalse(ledger.summaries(3)[COHORT]['ready'])
        ledger.clear()
        for stamp in (1, 2, 3):
            ledger.record([(COHORT, '11.1.0.%d' % i, MIB, 1) for i in range(1, 5)], stamp)
        self.assertFalse(ledger.summaries(3)[COHORT]['ready'])

    def test_download_peer_does_not_hide_separate_upload_distribution(self):
        ledger = learned()
        ledger.record([(COHORT, '15.5.0.1', KIB, 20*MIB)], 4)
        row = ledger.summaries(4)[COHORT]
        self.assertTrue(row['ready'])
        self.assertEqual(row['serving_peers'], 4)
        self.assertNotIn('15.5.0.1', row['qualified'])

    def test_capacity_does_not_keep_selectively_positive_partial_evidence(self):
        ledger = learned()
        with patch.object(history, 'MAX_PEERS', 4):
            ledger.record([(COHORT, '15.5.0.1', KIB, MIB)], 4)
        self.assertFalse(ledger.peers)
        self.assertEqual(ledger.counters['capacity_resets'], 1)

    def test_checkpoint_is_private_and_bound_to_boot_policy_clock(self):
        ledger = learned()
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'history.json')
            ledger.save(path, 3, 1800000003, 'boot', 'policy')
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            for boot, policy, wall in [('different', 'policy', 1800000010),
                                       ('boot', 'changed', 1800000010),
                                       ('boot', 'policy', 1800001010)]:
                self.assertFalse(DistributionHistory().restore(path, 10, wall, boot, policy))
            restored = DistributionHistory()
            self.assertTrue(restored.restore(path, 10, 1800000010, 'boot', 'policy'))
            self.assertTrue(restored.summaries(10)[COHORT]['ready'])
            value = json.loads(Path(path).read_text())
            value['peers'][0][2][0][1] = -1
            Path(path).write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                DistributionHistory().restore(path, 10, 1800000010, 'boot', 'policy')


class CrossPortTests(unittest.TestCase):
    def test_port_rotation_joins_but_clients_apps_and_hosts_remain_separate(self):
        stream = Stream()
        for i in range(8):
            stream.metadata(i, local_port=20000+i, other_port=30000+i)
        rows = stream.engine.fast_metadata(0)
        self.assertEqual(len({row['group'] for row in rows}), 8)
        self.assertEqual(len({row['cohort'] for row in rows}), 1)
        scenario = Scenario()
        scenario.metadata = rows
        for record, row in zip(scenario.records, rows):
            record['tuple'] = ct.flow_tuple(row)
        self.assertEqual(len(scenario.burst()), 8)
        for field, value in [('local_mac', '02:00:00:00:00:99'),
                             ('detected_application_name', 'Video Conference'),
                             ('host_server_name', 'upload.example')]:
            other = Stream()
            other.metadata(0)
            other.metadata(1, **{field: value})
            self.assertEqual(len({row['cohort'] for row in other.engine.fast_metadata(0)}), 2)

    def serial(self):
        scenario = Scenario(4)
        for i, row in enumerate(scenario.metadata):
            row.update(peer=PEERS[i], sport=20000+i, dport=30000+i)
            scenario.records[i]['tuple'] = ct.flow_tuple(row)
        scenario.poll(0)
        last = []
        for stamp in range(1, 213):
            index, tick = divmod(stamp-1, 70)
            if tick in (0, 1):
                scenario.records[index]['upload'] += 256*KIB
                scenario.records[index]['download'] += KIB
            last = scenario.poll(stamp)
            if index < 3:
                self.assertFalse(last)
            if tick == 1 and index < 3:
                scenario.metadata[index]['closed'] = True
        return scenario, last

    def test_serial_peers_cross_ports_qualify_before_window_end(self):
        scenario, rows = self.serial()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['detection_path'], 'rotating_peers')
        self.assertEqual(rows[0]['history_metrics']['serving_peers'], 4)
        self.assertEqual(rows[0]['history_metrics']['distributed_upload'], 2*MIB)
        self.assertEqual(rows[0]['upload'], 512*KIB)
        self.assertEqual(rows[0]['metrics']['serving_peers'], 1)
        self.assertEqual(rows[0]['aggregation'], 'cross_port')
        self.assertLess(rows[0]['observed_seconds'], 1800)

    def test_returning_peer_requires_new_bytes_and_multiple_polls(self):
        scenario, _ = self.serial()
        row = scenario.metadata[0]
        row.update(closed=False, id='new-flow', birth=row['birth']+1, sport=53000, dport=55000)
        scenario.records[0].update(id=999, tuple=ct.flow_tuple(row), upload=2**30, download=0)
        self.assertFalse(scenario.poll(213))  # Historic counters are only a baseline.
        scenario.records[0]['upload'] += 16*KIB
        self.assertFalse(scenario.poll(214))
        scenario.records[0]['upload'] += 16*KIB
        rows = scenario.poll(215)
        self.assertEqual(rows[0]['detection_path'], 'returning_peer')
        self.assertEqual(rows[0]['upload'], 32*KIB)
        self.assertEqual(rows[0]['required_upload_bytes'], 32*KIB)
        row['guards'] = ['protected_transport']
        self.assertFalse(scenario.observer.candidates(215.1, scenario.metadata))
        self.assertFalse(scenario.observer.history.summaries(215)[row['cohort']]['ready'])

    def test_new_classification_revokes_generic_history_and_rebaselines(self):
        scenario, rows = self.serial()
        self.assertTrue(rows)
        old = scenario.metadata[-1]['cohort']
        scenario.metadata[-1]['cohort'] = 'b'*24
        self.assertFalse(scenario.poll(213, up=KIB))
        self.assertFalse(scenario.observer.history.summaries(213)[old]['ready'])

    def test_missing_dump_recovers_both_directions_without_double_counting(self):
        scenario = Scenario()
        scenario.poll(0)
        scenario.poll(1, up=KIB, down=KIB)
        reader = scenario.observer.reader
        scenario.observer.reader = lambda: (_ for _ in ()).throw(ct.SnapshotError('read_timeout', 'timeout'))
        self.assertFalse(scenario.poll(2, up=KIB, down=10*KIB))
        scenario.observer.reader = reader
        scenario.poll(3, up=KIB, down=10*KIB)
        row = next(iter(scenario.observer.history.summaries(3).values()))
        self.assertEqual(row['upload'], 8*3*KIB)
        self.assertEqual(row['download'], 8*21*KIB)
        scenario.poll(4)
        self.assertEqual(scenario.observer.history.summaries(4), scenario.observer.history.summaries(3))
        self.assertEqual(scenario.observer.failures['read_timeout'], 1)
        self.assertEqual(scenario.observer.counters['recovered_reads'], 1)

    def test_receive_budget_excludes_decode_time_and_total_decode_is_bounded(self):
        harness = fast_tests.CounterSnapshotTests()
        record = (harness.payload(), 0x100, 2, (0, 0), 0)
        done = (b'\0'*4, 3, 2, (0, 0), 0)
        original = ct.counter_record
        tick = [0.0]
        def slow(body):
            tick[0] += .2
            return original(body)
        with patch.object(ct, 'counter_record', slow):
            self.assertEqual(len(harness.snapshot([record, done], clock=lambda: tick[0])), 1)
        tick[0] = 0
        def excessive(body):
            tick[0] += .7
            return original(body)
        with patch.object(ct, 'counter_record', excessive), self.assertRaises(ct.SnapshotError) as caught:
            harness.snapshot([record, done], clock=lambda: tick[0])
        self.assertEqual(caught.exception.code, 'decode_timeout')


if __name__ == '__main__':
    unittest.main()
