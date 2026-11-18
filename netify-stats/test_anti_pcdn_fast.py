"""Synthetic early-detection, counter provenance and protection regressions."""
import copy
import os
import socket
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'features'))
from anti_pcdn import conntrack as ct, fast
from anti_pcdn.config import validate
from anti_pcdn.fast import FastObserver
from anti_pcdn.runtime import Worker
from anti_pcdn.scoring import KIB, MIB
from test_anti_pcdn_engine import Stream
import test_anti_pcdn_firewall as firewall_tests
from test_anti_pcdn_firewall import conntrack_payload, ROW
from test_anti_pcdn_runtime import FakeFirewall


class Scenario:
    def __init__(self, count=8, **settings):
        self.stream = Stream(**settings)
        for i in range(count):
            self.stream.metadata(i)
        self.settings = self.stream.engine.settings
        self.metadata = self.stream.engine.fast_metadata(0)
        self.records = [dict(id=i + 1, tuple=ct.flow_tuple(row), upload=0, download=0)
                        for i, row in enumerate(self.metadata)]
        self.observer = FastObserver(self.settings, reader=lambda: copy.deepcopy(self.records))

    def poll(self, now, up=0, down=0):
        for record in self.records:
            record['upload'] += up
            record['download'] += down
        self.observer.poll(self.metadata, now)
        return self.observer.candidates(now)

    def burst(self, up=96 * 1024, down=1024):
        self.poll(0)
        for now in (1, 2, 3):
            rows = self.poll(now, up, down)
        return rows


class FastTests(unittest.TestCase):
    def test_two_mib_distribution_triggers_in_seconds_without_netify_stats(self):
        scenario = Scenario()
        rows = scenario.burst()
        self.assertEqual(len(rows), 8)
        self.assertTrue(all(row['decision'] == 'block' for row in rows))
        self.assertEqual(rows[0]['score'], 80)
        self.assertEqual(rows[0]['observed_seconds'], 3)
        self.assertEqual(rows[0]['metrics']['upload'], 2359296)
        self.assertEqual(rows[0]['connection_upload_bytes'], 294912)
        self.assertFalse(scenario.stream.engine.candidates(3))  # No delayed Netify stats needed.

    def test_initial_totals_replays_and_one_burst_are_not_new_evidence(self):
        scenario = Scenario()
        self.assertFalse(scenario.poll(0, up=20 * 1024 ** 3))
        for now in (1, 2, 3):
            self.assertFalse(scenario.poll(now))
        self.assertFalse(scenario.poll(4, up=2 * 1024 ** 2))
        self.assertFalse(scenario.poll(5))

    def test_normal_upload_download_and_handshake_fanout_do_not_qualify(self):
        for count, up, down in ((1, 8 * 1024 ** 2, 1024), (80, 1024, 0),
                                (8, 96 * 1024, 1024 ** 2), (7, 1024 ** 2, 0)):
            with self.subTest(count=count, up=up, down=down):
                self.assertFalse(Scenario(count, threshold=1).burst(up, down))

    def test_audit_samples_incomplete_distribution_without_single_upload_or_exemptions(self):
        scenario = Scenario(count=6)
        scenario.metadata[0]['guards'] = ['allowlisted']
        scenario.metadata[1]['guards'] = ['protected_transport']
        scenario.burst(up=200 * 1024)
        reports = []
        self.assertFalse(scenario.observer.candidates(3, scenario.metadata,
                                                    lambda row, reason: reports.append((row, reason))))
        self.assertEqual(len(reports), 4)
        self.assertEqual({reason for _, reason in reports}, {'distribution_evidence_incomplete'})
        self.assertTrue(all(row['connection_upload_bytes'] == 600 * 1024 for row, _ in reports))
        self.assertEqual({row['id'] for row, _ in reports}, {row['id'] for row in scenario.metadata[2:]})

    def test_peers_are_distinct_not_parallel_connections(self):
        scenario = Scenario()
        for i, row in enumerate(scenario.metadata):
            row['peer'], row['dport'] = '11.1.1.1', 4000 + i
            scenario.records[i]['tuple'] = ct.flow_tuple(row)
        self.assertFalse(scenario.burst())

    def test_inbound_direction_uses_lan_upload_not_original_peer_bytes(self):
        scenario = Scenario()
        for record in scenario.records:
            record['reply'] = record['tuple']
            record['tuple'] = ct.reverse(record['tuple'])
        self.assertTrue(scenario.burst(up=1024, down=96 * 1024))
        self.assertEqual(scenario.observer.rows[0]['upload'], 294912)

    def test_separate_behavior_cohorts_do_not_inherit_evidence(self):
        scenario = Scenario()
        for i, row in enumerate(scenario.metadata):
            row['cohort'] = 'separate-%s' % i
        self.assertFalse(scenario.burst())

    def mixed_distribution(self, established=True, distinct=8, per_poll=96*KIB, extra_upload=0):
        scenario = Scenario(9)
        for i, row in enumerate(scenario.metadata):
            row.update(peer='11.%d.1.1' % (i % distinct if i < 8 else i), dport=4000+i)
            scenario.records[i]['tuple'] = ct.flow_tuple(row)
        if established:
            cohort = scenario.metadata[0]['cohort']
            for stamp in (1, 2, 3):
                scenario.observer.history.record([(cohort, '11.%d.0.2' % n, 192*KIB, KIB)
                                                  for n in range(16, 20)], stamp)
        scenario.poll(4)
        for stamp in (5, 6, 7):
            scenario.records[-1]['download'] += 4*MIB
            scenario.records[0]['upload'] += extra_upload
            rows = scenario.poll(stamp, up=per_poll, down=KIB)
        return scenario, rows

    def test_established_distribution_promotes_new_peers_in_mixed_group(self):
        scenario, rows = self.mixed_distribution()
        self.assertEqual({row['id'] for row in rows}, {row['id'] for row in scenario.metadata[:-1]})
        self.assertEqual({row['detection_path'] for row in rows}, {'current_distribution'})
        self.assertTrue(all(r['required_upload_bytes'] == 128*KIB and r['upload'] == 288*KIB for r in rows))
        self.assertTrue(all(r['metrics']['download'] > r['metrics']['upload'] for r in rows))
        self.assertTrue(all(r['metrics']['distributed_upload'] == 2304*KIB for r in rows))
        scenario.metadata[0]['guards'] = ['protected_transport']
        self.assertFalse(scenario.observer.candidates(7.1, scenario.metadata))

    def test_new_peers_cannot_borrow_current_evidence_as_preexisting_history(self):
        scenario, rows = self.mixed_distribution(established=False)
        cohort = scenario.metadata[0]['cohort']
        self.assertTrue(scenario.observer.history.summaries(7)[cohort]['ready'])
        self.assertFalse(rows)
        reports = []
        scenario.observer.candidates(7, on_incomplete=lambda row, reason: reports.append((row, reason)))
        self.assertEqual(len(reports), 8)
        self.assertTrue(all(reason == 'connection_evidence_incomplete' and r['required_upload_bytes'] == 512*KIB
                            and r['upload_observations'] == 3 for r, reason in reports))

    def test_more_ports_or_one_large_receiver_cannot_unlock_the_lower_byte_floor(self):
        self.assertFalse(self.mixed_distribution(distinct=4)[1])
        scenario, rows = self.mixed_distribution(per_poll=48*KIB, extra_upload=256*KIB)
        self.assertEqual([row['id'] for row in rows], [scenario.metadata[0]['id']])
        self.assertEqual(rows[0]['detection_path'], 'rotating_peers')

    def test_rotating_peers_keep_past_evidence_but_only_live_upload_is_proposed(self):
        scenario = Scenario()
        scenario.poll(0)
        for i in range(8):
            if i:
                scenario.metadata[i - 1]['closed'] = True
            scenario.records[i]['upload'] += 300 * 1024
            rows = scenario.poll(i + 1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['peer'], scenario.metadata[7]['peer'])
        self.assertEqual(rows[0]['metrics']['serving_peers'], 8)
        self.assertEqual(rows[0]['metrics']['upload'], 2400 * 1024)
        self.assertEqual(len(scenario.observer.candidates(8, scenario.metadata)), 1)

    def test_vpn_proxy_allowlist_and_identity_guards_exclude_group_evidence(self):
        for guard in fast.EXCLUDED:
            with self.subTest(guard=guard):
                scenario = Scenario()
                scenario.metadata[0]['guards'] = [guard]
                self.assertFalse(scenario.burst())

    def test_late_protection_revokes_already_scored_group_before_action(self):
        scenario = Scenario()
        self.assertTrue(scenario.burst())
        scenario.metadata[0]['guards'] = ['protected_transport']
        self.assertFalse(scenario.observer.candidates(3.2, scenario.metadata))

    def test_new_kernel_mark_revokes_previous_group_contribution(self):
        scenario = Scenario()
        self.assertTrue(scenario.burst())
        scenario.records[0]['excluded'] = True
        self.assertFalse(scenario.poll(4, 96 * 1024, 1024))

    def test_protected_reused_tuple_revokes_prior_incarnation_evidence_immediately(self):
        scenario = Scenario()
        self.assertTrue(scenario.burst())
        changed = copy.deepcopy(scenario.metadata)
        changed[0].update(id='new-incarnation', birth=changed[0]['birth'] + 1,
                          guards=['protected_transport'])
        self.assertFalse(scenario.observer.candidates(3.1, changed))

    def test_disabled_observer_does_not_read_kernel_or_score(self):
        scenario = Scenario(enabled=False)
        scenario.observer.reader = lambda: self.fail('disabled observer read counters')
        self.assertFalse(scenario.burst())

    def test_stat_update_can_add_vpn_and_allowlist_protection(self):
        scenario = Scenario(allow_domains=['safe.example'])
        scenario.stream.event(0, 1, up=1, down=0, detected_protocol_name='WireGuard',
                              dns_host_name='safe.example')
        row = next(row for row in scenario.stream.engine.fast_metadata(1) if row['peer'] == '11.0.0.1')
        self.assertIn('protected_transport', row['guards'])
        self.assertIn('allowlisted', row['guards'])

    def test_kernel_id_and_metadata_incarnation_changes_start_new_baselines(self):
        scenario = Scenario()
        self.assertTrue(scenario.burst())
        for record in scenario.records:
            record['id'] += 100
            record['upload'] += 20 * 1024 ** 3
        self.assertFalse(scenario.poll(4))
        for row in scenario.metadata:
            row['birth'] += 1
        self.assertFalse(scenario.poll(5, up=1024 ** 2))

    def test_counter_regression_poll_gaps_and_errors_invalidate_fast_evidence(self):
        scenario = Scenario()
        self.assertTrue(scenario.burst())
        scenario.records[0]['upload'] = 1
        self.assertFalse(scenario.poll(4, up=1))
        self.assertFalse(scenario.poll(20, up=1024 ** 2))
        scenario.observer.reader = lambda: (_ for _ in ()).throw(OSError('denied'))
        self.assertFalse(scenario.poll(21))
        self.assertEqual(scenario.observer.error, 'denied')
        self.assertTrue(scenario.observer.entries)
        self.assertFalse(scenario.poll(24))
        self.assertFalse(scenario.observer.entries)

    def test_threshold_and_weight_caps_are_still_respected(self):
        scenario = Scenario(threshold=81)
        rows = scenario.burst()
        self.assertTrue(rows)
        self.assertTrue(all(row['score'] == 80 and row['decision'] == 'observe' for row in rows))

    def test_aging_and_suppression_remove_proposals(self):
        scenario = Scenario()
        rows = scenario.burst()
        self.assertFalse(scenario.observer.candidates(5))
        scenario.observer.suppress(rows[0], 30)
        self.assertFalse(scenario.poll(4, 96 * 1024, 1024))
        for now in range(5, 70):
            self.assertFalse(scenario.poll(now))
        self.assertEqual(scenario.observer.sample_count, 0)

    def test_resource_limits_reject_whole_partial_sample(self):
        for name, limit in (('MAX_TRACKED', 7), ('MAX_SAMPLES', 7)):
            with self.subTest(name=name), patch.object(fast, name, limit):
                scenario = Scenario()
                self.assertFalse(scenario.burst())
                self.assertTrue(scenario.observer.error)

    def test_observe_mode_logs_early_timing_without_installing_rules(self):
        scenario = Scenario(mode='observe')
        scenario.burst()
        firewall = FakeFirewall()
        with tempfile.TemporaryDirectory() as directory:
            worker = Worker(scenario.settings, engine=scenario.stream.engine, firewall=firewall,
                            runtime_dir=directory, clock=lambda: 3, wall=lambda: 1800000003)
            worker.connected = True
            worker.applied_generation = 0
            worker.fast = scenario.observer
            worker.evaluate(3)
            self.assertFalse(firewall.calls)
            record = worker.observations.recent[0]
            self.assertEqual(record['outcome'], 'would_block')
            self.assertEqual(record['evidence_source'], 'conntrack_fast')
            self.assertEqual(record['observed_seconds'], 3)
            self.assertEqual(record['connection_upload_bytes'], 294912)
            self.assertFalse(record['executed'])

    def test_late_protection_during_install_revokes_lease_before_next_action(self):
        for fields, guard in (({'detected_protocol_name': 'WireGuard'}, 'protected_transport'),
                              ({'proxy': True}, 'unsupported_proxy'),
                              ({'shared_transport': True}, 'shared_transport'),
                              ({'dns_host_name': 'safe.example'}, 'allowlisted')):
            with self.subTest(guard=guard), tempfile.TemporaryDirectory() as directory:
                scenario = Scenario(allow_domains=['safe.example'])
                scenario.burst()
                engine = scenario.stream.engine
                digests = {flow.peer: key[1] for key, flow in engine.flows.items()}
                firewall = FakeFirewall()
                worker = Worker(scenario.settings, engine=engine, firewall=firewall,
                                runtime_dir=directory, clock=lambda: 3, wall=lambda: 1800000003)
                worker.connected = worker.cleanup_ready = True
                worker.applied_generation = 0
                worker.fast = scenario.observer
                install = firewall.install

                def update_during_install(row, seconds, now):
                    lease = install(row, seconds, now)
                    worker.submit(dict(type='flow_stats', internal=True, interface='br-lan',
                                       flow=dict(digest=digests[row['peer']], **fields)))
                    return lease

                firewall.install = update_during_install
                with patch.object(firewall, 'release', wraps=firewall.release) as release:
                    worker.evaluate(3)
                    release.assert_called_once_with(firewall.calls[0]['id'], 3,
                                                    'protection_updated', guards=[guard])
                self.assertEqual(len(firewall.calls), 1)
                self.assertFalse(firewall.leases)
                self.assertEqual(worker.counters['protected_leases_released'], 1)
                self.assertFalse(worker.fast.holds)


class CounterSnapshotTests(unittest.TestCase):
    def payload(self, **fields):
        identity = ct.flow_tuple(ROW)
        accounting = b''.join(ct.attribute(0x8000 | key, ct.attribute(1, struct.pack('!Q', 10))
                                         + ct.attribute(2, struct.pack('!Q', amount)))
                              for key, amount in ((9, 1000), (10, 200)))
        return conntrack_payload(identity, **fields) + accounting

    def test_direct_counters_and_unsafe_paths(self):
        self.assertEqual(ct.counter_record(self.payload())['upload'], 1000)
        for fields in ({'zone': 1}, {'status': 0},
                       {'reply': (4, 6, '192.168.1.1', 7890, ROW['ip'], ROW['sport'])}):
            with self.subTest(fields=fields):
                self.assertIsNone(ct.counter_record(self.payload(**fields)))
        self.assertTrue(ct.counter_record(self.payload() + ct.attribute(8, struct.pack('!I', 1)))['excluded'])
        self.assertTrue(ct.counter_record(self.payload(status=8 | 1 << 14))['excluded'])
        self.assertIsNone(ct.counter_record(conntrack_payload(ct.flow_tuple(ROW))))

    def snapshot(self, packets, **kwargs):
        class Sock:
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def settimeout(self, *_): pass
            def bind(self, *_): pass
            def sendto(self, data, *_): self.sequence = struct.unpack_from('=I', data, 8)[0]
            def recvmsg(self, *_):
                body, kind, flags, sender, truncate = packets.pop(0)
                packet = struct.pack('=IHHII', len(body) + 16, kind, flags, self.sequence, 0) + body
                return packet, [], truncate, sender
        with patch.object(socket, 'AF_NETLINK', 16, create=True):
            return ct.counter_snapshot(sock_factory=lambda *_: Sock(), **kwargs)

    def test_atomic_multipart_dump_and_rejection_of_partial_output(self):
        record = (self.payload(), 0x100, 2, (0, 0), 0)
        done = (b'\0' * 4, 3, 2, (0, 0), 0)
        self.assertEqual(len(self.snapshot([record, done])), 1)
        for tail in ((b'\xff' * 4, 3, 2, (0, 0), 0),
                     (b'', 3, 0x12, (0, 0), 0),
                     (b'', 3, 2, (1, 0), 0),
                     (b'', 3, 2, (0, 0), socket.MSG_TRUNC), record):
            with self.subTest(tail=tail), self.assertRaises(ct.IdentityError):
                self.snapshot([record, tail, done])


class FastEnforcementTests(unittest.TestCase):
    def test_two_fresh_counter_increases_remove_the_extra_install_wait(self):
        scenario = Scenario()
        row = scenario.burst()[0]
        harness = firewall_tests.FirewallTests()
        harness.setUp()
        harness.identifier = row['ct_id']
        harness.firewall.neighbours = lambda *_: row['mac']
        self.assertEqual(harness.firewall.install(row, 30, 3)['ct_id'], row['ct_id'])
        self.assertFalse(harness.firewall.pending_identity)

    def test_fast_candidate_with_one_recent_increase_still_waits(self):
        scenario = Scenario()
        row = scenario.burst()[0]
        harness = firewall_tests.FirewallTests()
        harness.setUp()
        harness.identifier = row['ct_id']
        harness.firewall.neighbours = lambda *_: row['mac']
        row.pop('prior_upload_observed')
        self.assertIsNone(harness.firewall.install(row, 30, 3))
        self.assertTrue(harness.firewall.pending_identity)

    def test_kernel_id_reuse_is_rechecked_before_install(self):
        harness = firewall_tests.FirewallTests()
        harness.setUp()
        row = dict(ROW, evidence_source='conntrack_fast', ct_id=456)
        self.assertIsNone(harness.firewall.install(row, 30, 100))
        self.assertIn('identity changed', harness.firewall.error)
        self.assertFalse(harness.firewall.leases)


if __name__ == '__main__':
    unittest.main()
