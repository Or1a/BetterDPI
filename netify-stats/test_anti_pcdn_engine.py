"""Synthetic mechanism regressions, not a PCDN accuracy benchmark."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / 'features'))
from anti_pcdn import engine
from anti_pcdn.engine import Engine
from anti_pcdn.scoring import KIB, MIB, score

BASE = 1800000000
MAC = '02:11:22:33:44:55'


class Stream:
    def __init__(self, **settings):
        config = {'enabled': True, 'mode': 'auto'}
        config.update(settings)
        self.engine = Engine(config, now=0)
        self.totals = {}
        self.births = {}

    def metadata(self, number=0, now=0, **fields):
        raw = {'digest': str(number), 'first_seen_at': int((BASE + now) * 1000),
               'local_mac': MAC, 'local_ip': '192.168.1.2',
               'other_ip': '11.0.0.%d' % (number % 250 + 1),
               'local_port': 40000, 'other_port': 443, 'ip_protocol': 17,
               'other_type': 'remote', 'detected_protocol_name': 'QUIC'}
        raw.update(fields)
        self.births[number] = raw['first_seen_at']
        self.totals.setdefault(number, 0)
        message = {'type': 'flow', 'internal': True, 'interface': 'br-lan', 'flow': raw}
        self.engine.observe(message, now, BASE + now)
        return message

    def event(self, number=0, now=10, up=64*KIB, down=KIB, kind='flow_stats', **fields):
        self.totals[number] = self.totals.get(number, 0) + up + down
        raw = {'digest': str(number), 'last_seen_at': int((BASE + now) * 1000),
               'local_bytes': up, 'other_bytes': down, 'total_bytes': self.totals[number]}
        raw.update(fields)
        message = {'type': kind, 'internal': True, 'interface': 'br-lan', 'flow': raw}
        self.engine.observe(message, now, BASE + now)
        return message

    def populate(self, count=20, until=330, up=64*KIB, down=KIB, **metadata):
        for number in range(count):
            self.metadata(number, **metadata)
        for now in range(10, until + 1, 10):
            for number in range(count):
                self.event(number, now, up, down)
        return self.engine.candidates(until)


class ScoringTests(unittest.TestCase):
    def test_independent_families_are_capped_and_behavior_can_reach_eighty(self):
        metrics = {'peers': 100000, 'serving_peers': 100000,
                   'upload_minutes': 500, 'upload': 20*MIB, 'download': MIB}
        self.assertEqual(score(metrics)[0], 80)
        self.assertEqual(score(metrics, True)[0], 100)
        self.assertEqual(score({}, True)[0], 20)


class ObserverTests(unittest.TestCase):
    def test_small_ports_do_not_reserve_upload_groups_and_new_upload_is_observed(self):
        stream = Stream()
        for number in range(32):
            stream.metadata(number, local_port=40000 + number, ip_protocol=6)
        for number in range(32):
            stream.event(number, 10, up=100, down=200)
        self.assertEqual(len(stream.engine.groups), 0)
        stream.metadata(100, 10, local_port=8500)
        for now in range(20, 341, 10):
            for number in range(32):
                stream.event(number, now, up=100, down=200)
            stream.event(100, now, up=MIB, down=KIB)
        target = next(row for row in stream.engine.candidates(340) if row['sport'] == 8500)
        self.assertGreater(target['upload'], 0)
        self.assertEqual(len(stream.engine.groups), 1)
        self.assertEqual(len(stream.engine.flows), 33)
        self.assertEqual(stream.engine.counters['capacity_drops'], 0)
        self.assertNotIn('short_window_only', target['guards'])

    def test_closed_small_flows_keep_dedup_without_reserving_groups(self):
        stream = Stream()
        for number in range(32):
            stream.metadata(number, local_port=40000 + number)
        for number in range(32):
            stream.event(number, 1, up=100, down=200, kind='flow_purge')
        stream.metadata(100, 2, local_port=8500)
        event = stream.event(100, 10)
        stream.engine.observe(event, 11, BASE + 11)
        self.assertEqual(len(stream.engine.flows), 33)
        self.assertEqual(len(stream.engine.groups), 1)
        self.assertEqual(stream.engine.counters['duplicates'], 1)

    def test_cross_port_device_evidence_is_visible_but_never_authorizes_other_connections(self):
        stream = Stream()
        for number in range(20):
            stream.metadata(number, local_port=40000 + number)
        for now in range(10, 331, 10):
            for number in range(20):
                stream.event(number, now)
        rows = stream.engine.candidates(330)
        device = stream.engine.device_rows[0]
        self.assertEqual(device['score'], 80)
        self.assertEqual(device['ports'], 20)
        self.assertTrue(device['complete'])
        self.assertTrue(device['observation_only'])
        self.assertTrue(all(row['device_score'] == 80 and row['score'] == 0 and row['decision'] == 'observe' for row in rows))
        # Domain/host opt-outs still exclude their samples from device evidence.
        stream.engine.settings['allow_devices'] = [MAC]
        stream.engine.candidates(330)
        self.assertEqual(stream.engine.device_rows, [])

    def test_exclusion_cache_overflow_does_not_invalidate_known_unrelated_evidence(self):
        stream = Stream()
        stream.populate()
        for number in range(1000, 1000 + engine.MAX_IGNORED + 1):
            stream.metadata(number, 331, other_type='local')
        self.assertEqual(len(stream.engine.ignored), engine.MAX_IGNORED)
        self.assertEqual(stream.engine.counters['exclusion_capacity'], 1)
        self.assertTrue(all(row['decision'] == 'block' for row in stream.engine.candidates(331)))
        # An uncached, unidentifiable stats event is still quarantined until
        # its metadata proves that it really belongs to excluded traffic.
        number = 1000 + engine.MAX_IGNORED
        stream.event(number, 332)
        self.assertTrue(all(row['decision'] == 'observe' for row in stream.engine.candidates(332)))
        stream.metadata(number, 333, first_seen_at=(BASE + 331) * 1000, other_type='local')
        self.assertTrue(all(row['decision'] == 'block' for row in stream.engine.candidates(333)))

    def test_metadata_recovery_seeds_watermark_and_scopes_loss_without_replaying_bytes(self):
        stream = Stream()
        stream.populate()
        stream.event(1000, 331)
        self.assertGreater(stream.engine.coverage(331)['global_wait_seconds'], 0)
        raw = dict(digest='1000', first_seen_at=(BASE + 300) * 1000,
                   last_seen_at=(BASE + 331) * 1000, total_bytes=100*MIB,
                   local_bytes=100*MIB, other_bytes=0, local_mac='02:22:33:44:55:66',
                   local_ip='192.168.1.3', other_ip='8.8.8.8', local_port=8500,
                   other_port=443, ip_protocol=17, other_type='remote')
        stream.engine.observe(dict(type='flow_seed', interface='br-lan', internal=True, flow=raw), 332, BASE + 332)
        self.assertEqual(stream.engine.coverage(332)['global_wait_seconds'], 0)
        self.assertTrue(all(row['decision'] == 'block' for row in stream.engine.candidates(332)))
        flow = stream.engine.flows[('br-lan', '1000')]
        self.assertFalse(flow.samples)
        stream.event(1000, 333, up=100, down=20, total_bytes=100*MIB + 120)
        target = next(row for row in stream.engine.candidates(333) if row['sport'] == 8500)
        self.assertEqual((target['upload'], target['download']), (100, 20))
        self.assertIn('incomplete_window', target['guards'])
        stream.event(1000, 334, up=100, down=20, total_bytes=100*MIB, last_seen_at=(BASE + 330) * 1000)
        self.assertEqual(stream.engine.counters['recovery_overlap'], 1)
        self.assertEqual(sum(sample[1] for sample in flow.samples), 100)

    def test_unresolved_metadata_and_scoring_capacity_remain_bounded_and_fail_open(self):
        stream = Stream()
        stream.populate()
        for number in range(engine.MAX_RECOVERY + 1):
            stream.event(1000 + number, 331)
        self.assertEqual(len(stream.engine.missing), engine.MAX_RECOVERY)
        self.assertEqual(stream.engine.counters['recovery_capacity'], 1)
        self.assertTrue(all(row['decision'] == 'observe' for row in stream.engine.candidates(331)))
        other = Stream()
        for number in range(33):
            other.metadata(number, local_port=40000 + number)
        for number in range(33):
            other.event(number, 10)
        self.assertEqual(len(other.engine.groups), engine.MAX_DEVICE_GROUPS)
        self.assertEqual(len(other.engine.flows), 33)
        self.assertEqual(other.engine.counters['device_group_capacity'], 1)
        self.assertTrue(all(row['decision'] == 'observe' for row in other.engine.candidates(10)))

    def test_recovered_same_group_keeps_group_guard_for_a_full_new_window(self):
        stream = Stream()
        stream.populate()
        stream.event(1000, 331)
        metadata = dict(digest='1000', first_seen_at=(BASE + 300) * 1000,
                        last_seen_at=(BASE + 331) * 1000, total_bytes=1000,
                        local_mac=MAC, local_ip='192.168.1.2', other_ip='8.8.8.8',
                        local_port=40000, other_port=443, ip_protocol=17, other_type='remote')
        stream.engine.observe(dict(type='flow_seed', interface='br-lan', internal=True, flow=metadata), 332, BASE + 332)
        self.assertEqual(stream.engine.coverage(332)['global_wait_seconds'], 0)
        self.assertTrue(all(row['decision'] == 'observe' and row['wait_seconds'] >= 300
                            for row in stream.engine.candidates(332)))

    def test_many_known_inactive_losses_do_not_block_an_unrelated_complete_group(self):
        stream = Stream()
        stream.populate()
        for number in range(1000, 1000 + engine.MAX_GROUPS + 1):
            stream.metadata(number, 331, local_port=number)
        for number in range(1000, 1000 + engine.MAX_GROUPS + 1):
            stream.event(number, 332, total_bytes=1)
        self.assertEqual(stream.engine.coverage(332)['global_wait_seconds'], 0)
        self.assertEqual(stream.engine.counters['counter_gaps'], engine.MAX_GROUPS + 1)
        self.assertTrue(all(row['decision'] == 'block' for row in stream.engine.candidates(332)))
        stream.event(1000, 333, total_bytes=1 + 65*KIB)
        row = next(row for row in stream.engine.candidates(333) if row['sport'] == 1000)
        self.assertEqual(row['decision'], 'observe')
        self.assertIn('incomplete_window', row['guards'])

    def test_recovery_rejects_wrong_identity_and_future_snapshot_without_resolving_gap(self):
        for fields in ({'first_seen_at': (BASE + 1)*1000},
                       {'last_seen_at': (BASE + 100)*1000},
                       {'total_bytes': -1}):
            with self.subTest(fields=fields):
                stream = Stream()
                stream.event(now=10, first_seen_at=BASE*1000)
                raw = dict(digest='0', first_seen_at=BASE*1000,
                           last_seen_at=(BASE + 10)*1000, total_bytes=65*KIB)
                raw.update(fields)
                stream.engine.observe(dict(type='flow_seed', interface='br-lan', internal=True, flow=raw), 11, BASE + 11)
                self.assertEqual(len(stream.engine.missing), 1)
                self.assertFalse(stream.engine.flows)
                self.assertEqual(stream.engine.counters['recovery_rejected'], 1)

    def test_default_behavior_threshold_is_inclusive_and_mode_is_respected(self):
        stream = Stream()
        rows = stream.populate()
        self.assertEqual(len(rows), 20)
        self.assertTrue(all(row['score'] == 80 and row['decision'] == 'block' for row in rows))
        self.assertTrue(all(not row['guards'] for row in rows))
        self.assertEqual(len({row['group'] for row in rows}), 1)
        self.assertEqual(rows[0]['last_observed'], 330)
        self.assertEqual(rows[0]['metrics']['peers'], 20)
        observed = Stream(mode='observe').populate()
        self.assertTrue(all(row['threshold_met'] and row['decision'] == 'observe' for row in observed))
        stricter = Stream(threshold=81).populate()
        self.assertTrue(all(row['decision'] == 'observe' for row in stricter))

    def test_disabled_feature_does_not_allocate_windows(self):
        stream = Stream(enabled=False)
        stream.metadata()
        stream.event()
        self.assertEqual(stream.engine.flows, {})
        self.assertEqual(stream.engine.groups, {})
        self.assertEqual(stream.engine.candidates(10), [])

    def test_protocol_requires_an_exact_supported_integer(self):
        for protocol in (6.0, 17.0, True, '6'):
            with self.subTest(protocol=protocol):
                stream = Stream()
                stream.metadata(ip_protocol=protocol)
                stream.event()
                self.assertEqual(stream.engine.flows, {})
                self.assertEqual(stream.engine.groups, {})
                self.assertEqual(stream.engine.counters['invalid_events'], 1)
                self.assertEqual(stream.engine.counters['missing_metadata'], 0)

    def test_metadata_snapshots_and_wan_mirrors_do_not_count(self):
        stream = Stream()
        metadata = stream.metadata(local_bytes=100*MIB, other_bytes=0, total_bytes=100*MIB)
        self.assertEqual(stream.engine.candidates(0), [])
        event = stream.event()
        before = stream.engine.candidates(10)
        stream.engine.observe(metadata, 10, BASE + 10)
        for changed in ({'internal': False}, {'interface': 'wan'}, {'internal': 1}, {'interface': 'br-guest'}):
            stream.engine.observe(dict(event, **changed), 10, BASE + 10)
        self.assertEqual(stream.engine.candidates(10), before)

    def test_ipv6_identity_is_separate_and_router_local_legs_are_excluded(self):
        stream = Stream()
        stream.metadata(0)
        stream.metadata(1, local_ip='2001:4860::2', other_ip='2606:4700::1111')
        stream.event(0)
        stream.event(1)
        rows = stream.engine.candidates(10)
        self.assertEqual(len({row['group'] for row in rows}), 2)
        self.assertEqual({row['peer'] for row in rows}, {'11.0.0.1', '2606:4700::1111'})
        stream.metadata(2, 10, other_ip='192.168.1.3')
        stream.metadata(3, 10, other_ip='224.0.0.1')
        stream.event(2, 11)
        stream.event(3, 11)
        self.assertEqual(stream.engine.counters['missing_metadata'], 0)
        router = Engine({'enabled': True}, now=0, router_macs=[MAC])
        router.observe(stream.metadata(4, 11), 11, BASE+11)
        router.observe(stream.event(4, 12), 12, BASE+12)
        self.assertEqual(router.flows, {})
        self.assertEqual(router.counters['missing_metadata'], 0)

    def test_duplicate_and_final_purge_do_not_add_bytes_twice(self):
        stream = Stream()
        stream.metadata()
        event = stream.event()
        before = stream.engine.candidates(10)[0]['upload']
        stream.engine.observe(event, 10, BASE+10)
        self.assertEqual(stream.engine.candidates(10)[0]['upload'], before)
        stream.engine.observe(dict(event, type='flow_purge'), 10, BASE+10)
        self.assertEqual(stream.engine.candidates(10), [])
        self.assertEqual(stream.engine._sample_count, 1)
        self.assertEqual(stream.engine.counters['accepted_events'], 1)

    def test_purge_with_final_new_bytes_counts_once_and_keeps_tombstone(self):
        stream = Stream()
        stream.metadata()
        stream.event()
        last = stream.event(now=20, kind='flow_purge')
        stream.engine.observe(last, 21, BASE+21)
        flow = next(iter(stream.engine.flows.values()))
        self.assertEqual(sum(sample[1] for sample in flow.samples), 128*KIB)
        self.assertEqual(stream.engine.counters['accepted_events'], 2)
        self.assertTrue(flow.closed)

    def test_counter_overlap_gap_and_regression_invalidate_actions(self):
        for delta in (-1, 1):
            with self.subTest(delta=delta):
                stream = Stream()
                stream.populate()
                previous = stream.totals[0]
                stream.event(0, 340, total_bytes=previous + 65*KIB + delta)
                rows = stream.engine.candidates(340)
                self.assertTrue(rows)
                self.assertTrue(all(row['decision'] == 'observe' for row in rows))
                self.assertTrue(all('incomplete_window' in row['guards'] for row in rows))
                self.assertEqual(stream.engine.counters['counter_gaps'], 1)
        stream = Stream()
        stream.metadata()
        stream.event()
        stream.event(now=20, total_bytes=1)
        self.assertEqual(stream.engine.counters['regressions'], 1)
        self.assertEqual(next(iter(stream.engine.flows.values())).total, 65*KIB)

    def test_late_and_long_interval_reports_never_create_arrival_bursts(self):
        stream = Stream()
        stream.metadata()
        stream.event(now=100, up=100*MIB, last_seen_at=(BASE+10)*1000)
        self.assertEqual(stream.engine.candidates(100), [])
        stream.event(now=110, up=100*MIB)
        self.assertEqual(stream.engine.candidates(110), [])
        self.assertEqual(stream.engine.counters['delayed_events'], 2)
        stream.event(now=120, up=100*KIB)
        self.assertLessEqual(stream.engine.candidates(120)[0]['upload'], 100*KIB)

    def test_interval_bytes_are_distributed_across_source_time(self):
        stream = Stream()
        stream.metadata()
        stream.event(now=60, up=6*MIB, down=0)
        flow = next(iter(stream.engine.flows.values()))
        self.assertEqual([sample[1] for sample in flow.samples], [MIB]*6)
        self.assertEqual(stream.engine.candidates(60)[0]['metrics']['upload_minutes'], 1)

    def test_large_counters_conserve_integer_bytes_exactly(self):
        stream = Stream()
        stream.metadata()
        upload = (1 << 60) + 123
        stream.event(now=57, up=upload, down=12345)
        flow = next(iter(stream.engine.flows.values()))
        self.assertEqual(sum(sample[1] for sample in flow.samples), upload)
        self.assertEqual(sum(sample[2] for sample in flow.samples), 12345)

    def test_true_missing_metadata_gaps_but_deliberate_exclusions_do_not(self):
        stream = Stream()
        stream.populate()
        stream.metadata(100, 330, other_type='local')
        stream.event(100, 340)
        self.assertEqual(stream.engine.counters['missing_metadata'], 0)
        self.assertTrue(any(row['decision'] == 'block' for row in stream.engine.candidates(340)))
        stream.event(101, 340)
        self.assertTrue(all(row['decision'] == 'observe' for row in stream.engine.candidates(340)))
        self.assertEqual(stream.engine.counters['missing_metadata'], 1)

    def test_normal_downloads_and_small_handshake_churn_do_not_block(self):
        downloads = Stream().populate(up=KIB, down=MIB)
        handshakes = Stream().populate(up=100, down=30)
        for rows in (downloads, handshakes):
            self.assertTrue(all(row['score'] < 80 for row in rows))
            self.assertTrue(all(row['decision'] == 'observe' for row in rows))

    def test_high_group_score_cannot_target_non_uploading_member(self):
        stream = Stream()
        stream.populate()
        stream.metadata(100, 330)
        stream.event(100, 331, up=100, down=MIB)
        row = next(row for row in stream.engine.candidates(331) if row['peer'] == '11.0.0.101')
        self.assertGreaterEqual(row['score'], 80)
        self.assertEqual(row['decision'], 'observe')
        self.assertIn('not_uploading', row['guards'])

    def test_udp_stun_quic_are_neutral_but_known_vpn_is_guarded(self):
        for protocol in ('UDP', 'STUN', 'QUIC'):
            with self.subTest(protocol=protocol):
                self.assertTrue(all(row['decision'] == 'block' for row in
                                    Stream().populate(detected_protocol_name=protocol)))
        stream = Stream()
        stream.populate()
        stream.metadata(0, 330, first_seen_at=BASE*1000, detected_protocol_name='WireGuard')
        row = next(row for row in stream.engine.candidates(330) if row['peer'] == '11.0.0.1')
        self.assertIn('protected_transport', row['guards'])
        self.assertEqual(row['decision'], 'observe')

    def test_allowlist_is_authoritative_and_matching_respects_domain_boundaries(self):
        rows = Stream(allow_devices=[MAC]).populate()
        self.assertTrue(all('allowlisted' in row['guards'] and row['decision'] == 'observe' for row in rows))
        stream = Stream(allow_domains=['trusted.example'], pcdn_domains=['uploader.example'])
        stream.metadata(host_server_name='node.trusted.example')
        stream.event()
        self.assertIn('allowlisted', stream.engine.candidates(10)[0]['guards'])
        stream.metadata(1, 10, host_server_name='eviltrusted.example', dns_host_name='uploader.example')
        stream.event(1, 20)
        row = next(row for row in stream.engine.candidates(20) if row['peer'] == '11.0.0.2')
        self.assertNotIn('allowlisted', row['guards'])
        self.assertNotIn('domain', {reason['id'] for reason in row['reasons']})

    def test_same_flow_domain_hint_does_not_spread_to_other_peers(self):
        stream = Stream(pcdn_domains=['uploader.example'])
        stream.populate()
        stream.metadata(0, 330, first_seen_at=BASE*1000, host_server_name='edge.uploader.example')
        rows = stream.engine.candidates(330)
        self.assertEqual([row['score'] for row in rows].count(100), 1)
        self.assertEqual([row['score'] for row in rows].count(80), 19)

    def test_dns_hint_honors_allowlist_without_creating_domain_score(self):
        stream = Stream(allow_domains=['trusted.example'], pcdn_domains=['trusted.example'])
        stream.metadata(dns_host_name='edge.trusted.example')
        stream.event()
        row = stream.engine.candidates(10)[0]
        self.assertIn('allowlisted', row['guards'])
        self.assertNotIn('domain', {reason['id'] for reason in row['reasons']})
        stream.metadata(now=11, first_seen_at=BASE*1000, host_server_name='different.example')
        self.assertIn('allowlisted', stream.engine.candidates(11)[0]['guards'])

    def test_observed_host_multiplexing_and_proxy_evidence_prevent_action(self):
        for fields in ({'shared_transport': True}, {'proxy': True}, {'attribution': 'redirect'}):
            stream = Stream()
            rows = stream.populate(**fields)
            self.assertTrue(all(row['guards'] and row['decision'] == 'observe' for row in rows))
        stream = Stream()
        stream.metadata(host_server_name='one.example')
        stream.metadata(now=1, first_seen_at=BASE*1000, host_server_name='two.example')
        stream.event(now=10)
        self.assertIn('shared_transport', stream.engine.candidates(10)[0]['guards'])

    def test_reused_digest_requires_new_identity_and_cannot_replay_old_purge(self):
        stream = Stream()
        stream.metadata(host_server_name='old.example')
        old = stream.event()
        old_id = stream.engine.candidates(10)[0]['id']
        stream.metadata(now=20, host_server_name='new.example')
        stream.totals[0] = 0
        stream.engine.observe(dict(old, type='flow_purge'), 21, BASE+21)
        stream.event(now=30)
        row = stream.engine.candidates(30)[0]
        self.assertNotEqual(row['id'], old_id)
        self.assertEqual(row['host'], 'new.example')
        self.assertEqual(row['upload'], 64*KIB)
        self.assertEqual(stream.engine.counters['invalid_events'], 1)

    def test_same_birth_cannot_change_target_tuple(self):
        stream = Stream()
        stream.metadata()
        stream.event()
        stream.metadata(now=11, first_seen_at=BASE*1000, other_ip='8.8.8.8')
        row = stream.engine.candidates(11)[0]
        self.assertEqual(row['peer'], '11.0.0.1')
        self.assertIn('identity_changed', row['guards'])

    def test_source_gap_and_clock_jump_require_fresh_coverage(self):
        stream = Stream()
        rows = stream.populate()
        self.assertTrue(all(row['decision'] == 'block' for row in rows))
        stream.engine.gap(331, 'socket_reconnect')
        self.assertTrue(all('incomplete_window' in row['guards'] for row in stream.engine.candidates(331)))
        stream.engine.observe({}, 332, BASE+1000)
        self.assertEqual(stream.engine.counters['clock_gaps'], 1)
        self.assertEqual(stream.engine.candidates(100), [])
        self.assertEqual(stream.engine._sample_count, 0)

    def test_suppression_removes_blocked_flow_and_requires_its_fresh_window(self):
        stream = Stream()
        rows = stream.populate(count=24)
        stream.engine.suppress(rows[0], 450)
        blocked_id = rows[0]['id']
        remaining = stream.engine.candidates(330)
        self.assertEqual(len(remaining), 23)
        self.assertTrue(all(row['decision'] == 'block' for row in remaining))
        self.assertNotIn(blocked_id, {row['id'] for row in remaining})
        for now in range(340, 451, 10):
            for number in range(24):
                stream.event(number, now)
        self.assertNotIn(blocked_id, {row['id'] for row in stream.engine.candidates(450)})
        self.assertGreater(stream.engine.counters['suppressed_events'], 0)
        for now in range(460, 741, 10):
            for number in range(24):
                stream.event(number, now)
        held = next(row for row in stream.engine.candidates(740) if row['id'] == blocked_id)
        self.assertEqual(held['decision'], 'observe')
        self.assertIn('incomplete_window', held['guards'])
        for number in range(24):
            stream.event(number, 750)
        self.assertTrue(all(row['decision'] == 'block' for row in stream.engine.candidates(750)))
        self.assertEqual(stream.engine.counters['suppressions'], 1)

    def test_new_digest_same_suppressed_tuple_cannot_restore_retry_samples(self):
        stream = Stream()
        stream.metadata()
        stream.event()
        row = stream.engine.candidates(10)[0]
        stream.engine.suppress(row, 130)
        stream.metadata(100, 20, other_ip=row['peer'])
        stream.event(100, 30, up=100*MIB)
        self.assertEqual(stream.engine.candidates(30), [])
        self.assertEqual(stream.engine._sample_count, 0)

    def test_low_capacity_keeps_existing_dedup_cursors_and_fails_open(self):
        stream = Stream()
        with patch.object(engine, 'MAX_FLOWS', 2):
            stream.metadata(0)
            stream.metadata(1)
            event = stream.event(0)
            stream.metadata(2, 10)
            stream.engine.observe(event, 11, BASE+11)
        self.assertEqual(len(stream.engine.flows), 2)
        self.assertEqual(stream.engine.counters['accepted_events'], 1)
        self.assertEqual(stream.engine.counters['duplicates'], 1)
        self.assertEqual(stream.engine.counters['capacity_drops'], 1)
        self.assertTrue(all(row['decision'] == 'observe' for row in stream.engine.candidates(11)))

    def test_browsing_port_churn_cannot_disable_unrelated_complete_groups(self):
        stream = Stream()
        stream.populate()
        for number in range(100, 150):
            stream.metadata(number, 330, local_mac='02:22:33:44:55:66',
                            local_ip='192.168.1.3', local_port=20000+number, ip_protocol=6)
        for number in range(100, 150):
            stream.event(number, 331, up=100, down=200)
        rows = [row for row in stream.engine.candidates(331) if row['mac'] == MAC]
        self.assertEqual(len(rows), 20)
        self.assertTrue(all(row['decision'] == 'block' for row in rows))
        self.assertEqual(stream.engine.counters['capacity_drops'], 0)
        self.assertEqual(len(stream.engine.flows), 70)
        self.assertEqual(stream.engine.counters['missing_metadata'], 0)

    def test_same_connection_under_two_digests_is_counted_only_once(self):
        stream = Stream()
        stream.metadata(0)
        event = stream.event(0)
        stream.metadata(100, 10, first_seen_at=BASE*1000, other_ip='11.0.0.1')
        stream.engine.observe(dict(event, flow=dict(event['flow'], digest='100')), 10, BASE+10)
        self.assertEqual(stream.engine.counters['accepted_events'], 1)
        self.assertEqual(len(stream.engine.candidates(10)), 1)
        self.assertEqual(stream.engine.counters['duplicate_identities'], 1)

    def test_sample_capacity_is_hard_and_loss_is_visible(self):
        stream = Stream()
        stream.metadata()
        with patch.object(engine, 'MAX_SAMPLES', 1):
            stream.event()
            rejected = stream.event(now=20)
            stream.engine.observe(rejected, 20, BASE+20)
        self.assertEqual(stream.engine._sample_count, 1)
        self.assertEqual(stream.engine.counters['sample_drops'], 1)
        self.assertEqual(stream.engine.counters['duplicates'], 1)

    def test_stale_candidates_and_old_scores_decay_without_new_reports(self):
        stream = Stream()
        stream.populate()
        for now in range(340, 391, 10):
            stream.event(0, now, up=100, down=20)
        rows = stream.engine.candidates(390)
        self.assertTrue(all(row['score'] < 80 and row['decision'] == 'observe' for row in rows))
        self.assertEqual(stream.engine.candidates(406), [])


if __name__ == '__main__':
    unittest.main()
