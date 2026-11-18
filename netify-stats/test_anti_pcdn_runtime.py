"""Exercise subscriber isolation, loss handling and enforcement lifecycle."""
import copy
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'features'))
from anti_pcdn.config import DEFAULTS, save
from anti_pcdn.audit import AutoJournal, MAX_PENDING_BYTES
from anti_pcdn.runtime import Worker, QUEUE_LIMIT, QUEUE_DRAIN_LIMIT, MAX_ACTIONS
from netify_features import FeatureBridge


class FakeEngine:
    def __init__(self):
        self.counters = {}
        self.observations, self.gaps, self.suppressed, self.rows = [], [], [], []

    def observe(self, *args):
        self.observations.append(args)

    def gap(self, *args):
        self.gaps.append(args)

    def candidates(self, now):
        return copy.deepcopy(self.rows)

    def suppress(self, *args):
        self.suppressed.append(args)


class FakeFirewall:
    def __init__(self):
        self.leases, self.error, self.calls = {}, '', []
        self.pending = False
        self.pending_identity = False

    def install(self, row, seconds, now):
        self.calls.append(row)
        if self.pending:
            self.pending_identity = True
            return None
        self.pending_identity = False
        lease = dict(row, expires=now + seconds, state='installed')
        self.leases[row['id']] = lease
        return lease

    def release(self, token, now, reason='manual_release', **fields):
        del self.leases[token]
        return True

    def expire(self, now, cleanup=True):
        self.leases = {key: lease for key, lease in self.leases.items() if lease['expires'] > now}

    def clear(self, reason='worker_cleanup'):
        self.leases.clear()


class RuntimeTest(unittest.TestCase):
    def test_invalid_collector_input_invalidates_feature_coverage_once(self):
        from netify_collector import Collector
        collector = Collector.__new__(Collector)
        collector.invalid_messages, collector.minutes = 0, Mock()
        collector.handle = Mock()
        collector.features = FeatureBridge()
        collector.features.worker, collector.features.active = self.worker, True
        initial = self.worker.generation[0]
        for raw in (b'{broken', b'{"type":"flow","interface":[],"flow":{"digest":"x"}}'):
            collector.read_message(raw)
        self.assertEqual(collector.invalid_messages, 2)
        self.assertEqual(self.worker.generation[0], initial + 2)
        self.assertEqual(collector.minutes.note_gap.call_count, 2)
        collector.handle.assert_not_called()

    def test_requested_export_recovery_does_not_replay_cumulative_traffic(self):
        import netify_collector as collector
        from anti_pcdn.engine import Engine
        from test_minutes import CollectorMinuteTests
        self.worker.engine = Engine(self.settings, now=self.now)
        self.worker.submit(self.event(last_seen_at=int(self.wall * 1000), total_bytes=110))
        self.worker.consume(self.worker.queue.get_nowait())
        self.worker.publish(self.now)
        self.assertEqual(self.worker.recovery_keys, (('br-lan', 'x'),))
        raw = dict(digest='x', first_seen_at=int((self.wall - 30) * 1000),
                   last_seen_at=int(self.wall * 1000), total_bytes=10000,
                   local_bytes=10000, other_bytes=0,
                   local_mac='02:11:22:33:44:55', local_ip='192.168.1.2',
                   other_ip='8.8.8.8', local_port=8500, other_port=443,
                   ip_protocol=17, other_type='remote')
        bridge = FeatureBridge()
        bridge.worker, bridge.active = self.worker, True
        export_path = os.path.join(self.directory.name, 'export.json')
        with open(export_path, 'w') as handle:
            json.dump({'interfaces': {'br-lan': {'role': 'LAN'}}, 'flows': {'br-lan': [raw]}}, handle)
        with patch.object(collector.FeatureBridge, 'tick', return_value=None), \
                patch.object(collector, 'EXPORT_PATH', export_path), \
                CollectorMinuteTests().collector() as instance:
            instance.features = bridge
            instance.recover_metadata()
            self.assertEqual(self.worker.queue.qsize(), 1)
            instance.recover_metadata()
            self.assertEqual(self.worker.queue.qsize(), 1)  # Same export isn't queued again.
            self.assertEqual(instance.db.execute('SELECT SUM(upload) FROM hourly').fetchone()[0], None)
            self.worker.consume(self.worker.queue.get_nowait())
            flow = self.worker.engine.flows[('br-lan', 'x')]
            self.assertEqual(flow.total, 10000)
            self.assertFalse(flow.samples)
            self.now += 10
            self.wall += 10
            event = self.event(total_bytes=11020, last_seen_at=int(self.wall * 1000))
            event['flow'].update(local_bytes=1000, other_bytes=20)
            for _ in range(2):
                self.worker.submit(event)
                self.worker.consume(self.worker.queue.get_nowait())
            self.assertEqual(sum(sample[1] for sample in flow.samples), 1000)
            self.assertEqual(self.worker.engine.counters['duplicates'], 1)
            self.assertEqual(instance.db.execute('SELECT SUM(upload) FROM hourly').fetchone()[0], None)
            self.worker.publish(self.now)
            self.assertEqual(self.worker.recovery_keys, ())

    def test_missing_export_is_reported_without_stopping_live_collection(self):
        import netify_collector as collector
        from anti_pcdn.engine import Engine
        from test_minutes import CollectorMinuteTests
        self.worker.engine = Engine(self.settings, now=self.now)
        self.worker.submit(self.event(last_seen_at=int(self.wall * 1000), total_bytes=110))
        self.worker.consume(self.worker.queue.get_nowait())
        self.worker.publish(self.now)
        bridge = FeatureBridge()
        bridge.worker, bridge.active = self.worker, True
        with patch.object(collector.FeatureBridge, 'tick', return_value=None), \
                patch.object(collector, 'EXPORT_PATH', os.path.join(self.directory.name, 'absent.json')), \
                CollectorMinuteTests().collector() as instance:
            instance.features = bridge
            instance.recover_metadata()
            self.assertTrue(instance.export_error)
            self.assertTrue(self.worker.recovery_error)
            self.assertTrue(bridge.active)
            self.assertFalse(self.worker.stopping.is_set())

        export_path = os.path.join(self.directory.name, 'invalid-export.json')
        malformed = {'interfaces': {'br-lan': {'role': 'LAN'}}, 'flows': {'br-lan': [
            {'digest': 'x', 'detected_protocol_name': 'x' * 513}]}}
        for oversized in (True, False):
            with self.subTest(oversized=oversized):
                with open(export_path, 'w') as handle:
                    if oversized:
                        handle.truncate(collector.MAX_EXPORT_BYTES + 1)
                    else:
                        json.dump(malformed, handle)
                with patch.object(collector.FeatureBridge, 'tick', return_value=None), \
                        patch.object(collector, 'EXPORT_PATH', export_path), \
                        CollectorMinuteTests().collector() as instance:
                    instance.features = bridge
                    instance.recover_metadata()
                    self.assertTrue(self.worker.recovery_error)
                    self.assertEqual(self.worker.queue.qsize(), 0)
                    self.assertEqual(len(self.worker.engine.missing), 1)
                    self.assertTrue(bridge.active)

    def test_seed_queue_backpressure_does_not_claim_lost_live_increments(self):
        self.worker.recovery_keys = (('br-lan', 'x'),)
        for _ in range(QUEUE_LIMIT):
            self.worker.submit(self.event())
        generation = self.worker.generation
        self.assertFalse(self.worker.seed_metadata(self.event()))
        self.assertEqual(self.worker.generation, generation)
        self.assertEqual(self.worker.counters['recovery_deferred'], 1)
        self.assertEqual(self.worker.counters['queue_dropped'], 0)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.now, self.wall = 1000, 10000
        self.engine, self.firewall = FakeEngine(), FakeFirewall()
        self.settings = copy.deepcopy(DEFAULTS)
        self.settings.update(enabled=True, mode='auto')
        self.worker = Worker(self.settings, runtime_dir=self.directory.name,
                             engine=self.engine, firewall=self.firewall,
                             clock=lambda: self.now, wall=lambda: self.wall)
        self.worker.connected = True
        self.worker.cleanup_ready = True

    @staticmethod
    def event(**fields):
        return dict(type='flow_stats', internal=True, interface='br-lan',
                    flow=dict(digest='x', local_bytes=100, other_bytes=10, **fields))

    @staticmethod
    def row(number=0, **fields):
        return dict(id='%024x' % number, mac='02:11:22:33:44:55', score=80,
                    group='one', decision='block', guards=[], **fields)

    def test_projection_is_bounded_selected_lan_only_and_detached(self):
        message = self.event(unknown_nested={'huge': 'x' * 100000})
        self.worker.submit(dict(message, internal=False))
        self.worker.submit(dict(message, interface='eth0'))
        self.assertTrue(self.worker.queue.empty())
        self.worker.submit(message)
        message['flow']['local_bytes'] = 999
        self.worker.consume(self.worker.queue.get_nowait())
        event = self.engine.observations[0][0]
        self.assertEqual(event['flow']['local_bytes'], 100)
        self.assertNotIn('unknown_nested', event['flow'])
        self.worker.submit(self.event(host_server_name='x' * 513))
        self.assertEqual(self.worker.counters['invalid_events'], 1)

    def test_overflow_invalidates_queued_evidence_before_new_observations(self):
        for _ in range(QUEUE_LIMIT + 1):
            self.worker.submit(self.event())
        self.assertEqual(self.worker.queue.qsize(), QUEUE_LIMIT)
        self.assertEqual(self.worker.counters['queue_dropped'], 1)
        while not self.worker.queue.empty():
            self.worker.consume(self.worker.queue.get_nowait())
        self.assertFalse(self.engine.observations)
        self.assertEqual(self.engine.gaps[-1][1], 'queue_overflow')
        self.worker.submit(self.event())
        self.worker.consume(self.worker.queue.get_nowait())
        self.assertEqual(len(self.engine.observations), 1)

    def test_old_queue_and_disconnect_cannot_drive_actions(self):
        self.worker.submit(self.event())
        self.now += 6
        self.worker.consume(self.worker.queue.get_nowait())
        self.assertFalse(self.engine.observations)
        self.assertEqual(self.engine.gaps[-1][1], 'stale_queue')
        self.engine.rows = [self.row()]
        self.worker.connected = False
        self.worker.evaluate(self.now)
        self.assertFalse(self.firewall.calls)

    def test_observe_mode_and_guarded_rows_never_install(self):
        self.engine.rows = [self.row()]
        self.worker.settings['mode'] = 'observe'
        self.worker.evaluate(self.now)
        self.assertEqual(self.worker.rows[0]['score'], 80)
        self.assertFalse(self.firewall.calls)
        self.worker.settings['mode'] = 'auto'
        self.engine.rows[0]['guards'] = ['vpn']
        self.worker.evaluate(self.now)
        self.assertFalse(self.firewall.calls)

    def test_unconfirmed_startup_cleanup_prevents_new_actions(self):
        self.engine.rows = [self.row()]
        self.worker.cleanup_ready = False
        self.worker.evaluate(self.now)
        self.assertFalse(self.firewall.calls)

    def test_cleanup_success_requires_empty_lease_state(self):
        self.engine.rows = [self.row()]
        self.firewall.leases['old'] = dict(expires=self.now + 120, mac='old')
        self.firewall.clear = Mock(return_value=True)
        self.assertFalse(self.worker.clear_leases('cleanup_failed'))
        self.worker.evaluate(self.now)
        self.assertFalse(self.firewall.calls)

    def test_status_publication_does_not_run_firewall_maintenance(self):
        self.firewall.inspect = Mock(return_value={'supported': False})
        self.firewall.clear = Mock()
        self.worker.publish(self.now)
        self.firewall.inspect.assert_not_called()
        self.firewall.clear.assert_not_called()
        self.worker.check_platform(self.now)
        self.assertFalse(self.worker.execution_readiness['supported'])

    def test_auto_audit_tracks_deferrals_and_trigger_bytes_but_excludes_protected_rows(self):
        rows = [self.row(n, upload=200000, connection_upload_bytes=350000, threshold_met=True,
                         evidence_source='conntrack_fast', ct_id=n) for n in range(8)]
        rows[6]['guards'] = ['protected_transport']
        rows[7]['guards'] = ['allowlisted']
        self.engine.rows = rows
        self.firewall.pending = True
        self.worker.evaluate(self.now)
        self.worker.retries.clear()  # Revisit the exact same decision states.
        self.worker.evaluate(self.now)
        self.worker.publish(self.now)
        with open(self.worker.audit.path) as stream:
            entries = [json.loads(line) for line in stream]
        self.assertEqual(len(entries), 6)
        self.assertEqual({r['reason'] for r in entries}, {'identity_wait', 'action_budget'})
        self.assertTrue(all(r['connection_upload_bytes'] == 350000 for r in entries))
        self.assertEqual(os.stat(self.worker.audit.path).st_mode & 0o777, 0o600)

    def test_auto_audit_caps_buffer_reserves_lifecycle_space_and_rotates(self):
        journal = AutoJournal(self.directory.name)
        for n in range(500):
            journal.record('deferred', 1, self.row(n), detail='d' * 400)
        self.assertGreater(journal.dropped, 0)
        self.assertTrue(journal.record('first_drop', 2, self.row(), direction='upload'))
        self.assertLessEqual(journal.pending_bytes, MAX_PENDING_BYTES)
        with patch('anti_pcdn.audit.MAX_FILE_BYTES', MAX_PENDING_BYTES):
            with open(journal.path, 'wb') as handle:
                handle.truncate(MAX_PENDING_BYTES)
            journal.flush()
        self.assertEqual(journal.pending_bytes, 0)
        self.assertEqual(os.stat(journal.path + '.1').st_size, MAX_PENDING_BYTES)
        with open(journal.path) as stream:
            self.assertEqual([json.loads(line) for line in stream][-1]['kind'], 'first_drop')

    def test_unverified_kernel_write_does_not_feed_retry_evidence(self):
        self.engine.rows = [self.row()]
        def uncertain(row, seconds, now):
            self.firewall.leases[row['id']] = dict(row, expires=now + seconds,
                                                   state='unverified_cleanup_pending')
            self.firewall.error = 'readback and rollback failed'
            return None
        self.firewall.install = uncertain
        self.worker.evaluate(self.now)
        self.assertEqual(len(self.engine.suppressed), 1)
        self.assertEqual(self.worker.counters['leases_installed'], 0)
        self.assertEqual(self.worker.events[-1]['kind'], 'verification_failed')

    def test_action_budget_success_only_suppression_and_no_lease_renewal(self):
        self.engine.rows = [self.row(number) for number in range(20)]
        self.firewall.pending = True
        self.worker.evaluate(self.now)
        self.assertEqual(len(self.firewall.calls), MAX_ACTIONS)
        self.assertFalse(self.engine.suppressed)
        self.firewall.pending = False
        self.now += 10
        self.worker.evaluate(self.now)
        self.assertEqual(len(self.firewall.leases), MAX_ACTIONS)
        self.assertEqual(len(self.engine.suppressed), MAX_ACTIONS)
        expiry = self.firewall.leases[self.row()['id']]['expires']
        self.engine.rows = [self.row()]
        self.now += 10
        self.worker.evaluate(self.now)
        self.assertEqual(self.firewall.leases[self.row()['id']]['expires'], expiry)

    def test_failed_front_candidates_do_not_starve_later_connections(self):
        self.engine.rows = [self.row(number) for number in range(6)]
        install = self.firewall.install
        attempted = []
        def selective(row, seconds, now):
            attempted.append(row['id'])
            if row['id'] in {self.row(number)['id'] for number in range(4)}:
                return None
            return install(row, seconds, now)
        self.firewall.install = selective
        self.worker.evaluate(self.now)
        self.now += 10
        self.worker.evaluate(self.now)
        self.assertEqual(len(self.firewall.leases), 2)
        self.assertEqual(attempted, [self.row(number)['id'] for number in range(6)])

    def test_disconnect_during_install_rolls_back_and_stops_batch(self):
        self.engine.rows = [self.row(number) for number in range(6)]
        install = self.firewall.install
        def disconnect(row, seconds, now):
            lease = install(row, seconds, now)
            self.worker.connected = False
            self.worker.gap('disconnected')
            return lease
        self.firewall.install = disconnect
        self.worker.evaluate(self.now)
        self.assertEqual(len(self.firewall.calls), 1)
        self.assertFalse(self.firewall.leases)
        self.assertFalse(self.engine.suppressed)

    def test_ordinary_event_during_install_keeps_lease_and_rechecks_batch(self):
        self.engine.rows = [self.row(1), self.row(2)]
        install = self.firewall.install

        def submit_during_install(row, seconds, now):
            lease = install(row, seconds, now)
            self.worker.submit(self.event())
            return lease

        self.firewall.install = submit_during_install
        self.worker.evaluate(self.now)
        self.assertEqual(list(self.firewall.leases), [self.row(1)['id']])
        self.assertEqual(len(self.engine.observations), 1)
        self.assertEqual(len(self.engine.suppressed), 1)
        self.assertEqual(self.worker.counters['interrupted_installs'], 0)
        self.assertEqual(self.worker.counters['leases_kept_after_queue_drain'], 1)
        self.assertTrue(self.worker.queue.empty())
        self.worker.evaluate(self.now + 1)
        self.assertEqual(list(self.firewall.leases), [self.row(1)['id'], self.row(2)['id']])

    def test_backlog_after_install_withdraws_only_the_unreviewed_lease(self):
        self.worker.applied_generation = self.worker.generation[0]
        old = self.firewall.install(self.row(0), 120, self.now)
        self.engine.rows = [self.row(1), self.row(2)]
        install = self.firewall.install

        def backlog(row, seconds, now):
            lease = install(row, seconds, now)
            for _ in range(QUEUE_DRAIN_LIMIT + 1):
                self.worker.submit(self.event())
            return lease

        self.firewall.install = backlog
        with patch.object(self.firewall, 'release', wraps=self.firewall.release) as release:
            self.worker.evaluate(self.now)
            release.assert_called_once_with(self.row(1)['id'], self.now, 'observation_backlog')
        self.assertEqual(list(self.firewall.leases), [old['id']])
        self.assertEqual(len(self.engine.observations), QUEUE_DRAIN_LIMIT)
        self.assertEqual(self.worker.queue.qsize(), 1)
        self.assertFalse(self.engine.suppressed)

    def test_gap_during_scoring_vetoes_stale_candidates_with_empty_queue(self):
        def score_with_gap(_now):
            self.worker.gap('invalid_event')
            return [self.row(1)]

        self.engine.candidates = score_with_gap
        self.worker.evaluate(self.now)
        self.assertTrue(self.worker.queue.empty())
        self.assertFalse(self.firewall.calls)

    def test_failed_protection_cleanup_does_not_keep_another_new_lease(self):
        self.worker.applied_generation = self.worker.generation[0]
        protected = self.row(0, peer='192.0.2.1')
        self.firewall.install(protected, 120, self.now)
        self.engine.rows = [self.row(1, peer='192.0.2.2')]
        self.engine.protection_update = Mock(return_value=dict(protected, guards=['allowlisted']))
        install = self.firewall.install
        release = self.firewall.release

        def submit_during_install(row, seconds, now):
            lease = install(row, seconds, now)
            self.worker.submit(self.event())
            return lease

        def fail_protected_release(token, now, reason, **fields):
            if token == protected['id']:
                return False
            return release(token, now, reason, **fields)

        self.firewall.install = submit_during_install
        self.firewall.release = fail_protected_release
        self.firewall.clear = Mock(return_value=False)
        self.worker.evaluate(self.now)
        self.assertEqual(list(self.firewall.leases), [protected['id']])
        self.assertFalse(self.worker.cleanup_ready)
        self.assertEqual(self.worker.counters['interrupted_installs'], 1)
        self.assertFalse(self.engine.suppressed)

    def test_run_consumes_reports_arriving_during_kernel_poll_before_evaluation(self):
        self.worker.last_evaluation = self.now - 1
        self.worker.last_status = self.now
        self.worker.fast = Mock()
        self.engine.fast_metadata = Mock(return_value=[])
        self.worker.fast.poll.side_effect = lambda *_: self.worker.submit(self.event(total_bytes=110))
        self.worker.submit(self.event(total_bytes=100))

        def evaluate(_now):
            self.assertEqual([x[0]['flow']['total_bytes'] for x in self.engine.observations], [100, 110])
            self.worker.request_stop()

        self.worker.evaluate = Mock(side_effect=evaluate)
        self.worker.run()
        self.worker.evaluate.assert_called_once_with(self.now)
        self.assertEqual(self.worker.counters['evaluation_queue_deferred'], 0)

    def test_incomplete_window_takes_precedence_over_low_score_in_auto_audit(self):
        guarded = self.row(1, threshold_met=False, upload=200000, metrics={'peers': 10})
        guarded.update(guards=['incomplete_window'], decision='observe')
        complete = self.row(2, threshold_met=False, upload=200000, metrics={'peers': 10})
        complete.update(decision='observe')
        self.engine.rows = [guarded, complete]
        self.worker.evaluate(self.now)
        self.assertEqual([json.loads(line)['reason'] for line in self.worker.audit.pending],
                         ['evidence_incomplete', 'below_score'])

    def test_failed_release_after_interrupted_install_clears_owned_leases(self):
        self.engine.rows = [self.row(1), self.row(2)]
        install = self.firewall.install
        def interrupted(row, seconds, now):
            lease = install(row, seconds, now)
            self.worker.gap('queue_overflow')
            return lease
        self.firewall.install = interrupted
        self.firewall.release = lambda *_: False
        self.worker.evaluate(self.now)
        self.assertEqual(len(self.firewall.calls), 1)
        self.assertFalse(self.firewall.leases)
        self.assertFalse(self.engine.suppressed)
        self.assertEqual(self.worker.counters['interrupted_installs'], 1)

    def test_release_acknowledges_and_resets_observation_window(self):
        self.engine.rows = [self.row()]
        self.worker.evaluate(self.now)
        request = dict(id=self.row()['id'], request_id='a' * 32, timestamp=self.wall)
        path = os.path.join(self.directory.name, 'release.json')
        with open(path, 'w') as handle:
            json.dump(request, handle)
        self.worker.release_requests(self.now)
        self.assertFalse(self.firewall.leases)
        self.assertFalse(os.path.exists(path))
        self.assertEqual(self.worker.events[-1]['kind'], 'released')
        self.assertEqual(self.worker.events[-1]['request_id'], request['request_id'])
        self.assertEqual(self.engine.gaps[-1][1], 'manual_release')

    def test_expired_release_never_mutates_firewall_and_status_uses_wall_time(self):
        self.engine.rows = [self.row()]
        self.worker.evaluate(self.now)
        with open(os.path.join(self.directory.name, 'release.json'), 'w') as handle:
            json.dump(dict(id=self.row()['id'], request_id='a' * 32, timestamp=self.wall - 60), handle)
        self.worker.release_requests(self.now)
        self.assertTrue(self.firewall.leases)
        self.worker.publish(self.now)
        status = os.path.join(self.directory.name, 'status.json')
        with open(status) as handle:
            snapshot = json.load(handle)
        self.assertEqual(snapshot['leases'][0]['expires_at'], self.wall + 120)
        self.assertEqual(snapshot['leases'][0]['remaining'], 120)
        self.assertNotIn('expires', snapshot['leases'][0])
        self.assertEqual(os.stat(status).st_mode & 0o777, 0o600)

    def test_bridge_config_change_waits_for_old_worker_to_stop(self):
        config = os.path.join(self.directory.name, 'config.json')
        created = []
        def factory(*args):
            worker = Mock()
            worker.error = ''
            worker.is_alive.return_value = True
            created.append(worker)
            return worker
        bridge = FeatureBridge(config_path=config, factory=factory)
        bridge.tick()
        self.assertFalse(bridge.active)
        self.assertFalse(created)
        save(self.settings, config)
        bridge.tick()
        self.assertTrue(bridge.active)
        save(dict(self.settings, mode='observe'), config)
        bridge.tick()
        self.assertFalse(bridge.active)
        self.assertEqual(len(created), 1)
        created[0].request_stop.assert_called_once()
        created[0].is_alive.return_value = False
        bridge.tick()
        self.assertTrue(bridge.active)
        self.assertEqual(len(created), 2)
        save(dict(self.settings, enabled=False), config)
        bridge.tick()
        created[-1].is_alive.return_value = False
        bridge.tick()
        self.assertFalse(bridge.active)
        self.assertIsNone(bridge.worker)

    def test_collector_only_forwards_live_parsed_input_once(self):
        from netify_collector import Collector
        collector = Collector.__new__(Collector)
        collector.features = Mock(active=True)
        collector.handle = Mock()
        collector.invalid_messages = 0
        event = self.event()
        collector.read_message(json.dumps(event))
        collector.features.submit.assert_called_once_with(event)
        collector.handle.assert_called_once_with(event)
        collector.features.active = False
        collector.features.submit.reset_mock()
        collector.read_message(json.dumps(event))
        collector.features.submit.assert_not_called()
        collector.read_message('{bad json')
        collector.features.submit.assert_not_called()

    def test_actual_live_pipeline_scores_once_and_blocks_only_contributing_flows(self):
        from anti_pcdn.engine import Engine
        from netify_collector import Collector
        from test_anti_pcdn_engine import Stream, BASE
        stream = Stream()
        self.now, self.wall = 0, BASE
        self.worker.engine = Engine(self.settings, now=0)
        bridge = FeatureBridge()
        bridge.worker, bridge.active = self.worker, True
        collector = Collector.__new__(Collector)
        collector.features = bridge
        collector.handle, collector.invalid_messages = Mock(), 0
        def send(event):
            collector.read_message(json.dumps(event))
            if not self.worker.queue.empty():
                self.worker.consume(self.worker.queue.get_nowait())
        for number in range(21):
            send(stream.metadata(number))
        for now in range(10, 331, 10):
            self.now, self.wall = now, BASE + now
            for number in range(21):
                event = stream.event(number, now, up=65536 if number < 20 else 1024,
                                     down=1024 if number < 20 else 1024 * 1024)
                send(event)
                send(event)  # A duplicate export must not inflate any window.
                send(dict(event, internal=False, interface='wan'))
        self.worker.evaluate(self.now)
        self.assertEqual(self.worker.engine.counters['accepted_events'], 21 * 33)
        self.assertEqual(self.worker.engine.counters['duplicates'], 21 * 33)
        # The downloader reduces group upload ratio, so behavior alone is too
        # weak here. Its own guard also remains visible at a lower threshold.
        self.assertFalse(self.firewall.leases)
        self.worker.engine.settings['threshold'] = 60
        self.worker.evaluate(self.now)
        self.assertEqual(len(self.firewall.leases), MAX_ACTIONS)
        self.assertTrue(all(row['upload'] >= row['download'] * 3 for row in self.firewall.calls))
        self.assertTrue(any('not_uploading' in row['guards'] for row in self.worker.rows))


if __name__ == '__main__':
    unittest.main()
