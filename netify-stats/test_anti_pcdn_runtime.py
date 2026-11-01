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
from anti_pcdn.runtime import Worker, QUEUE_LIMIT, MAX_ACTIONS
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

    def release(self, token, now):
        del self.leases[token]
        return True

    def expire(self, now):
        self.leases = {key: lease for key, lease in self.leases.items() if lease['expires'] > now}

    def clear(self):
        self.leases.clear()


class RuntimeTest(unittest.TestCase):
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
