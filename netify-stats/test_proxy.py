import os
import json
import tempfile
import time
import unittest
from collections import OrderedDict
from contextlib import contextmanager
from unittest.mock import patch

import netify_collector as collector
import netify_storage as storage
from netify_proxy import RedirectMap


class ProxyTest(unittest.TestCase):
    @contextmanager
    def collector(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(collector, 'DATA_DIR', directory), patch.object(collector, 'RUNTIME_DIR', directory), patch.object(collector, 'DB_PATH', os.path.join(directory, 'stats.db')), patch.object(collector, 'EXPORT_PATH', os.path.join(directory, 'export.json')):
            instance = collector.Collector()
            instance.local_macs = {'aa:aa:aa:aa:aa:aa'}
            instance.proxy.refresh = lambda: None
            instance.proxy.ports = {7892}
            try:
                yield instance
            finally:
                instance.db.close()

    @staticmethod
    def stats(digest, interface='br-lan', upload=100, download=200, kind='flow_stats'):
        return {'type': kind, 'interface': interface, 'internal': True,
                'flow': {'digest': digest, 'local_bytes': upload, 'other_bytes': download}}

    @staticmethod
    def metadata(digest, interface='br-lan'):
        return {'interface': interface, 'internal': True, 'flow': {
            'digest': digest, 'other_type': 'remote', 'local_mac': 'bb:bb:bb:bb:bb:bb',
            'local_ip': '10.1.1.2', 'other_ip': '203.0.113.4'}}

    def fill_and_prune_hour(self, instance, bucket):
        instance.db.executemany('INSERT INTO hourly VALUES (?,?,?,?,?,?,?,?,?)',
            ((bucket, 'fillmac', '10.1.1.3', 'Unknown', 'TLS',
              '%06d.' % i + '.'.join(['a'*60]*3) + '.example', 1, 1, 1)
             for i in range(25000)))
        instance.db.commit()
        with patch.object(storage, 'read_limit', return_value=4), patch.object(storage.time, 'time', return_value=bucket+1):
            for _ in range(40):
                instance.storage.maintain()
                if instance.storage.pruned_hours:
                    break
        self.assertGreater(instance.storage.pruned_hours, 0)

    def test_mapping_direction_and_no_double_count(self):
        line = 'ipv4 2 tcp 6 100 src=10.1.1.2 dst=203.0.113.4 sport=12345 dport=443 packets=1 bytes=10 src=10.1.1.1 dst=10.1.1.2 sport=7892 dport=12345 packets=1 bytes=20'
        entries = dict(RedirectMap.parse(line, {7892}))
        self.assertEqual(len(entries), 4)
        self.assertEqual(RedirectMap.parse(line, {22}), [])
        self.assertEqual(RedirectMap.parse(line.replace('src=10.1.1.1', 'src=203.0.113.4'), {7892}), [])
        with tempfile.TemporaryDirectory() as directory, patch.object(collector, 'DATA_DIR', directory), patch.object(collector, 'RUNTIME_DIR', directory), patch.object(collector, 'DB_PATH', os.path.join(directory, 'stats.db')):
            instance = collector.Collector()
            instance.local_macs = {'aa:aa:aa:aa:aa:aa'}
            instance.proxy.refresh = lambda: None
            instance.proxy.entries = entries
            original = {'digest':'original', 'ip_protocol':6, 'local_ip':'10.1.1.2', 'local_port':12345,
                        'other_ip':'203.0.113.4', 'other_port':443, 'local_mac':'bb:bb:bb:bb:bb:bb',
                        'other_mac':'aa:aa:aa:aa:aa:aa', 'other_type':'remote', 'host_server_name':'example.com'}
            translated = dict(original, digest='redirect', local_ip='10.1.1.1', local_port=7892,
                              other_ip='10.1.1.2', other_port=12345, local_mac='aa:aa:aa:aa:aa:aa',
                              other_mac='bb:bb:bb:bb:bb:bb', other_type='local')
            for flow in (original, translated):
                instance.update_metadata({'interface':'br-lan', 'internal':True, 'flow':flow})
            # Include mirrored duplicate directions deliberately. Only original
            # download + translated upload may reach the device counters.
            for digest, local, other in (('original', 100, 200), ('redirect', 200, 100)):
                instance.add_stats({'interface':'br-lan', 'internal':True, 'flow':{
                    'digest':digest, 'local_bytes':local, 'other_bytes':other}})
            # WAN alias cannot inflate the result.
            instance.update_metadata({'interface':'eth0', 'internal':False, 'flow':original})
            instance.add_stats({'interface':'eth0', 'internal':False, 'flow':dict(original, local_bytes=9000, other_bytes=9000)})
            self.assertEqual(instance.db.execute('SELECT mac,ip,SUM(upload),SUM(download),SUM(flows) FROM hourly GROUP BY mac,ip').fetchall(),
                             [('bb:bb:bb:bb:bb:bb', '10.1.1.2', 100, 200, 1)])
            self.assertEqual((instance.proxy_upload, instance.proxy_download), (100, 200))
            # Admin/local traffic with no verified redirect must remain excluded.
            instance.update_metadata({'internal':True,'flow':dict(translated,digest='ssh',local_port=22)})
            self.assertIn(('', 'ssh'), instance.excluded)
            instance.db.close()

    def test_metadata_keeps_observed_domain_and_protocol_until_purge(self):
        with self.collector() as instance:
            message = self.metadata('known')
            message['flow'].update(ip_protocol=17, host_server_name='API.KIMI.COM',
                                   detected_protocol_name='QUIC', detected_application_name='native.app')
            instance.update_metadata(message)
            less = self.metadata('known')
            less['flow'].update(ip_protocol=17, detected_application_name='unclassified')
            instance.update_metadata(less)
            instance.add_stats(self.stats('known'), received_at=7201)
            self.assertEqual(instance.db.execute('SELECT application,protocol,host FROM hourly').fetchone(),
                             ('native.app', 'QUIC', 'api.kimi.com'))
            # A newly observed valid hostname can replace prior evidence.
            message['flow']['host_server_name'] = 'new.example'
            instance.update_metadata(message)
            self.assertEqual(instance.flows[('br-lan', 'known')]['host'], 'new.example')
            instance.add_stats(self.stats('known', kind='flow_purge'), received_at=7202)
            instance.update_metadata(less)
            self.assertEqual(instance.flows[('br-lan', 'known')]['host'], '203.0.113.4')
            self.assertEqual(instance.flows[('br-lan', 'known')]['protocol'], 'UDP')

    def test_metadata_transport_fallback_and_dns_hostname_do_not_guess_apps(self):
        with self.collector() as instance:
            for number, expected in ((6, 'TCP'), (17, 'UDP'), (1, 'Unknown')):
                message = self.metadata(str(number))
                message['flow'].update(ip_protocol=number, detected_protocol_name='unclassified',
                                       host_server_name='192.0.2.3', dns_host_name='real.example')
                _, meta = instance.normalize_metadata(message)
                self.assertEqual((meta['application'], meta['protocol'], meta['host']),
                                 ('Unknown', expected, 'real.example'))

    def test_ipv6_mapping(self):
        line = 'ipv6 10 tcp 6 100 src=2001:db8::2 dst=2001:db8:1::4 sport=12345 dport=443 src=2001:db8::1 dst=2001:db8::2 sport=7892 dport=12345'
        entries = dict(RedirectMap.parse(line, {7892}))
        self.assertEqual(entries[(6,'2001:db8::1',7892,'2001:db8::2',12345)]['client'], '2001:db8::2')

    def test_non_tcp_metadata_does_not_scan_tcp_conntrack(self):
        mapping = RedirectMap()
        with patch.object(mapping, 'refresh') as refresh:
            for protocol in (17, 1, 58, None):
                self.assertIsNone(mapping.lookup({'ip_protocol': protocol}))
            refresh.assert_not_called()
            mapping.lookup({'ip_protocol': 6})
            refresh.assert_called_once()

    def test_original_metadata_before_redirect_map_does_not_double_count(self):
        line = ('ipv4 2 tcp 6 100 src=10.1.1.2 dst=203.0.113.4 '
                'sport=12345 dport=443 src=10.1.1.1 dst=10.1.1.2 '
                'sport=7892 dport=12345')
        original = dict(self.metadata('original')['flow'], ip_protocol=6,
                        local_port=12345, other_port=443,
                        other_mac='aa:aa:aa:aa:aa:aa')
        translated = dict(original, digest='redirect', other_ip='10.1.1.1',
                          other_port=7892, other_type='local')
        with self.collector() as instance:
            instance.update_metadata({'interface': 'br-lan', 'internal': True,
                                      'flow': original})
            instance.proxy.entries = dict(RedirectMap.parse(line, {7892}))
            instance.update_metadata({'interface': 'br-lan', 'internal': True,
                                      'flow': translated})
            instance.add_stats(self.stats('original'))
            instance.add_stats(self.stats('redirect'))
            self.assertEqual(instance.db.execute(
                'SELECT SUM(upload), SUM(download), SUM(flows) FROM hourly'
            ).fetchone(), (100, 200, 1))

    def test_original_counters_before_redirect_map_are_corrected(self):
        line = ('ipv4 2 tcp 6 100 src=10.1.1.2 dst=203.0.113.4 '
                'sport=12345 dport=443 src=10.1.1.1 dst=10.1.1.2 '
                'sport=7892 dport=12345')
        original = dict(self.metadata('original')['flow'], ip_protocol=6,
                        local_port=12345, other_port=443,
                        other_mac='aa:aa:aa:aa:aa:aa')
        translated = dict(original, digest='redirect', other_ip='10.1.1.1',
                          other_port=7892, other_type='local')
        with self.collector() as instance:
            instance.update_metadata({'interface': 'br-lan', 'internal': True,
                                      'flow': original})
            instance.add_stats(self.stats('original'))
            self.assertEqual(instance.db.execute(
                'SELECT SUM(upload), SUM(download), SUM(flows) FROM hourly'
            ).fetchone(), (100, 200, 1))
            instance.proxy.entries = dict(RedirectMap.parse(line, {7892}))
            instance.update_metadata({'interface': 'br-lan', 'internal': True,
                                      'flow': translated})
            instance.add_stats(self.stats('redirect'))
            self.assertEqual(instance.db.execute(
                'SELECT SUM(upload), SUM(download), SUM(flows) FROM hourly'
            ).fetchone(), (100, 200, 1))
            self.assertEqual(instance.upload, 100)

    def test_late_correction_never_resurrects_a_capacity_pruned_hour(self):
        line = ('ipv4 2 tcp 6 100 src=10.1.1.2 dst=203.0.113.4 '
                'sport=12345 dport=443 src=10.1.1.1 dst=10.1.1.2 '
                'sport=7892 dport=12345')
        original = dict(self.metadata('original')['flow'], ip_protocol=6,
                        local_port=12345, other_port=443,
                        other_mac='aa:aa:aa:aa:aa:aa')
        translated = dict(original, digest='redirect', other_ip='10.1.1.1',
                          other_port=7892, other_type='local')
        with self.collector() as instance, patch.object(collector.time, 'time', return_value=7198):
            instance.update_metadata({'interface':'br-lan', 'internal':True, 'flow':original})
            instance.add_stats(self.stats('original'))
            # Real capacity maintenance removes the old hour while a newer
            # contribution from the same connection remains available.
            instance.add_stats(self.stats('original'), received_at=7201)
            self.fill_and_prune_hour(instance, 3600)
            self.assertEqual(instance.db.execute('SELECT DISTINCT bucket FROM hourly').fetchall(), [(7200,)])
            with patch.object(collector.time, 'time', return_value=7202):
                instance.proxy.entries = dict(RedirectMap.parse(line, {7892}))
                instance.update_metadata({'interface':'br-lan', 'internal':True, 'flow':translated})
                instance.add_stats(self.stats('redirect'))
            self.assertEqual(instance.db.execute(
                'SELECT bucket,SUM(upload),SUM(download),SUM(flows) FROM hourly GROUP BY bucket'
            ).fetchall(), [(7200, 100, 200, 1)])
            self.assertEqual(instance.db.execute(
                'SELECT COUNT(*) FROM hourly WHERE upload<0 OR download<0 OR flows<0'
            ).fetchone()[0], 0)
            # Session totals include pruned history and still correct both
            # original upload deltas; retained-history totals are independent.
            self.assertEqual((instance.upload, instance.download), (100, 400))

    def test_current_hour_cleanup_recounts_each_still_active_flow_once(self):
        with self.collector() as instance:
            for digest in ('first', 'second'):
                instance.update_metadata(self.metadata(digest))
                instance.add_stats(self.stats(digest), received_at=7201)
            self.fill_and_prune_hour(instance, 7200)
            self.assertEqual(instance.db.execute('SELECT COUNT(*) FROM hourly').fetchone()[0], 0)
            for digest in ('first', 'second', 'first'):
                instance.add_stats(self.stats(digest), received_at=7202)
            self.assertEqual(instance.db.execute(
                'SELECT SUM(upload),SUM(download),SUM(flows) FROM hourly'
            ).fetchone(), (300, 600, 2))

    def test_retention_invalidates_writer_ids_before_another_device_reuses_them(self):
        with self.collector() as instance:
            instance.update_metadata(self.metadata('original'))
            instance.add_stats(self.stats('original'), received_at=7201)
            old_id = instance.db.execute(
                'SELECT id FROM traffic_devices WHERE mac=?', ('bb:bb:bb:bb:bb:bb',)
            ).fetchone()[0]
            self.fill_and_prune_hour(instance, 7200)
            self.assertIsNone(instance.db.execute(
                'SELECT 1 FROM traffic_devices WHERE id=?', (old_id,)
            ).fetchone())
            # Reuse the freed device ID while the collector still holds its
            # original metadata; cached dimension IDs must not relabel bytes.
            instance.db.execute('INSERT INTO traffic_devices(id,mac,ip) VALUES (?,?,?)',
                                (old_id, 'cc:cc:cc:cc:cc:cc', '10.1.1.3'))
            instance.db.execute('INSERT INTO hourly VALUES (?,?,?,?,?,?,?,?,?)',
                (7200, 'cc:cc:cc:cc:cc:cc', '10.1.1.3', 'other-app', 'UDP', 'other.example', 7, 9, 1))
            instance.add_stats(self.stats('original'), received_at=7202)
            self.assertEqual(instance.db.execute(
                'SELECT mac,SUM(upload),SUM(download),SUM(flows) FROM hourly GROUP BY mac ORDER BY mac'
            ).fetchall(), [('bb:bb:bb:bb:bb:bb', 100, 200, 1), ('cc:cc:cc:cc:cc:cc', 7, 9, 1)])

    def test_current_hour_proxy_recreation_corrects_only_retained_contributions(self):
        line = ('ipv4 2 tcp 6 100 src=10.1.1.2 dst=203.0.113.4 '
                'sport=12345 dport=443 src=10.1.1.1 dst=10.1.1.2 '
                'sport=7892 dport=12345')
        original = dict(self.metadata('original')['flow'], ip_protocol=6,
                        local_port=12345, other_port=443,
                        other_mac='aa:aa:aa:aa:aa:aa')
        translated = dict(original, digest='redirect', other_ip='10.1.1.1',
                          other_port=7892, other_type='local')
        with self.collector() as instance, patch.object(collector.time, 'time', return_value=7198):
            instance.update_metadata({'interface':'br-lan', 'internal':True, 'flow':original})
            instance.add_stats(self.stats('original'))
            self.fill_and_prune_hour(instance, 3600)
            self.assertEqual(instance.db.execute('SELECT COUNT(*) FROM hourly').fetchone()[0], 0)
            # A new row now has only 100 bytes, although this collection
            # session saw 200 original bytes. Subtracting 200 would underflow.
            instance.add_stats(self.stats('original'), received_at=7199)
            instance.proxy.entries = dict(RedirectMap.parse(line, {7892}))
            instance.update_metadata({'interface':'br-lan', 'internal':True, 'flow':translated})
            instance.add_stats(self.stats('redirect'), received_at=7199)
            self.assertEqual(instance.db.execute(
                'SELECT SUM(upload),SUM(download),SUM(flows) FROM hourly'
            ).fetchone(), (100, 200, 1))
            self.assertEqual((instance.upload, instance.download), (100, 400))

    def test_temporary_dedup_keeps_completed_flows_exact_and_interface_scoped(self):
        with self.collector() as instance:
            for index in range(5000):
                digest = 'completed-%d' % index
                instance.update_metadata(self.metadata(digest))
                instance.add_stats(self.stats(digest, kind='flow_purge'), received_at=7201)
            self.assertEqual(instance.flows, {})
            # Reloaded metadata, as after a reconnect, must not count this
            # already-completed flow twice in the same hour.
            instance.update_metadata(self.metadata('completed-0'))
            instance.add_stats(self.stats('completed-0'), received_at=7202)
            instance.update_metadata(self.metadata('completed-0', interface='guest'))
            instance.add_stats(self.stats('completed-0', interface='guest'), received_at=7202)
            self.assertEqual(instance.db.execute('SELECT SUM(flows) FROM hourly').fetchone()[0], 5001)
            self.assertEqual(instance.db.execute('SELECT COUNT(*) FROM temp.seen_flows').fetchone()[0], 5001)
            # This state belongs only to this collector, never to historical
            # package schema or a second read-only query connection.
            self.assertIsNone(instance.db.execute(
                "SELECT 1 FROM main.sqlite_master WHERE name='seen_flows'"
            ).fetchone())
            self.assertEqual(instance.db.execute('PRAGMA temp_store').fetchone()[0], 1)
            self.assertEqual(instance.db.execute('PRAGMA temp.cache_size').fetchone()[0], -256)
            instance.add_stats(self.stats('completed-0'), received_at=10860)
            self.assertEqual(instance.db.execute(
                'SELECT DISTINCT bucket FROM temp.seen_flows'
            ).fetchall(), [(10800,)])
            self.assertEqual(instance.db.execute('SELECT SUM(flows) FROM hourly').fetchone()[0], 5002)

    def test_late_redirect_mapping_recovers_both_orientations_without_export(self):
        line = 'ipv4 2 tcp 6 100 src=10.1.1.2 dst=203.0.113.4 sport=12345 dport=443 src=10.1.1.1 dst=10.1.1.2 sport=7892 dport=12345'
        entries = dict(RedirectMap.parse(line, {7892}))
        original = dict(self.metadata('original')['flow'], ip_protocol=6,
                        local_port=12345, other_port=443, other_mac='aa:aa:aa:aa:aa:aa')
        for local_client in (True, False):
            with self.subTest(local_client=local_client), self.collector() as instance:
                translated = dict(original, digest='redirect', other_ip='10.1.1.1',
                                  other_port=7892, other_type='local')
                if not local_client:
                    for field in ('ip', 'port', 'mac'):
                        translated['local_' + field], translated['other_' + field] = (
                            translated['other_' + field], translated['local_' + field])
                instance.update_metadata({'interface': 'br-lan', 'internal': True, 'flow': translated})
                self.assertNotIn(('br-lan', 'redirect'), instance.excluded)
                instance.add_stats(self.stats('redirect', upload=100 if local_client else 200,
                                             download=200 if local_client else 100))
                # A zero-byte purge still has to be replayed after the delta.
                instance.add_stats(self.stats('redirect', upload=0, download=0, kind='flow_purge'))
                self.assertEqual(len(instance.pending_stats), 2)
                instance.proxy.entries = entries
                instance.recover_metadata()
                self.assertEqual(len(instance.pending_stats), 0)
                self.assertEqual(instance.pending_by_digest, {})
                self.assertNotIn(('br-lan', 'redirect'), instance.flows)
                self.assertEqual(instance.export_error, '')
                instance.update_metadata({'interface': 'br-lan', 'internal': True, 'flow': original})
                instance.add_stats(self.stats('original'))
                instance.add_stats(dict(self.stats('original', interface='eth0'), internal=False))
                self.assertEqual(instance.db.execute('SELECT SUM(upload),SUM(download),SUM(flows) FROM hourly').fetchone(),
                                 (100, 200, 1))
                self.assertEqual((instance.proxy_upload, instance.proxy_download), (100, 200))

    def test_recovery_index_does_not_scan_other_pending_flows(self):
        class NoScan(OrderedDict):
            def __iter__(self):
                raise AssertionError('metadata recovery scanned global queue')

            def items(self):
                raise AssertionError('metadata recovery scanned global queue')

            def values(self):
                raise AssertionError('metadata recovery scanned global queue')

        with self.collector() as instance:
            instance.pending_stats = NoScan()
            for index in range(1000):
                instance.add_stats(self.stats(str(index)))
            instance.add_stats(self.stats('0', interface='guest'))
            for index in reversed(range(1000)):
                instance.update_metadata(self.metadata(str(index)))
            self.assertEqual(instance.recovered_stats, 1000)
            self.assertEqual(len(instance.pending_stats), 1)
            self.assertEqual(set(instance.pending_by_digest), {('guest', '0')})
            instance.update_metadata(self.metadata('0', interface='guest'))
            self.assertEqual(instance.pending_by_digest, {})
            self.assertEqual(len(instance.pending_stats), 0)
            self.assertEqual(instance.db.execute('SELECT SUM(upload),SUM(download) FROM hourly').fetchone(), (100100, 200200))

    def test_queue_overflow_expiry_and_exclusion_keep_indexes_bounded(self):
        with self.collector() as instance, patch.object(collector, 'PENDING_LIMIT', 3):
            now = int(time.time())
            instance.add_stats(self.stats('overflow'), received_at=now)
            instance.add_stats(self.stats('retained'), received_at=now)
            instance.add_stats(self.stats('expired'), received_at=now-70)
            instance.add_stats(self.stats('local'), received_at=now)
            self.assertEqual(instance.unattributed_upload, 100)
            self.assertNotIn(('br-lan', 'overflow'), instance.pending_by_digest)
            instance.recover_metadata()
            self.assertEqual(instance.unattributed_upload, 200)
            self.assertNotIn(('br-lan', 'expired'), instance.pending_by_digest)
            local = self.metadata('local')
            local['flow']['other_type'] = 'local'
            instance.update_metadata(local)
            self.assertNotIn(('br-lan', 'local'), instance.pending_by_digest)
            self.assertEqual(instance.unattributed_upload, 200)
            instance.update_metadata(self.metadata('retained'))
            self.assertEqual(instance.pending_by_digest, {})
            self.assertEqual(len(instance.pending_stats), 0)
            instance.recover_metadata()
            self.assertEqual(instance.export_error, '')

    def test_export_reconnect_recovery_never_replays_export_byte_totals(self):
        with self.collector() as instance:
            # This snapshot deliberately has counters far larger than deltas.
            snapshot = self.metadata('active')['flow']
            snapshot.update(local_bytes=100000000, other_bytes=200000000)
            with open(collector.EXPORT_PATH, 'w') as handle:
                json.dump({'interfaces': {'br-lan': {'role': 'LAN'}},
                           'flows': {'br-lan': [snapshot]}}, handle)
            instance.add_stats(self.stats('active'))
            instance.recover_metadata()
            instance.flows.clear()
            instance.excluded.clear()
            instance.export_stamp = None
            instance.add_stats(self.stats('active'))
            instance.recover_metadata()
            self.assertEqual(instance.recovered_stats, 2)
            self.assertEqual(instance.pending_by_digest, {})
            self.assertEqual(instance.db.execute('SELECT SUM(upload),SUM(download) FROM hourly').fetchone(), (200, 400))

    def test_new_pending_flow_recovers_from_unchanged_export(self):
        with self.collector() as instance:
            snapshots = [self.metadata(digest)['flow'] for digest in ('first', 'second')]
            with open(collector.EXPORT_PATH, 'w') as handle:
                json.dump({'interfaces': {'br-lan': {'role': 'LAN'}},
                           'flows': {'br-lan': snapshots}}, handle)
            with patch.object(collector.json, 'load', wraps=json.load) as read_export:
                instance.add_stats(self.stats('not-in-export'))
                instance.add_stats(self.stats('first'))
                instance.recover_metadata()
                # The export stays byte-for-byte unchanged, but a previously
                # unseen pending digest still needs to be looked up in it.
                instance.add_stats(self.stats('second'))
                instance.recover_metadata()
                self.assertEqual(instance.recovered_stats, 2)
                self.assertEqual(set(instance.pending_by_digest), {('br-lan', 'not-in-export')})
                self.assertEqual(read_export.call_count, 2)
                instance.recover_metadata()
                self.assertEqual(read_export.call_count, 2)
            self.assertEqual(instance.db.execute('SELECT SUM(upload),SUM(download) FROM hourly').fetchone(), (200, 400))

    def test_expired_delta_is_not_revived_by_export(self):
        with self.collector() as instance:
            snapshot = self.metadata('expired')['flow']
            with open(collector.EXPORT_PATH, 'w') as handle:
                json.dump({'interfaces': {'br-lan': {'role': 'LAN'}},
                           'flows': {'br-lan': [snapshot]}}, handle)
            instance.add_stats(self.stats('expired'), received_at=int(time.time())-collector.PENDING_TTL)
            instance.recover_metadata()
            self.assertEqual(instance.recovered_stats, 0)
            self.assertEqual(instance.unattributed_upload, 100)
            self.assertEqual(instance.unattributed_download, 200)
            self.assertEqual(len(instance.pending_stats), 0)
            self.assertEqual(instance.db.execute('SELECT COUNT(*) FROM hourly').fetchone()[0], 0)

    def test_recovery_deadline_uses_elapsed_time_and_keeps_arrival_hour(self):
        with self.collector() as instance:
            with patch.object(collector.time, 'time', return_value=7199), \
                    patch.object(collector.time, 'monotonic', return_value=10):
                instance.add_stats(self.stats('recover'))
                instance.add_stats(self.stats('expire'))
            # A clock jump does not expire fresh socket deltas.
            with patch.object(collector.time, 'time', return_value=7199+86400), \
                    patch.object(collector.time, 'monotonic', return_value=20):
                instance.recover_metadata()
                self.assertEqual(len(instance.pending_stats), 2)
                instance.update_metadata(self.metadata('recover'))
            self.assertEqual(instance.db.execute(
                'SELECT bucket,upload,download FROM hourly'
            ).fetchall(), [(3600, 100, 200)])
            # A backwards clock step does not extend the sixty-second window.
            with patch.object(collector.time, 'time', return_value=100), \
                    patch.object(collector.time, 'monotonic', return_value=70):
                instance.recover_metadata()
            self.assertEqual(len(instance.pending_stats), 0)
            self.assertEqual((instance.unattributed_upload, instance.unattributed_download), (100, 200))

    def test_candidate_expiry_is_not_extended_by_clock_rollback(self):
        original = dict(self.metadata('original')['flow'], ip_protocol=6,
                        local_port=12345, other_port=443)
        with self.collector() as instance:
            with patch.object(collector.time, 'time', return_value=10000), \
                    patch.object(collector.time, 'monotonic', return_value=10):
                instance.update_metadata({'interface':'br-lan', 'internal':True, 'flow':original})
            self.assertEqual(len(instance.original_candidates), 1)
            with patch.object(collector.time, 'time', return_value=100), \
                    patch.object(collector.time, 'monotonic', return_value=71):
                instance.expire_original_candidates()
            self.assertEqual(len(instance.original_candidates), 0)

    def test_late_hour_does_not_reset_flow_counts_or_latest_device(self):
        with self.collector() as instance:
            instance.update_metadata(self.metadata('active'))
            instance.add_stats(self.stats('active'), received_at=7198)
            instance.add_stats(self.stats('active'), received_at=7201)
            instance.add_stats(self.stats('late'), received_at=7199)
            old_metadata = self.metadata('late')
            old_metadata['flow']['local_ip'] = '10.1.1.99'
            instance.update_metadata(old_metadata)
            self.assertEqual(instance.last_event, 7201)
            self.assertEqual(instance.db.execute('SELECT ip,seen FROM device_latest').fetchone(), ('10.1.1.2', 7201))
            instance.add_stats(self.stats('active'), received_at=7202)
            self.assertEqual(instance.db.execute('SELECT bucket,SUM(flows),SUM(upload),SUM(download) FROM hourly GROUP BY bucket').fetchall(),
                             [(3600, 2, 200, 400), (7200, 1, 200, 400)])
            instance.add_stats(self.stats('active'), received_at=7260)
            self.assertEqual(set(instance.seen), {7200})

    def test_clock_rollback_does_not_recount_every_delta_or_lose_future_keys(self):
        with self.collector() as instance:
            instance.update_metadata(self.metadata('active'))
            for timestamp in (10801, 7201, 7202, 7203, 10802):
                instance.add_stats(self.stats('active'), received_at=timestamp)
            self.assertEqual(instance.db.execute(
                'SELECT bucket,SUM(upload),SUM(download),SUM(flows) FROM hourly GROUP BY bucket'
            ).fetchall(), [(7200, 300, 600, 1), (10800, 200, 400, 1)])

    def test_pre_rollback_pending_replay_does_not_expire_current_flow_dedup(self):
        with self.collector() as instance:
            with patch.object(collector.time, 'time', return_value=36001):
                instance.add_stats(self.stats('future'))
            self.assertEqual(instance.seen_latest, 36001)
            with patch.object(collector.time, 'time', return_value=7201):
                instance.update_metadata(self.metadata('current'))
                instance.add_stats(self.stats('current'))
            with patch.object(collector.time, 'time', return_value=7202):
                instance.update_metadata(self.metadata('future'))
                self.assertEqual(instance.seen_latest, 7201)
                instance.add_stats(self.stats('current'))
            self.assertEqual(instance.db.execute(
                'SELECT bucket,SUM(upload),SUM(download),SUM(flows) FROM hourly GROUP BY bucket'
            ).fetchall(), [(7200, 200, 400, 1), (36000, 100, 200, 1)])


if __name__ == '__main__':
    unittest.main()
