import os
import json
import tempfile
import time
import unittest
from collections import OrderedDict
from contextlib import contextmanager
from unittest.mock import patch

import netify_collector as collector
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


if __name__ == '__main__':
    unittest.main()
