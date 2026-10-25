"""WAN is an independent evidence layer, never a supplement to LAN bytes."""
from pathlib import Path
import json
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

import netify_collector as collector
import netify_rpc as rpc
import netify_storage as storage
from netify_classify import Classifier
from netify_proxy import RedirectMap
from netify_wan import WanAccounting, query_wan
from test_storage import original_schema


class WanTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = self.tmp.name+'/stats.db'
        self.db = sqlite3.connect(self.path)
        self.addCleanup(self.db.close)
        original_schema(self.db)
        storage.compact_schema(self.db)
        self.attribution = RedirectMap()
        self.meter = WanAccounting(self.db,self.attribution)

    def metadata(self, digest='one', **values):
        flow = dict(digest=digest,first_seen_at=100000,other_type='remote',local_ip='203.0.113.1',
                    other_ip='192.0.2.1',local_port=40000,other_port=443,ip_protocol=6,detected_protocol_name='TLS')
        flow.update(values)
        return dict(type='flow',internal=False,interface='wan',flow=flow)

    def event(self, up=100, down=200, total=300, digest='one', kind='flow_stats', **values):
        flow = dict(digest=digest,local_bytes=up,other_bytes=down,total_bytes=total,last_seen_at=200000)
        flow.update(values)
        return dict(type=kind,internal=False,interface='wan',flow=flow)

    def total(self):
        return self.db.execute('SELECT SUM(upload),SUM(download) FROM wan_hourly').fetchone()

    def test_metadata_snapshot_purge_and_replays_do_not_inflate_bytes(self):
        self.meter.update_metadata(self.metadata(total_bytes=900000,local_bytes=500000))
        self.assertEqual(self.total(),(None,None))
        first = self.event()
        self.meter.add_stats(first,3600)
        self.meter.add_stats(first,3601)
        self.meter.add_stats(self.event(kind='flow_purge'),3602)
        self.assertEqual(self.total(),(100,200))
        self.meter.add_stats(self.event(up=10,down=20,total=330,kind='flow_purge'),3603)
        self.assertEqual(self.total(),(110,220))
        self.assertEqual(self.meter.stats['duplicates'],2)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM hourly_data').fetchone()[0],0)

    def test_counter_gaps_are_not_filled_and_overlaps_are_not_guessed(self):
        self.meter.update_metadata(self.metadata())
        self.meter.add_stats(self.event(),3600)
        self.meter.add_stats(self.event(up=10,down=20,total=500),3601)
        self.assertEqual(self.total(),(110,220))
        self.assertEqual(self.meter.stats['missing_delta_bytes'],170)
        self.meter.add_stats(self.event(up=10,down=20,total=510),3602)
        self.assertEqual(self.total(),(110,220))
        self.assertEqual(self.meter.stats['overlapping_events'],1)
        self.meter.add_stats(self.event(up=1,down=2,total=50),3603)
        self.assertEqual(self.total(),(110,220))
        self.assertEqual(self.meter.stats['counter_regressions'],1)
        self.meter.add_stats(self.event(total=None),3604)
        self.assertEqual(self.total(),(110,220))
        self.assertEqual(self.meter.stats['no_cumulative_events'],1)

    def test_new_incarnation_requires_new_metadata_and_rejects_old_reports(self):
        self.meter.update_metadata(self.metadata())
        self.meter.add_stats(self.event(),3600)
        self.meter.update_metadata(self.metadata(first_seen_at=300000))
        self.meter.add_stats(self.event(up=1,down=2,total=3,last_seen_at=400000),3601)
        self.meter.add_stats(self.event(last_seen_at=200000),3602)
        self.assertEqual(self.total(),(101,202))

    def test_missing_metadata_is_retained_as_unattributed_not_discarded(self):
        self.meter.add_stats(self.event(),3600)
        row = self.db.execute('SELECT category,evidence,upload FROM wan_hourly').fetchone()
        self.assertEqual(row,('unattributed','missing_metadata',100))
        self.meter.update_metadata(self.metadata(detected_protocol_name='WireGuard'))
        self.meter.add_stats(self.event(up=10,down=20,total=330),3601)
        counts = dict(self.db.execute('SELECT category,SUM(upload) FROM wan_hourly GROUP BY category'))
        self.assertEqual(counts,{'unattributed':100,'tunnel':10})

    def test_late_generic_metadata_does_not_erase_observed_vpn_protocol(self):
        self.meter.update_metadata(self.metadata(detected_protocol_name='WireGuard'))
        self.meter.update_metadata(self.metadata(detected_protocol_name='UDP'))
        self.meter.add_stats(self.event(),3600)
        self.assertEqual(self.db.execute('SELECT category,protocol FROM wan_hourly').fetchone(),('tunnel','WireGuard'))
        self.meter.update_metadata(self.metadata(first_seen_at=300000,detected_protocol_name='UDP'))
        self.meter.add_stats(self.event(up=1,down=2,total=3,last_seen_at=400000),3601)
        self.assertEqual(self.db.execute("SELECT protocol FROM wan_hourly WHERE category='unattributed'").fetchone()[0],'UDP')

    def test_exact_socket_owner_and_conntrack_classification(self):
        output = '''tcp 0 0 0.0.0.0:7892 0.0.0.0:* LISTEN 12/mihomo
 tcp 0 0 203.0.113.1:40000 192.0.2.1:443 ESTABLISHED 12/mihomo
 udp 0 0 0.0.0.0:41641 0.0.0.0:* 13/tailscaled
 tcp 0 0 203.0.113.1:40001 192.0.2.2:443 ESTABLISHED 14/uclient-fetch'''
        ports,owners = RedirectMap.socket_snapshot(output)
        self.assertEqual(ports,{7892})
        self.assertEqual(len(owners),2)
        self.attribution.socket_owners = owners
        self.attribution.ports_updated = self.attribution.owners_updated = time.monotonic()
        meta = self.metadata()['flow']
        self.assertEqual(self.meter.classify(meta)[:3],('proxy','socket:mihomo',''))
        meta.update(local_port=40001,other_ip='192.0.2.2')
        self.assertEqual(self.meter.classify(meta)[0],'router')
        meta.update(other_ip='192.0.2.3')
        self.assertEqual(self.meter.classify(meta)[0],'unattributed')
        self.attribution.ports_updated = self.attribution.owners_updated = float('-inf')
        meta = self.metadata()['flow']
        self.assertEqual(self.meter.classify(meta)[0],'unattributed')
        self.attribution.observe_client('10.0.1.2','aa:bb:cc:dd:ee:ff')
        line = 'ipv4 2 tcp 6 100 src=10.0.1.2 dst=192.0.2.1 sport=1234 dport=443 src=192.0.2.1 dst=203.0.113.1 sport=443 dport=40000'
        self.attribution.egress_entries = dict(RedirectMap.egress_tuple(line,self.attribution.clients,time.monotonic()))
        self.attribution.egress_updated = time.monotonic()
        self.assertEqual(self.meter.classify(meta)[:3],('forwarded','conntrack_lan_tuple','aa:bb:cc:dd:ee:ff'))
        # NAT flag, private address or proxy-looking port alone is insufficient.
        self.attribution.egress_entries = {}
        meta.update(ip_nat=True,local_port=7892)
        self.assertEqual(self.meter.classify(meta)[0],'unattributed')
        self.assertEqual(RedirectMap.egress_tuple(line,{},time.monotonic()),[])

    def test_failed_write_does_not_advance_duplicate_cursor(self):
        self.db.execute("""CREATE TRIGGER reject_wan BEFORE INSERT ON wan_hourly
                           BEGIN SELECT RAISE(ABORT,'simulated failure'); END""")
        with self.assertRaises(sqlite3.IntegrityError):
            self.meter.add_stats(self.event(),3600)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM temp.wan_cursors').fetchone()[0],0)
        self.db.execute('DROP TRIGGER reject_wan')
        self.meter.add_stats(self.event(),3600)
        self.assertEqual(self.total(),(100,200))

    def test_archive_interface_names_signed_residual_and_hour_scope(self):
        self.meter.update_metadata(self.metadata(detected_protocol_name='OpenVPN'))
        for bucket in (3600,7200,10800):
            self.meter.add_stats(self.event(total=bucket//3600*300,last_seen_at=bucket*1000),bucket)
            self.db.execute('INSERT INTO interface_hourly VALUES (?,?,?,?,?,?,?)',
                            (bucket,'wan',150,200,bucket,bucket+3,0))
        self.db.commit()
        with patch.object(rpc,'DB_PATH',self.path), patch.object(rpc.time,'time',return_value=10801):
            result = rpc.query_summary({'hours':2})
            self.assertEqual(result['range_start'],7200)
            self.assertEqual(result['total']['upload'],0)
            wan = result['wan_interfaces'][0]
            self.assertEqual((wan['upload'],wan['download']),(200,400))
            self.assertEqual(wan['residual'],{'upload':200,'download':-100})
            self.assertEqual([r['bucket'] for r in wan['hours']],[7200,10800])
            self.assertEqual(rpc.query_summary({'hours':2,'device':'a'})['wan_interfaces'],[])
        policy = storage.StoragePolicy(self.db,self.path)
        policy.archive(10800+storage.DETAIL_RETENTION_SECONDS+3600)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM wan_hourly').fetchone()[0],0)
        archived = query_wan(self.db,0,None,1000000)[0]
        self.assertEqual(archived['upload'],300)
        self.assertTrue(archived['archived'])
        self.assertEqual(archived['hours'],[])
        self.assertEqual(query_wan(self.db,0,1000000,1000000),[])
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM traffic_archive').fetchone()[0],0)

    def test_lan_and_wan_mirrors_never_add_to_one_device_total(self):
        with tempfile.TemporaryDirectory() as root, patch.object(collector,'DATA_DIR',root), \
                patch.object(collector,'RUNTIME_DIR',root), patch.object(collector,'DB_PATH',root+'/stats.db'):
            instance = collector.Collector()
            try:
                instance.proxy.lookup = lambda flow:None
                lan = self.metadata()
                lan.update(internal=True,interface='br-lan')
                lan['flow'].update(local_mac='aa:bb:cc:dd:ee:ff',local_ip='10.0.1.2',detected_protocol_name='WireGuard')
                instance.update_metadata(lan)
                event = self.event()
                event.update(internal=True,interface='br-lan')
                instance.add_stats(event,received_at=3600)
                instance.update_metadata(self.metadata(detected_protocol_name='WireGuard'))
                instance.add_stats(self.event(),received_at=3600)
                instance.add_stats(self.event(kind='flow_purge'),received_at=3601)
                self.assertEqual(instance.db.execute('SELECT SUM(upload),SUM(download) FROM hourly').fetchone(),(100,200))
                self.assertEqual(instance.db.execute('SELECT SUM(upload),SUM(download) FROM wan_hourly').fetchone(),(100,200))
                self.assertEqual((instance.upload,instance.download),(100,200))
            finally:
                instance.db.close()

    def test_guard_eviction_omits_old_identity_instead_of_recounting_it(self):
        with patch('netify_wan.CURSOR_LIMIT',2):
            self.meter.add_stats(self.event(digest='a'),3600)
            self.meter.add_stats(self.event(digest='b'),3601)
            self.meter.add_stats(self.event(digest='c'),3602)
            self.meter.add_stats(self.event(digest='a'),3603)
            self.meter.add_stats(self.event(digest='a',total=600),3604)
        self.assertEqual(self.total(),(300,600))
        self.assertEqual(self.meter.stats['capacity_omitted_events'],2)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM temp.wan_cursors').fetchone()[0],1)

    def test_expired_guards_cannot_allow_old_replays_after_rotation(self):
        with patch('netify_wan.CURSOR_LIMIT',2):
            for digest in ('a','b','c'):
                self.meter.add_stats(self.event(digest=digest),3600)
            self.meter.add_stats(self.event(digest='a'),18000)
            self.assertEqual(self.total(),(300,600))
            self.assertEqual(self.meter.stats['stale_events'],1)
            self.meter.update_metadata(self.metadata('a',first_seen_at=18000000))
            self.meter.add_stats(self.event(digest='a',last_seen_at=18000000),18000)
            self.assertEqual(self.total(),(400,800))
            self.assertLessEqual(len(self.meter.evicted),4)
        self.meter.add_stats(self.event(digest='future',last_seen_at=19000000),18000)
        self.assertEqual(self.total(),(400,800))
        self.assertEqual(self.meter.stats['clock_events'],1)

    def test_unknown_direction_suppresses_interface_residual(self):
        self.meter.add_stats(self.event(),3600)
        self.db.execute('INSERT INTO interface_hourly VALUES (3600,"wan",400,500,3600,3603,0)')
        self.db.commit()
        with patch.object(rpc,'DB_PATH',self.path),patch.object(rpc.time,'time',return_value=3605):
            row=rpc.query_summary({})['wan_interfaces'][0]
        self.assertNotIn('residual',row)
        self.assertEqual(row['direction_unconfirmed_bytes'],300)
        self.assertNotIn('residual_upload',row['hours'][0])

    def test_hour_window_has_exact_bucket_count_across_dst_fallback(self):
        import datetime
        now=int(datetime.datetime(2026,10,25,3,30,tzinfo=datetime.timezone.utc).timestamp())
        current=now//3600*3600
        for offset in range(26):
            bucket=current-offset*3600
            self.db.execute('INSERT INTO interface_hourly VALUES (?,?,?,?,?,?,?)',(bucket,'wan',20,10,bucket,bucket+3,0))
        self.db.commit()
        with patch.object(rpc,'DB_PATH',self.path),patch.object(rpc.time,'time',return_value=now):
            result=rpc.query_summary({'hours':24})
        self.assertEqual(result['range_start'],current-23*3600)
        self.assertLessEqual(result['range_end']-result['range_start'],24*3600)
        self.assertEqual(result['interfaces'][0]['upload'],240)

    def test_owner_scan_timeout_does_not_leave_a_subprocess_or_old_ownership(self):
        import netify_proxy as proxy
        from unittest.mock import MagicMock
        import subprocess
        process=MagicMock();process.poll.return_value=None
        with patch.object(proxy.subprocess,'Popen',return_value=process), \
                patch.object(proxy.select,'select',return_value=([],[],[])):
            with self.assertRaises(subprocess.TimeoutExpired):
                proxy.outbound_socket_snapshot()
        process.kill.assert_called_once()
        process.wait.assert_called_once()
        process.stdout.close.assert_called_once()
        self.attribution.want_egress=True
        self.attribution.socket_owners={(6,'203.0.113.1',40000,'192.0.2.1',443):'mihomo'}
        with patch.object(proxy,'outbound_socket_snapshot',side_effect=subprocess.TimeoutExpired('netstat',.15)):
            self.attribution.refresh()
        self.assertEqual(self.attribution.socket_owners,{})
        self.assertTrue(self.attribution.egress_error)
        self.assertEqual(self.meter.classify(self.metadata()['flow'])[0],'unattributed')

    def test_optional_wan_owner_timeout_preserves_lan_redirect_attribution(self):
        import io
        import subprocess
        import netify_proxy as proxy
        self.attribution.want_egress=True
        listener='tcp 0 0 0.0.0.0:7892 0.0.0.0:* LISTEN 12/mihomo'
        line='ipv4 2 tcp 6 100 src=10.0.1.2 dst=192.0.2.1 sport=1234 dport=443 src=10.0.1.1 dst=10.0.1.2 sport=7892 dport=1234'
        with patch.object(proxy,'outbound_socket_snapshot',side_effect=subprocess.TimeoutExpired('netstat',.15)), \
                patch.object(proxy.subprocess,'check_output',return_value=listener), \
                patch('netify_proxy.open',return_value=io.StringIO(line)):
            self.attribution.refresh()
        self.assertEqual(self.attribution.error,'')
        self.assertEqual(len(self.attribution.entries),4)
        self.assertTrue(self.attribution.egress_error)
        self.assertEqual(self.attribution.socket_owners,{})

    def test_older_archive_retains_vpn_protocol_evidence_without_new_bytes(self):
        from netify_query import aggregate
        self.db.execute("INSERT INTO traffic_devices VALUES (1,'device','192.0.2.2')")
        self.db.execute("INSERT INTO traffic_protocols VALUES (1,'WireGuard')")
        self.db.execute("INSERT INTO traffic_archive VALUES (1,'community:openai',1,100,200,1,0,3600)")
        result=aggregate(self.db,0,'',7200,Classifier(Path(__file__).parent/'rules/community-rules.json'),
                         {},{},1,1,'total','desc',['protocol:vpn'])
        self.assertEqual(result['total'],dict(upload=100,download=200,flows=1))
        self.assertEqual(result['vpn_total'],result['total'])
        self.assertEqual(result['applications'][0]['id'],'protocol:vpn')
        self.assertEqual(result['applications'][0]['devices'][0]['upload'],100)
        self.assertEqual(result['classification_coverage']['application']['upload'],0)

    def test_vpn_endpoint_hostname_does_not_turn_tunnel_into_inner_application(self):
        classifier = Classifier(Path(__file__).parent/'rules/community-rules.json')
        for protocol in ('WireGuard','OpenVPN','IPsec ESP','IKEv2'):
            self.assertEqual(classifier.classify('netify.endpoint','chatgpt.com',protocol),'protocol:vpn')
            self.assertFalse(classifier.describe_metadata('protocol:vpn')['application_identified'])
        self.assertEqual(classifier.classify('Unknown','chatgpt.com','TLS'),'community:openai')
        self.assertEqual(classifier.classify('Unknown','192.0.2.1','UDP'),'protocol:udp')


if __name__ == '__main__':
    unittest.main()
