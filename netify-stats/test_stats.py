import importlib.util
import os
import sqlite3
import tempfile
import time
import unittest


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(os.path.dirname(__file__), name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StatsTest(unittest.TestCase):
    def test_top_five_hosts_do_not_change_app_or_device_totals(self):
        import json
        collector, rpc = load('netify_collector'), load('netify_rpc')
        with tempfile.TemporaryDirectory() as directory:
            collector.DATA_DIR = collector.RUNTIME_DIR = directory
            collector.DB_PATH = rpc.DB_PATH = directory+'/stats.db'
            instance = collector.Collector()
            bucket = int(time.time())//3600*3600
            instance.db.executemany('INSERT INTO hourly VALUES (?,?,?,?,?,?,?,?,?)',
                [(bucket,'mac','ip','netify.test','TLS','host%d.example'%i,i,10*i,1) for i in range(1,11)])
            instance.db.commit()
            result = rpc.query_summary({'hours':0,'expanded':json.dumps(['netify.test'])})
            app = result['applications'][0]
            self.assertEqual([h['name'] for h in app['hosts']],['host%d.example'%i for i in (10,9,8,7,6)])
            self.assertEqual(app['download'],550)
            self.assertEqual(app['devices'][0]['download'],550)
            self.assertEqual(instance.db.execute('SELECT COUNT(*) FROM hourly').fetchone()[0],10)
            instance.db.close()

    def test_all_data_has_no_seven_day_retention_or_query_cap(self):
        collector = load('netify_collector')
        rpc = load('netify_rpc')
        with tempfile.TemporaryDirectory() as directory:
            collector.DATA_DIR = collector.RUNTIME_DIR = directory
            collector.DB_PATH = rpc.DB_PATH = os.path.join(directory, 'stats.db')
            collector.STATUS_PATH = os.path.join(directory, 'status.json')
            instance = collector.Collector()
            old = int(time.time())//3600*3600 - 30*86400
            instance.db.execute('INSERT INTO hourly VALUES (?,?,?,?,?,?,?,?,?)',
                (old,'mac','ip','app','TLS','host',123,456,1))
            instance.last_commit = time.monotonic()-4
            instance.maintenance()
            instance.db.commit()
            for params in ({}, {'hours':0}, {'hours':24*31}):
                result = rpc.query_summary(params)
                self.assertEqual(result['total']['download'], 456, str(params))
            self.assertEqual(rpc.query_summary({'hours':24})['total']['download'], 0)
            self.assertEqual(rpc.query_summary({'hours':0})['range_start'], old)
            trend = rpc.query_summary({'hours':0})
            self.assertLessEqual(len(trend['timeline']), 24)
            self.assertEqual(sum(row['download'] for row in trend['timeline']), 456)
            self.assertTrue(any(row['download'] == 0 for row in trend['timeline']))
            self.assertTrue(all(b['bucket']-a['bucket'] == trend['timeline_resolution_seconds']
                for a,b in zip(trend['timeline'], trend['timeline'][1:])))
            instance.db.close()

    def test_interface_accounting_restart_reset_and_dpi_separation(self):
        from netify_accounting import InterfaceAccounting
        collector = load('netify_collector')
        rpc = load('netify_rpc')
        with tempfile.TemporaryDirectory() as directory:
            collector.DATA_DIR = collector.RUNTIME_DIR = directory
            collector.DB_PATH = rpc.DB_PATH = os.path.join(directory, 'stats.db')
            instance = collector.Collector()
            now = int(time.time())
            account = instance.accounting
            account.record('eth0', 'boot:2', 1000, 500, now-12)
            account.record('eth0', 'boot:2', 1600, 900, now-9)
            instance.db.commit()
            account = InterfaceAccounting(instance.db)
            account.record('eth0', 'boot:2', 1700, 950, now-6)
            # Counter reset/recreated interface must not produce a huge jump.
            account.record('eth0', 'boot:3', 90000, 80000, now-3)
            account.record('eth0', 'boot:3', 90100, 80200, now)
            instance.db.commit()
            data = rpc.query_summary({'hours':24})
            self.assertEqual(data['total']['download'], 0)
            self.assertEqual(data['interfaces'][0]['download'], 800)
            self.assertEqual(data['interfaces'][0]['upload'], 650)
            self.assertEqual(data['interfaces'][0]['resets'], 1)
            self.assertEqual(data['interfaces'][0]['since'], now-12)
            instance.db.close()

    def test_metadata_recovery_and_interface_isolation(self):
        import json
        collector = load('netify_collector')
        with tempfile.TemporaryDirectory() as directory:
            collector.DATA_DIR = collector.RUNTIME_DIR = directory
            collector.DB_PATH = os.path.join(directory, 'stats.db')
            collector.EXPORT_PATH = os.path.join(directory, 'export.json')
            instance = collector.Collector()
            instance.local_macs = set()
            flow = {'digest':'same', 'other_type':'remote', 'local_mac':'aa:bb:cc:dd:ee:ff', 'local_ip':'10.1.1.2'}
            stats = {'type':'flow_stats', 'interface':'br-lan', 'internal':True, 'flow':{'digest':'same', 'local_bytes':20, 'other_bytes':30}}
            instance.add_stats(stats)
            self.assertEqual(len(instance.pending_stats), 1)
            with open(collector.EXPORT_PATH, 'w') as handle:
                json.dump({'interfaces':{'br-lan':{'role':'LAN'}}, 'flows':{'br-lan':[dict(flow, local_bytes=9999)]}}, handle)
            instance.recover_metadata()
            self.assertEqual(instance.recovered_stats, 1)
            instance.update_metadata({'interface':'eth0', 'internal':False, 'flow':flow})
            instance.add_stats(dict(stats, interface='eth0', internal=False))
            instance.add_stats(stats)
            instance.recover_metadata()
            self.assertEqual(instance.db.execute('SELECT SUM(upload),SUM(download) FROM hourly').fetchone(), (40,60))
            instance.add_stats(dict(stats, type='flow_purge', flow={'digest':'same','local_bytes':0,'other_bytes':0}))
            self.assertNotIn(('br-lan','same'), instance.flows)
            instance.add_stats(stats, received_at=int(time.time())-70)
            instance.recover_metadata()
            self.assertEqual(instance.unattributed_upload, 20)
            self.assertEqual(len(instance.pending_stats), 0)
            # Reconnect: the next export can restore active flows without replaying
            # exported byte counters or requiring a fresh detection event.
            instance.flows.clear()
            instance.export_stamp = None
            instance.add_stats(stats)
            instance.recover_metadata()
            self.assertEqual(instance.recovered_stats, 2)
            self.assertEqual(instance.db.execute('SELECT SUM(upload),SUM(download) FROM hourly').fetchone(), (60,90))
            instance.db.close()

    def test_malformed_messages_do_not_interrupt_capture(self):
        import json
        collector = load('netify_collector')
        with tempfile.TemporaryDirectory() as directory:
            collector.DATA_DIR = collector.RUNTIME_DIR = directory
            collector.DB_PATH = os.path.join(directory, 'stats.db')
            collector.STATUS_PATH = os.path.join(directory, 'status.json')
            instance = collector.Collector()
            instance.local_macs = set()
            for flow in ([], {'digest': []}, {'digest': 'x', 'local_mac': 123}):
                instance.read_message(json.dumps({'type': 'flow', 'flow': flow}))
            instance.read_message(json.dumps({'type':'flow', 'internal':True, 'flow':{'digest':'x','other_type':'remote','local_mac':'aa:bb:cc:dd:ee:ff','local_ip':'10.1.1.2','host_server_name':'chatgpt.com'}}))
            instance.read_message(json.dumps({'type':'flow_stats','flow':{'digest':'x','local_bytes':'bad'}}))
            instance.read_message(json.dumps({'type':'flow_stats','flow':{'digest':'x','local_bytes':20,'other_bytes':30}}))
            self.assertEqual(instance.invalid_messages, 4)
            self.assertEqual(instance.db.execute('SELECT SUM(upload),SUM(download) FROM hourly').fetchone(), (20,30))
            instance.db.close()

    def test_community_matching_and_conservation(self):
        from netify_classify import Classifier
        from pathlib import Path
        import json
        classifier = Classifier(Path(__file__).parent / 'rules/community-rules.json')
        self.assertEqual(classifier.error, '')
        self.assertEqual(classifier.classify('Unknown', 'chatgpt.com'), 'community:openai')
        self.assertEqual(classifier.classify('Unknown', 'v95-aw-cold.douyinvod.com'), 'community:douyin')
        self.assertEqual(classifier.classify('netify.example', 'chatgpt.com'), 'netify.example')
        self.assertEqual(classifier.classify('Unknown', 'fakechatgpt.com'), 'domain:fakechatgpt.com')
        self.assertEqual(classifier.classify('Unknown', 'chatgpt.com.evil.example'), 'domain:chatgpt.com.evil.example')
        self.assertEqual(classifier.classify('Unknown', '1.2.3.4'), 'Unknown')
        self.assertEqual(classifier.classify('Unknown', '2001:db8::1'), 'Unknown')
        self.assertEqual(classifier.classify('Unknown', 'CHATGPT.COM.'), 'community:openai')
        classifier.rules['exact']['shared.example'] = ['one', 'two']
        self.assertEqual(classifier.classify('Unknown', 'shared.example'), 'domain:shared.example')
        rpc = load('netify_rpc')
        rpc.Classifier = lambda: classifier
        collector = load('netify_collector')
        with tempfile.TemporaryDirectory() as directory:
            collector.DATA_DIR = collector.RUNTIME_DIR = directory
            collector.DB_PATH = rpc.DB_PATH = os.path.join(directory, 'stats.db')
            instance = collector.Collector()
            rows = [(int(time.time())//3600*3600, 'mac', 'ip', 'Unknown', 'TLS', host, 10, 100, 1)
                    for host in ['chatgpt.com', 'api.openai.com', 'v95-aw-cold.douyinvod.com', '1.2.3.4', 'fakechatgpt.com']]
            instance.db.executemany('INSERT INTO hourly VALUES (?,?,?,?,?,?,?,?,?)', rows)
            instance.db.commit()
            result = rpc.query_summary({'hours': 24, 'expanded': json.dumps(['community:openai'])})
            self.assertEqual(result['total']['download'], 500)
            self.assertEqual(sum(a['download'] for a in result['applications']), 500)
            app = next(a for a in result['applications'] if a['id'] == 'community:openai')
            self.assertEqual(app['download'], 200)
            self.assertEqual(sum(h['download'] for h in app['hosts']), 200)
            self.assertEqual(sum(d['download'] for d in app['devices']), 200)
            self.assertEqual(instance.db.execute("SELECT COUNT(*) FROM hourly WHERE application='Unknown'").fetchone()[0], 5)
            instance.db.close()

    def test_complete_consistent_rankings_and_hour_boundary(self):
        collector = load('netify_collector')
        rpc = load('netify_rpc')
        with tempfile.TemporaryDirectory() as directory:
            collector.DATA_DIR = directory
            collector.RUNTIME_DIR = directory
            collector.DB_PATH = rpc.DB_PATH = os.path.join(directory, 'stats.db')
            instance = collector.Collector()
            now = int(time.time())
            boundary = ((now - 3600) // 3600) * 3600
            rows = [(boundary, 'mac%d' % i, 'ip%d' % i, 'app%d' % i, 'TLS', 'host%d' % i, i + 1, 100, 1) for i in range(75)]
            instance.db.executemany('INSERT INTO hourly VALUES (?,?,?,?,?,?,?,?,?)', rows)
            instance.db.commit()
            result = rpc.query_summary({'hours': 1})
            self.assertEqual(result['app_count'], 75)
            self.assertEqual(result['device_count'], 75)
            self.assertEqual(len(result['applications']), 10)
            self.assertEqual(len(result['devices']), 10)
            self.assertEqual(result['total']['download'], 7500)
            self.assertTrue(all(not a['hosts'] for a in result['applications']))
            import json
            detail = rpc.query_summary({'hours': 1, 'expanded': json.dumps([a['id'] for a in result['applications']])})
            for app in detail['applications']:
                self.assertEqual(sum(d['download'] for d in app['devices']), app['download'])
                self.assertEqual(sum(h['upload'] for h in app['hosts']), app['upload'])
            pages = [rpc.query_summary({'hours': 1, 'app_page': page}) for page in range(1, 9)]
            self.assertEqual(sum(a['upload'] for p in pages for a in p['applications']), result['total']['upload'])
            ascending = rpc.query_summary({'hours': 1, 'sort': 'upload', 'direction': 'asc'})
            self.assertEqual(ascending['applications'][0]['upload'], 1)
            filtered = rpc.query_summary({'hours': 1, 'device': 'mac74'})
            self.assertEqual(filtered['total']['upload'], 75)
            self.assertEqual(rpc.query_summary({'hours': 'invalid'})['hours'], 24)
            instance.read_message(b'[]')
            instance.read_message(b'not json')
            instance.db.close()


if __name__ == '__main__':
    unittest.main()
