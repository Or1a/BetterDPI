"""Interface selection tests; no router changes or browser required."""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import netify_accounting as accounting
import netify_storage as storage


class InterfaceTests(unittest.TestCase):
    def test_selection_baselines_and_history(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / 'settings.json'
            status = root / 'status.json'
            config.write_text(json.dumps({'enabled': False, 'max_storage_mib': 16}))
            status.write_text(json.dumps({'interfaces': {'wan0': {'role': 'WAN'}}}))
            net = root / 'net'
            def counters(name, rx, tx):
                base = net / name
                (base / 'statistics').mkdir(parents=True, exist_ok=True)
                (base / 'ifindex').write_text('2' if name == 'wan0' else '3')
                (base / 'statistics/rx_bytes').write_text(str(rx))
                (base / 'statistics/tx_bytes').write_text(str(tx))
            counters('wan0', 100, 50)
            counters('br-lan', 9000, 8000)
            original_read = Path.read_text
            def read(path, *args, **kwargs):
                return 'boot-test' if str(path) == '/proc/sys/kernel/random/boot_id' else original_read(path, *args, **kwargs)
            with patch.object(storage, 'CONFIG_PATH', str(config)), patch.object(accounting, 'NET_ROOT', net), patch.object(Path, 'read_text', read):
                db = sqlite3.connect(':memory:')
                meter = accounting.InterfaceAccounting(db)
                self.assertEqual(accounting.interface_choices(), ['br-lan', 'wan0'])
                self.assertEqual(accounting.active_interfaces(), [])
                meter.sample(97)
                self.assertEqual(meter.error, '')
                accounting.save_interface('wan0')
                meter.sample(100)
                counters('wan0', 200, 70)
                meter.sample(103)
                accounting.save_interface('br-lan')
                meter.sample(106)
                counters('br-lan', 9050, 8070)
                meter.sample(109)
                # Switching back must not include the time spent on br-lan.
                counters('wan0', 10000, 9000)
                accounting.save_interface('wan0')
                meter.sample(112)
                counters('wan0', 10030, 9040)
                meter.sample(115)
                rows = db.execute('SELECT name,download,upload FROM interface_hourly ORDER BY name').fetchall()
                self.assertEqual(rows, [('br-lan', 50, 70), ('wan0', 130, 60)])
                self.assertEqual(json.loads(config.read_text())['max_storage_mib'], 16)
                self.assertFalse(json.loads(config.read_text())['enabled'])
                for invalid in ('../etc', 'missing', None, [], 1):
                    with self.assertRaises(ValueError):
                        accounting.save_interface(invalid)
                # Missing interfaces keep history and clear their baseline.
                (net / 'wan0/statistics/rx_bytes').unlink()
                meter.sample(118)
                self.assertTrue(meter.error)
                self.assertEqual(db.execute('SELECT COUNT(*) FROM interface_baseline').fetchone()[0], 0)
                accounting.save_interface('')
                self.assertEqual(accounting.active_interfaces(), [])
                meter.sample(121)
                self.assertEqual(meter.error, '')
                db.close()


class TunnelTests(unittest.TestCase):
    def setUp(self):
        # These fixtures simulate Linux netlink/sysfs; do not read the host's
        # boot identity or depend on its socket constants (e.g. on macOS).
        original_read = Path.read_text
        def read(path, *args, **kwargs):
            return 'boot-test' if str(path) == '/proc/sys/kernel/random/boot_id' else original_read(path, *args, **kwargs)
        for patcher in (patch.object(Path, 'read_text', read),
                        patch.object(accounting.socket, 'AF_NETLINK', 16, create=True),
                        patch.object(accounting.socket, 'NETLINK_ROUTE', 0, create=True)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_kernel_kind_not_interface_name_controls_discovery(self):
        import struct
        def attr(kind, value):
            length=4+len(value)
            return struct.pack('=HH',length,kind)+value+b'\0'*((-length)%4)
        def link(name,kind):
            return struct.pack('=BBHiII',0,0,1,7,0,0)+attr(3,name.encode()+b'\0')+attr(18,attr(1,kind.encode()+b'\0'))
        self.assertEqual(accounting._tunnel_link(link('vpn0','veth')),None)
        self.assertEqual(accounting._tunnel_link(link('wg0','wireguard')),('wg0',('wireguard',7)))
        self.assertEqual(accounting._tunnel_link(link('tailscale0','tun')),('tailscale0',('tun',7)))
        self.assertEqual(accounting._tunnel_link(link('../bad','tun')),None)
        with self.assertRaises(ValueError):
            accounting._tunnel_link(b'bad')
        with self.assertRaises(ValueError):
            list(accounting._attributes(b'\xff\xff\x01\x00'))

    def test_netlink_dump_checks_kernel_origin_sequence_and_completion(self):
        import struct
        from unittest.mock import MagicMock
        def attr(kind,value):
            length=4+len(value)
            return struct.pack('=HH',length,kind)+value+b'\0'*((-length)%4)
        payload=struct.pack('=BBHiII',0,0,1,7,0,0)+attr(3,b'wg0\0')+attr(18,attr(1,b'wireguard\0'))
        message=struct.pack('=IHHII',16+len(payload),16,2,1,0)+payload
        done=struct.pack('=IHHIIi',20,3,2,1,0,0)
        client=MagicMock();client.__enter__.return_value=client
        client.recvmsg.return_value=(message+done,[],0,(0,0))
        with patch.object(accounting.socket,'socket',return_value=client):
            self.assertEqual(accounting.discover_tunnels(),{'wg0':('wireguard',7)})
        self.assertEqual(client.sendto.call_args[0][1],(0,0))
        interrupted=struct.pack('=IHHIIi',20,3,0x10,1,0,0)
        client.recvmsg.return_value=(interrupted,[],0,(0,0))
        with patch.object(accounting.socket,'socket',return_value=client):
            with self.assertRaisesRegex(ValueError,'changed'):
                accounting.discover_tunnels()

    def test_tunnel_and_selected_interface_have_separate_nonadditive_histories(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);net=root/'net';config=root/'config.json'
            config.write_text('{"interface":"wg0"}')
            def counters(rx,tx,index=7):
                path=net/'wg0';(path/'statistics').mkdir(parents=True,exist_ok=True)
                (path/'ifindex').write_text(str(index))
                (path/'statistics/rx_bytes').write_text(str(rx))
                (path/'statistics/tx_bytes').write_text(str(tx))
            counters(1000,2000)
            with patch.object(storage,'CONFIG_PATH',str(config)), patch.object(accounting,'NET_ROOT',net), \
                    patch.object(accounting,'discover_tunnels',return_value={'wg0':('wireguard',7)}) as discover:
                db=sqlite3.connect(':memory:');meter=accounting.InterfaceAccounting(db)
                meter.sample(3600);counters(1100,2200);meter.sample(3603)
                self.assertEqual(discover.call_count,1)
                rows=[dict(name=n,download=d,upload=u) for n,d,u in db.execute('SELECT name,download,upload FROM interface_hourly')]
                interfaces,tunnels=accounting.split_interface_history(rows)
                self.assertEqual(interfaces,[dict(name='wg0',download=100,upload=200)])
                self.assertEqual(tunnels,[dict(name='wg0',kind='wireguard',download=100,upload=200)])
                # An interface recreated between discoveries must not add a
                # lifetime counter to either layer.
                counters(50000,60000,8);meter.sample(3606)
                self.assertTrue(meter.tunnel_sample_error)
                self.assertEqual(db.execute("SELECT SUM(download) FROM interface_hourly WHERE name='tunnel/wireguard/wg0'").fetchone()[0],100)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM interface_baseline WHERE name LIKE 'tunnel/%'").fetchone()[0],0)
                meter.tunnels={'wg0':('wireguard',8)}
                meter.sample(3609);counters(50100,60200,8);meter.sample(3612)
                self.assertEqual(db.execute("SELECT SUM(download) FROM interface_hourly WHERE name='tunnel/wireguard/wg0'").fetchone()[0],200)
                db.close()

    def test_failed_discovery_does_not_stop_the_selected_kernel_meter(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);net=root/'net';config=root/'config.json'
            config.write_text('{"interface":"wan"}')
            base=net/'wan';(base/'statistics').mkdir(parents=True)
            (base/'ifindex').write_text('2');(base/'statistics/rx_bytes').write_text('100');(base/'statistics/tx_bytes').write_text('200')
            with patch.object(storage,'CONFIG_PATH',str(config)),patch.object(accounting,'NET_ROOT',net), \
                    patch.object(accounting,'discover_tunnels',side_effect=OSError('not supported')):
                db=sqlite3.connect(':memory:');meter=accounting.InterfaceAccounting(db)
                meter.sample(3600);(base/'statistics/rx_bytes').write_text('150');meter.sample(3603)
                self.assertEqual(meter.error,'')
                self.assertIn('not supported',meter.tunnel_error)
                self.assertEqual(db.execute('SELECT download FROM interface_hourly').fetchone()[0],50)
                db.close()


if __name__ == '__main__':
    unittest.main()
