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


if __name__ == '__main__':
    unittest.main()
