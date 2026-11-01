"""Minute chart scopes are independent, and cannot change traffic totals."""
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import netify_rpc as rpc
from netify_minute import MinuteSeries
from netify_storage import HourlyWriter, compact_schema

NOW = 1800000000 // 3600 * 3600 + 1800
MAC_A = '02:11:22:33:44:01'
MAC_B = '02:11:22:33:44:02'


class MinuteQueryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name) / 'stats.db')
        self.db = sqlite3.connect(self.path)
        self.addCleanup(self.db.close)
        self.db.execute('''CREATE TABLE hourly (
            bucket INTEGER, mac TEXT, ip TEXT, application TEXT, protocol TEXT,
            host TEXT, upload INTEGER, download INTEGER, flows INTEGER,
            PRIMARY KEY(bucket,mac,ip,application,protocol,host))''')
        compact_schema(self.db)
        writer = HourlyWriter(self.db)
        hour = NOW // 3600 * 3600
        self.a = writer.write((hour - 3600, MAC_A, '192.168.1.2', 'netify.example',
                               'TLS', 'example.net', 1000, 2000, 1))
        writer.write((hour, MAC_A, '192.168.1.2', 'netify.example',
                      'TLS', 'example.net', 500, 800, 1))
        self.b = writer.write((hour, MAC_B, '192.168.1.3', 'netify.example',
                               'TLS', 'example.net', 900, 700, 1))
        self.minutes = MinuteSeries(self.db)
        self.minutes.add(NOW - 3540, self.a, 70, 100)
        self.minutes.add(NOW - 70, self.a, 20, 30)
        self.minutes.add(NOW - 70, self.b, 40, 60)
        for stamp in range(NOW - 120, NOW + 1, 3):
            self.minutes.heartbeat(stamp, True)
        self.minutes.flush(NOW)
        self.db.commit()
        self.patchers = [
            patch.object(rpc, 'DB_PATH', self.path),
            patch.object(rpc.time, 'time', return_value=NOW),
            patch.object(rpc, 'control_status', return_value={}),
            patch.object(rpc, 'read_status', return_value={}),
            patch.object(rpc, 'interface_choices', return_value=[]),
            patch.object(rpc, 'device_names', return_value={}),
            patch.object(rpc, 'load_json', return_value={}),
            patch.object(rpc, 'read_settings_snapshot', return_value={
                'enabled': True, 'interface': '', 'max_storage_mib': 0,
                'config_error': '', 'storage_error': ''}),
        ]
        for item in self.patchers:
            item.start()
            self.addCleanup(item.stop)

    def test_recent_chart_has_60_real_buckets_without_changing_totals(self):
        selected = rpc.query_summary({'hours': 1})
        result = rpc.query_summary({'hours': 1, 'trend': 'recent',
                                    'ubus_rpc_session': 'a' * 32})
        self.assertEqual(result['total'], selected['total'])
        self.assertEqual(result['devices'], selected['devices'])
        self.assertEqual(result['applications'], selected['applications'])
        self.assertEqual(result['total']['upload'], 1400)
        self.assertEqual(result['timeline_source'], 'device_minutes')
        self.assertEqual(result['timeline_resolution_seconds'], 60)
        self.assertEqual(len(result['timeline']), 60)
        self.assertEqual(result['timeline_range_start'], NOW - 3540)
        self.assertEqual(result['timeline_range_end'], NOW)
        self.assertEqual(result['range_start'], NOW // 3600 * 3600)
        self.assertEqual(sum(row['upload'] or 0 for row in result['timeline']), 130)
        self.assertTrue(result['minute_history_available'])
        json.dumps(result, allow_nan=False)

    def test_device_and_ip_selection_apply_to_minute_records(self):
        for device in (MAC_A, '192.168.1.2'):
            with self.subTest(device=device):
                result = rpc.query_summary({'trend': 'recent', 'device': device})
                self.assertEqual(sum(row['upload'] or 0 for row in result['timeline']), 90)
                self.assertEqual(sum(row['download'] or 0 for row in result['timeline']), 130)
                self.assertEqual(result['total']['upload'], 1500)

    def test_missing_and_observed_zero_minutes_remain_distinct(self):
        result = rpc.query_summary({'trend': 'recent'})
        lookup = {row['bucket']: row for row in result['timeline']}
        missing = lookup[NOW - 300]
        self.assertFalse(missing['covered'])
        self.assertEqual(missing['coverage'], 'missing')
        self.assertIsNone(missing['upload'])
        self.assertIsNone(missing['download'])
        empty = lookup[NOW - 60]
        self.assertTrue(empty['covered'])
        self.assertEqual(empty['coverage'], 'complete')
        self.assertEqual((empty['upload'], empty['download']), (0, 0))
        self.assertEqual(lookup[NOW - 3540]['coverage'], 'partial')

    def test_application_filters_use_hourly_data_without_leaking_device_minutes(self):
        for filters in ({'search': 'never-match-this-name'}, {'identification': 'unknown'},
                        {'application': 'missing-application'}):
            with self.subTest(filters=filters):
                result = rpc.query_summary(dict(filters, trend='recent', hours=1))
                baseline = rpc.query_summary(dict(filters, hours=1))
                self.assertEqual(result['timeline_source'], 'hourly')
                self.assertEqual(result['trend_fallback'], 'filtered')
                self.assertEqual(result['timeline'], baseline['timeline'])
                self.assertEqual(result['total'], baseline['total'])
                self.assertGreaterEqual(result['timeline_resolution_seconds'], 3600)

    def test_legacy_database_does_not_fabricate_minute_history(self):
        self.db.execute('DROP TABLE device_minutes')
        self.db.execute('DROP TABLE minute_coverage')
        self.db.commit()
        result = rpc.query_summary({'trend': 'recent'})
        self.assertEqual(result['timeline'], [])
        self.assertFalse(result['minute_history_available'])
        self.assertEqual(result['total']['upload'], 2400)
        # Read-only RPC must not migrate the legacy DB or manufacture rows.
        self.assertFalse(self.db.execute("SELECT name FROM sqlite_master WHERE name='device_minutes'").fetchone())

    def test_absent_database_retains_minute_request_and_unknown_history(self):
        with patch.object(rpc, 'DB_PATH', self.path + '.missing'):
            result = rpc.query_summary({'trend': 'recent'})
        self.assertEqual(result['trend_mode'], 'recent')
        self.assertEqual(result['timeline_source'], 'device_minutes')
        self.assertEqual(result['timeline'], [])
        self.assertFalse(result['minute_history_available'])

    def test_range_mode_keeps_hourly_totals_and_chart_consistent(self):
        for params in ({}, {'trend': 'range'}, {'trend': 'unsupported'}):
            with self.subTest(params=params):
                result = rpc.query_summary(params)
                self.assertEqual(result['timeline_source'], 'hourly')
                self.assertEqual(result['trend_mode'], 'range')
                self.assertEqual(sum(row['upload'] for row in result['timeline']), result['total']['upload'])


if __name__ == '__main__':
    unittest.main()
