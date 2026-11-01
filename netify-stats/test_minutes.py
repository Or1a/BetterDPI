"""Minute charts reuse accounted deltas and preserve gaps and corrections."""
from contextlib import contextmanager
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import netify_collector as collector
import netify_minute as minute
from netify_proxy import RedirectMap
from netify_storage import HourlyWriter, compact_schema

BASE = 1800000000
MAC = '02:11:22:33:44:55'


@contextmanager
def database():
    db = sqlite3.connect(':memory:')
    db.execute('''CREATE TABLE hourly (bucket INTEGER,mac TEXT,ip TEXT,application TEXT,
        protocol TEXT,host TEXT,upload INTEGER,download INTEGER,flows INTEGER,
        PRIMARY KEY(bucket,mac,ip,application,protocol,host))''')
    compact_schema(db)
    try:
        yield db, HourlyWriter(db), minute.MinuteSeries(db)
    finally:
        db.close()


def write(writer, timestamp=BASE, mac=MAC, ip='192.168.1.2', upload=100, download=200):
    return writer.write((timestamp // 3600 * 3600, mac, ip, 'App', 'UDP', 'example.com', upload, download, 1))


class MinuteTests(unittest.TestCase):
    def test_legacy_history_is_not_split_into_invented_minutes(self):
        db = sqlite3.connect(':memory:')
        try:
            result = minute.query_series(db, BASE - 3600, BASE)
            self.assertFalse(result['available'])
            self.assertEqual(result['timeline'], [])
        finally:
            db.close()
        with database() as (db, writer, series):
            write(writer)
            result = minute.query_series(db, BASE - 120, BASE + 1)
            self.assertTrue(result['available'])
            self.assertTrue(all(row['coverage'] == 'missing' and row['upload'] is None for row in result['timeline']))

    def test_exact_minute_assignment_and_zero_vs_missing(self):
        with database() as (db, writer, series):
            series.heartbeat(BASE, True)
            for second in range(3, 64, 3):
                series.heartbeat(BASE + second, True)
            device = write(writer)
            series.add(BASE + 1, device, 100, 200)
            series.add(BASE + 61, device, 300, 400)
            series.flush(BASE + 63)
            rows = minute.query_series(db, BASE - 60, BASE + 63)['timeline']
            self.assertEqual([row['coverage'] for row in rows], ['missing', 'complete', 'complete'])
            self.assertEqual([(row['upload'], row['download']) for row in rows], [(None, None), (100, 200), (300, 400)])
            rows = minute.query_series(db, BASE, BASE + 63, device='02:00:00:00:00:01')['timeline']
            self.assertTrue(all(row['covered'] and row['upload'] == 0 for row in rows))

    def test_disconnect_stall_and_restart_do_not_fill_gaps(self):
        with database() as (db, writer, series):
            series.heartbeat(BASE, True)
            series.heartbeat(BASE + 3, True)
            series.heartbeat(BASE + 6, False)
            series.heartbeat(BASE + 60, True)
            series.heartbeat(BASE + 63, True)
            series.heartbeat(BASE + 120, True)  # A long blocked event loop.
            series.flush(BASE + 120)
            rows = minute.query_series(db, BASE, BASE + 120)['timeline']
            self.assertEqual([row['coverage'] for row in rows], ['partial', 'partial', 'missing'])
            db.commit()
            restarted = minute.MinuteSeries(db)
            restarted.heartbeat(BASE + 180, True)
            restarted.flush(BASE + 180)
            row = minute.query_series(db, BASE + 120, BASE + 180)['timeline'][0]
            self.assertEqual(row['coverage'], 'missing')

    def test_device_mac_filter_combines_ip_changes_but_ip_filter_stays_specific(self):
        with database() as (db, writer, series):
            one = write(writer, ip='192.168.1.2')
            two = write(writer, ip='2001:db8::2')
            other = write(writer, mac='02:00:00:00:00:02')
            for device, value in ((one, 10), (two, 20), (other, 90)):
                series.add(BASE, device, value, value * 2)
            series.flush(BASE + 1)
            self.assertEqual(minute.query_series(db, BASE, BASE + 1, MAC)['timeline'][0]['upload'], 30)
            self.assertEqual(minute.query_series(db, BASE, BASE + 1, '192.168.1.2')['timeline'][0]['upload'], 100)

    def test_pending_projection_is_not_replayed_after_transaction_rollback(self):
        with database() as (db, writer, series):
            one = write(writer)
            series.add(BASE, one, 100, 200)
            db.rollback()
            writer.clear_cache()
            # A subsequent write can reuse the rolled-back dictionary ID.
            two = write(writer, mac='02:00:00:00:00:02')
            self.assertEqual(one, two)
            series.add(BASE, two, 300, 400)
            series.flush(BASE + 1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM device_minutes').fetchone()[0], 0)
            self.assertEqual(series.counters['discarded_batches'], 1)
            self.assertEqual(db.execute('SELECT SUM(upload),SUM(download) FROM hourly').fetchone(), (100, 200))
            series.add(BASE + 2, two, 5, 6)
            series.flush(BASE + 3)
            self.assertEqual(db.execute('SELECT upload,download FROM device_minutes').fetchone(), (5, 6))

    def test_retention_and_maximum_rows_are_bounded(self):
        with database() as (db, writer, series):
            device = write(writer)
            for number in range(125):
                series.add(BASE + number * 60, device, 1, 2)
            series.flush(BASE + 124 * 60)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM device_minutes').fetchone()[0], 120)
            self.assertEqual(db.execute('SELECT MIN(bucket) FROM device_minutes').fetchone()[0], BASE + 5 * 60)
            with patch.object(minute, 'MAX_ROWS', 3):
                series.flush(BASE + 124 * 60)
            self.assertLessEqual(db.execute('SELECT COUNT(*) FROM device_minutes').fetchone()[0], 3)
            self.assertEqual(series.counters['pruned_rows'], 117)

    def test_deleted_data_is_missing_even_with_complete_capture_heartbeat(self):
        with database() as (db, writer, series):
            device = write(writer)
            series.heartbeat(BASE, True)
            for second in range(3, 61, 3):
                series.heartbeat(BASE + second, True)
            series.add(BASE, device, 100, 200)
            series.flush(BASE + 60)
            series.prune_hours({BASE // 3600 * 3600})
            row = minute.query_series(db, BASE, BASE + 59)['timeline'][0]
            self.assertEqual((row['coverage'], row['upload'], row['download']), ('missing', None, None))

    def test_buffer_overflow_marks_coverage_incomplete_and_fk_cascade_is_safe(self):
        with database() as (db, writer, series):
            one = write(writer)
            two = write(writer, mac='02:00:00:00:00:02')
            with patch.object(minute, 'MAX_PENDING', 1):
                self.assertTrue(series.add(BASE, one, 100, 200))
                self.assertFalse(series.add(BASE, two, 300, 400))
            series.flush(BASE + 1)
            self.assertEqual(series.counters['buffer_drops'], 1)
            self.assertEqual(minute.query_series(db, BASE, BASE + 1)['timeline'][0]['coverage'], 'partial')
            db.execute('DELETE FROM hourly_data WHERE device_id=?', (one,))
            db.execute('DELETE FROM traffic_devices WHERE id=?', (one,))
            self.assertEqual(db.execute('SELECT COUNT(*) FROM device_minutes').fetchone()[0], 0)

    def test_late_correction_before_and_after_flush_does_not_go_negative(self):
        with database() as (db, writer, series):
            device = write(writer)
            series.add(BASE + 1, device, 100, 200)
            series.correct(BASE, device, 100)
            series.flush(BASE + 3)
            self.assertEqual(db.execute('SELECT upload,download FROM device_minutes').fetchone(), (0, 200))
            series.add(BASE + 10, device, 300, 0)
            series.flush(BASE + 11)
            series.correct(BASE, device, 300)
            series.flush(BASE + 12)
            self.assertEqual(db.execute('SELECT upload,download FROM device_minutes').fetchone(), (0, 200))
            series.correct(BASE, device, 300)
            series.flush(BASE + 13)
            self.assertEqual(db.execute('SELECT upload,download FROM device_minutes').fetchone(), (0, 200))
            self.assertEqual(series.counters['correction_gaps'], 1)

    def test_full_buffer_cannot_drop_a_known_duplicate_upload_correction(self):
        with database() as (db, writer, series):
            one = write(writer)
            two = write(writer, mac='02:00:00:00:00:02')
            series.add(BASE, one, 100, 0)
            series.flush(BASE + 1)
            db.commit()
            with patch.object(minute, 'MAX_PENDING', 1):
                series.add(BASE + 60, two, 1, 0)
                self.assertTrue(series.correct(BASE, one, 100))
                series.flush(BASE + 61)
                series.add(BASE + 60, one, 100, 0)
                series.flush(BASE + 62)
            self.assertEqual(db.execute('SELECT SUM(upload) FROM device_minutes WHERE device_id=?', (one,)).fetchone()[0], 100)

    def test_clock_rollback_discards_future_projection_but_not_hourly_history(self):
        with database() as (db, writer, series):
            device = write(writer, timestamp=BASE + 3600)
            series.add(BASE + 3600, device, 100, 200)
            series.heartbeat(BASE + 3600, True)
            series.heartbeat(BASE + 3603, True)
            series.flush(BASE + 3603)
            series.add(BASE + 6, device, 1, 2)
            series.heartbeat(BASE + 6, True)
            series.flush(BASE + 6)
            self.assertEqual(db.execute('SELECT MAX(bucket) FROM device_minutes').fetchone()[0], BASE)
            self.assertEqual(db.execute('SELECT MAX(bucket) FROM minute_coverage').fetchone()[0], BASE)
            self.assertEqual(db.execute('SELECT SUM(upload) FROM hourly').fetchone()[0], 100)


class CollectorMinuteTests(unittest.TestCase):
    @contextmanager
    def collector(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(collector, 'DATA_DIR', directory), \
                patch.object(collector, 'RUNTIME_DIR', directory), \
                patch.object(collector, 'DB_PATH', os.path.join(directory, 'stats.db')):
            instance = collector.Collector()
            instance.local_macs = {'aa:aa:aa:aa:aa:aa'}
            instance.proxy.refresh = lambda: None
            instance.proxy.ports = {7892}
            try:
                yield instance
            finally:
                instance.db.close()

    @staticmethod
    def metadata(digest='one', **fields):
        flow = dict(digest=digest, other_type='remote', local_mac=MAC, local_ip='10.1.1.2',
                    other_ip='203.0.113.4', ip_protocol=6, local_port=12345, other_port=443)
        flow.update(fields)
        return {'type': 'flow', 'interface': 'br-lan', 'internal': True, 'flow': flow}

    @staticmethod
    def event(digest='one', upload=100, download=200):
        return {'type': 'flow_stats', 'interface': 'br-lan', 'internal': True,
                'flow': {'digest': digest, 'local_bytes': upload, 'other_bytes': download}}

    def test_pending_metadata_uses_original_arrival_minute_and_wan_is_excluded(self):
        with self.collector() as instance:
            instance.add_stats(self.event(), received_at=BASE + 59)
            self.assertEqual(instance.minutes.pending, {})
            with patch.object(collector.time, 'time', return_value=BASE + 65):
                instance.update_metadata(self.metadata())
            event = dict(self.event(), interface='wan', internal=False)
            instance.add_stats(event, received_at=BASE + 65)
            instance.minutes.flush(BASE + 66)
            rows = minute.query_series(instance.db, BASE, BASE + 66)['timeline']
            self.assertEqual([(row['upload'], row['download']) for row in rows], [(100, 200), (None, None)])
            self.assertEqual(instance.db.execute('SELECT SUM(upload),SUM(download) FROM hourly').fetchone(), (100, 200))

    def test_pending_unknown_traffic_is_not_displayed_as_complete_zero(self):
        with self.collector() as instance:
            instance.minutes.heartbeat(BASE, True)
            for second in range(3, 61, 3):
                instance.minutes.heartbeat(BASE + second, True)
            instance.add_stats(self.event(), received_at=BASE + 10)
            instance.minutes.flush(BASE + 60)
            row = minute.query_series(instance.db, BASE, BASE + 59)['timeline'][0]
            self.assertEqual((row['coverage'], row['upload']), ('missing', None))
            instance.discard_pending(instance.pop_pending(next(iter(instance.pending_stats))))
            instance.minutes.flush(BASE + 61)
            self.assertEqual(instance.minutes.counters['unattributed_events'], 1)

    def test_late_redirect_removes_original_minute_upload_without_recounting(self):
        line = ('ipv4 2 tcp 6 100 src=10.1.1.2 dst=203.0.113.4 sport=12345 dport=443 '
                'packets=1 bytes=10 src=10.1.1.1 dst=10.1.1.2 sport=7892 dport=12345 packets=1 bytes=20')
        with self.collector() as instance:
            original = self.metadata('original')
            instance.update_metadata(original)
            instance.add_stats(self.event('original'), received_at=BASE + 59)
            instance.minutes.flush(BASE + 59)
            instance.db.commit()
            instance.proxy.entries = dict(RedirectMap.parse(line, {7892}))
            translated = self.metadata('translated', local_ip='10.1.1.1', local_port=7892,
                                       local_mac='aa:aa:aa:aa:aa:aa', other_ip='10.1.1.2',
                                       other_port=12345, other_mac=MAC, other_type='local')
            instance.update_metadata(translated)
            instance.add_stats(self.event('translated', upload=200, download=100), received_at=BASE + 61)
            instance.minutes.flush(BASE + 63)
            rows = minute.query_series(instance.db, BASE, BASE + 63)['timeline']
            self.assertEqual([(row['upload'], row['download']) for row in rows], [(0, 200), (100, 0)])
            self.assertEqual(instance.db.execute('SELECT SUM(upload),SUM(download) FROM hourly').fetchone(), (100, 200))
            # Repeated metadata reconciliation does not apply a second correction.
            instance.update_metadata(translated)
            instance.minutes.flush(BASE + 64)
            self.assertEqual(instance.db.execute('SELECT SUM(upload),SUM(download) FROM device_minutes').fetchone(), (100, 200))

    def test_rolled_back_original_cannot_correct_a_reused_device_id(self):
        with self.collector() as instance:
            instance.update_metadata(self.metadata('original'))
            instance.add_stats(self.event('original', upload=100, download=0), received_at=BASE)
            instance.db.rollback()
            instance.writer.clear_cache()
            instance.minutes.flush(BASE + 1)
            instance.db.commit()
            instance.update_metadata(self.metadata('other', local_mac='02:00:00:00:00:02',
                                                   local_ip='10.1.1.3', ip_protocol=17))
            instance.add_stats(self.event('other', upload=200, download=0), received_at=BASE + 2)
            instance.minutes.flush(BASE + 3)
            instance.db.commit()
            instance.reconcile_original('br-lan', (6, '10.1.1.2', 12345, '203.0.113.4', 443))
            instance.minutes.flush(BASE + 4)
            self.assertEqual(instance.db.execute('SELECT SUM(upload) FROM device_minutes').fetchone()[0], 200)
            self.assertEqual(instance.db.execute('SELECT SUM(upload) FROM hourly').fetchone()[0], 200)


if __name__ == '__main__':
    unittest.main()
