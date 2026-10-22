"""Service-state failure regression checks; uses temporary files and fake services."""
import json
import fcntl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import ANY, patch

import netify_control as control
import netify_storage as storage


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.config = root / 'settings.json'
        self.config.write_text(json.dumps({'enabled': True, 'max_storage_mib': 16, 'interface': 'eth0'}))
        for obj, name, value in ((storage, 'CONFIG_PATH', str(self.config)),
                                 (control, 'STATE_PATH', str(root / 'state.json')),
                                 (control, 'LOCK_PATH', str(root / 'control.lock')),
                                 (control, 'DB_PATH', str(root / 'absent.db'))):
            patcher = patch.object(obj, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_partial_stop_keeps_actual_state_and_retry_clears_error(self):
        running = [True, True]
        fail = [True]

        def run(*args, **kwargs):
            if args == ('/etc/init.d/netify-stats', 'stop'):
                running[0] = False
            if args == ('/etc/init.d/netifyd', 'stop'):
                if fail[0]:
                    raise RuntimeError('stop failed')
                running[1] = False

        with patch.object(control, 'runtime_state', side_effect=lambda: tuple(running)), patch.object(control, 'run', side_effect=run):
            with self.assertRaisesRegex(RuntimeError, 'stop failed'):
                control.set_enabled(False)
            status = control.control_status()
            self.assertFalse(status['enabled'])
            self.assertEqual(status['actual_state'], 'partial')
            self.assertFalse(status['applied'])
            self.assertIn('stop failed', status['apply_error'])
            fail[0] = False
            status = control.set_enabled(False)
            self.assertEqual(status['actual_state'], 'stopped')
            self.assertTrue(status['applied'])
            self.assertEqual(status['apply_error'], '')
        self.assertEqual(json.loads(self.config.read_text())['max_storage_mib'], 16)

    def test_start_command_success_does_not_claim_running(self):
        clock = [0.0]
        def sleep(seconds):
            clock[0] += seconds
        with patch.object(control, 'runtime_state', return_value=(False, False)), patch.object(control, 'run'), patch.object(control.time, 'sleep', side_effect=sleep), patch.object(control.time, 'monotonic', side_effect=lambda: clock[0]):
            with self.assertRaisesRegex(RuntimeError, 'Services did not fully start'):
                control.set_enabled(True)
            status = control.control_status()
        self.assertTrue(status['enabled'])
        self.assertFalse(status['applied'])
        self.assertEqual(status['actual_state'], 'stopped')

    def test_control_lock_returns_without_waiting_or_changing_target(self):
        before = self.config.read_text()
        with open(control.LOCK_PATH, 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            with self.assertRaisesRegex(RuntimeError, 'Another analysis toggle is in progress'):
                control.set_enabled(False)
        self.assertEqual(self.config.read_text(), before)
        self.assertFalse(Path(control.STATE_PATH).exists())

    def test_commands_share_deadline_and_stop_when_budget_expires(self):
        clock = [0.0]
        timeouts = []
        def slow_run(*args, timeout):
            timeouts.append(timeout)
            clock[0] += min(6, timeout)
        with patch.object(control.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(control, 'run', side_effect=slow_run), patch.object(control, 'runtime_state', return_value=(True, True)):
            with self.assertRaisesRegex(RuntimeError, 'Analysis toggle timed out'):
                control.set_enabled(True)
            self.assertIn('Analysis toggle timed out', control.control_status()['apply_error'])
        self.assertEqual(timeouts, [10, 9, 3])
        self.assertEqual(clock[0], 15)

    def test_live_orphaned_install_blocks_toggle_without_changing_settings(self):
        before = self.config.read_text()
        with patch.object(control, 'installation_active', return_value=True), \
                patch.object(control, 'run') as run:
            for enabled in (False, True):
                with self.subTest(enabled=enabled), self.assertRaisesRegex(RuntimeError, 'application update is being installed'):
                    control.set_enabled(enabled)
            run.assert_not_called()
        self.assertEqual(self.config.read_text(), before)
        self.assertFalse(Path(control.STATE_PATH).exists())

    def test_invalid_input_does_not_change_settings(self):
        before = self.config.read_text()
        with self.assertRaises(ValueError):
            control.set_enabled('false')
        self.assertEqual(self.config.read_text(), before)

    def test_status_with_corrupt_config_reports_unknown_without_guessing(self):
        for document in ('{broken', '{"enabled":"true"}', '[]'):
            with self.subTest(document=document):
                self.config.write_text(document)
                with patch.object(control, 'runtime_state', return_value=(True, True)):
                    status = control.control_status()
                self.assertIsNone(status['enabled'])
                self.assertFalse(status['applied'])
                self.assertEqual(status['actual_state'], 'unknown')
                self.assertTrue(status['config_error'])
                self.assertTrue(status['collector_running'])
                self.assertEqual(self.config.read_text(), document)

    def test_status_uses_supplied_snapshot_without_reading_settings_again(self):
        with patch.object(control, 'read_enabled') as read, \
                patch.object(control, 'runtime_state', return_value=(False, False)):
            status = control.control_status(False)
            read.assert_not_called()
        self.assertTrue(status['applied'])
        self.assertEqual(status['actual_state'], 'stopped')

    def test_broken_config_cannot_start_services(self):
        self.config.write_text('{broken')
        with patch.object(control, 'run') as run:
            with self.assertRaises(RuntimeError):
                control.set_enabled(True)
            run.assert_not_called()
        self.assertEqual(self.config.read_text(), '{broken')

    def test_invalid_interface_or_storage_cannot_start_services(self):
        for changes in ({'interface': 42}, {'max_storage_mib': '16'}, {'max_storage_mib': True}):
            values = {'enabled': False, 'interface': 'eth0', 'max_storage_mib': 16, **changes}
            document = json.dumps(values)
            with self.subTest(changes=changes):
                self.config.write_text(document)
                with patch.object(control, 'run') as run:
                    with self.assertRaisesRegex(RuntimeError, 'Cannot start analysis'):
                        control.set_enabled(True)
                    run.assert_not_called()
                self.assertEqual(self.config.read_text(), document)

    def test_explicit_start_can_repair_only_an_invalid_enabled_flag(self):
        self.config.write_text('{"enabled":"true","interface":"eth0","max_storage_mib":16}')
        with patch.object(control, 'run'), \
                patch.object(control, 'runtime_state', return_value=(True, True)):
            status = control.set_enabled(True)
        self.assertTrue(status['applied'])
        self.assertEqual(json.loads(self.config.read_text()),
                         {'enabled': True, 'interface': 'eth0', 'max_storage_mib': 16})

    def test_stop_remains_available_with_invalid_unrelated_settings(self):
        self.config.write_text('{"enabled":true,"interface":42,"max_storage_mib":"16"}')
        with patch.object(control, 'run') as run, \
                patch.object(control, 'runtime_state', return_value=(False, False)):
            status = control.set_enabled(False)
        self.assertTrue(status['applied'])
        run.assert_any_call('/etc/init.d/netify-stats', 'stop', timeout=ANY)
        self.assertEqual(json.loads(self.config.read_text()),
                         {'enabled': False, 'interface': 42, 'max_storage_mib': '16'})

    def test_legacy_error_is_normalized_without_rewriting_or_clearing_failure(self):
        state = Path(control.STATE_PATH)
        original = json.dumps({'apply_error': '开关尚未完整应用，请重试：服务未完整启动，请重试'},
                              ensure_ascii=False)
        state.write_text(original)
        with patch.object(control, 'runtime_state', return_value=(False, False)):
            status = control.control_status()
        self.assertEqual(status['apply_error'],
                         'Analysis setting could not be fully applied: Services did not fully start. Please try again.')
        self.assertTrue(status['enabled'])
        self.assertFalse(status['applied'])
        self.assertEqual(status['actual_state'], 'stopped')
        self.assertEqual(state.read_text(), original)

    def test_legacy_error_preserves_system_diagnostics_and_unrelated_text(self):
        state = Path(control.STATE_PATH)
        for original, expected in (
                ('开关尚未完整应用，请重试：[Errno 13] Permission denied: /tmp/用户文件',
                 'Analysis setting could not be fully applied: [Errno 13] Permission denied: /tmp/用户文件'),
                ('设置正在保存，请稍后重试', 'Settings are being saved. Please try again.'),
                ('应用错误：服务未完整启动，请重试', '应用错误：服务未完整启动，请重试')):
            document = json.dumps({'apply_error': original}, ensure_ascii=False)
            state.write_text(document)
            with patch.object(control, 'runtime_state', return_value=(True, False)):
                status = control.control_status()
            self.assertEqual(status['apply_error'], expected)
            self.assertFalse(status['applied'])
            self.assertEqual(state.read_text(), document)

    def test_proc_scan_checks_exact_program_arguments(self):
        root = Path(self.tmp.name) / 'proc'
        for pid, command in ((11, b'/usr/bin/python3\0/usr/sbin/netify-stats-collector\0'),
                             (12, b'/usr/sbin/netifyd\0-R\0'),
                             (13, b'/bin/echo\0/usr/sbin/netifyd\0')):
            directory = root / str(pid)
            directory.mkdir(parents=True)
            (directory / 'cmdline').write_bytes(command)
        with patch.object(control, 'PROC_PATH', str(root)):
            self.assertEqual(control.runtime_state(), (True, True))
            (root / '12' / 'cmdline').write_bytes(b'/usr/sbin/netifyd-helper\0')
            self.assertEqual(control.runtime_state(), (True, False))
            (root / '11' / 'cmdline').write_bytes(b'/bin/cat\0/usr/sbin/netify-stats-collector\0')
            self.assertEqual(control.runtime_state(), (False, False))
            (root / '11' / 'cmdline').write_bytes(b'/usr/bin/python3.13\0/usr/sbin/netify-stats-collector\0')
            self.assertEqual(control.runtime_state(), (True, False))
            (root / '11' / 'cmdline').write_bytes(b'/usr/bin/python3\0-c\0/usr/sbin/netify-stats-collector\0')
            self.assertEqual(control.runtime_state(), (False, False))


if __name__ == '__main__':
    unittest.main()
