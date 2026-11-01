"""Configuration and RPC tests use temporary files, never live firewall state."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import anti_pcdn_rpc as rpc
from anti_pcdn import config


class ConfigTests(unittest.TestCase):
    def test_defaults_are_independent_and_observe_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / 'missing.json'
            first = config.load(missing)
            self.assertFalse(first['enabled'])
            self.assertEqual(first['mode'], 'observe')
            first['weights']['domain'] = 0
            first['allow_devices'].append('02:11:22:33:44:55')
            self.assertEqual(config.load(missing), config.DEFAULTS)
            self.assertFalse(missing.exists())

    def test_strict_validation(self):
        for change in ({'enabled': 1}, {'mode': 'block'}, {'threshold': True}, {'threshold': 101},
                       {'threshold': 0}, {'ban_seconds': 29}, {'ban_seconds': 601},
                       {'interface': 'br-lan;reboot'}, {'interface': 'a' * 16}, {'extra': 1},
                       {'allow_devices': ['ff:ff:ff:ff:ff:ff']}, {'allow_devices': ['00:00:00:00:00:00']},
                       {'allow_devices': '02:11:22:33:44:55'}, {'allow_domains': ['example.org'] * 129},
                       {'weights': {'fanout': 100}}):
            with self.subTest(change=change), self.assertRaises(config.ConfigError):
                config.validate(change)
        for bad_weight in (True, 41, -1, 20.0):
            weights = dict(config.DEFAULTS['weights'], domain=bad_weight)
            with self.assertRaises(config.ConfigError):
                config.validate({'weights': weights})
        with self.assertRaises(config.ConfigError):
            config.validate({'weights': dict(config.DEFAULTS['weights'], domain=19)})

    def test_domains_match_only_whole_labels(self):
        settings = config.validate({'allow_domains': ['Uploader.Example.org.', 'uploader.example.org'],
                                    'allow_devices': ['02:AA:BB:CC:DD:EE']})
        self.assertEqual(settings['allow_domains'], ['uploader.example.org'])
        self.assertEqual(settings['allow_devices'], ['02:aa:bb:cc:dd:ee'])
        for host in ('uploader.example.org', 'node.uploader.example.org', 'NODE.UPLOADER.EXAMPLE.ORG.'):
            self.assertTrue(config.domain_matches(host, settings['allow_domains']))
        for host in ('fakeuploader.example.org', 'uploader.example.org.evil', None, 'https://uploader.example.org'):
            self.assertFalse(config.domain_matches(host, settings['allow_domains']))
        for host in ('*.example.org', 'https://example.org', '127.0.0.1', 'localhost', '-bad.example',
                     'x.' + 'a' * 64 + '.org', 'example.org/path', 'foo..org'):
            with self.subTest(host=host), self.assertRaises(config.ConfigError):
                config.validate({'pcdn_domains': [host]})

    def test_save_atomic_private_and_invalid_never_replaces(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'config.json'
            expected = config.save({'enabled': True, 'mode': 'auto'}, path)
            self.assertEqual(config.load(path), expected)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            original = path.read_bytes()
            with self.assertRaises(config.ConfigError):
                config.save({'threshold': True}, path)
            self.assertEqual(path.read_bytes(), original)
            with mock.patch.object(config.os, 'replace', side_effect=OSError('full')):
                with self.assertRaises(OSError):
                    config.save({}, path)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(list(Path(temporary).iterdir()), [path])

    def test_bad_and_oversized_disk_settings_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'config.json'
            for payload in (b'[1,2]', b'{', b'\xff', b' ' * (config.MAX_CONFIG_BYTES + 1)):
                path.write_bytes(payload)
                with self.assertRaises(config.ConfigError):
                    config.load(path)


class RpcTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for key, name in [('CONFIG_PATH', 'config.json'), ('STATUS_PATH', 'status.json'),
                          ('RELEASE_PATH', 'release.json'), ('COLLECTOR_STATUS_PATH', 'collector.json')]:
            patcher = mock.patch.object(rpc, key, str(self.root / name))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.id = 'a' * 24
        self.snapshot = {'timestamp': 1000, 'leases': [{'id': self.id}], 'mode': 'observe'}

    def write(self, name, value):
        (self.root / name).write_text(json.dumps(value))

    def call(self, method, params):
        output = io.StringIO()
        with mock.patch.object(rpc.sys, 'argv', ['rpc', 'call', method]), \
                mock.patch.object(rpc.sys, 'stdin', io.StringIO(json.dumps(params))), contextlib.redirect_stdout(output):
            self.assertEqual(rpc.main(), 0)
        return json.loads(output.getvalue())

    def test_reads_have_no_filesystem_mutations(self):
        result = rpc.status(now=1000)
        self.assertFalse(result['settings']['enabled'])
        self.assertTrue(result['stale'])
        self.assertEqual(list(self.root.iterdir()), [])
        self.write('status.json', self.snapshot)
        self.write('collector.json', {'timestamp': 999, 'connected': True})
        result = rpc.status(now=1000)
        self.assertFalse(result['stale'])
        self.assertTrue(result['collector_recent'])
        self.assertTrue(result['collector_connected'])
        self.assertTrue(rpc.status(now=1016)['stale'])
        self.assertTrue(rpc.status(now=999)['stale'])
        self.assertEqual(len(list(self.root.iterdir())), 2)
        self.write('status.json', {'timestamp': 10 ** 400})
        self.assertTrue(rpc.status(now=1000)['stale'])

    def test_configure_only_saves_feature_settings(self):
        result = self.call('configure', {'settings': {'enabled': True}})
        self.assertTrue(result['ok'])
        self.assertTrue(result['pending'])
        self.assertEqual([path.name for path in self.root.iterdir()], ['config.json'])
        self.assertFalse(self.call('configure', {'settings': {'enabled': 'yes'}})['ok'])
        self.assertFalse(self.call('configure', {'settings': {}, 'command': 'reboot'})['ok'])
        self.assertTrue(config.load(rpc.CONFIG_PATH)['enabled'])

    def test_bad_status_and_config_are_visible(self):
        self.write('config.json', {'mode': 'oops'})
        for payload in ('[]', '{"timestamp":NaN}', 'x' * (rpc.MAX_STATUS_BYTES + 1)):
            (self.root / 'status.json').write_text(payload)
            result = rpc.status(now=1000)
            self.assertTrue(result['runtime_error'])
            self.assertTrue(result['config_error'])
            self.assertFalse(result['settings']['enabled'])
            self.assertTrue(result['stale'])

    def test_release_publishes_one_private_complete_request(self):
        self.write('status.json', self.snapshot)
        first = rpc.release(self.id, now=1000)
        pending = rpc.read_object(rpc.RELEASE_PATH)
        self.assertEqual(pending['id'], self.id)
        self.assertEqual(pending['request_id'], first['request_id'])
        self.assertRegex(pending['request_id'], r'^[0-9a-f]{32}$')
        self.assertEqual(stat.S_IMODE(Path(rpc.RELEASE_PATH).stat().st_mode), 0o600)
        with self.assertRaisesRegex(ValueError, 'already pending'):
            rpc.release(self.id, now=1001)
        self.assertEqual(rpc.read_object(rpc.RELEASE_PATH), pending)
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), ['release.json', 'status.json'])
        self.assertEqual(rpc.status(now=1000)['release_pending']['request_id'], first['request_id'])

    def test_release_rejects_stale_missing_or_unlisted_lease(self):
        self.write('status.json', self.snapshot)
        for invalid in ('', '../release', 'a' * 23, 'A' * 24, 'b' * 24, True):
            with self.assertRaises(ValueError):
                rpc.release(invalid, now=1000)
        with self.assertRaisesRegex(ValueError, 'stale'):
            rpc.release(self.id, now=1016)
        self.assertFalse(Path(rpc.RELEASE_PATH).exists())


if __name__ == '__main__':
    unittest.main()
