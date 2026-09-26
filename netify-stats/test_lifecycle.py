"""Lifecycle hooks run only against rewritten temporary copies and fake services."""
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SOURCE = Path(__file__).resolve().parent
VALID_NETIFY = '''[netifyd]
enable_sink = no
upload_nat_flows = yes
export_json = yes
[socket]
listen_path[0] = /var/run/netifyd/netifyd.sock
dump_unknown_flows = yes
'''


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='netify-lifecycle-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in ('etc/init.d', 'usr/bin', 'usr/lib/netify-stats', 'tmp/netify-stats'):
            (self.root / name).mkdir(parents=True)
        (self.root / 'usr/bin/python3').symlink_to(sys.executable)
        shutil.copyfile(SOURCE / 'netify_storage.py', self.root / 'usr/lib/netify-stats/netify_storage.py')
        self.config = self.root / 'etc/netify-stats.json'
        self.config.write_text(json.dumps({'enabled': True, 'max_storage_mib': 16, 'interface': 'eth0'}))
        self.engine = self.root / 'etc/netifyd.conf'
        self.engine.write_text(VALID_NETIFY)
        self.history = self.root / 'tmp/netify-stats/stats.db'
        self.history.write_bytes(b'preserved history')
        self.log = self.root / 'services.log'
        for name in ('netify-stats', 'rpcd', 'netifyd'):
            service = self.root / 'etc/init.d' / name
            service.write_text('#!/bin/sh\nprintf "%s %s\\n" ' + shlex.quote(name) +
                               ' "$1" >> ' + shlex.quote(str(self.log)) + '\n' +
                               'if [ "$1" = stop ] && [ "${NS_TEST_STOP_FAIL:-0}" = 1 ]; then exit 1; fi\n')
            service.chmod(0o755)

    def run_script(self, relative, **environment):
        source = (SOURCE / relative).read_text()
        # Rewrite a private copy, not production hooks or their environment.
        self.assertEqual(source.count("ns_root=''"), 1)
        source = source.replace("ns_root=''", 'ns_root=' + shlex.quote(str(self.root)))
        if relative == 'netify-stats.init':
            source += '\n' + '\n'.join(
                name + '() { printf "%s\\n" ' + shlex.quote(name) + ' >> ' + shlex.quote(str(self.log)) + '; }'
                for name in ('procd_open_instance', 'procd_set_param', 'procd_close_instance'))
            source += '\nstart_service\n'
        script = self.root / 'isolated-hook.sh'
        script.write_text(source)
        return subprocess.run(['/bin/sh', str(script)], text=True, capture_output=True,
                              cwd=self.root,
                              env={**os.environ, 'IPKG_INSTROOT': '', 'PYTHONDONTWRITEBYTECODE': '1',
                                   'PYTHONPATH': '',
                                   **environment}, timeout=10)

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_enabled_install_replaces_collector_without_touching_netify_or_data(self):
        before = self.config.read_bytes(), self.engine.read_bytes(), self.history.read_bytes()
        result = self.run_script('packaging/post-install')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), ['netify-stats stop', 'netify-stats enable',
                                       'netify-stats start', 'rpcd restart'])
        self.assertEqual(before, (self.config.read_bytes(), self.engine.read_bytes(), self.history.read_bytes()))
        self.assertIn('socket is not ready', result.stderr)

    def test_disabled_install_keeps_autostart_off_even_without_engine_config(self):
        self.config.write_text('{"enabled":false,"max_storage_mib":16}')
        self.engine.unlink()
        result = self.run_script('packaging/post-install')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), ['netify-stats stop', 'netify-stats disable', 'rpcd restart'])
        self.assertFalse(json.loads(self.config.read_text())['enabled'])

    def test_invalid_prerequisites_do_not_start_collector(self):
        for old, new in (('listen_path[0]', '# listen_path[0]'),
                         ('upload_nat_flows = yes', 'upload_nat_flows = no'),
                         ('enable_sink = no', 'enable_sink = yes')):
            with self.subTest(setting=old):
                self.engine.write_text(VALID_NETIFY.replace(old, new))
                if self.log.exists():
                    self.log.unlink()
                result = self.run_script('packaging/post-install')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('prerequisites', result.stderr)
                self.assertEqual(self.calls(), ['netify-stats stop', 'netify-stats disable', 'rpcd restart'])

    def test_corrupt_settings_are_failure_not_disabled(self):
        self.config.write_text('{broken')
        for script in ('packaging/post-install', 'netify-stats.init'):
            with self.subTest(script=script):
                result = self.run_script(script)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.calls(), [])

    def test_init_disabled_and_missing_module_are_distinct(self):
        self.config.write_text('{"enabled":false}')
        self.assertEqual(self.run_script('netify-stats.init').returncode, 0)
        self.assertEqual(self.calls(), [])
        (self.root / 'usr/lib/netify-stats/netify_storage.py').unlink()
        self.assertNotEqual(self.run_script('netify-stats.init').returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_enabled_init_opens_procd_instance(self):
        result = self.run_script('netify-stats.init')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls()[0], 'procd_open_instance')
        self.assertEqual(self.calls()[-1], 'procd_close_instance')

    def test_stop_failure_aborts_install_and_uninstall(self):
        for script in ('packaging/post-install', 'packaging/pre-deinstall'):
            with self.subTest(script=script):
                if self.log.exists():
                    self.log.unlink()
                result = self.run_script(script, NS_TEST_STOP_FAIL='1')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.calls(), ['netify-stats stop'])
                self.assertTrue(self.config.exists())
                self.assertEqual(self.history.read_bytes(), b'preserved history')

    def test_uninstall_keeps_settings_and_history(self):
        before = self.config.read_bytes(), self.engine.read_bytes(), self.history.read_bytes()
        result = self.run_script('packaging/pre-deinstall')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), ['netify-stats stop', 'netify-stats disable'])
        self.assertEqual(before, (self.config.read_bytes(), self.engine.read_bytes(), self.history.read_bytes()))

    def test_image_build_hooks_never_invoke_services(self):
        for script in ('packaging/post-install', 'packaging/pre-deinstall'):
            with self.subTest(script=script):
                result = self.run_script(script, IPKG_INSTROOT=str(self.root / 'image'))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.calls(), [])


if __name__ == '__main__':
    unittest.main()
