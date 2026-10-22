"""Updater regressions with temporary state and fake packages; never install real packages."""
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import netify_control
import netify_update as update

PAYLOAD = b'a verified release package'


def manifest(version='0.3.0', series='24.10'):
    fmt = 'ipk' if series == '24.10' else 'apk'
    return {'schema': 1, 'version': version, 'tag': 'V' + version, 'packages': {
        series: {'filename': 'BetterDPI-%s-openwrt-%s.8-all.%s' % (version, series, fmt),
                 'format': fmt, 'size': len(PAYLOAD), 'sha256': hashlib.sha256(PAYLOAD).hexdigest()}}}


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for obj, name, value in ((update, 'STATE_DIR', str(self.root / 'state')),
                                 (netify_control, 'LOCK_PATH', str(self.root / 'control.lock'))):
            patcher = patch.object(obj, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        update._private_directory()
        self.platform = patch.object(update, 'platform_target', return_value=('24.10', '/fake/opkg'))
        self.platform.start()
        self.addCleanup(self.platform.stop)
        self.candidate = update.validate_manifest(manifest(), '24.10')

    def state(self, state='available', **extra):
        value = {'state': state, 'candidate': self.candidate, 'checked_at': int(time.time()),
                 'series': '24.10', 'manager': '/fake/opkg'}
        value.update(extra)
        update._write_state(value)
        return value

    def download(self, url, path, maximum, seconds, expected_size=None):
        data = json.dumps(manifest()).encode() if url == update.MANIFEST_URL else PAYLOAD
        Path(path).write_bytes(data)
        return hashlib.sha256(data).hexdigest()

    def assertError(self, code, function, *args):
        with self.assertRaises(update.UpdateError) as caught:
            function(*args)
        self.assertEqual(caught.exception.code, code)

    def test_numeric_versions_and_package_revisions(self):
        self.assertGreater(update.version_tuple('0.10.0'), update.version_tuple('0.9.9'))
        for version in ('0.3.0-r1', '0.3.0-2', '0.3.0'):
            self.assertEqual(update.installed_base(version), '0.3.0')
        for value in ('v0.3.0', '0.3.0-rc1', '0.03.0', '0.3', '1.2.3/../../file', None, True):
            self.assertError('invalid_manifest', update.version_tuple, value)

    def test_manifest_rejects_tags_paths_wrong_target_hash_and_sizes(self):
        changes = [lambda m: m.update(schema=True), lambda m: m.update(schema=2),
                   lambda m: m.update(tag='V0.4.0'), lambda m: m.update(version='0.3.0-rc1'),
                   lambda m: m['packages']['24.10'].update(filename='../../evil.ipk'),
                   lambda m: m['packages']['24.10'].update(filename='BetterDPI-0.3.0-openwrt-25.12.8-all.ipk'),
                   lambda m: m['packages']['24.10'].update(format='apk'),
                   lambda m: m['packages']['24.10'].update(size=True),
                   lambda m: m['packages']['24.10'].update(size=0),
                   lambda m: m['packages']['24.10'].update(size=update.MAX_PACKAGE + 1),
                   lambda m: m['packages']['24.10'].update(sha256='f'*63)]
        for change in changes:
            value = manifest()
            change(value)
            self.assertError('invalid_manifest', update.validate_manifest, value, '24.10')
        self.assertError('invalid_manifest', update.validate_manifest, manifest(), '25.12')

    def test_poll_does_not_import_network_stack_query_packages_or_create_files(self):
        code = ('import sys; import netify_update as u; u.STATE_DIR=%r; '
                'assert u.read_status("0.3.0")["state"] == "idle"; '
                'assert not ({"ssl", "urllib.request", "http.client"} & set(sys.modules))') % str(self.root / 'absent')
        subprocess.run([sys.executable, '-c', code], cwd=Path(update.__file__).parent, check=True)
        with patch.object(update, '_download') as download, patch.object(update, '_query_version') as query:
            update.read_status('0.3.0')
        download.assert_not_called()
        query.assert_not_called()
        self.assertFalse((self.root / 'absent').exists())

    def test_private_state_permissions_bounds_and_symlink_refusal(self):
        self.state()
        self.assertEqual(os.stat(update.STATE_DIR).st_mode & 0o777, 0o700)
        path = Path(update.STATE_DIR) / 'status.json'
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        path.write_text('x' * (update.MAX_STATE + 1))
        self.assertEqual(update.read_status('0.2.8')['error'], 'status_invalid')
        path.unlink()
        path.symlink_to(self.root / 'outside')
        self.assertEqual(update.read_status('0.2.8')['error'], 'status_invalid')

    def test_dead_worker_is_interrupted_not_automatically_installable(self):
        self.state('installing', worker_pid=99999999, worker_start='123')
        self.assertEqual(update.read_status('0.2.8')['state'], 'interrupted')
        with patch('subprocess.Popen') as spawn:
            self.assertEqual(update.start_install('0.2.8', '0.3.0')['error'], 'update_not_checked')
        spawn.assert_not_called()

    def test_live_orphan_installer_blocks_new_check_and_toggle(self):
        self.state('installing', installer_pid=os.getpid(), installer_start=update._identity(os.getpid()))
        self.assertTrue(update.read_status('0.2.8')['busy'])
        self.assertTrue(update.installation_active())
        with patch('subprocess.Popen') as spawn:
            self.assertEqual(update.start_check('0.2.8')['error'], 'operation_busy')
        spawn.assert_not_called()
        self.assertEqual(update._read_state()['state'], 'installing')

    def test_pid_reuse_does_not_preserve_busy(self):
        self.state('installing', installer_pid=os.getpid(), installer_start='wrong-start-time')
        self.assertFalse(update.installation_active())
        self.assertEqual(update.read_status('0.2.8')['state'], 'interrupted')

    def test_held_lock_transfers_to_worker_without_spawn_gap(self):
        inherited = []
        def launch(argv, **kwargs):
            inherited.append(os.dup(kwargs['pass_fds'][0]))
            self.assertTrue(kwargs['start_new_session'])
            self.assertEqual(argv[-1], '0.2.8')
            self.assertEqual(update.start_check('0.2.8')['error'], 'operation_busy')
            return Mock()
        with patch('subprocess.Popen', side_effect=launch) as spawn:
            self.assertTrue(update.start_check('0.2.8')['busy'])
            self.assertTrue(update.read_status('0.2.8')['busy'])
            self.assertEqual(update.start_check('0.2.8')['error'], 'operation_busy')
            self.assertEqual(spawn.call_count, 1)
        os.close(inherited[0])
        self.assertEqual(update.read_status('0.2.8')['state'], 'interrupted')

    def test_spawn_error_persists_for_next_summary(self):
        with patch('subprocess.Popen', side_effect=OSError('cannot spawn')):
            self.assertEqual(update.start_check('0.2.8')['error'], 'worker_start_failed')
        self.assertEqual(update.read_status('0.2.8')['error'], 'worker_start_failed')

    def test_manual_action_cleans_only_orphan_download_directories(self):
        orphan = Path(update.STATE_DIR) / 'download-orphan'
        orphan.mkdir()
        (orphan / 'package.ipk').write_bytes(PAYLOAD)
        external = self.root / 'external'
        external.mkdir()
        (external / 'keep').write_text('keep')
        (Path(update.STATE_DIR) / 'download-link').symlink_to(external, target_is_directory=True)
        self.state('installing', installer_pid=os.getpid(), installer_start=update._identity(os.getpid()))
        update.read_status('0.2.8')
        self.assertTrue(orphan.exists())
        self.assertEqual(update.start_check('0.2.8')['error'], 'operation_busy')
        self.assertTrue(orphan.exists())
        self.state('installing', installer_pid=99999999, installer_start='dead')
        with patch('subprocess.Popen', side_effect=OSError('fake start failure')):
            update.start_check('0.2.8')
        self.assertFalse(orphan.exists())
        self.assertTrue((external / 'keep').exists())

    def test_exact_recent_candidate_required_and_no_downgrade(self):
        cases = [('idle', '0.3.0', '0.2.8', {}, 'update_not_checked'),
                 ('available', '0.4.0', '0.2.8', {}, 'candidate_changed'),
                 ('available', '0.3.0', '0.3.0', {}, 'candidate_changed'),
                 ('available', '0.3.0', '0.2.8', {'checked_at': 1}, 'check_expired'),
                 ('available', '0.3.0', '0.2.8', {'checked_at': time.time()+3600}, 'check_expired')]
        for state, requested, current, extra, error in cases:
            self.state(state, **extra)
            with patch('subprocess.Popen') as spawn:
                self.assertEqual(update.start_install(current, requested)['error'], error)
            spawn.assert_not_called()
            self.assertEqual(update.read_status(current)['error'], error)

    def test_check_uses_installed_database_to_avoid_downgrade(self):
        for installed, expected in [('0.2.8-1', 'available'), ('0.4.0-r1', 'up_to_date')]:
            state = self.state('checking')
            with patch.object(update, '_download', side_effect=self.download), \
                    patch.object(update, '_query_version', return_value=installed):
                update._check(state, '0.2.8', self.temp.name)
            self.assertEqual(state['state'], expected)
            self.assertEqual(state['candidate'], self.candidate)
            self.assertEqual(state['installed_version'], installed)

    def test_hash_failure_never_invokes_package_manager(self):
        with patch.object(update, '_download', return_value='0'*64), \
                patch.object(update, '_run_installer') as run, patch.object(update, '_query_version') as query:
            self.assertError('checksum_mismatch', update._install, self.state('downloading'), '0.2.8', self.temp.name)
        run.assert_not_called()
        query.assert_not_called()

    def test_control_lock_blocks_install(self):
        with open(netify_control.LOCK_PATH, 'w') as lock, \
                patch.object(update, '_download', side_effect=self.download), \
                patch.object(update, '_run_installer') as install:
            fcntl.flock(lock, fcntl.LOCK_EX)
            self.assertError('operation_busy', update._install, self.state('downloading'), '0.2.8', self.temp.name)
        install.assert_not_called()

    def test_install_success_requires_matching_version_and_control_lock(self):
        for series, fmt in [('24.10', 'ipk'), ('25.12', 'apk')]:
            with tempfile.TemporaryDirectory(dir=self.temp.name) as directory:
                candidate = update.validate_manifest(manifest(series=series), series)
                state = self.state('downloading', candidate=candidate, series=series)
                def install(*args):
                    with open(netify_control.LOCK_PATH, 'a') as lock:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with patch.object(update, 'platform_target', return_value=(series, '/fake/' + fmt)), \
                        patch.object(update, '_download', side_effect=self.download), \
                        patch.object(update, '_query_version', side_effect=['0.2.8-r1', '0.3.0-r1']), \
                        patch.object(update, '_run_installer', side_effect=install) as run:
                    update._install(state, '0.2.8', directory)
                self.assertEqual(run.call_count, 1)
                self.assertEqual(state['state'], 'succeeded')
                self.assertEqual(state['installed_version'], '0.3.0-r1')

    def test_exit_zero_with_unchanged_version_fails_verification(self):
        with patch.object(update, '_download', side_effect=self.download), \
                patch.object(update, '_query_version', return_value='0.2.8-1'), \
                patch.object(update, '_run_installer'):
            self.assertError('install_verification_failed', update._install, self.state('downloading'), '0.2.8', self.temp.name)

    def test_external_upgrade_after_check_cannot_be_downgraded(self):
        state = self.state('downloading')
        with patch.object(update, '_download', side_effect=self.download), \
                patch.object(update, '_query_version', return_value='0.4.0-1'), \
                patch.object(update, '_run_installer') as run:
            update._install(state, '0.2.8', self.temp.name)
        run.assert_not_called()
        self.assertEqual(state['state'], 'up_to_date')

    def test_launcher_records_pid_closes_job_fd_and_runs_fixed_argv(self):
        # Actual fork/exec with a harmless Python executable records argv and
        # verifies neither lifecycle lock reaches package scripts.
        recorder = self.root / 'fake-manager'
        record = self.root / 'called.json'
        recorder.write_text('#!%s\nimport json,os,sys\nfds={}\nfor fd in os.listdir("/proc/self/fd"):\n try: fds[fd]=os.readlink("/proc/self/fd/"+fd)\n except OSError: pass\nopen(%r,"w").write(json.dumps({"argv":sys.argv[1:],"fds":fds,"pid":os.getpid()}))\n' % (sys.executable, str(record)))
        recorder.chmod(0o700)
        fd = os.open(update._path('job.lock'), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            for fmt, argv in [('ipk', ['install']), ('apk', ['add', '--no-network', '--allow-untrusted'])]:
                state = self.state('installing')
                update._run_installer(str(recorder), {'format': fmt}, '/tmp/pkg.'+fmt, state, fd)
                result = json.loads(record.read_text())
                self.assertEqual(result['argv'], argv+['/tmp/pkg.'+fmt])
                self.assertEqual(update._read_state()['installer_pid'], result['pid'])
                self.assertFalse(any('job.lock' in path for path in result['fds'].values()))
                self.assertEqual(result['fds']['1'], '/dev/null')
                self.assertEqual(result['fds']['2'], '/dev/null')
        finally:
            os.close(fd)

    def test_launcher_never_executes_when_pid_handshake_fails(self):
        marker = self.root / 'executed'
        executable = self.root / 'fake'
        executable.write_text('#!/bin/sh\ntouch '+str(marker)+'\n')
        executable.chmod(0o700)
        fd = os.open(update._path('job.lock'), os.O_CREAT | os.O_RDWR, 0o600)
        state = self.state('installing')
        try:
            with patch.object(update, '_write_state', side_effect=OSError('full disk')):
                self.assertError('install_failed', update._run_installer, str(executable), {'format':'ipk'}, '/tmp/file', state, fd)
        finally:
            os.close(fd)
        self.assertFalse(marker.exists())

    def test_killed_worker_cannot_interrupt_or_duplicate_orphan_installer(self):
        # Pause the forked launcher before publishing its PID. Killing the
        # worker there must leave a continuous lock-to-PID handoff, and the
        # eventual installer must be able to print even with no worker left.
        manager = self.root / 'survival-manager'
        manager.write_text('''#!%s
import os, pathlib, time
root = pathlib.Path(%r)
(root / 'installer.pid').write_text(str(os.getpid()))
deadline = time.monotonic() + 10
while not (root / 'finish').exists() and time.monotonic() < deadline:
    time.sleep(.01)
os.write(1, b'package database progress\\n')
(root / 'completed').touch()
''' % (sys.executable, str(self.root)))
        manager.chmod(0o700)
        script = self.root / 'survival-worker.py'
        script.write_text('''import sys, os, pathlib, time, fcntl
sys.path.insert(0, %r)
import netify_update as u
u.STATE_DIR = %r
root = pathlib.Path(%r)
fd = os.open(u._path('job.lock'), os.O_CREAT | os.O_RDWR, 0o600)
control = os.open(%r, os.O_CREAT | os.O_RDWR, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)
fcntl.flock(control, fcntl.LOCK_EX)
state = {'state': 'installing'}
u._write_state(state)
owner, original = os.getpid(), u._write_state
def publish(state):
    if os.getpid() != owner:
        (root / 'window').touch()
        deadline = time.monotonic() + 10
        while not (root / 'publish').exists() and time.monotonic() < deadline:
            time.sleep(.01)
    original(state)
u._write_state = publish
u._run_installer(%r, {'format': 'ipk'}, 'ignored', state, fd)
''' % (str(Path(update.__file__).parent), update.STATE_DIR, str(self.root),
       netify_control.LOCK_PATH, str(manager)))

        def wait_for(name):
            deadline = time.monotonic() + 5
            while not (self.root / name).exists():
                if time.monotonic() >= deadline:
                    self.fail('Timed out waiting for ' + name)
                time.sleep(.01)

        process = subprocess.Popen([sys.executable, str(script)], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        try:
            wait_for('window')
            process.kill()
            process.wait(timeout=5)
            self.assertTrue(update._lock_busy())
            with open(netify_control.LOCK_PATH, 'a') as control:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(control, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertTrue(update.installation_active())
            (self.root / 'publish').touch()
            wait_for('installer.pid')
            self.assertFalse(update._lock_busy())
            with open(netify_control.LOCK_PATH, 'a') as control:
                fcntl.flock(control, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertTrue(update.installation_active())
            self.assertEqual(update.start_check('0.2.8')['error'], 'operation_busy')
            (self.root / 'finish').touch()
            wait_for('completed')
            pid = int((self.root / 'installer.pid').read_text())
            deadline = time.monotonic() + 5
            while update._identity(pid) is not None and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertEqual(update.read_status('0.2.8')['state'], 'interrupted')
            self.assertFalse(update.installation_active())
        finally:
            (self.root / 'publish').touch()
            (self.root / 'finish').touch()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

    def test_query_version_is_installed_only_and_requires_matching_package(self):
        cases = [('apk', b'luci-app-netify-stats 0.2.8-r1\n', '0.2.8-r1'),
                 ('ipk', b'Package: luci-app-netify-stats\nVersion: 0.2.8-1\nStatus: install user installed\n', '0.2.8-1'),
                 ('apk', b'', None), ('apk', b'other 0.2.8-r1\n', None),
                 ('ipk', b'Package: luci-app-netify-stats\nVersion: 0.2.8-1\nStatus: deinstall ok not-installed\n', None)]
        for fmt, output, expected in cases:
            def run(argv, **kwargs):
                kwargs['stdout'].write(output)
                self.assertEqual(argv, ['/fake/pkg', 'status', update.PACKAGE] if fmt == 'ipk'
                                 else ['/fake/pkg', 'list', '--manifest', update.PACKAGE])
                return Mock(returncode=0)
            with patch('subprocess.run', side_effect=run):
                if expected:
                    self.assertEqual(update._query_version('/fake/pkg', fmt), expected)
                else:
                    self.assertError('installed_version_unknown', update._query_version, '/fake/pkg', fmt)

    def test_https_redirect_host_allowlist(self):
        for url in ('http://github.com/file', 'https://attacker.example/file',
                    'https://github.com@attacker.example/file', 'https://github.com:8443/file'):
            self.assertError('network_error', update._safe_url, url)
        for url in ('https://github.com/a', 'https://release-assets.githubusercontent.com/a?signature=abc'):
            update._safe_url(url)

    def test_download_bounds_bytes_size_and_verifies_tls(self):
        import urllib.request
        import ssl
        class Response(io.BytesIO):
            def __init__(self, content, headers):
                super().__init__(content)
                self.headers = headers
            def geturl(self):
                return update.MANIFEST_URL
        cases = [(PAYLOAD, {}, len(PAYLOAD), len(PAYLOAD), None),
                 (PAYLOAD, {}, 2, None, 'download_too_large'),
                 (PAYLOAD, {'Content-Length': str(len(PAYLOAD))}, 99, 99, 'size_mismatch'),
                 (PAYLOAD, {}, 99, 99, 'size_mismatch'),
                 (PAYLOAD, {'Content-Encoding': 'gzip'}, 99, None, 'network_error')]
        for i, (content, headers, limit, expected, error) in enumerate(cases):
            opener = Mock()
            opener.open.return_value = Response(content, headers)
            with patch.object(urllib.request, 'build_opener', return_value=opener) as build:
                args = (update.MANIFEST_URL, str(self.root / ('part%d'%i)), limit, 5, expected)
                if error:
                    self.assertError(error, update._download, *args)
                else:
                    self.assertEqual(update._download(*args), hashlib.sha256(content).hexdigest())
                context = build.call_args.args[1]._context
                self.assertTrue(context.check_hostname)
                self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
                self.assertError('network_error', build.call_args.args[0].redirect_request,
                                 None, None, 302, '', {}, 'http://github.com/no')

    def test_download_total_deadline_covers_a_stalled_server(self):
        import urllib.request
        opener = Mock()
        opener.open.side_effect = lambda *args, **kwargs: time.sleep(2)
        with patch.object(urllib.request, 'build_opener', return_value=opener):
            self.assertError('network_error', update._download, update.MANIFEST_URL,
                             str(self.root / 'stalled'), 64, .02)

    def test_platform_parses_data_without_execution_and_rejects_snapshot(self):
        self.platform.stop()
        path = self.root / 'release'
        with patch.object(update, 'RELEASE_FILES', (str(path),)), \
                patch.object(os.path, 'isfile', return_value=True), patch.object(os, 'access', return_value=True):
            path.write_text("DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='24.10.8'\n")
            self.assertEqual(update.platform_target(), ('24.10', '/bin/opkg'))
            path.write_text('ID=openwrt\nVERSION_ID="25.12.5"\n')
            self.assertEqual(update.platform_target(), ('25.12', '/bin/apk'))
            for release in ('SNAPSHOT', '24.10-SNAPSHOT', '22.03.1', '$(touch pwned)'):
                path.write_text("DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='%s'\n" % release)
                self.assertError('unsupported_platform', update.platform_target)
        self.assertFalse((self.root / 'pwned').exists())

    def test_worker_finishes_and_releases_lock_and_downloads(self):
        self.state('checking', action='check', job_id='abc')
        fd = os.open(update._path('job.lock'), os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        with patch.object(update, '_download', side_effect=self.download), \
                patch.object(update, '_query_version', return_value='0.2.8-1'):
            self.assertEqual(update.worker(fd, 'abc', '0.2.8'), 0)
        self.assertEqual(update.read_status('0.2.8')['state'], 'available')
        self.assertFalse(update._lock_busy())
        self.assertFalse(list(Path(update.STATE_DIR).glob('download-*')))


if __name__ == '__main__':
    unittest.main()
