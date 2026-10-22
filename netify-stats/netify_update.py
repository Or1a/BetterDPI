"""Manual, bounded Release upgrades. Importing this module never uses the network."""
import fcntl
import json
import os
import re
import stat
import time

STATE_DIR = '/var/run/netify-stats-update'
PACKAGE = 'luci-app-netify-stats'
REPOSITORY = 'https://github.com/Or1a/BetterDPI'
MANIFEST_URL = REPOSITORY + '/releases/latest/download/update.json'
MAX_MANIFEST = 64 * 1024
MAX_PACKAGE = 16 * 1024 * 1024
MAX_STATE = 16 * 1024
CHECK_MAX_AGE = 24 * 3600
ACTIVE = ('checking', 'downloading', 'installing')
STATES = ('idle', 'available', 'up_to_date', 'unsupported', 'succeeded',
          'failed', 'interrupted') + ACTIVE
RELEASE_FILES = ('/etc/openwrt_release', '/etc/os-release')
MANAGERS = {'24.10': ('opkg', 'ipk'), '25.12': ('apk', 'apk')}


class UpdateError(Exception):
    def __init__(self, code, detail=''):
        super().__init__(detail or code)
        self.code, self.detail = code, detail


def version_tuple(value):
    if not isinstance(value, str) or not re.fullmatch(r'(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})', value):
        raise UpdateError('invalid_manifest', 'A stable three-part version is required.')
    return tuple(map(int, value.split('.')))


def installed_base(value):
    if not isinstance(value, str):
        raise UpdateError('installed_version_unknown')
    base = re.sub(r'-(?:r)?[0-9]+$', '', value)
    try:
        version_tuple(base)
    except UpdateError:
        raise UpdateError('installed_version_unknown') from None
    return base


def validate_manifest(document, series):
    if not isinstance(document, dict) or type(document.get('schema')) is not int or document['schema'] != 1:
        raise UpdateError('invalid_manifest', 'Unsupported release manifest schema.')
    version = document.get('version')
    version_tuple(version)
    if document.get('tag') != 'V' + version or series not in MANAGERS:
        raise UpdateError('invalid_manifest', 'Release tag or target does not match.')
    packages = document.get('packages')
    package = packages.get(series) if isinstance(packages, dict) else None
    if not isinstance(package, dict):
        raise UpdateError('invalid_manifest', 'This release has no package for this OpenWrt series.')
    fmt = MANAGERS[series][1]
    filename = package.get('filename')
    pattern = r'BetterDPI-' + re.escape(version) + '-openwrt-' + re.escape(series) + r'\.[0-9]{1,3}-all\.' + fmt
    if not isinstance(filename, str) or not re.fullmatch(pattern, filename) or package.get('format') != fmt:
        raise UpdateError('invalid_manifest', 'Package filename or format does not match the target.')
    size, digest = package.get('size'), package.get('sha256')
    if type(size) is not int or not 0 < size <= MAX_PACKAGE:
        raise UpdateError('invalid_manifest', 'Invalid package size.')
    if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
        raise UpdateError('invalid_manifest', 'Invalid package checksum.')
    return {'version': version, 'tag': document['tag'], 'series': series,
            'filename': filename, 'format': fmt, 'size': size, 'sha256': digest}


def validate_candidate(candidate, series):
    if not isinstance(candidate, dict) or candidate.get('series') != series:
        raise UpdateError('candidate_changed')
    return validate_manifest({'schema': 1, 'version': candidate.get('version'),
                              'tag': candidate.get('tag'), 'packages': {series: candidate}}, series)


def platform_target():
    """Read release metadata as data, never execute it as shell code."""
    for filename in RELEASE_FILES:
        try:
            with open(filename, encoding='utf-8') as handle:
                data = handle.read(16385)
            if len(data) > 16384:
                continue
        except (OSError, UnicodeError):
            continue
        values = {}
        for line in data.splitlines():
            match = re.fullmatch(r'([A-Z_]+)=(?:"([^"\n]*)"|\x27([^\x27\n]*)\x27|([^\s]*))', line)
            if match:
                values[match[1]] = next(v for v in match.groups()[1:] if v is not None)
        release = values.get('DISTRIB_RELEASE') or values.get('VERSION_ID', '')
        identity = values.get('DISTRIB_ID') or values.get('ID', '')
        if identity.lower() != 'openwrt' or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', release):
            continue
        series = '.'.join(release.split('.')[:2])
        if series not in MANAGERS:
            raise UpdateError('unsupported_platform', 'Only stable OpenWrt 24.10 and 25.12 are supported.')
        name = MANAGERS[series][0]
        for directory in ('/bin', '/sbin', '/usr/bin', '/usr/sbin'):
            path = directory + '/' + name
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return series, path
        raise UpdateError('package_manager_missing', name + ' is not installed.')
    raise UpdateError('unsupported_platform', 'A supported stable OpenWrt release is required.')


def _path(name):
    return os.path.join(STATE_DIR, name)


def _private_directory():
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    info = os.lstat(STATE_DIR)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise UpdateError('status_invalid', 'Unsafe update state directory.')
    os.chmod(STATE_DIR, 0o700)


def _read_state():
    try:
        fd = os.open(_path('status.json'), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'r', encoding='utf-8') as handle:
            data = handle.read(MAX_STATE + 1)
        if len(data) > MAX_STATE:
            raise ValueError('oversized state')
        state = json.loads(data)
        if not isinstance(state, dict) or state.get('state') not in STATES:
            raise ValueError('invalid state')
        return state
    except FileNotFoundError:
        return {'state': 'idle'}
    except (OSError, ValueError, UnicodeError, RecursionError):
        return {'state': 'failed', 'error': 'status_invalid', 'detail': 'Update state could not be read.'}


def _write_state(state):
    import tempfile
    data = json.dumps(state, separators=(',', ':')).encode('utf-8')
    if len(data) > MAX_STATE:
        raise UpdateError('status_invalid', 'Update state is too large.')
    fd, path = tempfile.mkstemp(prefix='.status-', dir=STATE_DIR)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
        os.replace(path, _path('status.json'))
    finally:
        if os.path.exists(path):
            os.unlink(path)


def _identity(pid):
    if type(pid) is not int or pid <= 0:
        return None
    try:
        with open('/proc/%d/stat' % pid, encoding='ascii') as handle:
            fields = handle.read(4096).rsplit(')', 1)[1].split()
        return fields[19] if fields[0] != 'Z' else None
    except (OSError, IndexError, UnicodeError):
        return None


def _live(state, kind):
    saved = state.get(kind + '_start')
    return saved is not None and saved == _identity(state.get(kind + '_pid'))


def _lock_busy():
    try:
        fd = os.open(_path('job.lock'), os.O_RDWR | os.O_NOFOLLOW)
    except OSError:
        return False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return False
        except BlockingIOError:
            return True
    finally:
        os.close(fd)


def _clean(value):
    text = str(value or '')
    text = re.sub(r'https?://\S+', '[URL]', text)
    return ''.join(c for c in text if c in '\n\t' or 32 <= ord(c) < 127)[-2000:]


def _public(state, current_version, busy=None):
    result = {key: state[key] for key in ('state', 'series', 'candidate', 'checked_at', 'started_at',
                                         'finished_at', 'installed_version', 'error', 'detail') if key in state}
    result.update(current_version=current_version, busy=state.get('state') in ACTIVE if busy is None else busy)
    result.setdefault('error', '')
    result.setdefault('detail', '')
    return result


def read_status(current_version):
    """Cheap read-only poll: one small JSON file; inspect only known job PIDs."""
    state = _read_state()
    if state['state'] in ACTIVE and not (_lock_busy() or _live(state, 'worker') or _live(state, 'installer')):
        state.update(state='interrupted', error='interrupted',
                     detail='The update worker stopped. Check the installed version before trying again.')
    candidate = state.get('candidate')
    if state['state'] == 'available' and isinstance(candidate, dict):
        try:
            if version_tuple(candidate.get('version')) <= version_tuple(current_version):
                state['state'] = 'up_to_date'
        except UpdateError:
            state.update(state='failed', error='status_invalid')
    return _public(state, current_version)


def installation_active():
    """Guard analysis toggles even if an orphaned installer outlives its worker."""
    state = _read_state()
    return state['state'] == 'installing' and (
        _lock_busy() or _live(state, 'worker') or _live(state, 'installer'))


def _failure(current_version, code, detail='', state=None):
    state = dict(state or _read_state())
    state.update(state='unsupported' if code in ('unsupported_platform', 'package_manager_missing') else 'failed',
                 error=code, detail=_clean(detail), finished_at=int(time.time()))
    return _public(state, current_version, False)


def _clean_orphan_downloads():
    # Called only by a manual action while holding the job lock and after
    # checking installer liveness. A killed worker cannot clean its own tmpfs.
    import shutil
    with os.scandir(STATE_DIR) as entries:
        for entry in entries:
            if entry.name.startswith('download-') and entry.is_dir(follow_symlinks=False):
                shutil.rmtree(entry.path)


def start_check(current_version):
    return _start('check', current_version)


def start_install(current_version, version):
    return _start('install', current_version, version)


def _start(action, current_version, requested=None):
    import subprocess
    import sys
    fd = None
    writable = False
    try:
        version_tuple(current_version)
        _private_directory()
        fd = os.open(_path('job.lock'), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return dict(read_status(current_version), error='operation_busy', busy=True)
        old = _read_state()
        if old['state'] in ACTIVE and (_live(old, 'worker') or _live(old, 'installer')):
            return dict(_public(old, current_version), error='operation_busy', busy=True)
        writable = True
        _clean_orphan_downloads()
        series, manager = platform_target()
        candidate = None
        if action == 'install':
            if old.get('state') != 'available':
                raise UpdateError('update_not_checked', 'Check for an update before installing.')
            candidate = validate_candidate(old.get('candidate'), series)
            if not isinstance(requested, str) or candidate['version'] != requested:
                raise UpdateError('candidate_changed', 'The offered version changed. Check again.')
            if version_tuple(requested) <= version_tuple(current_version):
                raise UpdateError('candidate_changed', 'An upgrade must be newer than the running application.')
            age = time.time() - old.get('checked_at', 0)
            if age < -60 or age > CHECK_MAX_AGE:
                raise UpdateError('check_expired', 'The previous update check expired. Check again.')
        state = {'state': 'checking' if action == 'check' else 'downloading',
                 'action': action, 'job_id': os.urandom(16).hex(), 'series': series,
                 'manager': manager, 'started_at': int(time.time()), 'error': '', 'detail': ''}
        if candidate:
            state.update(candidate=candidate, checked_at=old['checked_at'])
        _write_state(state)
        try:
            subprocess.Popen([sys.executable, os.path.abspath(__file__), 'worker', str(fd), state['job_id'], current_version],
                             pass_fds=(fd,), start_new_session=True, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
        except OSError as exc:
            state.update(_failure(current_version, 'worker_start_failed', str(exc), state))
            _write_state(state)
        return _public(state, current_version)
    except (UpdateError, OSError, TypeError) as exc:
        code = exc.code if isinstance(exc, UpdateError) else 'status_invalid'
        failed = _failure(current_version, code, str(exc))
        if writable:
            try:
                _write_state(failed)
            except OSError:
                pass
        return failed
    finally:
        # Do not LOCK_UN here: the child inherits this same open file description.
        if fd is not None:
            os.close(fd)


def _safe_url(url):
    from urllib.parse import urlsplit
    try:
        parsed = urlsplit(url)
        valid = (parsed.scheme == 'https' and not parsed.username and not parsed.password
                 and parsed.port in (None, 443)
                 and parsed.hostname in ('github.com', 'release-assets.githubusercontent.com',
                                         'objects.githubusercontent.com'))
    except ValueError:
        valid = False
    if not valid:
        raise UpdateError('network_error', 'An unsafe release redirect was refused.')


def _download(url, destination, maximum, seconds, expected_size=None):
    """TLS-verified HTTPS, bounded bytes and total time, streaming SHA256."""
    import hashlib
    import signal
    import ssl
    import urllib.error
    import urllib.request

    class Redirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            _safe_url(newurl)
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    def expired(signum, frame):
        raise UpdateError('network_error', 'Release download timed out.')

    _safe_url(url)
    opener = urllib.request.build_opener(Redirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        request = urllib.request.Request(url, headers={'User-Agent': 'BetterDPI-Updater', 'Accept-Encoding': 'identity'})
        with opener.open(request, timeout=min(seconds, 10)) as response:
            _safe_url(response.geturl())
            encoding = response.headers.get('Content-Encoding', 'identity').lower()
            if encoding not in ('', 'identity'):
                raise UpdateError('network_error', 'Unexpected release content encoding.')
            length = response.headers.get('Content-Length')
            if length is not None:
                if not length.isdigit() or int(length) > maximum:
                    raise UpdateError('download_too_large')
                if expected_size is not None and int(length) != expected_size:
                    raise UpdateError('size_mismatch')
            digest, total = hashlib.sha256(), 0
            with open(destination, 'xb') as output:
                os.chmod(destination, 0o600)
                while True:
                    chunk = response.read(min(65536, maximum + 1 - total))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > maximum:
                        raise UpdateError('download_too_large')
                    output.write(chunk)
                    digest.update(chunk)
            if expected_size is not None and total != expected_size:
                raise UpdateError('size_mismatch')
            return digest.hexdigest()
    except urllib.error.HTTPError as exc:
        raise UpdateError('manifest_unavailable' if url == MANIFEST_URL and exc.code == 404 else 'network_error',
                          'Release server returned HTTP %d.' % exc.code) from None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise UpdateError('network_error', _clean(str(exc))) from None
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _query_version(manager, fmt):
    import subprocess
    import tempfile
    # File output avoids unbounded communicate() memory. These are read-only
    # package-database queries; unlike an installation, they may be timed out.
    command = [manager, 'status', PACKAGE] if fmt == 'ipk' else [manager, 'list', '--manifest', PACKAGE]
    with tempfile.TemporaryFile() as output:
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL,
                                    timeout=15, check=False)
            if result.returncode or output.tell() > 65536:
                raise UpdateError('installed_version_unknown')
            output.seek(0)
            text = output.read(65537).decode('utf-8', 'replace')
        except (OSError, subprocess.TimeoutExpired):
            raise UpdateError('installed_version_unknown') from None
    if fmt == 'apk':
        lines = [line.split() for line in text.splitlines() if line.strip()]
        if len(lines) != 1 or len(lines[0]) != 2 or lines[0][0] != PACKAGE:
            raise UpdateError('installed_version_unknown')
        version = lines[0][1]
    else:
        fields = dict(line.split(': ', 1) for line in text.splitlines() if ': ' in line)
        if fields.get('Package') != PACKAGE or fields.get('Status', '').split()[-1:] != ['installed']:
            raise UpdateError('installed_version_unknown')
        version = fields.get('Version')
    installed_base(version)
    return version


def _run_installer(manager, candidate, package, state, job_fd):
    command = ([manager, 'install', package] if candidate['format'] == 'ipk'
               else [manager, 'add', '--no-network', '--allow-untrusted', package])
    # The short launcher inherits the job lock before its PID is published.
    # After publishing, PID + start ticks guard orphaned installations. Release
    # the inherited FD before exec so package hooks cannot leak it to daemons.
    # DEVNULL also avoids SIGPIPE killing an installer if its worker disappears.
    pid = os.fork()
    if pid == 0:
        try:
            null = os.open(os.devnull, os.O_RDWR)
            for target in (0, 1, 2):
                os.dup2(null, target)
            if null > 2:
                os.close(null)
            state.update(installer_pid=os.getpid(), installer_start=_identity(os.getpid()))
            if state['installer_start'] is None:
                os._exit(126)
            _write_state(state)  # A failed handshake must never execute a package.
            os.close(job_fd)
            os.execv(manager, command)
        except BaseException:
            os._exit(126)
    state.update(installer_pid=pid, installer_start=_identity(pid))
    # Never time out or kill an installation while it may modify its database.
    while True:
        try:
            _, status = os.waitpid(pid, 0)
            break
        except InterruptedError:
            continue
    code = os.waitstatus_to_exitcode(status)
    if code:
        detail = 'Package manager exited with status %d.' % code
        if candidate['format'] == 'apk':
            detail += ' If dependencies are missing, install them with the system package manager before checking again.'
        raise UpdateError('install_failed', detail)


def _check(state, current_version, directory):
    path = os.path.join(directory, 'manifest.json')
    _download(MANIFEST_URL, path, MAX_MANIFEST, 20)
    try:
        with open(path, encoding='utf-8') as handle:
            document = json.load(handle)
        candidate = validate_manifest(document, state['series'])
    except (ValueError, UnicodeError, RecursionError):
        raise UpdateError('invalid_manifest', 'Release manifest is not valid JSON.') from None
    installed = _query_version(state['manager'], candidate['format'])
    baseline = max(version_tuple(current_version), version_tuple(installed_base(installed)))
    state.update(candidate=candidate, installed_version=installed, checked_at=int(time.time()),
                 state='available' if version_tuple(candidate['version']) > baseline else 'up_to_date')


def _install(state, current_version, directory, job_fd=None):
    from netify_control import LOCK_PATH
    series, manager = platform_target()
    candidate = validate_candidate(state.get('candidate'), series)
    if version_tuple(candidate['version']) <= version_tuple(current_version):
        raise UpdateError('candidate_changed')
    package = os.path.join(directory, candidate['filename'])
    url = REPOSITORY + '/releases/download/' + candidate['tag'] + '/' + candidate['filename']
    digest = _download(url, package, candidate['size'], 120, candidate['size'])
    if digest != candidate['sha256']:
        raise UpdateError('checksum_mismatch', 'The downloaded package failed SHA256 verification.')
    fd = os.open(LOCK_PATH, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise UpdateError('operation_busy', 'An analysis toggle is in progress. Check again after it finishes.') from None
        before = _query_version(manager, candidate['format'])
        state['installed_version'] = before
        if version_tuple(candidate['version']) <= version_tuple(installed_base(before)):
            state['state'] = 'up_to_date'
            return
        state['state'] = 'installing'
        _write_state(state)
        _run_installer(manager, candidate, package, state, job_fd)
        after = _query_version(manager, candidate['format'])
        state['installed_version'] = after
        if installed_base(after) != candidate['version']:
            raise UpdateError('install_verification_failed', 'The installed package version does not match the selected release.')
        state['state'] = 'succeeded'
    finally:
        os.close(fd)


def worker(fd, job_id, current_version):
    import tempfile
    state = _read_state()
    if state.get('job_id') != job_id or state.get('state') not in ACTIVE:
        return 1
    try:
        info = os.fstat(fd)
        lock = os.stat(_path('job.lock'), follow_symlinks=False)
        if (info.st_dev, info.st_ino) != (lock.st_dev, lock.st_ino):
            return 1
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state.update(worker_pid=os.getpid(), worker_start=_identity(os.getpid()))
        _write_state(state)
        with tempfile.TemporaryDirectory(prefix='download-', dir=STATE_DIR) as directory:
            if state['action'] == 'check':
                _check(state, current_version, directory)
            elif state['action'] == 'install':
                _install(state, current_version, directory, fd)
            else:
                raise UpdateError('status_invalid')
    except (UpdateError, OSError) as exc:
        state.update(state='failed', error=exc.code if isinstance(exc, UpdateError) else 'status_invalid',
                     detail=_clean(str(exc)))
    except Exception:
        state.update(state='interrupted', error='interrupted', detail='The update did not complete. Check again before retrying.')
    finally:
        state['finished_at'] = int(time.time())
        _write_state(state)
        os.close(fd)
    return 0


if __name__ == '__main__':
    import sys
    if len(sys.argv) == 5 and sys.argv[1] == 'worker':
        raise SystemExit(worker(int(sys.argv[2]), sys.argv[3], sys.argv[4]))
    raise SystemExit(1)
