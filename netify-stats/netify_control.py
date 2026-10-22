"""Root-only RPC service control; fixed commands, no caller-supplied shell."""
import fcntl
from contextlib import closing
import json
import os
import re
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path
from netify_storage import read_enabled, update_settings, settings_snapshot
from netify_update import installation_active

DB_PATH = '/tmp/netify-stats/stats.db'
STATE_PATH = '/var/run/netify-stats-control.json'
LOCK_PATH = '/var/run/netify-stats-control.lock'
PROC_PATH = '/proc'
_UNSET = object()


def normalize_legacy_error(error):
    """Translate only diagnostics emitted by older versions, without rewriting state."""
    if not isinstance(error, str):
        return error
    prefix = '开关尚未完整应用，请重试：'
    if error.startswith(prefix):
        return 'Analysis setting could not be fully applied: ' + normalize_legacy_error(error[len(prefix):])
    return {
        '开关操作超时，请重试': 'Analysis toggle timed out. Please try again.',
        '服务未完整启动，请重试': 'Services did not fully start. Please try again.',
        '服务未完整停止，请重试': 'Services did not fully stop. Please try again.',
        '已有开关操作正在执行，请稍后重试': 'Another analysis toggle is in progress. Please try again.',
        '设置正在保存，请稍后重试': 'Settings are being saved. Please try again.',
    }.get(error, error)


def run(*args, timeout=10):
    subprocess.run(args, check=True, capture_output=True, timeout=timeout)


def remaining(deadline):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError('Analysis toggle timed out. Please try again.')
    return seconds


def runtime_state():
    collector, netify = False, False
    for path in Path(PROC_PATH).glob('[0-9]*/cmdline'):
        try:
            args = path.read_bytes().split(b'\0')
            program = args[0].rsplit(b'/', 1)[-1]
            # A diagnostic command may mention the script as an argument.
            # Only its direct execution or our Python launcher is a collector.
            collector |= args[0] == b'/usr/sbin/netify-stats-collector' or (
                re.fullmatch(rb'python3(?:\.\d+)?', program) is not None
                and len(args) > 1 and args[1] == b'/usr/sbin/netify-stats-collector')
            netify |= program == b'netifyd'
            if collector and netify:
                break
        except OSError:
            pass
    return collector, netify


def collector_running():
    return runtime_state()[0]


def control_status(enabled=_UNSET):
    # Read-only status must stay available even when the desired configuration
    # is corrupt. Callers with a validated snapshot can avoid a second read.
    config_error = ''
    if enabled is _UNSET:
        try:
            enabled = read_enabled()
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            enabled = None
            config_error = str(exc)
    if enabled is not None and not isinstance(enabled, bool):
        raise ValueError('enabled must be boolean or unknown')
    collector, netify = runtime_state()
    try:
        error = normalize_legacy_error(json.loads(Path(STATE_PATH).read_text()).get('apply_error', ''))
    except (OSError, ValueError, AttributeError):
        error = ''
    return {'enabled': enabled, 'collector_running': collector, 'netify_running': netify,
            'actual_state': 'unknown' if enabled is None else 'running' if collector and netify else 'stopped' if not collector and not netify else 'partial',
            'applied': enabled is not None and collector == enabled and netify == enabled,
            'apply_error': error, 'config_error': config_error}


def record_error(error):
    descriptor, temporary = tempfile.mkstemp(prefix='.netify-control-', dir=str(Path(STATE_PATH).parent))
    try:
        with os.fdopen(descriptor, 'w') as handle:
            json.dump({'apply_error': error}, handle)
        os.replace(temporary, STATE_PATH)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def wait_for_state(enabled, deadline, collector_only=False):
    wait_deadline = min(deadline, time.monotonic() + 8)
    while True:
        current = runtime_state()
        if current[0] == enabled and (collector_only or current[1] == enabled):
            return
        remaining(deadline)
        if time.monotonic() >= wait_deadline:
            raise RuntimeError('Services did not fully start. Please try again.' if enabled
                               else 'Services did not fully stop. Please try again.')
        time.sleep(min(0.1, remaining(wait_deadline)))


def set_enabled(enabled):
    if not isinstance(enabled, bool):
        raise ValueError('enabled must be boolean')
    deadline = time.monotonic() + 15
    def command(*args):
        run(*args, timeout=min(10, remaining(deadline)))
    def validate_start(values):
        snapshot = settings_snapshot(values)
        if snapshot['config_error']:
            raise ValueError('Cannot start analysis: ' + snapshot['config_error'])
    with open(LOCK_PATH,'a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError('Another analysis toggle is in progress. Please try again.') from exc
        # A package manager can outlive its update worker. Its recorded process
        # identity keeps service toggles from racing the package lifecycle hooks.
        if installation_active():
            raise RuntimeError('An application update is being installed. Wait for it to finish before changing analysis.')
        try:
            # Validate the merged target while holding the settings lock. An
            # explicit toggle can repair a bad enabled flag, but must not start
            # services with invalid interface/storage settings. Stopping stays
            # available when those unrelated fields are invalid.
            update_settings({'enabled':enabled}, deadline=deadline,
                            validate=validate_start if enabled else None)
            if not enabled:
                command('/etc/init.d/netify-stats','stop')
                wait_for_state(False, deadline, collector_only=True)
                command('/etc/init.d/netify-stats','disable')
                command('/etc/init.d/netifyd','stop')
                command('/etc/init.d/netifyd','disable')
                wait_for_state(False, deadline)
            # Reset the measurement baseline, not history: paused WAN bytes
            # must not be backfilled on resume.
            if not enabled or not collector_running():
                if Path(DB_PATH).exists():
                    with closing(sqlite3.connect(DB_PATH,timeout=min(5, remaining(deadline)))) as db, db:
                        db.execute('DELETE FROM interface_baseline')
                        db.execute('PRAGMA busy_timeout=%d' % max(1, int(min(5, remaining(deadline))*1000)))
            command('/sbin/uci','set','netifyd.@netifyd[0].enabled='+('1' if enabled else '0'))
            command('/sbin/uci','commit','netifyd')
            if enabled:
                command('/etc/init.d/netifyd','enable')
                command('/etc/init.d/netify-stats','enable')
                command('/etc/init.d/netifyd','start')
                command('/etc/init.d/netify-stats','start')
                wait_for_state(True, deadline)
            remaining(deadline)
            record_error('')
        except Exception as exc:
            # After validation, desired state stays visible; retry reconciles
            # partial service changes rather than pretending rollback succeeded.
            error = 'Analysis setting could not be fully applied: '+str(exc)
            try:
                record_error(error)
            except OSError:
                pass
            raise RuntimeError(error) from exc
    return control_status()
