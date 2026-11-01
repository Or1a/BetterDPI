#!/usr/bin/python3
"""rpcd endpoint for independent Anti-PCDN settings and runtime snapshots."""
import copy
import json
import os
import re
import sys
import tempfile
import time
import uuid

sys.path.insert(0, '/usr/lib/netify-stats')
source_features = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'features')
if os.path.isdir(source_features):
    sys.path.insert(0, source_features)
from anti_pcdn.config import CONFIG_PATH, DEFAULTS, MAX_CONFIG_BYTES, load, save

RUNTIME_DIR = '/var/run/betterdpi-anti-pcdn'
STATUS_PATH = RUNTIME_DIR + '/status.json'
RELEASE_PATH = RUNTIME_DIR + '/release.json'
COLLECTOR_STATUS_PATH = '/var/run/netify-stats/status.json'
MAX_STATUS_BYTES = 256 * 1024
STALE_SECONDS = 15
METHODS = {'status': {}, 'configure': {'settings': {}}, 'release': {'id': ''}}


def read_object(path, limit=MAX_STATUS_BYTES):
    with open(path, 'rb') as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('Runtime status exceeds the size limit.')
    def invalid_constant(value):
        raise ValueError('Non-finite JSON number: ' + value)
    result = json.loads(raw, parse_constant=invalid_constant)
    if not isinstance(result, dict):
        raise ValueError('Expected a JSON object.')
    return result


def fresh(snapshot, now):
    timestamp = snapshot.get('timestamp')
    # Compare before subtracting: an arbitrarily large JSON integer must not
    # overflow conversion to float or turn a malformed snapshot into an RPC crash.
    return type(timestamp) in (int, float) and 0 <= timestamp <= now and now - timestamp <= STALE_SECONDS


def status(now=None):
    now = time.time() if now is None else now
    result = {'settings': copy.deepcopy(DEFAULTS), 'config_error': '', 'runtime': {},
              'runtime_error': '', 'stale': True, 'collector_recent': False,
              'collector_connected': False, 'release_pending': None}
    try:
        result['settings'] = load(CONFIG_PATH)
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        result['config_error'] = str(exc)
    try:
        result['runtime'] = read_object(STATUS_PATH)
        result['stale'] = not fresh(result['runtime'], now)
    except FileNotFoundError:
        result['runtime_error'] = 'No Anti-PCDN runtime status is available.'
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        result['runtime_error'] = str(exc)
    try:
        collector = read_object(COLLECTOR_STATUS_PATH)
        result['collector_recent'] = fresh(collector, now)
        result['collector_connected'] = result['collector_recent'] and collector.get('connected') is True
    except (OSError, ValueError, TypeError, RecursionError):
        pass
    try:
        pending = read_object(RELEASE_PATH, 1024)
        result['release_pending'] = {'id': pending.get('id'), 'request_id': pending.get('request_id')}
    except FileNotFoundError:
        pass
    except (OSError, ValueError, TypeError, RecursionError):
        result['release_pending'] = {'error': 'Invalid pending release request.'}
    return result


def configure(settings):
    return {'ok': True, 'settings': save(settings, CONFIG_PATH), 'pending': True}


def release(lease_id, now=None):
    if not isinstance(lease_id, str) or re.fullmatch(r'(?:[0-9a-f]{24}|[0-9a-f]{32})', lease_id) is None:
        raise ValueError('Invalid lease ID.')
    now = time.time() if now is None else now
    snapshot = read_object(STATUS_PATH)
    if not fresh(snapshot, now):
        raise ValueError('Runtime status is stale. Wait for the collector before requesting release.')
    leases = snapshot.get('leases', [])
    if not isinstance(leases, list) or not any(isinstance(item, dict) and item.get('id') == lease_id for item in leases):
        raise ValueError('This lease is no longer listed. Refresh the status.')
    request = {'id': lease_id, 'request_id': uuid.uuid4().hex, 'timestamp': now}
    # Hard-linking a fully written temporary file publishes atomically and will
    # never replace a request another RPC already queued.
    parent = os.path.dirname(RELEASE_PATH)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.release-', dir=parent)
    try:
        with os.fdopen(descriptor, 'w') as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(request, handle, separators=(',', ':'))
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, RELEASE_PATH)
        except FileExistsError as exc:
            raise ValueError('A release request is already pending; wait for its result.') from exc
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return dict(request, ok=True, pending=True)


def main():
    if len(sys.argv) == 2 and sys.argv[1] == 'list':
        print(json.dumps(METHODS, separators=(',', ':')))
        return 0
    try:
        if len(sys.argv) != 3 or sys.argv[1] != 'call' or sys.argv[2] not in METHODS:
            raise ValueError('Unknown Anti-PCDN method.')
        raw = sys.stdin.read(MAX_CONFIG_BYTES + 1)
        if len(raw.encode('utf-8')) > MAX_CONFIG_BYTES:
            raise ValueError('Request exceeds the size limit.')
        params = json.loads(raw or '{}')
        method = sys.argv[2]
        if not isinstance(params, dict) or set(params) - set(METHODS[method]):
            raise ValueError('Invalid method parameters.')
        if method == 'status':
            result = status()
        elif method == 'configure':
            result = configure(params.get('settings'))
        else:
            result = release(params.get('id'))
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        result = {'ok': False, 'error': str(exc)}
    print(json.dumps(result, separators=(',', ':'), allow_nan=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
