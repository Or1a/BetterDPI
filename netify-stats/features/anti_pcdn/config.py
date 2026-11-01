"""Independent, bounded Anti-PCDN settings; no traffic database dependency."""
import copy
import ipaddress
import json
import os
import re
import tempfile

CONFIG_PATH = '/etc/betterdpi-anti-pcdn.json'
MAX_CONFIG_BYTES = 64 * 1024
MAX_LIST_ITEMS = 128
DEFAULTS = {
    'enabled': False, 'mode': 'observe', 'interface': 'br-lan',
    'threshold': 80, 'ban_seconds': 120,
    'allow_devices': [], 'allow_domains': [], 'pcdn_domains': [],
    'weights': {'fanout': 25, 'serving_peers': 20, 'sustained': 20,
                'upload_ratio': 15, 'domain': 20},
}


class ConfigError(ValueError):
    pass


def domain(value):
    """Accept DNS names only; suffix matching always respects label boundaries."""
    if not isinstance(value, str) or len(value) > 254:
        raise ConfigError('Domain must be a DNS name of at most 253 characters.')
    value = value.strip().lower().rstrip('.')
    labels = value.split('.')
    if len(value) > 253 or len(labels) < 2 or any(
            re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) is None
            for label in labels):
        raise ConfigError('Use DNS names such as uploader.example.com; URLs and wildcards are not allowed.')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ConfigError('Domain hints must not be IP addresses.')


normalize_domain = domain


def matches(host, domains):
    if not isinstance(host, str) or len(host) > 254:
        return False
    try:
        host = domain(host)
    except ConfigError:
        return False
    return any(host == item or host.endswith('.' + item) for item in domains)


domain_matches = matches


def device_allowed(mac, settings):
    return isinstance(mac, str) and mac.lower() in settings.get('allow_devices', ())


def domain_allowed(host, settings):
    return matches(host, settings.get('allow_domains', ()))


def _integer(value, name, lower, upper):
    if type(value) is not int or not lower <= value <= upper:
        raise ConfigError('%s must be an integer from %d to %d.' % (name, lower, upper))
    return value


def validate(settings):
    if not isinstance(settings, dict):
        raise ConfigError('Settings must be a JSON object.')
    if set(settings) - set(DEFAULTS):
        raise ConfigError('Unknown Anti-PCDN setting.')
    result = copy.deepcopy(DEFAULTS)
    result.update(settings)
    if type(result['enabled']) is not bool:
        raise ConfigError('enabled must be boolean.')
    if result['mode'] not in ('observe', 'auto'):
        raise ConfigError('mode must be observe or auto.')
    if not isinstance(result['interface'], str) or re.fullmatch(
            r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}', result['interface']) is None:
        raise ConfigError('Use a valid LAN interface name of at most 15 characters.')
    _integer(result['threshold'], 'threshold', 1, 100)
    _integer(result['ban_seconds'], 'ban_seconds', 30, 600)
    for key in ('allow_devices', 'allow_domains', 'pcdn_domains'):
        values = result[key]
        if not isinstance(values, list) or len(values) > MAX_LIST_ITEMS:
            raise ConfigError('%s must be a list of at most %d entries.' % (key, MAX_LIST_ITEMS))
        normalized = []
        for value in values:
            if key == 'allow_devices':
                if not isinstance(value, str) or re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', value) is None:
                    raise ConfigError('Allowed devices must use colon-separated MAC addresses.')
                value = value.lower()
                if value == '00:00:00:00:00:00' or int(value[:2], 16) & 1:
                    raise ConfigError('Allowed devices must have a unicast MAC address.')
            else:
                value = domain(value)
            if value not in normalized:
                normalized.append(value)
        result[key] = normalized
    weights = result['weights']
    if not isinstance(weights, dict) or set(weights) != set(DEFAULTS['weights']):
        raise ConfigError('Provide all five score weights.')
    weights = {key: _integer(value, 'weight ' + key, 0, 40) for key, value in weights.items()}
    if sum(weights.values()) != 100:
        raise ConfigError('Score weights must total 100.')
    result['weights'] = weights
    return result


def load(path=CONFIG_PATH):
    try:
        with open(path, 'rb') as handle:
            raw = handle.read(MAX_CONFIG_BYTES + 1)
    except FileNotFoundError:
        return copy.deepcopy(DEFAULTS)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError('Anti-PCDN settings exceed the size limit.')
    try:
        return validate(json.loads(raw))
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise ConfigError('Invalid Anti-PCDN settings: ' + str(exc)) from exc


def save(settings, path=CONFIG_PATH):
    result = validate(settings)
    payload = (json.dumps(result, separators=(',', ':'), sort_keys=True) + '\n').encode('utf-8')
    if len(payload) > MAX_CONFIG_BYTES:
        raise ConfigError('Anti-PCDN settings exceed the size limit.')
    parent = os.path.dirname(os.fspath(path)) or '.'
    descriptor, temporary = tempfile.mkstemp(prefix='.anti-pcdn-', dir=parent)
    try:
        with os.fdopen(descriptor, 'wb') as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return result
