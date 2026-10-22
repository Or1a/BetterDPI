"""Domain attribution for reporting only; never overwrites native DPI records."""
from functools import lru_cache
import json
from pathlib import Path
import re
import socket

RULE_PATH = Path('/usr/share/netify-stats/community-rules.json')
HOST_NAME = re.compile(r'[a-z0-9_-]+(?:\.[a-z0-9_-]+)+')
IPV4_LITERAL = re.compile(r'(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}')
EVIDENCE_LIMIT = 5
# These are observed protocol names, not port-based application guesses. Keep
# the allowlist explicit: an unfamiliar DPI label must not silently become a
# known application or an inferred traffic category.
PROTOCOL_NAMES = {
    'tls': 'TLS / encrypted traffic', 'quic': 'QUIC', 'dns': 'DNS',
    'http': 'HTTP / web', 'stun': 'STUN / NAT traversal',
    'bittorrent': 'BitTorrent / P2P', 'ssh': 'SSH / remote access',
    'vpn': 'VPN protocol', 'tcp': 'TCP', 'udp': 'UDP',
}
PROTOCOL_ALIASES = {
    'tls': ('tls', 'ssl', 'ssl/tls', 'tls/ssl', 'https',
            'tlsv1', 'tlsv1.0', 'tlsv1.1', 'tlsv1.2', 'tlsv1.3',
            'tls 1.0', 'tls 1.1', 'tls 1.2', 'tls 1.3'),
    'quic': ('quic', 'gquic', 'ietf quic', 'http/3', 'http3'),
    'dns': ('dns', 'mdns', 'dnscrypt', 'doh', 'dot', 'doq',
            'dns-over-https', 'dns over https', 'dns-over-tls', 'dns over tls',
            'dns-over-quic', 'dns over quic'),
    'http': ('http', 'http/1.0', 'http/1.1', 'http/2', 'http2',
             'http_connect', 'http_proxy', 'http connect', 'http proxy'),
    'stun': ('stun',),
    'bittorrent': ('bittorrent', 'bittorrent dht', 'bittorrent_dht'),
    'ssh': ('ssh',),
    'vpn': ('openvpn', 'wireguard', 'ipsec', 'ipsec ike', 'ipsec esp'),
    'tcp': ('tcp',),
    'udp': ('udp',),
}
PROTOCOL_LOOKUP = {alias: category for category, aliases in PROTOCOL_ALIASES.items()
                   for alias in aliases}
PROTOCOL_KEYS = {category: 'protocol:' + category for category in PROTOCOL_NAMES}
# These suffixes identify shared hosting/CDN infrastructure, not its tenants.
# Check only rules already tagged with that provider; a more specific service
# rule (for example a named video CDN endpoint) retains its own application.
SHARED_PROVIDERS = {
    'aws': ('AWS', ('amazonaws.com', 'cloudfront.net')),
    'cloudflare': ('Cloudflare', ('workers.dev', 'pages.dev', 'r2.dev', 'cloudflare.net')),
    'azure': ('Azure', ('azurewebsites.net', 'azureedge.net', 'azurefd.net', 'cloudapp.net', 'blob.core.windows.net')),
    'akamai': ('Akamai', ('akamaized.net', 'edgekey.net', 'edgesuite.net')),
    'qcloud': ('Tencent Cloud', ('myqcloud.com',)),
    'google': ('Google infrastructure', ('appspot.com', 'googleapis.com')),
}
# Translation identifiers are presentation metadata, not replacements for the
# original community labels or the stable application IDs stored in history.
APP_NAME_MSGIDS = {
    'douyin': 'Douyin', 'wechat': 'WeChat', 'tencent': 'Tencent',
    'bilibili': 'Bilibili', 'huawei': 'Huawei', 'xiaomi': 'Xiaomi',
    'jd': 'JD.com', 'taobao': 'Taobao',
}


class Classifier:
    def __init__(self, path=RULE_PATH):
        self.error = ''
        self.app_sources = {}
        # Only community applications and the shared Unknown group need stored
        # evidence. Domain/native explanations can be derived for visible rows,
        # without retaining another object for every observed hostname.
        self.app_evidence = {}
        self.evidence_truncated = set()
        self._last_unresolved = (None, None)
        self._last_raw_host = None
        self._fallbacks = {}
        self.rules = {'exact': {}, 'suffix': {}, 'labels': {}, 'revision': ''}
        try:
            rules = json.loads(Path(path).read_text())
            if not isinstance(rules, dict) or rules.get('schema') != 1 or not all(isinstance(rules.get(k), dict) for k in ('exact', 'suffix', 'labels')):
                raise ValueError('unsupported community rule format')
            if any(not isinstance(v, list) or not v or not all(isinstance(tag, str) and tag for tag in v)
                   for section in ('exact', 'suffix') for v in rules[section].values()):
                raise ValueError('invalid rule candidates')
            if not all(isinstance(v, str) for v in rules['labels'].values()):
                raise ValueError('invalid rule labels')
            sources = rules.get('sources', [])
            if not isinstance(sources, list) or any(not isinstance(source, dict)
                    or not isinstance(source.get('id'), str) or not source['id']
                    or not isinstance(source.get('name'), str) or not source['name']
                    for source in sources):
                raise ValueError('invalid rule sources')
            default_source = rules.get('default_rule_source', 'dlc')
            if not isinstance(default_source, str) or not default_source:
                raise ValueError('invalid default rule source')
            provenance = rules.get('rule_sources', {})
            if not isinstance(provenance, dict) or any(not isinstance(provenance.get(kind, {}), dict)
                    or not all(isinstance(value, str) and value for value in provenance.get(kind, {}).values())
                    for kind in ('exact', 'suffix')):
                raise ValueError('invalid rule provenance')
            self.rules = rules
        except (OSError, ValueError) as exc:
            self.error = str(exc)
        # Per-instance cache avoids retaining old rule sets between API calls.
        # Native labels and IP literals need no rule lookup. Keeping only
        # normalized domains avoids retaining thousands of unrelated IP keys.
        self._classify_domain = lru_cache(maxsize=32768)(self._classify_domain)

    def classify(self, native, host, protocol=''):
        if native not in ('Unknown', 'Unclassified', '', None) and isinstance(native, str) and native.strip().lower() not in ('', 'unknown', 'unclassified'):
            return native
        if host is not None and host == self._last_raw_host:
            return self._unresolved(self._last_unresolved[1], protocol)
        if host is not None and not isinstance(host, str):
            return self._unresolved('invalid_host', protocol)
        raw_host = host
        host = (host or '').strip().lower().rstrip('.')
        # Query groups adjacent protocol variants of the same host. Retain just
        # one validation result, not an additional cache of all IP addresses.
        if host == self._last_unresolved[0]:
            return self._unresolved(self._last_unresolved[1], protocol)
        # Set only on bounded strings and clear it for domain lookups below.
        self._last_raw_host = raw_host if raw_host is not None and len(raw_host) <= 253 else None
        if not host or host == 'unknown':
            return self._unresolved('missing_host', protocol, host)
        if ':' in host:
            try:
                socket.inet_pton(socket.AF_INET6, host)
                return self._unresolved('ip_literal', protocol, host)
            except (OSError, ValueError):
                return self._unresolved('invalid_host', protocol, host)
        if '.' not in host or len(host) > 253:
            return self._unresolved('invalid_host', protocol, host)
        # Some platforms' inet_pton accept leading zeroes; reject those first
        # to keep the same strict IPv4 semantics on macOS and OpenWrt.
        if IPV4_LITERAL.fullmatch(host):
            try:
                socket.inet_pton(socket.AF_INET, host)
                return self._unresolved('ip_literal', protocol, host)
            except OSError:
                pass
        if not HOST_NAME.fullmatch(host):
            return self._unresolved('invalid_host', protocol, host)
        self._last_raw_host = None
        app, source, section, matched = self._classify_domain(host)
        if source:
            self.app_sources.setdefault(app, set()).add(source)
            reason = 'infrastructure' if app.startswith('infrastructure:') else 'community'
            self._remember_evidence(app, reason, section, matched, source)
        return app

    def _unresolved(self, reason, protocol, host=None):
        if host is not None and len(host) <= 253:
            self._last_unresolved = (host, reason)
        key = (reason, protocol if isinstance(protocol, str) and len(protocol) <= 128 else '')
        previous = self._fallbacks.get(key)
        if previous is not None:
            return previous
        observed = protocol.strip() if isinstance(protocol, str) else ''
        category = PROTOCOL_LOOKUP.get(observed.casefold()) if len(observed) <= 128 else None
        app = PROTOCOL_KEYS.get(category, 'Unknown')
        self._remember_evidence(app, reason)
        if category:
            self._remember_evidence(app, 'protocol', observed_protocol=observed, category=category)
        if len(self._fallbacks) < 64:
            self._fallbacks[key] = app
        return app

    def _remember_evidence(self, app, reason, section='', matched='', source='',
                           observed_protocol='', category=''):
        samples = self.app_evidence.setdefault(app, {})
        key = (reason, section, matched, source, observed_protocol)
        if key in samples:
            return
        def evidence():
            if reason == 'protocol':
                return {'reason': reason, 'protocol': observed_protocol, 'category': category,
                        'application_identified': False}
            return self._rule_evidence(section, matched, reason) if section else {'reason': reason}
        if len(samples) < EVIDENCE_LIMIT:
            samples[key] = evidence()
        else:
            self.evidence_truncated.add(app)
            # Sampling must not depend on SQL scan order, which can change
            # after a schema migration or a different query plan.
            largest = max(samples)
            if key < largest:
                del samples[largest]
                samples[key] = evidence()

    def _classify_domain(self, host):
        section, matched = 'exact', host
        candidates = self.rules['exact'].get(host)
        if candidates is None:
            section = 'suffix'
            labels = host.split('.')
            for offset in range(len(labels)-1):
                matched = '.'.join(labels[offset:])
                candidates = self.rules['suffix'].get(matched)
                if candidates is not None:
                    break
        if candidates:
            source = self.rules.get('rule_sources', {}).get(section, {}).get(
                matched, self.rules.get('default_rule_source', 'dlc'))
            if len(candidates) == 1:
                provider = SHARED_PROVIDERS.get(candidates[0])
                if provider and any(matched == suffix or matched.endswith('.' + suffix) for suffix in provider[1]):
                    return 'infrastructure:' + candidates[0], source, section, matched
                return 'community:' + candidates[0], source, section, matched
            return 'domain:' + host, None, section, matched
        # Keep cache values small: explanations are built only for the bounded
        # community samples or visible domain rows, never every cached hostname.
        return 'domain:' + host, None, None, None

    def _rule_evidence(self, section, matched, reason):
        source = self.rules.get('rule_sources', {}).get(section, {}).get(
            matched, self.rules.get('default_rule_source', 'dlc'))
        names = {item['id']: item['name'] for item in self.rules.get('sources', [])}
        evidence = {'reason': reason, 'matched_domain': matched, 'rule_type': section,
                    'source_id': source, 'source_name': names.get(source, source)}
        if reason == 'ambiguous':
            candidates = self.rules[section][matched]
            evidence.update(candidates=tuple(candidates[:EVIDENCE_LIMIT]),
                            candidate_count=len(candidates))
        return evidence

    def describe(self, key):
        if key == 'archive:domain':
            return 'Historical domain traffic', '仅识别域名（明细已归档）'
        if key.startswith('infrastructure:'):
            return SHARED_PROVIDERS[key.split(':', 1)[1]][0], '基础设施归属，应用未识别'
        if key.startswith('community:'):
            tag = key.split(':', 1)[1]
            names = {source['id']: source['name'] for source in self.rules.get('sources', [])}
            actual = [names.get(source, source) for source in sorted(self.app_sources.get(key, ()))]
            detail = '社区域名规则' + ('（' + ' / '.join(actual) + '）' if actual else '')
            return self.rules['labels'].get(tag, tag), detail
        if key.startswith('domain:'):
            return key.split(':', 1)[1], '仅识别域名'
        if key.startswith('protocol:'):
            return PROTOCOL_NAMES.get(key.split(':', 1)[1], key), '仅识别协议，应用未识别'
        if key == 'Unknown':
            return '未识别目标', '未识别'
        return key.removeprefix('netify.').replace('-', ' ').title(), 'Netify 原生识别'

    @staticmethod
    def identification_level(key):
        if key == 'Unknown':
            return 'unknown'
        if key == 'archive:domain' or key.startswith(('domain:', 'infrastructure:')):
            return 'domain'
        if key.startswith('protocol:'):
            return 'protocol'
        return 'application'

    def describe_metadata(self, key):
        """Let each LuCI session translate labels without changing raw data.

        Keep describe() and the API's name/source fields backward-compatible.
        Source names are factual provenance and should never be translated.
        """
        if key == 'archive:domain':
            result = {'name_i18n': 'Historical domain traffic',
                      'source_type': 'archived_domain', 'source_names': []}
        elif key.startswith('community:'):
            tag = key.split(':', 1)[1]
            names = {source['id']: source['name'] for source in self.rules.get('sources', [])}
            result = {'name_i18n': APP_NAME_MSGIDS.get(tag, ''),
                      'source_type': 'community',
                      'source_names': [names.get(source, source)
                                       for source in sorted(self.app_sources.get(key, ()))]}
        elif key.startswith('infrastructure:'):
            names = {source['id']: source['name'] for source in self.rules.get('sources', [])}
            result = {'name_i18n': '', 'source_type': 'infrastructure',
                      'source_names': [names.get(source, source) for source in sorted(self.app_sources.get(key, ()))]}
        elif key.startswith('domain:'):
            result = {'name_i18n': '', 'source_type': 'domain', 'source_names': []}
        elif key.startswith('protocol:'):
            result = {'name_i18n': PROTOCOL_NAMES.get(key.split(':', 1)[1], ''),
                      'source_type': 'protocol', 'source_names': []}
        elif key == 'Unknown':
            result = {'name_i18n': 'Unknown destination', 'source_type': 'unknown', 'source_names': []}
        else:
            result = {'name_i18n': '', 'source_type': 'native', 'source_names': []}
        samples = self.app_evidence.get(key, {})
        evidence = [samples[item] for item in sorted(samples)]
        if result['source_type'] == 'domain':
            _, _, section, matched = self._classify_domain(key.split(':', 1)[1])
            reason = 'ambiguous' if section and len(self.rules[section][matched]) > 1 else 'community'
            evidence = [self._rule_evidence(section, matched, reason) if section else {
                'reason': 'rules_unavailable' if self.error else 'unmatched_domain'}]
        elif result['source_type'] == 'native':
            evidence = [{'reason': 'native'}]
        # Return independent JSON-ready values: a caller must not be able to
        # mutate cached explanations used by another row or later request.
        result['classification_evidence'] = [
            {field: list(value) if isinstance(value, tuple) else value
             for field, value in item.items()} for item in evidence]
        result['classification_evidence_truncated'] = key in self.evidence_truncated
        result['identification_level'] = self.identification_level(key)
        result['application_identified'] = result['identification_level'] == 'application'
        result['detection_reason'] = {
            'native': 'native_app', 'community': 'community_rule',
            'protocol': 'protocol_fallback', 'unknown': 'insufficient_metadata',
            'infrastructure': 'shared_infrastructure',
            'archived_domain': 'archived_domain',
        }.get(result['source_type'], evidence[0]['reason'] if evidence else 'unmatched_domain')
        return result
