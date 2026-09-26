"""Domain attribution for reporting only; never overwrites native DPI records."""
from functools import lru_cache
import json
from pathlib import Path
import re
import socket

RULE_PATH = Path('/usr/share/netify-stats/community-rules.json')
HOST_NAME = re.compile(r'[a-z0-9_-]+(?:\.[a-z0-9_-]+)+')
IPV4_LITERAL = re.compile(r'(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}')
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

    def classify(self, native, host):
        if native and native.lower() not in ('unknown', 'unclassified'):
            return native
        host = (host or '').strip().lower().rstrip('.')
        if '.' not in host or ':' in host or len(host) > 253:
            return 'Unknown'
        # Some platforms' inet_pton accept leading zeroes; reject those first
        # to keep the same strict IPv4 semantics on macOS and OpenWrt.
        if IPV4_LITERAL.fullmatch(host):
            try:
                socket.inet_pton(socket.AF_INET, host)
                return 'Unknown'
            except OSError:
                pass
        if not HOST_NAME.fullmatch(host):
            return 'Unknown'
        app, source = self._classify_domain(host)
        if source:
            self.app_sources.setdefault(app, set()).add(source)
        return app

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
        if candidates and len(candidates) == 1:
            source = self.rules.get('rule_sources', {}).get(section, {}).get(
                matched, self.rules.get('default_rule_source', 'dlc'))
            return 'community:' + candidates[0], source
        return 'domain:' + host, None

    def describe(self, key):
        if key.startswith('community:'):
            tag = key.split(':', 1)[1]
            names = {source['id']: source['name'] for source in self.rules.get('sources', [])}
            actual = [names.get(source, source) for source in sorted(self.app_sources.get(key, ()))]
            detail = '社区域名规则' + ('（' + ' / '.join(actual) + '）' if actual else '')
            return self.rules['labels'].get(tag, tag), detail
        if key.startswith('domain:'):
            return key.split(':', 1)[1], '仅识别域名'
        if key == 'Unknown':
            return '未识别目标', '未识别'
        return key.removeprefix('netify.').replace('-', ' ').title(), 'Netify 原生识别'

    def describe_metadata(self, key):
        """Let each LuCI session translate labels without changing raw data.

        Keep describe() and the API's name/source fields backward-compatible.
        Source names are factual provenance and should never be translated.
        """
        if key.startswith('community:'):
            tag = key.split(':', 1)[1]
            names = {source['id']: source['name'] for source in self.rules.get('sources', [])}
            return {'name_i18n': APP_NAME_MSGIDS.get(tag, ''),
                    'source_type': 'community',
                    'source_names': [names.get(source, source)
                                     for source in sorted(self.app_sources.get(key, ()))]}
        if key.startswith('domain:'):
            return {'name_i18n': '', 'source_type': 'domain', 'source_names': []}
        if key == 'Unknown':
            return {'name_i18n': 'Unknown destination', 'source_type': 'unknown', 'source_names': []}
        return {'name_i18n': '', 'source_type': 'native', 'source_names': []}
