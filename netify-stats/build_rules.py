#!/usr/bin/env python3
"""Build offline attribution rules from pinned, separately attributed sources."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


# This is deliberately a reviewed allowlist, not all service-blocking rules.
# Blocking lists also contain shared CDNs, ads, broad Fediverse groups and
# spelling errors, which are unsuitable evidence for application ownership.
NEXTDNS_ALLOWLIST = {
    '9gag': ('9gag', ('9gag.com', '9cache.com')),
    'bereal': ('bereal', ('bere.al', 'bereal.com')),
    'ebay': ('ebay', ('ebaydesc.com',)),
    'pinterest': ('pinterest', ('pinterest.biz', 'pinterest.com.pt')),
    'snapchat': ('snap', ('sc-jpl.com', 'sc-prod.net')),
    'steam': ('steam', ('poweredbysteam.net', 'steamgames.net')),
    'tiktok': ('tiktok', ('tiktokshop.com', 'tiktok-eu.net', 'tiktok-row.net',
                         'tiktok-us.net', 'tiktokglobalshopv.com', 'tiktokv.eu',
                         'tiktokv.us', 'tiktokw.eu', 'tiktokw.us')),
    'tinder': ('tinder', ('gotinder.com', 'tinder.com', 'tindersparks.com')),
}

# Selected standalone entries in DLC's AI category files have no service file
# of their own. Assign only reviewed service domains; never import an entire
# category, its includes, or a shared hosting suffix as an application.
REVIEWED_DLC_SERVICES = {
    'category-ai-cn': {
        'qwen': ('Qwen', ('qianwen.com', 'qianwenai.com', 'qwen.ai', 'qwenlm.ai', 'tongyi.com')),
        'kimi': ('Kimi / Moonshot', ('kimi.com', 'moonshot.cn')),
        'zhipu': ('Zhipu / GLM', ('bigmodel.cn', 'chatglm.cn', 'z.ai', 'zhipuai.cn', 'zhipucn.com')),
        'minimax': ('MiniMax / Hailuo', ('hailuoai.com', 'minimaxi.com', 'xingyeai.com')),
        'kling': ('Kling AI', ('kechuangai.com', 'kling-ai.com', 'klingai.com')),
        'metaso': ('Metaso', ('metaso.cn', 'xiezuocat.com', 'meta.law')),
        'tiangong': ('Tiangong AI', ('tiangong.cn',)),
        'liblib': ('LibLibAI', ('liblib.art', 'liblib.cloud', 'liblib.tv')),
        'baichuan': ('Baichuan AI', ('baichuan-ai.com',)),
        'codebuddy': ('CodeBuddy / WorkBuddy', ('codebuddy.cn', 'workbuddy.cn')),
    },
    'category-ai-!cn': {
        'kimi': ('Kimi / Moonshot', ('kimi.ai', 'moonshot.ai')),
        'minimax': ('MiniMax / Hailuo', ('minimax.io',)),
        'midjourney': ('Midjourney', ('midjourney.com',)),
        'ollama': ('Ollama', ('ollama.com',)),
        'mistral': ('Mistral AI', ('mistral.ai',)),
        'openrouter': ('OpenRouter', ('openrouter.ai',)),
        'cohere': ('Cohere', ('cohere.ai', 'cohere.com')),
        'lmstudio': ('LM Studio', ('lmstudio.ai',)),
        'dify': ('Dify', ('dify.ai',)),
        'langchain': ('LangChain', ('langchain.com',)),
        'anythingllm': ('AnythingLLM', ('anythingllm.com',)),
        'crewai': ('CrewAI', ('crewai.com',)),
        'devin': ('Devin', ('devin.ai',)),
        'deepwiki': ('DeepWiki', ('deepwiki.com', 'deepwiki.org')),
        'openclaw': ('OpenClaw', ('openclaw.ai',)),
        'opencode': ('OpenCode', ('opencode.ai',)),
        'jasper': ('Jasper / Clipdrop', ('jasper.ai', 'clipdrop.co')),
        'lovart': ('Lovart', ('lovart.ai',)),
        'novelai': ('NovelAI', ('novelai.net',)),
        'tripo3d': ('Tripo AI', ('tripo3d.ai',)),
        'h2o-ai': ('H2O.ai', ('h2o.ai',)),
    },
}


def has_ownership(domain, exact, suffix):
    parts = domain.split('.')
    return (domain in exact or any('.'.join(parts[i:]) in suffix for i in range(len(parts)-1))
            or any(key.endswith('.' + domain) for table in (exact, suffix) for key in table))


def add_reviewed_dlc(source, exact, suffix, labels):
    added = {}
    for filename, services in REVIEWED_DLC_SERVICES.items():
        fields = [line.split('#', 1)[0].split() for line in
                  (source / 'data' / filename).read_text().splitlines()]
        tokens = {parts[0] for parts in fields if parts and '@ads' not in parts}
        for tag, (label, domains) in services.items():
            for domain in domains:
                if domain not in tokens and 'domain:' + domain not in tokens:
                    raise ValueError('reviewed domain missing from pinned DLC source: ' + domain)
                if has_ownership(domain, exact, suffix):
                    continue
                suffix[domain] = {tag}
                labels[tag] = label
                added[domain] = filename
    return added


def source_revision(source, revision):
    if revision is None:
        revision = subprocess.check_output(
            ['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('a full pinned source commit is required')
    return revision


def add_nextdns(source, exact, suffix, labels):
    added = {}
    for service, (tag, allowlist) in NEXTDNS_ALLOWLIST.items():
        domains = set((source / 'services' / service).read_text().splitlines())
        for domain in allowlist:
            if domain not in domains:
                raise ValueError('reviewed domain missing from pinned NextDNS source: ' + domain)
            # Existing exact/parent suffix rules retain priority even when
            # ambiguous. Existing child rules likewise prevent a new broader
            # suffix from filling their intentionally unresolved branches.
            if has_ownership(domain, exact, suffix):
                continue
            suffix[domain] = {tag}
            labels.setdefault(tag, tag.replace('-', ' ').title())
            added[domain] = 'nextdns-services'
    labels.update({'9gag': '9GAG', 'bereal': 'BeReal', 'tinder': 'Tinder'})
    return added


def build(source, destination, revision=None, nextdns_source=None, nextdns_revision=None):
    revision = source_revision(source, revision)
    exact, suffix, labels = {}, {}, {}
    skipped = 0
    for path in sorted((source / 'data').iterdir()):
        tag = path.name
        if not path.is_file() or tag.startswith(('category-', 'geolocation-', 'tld-')) or tag in ('cn', 'private', 'applications'):
            continue
        for line in path.read_text().splitlines():
            fields = line.split('#', 1)[0].split()
            if not fields:
                continue
            token = fields[0]
            if '@ads' in fields or token.startswith(('include:', 'regexp:', 'keyword:')):
                skipped += 1
                continue
            target = exact if token.startswith('full:') else suffix
            domain = token.removeprefix('full:').removeprefix('domain:').lower().rstrip('.')
            if '.' not in domain or not re.fullmatch(r'[a-z0-9_-]+(?:\.[a-z0-9_-]+)+', domain):
                skipped += 1
                continue
            target.setdefault(domain, set()).add(tag)
            labels[tag] = tag.replace('-', ' ').title()
    labels.update({'openai': 'OpenAI / ChatGPT', 'douyin': '抖音', 'wechat': '微信', 'tencent': '腾讯', 'bilibili': '哔哩哔哩', 'huawei': '华为', 'xiaomi': '小米', 'jd': '京东', 'taobao': '淘宝'})
    reviewed = add_reviewed_dlc(source, exact, suffix, labels)
    sources = [{'id': 'dlc', 'name': 'DLC', 'repo': 'https://github.com/v2fly/domain-list-community',
                'revision': revision, 'license': 'MIT', 'license_file': 'COMMUNITY-LICENSE',
                'rules': len(exact) + len(suffix)}]
    extra = {}
    if nextdns_source is not None:
        nextdns_revision = source_revision(nextdns_source, nextdns_revision)
        extra = add_nextdns(nextdns_source, exact, suffix, labels)
        sources.append({'id': 'nextdns-services', 'name': 'NextDNS services',
                        'repo': 'https://github.com/nextdns/services',
                        'revision': nextdns_revision, 'license': 'MIT',
                        'license_file': 'NEXTDNS-LICENSE', 'rules': len(extra)})
    # Ambiguous rules remain explicit rather than arbitrarily selecting an app.
    compiled = {'schema': 1, 'source': 'https://github.com/v2fly/domain-list-community',
                'revision': revision, 'license': 'MIT', 'labels': labels,
                'sources': sources, 'default_rule_source': 'dlc',
                'reviewed_rule_files': reviewed,
                'rule_sources': {'exact': {}, 'suffix': extra},
                'exact': {k: sorted(v) for k, v in exact.items()},
                'suffix': {k: sorted(v) for k, v in suffix.items()}, 'skipped': skipped}
    destination.mkdir(parents=True, exist_ok=True)
    blob = json.dumps(compiled, ensure_ascii=False, separators=(',', ':')).encode()
    (destination / 'community-rules.json').write_bytes(blob)
    (destination / 'COMMUNITY-LICENSE').write_bytes((source / 'LICENSE').read_bytes())
    if nextdns_source is not None:
        (destination / 'NEXTDNS-LICENSE').write_bytes((nextdns_source / 'LICENSE').read_bytes())
    print(json.dumps({'revision': revision, 'rules': len(exact)+len(suffix),
                      'sources': sources, 'bytes': len(blob), 'sha256': hashlib.sha256(blob).hexdigest()}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--revision', help='full DLC commit when using an extracted archive')
    parser.add_argument('--nextdns-source', type=Path, help='optional pinned NextDNS services checkout')
    parser.add_argument('--nextdns-revision', help='full NextDNS commit when using an extracted archive')
    args = parser.parse_args()
    build(args.source, args.destination, args.revision, args.nextdns_source, args.nextdns_revision)
