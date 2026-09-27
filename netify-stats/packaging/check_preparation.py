"""Read-only source/recipe consistency checks. Does not build or install a package."""
import ast
import json
from pathlib import Path
import re
import shlex
import sys


ROOT = Path(__file__).resolve().parents[1]
CATALOG_SOURCES = {
    'netify-stats.zh-cn.lmo': 'po/zh_Hans/netify-stats.po',
    'netify-stats.zh-tw.lmo': 'po/zh_Hant/netify-stats.po',
}


def check(root=ROOT):
    manifest = json.loads((root/'packaging/runtime-manifest.json').read_text())
    recipe = (root/'Makefile').read_text()
    installed = {}
    for line in recipe.splitlines():
        match = re.match(r'\s*\$\(INSTALL_(BIN|DATA)\) (.+)$', line)
        if not match:
            continue
        tokens = shlex.split(match[2])
        target = tokens[-1].replace('$(1)', '')
        for source in tokens[:-1]:
            source = source.removeprefix('./')
            destination = target + Path(source).name if target.endswith('/') else target
            assert source not in installed, 'Duplicate install: '+source
            installed[source] = [destination, '0755' if match[1] == 'BIN' else '0644']
    assert installed == manifest, 'Makefile installation differs from runtime-manifest.json'
    assert len({entry[0] for entry in manifest.values()}) == len(manifest), 'Duplicate destination'
    trees = {}
    for source in manifest:
        path = root/source
        assert path.is_file(), 'Missing source: '+source
        if path.suffix == '.py':
            trees[path.stem] = ast.parse(path.read_text(), filename=source)
    for module, tree in trees.items():
        for node in ast.walk(tree):
            imported = [node.module] if isinstance(node, ast.ImportFrom) else (
                [item.name for item in node.names] if isinstance(node, ast.Import) else [])
            for name in imported:
                if name and name.startswith('netify_'):
                    assert name in trees, module+' imports uninstalled module '+name
    assert not re.search(r'^PKG_BUILD_DEPENDS\s*[:+]?=', recipe, re.M), 'Pure-data package should not rebuild host dependencies'
    assert re.search(r'^define Build/Compile\n\s*:\s*\nendef$', recipe, re.M), 'Pure-data package must override the default source compiler'
    for name, source in CATALOG_SOURCES.items():
        assert (root/source).is_file(), 'Missing translation source: '+source
        assert (root/'i18n'/name).stat().st_size > 0, 'Missing precompiled translation: '+name
        assert 'i18n/'+name in manifest, 'Compiled translation missing from runtime manifest: '+name
    public_sources = (root/'packaging/source-files.txt').read_text().splitlines()
    assert len(public_sources) == len(set(public_sources)), 'Duplicate public source'
    assert set(manifest).issubset(public_sources), 'Runtime file missing from public source list'
    assert set(CATALOG_SOURCES.values()).issubset(public_sources), 'Translation source missing from public source list'
    for source in public_sources:
        path = root/source
        assert source and not Path(source).is_absolute() and '..' not in Path(source).parts
        assert path.is_file() and not path.is_symlink(), 'Missing or linked public source: '+source
        assert not source.startswith(('dist/','REVIEW','REPAIR','verify_','deploy_')), 'Private/test artifact in public source list'
        assert path.suffix not in ('.db','.apk','.key'), 'Private/binary artifact in public source list'
    version = next(ast.literal_eval(node.value) for node in trees['netify_rpc'].body
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'VERSION' for t in node.targets))
    package_version = re.search(r'^PKG_VERSION:=(.+)$', recipe, re.M)[1]
    assert version == package_version+'-dev', 'Development recipe/runtime version mismatch'
    assert re.search(r'^PKG_LICENSE:=GPL-3\.0-only$', recipe, re.M), 'Project license metadata mismatch'
    assert re.search(r'^PKG_LICENSE_FILES:=LICENSE$', recipe, re.M), 'Project license file metadata mismatch'
    assert manifest.get('LICENSE') == ['/usr/share/licenses/luci-app-netify-stats/LICENSE', '0644'], 'Project license installation mismatch'
    assert 'LICENSE' in public_sources, 'Project license missing from source list'
    assert (root/'packaging/netify-stats.keep').read_text().splitlines() == ['/etc/netify-stats.json']
    assert '/etc/netify-stats.json' not in {entry[0] for entry in manifest.values()}, 'Must not replace user settings'
    # SDK scripts call the installed hooks instead of maintaining a second copy.
    for section, filename in [('postinst','post-install'), ('prerm','pre-deinstall')]:
        body = re.search(r'define Package/luci-app-netify-stats/'+section+r'\n(.*?)\nendef', recipe, re.S)[1]
        expected = '#!/bin/sh\n[ -n "$IPKG_INSTROOT" ] && exit 0\nexec /usr/lib/netify-stats/package-'+filename
        assert body.replace('$$', '$').strip() == expected, 'Hook mismatch: '+section
    rules = json.loads((root/'rules/community-rules.json').read_text())
    assert rules.get('revision') and rules.get('source'), 'Missing rule provenance'
    for source in rules.get('sources', []):
        assert source.get('repo') and re.fullmatch('[0-9a-f]{40}', source.get('revision',''))
        assert source.get('license') and 'rules/'+source['license_file'] in manifest, 'Missing source license in package'
    for name in ('acl.json','menu.json'):
        json.loads((root/name).read_text())
    return {'version':version, 'runtime_files':len(manifest), 'internal_modules':len(trees),
            'source_checks':'passed', 'public_release_ready':False}


if __name__ == '__main__':
    print(json.dumps(check(), ensure_ascii=False))
    if '--release' in sys.argv:
        raise SystemExit('Stable release blocked: SDK/lifecycle validation is pending; see RELEASE-PREPARATION.md')
