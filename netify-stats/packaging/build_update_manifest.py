"""Build the bounded update descriptor from completed Release artifacts.

This file runs in release CI, never on a router. HTTPS and the descriptor's
hashes bind an update to a specific GitHub Release; this is not a package-signing
key or a replacement for a signed package repository.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re


TARGETS = {'24.10': ('24.10.8', 'ipk'), '25.12': ('25.12.5', 'apk')}
MAX_PACKAGE_SIZE = 16 * 1024 * 1024
STABLE_VERSION = re.compile(r'(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})')


def validate_version(version, tag):
    if not isinstance(version, str) or len(version) > 32 or not STABLE_VERSION.fullmatch(version):
        raise ValueError('Updates require a stable x.y.z package version')
    if tag != 'V' + version:
        raise ValueError('Release tag must match the package version')


def file_digest(path):
    if not path.is_file() or path.is_symlink():
        raise ValueError('Missing regular release artifact: ' + path.name)
    size = path.stat().st_size
    if not 0 < size <= MAX_PACKAGE_SIZE:
        raise ValueError('Release artifact must contain 1 to %d bytes: %s' % (MAX_PACKAGE_SIZE, path.name))
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(65536), b''):
            digest.update(block)
    return size, digest.hexdigest()


def build_manifest(release_dir, version, tag):
    validate_version(version, tag)
    release_dir = Path(release_dir)
    packages = {}
    for series, (sdk, extension) in TARGETS.items():
        filename = 'BetterDPI-%s-openwrt-%s-all.%s' % (version, sdk, extension)
        size, checksum = file_digest(release_dir / filename)
        alias = 'BetterDPI-openwrt-%s-all.%s' % (series, extension)
        if file_digest(release_dir / alias) != (size, checksum):
            raise ValueError('Fixed download alias differs from versioned package: ' + alias)
        packages[series] = {'filename': filename, 'format': extension,
                            'sha256': checksum, 'size': size}
    return {'schema': 1, 'version': version, 'tag': tag, 'packages': packages}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release-dir', type=Path, default=Path('release'))
    parser.add_argument('--version', required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--check-version', action='store_true', help='Validate stable version and tag without opening artifacts')
    args = parser.parse_args()
    try:
        validate_version(args.version, args.tag)
        if args.check_version:
            return
        manifest = build_manifest(args.release_dir, args.version, args.tag)
        temporary = args.release_dir / 'update.json.tmp'
        temporary.write_text(json.dumps(manifest, ensure_ascii=True, sort_keys=True, indent=2) + '\n')
        temporary.replace(args.release_dir / 'update.json')
    except (ValueError, OSError) as exc:
        parser.error(str(exc))


if __name__ == '__main__':
    main()
