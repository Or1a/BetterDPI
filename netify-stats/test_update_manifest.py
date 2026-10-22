"""Release descriptors must point at the actual reviewed package bytes."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('update_manifest', ROOT / 'packaging/build_update_manifest.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class UpdateManifestTest(unittest.TestCase):
    version = '0.3.0'

    def artifacts(self, root):
        values = {}
        for series, (sdk, extension) in builder.TARGETS.items():
            content = ('Package fixture for ' + sdk).encode()
            filename = 'BetterDPI-%s-openwrt-%s-all.%s' % (self.version, sdk, extension)
            (root / filename).write_bytes(content)
            (root / ('BetterDPI-openwrt-%s-all.%s' % (series, extension))).write_bytes(content)
            values[series] = content
        return values

    def test_descriptor_hashes_sizes_names_and_formats_come_from_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contents = self.artifacts(root)
            result = builder.build_manifest(root, self.version, 'V' + self.version)
            self.assertEqual({key: result[key] for key in ('schema', 'version', 'tag')},
                             {'schema': 1, 'version': self.version, 'tag': 'V' + self.version})
            self.assertEqual(set(result['packages']), {'24.10', '25.12'})
            for series, content in contents.items():
                item = result['packages'][series]
                self.assertEqual(item['sha256'], hashlib.sha256(content).hexdigest())
                self.assertEqual(item['size'], len(content))
                self.assertEqual(item['format'], builder.TARGETS[series][1])
                self.assertEqual((root / item['filename']).read_bytes(), content)
                self.assertNotIn('/', item['filename'])

    def test_tag_mismatch_and_prerelease_cannot_be_published_as_stable_updates(self):
        for version, tag in (('0.3.0', 'V0.2.8'), ('0.3.0-rc1', 'V0.3.0-rc1'),
                                ('03.0.0', 'V03.0.0'), ('0.3', 'V0.3'), ('../x', 'V../x'),
                                ('1000000.0.0', 'V1000000.0.0')):
            with self.subTest(version=version, tag=tag), self.assertRaises(ValueError):
                builder.validate_version(version, tag)
        builder.validate_version('1.12.304', 'V1.12.304')

    def test_missing_wrong_version_or_wrong_format_never_produces_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.artifacts(root)
            package = root / 'BetterDPI-0.3.0-openwrt-25.12.5-all.apk'
            for replacement in ('BetterDPI-0.2.8-openwrt-25.12.5-all.apk',
                                'BetterDPI-0.3.0-openwrt-25.12.5-all.ipk'):
                other = package.with_name(replacement)
                package.rename(other)
                with self.assertRaisesRegex(ValueError, 'Missing regular'):
                    builder.build_manifest(root, self.version, 'V' + self.version)
                other.rename(package)
            package.unlink()
            with self.assertRaisesRegex(ValueError, 'Missing regular'):
                builder.build_manifest(root, self.version, 'V' + self.version)

    def test_empty_oversized_or_linked_files_and_mismatched_alias_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.artifacts(root)
            alias = root / 'BetterDPI-openwrt-24.10-all.ipk'
            original = alias.read_bytes()
            alias.write_bytes(b'different bytes')
            with self.assertRaisesRegex(ValueError, 'alias differs'):
                builder.build_manifest(root, self.version, 'V' + self.version)
            alias.write_bytes(b'')
            with self.assertRaisesRegex(ValueError, '1 to'):
                builder.build_manifest(root, self.version, 'V' + self.version)
            with alias.open('wb') as handle:
                handle.truncate(builder.MAX_PACKAGE_SIZE + 1)
            with self.assertRaisesRegex(ValueError, '1 to'):
                builder.build_manifest(root, self.version, 'V' + self.version)
            alias.unlink()
            alias.symlink_to(root / 'BetterDPI-0.3.0-openwrt-24.10.8-all.ipk')
            with self.assertRaisesRegex(ValueError, 'Missing regular'):
                builder.build_manifest(root, self.version, 'V' + self.version)
            alias.unlink()
            alias.write_bytes(original)
            self.assertTrue(builder.build_manifest(root, self.version, 'V' + self.version))

    def test_cli_writes_only_a_complete_descriptor_and_version_check_needs_no_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command = [sys.executable, str(ROOT / 'packaging/build_update_manifest.py'),
                       '--version', self.version, '--tag', 'V' + self.version,
                       '--release-dir', str(root)]
            subprocess.run(command + ['--check-version'], check=True, capture_output=True)
            failed = subprocess.run(command, capture_output=True)
            self.assertNotEqual(failed.returncode, 0)
            self.assertFalse((root / 'update.json').exists())
            self.artifacts(root)
            subprocess.run(command, check=True, capture_output=True)
            self.assertEqual(json.loads((root / 'update.json').read_text()),
                             builder.build_manifest(root, self.version, 'V' + self.version))
            self.assertFalse((root / 'update.json.tmp').exists())


if __name__ == '__main__':
    unittest.main()
