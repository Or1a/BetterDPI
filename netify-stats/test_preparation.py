"""Packaging source checks only: never invokes a builder or lifecycle hook."""
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('preparation', ROOT/'packaging/check_preparation.py')
preparation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preparation)


class PreparationTest(unittest.TestCase):
    def package_fixture(self, root):
        files = {
            'features/anti_pcdn/__init__.py': ('', '/usr/lib/netify-stats/anti_pcdn/__init__.py'),
            'features/anti_pcdn/engine.py': ('from .scoring import score\n', '/usr/lib/netify-stats/anti_pcdn/engine.py'),
            'features/anti_pcdn/scoring.py': ('def score(): return 0\n', '/usr/lib/netify-stats/anti_pcdn/scoring.py'),
            'netify_features.py': ('def start():\n    from anti_pcdn.engine import Engine\n', '/usr/lib/netify-stats/netify_features.py'),
        }
        manifest = {}
        for source, (content, target) in files.items():
            path = root/source
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            manifest[source] = [target, '0644']
        return manifest

    def test_current_sources_and_recipe_agree_but_are_not_release_ready(self):
        result = preparation.check()
        self.assertEqual(result['source_checks'], 'passed')
        self.assertFalse(result['public_release_ready'])

    def test_missing_query_module_is_detected_even_if_both_lists_omit_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = json.loads((ROOT/'packaging/runtime-manifest.json').read_text())
            for filename in (*manifest, 'Makefile', 'packaging/runtime-manifest.json'):
                target = root/filename
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT/filename, target)
            manifest.pop('netify_query.py')
            (root/'packaging/runtime-manifest.json').write_text(json.dumps(manifest))
            recipe = (root/'Makefile').read_text().replace(' ./netify_query.py', '')
            (root/'Makefile').write_text(recipe)
            with self.assertRaisesRegex(AssertionError, 'imports uninstalled module netify_query'):
                preparation.check(root)

    def test_nested_imports_follow_installed_layout_and_include_lazy_imports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.package_fixture(root)
            trees, packages = preparation.python_modules(root, manifest)
            preparation.check_imports(trees, packages)
            self.assertIn('anti_pcdn.scoring', trees)
            manifest.pop('features/anti_pcdn/engine.py')
            with self.assertRaisesRegex(AssertionError, 'imports uninstalled module anti_pcdn.engine'):
                preparation.check_imports(*preparation.python_modules(root, manifest))

    def test_unrelated_flat_module_does_not_satisfy_relative_package_import(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.package_fixture(root)
            manifest['features/anti_pcdn/scoring.py'][0] = '/usr/lib/netify-stats/scoring.py'
            with self.assertRaisesRegex(AssertionError, 'imports uninstalled module anti_pcdn.scoring'):
                preparation.check_imports(*preparation.python_modules(root, manifest))

    def test_package_initializer_is_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.package_fixture(root)
            manifest.pop('features/anti_pcdn/__init__.py')
            with self.assertRaisesRegex(AssertionError, 'imports uninstalled package anti_pcdn'):
                preparation.check_imports(*preparation.python_modules(root, manifest))


if __name__ == '__main__':
    unittest.main()
