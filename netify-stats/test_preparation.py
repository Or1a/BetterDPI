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


if __name__ == '__main__':
    unittest.main()
