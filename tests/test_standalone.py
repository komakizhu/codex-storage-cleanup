from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
import json
import os
import shutil
import subprocess
import sys


SKILL_ROOT = Path(__file__).resolve().parents[1]


class StandalonePackageTests(TestCase):
    def test_package_runs_after_parent_checkout_is_absent(self):
        with TemporaryDirectory(prefix='codex-standalone-') as temp:
            package = Path(temp) / 'skill'
            shutil.copytree(SKILL_ROOT / 'scripts', package / 'scripts')
            home = Path(temp) / 'home'
            (home / '.codex').mkdir(parents=True)
            (home / '.codex' / 'config.toml').write_text('model = "test"\n')
            workspace = Path(temp) / 'output'
            env = {key: value for key, value in os.environ.items() if key not in {'PYTHONPATH', 'PYTHONHOME'}}
            launcher = (
                "import sys; from pathlib import Path; "
                "script, home, workspace = map(Path, sys.argv[1:4]); "
                "sys.path.insert(0, str(script.parent)); "
                "import scan_codex; "
                "sys.argv = [str(script), '--home', str(home), '--workspace', str(workspace), "
                "'--scan-mode', 'full', '--no-inventory']; "
                "raise SystemExit(scan_codex.main(_account_lookup=lambda: ('mac', home)))"
            )
            result = subprocess.run(
                [sys.executable, '-c', launcher, str(package / 'scripts' / 'scan_codex.py'),
                 str(home), str(workspace)],
                cwd=str(package), env=env, capture_output=True, text=True, timeout=90,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads((workspace / 'work' / 'storage-analysis-live.json').read_text())
            self.assertIn('usage_summary', data['large_file_discovery'])
            self.assertTrue((workspace / 'outputs' / 'codex-storage-cleanup-report.html').exists())

    def test_bilingual_metadata_and_version_are_present(self):
        metadata = (SKILL_ROOT / 'agents' / 'openai.yaml').read_text()
        self.assertIn('Codex 存储清理（Codex Storage Cleanup）', metadata)
        self.assertIn('查清 Codex 各处占用', metadata)
        self.assertEqual((SKILL_ROOT / 'VERSION').read_text().strip(), '2.1.4')
        skill = (SKILL_ROOT / 'SKILL.md').read_text()
        self.assertIn('中文：', skill)
        self.assertIn('English:', skill)
        self.assertIn('# Codex 存储清理（Codex Storage Cleanup）', skill)


if __name__ == '__main__':
    import unittest
    unittest.main()
