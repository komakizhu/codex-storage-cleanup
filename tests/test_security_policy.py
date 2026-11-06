from pathlib import Path
import sys
from unittest import TestCase


SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_ROOT / "scripts"))
import serve_codex_report


class CleanupReportSecurityTests(TestCase):
    def test_purpose_analysis_cannot_create_deletion_paths(self):
        for purpose in (
            {"trash_paths": ["/tmp/x"]},
            {"items": [{"trash_paths": ["/tmp/x"]}]},
        ):
            with self.subTest(purpose=purpose), self.assertRaises(ValueError):
                serve_codex_report._validate_discovery_is_read_only(
                    {"large_file_discovery": {"purpose_analysis": purpose}}
                )


if __name__ == "__main__":
    import unittest
    unittest.main()
