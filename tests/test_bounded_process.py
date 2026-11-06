from pathlib import Path
from tempfile import TemporaryDirectory
import os
import sys
import time
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import scan_budget
import storage_discovery


class BoundedProcessTests(unittest.TestCase):
    def test_blocked_zstd_source_reader_is_killed_with_remaining_budget(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "session.jsonl.zst"
            archive.write_bytes(b"compressed")
            fake_zstd = root / "zstd"
            fake_zstd.write_text(
                "#!/usr/bin/env python3\n"
                "import time\n"
                "time.sleep(10)\n"
            )
            fake_zstd.chmod(0o755)
            scan_budget.start(1)
            started = time.monotonic()
            try:
                with patch.object(storage_discovery.shutil, "which", return_value=str(fake_zstd)):
                    with self.assertRaises(scan_budget.ScanBudgetExceeded):
                        storage_discovery._source_references(archive)
                self.assertLess(time.monotonic() - started, 4)
            finally:
                scan_budget.stop()


if __name__ == "__main__":
    unittest.main()
