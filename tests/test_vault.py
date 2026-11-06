import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import time
from unittest import TestCase
from unittest.mock import patch

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import vault


class VaultLocationTests(TestCase):
    def _write_snapshot(self, root, snapshot_id, source='/tmp/source'):
        folder = root / snapshot_id
        payload = folder / 'payload'
        payload.mkdir(parents=True)
        (payload / 'value.txt').write_text('preserved')
        manifest = {
            'id': snapshot_id,
            'source': source,
            'category': 'generated',
            'volume_uuid': vault.EXPECTED_UUID,
            'signature': vault.signature(payload),
        }
        (folder / 'manifest.json').write_text(json.dumps(manifest))
        return folder

    def test_legacy_snapshot_can_be_verified_without_moving_it(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            new_root = root / 'new'
            old_root = root / 'old'
            snapshot_id = '20261015T010203Z-abcdef12'
            folder = self._write_snapshot(old_root, snapshot_id)
            with patch.object(vault, 'SNAPSHOTS', new_root), patch.object(vault, 'LEGACY_SNAPSHOTS', old_root), patch.object(vault, 'check_disk'):
                verified, manifest = vault.verify_snapshot(snapshot_id)
            self.assertEqual(verified, folder)
            self.assertEqual(manifest['id'], snapshot_id)
            self.assertTrue(folder.exists())
            self.assertFalse(new_root.exists())

    def test_duplicate_snapshot_id_is_reported_instead_of_selected(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            new_root = root / 'new'
            old_root = root / 'old'
            snapshot_id = '20261015T010203Z-abcdef12'
            self._write_snapshot(new_root, snapshot_id)
            self._write_snapshot(old_root, snapshot_id)
            with patch.object(vault, 'SNAPSHOTS', new_root), patch.object(vault, 'LEGACY_SNAPSHOTS', old_root), patch.object(vault, 'check_disk'):
                with self.assertRaisesRegex(vault.VaultError, 'conflict'):
                    vault.load_snapshot(snapshot_id)

    def test_new_write_location_is_distinct_from_legacy_location(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.object(vault, 'SNAPSHOTS', root / 'new'):
                path = vault.snapshot_write_dir('20261015T010203Z-abcdef12')
            self.assertEqual(path, root / 'new' / '20261015T010203Z-abcdef12')

    def test_update_cache_purge_checks_single_volume_tree_before_removal(self):
        with TemporaryDirectory() as temp:
            cache = Path(temp) / "Installation"
            cache.mkdir()
            (cache / "package.zip").write_bytes(b"update")
            args = argparse.Namespace(confirm_path=str(cache), permanent=True)
            with patch.object(vault, "UPDATE_INSTALLATION_CACHE", cache), \
                 patch.object(vault, "require_plain_single_volume_tree") as plain_tree, \
                 patch.object(vault, "require_not_open"), \
                 patch.object(vault.subprocess, "check_output", side_effect=["", "4"]), \
                 contextlib.redirect_stdout(io.StringIO()):
                vault.purge_update_cache(args)

            plain_tree.assert_called_once_with(cache)
            self.assertFalse(cache.exists())

    def test_legacy_snapshot_can_restore_without_overwriting(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            old_root = root / 'old'
            snapshot_id = '20261015T010203Z-abcdef12'
            folder = self._write_snapshot(old_root, snapshot_id)
            destination = root / 'restored'
            args = argparse.Namespace(
                snapshot_id=snapshot_id,
                destination=str(destination),
                confirm_destination=str(destination),
            )
            with patch.object(vault, 'SNAPSHOTS', root / 'new'), patch.object(vault, 'LEGACY_SNAPSHOTS', old_root), patch.object(vault, 'check_disk'):
                vault.restore(args)
            self.assertEqual((destination / 'value.txt').read_text(), 'preserved')
            self.assertTrue(folder.exists())

    def test_changed_snapshot_content_is_rejected(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            old_root = root / 'old'
            snapshot_id = '20261015T010203Z-abcdef12'
            folder = self._write_snapshot(old_root, snapshot_id)
            (folder / 'payload' / 'value.txt').write_text('changed')
            with patch.object(vault, 'SNAPSHOTS', root / 'new'), patch.object(vault, 'LEGACY_SNAPSHOTS', old_root), patch.object(vault, 'check_disk'):
                with self.assertRaisesRegex(vault.VaultError, 'verification failed'):
                    vault.verify_snapshot(snapshot_id)

    def test_archive_eviction_removes_only_files_older_than_seven_days(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            live = root / 'archived_sessions'
            (live.parent / 'sessions').mkdir()
            live.mkdir()
            old_time = time.time() - 8 * 86400
            old_jsonl = live / 'old.jsonl'
            old_zst = live / 'old.jsonl.zst'
            recent = live / 'recent.jsonl'
            for path in (old_jsonl, old_zst, recent):
                path.write_bytes(path.name.encode())
            for path in (old_jsonl, old_zst):
                os.utime(path, (old_time, old_time))

            snapshot_id = '20261015T010203Z-abcdef12'
            snapshot = root / 'snapshots' / snapshot_id
            payload = snapshot / 'payload'
            payload.mkdir(parents=True)
            for path in live.iterdir():
                shutil.copy2(path, payload / path.name)
            manifest = {
                'id': snapshot_id,
                'source': str(live),
                'category': 'codex-archives',
                'volume_uuid': vault.EXPECTED_UUID,
                'signature': vault.signature(live),
            }
            (snapshot / 'manifest.json').write_text(json.dumps(manifest))
            args = argparse.Namespace(
                snapshot_id=snapshot_id,
                confirm_source=str(live),
                older_than_days=7,
                permanent=True,
                only=[],
            )
            with patch.object(vault, 'SNAPSHOTS', root / 'snapshots'), patch.object(vault, 'LEGACY_SNAPSHOTS', root / 'legacy'), patch.object(vault, 'LIVE_ARCHIVES', live), patch.object(vault, 'check_disk'), patch.object(vault, 'require_not_open'):
                with patch('builtins.print') as printed:
                    vault.evict_archives(args)
            self.assertFalse(old_jsonl.exists())
            self.assertFalse(old_zst.exists())
            self.assertTrue(recent.exists())
            result = json.loads(printed.call_args.args[0])
            self.assertEqual(result['offloaded_files'], 2)


if __name__ == '__main__':
    import unittest
    unittest.main()
