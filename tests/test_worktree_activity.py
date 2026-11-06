from pathlib import Path
from tempfile import TemporaryDirectory
import os
import sqlite3
import time
import unittest
from unittest import mock

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import worktree_activity
from worktree_activity import IDLE_SECONDS, analyze_worktree_groups, extract_static_references, load_thread_activity, tree_activity


class WorktreeActivityTests(unittest.TestCase):
    def _make_index(self, home: Path, cwd: Path, timestamp: float, archived: int = 1) -> None:
        database = home / ".codex" / "state_1.sqlite"
        database.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(database)
        if not database.stat().st_size:
            connection.execute(
                "CREATE TABLE threads (id TEXT, cwd TEXT, updated_at INTEGER, recency_at INTEGER, "
                "updated_at_ms INTEGER, recency_at_ms INTEGER, archived INTEGER)"
            )
        else:
            connection.execute("DELETE FROM threads")
        connection.execute(
            "INSERT INTO threads VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("thread-1", str(cwd), int(timestamp), int(timestamp), int(timestamp * 1000), int(timestamp * 1000), archived),
        )
        connection.commit()
        connection.close()

    def _set_tree_old(self, root: Path, timestamp: float) -> None:
        for current, dirs, files in os.walk(root, topdown=False, followlinks=False):
            for name in files + dirs:
                path = Path(current) / name
                try:
                    os.utime(path, (timestamp, timestamp), follow_symlinks=False)
                except OSError:
                    pass
        os.utime(root, (timestamp, timestamp))

    def test_activity_uses_all_tree_entries_and_latest_conversation_time(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            first = home / ".codex" / "worktrees" / "first"
            second = home / ".codex" / "worktrees" / "second"
            (first / "ignored.tmp").mkdir(parents=True)
            (first / "ignored.tmp" / "value").write_text("old")
            second.mkdir(parents=True)
            (second / "value").write_text("old")
            link = first / "shared"
            link.symlink_to(second / "value")
            old = 1_700_000_000.0
            self._set_tree_old(first, old)
            self._set_tree_old(second, old)
            os.utime(first / "ignored.tmp" / "value", (old + 100, old + 100))
            self._make_index(home, first, old)
            activity = load_thread_activity(home)
            result = analyze_worktree_groups(
                [{"path": first, "active": False}, {"path": second, "active": False}],
                thread_activity=activity,
                symlinks=[{
                    "path": str(link), "resolved_target": str(second / "value"), "target_exists": True,
                }],
                now=old + IDLE_SECONDS + 101,
            )
            self.assertEqual(len(result["groups"]), 1)
            group = result["groups"][0]
            self.assertTrue(group["idle"], group)
            self.assertGreaterEqual(group["idle_for_seconds"], IDLE_SECONDS)
            self.assertEqual(group["thread_index_coverage"], "complete")
            self.assertIn(str(first / "ignored.tmp" / "value"), group["members"][0]["latest_file_mtime_path"])

    def test_exactly_seven_days_is_not_idle_and_recent_conversation_blocks(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            worktree = home / ".codex" / "worktrees" / "task"
            worktree.mkdir(parents=True)
            (worktree / "source").write_text("old")
            old = 1_700_000_000.0
            self._set_tree_old(worktree, old)
            self._make_index(home, worktree, old, archived=1)
            activity = load_thread_activity(home)
            boundary = analyze_worktree_groups(
                [{"path": worktree, "active": False}],
                thread_activity=activity,
                now=old + IDLE_SECONDS,
            )
            self.assertFalse(boundary["groups"][0]["idle"])
            self.assertEqual(boundary["groups"][0]["activity_status"], "recent")
            recent = analyze_worktree_groups(
                [{"path": worktree, "active": False}],
                thread_activity=activity,
                now=old + IDLE_SECONDS + 1,
            )
            self.assertTrue(recent["groups"][0]["idle"])
            # An unarchived session is an open-state unknown even if its last
            # activity is old, so it must keep the group out of migration.
            self._make_index(home, worktree, old, archived=0)
            blocked = analyze_worktree_groups(
                [{"path": worktree, "active": False}],
                thread_activity=load_thread_activity(home),
                now=old + IDLE_SECONDS + 1,
            )
            self.assertFalse(blocked["groups"][0]["idle"])
            self.assertTrue(any("未确认关闭" in item for item in blocked["groups"][0]["blockers"]))

    def test_missing_index_is_unknown_and_reference_cycle_forms_one_group(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            first = home / ".codex" / "worktrees" / "first"
            second = home / ".codex" / "worktrees" / "second"
            first.mkdir(parents=True)
            second.mkdir(parents=True)
            (first / "config.json").write_text("{}")
            (second / "config.json").write_text("{}")
            self.assertEqual(load_thread_activity(home)["coverage"], "unavailable")
            result = analyze_worktree_groups(
                [{"path": first, "active": False}, {"path": second, "active": False}],
                thread_activity=load_thread_activity(home),
                references=[
                    {"source_file": str(first / "config.json"), "path": str(second), "status": "exists"},
                    {"source_file": str(second / "config.json"), "path": str(first), "status": "exists"},
                ],
                now=time.time(),
            )
            self.assertEqual(len(result["groups"]), 1)
            self.assertEqual(result["groups"][0]["activity_status"], "unknown")
            self.assertFalse(result["groups"][0]["idle"])

    def test_tree_activity_does_not_follow_external_link(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            external = Path(temp) / "external"
            root.mkdir()
            external.mkdir()
            (external / "new").write_text("new")
            (root / "link").symlink_to(external)
            result = tree_activity(root)
            self.assertNotEqual(result["latest_mtime_path"], str(external / "new"))

    def test_invalid_reference_blocks_all_worktree_migrations(self):
        with TemporaryDirectory() as temp:
            first = Path(temp) / "first"
            second = Path(temp) / "second"
            first.mkdir()
            second.mkdir()
            old = 1_700_000_000.0
            self._set_tree_old(first, old)
            self._set_tree_old(second, old)
            result = analyze_worktree_groups(
                [{"path": first}, {"path": second}],
                thread_activity={"records": [], "coverage": "complete"},
                references=[{"source_file": str(first / "config"), "raw_path": "bad\x00path"}],
                now=old + IDLE_SECONDS + 1,
            )
            self.assertTrue(all(not group["idle"] for group in result["groups"]))
            self.assertTrue(all(group["activity_status"] == "unknown" for group in result["groups"]))
            self.assertEqual(result["references"][0]["status"], "invalid")

    def test_unknown_symlink_blocks_all_worktree_migrations(self):
        with TemporaryDirectory() as temp:
            first = Path(temp) / "first"
            second = Path(temp) / "second"
            first.mkdir()
            second.mkdir()
            old = 1_700_000_000.0
            self._set_tree_old(first, old)
            self._set_tree_old(second, old)
            result = analyze_worktree_groups(
                [{"path": first}, {"path": second}],
                thread_activity={"records": [], "coverage": "complete"},
                symlinks=[{"path": str(first / "link"), "target_exists": None}],
                now=old + IDLE_SECONDS + 1,
            )
            self.assertTrue(all(not group["idle"] for group in result["groups"]))
            self.assertTrue(all(group["activity_status"] == "unknown" for group in result["groups"]))

    def test_existing_t1_symlink_is_an_access_alias_not_a_blocker(self):
        with TemporaryDirectory() as temp:
            worktree = Path(temp) / "worktree"
            worktree.mkdir()
            (worktree / "source").write_text("old")
            old = 1_700_000_000.0
            self._set_tree_old(worktree, old)
            result = analyze_worktree_groups(
                [{"path": worktree, "active": False}],
                thread_activity={"records": [], "coverage": "complete"},
                symlinks=[{
                    "path": str(worktree / "old-entry"),
                    "target": "/Volumes/T1/Agent/archive/worktrees/tree",
                    "target_exists": None,
                }],
                now=old + IDLE_SECONDS + 1,
            )
            self.assertTrue(result["groups"][0]["idle"], result["groups"][0])
            self.assertEqual(result["references"], [])

    def test_static_reference_extraction_does_not_read_linked_config(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            root.mkdir()
            target = Path(temp) / "private"
            target.write_text('{"path": "/private"}')
            (root / "config.json").symlink_to(target)
            self.assertEqual(extract_static_references([root]), [])
            self.assertTrue(extract_static_references.last_issues)

    def test_inventory_reference_roots_use_nearest_ancestor_lookup(self):
        with TemporaryDirectory() as temp:
            outer = Path(temp) / "project"
            nested = outer / "nested"
            nested.mkdir(parents=True)
            outer_config = outer / "project.json"
            nested_config = nested / "project.json"
            outer_config.write_text('{"output_path": "/tmp/outer-output"}')
            nested_config.write_text('{"output_path": "/tmp/nested-output"}')
            inventory = [
                {"path": str(outer_config), "entry_type": "file"},
                {"path": str(nested_config), "entry_type": "file"},
            ]
            with mock.patch.object(
                worktree_activity, "_contains",
                side_effect=AssertionError("inventory lookup must not scan every root"),
            ):
                references = extract_static_references(
                    [outer, nested], inventory_records=inventory,
                )

            self.assertEqual({row["source_file"] for row in references}, {
                str(outer_config), str(nested_config),
            })
            self.assertEqual({row["raw_path"] for row in references}, {
                "/tmp/outer-output", "/tmp/nested-output",
            })


if __name__ == "__main__":
    unittest.main()
