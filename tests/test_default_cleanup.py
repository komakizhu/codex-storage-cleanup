import os
from pathlib import Path
from tempfile import TemporaryDirectory
from datetime import datetime, timedelta, timezone
import time
from unittest import TestCase
from unittest.mock import patch

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import apply_cleanup
import scan_codex
import cleanup_plan
import vault


class DefaultCleanupPolicyTests(TestCase):
    def test_each_direct_action_gets_a_fresh_reference_snapshot(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            cache = home / ".codex" / "cache"
            temp_cache = home / ".codex" / ".tmp"
            cache.mkdir(parents=True)
            temp_cache.mkdir()
            calls = []

            def references():
                calls.append(len(calls) + 1)
                if len(calls) == 1:
                    return [], []
                return [{
                    "path": str(temp_cache / "new-reference"),
                    "raw_path": str(temp_cache / "new-reference"),
                }], []

            plan = {
                "direct_delete": [
                    {"path": str(cache), "size_bytes": 0},
                    {"path": str(temp_cache), "size_bytes": 0},
                ],
                "archive_backup_then_delete": [],
                "worktree_migrations": [],
            }
            with patch.object(scan_codex, "open_handle_status", return_value=(False, "not open")):
                removed, skipped = apply_cleanup.apply_direct(
                    plan, home, fresh_reference_loader=references,
                )

            self.assertEqual(len(calls), 2)
            self.assertEqual([row["path"] for row in removed], [str(cache)])
            self.assertTrue(temp_cache.exists())
            self.assertIn("引用指向清理目标", skipped[0]["reason"])

    def test_direct_action_keeps_prior_success_when_later_reference_check_fails(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            cache = home / ".codex" / "cache"
            temp_cache = home / ".codex" / ".tmp"
            cache.mkdir(parents=True)
            temp_cache.mkdir()
            completed = []
            calls = 0

            def references():
                nonlocal calls
                calls += 1
                if calls == 1:
                    return [], []
                raise OSError("reference index unreadable")

            with patch.object(scan_codex, "open_handle_status", return_value=(False, "not open")):
                removed, skipped = apply_cleanup.apply_direct(
                    {
                        "direct_delete": [
                            {"path": str(cache), "size_bytes": 0},
                            {"path": str(temp_cache), "size_bytes": 0},
                        ],
                        "archive_backup_then_delete": [],
                        "worktree_migrations": [],
                    },
                    home,
                    fresh_reference_loader=references,
                    completed_records=completed,
                )

            self.assertIs(removed, completed)
            self.assertEqual([row["path"] for row in removed], [str(cache)])
            self.assertTrue(any("引用复核失败" in row["reason"] for row in skipped))

    def test_capacity_marks_each_unmeasured_eligible_path(self):
        plan = cleanup_plan.estimate_capacity(
            [],
            [{
                "path": "/tmp/archive",
                "eligible_paths": ["/tmp/archive/measured.jsonl", "/tmp/archive/missing.jsonl"],
                "eligible_bytes": 20,
            }],
            [],
            inventory=[{
                "path": "/tmp/archive/measured.jsonl",
                "identity": "1:2", "bytes": 10, "allocated_bytes": 4096,
            }],
            known_directories=["/tmp/archive"],
            human_bytes=scan_codex.human_bytes,
        )
        self.assertEqual(plan["unmeasured_paths"], ["/tmp/archive/missing.jsonl"])

    def test_candidate_entries_deduplicate_parent_child_and_hardlinked_files(self):
        plan = cleanup_plan.estimate_capacity(
            [
                {"path": "/tmp/project/output", "reason": "Confirmed generated output"},
                {"path": "/tmp/project/output/cache", "reason": "Regenerable cache"},
            ],
            [],
            [],
            inventory=[
                {"path": "/tmp/project/output", "identity": "dir:1", "bytes": 0,
                 "allocated_bytes": 4096, "directory": True},
                {"path": "/tmp/project/output/cache", "identity": "dir:2", "bytes": 0,
                 "allocated_bytes": 4096, "directory": True},
                {"path": "/tmp/project/output/cache/index", "identity": "1:10", "bytes": 20,
                 "allocated_bytes": 4096},
                {"path": "/tmp/project/output/cache/index-hardlink", "identity": "1:10", "bytes": 20,
                 "allocated_bytes": 4096},
                {"path": "/tmp/project/output/package", "identity": "1:11", "bytes": 30,
                 "allocated_bytes": 4096},
            ],
            known_directories=["/tmp/project/output", "/tmp/project/output/cache"],
            human_bytes=scan_codex.human_bytes,
        )
        entries = {row["path"]: row for row in plan["candidate_entries"]}
        self.assertEqual(plan["estimated_reclaimable_bytes"], 50)
        self.assertEqual(entries["/tmp/project/output/cache"]["logical_bytes"], 20)
        self.assertEqual(entries["/tmp/project/output"]["logical_bytes"], 30)
        self.assertEqual(entries["/tmp/project/output/cache"]["entity_count"], 1)
        self.assertEqual(plan["candidate_entry_counts"]["direct-delete"], 2)
        self.assertTrue(plan["candidate_entries_complete"])

    def test_execution_preflight_rechecks_new_session_activity(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            workspace = home / "project"
            target = workspace / "target"
            target.mkdir(parents=True)
            activity = {
                "coverage": "complete",
                "records": [{
                    "id": "new-session", "cwd": str(workspace),
                    "last_activity": time.time(), "archived": True,
                }],
            }
            item = {
                "path": str(target), "workspace_root": str(workspace),
                "git_state": "clean", "git_status_digest": "same",
            }
            with patch.object(apply_cleanup.worktree_activity, "load_thread_activity",
                              return_value=activity), \
                 patch.object(apply_cleanup.scan, "git_state", return_value="clean"), \
                 patch.object(apply_cleanup.scan, "git_status_snapshot",
                              return_value={"digest": "same"}):
                reason = apply_cleanup._fresh_project_preflight(
                    item, target, home, references=[],
                )
            self.assertIn("近 168 小时内有活动", reason)

    def test_execution_preflight_rechecks_new_path_reference(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            workspace = home / "project"
            target = workspace / "target"
            target.mkdir(parents=True)
            item = {
                "path": str(target), "workspace_root": str(workspace),
                "git_state": "clean", "git_status_digest": "same",
            }
            with patch.object(apply_cleanup.worktree_activity, "load_thread_activity",
                              return_value={"coverage": "complete", "records": []}), \
                 patch.object(apply_cleanup.scan, "git_state", return_value="clean"), \
                 patch.object(apply_cleanup.scan, "git_status_snapshot",
                              return_value={"digest": "same"}):
                reason = apply_cleanup._fresh_project_preflight(
                    item, target, home,
                    references=[{
                        "path": str(target / "new-reference.json"),
                        "raw_path": str(target / "new-reference.json"),
                    }],
                )
            self.assertIn("引用指向清理目标", reason)

    def test_post_action_retained_rank_uses_only_candidates_still_on_local_disk(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            codex = home / ".codex"
            candidate = codex / "cache" / "old"
            codex.mkdir()
            candidate.parent.mkdir()
            candidate.write_bytes(b"planned cache")
            (codex / "keep.bin").write_bytes(b"k" * 64)
            scan_result = {
                "confirmed_roots": [{
                    "path": str(codex), "source": "Codex fixed root",
                }],
                "top_retained_contents": [{"path": "initial"}],
            }
            plan = {
                "direct_delete": [{
                    "path": str(candidate), "default_action": "direct-delete",
                    "size_bytes": candidate.stat().st_size,
                }],
                "archive_backup_then_delete": [],
                "worktree_migrations": [],
            }

            before = apply_cleanup._refresh_retained_contents(
                scan_result, plan, home, [],
            )
            self.assertTrue(before["complete"])
            self.assertTrue(any(
                row["path"] == str(candidate)
                for retained in before["items"]
                for row in retained.get("policy_candidates_still_present", [])
            ))

            candidate.unlink()
            after = apply_cleanup._refresh_retained_contents(
                scan_result, plan, home, [],
            )
            self.assertTrue(after["complete"])
            self.assertFalse(any(
                row["path"] == str(candidate)
                for retained in after["items"]
                for row in retained.get("policy_candidates_still_present", [])
            ))

    def test_post_action_retained_refresh_reports_incomplete_measurement(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            codex = home / ".codex"
            codex.mkdir()
            with patch.object(
                apply_cleanup.scan.storage_discovery,
                "scan_large_files",
                return_value={
                    "all_files": [], "coverage_complete": False,
                    "errors": [{"path": str(codex), "reason": "read failed"}],
                    "skipped_mounts": [], "directories_scanned": 1,
                    "files_scanned": 0,
                },
            ):
                result = apply_cleanup._refresh_retained_contents(
                    {"confirmed_roots": [{"path": str(codex), "source": "Codex fixed root"}]},
                    {"direct_delete": [], "archive_backup_then_delete": [], "worktree_migrations": []},
                    home, [],
                )
            self.assertFalse(result["complete"])
            self.assertEqual(result["errors"][0]["reason"], "read failed")

    def test_archives_select_old_jsonl_and_zst_but_keep_recent_files(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            old_time = scan_codex.time.time() - 8 * 86400
            old_jsonl = root / 'old.jsonl'
            old_zst = root / 'old.jsonl.zst'
            recent = root / 'recent.jsonl'
            for path in (old_jsonl, old_zst, recent):
                path.write_bytes(b'archive')
            os.utime(old_jsonl, (old_time, old_time))
            os.utime(old_zst, (old_time, old_time))
            rows = scan_codex.old_archive_entries(root)
            self.assertEqual({row['name'] for row in rows}, {'old.jsonl', 'old.jsonl.zst'})

    def test_plan_separates_three_default_actions(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            data = {'items': [
                {'path': str(home / '.codex/cache'), 'default_action': 'direct-delete', 'tier': 'regenerable', 'size_bytes': 10},
                {'path': str(home / '.codex/archived_sessions'), 'default_action': 'backup-then-delete',
                 'archive_eligible_paths': [str(home / '.codex/archived_sessions/old.jsonl')],
                 'archive_eligible_bytes': 20, 'archive_eligible_count': 1, 'archive_retention_days': 7},
                {'path': str(home / '.codex/worktrees/final'), 'default_action': 'migrate-to-t1',
                 'size_bytes': 30, 'git_revision': 'abc', 'git_branch': 'feature'},
            ]}
            plan = apply_cleanup.build_plan(data, home)
            self.assertEqual(len(plan['direct_delete']), 1)
            self.assertEqual(len(plan['archive_backup_then_delete']), 1)
            self.assertEqual(len(plan['worktree_migrations']), 1)

    def test_direct_cleanup_only_removes_exact_regenerable_cache(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            cache = home / '.codex' / 'cache'
            cache.mkdir(parents=True)
            (cache / 'value.bin').write_bytes(b'x' * 1024)
            plan = {
                'direct_delete': [{'path': str(cache), 'size_bytes': 1024,
                                   'review_priority': '', 'retained_path': '', 'workspace_root': ''}],
                'archive_backup_then_delete': [], 'worktree_migrations': [],
            }
            with patch.object(scan_codex, 'open_handle_status', return_value=(False, 'idle')):
                removed, skipped = apply_cleanup.apply_direct(plan, home)
            self.assertFalse(cache.exists())
            self.assertEqual(len(removed), 1)
            self.assertEqual(skipped, [])

    def test_browser_cache_uses_exact_vault_operation(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            cache = home / "Library" / "Caches" / "Codex"
            cache.mkdir(parents=True)
            (cache / "cache.bin").write_bytes(b"x" * 32)
            plan = {
                "direct_delete": [{
                    "path": str(cache), "size_bytes": 32, "artifact_type": "Codex 浏览器缓存",
                    "cache_operation": "purge-browser-cache",
                }],
                "archive_backup_then_delete": [], "worktree_migrations": [],
            }
            with patch.object(scan_codex, "open_handle_status", return_value=(False, "idle")), \
                 patch.object(apply_cleanup, "run_vault", return_value={"kilobytes_before": 1}) as run_vault:
                removed, skipped = apply_cleanup.apply_direct(plan, home)

            self.assertEqual(skipped, [])
            self.assertEqual(removed[0]["method"], "verified-purge-browser-cache")
            self.assertEqual(removed[0]["bytes"], 1024)
            run_vault.assert_called_once_with(
                "purge-browser-cache", "--confirm-path", str(cache), "--permanent",
            )
            self.assertTrue(cache.is_dir())

    def test_old_codex_log_is_exactly_whitelisted_and_deleted(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            old_day = datetime.now(timezone.utc).date() - timedelta(days=9)
            root = home / "Library" / "Logs" / "com.openai.codex"
            log = root / old_day.strftime("%Y") / old_day.strftime("%m") / old_day.strftime("%d") / "old.log"
            recent = root / datetime.now(timezone.utc).strftime("%Y/%m/%d") / "recent.log"
            log.parent.mkdir(parents=True)
            recent.parent.mkdir(parents=True)
            log.write_bytes(b"old")
            recent.write_bytes(b"recent")
            old_mtime = time.time() - 9 * 86400
            os.utime(log, (old_mtime, old_mtime))
            self.assertTrue(apply_cleanup.cache_path_allowed(log, home))
            self.assertFalse(apply_cleanup.cache_path_allowed(recent, home))
            measured, error = scan_codex.safe_size(log)
            self.assertIsNone(error)

            plan = {
                "direct_delete": [{
                    "path": str(log), "size_bytes": 3,
                    "cache_operation": "purge-old-codex-log",
                }],
                "archive_backup_then_delete": [], "worktree_migrations": [],
            }
            with patch.object(scan_codex, "open_handle_status", return_value=(False, "idle")):
                removed, skipped = apply_cleanup.apply_direct(plan, home)

            self.assertEqual(skipped, [])
            self.assertEqual(removed[0]["bytes"], measured)
            self.assertFalse(log.exists())
            self.assertTrue(root.is_dir())
            self.assertTrue(recent.exists())

    def test_direct_cleanup_rejects_unlisted_directory(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            target = home / '.codex' / 'not-a-cache'
            target.mkdir(parents=True)
            path, reason = apply_cleanup.direct_candidate({
                'path': str(target), 'tier': 'regenerable', 'default_action': 'direct-delete',
            }, home)
            self.assertIsNone(path)
            self.assertIn('白名单', reason)

    def test_vault_archive_allowlist_includes_zst(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'one.jsonl.zst').write_bytes(b'z')
            (root / 'two.jsonl').write_bytes(b'j')
            self.assertEqual([path.name for path in vault.archive_files(root)], ['one.jsonl.zst', 'two.jsonl'])
            (root / 'metadata.txt').write_text('not a chat')
            with self.assertRaisesRegex(vault.VaultError, 'unexpected archive entry'):
                vault.archive_files(root)

    def test_capacity_deduplicates_parent_worktree_and_hardlinked_backup(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            worktree = home / '.codex' / 'worktrees' / 'task'
            build = worktree / 'build'
            build.mkdir(parents=True)
            (build / 'artifact').write_bytes(b'a' * 10)
            (worktree / 'source').write_bytes(b'b' * 20)
            backup = home / 'archive-copy'
            backup.parent.mkdir(exist_ok=True)
            os.link(build / 'artifact', backup)
            plan = apply_cleanup.build_plan({'items': [
                {'path': str(build), 'default_action': 'direct-delete', 'tier': 'regenerable', 'size_bytes': 10,
                 'review_priority': 'verified-regenerable-cache', 'regeneration_evidence': {
                     'source_entries': [str(worktree / 'source')],
                     'rebuild_command': 'test generator',
                     'rebuild_basis': 'source and generator are present',
                 }},
                {'path': str(backup.parent), 'default_action': 'backup-then-delete',
                 'backup_category': 'user-data', 'backup_eligible_paths': [str(backup)],
                 'backup_eligible_bytes': 10},
                {'path': str(worktree), 'default_action': 'migrate-to-t1', 'size_bytes': 30,
                 'association_group_id': 'group-test'},
            ]}, home)
            self.assertEqual(plan['estimated_reclaimable_bytes'], 30)
            self.assertEqual(plan['capacity']['estimated_categories']['direct_delete_bytes'], 10)
            self.assertEqual(plan['capacity']['estimated_categories']['backup_then_delete_bytes'], 0)
            self.assertEqual(plan['capacity']['estimated_categories']['worktree_move_bytes'], 20)

    def test_verified_duplicate_backup_is_revalidated_before_offload(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            keeper = home / 'project' / 'report.html'
            source = home / 'backups' / 'report-copy.html'
            keeper.parent.mkdir(parents=True)
            source.parent.mkdir(parents=True)
            content = b'finished duplicate' * 4096
            keeper.write_bytes(content)
            source.write_bytes(content)
            old = time.time() - 8 * 86400
            os.utime(keeper, (old, old))
            os.utime(source, (old, old))
            import hashlib
            evidence = {
                'sha256': hashlib.sha256(content).hexdigest(),
                'keep_path': str(keeper),
            }
            plan = {'archive_backup_then_delete': [{
                'path': str(source), 'home': str(home), 'eligible_paths': [str(source)],
                'eligible_bytes': len(content), 'retention_days': 7,
                'backup_category': 'user-data',
                'review_priority': 'verified-duplicate-backup',
                'retention_evidence': evidence,
            }]}
            calls = []
            def fake_vault(command, *args):
                calls.append((command, args))
                if command == 'backup':
                    return {'snapshot_id': 'snapshot-test', 'path': '/t1/snapshot'}
                source.unlink()
                return {'offloaded_files': 1, 'offloaded_bytes': len(content)}
            with patch.object(apply_cleanup, 'run_vault', side_effect=fake_vault), \
                 patch.object(apply_cleanup.scan, "open_handle_status", return_value=(False, "not open")):
                completed, skipped = apply_cleanup.apply_archives(plan)
            self.assertEqual(skipped, [])
            self.assertEqual(len(completed), 1)
            self.assertFalse(source.exists())
            self.assertEqual([item[0] for item in calls], ['backup', 'offload-user-data'])
            self.assertEqual(completed[0]['method'], 'verified-t1-backup-then-delete-duplicate')

    def test_closed_task_backup_is_revalidated_before_generic_offload(self):
        with TemporaryDirectory() as temp:
            source = Path(temp) / 'outputs' / 'final-report'
            source.mkdir(parents=True)
            marker = source / 'completion.json'
            marker.write_text('{"status":"completed"}')
            (source / 'report.html').write_text('report')
            old = time.time() - 8 * 86400
            for path in (source, marker, source / 'report.html'):
                os.utime(path, (old, old))
            calls = []

            def fake_vault(*args):
                calls.append(args)
                if args[0] == 'backup':
                    return {'snapshot_id': '20261015T010203Z-abcdef12', 'path': '/Volumes/T1/snapshot'}
                return {'offloaded_files': 2, 'offloaded_bytes': 6}

            plan = {'archive_backup_then_delete': [{
                'path': str(source), 'home': str(Path(temp)), 'eligible_paths': [str(source)], 'eligible_bytes': 6,
                'backup_category': 'user-data', 'retention_days': 7,
                'retention_evidence': {'completion_marker': {'path': str(marker)}},
            }]}
            with patch.object(apply_cleanup, 'run_vault', side_effect=fake_vault), \
                 patch.object(scan_codex, 'extract_static_references', return_value=[]):
                completed, skipped = apply_cleanup.apply_archives(plan)
            self.assertEqual(skipped, [])
            self.assertEqual(completed[0]['method'], 'verified-t1-backup-then-delete-closed-task-output')
            self.assertEqual(calls[0][0:4], ('backup', '--source', str(source), '--category'))
            self.assertIn('offload-user-data', calls[1])

    def test_backup_failure_keeps_the_local_source(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            source = home / "outputs" / "final-report"
            source.mkdir(parents=True)
            marker = source / "completion.json"
            marker.write_text('{"status":"completed"}')
            report = source / "report.html"
            report.write_text("final")
            old = time.time() - 8 * 86400
            for path in (source, marker, report):
                os.utime(path, (old, old))
            plan = {"archive_backup_then_delete": [{
                "path": str(source), "home": str(home),
                "eligible_paths": [str(source)], "eligible_bytes": 5,
                "backup_category": "user-data", "retention_days": 7,
                "retention_evidence": {"completion_marker": {"path": str(marker)}},
            }]}
            with patch.object(apply_cleanup, "run_vault",
                              side_effect=vault.VaultError("snapshot verification failed")), \
                 patch.object(apply_cleanup.scan, "open_handle_status",
                              return_value=(False, "not open")):
                completed, skipped = apply_cleanup.apply_archives(plan)
            self.assertEqual(completed, [])
            self.assertEqual(len(skipped), 1)
            self.assertEqual(report.read_text(), "final")


if __name__ == '__main__':
    import unittest
    unittest.main()
