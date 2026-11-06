from pathlib import Path
from tempfile import TemporaryDirectory
from datetime import datetime, timedelta, timezone
from unittest import TestCase, mock
import os
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import scan_context
import scan_codex as scan
import serve_codex_report as child_server


class CleanupPolicyTests(TestCase):
    def test_source_parse_failure_keeps_full_scan_coverage_unknown(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            codex = home / ".codex"
            codex.mkdir()
            (codex / "state.json").write_text("{}")
            result = scan.full_discovery(
                home, duplicate_hash=False, min_large_bytes=1,
                exclude_roots=[], scan_roots=[codex],
                project_discovery={
                    "roots": [{
                        "path": str(codex), "codex_source": True,
                        "evidence": "Codex fixed root",
                    }],
                    "issues": [{
                        "path": str(codex / "bad-state.json"),
                        "phase": "state-parse", "reason": "invalid source metadata",
                    }],
                    "references": [], "runtime_data": [],
                },
            )
            self.assertFalse(result["coverage"]["coverage_complete"])
            self.assertEqual(result["coverage"]["stages"]["source-extraction"], "partial")

    def test_capacity_and_file_count_reuse_the_current_inventory(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            context = scan_context.ScanContext(
                directory_sizes={
                    str(root): {
                        "logical_bytes": 4096, "file_count": 9,
                        "scan_complete": True,
                    },
                },
                path_sizes={
                    str(root): {
                        "logical_bytes": 4096, "file_count": 9,
                        "scan_complete": True,
                    },
                },
            )
            token = scan_context._CURRENT.set(context)
            try:
                with mock.patch.object(scan.os, "scandir",
                                       side_effect=AssertionError("inventory was walked twice")):
                    self.assertEqual(scan.safe_size(root), (4096, None))
                    self.assertEqual(scan.count_files(root), (9, None))
            finally:
                scan_context._CURRENT.reset(token)

    def test_workspace_artifact_classification_reuses_directory_parent_index(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            first = home / "project-one"
            second = home / "project-two"
            first_target = first / "target"
            second_target = second / "target"
            directories = [
                first, first / "src", first_target,
                second, second / "src", second_target,
            ]
            for path in directories:
                path.mkdir(parents=True, exist_ok=True)
            context = scan_context.ScanContext(directory_sizes={
                str(path): {"scan_complete": True} for path in directories
            })
            token = scan_context._CURRENT.set(context)
            try:
                inventory = tuple(context.directory_sizes)
                first_found = scan.discover_nested_dirs(first, inventory)
                parent_index = context.directory_children
                second_found = scan.discover_nested_dirs(second, inventory)
            finally:
                scan_context._CURRENT.reset(token)

            self.assertIn(first_target, first_found)
            self.assertIn(second_target, second_found)
            self.assertIs(parent_index, context.directory_children)
            self.assertEqual(
                sum(len(children) for children in (context.directory_children or {}).values()),
                len(directories),
            )

    def test_overlapping_workspace_roots_reuse_classification_but_rescan_pruned_worktrees(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            project = home / "project"
            nested_build = project / "module" / "build"
            linked_worktree = project / ".worktrees" / "old-task"
            linked_target = linked_worktree / "target"
            for path in (
                project,
                project / "module",
                nested_build,
                project / ".worktrees",
                linked_worktree,
                linked_target,
            ):
                path.mkdir(parents=True, exist_ok=True)

            context = scan_context.ScanContext(directory_sizes={
                str(path): {"scan_complete": True}
                for path in (
                    project,
                    project / "module",
                    nested_build,
                    project / ".worktrees",
                    linked_worktree,
                    linked_target,
                )
            })
            token = scan_context._CURRENT.set(context)
            try:
                inventory = tuple(context.directory_sizes)
                with mock.patch.object(
                    scan, "_inventory_cargo_output", return_value=False
                ) as cargo_probe:
                    project_results = scan.discover_nested_dirs(project, inventory)
                    worktree_results = scan.discover_nested_dirs(linked_worktree, inventory)
                    calls_after_worktree = cargo_probe.call_count
                    nested_results = scan.discover_nested_dirs(project / "module", inventory)
                    self.assertEqual(cargo_probe.call_count, calls_after_worktree)
            finally:
                scan_context._CURRENT.reset(token)

            self.assertEqual(project_results, [nested_build])
            self.assertEqual(worktree_results, [linked_target])
            self.assertEqual(nested_results, [nested_build])
            self.assertEqual(
                context.nested_dir_coverage[str(project / "module")],
                str(project),
            )
            self.assertEqual(
                context.nested_dir_coverage[str(linked_worktree)],
                str(linked_worktree),
            )

    def test_nested_artifact_discovery_uses_inventory_for_custom_cargo_target(self):
        with TemporaryDirectory() as temp:
            project = Path(temp)
            target = project / "build-output"
            fingerprint = target / "debug" / ".fingerprint"
            fingerprint.mkdir(parents=True)
            rustc_info = target / ".rustc_info.json"
            rustc_info.write_text("{}")
            directories = [project, target, target / "debug", fingerprint]
            context = scan_context.ScanContext(
                directory_sizes={
                    str(path): {"scan_complete": True} for path in directories
                },
                file_rows={
                    str(rustc_info): {
                        "path": str(rustc_info), "file_id": "1:10",
                        "logical_bytes": 2, "allocated_bytes": 4096,
                    },
                },
            )
            token = scan_context._CURRENT.set(context)
            try:
                with (
                    mock.patch.object(Path, "glob", side_effect=AssertionError("unexpected filesystem glob")),
                    mock.patch.object(scan, "cargo_output", side_effect=AssertionError("unexpected filesystem Cargo probe")),
                ):
                    found = scan.discover_nested_dirs(project, tuple(context.directory_sizes))
            finally:
                scan_context._CURRENT.reset(token)

            self.assertIn(target, found)

    def test_cache_evidence_reads_only_the_current_inventory(self):
        with TemporaryDirectory() as temp:
            project = Path(temp)
            cache = project / "__pycache__"
            cache.mkdir()
            source = project / "module.py"
            bytecode = cache / "module.pyc"
            source.write_text("value = 1\n")
            bytecode.write_bytes(b"bytecode")
            directories = [project, cache]
            context = scan_context.ScanContext(
                directory_sizes={
                    str(path): {"scan_complete": True} for path in directories
                },
                file_rows={
                    str(source): {
                        "path": str(source), "file_id": "1:10",
                        "logical_bytes": source.stat().st_size, "allocated_bytes": 4096,
                    },
                    str(bytecode): {
                        "path": str(bytecode), "file_id": "1:11",
                        "logical_bytes": bytecode.stat().st_size, "allocated_bytes": 4096,
                    },
                },
            )
            token = scan_context._CURRENT.set(context)
            try:
                with (
                    mock.patch.object(Path, "glob", side_effect=AssertionError("unexpected filesystem glob")),
                    mock.patch.object(Path, "rglob", side_effect=AssertionError("unexpected filesystem recursion")),
                ):
                    evidence = scan._cache_rebuild_evidence(cache)
            finally:
                scan_context._CURRENT.reset(token)

            self.assertEqual(evidence["kind"], "python-bytecode-cache")
            self.assertEqual(evidence["source_entries"], [str(source)])

    def test_codex_without_project_is_not_counted_as_unattributed(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            root = home / '.codex' / 'sessions'
            root.mkdir(parents=True)
            (root / 'session.jsonl').write_bytes(b'{}' * 20)
            result = scan.full_discovery(home, duplicate_hash=False, min_large_bytes=1000,
                                         exclude_roots=[], include_file_inventory=False)
            totals = result['totals']
            usage = result['usage_summary']
            self.assertGreater(totals['codex_logical_bytes'], 0)
            self.assertEqual(totals['unattributed_logical_bytes'], 0)
            self.assertGreater(usage['codex_without_project_logical_bytes'], 0)

    def test_small_files_are_kept_in_directory_total(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            directory = home / 'Documents' / 'ChatGPT' / 'TrollStore' / 'target'
            directory.mkdir(parents=True)
            for index in range(20):
                (directory / f'part-{index}.bin').write_bytes(b'x' * 200)
            project = directory.parent
            result = scan.full_discovery(home, duplicate_hash=False, min_large_bytes=1000,
                                         exclude_roots=[], include_file_inventory=False,
                                         scan_roots=[project],
                                         project_discovery={
                                             "roots": [{
                                                 "path": str(project),
                                                 "codex_source": True,
                                                 "evidence": "Codex test metadata",
                                             }],
                                             "issues": [], "references": [], "runtime_data": [],
                                         })
            row = next(item for item in result['directory_summary']
                       if Path(item['path']) in (directory, project))
            self.assertEqual(row['large_file_count'], 0)
            self.assertEqual(row['logical_bytes'], 4000)
            self.assertEqual(row['codex_logical_bytes'], 4000)

    def test_runtime_bundle_id_alias_does_not_expand_library_scope(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            path = home / 'Library' / 'Application Support' / 'com.slipstream.w4dj'
            path.mkdir(parents=True)
            (path / 'state.json').write_text('{}')
            result = scan.full_discovery(home, duplicate_hash=False, min_large_bytes=1000,
                                         exclude_roots=[], include_file_inventory=False)
            self.assertNotIn(str(path), result['scan_roots'])
            self.assertNotIn(str(path), [item['path'] for item in result['directory_summary']])

    def test_third_party_runtime_candidate_stays_unconfirmed(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            path = home / 'Library' / 'Application Support' / 'com.example.other-app'
            path.mkdir(parents=True)
            (path / 'data.bin').write_bytes(b'x' * 20)
            result = scan.full_discovery(home, duplicate_hash=False, min_large_bytes=1000,
                                         exclude_roots=[], include_file_inventory=False)
            self.assertNotIn(str(path), result['scan_roots'])
            self.assertNotIn(str(path), [item['path'] for item in result['directory_summary']])

    def test_full_discovery_does_not_enumerate_generic_application_support(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            data = home / 'Library' / 'Application Support' / 'Pet Studio'
            data.mkdir(parents=True)
            for index in range(4):
                (data / ('small-' + str(index))).write_bytes(b'x' * 50)
            result = scan.full_discovery(home, duplicate_hash=False, min_large_bytes=1000,
                                         exclude_roots=[], include_file_inventory=False)
            self.assertNotIn(str(data), [item['path'] for item in result['directory_summary']])

    def test_documents_chatgpt_is_not_an_implicit_scan_root(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            target = home / 'Documents' / 'ChatGPT'
            target.mkdir(parents=True)
            self.assertNotIn(target, [p for p, _, _ in scan.root_candidates(home)])

    def test_fixed_codex_cache_and_log_roots_are_included_without_walking_library(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            browser_cache = home / "Library" / "Caches" / "Codex"
            update_cache = (
                home / "Library" / "Caches" / "com.openai.codex"
                / "org.sparkle-project.Sparkle" / "Installation"
            )
            logs = home / "Library" / "Logs" / "com.openai.codex"
            unrelated = home / "Library" / "Caches" / "UnrelatedApp"
            for path in (browser_cache, update_cache, logs, unrelated):
                path.mkdir(parents=True)

            roots = {str(path): kind for path, _, kind in scan.root_candidates(home)}

            self.assertEqual(roots[str(browser_cache)], "codex-browser-cache")
            self.assertEqual(roots[str(update_cache)], "codex-update-cache")
            self.assertEqual(roots[str(logs)], "codex-logs")
            self.assertNotIn(str(unrelated), roots)
            self.assertNotIn(str(home / "Library"), roots)

    def test_only_old_dated_codex_logs_become_exact_cleanup_candidates(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            root = home / "Library" / "Logs" / "com.openai.codex"
            old_day = datetime.now(timezone.utc).date() - timedelta(days=9)
            old_log = root / old_day.strftime("%Y") / old_day.strftime("%m") / old_day.strftime("%d") / "old.log"
            recent_day = datetime.now(timezone.utc).date()
            recent_log = root / recent_day.strftime("%Y") / recent_day.strftime("%m") / recent_day.strftime("%d") / "recent.log"
            old_log.parent.mkdir(parents=True)
            recent_log.parent.mkdir(parents=True)
            old_log.write_bytes(b"old")
            recent_log.write_bytes(b"recent")
            old_mtime = time.time() - 9 * 86400
            os.utime(old_log, (old_mtime, old_mtime))

            context = scan_context.ScanContext(file_rows={
                str(old_log): {"modified_ns": int(old_mtime * 1_000_000_000)},
                str(recent_log): {"modified_ns": recent_log.stat().st_mtime_ns},
            })
            token = scan_context._CURRENT.set(context)
            try:
                items = []
                scan.scan_root(
                    {"user": "test", "home": temp, "platform": "macOS", "issues": [], "codex_roots": []},
                    root, "Codex logs", "codex-logs", items,
                )
            finally:
                scan_context._CURRENT.reset(token)

            self.assertEqual([item["path"] for item in items], [str(old_log)])
            self.assertEqual(items[0]["cache_operation"], "purge-old-codex-log")
            self.assertEqual(items[0]["default_action"], "direct-delete")

    def test_old_dependencies_retained_and_builds_require_retention_evidence(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ('node_modules', '.pnpm-store', '.venv', 'target', 'build'):
                path = root / name
                path.mkdir()
                old = time.time() - 86400 * 30
                os.utime(path, (old, old))
            user = {'user': 'test', 'home': temp, 'platform': 'macOS', 'issues': []}
            items = []
            with mock.patch.object(scan, 'safe_size', return_value=(1_000_000, None)):
                scan.add_project_artifacts(user=user, root=root, workspace_roots=[root], items=items)
            by_name = {item['name']: item for item in items}
            for name in ('node_modules', '.pnpm-store', '.venv'):
                self.assertEqual(by_name[name]['tier'], 'protected')
            for name in ('target', 'build'):
                self.assertEqual(by_name[name]['tier'], 'manual')
                self.assertTrue(by_name[name]['retained_path'])
            self.assertTrue(all(not item['trash_paths'] for item in items))

    def test_plugin_download_cache_is_not_actionable(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / '.codex'
            (root / 'plugins' / 'cache').mkdir(parents=True)
            user = {'user': 'test', 'home': temp, 'platform': 'macOS', 'issues': [], 'codex_roots': []}
            items = []
            with mock.patch.object(scan, 'safe_size', return_value=(1_000_000, None)), mock.patch.object(scan, 'open_handle_status', return_value=(False, 'idle')):
                scan.scan_root(user, root, 'Codex', 'codex', items)
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0]['tier'], 'protected')
            self.assertEqual(items[0]['trash_paths'], [])

    def test_cargo_registry_cache_is_retained(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            cache = root / 'cargo-home' / 'registry' / 'index' / 'index.crates.io' / '.cache'
            cache.mkdir(parents=True)
            user = {'user': 'test', 'home': temp, 'platform': 'macOS', 'issues': []}
            items = []
            with mock.patch.object(scan, 'safe_size', return_value=(43_000_000, None)):
                scan.add_project_artifacts(user=user, root=root, workspace_roots=[root], items=items)
            cargo = next(item for item in items if item['path'] == str(cache))
            self.assertEqual(cargo['artifact_type'], 'Cargo 下载缓存')
            self.assertEqual(cargo['tier'], 'protected')
            self.assertEqual(cargo['trash_paths'], [])

    def test_known_project_cache_is_direct_regenerable_with_real_evidence(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'module.py'
            source.write_text('print(1)\n')
            cache = root / '__pycache__'
            cache.mkdir()
            (cache / 'module.cpython-39.pyc').write_bytes(b'bytecode')
            user = {'user': 'test', 'home': temp, 'platform': 'macOS', 'issues': []}
            items = []
            with mock.patch.object(scan, 'safe_size', return_value=(1_000_000, None)):
                scan.add_project_artifacts(user=user, root=root, workspace_roots=[root], items=items)
            row = next(item for item in items if item['path'] == str(cache))
            self.assertEqual(row['tier'], 'regenerable')
            self.assertEqual(row['default_action'], 'direct-delete')
            self.assertEqual(row['review_priority'], 'verified-regenerable-cache')
            self.assertIn(str(source), row['source_entries'])
            self.assertNotIn('revalidated-by-scan', row['rebuild_basis'])

    def test_closed_old_task_output_enters_backup_then_delete(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / 'outputs' / 'final-report'
            output.mkdir(parents=True)
            (output / 'completion.json').write_text('{"status":"completed"}')
            (output / 'report.html').write_bytes(b'x' * 1024)
            old = time.time() - 8 * 86400
            for path in (output, output / 'completion.json', output / 'report.html', output.parent):
                os.utime(path, (old, old))
            user = {'user': 'test', 'home': temp, 'platform': 'macOS', 'issues': []}
            items = []
            with mock.patch.object(scan, 'open_handle_status', return_value=(False, 'idle')):
                scan.add_project_artifacts(user=user, root=root, workspace_roots=[root], items=items)
            row = next(item for item in items if item['path'] == str(output))
            self.assertEqual(row['default_action'], 'backup-then-delete')
            self.assertEqual(row['backup_category'], 'user-data')
            self.assertEqual(row['backup_eligible_paths'], [str(output)])
            self.assertIn('completion_marker', row['retention_evidence'])

    def test_referenced_old_task_output_is_not_auto_backup_candidate(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / 'outputs' / 'final-report'
            output.mkdir(parents=True)
            (output / 'completion.json').write_text('{"status":"completed"}')
            (output / 'report.html').write_bytes(b'x' * 1024)
            (root / 'package.json').write_text('{"output":"outputs/final-report"}')
            old = time.time() - 8 * 86400
            for path in (output, output / 'completion.json', output / 'report.html', output.parent, root / 'package.json'):
                os.utime(path, (old, old))
            user = {'user': 'test', 'home': temp, 'platform': 'macOS', 'issues': []}
            items = []
            with mock.patch.object(scan, 'open_handle_status', return_value=(False, 'idle')):
                scan.add_project_artifacts(user=user, root=root, workspace_roots=[root], items=items)
            self.assertFalse(any(item['path'] == str(output) and item.get('default_action') == 'backup-then-delete' for item in items))

    def test_verified_old_duplicate_backup_is_backup_then_delete_candidate(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            original = home / 'project' / 'report.html'
            duplicate = home / 'backups' / 'report-copy.html'
            original.parent.mkdir(parents=True)
            duplicate.parent.mkdir(parents=True)
            content = b'repeated finished report' * 4096
            original.write_bytes(content)
            duplicate.write_bytes(content)
            old = time.time() - 8 * 86400
            for path in (original, duplicate):
                os.utime(path, (old, old))
            import hashlib
            digest = hashlib.sha256(content).hexdigest()
            user = {'user': 'test', 'home': temp, 'platform': 'macOS', 'issues': []}
            items = []
            discovery = {'duplicates': {
                'verified': True,
                'groups': [{'sha256': digest, 'paths': [str(original), str(duplicate)]}],
            }}
            with mock.patch.object(scan, 'open_handle_status', return_value=(False, 'idle')):
                scan.add_verified_duplicate_backup_candidates(
                    user=user, home=home, discovery=discovery, items=items,
                )
            row = next(item for item in items if item['path'] == str(duplicate))
            self.assertEqual(row['default_action'], 'backup-then-delete')
            self.assertEqual(row['review_priority'], 'verified-duplicate-backup')
            self.assertEqual(row['retention_evidence']['keep_path'], str(original))

    def test_unverified_artifacts_do_not_inflate_candidate_total(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            (home / 'Documents' / 'ChatGPT' / 'Project' / 'target').mkdir(parents=True)
            old = time.time() - 86400 * 30
            os.utime(home / 'Documents' / 'ChatGPT' / 'Project' / 'target', (old, old))
            users = [{'user': 'test', 'home': temp, 'readable': True, 'codex_roots': [], 'issues': []}]
            with mock.patch.object(scan, 'user_homes', return_value=users), mock.patch.object(scan, 'active_process_snapshot', return_value=(False, [])), mock.patch.object(scan, 'safe_size', return_value=(1_000_000, None)):
                data = scan.build_data(
                    scope_home=home,
                    _account_lookup=lambda: ("mac", home),
                )
            self.assertEqual(data['summary']['candidate_bytes'], 0)
            self.assertEqual(data['users'][0]['candidate_bytes'], 0)
            self.assertEqual(data['summary']['manual_bytes'], 0)
            self.assertFalse(any(item['path'].endswith('/target') for item in data['items']))

    def test_full_discovery_reports_unknown_large_items_without_actions(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            large = home / '.codex' / 'unclassified' / 'deep' / 'item.data'
            large.parent.mkdir(parents=True)
            large.write_bytes(b'x' * 512)
            result = scan.full_discovery(home, duplicate_hash=True, min_large_bytes=128)
            self.assertTrue(result['enabled'])
            item = next(row for row in result['large_files'] if row['path'] == str(large))
            self.assertEqual(item['trash_paths'], [])
            self.assertEqual(result['duplicates']['groups'], [])
            self.assertIn('discovered_logical_bytes', result['totals'])
            self.assertIn('unattributed_logical_size', result['totals'])

    def test_compact_discovery_keeps_full_evidence_in_sidecar_files(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            first = home / '.codex' / 'first.bin'
            second = home / '.codex' / 'renamed.bin'
            first.parent.mkdir()
            first.write_bytes(b'x' * 512)
            second.write_bytes(b'x' * 512)
            inventory = home / 'work' / 'inventory.ndjson'
            duplicates = home / 'work' / 'duplicates.ndjson'
            result = scan.full_discovery(
                home,
                duplicate_hash=True,
                min_large_bytes=128,
                inventory_path=inventory,
                duplicate_evidence_path=duplicates,
                include_file_inventory=False,
            )
            self.assertEqual(result['file_inventory'], [])
            self.assertEqual(result['coverage']['all_file_inventory_count'], 2)
            self.assertTrue(inventory.exists())
            self.assertTrue(duplicates.exists())
            self.assertEqual(result['duplicates']['groups_count'], 1)
            self.assertEqual(result['duplicates']['groups_displayed_count'], 1)
            self.assertTrue(all(not item['trash_paths'] for item in result['duplicates']['groups']))

    def test_inventory_includes_hidden_files_and_deduplicates_hardlinks_in_retained_rank(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            codex = home / ".codex"
            codex.mkdir()
            hidden = codex / ".hidden-output"
            alias = codex / "visible-alias"
            hidden.write_bytes(b"x" * 512)
            os.link(hidden, alias)
            discovery = scan.full_discovery(
                home, duplicate_hash=False, min_large_bytes=1,
                include_file_inventory=True,
            )
            paths = {row["path"] for row in discovery["file_inventory"]}
            self.assertIn(str(hidden), paths)
            self.assertIn(str(alias), paths)
            retained = scan.top_retained_contents(
                discovery["file_inventory"],
                [{"path": str(codex), "codex_source": True, "evidence": "Codex fixed root"}],
                [{
                    "path": str(hidden), "default_action": "direct-delete",
                    "size_bytes": 512, "reason": "test candidate",
                }],
                home,
                include_cleanup_candidates=True,
            )
            self.assertEqual(sum(row["logical_bytes"] for row in retained), 512)
            self.assertEqual(sum(row["file_count"] for row in retained), 1)
            self.assertTrue(any(
                candidate["path"] == str(hidden)
                for row in retained
                for candidate in row.get("policy_candidates_still_present", [])
            ))

    def test_retained_ranking_assigns_cross_root_hardlink_to_specific_project_and_reads_manifest(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            codex = home / ".codex"
            project = home / "Documents" / "ChatGPT" / "confirmed-project"
            task = codex / "sessions" / "task-a"
            task.mkdir(parents=True)
            project.mkdir(parents=True)
            original = task / "result.bin"
            alias = project / "result.bin"
            original.write_bytes(b"artifact")
            os.link(original, alias)
            manifest = project / "package.json"
            manifest.write_text('{"name":"confirmed-widget"}')
            inventory = []
            for path in (original, alias, manifest):
                stat_result = path.stat()
                inventory.append({
                    "path": str(path),
                    "file_id": f"{stat_result.st_dev}:{stat_result.st_ino}",
                    "logical_bytes": stat_result.st_size,
                    "allocated_bytes": stat_result.st_blocks * 512,
                })

            retained = scan.top_retained_contents(
                inventory,
                [
                    {"path": str(codex), "codex_source": True, "evidence": "Codex fixed root"},
                    {"path": str(project), "codex_source": True, "evidence": "Codex project marker"},
                ],
                [],
                home,
            )

            self.assertEqual(retained[0]["path"], str(project))
            self.assertEqual(retained[0]["file_count"], 2)
            self.assertEqual(
                sum(row["logical_bytes"] for row in retained),
                original.stat().st_size + manifest.stat().st_size,
            )
            self.assertIn(
                sorted([str(alias), str(original)]),
                retained[0]["hard_link_paths"],
            )
            self.assertEqual(
                retained[0]["manifest_evidence"][0]["declared_name"],
                "confirmed-widget",
            )

    def test_invalid_and_empty_explicit_roots_are_not_promoted_to_full_scope(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            codex = home / ".codex"
            codex.mkdir()
            (codex / "state.json").write_text('{"state":"local"}')
            for roots in ([], [home.parent / "outside"]):
                with self.subTest(roots=roots):
                    result = scan.build_data(
                        scope_home=home,
                        full_discovery_enabled=True,
                        discovery_roots=roots,
                        _account_lookup=lambda: ("mac", home),
                    )
                    self.assertEqual(result["large_file_discovery"]["scan_roots"], [])
                    self.assertFalse(result["large_file_discovery"]["coverage"]["scope_complete"])

    def test_child_server_rejects_new_metadata_deletion(self):
        for field in ('source_references', 'metadata_candidates'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                child_server._validate_discovery_is_read_only({'large_file_discovery': {
                    'enabled': True, field: [{'path': '/tmp/example', 'trash_paths': ['/tmp/example']}]}})

    def test_child_server_rejects_discovery_only_action_record(self):
        with self.assertRaisesRegex(ValueError, '删除白名单'):
            child_server._validate_discovery_is_read_only({
                'large_file_discovery': {'enabled': True, 'trash_paths': [], 'large_files': []},
                'items': [{'path': '/tmp/unknown', 'discovery_origin': 'full-discovery', 'trash_paths': ['/tmp/unknown']}],
            })


if __name__ == '__main__':
    import unittest
    unittest.main()
