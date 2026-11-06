from pathlib import Path
from tempfile import TemporaryDirectory
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scan_codex
import storage_discovery


class CloudExclusionTests(unittest.TestCase):
    def test_full_discovery_passes_cloud_roots_to_walker(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            with patch.object(storage_discovery, "discover_project_roots", return_value=[]), \
                 patch.object(storage_discovery, "scan_large_files", side_effect=RuntimeError("captured")) as scan:
                with self.assertRaisesRegex(RuntimeError, "captured"):
                    scan_codex.full_discovery(home, duplicate_hash=False, min_large_bytes=1)
            excluded = scan.call_args.kwargs["exclude"]
            self.assertIn(home / "Library" / "Mobile Documents", excluded)
            self.assertIn(home / "Library" / "CloudStorage", excluded)

    def test_excluded_cloud_root_is_not_statted_or_traversed(self):
        with TemporaryDirectory() as temp:
            cloud = Path(temp) / "Library" / "Mobile Documents"
            cloud.mkdir(parents=True)
            (cloud / "private.bin").write_bytes(b"data")
            with patch.object(storage_discovery, "_safe_stat", side_effect=AssertionError("cloud accessed")):
                result = storage_discovery.scan_large_files([cloud], exclude=[cloud])
            self.assertEqual(result["all_files"], [])

    def test_source_reference_does_not_stat_cloud_target(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            state = home / ".codex" / "state.json"
            state.parent.mkdir()
            state.write_text("{}")
            cloud_target = home / "Library" / "Mobile Documents" / "private"
            original_stat = Path.stat

            def guarded_stat(path, *args, **kwargs):
                if path == cloud_target or cloud_target in path.parents:
                    raise AssertionError("cloud target accessed")
                return original_stat(path, *args, **kwargs)

            hint = {"raw_path": str(cloud_target), "source_role": "project", "field": "cwd"}
            with patch.object(storage_discovery, "discover_runtime_data", return_value=[]), \
                 patch.object(storage_discovery, "_walk_state_files", return_value=([state], [])), \
                 patch.object(storage_discovery, "_source_references", return_value=[hint]), \
                 patch.object(Path, "stat", guarded_stat):
                storage_discovery.discover_project_roots(home)
            self.assertEqual(hint["status"], "outside")

    def test_cloud_links_and_link_chains_are_not_followed(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            cloud = home / "Library" / "Mobile Documents"
            cloud.mkdir(parents=True)
            (cloud / "private").write_text("private")
            direct = home / "direct"
            direct.symlink_to(cloud / "private")
            chain = home / "chain"
            chain.symlink_to(direct)
            for link in (direct, chain):
                result = storage_discovery.safe_local_link(link, home, [cloud])
                self.assertIsNone(result["resolved_target"])
                self.assertIsNone(result["target_exists"])

    def test_cloud_path_with_parent_components_is_rejected_before_stat(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            cloud = home / "Library" / "Mobile Documents"
            disguised = home / "other" / ".." / "Library" / "Mobile Documents" / "private"
            with patch.object(Path, "lstat", side_effect=AssertionError("cloud accessed")):
                self.assertIsNone(storage_discovery.local_path_status(disguised, home, [cloud]))

    def test_full_discovery_avoids_cloud_contents_and_reports_exclusion(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            cloud = home / "Library" / "Mobile Documents"
            cloud.mkdir(parents=True)
            (cloud / "private.ipa").write_bytes(b"private")
            local = home / "Documents" / "ChatGPT" / "project"
            local.mkdir(parents=True)
            (local / "local.txt").write_text("local")
            (local / "cloud-link").symlink_to(cloud / "private.ipa")
            original_scandir = os.scandir
            original_stat, original_lstat, original_open = Path.stat, Path.lstat, Path.open

            def reject_cloud(path):
                if path == cloud or cloud in path.parents:
                    raise AssertionError("cloud path accessed")

            def guarded_stat(path, *args, **kwargs):
                reject_cloud(path)
                return original_stat(path, *args, **kwargs)

            def guarded_lstat(path, *args, **kwargs):
                reject_cloud(path)
                return original_lstat(path, *args, **kwargs)

            def guarded_open(path, *args, **kwargs):
                reject_cloud(path)
                return original_open(path, *args, **kwargs)

            def guarded_scandir(path):
                candidate = Path(path)
                if candidate == cloud or cloud in candidate.parents:
                    raise AssertionError("cloud directory traversed")
                return original_scandir(path)

            with patch.object(os, "scandir", guarded_scandir), \
                 patch.object(Path, "stat", guarded_stat), \
                 patch.object(Path, "lstat", guarded_lstat), \
                 patch.object(Path, "open", guarded_open), \
                 patch.object(storage_discovery, "_probe_mounted_images", return_value=(set(), [])), \
                 patch.object(storage_discovery, "_probe_open_paths", return_value=({}, [])), \
                 patch.object(storage_discovery, "_probe_processes", return_value=({}, [])):
                result = scan_codex.full_discovery(
                    home,
                    duplicate_hash=False,
                    min_large_bytes=1,
                    scan_roots=[local],
                    project_discovery={
                        "roots": [{
                            "path": str(local), "codex_source": True,
                            "evidence": "Codex test metadata",
                        }],
                        "issues": [], "references": [], "runtime_data": [],
                    },
                )
            paths = [row["path"] for row in result["large_files"]]
            self.assertIn(str(local / "local.txt"), paths)
            self.assertNotIn(str(cloud / "private.ipa"), paths)
            self.assertIn(str(cloud), [row["path"] for row in result["coverage"]["excluded_roots"]])
            self.assertTrue(any(row["target_exists"] is None for row in result["coverage"]["symlinks"]))

    def test_documents_containers_are_not_implicit_project_roots(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            codex = home / "Documents" / "Codex"
            chatgpt = home / "Documents" / "ChatGPT"
            (codex / "unrelated-project").mkdir(parents=True)
            (chatgpt / "unrelated-project").mkdir(parents=True)
            self.assertEqual(storage_discovery.discover_project_roots(home), [])

    def test_documents_entry_search_requires_codex_project_marker_and_stops_at_depth_three(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            marked = home / "Documents" / "Codex" / "group" / "project"
            unmarked = home / "Documents" / "ChatGPT" / "ordinary"
            too_deep = home / "Documents" / "ChatGPT" / "one" / "two" / "three" / "four"
            (marked / ".codex").mkdir(parents=True)
            (marked / ".codex" / "config.toml").write_text('model = "test"\n')
            unmarked.mkdir(parents=True)
            (too_deep / ".codex").mkdir(parents=True)
            (too_deep / ".codex" / "config.toml").write_text('model = "test"\n')
            roots = storage_discovery.discover_project_roots(home)
            by_path = {row["path"]: row for row in roots}
            self.assertIn(str(marked), by_path)
            self.assertEqual(by_path[str(marked)]["source_file"], str(marked / ".codex" / "config.toml"))
            self.assertNotIn(str(unmarked), by_path)
            self.assertNotIn(str(too_deep), by_path)

    def test_explicit_session_cwd_selects_only_its_project(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            project = home / "Documents" / "ChatGPT" / "2026-11-04" / "one-task"
            project.mkdir(parents=True)
            (project / "output.bin").write_bytes(b"task")
            state = home / ".codex" / "sessions" / "current.jsonl"
            state.parent.mkdir(parents=True)
            state.write_text('{"type":"session_meta","payload":{"id":"task-1","cwd":"' + str(project) + '"}}\n')
            with patch.object(storage_discovery, "discover_runtime_data", return_value=[]):
                roots = storage_discovery.discover_project_roots(home)
            paths = {row["path"] for row in roots}
            self.assertIn(str(project), paths)
            self.assertNotIn(str(home / "Documents" / "ChatGPT"), paths)
            self.assertNotIn(str(home / "Documents" / "ChatGPT" / "2026-11-04"), paths)

    def test_registered_worktrees_of_confirmed_project_are_included(self):
        with TemporaryDirectory() as temp:
            home = Path(temp).resolve()
            project = home / "Documents" / "ChatGPT" / "repo"
            project.mkdir(parents=True)

            def git(*args: str) -> None:
                subprocess.run(
                    ["git", "-C", str(project), *args],
                    check=True, capture_output=True, text=True,
                )

            git("init", "-q")
            git("config", "user.email", "test@example.invalid")
            git("config", "user.name", "Test")
            (project / "source.txt").write_text("source\n")
            git("add", "source.txt")
            git("commit", "-qm", "initial")
            codex_worktree = home / ".codex" / "worktrees" / "repo" / "one"
            project_worktree = project / ".worktrees" / "two"
            codex_worktree.parent.mkdir(parents=True)
            project_worktree.parent.mkdir(parents=True)
            git("worktree", "add", "-qb", "codex-one", str(codex_worktree))
            git("worktree", "add", "-qb", "project-two", str(project_worktree))
            session = home / ".codex" / "sessions" / "recent.jsonl"
            session.parent.mkdir(parents=True, exist_ok=True)
            session.write_text(
                '{"type":"session_meta","payload":{"id":"repo-session","cwd":"'
                + str(project) + '"}}\n'
            )
            roots = storage_discovery.discover_project_roots(home)
            paths = {row["path"] for row in roots}
            self.assertIn(str(project), paths)
            self.assertIn(str(codex_worktree), paths)
            self.assertIn(str(project_worktree), paths)

    def test_single_file_reference_does_not_expand_to_parent(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            project = home / "Documents" / "ChatGPT" / "project"
            project.mkdir(parents=True)
            target = project / "result.db"
            target.write_bytes(b"result")
            state = home / ".codex" / "config.toml"
            state.parent.mkdir(parents=True)
            with patch.object(
                storage_discovery, "_source_references",
                return_value=[{
                    "raw_path": str(target), "field": "projects.test.path",
                    "source_file": str(state), "source_role": "project",
                    "record_id": "test", "path_base": str(state.parent),
                }],
            ), patch.object(storage_discovery, "_walk_state_files", return_value=([state], [])):
                roots = storage_discovery.discover_project_roots(home)
            paths = {Path(row["path"]) for row in roots}
            self.assertIn(target, paths)
            self.assertNotIn(project, paths)

    def test_broad_session_cwd_is_rejected_as_project_root(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            container = home / "Documents" / "Codex"
            container.mkdir(parents=True)
            state = home / ".codex" / "sessions" / "broad.jsonl"
            state.parent.mkdir(parents=True)
            state.write_text(
                '{"type":"session_meta","payload":{"id":"broad","cwd":"'
                + str(container) + '"}}\n'
            )
            roots = storage_discovery.discover_project_roots(home)
            self.assertNotIn(str(container), {row["path"] for row in roots})
            self.assertTrue(any(
                issue.get("code") == "non-project-container"
                for issue in storage_discovery.discover_project_roots.last_issues
            ))

if __name__ == "__main__":
    unittest.main()
