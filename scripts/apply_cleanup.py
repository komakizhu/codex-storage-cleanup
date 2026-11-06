#!/usr/bin/env python3
"""Apply the Codex storage skill's three default cleanup policies.

The scanner remains read-only.  This entry point is the explicit execution
boundary: it rescans the current user, revalidates every exact path, deletes
only verified regenerable items, moves only fully checked worktree groups idle over 168 hours to T1 with an old-path
symlink, and snapshots archived sessions before removing
only files older than the retention window.
"""

from __future__ import annotations

import argparse
from bisect import bisect_left
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time
from typing import Any, Callable

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import scan_codex as scan
import scan_budget
import cleanup_plan
import build_evidence
import worktree_activity
from move_worktree import move_worktree, move_worktree_group
from vault import VaultError

try:
    import pwd
except ImportError:
    pwd = None


ARCHIVE_RETENTION_DAYS = 7
SAFE_CACHE_RELATIVES = {
    Path(".codex/cache"),
    Path(".codex/.tmp"),
}
SAFE_APP_CACHE_RELATIVES = {
    Path("Crashpad/pending"),
    Path("Default/Cache"),
    Path("Default/Code Cache"),
    Path("Default/GPUCache"),
    Path("GraphiteDawnCache"),
    Path("GPUPersistentCache"),
    Path("component_crx_cache"),
    Path("extensions_crx_cache"),
    Path("Safe Browsing"),
}
BUILD_NAMES = {
    "target", "dist", "build", ".build", ".vite", ".next", "out", "coverage",
    "__pycache__", ".pytest_cache", ".cache",
}


class CleanupError(Exception):
    pass


def under(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def exact_path(value: str | Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise CleanupError(f"路径必须是绝对路径：{path}")
    return path


def json_from_process(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    if result.returncode:
        message = (result.stderr or result.stdout).strip()
        raise CleanupError(message or f"命令失败，退出码 {result.returncode}")
    for line in reversed(result.stdout.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                return value
    raise CleanupError("命令没有返回可解析的 JSON 结果")


def run_vault(*args: str) -> dict[str, Any]:
    vault = SCRIPT_DIR / "vault.py"
    result = subprocess.run(
        [sys.executable, str(vault), *args],
        capture_output=True,
        text=True,
        timeout=600,
    )
    return json_from_process(result)


def cache_path_allowed(path: Path, home: Path) -> bool:
    allowed = False
    for relative in SAFE_CACHE_RELATIVES:
        if path == home / relative:
            allowed = True
            break
    if path in {
        home / "Library" / "Caches" / "Codex",
        home / "Library" / "Caches" / "com.openai.codex"
        / "org.sparkle-project.Sparkle" / "Installation",
    }:
        allowed = True
    if _is_eligible_codex_log(path, home):
        allowed = True
    app_roots = (
        home / "Library" / "Application Support" / "Codex",
        home / "Library" / "Application Support" / "OpenAI" / "Codex",
    )
    allowed = allowed or any(
        path == root / relative
        for root in app_roots for relative in SAFE_APP_CACHE_RELATIVES
    )
    if not allowed:
        return False
    return scan.storage_discovery.local_path_status(
        path, home,
        (home / "Library" / "Mobile Documents", home / "Library" / "CloudStorage"),
    ) is True


def _is_eligible_codex_log(path: Path, home: Path) -> bool:
    root = home / "Library" / "Logs" / "com.openai.codex"
    if root.is_symlink() or path.is_symlink() or not under(path, root) or path == root:
        return False
    try:
        relative = path.relative_to(root)
        if len(relative.parts) != 4 or path.suffix != ".log":
            return False
        year, month, day, _name = relative.parts
        folder_date = datetime.strptime(f"{year}-{month}-{day}", "%Y-%m-%d").date()
        stat_result = path.lstat()
        cutoff = datetime.now(timezone.utc).timestamp() - ARCHIVE_RETENTION_DAYS * 86400
        home_device = home.stat().st_dev
        if stat_result.st_dev != home_device:
            return False
        for index, _part in enumerate(relative.parts[:-1], start=1):
            parent = root.joinpath(*relative.parts[:index])
            if parent.is_symlink() or not parent.is_dir() or parent.stat().st_dev != home_device:
                return False
    except (OSError, ValueError):
        return False
    return (
        folder_date < datetime.fromtimestamp(cutoff, tz=timezone.utc).date()
        and stat.S_ISREG(stat_result.st_mode)
        and stat_result.st_uid == os.getuid()
        and stat_result.st_mtime < cutoff
    )


def is_verified_old_build(item: dict[str, Any], path: Path, home: Path) -> bool:
    if item.get("review_priority") != "delete-old-build":
        return False
    if item.get("default_action") != "direct-delete":
        return False
    artifact_type = str(item.get("artifact_type") or "")
    known_generated = path.name in BUILD_NAMES or path.name.startswith("target-")
    known_generated = known_generated or artifact_type in {"Rust 编译产物", "前端构建产物", "Swift/Xcode 编译产物"}
    if not known_generated or not item.get("source_entries") or not item.get("rebuild_basis"):
        return False
    workspace = exact_path(item.get("workspace_root", "")) if item.get("workspace_root") else None
    keeper = exact_path(item.get("retained_path", "")) if item.get("retained_path") else None
    if workspace is None or keeper is None or keeper == path:
        return False
    return (
        under(path, home)
        and under(path, workspace)
        and path != workspace
        and keeper.exists()
        and path.name not in {"node_modules", ".pnpm-store", ".venv", "venv", "env"}
    )


def _valid_rebuild_evidence(item: dict[str, Any], path: Path) -> tuple[bool, str]:
    evidence = item.get("regeneration_evidence") or {}
    source_entries = item.get("source_entries") or evidence.get("source_entries")
    rebuild_basis = item.get("rebuild_basis") or evidence.get("rebuild_basis")
    rebuild_command = item.get("rebuild_command") or evidence.get("rebuild_command")
    if not source_entries or not rebuild_basis or not rebuild_command:
        return False, "缺少输入源码、生成方法或重建依据"
    if any(token in str(rebuild_basis) for token in ("待核实", "revalidated-by-scan", "placeholder")):
        return False, "重建依据仍是占位或待核实内容"
    if any(token in str(rebuild_command) for token in ("待查", "待核实", "revalidated-by-scan", "placeholder")):
        return False, "重建方法仍是占位或待核实内容"
    for raw in source_entries:
        try:
            source = exact_path(raw)
        except CleanupError:
            return False, f"源码证据路径不是绝对路径：{raw}"
        if path == source or under(path, source):
            return False, "源码入口位于拟删目录内"
        if not source.exists() or source.is_symlink():
            return False, f"源码或配置证据已不存在：{source}"
    return True, "已重新核对源码、配置和实际重建方法"


def _revalidate_build_evidence(item: dict[str, Any], path: Path) -> tuple[bool, str]:
    try:
        fresh = build_evidence.inspect_artifact(path)
    except (ValueError, OSError, TypeError, KeyError) as error:
        return False, f"构建证据重新核对失败：{error}"
    planned_keeper = item.get("retained_path")
    if planned_keeper:
        try:
            keeper = exact_path(planned_keeper)
        except CleanupError:
            return False, "项目最新完整构建路径缺少可验证的绝对路径"
        if keeper == path:
            return False, "拟删除项变成了项目保留构建"
        if not keeper.exists():
            return False, "项目最新完整构建已不存在"
    item.update(fresh)
    return _valid_rebuild_evidence(item, path)


def direct_candidate(item: dict[str, Any], home: Path) -> tuple[Path | None, str]:
    if item.get("default_action") != "direct-delete" or item.get("tier") != "regenerable":
        return None, "不是默认可再生清理项"
    raw = item.get("path")
    if not raw:
        return None, "没有精确路径"
    path = exact_path(raw)
    if not under(path, home) or path == home or path.is_symlink():
        return None, "路径越过当前用户主目录或是符号链接"
    if not path.exists():
        return None, "路径已经不存在"
    if item.get("review_priority") == "delete-old-build":
        valid, reason = _revalidate_build_evidence(item, path)
        if not valid or not is_verified_old_build(item, path, home):
            return None, reason or "路径不在已核实旧构建白名单"
    elif cache_path_allowed(path, home):
        pass
    else:
        valid, reason = _valid_rebuild_evidence(item, path)
        if not valid:
            return None, "路径不在可再生缓存白名单，且" + reason
    try:
        if path.stat().st_uid != os.getuid():
            return None, "路径不属于当前用户"
    except (AttributeError, OSError):
        pass
    active, note = scan.open_handle_status(path)
    if active is not False:
        return None, note or "打开状态未知或仍在使用"
    return path, "已重新核对：精确路径、非链接、当前用户、没有打开句柄"


def remove_direct(path: Path) -> int:
    measured, error = scan.safe_size(path, timeout=30)
    if measured is None:
        raise CleanupError(f"删除前无法完整测量路径：{error or path}")
    mode = path.lstat().st_mode
    if stat.S_ISDIR(mode):
        shutil.rmtree(path)
    elif stat.S_ISREG(mode):
        path.unlink()
    else:
        raise CleanupError(f"拒绝删除特殊文件：{path}")
    return int(measured)


def _entity_size(path: Path) -> int:
    try:
        stat_result = path.lstat()
        return int(stat_result.st_size)
    except OSError:
        return 0


def _file_entities(path: Path, fallback_size: int = 0) -> list[dict[str, Any]]:
    """Return logical file entities, deduplicated later by device/inode."""
    if not path.exists() or path.is_symlink():
        return [{"identity": f"virtual:{path}", "path": str(path), "bytes": int(fallback_size), "virtual": True}]
    try:
        if path.is_file():
            stat_result = path.lstat()
            identity = f"{stat_result.st_dev}:{stat_result.st_ino}" if stat_result.st_ino else f"path:{path}"
            return [{"identity": identity, "path": str(path), "bytes": _entity_size(path), "virtual": False}]
        if not path.is_dir():
            return []
    except OSError:
        return [{"identity": f"virtual:{path}", "path": str(path), "bytes": int(fallback_size), "virtual": True}]
    entities: list[dict[str, Any]] = []
    try:
        for current, dirs, files in os.walk(path, followlinks=False):
            current_path = Path(current)
            dirs[:] = [name for name in dirs if not (current_path / name).is_symlink()]
            for name in files:
                child = current_path / name
                if child.is_symlink():
                    continue
                try:
                    stat_result = child.lstat()
                except OSError:
                    continue
                identity = f"{stat_result.st_dev}:{stat_result.st_ino}" if stat_result.st_ino else f"path:{child}"
                entities.append({"identity": identity, "path": str(child), "bytes": _entity_size(child), "virtual": False})
    except OSError:
        return [{"identity": f"virtual:{path}", "path": str(path), "bytes": int(fallback_size), "virtual": True}]
    if not entities:
        return [{"identity": f"virtual:{path}", "path": str(path), "bytes": int(fallback_size), "virtual": True}]
    return entities


def _plan_entities(
    row: dict[str, Any],
    inventory_index: tuple[list[str], dict[str, dict[str, Any]]] | None = None,
    known_directories: set[str] | None = None,
) -> list[dict[str, Any]]:
    eligible = list(row.get("eligible_paths") or [])
    targets = eligible or [row["path"]]
    if inventory_index is not None:
        sorted_paths, records_by_path = inventory_index
        entities: list[dict[str, Any]] = []
        for raw_path in targets:
            path_text = str(exact_path(raw_path))
            exact = records_by_path.get(path_text)
            if exact is not None and not exact.get("directory"):
                entities.append(dict(exact))
                continue
            if exact is not None and exact.get("directory"):
                path_text = str(Path(path_text).absolute())
            prefix = path_text.rstrip(os.sep) + os.sep
            index = bisect_left(sorted_paths, prefix)
            while index < len(sorted_paths) and sorted_paths[index].startswith(prefix):
                entities.append(dict(records_by_path[sorted_paths[index]]))
                index += 1
            if not entities and known_directories is not None and path_text in known_directories:
                continue
        return entities
    if eligible:
        entities: list[dict[str, Any]] = []
        for path_text in eligible:
            entities.extend(_file_entities(exact_path(path_text)))
        if entities and all(item.get("virtual") for item in entities):
            declared = int(row.get("eligible_bytes") or 0)
            if declared:
                share = declared // len(entities)
                remainder = declared - share * len(entities)
                for index, entity in enumerate(entities):
                    entity["bytes"] = share + (remainder if index == 0 else 0)
        return entities
    return _file_entities(exact_path(row["path"]), int(row.get("size_bytes") or 0))


def _estimate_capacity(
    direct: list[dict[str, Any]],
    backups: list[dict[str, Any]],
    worktrees: list[dict[str, Any]],
    inventory: list[dict[str, Any]] | None = None,
    known_directories: list[str] | None = None,
) -> dict[str, Any]:
    """Allocate each logical entity to one final action, including hardlinks."""
    rows: list[tuple[str, dict[str, Any]]] = []
    rows.extend(("direct-delete", row) for row in direct)
    rows.extend(("backup-then-delete", row) for row in backups)
    rows.extend(("migrate-to-t1", row) for row in worktrees)
    priority = {"direct-delete": 0, "backup-then-delete": 1, "migrate-to-t1": 2}
    rows.sort(key=lambda pair: (priority[pair[0]], -len(Path(pair[1]["path"]).parts), pair[1]["path"]))
    assigned: set[str] = set()
    virtual_claims: list[tuple[Path, int]] = []
    buckets = {"direct-delete": 0, "backup-then-delete": 0, "migrate-to-t1": 0}
    counts = {key: 0 for key in buckets}
    records_by_path = {
        str(Path(row["path"]).absolute()): {
            "identity": str(row.get("identity") or row["path"]),
            "path": str(Path(row["path"]).absolute()),
            "bytes": int(row.get("bytes") or 0),
            "allocated_bytes": row.get("allocated_bytes"),
            "virtual": False,
            "directory": bool(row.get("directory")),
        }
        for row in (inventory or [])
        if row.get("path")
    }
    inventory_index = (
        sorted(records_by_path),
        records_by_path,
    ) if inventory is not None else None
    missing_paths: set[str] = set()
    known_directory_set = {str(Path(value).absolute()) for value in (known_directories or [])}
    for action, row in rows:
        entities = _plan_entities(row, inventory_index, known_directory_set)
        target_paths = row.get("eligible_paths") or [row.get("path", "")]
        if inventory_index is not None and not entities and not any(
            str(Path(value).absolute()) in known_directory_set
            or str(Path(value).absolute()) in records_by_path
            for value in target_paths if value
        ):
            missing_paths.add(str(row.get("path") or ""))
        for entity in entities:
            identity = str(entity["identity"])
            amount = int(entity.get("bytes") or 0)
            if identity in assigned:
                continue
            if entity.get("virtual"):
                entity_path = Path(entity["path"])
                covered = sum(size for child, size in virtual_claims if child.is_relative_to(entity_path))
                amount = max(amount - covered, 0)
                if amount:
                    virtual_claims.append((entity_path, amount))
            if amount <= 0:
                assigned.add(identity)
                continue
            assigned.add(identity)
            buckets[action] += amount
            counts[action] += 1
    total = sum(buckets.values())
    return {
        "basis": (
            "复用本次扫描文件清单；同一 device/inode 只计一次；父工作树和内部候选按执行顺序分摊"
            if inventory_index is not None else
            "测试/兼容调用按精确路径展开文件实体；同一 device/inode 只计一次"
        ),
        "inventory_reused": inventory_index is not None,
        "unmeasured_paths": sorted(missing_paths),
        "estimated_reclaimable_bytes": total,
        "estimated_reclaimable_size": scan.human_bytes(total),
        "estimated_categories": {
            "direct_delete_bytes": buckets["direct-delete"],
            "direct_delete_size": scan.human_bytes(buckets["direct-delete"]),
            "backup_then_delete_bytes": buckets["backup-then-delete"],
            "backup_then_delete_size": scan.human_bytes(buckets["backup-then-delete"]),
            "worktree_move_bytes": buckets["migrate-to-t1"],
            "worktree_move_size": scan.human_bytes(buckets["migrate-to-t1"]),
        },
        "entity_counts": counts,
        "physical_reclaimable": "未知：APFS 克隆、快照、硬链接之外的共享空间需要执行后测量",
    }


def _stable_file_digest(path: Path) -> str:
    before = path.stat()
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    after = path.stat()
    if (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    ):
        raise CleanupError(f"文件在重复校验期间发生变化：{path}")
    return digest.hexdigest()


def build_plan(data: dict[str, Any], home: Path) -> dict[str, Any]:
    shared = data.get("cleanup_plan")
    if isinstance(shared, dict):
        return shared
    return cleanup_plan.build_plan(
        data,
        home,
        human_bytes=scan.human_bytes,
        file_entities=_file_entities,
    )


def _paths_overlap(left: Path, right: Path) -> bool:
    return under(left, right) or under(right, left)


def _fresh_scope_references(home: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    roots = scan.storage_discovery.discover_project_roots(home)
    issues = [
        dict(issue) for issue in getattr(scan.storage_discovery.discover_project_roots, "last_issues", [])
        if issue.get("severity") != "info"
    ]
    project_paths: list[Path] = []
    seen: set[str] = set()
    for row in roots:
        raw = row.get("path")
        if not row.get("codex_source") or not raw:
            continue
        path = Path(raw).absolute()
        if path == home / ".codex" or path.is_symlink() or not path.is_dir():
            continue
        key = str(path)
        if key not in seen:
            seen.add(key)
            project_paths.append(path)
    references = list(
        getattr(scan.storage_discovery.discover_project_roots, "last_references", [])
    )
    references.extend(worktree_activity.extract_static_references(project_paths))
    issues.extend(getattr(worktree_activity.extract_static_references, "last_issues", []))
    return references, issues


def _fresh_project_preflight(
    item: dict[str, Any],
    target: Path,
    home: Path,
    *,
    references: list[dict[str, Any]] | None = None,
    reference_issues: list[dict[str, Any]] | None = None,
) -> str | None:
    """Recheck project activity, Git state and references immediately before action."""
    blocking_issues = [
        issue for issue in (reference_issues or [])
        if issue.get("severity") != "info"
    ]
    if blocking_issues:
        first = blocking_issues[0]
        return f"全范围引用复核不完整：{first.get('path') or first.get('source_file') or ''} {first.get('reason') or ''}".strip()
    raw_workspace = item.get("workspace_root")
    if not raw_workspace:
        current_refs = references or []
        for reference in current_refs:
            raw = reference.get("raw_path") or reference.get("path")
            if not raw:
                return "发现无法解释的路径引用；保留清理目标"
            path = Path(os.path.expanduser(str(raw)))
            if not path.is_absolute() and reference.get("path_base"):
                path = Path(reference["path_base"]) / path
            if _paths_overlap(path.absolute(), target):
                return f"当前项目引用指向清理目标或其父子路径：{path}"
        return None
    try:
        workspace = exact_path(raw_workspace)
    except CleanupError as error:
        return str(error)
    if (
        not under(workspace, home)
        or workspace == home
        or not workspace.is_dir()
        or workspace.is_symlink()
    ):
        return "项目工作区已消失、越界或经过符号链接"

    activity = worktree_activity.load_thread_activity(home)
    if activity.get("coverage") != "complete":
        return "当前会话活动索引不完整；项目清理状态未知"
    now = time.time()
    for row in activity.get("records", []):
        cwd_value = row.get("cwd")
        if isinstance(cwd_value, str) and "\x00" in cwd_value:
            return "会话索引包含无法解析的当前目录；项目活动状态未知"
        cwd = worktree_activity._absolute_path(cwd_value)
        if cwd is None or not under(cwd, workspace):
            continue
        last_activity = row.get("last_activity")
        if last_activity is None:
            return "项目关联会话缺少可解释活动时间"
        if row.get("archived") is not True or now - float(last_activity) <= worktree_activity.IDLE_SECONDS:
            return "项目存在未确认关闭或近 168 小时内有活动的会话"

    current_git_state = scan.git_state(workspace)
    if current_git_state == "Git 状态不可读":
        return "项目 Git 状态现在无法读取"
    planned_git_state = item.get("git_state")
    if planned_git_state and current_git_state != planned_git_state:
        return "项目 Git 状态自扫描后发生变化"
    planned_git_digest = item.get("git_status_digest")
    if planned_git_digest is not None:
        current_git_digest = scan.git_status_snapshot(workspace).get("digest")
        if current_git_digest != planned_git_digest:
            return "Git 文件状态自扫描后发生变化"

    current_references = references
    if current_references is None:
        current_references = worktree_activity.extract_static_references([workspace])
        if getattr(worktree_activity.extract_static_references, "last_issues", []):
            return "项目配置/任务引用读取不完整；保留清理目标"
    for reference in current_references:
        raw = reference.get("raw_path") or reference.get("path")
        if not raw:
            return "项目中存在无法解释的引用；保留清理目标"
        path = Path(os.path.expanduser(str(raw)))
        if not path.is_absolute() and reference.get("path_base"):
            path = Path(reference["path_base"]) / path
        try:
            resolved = path.absolute()
        except (OSError, ValueError):
            return "项目引用路径无法解析；保留清理目标"
        if _paths_overlap(resolved, target):
            return f"项目现在有引用指向清理目标或其父子路径：{resolved}"
    return None


def apply_direct(
    plan: dict[str, Any],
    home: Path,
    *,
    fresh_references: list[dict[str, Any]] | None = None,
    reference_issues: list[dict[str, Any]] | None = None,
    fresh_reference_loader: Callable[[], tuple[list[dict[str, Any]], list[dict[str, Any]]]] | None = None,
    completed_records: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    removed = completed_records if completed_records is not None else []
    skipped: list[dict[str, Any]] = []
    for planned in plan["direct_delete"]:
        item = dict(planned)
        item.setdefault("tier", "regenerable")
        item.setdefault("default_action", "direct-delete")
        path, reason = direct_candidate(item, home)
        if path is not None:
            try:
                current_references, current_issues = (
                    fresh_reference_loader()
                    if fresh_reference_loader is not None
                    else (fresh_references or [], reference_issues or [])
                )
            except (CleanupError, OSError, subprocess.SubprocessError) as error:
                skipped.append({"path": planned["path"], "reason": f"执行前引用复核失败：{error}"})
                continue
            reason = _fresh_project_preflight(
                item, path, home,
                references=current_references,
                reference_issues=current_issues,
            )
            if reason is not None:
                path = None
        if path is None:
            skipped.append({"path": planned["path"], "reason": reason or "当前执行复核未通过"})
            continue
        try:
            operation = item.get("cache_operation")
            if operation in {"purge-browser-cache", "purge-update-cache"}:
                command = [
                    operation,
                    "--confirm-path", str(path),
                    "--permanent",
                ]
                purged = run_vault(*command)
                bytes_before = int(purged.get("kilobytes_before") or 0) * 1024
                method = f"verified-{operation}"
            else:
                bytes_before = remove_direct(path)
                method = (
                    "verified-old-codex-log-delete"
                    if operation == "purge-old-codex-log"
                    else "permanent-regenerable-delete"
                )
        except (OSError, CleanupError) as error:
            skipped.append({"path": str(path), "reason": str(error)})
            continue
        except (VaultError, subprocess.SubprocessError) as error:
            skipped.append({"path": str(path), "reason": str(error)})
            continue
        removed.append({"path": str(path), "bytes": bytes_before, "method": method})
    return removed, skipped


def _validate_archived_session_candidates(
    source: Path,
    eligible_paths: list[str],
    home: Path,
    reference_rows: list[dict[str, Any]],
) -> list[Path]:
    if not eligible_paths:
        raise CleanupError("扫描计划没有列出可删除的精确归档文件")
    activity = worktree_activity.load_thread_activity(home)
    if activity.get("coverage") != "complete":
        raise CleanupError("当前会话活动索引不完整；归档活动状态未知")
    by_id = {
        str(row.get("id")): row
        for row in activity.get("records", [])
        if row.get("id") is not None
    }
    cutoff = time.time() - ARCHIVE_RETENTION_DAYS * 86400
    selected: list[Path] = []
    seen: set[Path] = set()
    for raw in eligible_paths:
        path = exact_path(raw)
        if path.parent != source or path in seen or path.is_symlink() or not path.is_file():
            raise CleanupError(f"归档候选不是计划中的精确普通文件：{path}")
        seen.add(path)
        stat_result = path.lstat()
        if stat_result.st_mtime >= cutoff:
            raise CleanupError(f"归档文件现在未超过 7 天：{path}")
        header = scan.storage_discovery.read_session_metadata_header(path)
        thread = by_id.get(str(header.get("id")))
        if thread is None:
            raise CleanupError(f"归档会话未出现在当前活动索引，状态未知：{path}")
        last_activity = thread.get("last_activity")
        if thread.get("archived") is not True or last_activity is None:
            raise CleanupError(f"归档会话尚未确认结束或缺少活动时间：{path}")
        if time.time() - float(last_activity) <= ARCHIVE_RETENTION_DAYS * 86400:
            raise CleanupError(f"归档会话最近仍有活动：{path}")
        for reference in reference_rows:
            raw_reference = reference.get("raw_path") or reference.get("path")
            if not raw_reference:
                raise CleanupError("存在无法解释的路径引用；归档状态未知")
            referenced = Path(os.path.expanduser(str(raw_reference)))
            if not referenced.is_absolute() and reference.get("path_base"):
                referenced = Path(reference["path_base"]) / referenced
            if _paths_overlap(referenced.absolute(), path):
                raise CleanupError(f"发现引用此归档文件的路径：{referenced}")
        selected.append(path)
    return selected


def apply_archives(
    plan: dict[str, Any],
    *,
    fresh_references: list[dict[str, Any]] | None = None,
    reference_issues: list[dict[str, Any]] | None = None,
    fresh_reference_loader: Callable[[], tuple[list[dict[str, Any]], list[dict[str, Any]]]] | None = None,
    completed_records: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    completed = completed_records if completed_records is not None else []
    skipped: list[dict[str, Any]] = []
    for archive in plan["archive_backup_then_delete"]:
        source = exact_path(archive["path"])
        try:
            current_references, current_issues = (
                fresh_reference_loader()
                if fresh_reference_loader is not None
                else (fresh_references or [], reference_issues or [])
            )
            category = archive.get("backup_category") or "codex-archives"
            if category == "codex-archives":
                if current_issues:
                    raise CleanupError("全范围引用复核不完整；归档状态未知")
                eligible = _validate_archived_session_candidates(
                    source,
                    list(archive.get("eligible_paths") or []),
                    exact_path(archive["home"]),
                    current_references,
                )
                active, note = scan.open_handle_status(source)
                if active is not False:
                    raise CleanupError(note or "归档目录仍在使用或打开状态未知")
                backup = run_vault("backup", "--source", str(source), "--category", category)
                evicted = run_vault(
                    "evict-archives", backup["snapshot_id"], "--confirm-source", str(source),
                    "--older-than-days", str(max(archive["retention_days"], ARCHIVE_RETENTION_DAYS)),
                    *[argument for path in eligible for argument in ("--only", str(path))],
                    "--permanent",
                )
                method = "verified-t1-backup-then-delete-old-archives"
            else:
                eligible = [exact_path(value) for value in archive.get("eligible_paths", [])]
                if eligible != [source]:
                    raise CleanupError("非归档成果必须以完整、独立的精确路径进入备份后删除；混合目录暂不执行")
                if current_issues:
                    raise CleanupError("全范围引用复核不完整；成果引用状态未知")
                preflight_issue = _fresh_project_preflight(
                    archive, source, exact_path(archive["home"]),
                    references=current_references,
                    reference_issues=current_issues,
                )
                if preflight_issue:
                    raise CleanupError(preflight_issue)
                activity = scan.tree_activity(source)
                latest = activity.get("latest_mtime")
                if activity.get("mtime_errors") or latest is None or time.time() - latest <= max(int(archive.get("retention_days") or ARCHIVE_RETENTION_DAYS), ARCHIVE_RETENTION_DAYS) * 86400:
                    raise CleanupError("成果最近仍有活动，或活动时间无法确认")
                active, note = scan.open_handle_status(source)
                if active is not False:
                    raise CleanupError(note or "成果仍在使用或打开状态未知")
                retention_evidence = archive.get("retention_evidence") or {}
                if archive.get("review_priority") == "verified-duplicate-backup":
                    keeper_text = retention_evidence.get("keep_path")
                    expected_digest = retention_evidence.get("sha256")
                    if not keeper_text or not expected_digest:
                        raise CleanupError("重复备份缺少保留路径或内容校验依据")
                    keeper = exact_path(keeper_text)
                    if not source.is_file() or source.is_symlink() or not keeper.is_file() or keeper.is_symlink():
                        raise CleanupError("重复备份源或保留副本不是可核验的普通文件")
                    source_stat, keeper_stat = source.stat(), keeper.stat()
                    if (source_stat.st_dev, source_stat.st_ino) == (keeper_stat.st_dev, keeper_stat.st_ino):
                        raise CleanupError("源与保留副本是同一硬链接实体，不计为可释放副本")
                    if _stable_file_digest(source) != expected_digest or _stable_file_digest(keeper) != expected_digest:
                        raise CleanupError("重复备份内容已变化或不再与保留副本一致")
                else:
                    marker = (retention_evidence.get("completion_marker") or {}).get("path")
                    current_completion = scan._completion_evidence(source)
                    if (
                        not marker
                        or not current_completion
                        or current_completion.get("path") != marker
                    ):
                        raise CleanupError("结束标记已经变化或无法重新读取")
                backup = run_vault("backup", "--source", str(source), "--category", "user-data")
                evicted = run_vault(
                    "offload-user-data", backup["snapshot_id"], "--confirm-source", str(source), "--permanent"
                )
                method = (
                    "verified-t1-backup-then-delete-duplicate"
                    if archive.get("review_priority") == "verified-duplicate-backup"
                    else "verified-t1-backup-then-delete-closed-task-output"
                )
            completed.append({
                "source": str(source),
                "snapshot_id": backup["snapshot_id"],
                "snapshot": backup.get("path"),
                "snapshot_reused": bool(backup.get("reused")),
                "offloaded_files": evicted.get("offloaded_files", 1 if category != "codex-archives" else 0),
                "offloaded_bytes": evicted.get("offloaded_bytes", evicted.get("bytes", 0)),
                "method": method,
            })
        except (CleanupError, VaultError, OSError, subprocess.SubprocessError) as error:
            skipped.append({"path": str(source), "reason": str(error)})
    return completed, skipped


def apply_worktrees(
    plan: dict[str, Any],
    *,
    home: Path | None = None,
    fresh_references: list[dict[str, Any]] | None = None,
    reference_issues: list[dict[str, Any]] | None = None,
    fresh_reference_loader: Callable[[], tuple[list[dict[str, Any]], list[dict[str, Any]]]] | None = None,
    completed_records: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    completed = completed_records if completed_records is not None else []
    skipped: list[dict[str, Any]] = []
    grouped: dict[str, list[dict[str, Any]]] = {}
    for worktree in plan["worktree_migrations"]:
        group_key = str(worktree.get("association_group_id") or worktree["path"])
        grouped.setdefault(group_key, []).append(worktree)
    for group_id, worktrees in grouped.items():
        try:
            current_references, current_issues = (
                fresh_reference_loader()
                if fresh_reference_loader is not None
                else (fresh_references or [], reference_issues or [])
            )
        except (CleanupError, OSError, subprocess.SubprocessError) as error:
            skipped.append({
                "path": [row["path"] for row in worktrees],
                "group_id": group_id,
                "reason": f"执行前引用复核失败：{error}",
            })
            continue
        if current_issues:
            skipped.append({
                "path": [row["path"] for row in worktrees],
                "group_id": group_id,
                "reason": "全范围配置/任务引用读取不完整；关联组状态未知",
            })
            continue
        expected_group_paths = {
            str(Path(path).absolute())
            for worktree in worktrees
            for path in (worktree.get("association_group_paths") or [worktree["path"]])
        }
        actual_group_paths = {str(Path(worktree["path"]).absolute()) for worktree in worktrees}
        if not expected_group_paths.issubset(actual_group_paths):
            skipped.append({
                "path": sorted(actual_group_paths),
                "group_id": group_id,
                "reason": "关联组候选不完整，未执行部分迁移",
            })
            continue
        sources = [exact_path(worktree["path"]) for worktree in worktrees]
        revisions = {str(source): str(worktree.get("git_revision") or "") for source, worktree in zip(sources, worktrees)}
        allow_dirty = any(worktree.get("git_clean") is not True for worktree in worktrees)
        execution_home = home or Path.home().absolute()
        activity = worktree_activity.load_thread_activity(execution_home)
        if activity.get("coverage") != "complete":
            skipped.append({
                "path": [str(source) for source in sources],
                "group_id": group_id,
                "reason": "当前会话活动索引不完整；工作树活动状态未知",
            })
            continue
        trees = {str(source): worktree_activity.tree_activity(source) for source in sources}
        if any(tree.get("mtime_errors") for tree in trees.values()):
            skipped.append({
                "path": [str(source) for source in sources],
                "group_id": group_id,
                "reason": "执行前文件活动或挂载边界复核不完整",
            })
            continue
        symlinks = [
            link for tree in trees.values()
            for link in tree.get("symlinks", [])
        ]
        fresh_worktrees: list[dict[str, Any]] = []
        status_changed = False
        for planned, source in zip(worktrees, sources):
            current = scan.inspect_worktree(source)
            if (
                not current.get("linked_worktree_registered")
                or current.get("git_status_readable") is not True
                or current.get("active") is not False
                or current.get("current_working_directory")
                or str(current.get("git_revision") or "") != str(planned.get("git_revision") or "")
                or current.get("git_status_digest") != planned.get("git_status_digest")
            ):
                status_changed = True
                break
            fresh_worktrees.append({"path": source, "active": False})
        if status_changed:
            skipped.append({
                "path": [str(source) for source in sources],
                "group_id": group_id,
                "reason": "执行前 Git 登记、提交、文件状态或打开句柄与扫描结果不同",
            })
            continue
        references: list[dict[str, Any]] = []
        references.extend(current_references)
        current_group_analysis = worktree_activity.analyze_worktree_groups(
            fresh_worktrees,
            thread_activity=activity,
            references=references,
            symlinks=symlinks,
            activity_by_path=trees,
        )
        current_groups = current_group_analysis.get("groups", [])
        if (
            len(current_groups) != 1
            or set(current_groups[0].get("paths") or []) != {str(source) for source in sources}
            or current_groups[0].get("idle") is not True
        ):
            reason = (
                "; ".join(current_groups[0].get("blockers") or [])
                if current_groups else "执行前无法建立完整关联组"
            )
            skipped.append({
                "path": [str(source) for source in sources],
                "group_id": group_id,
                "reason": reason or "工作树活动、引用或关联范围自扫描后发生变化",
            })
            continue
        try:
            completed.extend(move_worktree_group(
                sources,
                revisions,
                allow_dirty=allow_dirty,
                group_id=None if group_id.startswith("/") else group_id,
                references=references,
            ))
        except (CleanupError, VaultError, OSError, subprocess.SubprocessError) as error:
            skipped.append({"path": str(sources), "group_id": group_id, "reason": str(error)})
    return completed, skipped


def _refresh_retained_contents(
    scan_result: dict[str, Any],
    plan: dict[str, Any],
    home: Path,
    migrated: list[dict[str, Any]],
) -> dict[str, Any]:
    started = time.monotonic()
    migrated_sources = {
        str(Path(row.get("source", "")).absolute())
        for row in migrated if row.get("source")
    }
    roots = [
        row for row in scan_result.get("confirmed_roots", [])
        if row.get("path") and str(Path(row["path"]).absolute()) not in migrated_sources
    ]
    scan_roots = [Path(row["path"]) for row in roots]
    measured = scan.storage_discovery.scan_large_files(
        scan_roots,
        min_bytes=(1 << 63) - 1,
        exclude=[
            home / "Library" / "Mobile Documents",
            home / "Library" / "CloudStorage",
        ],
        link_scope_root=home,
        metadata_first=True,
    )
    candidates: list[dict[str, Any]] = []
    def still_local(path_text: str) -> bool:
        try:
            mode = Path(path_text).lstat().st_mode
        except OSError:
            return False
        return not stat.S_ISLNK(mode) and (stat.S_ISREG(mode) or stat.S_ISDIR(mode))

    candidates.extend({
        **row, "default_action": "direct-delete",
        "path": row.get("path", ""),
    } for row in plan.get("direct_delete", [])
        if row.get("path") and still_local(str(row["path"])))
    for archive in plan.get("archive_backup_then_delete", []):
        for path in archive.get("eligible_paths", []):
            if still_local(str(path)):
                candidates.append({
                    "path": path, "default_action": "backup-then-delete",
                    "recommendation": archive.get("review_priority", ""),
                })
    candidates.extend({
        **row, "default_action": "migrate-to-t1",
        "path": row.get("path", ""),
    } for row in plan.get("worktree_migrations", [])
        if row.get("path") and still_local(str(row["path"])))
    retained = scan.top_retained_contents(
        measured.get("all_files", []),
        [
            {
                "path": row["path"], "codex_source": True,
                "evidence": row.get("source", "本轮确认的 Codex 根"),
            }
            for row in roots
        ],
        candidates,
        home,
        include_cleanup_candidates=True,
    )
    elapsed = round(time.monotonic() - started, 3)
    return {
        "items": retained,
        "complete": bool(measured.get("coverage_complete")),
        "elapsed_seconds": elapsed,
        "directories_scanned": measured.get("directories_scanned"),
        "files_scanned": measured.get("files_scanned"),
        "errors": measured.get("errors", []),
        "skipped_mounts": measured.get("skipped_mounts", []),
    }


def _prepare_run_workspace(home: Path, requested: Path | None) -> Path:
    if requested is None:
        run_id = time.strftime("%Y%m%dT%H%M%S", time.gmtime()) + f"-{time.time_ns() % 1_000_000_000:09d}"
        workspace = Path.home() / ".codex" / "skill-workspaces" / "codex-storage-cleanup" / "cleanup-runs" / run_id
    else:
        workspace = requested.expanduser().absolute()
    workspace = Path(os.path.abspath(workspace))
    if not under(workspace, home) or workspace == home:
        raise CleanupError("清理报告目录必须位于当前账号 home 内的精确子目录")
    excluded = (
        home / "Library" / "Mobile Documents",
        home / "Library" / "CloudStorage",
    )
    existing = workspace
    while not existing.exists() and existing != existing.parent:
        existing = existing.parent
    if (
        scan.storage_discovery.local_path_status(existing, home, excluded) is not True
        or existing.is_symlink()
        or int(existing.stat().st_dev) != int(home.stat().st_dev)
    ):
        raise CleanupError("清理报告目录经过链接、云路径或其他卷；未创建目录")
    if workspace.exists() and (workspace.is_symlink() or not workspace.is_dir()):
        raise CleanupError("清理报告路径不是普通目录")
    workspace.mkdir(parents=True, exist_ok=True)
    if (
        scan.storage_discovery.local_path_status(workspace, home, excluded) is not True
        or int(workspace.stat().st_dev) != int(home.stat().st_dev)
    ):
        raise CleanupError("清理报告目录未能通过本机路径与卷边界复核")
    return workspace


def _write_result_report(workspace: Path, output: dict[str, Any]) -> Path:
    destination = workspace / "cleanup-run.json"
    temporary = workspace / ".cleanup-run.json.tmp"
    temporary.write_text(
        json.dumps(output, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, help="必须与系统账号资料中的当前 home 完全一致")
    parser.add_argument("--workspace", type=Path, help="本轮独立报告目录；默认写入当前项目 work/cleanup-runs")
    parser.add_argument("--older-than-days", type=int, default=ARCHIVE_RETENTION_DAYS)
    parser.add_argument("--apply", action="store_true", help="执行默认策略；不带此参数只输出计划")
    args = parser.parse_args()
    scan_budget.start()
    if os.name == "nt" or pwd is None:
        account_name, system_home = scan.system_account_home()
    else:
        account = pwd.getpwuid(os.getuid())
        account_name, system_home = account.pw_name, Path(account.pw_dir).absolute()
    if account_name != "mac" or system_home != Path("/Users/mac"):
        raise CleanupError(
            f"此清理入口仅允许系统账号 mac、home /Users/mac；当前为 {account_name}:{system_home}"
        )
    home = (args.home or system_home).expanduser().absolute()
    if home != system_home:
        raise SystemExit("默认执行只允许当前用户主目录；其他用户只能检查，不能由此入口删除或迁移")
    if system_home != Path.home().absolute():
        raise SystemExit(
            f"系统账号资料确认当前账号为 {account_name}、home 为 {system_home}，"
            f"但进程 HOME 解析为 {Path.home().absolute()}；为避免账号错配，未扫描或清理"
        )
    if args.older_than_days < ARCHIVE_RETENTION_DAYS:
        raise SystemExit(f"--older-than-days 不能小于 {ARCHIVE_RETENTION_DAYS}")
    workspace = _prepare_run_workspace(home, args.workspace)
    worktree_activity.clear_inventory_activity()
    data = scan.build_data(
        scope_home=home,
        full_discovery_enabled=True,
        archive_retention_days=args.older_than_days,
        discovery_exclude_roots=[workspace],
    )
    discovery = data.get("large_file_discovery", {})
    coverage = discovery.get("coverage", {})
    scan_result = {
        "account": account_name,
        "home": str(system_home),
        "scan_roots": discovery.get("scan_roots", []),
        "confirmed_roots": coverage.get("confirmed_roots", []),
        "excluded_roots": coverage.get("excluded_roots", []),
        "phase_timings": coverage.get("phase_timings", {}),
        "elapsed_seconds": round(scan_budget.elapsed(), 3),
        "budget_seconds": scan_budget.configured_seconds(),
        "budget_exhausted": bool(coverage.get("budget_exhausted"))
        or scan_budget.elapsed() > scan_budget.configured_seconds(),
        "scope_complete": coverage.get("scope_complete"),
        "scope_status": coverage.get("scope_status"),
        "coverage_complete": coverage.get("coverage_complete"),
        "cleanup_plan_complete": coverage.get("cleanup_plan_complete"),
        "coverage_gaps": coverage.get("gap_count", 0),
        "top_retained_contents": discovery.get("top_retained_contents", []),
    }
    blockers = []
    if not discovery.get("enabled"):
        blockers.append("未执行完整 Codex 扫描")
    if scan_result["scope_complete"] is not True:
        blockers.append("扫描范围不是全部已确认 Codex 根")
    if scan_result["coverage_complete"] is not True:
        blockers.append("来源发现、文件清单或分析覆盖不完整")
    if scan_result["cleanup_plan_complete"] is not True:
        blockers.append("清理计划未完整复用本次扫描清单")
    if scan_result["budget_exhausted"]:
        blockers.append("完整扫描超过共享 1200 秒预算")
    if blockers:
        scan_budget.stop()
        failed_output = {
            "status": "failed",
            "mode": "apply" if args.apply else "plan",
            "plan": None,
            "scan": scan_result,
            "diagnostics": blockers + list(coverage.get("diagnostics") or []),
            "actions_executed": False,
            "workspace": str(workspace),
            "acceptance_passed": False,
        }
        report_path = _write_result_report(workspace, failed_output)
        failed_output["report"] = str(report_path)
        print(json.dumps(failed_output, ensure_ascii=False, indent=2))
        return 2

    plan = build_plan(data, home)
    plan_capacity = plan.get("capacity") or {}
    if plan_capacity.get("inventory_reused") is not True or plan_capacity.get("unmeasured_paths"):
        scan_budget.stop()
        failed_output = {
            "status": "failed",
            "mode": "apply" if args.apply else "plan",
            "plan": None,
            "scan": scan_result,
            "diagnostics": [
                "清理计划容量未能完整复用本次扫描清单",
                *plan_capacity.get("unmeasured_paths", []),
            ],
            "actions_executed": False,
            "workspace": str(workspace),
            "acceptance_passed": False,
        }
        report_path = _write_result_report(workspace, failed_output)
        failed_output["report"] = str(report_path)
        print(json.dumps(failed_output, ensure_ascii=False, indent=2))
        return 2
    data.pop("_scan_file_entities", None)
    data.pop("_scan_known_directories", None)
    worktree_activity.clear_inventory_activity()
    output: dict[str, Any] = {
        "status": "ready",
        "mode": "apply" if args.apply else "plan",
        "plan": plan,
        "scan": scan_result,
        "workspace": str(workspace),
        "acceptance_passed": False,
    }
    output["report"] = str(workspace / "cleanup-run.json")
    scan_result["acceptance_passed"] = True
    scan_result["elapsed_seconds"] = round(scan_budget.elapsed(), 3)
    scan_budget.check("清理计划与汇报数据生成")
    scan_result["budget_exhausted"] = scan_budget.elapsed() > scan_result["budget_seconds"]
    if scan_result["budget_exhausted"]:
        output.update(
            status="failed",
            plan=None,
            diagnostics=["清理计划或汇报数据生成超过 1200 秒预算"],
            actions_executed=False,
        )
        scan_result["acceptance_passed"] = False
        scan_budget.stop()
        report_path = _write_result_report(workspace, output)
        output["report"] = str(report_path)
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 2
    report_path = _write_result_report(workspace, output)
    scan_elapsed = scan_budget.elapsed()
    if scan_elapsed > scan_result["budget_seconds"]:
        output.update(
            status="failed",
            plan=None,
            diagnostics=["清理计划报告写入超过 1200 秒预算"],
            actions_executed=False,
        )
        scan_result["budget_exhausted"] = True
        scan_result["acceptance_passed"] = False
        scan_budget.stop()
        report_path = _write_result_report(workspace, output)
        output["report"] = str(report_path)
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 2
    scan_elapsed = scan_budget.stop()
    scan_result["elapsed_seconds"] = round(scan_elapsed, 3)
    scan_result["budget_exhausted"] = False
    scan_result["acceptance_passed"] = True
    if args.apply:
        worktree_activity.clear_inventory_activity()
        actions = {
            "direct_deleted": [],
            "archive_backups_and_deletions": [],
            "worktree_migrations": [],
            "skipped": [],
            "failures": [],
            "free_bytes_before": None,
            "free_bytes_after": None,
            "free_space_delta_bytes": None,
            "post_action_retained_contents": {
                "complete": False,
                "items": [],
                "errors": [{"reason": "事后复测尚未完成"}],
            },
        }
        try:
            actions["free_bytes_before"] = shutil.disk_usage(home).free
        except OSError as error:
            actions["failures"].append({"phase": "free-space-before", "reason": str(error)})

        reference_loader = lambda: _fresh_scope_references(home)
        try:
            _removed, direct_skipped = apply_direct(
                plan, home,
                fresh_reference_loader=reference_loader,
                completed_records=actions["direct_deleted"],
            )
            actions["skipped"].extend(direct_skipped)
        except Exception as error:
            actions["failures"].append({"phase": "direct-delete", "reason": str(error)})
        try:
            _archived, archive_skipped = apply_archives(
                plan,
                fresh_reference_loader=reference_loader,
                completed_records=actions["archive_backups_and_deletions"],
            )
            actions["skipped"].extend(archive_skipped)
        except Exception as error:
            actions["failures"].append({"phase": "archive-backup-delete", "reason": str(error)})
        try:
            _migrated, worktree_skipped = apply_worktrees(
                plan,
                home=home,
                fresh_reference_loader=reference_loader,
                completed_records=actions["worktree_migrations"],
            )
            actions["skipped"].extend(worktree_skipped)
        except Exception as error:
            actions["failures"].append({"phase": "worktree-migration", "reason": str(error)})
        try:
            retained_refresh = _refresh_retained_contents(
                scan_result, plan, home, actions["worktree_migrations"],
            )
            actions["post_action_retained_contents"] = retained_refresh
        except Exception as error:
            actions["failures"].append({"phase": "post-action-retained-refresh", "reason": str(error)})
            retained_refresh = actions["post_action_retained_contents"]
        scan_result["initial_top_retained_contents"] = scan_result.get("top_retained_contents", [])
        scan_result["top_retained_contents_complete"] = retained_refresh["complete"]
        scan_result["top_retained_contents_status"] = (
            "post-action-measured" if retained_refresh["complete"]
            else "post-action-refresh-incomplete"
        )
        if retained_refresh["complete"]:
            scan_result["top_retained_contents"] = retained_refresh["items"]
        try:
            actions["free_bytes_after"] = shutil.disk_usage(home).free
            if actions["free_bytes_before"] is not None:
                actions["free_space_delta_bytes"] = (
                    actions["free_bytes_after"] - actions["free_bytes_before"]
                )
        except OSError as error:
            actions["failures"].append({"phase": "free-space-after", "reason": str(error)})
        output["result"] = actions
        output["actions_executed"] = bool(
            actions["direct_deleted"]
            or actions["archive_backups_and_deletions"]
            or actions["worktree_migrations"]
        )
        output["acceptance_passed"] = True
        output["status"] = "completed" if not actions["failures"] else "partial_failure"
        try:
            _write_result_report(workspace, output)
        except OSError as error:
            output["result"]["failures"].append({
                "phase": "result-report-write",
                "reason": f"实际动作记录仍在标准输出，但报告文件未能写入：{error}",
            })
            output["status"] = "partial_failure"
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0 if output["status"] == "completed" or output["status"] == "ready" else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CleanupError, OSError, subprocess.SubprocessError, scan_budget.ScanBudgetExceeded) as error:
        print(json.dumps({
            "status": "failed",
            "mode": "apply" if "--apply" in sys.argv else "plan",
            "plan": None,
            "scan": {
                "budget_seconds": scan_budget.configured_seconds(),
                "elapsed_seconds": round(scan_budget.elapsed(), 3),
                "budget_exhausted": isinstance(error, scan_budget.ScanBudgetExceeded),
                "failure_phase": getattr(error, "phase", None),
            },
            "diagnostics": [str(error)],
            "actions_executed": False,
        }, ensure_ascii=False, indent=2))
        raise SystemExit(2)
