#!/usr/bin/env python3
"""Create a Codex-only, current-account cleanup ledger.

This scanner is intentionally narrower than a disk analyzer.  It discovers
Codex roots, records protected containers, and proposes only exact child paths
that have a recognizable Codex provenance.  It never moves or deletes files.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import getpass
import hashlib
import json
import os
from pathlib import Path
import platform as platform_module
import re
import shutil
import subprocess
import stat
import sys
import time
from typing import Any, Callable, Iterable

# The child skill is runnable after it is copied out of the parent repository.
# Keep every runtime import next to this entry point so an installed standalone
# package never reaches back into ``storage-observatory``.
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import storage_discovery
import storage_explain
import bounded_process
import scan_budget
import scan_context
import cleanup_plan
from build_evidence import cargo_output, decide_builds, toml as parse_toml
from chat_report import option_totals, render_chat_report
from worktree_activity import analyze_worktree_groups, extract_static_references, load_thread_activity, tree_activity

try:
    import pwd
except ImportError:  # Windows has no pwd module.
    pwd = None  # type: ignore[assignment]


MIN_BYTES = 256 * 1024
OLD_ARTIFACT_DAYS = 2
ARCHIVE_RETENTION_DAYS = 7
SYSTEM_PROFILE_NAMES = {
    "Shared", "Guest", "Public", "Default", "Default User", "All Users",
    "DefaultAppPool", "root",
}
BUILD_DIR_NAMES = {
    "target", "dist", "build", ".build", ".vite", ".next", "out", "coverage",
    "node_modules", ".pnpm-store", "__pycache__", ".pytest_cache", ".cache",
    ".venv", "venv", "env", "DerivedData", "intermediate", "intermediates",
    "transcode", "transcoded", "extract", "extracted", ".unpacked", "index",
}
DOWNLOAD_DIR_NAMES = {"node_modules", ".pnpm-store", ".venv", "venv", "env"}

BACKUP_OUTPUT_PARENT_NAMES = {
    "output", "outputs", "deliverable", "deliverables", "report", "reports",
    "screenshot", "screenshots", "media", "exports", "export", "handoff",
    "handoff-materials", "generated", "generated-images", "captures", "recordings",
    "backups", "backup", "snapshots",
}
BACKUP_OUTPUT_NAME_HINTS = (
    "report", "screenshot", "screen", "handoff", "deliverable", "final", "complete",
    "export", "preview", "media", "recording", "capture", "result", "backup", "snapshot",
)
DUPLICATE_BACKUP_NAME_HINTS = (
    "backup", "copy", "duplicate", "clone", "mirror", "snapshot",
)
COMPLETION_VALUES = {
    "done", "completed", "complete", "closed", "finished", "success", "succeeded",
    "delivered", "final", "finalized", "archived",
}


def is_download_cache_path(path: Path) -> bool:
    """Recognize dependency downloads without treating every project cache as one."""
    parts = [part.casefold() for part in path.parts]
    for anchor in ("cargo-home", ".cargo"):
        if anchor not in parts:
            continue
        start = parts.index(anchor) + 1
        if any(part in {"registry", "git"} for part in parts[start:]):
            return True
    return False


def _completion_evidence(path: Path) -> dict[str, Any] | None:
    """Find an explicit task/output completion marker without executing files."""
    markers: list[Path] = []
    try:
        for child in path.iterdir() if path.is_dir() else [path]:
            if child.is_file() and child.name.casefold() in {
                "completion.json", "completed.json", "status.json", "manifest.json",
                "task.json", "handoff.json", "result.json", "done", ".done", ".complete",
            }:
                markers.append(child)
    except OSError:
        return None
    for marker in markers:
        if marker.name.casefold() in {"done", ".done", ".complete"}:
            return {"path": str(marker), "status": "completed-marker"}
        try:
            payload = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            continue
        values: list[str] = []
        if isinstance(payload, dict):
            for key in ("status", "state", "phase", "result", "runStatus"):
                value = payload.get(key)
                if isinstance(value, str):
                    values.append(value.casefold())
            if any(payload.get(key) for key in ("completed_at", "completedAt", "finished_at", "finishedAt", "closed_at", "closedAt", "delivered_at", "deliveredAt")):
                values.append("completed-marker")
        if any(value in COMPLETION_VALUES for value in values) or "completed-marker" in values:
            return {"path": str(marker), "status": ",".join(values) or "completed-marker"}
    return None


def _backup_output_candidate(
    *, user: dict[str, Any], root: Path, workspace: Path, path: Path,
    references: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Create a backup-then-delete row only with age, closure and reference evidence."""
    lowered = path.name.casefold()
    parent_hint = (
        path.name.casefold() in BACKUP_OUTPUT_PARENT_NAMES
        or path.parent.name.casefold() in BACKUP_OUTPUT_PARENT_NAMES
        or workspace.name.casefold() in BACKUP_OUTPUT_PARENT_NAMES
        or workspace.parent.name.casefold() in BACKUP_OUTPUT_PARENT_NAMES
    )
    name_hint = any(token in lowered for token in BACKUP_OUTPUT_NAME_HINTS)
    if not parent_hint and not name_hint:
        return None
    completion = _completion_evidence(path)
    if not completion:
        return None
    activity = tree_activity(path)
    latest = activity.get("latest_mtime")
    if latest is None or time.time() - latest <= ARCHIVE_RETENTION_DAYS * 86400:
        return None
    path_key_value = path_key(path)
    matched_references: list[dict[str, Any]] = []
    for reference in references:
        raw = reference.get("path") or reference.get("raw_path")
        if not raw:
            continue
        try:
            referenced = Path(os.path.expanduser(str(raw)))
            if not referenced.is_absolute() and reference.get("path_base"):
                referenced = Path(reference["path_base"]) / referenced
            referenced = referenced.absolute()
            referenced_key = path_key(referenced)
            if (
                referenced_key == path_key_value
                or path_key_value.startswith(referenced_key + os.sep)
                or referenced_key.startswith(path_key_value + os.sep)
            ):
                matched_references.append(reference)
        except (OSError, ValueError):
            continue
    if matched_references:
        return None
    item = candidate_item(
        user=user,
        path=path,
        tier="manual",
        artifact_type="已结束任务成果/交付材料",
        provenance=f"已确认 Codex 工作区 {workspace} 内的输出候选：{path}",
        reason=(
            f"文件树最近活动距今超过 {ARCHIVE_RETENTION_DAYS} 天，且存在明确结束标记 {completion['path']}；"
            "没有发现受支持的项目或任务引用。"
        ),
        recommendation="先备份到 T1 并校验恢复方法，再删除本机这一个精确成果路径；不扩大到工作区根目录。",
        recovery="从 T1 的 user-data 快照按 manifest 校验后恢复到新路径。",
        root=root,
        workspace_root=workspace,
        action="open",
        handle_check=True,
        force_small=True,
        extra={
            "default_action": "backup-then-delete",
            "backup_category": "user-data",
            "backup_eligible_paths": [str(path)],
            "backup_eligible_bytes": 0,
            "backup_eligible_count": 1,
            "backup_retention_days": ARCHIVE_RETENTION_DAYS,
            "retention_evidence": {
                "latest_activity_at": activity.get("latest_activity_at"),
                "completion_marker": completion,
                "reference_status": "未发现受支持引用",
                "activity_errors": activity.get("mtime_errors", []),
            },
            "reference_evidence": [],
            "review_priority": "closed-task-output",
        },
    )
    if not item:
        return None
    item["backup_eligible_bytes"] = int(item.get("size_bytes") or 0)
    if item.get("active") is not False:
        item["default_action"] = "retain"
        item["review_priority"] = "closed-task-output-active-or-unknown"
        item["recommendation"] = "保留：当前使用状态为活动或未知，不能备份后删除。"
    return item


def _matches_supported_reference(path: Path, references: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return references that point at, into, or contain one exact path."""
    matched: list[dict[str, Any]] = []
    path_key_value = path_key(path)
    for reference in references:
        raw = reference.get("path") or reference.get("raw_path")
        if not raw:
            continue
        try:
            referenced = Path(os.path.expanduser(str(raw)))
            if not referenced.is_absolute() and reference.get("path_base"):
                referenced = Path(reference["path_base"]) / referenced
            referenced_key = path_key(referenced.absolute())
            if (
                referenced_key == path_key_value
                or path_key_value.startswith(referenced_key + os.sep)
                or referenced_key.startswith(path_key_value + os.sep)
            ):
                matched.append(reference)
        except (OSError, ValueError):
            continue
    return matched


def add_verified_duplicate_backup_candidates(
    *, user: dict[str, Any], home: Path, discovery: dict[str, Any], items: list[dict[str, Any]],
    static_references: list[dict[str, Any]] | None = None,
) -> None:
    """Promote only content-verified, old duplicate backup files to user-data review."""
    duplicates = discovery.get("duplicates") or {}
    if not duplicates.get("verified"):
        return
    existing = {path_key(Path(item["path"])) for item in items if item.get("path")}
    for group in duplicates.get("groups", []):
        digest = group.get("sha256")
        raw_paths = group.get("paths") or []
        if not digest or len(raw_paths) < 2:
            continue
        paths: list[Path] = []
        for raw_path in raw_paths:
            try:
                path = Path(raw_path).expanduser().absolute()
            except (OSError, TypeError, ValueError):
                continue
            if path_key(path) in {path_key(value) for value in paths} or not path.is_file() or path.is_symlink():
                continue
            try:
                path.relative_to(home)
            except ValueError:
                continue
            paths.append(path)
        if len(paths) < 2:
            continue
        def backup_like(path: Path) -> bool:
            parts = {part.casefold() for part in path.parts}
            return (
                bool(parts & {name.casefold() for name in BACKUP_OUTPUT_PARENT_NAMES})
                or any(token in path.name.casefold() for token in DUPLICATE_BACKUP_NAME_HINTS)
            )
        backup_paths = [path for path in paths if backup_like(path)]
        if not backup_paths:
            continue
        keeper_candidates = [path for path in paths if path not in backup_paths]
        keeper = min(keeper_candidates or paths, key=lambda path: (len(path.parts), str(path)))
        for path in backup_paths:
            if path == keeper or path_key(path) in existing:
                continue
            try:
                modified = path.stat().st_mtime
            except OSError:
                continue
            if time.time() - modified <= ARCHIVE_RETENTION_DAYS * 86400:
                continue
            references = (
                static_references if static_references is not None
                else extract_static_references([path.parent])
            )
            if _matches_supported_reference(path, references):
                continue
            item = candidate_item(
                user=user,
                path=path,
                tier="manual",
                artifact_type="本机重复备份/重复成果",
                provenance=f"全面发现的完整 SHA-256 重复组：{path}",
                reason=(
                    f"完整 SHA-256 与另一份文件一致，且保留路径为 {keeper}；"
                    f"该副本最近活动距今超过 {ARCHIVE_RETENTION_DAYS} 天，位于备份/导出类路径。"
                ),
                recommendation="先把这一份独立重复文件备份到 T1 并校验，再删除本机副本；保留另一份原始成果。",
                recovery="从 T1 的 user-data 快照按 manifest 恢复到新路径。",
                root=home,
                action="open",
                handle_check=True,
                force_small=True,
                extra={
                    "default_action": "backup-then-delete",
                    "backup_category": "user-data",
                    "backup_eligible_paths": [str(path)],
                    "backup_eligible_bytes": 0,
                    "backup_eligible_count": 1,
                    "backup_retention_days": ARCHIVE_RETENTION_DAYS,
                    "retention_evidence": {
                        "latest_activity_at": iso_time(modified),
                        "sha256": digest,
                        "duplicate_paths": [str(value) for value in paths],
                        "keep_path": str(keeper),
                        "reference_status": "未发现受支持引用",
                    },
                    "reference_evidence": [],
                    "review_priority": "verified-duplicate-backup",
                },
            )
            if not item:
                continue
            item["backup_eligible_bytes"] = int(item.get("size_bytes") or 0)
            if item.get("active") is not False:
                item["default_action"] = "retain"
                item["review_priority"] = "duplicate-backup-active-or-unknown"
            items.append(item)
            existing.add(path_key(path))


def _ensure_inventory_indexes(
    context: scan_context.ScanContext,
    inventory_directories: Iterable[str] | None = None,
) -> None:
    if context.directory_children is None:
        children: dict[Path, list[Path]] = {}
        directories: set[Path] = set()
        source = context.directory_sizes if inventory_directories is None else inventory_directories
        for raw in source:
            child = Path(raw).absolute()
            directories.add(child)
            if child != child.parent:
                children.setdefault(child.parent, []).append(child)
        for entries in children.values():
            entries.sort(key=lambda item: (item.name.casefold(), str(item)), reverse=True)
        context.directory_children = children
        context.directory_paths = directories
    elif context.directory_paths is None:
        directories = set()
        for parent, children in context.directory_children.items():
            directories.add(parent)
            directories.update(children)
        context.directory_paths = directories

    if context.files_by_directory is None:
        files: dict[Path, list[str]] = {}
        for raw_path in context.file_rows:
            path = Path(raw_path).absolute()
            files.setdefault(path.parent, []).append(str(path))
        context.files_by_directory = files


def _inventory_files_under(path: Path) -> list[Path] | None:
    """Read descendant file paths from the current inventory, without a second walk."""
    context = scan_context.current()
    if context is None:
        return None
    root = path.absolute()
    _ensure_inventory_indexes(context)
    key = str(root)
    if key in context.subtree_files:
        return [Path(value) for value in context.subtree_files[key]]
    if context.directory_paths is None:
        return None
    if root not in context.directory_paths:
        parent = root.parent
        parent_row = context.directory_sizes.get(str(parent))
        if parent in context.directory_paths and parent_row and parent_row.get("scan_complete"):
            return []
        return None
    root_row = context.directory_sizes.get(key)
    if root_row is not None and not root_row.get("scan_complete"):
        return None
    files_by_directory = context.files_by_directory or {}
    children_by_directory = context.directory_children or {}
    found: list[str] = []
    stack = [root]
    while stack:
        scan_budget.check("Codex 清理缓存来源复核")
        current = stack.pop()
        found.extend(files_by_directory.get(current, ()))
        stack.extend(children_by_directory.get(current, ()))
    context.subtree_files[key] = tuple(found)
    return [Path(value) for value in found]


def _direct_inventory_files(path: Path) -> list[Path] | None:
    context = scan_context.current()
    if context is None:
        return None
    _ensure_inventory_indexes(context)
    directory = path.absolute()
    if directory not in (context.directory_paths or set()):
        parent_row = context.directory_sizes.get(str(directory.parent))
        if (
            directory.parent in (context.directory_paths or set())
            and parent_row and parent_row.get("scan_complete")
        ):
            return []
        return None
    return [
        Path(value)
        for value in (context.files_by_directory or {}).get(directory, ())
    ]


def _files_below(path: Path) -> list[Path] | None:
    indexed = _inventory_files_under(path)
    if indexed is not None:
        return indexed
    if scan_context.current() is not None:
        return None
    try:
        return [
            entry for entry in path.rglob("*")
            if entry.is_file() and not entry.is_symlink()
        ]
    except OSError:
        return None


def _direct_files(path: Path) -> list[Path] | None:
    indexed = _direct_inventory_files(path)
    if indexed is not None:
        return indexed
    if scan_context.current() is not None:
        return None
    try:
        return [entry for entry in path.iterdir() if entry.is_file() and not entry.is_symlink()]
    except OSError:
        return None


def _cache_rebuild_evidence(path: Path) -> dict[str, Any] | None:
    """Return evidence for small, known-generated project caches."""
    name = path.name.casefold()
    parent = path.parent
    if name == "__pycache__":
        files = _files_below(path)
        direct = _direct_files(parent)
        if (
            files is None or direct is None or not files
            or any(entry.suffix.casefold() not in {".pyc", ".pyo", ".ds_store"} for entry in files)
        ):
            return None
        sources = [str(candidate) for candidate in direct if candidate.suffix.casefold() == ".py"]
        if not sources:
            return None
        return {
            "kind": "python-bytecode-cache",
            "source_entries": sources,
            "rebuild_command": "Python interpreter regenerates __pycache__ from the adjacent .py source",
            "rebuild_basis": "目录内仅有 Python 字节码缓存，且同目录存在源码入口；不包含用户独有文件",
        }
    if name == ".pytest_cache":
        files = _files_below(path)
        project_files = _files_below(parent)
        if (
            files is None or project_files is None or not files
            or any(entry.name not in {"README.md", ".gitignore"} and entry.suffix.casefold() not in {".json", ".txt"} for entry in files)
        ):
            return None
        sources = [
            str(candidate) for candidate in project_files
            if candidate.name.startswith("test_") and candidate.suffix.casefold() == ".py"
        ]
        if not sources:
            return None
        return {
            "kind": "pytest-cache",
            "source_entries": sources[:64],
            "rebuild_command": "pytest recreates .pytest_cache when tests run",
            "rebuild_basis": "目录结构和文件类型符合 pytest 缓存，且项目内存在测试源码；不包含用户独有输出",
        }
    if name in {".vite", ".cache"}:
        marker = path / "CACHEDIR.TAG"
        package = parent / "package.json"
        direct = _direct_files(parent)
        if direct is None:
            return None
        direct_names = {candidate.name: candidate for candidate in direct}
        config = next(
            (
                direct_names[name]
                for name in sorted(direct_names)
                if name.startswith("vite.config.")
            ),
            None,
        )
        context = scan_context.current()
        package_present = (
            str(package.absolute()) in context.file_rows
            if context is not None else package.is_file()
        )
        marker_present = (
            str(marker.absolute()) in context.file_rows
            if context is not None else marker.is_file() and not marker.is_symlink()
        )
        if name == ".vite" and not (package_present and config):
            return None
        if name == ".cache" and not marker_present:
            return None
        sources = [str(item) for item in (package if package_present else None, config) if item]
        for folder in ("src", "app", "lib"):
            folder_path = parent / folder
            indexed = _files_below(folder_path)
            if indexed is None:
                if context is not None:
                    return None
                try:
                    indexed = [
                        candidate for candidate in folder_path.rglob("*")
                        if candidate.is_file() and not candidate.is_symlink()
                    ]
                except OSError:
                    return None
            sources.extend(str(candidate) for candidate in indexed)
        if not sources:
            return None
        return {
            "kind": "project-rebuild-cache",
            "source_entries": sources[:128],
            "rebuild_command": "project build/development tooling regenerates this cache from the recorded configuration",
            "rebuild_basis": "存在项目配置、源码入口和缓存标记；缓存目录不作为交付成果保留",
        }
    if name in {"deriveddata", "intermediate", "intermediates", "transcode", "transcoded", "extract", "extracted", ".unpacked", "index"}:
        markers = [path / marker for marker in ("CACHEDIR.TAG", ".codex-generated", ".generated", ".rebuild")]
        context = scan_context.current()
        if context is not None:
            if not any(str(marker.absolute()) in context.file_rows for marker in markers):
                return None
        elif not any(marker.is_file() and not marker.is_symlink() for marker in markers):
            return None
        direct = _direct_files(parent)
        if direct is None:
            return None
        source_names = {
            "package.json", "package-lock.json", "pnpm-lock.yaml", "cargo.toml",
            "pyproject.toml", "makefile", "readme.md",
        }
        sources = [
            str(candidate) for candidate in direct
            if candidate.name.casefold() in source_names
        ]
        for folder in ("src", "Sources", "app", "inputs", "resources"):
            folder_path = parent / folder
            indexed = _files_below(folder_path)
            if indexed is None:
                if context is not None:
                    return None
                try:
                    indexed = [
                        candidate for candidate in folder_path.rglob("*")
                        if candidate.is_file() and not candidate.is_symlink()
                    ]
                except OSError:
                    return None
            sources.extend(str(candidate) for candidate in indexed)
        if not sources:
            return None
        return {
            "kind": "rebuildable-intermediate",
            "source_entries": sources[:128],
            "rebuild_command": "项目输入和配置按 marker 记录的方法重新生成中间/转码/索引目录",
            "rebuild_basis": "存在明确生成标记、项目输入或构建配置；目录不是独有交付成果",
        }
    return None

PRUNE_DIR_NAMES = {
    ".git", ".hg", ".svn", ".idea", ".vscode", ".superpowers", ".worktrees",
    ".codex", "__MACOSX",
}
APP_CACHE_RELATIVE = (
    "Crashpad/pending",
    "Default/Cache",
    "Default/Code Cache",
    "Default/GPUCache",
    "GraphiteDawnCache",
    "GPUPersistentCache",
    "component_crx_cache",
    "extensions_crx_cache",
    "Safe Browsing",
)


def human_bytes(value: int | float | None) -> str:
    if value is None:
        return "未读取"
    number = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if number < 1000 or unit == "TB":
            if unit in ("B", "KB"):
                return f"{int(number)} {unit}"
            return f"{number:.2f} {unit}"
        number /= 1000
    return f"{number:.2f} TB"


def iso_time(timestamp: float | None) -> str:
    if not timestamp:
        return "未读取"
    return datetime.fromtimestamp(timestamp).astimezone().strftime("%Y-%m-%d %H:%M")


def path_key(path: Path | str) -> str:
    value = os.path.normcase(os.path.abspath(os.fspath(path)))
    # APFS and Windows are commonly case-insensitive even though Python's
    # POSIX normcase does not fold case on macOS.
    return value.casefold() if sys.platform == "darwin" or os.name == "nt" else value


def path_exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def path_is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def path_is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def is_reparse_or_link(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        attrs = getattr(path.lstat(), "st_file_attributes", 0)
        return bool(attrs & 0x0400)  # FILE_ATTRIBUTE_REPARSE_POINT
    except OSError:
        return True


def safe_size(path: Path, timeout: int = 24) -> tuple[int | None, str | None]:
    """Measure without following the candidate itself when it is a link."""
    if not path_exists(path):
        return None, "路径不存在"
    if is_reparse_or_link(path):
        return None, "路径是符号链接或重解析点"
    context = scan_context.current()
    inventory = context.path_sizes.get(str(path.absolute())) if context else None
    if inventory is not None:
        if not inventory.get("scan_complete"):
            return None, "本次文件清单覆盖不完整"
        return int(inventory.get("logical_bytes") or 0), None
    if os.name != "nt" and shutil.which("du"):
        try:
            result = bounded_process.run(
                ["du", "-sk", str(path)],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return None, f"测量超过 {timeout} 秒"
        except OSError as error:
            return None, str(error)
        match = re.match(r"\s*(\d+)", result.stdout or "")
        if result.returncode == 0 and match and not re.search(
            r"permission denied|operation not permitted", result.stderr or "", re.I
        ):
            return int(match.group(1)) * 1024, None
        return None, (result.stderr.strip() or "无法完整读取")[:240]
    deadline = time.monotonic() + timeout
    total = 0
    stack = [path]
    try:
        while stack:
            if time.monotonic() > deadline:
                return None, f"测量超过 {timeout} 秒"
            current = stack.pop()
            if is_reparse_or_link(current):
                continue
            if path_is_file(current):
                total += current.stat().st_size
                continue
            with os.scandir(current) as entries:
                for entry in entries:
                    child = Path(entry.path)
                    if is_reparse_or_link(child):
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(child)
                    elif entry.is_file(follow_symlinks=False):
                        total += entry.stat(follow_symlinks=False).st_size
        return total, None
    except (OSError, PermissionError) as error:
        return None, str(error)


def count_files(path: Path, limit: int | None = None) -> tuple[int | None, str | None]:
    context = scan_context.current()
    inventory = context.path_sizes.get(str(path.absolute())) if context else None
    if inventory is not None:
        if not inventory.get("scan_complete"):
            return None, "本次文件清单覆盖不完整"
        count = int(inventory.get("file_count") or 0)
        if limit is not None and count >= limit:
            return limit, f"文件数达到 {limit} 上限"
        return count, None
    count = 0
    stack = [path]
    try:
        while stack:
            scan_budget.check("Codex 文件计数")
            current = stack.pop()
            with os.scandir(current) as entries:
                for entry in entries:
                    child = Path(entry.path)
                    if is_reparse_or_link(child):
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(child)
                    elif entry.is_file(follow_symlinks=False):
                        count += 1
                        if limit is not None and count >= limit:
                            return count, f"文件数达到 {limit} 上限"
        return count, None
    except (OSError, PermissionError) as error:
        return None, str(error)


def open_handle_status(path: Path, timeout: int = 4) -> tuple[bool | None, str]:
    """Return a path-specific open-handle check where the platform supports it."""
    if os.name == "nt":
        return None, "Windows 上没有找到可用的检查工具；操作前请再确认"
    lsof = shutil.which("lsof")
    if not lsof:
        return None, "没有找到可用的检查工具；操作前请再确认"
    try:
        result = bounded_process.run(
            [lsof, "+D", str(path)], capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return None, f"检查目录是否正在使用时超过 {timeout} 秒"
    except OSError as error:
        return None, str(error)
    lines = [line for line in (result.stdout or "").splitlines() if line.strip()]
    if len(lines) > 1:
        sample = "；".join(line.split()[0] for line in lines[1:4])
        return True, f"发现程序正在使用这个目录：{sample}"
    if result.returncode not in (0, 1) or result.stderr.strip():
        return None, "使用状态检查不完整：" + result.stderr.strip()[:200]
    return False, "没有发现程序正在使用这个目录"


def active_process_snapshot() -> tuple[bool, list[str]]:
    if os.name == "nt":
        try:
            result = bounded_process.run(
                ["tasklist", "/fo", "csv", "/nh"],
                capture_output=True,
                text=True,
                timeout=4,
            )
            rows = result.stdout.splitlines()
            names = [row.split(",", 1)[0].strip('"') for row in rows]
        except (OSError, subprocess.TimeoutExpired):
            return False, []
    else:
        try:
            result = bounded_process.run(
                ["ps", "-axo", "comm="], capture_output=True, text=True, timeout=4
            )
            names = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        except (OSError, subprocess.TimeoutExpired):
            return False, []
    needles = ("codex", "cargo", "rustc", "node", "npm", "pnpm", "vite", "tauri")
    matched = []
    for name in names:
        lower = name.lower()
        if any(needle in lower for needle in needles):
            short = os.path.basename(name)
            if short not in matched:
                matched.append(short)
    return any("codex" in name.lower() for name in matched), matched[:12]


def git_status_snapshot(path: Path) -> dict[str, Any]:
    current = path
    while current != current.parent:
        if path_exists(current / ".git"):
            key = str(current.absolute())
            context = scan_context.current()
            cached = context.git_status_cache.get(key) if context else None
            if cached is not None:
                return dict(cached)
            try:
                result = bounded_process.run(
                    ["git", "-C", str(current), "status", "--short", "--porcelain=v1"],
                    capture_output=True,
                    text=True,
                    timeout=4,
                )
                if result.returncode != 0:
                    snapshot = {"state": "Git 状态不可读", "digest": None}
                else:
                    status = result.stdout
                    snapshot = {
                        "state": "有未提交变更" if status.strip() else "干净",
                        "digest": hashlib.sha256(status.encode("utf-8")).hexdigest(),
                    }
            except (OSError, subprocess.TimeoutExpired):
                snapshot = {"state": "Git 状态不可读", "digest": None}
            if context is not None:
                context.git_status_cache[key] = dict(snapshot)
            return snapshot
        current = current.parent
    return {"state": "不适用", "digest": None}


def git_state(path: Path) -> str:
    return str(git_status_snapshot(path)["state"])


def inspect_worktree(path: Path) -> dict[str, Any]:
    """Return evidence for a Codex-managed worktree without changing it."""
    result: dict[str, Any] = {
        "git_clean": False,
        "git_revision": "",
        "git_branch": "",
        "git_root": "",
        "linked_worktree_registered": False,
        "has_head": False,
        "git_status_readable": False,
        "finalized_candidate": False,
        "finalization_reason": "不是可识别的 Git worktree",
    }
    git_marker = path / ".git"
    if (
        not path_is_dir(path)
        or is_reparse_or_link(path)
        or is_reparse_or_link(git_marker)
        or not git_marker.is_file()
    ):
        result["finalization_reason"] = "不是已登记 linked worktree"
        return result
    try:
        def git(*args: str) -> str:
            command = bounded_process.run(
                ["git", "-C", str(path), *args],
                capture_output=True,
                text=True,
                timeout=4,
            )
            if command.returncode != 0:
                raise RuntimeError((command.stderr or command.stdout).strip() or "git 命令失败")
            return command.stdout.strip()

        result["git_root"] = git("rev-parse", "--show-toplevel")
        common_dir_text = git("rev-parse", "--git-common-dir")
        common_dir = Path(common_dir_text)
        if not common_dir.is_absolute():
            common_dir = path / common_dir
        common_key = str(common_dir.resolve())
        context = scan_context.current()
        registered_paths = context.git_worktree_lists.get(common_key) if context else None
        if registered_paths is None:
            listing = git("worktree", "list", "--porcelain")
            registered_paths = {
                str(Path(line[9:]).absolute())
                for line in listing.splitlines()
                if line.startswith("worktree ")
            }
            if context is not None:
                context.git_worktree_lists[common_key] = registered_paths
        if str(path.absolute()) not in registered_paths:
            result["finalization_reason"] = "Git worktree list 未登记此路径"
            return result
        result["linked_worktree_registered"] = True
        try:
            result["git_revision"] = git("rev-parse", "HEAD")
            result["has_head"] = True
        except RuntimeError as error:
            # An unborn branch is not proof of activity.  Keep the Git
            # structure readable so the idle-group path can preserve it.
            result["git_revision_error"] = str(error)
        result["git_branch"] = git("branch", "--show-current") or "detached"
        status = git("status", "--porcelain", "--untracked-files=all")
        result["git_status_readable"] = True
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        result["finalization_reason"] = f"Git 状态不可读：{error}"
        return result
    result["git_clean"] = not bool(status)
    result["git_status_digest"] = hashlib.sha256(status.encode("utf-8")).hexdigest()
    current = Path.cwd().resolve().is_relative_to(path.resolve())
    result["current_working_directory"] = current
    active, note = (True, "当前执行目录仍在 worktree 内") if current else open_handle_status(path)
    result["active"] = active
    result["activity"] = note
    if current:
        result["finalization_reason"] = "当前执行目录，暂不迁移"
        return result
    if active is not False:
        result["finalization_reason"] = "仍有打开句柄或活动状态未知"
    elif not result["git_clean"]:
        # Dirty content is eligible for the separate long-idle group route;
        # it is never silently treated as a finalized clean worktree.
        result["finalization_reason"] = "存在未提交或未跟踪变更；仅可由关联组长期闲置规则进一步判断"
    elif not result["has_head"]:
        result["finalization_reason"] = "Git 状态可读但没有有效 HEAD；仅可由关联组长期闲置规则进一步判断"
    else:
        result["finalized_candidate"] = True
        result["finalization_reason"] = "Git 工作树干净、已有提交、非当前目录且没有打开句柄"
    return result


def old_archive_entries(path: Path, older_than_days: int = ARCHIVE_RETENTION_DAYS) -> list[dict[str, Any]]:
    """List only real archived conversation files older than the retention window."""
    cutoff = time.time() - older_than_days * 86400
    entries: list[dict[str, Any]] = []
    context = scan_context.current()
    inventory_file_rows = context.file_rows if context else {}
    indexed_rows = [
        row for row in inventory_file_rows.values()
        if Path(row["path"]).parent == path.absolute()
    ]
    if inventory_file_rows and not indexed_rows:
        children = []
    elif indexed_rows:
        children = [Path(row["path"]) for row in indexed_rows]
    else:
        try:
            children = sorted(path.iterdir(), key=lambda item: item.name)
        except OSError:
            return entries
    for child in children:
        if is_reparse_or_link(child) or not path_is_file(child):
            continue
        if not (child.name.endswith(".jsonl") or child.name.endswith(".jsonl.zst")):
            continue
        record = inventory_file_rows.get(str(child.absolute()))
        if record is not None:
            modified = int(record.get("modified_ns") or 0) / 1_000_000_000
            size_bytes = int(record.get("logical_bytes") or 0)
        else:
            try:
                stat = child.stat()
            except OSError:
                continue
            modified = stat.st_mtime
            size_bytes = stat.st_size
        if modified >= cutoff:
            continue
        entries.append({
            "path": str(child),
            "name": child.name,
            "size_bytes": size_bytes,
            "modified_at": iso_time(modified),
            "age_days": round(max(time.time() - modified, 0) / 86400, 1),
        })
    return entries


def user_homes() -> list[dict[str, Any]]:
    if os.name == "nt":
        parent = Path(os.environ.get("SystemDrive", "C:")) / "Users"
        excludes = {name.lower() for name in SYSTEM_PROFILE_NAMES}
    else:
        parent = Path("/Users")
        excludes = SYSTEM_PROFILE_NAMES
    records: list[dict[str, Any]] = []
    if not path_exists(parent):
        return records
    account_by_home: dict[str, str] = {}
    if os.name != "nt" and pwd is not None:
        try:
            account_by_home = {
                path_key(entry.pw_dir): entry.pw_name
                for entry in pwd.getpwall()
                if entry.pw_dir
            }
        except (ImportError, OSError):
            account_by_home = {}
    try:
        entries = sorted(parent.iterdir(), key=lambda item: item.name.lower())
    except OSError:
        return records
    for home in entries:
        if not path_is_dir(home) or is_reparse_or_link(home):
            continue
        if (home.name.lower() in excludes if os.name == "nt" else home.name in excludes):
            continue
        try:
            readable = os.access(home, os.R_OK | os.X_OK)
            if readable:
                with os.scandir(home):
                    pass
        except OSError:
            readable = False
        records.append({
            "user": account_by_home.get(path_key(home), home.name),
            "home": str(home),
            "readable": bool(readable),
            "identity_source": "系统账户资料" if path_key(home) in account_by_home else "用户目录",
            "codex_roots": [],
            "issues": [] if readable else ["主目录不可完整读取"],
        })
    return records


def system_account_home() -> tuple[str, Path]:
    """Read the execution account and home from the OS account database."""
    if os.name != "nt" and pwd is not None:
        account = pwd.getpwuid(os.getuid())
        return account.pw_name, Path(account.pw_dir).absolute()
    return getpass.getuser(), Path.home().absolute()


def current_account_record(user: str, home: Path) -> dict[str, Any]:
    readable = False
    try:
        readable = os.access(home, os.R_OK | os.X_OK)
        if readable:
            with os.scandir(home):
                pass
    except OSError:
        readable = False
    return {
        "user": user,
        "home": str(home),
        "readable": readable,
        "identity_source": "系统账号资料",
        "codex_roots": [],
        "issues": [] if readable else ["当前账号主目录不可完整读取"],
    }


def active_workspace_roots(home: Path) -> set[str]:
    cwd = Path.cwd().absolute()
    if not storage_discovery._same_or_below(cwd, home):
        return set()
    try:
        result = bounded_process.run(
            ["git", "-C", str(cwd), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=4,
        )
        if result.returncode == 0 and result.stdout.strip():
            root = Path(result.stdout.strip()).absolute()
            if storage_discovery._same_or_below(root, home):
                return {str(root)}
    except (OSError, subprocess.SubprocessError):
        pass
    return {str(cwd)}


def root_candidates(home: Path) -> list[tuple[Path, str, str]]:
    if os.name == "nt":
        candidates = [
            (home / ".codex", "用户的 Codex 文件夹", "codex"),
            (home / "AppData" / "Local" / "Codex", "Codex 应用数据文件夹", "app-data"),
            (home / "AppData" / "Roaming" / "Codex", "Codex 应用数据文件夹", "app-data"),
            (home / "AppData" / "Local" / "OpenAI" / "Codex", "Codex 应用数据文件夹", "app-data"),
            (home / "AppData" / "Roaming" / "OpenAI" / "Codex", "Codex 应用数据文件夹", "app-data"),
        ]
    else:
        candidates = [
            (home / ".codex", "用户的 Codex 文件夹", "codex"),
            (home / "Library" / "Application Support" / "Codex", "Codex 应用数据文件夹", "app-data"),
            (home / "Library" / "Application Support" / "OpenAI" / "Codex", "Codex 应用数据文件夹", "app-data"),
            (home / "Library" / "Caches" / "Codex", "Codex 浏览器缓存", "codex-browser-cache"),
            (
                home / "Library" / "Caches" / "com.openai.codex"
                / "org.sparkle-project.Sparkle" / "Installation",
                "Codex 应用更新缓存", "codex-update-cache",
            ),
            (home / "Library" / "Logs" / "com.openai.codex", "Codex 诊断日志", "codex-logs"),
        ]
    seen: set[str] = set()
    roots: list[tuple[Path, str, str]] = []
    for path, label, kind in candidates:
        key = path_key(path)
        if key in seen or storage_discovery.local_path_status(path, home, (home / "Library" / "Mobile Documents", home / "Library" / "CloudStorage")) is not True or is_reparse_or_link(path) or not path_is_dir(path):
            continue
        seen.add(key)
        roots.append((path, label, kind))
    return roots


def candidate_item(
    *,
    user: dict[str, Any],
    path: Path,
    tier: str,
    artifact_type: str,
    provenance: str,
    reason: str,
    recommendation: str,
    recovery: str,
    root: Path,
    workspace_root: Path | None = None,
    action: str = "open",
    handle_check: bool = False,
    force_small: bool = False,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    size_bytes, size_error = safe_size(path)
    if size_bytes is None:
        user["issues"].append({"path": str(path), "reason": size_error or "无法测量"})
        return None
    if size_bytes < MIN_BYTES and not force_small:
        return None
    try:
        stat = path.stat()
        modified_at = stat.st_mtime
    except OSError:
        modified_at = None
    handle_state: bool | None = None
    handle_note = "还没有检查；处理前请再确认"
    if handle_check:
        handle_state, handle_note = open_handle_status(path)
    elif action == "trash":
        handle_note = "扫描时没有逐层检查；处理前请再确认"
    item: dict[str, Any] = {
        "user": user["user"],
        "home": user["home"],
        "platform": user["platform"],
        "path": str(path),
        "name": path.name or str(path),
        "tier": tier,
        "artifact_type": artifact_type,
        "size_bytes": size_bytes,
        "size": human_bytes(size_bytes),
        "modified_at": iso_time(modified_at),
        "age_days": round(max(time.time() - modified_at, 0) / 86400, 1) if modified_at else None,
        "provenance": provenance,
        "reason": reason,
        "recommendation": recommendation,
        "recovery": recovery,
        "activity": handle_note,
        "active": handle_state,
        "git_state": git_state(workspace_root or path.parent) if workspace_root else "不适用",
        "git_status_digest": (
            git_status_snapshot(workspace_root or path.parent)["digest"]
            if workspace_root else None
        ),
        "root": str(root),
        "workspace_root": str(workspace_root) if workspace_root else "",
        "verified": not bool(size_error) and not is_reparse_or_link(path),
        "trash_paths": [str(path)] if action == "trash" else [],
        "default_action": "direct-delete" if tier == "regenerable" and action == "trash" else "review",
        "open_paths": [str(path)] if path_exists(path) else [],
    }
    if extra:
        item.update(extra)
    candidate_path = path.absolute()
    context = scan_context.current()
    active_roots = context.active_workspace_roots if context else set()
    if any(
        candidate_path == Path(active_root) or candidate_path.is_relative_to(Path(active_root))
        for active_root in active_roots
    ):
        item.update({
            "tier": "protected",
            "default_action": "retain",
            "trash_paths": [],
            "active": True,
            "activity": "当前 Codex 执行目录所在项目；本轮保留",
            "recommendation": "当前 Codex 正在使用这个项目；本轮不删除或迁移其中内容。",
        })
    return item


def _inventory_cargo_output(path: Path, context: scan_context.ScanContext) -> bool:
    _ensure_inventory_indexes(context)
    file_paths = context.file_rows
    directories = context.directory_paths or set()
    if str((path / ".rustc_info.json").absolute()) not in file_paths:
        return False
    children = context.directory_children or {}
    for child in children.get(path.absolute(), ()):
        if child.name in {"debug", "release", "dev"}:
            if child / ".fingerprint" in directories:
                return True
        for grandchild in children.get(child, ()):
            if grandchild.name in {"debug", "release"} and grandchild / ".fingerprint" in directories:
                return True
    return False


def discover_nested_dirs(root: Path, inventory_directories: Iterable[str] | None = None) -> list[Path]:
    found: list[Path] = []
    found_keys: set[str] = set()
    root = root.absolute()
    stack: list[Path] = [root]
    inventory_children: dict[Path, list[Path]] | None = None
    inventory_directories_set: set[Path] | None = None
    inventory_files_by_directory: dict[Path, list[str]] | None = None
    inventory_file_paths: dict[str, dict[str, Any]] | None = None
    context = scan_context.current()
    if inventory_directories is not None:
        if context is not None:
            _ensure_inventory_indexes(context, inventory_directories)
            inventory_children = context.directory_children
            inventory_directories_set = context.directory_paths
            inventory_files_by_directory = context.files_by_directory
            inventory_file_paths = context.file_rows
            cached = context.nested_dir_results.get(str(root))
            if cached is not None:
                return list(cached)
            covering_root = context.nested_dir_coverage.get(str(root))
            covering_results = (
                context.nested_dir_results.get(covering_root)
                if covering_root is not None else None
            )
            if covering_results is not None and covering_root != str(root):
                descendants: list[Path] = []
                for candidate in covering_results:
                    try:
                        relative = candidate.relative_to(root)
                    except ValueError:
                        continue
                    if relative.parts:
                        descendants.append(candidate)
                context.nested_dir_results[str(root)] = tuple(descendants)
                context.nested_dir_coverage.setdefault(str(root), covering_root)
                return descendants
        else:
            inventory_children = {}
            inventory_directories_set = set()
            for raw in inventory_directories:
                child = Path(raw).absolute()
                inventory_directories_set.add(child)
                if child == child.parent:
                    continue
                inventory_children.setdefault(child.parent, []).append(child)
            for entries in inventory_children.values():
                entries.sort(key=lambda item: (item.name.casefold(), str(item)), reverse=True)
    while stack:
        scan_budget.check("Codex 项目产物分类")
        current = stack.pop()
        if context is not None and inventory_children is not None:
            context.nested_dir_coverage.setdefault(str(current), str(root))
        if inventory_children is not None:
            entries = inventory_children.get(current, [])
            current_file_paths = (inventory_files_by_directory or {}).get(current, [])
            current_file_names = {Path(value).name for value in current_file_paths}
        else:
            try:
                entries = sorted(current.iterdir(), key=lambda item: item.name.lower(), reverse=True)
            except OSError:
                continue
            current_file_paths = []
            current_file_names = set()
        package_json = current / "package.json"
        package_present = (
            "package.json" in current_file_names
            if inventory_children is not None else package_json.is_file()
        )
        if package_present:
            try:
                package = json.loads(package_json.read_text(encoding="utf-8"))
                scripts = package.get("scripts", {}) if isinstance(package, dict) else {}
                dependencies = {
                    **(package.get("dependencies", {}) if isinstance(package, dict) else {}),
                    **(package.get("devDependencies", {}) if isinstance(package, dict) else {}),
                }
                if inventory_children is not None:
                    configs = [
                        Path(value) for value in current_file_paths
                        if Path(value).name.startswith(("vite.config.", "next.config."))
                    ]
                    configs.sort(key=lambda item: item.name.casefold())
                else:
                    configs = list(current.glob("vite.config.*")) + list(current.glob("next.config.*"))

                def add_configured_output(value: Any) -> None:
                    if not isinstance(value, str) or not value.strip():
                        return
                    output = (current / value).resolve()
                    output_exists = (
                        output in (inventory_directories_set or set())
                        if inventory_children is not None else output.is_dir()
                    )
                    if output_exists and not is_reparse_or_link(output):
                        key_path = path_key(output)
                        if key_path not in found_keys:
                            found.append(output)
                            found_keys.add(key_path)
                for config in configs:
                    text = config.read_text(encoding="utf-8", errors="replace")
                    key = "outDir" if "vite" in config.name or "vite" in str(dependencies).casefold() else "distDir"
                    if key == "outDir" and not ("vite" in dependencies or "vite" in str(scripts)):
                        continue
                    if key == "distDir" and not ("next" in dependencies or "next" in str(scripts)):
                        continue
                    for match in re.finditer(rf"{key}\s*:\s*['\"]([^'\"]+)['\"]", text):
                        add_configured_output(match.group(1))
                for field in ("outputDirectory", "buildDirectory", "buildDir", "distDir", "outDir"):
                    add_configured_output(package.get(field))
                for script in scripts.values() if isinstance(scripts, dict) else ():
                    if not isinstance(script, str) or not re.search(r"\b(build|bundle|compile|export)\b", script, re.I):
                        continue
                    for match in re.finditer(
                        r"(?:--(?:out-dir|outDir|output-dir|output-path|target-dir|dist-dir)|(?:OUT_DIR|OUTPUT_DIR))\s*(?:=|\s+)\s*['\"]?([^\s'\"]+)",
                        script,
                    ):
                        add_configured_output(match.group(1))
            except (OSError, ValueError, TypeError):
                pass
        for manifest in (current / "Cargo.toml", current / ".cargo" / "config.toml", current / ".cargo" / "config"):
            manifest_present = (
                str(manifest.absolute()) in (inventory_file_paths or {})
                if inventory_children is not None else manifest.is_file() and not manifest.is_symlink()
            )
            if not manifest_present:
                continue
            try:
                cargo_config = parse_toml(str(manifest))
                build_config = cargo_config.get("build", {}) if isinstance(cargo_config, dict) else {}
                target_dir = build_config.get("target-dir") if isinstance(build_config, dict) else None
                if isinstance(target_dir, str):
                    output = (current / target_dir).resolve()
                    output_exists = (
                        output in (inventory_directories_set or set())
                        if inventory_children is not None else output.is_dir()
                    )
                    if output_exists and not is_reparse_or_link(output):
                        key_path = path_key(output)
                        if key_path not in found_keys:
                            found.append(output)
                            found_keys.add(key_path)
            except (OSError, ValueError, TypeError):
                pass
        for entry in entries:
            if inventory_children is None and (not path_is_dir(entry) or is_reparse_or_link(entry)):
                continue
            name = entry.name
            # Cargo's registry contains an ``index`` directory, but that is
            # a download cache rather than a project build output. Continue
            # walking its known cache levels so the candidate is the actual
            # cache (for example ``.../index/<source>/.cache``).
            cargo_cache_ancestor = is_download_cache_path(entry)
            cargo_cache_terminal = name.casefold() in {".cache", "cache", "src", "git", "db"}
            is_cargo_output = (
                _inventory_cargo_output(entry, context)
                if inventory_children is not None and context is not None
                else cargo_output(entry)
            )
            if (name in BUILD_DIR_NAMES or is_cargo_output) and not (
                cargo_cache_ancestor and not cargo_cache_terminal
            ):
                key = path_key(entry)
                if key not in found_keys:
                    found.append(entry)
                    found_keys.add(key)
                continue
            if name in PRUNE_DIR_NAMES:
                continue
            stack.append(entry)
    if context is not None and inventory_children is not None:
        context.nested_dir_results[str(root)] = tuple(found)
    return found


def worktree_roots(root: Path) -> list[Path]:
    result: list[Path] = []
    try:
        first_level = [item for item in root.iterdir() if path_is_dir(item) and not is_reparse_or_link(item)]
    except OSError:
        return result
    for branch in first_level:
        if path_exists(branch / ".git"):
            result.append(branch)
            continue
        try:
            children = [item for item in branch.iterdir() if path_is_dir(item) and not is_reparse_or_link(item)]
        except OSError:
            continue
        if children:
            result.extend(children)
        else:
            result.append(branch)
    return result


def add_project_artifacts(
    *,
    user: dict[str, Any],
    root: Path,
    workspace_roots: Iterable[Path],
    items: list[dict[str, Any]],
    source_evidence: str = "Codex 元数据关联",
    static_references: list[dict[str, Any]] | None = None,
) -> None:
    seen: set[str] = set()
    context = scan_context.current()
    inventory_directories = (
        tuple(context.directory_sizes) if context else None
    )
    for workspace in workspace_roots:
        for path in discover_nested_dirs(workspace, inventory_directories):
            key = path_key(path)
            if key in seen:
                continue
            seen.add(key)
            try:
                stat = path.stat()
                age_days = max(time.time() - stat.st_mtime, 0) / 86400
            except OSError:
                age_days = 0
            name = path.name
            labels = {
                "target": ("Rust/Tauri 构建产物", "这是完整的构建目录；里面的源代码和 Git 文件夹会保留。"),
                "dist": ("前端发布产物", "项目设置和源代码不在清理范围内；这里只展示这个完整的输出文件夹。"),
                "build": ("构建输出", "只有确认整个文件夹都能重新生成时才处理；不会扩大到父工作区。"),
                ".build": ("Swift/Xcode 构建输出", "SwiftPM 或 Xcode 生成的构建目录；只有核对源码和配置后才处理。"),
                "node_modules": ("项目依赖目录", "可以重新安装，但可能让项目第一次启动变慢；请你确认。"),
                ".pnpm-store": ("项目包缓存", "可重新下载的包缓存；不删除项目源文件。"),
                ".vite": ("Vite 构建缓存", "删掉后会重新生成的前端缓存；这里只展示具体的子文件夹。"),
                ".next": ("Next.js 构建产物", "删掉后会重新生成的框架文件；这里只展示具体的子文件夹。"),
                "out": ("导出产物", "可能是你要保留的输出文件；请你确认是否还需要。"),
                "coverage": ("测试覆盖率输出", "删掉后可以重新生成，但可能是你要保留的测试记录。"),
                "__pycache__": ("Python 字节码缓存", "删掉后会重新生成，不影响源代码。"),
                ".pytest_cache": ("pytest 测试缓存", "删掉后会重新生成，不影响源代码。"),
                ".cache": ("项目缓存", "删掉后可以重新生成，但要先确认它确实属于这个项目。"),
                ".venv": ("Python 虚拟环境", "可以重新创建，但可能需要一些时间；它不代表整个工作区没有用。"),
                "venv": ("Python 虚拟环境", "可以重新创建，但可能需要一些时间；它不代表整个工作区没有用。"),
                "env": ("运行环境目录", "可能包含你的配置；请你确认。"),
            }
            artifact_type, name_reason = labels.get(name, ("工作区旧产物", "这个文件夹位于 Codex 管理的工作区里。"))
            retain_download = name in DOWNLOAD_DIR_NAMES or is_download_cache_path(path)
            if is_download_cache_path(path):
                artifact_type = "Cargo 下载缓存"
                name_reason = "Cargo registry/git 下载缓存，删除后需要重新下载并消耗流量。"
            if retain_download:
                tier = "protected"
                reason = "依赖或环境目录，删除后可能需要重新下载、安装并消耗流量。"
                action = "open"
                recommendation = "默认保留；可重新下载不代表值得清理。"
            elif age_days < OLD_ARTIFACT_DAYS:
                tier = "protected"
                reason = "最近修改，不能按旧产物处理；可能属于当前任务或正在使用的构建。"
                action = "open"
                recommendation = "保留；先确认对应任务已经关闭。"
            else:
                tier = "manual"
                reason = f"{name_reason} 最近修改约 {age_days:.1f} 天前，还需要你结合项目设置和实际情况确认。"
                action = "open"
                recommendation = "优先核实这个旧产物：确认来源、重建命令和本地依赖，并找出同组最新完整可用版本的精确保留路径；只有一份则保留。"
            cache_evidence = None if retain_download else _cache_rebuild_evidence(path)
            if cache_evidence:
                tier = "regenerable"
                action = "trash"
                artifact_type = {
                    "python-bytecode-cache": "Python 字节码缓存",
                    "pytest-cache": "pytest 测试缓存",
                    "project-rebuild-cache": "项目可重建缓存",
                    "rebuildable-intermediate": "可重建中间/转码/索引产物",
                }.get(cache_evidence["kind"], artifact_type)
                reason = cache_evidence["rebuild_basis"]
                recommendation = "确认没有进程使用后可直接删除；输入源码和项目配置仍保留，需要时可重新生成。"
            item = candidate_item(
                user=user,
                path=path,
                tier=tier,
                artifact_type=artifact_type,
                provenance=f"Codex 状态/配置明确关联的项目：{workspace}；依据：{source_evidence}",
                reason=reason,
                recommendation=recommendation,
                recovery="回收站可恢复；重建方式由项目的构建配置决定。",
                root=root,
                workspace_root=workspace,
                action=action,
                handle_check=False,
                extra={
                    "workspace_kind": "worktree" if root.name == ".codex" else "documents",
                    "retained_path": "待核实：同组最新完整可用产物；唯一版本保留",
                    "rebuild_command": "待查项目配置及对应源码版本",
                    "network_cost": "可能需要重新下载" if retain_download else "未知；待核实本地依赖和工具链",
                    "rebuild_time": "未知；未运行构建",
                    **(cache_evidence or {}),
                    "regeneration_evidence": cache_evidence or {},
                    "review_priority": (
                        "verified-regenerable-cache" if cache_evidence else
                        "retain-download" if retain_download else "old-artifact"
                    ),
                },
            )
            if item:
                items.append(item)

        # User-visible deliverables are not caches.  A narrow second pass
        # promotes only old paths with an explicit completion marker and no
        # supported reference; everything else remains review-only.
        try:
            output_references = (
                static_references if static_references is not None
                else extract_static_references([workspace])
            )
            children = list(workspace.iterdir()) if workspace.is_dir() else []
        except OSError:
            output_references, children = [], []
        output_paths: list[Path] = []
        for child in children:
            output_paths.append(child)
            if child.is_dir() and child.name.casefold() in BACKUP_OUTPUT_PARENT_NAMES:
                try:
                    output_paths.extend(child.iterdir())
                except OSError:
                    pass
        seen_outputs: set[str] = set()
        for output_path in output_paths:
            key = path_key(output_path)
            if key in seen_outputs or is_reparse_or_link(output_path):
                continue
            seen_outputs.add(key)
            output_item = _backup_output_candidate(
                user=user, root=root, workspace=workspace, path=output_path,
                references=output_references,
            )
            if output_item:
                items.append(output_item)


def scan_root(
    user: dict[str, Any], root: Path, label: str, kind: str, items: list[dict[str, Any]],
    archive_retention_days: int = ARCHIVE_RETENTION_DAYS,
    source_evidence: str | None = None,
    static_references: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    size_bytes, size_error = safe_size(root, timeout=40)
    root_info: dict[str, Any] = {
        "path": str(root),
        "label": label,
        "kind": kind,
        "size_bytes": size_bytes or 0,
        "size": human_bytes(size_bytes),
        "readable": size_error is None,
        "issues": [],
        "workspace_roots": [],
        "source_evidence": source_evidence or "固定 Codex 根路径",
    }
    if size_error:
        root_info["issues"].append(size_error)
        user["issues"].append({"path": str(root), "reason": size_error})
    user["codex_roots"].append(root_info)
    if root.is_file():
        # A precise file reference proves only this file. It never promotes
        # the containing directory to an actionable project root.
        root_info["scope"] = "exact-file"
        return root_info
    if kind == "codex-runtime":
        item = candidate_item(
            user=user,
            path=root,
            tier="protected",
            artifact_type="Codex 项目运行数据",
            provenance=f"已确认项目配置声明的精确运行数据路径：{source_evidence}",
            reason="这是项目配置明确指定的运行数据；本轮只统计并保留，不按项目构建产物分类。",
            recommendation="保留；只有来源配置、用途和依赖关系发生变化后才重新评估。",
            recovery="恢复方式由所属 Codex 项目配置和运行时决定。",
            root=root,
            action="open",
            force_small=True,
            extra={
                "default_action": "retain",
                "review_priority": "confirmed-codex-runtime",
                "source_file": source_evidence,
                "trash_paths": [],
            },
        )
        if item:
            items.append(item)
        return root_info
    if kind in {"documents", "codex-project"}:
        workspace_roots = [root] if kind == "codex-project" else discover_workspace_roots(root)
        root_info["workspace_roots"] = [str(item) for item in workspace_roots]
        seen_worktrees: set[str] = set()
        for workspace in workspace_roots:
            worktrees_dir = workspace / ".worktrees"
            if not path_is_dir(worktrees_dir) or is_reparse_or_link(worktrees_dir):
                continue
            for worktree in worktree_roots(worktrees_dir):
                marker = worktree / ".git"
                if not marker.is_file() or is_reparse_or_link(marker):
                    continue
                key = path_key(worktree)
                if key in seen_worktrees:
                    continue
                seen_worktrees.add(key)
                evidence = inspect_worktree(worktree)
                if not evidence.get("git_root") or not evidence.get("linked_worktree_registered"):
                    continue
                finalized = bool(evidence.get("finalized_candidate"))
                item = candidate_item(
                    user=user,
                    path=worktree,
                    tier="manual" if finalized else "protected",
                    artifact_type="已定稿项目 Git worktree" if finalized else "项目 Git worktree",
                    provenance=f"项目 {workspace} 登记的 linked worktree：{worktrees_dir}",
                    reason=evidence.get("finalization_reason", "Git 状态不可读"),
                    recommendation=(
                        "若关联组连续超过 168 小时无活动且所有检查通过，默认移动到 T1；原路径保留软链接。"
                        if finalized else "保留；仍需关联组连续超过 168 小时无活动并通过全部检查。"
                    ),
                    recovery="T1 工作树保持原有内容并保留本机 Git 公共元数据。",
                    root=root,
                    workspace_root=worktree,
                    action="open",
                    handle_check=False,
                    force_small=True,
                    extra={
                        **evidence,
                        "workspace_kind": "project-worktree",
                        "default_action": "migrate-to-t1" if finalized else "retain",
                        "review_priority": "finalized-worktree" if finalized else "active-worktree",
                        "backup_required": finalized,
                    },
                )
                if item:
                    items.append(item)
        add_project_artifacts(
            user=user,
            root=root,
            workspace_roots=workspace_roots,
            items=items,
            source_evidence=source_evidence or f"Codex 工作区登记：{root}",
            static_references=static_references,
        )
        return root_info
    if kind == "app-data":
        for relative in APP_CACHE_RELATIVE:
            path = root / Path(relative)
            if not path_is_dir(path) or is_reparse_or_link(path):
                continue
            is_crash = relative == "Crashpad/pending"
            item = candidate_item(
                user=user,
                path=path,
                tier="manual" if is_crash else "regenerable",
                artifact_type="Codex 崩溃诊断转储" if is_crash else "Codex 应用缓存",
                provenance=f"位于 Codex 应用数据文件夹：{root}；具体位置是 {relative}",
                reason=(
                    "待提交的崩溃报告可能包含诊断信息；如果 Codex 还在运行，请先退出并确认不再需要。"
                    if is_crash else
                    "浏览器和页面缓存删掉后会重新生成；只有在没有程序使用它时才考虑处理。"
                ),
                recommendation=(
                    "关闭 Codex，确认不需要这份崩溃报告并明确授权后，再移到废纸篓/回收站。"
                    if is_crash else
                    "确认没有程序正在使用后，再移到废纸篓/回收站；不会碰登录信息、设置或数据库。"
                ),
                recovery="macOS 废纸篓或 Windows 回收站可恢复；应用需要时会重新生成。",
                root=root,
                action="trash",
                handle_check=True,
                extra={"app_data_relative": relative},
            )
            if item:
                if is_crash:
                    item["active"] = True if user.get("codex_running") else item["active"]
                    if user.get("codex_running"):
                        item["activity"] = "Codex 进程仍在运行；退出后重新检查"
                items.append(item)
        return root_info
    if kind in {"codex-browser-cache", "codex-update-cache"}:
        operation = (
            "purge-browser-cache"
            if kind == "codex-browser-cache"
            else "purge-update-cache"
        )
        item = candidate_item(
            user=user,
            path=root,
            tier="regenerable",
            artifact_type="Codex 浏览器缓存" if kind == "codex-browser-cache" else "Codex 更新安装缓存",
            provenance=f"Codex 客户端固定缓存路径：{root}",
            reason=(
                "Codex/ChatGPT 完全退出且没有打开句柄后，浏览器缓存可重新生成。"
                if kind == "codex-browser-cache"
                else "确认更新器没有运行且缓存文件没有打开句柄后，可重新下载更新包。"
            ),
            recommendation="仅由专用清理器复核进程、句柄、路径和卷后删除；不备份。",
            recovery="Codex 或 ChatGPT 需要时会重新生成缓存。",
            root=root,
            action="trash",
            handle_check=False,
            force_small=True,
            extra={"cache_operation": operation},
        )
        if item:
            items.append(item)
        return root_info
    if kind == "codex-logs":
        context = scan_context.current()
        if context is None:
            root_info["issues"].append("缺少本次扫描文件清单；日志候选状态未知")
            return root_info
        cutoff = datetime.now(timezone.utc).timestamp() - ARCHIVE_RETENTION_DAYS * 86400
        cutoff_date = datetime.fromtimestamp(cutoff, tz=timezone.utc).date()
        for raw_path, record in sorted(context.file_rows.items()):
            path = Path(raw_path)
            try:
                relative = path.relative_to(root)
            except ValueError:
                continue
            if len(relative.parts) != 4 or path.suffix != ".log":
                continue
            year, month, day, _filename = relative.parts
            try:
                folder_date = datetime.strptime(
                    f"{year}-{month}-{day}", "%Y-%m-%d"
                ).date()
                stat_result = path.lstat()
            except (ValueError, OSError):
                root_info["issues"].append(f"日志状态无法读取：{path}")
                continue
            if (
                folder_date >= cutoff_date
                or stat_result.st_mtime >= cutoff
                or not stat.S_ISREG(stat_result.st_mode)
                or stat_result.st_uid != os.getuid()
            ):
                continue
            item = candidate_item(
                user=user,
                path=path,
                tier="regenerable",
                artifact_type="Codex 旧诊断日志",
                provenance=f"Codex 固定日志目录及日期路径：{root}",
                reason="日志目录日期和文件修改时间都超过 7 天；只删除此精确日志文件。",
                recommendation="执行前重新核对日期、所有权和打开句柄；旧日志不做备份。",
                recovery="已删除的旧诊断日志不能恢复。",
                root=root,
                action="trash",
                handle_check=False,
                force_small=True,
                extra={"cache_operation": "purge-old-codex-log"},
            )
            if item:
                items.append(item)
        return root_info

    # The .codex root contains both data and managed worktrees.  Keep the
    # containers visible as protected context, but only propose child paths.
    for name in (
        "sessions", "worktrees", "generated_images", "attachments", "plans", "skills",
        "automations", "computer-use", "shell_snapshots", "dictation-history",
    ):
        protected = root / name
        if path_is_dir(protected) and not is_reparse_or_link(protected):
            p_size, _ = safe_size(protected, timeout=28)
            item = candidate_item(
                user=user,
                path=protected,
                tier="protected",
                artifact_type={
                    "sessions": "当前/普通会话",
                    "worktrees": "Codex 工作目录集合",
                    "generated_images": "生成图片与用户输出",
                    "attachments": "会话附件",
                    "plans": "计划与任务上下文",
                    "skills": "已安装 skill",
                    "automations": "自动化配置",
                    "computer-use": "Computer Use 会话与应用",
                    "shell_snapshots": "Shell 快照与执行上下文",
                    "dictation-history": "听写历史",
                }[name],
                provenance=f"位于用户的 Codex 文件夹：{root}",
                reason="这是活动数据、用户输出、源代码容器或应用状态；本 skill 不把容器根当成可删除对象。",
                recommendation="保留；如果要处理里面的内容，必须先找到具体的子文件夹，并单独征得同意。",
                recovery="由 Codex 应用状态或用户备份负责恢复。",
                root=root,
                action="open",
                force_small=True,
                extra={"protected_context": True, "measured_bytes": p_size or 0},
            )
            if item:
                items.append(item)
    archive = root / "archived_sessions"
    if path_is_dir(archive) and not is_reparse_or_link(archive):
        files, file_note = count_files(archive)
        old_archives = old_archive_entries(archive, archive_retention_days)
        old_archive_bytes = sum(int(entry["size_bytes"]) for entry in old_archives)
        item = candidate_item(
            user=user,
            path=archive,
            tier="manual",
            artifact_type="归档/已关闭会话",
            provenance=f"Codex 固定归档目录：{archive}",
            reason=(
                f"归档会话按文件年龄处理；超过 {archive_retention_days} 天的已关闭会话先完整备份并校验，"
                "再只删除这些旧文件，不触碰最近归档和普通 sessions。"
            ),
            recommendation=(
                f"默认处理 {len(old_archives)} 个超过 {archive_retention_days} 天的归档文件：先备份到 T1 并校验，"
                "然后删除本机对应旧文件；较新的归档继续保留。"
                if old_archives else "目前没有超过 7 天的归档文件，继续保留。"
            ),
            recovery="保留备份；应用可能需要重建本地索引。",
            root=root,
            action="open",
            force_small=True,
            extra={
                "file_count": files,
                "file_count_note": file_note or "",
                "backup_required": bool(old_archives),
                "archive_retention_days": archive_retention_days,
                "archive_eligible_count": len(old_archives),
                "archive_eligible_bytes": old_archive_bytes,
                "archive_eligible_paths": [entry["path"] for entry in old_archives],
                "archive_eligible_files": old_archives,
                "default_action": "backup-then-delete" if old_archives else "retain",
                "review_priority": "archive-old" if old_archives else "archive-retain",
            },
        )
        if item:
            items.append(item)

    for relative, artifact_type, description in (
        ("cache", "Codex 用户缓存", "Codex 文件夹里的应用缓存，删掉后会重新生成。"),
        ("plugins/cache", "Codex 插件缓存", "插件包缓存，可按需重新下载；不删除已安装 skill。"),
        (".tmp", "Codex 临时文件", "Codex 任务或插件安装留下的临时文件；请先确认没有正在运行的任务。"),
    ):
        path = root / Path(relative)
        if not path_is_dir(path) or is_reparse_or_link(path):
            continue
        item = candidate_item(
            user=user,
            path=path,
            tier="regenerable",
            artifact_type=artifact_type,
            provenance=f"位于用户的 Codex 文件夹：{root}；具体位置是 {relative}",
            reason=description,
            recommendation="确认没有程序、任务或安装过程正在使用后，再移到废纸篓/回收站。",
            recovery="废纸篓/回收站可恢复；需要时 Codex 或插件系统会重新生成。",
            root=root,
            action="trash",
            handle_check=True,
        )
        if item:
            if relative == "plugins/cache":
                item["tier"] = "protected"
                item["default_action"] = "retain"
                item["recommendation"] = "默认保留插件包，避免重新下载；不计入推荐清理量。"
                item["trash_paths"] = []
            if item["active"] is True:
                item["tier"] = "protected"
                item["default_action"] = "retain"
                item["recommendation"] = "现在还有程序正在使用，先保留；退出 Codex 后重新检查。"
                item["trash_paths"] = []
            items.append(item)

    visualizations = root / "visualizations"
    if path_is_dir(visualizations) and not is_reparse_or_link(visualizations):
        try:
            buckets = sorted(visualizations.iterdir(), key=lambda item: item.name)
        except OSError:
            buckets = []
        for bucket in buckets:
            if not path_is_dir(bucket) or is_reparse_or_link(bucket) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", bucket.name):
                continue
            try:
                bucket_date = datetime.strptime(bucket.name, "%Y-%m-%d").date()
                age = (datetime.now().date() - bucket_date).days
            except ValueError:
                continue
            if age < OLD_ARTIFACT_DAYS:
                continue
            item = candidate_item(
                user=user,
                path=bucket,
                tier="manual",
                artifact_type="历史可视化/任务产物",
                provenance=f"Codex 生成的 visualizations 日期桶：{bucket}",
                reason="这是 Codex 任务生成的报告、输入或输出；属于用户可见产物，不按缓存自动清除。",
                recommendation="确认其中没有需要保留的报告、媒体或输入后，再按日期桶移到废纸篓/回收站。",
                recovery="废纸篓/回收站可恢复。",
                root=root,
                action="trash",
                handle_check=False,
                extra={"date_bucket": bucket.name},
            )
            if item:
                items.append(item)

    try:
        direct_children = list(root.iterdir())
    except OSError:
        direct_children = []
    log_databases = [
        child for child in direct_children
        if path_is_file(child) and not is_reparse_or_link(child)
        and re.match(r"logs(?:[_-].*)?\.sqlite(?:[-.]|$)", child.name, re.I)
    ]
    for path in sorted(log_databases, key=lambda item: item.name):
        item = candidate_item(
            user=user,
            path=path,
            tier="protected",
            artifact_type="Codex 日志数据库",
            provenance=f"位于用户的 Codex 文件夹：{root}；这是 SQLite 日志文件及其相关文件。",
            reason="日志数据库可能被当前应用、索引或诊断流程使用；不能仅按文件名或年龄删除。",
            recommendation="保留；如需清理，先确认应用格式、关闭进程并单独备份/授权。",
            recovery="依赖用户备份或应用重建，不能保证完整恢复。",
            root=root,
            action="open",
            force_small=True,
        )
        if item:
            items.append(item)
    backups = [
        child for child in direct_children
        if path_is_file(child) and not is_reparse_or_link(child)
        and re.search(r"(?:\.bak\d*|\.backup(?:\.|$)|\.tmp-[0-9])", child.name, re.I)
    ]
    for path in sorted(backups, key=lambda item: item.name):
        item = candidate_item(
            user=user,
            path=path,
            tier="manual",
            artifact_type="Codex 状态备份/临时文件",
            provenance=f"位于用户的 Codex 文件夹：{root}；文件名显示它可能是备份或临时文件。",
            reason="备份可能是恢复所需的状态，不能只按文件名自动删除。",
            recommendation="确认对应主文件和恢复需求后，逐个授权移到废纸篓/回收站。",
            recovery="废纸篓/回收站可恢复。",
            root=root,
            action="trash",
            force_small=True,
        )
        if item:
            items.append(item)

    worktrees = root / "worktrees"
    if path_is_dir(worktrees) and not is_reparse_or_link(worktrees):
        roots = worktree_roots(worktrees)
        root_info["workspace_roots"] = [str(item) for item in roots]
        for worktree in roots:
            evidence = inspect_worktree(worktree)
            if not evidence.get("git_root") or not evidence.get("linked_worktree_registered"):
                continue
            finalized = bool(evidence.get("finalized_candidate"))
            item = candidate_item(
                user=user,
                path=worktree,
                tier="manual" if finalized else "protected",
                artifact_type="已定稿 Git worktree" if finalized else "Git worktree",
                provenance=f"Codex 管理的 worktree：{worktrees}",
                reason=evidence.get("finalization_reason", "Git 状态不足以判断"),
                recommendation=(
                    "默认移动到 T1 的 Agent/archive/storage-observatory/worktrees，原路径保留软链接；"
                    "校验内容、修复 Git 登记后移除本机副本，释放空间。"
                    if finalized else "保留：Git 状态未能证明已经定稿或当前仍有活动。"
                ),
                recovery="T1 快照可按 manifest 校验并恢复到新路径。",
                root=root,
                workspace_root=worktree,
                action="open",
                handle_check=False,
                force_small=True,
                extra={
                    **evidence,
                    "default_action": "migrate-to-t1" if finalized else "retain",
                    "review_priority": "finalized-worktree" if finalized else "active-worktree",
                    "backup_required": finalized,
                },
            )
            if item:
                items.append(item)
        add_project_artifacts(
            user=user, root=root, workspace_roots=roots, items=items,
            static_references=static_references,
        )
    return root_info


def discover_workspace_roots(root: Path) -> list[Path]:
    """Keep the Documents root protected while exposing project children as context."""
    result: list[Path] = []
    try:
        for date_or_project in sorted(root.iterdir(), key=lambda item: item.name.lower()):
            if not path_is_dir(date_or_project) or is_reparse_or_link(date_or_project):
                continue
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_or_project.name):
                try:
                    children = [item for item in date_or_project.iterdir() if path_is_dir(item) and not is_reparse_or_link(item)]
                except OSError:
                    children = []
                result.extend(children or [date_or_project])
            else:
                result.append(date_or_project)
    except OSError:
        pass
    return result


def stable_count(items: list[dict[str, Any]], tier: str) -> int:
    return sum(1 for item in items if item.get("tier") == tier)


def _local_symlink_references(worktree_paths: Iterable[Path], home: Path) -> list[dict[str, Any]]:
    """Collect links inside worktrees without following them."""
    result: list[dict[str, Any]] = []
    for root in worktree_paths:
        if is_reparse_or_link(root) or not path_is_dir(root):
            continue
        try:
            for current, dirs, files in os.walk(root, followlinks=False):
                current_path = Path(current)
                names = list(dirs) + list(files)
                # Do not descend through linked directories; retain their
                # relationship as evidence instead.
                dirs[:] = [name for name in dirs if not (current_path / name).is_symlink()]
                for name in names:
                    link = current_path / name
                    if not link.is_symlink():
                        continue
                    try:
                        result.append(storage_discovery.safe_local_link(link, home, (home / "Library" / "Mobile Documents", home / "Library" / "CloudStorage")))
                    except OSError:
                        result.append({"path": str(link), "target_exists": None})
        except OSError:
            continue
    return result


def annotate_worktree_activity(
    items: list[dict[str, Any]],
    home: Path,
    *,
    project_references: list[dict[str, Any]] | None = None,
    project_issues: list[dict[str, Any]] | None = None,
    symlink_records: list[dict[str, Any]] | None = None,
    static_references: list[dict[str, Any]] | None = None,
    static_reference_issues: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Attach group activity evidence and select finalized/idle migrations."""
    worktree_items = [item for item in items if item.get("workspace_root") and item.get("git_root")]
    if not worktree_items:
        return {"groups": [], "by_path": {}, "references": [], "issues": [], "idle_threshold_seconds": 168 * 3600}
    paths = [Path(item["path"]).absolute() for item in worktree_items]
    items_by_path = {str(Path(item["path"]).absolute()): item for item in worktree_items}
    references = list(project_references or [])
    source_issues = list(project_issues or [])
    if static_references is None:
        static_references = extract_static_references(paths)
        static_issues = list(getattr(extract_static_references, "last_issues", []))
    else:
        static_issues = list(static_reference_issues or [])
    references.extend(static_references)
    activity = load_thread_activity(home)
    analysis = analyze_worktree_groups(
        worktree_items,
        thread_activity=activity,
        references=references,
        symlinks=[
            row for row in (symlink_records or [])
            if any(
                str(row.get("path", "")).startswith(str(path) + os.sep)
                for path in paths
            )
        ],
    )
    analysis["issues"] = source_issues + static_issues + list(analysis.get("issues", []))
    for group in analysis.get("groups", []):
        group_paths = [Path(path).absolute() for path in group.get("paths", [])]
        relevant_issues: list[dict[str, Any]] = []
        for issue in source_issues + static_issues:
            raw_path = issue.get("path") or issue.get("source_file")
            if not raw_path:
                continue
            try:
                issue_path = Path(str(raw_path)).expanduser().absolute()
            except OSError:
                continue
            if any(
                issue_path == group_path
                or issue_path.is_relative_to(group_path)
                or group_path.is_relative_to(issue_path)
                for group_path in group_paths
            ):
                relevant_issues.append(issue)
        if relevant_issues:
            group["blockers"] = sorted(set(group.get("blockers", [])) | {
                "关联组内存在未解决的配置/任务引用读取缺口"
            })
            group["activity_status"] = "unknown"
            group["idle"] = False
            group["reference_issues"] = relevant_issues
    for item in worktree_items:
        group = analysis.get("by_path", {}).get(str(Path(item["path"]).absolute()))
        if not group:
            item.update({
                "activity_status": "unknown",
                "group_status": "unknown",
                "migration_blockers": ["无法建立关联组活动证据"],
                "default_action": "retain",
                "review_priority": "worktree-activity-unknown",
            })
            continue
        item.update({
            "association_group_id": group["group_id"],
            "association_group_paths": group["paths"],
            "association_group": group,
            "latest_activity_at": group.get("latest_activity_at"),
            "latest_activity_epoch": group.get("latest_activity_epoch"),
            "idle_for_hours": group.get("idle_for_hours"),
            "idle_candidate": bool(group.get("idle")),
            "activity_status": group.get("activity_status", "unknown"),
            "group_status": group.get("activity_status", "unknown"),
            "migration_blockers": group.get("blockers", []),
            "reference_evidence": group.get("references", []),
        })
        # A finalization marker is only a candidate signal; it never overrides
        # recent or unknown activity.  Every group must still pass the full
        # continuous 168-hour idle check before it can move.
        no_group_blockers = not group.get("blockers") and group.get("idle") is True
        group_members = [items_by_path.get(str(Path(path).absolute())) for path in group.get("paths", [])]
        all_group_members_finalized = bool(group_members) and all(
            member is not None and member.get("finalized_candidate") for member in group_members
        )
        finalized_route = bool(item.get("finalized_candidate")) and all_group_members_finalized and no_group_blockers
        idle_route = bool(group.get("idle"))
        can_migrate = (finalized_route or idle_route) and item.get("active") is False and not item.get("current_working_directory")
        if can_migrate:
            item["default_action"] = "migrate-to-t1"
            item["tier"] = "manual"
            item["review_priority"] = (
                "finalized-worktree" if finalized_route else "idle-worktree-group"
            )
            item["backup_required"] = True
            item["migration_reason"] = (
                "Git 工作树已定稿，关联组已连续超过 168 小时无活动且句柄、引用和 Git 检查通过；"
                "迁移完整保留其工作资料。"
                if finalized_route else
                "关联组超过连续 168 小时没有文件或相关会话活动；允许迁移脏工作树并完整保留工作资料。"
            )
            item["recommendation"] = "将整个关联组移动到 T1，校验并修复 Git/引用后，原路径保留软链接。"
        else:
            item["default_action"] = "retain"
            item["review_priority"] = "active-worktree" if group.get("activity_status") == "recent" and not group.get("blockers") else "worktree-activity-unknown"
            item["backup_required"] = False
            item["recommendation"] = "保留：关联组仍有近期活动、打开状态未知或活动证据不完整。"
    return analysis


def normalize_association(association: dict[str, Any] | None) -> dict[str, Any]:
    """Give every inventory record the same source/ownership vocabulary."""
    value = dict(association or {})
    codex_related = bool(value.get("codex_related"))
    value.setdefault("project_key", None)
    value.setdefault("source_root", None)
    value.setdefault("evidence", "来源暂未确认")
    value.setdefault("codex_source_evidence", "Codex 来源暂未确认")
    value.setdefault("confidence", "unknown")
    value.setdefault("origin_state", "confirmed-codex" if codex_related else "unknown")
    value.setdefault("source_status", "confirmed" if codex_related else "unknown")
    value.setdefault("evidence_status", "readable" if codex_related else "missing")
    value.setdefault("evidence_error", None)
    value.setdefault("association_status", "confirmed" if codex_related else "unconfirmed")
    value.setdefault("activity_status", "not-checked")
    value.setdefault("disposition_class", "本地保留" if codex_related else "暂不处理")
    value.setdefault("planned_disposition_class", value.get("disposition_class", "暂不处理"))
    value.setdefault("suggested_disposition", "保留；按现有规则进一步评估" if codex_related else "暂不处理")
    value.setdefault("retention_note", "保留项待确认")
    value.setdefault("recovery_cost", "恢复代价待确认")
    value.setdefault("association_candidates", [])
    value.setdefault("association_errors", [])
    value.setdefault("evidence_paths", [])
    value["codex_related"] = codex_related
    return value


def _location_label(path: str, home: Path) -> str:
    try:
        relative = Path(path).relative_to(home).parts
    except ValueError:
        return "其他位置"
    if not relative:
        return "用户主目录"
    if relative[0] == ".codex":
        return ".codex"
    if relative[:2] == ("Documents", "Codex"):
        return "Documents/Codex 工程"
    if relative[:2] == ("Documents", "ChatGPT"):
        return "Documents/ChatGPT 工程"
    if relative[0] == "Library":
        return "Library/" + "/".join(relative[1:3]) if len(relative) >= 3 else "Library"
    return relative[0]


def build_usage_summary(records: list[dict[str, Any]], directory_summary: list[dict[str, Any]], home: Path) -> dict[str, Any]:
    """Build one non-overlapping Codex total and its human-readable breakdown."""
    unique: dict[str, dict[str, Any]] = {}
    for record in records:
        file_id = str(record.get("file_id") or record.get("path"))
        unique.setdefault(file_id, record)
    codex_records = [record for record in unique.values() if record.get("codex_related")]
    codex_logical = sum(int(record.get("logical_bytes") or 0) for record in codex_records)
    codex_allocated_values = [record.get("allocated_bytes") for record in codex_records]
    codex_allocated = None if any(value is None for value in codex_allocated_values) else sum(int(value or 0) for value in codex_allocated_values)
    project_rows: dict[str, dict[str, Any]] = {}
    for row in directory_summary:
        for project in row.get("project_totals") or []:
            key = project.get("project_key") or "Codex（项目名称暂未确认）"
            target = project_rows.setdefault(key, {"project_key": key, "logical_bytes": 0, "allocated_values": []})
            target["logical_bytes"] += int(project.get("logical_bytes") or 0)
            target["allocated_values"].append(project.get("allocated_bytes"))
    location_groups: dict[str, dict[str, Any]] = {}
    for row in directory_summary:
        logical = int(row.get("codex_logical_bytes") or 0)
        if not logical:
            continue
        label = _location_label(str(row.get("path") or ""), home)
        target = location_groups.setdefault(label, {
            "label": label, "logical_bytes": 0, "allocated_values": [],
            "paths": [], "project_keys": set(), "coverage_statuses": set(),
        })
        target["logical_bytes"] += logical
        allocated = row.get("codex_allocated_bytes")
        target["allocated_values"].append(allocated)
        if row.get("path"):
            target["paths"].append(str(row["path"]))
        target["project_keys"].update(row.get("project_keys") or [])
        target["coverage_statuses"].add(row.get("coverage_status", "未记录"))
    locations = []
    for label, value in location_groups.items():
        allocated_values = value["allocated_values"]
        allocated = None if any(item is None for item in allocated_values) else sum(int(item or 0) for item in allocated_values)
        paths = sorted(set(value["paths"]))
        locations.append({
            "path": paths[0] if len(paths) == 1 else label,
            "paths": paths[:20],
            "path_count": len(paths),
            "label": label,
            "logical_bytes": value["logical_bytes"],
            "logical_size": storage_discovery.human_bytes(value["logical_bytes"]),
            "allocated_bytes": allocated,
            "allocated_size": storage_discovery.human_bytes(allocated),
            "project_keys": sorted(value["project_keys"]),
            "coverage_status": "partial" if "partial" in value["coverage_statuses"] else "complete",
        })
    locations.sort(key=lambda item: item["logical_bytes"], reverse=True)
    projects = []
    for key, value in sorted(project_rows.items(), key=lambda item: item[1]["logical_bytes"], reverse=True):
        allocated_values = value["allocated_values"]
        allocated = None if any(item is None for item in allocated_values) else sum(int(item or 0) for item in allocated_values)
        projects.append({
            "project_key": key,
            "logical_bytes": value["logical_bytes"],
            "logical_size": storage_discovery.human_bytes(value["logical_bytes"]),
            "allocated_bytes": allocated,
            "allocated_size": storage_discovery.human_bytes(allocated),
        })
    codex_without_project = sum(int(record.get("logical_bytes") or 0) for record in codex_records if not record.get("project_key"))
    unconfirmed = sum(int(record.get("logical_bytes") or 0) for record in unique.values() if not record.get("codex_related"))
    return {
        "basis": "同一份文件清单；按文件身份去重；目录按不重叠边界归组",
        "codex_logical_bytes": codex_logical,
        "codex_logical_size": storage_discovery.human_bytes(codex_logical),
        "codex_allocated_bytes": codex_allocated,
        "codex_allocated_size": storage_discovery.human_bytes(codex_allocated),
        "codex_without_project_logical_bytes": codex_without_project,
        "codex_without_project_logical_size": storage_discovery.human_bytes(codex_without_project),
        "unconfirmed_logical_bytes": unconfirmed,
        "unconfirmed_logical_size": storage_discovery.human_bytes(unconfirmed),
        "locations": locations,
        "projects": projects,
        "trash_paths": [],
    }


def top_retained_contents(
    records: list[dict[str, Any]],
    roots: list[dict[str, Any]],
    items: list[dict[str, Any]],
    home: Path,
    *,
    include_cleanup_candidates: bool = False,
) -> list[dict[str, Any]]:
    """Rank non-overlapping Codex locations from the current local inventory."""
    def within(path: Path, root: Path) -> bool:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False

    root_paths = [
        (Path(row["path"]).absolute(), row.get("evidence", "Codex 元数据关联"))
        for row in roots if row.get("codex_source") and row.get("path")
    ]
    root_evidence = {str(path): evidence for path, evidence in root_paths}
    worktree_paths = {
        str(Path(item["path"]).absolute())
        for item in items if item.get("workspace_root") and item.get("git_root")
    }
    def group_for(raw_path: str) -> tuple[Path, str] | None:
        path = Path(raw_path).absolute()
        ancestors = (path, *path.parents)
        worktree = next(
            (candidate for candidate in ancestors if str(candidate) in worktree_paths),
            None,
        )
        if worktree is not None:
            return worktree, "Codex 登记的 linked worktree"
        root = next(
            (candidate for candidate in ancestors if str(candidate) in root_evidence),
            None,
        )
        if root is None:
            return None
        relative = path.relative_to(root)
        if root.name == ".codex" and relative.parts:
            if relative.parts[0] == "worktrees" and len(relative.parts) > 1:
                group_path = root / relative.parts[0] / relative.parts[1]
            else:
                group_path = root / relative.parts[0]
        else:
            group_path = root
        return group_path, root_evidence[str(root)]

    variants_by_id: dict[str, list[dict[str, Any]]] = {}
    for index, record in enumerate(records):
        if index % 1000 == 0:
            scan_budget.check("最大保留内容硬链接归组")
        if not record.get("path"):
            continue
        file_id = str(record.get("file_id") or record["path"])
        variants_by_id.setdefault(file_id, []).append(record)

    groups: dict[str, dict[str, Any]] = {}
    file_group_by_id: dict[str, str] = {}
    file_group_by_path: dict[str, str] = {}
    for index, (file_id, variants) in enumerate(variants_by_id.items()):
        if index % 1000 == 0:
            scan_budget.check("最大保留内容统计")
        classified = []
        for record in variants:
            match = group_for(str(record["path"]))
            if match is None:
                continue
            group_path, evidence = match
            chosen_path = str(Path(record["path"]).absolute())
            classified.append((
                -len(group_path.parts), str(group_path), chosen_path,
                group_path, evidence, record,
            ))
        if not classified:
            continue
        classified.sort(key=lambda row: row[:3])
        _depth, key, chosen_path, group_path, evidence, record = classified[0]
        file_group_by_id[file_id] = key
        for variant in variants:
            if variant.get("path"):
                file_group_by_path[str(Path(variant["path"]).absolute())] = key
        key = str(group_path)
        row = groups.setdefault(key, {
            "path": key, "logical_bytes": 0, "allocated_bytes": 0,
            "allocation_unknown": False, "file_count": 0, "file_ids": set(),
            "codex_evidence": evidence, "largest_files": [],
            "hard_link_paths": [], "component_names": set(),
            "manifest_paths": set(),
        })
        row["logical_bytes"] += int(record.get("logical_bytes") or 0)
        allocated = record.get("allocated_bytes")
        if allocated is None:
            row["allocation_unknown"] = True
        else:
            row["allocated_bytes"] += int(allocated)
        row["file_count"] += 1
        row["file_ids"].add(file_id)
        paths = sorted({
            str(Path(variant["path"]).absolute())
            for variant in variants if variant.get("path")
        })
        if len(paths) > 1:
            row["hard_link_paths"].append(paths)
        for member_path in paths:
            try:
                relative_member = Path(member_path).relative_to(group_path)
            except ValueError:
                continue
            if relative_member.parts:
                row["component_names"].add(relative_member.parts[0])
            if Path(member_path).name in {
                "Cargo.toml", "Package.swift", "package.json", "pyproject.toml",
                "codex-task.json", ".codex-task.json", "codex-run.json",
            }:
                row["manifest_paths"].add(member_path)
        row["largest_files"].append({
            "path": chosen_path,
            "logical_bytes": int(record.get("logical_bytes") or 0),
            "allocated_bytes": record.get("allocated_bytes"),
            "hard_link_paths": paths if len(paths) > 1 else [],
        })
        row["largest_files"].sort(key=lambda item: (-item["logical_bytes"], item["path"]))
        del row["largest_files"][5:]

    retained: list[dict[str, Any]] = []
    for row in groups.values():
        row["_file_identity_set"] = set(row["file_ids"])
        path = Path(row["path"])
        parts = {part.casefold() for part in path.parts}
        if path.name == "sessions" or path.name == "archived_sessions":
            reason = "会话数据按默认规则保留；只有超过 7 天且符合归档条件的精确文件才会先备份校验再删除。"
            condition = "逐文件核实归档年龄、活动状态及 T1 快照校验。"
        elif path.name == "worktrees" or "worktrees" in parts:
            reason = "这是源码和任务资料；只迁移关联组连续超过 168 小时无活动且活动、句柄、引用、Git 检查全部通过的整组。"
            condition = "未通过 168 小时或任一安全检查的工作树留在本机。"
        elif path.name in {"generated_images", "visualizations", "outputs", "attachments"}:
            reason = "这是用户可见成果或附件，不能仅因名称或年龄删除。"
            condition = "只有具备结束标记、超过 7 天无活动且无引用的精确成果，才备份校验后删除。"
        elif ".codex" not in parts:
            reason = "这是 Codex 元数据关联的项目内容；源码、依赖和用户成果默认保留。"
            condition = "只处理项目内有来源与重建证据的精确可再生内容或冗余旧构建。"
        else:
            reason = "这是 Codex 状态或用户数据，默认保留；只处理通过检查的精确可再生子项。"
            condition = "活动、来源、可再生性或引用状态未知时继续保留。"
        row["file_ids"] = len(row["file_ids"])
        row["allocated_bytes"] = None if row["allocation_unknown"] else row["allocated_bytes"]
        row["retained_reason"] = reason
        row["retention_reason"] = reason
        row["remaining_condition"] = condition
        row["evidence"] = row.pop("codex_evidence")
        row["allocation_unknown"] = row.pop("allocation_unknown")
        row["component_names"] = sorted(row["component_names"], key=str.casefold)[:12]
        row["hard_link_paths"] = sorted(row["hard_link_paths"], key=lambda values: tuple(values))
        row["manifest_paths"] = sorted(row.pop("manifest_paths"))[:4]
        relative = path.relative_to(home) if path.is_relative_to(home) else path
        parts = [part.casefold() for part in relative.parts]
        if "worktrees" in parts or ".worktrees" in parts:
            row["purpose"] = "关联 Git worktree 源码、配置和任务工作资料"
        elif path.name == "sessions":
            row["purpose"] = "Codex 会话活动与任务上下文"
        elif path.name == "archived_sessions":
            row["purpose"] = "已归档 Codex 会话文件"
        elif path.name == "cache" or "cache" in parts:
            row["purpose"] = "Codex 或已确认项目中的缓存/构建辅助数据"
        elif ".codex" in parts:
            row["purpose"] = "Codex 状态、插件配置或用户数据"
        else:
            row["purpose"] = "Codex 元数据关联的本地项目内容"
        row["largest_files"] = sorted(
            row["largest_files"], key=lambda item: (-item["logical_bytes"], item["path"])
        )
        retained.append(row)
    retained.sort(key=lambda row: (-int(row["logical_bytes"]), row["path"]))
    top = retained[:3]
    for row in top:
        row["manifest_evidence"] = []
        for manifest_path in row.pop("manifest_paths", []):
            scan_budget.check("最大保留项来源证据")
            manifest = Path(manifest_path)
            try:
                if manifest.stat().st_size > 64 * 1024:
                    row["manifest_evidence"].append({
                        "path": manifest_path,
                        "status": "文件超过 64 KiB，未读取内容",
                    })
                    continue
                if manifest.name == "Package.swift":
                    row["manifest_evidence"].append({
                        "path": manifest_path,
                        "kind": "Swift package manifest",
                        "status": "清单存在；未执行项目代码",
                    })
                    continue
                text = manifest.read_text(encoding="utf-8", errors="replace")
                if manifest.name == "package.json":
                    parsed = json.loads(text)
                    detail = parsed.get("name") if isinstance(parsed, dict) else None
                    evidence_kind = "Node 项目清单"
                elif manifest.name in {"Cargo.toml", "pyproject.toml"}:
                    parsed = parse_toml(str(manifest))
                    section = parsed.get("package") or parsed.get("project") or {}
                    detail = section.get("name") if isinstance(section, dict) else None
                    evidence_kind = "项目构建/包清单"
                else:
                    parsed = json.loads(text)
                    detail = None
                    if isinstance(parsed, dict):
                        detail = parsed.get("name") or parsed.get("task") or parsed.get("project")
                    evidence_kind = "Codex 任务来源标记"
                row["manifest_evidence"].append({
                    "path": manifest_path,
                    "kind": evidence_kind,
                    "declared_name": detail,
                    "status": "读取并解析",
                })
            except (OSError, ValueError, TypeError):
                row["manifest_evidence"].append({
                    "path": manifest_path,
                    "status": "来源文件无法读取或解析；用途保持未知",
                })
        row["manifest_evidence_status"] = (
            "已检查有限的项目/任务来源文件"
            if row["manifest_evidence"]
            else "清单中没有受支持的项目/任务来源文件；具体用途证据不足"
        )
        path = Path(row["path"])
        related = [
            item for item in items
            if item.get("path") and (
                within(Path(item["path"]).absolute(), path)
                or within(path, Path(item["path"]).absolute())
                or file_group_by_path.get(str(Path(item["path"]).absolute())) == str(path)
            )
        ]
        candidates = [
            {
                "path": item["path"],
                "proposed_action": item.get("default_action", "review"),
                "reason": item.get("recommendation") or item.get("reason") or "",
            }
            for item in related
            if item.get("default_action") in {"direct-delete", "backup-then-delete", "migrate-to-t1"}
        ]
        if candidates:
            row["policy_candidates_still_present"] = candidates[:8]
        row.pop("_file_identity_set", None)
    return top


def full_discovery(
    home: Path,
    *,
    duplicate_hash: bool,
    min_large_bytes: int,
    exclude_roots: Iterable[str | Path] = (),
    scan_roots: Iterable[str | Path] | None = None,
    hash_stall_seconds: int = storage_discovery.DEFAULT_HASH_STALL_SECONDS,
    inventory_path: str | Path | None = None,
    duplicate_evidence_path: str | Path | None = None,
    include_file_inventory: bool = True,
    metadata_first: bool = False,
    project_discovery: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the broad read-only discovery pass without creating action items.

    The scanner keeps one inventory for all regular files.  The large-file
    view is only a presentation threshold; it is never a discovery boundary.
    """
    phase_timings = {}
    phase_started = time.monotonic()
    def finish_phase(name):
        nonlocal phase_started
        scan_budget.check(f"全面发现阶段 {name}")
        phase_timings[name] = round(time.monotonic() - phase_started, 3)
        print(f"[storage-discovery] 阶段 {name} 完成 · {phase_timings[name]} 秒", file=sys.stderr, flush=True)
        phase_started = time.monotonic()
    print('[storage-discovery] 开始来源提取', file=sys.stderr, flush=True)
    if project_discovery is None:
        project_roots = storage_discovery.discover_project_roots(home)
        project_gaps = list(getattr(storage_discovery.discover_project_roots, "last_issues", []))
        source_references = list(getattr(storage_discovery.discover_project_roots, "last_references", []))
        runtime_data = list(getattr(storage_discovery.discover_project_roots, "last_runtime_data", []))
    else:
        project_roots = list(project_discovery.get("roots", []))
        project_gaps = list(project_discovery.get("issues", []))
        source_references = list(project_discovery.get("references", []))
        runtime_data = list(project_discovery.get("runtime_data", []))
    finish_phase('source-extraction')
    actual_scan_roots = (
        list(scan_roots)
        if scan_roots is not None
        else [Path(item["path"]) for item in project_roots]
    )
    progress_state = {"last": 0.0}
    def scan_progress(snapshot: dict[str, int]) -> None:
        now = time.monotonic()
        if now - progress_state["last"] >= 15:
            print(
                f"[storage-discovery] 遍历目录 {snapshot['directories']} · 文件 {snapshot['files']} · 大项 {snapshot['large_files']}",
                file=sys.stderr,
                flush=True,
            )
            progress_state["last"] = now
    cloud_excluded_roots = [home / "Library" / "Mobile Documents", home / "Library" / "CloudStorage"]
    result = storage_discovery.scan_large_files(
        actual_scan_roots,
        min_bytes=min_large_bytes,
        exclude=[*exclude_roots, *cloud_excluded_roots],
        link_scope_root=home,
        progress=scan_progress,
        metadata_first=metadata_first,
    )
    finish_phase('traversal')
    records = result.get("all_files", result["files"])
    storage_discovery.supplement_project_roots(home, project_roots, records)
    # Source-root containment is cheap and applies to every file. Git and
    # explicit project identity are resolved for large files and VM members;
    # small files still contribute to Codex/source totals without triggering a
    # subprocess for every cache byte.
    # The inventory can contain millions of files while Codex may expose many
    # source roots.  A linear ``relative_to`` probe for every file turns that
    # into an avoidable O(files * roots) pass.  Keep longest-prefix semantics
    # but resolve containment through a path-component trie instead.
    containing_root = storage_discovery.project_root_lookup(project_roots)

    association_errors: list[dict[str, Any]] = []
    for index, item in enumerate(records):
        if index % 1000 == 0:
            scan_budget.check("Codex 项目归属分析")
        path = Path(item["path"])
        containing = containing_root(path)
        needs_identity = bool(item.get("large") or item.get("kind") in {"virtual-machine-disk", "container-disk"})
        if needs_identity:
            association = storage_discovery.associate_project(item["path"], project_roots, scope_home=home)
        elif containing:
            association = {
                "project_key": containing.get("project_key"), "source_root": containing.get("path"),
                "evidence": containing.get("evidence", "来源根包含路径"),
                "codex_source_evidence": containing.get('codex_source_evidence', '未确认 Codex 来源'),
                "codex_related": bool(containing.get("codex_source")), "confidence": "source-only" if not containing.get("project_key") else "medium",
                "association_candidates": [], "association_errors": [],
            }
            for field in ("runtime_mapping_id", "app_id", "purpose", "source_status", "origin_state",
                          "evidence_status", "evidence_error", "association_status", "activity_status",
                          "disposition_class", "planned_disposition_class", "suggested_disposition",
                          "retention_note", "recovery_cost", "t1_hint", "evidence_paths"):
                if containing.get(field) is not None:
                    association[field] = containing[field]
        else:
            association = {
                "project_key": None, "source_root": None, "evidence": "未在 Codex 来源根内；未发现明确项目引用",
                "codex_source_evidence": "来源未知", "codex_related": False, "confidence": "unknown",
                "association_candidates": [], "association_errors": [], "origin_state": "unknown",
                "source_status": "unknown", "evidence_status": "missing", "evidence_error": None,
                "activity_status": "not-checked", "disposition_class": "暂不处理",
                "planned_disposition_class": "暂不处理", "suggested_disposition": "暂不处理",
                "retention_note": "保留项待确认", "recovery_cost": "恢复代价待确认",
            }
        association = normalize_association(association)
        item.update({
            "project_key": association.get("project_key"), "source_root": association.get("source_root"),
            "source_evidence": association.get("evidence"), "codex_source_evidence": association.get("codex_source_evidence"),
            "codex_related": association.get("codex_related", False), "project_confidence": association.get("confidence"),
            "origin_state": association.get("origin_state", "unknown"), "source_status": association.get("source_status", "unknown"),
            "evidence_status": association.get("evidence_status", "missing"), "evidence_error": association.get("evidence_error"), "association_status": association.get("association_status", "unconfirmed"),
            "runtime_mapping_id": association.get("runtime_mapping_id"), "app_id": association.get("app_id"),
            "purpose": association.get("purpose"), "activity_status": association.get("activity_status", "not-checked"),
            "disposition_class": association.get("disposition_class", "暂不处理"),
            "planned_disposition_class": association.get("planned_disposition_class", association.get("disposition_class", "暂不处理")),
            "suggested_disposition": association.get("suggested_disposition", "暂不处理"),
            "retention_note": association.get("retention_note", "保留项待确认"),
            "recovery_cost": association.get("recovery_cost", "恢复代价待确认"),
            "t1_hint": association.get("t1_hint"), "evidence_paths": association.get("evidence_paths", []),
            "association_candidates": association.get("association_candidates", []), "trash_paths": [],
            "discovery_only": True, "discovery_origin": "full-discovery",
        })
        association_errors.extend({"path": item["path"], "reason": error, "phase": "project-association"} for error in association.get("association_errors", []))

    finish_phase('project-association')
    print('[storage-discovery] 开始镜像依赖、挂载及运行检查', file=sys.stderr, flush=True)
    virtual_machines = storage_discovery.discover_virtual_machines(home, records)
    finish_phase('vm-dependencies')
    print('[storage-discovery] 开始重复分析', file=sys.stderr, flush=True)
    def hash_progress(snapshot: dict[str, Any]) -> None:
        now = time.monotonic()
        if now - progress_state["last"] >= 15:
            print(
                f"[storage-discovery] 重复校验 {snapshot['path']} · 已读 {snapshot['bytes']} 字节",
                file=sys.stderr,
                flush=True,
            )
            progress_state["last"] = now
    duplicates = storage_discovery.analyze_duplicates(
        records,
        full_hash=duplicate_hash,
        blocked_paths=virtual_machines.get("blocked_duplicate_paths", []),
        hash_stall_seconds=hash_stall_seconds,
        progress=hash_progress if duplicate_hash else None,
    )
    finish_phase('duplicate-analysis')
    test_runs = storage_discovery.discover_test_runs(
        home,
        project_roots,
        result["files"],
        records,
        symlinks=result.get("symlinks", []),
    )
    metadata_candidates = list(getattr(storage_discovery.discover_test_runs, 'last_candidates', []))
    for run in test_runs:
        run_project_paths = [path for path in run.get("project_paths", []) if storage_discovery._same_or_below(Path(path), home)]
        association = storage_discovery.associate_project(run["path"], project_roots, run_project_paths, scope_home=home)
        run.update({
            "project_key": association.get("project_key"),
            "source_root": association.get("source_root"),
            "source_evidence": association.get("evidence"),
            "codex_source_evidence": association.get("codex_source_evidence"),
            "codex_related": association.get("codex_related", False),
            "project_confidence": association.get("confidence"),
            "trash_paths": [], "discovery_only": True, "discovery_origin": "full-discovery",
        })
    for vm_item in virtual_machines.get("items", []):
        vm_item["discovery_only"] = True
        vm_item["discovery_origin"] = "full-discovery"
    for duplicate_key in ("groups", "deferred_groups", "unverified_same_size_groups", "hash_failures"):
        for duplicate_item in duplicates.get(duplicate_key, []):
            duplicate_item["discovery_only"] = True
            duplicate_item["discovery_origin"] = "full-discovery"
    finish_phase('test-analysis')
    unique_ids: set[str] = set()
    logical_bytes = 0
    allocated_values: list[int] = []
    codex_logical_bytes = 0
    unattributed_logical_bytes = 0
    codex_without_project_logical_bytes = 0
    large_logical_bytes = 0
    large_allocated_values: list[int] = []
    for index, item in enumerate(records):
        if index % 1000 == 0:
            scan_budget.check("Codex 容量汇总")
        if item["file_id"] in unique_ids:
            continue
        unique_ids.add(item["file_id"])
        logical_bytes += int(item.get("logical_bytes") or 0)
        if item.get("allocated_bytes") is not None:
            allocated_values.append(int(item["allocated_bytes"]))
        if item.get("large"):
            large_logical_bytes += int(item.get("logical_bytes") or 0)
            if item.get("allocated_bytes") is not None:
                large_allocated_values.append(int(item["allocated_bytes"]))
        if item.get("codex_related"):
            codex_logical_bytes += int(item.get("logical_bytes") or 0)
            if not item.get("project_key"):
                codex_without_project_logical_bytes += int(item.get("logical_bytes") or 0)
        else:
            unattributed_logical_bytes += int(item.get("logical_bytes") or 0)
    allocation_complete = len(allocated_values) == len(unique_ids)
    allocated_bytes = sum(allocated_values) if allocation_complete else None
    large_unique_ids: set[str] = set()
    for index, item in enumerate(records):
        if index % 1000 == 0:
            scan_budget.check("Codex 大文件容量汇总")
        if item.get("large"):
            large_unique_ids.add(item["file_id"])
    large_allocation_complete = len(large_allocated_values) == len(large_unique_ids)
    large_allocated_bytes = sum(large_allocated_values) if large_allocation_complete else None
    coverage_errors = list(result.get("errors", [])) + project_gaps + association_errors + list(virtual_machines.get("gaps", []))
    test_gaps = [gap for run in test_runs + metadata_candidates for gap in run.get("parse_gaps", [])]
    coverage_errors.extend(test_gaps)
    hash_gaps = list(duplicates.get("hash_failures", [])) if duplicate_hash else []
    coverage_errors.extend({"path": gap.get("path", ""), "reason": gap.get("reason", "校验失败"), "phase": "duplicate-hash"} for gap in hash_gaps)
    coverage_summary = storage_discovery.aggregate_diagnostics(coverage_errors,
        traversal_complete=result.get('traversal_complete', result['coverage_complete']), hash_requested=duplicate_hash)
    if result.get('signature_unchecked_count'):
        coverage_summary['stages']['type-identification'] = 'partial'
        coverage_summary['content_identification_complete'] = False
    else:
        coverage_summary['content_identification_complete'] = True
    coverage_complete = coverage_summary['coverage_complete']
    explanations = storage_explain.analyze(home, coverage_summary['diagnostics'], test_runs + metadata_candidates)
    finish_phase('purpose-analysis')
    small_summary = result.get("small_file_summary", [])
    directory_summary = storage_discovery.build_directory_summary(
        records,
        actual_scan_roots,
        extra_roots=[root.get("path") for root in project_roots],
        runtime_data=runtime_data,
        test_runs=test_runs,
        coverage_status="complete" if coverage_complete else "partial",
    )
    usage_summary = build_usage_summary(records, directory_summary, home)
    inventory_output = Path(inventory_path).expanduser().absolute() if inventory_path else None
    if inventory_output:
        inventory_output.parent.mkdir(parents=True, exist_ok=True)
        with inventory_output.open("w", encoding="utf-8") as stream:
            for item in records:
                stream.write(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n")
    duplicate_output = Path(duplicate_evidence_path).expanduser().absolute() if duplicate_evidence_path else None
    report_duplicates = duplicates
    if duplicate_output:
        duplicate_output.parent.mkdir(parents=True, exist_ok=True)
        evidence_keys = ("groups", "deferred_groups", "unverified_same_size_groups", "hash_failures")
        with duplicate_output.open("w", encoding="utf-8") as stream:
            for evidence_key in evidence_keys:
                for record in duplicates.get(evidence_key, []):
                    stream.write(json.dumps({"kind": evidence_key, "record": record}, ensure_ascii=False, separators=(",", ":")) + "\n")
        report_duplicates = dict(duplicates)
        display_limit = 200
        for evidence_key in evidence_keys:
            values = list(duplicates.get(evidence_key, []))
            report_duplicates[evidence_key] = values[:display_limit]
            report_duplicates[f"{evidence_key}_count"] = len(values)
            report_duplicates[f"{evidence_key}_displayed_count"] = min(len(values), display_limit)
        report_duplicates["full_evidence_path"] = str(duplicate_output)
        report_duplicates["display_limit"] = display_limit
    return {
        "enabled": True,
        "scope": str(home),
        "scan_roots": result.get("roots", [str(home)]),
        "scan_mode": "confirmed-codex-roots",
        "project_roots": project_roots,
        "runtime_mappings": runtime_data,
        'source_references': source_references,
        'metadata_candidates': metadata_candidates,
        'purpose_analysis': explanations,
        "large_files": result["files"],
        "file_inventory": records if include_file_inventory else [],
        "file_inventory_path": str(inventory_output) if inventory_output else None,
        "small_file_summary": small_summary,
        "directory_summary": directory_summary,
        "directory_sizes": result.get("directory_sizes", {}),
        "directory_activity": result.get("directory_activity", {}),
        "directory_summary_meta": {
            "status": "已记录",
            "total_count": len(directory_summary),
            "omitted_count": 0,
            "omitted_logical_bytes": 0,
            "omitted_allocated_bytes": 0,
        },
        "usage_summary": usage_summary,
        "test_runs": sorted(test_runs, key=lambda item: item["path"]),
        "virtual_machines": virtual_machines,
        "duplicates": report_duplicates,
        "coverage": {
            **coverage_summary,
            "roots": result["roots"],
            "excluded_roots": [{"path": str(path), "reason": "云同步目录按本地范围排除，未扫描"} for path in cloud_excluded_roots],
            "coverage_scope_note": "覆盖状态仅适用于排除云同步目录后的范围；排除不代表云目录为空或无引用。",
            "directories_scanned": result["directories_scanned"],
            "files_scanned": result["files_scanned"],
            "error_count": len(coverage_errors),
            "errors": coverage_errors,
            "skipped_mounts": result["skipped_mounts"],
            "symlinks": result["symlinks"],
            "interrupted": result["interrupted"],
            "coverage_complete": coverage_complete,
            "budget_exhausted": any(
                "扫描预算" in str(error.get("reason", "")) for error in coverage_errors
            ),
            "excluded_non_codex": [
                {"path": str(home / "Documents"), "reason": "仅用于有限项目入口发现，未递归扫描整个 Documents"},
                {"path": str(home / "Library" / "Mobile Documents"), "reason": "iCloud/云同步范围排除"},
                {"path": str(home / "Library" / "CloudStorage"), "reason": "iCloud/云同步范围排除"},
            ],
            "min_large_bytes": min_large_bytes,
            "duplicate_hash_requested": duplicate_hash,
            "hash_stall_seconds": hash_stall_seconds,
            "elapsed_seconds": result.get("elapsed_seconds"),
            "phase_timings": phase_timings,
            "metadata_first": metadata_first,
            "signature_unchecked_count": result.get('signature_unchecked_count', 0),
            "all_file_inventory_count": len(records),
            "file_inventory_path": str(inventory_output) if inventory_output else None,
            "large_file_count": len(result["files"]),
            "small_file_summary": small_summary,
            "directory_summary_count": len(directory_summary),
            "directory_summary_coverage": "complete" if coverage_complete else "partial",
            "runtime_mapping_count": len(runtime_data),
            "runtime_mapping_ids": sorted(item.get("id") for item in runtime_data if item.get("id")),
            "runtime_mapping_state_digest": storage_discovery.runtime_mapping_state_digest(runtime_data),
            "runtime_mapping_current_count": sum(1 for item in runtime_data if item.get("source_status") == "current"),
            "runtime_mapping_missing_count": sum(1 for item in runtime_data if item.get("source_status") != "current"),
            "project_discovery_gap_count": len(project_gaps),
            "test_profile_gap_count": len(test_gaps),
            "vm_gap_count": len(virtual_machines.get("gaps", [])),
            "duplicate_hash_gap_count": len(hash_gaps),
            "duplicate_evidence_path": str(duplicate_output) if duplicate_output else None,
        },
        "totals": {
            "scanned_logical_bytes": result["all_logical_bytes"],
            "scanned_logical_size": storage_discovery.human_bytes(result["all_logical_bytes"]),
            "scanned_allocated_bytes": result["all_allocated_bytes"],
            "scanned_allocated_size": storage_discovery.human_bytes(result["all_allocated_bytes"]),
            "discovered_logical_bytes": logical_bytes,
            "discovered_logical_size": storage_discovery.human_bytes(logical_bytes),
            "discovered_allocated_bytes": allocated_bytes,
            "discovered_allocated_size": storage_discovery.human_bytes(allocated_bytes),
            "large_logical_bytes": large_logical_bytes,
            "large_logical_size": storage_discovery.human_bytes(large_logical_bytes),
            "large_allocated_bytes": large_allocated_bytes,
            "large_allocated_size": storage_discovery.human_bytes(large_allocated_bytes),
            "codex_logical_bytes": codex_logical_bytes,
            "codex_logical_size": storage_discovery.human_bytes(codex_logical_bytes),
            "unattributed_logical_bytes": unattributed_logical_bytes,
            "unattributed_logical_size": storage_discovery.human_bytes(unattributed_logical_bytes),
            "codex_without_project_logical_bytes": codex_without_project_logical_bytes,
            "codex_without_project_logical_size": storage_discovery.human_bytes(codex_without_project_logical_bytes),
            "duplicate_logical_bytes": duplicates.get("logical_duplicate_bytes", 0),
            "duplicate_logical_size": duplicates.get("logical_duplicate_size", "0 B"),
            "physical_reclaimable": duplicates.get("physical_reclaimable", "未知"),
        },
        "trash_paths": [],
    }


@scan_context.scoped
def build_data(
    *,
    scope_home: Path | None = None,
    # Library callers keep the historical bounded default; the CLI and the
    # cleanup executor explicitly pass full discovery so their read-only plan
    # and execution rescan share the same broad source.
    full_discovery_enabled: bool = False,
    duplicate_hash: bool = False,
    min_large_bytes: int = storage_discovery.DEFAULT_LARGE_BYTES,
    discovery_exclude_roots: Iterable[str | Path] = (),
    discovery_roots: Iterable[str | Path] | None = None,
    hash_stall_seconds: int = storage_discovery.DEFAULT_HASH_STALL_SECONDS,
    discovery_inventory_path: str | Path | None = None,
    discovery_duplicate_evidence_path: str | Path | None = None,
    discovery_metadata_first: bool = True,
    archive_retention_days: int = ARCHIVE_RETENTION_DAYS,
    include_cleanup_candidates_in_retained: bool = False,
    discovery_subset_exclusions: Iterable[str | Path] = (),
    _account_lookup: Callable[[], tuple[str, Path]] | None = None,
) -> dict[str, Any]:
    context = scan_context.current()
    assert context is not None
    build_started = time.monotonic()
    phase_started = build_started
    build_phase_timings: dict[str, float] = {}

    def finish_build_phase(name: str) -> None:
        nonlocal phase_started
        scan_budget.check(name)
        now = time.monotonic()
        build_phase_timings[name] = round(now - phase_started, 3)
        phase_started = now

    now = time.time()
    context.git_identity_cache.clear()
    current_user, system_home = (_account_lookup or system_account_home)()
    scoped_home = (scope_home or system_home).expanduser().absolute()
    if current_user != "mac" or (
        _account_lookup is None and system_home != Path("/Users/mac")
    ):
        raise ValueError(
            f"Codex 清理只允许当前系统账号 mac、home /Users/mac；"
            f"实际为 {current_user}:{system_home}"
        )
    if scoped_home != system_home:
        raise ValueError(
            f"Codex 扫描只允许当前执行账号 {current_user} 的系统 home：{system_home}"
        )
    context.active_workspace_roots = active_workspace_roots(scoped_home)
    system_name = platform_module.system()
    platform_label = {"Darwin": "macOS", "Windows": "Windows", "Linux": "Linux"}.get(system_name, system_name)
    users = [
        current_account_record(current_user, system_home)
    ]
    project_roots = storage_discovery.discover_project_roots(scoped_home)
    project_discovery = {
        "roots": project_roots,
        "issues": list(getattr(storage_discovery.discover_project_roots, "last_issues", [])),
        "references": list(getattr(storage_discovery.discover_project_roots, "last_references", [])),
        "runtime_data": list(getattr(storage_discovery.discover_project_roots, "last_runtime_data", [])),
    }
    fixed_specs = [
        (path, label, kind, "受支持的 Codex 固定根路径")
        for path, label, kind in root_candidates(scoped_home)
    ]
    root_specs = list(fixed_specs)
    for source in project_roots:
        if not source.get("codex_source"):
            continue
        path = Path(source["path"]).absolute()
        if any(path == existing[0] for existing in root_specs):
            continue
        evidence = str(source.get("evidence") or "Codex 状态或会话元数据显式关联")
        if source.get("source_file"):
            evidence += f"; 来源文件 {source['source_file']}"
        if source.get("source_field"):
            evidence += f"; 字段 {source['source_field']}"
        runtime_root = source.get("root_kind") == "codex-runtime"
        root_specs.append((
            path,
            "Codex 项目运行数据" if runtime_root else "Codex 状态关联的项目/任务工作区",
            "codex-runtime" if runtime_root else "codex-project",
            evidence,
        ))
    root_specs.sort(key=lambda row: (len(row[0].parts), str(row[0])))
    try:
        home_device = int(scoped_home.stat().st_dev)
    except OSError:
        home_device = -1
    local_specs: list[tuple[Path, str, str, str]] = []
    external_root_issues: list[dict[str, Any]] = []
    for row in root_specs:
        try:
            root_device = int(row[0].lstat().st_dev)
        except OSError as error:
            external_root_issues.append({
                "path": str(row[0]), "reason": f"Codex 根无法核对卷归属：{error}",
                "phase": "scan-root-volume", "severity": "info",
            })
            continue
        if home_device < 0 or root_device != home_device:
            external_root_issues.append({
                "path": str(row[0]), "reason": "根位于账号 home 所在本机卷之外；按默认范围排除",
                "phase": "scan-root-volume", "severity": "info",
            })
            continue
        local_specs.append(row)
    root_specs = local_specs
    project_discovery["issues"].extend(external_root_issues)
    all_confirmed_root_paths = {row[0] for row in root_specs}
    inventory_root_specs = [
        row for row in root_specs
        if not any(parent in all_confirmed_root_paths for parent in row[0].parents)
    ]
    confirmed_roots = [row[0] for row in inventory_root_specs]
    if discovery_roots is not None:
        validated_roots: list[Path] = []
        excluded_roots: list[dict[str, str]] = []
        for raw in discovery_roots:
            path = Path(raw).expanduser().absolute()
            if (
                not any(path == root or path.is_relative_to(root) for root in confirmed_roots)
                or storage_discovery.local_path_status(
                    path, scoped_home,
                    (scoped_home / "Library" / "Mobile Documents", scoped_home / "Library" / "CloudStorage"),
                ) is not True
                or is_reparse_or_link(path)
                or not (path_is_dir(path) or path_is_file(path))
            ):
                excluded_roots.append({"path": str(path), "reason": "不在已确认 Codex 根内、不可读、云目录或链接路径"})
                continue
            validated_roots.append(path)
        if excluded_roots:
            project_discovery["issues"].extend({
                "path": item["path"], "reason": item["reason"], "phase": "scan-root-validation"
            } for item in excluded_roots)
        scan_roots = validated_roots
    else:
        scan_roots = confirmed_roots
    candidate_root_specs = [
        row for row in root_specs
        if any(row[0] == scan_root or row[0].is_relative_to(scan_root) for scan_root in scan_roots)
    ]
    for scan_path in scan_roots:
        if not any(row[0] == scan_path for row in candidate_root_specs):
            candidate_root_specs.append((
                scan_path,
                "已确认 Codex 根内的显式扫描子目录",
                "codex-project",
                "通过已确认 Codex 根内边界校验；本次仅扫描该子目录",
            ))
    candidate_root_specs.sort(key=lambda row: (len(row[0].parts), str(row[0])))
    finish_build_phase("账号核验与 Codex 根发现")

    context.directory_sizes.clear()
    context.path_sizes.clear()
    context.file_rows.clear()
    context.static_references = None
    context.static_reference_issues.clear()
    large_file_discovery = (
        full_discovery(
            scoped_home,
            duplicate_hash=duplicate_hash,
            min_large_bytes=min_large_bytes,
            exclude_roots=[*discovery_exclude_roots],
            scan_roots=scan_roots,
            hash_stall_seconds=hash_stall_seconds,
            inventory_path=discovery_inventory_path,
            duplicate_evidence_path=discovery_duplicate_evidence_path,
            include_file_inventory=True,
            metadata_first=discovery_metadata_first,
            project_discovery=project_discovery,
        )
        if full_discovery_enabled else {
            "enabled": False,
            "scope": "未执行 Codex 范围全面发现",
            "trash_paths": [],
        }
    )
    finish_build_phase("文件清单与基础分析")
    if full_discovery_enabled:
        coverage_complete = bool(large_file_discovery.get("coverage", {}).get("coverage_complete"))
        discovery_result_sizes = large_file_discovery.get("directory_sizes", {})
        context.directory_sizes = {
            str(Path(path).absolute()): {**row, "scan_complete": coverage_complete and bool(row.get("scan_complete"))}
            for path, row in discovery_result_sizes.items()
        }
        context.path_sizes = dict(context.directory_sizes)
        file_rows = large_file_discovery.get("file_inventory", [])
        context.file_rows = {
            str(Path(row["path"]).absolute()): row
            for row in file_rows
            if row.get("path")
        }
        for path, row in context.file_rows.items():
            context.path_sizes[path] = {
                "logical_bytes": int(row.get("logical_bytes") or 0),
                "file_count": 1,
                "scan_complete": coverage_complete,
                "entry_type": "file",
            }

        reference_roots: list[Path] = []
        for path, _label, kind, _evidence in root_specs:
            if kind == "codex-project":
                reference_roots.append(path)
                worktrees_dir = path / ".worktrees"
            elif kind == "codex":
                worktrees_dir = path / "worktrees"
            else:
                continue
            if path_is_dir(worktrees_dir) and not is_reparse_or_link(worktrees_dir):
                reference_roots.extend(worktree_roots(worktrees_dir))
        inventory_entries = list(file_rows)
        for link_row in large_file_discovery.get("coverage", {}).get("symlinks", []):
            link_row["entry_type"] = "symlink"
            link_row["name"] = Path(link_row.get("path", "")).name
            inventory_entries.append(link_row)
        context.static_references = extract_static_references(
            reference_roots,
            inventory_records=inventory_entries,
        )
        context.static_reference_issues = list(getattr(extract_static_references, "last_issues", []))
        context.directory_activity = large_file_discovery.get("directory_activity", {})
        finish_build_phase("静态引用索引")

    items: list[dict[str, Any]] = []
    for user in users:
        user["platform"] = platform_label
        user["codex_running"], user["active_processes"] = active_process_snapshot()
        if not user["readable"]:
            continue
        for root, label, kind, evidence in candidate_root_specs:
            scan_root(
                user, root, label, kind, items, archive_retention_days, evidence,
                static_references=context.static_references,
            )

    # Do not publish duplicate nested records if a case-insensitive path was
    # discovered through two platform-specific aliases.
    unique: dict[tuple[str, str], dict[str, Any]] = {}
    for item in items:
        key = (path_key(item["path"]), item["tier"])
        if key not in unique or item["size_bytes"] > unique[key]["size_bytes"]:
            unique[key] = item
    items = list(unique.values())
    items = decide_builds(items, open_handle_status)
    worktree_analysis = annotate_worktree_activity(
        items,
        scoped_home,
        project_references=project_discovery["references"],
        project_issues=project_discovery["issues"] + context.static_reference_issues,
        symlink_records=large_file_discovery.get("coverage", {}).get("symlinks", []),
        static_references=context.static_references,
        static_reference_issues=context.static_reference_issues,
    )
    finish_build_phase("清理候选与活动/引用复核")
    large_file_discovery["top_retained_contents"] = top_retained_contents(
        large_file_discovery.get("file_inventory", []),
        [
            {"path": str(path), "codex_source": True, "evidence": evidence}
            for path, _label, _kind, evidence in candidate_root_specs
        ],
        items,
        scoped_home,
        include_cleanup_candidates=True,
    )
    large_file_discovery.pop("file_inventory", None)
    large_file_discovery.pop("directory_sizes", None)
    large_file_discovery.pop("directory_activity", None)
    if full_discovery_enabled:
        scoped_user = next((user for user in users if path_key(user["home"]) == path_key(scoped_home)), None)
        if scoped_user:
            add_verified_duplicate_backup_candidates(
                user=scoped_user,
                home=scoped_home,
                discovery=large_file_discovery,
                items=items,
                static_references=context.static_references,
            )
    items.sort(key=lambda item: (item["tier"], -int(item.get("size_bytes") or 0), item["path"]))
    finish_build_phase("最大保留项与候选计划")

    green = [item for item in items if item["tier"] == "regenerable" and item.get("trash_paths")]
    manual = [item for item in items if item["tier"] == "manual"]
    protected = [item for item in items if item["tier"] == "protected"]
    candidate_items = green  # Unverified/user-data items are not recommended space.
    category_totals: dict[str, dict[str, Any]] = {}
    for item in candidate_items:
        key = item["artifact_type"]
        bucket = category_totals.setdefault(key, {"name": key, "size_bytes": 0, "count": 0})
        bucket["size_bytes"] += int(item.get("size_bytes") or 0)
        bucket["count"] += 1
    categories = sorted(category_totals.values(), key=lambda item: item["size_bytes"], reverse=True)
    for bucket in categories:
        bucket["size"] = human_bytes(bucket["size_bytes"])

    for user in users:
        roots = user.get("codex_roots") or []
        codex_bytes = sum(int(root.get("size_bytes") or 0) for root in roots)
        user_items = [item for item in items if item["user"] == user["user"] and item["home"] == user["home"]]
        candidate_bytes = sum(int(item.get("size_bytes") or 0) for item in user_items if item["tier"] == "regenerable")
        user["codex_bytes"] = codex_bytes
        user["codex_size"] = human_bytes(codex_bytes)
        user["candidate_bytes"] = candidate_bytes
        user["candidate_size"] = human_bytes(candidate_bytes)
        user["candidate_count"] = sum(1 for item in user_items if item["tier"] == "regenerable")
        user["protected_size"] = human_bytes(max(codex_bytes - candidate_bytes, 0))
        user["status"] = (
            "不可读取" if not user["readable"]
            else "部分受限" if user.get("issues")
            else "已读取"
        )

    codex_bytes = sum(int(user.get("codex_bytes") or 0) for user in users)
    candidate_bytes = sum(int(item.get("size_bytes") or 0) for item in candidate_items)
    green_bytes = sum(int(item.get("size_bytes") or 0) for item in green)
    build_items = [item for item in green if item.get("review_priority") == "delete-old-build"]
    build_bytes = sum(item["size_bytes"] for item in build_items)
    backup_items = [item for item in items if item.get("default_action") == "backup-then-delete"]
    archive_items = [item for item in backup_items if (item.get("backup_category") or "codex-archives") == "codex-archives"]
    archive_bytes = sum(int(item.get("archive_eligible_bytes") or 0) for item in archive_items)
    backup_bytes = sum(int(item.get("archive_eligible_bytes") or item.get("backup_eligible_bytes") or 0) for item in backup_items)
    duplicate_backup_items = [item for item in backup_items if item.get("review_priority") == "verified-duplicate-backup"]
    closed_output_items = [
        item for item in backup_items
        if (item.get("backup_category") or "codex-archives") != "codex-archives"
        and item.get("review_priority") != "verified-duplicate-backup"
    ]
    finalized_worktrees = [item for item in items if item.get("default_action") == "migrate-to-t1"]
    idle_worktrees = [item for item in finalized_worktrees if item.get("review_priority") == "idle-worktree-group"]
    manual_bytes = sum(int(item.get("size_bytes") or 0) for item in manual)
    protected_bytes = sum(int(item.get("size_bytes") or 0) for item in protected)
    timeline_buckets: dict[str, int] = {}
    for item in candidate_items:
        date = str(item.get("modified_at") or "未读取")[:10]
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
            timeline_buckets[date] = timeline_buckets.get(date, 0) + int(item.get("size_bytes") or 0)
    timeline = [
        {"date": date, "size_bytes": size, "size": human_bytes(size)}
        for date, size in sorted(timeline_buckets.items())[-14:]
    ]
    top_paths = [
        {
            "name": item["name"],
            "path": item["path"],
            "size_bytes": item["size_bytes"],
            "size": item["size"],
            "tier": item["tier"],
            "artifact_type": item["artifact_type"],
        }
        for item in sorted(candidate_items, key=lambda item: item["size_bytes"], reverse=True)[:14]
    ]
    codex_root_paths = [root["path"] for user in users for root in user.get("codex_roots", [])]
    issues = [
        {"user": user["user"], "home": user["home"], **issue}
        for user in users for issue in user.get("issues", [])
    ]
    unreadable = [user["home"] for user in users if not user["readable"]]
    generated_at = datetime.fromtimestamp(now).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    payload: dict[str, Any] = {
        "report_kind": "codex-storage-cleanup",
        "report_title": "Codex 文件清理检查",
        "generated_at": generated_at,
        "platform": {
            "name": platform_label,
            "system": system_name,
            "release": platform_module.release(),
            "arch": platform_module.machine(),
            "current_user": current_user,
            "active_processes": sorted({name for user in users for name in user.get("active_processes", [])}),
        },
        "scope": {
            "user_count": len(users),
            "readable_user_count": sum(1 for user in users if user["readable"]),
            "codex_root_count": len(codex_root_paths),
            "root_paths": codex_root_paths,
            "unreadable_homes": unreadable,
            "authorization_required": True,
            "default_cleanup_policy": "apply-defaults",
            "default_cleanup_policy_text": (
                "可再生缓存和经源码证实的旧构建直接删除；超过 7 天的归档会话先备份到 T1 再删除；"
                "关联组连续超过 168 小时无文件/会话活动且所有检查通过的 worktree 移动到 T1；定稿标记不能覆盖近期或未知状态，校验后移除本机副本并保留原路径软链接。"
            ),
            "account": scoped_home.name,
            "scan_mode": "confirmed-codex-roots" if full_discovery_enabled and not discovery_roots else "fixed" if not full_discovery_enabled else "explicit-codex-subroots",
            "discovery_roots": [str(path) for path in scan_roots] if full_discovery_enabled else [],
            "confirmed_roots": [
                {"path": str(path), "label": label, "kind": kind, "evidence": evidence}
                for path, label, kind, evidence in root_specs
            ],
            "scope_note": "仅扫描当前指定账号内有 Codex 固定路径或受支持 Codex 状态/会话依据的根；不遍历整个 home、Documents 或 Library。",
        },
        "users": users,
        "items": items,
        "worktree_analysis": worktree_analysis,
        "green": green,
        "yellow": manual,
        "red": protected,
        "categories": categories,
        "timeline": timeline,
        "top_paths": top_paths,
        "summary": {
            "codex_bytes": codex_bytes,
            "codex_size": human_bytes(codex_bytes),
            "candidate_bytes": candidate_bytes,
            "candidate_size": human_bytes(candidate_bytes),
            "regenerable_bytes": green_bytes,
            "old_build_bytes": build_bytes,
            "old_build_count": len(build_items),
            "archive_backup_delete_bytes": archive_bytes,
            "archive_backup_delete_size": human_bytes(archive_bytes),
            "archive_backup_delete_count": sum(int(item.get("archive_eligible_count") or 0) for item in archive_items),
            "backup_then_delete_bytes": backup_bytes,
            "backup_then_delete_size": human_bytes(backup_bytes),
            "backup_then_delete_count": len(backup_items),
            "closed_task_output_bytes": sum(int(item.get("backup_eligible_bytes") or 0) for item in closed_output_items),
            "closed_task_output_size": human_bytes(sum(int(item.get("backup_eligible_bytes") or 0) for item in closed_output_items)),
            "closed_task_output_count": len(closed_output_items),
            "duplicate_backup_bytes": sum(int(item.get("backup_eligible_bytes") or 0) for item in duplicate_backup_items),
            "duplicate_backup_size": human_bytes(sum(int(item.get("backup_eligible_bytes") or 0) for item in duplicate_backup_items)),
            "duplicate_backup_count": len(duplicate_backup_items),
            "finalized_worktree_count": len(finalized_worktrees),
            "idle_worktree_count": len(idle_worktrees),
            "worktree_migration_bytes": sum(int(item.get("size_bytes") or 0) for item in finalized_worktrees),
            "worktree_migration_size": human_bytes(sum(int(item.get("size_bytes") or 0) for item in finalized_worktrees)),
            "secondary_bytes": green_bytes - build_bytes,
            "regenerable_size": human_bytes(green_bytes),
            "manual_bytes": manual_bytes,
            "manual_size": human_bytes(manual_bytes),
            "protected_bytes": protected_bytes,
            "protected_size": human_bytes(protected_bytes),
            "candidate_count": len(candidate_items),
            "regenerable_count": len(green),
            "manual_count": len(manual),
            "protected_count": len(protected),
            "overview": (
                f"建议清理旧构建 {len(build_items)} 项，{human_bytes(build_bytes)}；每项目保留最新一份。"
                f"可再生缓存 {human_bytes(green_bytes - build_bytes)} 直接清理；"
                f"超过 7 天的归档及有结束证据的任务成果先备份后删 {human_bytes(backup_bytes)}；"
                f"定稿/长期闲置 worktree 移动到 T1 {human_bytes(sum(int(item.get('size_bytes') or 0) for item in finalized_worktrees))}；"
                f"未确认或用户数据 {human_bytes(manual_bytes)}。"
            ),
            "priority": [
                "默认直接删除可再生缓存和已证实的旧构建，每项目保留最新一份；不备份，因为它们可以从源码或程序重新生成。",
                "默认仅把关联组连续超过 168 小时无文件/会话活动且所有检查通过的 worktree 移动到 T1；定稿标记不能覆盖近期或未知状态，校验后删除本机副本并保留原路径软链接，计入预计释放量。",
                "默认把超过 7 天的归档会话，以及有结束标记且无引用的旧任务成果，完整备份到 T1，校验成功后删除对应本机路径；最近活动或证据不足的继续保留。",
            ],
            "long_term": [
                "每用户每项目保留最新一份构建目录，正在使用或明确指定保留的目录额外保留。",
                "默认保留 Cargo 下载缓存、依赖环境、工具链和插件包，避免反复下载；低成本缓存仅为次选。",
            ],
        },
        "ledger_meta": {
            "min_bytes": MIN_BYTES,
            "old_artifact_days": OLD_ARTIFACT_DAYS,
            "archive_retention_days": archive_retention_days,
            "issues": issues,
            "inspection_only": True,
            "scan_budget_seconds": scan_budget.configured_seconds(),
            "scan_elapsed_seconds": large_file_discovery.get("coverage", {}).get("elapsed_seconds"),
            "scan_budget_exhausted": large_file_discovery.get("coverage", {}).get("budget_exhausted", False),
            "default_cleanup_available": True,
            "default_cleanup_entrypoint": "scripts/apply_cleanup.py",
            "recommendation_review_pending": any(item.get("review_error") for item in items),
        },
        # The child server uses these homes for containment checks.  It never
        # treats a home itself as an action target.
        "allowed_user_homes": [user["home"] for user in users if user["readable"]],
    }
    if full_discovery_enabled:
        coverage = large_file_discovery.setdefault("coverage", {})
        phase_timings = dict(coverage.get("phase_timings") or {})
        phase_timings.update(build_phase_timings)
        coverage["phase_timings"] = phase_timings
        coverage["confirmed_roots"] = [
            {
                "path": str(path),
                "label": label,
                "kind": kind,
                "source": evidence,
            }
            for path, label, kind, evidence in candidate_root_specs
        ]
        excluded_roots = list(coverage.get("excluded_roots") or [])
        excluded_roots.extend(
            {
                "path": issue.get("path") or issue.get("source_file") or "",
                "reason": issue.get("reason", "按当前范围排除"),
            }
            for issue in project_discovery["issues"]
            if issue.get("phase") in {"scan-root-volume", "scan-root-validation"}
            or issue.get("code") in {"cloud-excluded", "outside-reference", "non-project-container"}
        )
        excluded_roots.extend([
            {"path": str(scoped_home), "reason": "只发现当前账号的 Codex 根；不递归整个 home"},
            {"path": str(scoped_home / "Documents"), "reason": "仅接受已确认的精确项目根；不递归整个 Documents"},
            {"path": str(scoped_home / "Library"), "reason": "只扫描固定 Codex 应用路径；不递归通用 Library"},
        ])
        excluded_roots.extend(
            {
                "path": str(Path(value).absolute()),
                "reason": (
                    "本轮报告写入目录；只排除此精确目录"
                    if index == 0 else "用户显式排除；结果作为扫描子集"
                ),
            }
            for index, value in enumerate(discovery_exclude_roots)
        )
        coverage["excluded_roots"] = excluded_roots
        explicit_exclusions = [str(Path(value).absolute()) for value in discovery_subset_exclusions]
        scope_complete = discovery_roots is None and not explicit_exclusions
        coverage["scope_complete"] = scope_complete
        coverage["scope_status"] = "全部已确认 Codex 根" if scope_complete else "显式 Codex 子集/排除"
        coverage["budget_seconds"] = scan_budget.configured_seconds()
        coverage["budget_exhausted"] = bool(coverage.get("budget_exhausted"))
        coverage["explicit_exclusions"] = explicit_exclusions
        coverage["scan_total_elapsed_seconds"] = round(time.monotonic() - build_started, 3)
        coverage["budget_exhausted"] = (
            bool(coverage.get("budget_exhausted"))
            or coverage["scan_total_elapsed_seconds"] > scan_budget.configured_seconds()
        )
        coverage["coverage_complete"] = (
            coverage.get("coverage_complete") is True
            and not coverage["budget_exhausted"]
        )
        payload["ledger_meta"]["scan_elapsed_seconds"] = coverage["scan_total_elapsed_seconds"]
        payload["ledger_meta"]["scan_budget_exhausted"] = coverage["budget_exhausted"]
    payload['cleanup_options'] = option_totals(items)
    payload['chat_report'] = render_chat_report(payload)
    payload["large_file_discovery"] = large_file_discovery
    if full_discovery_enabled:
        # Temporary input for the cleanup plan. The CLI removes it before
        # writing user-facing reports; apply_cleanup consumes it in memory.
        payload["_scan_file_entities"] = [
            {
                "path": row["path"],
                "identity": row.get("file_id") or row["path"],
                "bytes": int(row.get("logical_bytes") or 0),
                "allocated_bytes": row.get("allocated_bytes"),
            }
            for row in context.file_rows.values()
        ]
        payload["_scan_known_directories"] = sorted(context.directory_activity)
        plan_started = time.monotonic()
        scan_budget.check("清理计划生成")
        plan = cleanup_plan.build_plan(
            payload,
            scoped_home,
            human_bytes=human_bytes,
        )
        plan_summary = cleanup_plan.summarize(plan)
        scan_budget.check("清理计划生成")
        payload["cleanup_plan"] = plan
        payload["cleanup_plan_summary"] = plan_summary
        coverage = large_file_discovery.setdefault("coverage", {})
        coverage["phase_timings"] = {
            **(coverage.get("phase_timings") or {}),
            "cleanup-plan": round(time.monotonic() - plan_started, 3),
        }
        coverage["cleanup_plan_complete"] = not plan_summary["unmeasured_paths"]
        coverage["cleanup_plan_unmeasured_paths"] = plan_summary["unmeasured_paths"]
        if not coverage["cleanup_plan_complete"]:
            coverage["coverage_complete"] = False
            coverage.setdefault("diagnostics", []).append({
                "phase": "cleanup-plan",
                "code": "unmeasured-action-path",
                "severity": "error",
                "reason": "清理候选路径未能在本次文件清单中完整测量",
                "paths": plan_summary["unmeasured_paths"],
                "trash_paths": [],
            })
        coverage["acceptance_passed"] = (
            coverage.get("scope_complete") is True
            and coverage.get("coverage_complete") is True
            and coverage["cleanup_plan_complete"] is True
            and coverage.get("budget_exhausted") is not True
        )
    payload['chat_report'] = render_chat_report(payload)
    return payload


def main(
    *,
    _account_lookup: Callable[[], tuple[str, Path]] | None = None,
) -> int:
    command_started = time.monotonic()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True, help="报告与快照输出目录")
    parser.add_argument("--home", type=Path, help="限定一个本地用户主目录；默认由系统账号资料解析")
    parser.add_argument("--account", help="macOS 用户名；等价于 /Users/<account>")
    parser.add_argument("--root", action="append", type=Path, help="仅可指定已确认 Codex 根内的子目录；可重复指定")
    parser.add_argument("--scan-mode", choices=("fixed", "full"), default="full", help="full 表示已确认 Codex 根的全集")
    parser.add_argument("--full-discovery", action="store_true", help="兼容参数：等价于 --scan-mode full")
    parser.add_argument("--duplicate-hash", action="store_true", help="对同大小候选执行稳定 SHA-256 校验")
    parser.add_argument("--min-large-bytes", type=int, default=storage_discovery.DEFAULT_LARGE_BYTES)
    parser.add_argument("--hash-stall-seconds", type=int, default=storage_discovery.DEFAULT_HASH_STALL_SECONDS)
    parser.add_argument("--exclude", action="append", default=[], type=Path, help="额外排除指定路径；结果会标记为扫描子集")
    parser.add_argument("--no-inventory", action="store_true", help="兼容参数；默认只在内存中复用当次文件清单")
    parser.add_argument("--save-inventory", action="store_true", help="另存大体积 NDJSON 清单；会增加运行时间和磁盘写入")
    parser.add_argument("--metadata-first", dest="metadata_first", action="store_true", default=True,
                        help="默认只读取文件元数据及大文件/镜像签名；小文件类型单独标为未检查")
    parser.add_argument("--read-all-signatures", dest="metadata_first", action="store_false",
                        help="对所有文件读取签名；可能显著增加扫描耗时")
    parser.add_argument("--budget-seconds", type=int, default=scan_budget.DEFAULT_SCAN_BUDGET_SECONDS)
    parser.add_argument("--include-cleanup-candidates-in-retained", action="store_true",
                        help="复测清理后现存内容时，将仍在本机的默认策略候选也列作保留项")
    args = parser.parse_args()
    if args.budget_seconds < 1:
        parser.error("--budget-seconds 必须大于 0")
    scan_budget.start(args.budget_seconds)
    account_name, system_home = (_account_lookup or system_account_home)()
    if account_name != "mac" or (
        _account_lookup is None and system_home != Path("/Users/mac")
    ):
        parser.error(
            f"Codex 清理仅允许当前系统账号 mac、home /Users/mac；"
            f"实际为 {account_name}:{system_home}"
        )
    if args.account:
        if args.account != account_name:
            parser.error("默认扫描只允许当前执行账号")
        args.home = system_home
    elif args.home is None:
        args.home = system_home
    elif args.home.expanduser().absolute() != system_home:
        parser.error("--home 必须与系统账号资料中的当前用户 home 一致")
    scan_mode = "full" if args.full_discovery else args.scan_mode
    discovery_roots = [path.absolute() for path in args.root] if args.root is not None else None
    workspace = args.workspace.resolve()
    (workspace / "work").mkdir(parents=True, exist_ok=True)
    (workspace / "outputs").mkdir(parents=True, exist_ok=True)
    print('[storage-discovery] 开始构建、缓存及用户范围检查', file=sys.stderr, flush=True)
    payload = build_data(
        scope_home=args.home,
        full_discovery_enabled=scan_mode == "full",
        duplicate_hash=args.duplicate_hash,
        min_large_bytes=max(args.min_large_bytes, 1),
        discovery_exclude_roots=[workspace, *args.exclude],
        discovery_roots=discovery_roots,
        discovery_subset_exclusions=args.exclude,
        hash_stall_seconds=max(args.hash_stall_seconds, 1),
        discovery_inventory_path=workspace / "work" / "codex-discovery-inventory.ndjson" if args.save_inventory else None,
        discovery_duplicate_evidence_path=workspace / "work" / "codex-discovery-duplicates.ndjson",
        discovery_metadata_first=args.metadata_first,
        include_cleanup_candidates_in_retained=args.include_cleanup_candidates_in_retained,
        _account_lookup=_account_lookup,
    )
    payload['scan_elapsed_seconds'] = round(time.monotonic() - command_started, 3)
    data_collection_elapsed = payload['scan_elapsed_seconds']
    try:
        payload['free_bytes'] = shutil.disk_usage(args.home).free
    except OSError:
        payload['free_bytes'] = None
    payload['chat_report'] = render_chat_report(payload)
    payload.pop("_scan_file_entities", None)
    payload.pop("_scan_known_directories", None)
    data_path = workspace / "work" / "storage-analysis-live.json"
    data_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    report_path = workspace / "outputs" / "codex-storage-cleanup-report.html"
    builder = Path(__file__).with_name("build_codex_report.py")
    report_started = time.monotonic()
    result = bounded_process.run(
        [sys.executable, str(builder), str(data_path), str(report_path)],
        capture_output=True,
        text=True,
        timeout=90,
    )
    if result.returncode:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        return result.returncode
    total_elapsed = round(time.monotonic() - command_started, 3)
    discovery_coverage = payload["large_file_discovery"].get("coverage", {})
    discovery_coverage["phase_timings"] = {
        **(discovery_coverage.get("phase_timings") or {}),
        "report-generation": round(time.monotonic() - report_started, 3),
    }
    discovery_coverage["scan_total_elapsed_seconds"] = total_elapsed
    discovery_coverage["budget_exhausted"] = (
        bool(discovery_coverage.get("budget_exhausted"))
        or total_elapsed > scan_budget.configured_seconds()
    )
    if discovery_coverage["budget_exhausted"]:
        discovery_coverage["coverage_complete"] = False
    discovery_coverage["acceptance_passed"] = (
        discovery_coverage.get("scope_complete") is True
        and discovery_coverage.get("coverage_complete") is True
        and discovery_coverage.get("cleanup_plan_complete") is True
        and discovery_coverage.get("budget_exhausted") is not True
    )
    payload["scan_elapsed_seconds"] = total_elapsed
    payload["chat_report"] = render_chat_report(payload)
    data_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    metrics = {
        'total_elapsed_seconds': total_elapsed,
        'data_collection_seconds': data_collection_elapsed,
        'report_completed': True,
        'scope_complete': discovery_coverage.get("scope_complete"),
        'coverage_complete': discovery_coverage.get("coverage_complete"),
        'cleanup_plan_complete': discovery_coverage.get("cleanup_plan_complete"),
        'acceptance_passed': discovery_coverage.get("acceptance_passed"),
        'budget_exhausted': discovery_coverage.get("budget_exhausted"),
    }
    (workspace / 'work/run-metrics.json').write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2), encoding='utf-8'
    )
    final_elapsed = round(time.monotonic() - command_started, 3)
    if final_elapsed > scan_budget.configured_seconds():
        discovery_coverage["budget_exhausted"] = True
        discovery_coverage["coverage_complete"] = False
        discovery_coverage["acceptance_passed"] = False
    discovery_coverage["scan_total_elapsed_seconds"] = final_elapsed
    payload["scan_elapsed_seconds"] = final_elapsed
    metrics.update({
        "total_elapsed_seconds": final_elapsed,
        "scope_complete": discovery_coverage.get("scope_complete"),
        "coverage_complete": discovery_coverage.get("coverage_complete"),
        "cleanup_plan_complete": discovery_coverage.get("cleanup_plan_complete"),
        "acceptance_passed": discovery_coverage.get("acceptance_passed"),
        "budget_exhausted": discovery_coverage.get("budget_exhausted"),
    })
    data_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    (workspace / 'work/run-metrics.json').write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2), encoding='utf-8'
    )
    print(json.dumps({
        "data": str(data_path),
        "report": str(report_path),
        "platform": payload["platform"]["name"],
        "users": payload["scope"]["user_count"],
        "codex_roots": payload["scope"]["codex_root_count"],
        "candidate_count": payload["summary"]["candidate_count"],
        "candidate_size": payload["summary"]["candidate_size"],
        "regenerable_count": payload["summary"]["regenerable_count"],
        "manual_count": payload["summary"]["manual_count"],
        "protected_count": payload["summary"]["protected_count"],
        "large_discovery_enabled": payload["large_file_discovery"].get("enabled", False),
        "scope_complete": discovery_coverage.get("scope_complete"),
        "coverage_complete": discovery_coverage.get("coverage_complete"),
        "cleanup_plan_complete": discovery_coverage.get("cleanup_plan_complete"),
        "acceptance_passed": discovery_coverage.get("acceptance_passed"),
        "budget_exhausted": discovery_coverage.get("budget_exhausted"),
        "large_file_count": len(payload["large_file_discovery"].get("large_files", [])),
        "duplicate_logical_size": payload["large_file_discovery"].get("duplicates", {}).get("logical_duplicate_size", "未检查"),
        "virtual_machine_count": len(payload["large_file_discovery"].get("virtual_machines", {}).get("items", [])),
        "issues": len(payload["ledger_meta"]["issues"]),
        "cleanup_options": payload["cleanup_options"],
        "chat_report": payload["chat_report"],
    }, ensure_ascii=False, indent=2))
    return 0 if (
        discovery_coverage.get("scope_complete") is True
        and discovery_coverage.get("coverage_complete") is True
        and discovery_coverage.get("cleanup_plan_complete") is True
        and discovery_coverage.get("acceptance_passed") is True
        and discovery_coverage.get("budget_exhausted") is not True
    ) else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except scan_budget.ScanBudgetExceeded as error:
        print(json.dumps({
            "status": "failed",
            "scan": {
                "budget_seconds": scan_budget.configured_seconds(),
                "elapsed_seconds": round(scan_budget.elapsed(), 3),
                "budget_exhausted": True,
                "failure_phase": error.phase,
                "scope_complete": False,
                "coverage_complete": False,
            },
            "diagnostics": [str(error)],
        }, ensure_ascii=False, indent=2), file=sys.stderr)
        raise SystemExit(2)
