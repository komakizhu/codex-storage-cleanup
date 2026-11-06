"""Read-only worktree activity and reference grouping.

The cleanup policy cannot use a commit timestamp as a proxy for whether a
worktree is still in use.  This module keeps the evidence collection separate
from the action code so it can be exercised with temporary repositories and
so a missing conversation index remains visible as unknown evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
from typing import Any, Iterable

import scan_budget
import scan_context


IDLE_SECONDS = 168 * 60 * 60


def set_inventory_activity(values: dict[str, dict[str, Any]]) -> None:
    context = scan_context.current()
    if context is not None:
        context.directory_activity = values


def clear_inventory_activity() -> None:
    context = scan_context.current()
    if context is not None:
        context.directory_activity.clear()


def parse_timestamp(value: Any) -> float | None:
    """Convert supported index timestamps to Unix seconds without guessing."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        if number <= 0:
            return None
        # Codex stores both second and millisecond columns.
        return number / 1000.0 if number >= 100_000_000_000 else number
    text = str(value).strip()
    if not text:
        return None
    try:
        return parse_timestamp(float(text))
    except ValueError:
        pass
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _last_activity(row: dict[str, Any]) -> tuple[float | None, list[str]]:
    values: list[tuple[float, str]] = []
    for field in ("updated_at_ms", "recency_at_ms", "updated_at", "recency_at"):
        value = parse_timestamp(row.get(field))
        if value is not None:
            values.append((value, field))
    if not values:
        return None, []
    latest = max(value for value, _ in values)
    return latest, sorted({field for value, field in values if value == latest})


def _database_paths(home: Path) -> list[Path]:
    root = home / ".codex"
    paths = [root / "state.sqlite"]
    try:
        paths.extend(sorted(root.glob("state*.sqlite")))
    except OSError:
        pass
    result: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = os.path.normcase(os.path.abspath(path))
        if key in seen or not path.is_file() or path.is_symlink():
            continue
        seen.add(key)
        result.append(path)
    return result


def _read_sqlite(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    records: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    uri = f"file:{path}?mode=ro"
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=2)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        tables = {
            str(row[0]) for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        if "threads" not in tables:
            issues.append({"path": str(path), "reason": "会话索引没有 threads 表", "phase": "conversation-index"})
            return records, issues
        columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(threads)")
        }
        requested = (
            "id", "cwd", "updated_at", "recency_at", "updated_at_ms",
            "recency_at_ms", "archived", "archived_at", "project_id",
        )
        selected = [field for field in requested if field in columns]
        if "cwd" not in columns or not any(field in columns for field in ("updated_at_ms", "updated_at", "recency_at_ms", "recency_at")):
            issues.append({"path": str(path), "reason": "会话索引缺少 cwd 或活动时间字段", "phase": "conversation-index"})
            return records, issues
        query = "SELECT " + ", ".join(selected) + " FROM threads"
        for raw in connection.execute(query):
            row = dict(raw)
            last, fields = _last_activity(row)
            row.update({
                "last_activity": last,
                "activity_fields": fields,
                "activity_source": str(path),
                "activity_evidence": "threads 索引的 updated_at/recency_at 取最大值；未使用创建时间",
                "archived": bool(row.get("archived")) if row.get("archived") is not None else None,
            })
            records.append(row)
    except (OSError, sqlite3.Error) as error:
        issues.append({"path": str(path), "reason": str(error), "phase": "conversation-index"})
    finally:
        if connection is not None:
            connection.close()
    return records, issues


def _read_session_index(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    records: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    try:
        with path.open(encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as error:
                    issues.append({"path": str(path), "line": line_number, "reason": str(error), "phase": "conversation-index"})
                    continue
                if not isinstance(row, dict):
                    issues.append({"path": str(path), "line": line_number, "reason": "索引行不是对象", "phase": "conversation-index"})
                    continue
                last, fields = _last_activity(row)
                records.append({
                    **row,
                    "last_activity": last,
                    "activity_fields": fields,
                    "activity_source": str(path),
                    "activity_evidence": "补充 session_index.jsonl updated_at；不读取会话正文",
                    "archived": None,
                })
    except OSError as error:
        issues.append({"path": str(path), "reason": str(error), "phase": "conversation-index"})
    return records, issues


def load_thread_activity(home: str | Path) -> dict[str, Any]:
    """Read only the local activity indexes needed to associate worktrees."""
    root = Path(home).expanduser().absolute() / ".codex"
    records: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    sources: list[str] = []
    for database in _database_paths(Path(home).expanduser().absolute()):
        rows, errors = _read_sqlite(database)
        records.extend(rows)
        issues.extend(errors)
        sources.append(str(database))
    index = root / "session_index.jsonl"
    if index.is_file() and not index.is_symlink():
        rows, errors = _read_session_index(index)
        # SQLite is authoritative when the same session exists in both
        # indexes.  Keep JSONL-only rows as a fallback for older installations.
        known = {str(row.get("id")) for row in records if row.get("id")}
        records.extend(row for row in rows if not row.get("id") or str(row.get("id")) not in known)
        issues.extend(errors)
        sources.append(str(index))
    if not sources:
        coverage = "unavailable"
        issues.append({"path": str(root), "reason": "没有可读取的会话索引；相关活动保持未知", "phase": "conversation-index"})
    elif issues:
        coverage = "partial"
    else:
        coverage = "complete"
    return {"records": records, "issues": issues, "sources": sources, "coverage": coverage}


def _safe_mtime(path: Path) -> float | None:
    try:
        return path.lstat().st_mtime
    except OSError:
        return None


def tree_activity(path: str | Path) -> dict[str, Any]:
    """Return the newest mtime for every entry, including ignored entries."""
    root = Path(path).expanduser().absolute()
    context = scan_context.current()
    activity = context.directory_activity if context is not None else {}
    indexed = activity.get(str(root))
    if indexed is not None:
        if not indexed.get("scan_complete"):
            return {
                "latest_mtime": None, "latest_mtime_path": str(root),
                "latest_activity_at": None,
                "mtime_errors": [{"path": str(root), "reason": "本次文件清单覆盖不完整", "phase": "worktree-mtime"}],
                "mtime_evidence": "共用当次 Codex 文件清单；覆盖不完整，活动状态未知",
            }
        stamp_ns = int(indexed.get("latest_mtime_ns") or 0)
        stamp = stamp_ns / 1_000_000_000 if stamp_ns else None
        return {
            "latest_mtime": stamp,
            "latest_mtime_path": str(root),
            "latest_activity_at": datetime.fromtimestamp(stamp).astimezone().isoformat() if stamp else None,
            "mtime_errors": [],
            "mtime_evidence": "共用当次 Codex 文件清单；含文件、目录、忽略项且不跟随符号链接",
        }
    latest: float | None = None
    latest_path = ""
    errors: list[dict[str, Any]] = []
    symlinks: list[dict[str, Any]] = []
    stack = [root]
    visited: set[tuple[int, int]] = set()
    try:
        root_device = int(root.lstat().st_dev)
    except OSError as error:
        return {
            "latest_mtime": None, "latest_mtime_path": str(root),
            "latest_activity_at": None,
            "mtime_errors": [{"path": str(root), "reason": str(error), "phase": "worktree-mtime"}],
            "symlinks": [],
            "mtime_evidence": "工作树根无法读取；活动状态未知",
        }
    while stack:
        scan_budget.check("worktree 活动复核")
        current = stack.pop()
        current_mtime = _safe_mtime(current)
        if current_mtime is not None and (latest is None or current_mtime > latest):
            latest, latest_path = current_mtime, str(current)
        try:
            entry_stat = current.lstat()
            identity = (int(entry_stat.st_dev), int(entry_stat.st_ino))
            if stat.S_ISLNK(entry_stat.st_mode):
                raw_target = os.readlink(current)
                target = Path(os.path.abspath(
                    raw_target if os.path.isabs(raw_target) else current.parent / raw_target
                ))
                target_is_t1 = target == Path("/Volumes/T1") or Path("/Volumes/T1") in target.parents
                symlinks.append({
                    "path": str(current), "target": raw_target,
                    "resolved_target": str(target),
                    "target_exists": False if target_is_t1 else None,
                })
                continue
            if identity in visited or not stat.S_ISDIR(entry_stat.st_mode):
                continue
            if current != root and int(entry_stat.st_dev) != root_device:
                errors.append({
                    "path": str(current), "reason": "工作树内发现嵌套挂载；活动和引用范围不完整",
                    "phase": "worktree-mount",
                })
                continue
            visited.add(identity)
            with os.scandir(current) as entries:
                children = [Path(entry.path) for entry in entries]
        except OSError as error:
            errors.append({"path": str(current), "reason": str(error), "phase": "worktree-mtime"})
            continue
        stack.extend(children)
    return {
        "latest_mtime": latest,
        "latest_mtime_path": latest_path,
        "latest_activity_at": datetime.fromtimestamp(latest).astimezone().isoformat() if latest else None,
        "mtime_errors": errors,
        "symlinks": symlinks,
        "mtime_evidence": "遍历 worktree 内所有文件、目录项、忽略项；不跟随符号链接",
    }


def _absolute_path(value: Any, base: Path | None = None) -> Path | None:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        return None
    try:
        expanded = os.path.expanduser(value.strip())
        path = Path(expanded)
        if not path.is_absolute() and base is not None:
            path = base / path
        return path.absolute()
    except (OSError, ValueError):
        return None


def _contains(parent: Path, child: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _node_for(path: Path | None, nodes: list[Path]) -> int | None:
    if path is None:
        return None
    matches = [(index, node) for index, node in enumerate(nodes) if _contains(node, path)]
    return max(matches, key=lambda pair: len(pair[1].parts))[0] if matches else None


def _reference_rows(
    nodes: list[Path],
    references: Iterable[dict[str, Any]],
    symlinks: Iterable[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[tuple[int, int]]]:
    rows: list[dict[str, Any]] = []
    edges: list[tuple[int, int]] = []
    for reference in references:
        invalid = reference.get("status") == "invalid" or any(
            isinstance(reference.get(key), str) and "\x00" in reference[key]
            for key in ("source_file", "source_path", "path", "resolved_path", "raw_path", "path_base")
        )
        source = _absolute_path(reference.get("source_file") or reference.get("source_path"))
        target = None if invalid else _absolute_path(
            reference.get("path") or reference.get("resolved_path") or reference.get("raw_path"),
            Path(reference["path_base"]) if reference.get("path_base") else None,
        )
        source_node = _node_for(source, nodes)
        target_node = _node_for(target, nodes)
        row = {
            "kind": "configuration-or-task-reference",
            "source": str(source) if source else None,
            "target": str(target) if target else None,
            "raw_path": reference.get("raw_path"),
            "path_base": reference.get("path_base"),
            "field": reference.get("field"),
            "source_file": reference.get("source_file"),
            "status": "invalid" if invalid else reference.get("status", "unknown"),
            "source_node": source_node,
            "target_node": target_node,
        }
        rows.append(row)
        if source_node is not None and target_node is not None and source_node != target_node:
            edges.append((source_node, target_node))
    for link in symlinks:
        # The old local entry of a worktree already migrated to T1 is an
        # access alias, not a project-location reference.  T1 is checked by
        # the executor before a new migration; this alias must not connect or
        # block otherwise unrelated worktree groups.
        raw_target = link.get("target") or link.get("resolved_target")
        if isinstance(raw_target, str):
            try:
                target_hint = Path(raw_target).expanduser().absolute()
                t1_root = Path("/Volumes/T1")
                if target_hint == t1_root or target_hint.is_relative_to(t1_root):
                    continue
            except (OSError, ValueError):
                pass
        source = _absolute_path(link.get("path"))
        target = _absolute_path(link.get("resolved_target"))
        source_node = _node_for(source, nodes)
        target_node = _node_for(target, nodes)
        rows.append({
            "kind": "symbolic-link",
            "source": str(source) if source else None,
            "target": str(target) if target else None,
            "status": "unknown" if link.get("target_exists") is None else "exists" if link.get("target_exists") else "missing",
            "source_node": source_node,
            "target_node": target_node,
        })
        if source_node is not None and target_node is not None and source_node != target_node:
            edges.append((source_node, target_node))
    return rows, edges


def _thread_matches(path: Path, records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for record in records:
        cwd = _absolute_path(record.get("cwd"))
        if cwd is None or not _contains(path, cwd):
            continue
        matches.append(record)
    return matches


def _group_id(paths: Iterable[Path]) -> str:
    digest = hashlib.sha256("\0".join(sorted(str(path) for path in paths)).encode()).hexdigest()
    return "worktree-group-" + digest[:16]


def analyze_worktree_groups(
    worktrees: Iterable[dict[str, Any] | str | Path],
    *,
    thread_activity: dict[str, Any] | None = None,
    references: Iterable[dict[str, Any]] = (),
    symlinks: Iterable[dict[str, Any]] = (),
    activity_by_path: dict[str, dict[str, Any]] | None = None,
    now: float | None = None,
    idle_seconds: int = IDLE_SECONDS,
) -> dict[str, Any]:
    """Build reference-connected groups and determine their idle evidence."""
    now = time.time() if now is None else float(now)
    rows = list(worktrees)
    nodes = [Path(row["path"] if isinstance(row, dict) else row).expanduser().absolute() for row in rows]
    parents = list(range(len(nodes)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left, right = find(left), find(right)
        if left != right:
            parents[right] = left

    reference_rows, edges = _reference_rows(nodes, references, symlinks)
    for left, right in edges:
        union(left, right)
    activity = thread_activity or {"records": [], "issues": [], "sources": [], "coverage": "not-provided"}
    records = list(activity.get("records", []))
    invalid_thread_path = any(isinstance(row.get("cwd"), str) and "\x00" in row["cwd"] for row in records)
    grouped: dict[int, list[int]] = {}
    for index in range(len(nodes)):
        grouped.setdefault(find(index), []).append(index)
    result_groups: list[dict[str, Any]] = []
    by_index: dict[int, dict[str, Any]] = {}
    for member_indexes in sorted(grouped.values(), key=lambda group: str(nodes[group[0]])):
        member_paths = [nodes[index] for index in member_indexes]
        group_id = _group_id(member_paths)
        members: list[dict[str, Any]] = []
        latest_values: list[float] = []
        blockers: list[str] = []
        if invalid_thread_path:
            blockers.append("会话索引存在无法解析的当前目录，不能确认关联组无会话活动")
        group_references = [row for row in reference_rows if row.get("source_node") in member_indexes or row.get("target_node") in member_indexes]
        for reference in group_references:
            # Only an unparseable reference originating inside this group can
            # make moving its source unsafe. External absolute targets remain
            # at their existing locations, and inbound paths continue to use
            # the old-path symlink after migration.
            if reference.get("source_node") not in member_indexes:
                continue
            if reference.get("status") in {"invalid", "unresolved"} or not reference.get("target"):
                blockers.append("关联组内有无法解析的路径引用")
            elif reference.get("kind") == "symbolic-link" and reference.get("status") == "unknown":
                blockers.append("关联组内有无法核实的非 T1 软链接目标")
        for index in member_indexes:
            path = nodes[index]
            tree = (
                activity_by_path.get(str(path), {})
                if activity_by_path is not None else tree_activity(path)
            )
            if tree.get("latest_mtime") is not None:
                latest_values.append(float(tree["latest_mtime"]))
            if tree.get("mtime_errors"):
                blockers.append(f"{path} 的文件活动时间读取不完整")
            threads = _thread_matches(path, records)
            thread_values = [float(row["last_activity"]) for row in threads if row.get("last_activity") is not None]
            latest_values.extend(thread_values)
            if threads:
                for thread in threads:
                    if thread.get("last_activity") is None:
                        blockers.append(f"会话 {thread.get('id') or thread.get('thread_name') or '未知'} 缺少可解释活动时间")
                    if thread.get("archived") is not True:
                        blockers.append(f"会话 {thread.get('id') or thread.get('thread_name') or '未知'} 未确认关闭")
            members.append({
                "path": str(path),
                "latest_file_mtime": tree.get("latest_mtime"),
                "latest_file_mtime_path": tree.get("latest_mtime_path"),
                "latest_file_activity_at": tree.get("latest_activity_at"),
                "conversation_count": len(threads),
                "conversation_ids": [thread.get("id") or thread.get("thread_name") for thread in threads],
                "conversation_activity": [
                    {
                        "id": thread.get("id") or thread.get("thread_name"),
                        "cwd": thread.get("cwd"),
                        "last_activity": thread.get("last_activity"),
                        "activity_fields": thread.get("activity_fields", []),
                        "archived": thread.get("archived"),
                        "source": thread.get("activity_source"),
                    }
                    for thread in threads
                ],
                "mtime_evidence": tree.get("mtime_evidence"),
                "activity_errors": tree.get("mtime_errors", []),
            })
        if activity.get("coverage") in {"unavailable", "partial"}:
            blockers.append("会话索引覆盖不完整，不能证明关联组没有对话活动")
        for reference in reference_rows:
            if (
                reference.get("status") in {"invalid", "unresolved", "unknown"}
                or not reference.get("target")
            ):
                blockers.append("存在无法解释的路径引用，不能确认关联组引用关系完整")
                break
        latest = max(latest_values) if latest_values else None
        age = max(now - latest, 0) if latest is not None else None
        if latest is None:
            blockers.append("关联组没有可解释的文件或会话活动时间")
        if any(row.get("active") is True for row in rows if isinstance(row, dict) and Path(row.get("path", "")).absolute() in member_paths):
            blockers.append("关联组仍有打开句柄")
        group = {
            "group_id": group_id,
            "paths": [str(path) for path in member_paths],
            "members": members,
            "references": group_references,
            "latest_activity_epoch": latest,
            "latest_activity_at": datetime.fromtimestamp(latest).astimezone().isoformat() if latest else None,
            "idle_for_seconds": age,
            "idle_for_hours": round(age / 3600, 2) if age is not None else None,
            "idle_threshold_seconds": idle_seconds,
            "idle_threshold": "超过连续 168 小时；恰好七天不算闲置",
            "idle": bool(age is not None and age > idle_seconds and not blockers),
            "activity_status": (
                "unknown" if latest is None or blockers
                else "recent" if age is not None and age <= idle_seconds
                else "known"
            ),
            "blockers": sorted(set(blockers)),
            "thread_index_coverage": activity.get("coverage", "unknown"),
            "thread_index_sources": list(activity.get("sources", [])),
        }
        result_groups.append(group)
        for index in member_indexes:
            by_index[index] = group
    return {
        "groups": result_groups,
        "by_path": {str(nodes[index]): by_index[index] for index in range(len(nodes))},
        "references": reference_rows,
        "issues": list(activity.get("issues", [])),
        "idle_threshold_seconds": idle_seconds,
    }


def extract_static_references(
    roots: Iterable[str | Path],
    *,
    inventory_records: Iterable[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Extract path-shaped values from supported config and build scripts.

    This is deliberately static: no project script is imported or executed.
    """
    references: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    path_key = re.compile(r"(?:path|root|workspace|worktree|directory|cwd|project|repo|source|input|output|artifact|build|target)", re.I)
    literal = re.compile(r"['\"]([^'\"]+)['\"]")
    allowed_names = re.compile(r"(?:config|manifest|project|workspace|build|task|workflow|package|pyproject|cargo|vite|next|Makefile)", re.I)
    normalized_roots = [
        Path(value).expanduser().absolute()
        for value in roots
        if not Path(value).expanduser().is_symlink() and Path(value).expanduser().is_dir()
    ]
    roots_by_path = {str(root): root for root in normalized_roots}

    def root_for_path(path: Path) -> Path | None:
        current = path
        while True:
            root = roots_by_path.get(str(current))
            if root is not None:
                return root
            if current == current.parent:
                return None
            current = current.parent

    def source_rows() -> Iterable[tuple[dict[str, Any], Path]]:
        if inventory_records is not None:
            for row in inventory_records:
                scan_budget.check("Codex 路径引用索引")
                try:
                    path = Path(str(row.get("path", ""))).absolute()
                except (OSError, ValueError):
                    continue
                root = root_for_path(path)
                if root is not None:
                    yield row, root
            return
        for root in normalized_roots:
            try:
                root_device = int(root.lstat().st_dev)
            except OSError as error:
                issues.append({
                    "path": str(root), "reason": str(error),
                    "phase": "static-reference-extraction",
                })
                continue
            for current, dirs, files in os.walk(
                root,
                followlinks=False,
                onerror=lambda error: issues.append({
                    "path": getattr(error, "filename", str(root)),
                    "reason": str(error),
                    "phase": "static-reference-extraction",
                }),
            ):
                scan_budget.check("Codex 路径引用读取")
                current_path = Path(current)
                allowed_dirs = []
                for name in dirs:
                    child = current_path / name
                    if name in {
                        ".git", ".worktrees", "worktrees", "sessions", "archived_sessions",
                        "node_modules", ".build", "target", ".venv",
                    } or child.is_symlink():
                        continue
                    try:
                        if int(child.lstat().st_dev) != root_device:
                            issues.append({
                                "path": str(child), "reason": "嵌套挂载未遍历，引用状态未知",
                                "phase": "static-reference-extraction",
                            })
                            continue
                    except OSError as error:
                        issues.append({
                            "path": str(child), "reason": str(error),
                            "phase": "static-reference-extraction",
                        })
                        continue
                    allowed_dirs.append(name)
                dirs[:] = allowed_dirs
                for name in files:
                    path = current_path / name
                    yield (
                        {
                            "path": str(path),
                            "entry_type": "symlink" if path.is_symlink() else "file",
                        },
                        root,
                    )

    for row, root in source_rows():
        scan_budget.check("Codex 路径引用读取")
        path = Path(str(row.get("path", ""))).absolute()
        name = path.name
        relative_parts = path.relative_to(root).parts
        if any(part in {
            ".git", ".worktrees", "worktrees", "sessions", "archived_sessions",
            "node_modules", ".build", "target", ".venv",
        } for part in relative_parts):
            continue
        if not allowed_names.search(name) or path.suffix.casefold() not in {".json", ".toml", ".yaml", ".yml", ".ini", ".cfg", ".js", ".ts", ".py", ".sh", ""}:
            continue
        if row.get("entry_type") == "symlink":
            issues.append({"path": str(path), "reason": "配置文件是链接，未跟随", "phase": "static-reference-extraction"})
            continue
        if row.get("entry_type", "file") != "file":
            continue
        try:
            with path.open(encoding="utf-8", errors="replace") as stream:
                text = stream.read()
        except OSError:
            issues.append({
                "path": str(path),
                "reason": "配置或任务文件不可读取；引用关系保持未知",
                "phase": "static-reference-extraction",
            })
            continue
        for match in literal.finditer(text):
            value = match.group(1)
            if not value:
                continue
            if not value.startswith(("/", "./", "../", "~")):
                # A supported config often stores a project-relative
                # output as ``"output": "outputs/final"``. Keep
                # those values only when the nearby key is path-like;
                # arbitrary labels must not become references.
                prefix = text[max(0, match.start() - 96):match.start()]
                key_match = re.search(
                    r"(?:path|root|workspace|worktree|directory|cwd|project|repo|source|input|output|artifact|build|target)"
                    r"\s*['\"]?\s*(?:[:=])\s*$",
                    prefix,
                    re.I,
                )
                if not key_match or value.casefold().startswith(("http://", "https://", "git@")):
                    continue
            references.append({
                "raw_path": value,
                "path_base": str(path.parent),
                "source_file": str(path),
                "field": "static-literal",
                "status": "static-unverified",
            })
    extract_static_references.last_issues = issues  # type: ignore[attr-defined]
    return references
