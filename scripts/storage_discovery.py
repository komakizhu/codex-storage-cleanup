#!/usr/bin/env python3
"""Read-only discovery primitives shared by the Codex storage reports.

The module deliberately stops at evidence collection. It never deletes,
mounts, starts, repairs, converts, or rewrites an artifact. Discovery and
cleanup policy are separate: every record created here has an empty
``trash_paths`` field.
"""

from __future__ import annotations

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import subprocess
import bounded_process
import scan_budget
import scan_context
from threading import Lock
import time
from typing import Any, Callable, Iterable


DEFAULT_LARGE_BYTES = 100_000_000
DEFAULT_HASH_STALL_SECONDS = 60
DEFAULT_HASH_WORKERS = 4

def discover_runtime_data(home: str | Path) -> list[dict[str, Any]]:
    """Compatibility shim; runtime roots require explicit project evidence."""
    return []


def runtime_mapping_state_digest(runtime_data: Iterable[dict[str, Any]]) -> str:
    """Hash mapping identities and read states for daily coverage comparison."""
    states = [
        {
            "id": str(row.get("id", "")),
            "source_status": str(row.get("source_status", "未记录")),
            "evidence_status": str(row.get("evidence_status", "未记录")),
            "association_status": str(row.get("association_status", "未记录")),
            "origin_state": str(row.get("origin_state", "未记录")),
        }
        for row in runtime_data
        if isinstance(row, dict)
    ]
    states.sort(key=lambda row: (row["id"], row["source_status"], row["evidence_status"], row["association_status"], row["origin_state"]))
    payload = json.dumps(states, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def aggregate_diagnostics(events: list[dict[str, Any]], *, traversal_complete: bool = True,
                          hash_requested: bool = True) -> dict[str, Any]:
    """Count events, diagnoses and paths separately, retaining every origin."""
    stages = {name: 'complete' for name in ('traversal', 'source-extraction', 'project-association',
                                           'test-analysis', 'vm-dependencies', 'duplicate-hash', 'type-identification')}
    if not traversal_complete:
        stages['traversal'] = 'partial'
    if not hash_requested:
        stages['duplicate-hash'] = 'unchecked'
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    def stage_for(phase: str) -> str:
        if phase == 'file-signature':
            return 'type-identification'
        if phase.startswith('state'):
            return 'source-extraction'
        if phase.startswith(('project', 'association')):
            return 'project-association'
        if phase.startswith('test'):
            return 'test-analysis'
        if phase.startswith(('vm', 'image', 'mount', 'process', 'open')):
            return 'vm-dependencies'
        if phase == 'duplicate-hash':
            return phase
        return 'traversal'
    for event in events:
        phase = event.get('phase', 'traversal')
        stage = stage_for(phase)
        code = event.get('code', phase)
        path = event.get('path', '')
        severity = event.get('severity', 'error')
        if severity == 'error':
            stages[stage] = 'partial'
        key = (stage, code, path)
        item = grouped.setdefault(key, {'phase': stage, 'code': code, 'path': path,
                                         'severity': severity, 'reason': event.get('reason', ''),
                                         'occurrences': 0, 'sources': [], 'blocked_checks': [],
                                         'discovery_only': True, 'trash_paths': []})
        item['occurrences'] += 1
        item['sources'].append(dict(event))
        if severity == 'error':
            item['severity'] = 'error'
            item['blocked_checks'] = [stage]
    diagnostics = list(grouped.values())
    inventory_stages = ('traversal', 'source-extraction', 'project-association', 'test-analysis', 'vm-dependencies')
    return {'stages': stages, 'diagnostics': diagnostics, 'raw_event_count': len(events),
            'unique_diagnostic_count': len(diagnostics),
            'unique_affected_path_count': len({item['path'] for item in diagnostics}),
            'gap_count': sum(item['severity'] == 'error' for item in diagnostics),
            'coverage_complete': all(stages[name] == 'complete' for name in inventory_stages)}

# These are format hints, not discovery allowlists. Generic .img/.bin/.raw
# files need an additional header, configuration, or container-path signal.
VM_DIR_SUFFIXES = (".pvm", ".vmwarevm", ".utm", ".virtualbox", ".sparsebundle", ".hdd")
VM_FILE_SUFFIXES = {".vmdk", ".vdi", ".vhd", ".vhdx", ".qcow", ".qcow2", ".hdd"}
RAW_DISK_PATH_HINTS = (
    "virtual-machine", "virtual machine", "qemu", "utm", "parallels", "vmware", "virtualbox",
    "docker", "colima", "orbstack", "rancher", "containerd", "disk", "volume", "snapshot", "delta",
)
AMBIGUOUS_IMAGE_SUFFIXES = {".img", ".bin", ".dmg"}
VM_CONFIG_SUFFIXES = {".vmx", ".vbox", ".pvs", ".utm", ".plist", ".xml", ".json"}
CONTAINER_DISK_HINTS = ("docker", "colima", "orbstack", "rancher", "containerd")

TEST_SIGNAL_NAMES = {
    "manifest.json", "run.json", "state.json", "status.json", "summary.json",
    "report.json", "report.jsonl", "analysis-report.jsonl", "results.json",
    "results.jsonl", "completion.json", "completion.jsonl", "metadata.json",
}
STATE_FILE_HINTS = ("state", "workspace", "project", "task", "session", "thread", "global", "config")
PATH_FIELD_HINTS = (
    "path", "root", "workspace", "worktree", "directory", "cwd", "project",
    "repo", "repository", "folder", "source", "input", "output", "model",
    "database", "intermediate", "result", "image", "disk", "backing", "parent",
)

IMAGE_MAGIC = {
    b"QFI\xfb": "qcow",
    b"conectix": "vhd",
    b"KDMV": "vmdk",
    b"vhdxfile": "vhdx",
}


def human_bytes(value: int | None) -> str:
    if value is None:
        return "未读取"
    number = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if number < 1000 or unit == "TB":
            return f"{int(number)} {unit}" if unit in ("B", "KB") else f"{number:.2f} {unit}"
        number /= 1000
    return f"{number:.2f} TB"


def _safe_stat(path: Path, follow_symlinks: bool = False) -> os.stat_result | None:
    try:
        return path.stat() if follow_symlinks else path.lstat()
    except (OSError, ValueError):
        return None


def _safe_exists(path: Path) -> bool:
    try:
        return path.exists()
    except (OSError, ValueError):
        return False


def _safe_is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except (OSError, ValueError):
        return False


def _same_or_below(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _file_id(stat_result: os.stat_result) -> str:
    return f"{getattr(stat_result, 'st_dev', 0)}:{getattr(stat_result, 'st_ino', 0)}"


def _allocated_bytes(stat_result: os.stat_result) -> int | None:
    blocks = getattr(stat_result, "st_blocks", None)
    return int(blocks) * 512 if blocks is not None else None


def _is_container_path(path: Path) -> bool:
    lowered = str(path).casefold()
    return any(token in lowered for token in CONTAINER_DISK_HINTS)


def _raw_disk_evidence(path: Path) -> bool:
    lowered = str(path).casefold()
    return path.suffix.casefold() == ".raw" and any(token in lowered for token in RAW_DISK_PATH_HINTS)


def _kind_for_path(path: Path, header: bytes = b"", tail: bytes = b"") -> str:
    lowered = str(path).casefold()
    suffix = path.suffix.casefold()
    image_signature = any(header.startswith(magic) or tail.startswith(magic) for magic in IMAGE_MAGIC)
    # Container application resources include arbitrary .bin/.img files. A
    # vendor name is not disk evidence for these ambiguous formats.
    if _is_container_path(path) and (suffix in VM_FILE_SUFFIXES or suffix == ".raw" or image_signature):
        return "container-disk"
    if suffix in VM_FILE_SUFFIXES or _raw_disk_evidence(path) or any(token in lowered for token in (".pvm/", ".vmwarevm/", ".utm/", ".virtualbox/")):
        return "virtual-machine-disk"
    if image_signature:
        return "virtual-machine-disk"
    if suffix in {".bin", ".safetensors", ".onnx", ".pt", ".pth", ".ckpt"} and any(
        token in lowered for token in ("model", "models", "checkpoint", "weights", "asset")
    ):
        return "model-or-asset"
    if suffix in {".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".dmg", ".pkg"}:
        return "archive-or-installer"
    return "unknown-large-file"


def _read_signatures(path: Path, known_size: int | None = None) -> tuple[bytes, bytes, str | None]:
    """Read only image signatures; never decode an image as a whole text file."""
    try:
        with path.open("rb") as stream:
            header = stream.read(512)
            size = known_size if known_size is not None else os.fstat(stream.fileno()).st_size
            tail = b""
            if size > 512:
                stream.seek(max(size - 512, 0))
                tail = stream.read(512)
            return header, tail, None
    except OSError as error:
        return b"", b"", str(error)


def _is_mount_boundary(path: Path, root_device: int) -> bool:
    stat_result = _safe_stat(path)
    return bool(stat_result and getattr(stat_result, "st_dev", root_device) != root_device)


def _record_error(errors: list[dict[str, Any]], path: Path | str, reason: str, *, phase: str = "scan") -> None:
    errors.append({"path": str(path), "reason": reason, "phase": phase})


def _under_any(path: Path, roots: Iterable[Path]) -> bool:
    return any(_same_or_below(path, root) for root in roots)


def local_path_status(path: Path, home: Path, excluded: Iterable[Path]) -> bool | None:
    """Check a local path component by component without following links."""
    path, home = Path(os.path.abspath(path)), Path(os.path.abspath(home))
    excluded = tuple(Path(os.path.abspath(root)) for root in excluded)
    if not _same_or_below(path, home) or _under_any(path, excluded):
        return None
    current = home
    for part in path.relative_to(home).parts:
        current = current / part
        if _under_any(current, excluded):
            return None
        try:
            info = current.lstat()
        except FileNotFoundError:
            return False
        except (OSError, ValueError):
            return None
        if stat.S_ISLNK(info.st_mode):
            return None
    return True


def safe_local_link(path: Path, home: Path, excluded: Iterable[Path]) -> dict[str, Any]:
    target = os.readlink(path)
    resolved = Path(os.path.abspath(os.path.join(str(path.parent), target)))
    exists = local_path_status(resolved, home, excluded)
    return {"path": str(path), "target": target,
            "resolved_target": str(resolved) if exists is not None else None,
            "target_exists": exists,
            "reason": "链接目标在范围外或含未解析链接，未跟随" if exists is None else "本地链接目标已核对"}


def scan_large_files(
    roots: Iterable[str | Path],
    *,
    min_bytes: int = DEFAULT_LARGE_BYTES,
    exclude: Iterable[str | Path] = (),
    same_filesystem: bool = True,
    progress: Callable[[dict[str, int]], None] | None = None,
    metadata_first: bool = False,
    link_scope_root: str | Path | None = None,
) -> dict[str, Any]:
    """Walk all readable files without following links or crossing mounts.

    ``files`` remains the backwards-compatible large-file view. ``all_files``
    contains every regular file so small items can be aggregated, attributed,
    and considered for duplicate evidence without changing the display
    threshold. All byte totals use unique filesystem file identities.
    """
    started = time.monotonic()
    requested_roots = sorted(
        {Path(os.path.abspath(Path(root).expanduser())) for root in roots},
        key=lambda item: (len(item.parts), str(item)),
    )
    normalized_roots: list[Path] = []
    for root in requested_roots:
        if any(_same_or_below(root, existing) for existing in normalized_roots):
            continue
        normalized_roots.append(root)
    excluded = [Path(os.path.abspath(Path(item).expanduser())) for item in exclude]
    files: list[dict[str, Any]] = []
    all_files: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    skipped_mounts: list[dict[str, Any]] = []
    symlinks: list[dict[str, Any]] = []
    directory_records: list[dict[str, Any]] = []
    visited_dirs = 0
    visited_files = 0
    interrupted = False
    signature_unchecked_count = 0
    directory_activity: dict[str, int] = {}
    seen_dir_ids: set[str] = set()
    unique_files: dict[str, dict[str, Any]] = {}
    small_buckets: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "kind": "unknown-large-file", "count": 0, "logical_bytes": 0,
        "allocated_bytes": 0, "allocation_unknown_count": 0, "paths": [],
    })
    root_children: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "path": "", "count": 0, "logical_bytes": 0, "allocated_bytes": 0,
        "allocation_unknown_count": 0, "file_ids": set(), "path_count": 0,
    })
    file_activity_by_parent: dict[str, int] = {}

    def excluded_path(path: Path) -> bool:
        return _under_any(path, excluded)

    def record_file(child: Path, stat_result: os.stat_result, root: Path) -> None:
        nonlocal signature_unchecked_count
        logical_bytes = int(stat_result.st_size)
        file_id = _file_id(stat_result)
        signature_checked = (
            not metadata_first
            or logical_bytes >= min_bytes
            or child.suffix.casefold() in VM_FILE_SUFFIXES | AMBIGUOUS_IMAGE_SUFFIXES | {'.raw'}
        )
        if signature_checked:
            header, tail, signature_error = _read_signatures(child, logical_bytes)
        else:
            header, tail, signature_error = b'', b'', None
            signature_unchecked_count += 1
        kind = _kind_for_path(child, header, tail)
        if signature_error:
            _record_error(errors, child, signature_error, phase='file-signature')
        allocated = _allocated_bytes(stat_result)
        record = {
            "path": str(child), "name": child.name,
            "entry_type": "file",
            "logical_bytes": logical_bytes, "logical_size": human_bytes(logical_bytes),
            "allocated_bytes": allocated, "allocated_size": human_bytes(allocated),
            "file_id": file_id, "link_count": int(getattr(stat_result, "st_nlink", 1)),
            "device": int(getattr(stat_result, "st_dev", 0)),
            "inode": int(getattr(stat_result, "st_ino", 0)),
            "modified_ns": int(getattr(stat_result, "st_mtime_ns", 0)),
            "changed_ns": int(getattr(stat_result, "st_ctime_ns", 0)),
            "kind": kind, "sparse": allocated is not None and allocated < logical_bytes,
            "large": logical_bytes >= min_bytes,
            "signature_status": "unreadable" if signature_error else ("read" if signature_checked else "unchecked"),
            "signature_error": signature_error,
            "source_evidence": "待归属分析", "project_key": None,
            "trash_paths": [],
        }
        all_files.append(record)
        if logical_bytes >= min_bytes:
            files.append(record)
        try:
            relative = child.relative_to(root)
            top = root if not relative.parts else root / relative.parts[0]
        except ValueError:
            top = root
        top_key = str(top)
        top_bucket = root_children[top_key]
        top_bucket["path"] = top_key
        top_bucket["path_count"] += 1
        if child != root:
            parent_key = str(child.parent)
            file_activity_by_parent[parent_key] = max(
                file_activity_by_parent.get(parent_key, 0),
                int(stat_result.st_mtime_ns),
            )
        if file_id in unique_files:
            return
        unique_files[file_id] = record
        if logical_bytes < min_bytes:
            bucket = small_buckets[kind]
            bucket["count"] += 1
            bucket["logical_bytes"] += logical_bytes
            if allocated is None:
                bucket["allocation_unknown_count"] += 1
            else:
                bucket["allocated_bytes"] += allocated
            if len(bucket["paths"]) < 8:
                bucket["paths"].append(str(child))
        top_bucket["count"] += 1
        top_bucket["logical_bytes"] += logical_bytes
        top_bucket["file_ids"].add(file_id)
        if allocated is None:
            top_bucket["allocation_unknown_count"] += 1
        else:
            top_bucket["allocated_bytes"] += allocated

    for root in normalized_roots:
        if excluded_path(root):
            continue
        root_stat = _safe_stat(root)
        if not root_stat:
            _record_error(errors, root, "根路径不存在或不可读取")
            continue
        if root.is_symlink():
            try:
                root_link_stat = root.lstat()
                symlinks.append({
                    "path": str(root), "target": os.readlink(root),
                    "resolved_target": None, "target_exists": None,
                    "file_id": _file_id(root_link_stat),
                    "device": int(getattr(root_link_stat, "st_dev", 0)),
                    "inode": int(getattr(root_link_stat, "st_ino", 0)),
                    "modified_ns": int(getattr(root_link_stat, "st_mtime_ns", 0)),
                    "kind": "symlink",
                    "reason": "扫描根本身是符号链接；未检查目标",
                })
            except OSError as error:
                _record_error(errors, root, f"无法读取根符号链接：{error}", phase="symlink")
            _record_error(errors, root, "根路径是符号链接；未跟随")
            continue
        root_device = getattr(root_stat, "st_dev", 0)
        if stat.S_ISREG(root_stat.st_mode):
            visited_files += 1
            record_file(root, root_stat, root)
            continue
        if not stat.S_ISDIR(root_stat.st_mode):
            _record_error(errors, root, "Codex 来源根不是普通文件或目录", phase="root-type")
            continue
        stack = [root]
        try:
            while stack:
                scan_budget.check("Codex 文件清单遍历")
                current = stack.pop()
                if excluded_path(current):
                    continue
                current_stat = _safe_stat(current)
                if not current_stat:
                    _record_error(errors, current, "无法读取目录状态")
                    continue
                current_id = _file_id(current_stat)
                if current_id in seen_dir_ids:
                    continue
                seen_dir_ids.add(current_id)
                if same_filesystem and current != root and _is_mount_boundary(current, root_device):
                    skipped_mounts.append({"path": str(current), "reason": "跨文件系统挂载点"})
                    continue
                visited_dirs += 1
                directory_activity[str(current)] = int(getattr(current_stat, "st_mtime_ns", 0))
                directory_records.append({
                    "path": str(current),
                    "kind": "directory",
                    "file_id": current_id,
                    "device": int(getattr(current_stat, "st_dev", 0)),
                    "inode": int(getattr(current_stat, "st_ino", 0)),
                    "logical_bytes": 0,
                    "allocated_bytes": 0,
                    "modified_ns": int(getattr(current_stat, "st_mtime_ns", 0)),
                    "changed_ns": int(getattr(current_stat, "st_ctime_ns", 0)),
                    "scan_complete": True,
                })
                try:
                    with os.scandir(current) as iterator:
                        entries = list(iterator)
                except OSError as error:
                    _record_error(errors, current, str(error), phase="directory")
                    continue
                for entry in entries:
                    child = Path(entry.path)
                    if excluded_path(child):
                        continue
                    try:
                        if entry.is_symlink():
                            try:
                                link_stat = entry.stat(follow_symlinks=False)
                                link_record = safe_local_link(
                                    child, Path(link_scope_root) if link_scope_root else root, excluded
                                )
                                link_record.update({
                                    "file_id": _file_id(link_stat),
                                    "device": int(getattr(link_stat, "st_dev", 0)),
                                    "inode": int(getattr(link_stat, "st_ino", 0)),
                                    "modified_ns": int(getattr(link_stat, "st_mtime_ns", 0)),
                                    "kind": "symlink",
                                })
                                symlinks.append(link_record)
                            except (OSError, ValueError) as error:
                                _record_error(errors, child, f"无法读取符号链接：{error}", phase="symlink")
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            if excluded_path(child):
                                continue
                            if same_filesystem and _is_mount_boundary(child, root_device):
                                skipped_mounts.append({"path": str(child), "reason": "跨文件系统挂载点"})
                            else:
                                stack.append(child)
                            continue
                        if not entry.is_file(follow_symlinks=False):
                            continue
                        visited_files += 1
                        try:
                            stat_result = entry.stat(follow_symlinks=False)
                        except OSError as error:
                            _record_error(errors, child, str(error), phase="file-stat")
                            continue
                        record_file(child, stat_result, root)
                    except OSError as error:
                        _record_error(errors, child, str(error), phase="file")
                if progress and visited_dirs % 100 == 0:
                    progress({"directories": visited_dirs, "files": visited_files, "large_files": len(files)})
        except KeyboardInterrupt:
            interrupted = True
            _record_error(errors, root, "扫描被中断；结果为部分覆盖", phase="interrupt")
            break

    for bucket in small_buckets.values():
        if bucket["allocation_unknown_count"]:
            bucket["allocated_bytes"] = None
        bucket["allocated_size"] = human_bytes(bucket["allocated_bytes"])
    directory_coverage_status = "complete" if not errors and not skipped_mounts and not interrupted else "partial"
    root_set = set(normalized_roots)
    directory_sizes: dict[str, dict[str, Any]] = {
        path: {
            "logical_bytes": 0, "allocated_bytes": 0, "allocation_unknown": False,
            "file_count": 0, "latest_modified_ns": modified,
            "scan_complete": directory_coverage_status == "complete",
        }
        for path, modified in directory_activity.items()
    }
    for record in unique_files.values():
        file_path = Path(record["path"])
        modified = int(record.get("modified_ns") or 0)
        if file_path in root_set:
            bucket = directory_sizes.setdefault(str(file_path), {
                "logical_bytes": 0, "allocated_bytes": 0, "allocation_unknown": False,
                "file_count": 0, "latest_modified_ns": 0,
                "scan_complete": directory_coverage_status == "complete",
            })
            bucket["latest_modified_ns"] = max(bucket["latest_modified_ns"], modified)
            bucket["logical_bytes"] += int(record.get("logical_bytes") or 0)
            allocated = record.get("allocated_bytes")
            if allocated is None:
                bucket["allocation_unknown"] = True
            else:
                bucket["allocated_bytes"] += int(allocated)
            bucket["file_count"] += 1
            continue
        current = file_path.parent
        while True:
            bucket = directory_sizes.setdefault(str(current), {
                "logical_bytes": 0, "allocated_bytes": 0, "allocation_unknown": False,
                "file_count": 0, "latest_modified_ns": 0,
                "scan_complete": directory_coverage_status == "complete",
            })
            bucket["latest_modified_ns"] = max(bucket["latest_modified_ns"], modified)
            bucket["logical_bytes"] += int(record.get("logical_bytes") or 0)
            allocated = record.get("allocated_bytes")
            if allocated is None:
                bucket["allocation_unknown"] = True
            else:
                bucket["allocated_bytes"] += int(allocated)
            bucket["file_count"] += 1
            if current in root_set:
                break
            parent = current.parent
            if parent == current:
                break
            current = parent
    for parent_path, modified in file_activity_by_parent.items():
        bucket = directory_sizes.get(parent_path)
        if bucket:
            bucket["latest_modified_ns"] = max(
                int(bucket.get("latest_modified_ns") or 0),
                modified,
            )
    for path in sorted(directory_activity, key=lambda value: len(Path(value).parts), reverse=True):
        current = Path(path)
        root = current
        while root not in root_set and root != root.parent:
            root = root.parent
        parent = current.parent
        if root not in root_set or parent == current or parent == root:
            continue
        child = directory_sizes.get(path)
        parent_bucket = directory_sizes.setdefault(str(parent), {
            "logical_bytes": 0, "allocated_bytes": 0, "allocation_unknown": False,
            "file_count": 0, "latest_modified_ns": 0,
            "scan_complete": directory_coverage_status == "complete",
        })
        if child:
            parent_bucket["latest_modified_ns"] = max(
                parent_bucket["latest_modified_ns"], child["latest_modified_ns"]
            )
    for bucket in directory_sizes.values():
        if bucket["allocation_unknown"]:
            bucket["allocated_bytes"] = None
    for row in directory_records:
        directory_summary_row = directory_sizes.get(row["path"], {})
        row["latest_modified_ns"] = int(
            directory_summary_row.get("latest_modified_ns")
            or row.get("modified_ns")
            or 0
        )
        row["scan_complete"] = bool(directory_summary_row.get("scan_complete"))
    directory_activity = {
        path: {
            "latest_mtime_ns": int(row.get("latest_modified_ns") or 0),
            "scan_complete": bool(row.get("scan_complete")),
        }
        for path, row in directory_sizes.items()
    }
    directory_summary = []
    for bucket in root_children.values():
        file_ids = set(bucket.pop("file_ids", set()))
        members = [unique_files[file_id] for file_id in file_ids if file_id in unique_files]
        path_count = int(bucket.get("path_count", bucket.get("count", 0)))
        bucket["count"] = len(members)
        bucket["file_count"] = len(members)
        bucket["path_count"] = path_count
        bucket["hard_link_path_count"] = max(path_count - len(members), 0)
        bucket["logical_bytes"] = sum(int(item.get("logical_bytes") or 0) for item in members)
        allocated_members = [item.get("allocated_bytes") for item in members]
        bucket["allocated_bytes"] = None if any(value is None for value in allocated_members) else sum(int(value) for value in allocated_members)
        bucket["logical_size"] = human_bytes(bucket["logical_bytes"])
        bucket["allocated_size"] = human_bytes(bucket["allocated_bytes"])
        bucket.update({
            "source_status": "unknown", "origin_state": "unknown",
            "evidence_status": "missing", "evidence_error": None,
            "purpose": "目录级来源尚未关联", "suggested_disposition": "暂不处理",
            "disposition_class": "暂不处理", "planned_disposition_class": "暂不处理",
            "coverage_status": directory_coverage_status, "evidence": "目录汇总；来源待关联",
            "reclaimable_bytes": None, "reclaimable_size": "未知",
            "trash_paths": [], "discovery_only": True,
        })
        directory_summary.append(bucket)
    files.sort(key=lambda item: item["logical_bytes"], reverse=True)
    all_files.sort(key=lambda item: item["logical_bytes"], reverse=True)
    unique_records = list(unique_files.values())
    all_logical_bytes = sum(int(item["logical_bytes"]) for item in unique_records)
    allocation_unknown = any(item.get("allocated_bytes") is None for item in unique_records)
    all_allocated_bytes: int | None = None if allocation_unknown else sum(int(item["allocated_bytes"]) for item in unique_records)
    elapsed = time.monotonic() - started
    return {
        "roots": [str(item) for item in normalized_roots],
        "requested_roots": [str(item) for item in requested_roots],
        "overlapping_roots_removed": len(requested_roots) - len(normalized_roots),
        "min_bytes": min_bytes,
        "files": files, "large_files": files, "all_files": all_files,
        "errors": errors, "skipped_mounts": skipped_mounts, "symlinks": symlinks,
        "directories_scanned": visited_dirs, "files_scanned": visited_files,
        "directory_records": directory_records,
        "directory_sizes": directory_sizes,
        "directory_activity": directory_activity,
        "all_logical_bytes": all_logical_bytes, "all_allocated_bytes": all_allocated_bytes,
        "all_file_id_count": len(unique_files), "hard_link_path_count": len(all_files) - len(unique_files),
        "small_file_summary": sorted(small_buckets.values(), key=lambda item: item["logical_bytes"], reverse=True),
        "directory_summary": sorted(directory_summary, key=lambda item: item["logical_bytes"], reverse=True),
        "interrupted": interrupted,
        "coverage_complete": not errors and not skipped_mounts and not interrupted,
        "traversal_complete": not any(error.get('phase') != 'file-signature' for error in errors) and not skipped_mounts and not interrupted,
        "scan_started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scan_finished_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "elapsed_seconds": round(elapsed, 3),
        "signature_unchecked_count": signature_unchecked_count,
        "metadata_first": metadata_first,
    }


def build_directory_summary(
    records: list[dict[str, Any]],
    roots: Iterable[str | Path],
    *,
    extra_roots: Iterable[str | Path] = (),
    runtime_data: Iterable[dict[str, Any]] = (),
    test_runs: Iterable[dict[str, Any]] = (),
    coverage_status: str = "complete",
) -> list[dict[str, Any]]:
    """Build a non-overlapping directory ledger from one file inventory.

    The ledger intentionally selects useful directory boundaries (home-level,
    Library/app-level, mapped runtime roots and test batches). Each unique
    filesystem file identity is assigned to its deepest selected boundary, so
    parent and child rows never add the same bytes twice.
    """
    normalized_roots = [Path(root).expanduser().absolute() for root in roots]
    candidate_paths: set[str] = set()

    def add_candidate(value: str | Path) -> None:
        if not value:
            return
        path = Path(value).expanduser().absolute()
        candidate_paths.add(str(path))

    for root in normalized_roots:
        add_candidate(root)
    root_lookup = project_root_lookup([{"path": str(root)} for root in normalized_roots])
    for index, record in enumerate(records):
        if index % 1000 == 0:
            scan_budget.check("Codex 目录汇总")
        path = Path(record["path"]).expanduser().absolute()
        root = root_lookup(path)
        if root:
            try:
                relative = path.relative_to(Path(root["path"]).absolute())
            except ValueError:
                relative = None
            if relative and relative.parts:
                add_candidate(Path(root["path"]) / relative.parts[0])

    for value in extra_roots:
        add_candidate(value)
    for run in test_runs:
        add_candidate(run.get("path", ""))
    for mapping in runtime_data:
        if mapping.get("source_status") == "current":
            add_candidate(mapping.get("path", ""))

    candidate_paths = {
        value for value in candidate_paths
        if not Path(value).is_symlink() and Path(value).is_dir()
    }
    unique_by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for index, record in enumerate(records):
        if index % 1000 == 0:
            scan_budget.check("Codex 目录汇总去重")
        file_id = str(record.get("file_id") or record.get("path"))
        unique_by_id[file_id].append(record)
    candidate_set = {Path(path) for path in candidate_paths}
    assignment: dict[str, Path] = {}
    for file_id, variants in unique_by_id.items():
        best: Path | None = None
        for variant in variants:
            current = Path(variant["path"]).expanduser().absolute()
            while True:
                if current in candidate_set:
                    if best is None or len(current.parts) > len(best.parts):
                        best = current
                    break
                parent = current.parent
                if parent == current:
                    break
                current = parent
        if best is not None:
            assignment[file_id] = best

    metadata = {str(Path(item.get("path", "")).expanduser().absolute()): item for item in runtime_data if item.get("path")}
    grouped: dict[str, dict[str, Any]] = {}
    for file_id, candidate in assignment.items():
        variants = unique_by_id[file_id]
        representative = variants[0]
        key = str(candidate)
        row = grouped.setdefault(key, {
            "path": key, "file_count": 0, "path_count": 0, "hard_link_path_count": 0,
            "large_file_count": 0, "logical_bytes": 0, "allocated_bytes": 0,
            "codex_file_count": 0, "codex_logical_bytes": 0, "codex_allocated_bytes": 0,
            "codex_allocation_unknown_count": 0, "project_totals": defaultdict(lambda: {"logical_bytes": 0, "allocated_bytes": 0, "allocated_unknown": 0}),
            "allocation_unknown_count": 0, "file_ids": set(), "project_keys": set(),
            "source_statuses": set(), "association_statuses": set(), "origin_states": set(), "purposes": set(),
            "activity_statuses": set(), "disposition_classes": set(),
            "retention_notes": set(), "recovery_costs": set(),
            "evidence_paths": set(), "runtime_mapping_id": None,
            "source_roots": set(), "trash_paths": [], "discovery_only": True,
        })
        row["file_ids"].add(file_id)
        row["file_count"] += 1
        row["path_count"] += len(variants)
        row["hard_link_path_count"] += max(len(variants) - 1, 0)
        row["large_file_count"] += int(bool(representative.get("large")))
        row["logical_bytes"] += int(representative.get("logical_bytes") or 0)
        allocated = representative.get("allocated_bytes")
        if allocated is None:
            row["allocation_unknown_count"] += 1
        else:
            row["allocated_bytes"] += int(allocated)
        if representative.get("codex_related"):
            row["codex_file_count"] += 1
            row["codex_logical_bytes"] += int(representative.get("logical_bytes") or 0)
            if allocated is None:
                row["codex_allocation_unknown_count"] += 1
            else:
                row["codex_allocated_bytes"] += int(allocated)
            project = representative.get("project_key") or "Codex（项目暂未标注）"
            project_row = row["project_totals"][project]
            project_row["logical_bytes"] += int(representative.get("logical_bytes") or 0)
            if allocated is None:
                project_row["allocated_unknown"] += 1
            else:
                project_row["allocated_bytes"] += int(allocated)
        for variant in variants:
            if variant.get("project_key"):
                row["project_keys"].add(variant["project_key"])
            if variant.get("source_status"):
                row["source_statuses"].add(variant["source_status"])
            if variant.get("association_status"):
                row["association_statuses"].add(variant["association_status"])
            if variant.get("origin_state"):
                row["origin_states"].add(variant["origin_state"])
            if variant.get("purpose"):
                row["purposes"].add(variant["purpose"])
            if variant.get("activity_status"):
                row["activity_statuses"].add(variant["activity_status"])
            if variant.get("disposition_class"):
                row["disposition_classes"].add(variant["disposition_class"])
            if variant.get("retention_note"):
                row["retention_notes"].add(variant["retention_note"])
            if variant.get("recovery_cost"):
                row["recovery_costs"].add(variant["recovery_cost"])
            if variant.get("source_root"):
                row["source_roots"].add(variant["source_root"])
            if variant.get("source_evidence"):
                row["evidence_paths"].add(variant["source_evidence"])

    rows: list[dict[str, Any]] = []
    for key, row in grouped.items():
        mapping = metadata.get(key)
        source_statuses = row.pop("source_statuses")
        association_statuses = row.pop("association_statuses")
        origin_states = row.pop("origin_states")
        activity_statuses = row.pop("activity_statuses")
        disposition_classes = row.pop("disposition_classes")
        retention_notes = row.pop("retention_notes")
        recovery_costs = row.pop("recovery_costs")
        row.pop("file_ids", None)
        row["allocated_bytes"] = None if row["allocation_unknown_count"] else row["allocated_bytes"]
        row["codex_allocated_bytes"] = None if row["codex_allocation_unknown_count"] else row["codex_allocated_bytes"]
        row["logical_size"] = human_bytes(row["logical_bytes"])
        row["allocated_size"] = human_bytes(row["allocated_bytes"])
        row["source_status"] = mapping.get("source_status") if mapping else (next(iter(source_statuses)) if len(source_statuses) == 1 else "unknown")
        row["evidence_status"] = mapping.get("evidence_status") if mapping else ("missing" if row["source_status"] == "unknown" else "readable")
        row["evidence_error"] = mapping.get("evidence_error") if mapping else None
        row["association_status"] = mapping.get("association_status") if mapping else (next(iter(association_statuses)) if len(association_statuses) == 1 else "unconfirmed")
        row["origin_state"] = mapping.get("origin_state") if mapping else (next(iter(origin_states)) if len(origin_states) == 1 else "unknown")
        row["activity_status"] = mapping.get("activity_status") if mapping else (next(iter(activity_statuses)) if len(activity_statuses) == 1 else "not-checked")
        row["disposition_class"] = mapping.get("disposition_class") if mapping else (next(iter(disposition_classes)) if len(disposition_classes) == 1 else "暂不处理")
        row["planned_disposition_class"] = mapping.get("planned_disposition_class") if mapping else (next(iter(disposition_classes)) if len(disposition_classes) == 1 else "暂不处理")
        row["runtime_mapping_id"] = mapping.get("id") if mapping else None
        row["purpose"] = mapping.get("purpose") if mapping else ("；".join(sorted(row.pop("purposes"))) or "目录用途待确认")
        row.pop("purposes", None)
        row["project_keys"] = sorted(row.pop("project_keys"))
        project_totals = row.pop("project_totals")
        row["project_totals"] = [
            {
                "project_key": project,
                "logical_bytes": int(values.get("logical_bytes") or 0),
                "logical_size": human_bytes(values.get("logical_bytes") or 0),
                "allocated_bytes": None if values.get("allocated_unknown") else int(values.get("allocated_bytes") or 0),
                "allocated_size": human_bytes(None if values.get("allocated_unknown") else values.get("allocated_bytes") or 0),
            }
            for project, values in sorted(project_totals.items(), key=lambda item: item[0])
        ]
        row["source_roots"] = sorted(row.pop("source_roots"))
        row["evidence_paths"] = sorted(row.pop("evidence_paths"))
        row["source_evidence"] = (mapping.get("evidence") if mapping else
                                   "；".join(row["evidence_paths"]) or "来源未知；缺少可读取证据")
        row["retention_note"] = mapping.get("retention_note") if mapping else ("；".join(sorted(retention_notes)) or "保留项待确认")
        row["recovery_cost"] = mapping.get("recovery_cost") if mapping else ("；".join(sorted(recovery_costs)) or "恢复代价待确认")
        row["coverage_status"] = coverage_status
        row["reclaimable_bytes"] = None
        row["reclaimable_size"] = "未知"
        row["suggested_disposition"] = (mapping.get("suggested_disposition") if mapping else
                                         "本地保留；需单独授权后评估" if row["origin_state"] == "mapped-project-runtime" else
                                         "第三方数据；暂不处理" if row["origin_state"] == "confirmed-unrelated" else
                                         "保留；按现有规则进一步评估" if row["origin_state"] == "confirmed-codex" else
                                         "暂不处理")
        row["t1_hint"] = mapping.get("t1_hint") if mapping else None
        row["trash_paths"] = []
        rows.append(row)
    return sorted(rows, key=lambda item: int(item.get("logical_bytes") or 0), reverse=True)


def _stat_key(stat_result: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        int(getattr(stat_result, "st_dev", 0)), int(getattr(stat_result, "st_ino", 0)),
        int(getattr(stat_result, "st_size", 0)), int(getattr(stat_result, "st_mtime_ns", 0)),
        int(getattr(stat_result, "st_ctime_ns", 0)), int(getattr(stat_result, "st_mode", 0)),
    )


def _hash_file_stable(
    path: Path,
    chunk_size: int = 4 * 1024 * 1024,
    stall_timeout: int = DEFAULT_HASH_STALL_SECONDS,
    progress: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Hash through a no-follow descriptor and reject changes or stalls."""
    before_path = _safe_stat(path)
    if not before_path or path.is_symlink():
        return {"status": "unreadable", "reason": "扫描前无法读取文件或路径是符号链接"}
    if int(getattr(before_path, "st_size", -1)) == 0:
        after_path = _safe_stat(path)
        if after_path and _stat_key(before_path) == _stat_key(after_path):
            return {"status": "verified", "sha256": hashlib.sha256(b"").hexdigest(), "bytes": 0}
        return {"status": "changed", "reason": "空文件在校验前后文件标识或修改状态发生变化"}
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as error:
        return {"status": "unreadable", "reason": str(error)}
    digest = hashlib.sha256()
    read_bytes = 0
    stream = None
    after_fd = None
    try:
        before_fd = os.fstat(fd)
        if _stat_key(before_path)[:2] != _stat_key(before_fd)[:2]:
            return {"status": "changed", "reason": "打开后文件标识发生变化"}
        stream = os.fdopen(fd, "rb", closefd=True)
        while True:
            started = time.monotonic()
            try:
                chunk = stream.read(chunk_size)
            except OSError as error:
                return {"status": "unreadable", "reason": str(error)}
            elapsed = time.monotonic() - started
            if elapsed > stall_timeout:
                return {"status": "stalled", "reason": f"连续 {stall_timeout} 秒没有读取进展"}
            if not chunk:
                break
            digest.update(chunk)
            read_bytes += len(chunk)
            if progress:
                progress({"path": str(path), "bytes": read_bytes})
        after_fd = os.fstat(stream.fileno())
    finally:
        if stream is None:
            try:
                os.close(fd)
            except OSError:
                pass
        else:
            stream.close()
    after_path = _safe_stat(path)
    if not after_path:
        return {"status": "changed", "reason": "校验后文件消失"}
    if after_fd is None or _stat_key(before_path) != _stat_key(after_path) or _stat_key(before_path) != _stat_key(after_fd):
        return {"status": "changed", "reason": "校验前后文件标识、大小或修改状态发生变化"}
    return {"status": "verified", "sha256": digest.hexdigest(), "bytes": read_bytes}


def analyze_duplicates(
    files: list[dict[str, Any]],
    *,
    full_hash: bool = False,
    blocked_paths: Iterable[str | Path] = (),
    hash_stall_seconds: int = DEFAULT_HASH_STALL_SECONDS,
    progress: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Find content duplicates while excluding hard links from extra copies."""
    by_size: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for item in files:
        if item.get("logical_bytes") is not None:
            by_size[int(item.get("logical_bytes", 0))].append(item)
    hard_link_groups: dict[str, list[str]] = defaultdict(list)
    for item in files:
        if item.get("file_id"):
            hard_link_groups[str(item["file_id"])].append(item["path"])
    hard_link_groups = {key: value for key, value in hard_link_groups.items() if len(value) > 1}
    blocked = {str(Path(path).expanduser().absolute()) for path in blocked_paths}
    groups: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    hash_failures: list[dict[str, Any]] = []
    unverified: list[dict[str, Any]] = []
    hash_executor = ThreadPoolExecutor(max_workers=DEFAULT_HASH_WORKERS) if full_hash else None
    progress_lock = Lock()

    def hash_one(item: dict[str, Any]) -> dict[str, Any]:
        def report(snapshot: dict[str, Any]) -> None:
            if progress:
                with progress_lock:
                    progress(snapshot)
        try:
            return _hash_file_stable(
                Path(item["path"]),
                stall_timeout=hash_stall_seconds,
                progress=report if progress else None,
            )
        except OSError as error:
            return {"status": "unreadable", "reason": str(error)}

    try:
        for size, candidates in sorted(by_size.items()):
            unique_ids = {item.get("file_id") for item in candidates}
            if len(candidates) < 2 or len(unique_ids) < 2:
                continue
            if not full_hash:
                unverified.append({
                    "logical_bytes": size, "logical_size": human_bytes(size),
                    "paths": [item["path"] for item in candidates],
                    "reason": "仅同大小，未执行内容校验", "trash_paths": [],
                })
                continue
            representatives: dict[str, dict[str, Any]] = {}
            paths_by_id: dict[str, list[str]] = defaultdict(list)
            for item in candidates:
                file_id = str(item.get("file_id"))
                representatives.setdefault(file_id, item)
                paths_by_id[file_id].append(item["path"])
            hash_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
            failed_paths: list[dict[str, Any]] = []
            representative_items = list(representatives.values())
            for start in range(0, len(representative_items), DEFAULT_HASH_WORKERS * 4):
                batch = representative_items[start:start + DEFAULT_HASH_WORKERS * 4]
                futures = [hash_executor.submit(hash_one, item) for item in batch] if hash_executor else []
                for item, future in zip(batch, futures):
                    result = future.result()
                    item["hash_status"] = result.get("status")
                    if result.get("status") == "verified":
                        item["sha256"] = result["sha256"]
                        hash_groups[result["sha256"]].append(item)
                    else:
                        failure = {"path": item["path"], "status": result.get("status"), "reason": result.get("reason"), "trash_paths": []}
                        failed_paths.append(failure)
                        hash_failures.append(failure)
                        if result.get("status") == "changed":
                            changed.append(failure)
            for digest, members in hash_groups.items():
                if len(members) < 2:
                    continue
                member_paths = [path for member in members for path in paths_by_id[str(member["file_id"])] ]
                logical_extra = size * (len(members) - 1)
                allocated_values = [member.get("allocated_bytes") for member in members[1:]]
                allocated_extra = sum(value for value in allocated_values if value is not None)
                record = {
                    "sha256": digest, "kind": sorted({member.get("kind", "unknown") for member in members}),
                    "logical_bytes": size, "logical_size": human_bytes(size),
                    "copy_count": len(members), "path_count": len(member_paths),
                    "extra_logical_bytes": logical_extra, "extra_logical_size": human_bytes(logical_extra),
                    "extra_allocated_bytes_upper_bound": allocated_extra,
                    "extra_allocated_size_upper_bound": human_bytes(allocated_extra),
                    "paths": member_paths,
                    "project_keys": sorted({member.get("project_key") for member in members if member.get("project_key")}),
                    "evidence": "完整 SHA-256；每个文件实体扫描前后稳定",
                    "trash_paths": [],
                }
                absolute_members = {str(Path(path).expanduser().absolute()) for path in member_paths}
                if absolute_members & blocked:
                    record["evidence"] = "完整 SHA-256，但镜像运行、挂载或依赖状态阻止确认可替代性"
                    record["deferred_reason"] = "虚拟机/容器使用状态未确认或存在活动依赖"
                    deferred.append(record)
                else:
                    groups.append(record)
            if failed_paths:
                unverified.append({
                    "logical_bytes": size, "logical_size": human_bytes(size),
                    "paths": [item["path"] for item in candidates],
                    "failed_paths": failed_paths,
                    "reason": "候选中存在读取失败、停滞或校验期间变化；未把失败项当作重复副本",
                    "trash_paths": [],
                })
    finally:
        if hash_executor:
            hash_executor.shutdown(wait=True)

    groups.sort(key=lambda item: item["extra_logical_bytes"], reverse=True)
    deferred.sort(key=lambda item: item["extra_logical_bytes"], reverse=True)
    logical_duplicate_bytes = sum(item["extra_logical_bytes"] for item in groups)
    return {
        "groups": groups, "deferred_groups": deferred,
        "unverified_same_size_groups": unverified, "hash_failures": hash_failures,
        "hard_link_groups": hard_link_groups, "changed_during_hash": changed,
        "verified": bool(full_hash), "hash_stall_seconds": hash_stall_seconds,
        "logical_duplicate_bytes": logical_duplicate_bytes,
        "logical_duplicate_size": human_bytes(logical_duplicate_bytes),
        "physical_reclaimable": "未知：APFS 克隆、快照共享、使用状态和依赖关系未转换为实际释放量",
        "trash_paths": [],
    }


def _path_hints(value: Any, result: list[dict[str, str]], key: str = "") -> None:
    if isinstance(value, dict):
        for child_key, child in value.items():
            _path_hints(child, result, str(child_key))
    elif isinstance(value, list):
        for child in value:
            _path_hints(child, result, key)
    elif isinstance(value, str):
        key_text = key.casefold()
        if any(token in key_text for token in ("path", "root", "workspace", "worktree", "directory", "cwd", "project", "repo", "folder")) and value.startswith(("/", "~", "\\")):
            result.append({"path": os.path.abspath(os.path.expanduser(value)), "field": key})


def _walk_state_files(root: Path) -> tuple[list[Path], list[dict[str, Any]]]:
    """Only documented Codex sources, never arbitrary worktree configuration."""
    files: list[Path] = []
    errors: list[dict[str, Any]] = []
    if root.is_symlink() or not root.is_dir():
        return files, errors
    try:
        root_device = int(root.stat().st_dev)
    except OSError as error:
        return files, [{"path": str(root), "reason": str(error), "phase": "state-root"}]
    try:
        for name in ('config.toml', '.codex-global-state.json'):
            path = root / name
            if not path.is_symlink() and path.exists():
                files.append(path)
        for name in ('sessions', 'archived_sessions'):
            directory = root / name
            if directory.is_symlink() or not directory.is_dir():
                continue
            for current, dirs, names in os.walk(directory, followlinks=False,
                    onerror=lambda error: errors.append({'path': error.filename, 'reason': str(error), 'phase': 'state-walk'})):
                scan_budget.check("Codex 状态索引读取")
                current_path = Path(current)
                allowed_dirs = []
                for item in dirs:
                    child = current_path / item
                    try:
                        if child.is_symlink():
                            continue
                        if int(child.stat().st_dev) != root_device:
                            errors.append({
                                "path": str(child), "reason": "跨卷目录按默认范围排除",
                                "phase": "state-cross-volume", "severity": "info",
                            })
                            continue
                        allowed_dirs.append(item)
                    except OSError as error:
                        errors.append({"path": str(child), "reason": str(error), "phase": "state-walk"})
                dirs[:] = allowed_dirs
                files.extend(Path(current) / item for item in names
                             if (item.endswith('.jsonl') or item.endswith('.jsonl.zst'))
                             and not (Path(current) / item).is_symlink())
    except OSError as error:
        errors.append({"path": str(root), "reason": str(error), "phase": "state-walk"})
    return files, errors


def _source_references(state: Path) -> list[dict[str, Any]]:
    """Whitelist source schema; no chat, environment, or recursive path mining."""
    hints: list[dict[str, Any]] = []
    def emit(value: Any, field: str, identity: str | None = None, timestamp: Any = None,
             temporal: str = 'unknown', source_role: str = 'project') -> None:
        if isinstance(value, list):
            for index, item in enumerate(value):
                emit(item, f'{field}[{index}]', identity, timestamp, temporal, source_role)
        elif isinstance(value, str):
            hints.append({'raw_path': value, 'field': field, 'source_file': str(state),
                          'record_id': identity, 'timestamp': timestamp, 'temporal_status': temporal,
                          'path_base': str(state.parent), 'source_role': source_role,
                          'discovery_only': True, 'trash_paths': []})
    if state.suffix == '.toml':
        # Reuse the existing local Python 3.9-compatible parser adapter.
        import importlib.util
        parser_path = Path(__file__).resolve().with_name('build_evidence.py')
        spec = importlib.util.spec_from_file_location('_storage_toml_adapter', parser_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        data = module.toml(str(state))
        projects = data.get('projects', {})
        if isinstance(projects, dict):
            for key, project in projects.items():
                if isinstance(project, dict):
                    emit(key, f'projects.{key}', str(key))
                    for field in ('path', 'root', 'project_root', 'workspace_root'):
                        emit(project.get(field), f'projects.{key}.{field}', str(key))
        for field in ('project_root', 'workspace_root', 'project_roots', 'workspace_roots'):
            emit(data.get(field), field)
    elif state.suffix == '.jsonl' or state.name.endswith('.jsonl.zst'):
        # Metadata headers precede conversation records. Stop at the first
        # non-header record; cap bytes read so a large body record is never
        # buffered as though it were metadata.
        max_header_bytes = 512 * 1024
        header_seen = [False]
        stream_state = {"early_exit": False}

        def bounded_lines(stream):
            total = 0
            line_number = 0
            while total < max_header_bytes:
                scan_budget.check("会话来源头读取")
                line_number += 1
                remaining = max_header_bytes - total
                # Once a metadata header was found, read only a small prefix
                # of the next record to recognize the body boundary.
                line_limit = min(remaining, 8 * 1024) if header_seen[0] else remaining
                raw = stream.readline(line_limit + 1)
                if not raw:
                    break
                if len(raw) > line_limit:
                    if header_seen[0]:
                        stream_state["early_exit"] = True
                        break
                    raise ValueError('会话头超过 512 KB；来源未检查')
                if header_seen[0] and not raw.endswith(b'\n'):
                    break
                total += len(raw)
                yield line_number, raw.decode('utf-8', errors='replace')
            if total >= max_header_bytes:
                stream_state["early_exit"] = True

        def consume_lines(lines):
            for line_number, line in lines:
                if not line.strip():
                    continue
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise ValueError('会话头不是已支持对象 schema')
                if record.get('type') != 'session_meta':
                    if not header_seen[0]:
                        raise ValueError('未发现 session_meta 头；来源未检查')
                    return True
                header_seen[0] = True
                payload = record.get('payload', {})
                if not isinstance(payload, dict):
                    raise ValueError('session_meta payload schema 未支持')
                emit(payload.get('cwd'), f'session_meta.cwd:{line_number}',
                     payload.get('id') or payload.get('session_id'), payload.get('timestamp'),
                     'historical' if 'archived_sessions' in state.parts else 'unknown', 'session')
            return False

        if state.name.endswith('.jsonl.zst'):
            zstd = shutil.which('zstd')
            if not zstd:
                raise ValueError('缺少 zstd 解压工具；压缩会话来源暂未检查')
            bounded_process.consume_stream(
                [zstd, '-dc', '--', str(state)],
                lambda stream: (
                    consume_lines(bounded_lines(stream)),
                    stream_state["early_exit"],
                ),
                timeout=scan_budget.DEFAULT_SCAN_BUDGET_SECONDS,
                phase="压缩会话来源读取",
                stop_early=lambda result: bool(result[0] or result[1]),
            )
        else:
            with state.open('rb') as stream:
                consume_lines(bounded_lines(stream))
    else:
        data = json.loads(state.read_text(encoding='utf-8'))
        if not isinstance(data, dict) or not any(field in data for field in ('active-workspace-roots', 'electron-saved-workspace-roots', 'thread-workspace-root-hints', 'thread-projectless-output-directories', 'local-projects')):
            raise ValueError('全局状态项目字段 schema 未支持；来源未检查')
        for field in ('active-workspace-roots', 'electron-saved-workspace-roots'):
            emit(data.get(field), field)
        for field in ('thread-workspace-root-hints', 'thread-projectless-output-directories'):
            values = data.get(field, {})
            if isinstance(values, dict):
                for identity, value in values.items():
                    emit(value, f'{field}.{identity}', identity, source_role='thread')
        projects = data.get('local-projects', {})
        if isinstance(projects, dict):
            for identity, value in projects.items():
                if isinstance(value, dict):
                    emit(value.get('rootPaths'), f'local-projects.{identity}.rootPaths',
                         identity, value.get('updatedAt'), source_role='project')
    return hints


def read_session_metadata_header(path: str | Path, *, timeout: int = 30) -> dict[str, Any]:
    """Read only a supported session_meta header, including compressed archives."""
    source = Path(path).expanduser().absolute()
    max_header_bytes = 512 * 1024

    def parse(stream) -> dict[str, Any]:
        total = 0
        for line_number in range(1, max_header_bytes + 2):
            scan_budget.check("归档会话头复核")
            remaining = max_header_bytes - total
            if remaining <= 0:
                raise ValueError("会话头超过 512 KB，状态保持未知")
            raw = stream.readline(min(remaining, 8 * 1024) + 1)
            if not raw:
                break
            if len(raw) > min(remaining, 8 * 1024):
                raise ValueError("会话头行超过读取上限，状态保持未知")
            total += len(raw)
            try:
                record = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ValueError(f"会话元数据无法解析：{error}") from error
            if not isinstance(record, dict):
                raise ValueError("会话头不是对象，状态保持未知")
            if record.get("type") != "session_meta":
                raise ValueError("文件开头没有受支持的 session_meta 头")
            payload = record.get("payload")
            if not isinstance(payload, dict) or not payload.get("id"):
                raise ValueError("session_meta 缺少会话 ID，状态保持未知")
            return {
                "id": str(payload["id"]),
                "cwd": payload.get("cwd"),
                "timestamp": payload.get("timestamp"),
                "line": line_number,
            }
        raise ValueError("没有读取到 session_meta 头，状态保持未知")

    if source.name.endswith(".jsonl.zst"):
        zstd = shutil.which("zstd")
        if not zstd:
            raise ValueError("缺少 zstd 解压工具，归档状态保持未知")
        result = bounded_process.consume_stream(
            [zstd, "-dc", "--", str(source)],
            parse,
            timeout=timeout,
            phase="归档压缩会话头读取",
            stop_early=lambda value: bool(value),
        )
        if not isinstance(result, dict):
            raise ValueError("压缩会话头读取结果无效")
        return result
    with source.open("rb") as stream:
        return parse(stream)


def _normalize_remote(remote: str) -> str:
    remote = remote.strip()
    if not remote:
        return ""
    if "@" in remote and ":" in remote and "://" not in remote:
        host, path = remote.split("@", 1)[1].split(":", 1)
        remote = "https://" + host + "/" + path
    try:
        from urllib.parse import urlsplit, urlunsplit
        parsed = urlsplit(remote)
        if parsed.scheme and parsed.netloc:
            host = parsed.hostname or parsed.netloc
            netloc = host + (f":{parsed.port}" if parsed.port else "")
            path = parsed.path.rstrip("/").removesuffix(".git")
            return urlunsplit((parsed.scheme, netloc, path, "", ""))
    except (ValueError, TypeError):
        pass
    return remote.split("#", 1)[0].removesuffix(".git")


_GIT_IDENTITY_CACHE: dict[str, dict[str, Any]] = {}


def _git_identity(ancestor: Path) -> dict[str, Any]:
    cache_key = str(ancestor.absolute())
    context = scan_context.current()
    identity_cache = context.git_identity_cache if context is not None else _GIT_IDENTITY_CACHE
    cached = identity_cache.get(cache_key)
    if cached is not None:
        return {**cached, "errors": list(cached.get("errors", []))}
    remote = ""
    common_dir = ""
    errors: list[str] = []
    try:
        result = bounded_process.run(["git", "-C", str(ancestor), "config", "--get", "remote.origin.url"], capture_output=True, text=True, timeout=4)
        if result.returncode == 0:
            remote = _normalize_remote(result.stdout)
    except (OSError, subprocess.SubprocessError) as error:
        errors.append(str(error))
    try:
        result = bounded_process.run(["git", "-C", str(ancestor), "rev-parse", "--git-common-dir"], capture_output=True, text=True, timeout=4)
        if result.returncode == 0 and result.stdout.strip():
            common_dir = str((ancestor / result.stdout.strip()).resolve())
        else:
            errors.append("无法读取 Git common-dir")
    except (OSError, subprocess.SubprocessError) as error:
        errors.append(str(error))
    identity = {"project_key": remote or common_dir or str(ancestor), "common_dir": common_dir, "remote": remote, "errors": errors}
    identity_cache[cache_key] = identity
    return {**identity, "errors": list(errors)}


def _broad_codex_container(path: Path, home: Path) -> bool:
    """Reject account-wide containers even when a session used one as cwd."""
    try:
        relative = path.absolute().relative_to(home.absolute())
    except ValueError:
        return False
    if not relative.parts:
        return True
    if path.name.casefold() in {
        "worktrees", ".worktrees", "sessions", "archived_sessions",
        "visualizations", "outputs", "downloads",
    }:
        return True
    first = relative.parts[0].casefold()
    if first in {"library", "downloads", "desktop", "pictures", "movies", "music"}:
        return len(relative.parts) == 1
    if first == "documents" and len(relative.parts) == 1:
        return True
    if first == "documents" and len(relative.parts) >= 2:
        container = relative.parts[1].casefold()
        if container in {"codex", "chatgpt"} and len(relative.parts) == 2:
            return True
        if (
            container in {"codex", "chatgpt"} and len(relative.parts) == 3
            and re.fullmatch(r"\d{4}-\d{2}-\d{2}", relative.parts[2])
        ):
            return True
    return False


def _codex_project_root(path: Path, home: Path, source_role: str) -> tuple[Path | None, str | None]:
    """Resolve a metadata path to one project, never to an account container."""
    path = Path(os.path.abspath(path.expanduser()))
    if _broad_codex_container(path, home):
        return None, "Codex 元数据指向账号级容器；不递归扩大为项目根"
    excluded = (home / "Library" / "Mobile Documents", home / "Library" / "CloudStorage")
    if local_path_status(path, home, excluded) is not True or not path.is_dir():
        return None, "项目路径不存在、不可读、属于云目录或包含未解析链接"
    try:
        if int(path.stat().st_dev) != int(home.stat().st_dev):
            return None, "项目位于当前账号 home 所在卷之外；按默认范围排除"
    except OSError:
        return None, "项目卷归属无法核实；按默认范围排除"

    git_root = bounded_process.run(
        ["git", "-C", str(path), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        timeout=4,
    )
    if git_root.returncode == 0 and git_root.stdout.strip():
        candidate = Path(git_root.stdout.strip()).absolute()
        if local_path_status(candidate, home, excluded) is True and not _broad_codex_container(candidate, home):
            return candidate, "通过 Git worktree 根解析到具体项目"

    if source_role in {"project", "thread"}:
        return path, "Codex 全局项目状态显式记录的精确项目路径"

    # A session cwd proves Codex activity at that exact directory. If it is
    # not inside a Git repository, keep only that directory as the project.
    return path, "Codex 会话头记录的精确 cwd"


_RUNTIME_PATH_FIELDS = {
    "runtimepath",
    "runtimedatapath",
    "runtimedatadir",
    "runtimedirectory",
    "taskruntimepath",
    "taskruntimedir",
    "taskdatapath",
    "taskdatadir",
}


def _runtime_paths_from_config(value: Any, *, allow_root_fields: bool) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []

    def collect_paths(item: Any, field: str) -> None:
        if isinstance(item, str):
            found.append((item, field))
        elif isinstance(item, list):
            for index, child in enumerate(item):
                collect_paths(child, f"{field}[{index}]")
        elif isinstance(item, dict):
            for key in ("path", "directory", "dir"):
                if key in item:
                    collect_paths(item[key], f"{field}.{key}")

    def walk(item: Any, prefix: str = "", in_codex_section: bool = False) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                field = f"{prefix}.{key}" if prefix else str(key)
                normalized = re.sub(r"[^a-z0-9]", "", str(key).casefold())
                if normalized in _RUNTIME_PATH_FIELDS and (allow_root_fields or in_codex_section):
                    collect_paths(child, field)
                    continue
                walk(
                    child,
                    field,
                    in_codex_section or normalized in {"codex", "codexruntime", "codexstorage"},
                )
        elif isinstance(item, list):
            for index, child in enumerate(item):
                walk(child, f"{prefix}[{index}]", in_codex_section)

    walk(value)
    return found


def discover_project_runtime_data(
    project_roots: Iterable[dict[str, Any]],
    home: str | Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Resolve only exact runtime paths named by a confirmed Codex project config."""
    home = Path(home).expanduser().absolute()
    excluded = (home / "Library" / "Mobile Documents", home / "Library" / "CloudStorage")
    try:
        home_device = int(home.stat().st_dev)
    except OSError:
        home_device = -1
    runtime_rows: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    references: list[dict[str, Any]] = []
    seen_sources: set[str] = set()
    seen_paths: set[str] = set()

    for project in project_roots:
        if not project.get("codex_source"):
            continue
        root = Path(str(project.get("path", ""))).expanduser().absolute()
        if root == home / ".codex" or not root.is_dir() or root.is_symlink():
            continue
        source_specs = [
            (root / ".codex" / "config.toml", "toml", True),
            (root / ".codex-task.json", "json", True),
            (root / "codex-task.json", "json", True),
            (root / "codex-run.json", "json", True),
            (root / "package.json", "package-json", True),
        ]
        for source, source_kind, allow_root_fields in source_specs:
            source_key = str(source.absolute())
            if source_key in seen_sources:
                continue
            seen_sources.add(source_key)
            try:
                source_info = source.lstat()
            except FileNotFoundError:
                continue
            except OSError as error:
                issues.append({
                    "path": source_key, "reason": f"Codex runtime 配置状态不可读：{error}",
                    "phase": "project-runtime-source",
                })
                continue
            if stat.S_ISLNK(source_info.st_mode):
                issues.append({
                    "path": source_key, "reason": "Codex runtime 配置是链接；未跟随",
                    "phase": "project-runtime-source",
                })
                continue
            if not stat.S_ISREG(source_info.st_mode):
                continue
            if source_info.st_size > 1_000_000:
                issues.append({
                    "path": source_key, "reason": "Codex runtime 配置超过 1 MB；路径来源保持未知",
                    "phase": "project-runtime-source",
                })
                continue
            try:
                if source_kind == "toml":
                    import importlib.util

                    parser_path = Path(__file__).resolve().with_name("build_evidence.py")
                    spec = importlib.util.spec_from_file_location("_storage_runtime_toml", parser_path)
                    if spec is None or spec.loader is None:
                        raise ValueError("无法加载 TOML 解析器")
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    parsed = module.toml(str(source))
                else:
                    parsed = json.loads(source.read_text(encoding="utf-8"))
                    if not isinstance(parsed, dict):
                        raise ValueError("runtime 配置根对象不是 JSON 对象")
                    if source_kind == "package-json":
                        parsed = parsed.get("codex", {})
                        if not isinstance(parsed, dict):
                            continue
                values = _runtime_paths_from_config(
                    parsed,
                    allow_root_fields=allow_root_fields,
                )
            except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
                issues.append({
                    "path": source_key, "reason": f"Codex runtime 配置无法解析：{error}",
                    "phase": "project-runtime-source",
                })
                continue

            for raw_path, field in values:
                scan_budget.check("Codex 项目 runtime 路径发现")
                hint = {
                    "raw_path": raw_path,
                    "field": field,
                    "source_file": source_key,
                    "path_base": str(root),
                    "source_role": "project-runtime",
                    "discovery_only": True,
                    "trash_paths": [],
                }
                if not raw_path.strip() or any(char in raw_path for char in ("\x00", "$", "*", "?")):
                    hint["status"] = "invalid"
                    issues.append({
                        **hint, "path": raw_path, "phase": "project-runtime-source",
                        "reason": "runtime 路径为空或包含不支持的变量/通配符",
                    })
                    continue
                target = Path(os.path.expanduser(raw_path))
                if not target.is_absolute():
                    target = root / target
                target = Path(os.path.abspath(target))
                hint["path"] = str(target)
                if not _same_or_below(target, home) or _under_any(target, excluded):
                    hint["status"] = "outside"
                    runtime_rows.append({
                        **hint, "id": "runtime:" + hashlib.sha256(
                            f"{source_key}\0{field}\0{target}".encode()
                        ).hexdigest()[:16],
                        "path": str(target), "source_status": "excluded",
                        "evidence_status": "scope-excluded",
                        "association_status": "excluded",
                        "origin_state": "confirmed-codex-runtime",
                        "purpose": "项目配置声明的精确 Codex 运行数据路径",
                    })
                    continue
                if _broad_codex_container(target, home):
                    hint["status"] = "invalid"
                    issues.append({
                        **hint, "phase": "project-runtime-source",
                        "reason": "runtime 路径指向账号级或通用容器；不扩大扫描范围",
                    })
                    continue
                local_status = local_path_status(target, home, excluded)
                if local_status is None:
                    hint["status"] = "unresolved"
                    issues.append({
                        **hint, "phase": "project-runtime-source",
                        "reason": "runtime 路径含链接、云目录或无法核实的路径组件；未跟随",
                    })
                    continue
                if local_status is False:
                    hint["status"] = "missing"
                    runtime_rows.append({
                        **hint, "id": "runtime:" + hashlib.sha256(
                            f"{source_key}\0{field}\0{target}".encode()
                        ).hexdigest()[:16],
                        "source_status": "missing",
                        "evidence_status": "historical-path-missing",
                        "association_status": "historical",
                        "origin_state": "confirmed-codex-runtime",
                        "purpose": "项目配置声明的精确 Codex 运行数据路径",
                    })
                    continue
                try:
                    info = target.stat()
                    if int(info.st_dev) != home_device:
                        hint["status"] = "outside-volume"
                        runtime_rows.append({
                            **hint, "id": "runtime:" + hashlib.sha256(
                                f"{source_key}\0{field}\0{target}".encode()
                            ).hexdigest()[:16],
                            "source_status": "outside-volume",
                            "evidence_status": "volume-excluded",
                            "association_status": "excluded",
                            "origin_state": "confirmed-codex-runtime",
                            "purpose": "项目配置声明的精确 Codex 运行数据路径",
                        })
                        continue
                except OSError as error:
                    issues.append({
                        **hint, "phase": "project-runtime-source",
                        "reason": f"runtime 路径卷归属无法核实：{error}",
                    })
                    continue
                target_key = str(target)
                if target_key in seen_paths:
                    continue
                seen_paths.add(target_key)
                hint["status"] = "exists"
                runtime_rows.append({
                    **hint,
                    "id": "runtime:" + hashlib.sha256(
                        f"{source_key}\0{field}\0{target}".encode()
                    ).hexdigest()[:16],
                    "source_status": "current",
                    "evidence_status": "source-config",
                    "association_status": "confirmed",
                    "origin_state": "confirmed-codex-runtime",
                    "project_key": project.get("project_key"),
                    "codex_related": True,
                    "activity_status": "not-checked",
                    "disposition_class": "本地保留",
                    "planned_disposition_class": "暂不处理",
                    "purpose": "项目配置声明的精确 Codex 运行数据路径",
                    "evidence": f"Codex 项目来源 {source_key} 字段 {field}",
                    "coverage_status": "pending-scan",
                    "trash_paths": [],
                })
                references.append({
                    **hint,
                    "source_path": source_key,
                    "status": "exists",
                })
    return runtime_rows, issues, references


def discover_project_roots(home: str | Path) -> list[dict[str, Any]]:
    """Find Codex source roots and explicit project references.

    A Codex root proves source provenance only. It does not invent a project
    identity; that identity comes from Git or an explicit path reference.
    """
    home = Path(home).expanduser().absolute()
    candidates: list[dict[str, Any]] = []
    candidates_by_path: dict[str, dict[str, Any]] = {}
    issues: list[dict[str, Any]] = []
    references: list[dict[str, Any]] = []
    try:
        home_device = int(home.stat().st_dev)
    except OSError:
        home_device = -1

    def add(
        path: Path,
        evidence: str,
        codex_source: bool,
        *,
        project_key: str | None = None,
        references: Iterable[str] = (),
        source_file: str | None = None,
        source_field: str | None = None,
    ) -> None:
        if _under_any(path, (home / "Library" / "Mobile Documents", home / "Library" / "CloudStorage")):
            return
        if (
            local_path_status(path, home, (home / "Library" / "Mobile Documents", home / "Library" / "CloudStorage")) is not True
            or not (path.is_dir() or path.is_file())
        ):
            return
        try:
            if home_device < 0 or int(path.stat().st_dev) != home_device:
                issues.append({
                    "path": str(path), "reason": "Codex 路径位于当前账号 home 所在卷之外；按默认范围排除",
                    "phase": "scan-root-volume", "severity": "info",
                })
                return
        except OSError as error:
            issues.append({
                "path": str(path), "reason": f"无法核实 Codex 路径所属卷：{error}",
                "phase": "scan-root-volume", "severity": "info",
            })
            return
        normalized = str(path)
        existing = candidates_by_path.get(normalized)
        if existing:
            existing["codex_source"] = bool(existing.get("codex_source") or codex_source)
            if project_key and not existing.get("project_key"):
                existing["project_key"] = project_key
            existing["references"] = sorted(set(existing.get("references", [])) | set(references))
            if codex_source:
                existing["evidence"] = evidence
                if source_file:
                    existing["source_file"] = source_file
                if source_field:
                    existing["source_field"] = source_field
            return
        candidate = {
            "path": normalized, "evidence": evidence, "codex_source": codex_source,
            "project_key": project_key, "references": sorted(set(references)),
            "source_file": source_file, "source_field": source_field, "trash_paths": [],
        }
        if source_field == "project runtime path":
            candidate["root_kind"] = "codex-runtime"
        candidates.append(candidate)
        candidates_by_path[normalized] = candidate

    add(home / ".codex", "Codex 全局/任务状态根", True)

    excluded = (home / "Library" / "Mobile Documents", home / "Library" / "CloudStorage")
    entry_errors: list[dict[str, Any]] = []
    ignored_entry_names = {
        ".git", ".worktrees", "worktrees", "node_modules", ".venv", "venv",
        "build", "dist", "target", ".build", "vendor",
    }
    marker_names = ("config.toml", "settings.json")
    documents_device = home_device
    for container_name in ("Codex", "ChatGPT"):
        container = home / "Documents" / container_name
        if local_path_status(container, home, excluded) is not True:
            continue
        try:
            if int(container.stat().st_dev) != documents_device:
                continue
        except OSError as error:
            entry_errors.append({
                "path": str(container), "reason": str(error),
                "phase": "project-entry-discovery",
            })
            continue
        queue: list[tuple[Path, int]] = [(container, 0)]
        while queue:
            scan_budget.check("Documents 下有限项目入口发现")
            current, depth = queue.pop()
            try:
                with os.scandir(current) as iterator:
                    children = list(iterator)
            except OSError as error:
                entry_errors.append({
                    "path": str(current), "reason": str(error),
                    "phase": "project-entry-discovery",
                })
                continue
            codex_marker: Path | None = None
            child_dirs: list[Path] = []
            for entry in children:
                if entry.is_symlink():
                    continue
                child = Path(entry.path)
                try:
                    if entry.is_dir(follow_symlinks=False):
                        if child.name == ".codex":
                            for marker_name in marker_names:
                                marker = child / marker_name
                                try:
                                    marker_info = marker.lstat()
                                except FileNotFoundError:
                                    continue
                                if stat.S_ISREG(marker_info.st_mode):
                                    codex_marker = marker
                                    break
                        if (
                            depth < 3
                            and entry.name not in ignored_entry_names
                            and int(entry.stat(follow_symlinks=False).st_dev) == documents_device
                            and not _is_mount_boundary(child, documents_device)
                        ):
                            child_dirs.append(child)
                    elif (
                        entry.is_file(follow_symlinks=False)
                        and depth > 0
                        and entry.name in {".codex-task.json", "codex-task.json", "codex-run.json"}
                    ):
                        codex_marker = child
                except OSError as error:
                    entry_errors.append({
                        "path": str(child), "reason": str(error),
                        "phase": "project-entry-discovery",
                    })
            if codex_marker is not None and depth > 0:
                add(
                    current,
                    f"Documents/{container_name} 第 {depth} 层项目中的 Codex 配置入口",
                    True,
                    source_file=str(codex_marker),
                    source_field="Codex project marker",
                )
                continue
            if depth < 3:
                queue.extend((child, depth + 1) for child in sorted(child_dirs, key=str))

    runtime_data, runtime_issues, runtime_references = discover_project_runtime_data(
        candidates, home
    )
    issues.extend(runtime_issues)
    references.extend(runtime_references)
    for runtime in runtime_data:
        if runtime.get("source_status") != "current":
            continue
        runtime_path = Path(runtime["path"])
        add(
            runtime_path,
            str(runtime.get("evidence") or "确认项目配置中的精确 Codex runtime 路径"),
            True,
            project_key=runtime.get("project_key"),
            references=[str(runtime_path)],
            source_file=runtime.get("source_file"),
            source_field="project runtime path",
        )
        runtime_root = candidates_by_path.get(str(runtime_path))
        if runtime_root is not None:
            runtime_root.update({
                "root_kind": "codex-runtime",
                "runtime_mapping_id": runtime.get("id"),
                "purpose": runtime.get("purpose"),
                "source_status": runtime.get("source_status"),
                "evidence_status": runtime.get("evidence_status"),
                "association_status": runtime.get("association_status"),
                "origin_state": runtime.get("origin_state"),
                "activity_status": runtime.get("activity_status"),
                "disposition_class": runtime.get("disposition_class"),
                "planned_disposition_class": runtime.get("planned_disposition_class"),
                "suggested_disposition": "本轮只统计并保留",
                "retention_note": "项目配置声明的精确运行数据路径；默认保留",
                "recovery_cost": "用途或依赖状态变化前不处理",
                "evidence_paths": [runtime.get("source_file"), str(runtime_path)],
            })

    codex_state_root = home / ".codex"
    try:
        state_on_home_volume = (
            codex_state_root.is_dir()
            and int(codex_state_root.stat().st_dev) == home_device
        )
    except OSError:
        state_on_home_volume = False
    if codex_state_root.exists() and not state_on_home_volume:
        state_files, state_errors = [], [{
            "path": str(codex_state_root),
            "reason": "Codex 状态目录位于当前账号 home 所在卷之外；按默认范围排除",
            "phase": "state-cross-volume", "severity": "info",
        }]
    else:
        state_files, state_errors = _walk_state_files(codex_state_root)
    issues.extend(state_errors)
    issues.extend(entry_errors)
    references: list[dict[str, Any]] = []
    for state in state_files:
        try:
            for hint in _source_references(state):
                references.append(hint)
                value = hint['raw_path']
                if '\x00' in value or ':' in value or '$' in value:
                    hint['status'] = 'invalid'
                    issues.append({**hint, 'path': value, 'phase': 'project-reference', 'code': 'invalid-reference', 'reason': '无效路径或路径列表，未作为项目根'})
                    continue
                hinted = Path(value).expanduser()
                if not hinted.is_absolute():
                    if hint['source_role'] == 'session':
                        hint['status'] = 'unresolved'
                        issues.append({**hint, 'path': value, 'phase': 'project-reference', 'code': 'unresolved-relative', 'reason': '会话相对 cwd 缺少可靠基准'})
                        continue
                    hinted = state.parent / hinted
                hinted = Path(os.path.abspath(hinted))
                hint['path'] = str(hinted)
                if _under_any(hinted, (home / "Library" / "Mobile Documents", home / "Library" / "CloudStorage")):
                    hint['status'] = 'outside'
                    issues.append({**hint, 'phase': 'project-reference', 'severity': 'info', 'code': 'cloud-excluded', 'reason': '云同步目录按本地清理范围排除'})
                    continue
                if not _same_or_below(hinted, home):
                    hint['status'] = 'outside'
                    issues.append({**hint, "reason": "范围外引用；仅记录，不跟随", "phase": "project-reference", 'severity': 'info', 'code': 'outside-reference'})
                    continue
                target_status = local_path_status(hinted, home, (home / "Library" / "Mobile Documents", home / "Library" / "CloudStorage"))
                if target_status is None:
                    hint['status'] = 'unresolved'
                    issues.append({**hint, 'phase': 'project-reference', 'code': 'unresolved-link', 'reason': '引用包含符号链接或不可读取，未跟随'})
                    continue
                try:
                    hinted.stat()
                except FileNotFoundError:
                    hint['status'] = 'missing'
                    issues.append({**hint, 'phase': 'project-reference', 'code': 'missing-reference', 'severity': 'info', 'reason': '引用路径已不存在；保留历史线索，不计占用'})
                    continue
                except OSError as error:
                    hint['status'] = 'unreadable'
                    issues.append({**hint, 'phase': 'project-reference', 'code': 'unreadable-reference', 'reason': str(error)})
                    continue
                hint['status'] = 'exists'
                if hinted.is_file():
                    hint['scope'] = 'file'
                    add(
                        hinted,
                        f"Codex 状态/会话显式记录的精确文件：{hint['field']}",
                        True,
                        project_key=('codex-project:' + str(hint['record_id']))
                        if hint['source_role'] == 'project' and hint.get('record_id') else None,
                        references=[str(hinted)],
                    )
                    continue
                identity = _git_identity(hinted) if (hinted / ".git").exists() else {"project_key": None}
                explicit_identity = ('codex-project:' + str(hint['record_id'])) if hint['source_role'] == 'project' and hint.get('record_id') else None
                project_root, root_evidence = _codex_project_root(hinted, home, hint.get("source_role", "project"))
                if project_root is None:
                    hint["scope"] = "directory-not-included"
                    hint["scope_reason"] = root_evidence
                    issues.append({
                        **hint, "path": str(hinted), "phase": "project-reference",
                        "severity": "info", "code": "non-project-container",
                        "reason": root_evidence or "没有确认具体 Codex 项目根",
                    })
                    continue
                identity = _git_identity(project_root) if (project_root / ".git").exists() else {"project_key": None}
                add(
                    project_root,
                    f"Codex 状态/配置显式路径：{hint['field']}；{root_evidence}",
                    True,
                    project_key=identity.get("project_key") or explicit_identity,
                    references=[str(hinted)],
                )
                root = next((item for item in candidates if item['path'] == str(project_root)), None)
                if root is not None:
                    root.setdefault('source_references', []).append(hint)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            issues.append({"path": str(state), 'source_file': str(state), "reason": str(error), "phase": "state-parse", 'code': 'source-parse'})

    # Codex metadata confirms the project first.  Git's worktree registry then
    # supplies only the linked worktrees belonging to that confirmed project.
    confirmed_projects = [
        row for row in list(candidates)
        if row.get("codex_source")
        and row.get("root_kind") != "codex-runtime"
        and row.get("path") != str(home / ".codex")
        and Path(row.get("path", "")).is_dir()
        and (Path(row["path"]) / ".git").exists()
        and not (Path(row["path"]) / ".git").is_symlink()
    ]
    seen_worktree_queries: set[str] = set()
    for project in confirmed_projects:
        project_path = Path(project["path"]).absolute()
        try:
            common_result = bounded_process.run(
                ["git", "-C", str(project_path), "rev-parse", "--path-format=absolute", "--git-common-dir"],
                capture_output=True, text=True, timeout=4,
            )
            if common_result.returncode != 0 or not common_result.stdout.strip():
                continue
            common_dir = str(Path(common_result.stdout.strip()).absolute())
            if common_dir in seen_worktree_queries:
                continue
            seen_worktree_queries.add(common_dir)
            listing = bounded_process.run(
                ["git", "-C", str(project_path), "worktree", "list", "--porcelain"],
                capture_output=True, text=True, timeout=4,
            )
        except (OSError, subprocess.SubprocessError) as error:
            issues.append({
                "path": str(project_path), "reason": f"Git linked worktree 登记无法读取：{error}",
                "phase": "worktree-registry",
            })
            continue
        if listing.returncode != 0:
            issues.append({
                "path": str(project_path),
                "reason": (listing.stderr or listing.stdout).strip() or "Git linked worktree 登记读取失败",
                "phase": "worktree-registry",
            })
            continue
        for line in listing.stdout.splitlines():
            if not line.startswith("worktree "):
                continue
            registered = Path(line[9:]).expanduser()
            if not registered.is_absolute():
                registered = project_path / registered
            registered = Path(os.path.abspath(registered))
            if registered == project_path:
                continue
            if not _same_or_below(registered, home):
                issues.append({
                    "path": str(registered), "reason": "Git 登记的 worktree 位于当前账号 home 之外；按默认范围排除",
                    "phase": "worktree-registry", "severity": "info",
                })
                continue
            if not registered.is_dir():
                issues.append({
                    "path": str(registered), "reason": "Git 登记的 worktree 当前不存在；保留登记线索，不计本机占用",
                    "phase": "worktree-registry", "severity": "info",
                })
                continue
            add(
                registered,
                f"由已确认 Codex 项目 {project_path} 的 Git worktree list 登记",
                True,
                project_key=project.get("project_key"),
                source_file=str(project_path / ".git"),
                source_field="git worktree list --porcelain",
            )
    discover_project_roots.last_issues = issues  # type: ignore[attr-defined]
    discover_project_roots.last_references = references  # type: ignore[attr-defined]
    discover_project_roots.last_runtime_data = runtime_data  # type: ignore[attr-defined]
    return sorted(candidates, key=lambda item: (len(Path(item["path"]).parts), item["path"]))


def _normalized_tokens(value: str) -> set[str]:
    return {token for token in re.split(r"[^a-zA-Z0-9]+", value.casefold()) if len(token) >= 3}


def supplement_project_roots(home: Path, roots: list[dict[str, Any]], records: list[dict[str, Any]]) -> None:
    """Inventory evidence supplies identities, never invents Codex provenance."""
    existing = {item['path']: item for item in roots}
    discovered: dict[Path, bool] = {}
    for record in records:
        path = Path(record['path'])
        if path.name == '.git' or (path.name == 'HEAD' and path.parent.name == '.git'):
            discovered[path.parent if path.name == '.git' else path.parent.parent] = True
        elif path.name in {'Cargo.toml', 'Package.swift', 'package.json', 'pyproject.toml'}:
            discovered.setdefault(path.parent, False)
    for path, git in discovered.items():
        if not _same_or_below(path, home) or path.is_symlink():
            continue
        key = str(path)
        identity = _git_identity(path) if git else {'project_key': None}
        if key in existing:
            if identity.get('project_key'):
                existing[key]['project_key'] = identity['project_key']
            continue
        item = {'path': key, 'project_key': identity.get('project_key'),
                'evidence': '全量清单 Git/项目 manifest 身份线索', 'codex_source': False,
                'references': [], 'discovery_only': True, 'trash_paths': []}
        roots.append(item)
        existing[key] = item


def project_root_lookup(roots: list[dict[str, Any]]) -> Callable[[Path], dict[str, Any] | None]:
    """Independent longest identity/source matches in O(path depth)."""
    marker = object()
    index: dict[Any, Any] = {}
    for root in roots:
        node = index
        for part in Path(root['path']).parts:
            node = node.setdefault(part, {})
        node[marker] = root
    def lookup(path: Path) -> dict[str, Any] | None:
        node = index
        result = None
        for part in path.parts:
            node = node.get(part)
            if node is None:
                break
            if marker in node:
                root = node[marker]
                previous = result or {}
                result = {**root, 'project_key': root.get('project_key') or previous.get('project_key'),
                          'codex_source': bool(root.get('codex_source') or previous.get('codex_source')),
                          'codex_source_evidence': root.get('evidence') if root.get('codex_source') else previous.get('codex_source_evidence', '来源未知')}
                for field in ('runtime_mapping_id', 'app_id', 'purpose', 'source_status',
                              'evidence_status', 'evidence_error',
                              'association_status',
                              'origin_state', 'activity_status', 'disposition_class',
                              'planned_disposition_class', 'suggested_disposition',
                              'retention_note', 'recovery_cost',
                              't1_hint', 'evidence_paths'):
                    if root.get(field) is not None:
                        result[field] = root[field]
        return result
    return lookup


def associate_project(path: str | Path, project_roots: list[dict[str, Any]], explicit_paths: Iterable[str | Path] = (), scope_home: Path | None = None) -> dict[str, Any]:
    """Associate by explicit/Git evidence; names never assign a project key."""
    path = Path(path).expanduser().absolute()
    association_errors: list[str] = []
    try:
        path_is_dir = path.is_dir()
    except (OSError, ValueError) as error:
        path_is_dir = False
        association_errors.append(f"归属路径无法检查目录状态：{error}")
    current = path if path_is_dir else path.parent
    explicit: list[Path] = []
    for item in explicit_paths:
        raw = str(item)
        if "\x00" in raw:
            association_errors.append("显式项目路径含嵌入 NUL 字节，未用于归属")
            continue
        try:
            explicit.append(Path(item).expanduser().absolute())
        except (OSError, ValueError) as error:
            association_errors.append(f"显式项目路径无法解析：{error}")
    roots = sorted(project_roots, key=lambda item: len(Path(item["path"]).parts), reverse=True)
    containing = next((root for root in roots if _same_or_below(current, Path(root["path"]))), None)
    codex_source = next((root for root in roots if root.get('codex_source') and _same_or_below(current, Path(root['path']))), None)
    identity_root = next((root for root in roots if root.get('project_key') and _same_or_below(current, Path(root['path']))), None)
    runtime_root = next((root for root in roots if root.get('runtime_mapping_id') and _same_or_below(current, Path(root['path']))), None)

    def enrich(result: dict[str, Any]) -> dict[str, Any]:
        if runtime_root:
            for field in ('runtime_mapping_id', 'app_id', 'purpose', 'source_status',
                          'evidence_status', 'evidence_error',
                          'association_status',
                          'origin_state', 'activity_status', 'disposition_class',
                          'planned_disposition_class', 'suggested_disposition',
                          'retention_note', 'recovery_cost',
                          't1_hint', 'evidence_paths'):
                if runtime_root.get(field) is not None:
                    result[field] = runtime_root[field]
        result.setdefault('origin_state', 'confirmed-codex' if result.get('codex_related') else 'unknown')
        result.setdefault('source_status', 'confirmed' if result.get('codex_related') else 'unknown')
        result.setdefault('evidence_status', 'readable' if result.get('codex_related') else 'missing')
        result.setdefault('evidence_error', None)
        result.setdefault('association_status', 'confirmed' if result.get('codex_related') else 'unconfirmed')
        result.setdefault('activity_status', 'not-checked')
        result.setdefault('disposition_class', '本地保留' if result.get('codex_related') else '暂不处理')
        result.setdefault('planned_disposition_class', result.get('disposition_class'))
        result.setdefault('suggested_disposition', '保留；按现有规则进一步评估' if result.get('codex_related') else '暂不处理')
        result.setdefault('retention_note', '保留项待确认')
        result.setdefault('recovery_cost', '恢复代价待确认')
        return result
    for reference in explicit:
        if scope_home is not None and local_path_status(reference, scope_home, (scope_home / "Library" / "Mobile Documents", scope_home / "Library" / "CloudStorage")) is not True:
            association_errors.append(f"显式项目路径在范围外或不可安全解析：{reference}")
            continue
        try:
            reference_is_dir = reference.is_dir()
        except (OSError, ValueError) as error:
            reference_is_dir = False
            association_errors.append(f"显式项目路径无法检查目录状态：{error}")
        reference_dir = reference if reference_is_dir else reference.parent
        if not _safe_is_dir(reference_dir):
            association_errors.append(f"显式项目路径不存在或不可读取：{reference}")
            continue
        explicit_root = next((root for root in roots if Path(root["path"]) == reference_dir), None)
        if explicit_root and explicit_root.get("project_key"):
            return enrich({
                "project_key": explicit_root["project_key"], "source_root": str(reference_dir),
                "evidence": "测试/任务 manifest 的显式项目路径引用", "codex_source_evidence": explicit_root.get("evidence", "显式项目路径"),
                "codex_related": bool(codex_source or explicit_root.get('codex_source')), "confidence": "high", "association_candidates": [], "association_errors": association_errors,
            })
        if _safe_exists(reference_dir / ".git"):
            identity = _git_identity(reference_dir)
            return enrich({
                "project_key": identity["project_key"], "source_root": str(reference_dir),
                "common_dir": identity.get("common_dir"), "remote": identity.get("remote"),
                "evidence": "测试/任务 manifest 的显式项目路径引用及 Git 身份",
                "codex_source_evidence": "显式项目身份引用（不单独证明 Codex 来源）", "codex_related": bool(codex_source),
                "confidence": "high", "association_candidates": [], "association_errors": association_errors + identity.get("errors", []),
            })
    for ancestor in (current, *current.parents):
        if not _safe_exists(ancestor / ".git"):
            continue
        identity = _git_identity(ancestor)
        return enrich({
            "project_key": identity["project_key"], "source_root": str(ancestor), "common_dir": identity.get("common_dir"), "remote": identity.get("remote"),
            "evidence": "Git common-dir/仓库来源" + ("（含规范化 remote）" if identity.get("remote") else ""),
            "codex_source_evidence": codex_source.get("evidence") if codex_source else "未确认 Codex 来源",
            "codex_related": bool(codex_source), "confidence": "high", "association_candidates": [], "association_errors": association_errors + identity.get("errors", []),
        })
    if containing:
        project_key = identity_root.get('project_key') if identity_root else None
        if project_key:
            return enrich({
                "project_key": project_key, "source_root": containing["path"], "evidence": containing["evidence"],
                "codex_source_evidence": codex_source['evidence'] if codex_source else "未确认 Codex 来源",
                "codex_related": bool(codex_source), "confidence": "medium", "association_candidates": [], "association_errors": association_errors,
            })
        return enrich({
            "project_key": None, "source_root": containing["path"], "evidence": containing["evidence"] + "；已确认来源但没有项目身份",
            "codex_source_evidence": codex_source['evidence'] if codex_source else "未确认 Codex 来源",
            "codex_related": bool(codex_source), "confidence": "source-only", "association_candidates": [], "association_errors": association_errors,
        })
    candidate_names = []
    tokens = _normalized_tokens(current.name)
    for root in roots:
        overlap = tokens & _normalized_tokens(Path(root["path"]).name)
        if overlap:
            candidate_names.append({"project_key": root.get("project_key"), "root": root["path"], "tokens": sorted(overlap), "reason": "仅名称相似，未用于归组"})
    return enrich({
        "project_key": None, "source_root": None, "evidence": "未找到 Git、明确配置或显式路径引用", "codex_source_evidence": "来源未知",
        "codex_related": False, "confidence": "unknown", "association_candidates": candidate_names, "association_errors": association_errors,
    })


def _jsonc_text(text: str) -> str:
    """Remove comments and trailing commas lexically, preserving string bytes."""
    chars = list(text)
    quoted = escaped = False
    index = 0
    while index < len(chars):
        char = chars[index]
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char == '/' and index + 1 < len(chars) and chars[index + 1] in ('/', '*'):
            block = chars[index + 1] == '*'
            end = text.find('*/', index + 2) if block else text.find('\n', index + 2)
            if block and end < 0:
                raise ValueError('截断的 JSONC 注释')
            end = len(chars) if end < 0 else end + (2 if block else 0)
            for pos in range(index, end):
                if chars[pos] not in '\r\n':
                    chars[pos] = ' '
            index = end - 1
        index += 1
    quoted = escaped = False
    for index, char in enumerate(chars):
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char == ',':
            end = index + 1
            while end < len(chars) and chars[end].isspace():
                end += 1
            if end < len(chars) and chars[end] in ']}':
                chars[index] = ' '
    return ''.join(chars)


def _parse_jsonish_file(path: Path, issues: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    def diagnostic(code: str, reason: str, severity: str = 'error', **details: Any) -> None:
        if issues is not None:
            issues.append({'path': str(path), 'source_file': str(path), 'phase': 'test-metadata',
                           'code': code, 'severity': severity, 'reason': reason, **details})
    def collect(value: Any, line: int = 1, offset: int = 0) -> None:
        if isinstance(value, dict):
            records.append({**value, '_storage_location': {'source_file': str(path), 'line': line,
                                                          'offset': offset, 'record_index': len(records)}})
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    collect(item, line, offset)
    try:
        before = path.stat()
        if before.st_size == 0:
            diagnostic('empty-metadata', '空元数据，无法判断格式或完成状态')
            return records
        stream_format = path.suffix.casefold() in {'.jsonl', '.ndjson'}
        if not stream_format:
            with path.open(encoding='utf-8') as stream:
                first = stream.readline(25_000_001)
                while first and not first.strip():
                    first = stream.readline(25_000_001)
            try:
                first_value, first_end = json.JSONDecoder().raw_decode(first, len(first) - len(first.lstrip()))
                stream_format = isinstance(first_value, dict) and (before.st_size > len(first.encode('utf-8')) or first[first_end:].strip())
            except ValueError:
                pass
        if not stream_format:
            if before.st_size > 25_000_000:
                diagnostic('parse-budget', '单个 JSON 超过 25 MB 解析预算', unparsed_bytes=before.st_size)
                return records
            text = path.read_text(encoding='utf-8')
            try:
                collect(json.loads(text))
            except ValueError as strict_error:
                try:
                    collect(json.loads(_jsonc_text(text)))
                    diagnostic('jsonc-recovered', '已按 JSONC 解析注释或尾逗号', 'info')
                except ValueError:
                    # A broken pretty-printed JSON document is one failed
                    # document, not hundreds of fictitious JSONL bad lines.
                    diagnostic('invalid-json', str(strict_error),
                               line=getattr(strict_error, 'lineno', 1), offset=getattr(strict_error, 'pos', 0))
        if stream_format:
            decoder = json.JSONDecoder()
            with path.open(encoding='utf-8') as stream:
                offset = 0
                for line_number, line in enumerate(stream, 1):
                    position = 0
                    decoded = 0
                    while position < len(line):
                        while position < len(line) and line[position].isspace():
                            position += 1
                        if position == len(line):
                            break
                        try:
                            start_position = position
                            value, position = decoder.raw_decode(line, position)
                            collect(value, line_number, offset + len(line[:start_position].encode('utf-8')))
                            decoded += 1
                        except ValueError as error:
                            diagnostic('truncated-tail' if offset + len(line.encode('utf-8')) >= before.st_size else 'invalid-record',
                                       str(error), line=line_number, offset=offset + len(line[:position].encode('utf-8')))
                            break
                    if decoded > 1:
                        diagnostic('concatenated-records', '已恢复同一行拼接 JSON 对象', 'info', line=line_number, offset=offset)
                    offset += len(line.encode('utf-8'))
        after = path.stat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            diagnostic('file-changed', '解析期间文件变化，完成状态不稳定')
    except (OSError, ValueError) as error:
        diagnostic('read-failed', str(error))
    return records


def _reference_role(key: str) -> str:
    lowered = key.casefold()
    if "model" in lowered or "weight" in lowered:
        return "models"
    if "database" in lowered or lowered.endswith("db"):
        return "databases"
    if "intermediate" in lowered or "tmp" in lowered:
        return "intermediates"
    if "output" in lowered or "result" in lowered or "report" in lowered:
        return "results"
    if lowered == 'exportedfilename':
        return 'results'
    if "project" in lowered or "workspace" in lowered or "repo" in lowered or lowered in {"root", "cwd"}:
        return "project"
    return "inputs"


RUN_PATH_FIELDS = {'project_root', 'workspace_root', 'repo_root', 'input_path', 'input_paths',
                   'output_path', 'output_paths', 'result_path', 'results_path', 'report_path',
                   'model_path', 'database_path', 'intermediate_path', 'artifact_path', 'exportedfilename'}


RUN_STATUS_VALUES = {
    'running', 'starting', 'queued', 'in_progress', 'in-progress', 'pending',
    'failed', 'error', 'blocked', 'partial', 'cancelled', 'canceled', 'aborted',
    'timed_out', 'timeout', 'completed', 'complete', 'done', 'success',
    'succeeded', 'finished', 'skipped', 'notrequested', 'not_requested', 'not-requested',
}


def _run_identity(record: dict[str, Any]) -> str | None:
    for key in ('run_id', 'runId', 'batch_id', 'batchId', 'execution_id', 'executionId', 'test_id', 'testId'):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _run_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _run_path_value(value: Any) -> bool:
    if isinstance(value, str):
        # A NUL-containing reference is invalid for use, but it is still
        # evidence that a run record attempted to describe an artifact.  The
        # reference parser records it as a gap instead of silently discarding
        # the surrounding run.
        return bool(value.strip())
    if isinstance(value, (list, tuple)):
        return bool(value) and all(isinstance(item, str) and item.strip() for item in value)
    return False


def _run_status(record: dict[str, Any]) -> str | None:
    for key in ('status', 'state', 'stage', 'phase', 'runStatus'):
        value = record.get(key)
        if isinstance(value, str):
            normalized = value.strip().casefold()
            if normalized in RUN_STATUS_VALUES:
                return normalized
    return None


def _has_invalid_run_status(record: dict[str, Any]) -> bool:
    # Configuration/fixture objects often contain a business status such as
    # ``notRequested``.  Only validate status values after the record has a
    # recognizable run identity, count, or artifact reference.
    identity = _run_identity(record)
    has_counts = any(_run_count(record.get(key)) for key in (
        'expected', 'expected_count', 'expectedCount', 'total', 'total_count',
        'totalCount', 'planned', 'completed', 'completed_count',
        'completedCount', 'done_count', 'doneCount', 'finished'))
    has_artifacts = any(_run_path_value(record.get(key)) for key in RUN_PATH_FIELDS - {'project_root', 'workspace_root', 'repo_root'})
    if not (identity or has_counts or has_artifacts):
        return False
    for key in ('status', 'state', 'stage', 'phase', 'runStatus'):
        value = record.get(key)
        if value in (None, ''):
            continue
        if not isinstance(value, str) or value.strip().casefold() not in RUN_STATUS_VALUES:
            return True
    return False


def _run_record(record: dict[str, Any]) -> bool:
    if isinstance(record.get('testIdentifier'), str) and isinstance(record.get('attachments'), list):
        return True  # XCTest result export schema, not a project-name special case.
    identity = _run_identity(record)
    expected = any(_run_count(record.get(key)) for key in ('expected', 'expected_count', 'expectedCount', 'total', 'total_count', 'totalCount', 'planned'))
    completed = any(_run_count(record.get(key)) for key in ('completed', 'completed_count', 'completedCount', 'done_count', 'doneCount', 'finished'))
    counts = expected or completed
    count_pair = expected and completed
    artifacts = any(_run_path_value(record.get(key)) for key in RUN_PATH_FIELDS - {'project_root', 'workspace_root', 'repo_root'})
    status = _run_status(record)
    return bool((identity and (status or counts or artifacts)) or
                (status and (artifacts or count_pair)))


def _record_references(
    value: Any,
    root: Path,
    references: list[str],
    roles: dict[str, list[str]],
    project_paths: list[str],
    key: str = "",
    gaps: list[dict[str, Any]] | None = None,
    provenance: dict[str, Any] | None = None,
    field_path: str = '',
) -> None:
    if isinstance(value, dict):
        for child_key, child in value.items():
            _record_references(child, root, references, roles, project_paths, str(child_key), gaps,
                               provenance, f'{field_path}.{child_key}'.lstrip('.'))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _record_references(child, root, references, roles, project_paths, key, gaps,
                               provenance, f'{field_path}[{index}]')
    elif isinstance(value, str) and value and not value.startswith(("http://", "https://")):
        lowered = key.casefold()
        if lowered not in RUN_PATH_FIELDS:
            return
        if "\x00" in value:
            if gaps is not None:
                gaps.append({**(provenance or {}), "path": str(root), 'field': field_path,
                             'code': 'invalid-reference', 'role': _reference_role(key), "reason": "引用路径含嵌入 NUL 字节，未使用", "phase": "test-reference"})
            return
        reference = Path(os.path.expanduser(value))
        if not reference.is_absolute():
            reference = root / reference
        reference = reference.absolute()
        path_text = str(reference)
        references.append(path_text)
        role = _reference_role(key)
        roles[role].append(path_text)
        if role == "project":
            project_paths.append(path_text)


def profile_test_run(
    path: str | Path,
    metadata_paths: Iterable[str | Path] | None = None,
    log_paths: Iterable[str | Path] | None = None,
    symlink_paths: Iterable[str | Path] | None = None,
    scope_home: str | Path | None = None,
) -> dict[str, Any]:
    """Describe a test run, preserving metadata gaps and dependencies."""
    root = Path(path).expanduser().absolute()
    scope = Path(scope_home).expanduser().absolute() if scope_home is not None else None
    statuses: list[str] = []
    references: list[str] = []
    project_paths: list[str] = []
    report_files: list[str] = []
    metadata_files: list[str] = []
    parse_gaps: list[dict[str, Any]] = []
    artifact_roles: dict[str, list[str]] = {"inputs": [], "models": [], "intermediates": [], "results": [], "databases": [], "project": []}
    expected_count: int | None = None
    completed_count: int | None = None
    status_records = 0
    run_evidence: list[dict[str, Any]] = []
    candidate_kinds: set[str] = set()
    ordered_events: dict[tuple[str, str], list[str]] = defaultdict(list)
    unordered_statuses: list[str] = []
    run_counts: dict[tuple[str, str], dict[str, int | None]] = {}
    run_identities: set[str] = set()
    run_boundaries: list[dict[str, Any]] = []

    def process_file(file_path: Path) -> None:
        nonlocal expected_count, completed_count, status_records
        if file_path.is_symlink():
            parse_gaps.append({"path": str(file_path), "reason": "测试文件是链接，未跟随", "phase": "test-file"})
            return
        try:
            file_size = file_path.stat().st_size
        except (OSError, ValueError) as error:
            parse_gaps.append({"path": str(file_path), "reason": str(error), "phase": "test-file"})
            return
        suffix = file_path.suffix.casefold()
        if suffix in {".json", ".jsonl", ".ndjson"}:
            metadata_files.append(str(file_path))
            records = _parse_jsonish_file(file_path, parse_gaps)
            for record in records:
                invalid_status = _has_invalid_run_status(record)
                if invalid_status:
                    parse_gaps.append({
                        'path': str(file_path), 'phase': 'test-status',
                        'code': 'ambiguous-run-record',
                        'reason': '运行状态字段存在但类型/取值不受支持，不能与有效运行合并',
                    })
                if not _run_record(record):
                    invalid_identity = any(
                        key in record and record.get(key) not in (None, '') and
                        not (isinstance(record.get(key), str) and record.get(key).strip())
                        for key in ('run_id', 'runId', 'batch_id', 'batchId', 'execution_id', 'executionId'))
                    if invalid_identity:
                        parse_gaps.append({
                            'path': str(file_path), 'phase': 'test-status',
                            'code': 'ambiguous-run-record',
                            'reason': '运行身份字段存在但类型/取值不受支持，不能与有效运行合并',
                        })
                    if any(key in record for key in ('Put', 'Key', 'fixtures', 'test_cases')):
                        candidate_kinds.add('test-fixture')
                    elif any(key in record for key in ('$schema', 'compilerOptions', 'dependencies', 'devDependencies', 'package', 'rustc', 'target', 'files')):
                        candidate_kinds.add('configuration-or-dependency')
                    else:
                        candidate_kinds.add('unrecognized-metadata')
                    continue
                record_identity = _run_identity(record)
                record_status = _run_status(record)
                run_evidence.append({'source_file': str(file_path), 'record_id': record_identity or record.get('testIdentifier'), 'evidence': '运行身份/状态与计数或产物结构'})
                if file_path.name.casefold() in {'manifest.json', 'run.json', 'metadata.json'}:
                    for field in ('run_directory', 'run_dir', 'batch_directory'):
                        raw = record.get(field)
                        if isinstance(raw, str):
                            if '\x00' in raw:
                                parse_gaps.append({'path': str(file_path), 'source_file': str(file_path), 'field': field, 'phase': 'test-reference', 'code': 'invalid-run-boundary', 'reason': '批次边界含 NUL'})
                                continue
                            boundary = Path(raw).expanduser()
                            if not boundary.is_absolute():
                                boundary = file_path.parent / boundary
                            run_boundaries.append({'path': os.path.abspath(boundary), 'source_file': str(file_path), 'field': field})
                identity = record_identity
                if identity:
                    run_identities.add(identity)
                    counts = run_counts.setdefault((str(file_path), identity), {'expected': None, 'completed': None})
                    for key in ('expected', 'expected_count', 'expectedCount', 'total', 'total_count', 'totalCount', 'planned'):
                        if _run_count(record.get(key)):
                            counts['expected'] = record[key]
                    for key in ('completed', 'completed_count', 'completedCount', 'done_count', 'doneCount', 'finished'):
                        if _run_count(record.get(key)):
                            counts['completed'] = record[key]
                status_records += 1
                if record_status is not None:
                    statuses.append(record_status)
                    if identity:
                        ordered_events[(str(file_path), identity)].append(record_status)
                    else:
                        unordered_statuses.append(record_status)
                for key in ("expected", "expected_count", "expectedCount", "total", "total_count", "totalCount", "planned"):
                    if _run_count(record.get(key)):
                        expected_count = max(expected_count or 0, int(record[key]))
                for key in ("completed", "completed_count", "completedCount", "done_count", "doneCount", "finished"):
                    if _run_count(record.get(key)):
                        completed_count = max(completed_count or 0, int(record[key]))
                provenance = {**record.get('_storage_location', {}), 'record_id': identity or record.get('testIdentifier')}
                _record_references(record, file_path.parent, references, artifact_roles, project_paths,
                                   gaps=parse_gaps, provenance=provenance)
            if file_path.name.casefold() in TEST_SIGNAL_NAMES or "report" in file_path.name.casefold() or "result" in file_path.name.casefold():
                report_files.append(str(file_path))
        elif suffix in {".log", ".txt", ".out"}:
            try:
                if file_size > 10_000_000:
                    with file_path.open("rb") as stream:
                        stream.seek(max(file_size - 200_000, 0))
                        text = stream.read().decode("utf-8", errors="replace")
                else:
                    text = file_path.read_text(encoding="utf-8", errors="replace")
                # Logs are members, not independent proof of run identity or completion.
                candidate_kinds.add('unrecognized-log')
            except (OSError, ValueError) as error:
                parse_gaps.append({"path": str(file_path), "reason": str(error), "phase": "test-log"})

    if metadata_paths is None and log_paths is None:
        try:
            for current, dirs, files in os.walk(root, followlinks=False):
                dirs[:] = [name for name in dirs if not (Path(current) / name).is_symlink()]
                for name in files:
                    process_file(Path(current) / name)
        except OSError as error:
            parse_gaps.append({"path": str(root), "reason": str(error), "phase": "test-walk"})
    else:
        direct_paths = sorted({Path(item) for item in (metadata_paths or ())} | {Path(item) for item in (log_paths or ())}, key=str)
        for file_path in direct_paths:
            process_file(file_path)

    # Ordering is only reliable within one file and one explicit identity.
    effective_statuses = list(unordered_statuses)
    effective_statuses.extend(values[-1] for values in ordered_events.values() if values)
    normalized_statuses = set(effective_statuses)
    count_conflict = len({(row['expected'], row['completed']) for row in run_counts.values()}) > 1
    if len(run_counts) == 1:
        last_counts = next(iter(run_counts.values()))
        expected_count, completed_count = last_counts['expected'], last_counts['completed']
    elif len(run_identities) > 1 or count_conflict:
        expected_count = completed_count = None
    active = bool(normalized_statuses & {"running", "starting", "in_progress", "in-progress", "pending"})
    failed = bool(normalized_statuses & {"failed", "error", "blocked", "partial"})
    complete = bool(normalized_statuses & {"completed", "complete", "done", "success", "succeeded", "finished"})
    if expected_count is not None and completed_count is not None and completed_count < expected_count:
        active = True
    if active:
        completion = "incomplete"
    elif failed:
        completion = "failed-or-partial"
    elif complete:
        completion = "completed"
    else:
        completion = "unknown"
    if any(gap.get('severity', 'error') == 'error' for gap in parse_gaps):
        completion = 'partial' if run_evidence else 'unknown'
    terminal_conflict = any(
        bool(set(values) & {'completed', 'complete', 'done', 'success', 'succeeded', 'finished'})
        and bool(set(values) & {'failed', 'error', 'blocked'})
        for values in ordered_events.values())
    impossible_counts = expected_count is not None and completed_count is not None and (completed_count > expected_count or completed_count < 0 or expected_count < 0)
    unknown_statuses = normalized_statuses - {'running', 'starting', 'in_progress', 'in-progress', 'pending', 'failed', 'error', 'blocked', 'partial', 'completed', 'complete', 'done', 'success', 'succeeded', 'finished'}
    ambiguous_records = any(gap.get('code') == 'ambiguous-run-record' for gap in parse_gaps)
    if (terminal_conflict or len(run_identities) > 1 or count_conflict or impossible_counts or
            ambiguous_records or (completion == 'completed' and
            (unknown_statuses or (expected_count is not None and completed_count is None)))):
        completion = 'unknown'
        parse_gaps.append({'path': str(root), 'phase': 'test-status', 'code': 'ambiguous-completion',
                           'reason': '混合运行身份、终态/计数矛盾或缺少完成计数，不能确认完成'})
    symlink_references: list[str] = []
    if symlink_paths is not None:
        for raw_path in symlink_paths:
            try:
                link = safe_local_link(Path(raw_path), scope or root, ((scope or root) / "Library" / "Mobile Documents", (scope or root) / "Library" / "CloudStorage"))
                if link["resolved_target"] is None:
                    parse_gaps.append({"path": str(raw_path), "reason": "链接目标未安全解析", "phase": "test-link"})
                else:
                    symlink_references.append(link["resolved_target"])
            except (OSError, ValueError) as error:
                parse_gaps.append({"path": str(raw_path), "reason": str(error), "phase": "test-link"})
    else:
        try:
            for current, dirs, files in os.walk(root, followlinks=False):
                for name in dirs + files:
                    item = Path(current) / name
                    if item.is_symlink():
                        try:
                            link = safe_local_link(item, scope or root, ((scope or root) / "Library" / "Mobile Documents", (scope or root) / "Library" / "CloudStorage"))
                            if link["resolved_target"] is None:
                                parse_gaps.append({"path": str(item), "reason": "链接目标未安全解析", "phase": "test-link"})
                            else:
                                symlink_references.append(link["resolved_target"])
                        except OSError as error:
                            parse_gaps.append({"path": str(item), "reason": str(error), "phase": "test-link"})
        except OSError as error:
            parse_gaps.append({"path": str(root), "reason": str(error), "phase": "test-link"})
    references = sorted(set(references + symlink_references))
    roles = {key: sorted(set(values)) for key, values in artifact_roles.items()}
    role_totals: dict[str, dict[str, Any]] = {}
    for role, role_paths in roles.items():
        seen_ids: set[str] = set()
        logical = 0
        allocated_values: list[int] = []
        allocation_unknown = False
        missing: list[str] = []
        unmeasured: list[str] = []
        external: list[str] = []
        for raw_path in role_paths:
            item_path = Path(raw_path)
            if scope is not None and local_path_status(item_path, scope, (scope / "Library" / "Mobile Documents", scope / "Library" / "CloudStorage")) is None:
                external.append(raw_path)
                continue
            stat_result = _safe_stat(item_path)
            if not stat_result or item_path.is_symlink():
                missing.append(raw_path)
                continue
            file_id = _file_id(stat_result)
            if file_id in seen_ids:
                continue
            seen_ids.add(file_id)
            if item_path.is_dir():
                unmeasured.append(raw_path)
                continue
            logical += int(stat_result.st_size)
            allocated = _allocated_bytes(stat_result)
            if allocated is None:
                allocation_unknown = True
            else:
                allocated_values.append(allocated)
        measurement_unknown = bool(missing or unmeasured or external or any(gap.get('role') == role for gap in parse_gaps))
        allocated_total = None if allocation_unknown or measurement_unknown else sum(allocated_values)
        logical_total = None if measurement_unknown else logical
        role_totals[role] = {
            "logical_bytes": logical_total, "logical_size": human_bytes(logical_total), 'measured_logical_lower_bound': logical,
            "allocated_bytes": allocated_total, "allocated_size": human_bytes(allocated_total),
            "missing_paths": sorted(set(missing)),
            'unmeasured_paths': unmeasured, 'external_paths': external,
        }
    return {
        "path": str(root), "completion_status": completion, "status_evidence": sorted(normalized_statuses), "status_record_count": status_records,
        "expected_count": expected_count, "completed_count": completed_count, "report_files": sorted(set(report_files)), "metadata_files": sorted(set(metadata_files)),
        'run_identity_counts': [{'source_file': key[0], 'record_id': key[1], **value} for key, value in run_counts.items()],
        'run_ids': sorted(run_identities), 'run_boundaries': run_boundaries,
        "references": references, "project_paths": sorted(set(project_paths)), "artifact_roles": roles, "artifact_role_totals": role_totals, "dependency_count": len(references), "parse_gaps": parse_gaps,
        "content_profile": _directory_names(root), "has_evidence": bool(run_evidence),
        'run_evidence': run_evidence, 'candidate_kinds': sorted(candidate_kinds),
        'discovery_only': True, "trash_paths": [],
    }


def _directory_names(root: Path) -> list[str]:
    try:
        return sorted(item.name for item in root.iterdir())
    except OSError:
        return []


def discover_test_runs(
    home: str | Path,
    project_roots: list[dict[str, Any]],
    large_files: list[dict[str, Any]],
    all_files: list[dict[str, Any]] | None = None,
    symlinks: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Locate test batches from metadata/content, not a name-only allowlist."""
    home = Path(home).expanduser().absolute()
    candidates: set[Path] = set()
    signaled_directory_checks: set[str] = set()
    direct_names_by_directory: dict[Path, set[str]] = defaultdict(set)
    metadata_paths_by_directory: dict[Path, list[Path]] = defaultdict(list)
    log_paths_by_directory: dict[Path, list[Path]] = defaultdict(list)
    symlink_paths_by_directory: dict[Path, list[Path]] = defaultdict(list)
    for item in all_files or large_files:
        file_path = Path(item["path"])
        direct_names_by_directory[file_path.parent].add(file_path.name.casefold())
        if file_path.suffix.casefold() in {".json", ".jsonl", ".ndjson"}:
            metadata_paths_by_directory[file_path.parent].append(file_path)
        elif file_path.suffix.casefold() in {".log", ".txt", ".out"}:
            log_paths_by_directory[file_path.parent].append(file_path)
    for item in symlinks or []:
        link_path = Path(item["path"])
        symlink_paths_by_directory[link_path.parent].append(link_path)

    def add_if_signaled(directory: Path, names: Iterable[str] | None = None) -> None:
        directory_key = str(directory)
        if directory_key in signaled_directory_checks:
            return
        try:
            direct_names = {str(name).casefold() for name in (names if names is not None else ())}
            has_metadata = bool(direct_names & TEST_SIGNAL_NAMES) or any(
                any(token in name for token in ("run", "test", "result", "report", "state", "status", "manifest"))
                and Path(name).suffix.casefold() in {".json", ".jsonl", ".ndjson", ".log", ".txt"}
                for name in direct_names
            )
            # Directory names are only routing hints for the walk.  They do
            # not create a test-run profile without manifest/state/result
            # evidence inside the directory.
            if not has_metadata:
                return
            signaled_directory_checks.add(directory_key)
            if _safe_is_dir(directory) and not directory.is_symlink() and _same_or_below(directory, home):
                candidates.add(directory)
        except (OSError, ValueError):
            return

    # A directory can only be signaled by its own direct metadata names.
    # Ancestors with such files already occur in this index; empty ancestors
    # cannot gain evidence by being revisited for every descendant file.
    for directory, names in direct_names_by_directory.items():
        add_if_signaled(directory, names)
    if all_files is None:
        for root_record in project_roots:
            root = Path(root_record["path"])
            if not _safe_is_dir(root):
                continue
            try:
                for current, dirs, files in os.walk(root, followlinks=False):
                    dirs[:] = [name for name in dirs if name not in {".git", "node_modules", ".build", ".venv"}]
                    current_path = Path(current)
                    if any(Path(name).suffix.casefold() in {".json", ".jsonl", ".ndjson", ".log", ".txt"} for name in files):
                        add_if_signaled(current_path, files)
            except OSError:
                continue

    ordered = sorted(candidates, key=lambda item: len(item.parts), reverse=True)
    profiles: list[dict[str, Any]] = []
    other_candidates: list[dict[str, Any]] = []
    for candidate in ordered:
        if all_files is None:
            profile = profile_test_run(candidate, scope_home=home)
            try:
                direct_metadata = any(
                    item.is_file() and (item.suffix.casefold() in {".json", ".jsonl", ".ndjson", ".log", ".txt"})
                    for item in candidate.iterdir()
                )
            except (OSError, ValueError):
                direct_metadata = False
        else:
            metadata_paths = metadata_paths_by_directory.get(candidate, [])
            log_paths = log_paths_by_directory.get(candidate, [])
            profile = profile_test_run(
                candidate,
                metadata_paths=metadata_paths,
                log_paths=log_paths,
                symlink_paths=symlink_paths_by_directory.get(candidate, []),
                scope_home=home,
            )
            direct_metadata = bool(metadata_paths or log_paths)
        if not profile.get("has_evidence"):
            kinds = profile.get('candidate_kinds', [])
            profile['classification'] = kinds[0] if len(kinds) == 1 else 'mixed-or-unrecognized-metadata'
            other_candidates.append(profile)
            continue
        if candidate == home and not profile.get('run_boundaries'):
            profile['classification'] = 'unresolved-run-boundary'
            profile['parse_gaps'].append({'path': str(candidate), 'phase': 'test-metadata', 'code': 'home-run-boundary', 'reason': '主目录散落记录不能建立主目录测试批次'})
            other_candidates.append(profile)
            continue
        declared = {row['path'] for row in profile.get('run_boundaries', [])}
        if declared:
            boundary = Path(next(iter(declared)))
            if len(declared) == 1 and _same_or_below(boundary, home) and boundary != home and _safe_is_dir(boundary) and not boundary.is_symlink():
                profile['metadata_root'] = profile['path']
                profile['path'] = str(boundary)
                if boundary not in candidates:
                    target = profile_test_run(boundary,
                        metadata_paths=metadata_paths_by_directory.get(boundary, []),
                        log_paths=log_paths_by_directory.get(boundary, []),
                        symlink_paths=symlink_paths_by_directory.get(boundary, []), scope_home=home) if all_files is not None else profile_test_run(boundary, scope_home=home)
                    if target.get('has_evidence') or target.get('parse_gaps'):
                        target['path'] = str(boundary)
                        profiles.append(target)
            else:
                profile['completion_status'] = 'unknown'
                profile['parse_gaps'].append({'path': str(candidate), 'phase': 'test-reference', 'code': 'unresolved-run-boundary', 'reason': '声明的批次边界冲突、不可用、越界或过宽'})
        if not direct_metadata and any(_same_or_below(Path(other["path"]), candidate) for other in profiles):
            continue
        explicit_paths = [reference for reference in profile.get("project_paths", []) if _same_or_below(Path(reference), home)]
        association = associate_project(profile['path'], project_roots, explicit_paths, scope_home=home)
        profile.update({
            "project_key": association.get("project_key"), "source_root": association.get("source_root"), "source_evidence": association.get("evidence"),
            "project_confidence": association.get("confidence"), "codex_source_evidence": association.get("codex_source_evidence"), "codex_related": association.get("codex_related", False),
            "association_candidates": association.get("association_candidates", []), "trash_paths": [],
        })
        profiles.append(profile)
    discover_test_runs.last_candidates = other_candidates  # type: ignore[attr-defined]
    by_boundary: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for profile in profiles:
        by_boundary[profile['path']].append(profile)
    profiles = []
    for path, group in by_boundary.items():
        base = group[0]
        if len(group) > 1:
            boundary_profiles = [{key: item.get(key) for key in ('metadata_root', 'path', 'completion_status')} for item in group]
            for key in ('references', 'project_paths', 'metadata_files', 'report_files', 'status_evidence', 'run_ids'):
                base[key] = sorted({value for item in group for value in item.get(key, [])})
            base['metadata_roots'] = sorted({item.get('metadata_root', item['path']) for item in group})
            base['parse_gaps'] = [gap for item in group for gap in item.get('parse_gaps', [])]
            base['run_evidence'] = [evidence for item in group for evidence in item.get('run_evidence', [])]
            base['run_identity_counts'] = [row for item in group for row in item.get('run_identity_counts', [])]
            base['has_evidence'] = any(item.get('has_evidence') for item in group)
            base['artifact_roles'] = {role: sorted({value for item in group for value in item.get('artifact_roles', {}).get(role, [])}) for role in base['artifact_roles']}
            base['artifact_role_totals'] = {role: {'logical_bytes': None, 'allocated_bytes': None, 'logical_size': '未读取', 'allocated_size': '未读取', 'reason': '多来源合并后不累加可能重叠的引用占用'} for role in base['artifact_roles']}
            base['dependency_count'] = len(base['references'])
            completions = {item['completion_status'] for item in group}
            counts = {(item.get('expected_count'), item.get('completed_count')) for item in group}
            if len(completions) > 1 or len(base['run_ids']) > 1 or len(counts) > 1:
                base['completion_status'] = 'partial'
                base['expected_count'] = base['completed_count'] = None
                base['parse_gaps'].append({'path': path, 'phase': 'test-status', 'code': 'boundary-status-conflict', 'reason': '同一声明批次的多来源状态/身份/计数不一致，不能确认完成'})
            base['boundary_profiles'] = boundary_profiles
        profiles.append(base)
    # Explicit descendant artifact references establish membership, not a new
    # interchangeable batch. A distinct run identity always remains separate.
    members: set[int] = set()
    for child in profiles:
        child_path = Path(child['path'])
        for parent in profiles:
            parent_path = Path(parent['path'])
            if child is parent or child_path == parent_path or not _same_or_below(child_path, parent_path):
                continue
            if child.get('run_ids') and not set(child['run_ids']).issubset(parent.get('run_ids', [])):
                continue
            if not any(_same_or_below(Path(reference), child_path) for reference in parent.get('references', [])):
                continue
            parent.setdefault('member_profiles', []).append(child)
            parent['parse_gaps'].extend(child.get('parse_gaps', []))
            parent['references'] = sorted(set(parent['references']) | set(child.get('references', [])))
            parent['dependency_count'] = len(parent['references'])
            parent['artifact_roles'] = {role: sorted(set(values) | set(child.get('artifact_roles', {}).get(role, []))) for role, values in parent['artifact_roles'].items()}
            parent['artifact_role_totals'] = {role: {'logical_bytes': None, 'allocated_bytes': None, 'logical_size': '未读取', 'allocated_size': '未读取', 'reason': '成员引用存在重叠，不累加为已测量占用'} for role in parent['artifact_roles']}
            if child.get('completion_status') != 'completed':
                parent['completion_status'] = 'partial'
            members.add(id(child))
            break
    profiles = [profile for profile in profiles if id(profile) not in members]
    # Build the reverse reference graph by walking reference ancestors.  The
    # previous all-pairs containment check multiplied every batch by every
    # other batch and became unbounded on a full home inventory.
    profiles_by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    incoming_by_path: dict[str, set[str]] = defaultdict(set)
    for profile in profiles:
        profiles_by_path[str(profile["path"])].append(profile)
    for other in profiles:
        other_path = str(other["path"])
        for raw_reference in other.get("references", []):
            try:
                reference = Path(raw_reference)
            except (OSError, ValueError):
                continue
            for ancestor in (reference, *reference.parents):
                targets = profiles_by_path.get(str(ancestor), ())
                for target in targets:
                    if target is not other:
                        incoming_by_path[str(target["path"])].add(other_path)
    for profile in profiles:
        profile["referenced_by"] = sorted(incoming_by_path.get(str(profile["path"]), set()))
        profile["dependency_edges"] = [{"from": profile["path"], "to": reference, "exists": _safe_exists(Path(reference))} for reference in profile.get("references", [])]
    return sorted(profiles, key=lambda item: item["path"])


def _regex_disk_references(text: str) -> list[str]:
    pattern = re.compile(r"(?:parentFileNameHint|parentFileName|fileName|filename|backing_file|backing-file|disk|image|source|path|file)\s*(?:=|:)\s*[\"']?([^\"'\r\n,;]+)")
    values: list[str] = []
    for match in pattern.finditer(text):
        raw = match.group(1).strip().strip("[]")
        if raw and not raw.startswith(("http://", "https://")):
            values.append(raw.replace("\\", os.sep))
    return values


def _parse_reference_values(path: Path) -> tuple[list[str], list[str]]:
    """Parse only config/descriptor metadata and return references plus gaps."""
    references: list[str] = []
    gaps: list[str] = []
    suffix = path.suffix.casefold()
    name = path.name.casefold()
    try:
        size = path.stat().st_size
        if suffix in {".plist", ".vbox", ".xml"} or name.endswith(".vbox"):
            data = path.read_bytes()
            if len(data) > 8_000_000:
                return references, ["配置文件超过 8 MB，未解析"]
            try:
                value = plistlib.loads(data)
                hints: list[dict[str, str]] = []
                _path_hints(value, hints)
                references.extend(item["path"] for item in hints)
            except (ValueError, plistlib.InvalidFileException):
                references.extend(_regex_disk_references(data.decode("utf-8", errors="replace")))
        elif suffix in {".json", ".utm", ".pvs"} and size <= 8_000_000:
            value = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            hints = []
            _path_hints(value, hints)
            references.extend(item["path"] for item in hints)
        elif suffix in {".vmx", ".vmdk", ".vbox", ".xml", ".utm", ".pvs"} and size <= 8_000_000:
            references.extend(_regex_disk_references(path.read_text(encoding="utf-8", errors="replace")))
        elif size > 8_000_000:
            gaps.append("元数据文件超过 8 MB，未解析")
    except (OSError, ValueError, json.JSONDecodeError, UnicodeError) as error:
        gaps.append(str(error))
    resolved: list[str] = []
    for raw in references:
        if "\x00" in raw:
            gaps.append("引用路径含嵌入 NUL 字节，未解析")
            continue
        value = Path(raw).expanduser()
        if not value.is_absolute():
            value = path.parent / value
        resolved.append(str(value.absolute()))
    return sorted(set(resolved)), gaps


def _qcow_backing_reference(path: Path) -> tuple[list[str], list[str]]:
    try:
        with path.open("rb") as stream:
            header = stream.read(104)
        if not header.startswith(b"QFI\xfb") or len(header) < 32:
            return [], []
        offset = int.from_bytes(header[8:16], "big")
        length = int.from_bytes(header[16:20], "big")
        if length <= 0 or length > 4096:
            return [], ["QCOW backing 文件名长度不支持"]
        with path.open("rb") as stream:
            stream.seek(offset)
            raw = stream.read(length)
        return [raw.decode("utf-8", errors="replace").rstrip("\x00")], []
    except OSError as error:
        return [], [str(error)]


def _vm_signature(path: Path) -> tuple[bool, str]:
    suffix = path.suffix.casefold()
    header, tail, error = _read_signatures(path)
    if error:
        return False, f"镜像头读取失败：{error}"
    if header.startswith(b"QFI\xfb"):
        return True, "QCOW 文件头"
    if header.startswith(b"KDMV"):
        return True, "VMDK 稀疏文件头"
    if header.startswith(b"vhdxfile"):
        return True, "VHDX 文件头"
    if tail.startswith(b"conectix"):
        return True, "VHD 尾部签名"
    if suffix in VM_FILE_SUFFIXES:
        return True, f"明确镜像扩展名 {suffix}"
    if _raw_disk_evidence(path):
        return True, "RAW 扩展名与虚拟机/容器路径证据"
    if suffix in AMBIGUOUS_IMAGE_SUFFIXES and (_is_container_path(path) or any(token in str(path).casefold() for token in (".pvm/", ".utm/", ".vmwarevm/"))):
        return True, "容器/虚拟机包路径与镜像扩展名"
    return False, "没有文件头、配置或虚拟机包证据"


def _probe_mounted_images() -> tuple[set[str], list[dict[str, Any]]]:
    mounted: set[str] = set()
    gaps: list[dict[str, Any]] = []
    if os.sys.platform == "darwin":
        try:
            result = bounded_process.run(["hdiutil", "info", "-plist"], capture_output=True, text=False, timeout=8)
            if result.returncode == 0:
                raw_stdout = result.stdout.encode() if isinstance(result.stdout, str) else result.stdout
                value = plistlib.loads(raw_stdout)
                def walk(node: Any) -> None:
                    if isinstance(node, dict):
                        for key, child in node.items():
                            if key.casefold() in {"image-path", "imagepath"} and isinstance(child, str):
                                mounted.add(os.path.abspath(child))
                            walk(child)
                    elif isinstance(node, list):
                        for child in node:
                            walk(child)
                walk(value)
            else:
                stderr = result.stderr.decode('utf-8', errors='replace') if isinstance(result.stderr, bytes) else result.stderr
                gaps.append({"path": "hdiutil", "reason": (stderr or "无法读取镜像挂载信息")[:240], "phase": "vm-mount"})
        except (OSError, subprocess.SubprocessError, plistlib.InvalidFileException) as error:
            gaps.append({"path": "hdiutil", "reason": str(error), "phase": "vm-mount"})
    else:
        gaps.append({"path": "镜像挂载状态", "reason": "当前平台没有 hdiutil 适配；状态未知", "phase": "vm-mount"})
    return mounted, gaps


def _probe_open_path(path: Path) -> tuple[str, str]:
    lsof = shutil.which("lsof")
    if not lsof:
        return "unknown", "没有 lsof，无法检查打开句柄"
    try:
        result = bounded_process.run([lsof, "-nP", "-F", "n", "--", str(path)], capture_output=True, text=True, timeout=8)
        if result.returncode == 0 and any(line.startswith("n") for line in result.stdout.splitlines()):
            return "active", "lsof 发现打开句柄"
        if result.returncode in (1, 2) and not result.stderr.strip():
            return "not-detected", "未发现精确路径打开句柄"
        return "unknown", (result.stderr or "打开句柄检查不完整")[:240]
    except (OSError, subprocess.SubprocessError) as error:
        return "unknown", str(error)


def _probe_open_paths(paths: Iterable[Path]) -> tuple[dict[str, tuple[str, str]], list[dict[str, Any]]]:
    """Probe open handles once for a candidate set instead of spawning lsof per path."""
    normalized = sorted({str(path) for path in paths})
    lsof = shutil.which("lsof")
    if not lsof:
        reason = "没有 lsof，无法检查打开句柄"
        return {path: ("unknown", reason) for path in normalized}, [{"path": "lsof", "reason": reason, "phase": "vm-open-handle"}]
    try:
        result = bounded_process.run([lsof, "-nP", "-F", "n"], capture_output=True, text=True, timeout=15)
        opened = {os.path.abspath(line[1:]) for line in result.stdout.splitlines() if line.startswith("n") and len(line) > 1}
        if result.returncode not in (0, 1, 2) and not opened:
            raise OSError(result.stderr or "lsof 失败")
        statuses: dict[str, tuple[str, str]] = {}
        for path in normalized:
            statuses[path] = ("active", "批量 lsof 发现打开句柄") if os.path.abspath(path) in opened else ("unknown", "未解析链接别名，打开句柄状态未知")
        gaps: list[dict[str, Any]] = []
        if result.returncode not in (0, 1) or result.stderr.strip():
            gaps.append({"path": "lsof", "reason": (result.stderr or "打开句柄检查不完整")[:240], "phase": "vm-open-handle"})
            for path, (status, _) in list(statuses.items()):
                if status != 'active':
                    statuses[path] = ('unknown', 'lsof 检查不完整，不能排除占用')
        return statuses, gaps
    except (OSError, subprocess.SubprocessError) as error:
        reason = str(error)
        return {path: ("unknown", reason) for path in normalized}, [{"path": "lsof", "reason": reason, "phase": "vm-open-handle"}]


def _probe_processes(paths: Iterable[Path]) -> tuple[dict[str, str], list[dict[str, Any]]]:
    status: dict[str, str] = {}
    gaps: list[dict[str, Any]] = []
    try:
        result = bounded_process.run(["ps", "-axo", "command="], capture_output=True, text=True, timeout=8)
        if result.returncode != 0:
            raise OSError(result.stderr or "ps 失败")
        commands = result.stdout.casefold()
        for path in paths:
            token = str(path).casefold()
            status[str(path)] = "active" if token in commands else "not-detected"
    except (OSError, subprocess.SubprocessError) as error:
        gaps.append({"path": "ps", "reason": str(error), "phase": "vm-process"})
        for path in paths:
            status[str(path)] = "unknown"
    return status, gaps


def discover_virtual_machines(home: str | Path, file_records: list[dict[str, Any]]) -> dict[str, Any]:
    """Identify VM/container evidence and dependencies without touching images."""
    home = Path(home).expanduser().absolute()
    candidates: dict[str, dict[str, Any]] = {}
    package_paths: set[Path] = set()
    gaps: list[dict[str, Any]] = []

    def add_file(record: dict[str, Any], evidence: str) -> None:
        path = Path(record["path"])
        key = str(path)
        if key not in candidates:
            candidates[key] = {**record, "path": key, "vm_evidence": evidence, "open_status": "unknown", "mounted": "unknown", "trash_paths": []}

    for record in file_records:
        path = Path(record["path"])
        inventory_kind = record.get("kind")
        if inventory_kind in {"virtual-machine-disk", "container-disk"}:
            is_vm, evidence = True, f"统一文件清单类型：{inventory_kind}"
        elif inventory_kind is None:
            is_vm, evidence = _vm_signature(path)
        else:
            is_vm, evidence = False, "统一文件清单未识别为虚拟机磁盘"
        if is_vm:
            add_file(record, evidence)
        for ancestor in path.parents:
            if ancestor.suffix.casefold() in VM_DIR_SUFFIXES:
                package_paths.add(ancestor)
                break

    def package_metadata(package: Path) -> dict[str, Any]:
        members = [record for record in file_records if _same_or_below(Path(record["path"]), package)]
        config_files: list[str] = []
        references: list[str] = []
        parse_gaps: list[dict[str, Any]] = []
        snapshots: list[str] = []
        seen_ids: set[str] = set()
        unique_members: list[dict[str, Any]] = []
        for record in members:
            file_id = str(record.get("file_id"))
            if file_id not in seen_ids:
                seen_ids.add(file_id)
                unique_members.append(record)
            child = Path(record["path"])
            lower = child.name.casefold()
            if child.suffix.casefold() in VM_CONFIG_SUFFIXES or child.suffix.casefold() in VM_FILE_SUFFIXES or any(token in lower for token in ("snapshot", "delta", "parent", "descriptor")):
                if child.suffix.casefold() in VM_CONFIG_SUFFIXES or "snapshot" in lower or "delta" in lower or "parent" in lower:
                    config_files.append(str(child))
                refs, ref_gaps = _parse_reference_values(child)
                if child.suffix.casefold() == ".qcow2":
                    qcow_refs, qcow_gaps = _qcow_backing_reference(child)
                    refs.extend(qcow_refs)
                    ref_gaps.extend(qcow_gaps)
                references.extend(refs)
                parse_gaps.extend({"path": str(child), "reason": reason, "phase": "vm-dependency"} for reason in ref_gaps)
                if any(token in lower for token in ("snapshot", "delta", "parent")):
                    snapshots.append(str(child))
        resolved: list[str] = []
        missing: list[str] = []
        external: list[str] = []
        for raw in sorted(set(references)):
            reference = Path(raw).expanduser()
            if not reference.is_absolute():
                reference = package / reference
            reference = reference.absolute()
            status = local_path_status(reference, home, (home / "Library" / "Mobile Documents", home / "Library" / "CloudStorage"))
            if status is None:
                external.append(str(reference))
            elif status:
                resolved.append(str(reference))
            else:
                missing.append(str(reference))
        logical = sum(int(record.get("logical_bytes") or 0) for record in unique_members)
        allocation_values = [record.get("allocated_bytes") for record in unique_members]
        allocation_known = all(value is not None for value in allocation_values)
        allocated = sum(int(value) for value in allocation_values if value is not None) if allocation_known else None
        return {
            "member_paths": sorted(record["path"] for record in members), "member_count": len(members),
            "logical_bytes": logical, "logical_size": human_bytes(logical), "allocated_bytes": allocated, "allocated_size": human_bytes(allocated),
            "config_files": sorted(set(config_files)), "dependency_paths": sorted(set(resolved)), "missing_dependency_paths": sorted(set(missing)),
            "external_dependency_paths": sorted(set(external)), "snapshot_metadata": sorted(set(snapshots)), "dependency_gaps": parse_gaps,
        }

    for package in sorted(package_paths):
        metadata = package_metadata(package)
        candidates[str(package)] = {"path": str(package), "name": package.name, "kind": "virtual-machine-package", "vm_evidence": "虚拟机包成员清单与包后缀", "trash_paths": [], "open_status": "unknown", "mounted": "unknown", **metadata}
        gaps.extend(metadata.get("dependency_gaps", []))

    def resolve_references(base: Path, raw_references: Iterable[str]) -> tuple[list[str], list[str], list[str]]:
        resolved: list[str] = []
        missing: list[str] = []
        external: list[str] = []
        for raw in sorted(set(raw_references)):
            reference = Path(raw).expanduser()
            if not reference.is_absolute():
                reference = base.parent / reference
            reference = reference.absolute()
            status = local_path_status(reference, home, (home / "Library" / "Mobile Documents", home / "Library" / "CloudStorage"))
            if status is None:
                external.append(str(reference))
            elif status:
                resolved.append(str(reference))
            else:
                missing.append(str(reference))
        return sorted(set(resolved)), sorted(set(missing)), sorted(set(external))

    # Standalone descriptor disks can carry parent/backing references too;
    # parse those independently from package metadata.
    for path, item in list(candidates.items()):
        if item.get("kind") == "virtual-machine-package":
            continue
        disk_path = Path(path)
        refs, ref_gaps = _parse_reference_values(disk_path)
        if disk_path.suffix.casefold() == ".qcow2":
            qcow_refs, qcow_gaps = _qcow_backing_reference(disk_path)
            refs.extend(qcow_refs)
            ref_gaps.extend(qcow_gaps)
        resolved, missing, external = resolve_references(disk_path, refs)
        item["config_files"] = [str(disk_path)] if refs or ref_gaps else []
        item["dependency_paths"] = resolved
        item["missing_dependency_paths"] = missing
        item["external_dependency_paths"] = external
        item["dependency_gaps"] = [{"path": str(disk_path), "reason": reason, "phase": "vm-dependency"} for reason in ref_gaps]
        if any(token in disk_path.name.casefold() for token in ("snapshot", "delta", "parent")):
            item["snapshot_metadata"] = [str(disk_path)]

    mounted, mount_gaps = _probe_mounted_images()
    gaps.extend(mount_gaps)
    probe_paths = {Path(path) for path in candidates}
    for item in candidates.values():
        probe_paths.update(Path(member) for member in item.get("member_paths", []))
    process_status, process_gaps = _probe_processes(probe_paths)
    gaps.extend(process_gaps)
    open_status, open_gaps = _probe_open_paths(probe_paths)
    gaps.extend(open_gaps)
    for path, item in candidates.items():
        candidate_path = Path(path)
        member_mount = any(os.path.abspath(member) in mounted for member in item.get("member_paths", []))
        item["mounted"] = "yes" if os.path.abspath(path) in mounted or member_mount else "unknown"
        member_open = [open_status.get(member) for member in item.get("member_paths", []) if open_status.get(member)]
        if open_status.get(path, ("unknown", "批量打开句柄检查没有该路径"))[0] == "active" or any(status == "active" for status, _ in member_open):
            item["open_status"], item["open_evidence"] = "active", "批量 lsof 发现虚拟机路径或成员打开句柄"
        elif member_open and any(status == "unknown" for status, _ in member_open):
            item["open_status"], item["open_evidence"] = "unknown", next(evidence for status, evidence in member_open if status == "unknown")
        else:
            item["open_status"], item["open_evidence"] = open_status.get(path, ("unknown", "批量打开句柄检查没有该路径"))
        item["process_status"] = process_status.get(path, "unknown")
        blocked = item["mounted"] in {"yes", "unknown"} or item["open_status"] in {"active", "unknown"} or item.get("process_status") in {"active", "unknown"}
        blocked = blocked or bool(item.get("missing_dependency_paths") or item.get("external_dependency_paths") or item.get("dependency_gaps"))
        item["duplicate_blocked"] = blocked
        item["duplicate_block_reason"] = "运行/挂载/依赖状态未确认" if blocked else "静止且依赖状态可读"
        item["project_key"] = None
        item["source_evidence"] = item.get("vm_evidence", "")
    dependency_graph = {
        path: [dependency for dependency in item.get("dependency_paths", []) if dependency in candidates]
        for path, item in candidates.items()
    }
    dependency_cycles: list[list[str]] = []
    visiting: set[str] = set()
    visited: set[str] = set()
    def visit(node: str, trail: list[str]) -> None:
        if node in visiting:
            cycle = trail[trail.index(node):] + [node] if node in trail else trail + [node]
            if cycle not in dependency_cycles:
                dependency_cycles.append(cycle)
            return
        if node in visited:
            return
        visiting.add(node)
        for child in dependency_graph.get(node, []):
            visit(child, trail + [node])
        visiting.remove(node)
        visited.add(node)
    for node in dependency_graph:
        visit(node, [])
    if dependency_cycles:
        cycle_nodes = {node for cycle in dependency_cycles for node in cycle}
        for node in cycle_nodes:
            candidates[node]["duplicate_blocked"] = True
            candidates[node]["duplicate_block_reason"] = "父盘/差分盘依赖存在循环"
    blocked_paths = {path for path, item in candidates.items() if item.get('duplicate_blocked') and item.get('kind') != 'virtual-machine-package'}
    for package in candidates.values():
        if package.get('kind') == 'virtual-machine-package' and package.get('duplicate_blocked'):
            for member in package.get('member_paths', []):
                blocked_paths.add(member)
                if member in candidates:
                    candidates[member]['duplicate_blocked'] = True
                    candidates[member]['duplicate_block_reason'] = '所在虚拟机包运行/挂载/依赖状态未确认'
    blocked_paths = sorted(blocked_paths)
    return {
        "items": sorted(candidates.values(), key=lambda item: int(item.get("logical_bytes") or 0), reverse=True),
        "tools": {name: bool(shutil.which(name)) for name in ("prlctl", "VBoxManage", "qemu-img", "lsof", "hdiutil")},
        "blocked_duplicate_paths": blocked_paths, "dependency_graph": dependency_graph, "dependency_cycles": dependency_cycles, "gaps": gaps,
        "coverage": "只读文件头、包成员、配置、父/差分盘、快照、挂载、进程和打开句柄检查；未启动、挂载、修复或转换镜像", "trash_paths": [],
    }


def summarize_packages(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return package-level summaries without double-counting child entities."""
    packages: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in files:
        path = Path(item["path"])
        for ancestor in path.parents:
            if ancestor.suffix.casefold() in VM_DIR_SUFFIXES:
                packages[str(ancestor)].append(item)
                break
    result = []
    for path, members in packages.items():
        seen: set[str] = set()
        unique = []
        for item in members:
            file_id = str(item.get("file_id"))
            if file_id not in seen:
                seen.add(file_id)
                unique.append(item)
        logical = sum(int(item.get("logical_bytes") or 0) for item in unique)
        values = [item.get("allocated_bytes") for item in unique]
        allocated = sum(int(value) for value in values if value is not None) if all(value is not None for value in values) else None
        result.append({"path": path, "member_count": len(members), "logical_bytes": logical, "logical_size": human_bytes(logical), "allocated_bytes": allocated, "allocated_size": human_bytes(allocated), "kind": "package", "trash_paths": []})
    return sorted(result, key=lambda item: item["logical_bytes"], reverse=True)


discover_project_roots.last_issues = []  # type: ignore[attr-defined]
