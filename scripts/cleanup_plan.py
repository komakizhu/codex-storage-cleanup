"""Pure cleanup-plan construction over already discovered candidates."""
from __future__ import annotations

from bisect import bisect_left
import os
from pathlib import Path
from typing import Any, Callable

import scan_budget


def _path(value: str | Path) -> Path:
    return Path(value).expanduser().absolute()


def _path_entities(
    row: dict[str, Any],
    file_entities: Callable[[Path, int], list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    eligible = list(row.get("eligible_paths") or [])
    if not eligible:
        return file_entities(_path(row["path"]), int(row.get("size_bytes") or 0))

    entities: list[dict[str, Any]] = []
    for item in eligible:
        entities.extend(file_entities(_path(item), 0))
    if entities and all(entity.get("virtual") for entity in entities):
        declared = int(row.get("eligible_bytes") or 0)
        if declared:
            share, remainder = divmod(declared, len(entities))
            for index, entity in enumerate(entities):
                entity["bytes"] = share + (remainder if index == 0 else 0)
    return entities


def estimate_capacity(
    direct: list[dict[str, Any]],
    backups: list[dict[str, Any]],
    worktrees: list[dict[str, Any]],
    *,
    inventory: list[dict[str, Any]] | None = None,
    known_directories: list[str] | None = None,
    human_bytes: Callable[[int | float | None], str],
    file_entities: Callable[[Path, int], list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Measure plan targets from the current inventory, or a compatibility walk."""
    rows: list[tuple[str, dict[str, Any]]] = []
    rows.extend(("direct-delete", row) for row in direct)
    rows.extend(("backup-then-delete", row) for row in backups)
    rows.extend(("migrate-to-t1", row) for row in worktrees)
    priorities = {"direct-delete": 0, "backup-then-delete": 1, "migrate-to-t1": 2}
    rows.sort(key=lambda pair: (
        priorities[pair[0]],
        -len(_path(pair[1].get("path") or "").parts),
        str(pair[1].get("path") or ""),
    ))

    records_by_path: dict[str, dict[str, Any]] = {}
    for index, record in enumerate(inventory or []):
        if index % 1024 == 0:
            scan_budget.check("清理计划容量索引")
        if not record.get("path"):
            continue
        path = str(_path(record["path"]))
        records_by_path[path] = {
            "identity": str(record.get("identity") or record["path"]),
            "path": path,
            "bytes": int(record.get("bytes") or 0),
            "allocated_bytes": record.get("allocated_bytes"),
            "virtual": False,
            "directory": bool(record.get("directory")),
        }
    scan_budget.check("清理计划容量索引")
    sorted_paths = sorted(records_by_path)
    known_dirs = {str(_path(value)) for value in (known_directories or [])}
    measured_inventory = inventory is not None
    virtual_claims: list[tuple[Path, int]] = []
    buckets = {action: 0 for action, _ in rows}
    counts = {action: 0 for action, _ in rows}
    missing_paths: set[str] = set()

    if measured_inventory:
        target_rows: dict[str, list[int]] = {}
        for row_index, (action, row) in enumerate(rows):
            if row_index % 128 == 0:
                scan_budget.check("清理计划目标索引")
            targets = list(row.get("eligible_paths") or [row.get("path") or ""])
            for target in targets:
                if not target:
                    continue
                target_path = _path(target)
                target_text = str(target_path)
                target_rows.setdefault(target_text, []).append(row_index)
                record = records_by_path.get(target_text)
                if record is not None and not record.get("directory"):
                    continue
                if record and record.get("directory") or target_text in known_dirs:
                    continue
                prefix = target_text.rstrip(os.sep) + os.sep
                child_index = bisect_left(sorted_paths, prefix)
                if (
                    child_index < len(sorted_paths)
                    and sorted_paths[child_index].startswith(prefix)
                ):
                    continue
                missing_paths.add(target_text)

        # Assign every inventory path once. Ancestor lookup selects the first
        # eligible action in the same priority/depth order used by execution.
        best_by_identity: dict[str, tuple[int, str, dict[str, Any]]] = {}
        for index, (path_text, record) in enumerate(records_by_path.items()):
            if index % 1024 == 0:
                scan_budget.check("清理计划容量分摊")
            if record.get("directory"):
                continue
            best_row: int | None = None
            current = Path(path_text)
            while True:
                candidates = target_rows.get(str(current))
                if candidates:
                    candidate = candidates[0]
                    best_row = candidate if best_row is None else min(best_row, candidate)
                parent = current.parent
                if parent == current:
                    break
                current = parent
            if best_row is None:
                continue
            identity = str(record.get("identity") or path_text)
            candidate_key = (best_row, path_text)
            previous = best_by_identity.get(identity)
            if previous is None or candidate_key < (previous[0], previous[1]):
                best_by_identity[identity] = (best_row, path_text, record)

        for index, (row_index, _path_text, entity) in enumerate(best_by_identity.values()):
            if index % 1024 == 0:
                scan_budget.check("清理计划容量汇总")
            action = rows[row_index][0]
            amount = int(entity.get("bytes") or 0)
            if amount > 0:
                buckets[action] += amount
                counts[action] += 1
    else:
        assigned: set[str] = set()
        for index, (action, row) in enumerate(rows):
            if index % 128 == 0:
                scan_budget.check("清理计划容量分摊")
            if file_entities is not None:
                entities = _path_entities(row, file_entities)
            else:
                entities = []
                missing_paths.add(str(row.get("path") or ""))
            for entity_index, entity in enumerate(entities):
                if entity_index % 1024 == 0:
                    scan_budget.check("清理计划容量分摊")
                identity = str(entity.get("identity") or entity.get("path") or "")
                if not identity or identity in assigned:
                    continue
                amount = int(entity.get("bytes") or 0)
                if entity.get("virtual"):
                    path = _path(entity.get("path") or row.get("path") or "")
                    covered = sum(
                        size for claimed, size in virtual_claims
                        if claimed.is_relative_to(path)
                    )
                    amount = max(amount - covered, 0)
                    if amount:
                        virtual_claims.append((path, amount))
                assigned.add(identity)
                if amount > 0:
                    buckets[action] += amount
                    counts[action] += 1

    total = sum(buckets.values())
    return {
        "basis": (
            "复用本次扫描文件清单；同一 device/inode 只计一次；父工作树和内部候选按执行顺序分摊"
            if measured_inventory else
            "测试/兼容调用按精确路径展开文件实体；同一 device/inode 只计一次"
        ),
        "inventory_reused": measured_inventory,
        "unmeasured_paths": sorted(path for path in missing_paths if path),
        "estimated_reclaimable_bytes": total,
        "estimated_reclaimable_size": human_bytes(total),
        "estimated_categories": {
            "direct_delete_bytes": buckets.get("direct-delete", 0),
            "direct_delete_size": human_bytes(buckets.get("direct-delete", 0)),
            "backup_then_delete_bytes": buckets.get("backup-then-delete", 0),
            "backup_then_delete_size": human_bytes(buckets.get("backup-then-delete", 0)),
            "worktree_move_bytes": buckets.get("migrate-to-t1", 0),
            "worktree_move_size": human_bytes(buckets.get("migrate-to-t1", 0)),
        },
        "entity_counts": {
            "direct-delete": counts.get("direct-delete", 0),
            "backup-then-delete": counts.get("backup-then-delete", 0),
            "migrate-to-t1": counts.get("migrate-to-t1", 0),
        },
        "physical_reclaimable": "未知：APFS 克隆、快照和共享空间需执行后实测",
    }


def build_plan(
    data: dict[str, Any],
    home: Path,
    *,
    human_bytes: Callable[[int | float | None], str],
    file_entities: Callable[[Path, int], list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    direct: list[dict[str, Any]] = []
    backups: list[dict[str, Any]] = []
    worktrees: list[dict[str, Any]] = []
    seen_direct: set[str] = set()

    for index, item in enumerate(data.get("items", [])):
        if index % 128 == 0:
            scan_budget.check("清理计划候选归组")
        action = item.get("default_action")
        path = str(item.get("path") or "")
        if action == "direct-delete" and path and path not in seen_direct:
            direct.append({
                key: item.get(key)
                for key in (
                    "path", "size_bytes", "artifact_type", "review_priority", "retained_path",
                    "workspace_root", "source_entries", "source_revision", "rebuild_command",
                    "rebuild_basis", "completed_outputs", "regeneration_evidence", "project_key",
                    "evidence_paths", "retention", "activity", "active", "git_state",
                    "git_status_digest",
                )
            })
            seen_direct.add(path)
        elif action == "backup-then-delete" and (
            item.get("archive_eligible_paths") or item.get("backup_eligible_paths")
        ):
            eligible = list(
                item.get("archive_eligible_paths")
                or item.get("backup_eligible_paths")
                or []
            )
            backups.append({
                "path": path,
                "home": str(home),
                "eligible_paths": eligible,
                "eligible_bytes": int(
                    item.get("archive_eligible_bytes")
                    or item.get("backup_eligible_bytes")
                    or 0
                ),
                "eligible_count": int(
                    item.get("archive_eligible_count")
                    or item.get("backup_eligible_count")
                    or len(eligible)
                ),
                "retention_days": int(
                    item.get("archive_retention_days")
                    or item.get("backup_retention_days")
                    or 7
                ),
                "backup_category": item.get("backup_category") or "codex-archives",
                "retention_evidence": item.get("retention_evidence", {}),
                "review_priority": item.get("review_priority", ""),
            })
        elif action == "migrate-to-t1" and path:
            worktrees.append({
                key: item.get(key)
                for key in (
                    "path", "size_bytes", "git_revision", "git_branch", "git_root", "git_clean",
                    "has_head", "git_status_readable", "active", "current_working_directory",
                    "default_action", "review_priority", "activity_status", "group_status",
                    "backup_required", "finalization_reason", "migration_reason",
                    "association_group_id", "association_group_paths", "association_group",
                    "reference_evidence", "latest_activity_at", "idle_for_hours",
                    "idle_candidate", "migration_blockers", "git_state", "git_status_digest",
                )
            })

    capacity = estimate_capacity(
        direct,
        backups,
        worktrees,
        inventory=data.get("_scan_file_entities"),
        known_directories=data.get("_scan_known_directories"),
        human_bytes=human_bytes,
        file_entities=file_entities,
    )
    return {
        "home": str(home),
        "estimated_reclaimable_bytes": capacity["estimated_reclaimable_bytes"],
        "estimated_reclaimable_size": capacity["estimated_reclaimable_size"],
        "capacity": capacity,
        "worktree_move_bytes": capacity["estimated_categories"]["worktree_move_bytes"],
        "direct_delete": direct,
        "archive_backup_then_delete": backups,
        "backup_then_delete": backups,
        "worktree_migrations": worktrees,
        "policy": {
            "direct_delete": "可再生缓存和源码已核实、每项目保留最新一份的旧构建，不做备份",
            "archive_backup_then_delete": "超过 7 天的归档会话先完整备份并校验，再只删除旧文件",
            "worktree_migrations": "关联组连续超过 168 小时无活动且检查通过后迁到 T1",
        },
    }


def summarize(plan: dict[str, Any]) -> dict[str, Any]:
    capacity = plan.get("capacity") or {}
    return {
        "unmeasured_paths": list(capacity.get("unmeasured_paths") or []),
        "estimated_reclaimable_bytes": int(plan.get("estimated_reclaimable_bytes") or 0),
        "estimated_categories": dict(capacity.get("estimated_categories") or {}),
        "entity_counts": dict(capacity.get("entity_counts") or {}),
    }
