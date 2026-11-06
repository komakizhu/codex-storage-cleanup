"""Move one or more linked worktrees to T1 with a recoverable old entry point."""

from __future__ import annotations

from pathlib import Path
import json
import os
import shutil
import subprocess
import uuid

import scan_codex as scan
import vault


def git(path: Path, *args: str, timeout: int = 60) -> str:
    return subprocess.check_output(
        ["git", "-C", str(path), *args], text=True, stderr=subprocess.PIPE,
        timeout=timeout,
    ).strip()


def _try_git(path: Path, *args: str) -> tuple[bool, str]:
    try:
        return True, git(path, *args)
    except (OSError, subprocess.CalledProcessError):
        return False, ""


def _validate_source(source: Path, expected_revision: str, allow_dirty: bool) -> dict:
    source = source.absolute()
    codex_worktrees = Path.home() / ".codex" / "worktrees"
    project_roots = (
        Path.home() / "Documents" / "ChatGPT",
        Path.home() / "Documents" / "Codex",
    )
    in_codex_worktrees = source.is_relative_to(codex_worktrees) and source != codex_worktrees
    in_project_worktrees = (
        source.parent.name == ".worktrees"
        and any(source.parent.parent.is_relative_to(root) for root in project_roots)
    )
    if not (in_codex_worktrees or in_project_worktrees) or source.resolve() != source:
        raise vault.VaultError("迁移源必须是当前用户 Codex 根或受支持项目中的真实 linked worktree")
    if not (source / ".git").is_file() or (source / ".git").is_symlink():
        raise vault.VaultError("需要 linked worktree；主仓库须另行处理其关联工作树")
    if source.stat().st_uid != os.getuid() or Path.cwd().resolve().is_relative_to(source):
        raise vault.VaultError("当前目录或非当前用户目录不可迁移")
    common = Path(git(source, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    if common.is_relative_to(source):
        raise vault.VaultError("公共 Git 目录不能位于迁移源内")
    registrations = git(source, "worktree", "list", "--porcelain").split("\n\n")
    record = next((record for record in registrations if record.splitlines() and record.splitlines()[0] == f"worktree {source}"), "")
    if not record or any(line.startswith(("locked", "prunable")) for line in record.splitlines()):
        raise vault.VaultError("工作树未登记、已锁定或登记异常")
    if (source / ".gitmodules").exists():
        raise vault.VaultError("含子模块，需要先逐个核对其路径关系")
    has_head, revision = _try_git(source, "rev-parse", "HEAD")
    if expected_revision and (not has_head or revision != expected_revision):
        raise vault.VaultError("提交已变化，需重新扫描")
    status = git(source, "status", "--porcelain", "--untracked-files=all")
    if status and not allow_dirty:
        raise vault.VaultError("工作树包含未提交内容")
    current = Path.cwd().resolve().is_relative_to(source)
    active, note = (True, "当前执行目录仍在 worktree 内") if current else scan.open_handle_status(source)
    if active is not False:
        raise vault.VaultError("工作树仍被使用或句柄状态未知")
    return {
        "source": source,
        "common": common,
        "has_head": has_head,
        "revision": revision,
        "expected_revision": expected_revision,
        "status": status,
        "active_note": note,
    }


def _link_repairs(source: Path, target: Path, mapping: dict[Path, Path]) -> list[dict[str, str]]:
    """Repair relative/absolute links that crossed worktree boundaries."""
    repairs: list[dict[str, str]] = []
    try:
        for current, dirs, files in os.walk(target, followlinks=False):
            current_path = Path(current)
            names = list(dirs) + list(files)
            dirs[:] = [name for name in dirs if not (current_path / name).is_symlink()]
            for name in names:
                link = current_path / name
                if not link.is_symlink():
                    continue
                raw = os.readlink(link)
                # Resolve relative links against the original source layout.
                # Resolving against the T1 copy would incorrectly turn a
                # source-side ``../peer`` link into a T1-local path before
                # we have identified the peer worktree.
                relative_inside = link.relative_to(target)
                original_link = source / relative_inside
                lexical_target = (
                    Path(os.path.abspath(original_link.parent / raw))
                    if not os.path.isabs(raw) else Path(os.path.abspath(raw))
                )
                resolved = lexical_target.resolve()
                peer_source = next((root for root in mapping if resolved == root or resolved.is_relative_to(root)), None)
                if peer_source is not None and peer_source != source:
                    peer_target = mapping[peer_source]
                    relative = resolved.relative_to(peer_source)
                    new_resolved = peer_target / relative
                    new_raw = os.path.relpath(new_resolved, link.parent)
                elif peer_source is None and not os.path.isabs(raw):
                    # Rebase a relative external link so the T1 copy still
                    # addresses the same original location after its parent
                    # tree moves.  Do not follow or rewrite absolute links.
                    new_raw = os.path.relpath(lexical_target, link.parent)
                else:
                    continue
                if new_raw == raw:
                    continue
                link.unlink()
                link.symlink_to(new_raw)
                repairs.append({"path": str(link), "old_target": raw, "new_target": new_raw})
    except (OSError, ValueError) as error:
        raise vault.VaultError(f"工作树引用检查/修复失败：{error}") from error
    return repairs


def _repair_config_references(
    references: list[dict], mapping: dict[Path, Path],
) -> dict[Path, list[dict[str, str]]]:
    """Rewrite supported cross-worktree path literals in copied config files."""
    repairs_by_source: dict[Path, list[dict[str, str]]] = {source: [] for source in mapping}
    seen: set[tuple[str, str, str]] = set()
    for reference in references:
        if reference.get("kind") != "configuration-or-task-reference":
            continue
        source_file_text = reference.get("source_file") or reference.get("source")
        target_text = reference.get("target")
        if not source_file_text or not target_text:
            raise vault.VaultError("配置/任务引用缺少引用方或被引用方，不能安全搬移")
        source_file = Path(str(source_file_text)).expanduser().absolute()
        target_path = Path(str(target_text)).expanduser().absolute()
        source_root = next((root for root in mapping if source_file == root or source_file.is_relative_to(root)), None)
        target_root = next((root for root in mapping if target_path == root or target_path.is_relative_to(root)), None)
        if source_root is None:
            # Inbound paths keep working through the verified old-path
            # symlink, so they do not need to be edited at their source.
            continue
        raw_path = reference.get("raw_path")
        if not raw_path:
            if os.path.isabs(str(target_text)):
                raw_path = str(target_path)
            else:
                raise vault.VaultError("相对配置引用缺少原始路径字面量，不能安全搬移")
        key = (str(source_file), str(target_path), str(raw_path))
        if key in seen:
            continue
        seen.add(key)
        source_relative = source_file.relative_to(source_root)
        target_file = mapping[source_root] / source_relative
        if not target_file.is_file() or target_file.is_symlink():
            raise vault.VaultError(f"引用方文件在 T1 副本中不存在：{target_file}")
        raw_text = str(raw_path)
        if target_root is not None:
            target_relative = target_path.relative_to(target_root)
            new_target = mapping[target_root] / target_relative
            if os.path.isabs(raw_text):
                new_text = str(new_target)
            elif source_root == target_root:
                # Relative references inside one copied tree keep the same
                # relationship because the directory layout is unchanged.
                continue
            else:
                new_text = os.path.relpath(new_target, target_file.parent)
        elif os.path.isabs(raw_text):
            # Absolute external references keep pointing to the same location;
            # existing missing targets remain pre-existing missing targets.
            continue
        else:
            # Preserve the original external target of a relative reference
            # after moving the source file to the T1 copy.
            new_text = os.path.relpath(target_path, target_file.parent)
        if raw_text.startswith("./") and not new_text.startswith("."):
            new_text = "./" + new_text
        if raw_text == new_text:
            continue
        try:
            content = target_file.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise vault.VaultError(f"配置/任务引用文件不可读取：{target_file}: {error}") from error
        if raw_text not in content:
            raise vault.VaultError(f"未在引用方找到原始路径字面量：{target_file}: {raw_text}")
        target_file.write_text(content.replace(raw_text, new_text), encoding="utf-8")
        repairs_by_source[source_root].append({
            "source_file": str(target_file),
            "old_target": raw_text,
            "new_target": new_text,
        })
    return repairs_by_source


def move_worktree_group(
    sources: list[Path],
    expected_revisions: dict[str, str] | None = None,
    *,
    allow_dirty: bool = False,
    group_id: str | None = None,
    references: list[dict] | None = None,
) -> list[dict]:
    """Copy, repair, switch, and remove a whole associated group together."""
    if not sources:
        return []
    expected_revisions = expected_revisions or {}
    references = references or []
    unique_sources: list[Path] = []
    seen: set[str] = set()
    for raw in sources:
        source = Path(raw).absolute()
        key = str(source)
        if key not in seen:
            seen.add(key)
            unique_sources.append(source)
    preflight = [
        _validate_source(source, expected_revisions.get(str(source), ""), allow_dirty)
        for source in unique_sources
    ]
    vault.check_disk()
    root = vault.DISK / "Agent" / "archive" / "storage-observatory" / "worktrees"
    if root.exists() and root.is_symlink():
        raise vault.VaultError("迁移目标路径不能经过符号链接")
    root.mkdir(parents=True, exist_ok=True)
    if root.stat().st_dev != vault.DISK.stat().st_dev:
        raise vault.VaultError("迁移目标不在指定 T1 卷")

    records: list[dict] = []
    mapping: dict[Path, Path] = {}
    try:
        for evidence in preflight:
            source = evidence["source"]
            before = vault.signature(source)
            if shutil.disk_usage(vault.DISK).free < before["bytes"] + 64 * 1024 * 1024:
                raise vault.VaultError("T1 空间不足")
            folder = root / (source.name + "-" + uuid.uuid4().hex[:12])
            folder.mkdir()
            target = folder / "worktree"
            record = {
                "source": str(source),
                "destination": str(target),
                "git_revision": evidence["revision"],
                "expected_git_revision": evidence["expected_revision"],
                "git_common_dir": str(evidence["common"]),
                "expected_status": evidence["status"],
                "local_source_retained": False,
                "method": "move-to-t1-with-symlink",
                "group_id": group_id,
                "state": "copying",
                "signature": before,
                "reference_repairs": [],
                "usage": "连接 T1 后可从原路径或 destination 打开、修改和提交；拔盘时入口不可用。公共 Git 元数据仍在本机。",
            }
            record_path = folder / "migration.json"
            record["record_path"] = str(record_path)
            record_path.write_text(json.dumps(record, ensure_ascii=False, indent=2, default=str) + "\n")
            try:
                vault.copy_exact(source, target)
            except Exception:
                # A failed copy is not a recoverable T1 worktree. Remove its
                # partial destination so a retry cannot mistake it for a
                # verified duplicate; the source was never switched.
                if folder.is_dir() and not folder.is_symlink():
                    shutil.rmtree(folder)
                raise
            try:
                copied_signature = vault.signature(target)
                source_signature = vault.signature(source)
            except Exception:
                if folder.is_dir() and not folder.is_symlink():
                    shutil.rmtree(folder)
                raise
            if copied_signature != before or source_signature != before:
                if folder.is_dir() and not folder.is_symlink():
                    shutil.rmtree(folder)
                raise vault.VaultError(f"复制校验失败，原件保留；检查 {folder}")
            record["state"] = "verified-copy"
            record_path.write_text(json.dumps(record, ensure_ascii=False, indent=2, default=str) + "\n")
            records.append({**record, "folder": folder, "target": target, "staging": None, "locked": False})
            mapping[source] = target

        config_repairs = _repair_config_references(references, mapping)
        for record in records:
            source = Path(record["source"])
            target = Path(record["destination"])
            record["reference_repairs"] = config_repairs.get(source, [])
            record["reference_repairs"].extend(_link_repairs(source, target, mapping))
            record["copied_signature"] = vault.signature(target)

        # All copies are verified before any original entry is switched.
        for record in records:
            source = Path(record["source"])
            staging = source.with_name(source.name + ".moving-" + uuid.uuid4().hex[:12])
            record["staging"] = str(staging)
            source.rename(staging)
            record["state"] = "switching"
            Path(record["record_path"]).write_text(json.dumps(record, ensure_ascii=False, indent=2, default=str) + "\n")
        for record in records:
            common = Path(record["git_common_dir"])
            target = Path(record["destination"])
            git(common, "worktree", "repair", str(target))
        for record in records:
            record["expected_target_status"] = git(
                Path(record["destination"]), "status", "--porcelain", "--untracked-files=all",
                timeout=300,
            )
        for record in records:
            source = Path(record["source"])
            target = Path(record["destination"])
            source_status = git(target, "status", "--porcelain", "--untracked-files=all", timeout=300)
            if record["expected_git_revision"] and git(target, "rev-parse", "HEAD") != record["expected_git_revision"]:
                raise vault.VaultError("迁移后 Git 提交校验失败")
            if source_status != record.get("expected_target_status", record["expected_status"]):
                raise vault.VaultError("迁移后未提交/未跟踪状态发生变化")
            if vault.signature(target) != record["copied_signature"]:
                raise vault.VaultError("迁移后引用修复或内容发生变化")
            git(Path(record["git_common_dir"]), "worktree", "lock", "--reason", "T1 removable drive; preserve offline registration", str(target))
            record["locked"] = True
            source.symlink_to(target, target_is_directory=True)
            if not source.is_symlink() or git(
                source, "status", "--porcelain", "--untracked-files=all", timeout=300
            ) != record.get("expected_target_status", record["expected_status"]):
                raise vault.VaultError("旧路径软链接入口校验失败")
            record["state"] = "linked-removing-local"
            Path(record["record_path"]).write_text(json.dumps(record, ensure_ascii=False, indent=2, default=str) + "\n")
        for record in records:
            staging = Path(record["staging"])
            target = Path(record["destination"])
            source = Path(record["source"])
            if vault.signature(staging) != record["signature"]:
                raise vault.VaultError("搬移期间本机暂存文件发生变化")
            if vault.signature(target) != record["copied_signature"]:
                raise vault.VaultError("删除本机副本前 T1 内容校验失败")
            if not source.is_symlink() or git(
                source, "status", "--porcelain", "--untracked-files=all", timeout=300
            ) != record.get("expected_target_status", record["expected_status"]):
                raise vault.VaultError("删除本机副本前旧路径入口校验失败")
            shutil.rmtree(staging)
            record["temporary_local_path"] = str(staging)
            record["state"] = "complete"
            record["local_source_retained"] = False
            Path(record["record_path"]).write_text(json.dumps(record, ensure_ascii=False, indent=2, default=str) + "\n")
        for record in records:
            for key in ("folder", "target", "staging", "record_path", "locked"):
                record.pop(key, None)
        return records
    except Exception:
        # Keep T1 copies for inspection/retry, but restore every local entry
        # that has not reached the irreversible local-removal point.
        if not any(record.get("staging") for record in records):
            # No local entry has been switched yet.  Remove verified/partial
            # T1 folders as well so a retry cannot accumulate duplicate
            # migrations while the source remains authoritative.
            for record in records:
                folder = Path(record.get("folder", ""))
                try:
                    if folder.is_dir() and not folder.is_symlink():
                        shutil.rmtree(folder)
                except OSError:
                    pass
            raise
        for record in reversed(records):
            source = Path(record["source"])
            staging_text = record.get("staging")
            staging = Path(staging_text) if staging_text else None
            target = Path(record["destination"])
            try:
                if source.is_symlink():
                    source.unlink()
                if record.get("locked"):
                    git(Path(record["git_common_dir"]), "worktree", "unlock", str(target))
                if staging and staging.exists() and not source.exists():
                    staging.rename(source)
                elif not source.exists() and target.exists():
                    # Once the target was verified and the local staging copy
                    # was removed, keep the usable T1 target and restore the
                    # old entry point for reconnect/retry.
                    source.symlink_to(target, target_is_directory=True)
                if source.exists() and not source.is_symlink():
                    git(Path(record["git_common_dir"]), "worktree", "repair", str(source))
                record["state"] = (
                    "rolled-back-to-t1-link" if source.is_symlink() and not staging else
                    "rolled-back-local-preserved"
                )
                record["local_source_retained"] = source.exists() and not source.is_symlink()
                Path(record["record_path"]).write_text(json.dumps(record, ensure_ascii=False, indent=2, default=str) + "\n")
            except (OSError, subprocess.SubprocessError):
                record["state"] = "rollback-incomplete-local-and-t1-record-retained"
                try:
                    Path(record["record_path"]).write_text(json.dumps(record, ensure_ascii=False, indent=2, default=str) + "\n")
                except OSError:
                    pass
        raise


def move_worktree(source: Path, expected_revision: str, *, allow_dirty: bool = False) -> dict:
    """Compatibility wrapper for one finalized linked worktree."""
    result = move_worktree_group([source], {str(Path(source).absolute()): expected_revision}, allow_dirty=allow_dirty)
    return result[0]
