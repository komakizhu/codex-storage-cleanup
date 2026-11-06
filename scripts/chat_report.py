"""Generate the short, human-readable report shown in chat.

The JSON/HTML reports keep the detailed evidence. This module deliberately
keeps the conversation summary focused on the answer a person needs: how much
Codex uses, where it is, what changed, and what can be considered next.
"""
from __future__ import annotations

from datetime import datetime
import re
from typing import Any


def option_totals(items):
    """Keep the existing cleanup option accounting for the legacy ledger."""
    unique = {item['path']: item for item in items}
    builds = [item for item in unique.values() if item.get('source_entries') and item.get('rebuild_basis')]
    old = [item for item in builds if item.get('review_priority') == 'delete-old-build']
    size = lambda rows: sum(int(item.get('size_bytes') or 0) for item in rows)
    return {
        'keep_latest_bytes': size(old),
        'all_build_bytes': size(builds),
        'all_build_in_use_bytes': size([item for item in builds if item.get('active') is True]),
        'all_build_usage_unknown_bytes': size([item for item in builds if item.get('active') is None]),
        'all_build_idle_bytes': size([item for item in builds if item.get('active') is False]),
        'secondary_cache_bytes': size([item for item in unique.values() if item.get('tier') == 'regenerable' and item.get('review_priority') != 'delete-old-build']),
        'session_bytes': size([item for item in unique.values() if item.get('artifact_type') in {'归档/已关闭会话', '当前/普通会话'}]),
        'image_output_bytes': size([item for item in unique.values() if item.get('artifact_type') == '生成图片与用户输出']),
        'archive_backup_delete_bytes': sum(int(item.get('archive_eligible_bytes') or 0) for item in unique.values()),
        'backup_then_delete_bytes': sum(int(item.get('archive_eligible_bytes') or item.get('backup_eligible_bytes') or 0) for item in unique.values() if item.get('default_action') == 'backup-then-delete'),
        'closed_task_output_bytes': sum(int(item.get('backup_eligible_bytes') or 0) for item in unique.values() if item.get('backup_category') == 'user-data' and item.get('review_priority') != 'verified-duplicate-backup' and item.get('default_action') == 'backup-then-delete'),
        'duplicate_backup_bytes': sum(int(item.get('backup_eligible_bytes') or 0) for item in unique.values() if item.get('review_priority') == 'verified-duplicate-backup' and item.get('default_action') == 'backup-then-delete'),
        'finalized_worktree_bytes': size([item for item in unique.values() if item.get('default_action') == 'migrate-to-t1']),
        'idle_worktree_bytes': size([item for item in unique.values() if item.get('default_action') == 'migrate-to-t1' and item.get('review_priority') == 'idle-worktree-group']),
    }


def _number(value):
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    match = re.match(r'^\s*([-+]?(?:\d+(?:\.\d*)?|\.\d+))\s*(B|KB|MB|GB|TB)?\s*$', str(value), re.I)
    if not match:
        return None
    unit = (match.group(2) or 'B').upper()
    return float(match.group(1)) * {'B': 1, 'KB': 1_000, 'MB': 1_000_000,
                                    'GB': 1_000_000_000, 'TB': 1_000_000_000_000}[unit]


def _bytes(value):
    number = _number(value)
    if number is None:
        return None
    try:
        return int(number)
    except (TypeError, ValueError):
        return None


def _size(value):
    """Use decimal units consistently with the storage reports."""
    number = _bytes(value)
    if number is None:
        return '未记录'
    units = ('B', 'KB', 'MB', 'GB', 'TB')
    amount = float(max(number, 0))
    for unit in units:
        if amount < 1000 or unit == 'TB':
            if unit == 'B':
                return f'{round(amount):,} B'
            return f'{amount:.2f} {unit}'
        amount /= 1000
    return f'{amount:.2f} TB'


def _delta(value):
    number = _bytes(value)
    if number is None:
        return '未记录'
    if number > 0:
        return f'增加 {_size(number)}'
    if number < 0:
        return f'减少 {_size(abs(number))}'
    return '没有变化'


def _time(value):
    number = _number(value)
    return '未记录' if number is None else f'{number:.2f} 秒'


def _recorded_time(value):
    if not value:
        return '未记录'
    text = str(value)
    try:
        return datetime.fromisoformat(text.replace('Z', '+00:00')).astimezone().strftime('%Y-%m-%d %H:%M')
    except ValueError:
        return text


def _location_rows(discovery: dict[str, Any]) -> list[dict[str, Any]]:
    usage = discovery.get('usage_summary') or {}
    rows = usage.get('locations')
    if isinstance(rows, list):
        return [row for row in rows if isinstance(row, dict) and _bytes(row.get('logical_bytes'))]
    return []


def _project_rows(discovery: dict[str, Any]) -> list[dict[str, Any]]:
    usage = discovery.get('usage_summary') or {}
    rows = usage.get('projects')
    if isinstance(rows, list):
        return [row for row in rows if isinstance(row, dict) and _bytes(row.get('logical_bytes'))]
    return []


def _project_label(value):
    text = str(value or '').strip()
    if not text or '项目暂未' in text or '项目名称暂未' in text:
        return '项目名称暂未确认'
    if text.endswith('/.git'):
        return text[:-5].rstrip('/').rsplit('/', 1)[-1]
    if text.startswith(('https://github.com/', 'http://github.com/')):
        return text.rstrip('/').rsplit('/', 1)[-1]
    if text.startswith('codex-project:'):
        return text.rsplit('/', 1)[-1]
    return text


def _codex_total(payload: dict[str, Any], discovery: dict[str, Any]):
    usage = discovery.get('usage_summary') or {}
    value = usage.get('codex_logical_bytes')
    if value is not None:
        return value
    totals = discovery.get('totals') or {}
    for key in ('codex_logical_bytes', 'codex_logical_size'):
        if totals.get(key) is not None:
            return totals[key]
    return (payload.get('summary') or {}).get('codex_bytes')


def _advice(totals: dict[str, int]) -> list[str]:
    advice = []
    old = totals.get('keep_latest_bytes', 0)
    if old:
        advice.append(f'已核实旧构建默认直接删除，按每个项目保留最新一份，预计释放约 {_size(old)}。')
    if totals.get('all_build_in_use_bytes'):
        advice.append(f'有 {_size(totals["all_build_in_use_bytes"])} 构建仍在使用，先保留。')
    if totals.get('all_build_usage_unknown_bytes'):
        advice.append(f'有 {_size(totals["all_build_usage_unknown_bytes"])} 构建还没确认是否在用，暂不处理。')
    if totals.get('secondary_cache_bytes'):
        advice.append(f'可再生应用缓存和临时文件约 {_size(totals["secondary_cache_bytes"])}，默认直接清理；下载依赖和工具缓存继续保留。')
    if totals.get('archive_backup_delete_bytes'):
        advice.append(f'超过 7 天的归档会话约 {_size(totals["archive_backup_delete_bytes"])}，先备份到 T1 并校验，再删除本机旧文件。')
    if totals.get('closed_task_output_bytes'):
        advice.append(f'有结束证据且没有受支持引用的旧任务成果约 {_size(totals["closed_task_output_bytes"])}，先备份到 T1 并校验，再删除本机副本。')
    if totals.get('duplicate_backup_bytes'):
        advice.append(f'内容已完整校验的本机重复备份约 {_size(totals["duplicate_backup_bytes"])}，先备份到 T1 并校验，再删除重复副本。')
    if totals.get('finalized_worktree_bytes'):
        advice.append(f'关联组连续超过 168 小时闲置且检查通过的 worktree 约 {_size(totals["finalized_worktree_bytes"])}，移动到 T1 后移除本机副本，以原路径软链接访问。')
    if not advice:
        advice.append('目前没有能直接确认可以清理的内容。')
    advice.append('扫描本身只读；执行默认策略需调用 `scripts/apply_cleanup.py --apply`。')
    return advice


def render_chat_report(payload):
    """Render a concise Chinese report without internal scanner terminology."""
    payload = payload or {}
    discovery = payload.get('large_file_discovery') or {}
    usage = discovery.get('usage_summary') or {}
    total = _codex_total(payload, discovery)
    free = payload.get('free_bytes')
    if free is None:
        free = discovery.get('free_bytes')
    elapsed = payload.get('scan_total_elapsed_seconds')
    if elapsed is None:
        elapsed = payload.get('scan_elapsed_seconds') or discovery.get('elapsed_seconds')
    option = option_totals(payload.get('items', []))
    lines = [
        f'Codex 总占用：{_size(total)}',
        f'检查时间：{_recorded_time(payload.get("generated_at") or payload.get("checked_at"))}',
        f'可用空间：{_size(free)}',
        f'检查耗时：{_time(elapsed)}',
        '',
    ]

    locations = _location_rows(discovery)
    lines.append('按位置：')
    if locations:
        lines.append('| 位置 | Codex 占用 |')
        lines.append('|---|---:|')
        for row in locations[:12]:
            label = row.get('label') or row.get('path') or '未记录位置'
            lines.append(f'| {label} | {_size(row.get("logical_bytes"))} |')
        if len(locations) > 12:
            lines.append(f'| 其他位置（{len(locations) - 12} 个） | {_size(sum(_bytes(row.get("logical_bytes")) or 0 for row in locations[12:]))} |')
    else:
        lines.append('暂时没有按位置拆出的记录。')

    projects = _project_rows(discovery)
    lines.extend(['', '按项目：'])
    if projects:
        lines.append('| 项目 | Codex 占用 |')
        lines.append('|---|---:|')
        for row in projects[:20]:
            label = _project_label(row.get('project_key'))
            lines.append(f'| {label} | {_size(row.get("logical_bytes"))} |')
        if len(projects) > 20:
            lines.append(f'| 其他项目（{len(projects) - 20} 个） | {_size(sum(_bytes(row.get("logical_bytes")) or 0 for row in projects[20:]))} |')
    else:
        lines.append('暂时没有能确认项目名称的记录。')

    retained = discovery.get('top_retained_contents') or []
    lines.extend(['', '最大的三项保留内容：'])
    if retained:
        for index, row in enumerate(retained[:3], 1):
            allocated = _size(row.get('allocated_bytes'))
            lines.append(
                f'{index}. {row.get("path", "路径未记录")}：逻辑 {_size(row.get("logical_bytes"))}，'
                f'分配 {allocated}；{row.get("retained_reason", "保留原因未记录")} '
                f'条件：{row.get("remaining_condition", "无")}'
            )
            candidates = row.get("policy_candidates_still_present") or []
            if candidates:
                lines.append(f'   仍在本机的默认策略候选：{len(candidates)} 项；需按执行结果确认是否跳过或失败。')
    else:
        lines.append('本次范围内没有可计量的保留项目。')

    comparison = payload.get('comparison') or payload.get('change') or {}
    if isinstance(comparison, dict):
        change = comparison.get('codex_bytes_delta')
        if change is None:
            change = comparison.get('delta_bytes')
        if change is not None:
            lines.extend(['', f'和上次相比：{_delta(change)}。'])
        coverage = comparison.get('coverage_change')
        if coverage:
            lines.append(f'覆盖范围：{coverage}。')

    lines.extend(['', '处理建议：'])
    lines.extend(f'- {item}' for item in _advice(option))
    if usage.get('codex_without_project_logical_bytes'):
        lines.append(f'- 其中 {_size(usage.get("codex_without_project_logical_bytes"))} 属于 Codex，但暂时没有对应项目名称。')
    if discovery.get('enabled') and discovery.get('coverage', {}).get('coverage_complete') is False:
        lines.append('- 有些位置这次没能完整读到，已保留在详细记录里，不能按零计算。')
    lines.extend([
        '',
        'T1 存放规划：',
        '- 源码、Git、会话、数据库、凭据和独有成果默认不动；关联组连续超过 168 小时闲置且所有检查通过的完整 worktree 移动到 T1，校验后删除本机副本并保留原路径软链接。',
        '- 已有腾讯语音资料放在 `Agent/work/rime-voice-data`，Pet Studio 放在 `Agent/work/pet-studio-data`；迁移尚未验收，不能当作已完成备份。',
        '- MusicCardProbe 归档放在 `Agent/archive/MusicCardProbe`；新快照写入 `/Volumes/T1/Agent/archive/storage-observatory/snapshots`，旧快照位置保持可恢复。',
    ])
    lines.append('详细路径和诊断记录保存在报告的诊断区。')
    return '\n'.join(lines)
