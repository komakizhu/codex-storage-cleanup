"""Generate the short, human-readable report shown in chat.

The JSON/HTML reports keep the detailed evidence. This module deliberately
keeps the conversation summary focused on the answer a person needs: how much
Codex uses, where it is, what changed, and what can be considered next.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
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


def _path_link(label, path):
    path = str(path or '')
    label = str(label or path or '路径未记录')
    if path.startswith('/'):
        return f'[{label}](<{path}>)'
    return f'`{label}`'


def _coverage_state(payload, discovery, coverage):
    status = payload.get('status')
    cleanup_plan = payload.get('cleanup_plan') or {}
    capacity = cleanup_plan.get('capacity') or {}
    if status in {'failed', 'partial', 'skipped'}:
        return 'partial'
    if any(coverage.get(key) is False for key in (
        'scope_complete', 'coverage_complete', 'cleanup_plan_complete', 'acceptance_passed',
    )) or coverage.get('budget_exhausted') is True or capacity.get('candidate_entries_complete') is False:
        return 'partial'
    if all(coverage.get(key) is True for key in (
        'scope_complete', 'coverage_complete', 'cleanup_plan_complete',
        'acceptance_passed',
    )) and coverage.get('budget_exhausted') is not True:
        return 'complete'
    if discovery or coverage or status:
        return 'unknown'
    return 'item-ledger' if payload.get('items') else 'unknown'


def _coverage_label(coverage, state):
    if state == 'complete':
        return '完整并通过验收'
    if state == 'partial':
        gaps = coverage.get('gap_count')
        errors = coverage.get('error_count')
        details = []
        if isinstance(gaps, int):
            details.append(f'{gaps:,} 个缺口')
        if isinstance(errors, int):
            details.append(f'{errors:,} 条错误')
        suffix = '；'.join(details)
        return '未完成' + (f'（{suffix}）' if suffix else '')
    return '状态未知'


def _change_for(label, comparison, field):
    if not comparison.get('delta_comparable'):
        return '未比较'
    for row in comparison.get(field, []) if isinstance(comparison.get(field), list) else []:
        if isinstance(row, dict) and str(row.get('label') or '') == str(label):
            return _delta(row.get('delta_bytes'))
    return '无匹配的上次分组'


def _diagnostic_summary(payload, coverage):
    gap_count = coverage.get('gap_count')
    error_count = coverage.get('error_count')
    details = []
    if isinstance(gap_count, int):
        details.append(f'{gap_count:,} 个缺口')
    if isinstance(error_count, int):
        details.append(f'{error_count:,} 条错误')
    reason = payload.get('reason') or payload.get('failure')
    if isinstance(reason, str) and reason.strip():
        candidates = [line.strip() for line in reason.splitlines() if line.strip()]
        specific = next((
            line for line in reversed(candidates)
            if any(token in line.lower() for token in (
                'no space left', 'errno 28', 'timed out', 'timeoutexpired',
                'permission denied', 'budget exceeded', '预算超时',
            ))
        ), None)
        summary = specific or (candidates[0] if candidates else '')
        if summary:
            details.append(summary[:220])
    return '；'.join(details) or '本轮未取得可用的完整扫描记录'


_CANDIDATE_ACTIONS = {
    'direct-delete': ('建议安全清理', '确认路径仍未使用后，按默认策略处理。'),
    'backup-then-delete': ('先备份再删', '先备份到 T1 并校验，再处理这个精确路径。'),
    'migrate-to-t1': ('暂不处理 / 搬移', '仅在关联组通过 168 小时闲置、活动、句柄、引用和 Git 检查后迁移。'),
}


def _evidence_value(value):
    if isinstance(value, str):
        return ' '.join(value.split())
    if isinstance(value, bool):
        return '是' if value else '否'
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        parts = [_evidence_value(item) for item in value[:3]]
        return '；'.join(part for part in parts if part)
    if isinstance(value, dict):
        preferred = ('summary', 'reason', 'source', 'path', 'status', 'field', 'evidence')
        parts = [f'{key}：{_evidence_value(value[key])}' for key in preferred
                 if key in value and _evidence_value(value[key])]
        if not parts:
            parts = [f'{key}：{_evidence_value(item)}' for key, item in list(value.items())[:3]
                     if _evidence_value(item)]
        return '；'.join(parts[:3])
    return ''


def _candidate_evidence(entry):
    fields = (
        ('reason', '判断'), ('recommendation', '建议'), ('provenance', '来源'),
        ('evidence_paths', '证据路径'), ('source_entries', '来源记录'),
        ('rebuild_basis', '可重建依据'), ('regeneration_evidence', '生成证据'),
        ('completed_outputs', '完成产物'), ('retention_evidence', '保留期证据'),
        ('reference_evidence', '引用证据'), ('migration_reason', '迁移依据'),
        ('activity', '活动检查'), ('idle_for_hours', '闲置时长'),
        ('group_status', '关联组状态'), ('git_state', 'Git 状态'),
        ('backup_category', '备份类别'),
    )
    parts = []
    for key, label in fields:
        value = _evidence_value(entry.get(key))
        if value:
            parts.append(f'{label}：{value}')
    return '；'.join(parts)[:600]


def _candidate_rows(payload):
    plan = payload.get('cleanup_plan') or {}
    capacity = plan.get('capacity') or {}
    if isinstance(capacity.get('candidate_entries'), list):
        raw_rows = capacity['candidate_entries']
        list_present = True
        list_complete = capacity.get('candidate_entries_complete')
    elif isinstance(payload.get('candidate_entries'), list):
        raw_rows = payload['candidate_entries']
        list_present = True
        list_complete = payload.get('candidate_entries_complete')
    else:
        raw_rows = []
        list_present = False
        list_complete = None
        for item in payload.get('items', []) if isinstance(payload.get('items'), list) else []:
            if not isinstance(item, dict) or item.get('default_action') not in _CANDIDATE_ACTIONS:
                continue
            raw_rows.append({
                **item,
                'action': item.get('default_action'),
                'logical_bytes': item.get('logical_bytes', item.get('size_bytes')),
            })

    rows = {}
    unverified = 0
    conflicts = set()
    for entry in raw_rows:
        if not isinstance(entry, dict) or entry.get('action') not in _CANDIDATE_ACTIONS:
            unverified += 1
            continue
        path = str(entry.get('path') or '').strip()
        raw_amount = entry.get('logical_bytes')
        if raw_amount is None:
            raw_amount = entry.get('size_bytes')
        amount = _bytes(raw_amount)
        evidence = _candidate_evidence(entry)
        if not path or amount is None or amount < 0 or not evidence:
            unverified += 1
            continue
        key = (entry['action'], path)
        if key in rows:
            if rows[key]['logical_bytes'] != amount:
                conflicts.add(key)
            continue
        rows[key] = {**entry, 'path': path, 'logical_bytes': amount, '_evidence_text': evidence}
    for key in conflicts:
        rows.pop(key, None)
        unverified += 1
    return list(rows.values()), list_present, list_complete, unverified


def _gb(value):
    number = _bytes(value)
    if number is None:
        return '未知'
    if number == 0:
        return '0.00 GB'
    suffix = _size(number)
    gb = f'{number / 1_000_000_000:.2f} GB'
    return gb if number >= 10_000_000 else f'{gb}（{suffix}）'


def _table_cell(value):
    return str(value).replace('|', '\\|').replace('\n', ' ').replace('\r', ' ')


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


def render_chat_report(payload):
    """Render the three user-facing tables, preserving unknown scan states."""
    payload = payload or {}
    discovery = payload.get('large_file_discovery') or {}
    usage = discovery.get('usage_summary') or {}
    coverage = discovery.get('coverage') or payload.get('coverage') or {}
    comparison = payload.get('comparison') or {}
    total = _codex_total(payload, discovery)
    free = payload.get('free_bytes')
    if free is None:
        free = discovery.get('free_bytes')
    elapsed = payload.get('scan_total_elapsed_seconds')
    if elapsed is None:
        elapsed = payload.get('scan_elapsed_seconds') or discovery.get('elapsed_seconds')
    state = _coverage_state(payload, discovery, coverage)
    options = payload.get('cleanup_options')
    if not isinstance(options, dict):
        options = option_totals(payload.get('items', []))
    options = {**option_totals([]), **options}
    complete = state == 'complete'
    current_total = '未测' if total is None else _size(total)
    if total is not None and not complete:
        current_total += '（部分测量）'
    previous_total = comparison.get('previous_codex_bytes')
    previous_free = comparison.get('previous_free_bytes')
    previous_coverage = comparison.get('previous_coverage_complete')
    previous_coverage_label = (
        '完整' if previous_coverage is True else
        '未完成' if previous_coverage is False else '未记录'
    )
    total_delta = (
        _delta(comparison.get('codex_bytes_delta'))
        if comparison.get('delta_comparable') and comparison.get('codex_bytes_delta') is not None
        else '未比较'
    )
    free_delta = (
        _delta(comparison.get('free_bytes_delta'))
        if comparison.get('free_delta_comparable') and comparison.get('free_bytes_delta') is not None
        else '未比较'
    )
    comparability = (
        '同范围完整扫描' if comparison.get('delta_comparable')
        else ('本轮未完成，不能比较' if state != 'complete' else '尚无可比的完整基线')
    )
    timestamp = _recorded_time(payload.get('generated_at') or payload.get('checked_at'))
    account = (payload.get('platform') or {}).get('current_user') or Path(str(payload.get('home') or '')).name
    if not account:
        account = '未记录'
    lines = [
        f'Codex 存储检查：{_coverage_label(coverage, state)}',
        f'检查时间：{timestamp}；账号：{account}；耗时：{_time(elapsed)}',
        '',
        '### 1. 空间变化',
        '| 指标 | 上次成功值 | 本次测量 | 变化 | 可比性 |',
        '|---|---:|---:|---:|---|',
        f'| Codex 逻辑占用 | {_size(previous_total)} | {current_total} | {total_delta} | {comparability} |',
        f'| 本机可用空间 | {_size(previous_free)} | {_size(free)} | {free_delta} | {comparability if comparison.get("free_delta_comparable") else "未核对同卷基线"} |',
        f'| 扫描覆盖 | {previous_coverage_label} | {_coverage_label(coverage, state)} | 未比较 | 本轮状态：{_coverage_label(coverage, state)} |',
        '',
        '### 2. 增长来源与已知占用',
        '位置和项目是同一批数据的不同视角，不能相加；没有同范围完整基线时，变化列会标“未比较”。',
        '| 视角 | 位置或任务 | 占用 | 较上次变化 | 具体是什么、产生原因与证据 |',
        '|---|---|---:|---:|---|',
    ]
    locations = _location_rows(discovery)
    source_count = 0
    for row in locations[:12]:
        label = row.get('label') or row.get('path') or '位置未记录'
        path = row.get('path')
        description = row.get('purpose') or row.get('retained_reason') or 'Codex 来源记录中的位置汇总。'
        evidence = row.get('source_evidence') or usage.get('basis') or '本轮容量清单'
        detail = f'{description}；依据：{evidence}'
        lines.append(f'| 位置 | {_path_link(label, path)} | {_size(row.get("logical_bytes"))} | {_change_for(label, comparison, "location_deltas")} | {detail} |')
        source_count += 1
    if len(locations) > 12:
        remaining = locations[12:]
        lines.append(f'| 位置 | 其他位置（{len(remaining)} 个） | {_size(sum(_bytes(row.get("logical_bytes")) or 0 for row in remaining))} | 未比较 | 汇总自本次已测位置；不是新增空间。 |')
        source_count += 1
    projects = _project_rows(discovery)
    retained = discovery.get('top_retained_contents') or []
    for row in projects[:8]:
        label = _project_label(row.get('project_key'))
        lines.append(f'| 项目 | `{label}` | {_size(row.get("logical_bytes"))} | {_change_for(label, comparison, "project_deltas")} | 按项目身份归组的 Codex 占用；与位置视角重叠。 |')
        source_count += 1
    for row in retained[:5]:
        path = row.get('path') or ''
        label = path.rsplit('/', 1)[-1] or path or '路径未记录'
        reason = row.get('retained_reason') or '按策略保留的用户或运行数据。'
        condition = row.get('remaining_condition')
        detail = reason + (f'；复核条件：{condition}' if condition else '')
        lines.append(f'| 保留明细 | {_path_link(label, path)} | {_size(row.get("logical_bytes"))} | 未比较 | {detail} |')
        source_count += 1
    if not source_count:
        lines.append('| 位置/项目 | 未取得明细 | 未知 | 未比较 | 扫描没有提供可用的容量分组，不能据此判断为零占用。 |')

    candidates, candidate_list_present, candidate_list_complete, unverified_count = _candidate_rows(payload)
    candidate_totals = {action: 0 for action in _CANDIDATE_ACTIONS}
    candidate_counts = {action: 0 for action in _CANDIDATE_ACTIONS}
    for entry in candidates:
        candidate_totals[entry['action']] += entry['logical_bytes']
        candidate_counts[entry['action']] += 1
    candidate_total_bytes = sum(candidate_totals.values())
    candidate_total_count = sum(candidate_counts.values())
    summary_complete = (
        state == 'complete' and unverified_count == 0 and candidate_list_complete is not False
    )
    lines.extend([
        '',
        '### 3. 清理建议（只给计划，不执行）',
        '| 类别 | 候选路径 | 单项占用 | 建议 | 逐项依据 |',
        '|---|---|---:|---|---|',
    ])
    for entry in candidates:
        action_label, recommendation = _CANDIDATE_ACTIONS[entry['action']]
        artifact_type = entry.get('artifact_type')
        evidence = entry['_evidence_text']
        if artifact_type:
            evidence = f'类型：{_evidence_value(artifact_type)}；{evidence}'
        lines.append(
            f'| {action_label} | {_path_link(entry["path"], entry["path"])} | '
            f'{_gb(entry["logical_bytes"])} | {recommendation} | {_table_cell(evidence)} |'
        )
    if unverified_count:
        lines.append(
            f'| 待补证据 | 未展示 {unverified_count} 条记录 | 未知 | 暂不计入候选小计 | '
            '路径、单项容量或判断依据缺失，不能当作已确认候选。 |'
        )

    for action, (label, _recommendation) in _CANDIDATE_ACTIONS.items():
        amount = candidate_totals[action]
        count = candidate_counts[action]
        if summary_complete:
            subtotal = f'{_gb(amount)} / {count} 项'
        elif count:
            prefix = '当前清单小计' if state == 'item-ledger' else '部分清单已确认小计'
            suffix = '不是全盘总量' if state == 'item-ledger' else '该类全量未知'
            subtotal = f'{prefix} {_gb(amount)} / {count} 项；{suffix}'
        elif state == 'item-ledger' and candidate_list_present:
            subtotal = '当前清单未列出；全盘总量未知'
        elif state == 'partial':
            subtotal = '部分清单没有本类单项证据；类别总量未知'
        else:
            subtotal = '未知（未取得本类单项证据）'
        lines.append(
            f'| {label}小计 | - | {_table_cell(subtotal)} | 按逐项候选去重汇总 | '
            '父子目录与硬链接不重复计算。 |'
        )

    if summary_complete:
        total_text = f'{_gb(candidate_total_bytes)} / {candidate_total_count} 项'
        total_reason = '完整扫描通过验收，以上候选清单覆盖完整。'
    elif candidates:
        prefix = '当前清单小计' if state == 'item-ledger' else '部分清单已确认小计'
        total_text = f'{prefix} {_gb(candidate_total_bytes)} / {candidate_total_count} 项；整体候选总量未知'
        total_reason = '本轮只列出有单项依据的记录；当前清单不完整，不能把已确认小计当作全盘总量。'
    elif state == 'item-ledger':
        total_text = '当前清单未列出候选；整体候选总量未知'
        total_reason = '收到的是局部条目清单，不代表完整扫描结果。'
    elif state == 'partial':
        total_text = '未知（候选清单不完整；本轮没有可展示的逐项候选证据；整体候选总量未知）'
        total_reason = '整体候选总量未知；缺口不按零计算，占位 0 不表示没有候选。'
    else:
        total_text = '未知（本轮没有可展示的逐项候选证据；整体候选总量未知）'
        total_reason = '扫描未通过完整验收；缺口不按零计算，占位 0 不表示没有候选。'
    lines.append(
        f'| 候选总量 | - | {_table_cell(total_text)} | 只读建议，不执行 | {_table_cell(total_reason)} |'
    )
    for row in retained[:3]:
        path = row.get('path') or ''
        label = row.get('retained_reason') or '按策略保留的用户或运行数据'
        condition = row.get('remaining_condition')
        detail = label + (f'；复核条件：{condition}' if condition else '')
        lines.append(
            f'| 保留（非候选） | {_path_link(path, path)} | {_gb(row.get("logical_bytes"))} | '
            f'保持原位 | {_table_cell(detail)}；不计入候选总量。 |'
        )
    if not retained:
        lines.append(
            '| 保留（非候选） | 未逐项展开 | 未知 | 默认保持原位 | '
            '活动会话、数据库、源码、用户成果、依赖和未验明用途的数据保留。 |'
        )
    basis = ((payload.get('cleanup_plan') or {}).get('capacity') or {}).get('basis')
    if basis:
        lines.append('')
        lines.append(f'候选容量依据：{_table_cell(basis)}。')
    if state != 'complete':
        lines.append(f'扫描缺口：{_table_cell(_diagnostic_summary(payload, coverage))}。')
    if unverified_count or candidate_list_complete is False:
        lines.append('候选明细覆盖不完整；未确认的整体总量保持未知。')
    lines.extend([
        '',
        '单项占用是候选对象的逻辑大小，不承诺实际释放同额空间；报告只读，任何未确认的整体总量都标为未知。',
    ])
    return '\n'.join(lines)
