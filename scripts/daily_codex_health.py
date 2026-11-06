#!/usr/bin/env python3
"""Daily read-only health check. No deletion, service, browser or VM actions."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import fcntl
import pwd

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import bounded_process
import scan_budget
from chat_report import render_chat_report

REPO = Path(__file__).resolve().parents[1]
SCANNER = SCRIPT_DIR / 'scan_codex.py'
DEFAULT_WORKSPACE = Path.home() / '.codex/skill-workspaces/codex-storage-cleanup/daily'


def _read_json(path, expected_type):
    """Read one checker-owned JSON file without letting bad state abort a run."""
    path = Path(path)
    if not path.exists():
        return None, None
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError, UnicodeError) as error:
        return None, f'{path.name} 读取失败：{error}'
    if not isinstance(value, expected_type):
        return None, f'{path.name} 根类型错误：需要 {expected_type.__name__}'
    return value, None


def _validate_summary(summary):
    """Validate known fields while keeping old, minimal summaries readable."""
    if summary is None:
        return '摘要记录为空'
    if not isinstance(summary, dict):
        return '摘要不是 JSON 对象'
    for key in ('status', 'home', 'report', 'reason'):
        if key in summary and not isinstance(summary[key], str):
            return f'摘要字段 {key} 类型错误'
    if 'totals' in summary and not isinstance(summary['totals'], dict):
        return '摘要字段 totals 类型错误'
    if 'coverage' in summary and not isinstance(summary['coverage'], dict):
        return '摘要字段 coverage 类型错误'
    if 'directory_summary' in summary and not isinstance(summary['directory_summary'], list):
        return '摘要字段 directory_summary 类型错误'
    if 'directory_summary_meta' in summary and not isinstance(summary['directory_summary_meta'], dict):
        return '摘要字段 directory_summary_meta 类型错误'
    for key in ('budget_seconds', 'free_bytes', 'elapsed_seconds', 'scan_elapsed_seconds',
                'scan_total_elapsed_seconds', 'allocated_delta_bytes'):
        if key in summary and summary[key] is not None and (isinstance(summary[key], bool) or
                               not isinstance(summary[key], (int, float))):
            return f'摘要字段 {key} 类型错误'
    totals = summary.get('totals')
    if isinstance(totals, dict):
        for key, value in totals.items():
            if key.endswith('_bytes') and value is not None and (isinstance(value, bool) or
                                                                  not isinstance(value, int)):
                return f'摘要 totals.{key} 类型错误'
    return None


def _valid_summary(summary):
    return isinstance(summary, dict) and _validate_summary(summary) is None


def _summary_reports(previous, history):
    reports = []
    values = ([previous] if isinstance(previous, dict) else []) + list(history or [])
    for summary in values:
        # An invalid summary must not be treated as a successful baseline, but
        # its report path can still point at evidence worth protecting while
        # recovery output is selected.
        if not isinstance(summary, dict):
            continue
        report = summary.get('report')
        if isinstance(report, str) and report:
            reports.append(Path(report).absolute())
    return reports


def _inside(path, root):
    try:
        Path(path).absolute().relative_to(Path(root).absolute())
        return True
    except ValueError:
        return False


def _select_pending_workspace(workspace, previous, history, previous_error, history_error):
    """Choose a report slot without overwriting a report when state is corrupt."""
    workspace = Path(workspace).absolute()
    protected_reports = _summary_reports(previous, history)
    slots = [workspace / 'slot-a', workspace / 'slot-b']
    if previous_error or history_error:
        for slot in slots:
            report = slot / 'outputs/codex-storage-cleanup-report.html'
            if not report.exists() and not any(_inside(item, slot) for item in protected_reports):
                return slot
        index = 0
        while True:
            candidate = workspace / ('recovery' if index == 0 else f'recovery-{index}')
            if not candidate.exists():
                return candidate
            index += 1
    active_report = previous.get('report', '') if isinstance(previous, dict) else ''
    if isinstance(active_report, str) and _inside(active_report, slots[0]):
        return slots[1]
    return slots[0]


def _atomic_write_json(path, value):
    path = Path(path)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2))
    temporary.replace(path)


def _compact_directory_summary(discovery, limit=24):
    """Keep directory-level evidence without retaining the file inventory."""
    rows = discovery.get('directory_summary')
    if not isinstance(rows, list):
        return {'rows': [], 'total_count': None, 'omitted_count': None,
                'omitted_logical_bytes': None, 'omitted_allocated_bytes': None,
                'path_digest': None, 'state_digest': None, 'status': '未记录'}
    ordered = sorted((row for row in rows if isinstance(row, dict)),
                     key=lambda row: int(row.get('logical_bytes') or 0), reverse=True)
    shown = []
    for row in ordered[:limit]:
        shown.append({key: row.get(key) for key in (
            'path', 'file_count', 'path_count', 'hard_link_path_count', 'large_file_count',
            'logical_bytes', 'logical_size', 'allocated_bytes', 'allocated_size',
            'codex_file_count', 'codex_logical_bytes', 'codex_allocated_bytes',
            'project_keys', 'source_roots', 'project_totals', 'codex_related',
            'project_key', 'source_root', 'source_status', 'evidence_status', 'evidence_error', 'association_status', 'origin_state',
            'runtime_mapping_id', 'app_id', 'purpose', 'activity_status', 'disposition_class',
            'planned_disposition_class', 'coverage_status', 'suggested_disposition',
            'retention_note', 'recovery_cost', 'reclaimable_bytes',
            'reclaimable_size', 'source_evidence', 't1_hint',
            'trash_paths',
        )})
    omitted = ordered[limit:]
    allocated_values = [row.get('allocated_bytes') for row in omitted]
    path_digest = hashlib.sha256(
        '\0'.join(sorted(str(row.get('path', '')) for row in ordered)).encode('utf-8')
    ).hexdigest() if ordered else None
    state_payload = [
        {
            key: row.get(key, '未记录')
            for key in ('path', 'project_keys', 'source_roots', 'project_key', 'source_root', 'source_status',
                        'evidence_status', 'association_status', 'origin_state', 'runtime_mapping_id',
                        'coverage_status')
        }
        for row in ordered
    ]
    state_payload.sort(key=lambda row: tuple(str(row.get(key, '')) for key in (
        'path', 'project_key', 'source_root', 'source_status', 'evidence_status',
        'origin_state', 'runtime_mapping_id', 'coverage_status')))
    state_digest = hashlib.sha256(
        json.dumps(state_payload, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    ).hexdigest() if state_payload else None
    return {
        'rows': shown,
        'total_count': len(ordered),
        'omitted_count': len(omitted),
        'omitted_logical_bytes': sum(int(row.get('logical_bytes') or 0) for row in omitted),
        'omitted_allocated_bytes': None if any(value is None for value in allocated_values) else sum(int(value or 0) for value in allocated_values),
        'path_digest': path_digest,
        'state_digest': state_digest,
        'status': '已记录',
    }


def _comparison_signature(coverage, directory_summary_meta):
    stages = coverage.get('stages') if isinstance(coverage, dict) else None
    return {
        'stages': {key: (stages or {}).get(key, '未记录') for key in (
            'traversal', 'source-extraction', 'project-association', 'test-analysis',
            'vm-dependencies', 'type-identification',
        )},
        'directory_summary_coverage': coverage.get('directory_summary_coverage', '未记录') if isinstance(coverage, dict) else '未记录',
        'runtime_mapping_count': coverage.get('runtime_mapping_count', '未记录') if isinstance(coverage, dict) else '未记录',
        'runtime_mapping_current_count': coverage.get('runtime_mapping_current_count', '未记录') if isinstance(coverage, dict) else '未记录',
        'directory_summary_count': directory_summary_meta.get('total_count', '未记录'),
        'directory_summary_path_digest': directory_summary_meta.get('path_digest', '未记录'),
        'directory_summary_state_digest': directory_summary_meta.get('state_digest', '未记录'),
        'scan_roots': sorted(coverage.get('roots', [])) if isinstance(coverage, dict) else [],
        'scope_complete': coverage.get('scope_complete') if isinstance(coverage, dict) else None,
        'coverage_complete': coverage.get('coverage_complete') if isinstance(coverage, dict) else None,
        'cleanup_plan_complete': coverage.get('cleanup_plan_complete') if isinstance(coverage, dict) else None,
        'acceptance_passed': coverage.get('acceptance_passed') if isinstance(coverage, dict) else None,
        'budget_exhausted': coverage.get('budget_exhausted') if isinstance(coverage, dict) else None,
        'runtime_mapping_ids': sorted(coverage.get('runtime_mapping_ids', [])) if isinstance(coverage, dict) else [],
        'runtime_mapping_state_digest': coverage.get('runtime_mapping_state_digest', '未记录') if isinstance(coverage, dict) else '未记录',
    }


def _coverage_change(previous, current):
    if not isinstance(previous, dict) or previous.get('status') != 'completed':
        return {'status': '未比较', 'reason': '没有可用的上一份成功摘要'}
    old_signature = previous.get('coverage', {}).get('comparison_signature') if isinstance(previous.get('coverage'), dict) else None
    new_signature = current.get('coverage', {}).get('comparison_signature') if isinstance(current.get('coverage'), dict) else None
    if not old_signature or not new_signature:
        return {'status': '新增覆盖', 'reason': '上一份摘要未记录目录或来源覆盖签名'}
    if old_signature != new_signature:
        return {'status': '覆盖变化', 'reason': '目录、来源映射或阶段状态发生变化'}
    return {'status': '覆盖未变化', 'reason': '目录、来源映射和必要阶段状态一致'}



def _recover_partial_measurement(pending, home, health, error):
    """Preserve measured capacity when the final report stage times out.

    The scanner writes its JSON before building the large HTML report.  A
    timeout at that point must not erase the useful capacity result or replace
    the last successful daily summary.  The recovered record remains failed
    for execution status, while its measurement and plain-language report are
    explicitly marked partial.
    """
    pending = Path(pending)
    data_path = pending / 'work/storage-analysis-live.json'
    if not data_path.exists():
        return False
    try:
        data = json.loads(data_path.read_text())
        discovery = data.get('large_file_discovery') or {}
        if not isinstance(discovery, dict):
            return False
    except (OSError, ValueError, TypeError, UnicodeError):
        return False

    coverage = dict(discovery.get('coverage') or {})
    compact_keys = {'roots', 'runtime_mapping_ids'}
    coverage = {
        key: value for key, value in coverage.items()
        if not isinstance(value, list) or key in compact_keys
    }
    health['partial_data_status'] = '已测得容量；本轮收尾未完成'
    health['partial_data_path'] = str(data_path)
    health['run_completion'] = 'timed-out-after-measurement'
    health['totals'] = discovery.get('totals') or {}
    health['usage_summary'] = discovery.get('usage_summary') or {}
    health['coverage'] = coverage
    stages = coverage.get('stages') or {}
    capacity_complete = (
        stages.get('traversal') == 'complete'
        and coverage.get('scope_complete') is True
        and coverage.get('coverage_complete') is True
        and coverage.get('budget_exhausted') is not True
        and health['totals'].get('scanned_logical_bytes') is not None
    )
    health['capacity_status'] = 'complete' if capacity_complete else 'partial'
    health['measurement_status'] = 'complete' if capacity_complete else 'partial'
    health['source_status'] = 'complete' if all(
        stages.get(stage) == 'complete'
        for stage in ('source-extraction', 'project-association')
    ) else 'partial'
    health['analysis_status'] = 'complete' if all(
        stages.get(stage) == 'complete'
        for stage in ('test-analysis', 'vm-dependencies', 'type-identification')
    ) else 'partial'
    health['cleanup_status'] = '只读；未授权任何删除或迁移'
    try:
        health['free_bytes'] = shutil.disk_usage(home).free
    except OSError:
        health['free_bytes'] = None
    report_payload = dict(data)
    report_payload.update({
        'free_bytes': health['free_bytes'],
        'scan_total_elapsed_seconds': data.get('scan_elapsed_seconds'),
        'checked_at': health.get('checked_at'),
        'comparison': {'coverage_change': '本轮未完成，暂不比较'},
    })
    health['chat_report'] = render_chat_report(report_payload)
    output_dir = pending / 'outputs'
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        partial_report = output_dir / 'codex-storage-cleanup-partial.md'
        partial_report.write_text(
            health['chat_report']
            + '\n\n本轮检查没有完成最后的报告收尾：'
            + str(error)
            + '。上面的容量是已经实际读到的结果，覆盖不完整的部分没有按零计算。\n',
            encoding='utf-8',
        )
        health['partial_report'] = str(partial_report)
    except OSError as write_error:
        health['partial_report_error'] = str(write_error)
    return True

def scan_command(home, workspace, budget_seconds=1200):
    workspace = Path(workspace)
    return [sys.executable, str(SCANNER), '--home', str(home), '--workspace', str(workspace),
            '--scan-mode', 'full', '--no-inventory', '--budget-seconds', str(budget_seconds)]


def run_check(home, workspace, budget=1200):
    started = time.monotonic()
    scan_budget.start(budget)
    workspace = Path(workspace).absolute()
    account = pwd.getpwuid(os.getuid())
    system_home = Path(account.pw_dir).absolute()
    if account.pw_name != 'mac' or system_home != Path('/Users/mac') or Path(home).absolute() != system_home:
        return {
            'status': 'failed',
            'reason': f'系统账号核验不匹配；仅允许 mac:/Users/mac，实际为 {account.pw_name}:{system_home}',
            'inspection_only': True,
            'trash_paths': [],
        }
    workspace.mkdir(parents=True, exist_ok=True)
    with (workspace / 'health-run.lock').open('a') as lease:
        try:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {'status': 'skipped', 'reason': '同工作目录已有检查正在运行', 'inspection_only': True, 'trash_paths': []}
        return _run_check(home, workspace, budget, started=started)


def _run_check(home, workspace, budget=1200, *, started=None):
    if started is None:
        started = time.monotonic()
        scan_budget.start(budget)
    home, workspace = Path(home).absolute(), Path(workspace).absolute()
    workspace.mkdir(parents=True, exist_ok=True)
    latest = workspace / 'health-latest.json'
    previous, previous_error = _read_json(latest, dict)
    history_path = workspace / 'health-history.json'
    history, history_error = _read_json(history_path, list)
    history = history or []
    summary_error = previous_error or (_validate_summary(previous) if previous is not None else None)
    history_item_errors = []
    valid_history = []
    for item in history:
        error = _validate_summary(item)
        if error:
            history_item_errors.append(error)
        else:
            valid_history.append(item)
    if history_item_errors and not history_error:
        history_error = f'历史中有 {len(history_item_errors)} 条记录无效'
    pending = _select_pending_workspace(workspace, previous, valid_history,
                                        summary_error, history_error)
    health = {'checked_at': datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat(),
              'home': str(home), 'inspection_only': True, 'trash_paths': [],
              'complete_content_verification': False, 'budget_seconds': budget}
    checkpoint = workspace / 'run-state.json'
    try:
        _atomic_write_json(checkpoint, {
            'status': 'running', 'started_at': health['checked_at'],
            'home': str(home), 'workspace': str(workspace),
            'last_success': previous.get('checked_at') if isinstance(previous, dict) else None,
        })
    except (OSError, TypeError, ValueError):
        pass
    if summary_error:
        health['previous_summary_status'] = 'invalid'
        health['previous_summary_error'] = summary_error
    elif previous is None:
        health['previous_summary_status'] = 'missing'
    else:
        health['previous_summary_status'] = 'valid'
    if history_error:
        health['history_status'] = 'invalid-or-partial'
        health['history_error'] = history_error
    else:
        health['history_status'] = 'valid' if history else 'missing'
    if history_item_errors:
        health['history_invalid_record_count'] = len(history_item_errors)
    valid_previous_success = (_valid_summary(previous) and previous.get('status') == 'completed' and
                              (previous.get('home') is None or previous.get('home') == str(home)))
    try:
        remaining = scan_budget.remaining()
        if remaining is None or remaining <= 0:
            raise scan_budget.ScanBudgetExceeded('日报检查超过共享扫描预算', 'daily-runner')
        result = bounded_process.run(
            scan_command(home, pending, max(int(remaining), 1)),
            timeout=remaining,
            terminate_group=True,
        )
        if result.returncode:
            raise RuntimeError('检查进程失败：' + str(result.returncode) + ' ' + (result.stderr or '')[-1000:])
        data = json.loads((pending / 'work/storage-analysis-live.json').read_text())
        discovery = data['large_file_discovery']
        metrics = json.loads((pending / 'work/run-metrics.json').read_text())
        coverage = discovery.get('coverage') or {}
        if (
            coverage.get('scope_complete') is not True
            or coverage.get('coverage_complete') is not True
            or coverage.get('cleanup_plan_complete') is not True
            or coverage.get('acceptance_passed') is not True
            or coverage.get('budget_exhausted') is True
            or metrics.get('total_elapsed_seconds', budget + 1) > budget
            or metrics.get('report_completed') is not True
            or metrics.get('acceptance_passed') is not True
            or time.monotonic() - started > budget
        ):
            raise RuntimeError('范围、覆盖或 1200 秒预算验收未通过；日报状态标为失败')
        health.update(status='completed', totals=discovery['totals'], coverage=discovery['coverage'],
                      cleanup_options=data['cleanup_options'], scan_elapsed_seconds=data.get('scan_elapsed_seconds'),
                      report=str(pending / 'outputs/codex-storage-cleanup-report.html'))
        health['usage_summary'] = discovery.get('usage_summary') or {}
        health['scan_total_elapsed_seconds'] = metrics['total_elapsed_seconds']
        explanation = discovery.get('purpose_analysis') or {}
        health['purpose_analysis'] = {key: explanation.get(key) for key in
                                      ('status', 'target_count', 'counts', 'elapsed_seconds', 'failure',
                                       'phase_status', 'budget_exhausted', 'item_timeout_seconds', 'worker_count')}
        directory_meta = _compact_directory_summary(discovery)
        health['directory_summary'] = directory_meta['rows']
        health['directory_summary_meta'] = {key: value for key, value in directory_meta.items() if key != 'rows'}
        # Keep compact stage/count information, not path/event inventories.
        compact_list_keys = {'roots', 'runtime_mapping_ids'}
        health['coverage'] = {key: value for key, value in health['coverage'].items()
                              if not isinstance(value, list) or key in compact_list_keys}
        health['coverage']['comparison_signature'] = _comparison_signature(
            health['coverage'], directory_meta)
        health['coverage_change'] = _coverage_change(previous, health)
        if isinstance(previous, dict) and previous.get('status') == 'completed' and previous.get('home') == str(home):
            before = previous.get('totals', {}).get('scanned_allocated_bytes')
            now = health['totals'].get('scanned_allocated_bytes')
            comparable = (previous.get('coverage', {}).get('stages', {}).get('traversal') == 'complete' and
                          health['coverage']['stages'].get('traversal') == 'complete' and
                          health['coverage_change'].get('status') == '覆盖未变化' and
                          health['directory_summary_meta'].get('status') == '已记录')
            health['allocated_delta_bytes'] = now - before if comparable and now is not None and before is not None else None
            health['delta_comparable'] = comparable
        stages = health['coverage'].get('stages', {})
        capacity_complete = (stages.get('traversal') == 'complete' and
                             health['coverage'].get('scope_complete') is True and
                             health['coverage'].get('coverage_complete') is True and
                             health['coverage'].get('budget_exhausted') is not True and
                             health['totals'].get('scanned_logical_bytes') is not None)
        health['capacity_status'] = 'complete' if capacity_complete else 'partial'
        health['source_status'] = 'complete' if all(stages.get(stage) == 'complete' for stage in (
            'source-extraction', 'project-association')) else 'partial'
        health['analysis_status'] = 'complete' if all(stages.get(stage) == 'complete' for stage in (
            'test-analysis', 'vm-dependencies', 'type-identification')) else 'partial'
        health['cleanup_status'] = '只读；未授权任何删除或迁移'
        health['measurement_status'] = 'complete' if capacity_complete else 'partial'
        health['free_bytes'] = shutil.disk_usage(home).free
        previous_usage = (previous or {}).get('usage_summary') or {}
        current_usage = health.get('usage_summary') or {}
        current_codex = current_usage.get('codex_logical_bytes')
        previous_codex = previous_usage.get('codex_logical_bytes')
        health['comparison'] = {
            'codex_bytes_delta': (current_codex - previous_codex
                                  if isinstance(current_codex, int) and isinstance(previous_codex, int)
                                  else None),
            'coverage_change': health['coverage_change'].get('status'),
        }
        report_payload = dict(data)
        report_payload.update({
            'free_bytes': health['free_bytes'],
            'scan_total_elapsed_seconds': health['scan_total_elapsed_seconds'],
            'checked_at': health['checked_at'],
            'comparison': health['comparison'],
        })
        health['chat_report'] = render_chat_report(report_payload)
        try:
            _atomic_write_json(checkpoint, {
                'status': 'completed', 'finished_at': health['checked_at'],
                'home': str(home), 'workspace': str(workspace),
                'report': health['report'],
            })
        except (OSError, TypeError, ValueError):
            pass
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.TimeoutExpired) as error:
        health.update(status='failed', reason=str(error), previous_success_preserved=valid_previous_success)
        _recover_partial_measurement(pending, home, health, error)
        try:
            _atomic_write_json(checkpoint, {
                'status': 'failed', 'finished_at': health['checked_at'],
                'home': str(home), 'workspace': str(workspace), 'reason': str(error),
                'resume_from': str(pending / 'work'),
            })
        except (OSError, TypeError, ValueError):
            pass
    health['elapsed_seconds'] = round(time.monotonic() - started, 3)
    if health['status'] == 'failed':
        health.setdefault('previous_success_preserved', valid_previous_success)
    # Keep the compact coverage summary for trend/RCA review. The coverage
    # value was already stripped of path/event lists above, so this does not
    # turn the history file into an inventory; it preserves stage state,
    # gap counts and timings across daily checks.
    history_entry = {key: value for key, value in health.items() if key != 'cleanup_options'}
    persistence_errors = []
    try:
        # Only this runner's generated summaries are replaced; no user data pruning.
        target = latest if health['status'] == 'completed' else workspace / 'health-last-failure.json'
        _atomic_write_json(target, health)
    except (OSError, TypeError, ValueError) as error:
        persistence_errors.append(f'摘要写入失败：{error}')
    try:
        _atomic_write_json(history_path, (valid_history + [history_entry])[-30:])
    except (OSError, TypeError, ValueError) as error:
        persistence_errors.append(f'历史写入失败：{error}')
    if persistence_errors:
        health['status'] = 'failed'
        health['persistence_errors'] = persistence_errors
        health['reason'] = '；'.join(persistence_errors)
        health['previous_success_preserved'] = valid_previous_success
        try:
            _atomic_write_json(workspace / 'health-last-failure.json', health)
        except (OSError, TypeError, ValueError):
            pass
    return health


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', type=Path, default=Path.home())
    parser.add_argument('--workspace', type=Path, default=DEFAULT_WORKSPACE)
    parser.add_argument('--budget-seconds', type=int, default=1200)
    args = parser.parse_args()
    if args.budget_seconds < 1:
        parser.error('检查预算必须大于零')
    account = pwd.getpwuid(os.getuid())
    if account.pw_name != 'mac' or Path(account.pw_dir).absolute() != Path('/Users/mac'):
        parser.error('此清理技能仅允许在系统账号 mac、home /Users/mac 下运行')
    if args.home.expanduser().absolute() != Path(account.pw_dir).absolute():
        parser.error('--home 必须与系统账号资料确认的 /Users/mac 一致')
    if str(args.workspace).startswith('/Volumes/T1/'):
        volume = Path('/Volumes/T1')
        if not volume.is_mount() or not volume.is_dir() or not os.access(volume, os.W_OK):
            parser.error('T1 未挂载或不可写；没有创建替代本地工作目录')
    health = run_check(args.home, args.workspace, args.budget_seconds)
    print(json.dumps(health, ensure_ascii=False, indent=2))
    return 0 if health['status'] in ('completed', 'skipped') else 1


if __name__ == '__main__':
    raise SystemExit(main())
