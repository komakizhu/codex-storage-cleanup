"""Bounded, read-only investigation of unresolved storage findings.

Only structural metadata is exported: never file contents or chat text. An
explanation cannot resolve a coverage failure or grant deletion permission.
"""
import collections
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time

import bounded_process

SAMPLE_BYTES = 131072
PURPOSE_ITEM_TIMEOUT_SECONDS = 5.0
PURPOSE_WORKER_COUNT = 4
PURPOSE_DEFAULT_BUDGET_SECONDS = 120.0


def safe_stat(path, home):
    """Reject scope escapes, links in any component and mounted volumes."""
    home, path = Path(os.path.abspath(home)), Path(os.path.abspath(path))
    relative = path.relative_to(home)
    base = home.lstat()
    if stat.S_ISLNK(base.st_mode):
        raise ValueError('扫描根是链接')
    current = home
    value = base
    for part in relative.parts:
        current /= part
        value = current.lstat()
        if stat.S_ISLNK(value.st_mode):
            raise ValueError('路径含符号链接，未跟随')
        if value.st_dev != base.st_dev:
            raise ValueError('路径位于其他挂载卷，未读取')
    return value


def explain_one(diagnostic, home, profile=None):
    path = Path(diagnostic['path'])
    row = {'path': str(path), 'code': diagnostic['code'],
           'purpose': '用途仍不明确', 'confidence': 'unknown',
           'recommendation': '需要进一步核实', 'evidence': [], 'remaining_questions': [],
           'inspection_status': 'completed', 'coverage_resolved': False,
           'usage_status': '未检查，不能确认当前闲置',
           'discovery_only': True, 'discovery_origin': 'full-discovery', 'trash_paths': []}
    if profile:
        row['project_key'] = profile.get('project_key')
        row['source_root'] = profile.get('source_root')
        row['completion_status'] = profile.get('completion_status', 'unknown')
        row['run_ids'] = profile.get('run_ids') or []
        row['roles'] = {key: len(value) for key, value in (profile.get('artifact_roles') or {}).items()}
        row['references'] = profile.get('references') or []
        row['run_identity_counts'] = profile.get('run_identity_counts') or []
        if profile.get('has_evidence'):
            row.update(purpose='执行批次及其输入、结果或运行记录', confidence='evidence', recommendation='保留')
            row['evidence'].append('已有运行身份和状态/产物证据；项目与批次仍分别判断')
        if len(row['run_ids']) > 1:
            row['remaining_questions'].append('同一目录包含多个运行身份，需分别核对，不能把整个目录当作一个已完成批次')
        for counts in row['run_identity_counts']:
            expected, completed = counts.get('expected'), counts.get('completed')
            if expected is None or completed is None:
                row['remaining_questions'].append('运行计数缺失，文件存在不能证明运行完成')
            elif completed != expected:
                row['remaining_questions'].append('完成计数与预期计数不一致')
        if row['references']:
            row['remaining_questions'].append('该项引用其他路径；清理前需同时核实引用关系和使用状态')
    changed_during_read = False
    try:
        before = safe_stat(path, home)
        row['logical_bytes'] = before.st_size if stat.S_ISREG(before.st_mode) else None
        row['allocated_bytes'] = before.st_blocks * 512 if stat.S_ISREG(before.st_mode) else None
        if stat.S_ISDIR(before.st_mode):
            names = []
            for attempt in range(3):
                try:
                    names = []
                    with os.scandir(path) as entries:
                        for entry in entries:
                            if len(names) == 128:
                                row['directory_sample_truncated'] = True
                                break
                            names.append(entry.name)
                    break
                except InterruptedError:
                    if attempt == 2:
                        raise
            row['directory_entry_sample'] = names
            row['evidence'].append('重新读取目录成功；仅查看直属成员样本，没有补齐原遍历占用')
        elif stat.S_ISREG(before.st_mode):
            if path.suffix.lower() in {'.json', '.jsonl', '.ndjson'} and row['confidence'] == 'unknown':
                row.update(purpose='结构化记录文件，具体用途仍需结合项目确认', confidence='context')
            fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
            with os.fdopen(fd, 'rb') as stream:
                opened = os.fstat(stream.fileno())
                if not _same_file_state(opened, before):
                    raise ValueError('打开时文件身份变化')
                head = stream.read(SAMPLE_BYTES)
                stream.seek(max(0, before.st_size - SAMPLE_BYTES))
                tail = stream.read(SAMPLE_BYTES)
                after = os.fstat(stream.fileno())
            if not _same_file_state(after, before):
                changed_during_read = True
                row['remaining_questions'].append('读取期间文件变化，结构判断不可作为稳定结论')
            row['sampled_bytes'] = min(before.st_size, SAMPLE_BYTES * 2)
            row['sample_only'] = before.st_size > SAMPLE_BYTES
            row['evidence'].append('只读取限定头尾样本，未导出原文；样本不能证明整个文件格式正确')
            if not head:
                row['evidence'].append('实际文件为零字节，没有可解析记录')
            elif before.st_size <= SAMPLE_BYTES:
                try:
                    value = json.loads(head)
                    row['structure'] = type(value).__name__
                    if isinstance(value, dict):
                        row['top_level_fields'] = list(value)[:64]
                        if any(key in value for key in ('compilerOptions', 'dependencies', 'devDependencies', '$schema')):
                            row.update(purpose='配置或依赖元数据', confidence='evidence', recommendation='保留')
                    elif isinstance(value, list):
                        row['record_count'] = len(value)
                except (ValueError, UnicodeError):
                    stripped = tail.rstrip()
                    row['evidence'].append('样本不能按单个严格 JSON 解析')
                    if stripped and stripped[-1:] not in (b'}', b']'):
                        row['remaining_questions'].append('末尾没有完整 JSON 结束符，可能截断；也可能采用其他记录格式')
            else:
                row['remaining_questions'].append('仅检查大文件头尾，完整记录和格式仍未解析')
            parts = path.relative_to(Path(home)).parts
            if '.cargo' in parts or 'node_modules' in parts:
                row.update(purpose='依赖树中的数据；可能是测试夹具或依赖元数据', confidence='context', recommendation='保留')
                row['evidence'].append('位置属于下载依赖，文件名不能证明它是用户执行结果')
        else:
            row.update(inspection_status='unsupported')
            row['remaining_questions'].append('不是普通文件或目录，未读取')
        relative = path.relative_to(Path(home)).parts
        if len(relative) >= 3 and relative[:2] == ('Library', 'Containers'):
            row['application_identifier'] = relative[2]
            if not profile or not profile.get('has_evidence'):
                row.update(purpose='应用容器中的设置、缓存或临时数据', confidence='context', recommendation='保留')
                row['evidence'].append('容器标识说明归属应用，不能证明文件可重建或已闲置')
        if len(relative) >= 3 and relative[:2] == ('Library', 'Messages'):
            row.update(purpose='消息附件，可能是用户保存的报告', confidence='context', recommendation='保留')
    except (OSError, ValueError) as error:
        row.update(inspection_status='unreadable', read_error=str(error))
        row['remaining_questions'].append('本次仍无法安全读取；原覆盖缺口继续保留')
    if changed_during_read:
        # Content and path context may have been inspected above, but none of
        # it is stable evidence after a concurrent write. Apply this last so
        # later classifiers cannot promote a changed file back to confidence.
        row.update(inspection_status='changed', confidence='unknown',
                   recommendation='需要进一步核实',
                   purpose='文件在读取期间变化，用途仍不确定')
        row['remaining_questions'].append('文件变化使本次内容和上下文判断失效')
    if not row['remaining_questions']:
        row['remaining_questions'].append(diagnostic.get('reason', '用途说明不代表完成状态或可删除性已确认'))
    row['remaining_questions'] = list(dict.fromkeys(row['remaining_questions']))
    return row


def _same_file_state(first, second):
    """Compare metadata that is present on both stat-like objects."""
    for field in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_mode'):
        left, right = getattr(first, field, None), getattr(second, field, None)
        if left is not None and right is not None and left != right:
            return False
    return True


def _fallback_row(target, reason):
    return {
        'path': target['path'], 'code': target['code'], 'purpose': '用途仍未检查',
        'inspection_status': 'unchecked', 'recommendation': '需要进一步核实',
        'remaining_questions': [reason], 'coverage_resolved': False,
        'discovery_only': True, 'discovery_origin': 'full-discovery',
        'trash_paths': [], 'referenced_by': [], 'referenced_by_status': 'unchecked',
    }


def _path_prefixes(path):
    parts = Path(os.path.normpath(path)).parts
    prefixes = []
    for index in range(1, len(parts) + 1):
        prefixes.append(os.path.normpath(os.path.join(*parts[:index])))
    return prefixes


def _build_reference_index(profiles, deadline):
    exact = collections.defaultdict(list)
    descendants = collections.defaultdict(list)
    for profile in profiles:
        source = profile.get('path')
        for reference in profile.get('references') or []:
            if time.monotonic() >= deadline:
                return None, '引用索引达到时间预算，未完成'
            try:
                normalized = os.path.normpath(reference)
                if time.monotonic() >= deadline:
                    return None, '引用索引达到时间预算，未完成'
                if not normalized:
                    continue
                item = {'source_run': source, 'reference': reference}
                exact[normalized].append(item)
                for prefix in _path_prefixes(normalized):
                    if time.monotonic() >= deadline:
                        return None, '引用索引达到时间预算，未完成'
                    descendants[prefix].append(item)
            except (TypeError, ValueError, OSError):
                return None, '引用索引包含无法规范化的路径'
    return {'exact': exact, 'descendants': descendants}, None


def _lookup_references(index, target_path):
    normalized = os.path.normpath(target_path)
    found = []
    seen = set()
    for prefix in _path_prefixes(normalized):
        for item in index['exact'].get(prefix, []):
            key = (item.get('source_run'), item.get('reference'))
            if key not in seen:
                seen.add(key)
                found.append(item)
    for item in index['descendants'].get(normalized, []):
        key = (item.get('source_run'), item.get('reference'))
        if key not in seen:
            seen.add(key)
            found.append(item)
    return found


def _run_target_worker(home, target, profile, item_timeout, deadline):
    if time.monotonic() >= deadline:
        return '', '用途分析总预算已用尽'
    payload = {'home': str(home), 'targets': [target],
               'profiles': {target['path']: profile or {}}}
    try:
        encoded = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        if time.monotonic() >= deadline:
            return '', '用途分析准备阶段达到总预算'
        with tempfile.TemporaryFile() as source:
            source.write(encoded)
            source.seek(0)
            if time.monotonic() >= deadline:
                return '', '用途分析准备阶段达到总预算'
            try:
                result = bounded_process.run(
                    [sys.executable, str(Path(__file__).absolute())], stdin=source,
                    timeout=item_timeout, terminate_group=True)
            except subprocess.TimeoutExpired as error:
                return error.output or '', '该项用途分析达到单项时间预算'
        output = result.stdout or ''
        failure = None if result.returncode == 0 else '用途分析进程失败：' + str(result.returncode)
        return output, failure
    except (OSError, TypeError, ValueError) as error:
        return '', str(error)


def _decode_output(output):
    if isinstance(output, bytes):
        return output.decode('utf-8', errors='replace')
    return output or ''


def analyze(home, diagnostics, profiles, timeout=PURPOSE_DEFAULT_BUDGET_SECONDS):
    targets = [row for row in diagnostics if row.get('severity') == 'error']
    if not targets:
        return {'status': 'completed', 'items': [], 'counts': {}, 'target_count': 0,
                'trash_paths': [], 'phase_status': {'preparation': 'complete',
                'per-item': 'complete', 'reference-analysis': 'complete', 'aggregation': 'complete'}}
    started = time.monotonic()
    deadline = started + max(float(timeout), 0.0)
    # Reuse existing metadata; do not rescan a project tree. Preparation is
    # part of the same deadline as file reads and result aggregation.
    by_path = {}
    fields = ('project_key', 'source_root', 'completion_status', 'run_ids', 'artifact_roles',
              'references', 'run_identity_counts', 'has_evidence')
    for profile in profiles:
        if time.monotonic() >= deadline:
            break
        if not profile.get('path'):
            continue
        context = {key: profile.get(key) for key in fields}
        by_path[profile['path']] = context
        for gap in profile.get('parse_gaps', []):
            by_path.setdefault(gap.get('path'), context)
    preparation_status = 'complete' if time.monotonic() < deadline else 'partial'
    reference_index, reference_failure = _build_reference_index(profiles, deadline)
    reference_status = 'complete' if reference_index is not None else 'partial'
    items_by_key = {}
    failures = []
    budget_exhausted = time.monotonic() >= deadline
    executor = ThreadPoolExecutor(max_workers=PURPOSE_WORKER_COUNT)
    in_flight = {}
    next_index = 0
    try:
        while next_index < len(targets) or in_flight:
            while (next_index < len(targets) and len(in_flight) < PURPOSE_WORKER_COUNT and
                   time.monotonic() < deadline):
                target = targets[next_index]
                remaining = deadline - time.monotonic()
                item_timeout = min(PURPOSE_ITEM_TIMEOUT_SECONDS, max(remaining, 0.001))
                future = executor.submit(_run_target_worker, home, target,
                                         by_path.get(target['path'], {}), item_timeout, deadline)
                in_flight[future] = target
                next_index += 1
            if not in_flight:
                budget_exhausted = next_index < len(targets) or time.monotonic() >= deadline
                break
            remaining = max(deadline - time.monotonic(), 0.0)
            done, _ = wait(in_flight, timeout=remaining, return_when=FIRST_COMPLETED)
            if not done:
                budget_exhausted = True
                break
            for future in done:
                target = in_flight.pop(future)
                try:
                    output, failure = future.result()
                except Exception as error:  # worker failures become visible rows
                    output, failure = '', str(error)
                if failure:
                    failures.append(failure)
                for line in _decode_output(output).splitlines():
                    try:
                        row = json.loads(line)
                        key = (row['code'], row['path'])
                        items_by_key[key] = row
                    except (ValueError, TypeError, KeyError):
                        failures.append('用途分析返回了无法解析的记录')
                if time.monotonic() >= deadline:
                    budget_exhausted = True
                if failure and (target['code'], target['path']) in items_by_key:
                    items_by_key[(target['code'], target['path'])].setdefault('remaining_questions', []).append(failure)
    finally:
        if next_index < len(targets) or in_flight:
            budget_exhausted = True
        for future in in_flight:
            future.cancel()
        executor.shutdown(wait=False, cancel_futures=True)

    aggregation_status = 'complete'
    items = []
    for target in targets:
        aggregation_budget_exhausted = time.monotonic() >= deadline
        if aggregation_budget_exhausted:
            aggregation_status = 'partial'
        key = (target['code'], target['path'])
        row = items_by_key.get(key) or _fallback_row(
            target, '用途分析未在总预算内返回结果' if budget_exhausted else
            (failures[0] if failures else '分析未返回结果'))
        row['trash_paths'] = []
        row['discovery_only'] = True
        row['coverage_resolved'] = False
        if reference_index is None or aggregation_budget_exhausted:
            row['referenced_by'] = []
            row['referenced_by_status'] = 'unchecked'
            row.setdefault('remaining_questions', []).append(
                reference_failure or '总预算已用尽，引用关系未完成检查')
        else:
            try:
                inbound = [item for item in _lookup_references(reference_index, target['path'])
                           if item.get('source_run') != target['path']]
                row['referenced_by'] = inbound
                row['referenced_by_status'] = 'complete'
                if inbound:
                    row.setdefault('remaining_questions', []).append('其他运行记录引用该路径，需核实是否仍被依赖')
                    row['recommendation'] = '保留'
            except (TypeError, ValueError, OSError) as error:
                row['referenced_by'] = []
                row['referenced_by_status'] = 'unchecked'
                row.setdefault('remaining_questions', []).append('引用关系整理失败：' + str(error))
                aggregation_status = 'partial'
        row['remaining_questions'] = list(dict.fromkeys(row.get('remaining_questions', [])))
        items.append(row)
    status = 'partial' if (failures or budget_exhausted or reference_index is None or
                           aggregation_status != 'complete' or any(item.get('inspection_status') == 'unchecked' for item in items)) else 'completed'
    failure = '；'.join(dict.fromkeys(failures)) or reference_failure
    if budget_exhausted and not failure:
        failure = '用途分析总预算已用尽，已返回部分结果'
    return {'status': status, 'failure': failure,
            'elapsed_seconds': round(time.monotonic() - started, 3), 'budget_seconds': timeout,
            'item_timeout_seconds': PURPOSE_ITEM_TIMEOUT_SECONDS,
            'worker_count': PURPOSE_WORKER_COUNT,
            'target_count': len(targets), 'items': items,
            'counts': dict(collections.Counter(row['recommendation'] for row in items)),
            'phase_status': {'preparation': preparation_status, 'per-item': 'partial' if budget_exhausted or failures else 'complete',
                             'reference-analysis': reference_status, 'aggregation': aggregation_status},
            'budget_exhausted': budget_exhausted,
            'discovery_only': True, 'trash_paths': []}


if __name__ == '__main__':
    payload = json.load(sys.stdin)
    for target in payload['targets']:
        row = explain_one(target, payload['home'], payload['profiles'].get(target['path']))
        print(json.dumps(row, ensure_ascii=False), flush=True)
