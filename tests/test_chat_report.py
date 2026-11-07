from pathlib import Path
import sys
from unittest import TestCase

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from chat_report import option_totals, render_chat_report


class ChatReportTests(TestCase):
    def test_partial_usage_is_visible_in_the_three_report_tables(self):
        report = render_chat_report({
            'status': 'failed',
            'items': [],
            'large_file_discovery': {
                'enabled': True,
                'usage_summary': {
                    'codex_logical_bytes': 800_000_000,
                    'locations': [{'label': 'Library/Application Support/Pet Studio', 'logical_bytes': 870_000_000}],
                    'projects': [{'project_key': 'Pet Studio', 'logical_bytes': 870_000_000}],
                },
                'coverage': {
                    'coverage_complete': False, 'scope_complete': True,
                    'gap_count': 12, 'error_count': 4,
                    'stages': {'traversal': 'complete'},
                },
            },
        })
        self.assertIn('### 1. 空间变化', report)
        self.assertIn('### 2. 增长来源与已知占用', report)
        self.assertIn('### 3. 清理建议', report)
        self.assertIn('800.00 MB（部分测量）', report)
        self.assertIn('Library/Application Support/Pet Studio', report)
        self.assertIn('Pet Studio', report)
        self.assertIn('12 个缺口', report)
        self.assertIn('缺口不按零计算', report)
        self.assertIn('整体候选总量未知', report)
        self.assertNotIn('没有能直接确认可以清理的内容', report)
        self.assertNotIn('目录级汇总', report)
        self.assertNotIn('文件数', report)

    def test_missing_usage_is_reported_without_filling_zero(self):
        report = render_chat_report({
            'items': [],
            'status': 'failed',
            'reason': 'scanner failed before producing measurements',
            'large_file_discovery': {
                'enabled': True,
                'totals': {},
                'coverage': {},
            },
        })
        self.assertIn('| Codex 逻辑占用 | 未记录 | 未测 | 未比较 |', report)
        self.assertIn('未取得明细', report)
        self.assertIn('未知（候选清单不完整；本轮没有可展示的逐项候选证据；整体候选总量未知）', report)
        self.assertIn('scanner failed before producing measurements', report)
        self.assertNotIn('0 B', report)

    def test_alternative_plan_includes_keepers_without_expanding_deletion(self):
        def build(path, size, state, priority):
            return dict(path=path, size_bytes=size, active=state, review_priority=priority,
                        source_entries=['src/main.rs'], rebuild_basis='verified', trash_paths=[])
        old = build('/old', 10_000_000_000, False, 'delete-old-build')
        latest = build('/latest', 20_000_000_000, None, 'old-artifact')
        busy = build('/busy', 5_000_000_000, True, 'old-artifact')
        parent = dict(path='/workspace', size_bytes=100_000_000_000, tier='protected')
        old['default_action'] = 'direct-delete'
        latest['default_action'] = 'retain'
        busy['default_action'] = 'retain'
        items = [old, latest, busy, parent, dict(old)]
        totals = option_totals(items)
        self.assertEqual(totals['keep_latest_bytes'], 10_000_000_000)
        self.assertEqual(totals['all_build_bytes'], 35_000_000_000)
        self.assertEqual(totals['all_build_usage_unknown_bytes'], 20_000_000_000)
        self.assertEqual(totals['all_build_in_use_bytes'], 5_000_000_000)
        self.assertEqual(latest['trash_paths'], [])
        report = render_chat_report({'items': items})
        self.assertIn('10.00 GB', report)
        self.assertIn('当前清单小计 10.00 GB / 1 项；整体候选总量未知', report)

    def test_partial_candidates_list_paths_evidence_and_confirmed_subtotals(self):
        row = {
            'action': 'direct-delete', 'path': '/cache/old-index',
            'logical_bytes': 1_250_000_000, 'artifact_type': '可再生索引缓存',
            'reason': '索引可由已确认的数据源重新生成',
            'evidence_paths': ['/Users/mac/.codex/state/index-manifest.json'],
        }
        report = render_chat_report({
            'status': 'failed', 'items': [],
            'cleanup_plan': {'capacity': {
                'candidate_entries': [row, dict(row)],
                'candidate_entries_complete': False,
                'unmeasured_paths': ['/cache/unreadable'],
            }},
            'large_file_discovery': {'coverage': {
                'scope_complete': True, 'coverage_complete': False,
                'cleanup_plan_complete': False, 'acceptance_passed': False,
                'gap_count': 2, 'error_count': 1,
            }},
        })
        self.assertIn('/cache/old-index', report)
        self.assertIn('1.25 GB', report)
        self.assertIn('索引可由已确认的数据源重新生成', report)
        self.assertIn('部分清单已确认小计 1.25 GB / 1 项；该类全量未知', report)
        self.assertIn('部分清单已确认小计 1.25 GB / 1 项；整体候选总量未知', report)
        self.assertNotIn('0.00 GB / 0 项', report)

    def test_partial_empty_candidate_ledger_never_becomes_zero(self):
        report = render_chat_report({
            'status': 'failed', 'items': [],
            'cleanup_options': {'keep_latest_bytes': 0, 'backup_then_delete_bytes': 0},
            'cleanup_plan': {'capacity': {
                'candidate_entries': [], 'candidate_entries_complete': False,
            }},
            'large_file_discovery': {'coverage': {
                'scope_complete': True, 'coverage_complete': False,
                'cleanup_plan_complete': False, 'acceptance_passed': False,
                'gap_count': 2011, 'error_count': 10239,
            }},
        })
        self.assertIn('候选总量 | - | 未知（候选清单不完整；本轮没有可展示的逐项候选证据；整体候选总量未知）', report)
        self.assertIn('整体候选总量未知', report)
        self.assertIn('2,011 个缺口', report)
        self.assertNotIn('0.00 GB / 0 项', report)
        self.assertNotIn('完整扫描确认本轮没有', report)

    def test_complete_candidates_have_category_subtotals_and_deduplicated_total(self):
        entries = [
            {'action': 'direct-delete', 'path': '/build/old', 'logical_bytes': 2_000_000_000,
             'artifact_type': '旧构建', 'reason': '源码和完成产物均已核实',
             'rebuild_basis': '可由当前源码重新构建'},
            {'action': 'backup-then-delete', 'path': '/archive/old.jsonl', 'logical_bytes': 500_000_000,
             'artifact_type': '归档会话', 'reason': '超过保留期且无受支持引用',
             'retention_evidence': {'status': 'verified'}},
            {'action': 'direct-delete', 'path': '/build/old', 'logical_bytes': 2_000_000_000,
             'artifact_type': '旧构建', 'reason': '源码和完成产物均已核实',
             'rebuild_basis': '可由当前源码重新构建'},
        ]
        report = render_chat_report({
            'status': 'completed', 'items': [],
            'cleanup_plan': {'capacity': {
                'candidate_entries': entries, 'candidate_entries_complete': True,
            }},
            'large_file_discovery': {'coverage': {
                'scope_complete': True, 'coverage_complete': True,
                'cleanup_plan_complete': True, 'acceptance_passed': True,
                'budget_exhausted': False,
            }},
        })
        self.assertIn('/build/old', report)
        self.assertIn('/archive/old.jsonl', report)
        self.assertIn('建议安全清理小计 | - | 2.00 GB / 1 项', report)
        self.assertIn('先备份再删小计 | - | 0.50 GB / 1 项', report)
        self.assertIn('候选总量 | - | 2.50 GB / 2 项', report)
        self.assertIn('完整扫描通过验收', report)

    def test_candidate_without_single_item_evidence_keeps_total_unknown(self):
        report = render_chat_report({
            'status': 'completed', 'items': [],
            'cleanup_plan': {'capacity': {
                'candidate_entries': [{
                    'action': 'direct-delete', 'path': '/cache/unknown',
                    'logical_bytes': 5_000_000,
                    'artifact_type': '缓存',
                }],
                'candidate_entries_complete': True,
            }},
            'large_file_discovery': {'coverage': {
                'scope_complete': True, 'coverage_complete': True,
                'cleanup_plan_complete': True, 'acceptance_passed': True,
                'budget_exhausted': False,
            }},
        })
        self.assertIn('未展示 1 条记录', report)
        self.assertIn('整体候选总量未知', report)
        self.assertNotIn('| 建议安全清理 | [`/cache/unknown`]', report)

    def test_complete_zero_candidates_is_distinct_from_failed_zero_placeholder(self):
        report = render_chat_report({
            'status': 'completed',
            'items': [],
            'cleanup_options': {},
            'large_file_discovery': {
                'enabled': True,
                'usage_summary': {'codex_logical_bytes': 1_000_000_000},
                'coverage': {
                    'scope_complete': True, 'coverage_complete': True,
                    'cleanup_plan_complete': True, 'acceptance_passed': True,
                    'budget_exhausted': False,
                },
            },
        })
        self.assertIn('完整并通过验收', report)
        self.assertIn('0.00 GB / 0 项', report)
        self.assertNotIn('不等于 0', report)

    def test_user_outputs_are_not_disposable_cache(self):
        items = [dict(path='/images', artifact_type='生成图片与用户输出', size_bytes=100),
                 dict(path='/sessions', artifact_type='当前/普通会话', size_bytes=200),
                 dict(path='/cache', tier='regenerable', size_bytes=10)]
        totals = option_totals(items)
        self.assertEqual(totals['secondary_cache_bytes'], 10)
        self.assertEqual(totals['session_bytes'], 200)
        self.assertEqual(totals['image_output_bytes'], 100)
        self.assertEqual(totals['all_build_bytes'], 0)
