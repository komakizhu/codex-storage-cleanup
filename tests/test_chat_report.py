from pathlib import Path
import sys
from unittest import TestCase

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from chat_report import option_totals, render_chat_report


class ChatReportTests(TestCase):
    def test_usage_summary_is_visible_in_plain_language(self):
        report = render_chat_report({
            'items': [],
            'large_file_discovery': {
                'enabled': True,
                'usage_summary': {
                    'codex_logical_bytes': 800_000_000,
                    'locations': [{'label': 'Library/Application Support/Pet Studio', 'logical_bytes': 870_000_000}],
                    'projects': [{'project_key': 'Pet Studio', 'logical_bytes': 870_000_000}],
                },
                'coverage': {'coverage_complete': False, 'stages': {'traversal': 'complete'}},
            },
        })
        self.assertIn('Codex 总占用：800.00 MB', report)
        self.assertIn('Library/Application Support/Pet Studio', report)
        self.assertIn('Pet Studio', report)
        self.assertIn('有些位置这次没能完整读到', report)
        self.assertNotIn('目录级汇总', report)
        self.assertNotIn('文件数', report)

    def test_missing_usage_is_reported_without_filling_zero(self):
        report = render_chat_report({
            'items': [],
            'large_file_discovery': {
                'enabled': True,
                'totals': {},
                'coverage': {},
            },
        })
        self.assertIn('Codex 总占用：未记录', report)
        self.assertIn('暂时没有按位置拆出的记录', report)
        self.assertNotIn('0 B', report)

    def test_alternative_plan_includes_keepers_without_expanding_deletion(self):
        def build(path, size, state, priority):
            return dict(path=path, size_bytes=size, active=state, review_priority=priority,
                        source_entries=['src/main.rs'], rebuild_basis='verified', trash_paths=[])
        old = build('/old', 10_000_000_000, False, 'delete-old-build')
        latest = build('/latest', 20_000_000_000, None, 'old-artifact')
        busy = build('/busy', 5_000_000_000, True, 'old-artifact')
        parent = dict(path='/workspace', size_bytes=100_000_000_000, tier='protected')
        items = [old, latest, busy, parent, dict(old)]
        totals = option_totals(items)
        self.assertEqual(totals['keep_latest_bytes'], 10_000_000_000)
        self.assertEqual(totals['all_build_bytes'], 35_000_000_000)
        self.assertEqual(totals['all_build_usage_unknown_bytes'], 20_000_000_000)
        self.assertEqual(totals['all_build_in_use_bytes'], 5_000_000_000)
        self.assertEqual(latest['trash_paths'], [])
        report = render_chat_report({'items': items})
        self.assertIn('已核实旧构建默认直接删除', report)
        self.assertIn('有 5.00 GB 构建仍在使用', report)
        self.assertIn('有 20.00 GB 构建还没确认是否在用', report)

    def test_user_outputs_are_not_disposable_cache(self):
        items = [dict(path='/images', artifact_type='生成图片与用户输出', size_bytes=100),
                 dict(path='/sessions', artifact_type='当前/普通会话', size_bytes=200),
                 dict(path='/cache', tier='regenerable', size_bytes=10)]
        totals = option_totals(items)
        self.assertEqual(totals['secondary_cache_bytes'], 10)
        self.assertEqual(totals['session_bytes'], 200)
        self.assertEqual(totals['image_output_bytes'], 100)
        self.assertEqual(totals['all_build_bytes'], 0)
