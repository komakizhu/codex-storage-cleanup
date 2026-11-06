from unittest import TestCase
from unittest.mock import patch
from types import SimpleNamespace
from tempfile import TemporaryDirectory
from pathlib import Path
import json
import subprocess
import sys
import fcntl

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import daily_codex_health as daily
import storage_discovery as discovery


class DailyHealthTests(TestCase):
    def test_directory_summary_is_compact_and_coverage_change_is_not_growth(self):
        with TemporaryDirectory() as temp:
            workspace = Path(temp)
            scan_count = {'value': 0}

            def successful_scan(command, **kwargs):
                scan_count['value'] += 1
                staged = Path(command[command.index('--workspace') + 1])
                work = staged / 'work'
                work.mkdir(parents=True)
                rows = [{
                    'path': str(workspace / ('dir-' + str(index))), 'file_count': 1,
                    'logical_bytes': 1000 - index, 'allocated_bytes': 1000 - index,
                    'logical_size': '1 KB', 'allocated_size': '1 KB',
                    'source_status': 'unknown', 'origin_state': 'unknown',
                    'suggested_disposition': '暂不处理', 'trash_paths': [],
                } for index in range(30)]
                (work / 'storage-analysis-live.json').write_text(json.dumps({
                    'large_file_discovery': {
                        'totals': {'scanned_allocated_bytes': 10},
                        'coverage': {
                            'stages': {'traversal': 'complete', 'source-extraction': 'complete',
                                       'project-association': 'complete'},
                            'coverage_complete': True, 'directory_summary_coverage': 'complete',
                            'runtime_mapping_count': 1, 'runtime_mapping_current_count': scan_count['value'],
                        },
                        'directory_summary': rows,
                    },
                    'cleanup_options': {},
                }))
                (work / 'run-metrics.json').write_text(json.dumps({'total_elapsed_seconds': 1}))
                return SimpleNamespace(returncode=0, stderr='')

            with patch.object(daily.bounded_process, 'run', side_effect=successful_scan):
                first = daily.run_check('/Users/mac2', workspace, budget=1)
            self.assertEqual(len(first['directory_summary']), 24)
            self.assertEqual(first['directory_summary_meta']['omitted_count'], 6)
            self.assertEqual(first['coverage_change']['status'], '未比较')

            with patch.object(daily.bounded_process, 'run', side_effect=successful_scan):
                second = daily.run_check('/Users/mac2', workspace, budget=1)
            self.assertFalse(second['delta_comparable'])
            self.assertEqual(second['allocated_delta_bytes'], None)
            self.assertEqual(second['coverage_change']['status'], '覆盖变化')

    def test_directory_state_change_is_a_coverage_change(self):
        rows = [{
            'path': '/tmp/project-data', 'project_key': None,
            'source_root': None, 'source_status': 'unknown',
            'evidence_status': 'missing', 'origin_state': 'unknown',
            'runtime_mapping_id': None, 'coverage_status': 'partial',
            'logical_bytes': 1, 'allocated_bytes': 1,
        }]
        first_meta = daily._compact_directory_summary({'directory_summary': rows})
        first = daily._comparison_signature({'roots': ['/tmp'], 'runtime_mapping_ids': []}, first_meta)
        rows[0].update(project_key='Pet Studio', source_root='/tmp/Library/Application Support/Pet Studio',
                       source_status='current', evidence_status='mapped-only',
                       origin_state='mapped-project-runtime', runtime_mapping_id='pet-studio',
                       coverage_status='complete')
        second_meta = daily._compact_directory_summary({'directory_summary': rows})
        second = daily._comparison_signature({'roots': ['/tmp'], 'runtime_mapping_ids': []}, second_meta)
        self.assertNotEqual(first['directory_summary_state_digest'], second['directory_summary_state_digest'])
        self.assertNotEqual(first, second)

    def test_test_candidate_routing_checks_each_directory_only_once(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            batch = home / 'project/deep/batch'
            batch.mkdir(parents=True)
            (batch / 'manifest.json').write_text(json.dumps({'run_id':'r', 'status':'completed', 'total':1, 'completed_count':1}))
            for i in range(200):
                (batch / ('data-' + str(i))).write_bytes(b'x')
            inventory = discovery.scan_large_files([home], min_bytes=100)
            with patch.object(discovery, '_safe_is_dir', wraps=discovery._safe_is_dir) as probe:
                profiles = discovery.discover_test_runs(home, [], inventory['files'], inventory['all_files'])
            self.assertEqual(len(profiles), 1)
            self.assertLess(probe.call_count, 20)

    def test_overlapping_check_is_skipped_without_touching_results(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            with (root / 'health-run.lock').open('a') as lease:
                fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with patch.object(daily, '_run_check') as scan:
                    health = daily.run_check(root, root)
            scan.assert_not_called()
            self.assertEqual(health['status'], 'skipped')
            self.assertFalse((root / 'health-latest.json').exists())

    def test_hdiutil_bytes_failure_remains_json_serializable(self):
        with patch.object(discovery.os.sys, 'platform', 'darwin'), patch.object(discovery.bounded_process, 'run', return_value=SimpleNamespace(returncode=1, stderr=b'permission denied')):
            mounted, gaps = discovery._probe_mounted_images()
        self.assertFalse(mounted)
        self.assertIn('permission denied', json.dumps(gaps))

    def test_unknown_vm_package_blocks_member_duplicates(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            package = root / 'example.utm'
            package.mkdir()
            (package / 'config.plist').write_text('invalid plist')
            disk = package / 'disk.qcow2'
            disk.write_bytes(b'QFI\xfb' + b'\x00' * 128)
            files = discovery.scan_large_files([root])['all_files']
            paths = [str(package), *[v['path'] for v in files]]
            with patch.object(discovery, '_probe_mounted_images', return_value=(set(), [])), patch.object(discovery, '_probe_processes', return_value=({p:'not-detected' for p in paths}, [])), patch.object(discovery, '_probe_open_paths', return_value=({p:('not-detected','idle') for p in paths}, [])):
                result = discovery.discover_virtual_machines(root, files)
            self.assertIn(str(disk), result['blocked_duplicate_paths'])
            item = next(v for v in result['items'] if v['path'] == str(disk))
            self.assertTrue(item['duplicate_blocked'])

    def test_daily_command_cannot_delete_or_start_services(self):
        command = daily.scan_command('/Users/mac2', '/example/report')
        self.assertIn('--no-inventory', command)
        self.assertIn('--metadata-first', command)
        self.assertNotIn('--duplicate-hash', command)
        self.assertTrue(command[1].endswith('scan_codex.py'))

    def test_failed_check_preserves_previous_success(self):
        with TemporaryDirectory() as temp:
            workspace = Path(temp)
            previous = {'status': 'completed', 'marker': 'keep'}
            (workspace / 'health-latest.json').write_text(json.dumps(previous))
            with patch.object(daily.bounded_process, 'run', side_effect=subprocess.TimeoutExpired(['scan'], .1)):
                health = daily.run_check(workspace, workspace, budget=.1)
            self.assertEqual(health['status'], 'failed')
            self.assertEqual(json.loads((workspace / 'health-latest.json').read_text()), previous)
            self.assertEqual(health['trash_paths'], [])
            self.assertTrue(health['previous_success_preserved'])

    def test_corrupt_latest_summary_does_not_block_scan_or_failure_record(self):
        with TemporaryDirectory() as temp:
            workspace = Path(temp)
            latest = workspace / 'health-latest.json'
            latest.write_text('{broken')
            with patch.object(daily.bounded_process, 'run', return_value=SimpleNamespace(returncode=2, stderr='scanner failed')) as scanner:
                health = daily.run_check('/Users/mac2', workspace, budget=1)
            self.assertTrue(scanner.called)
            self.assertEqual(health['status'], 'failed')
            self.assertEqual(latest.read_text(), '{broken')
            self.assertTrue((workspace / 'health-last-failure.json').exists())
            self.assertEqual(health['previous_summary_status'], 'invalid')

    def test_unknown_allocation_delta_is_a_valid_summary_value(self):
        self.assertIsNone(daily._validate_summary({
            'status': 'completed', 'allocated_delta_bytes': None,
        }))

    def test_corrupt_history_is_reported_and_replaced_after_success(self):
        with TemporaryDirectory() as temp:
            workspace = Path(temp)
            (workspace / 'health-history.json').write_text('{broken')

            def successful_scan(command, **kwargs):
                staged = Path(command[command.index('--workspace') + 1])
                work = staged / 'work'
                work.mkdir(parents=True)
                (work / 'storage-analysis-live.json').write_text(json.dumps({
                    'large_file_discovery': {
                        'totals': {'scanned_allocated_bytes': 5},
                        'coverage': {'stages': {'traversal': 'complete'}},
                    },
                    'cleanup_options': {},
                }))
                (work / 'run-metrics.json').write_text(json.dumps({'total_elapsed_seconds': 1}))
                return SimpleNamespace(returncode=0, stderr='')

            with patch.object(daily.bounded_process, 'run', side_effect=successful_scan):
                health = daily.run_check('/Users/mac2', workspace, budget=1)
            self.assertEqual(health['status'], 'completed')
            self.assertEqual(health['history_status'], 'invalid-or-partial')
            history = json.loads((workspace / 'health-history.json').read_text())
            self.assertEqual(len(history), 1)
            self.assertEqual(history[0]['status'], 'completed')

    def test_invalid_history_record_does_not_make_recovery_reuse_its_report_slot(self):
        with TemporaryDirectory() as temp:
            workspace = Path(temp)
            preserved = workspace / 'slot-a/outputs/old-report.html'
            preserved.parent.mkdir(parents=True)
            preserved.write_text('preserve this evidence')
            (workspace / 'health-history.json').write_text(json.dumps([{
                'status': 'completed', 'report': str(preserved),
                'allocated_delta_bytes': 'not-a-number',
            }]))
            with patch.object(daily.bounded_process, 'run', side_effect=OSError('sample failure')):
                health = daily.run_check(workspace, workspace)
            self.assertEqual(health['status'], 'failed')
            self.assertEqual(preserved.read_text(), 'preserve this evidence')
            self.assertNotEqual(health.get('report'), str(preserved))

    def test_metadata_first_does_not_hide_small_unknown_files(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'unknown.data').write_bytes(b'QFI\xfb' + b'x' * 8)
            result = discovery.scan_large_files([root], min_bytes=100, metadata_first=True)
            self.assertEqual(result['files_scanned'], 1)
            self.assertEqual(result['all_logical_bytes'], 12)
            self.assertEqual(result['signature_unchecked_count'], 1)
            self.assertEqual(result['all_files'][0]['signature_status'], 'unchecked')

    def test_failure_after_writing_staged_evidence_preserves_old_report(self):
        with TemporaryDirectory() as temp:
            workspace = Path(temp)
            old = workspace / 'slot-a/outputs/codex-storage-cleanup-report.html'
            old.parent.mkdir(parents=True)
            old.write_text('previous verified report')
            (workspace / 'health-latest.json').write_text(json.dumps({'status': 'completed', 'report': str(old)}))
            def failing_scan(command, **kwargs):
                staged = Path(command[command.index('--workspace') + 1])
                (staged / 'work').mkdir(parents=True)
                (staged / 'work/storage-analysis-live.json').write_text('partial new evidence')
                return SimpleNamespace(returncode=1, stderr='builder failed')
            with patch.object(daily.bounded_process, 'run', side_effect=failing_scan):
                health = daily.run_check(workspace, workspace)
            self.assertEqual(health['status'], 'failed')
            self.assertEqual(old.read_text(), 'previous verified report')
            self.assertEqual(json.loads((workspace / 'health-latest.json').read_text())['report'], str(old))

    def test_signature_failure_is_a_type_coverage_gap(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'data').write_bytes(b'x')
            with patch.object(discovery, '_read_signatures', return_value=(b'', b'', 'permission denied')):
                result = discovery.scan_large_files([root])
            self.assertFalse(result['coverage_complete'])
            self.assertTrue(result['traversal_complete'])
            aggregate = discovery.aggregate_diagnostics(result['errors'])
            self.assertEqual(aggregate['stages']['type-identification'], 'partial')
            self.assertEqual(aggregate['diagnostics'][0]['path'], str(root / 'data'))

    def test_child_pipeline_signature_failure_does_not_poison_measured_traversal(self):
        sys.path.insert(0, str(daily.SCANNER.parent))
        import scan_codex
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'data').write_bytes(b'x')
            with patch.object(discovery, '_read_signatures', return_value=(b'', b'', 'permission denied')), patch.object(discovery, 'discover_virtual_machines', return_value={'items': [], 'gaps': [], 'blocked_duplicate_paths': []}):
                result = scan_codex.full_discovery(root, duplicate_hash=False, min_large_bytes=100, exclude_roots=[], include_file_inventory=False)
            self.assertEqual(result['coverage']['stages']['traversal'], 'complete')
            self.assertEqual(result['coverage']['stages']['type-identification'], 'partial')
            self.assertEqual(result['totals']['scanned_logical_bytes'], 1)
            self.assertEqual(result['file_inventory'], [])
            self.assertEqual(result['coverage']['gap_count'], 1)

    def test_history_retains_only_generated_last_thirty_summaries(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'health-history.json').write_text(json.dumps([{'day': i} for i in range(30)]))
            with patch.object(daily.bounded_process, 'run', side_effect=OSError('sample failure')):
                daily.run_check(root, root)
            history = json.loads((root / 'health-history.json').read_text())
            self.assertEqual(len(history), 30)
            self.assertEqual(history[0], {'day': 1})

    def test_history_keeps_compact_coverage_summary(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            def successful_scan(command, **kwargs):
                staged = Path(command[command.index('--workspace') + 1])
                work = staged / 'work'
                work.mkdir(parents=True)
                coverage = {
                    'gap_count': 4,
                    'stages': {'traversal': 'partial'},
                    'diagnostics': [{'path': '/should-not-be-kept'}],
                }
                data = {
                    'large_file_discovery': {'totals': {}, 'coverage': coverage},
                    'cleanup_options': {},
                    'scan_elapsed_seconds': 1,
                }
                (work / 'storage-analysis-live.json').write_text(json.dumps(data))
                (work / 'run-metrics.json').write_text(json.dumps({'total_elapsed_seconds': 1}))
                return SimpleNamespace(returncode=0, stderr='')

            with patch.object(daily.bounded_process, 'run', side_effect=successful_scan):
                daily.run_check('/Users/mac2', root, budget=1)
            loaded = json.loads((root / 'health-history.json').read_text())
            self.assertEqual(loaded[0]['coverage']['gap_count'], 4)
            self.assertNotIn('diagnostics', loaded[0]['coverage'])
