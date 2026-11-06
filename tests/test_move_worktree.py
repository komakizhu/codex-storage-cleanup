from pathlib import Path
from tempfile import TemporaryDirectory
import os
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import move_worktree as mover
import apply_cleanup


class MoveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name).resolve()
        self.repo = self.home / 'repo'
        self.source = self.home / '.codex/worktrees/task'
        self.disk = self.home / 'disk'
        self.disk.mkdir()
        self.repo.mkdir()
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        mover.git(self.repo, 'config', 'user.email', 'test@example.com')
        mover.git(self.repo, 'config', 'user.name', 'Test')
        (self.repo / 'source.txt').write_text('preserved source')
        (self.repo / '.gitignore').write_text('ignored.txt\n')
        mover.git(self.repo, 'add', '.')
        mover.git(self.repo, 'commit', '-qm', 'initial')
        self.source.parent.mkdir(parents=True)
        mover.git(self.repo, 'worktree', 'add', '-b', 'task', str(self.source))
        self.rev = mover.git(self.source, 'rev-parse', 'HEAD')
        for context in (patch.object(Path, 'home', return_value=self.home),
                        patch.object(mover.vault, 'DISK', self.disk),
                        patch.object(mover.vault, 'check_disk'),
                        patch.object(mover.scan, 'open_handle_status', return_value=(False, 'idle'))):
            context.start()
            self.addCleanup(context.stop)

    def test_real_git_move_old_entry_and_lock(self):
        result = mover.move_worktree(self.source, self.rev)
        target = Path(result['destination'])
        self.assertTrue(self.source.is_symlink())
        self.assertEqual((self.source / 'source.txt').read_text(), 'preserved source')
        self.assertEqual(mover.git(target, 'status', '--porcelain'), '')
        self.assertEqual(mover.git(self.source, 'rev-parse', 'HEAD'), self.rev)
        self.assertIn('locked T1 removable drive', mover.git(self.repo, 'worktree', 'list', '--porcelain'))
        self.assertFalse(Path(result['temporary_local_path']).exists())
        self.assertEqual(apply_cleanup.build_plan({'items': [
            {'path': '/work/task', 'size_bytes': 100, 'default_action': 'migrate-to-t1'},
            {'path': '/work/task/build', 'size_bytes': 30, 'default_action': 'direct-delete'},
            {'path': '/archives', 'archive_eligible_bytes': 20, 'archive_eligible_paths': ['/archives/a'], 'default_action': 'backup-then-delete'},
        ]}, self.home)['estimated_reclaimable_bytes'], 120)
        # Simulate unplugging: git prune must preserve the locked registration.
        offline = target.with_name('offline')
        target.rename(offline)
        mover.git(self.repo, 'worktree', 'prune', '--expire', 'now')
        self.assertIn(str(target), mover.git(self.repo, 'worktree', 'list', '--porcelain'))
        offline.rename(target)
        self.assertEqual(mover.git(self.source, 'status', '--porcelain'), '')

    def test_repair_failure_restores_local_source(self):
        original = mover.git
        def fail_target(path, *args):
            if args[:2] == ('worktree', 'repair') and str(self.disk) in args[-1]:
                raise RuntimeError('simulated repair failure')
            return original(path, *args)
        with patch.object(mover, 'git', side_effect=fail_target):
            with self.assertRaisesRegex(RuntimeError, 'simulated'):
                mover.move_worktree(self.source, self.rev)
        self.assertFalse(self.source.is_symlink())
        self.assertEqual(mover.git(self.source, 'rev-parse', 'HEAD'), self.rev)
        self.assertEqual(mover.git(self.source, 'status', '--porcelain'), '')

    def test_mismatch_never_removes_original(self):
        def corrupt(a, b):
            shutil.copytree(a, b)
            (b / 'source.txt').write_text('bad')
        with patch.object(mover.vault, 'copy_exact', side_effect=corrupt):
            with self.assertRaisesRegex(mover.vault.VaultError, '复制校验失败'):
                mover.move_worktree(self.source, self.rev)
        self.assertFalse(self.source.is_symlink())
        self.assertEqual((self.source / 'source.txt').read_text(), 'preserved source')

    def test_dirty_and_absent_disk_preserve_source(self):
        (self.source / 'source.txt').write_text('new work')
        with self.assertRaisesRegex(mover.vault.VaultError, '未提交'):
            mover.move_worktree(self.source, self.rev)
        (self.source / 'source.txt').write_text('preserved source')
        with patch.object(mover.vault, 'check_disk', side_effect=mover.vault.VaultError('disk absent')):
            with self.assertRaisesRegex(mover.vault.VaultError, 'disk absent'):
                mover.move_worktree(self.source, self.rev)
        self.assertTrue(self.source.is_dir())

    def test_idle_dirty_worktree_moves_all_untracked_content_when_explicitly_allowed(self):
        (self.source / 'source.txt').write_text('changed but preserved')
        (self.source / 'untracked.txt').write_text('new task material')
        (self.source / 'ignored.txt').write_text('ignored task material')
        before = mover.git(self.source, 'status', '--porcelain', '--untracked-files=all')
        result = mover.move_worktree(self.source, self.rev, allow_dirty=True)
        target = Path(result['destination'])
        self.assertTrue(self.source.is_symlink())
        self.assertEqual((target / 'source.txt').read_text(), 'changed but preserved')
        self.assertEqual((target / 'untracked.txt').read_text(), 'new task material')
        self.assertEqual((target / 'ignored.txt').read_text(), 'ignored task material')
        self.assertEqual(mover.git(self.source, 'status', '--porcelain', '--untracked-files=all'), before)
        self.assertEqual(mover.git(target, 'status', '--porcelain', '--untracked-files=all'), before)

    def test_associated_group_moves_dirty_members_and_repairs_cross_worktree_link(self):
        second = self.home / '.codex/worktrees/other'
        mover.git(self.repo, 'worktree', 'add', '-b', 'other', str(second))
        second_revision = mover.git(second, 'rev-parse', 'HEAD')
        # Relative links are common in worktrees and must be resolved using
        # the original sibling layout before both roots are renamed.
        (self.source / 'peer.txt').symlink_to(Path('../other/source.txt'))
        (self.source / 'peer-config.json').write_text('{"peer": "../other/source.txt"}\n')
        (second / 'other-untracked.txt').write_text('other task material')
        revisions = {str(self.source): self.rev, str(second): second_revision}
        references = [{
            'kind': 'configuration-or-task-reference',
            'source_file': str(self.source / 'peer-config.json'),
            'target': str(second / 'source.txt'),
            'raw_path': '../other/source.txt',
            'path_base': str(self.source),
        }]
        results = mover.move_worktree_group(
            [self.source, second], revisions, allow_dirty=True, group_id='worktree-group-test',
            references=references,
        )
        self.assertEqual(len(results), 2)
        first_target = Path(next(item['destination'] for item in results if item['source'] == str(self.source)))
        second_target = Path(next(item['destination'] for item in results if item['source'] == str(second)))
        self.assertTrue(self.source.is_symlink())
        self.assertTrue(second.is_symlink())
        self.assertEqual((first_target / 'peer.txt').resolve(), second_target / 'source.txt')
        expected_relative = os.path.relpath(second_target / 'source.txt', first_target)
        self.assertEqual(
            (first_target / 'peer-config.json').read_text(),
            '{"peer": "' + expected_relative + '"}\n',
        )
        self.assertEqual((second_target / 'other-untracked.txt').read_text(), 'other task material')
        self.assertIn('worktree-group-test', (first_target.parent / 'migration.json').read_text())
