"""Read-only command probes with bounded caller wait, even after SIGKILL.

subprocess.run(timeout=...) waits without a deadline after killing a child.
On macOS a child stuck in a kernel wait may not exit immediately. Never use
a Popen context manager here: its __exit__ also waits without a deadline.
"""
import subprocess
import threading
import os
import signal
import queue

import scan_budget


def _close_streams(process):
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream:
            stream.close()


def _reap_later(process):
    def reap():
        try:
            process.communicate()
        except (OSError, ValueError):
            pass
        finally:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream:
                    stream.close()
    threading.Thread(target=reap, name='storage-probe-reaper', daemon=True).start()


def _reap_after_reader(process, reader):
    def wait_for_reader():
        reader.join()
        _reap_later(process)
    threading.Thread(target=wait_for_reader, name='storage-stream-reaper', daemon=True).start()


def _kill_and_reap(process, *, wait_seconds=1, close_streams=False):
    try:
        if os.name == 'posix':
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=wait_seconds)
        if close_streams:
            _close_streams(process)
        return True
    except subprocess.TimeoutExpired:
        _reap_later(process)
        return False


def run(args, *, timeout, capture_output=True, text=True, check=False, terminate_group=False, **kwargs):
    timeout = scan_budget.bounded_timeout(timeout, args)
    if capture_output:
        kwargs.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if terminate_group and os.name == 'posix':
        kwargs['start_new_session'] = True
    process = subprocess.Popen(args, text=text, **kwargs)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except BaseException:
        try:
            if terminate_group and os.name == 'posix':
                os.killpg(process.pid, signal.SIGKILL)  # Only this run's new session.
            else:
                process.kill()  # Only the child created by this call.
        except ProcessLookupError:
            pass
        finally:
            _reap_later(process)
        raise
    result = subprocess.CompletedProcess(args, process.returncode, stdout, stderr)
    if check:
        result.check_returncode()
    return result


def consume_stream(args, consumer, *, timeout, phase, stop_early=None):
    """Consume a bounded subprocess stream while the caller enforces its deadline."""
    timeout = scan_budget.bounded_timeout(timeout, args, phase)
    process = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=(os.name == 'posix'),
    )
    try:
        scan_budget.check(phase)
    except BaseException:
        _kill_and_reap(process)
        raise
    results = queue.Queue(maxsize=1)

    def read_stream():
        try:
            results.put((True, consumer(process.stdout)))
        except BaseException as error:
            results.put((False, error))

    reader = threading.Thread(target=read_stream, name='codex-bounded-stream-reader', daemon=True)
    reader.start()
    reader.join(timeout=timeout)
    if reader.is_alive():
        _kill_and_reap(process)
        reader.join(timeout=1)
        if reader.is_alive():
            _reap_after_reader(process, reader)
        else:
            _close_streams(process)
        raise scan_budget.ScanBudgetExceeded(
            f"{phase}超过剩余扫描预算；未生成可执行清理计划",
            phase,
        )

    succeeded, value = results.get_nowait()
    if not succeeded:
        _kill_and_reap(process, close_streams=True)
        raise value
    if stop_early and stop_early(value):
        if not _kill_and_reap(process, close_streams=True):
            raise scan_budget.ScanBudgetExceeded(
                f"{phase}结束后子进程未能在限定时间内回收",
                phase,
            )
        return value

    try:
        return_code = process.wait(timeout=scan_budget.bounded_timeout(timeout, args, phase))
    except subprocess.TimeoutExpired as error:
        _kill_and_reap(process, close_streams=True)
        raise scan_budget.ScanBudgetExceeded(
            f"{phase}超过剩余扫描预算；未生成可执行清理计划",
            phase,
        ) from error
    if return_code:
        _close_streams(process)
        raise subprocess.CalledProcessError(return_code, args)
    _close_streams(process)
    return value
