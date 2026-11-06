"""One shared monotonic deadline for a complete Codex scan."""
from __future__ import annotations

import time

DEFAULT_SCAN_BUDGET_SECONDS = 20 * 60
_deadline: float | None = None
_started: float | None = None
_budget_seconds = DEFAULT_SCAN_BUDGET_SECONDS


class ScanBudgetExceeded(RuntimeError):
    def __init__(self, message: str, phase: str = "scan"):
        super().__init__(message)
        self.phase = phase


def start(seconds: int = DEFAULT_SCAN_BUDGET_SECONDS) -> None:
    global _deadline, _started, _budget_seconds
    _budget_seconds = max(int(seconds), 1)
    _started = time.monotonic()
    _deadline = _started + _budget_seconds


def active() -> bool:
    return _deadline is not None


def stop() -> float:
    elapsed_seconds = elapsed()
    global _deadline
    _deadline = None
    return elapsed_seconds


def elapsed() -> float:
    return 0.0 if _started is None else max(time.monotonic() - _started, 0.0)


def remaining() -> float | None:
    if _deadline is None:
        return None
    return max(_deadline - time.monotonic(), 0.0)


def configured_seconds() -> int:
    return _budget_seconds


def check(phase: str = "扫描") -> None:
    left = remaining()
    if left is not None and left <= 0:
        raise ScanBudgetExceeded(
            f"{phase}超过 {_budget_seconds} 秒扫描预算；未生成可执行清理计划",
            phase,
        )


def bounded_timeout(timeout: float, args=None, phase: str = "外部扫描命令") -> float:
    left = remaining()
    if left is None:
        return timeout
    if left <= 0:
        raise ScanBudgetExceeded(
            f"扫描命令超过 {_budget_seconds} 秒预算：{args!r}",
            phase,
        )
    return min(float(timeout), left)
