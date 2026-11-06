"""Per-invocation indexes shared by one Codex scan."""
from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import wraps
from pathlib import Path
from typing import Any, Callable, TypeVar


@dataclass
class ScanContext:
    directory_sizes: dict[str, dict[str, Any]] = field(default_factory=dict)
    path_sizes: dict[str, dict[str, Any]] = field(default_factory=dict)
    file_rows: dict[str, dict[str, Any]] = field(default_factory=dict)
    git_worktree_lists: dict[str, set[str] | None] = field(default_factory=dict)
    git_status_cache: dict[str, dict[str, Any]] = field(default_factory=dict)
    static_references: list[dict[str, Any]] | None = None
    static_reference_issues: list[dict[str, Any]] = field(default_factory=list)
    active_workspace_roots: set[str] = field(default_factory=set)
    directory_activity: dict[str, dict[str, Any]] = field(default_factory=dict)
    directory_children: dict[Path, list[Path]] | None = None
    directory_paths: set[Path] | None = None
    files_by_directory: dict[Path, list[str]] | None = None
    subtree_files: dict[str, tuple[str, ...]] = field(default_factory=dict)
    nested_dir_results: dict[str, tuple[Path, ...]] = field(default_factory=dict)
    nested_dir_coverage: dict[str, str] = field(default_factory=dict)
    git_identity_cache: dict[str, dict[str, Any]] = field(default_factory=dict)


_CURRENT: ContextVar[ScanContext | None] = ContextVar("codex_scan_context", default=None)
F = TypeVar("F", bound=Callable[..., Any])


def current() -> ScanContext | None:
    return _CURRENT.get()


def scoped(function: F) -> F:
    @wraps(function)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        token = _CURRENT.set(ScanContext())
        try:
            return function(*args, **kwargs)
        finally:
            _CURRENT.reset(token)

    return wrapped  # type: ignore[return-value]
