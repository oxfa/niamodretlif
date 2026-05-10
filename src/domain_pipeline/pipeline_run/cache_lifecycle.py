"""Layered GitHub Actions sqlite cache lifecycle diagnostics."""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

CacheScope = Literal["worker", "aggregate"]
GitHubRestoreState = Literal["exact", "fallback", "miss"]
VisibleCandidateState = Literal["none", "visible", "unknown"]
DbFileState = Literal["missing", "present"]
SidecarState = Literal["none", "wal_only", "shm_only", "wal_and_shm"]
SqliteCheckState = Literal[
    "not_checked_missing",
    "ok",
    "sqlite_unreadable",
    "sqlite_integrity_failed",
]
LifecycleOutcome = Literal[
    "restore_hit_readable",
    "restore_hit_unusable",
    "restore_miss_no_visible_candidates",
    "restore_miss_visible_candidates",
    "restore_miss_candidate_visibility_unknown",
]

_DETAIL_MAX_LENGTH = 160


@dataclass(frozen=True)
class GitHubCacheLifecycleState:
    """GitHub cache restore and visible-candidate state."""

    github_restore_state: GitHubRestoreState
    github_cache_hit_raw: str
    github_visible_candidate_count: int
    github_visible_candidate_page_count: int
    github_visible_candidate_state: VisibleCandidateState


@dataclass(frozen=True)
class LocalCacheLifecycleState:
    """Local cache file, sidecar, and sqlite usability state."""

    db_file_state: DbFileState
    db_size_bytes: int
    sqlite_sidecar_state: SidecarState
    sqlite_check_state: SqliteCheckState
    sqlite_check_detail: str


@dataclass(frozen=True)
class CacheLifecycleSnapshot:
    """One layered cache lifecycle observation rendered into workflow logs."""

    scope: CacheScope
    github: GitHubCacheLifecycleState
    local: LocalCacheLifecycleState
    lifecycle_outcome: LifecycleOutcome

    @property
    def github_restore_state(self) -> GitHubRestoreState:
        """Return GitHub actions/cache restore state."""
        return self.github.github_restore_state

    @property
    def github_cache_hit_raw(self) -> str:
        """Return the raw actions/cache cache-hit value."""
        return self.github.github_cache_hit_raw

    @property
    def github_visible_candidate_count(self) -> int:
        """Return total visible candidate count from the GitHub API response."""
        return self.github.github_visible_candidate_count

    @property
    def github_visible_candidate_page_count(self) -> int:
        """Return visible candidates present in the inspected response page."""
        return self.github.github_visible_candidate_page_count

    @property
    def github_visible_candidate_state(self) -> VisibleCandidateState:
        """Return whether GitHub-visible candidates were observed."""
        return self.github.github_visible_candidate_state

    @property
    def db_file_state(self) -> DbFileState:
        """Return whether the local sqlite cache file exists."""
        return self.local.db_file_state

    @property
    def db_size_bytes(self) -> int:
        """Return local sqlite cache file size."""
        return self.local.db_size_bytes

    @property
    def sqlite_sidecar_state(self) -> SidecarState:
        """Return local sqlite WAL/SHM sidecar state."""
        return self.local.sqlite_sidecar_state

    @property
    def sqlite_check_state(self) -> SqliteCheckState:
        """Return sqlite quick-check state."""
        return self.local.sqlite_check_state

    @property
    def sqlite_check_detail(self) -> str:
        """Return sqlite quick-check detail."""
        return self.local.sqlite_check_detail


@dataclass(frozen=True)
class CacheLifecycleInspectionRequest:
    """Filesystem inputs for one cache lifecycle inspection."""

    scope: CacheScope
    cache_hit: str
    candidate_response_path: Path
    cache_path: Path
    wal_path: Path
    shm_path: Path


def github_restore_state(cache_hit: str) -> GitHubRestoreState:
    """Return the GitHub restore state represented by actions/cache cache-hit."""
    if cache_hit == "true":
        return "exact"
    if cache_hit == "false":
        return "fallback"
    return "miss"


def inspect_cache_lifecycle(
    request: CacheLifecycleInspectionRequest,
) -> CacheLifecycleSnapshot:
    """Inspect restore, visible candidate, local file, and sqlite usability state."""
    restore_state = github_restore_state(request.cache_hit)
    candidate_count, page_count, candidate_state = _candidate_state(
        request.candidate_response_path
    )
    db_state, db_size = _db_file_state(request.cache_path)
    sidecar_state = _sidecar_state(request.wal_path, request.shm_path)
    sqlite_state, sqlite_detail = _sqlite_check_state(request.cache_path, db_state)
    outcome = _lifecycle_outcome(
        restore_state=restore_state,
        candidate_state=candidate_state,
        sqlite_state=sqlite_state,
    )
    return CacheLifecycleSnapshot(
        scope=request.scope,
        github=GitHubCacheLifecycleState(
            github_restore_state=restore_state,
            github_cache_hit_raw=request.cache_hit,
            github_visible_candidate_count=candidate_count,
            github_visible_candidate_page_count=page_count,
            github_visible_candidate_state=candidate_state,
        ),
        local=LocalCacheLifecycleState(
            db_file_state=db_state,
            db_size_bytes=db_size,
            sqlite_sidecar_state=sidecar_state,
            sqlite_check_state=sqlite_state,
            sqlite_check_detail=sqlite_detail,
        ),
        lifecycle_outcome=outcome,
    )


def render_lifecycle_log_lines(snapshot: CacheLifecycleSnapshot) -> list[str]:
    """Render one snapshot as stable key=value lines for tee-based logs."""
    prefix = f"{snapshot.scope} baseline cache"
    fields = [
        ("github_restore_state", snapshot.github_restore_state),
        ("github_cache_hit_raw", snapshot.github_cache_hit_raw),
        ("github_visible_candidate_count", snapshot.github_visible_candidate_count),
        (
            "github_visible_candidate_page_count",
            snapshot.github_visible_candidate_page_count,
        ),
        ("github_visible_candidate_state", snapshot.github_visible_candidate_state),
        ("db_file_state", snapshot.db_file_state),
        ("db_size_bytes", snapshot.db_size_bytes),
        ("sqlite_sidecar_state", snapshot.sqlite_sidecar_state),
        ("sqlite_check_state", snapshot.sqlite_check_state),
        ("sqlite_check_detail", snapshot.sqlite_check_detail),
        ("lifecycle_outcome", snapshot.lifecycle_outcome),
    ]
    return [f"{prefix} {name}={value}" for name, value in fields]


def _candidate_state(
    candidate_response_path: Path,
) -> tuple[int, int, VisibleCandidateState]:
    payload = json.loads(candidate_response_path.read_text(encoding="utf-8"))
    actions_caches = payload.get("actions_caches")
    page_count = len(actions_caches) if isinstance(actions_caches, list) else -1
    total_count = payload.get("total_count")
    if isinstance(total_count, int) and total_count >= 0:
        return total_count, page_count, _visible_candidate_state(total_count)
    if page_count >= 0:
        return page_count, page_count, _visible_candidate_state(page_count)
    return -1, -1, "unknown"


def _visible_candidate_state(count: int) -> VisibleCandidateState:
    return "visible" if count > 0 else "none"


def _db_file_state(cache_path: Path) -> tuple[DbFileState, int]:
    if not cache_path.is_file():
        return "missing", 0
    return "present", cache_path.stat().st_size


def _sidecar_state(wal_path: Path, shm_path: Path) -> SidecarState:
    wal_exists = wal_path.is_file()
    shm_exists = shm_path.is_file()
    if wal_exists and shm_exists:
        return "wal_and_shm"
    if wal_exists:
        return "wal_only"
    if shm_exists:
        return "shm_only"
    return "none"


def _sqlite_check_state(
    cache_path: Path, db_state: DbFileState
) -> tuple[SqliteCheckState, str]:
    if db_state == "missing":
        return "not_checked_missing", "none"
    try:
        connection = sqlite3.connect(
            f"{cache_path.resolve().as_uri()}?mode=ro", uri=True
        )
        try:
            rows = connection.execute("PRAGMA quick_check").fetchall()
        finally:
            connection.close()
    except sqlite3.DatabaseError as exc:
        return "sqlite_unreadable", _sanitize_detail(str(exc))
    except OSError as exc:
        return "sqlite_unreadable", _sanitize_detail(str(exc))
    details = [str(row[0]) for row in rows if row]
    if details == ["ok"]:
        return "ok", "ok"
    return "sqlite_integrity_failed", _sanitize_detail(";".join(details) or "empty")


def _lifecycle_outcome(
    *,
    restore_state: GitHubRestoreState,
    candidate_state: VisibleCandidateState,
    sqlite_state: SqliteCheckState,
) -> LifecycleOutcome:
    if restore_state in {"exact", "fallback"}:
        return (
            "restore_hit_readable" if sqlite_state == "ok" else "restore_hit_unusable"
        )
    if candidate_state == "none":
        return "restore_miss_no_visible_candidates"
    if candidate_state == "visible":
        return "restore_miss_visible_candidates"
    return "restore_miss_candidate_visibility_unknown"


def _sanitize_detail(value: str) -> str:
    cleaned = re.sub(r"\s+", "_", value.strip())
    return cleaned[:_DETAIL_MAX_LENGTH] if cleaned else "none"
