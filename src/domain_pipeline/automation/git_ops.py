"""Small git helpers for workflow-safe automation commits."""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


def _run_git(
    args: list[str],
    *,
    cwd: Path,
    check: bool = True,
    capture_output: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=check,
        capture_output=capture_output,
        text=True,
    )


def _remote_ref_exists(cwd: Path, *, remote_ref: str) -> bool:
    return (
        _run_git(
            ["show-ref", "--verify", "--quiet", f"refs/remotes/{remote_ref}"],
            cwd=cwd,
            check=False,
        ).returncode
        == 0
    )


def _pathspec_has_tracked_entries(cwd: Path, *, pathspec: str) -> bool:
    result = _run_git(["ls-files", "--", pathspec], cwd=cwd, check=False)
    return bool(result.stdout.strip())


def _current_branch_name(cwd: Path) -> str:
    result = _run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=cwd)
    return result.stdout.strip()


def configure_actor(cwd: Path) -> None:
    """Use the standard GitHub Actions bot identity."""
    _run_git(["config", "user.name", "github-actions[bot]"], cwd=cwd)
    _run_git(
        [
            "config",
            "user.email",
            "41898282+github-actions[bot]@users.noreply.github.com",
        ],
        cwd=cwd,
    )


def prepare_automation_worktree(
    cwd: Path,
    *,
    worktree_path: Path,
    target_branch: str,
    base_ref: str,
) -> None:
    """Prepare one dedicated automation worktree without switching the main checkout."""
    worktree_path = worktree_path.resolve()
    worktree_path.parent.mkdir(parents=True, exist_ok=True)
    _run_git(["fetch", "origin", target_branch], cwd=cwd, check=False)
    _run_git(["worktree", "prune"], cwd=cwd, check=False)
    _run_git(
        ["worktree", "remove", "--force", str(worktree_path)], cwd=cwd, check=False
    )
    if worktree_path.exists():
        shutil.rmtree(worktree_path)
    remote_ref = f"origin/{target_branch}"
    start_point = (
        remote_ref if _remote_ref_exists(cwd, remote_ref=remote_ref) else base_ref
    )
    if _current_branch_name(cwd) == target_branch:
        _run_git(
            [
                "worktree",
                "add",
                "--force",
                "--detach",
                str(worktree_path),
                start_point,
            ],
            cwd=cwd,
        )
        return
    _run_git(
        [
            "worktree",
            "add",
            "--force",
            "-B",
            target_branch,
            str(worktree_path),
            start_point,
        ],
        cwd=cwd,
    )


def commit_paths(
    cwd: Path,
    *,
    paths: list[str],
    message: str,
) -> str | None:
    """Stage explicit paths and create one commit when they changed."""
    stageable_paths = [
        path
        for path in paths
        if (cwd / path).exists() or _pathspec_has_tracked_entries(cwd, pathspec=path)
    ]
    logger.debug(
        "Commit path request in %s: message=%r requested_paths=%s stageable_paths=%s",
        cwd,
        message,
        paths,
        stageable_paths,
    )
    if not stageable_paths:
        logger.info(
            "Skipping commit in %s because no requested publish paths were present",
            cwd,
        )
        return None
    _run_git(["add", "-A", "--", *stageable_paths], cwd=cwd)
    diff_result = _run_git(["diff", "--cached", "--quiet"], cwd=cwd, check=False)
    if diff_result.returncode == 0:
        logger.info(
            "Skipping commit in %s because staged publish paths produced no diff: %s",
            cwd,
            stageable_paths,
        )
        return None
    _run_git(["commit", "-m", message], cwd=cwd)
    commit_sha = current_head_sha(cwd)
    logger.info(
        "Created publish commit %s in %s from paths=%s",
        commit_sha,
        cwd,
        stageable_paths,
    )
    return commit_sha


def push_current_branch(
    cwd: Path,
    *,
    branch: str,
    max_retries: int,
) -> int:
    """Push the current branch with one bounded fetch/rebase retry loop."""
    retries_used = 0
    refspec = f"HEAD:refs/heads/{branch}"
    while True:
        push_result = _run_git(
            ["push", "origin", refspec],
            cwd=cwd,
            check=False,
        )
        if push_result.returncode == 0:
            return retries_used
        if retries_used >= max_retries:
            error_output = push_result.stderr.strip() or push_result.stdout.strip()
            raise RuntimeError(
                f"push failed after {max_retries} retries:\n{error_output}"
            )
        retries_used += 1
        _run_git(["fetch", "origin", branch], cwd=cwd)
        rebase_result = _run_git(
            ["rebase", f"origin/{branch}"],
            cwd=cwd,
            check=False,
        )
        if rebase_result.returncode != 0:
            _run_git(["rebase", "--abort"], cwd=cwd, check=False)
            raise RuntimeError(
                "rebase failed while retrying push:\n"
                f"{rebase_result.stderr.strip() or rebase_result.stdout.strip()}"
            )


def current_head_sha(cwd: Path) -> str:
    """Return the current HEAD commit SHA."""
    result = _run_git(["rev-parse", "HEAD"], cwd=cwd)
    return result.stdout.strip()


def validate_publish_candidate_sizes(
    cwd: Path,
    *,
    paths: list[str],
    warning_bytes: int,
    error_bytes: int,
) -> dict[str, object]:
    """Validate file sizes for publish candidates that will be committed to Git."""
    checked_files: list[dict[str, object]] = []
    warning_entries: list[dict[str, object]] = []
    error_entries: list[dict[str, object]] = []

    for pathspec in paths:
        candidate_path = cwd / pathspec
        if not candidate_path.is_file():
            continue
        size_bytes = candidate_path.stat().st_size
        entry = {"path": pathspec, "size_bytes": size_bytes}
        checked_files.append(entry)
        if size_bytes > error_bytes:
            error_entries.append(entry)
        elif size_bytes > warning_bytes:
            warning_entries.append(entry)

    if error_entries:
        rendered = ", ".join(
            f"{entry['path']} ({entry['size_bytes']} bytes)" for entry in error_entries
        )
        raise RuntimeError(
            "publish candidates exceed the GitHub hard file-size limit: " f"{rendered}"
        )

    return {
        "checked_files": checked_files,
        "warnings": warning_entries,
        "warning_limit_bytes": warning_bytes,
        "error_limit_bytes": error_bytes,
    }
