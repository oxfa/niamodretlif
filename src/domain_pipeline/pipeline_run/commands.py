"""Runner-facing command dispatch for one configured pipeline run."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

from domain_pipeline.aggregate import (
    aggregate_batch,
    validate_aggregate_readiness,
)
from domain_pipeline.pipeline_run.cache_lifecycle import (
    inspect_cache_lifecycle,
    render_lifecycle_log_lines,
)
from domain_pipeline.pipeline_run.settings import (
    batch_id_from_run,
    default_worker_ids,
    validate_run_settings,
)
from domain_pipeline.paths import PathLayout
from domain_pipeline.prepare import prepare_batch, write_prepared_batch
from domain_pipeline.publish import (
    commit_paths,
    configure_actor,
    prepare_publish_worktree,
    push_current_branch,
    validate_publish_candidate_sizes,
)
from domain_pipeline.worker.runtime import run_worker
from domain_pipeline.worker.aggregate_manifest import finalize_worker_aggregate_handoff
from domain_pipeline.worker.status import (
    finalize_worker_statuses,
    initialize_worker_statuses,
    materialize_incomplete_statuses,
)


def _print_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def suppress_token_bearing_library_debug_logs() -> None:
    """Keep third-party request URLs with query credentials out of debug logs."""
    logging.getLogger("urllib3.connectionpool").setLevel(logging.INFO)


def _configure_worker_logging(log_level: str) -> None:
    """Configure stderr logging for worker subprocess runs."""
    level_name = str(log_level).upper()
    level = getattr(logging, level_name, None)
    if not isinstance(level, int):
        raise ValueError(f"unsupported log level: {log_level!r}")
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
        force=True,
    )
    suppress_token_bearing_library_debug_logs()


def _configure_command_logging(log_level: str | None) -> None:
    """Configure stderr logging for non-worker pipeline-run commands."""
    if log_level is None:
        return
    _configure_worker_logging(log_level)


def _resolve_source_root(args: argparse.Namespace) -> Path:
    return Path(getattr(args, "source_root", ".")).resolve()


def _resolve_state_root(args: argparse.Namespace, source_root: Path) -> Path:
    state_root = getattr(args, "state_root", None)
    return Path(state_root).resolve() if state_root is not None else source_root


def _publish_worktree_root(workspace_root: Path) -> Path:
    return PathLayout(workspace_root).publish_worktree_root()


def _handle_prepare_batch(
    args: argparse.Namespace,
    source_root: Path,
    state_root: Path,
) -> int:
    worker_ids = default_worker_ids(args.worker_count)
    batch_id = batch_id_from_run(args.run_id, args.run_attempt)
    prepared = prepare_batch(
        source_root=source_root,
        config_path=Path(args.config),
        worker_ids=worker_ids,
        batch_id=batch_id,
    )
    committed_paths = write_prepared_batch(prepared, state_root=state_root)
    _print_json(
        {
            "batch_id": batch_id,
            "committed_paths": committed_paths,
            "expected_workers": [
                manifest.worker_id for manifest in prepared.worker_manifests
            ],
        }
    )
    return 0


def _handle_validate_run_settings(args: argparse.Namespace) -> int:
    payload = validate_run_settings(
        worker_count=args.worker_count,
        max_parallel_workers_raw=args.max_parallel_workers,
        max_parallel_workers_default_raw=args.max_parallel_workers_default,
        worker_runtime_seconds_raw=args.worker_runtime_seconds,
    )
    _print_json(payload)
    return 0


def _handle_initialize_worker_statuses(
    args: argparse.Namespace, state_root: Path
) -> int:
    payload = initialize_worker_statuses(
        batch_id=args.batch_id,
        worker_id=args.worker_id,
        state_root=state_root,
    )
    _print_json(payload)
    return 0


def _handle_worker(
    args: argparse.Namespace,
    source_root: Path,
    state_root: Path,
) -> int:
    _configure_worker_logging(args.log_level)
    payload = run_worker(
        batch_id=args.batch_id,
        worker_id=args.worker_id,
        source_root=source_root,
        state_root=state_root,
        max_runtime_seconds=args.max_runtime_seconds,
    )
    _print_json(payload)
    return 0


def _handle_finalize_worker_statuses(
    args: argparse.Namespace,
    state_root: Path,
) -> int:
    written_paths = finalize_worker_statuses(
        batch_id=args.batch_id,
        worker_id=args.worker_id,
        state_root=state_root,
        output_commit_sha=args.output_commit_sha,
        push_retry_count=args.push_retry_count,
        fallback_conclusion=args.fallback_conclusion,
        fallback_failure_reason=args.fallback_failure_reason,
    )
    _print_json({"written_paths": written_paths})
    return 0


def _handle_finalize_worker_aggregate_handoff(
    args: argparse.Namespace,
    state_root: Path,
) -> int:
    payload = finalize_worker_aggregate_handoff(
        batch_id=args.batch_id,
        worker_id=args.worker_id,
        state_root=state_root,
    )
    _print_json(payload)
    return 0


def _handle_validate_aggregate(args: argparse.Namespace, state_root: Path) -> int:
    _configure_command_logging(args.log_level)
    readiness = validate_aggregate_readiness(args.batch_id, state_root=state_root)
    _print_json(readiness)
    return 0


def _handle_aggregate(args: argparse.Namespace, state_root: Path) -> int:
    _configure_command_logging(args.log_level)
    payload = aggregate_batch(
        batch_id=args.batch_id,
        state_root=state_root,
    )
    _print_json(payload)
    return 0


def _handle_materialize_incomplete_statuses(
    args: argparse.Namespace, state_root: Path
) -> int:
    _configure_command_logging(args.log_level)
    payload = materialize_incomplete_statuses(
        batch_id=args.batch_id,
        state_root=state_root,
        failure_reason=args.failure_reason,
    )
    _print_json(payload)
    return 0


def _handle_inspect_cache_lifecycle(args: argparse.Namespace) -> int:
    """Emit layered GitHub Actions sqlite cache lifecycle log lines."""
    snapshot = inspect_cache_lifecycle(
        scope=args.scope,
        cache_hit=args.cache_hit,
        candidate_response_path=Path(args.candidate_response),
        cache_path=Path(args.cache_path),
        wal_path=Path(args.wal_path),
        shm_path=Path(args.shm_path),
    )
    for line in render_lifecycle_log_lines(snapshot):
        print(line)
    return 0


def _build_command_handlers(
    args: argparse.Namespace,
    source_root: Path,
    state_root: Path,
) -> dict[str, Any]:
    command_handlers = _build_git_command_handlers(args, source_root, state_root)
    command_handlers.update(
        _build_workflow_command_handlers(args, source_root, state_root)
    )
    return command_handlers


def _build_git_command_handlers(
    args: argparse.Namespace,
    source_root: Path,
    state_root: Path,
) -> dict[str, Any]:
    publish_root = _publish_worktree_root(state_root)
    return {
        "commit-paths": lambda: _configure_command_logging(args.log_level)
        or _print_json(
            {
                "commit_sha": commit_paths(
                    publish_root,
                    paths=args.paths,
                    message=args.message,
                )
            }
        )
        or 0,
        "configure-git": lambda: configure_actor(publish_root) or 0,
        "finalize-worker-statuses": lambda: _handle_finalize_worker_statuses(
            args,
            state_root,
        ),
        "finalize-worker-aggregate-handoff": lambda: (
            _handle_finalize_worker_aggregate_handoff(args, state_root)
        ),
        "prepare-publish-worktree": lambda: prepare_publish_worktree(
            source_root,
            worktree_path=publish_root,
            target_branch=args.target_branch,
            base_ref=args.base_ref,
        )
        or 0,
        "validate-publish-candidate-sizes": lambda: _configure_command_logging(
            args.log_level
        )
        or _print_json(
            validate_publish_candidate_sizes(
                publish_root,
                paths=args.paths,
                warning_bytes=args.warning_bytes,
                error_bytes=args.error_bytes,
            )
        )
        or 0,
        "push-branch": lambda: _configure_command_logging(args.log_level)
        or _print_json(
            {
                "retries_used": push_current_branch(
                    publish_root,
                    branch=args.branch,
                    max_retries=args.max_retries,
                )
            }
        )
        or 0,
    }


def _build_workflow_command_handlers(
    args: argparse.Namespace,
    source_root: Path,
    state_root: Path,
) -> dict[str, Any]:
    return {
        "aggregate": lambda: _handle_aggregate(args, state_root),
        "initialize-worker-statuses": lambda: _handle_initialize_worker_statuses(
            args,
            state_root,
        ),
        "inspect-cache-lifecycle": lambda: _handle_inspect_cache_lifecycle(args),
        "materialize-incomplete-statuses": lambda: (
            _handle_materialize_incomplete_statuses(args, state_root)
        ),
        "prepare-batch": lambda: _handle_prepare_batch(args, source_root, state_root),
        "validate-run-settings": lambda: _handle_validate_run_settings(args),
        "validate-aggregate": lambda: _handle_validate_aggregate(args, state_root),
        "worker": lambda: _handle_worker(args, source_root, state_root),
    }


def _add_root_args(
    parser: argparse.ArgumentParser, *, state_required: bool = False
) -> None:
    parser.add_argument("--source-root", default=".")
    parser.add_argument("--state-root", required=state_required, default=None)


def _add_arguments(
    parser: argparse.ArgumentParser,
    arguments: list[tuple[str, dict[str, Any]]],
) -> None:
    for name, kwargs in arguments:
        parser.add_argument(name, **kwargs)


def _add_log_level_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--log-level",
        choices=["warning", "info", "debug"],
        default="warning",
    )


def _add_workflow_subcommands(subparsers: Any) -> None:
    validate_settings_parser = subparsers.add_parser("validate-run-settings")
    _add_arguments(
        validate_settings_parser,
        [
            ("--worker-count", {"type": int, "default": 18}),
            ("--max-parallel-workers", {"default": ""}),
            ("--max-parallel-workers-default", {"default": ""}),
            ("--worker-runtime-seconds", {"default": ""}),
        ],
    )

    prepare_batch_parser = subparsers.add_parser("prepare-batch")
    _add_root_args(prepare_batch_parser)
    _add_arguments(
        prepare_batch_parser,
        [
            ("--config", {"required": True}),
            ("--run-id", {"required": True}),
            ("--run-attempt", {"required": True}),
            ("--worker-count", {"type": int, "default": 18}),
        ],
    )

    initialize_status_parser = subparsers.add_parser("initialize-worker-statuses")
    _add_root_args(initialize_status_parser)
    _add_arguments(
        initialize_status_parser,
        [
            ("--batch-id", {"required": True}),
            ("--worker-id", {"required": True}),
        ],
    )

    worker_parser = subparsers.add_parser("worker")
    _add_root_args(worker_parser)
    _add_arguments(
        worker_parser,
        [
            ("--batch-id", {"required": True}),
            ("--worker-id", {"required": True}),
            (
                "--log-level",
                {
                    "choices": ["warning", "info", "debug"],
                    "default": "warning",
                },
            ),
            ("--max-runtime-seconds", {"type": float, "default": None}),
        ],
    )

    finalize_status_parser = subparsers.add_parser("finalize-worker-statuses")
    _add_root_args(finalize_status_parser)
    _add_arguments(
        finalize_status_parser,
        [
            ("--batch-id", {"required": True}),
            ("--worker-id", {"required": True}),
            ("--output-commit-sha", {"required": True}),
            ("--push-retry-count", {"type": int, "required": True}),
            ("--fallback-conclusion", {"default": None}),
            ("--fallback-failure-reason", {"default": None}),
        ],
    )

    finalize_handoff_parser = subparsers.add_parser("finalize-worker-aggregate-handoff")
    _add_root_args(finalize_handoff_parser)
    _add_arguments(
        finalize_handoff_parser,
        [
            ("--batch-id", {"required": True}),
            ("--worker-id", {"required": True}),
        ],
    )

    validate_aggregate_parser = subparsers.add_parser("validate-aggregate")
    _add_root_args(validate_aggregate_parser)
    _add_log_level_argument(validate_aggregate_parser)
    _add_arguments(validate_aggregate_parser, [("--batch-id", {"required": True})])

    aggregate_parser = subparsers.add_parser("aggregate")
    _add_root_args(aggregate_parser)
    _add_log_level_argument(aggregate_parser)
    _add_arguments(
        aggregate_parser,
        [
            ("--batch-id", {"required": True}),
        ],
    )

    materialize_status_parser = subparsers.add_parser("materialize-incomplete-statuses")
    _add_root_args(materialize_status_parser)
    _add_log_level_argument(materialize_status_parser)
    _add_arguments(
        materialize_status_parser,
        [
            ("--batch-id", {"required": True}),
            ("--failure-reason", {"required": True}),
        ],
    )

    inspect_cache_parser = subparsers.add_parser("inspect-cache-lifecycle")
    _add_arguments(
        inspect_cache_parser,
        [
            ("--scope", {"choices": ["worker", "aggregate"], "required": True}),
            ("--cache-hit", {"required": True}),
            ("--candidate-response", {"required": True}),
            ("--cache-path", {"required": True}),
            ("--wal-path", {"required": True}),
            ("--shm-path", {"required": True}),
        ],
    )


def _add_git_subcommands(subparsers: Any) -> None:
    configure_git_parser = subparsers.add_parser("configure-git")
    _add_root_args(configure_git_parser)

    worktree_parser = subparsers.add_parser("prepare-publish-worktree")
    _add_root_args(worktree_parser, state_required=True)
    _add_arguments(
        worktree_parser,
        [
            ("--target-branch", {"required": True}),
            ("--base-ref", {"required": True}),
        ],
    )

    commit_parser = subparsers.add_parser("commit-paths")
    _add_root_args(commit_parser)
    _add_log_level_argument(commit_parser)
    commit_parser.add_argument("--message", required=True)
    commit_parser.add_argument("--path", dest="paths", action="append", default=[])

    validate_publish_parser = subparsers.add_parser("validate-publish-candidate-sizes")
    _add_root_args(validate_publish_parser)
    _add_log_level_argument(validate_publish_parser)
    validate_publish_parser.add_argument(
        "--warning-bytes",
        type=int,
        default=50 * 1024 * 1024,
    )
    validate_publish_parser.add_argument(
        "--error-bytes",
        type=int,
        default=100 * 1024 * 1024,
    )
    validate_publish_parser.add_argument(
        "--path",
        dest="paths",
        action="append",
        default=[],
    )

    push_parser = subparsers.add_parser("push-branch")
    _add_root_args(push_parser)
    _add_log_level_argument(push_parser)
    _add_arguments(
        push_parser,
        [
            ("--branch", {"required": True}),
            ("--max-retries", {"type": int, "default": 3}),
        ],
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the pipeline-run command parser."""
    parser = argparse.ArgumentParser(description="Domain pipeline run commands")
    subparsers = parser.add_subparsers(dest="command", required=True)
    _add_workflow_subcommands(subparsers)
    _add_git_subcommands(subparsers)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the pipeline-run command dispatcher."""
    parser = build_parser()
    args = parser.parse_args(argv)
    source_root = _resolve_source_root(args)
    state_root = _resolve_state_root(args, source_root)
    command_handler = _build_command_handlers(args, source_root, state_root).get(
        args.command
    )
    if command_handler is not None:
        return command_handler()
    parser.error(f"unknown command {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
