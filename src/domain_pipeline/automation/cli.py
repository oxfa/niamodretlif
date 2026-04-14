"""CLI entrypoint for GitHub automation helpers."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

from .workflows import (
    WORKER_METADATA_ARTIFACT_NAME,
    aggregate_batch,
    batch_id_from_run,
    bootstrap_worker_metadata,
    default_worker_ids,
    download_worker_metadata,
    finalize_worker_statuses,
    initialize_worker_statuses,
    load_manifest,
    materialize_incomplete_statuses,
    prepare_batch,
    validate_aggregate_readiness,
    validate_manifest_payload,
    validate_run_settings,
    write_done_marker,
    write_prepared_batch,
    run_worker,
)
from .git_ops import (
    commit_paths,
    configure_actor,
    current_head_sha,
    prepare_automation_worktree,
    push_current_branch,
    validate_publish_candidate_sizes,
)


def _print_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


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


def _configure_command_logging(log_level: str | None) -> None:
    """Configure stderr logging for non-worker automation commands."""
    if log_level is None:
        return
    _configure_worker_logging(log_level)


def _resolve_source_root(args: argparse.Namespace) -> Path:
    return Path(getattr(args, "source_root", ".")).resolve()


def _resolve_state_root(args: argparse.Namespace, source_root: Path) -> Path:
    state_root = getattr(args, "state_root", None)
    return Path(state_root).resolve() if state_root is not None else source_root


def _handle_orchestrate(
    args: argparse.Namespace,
    source_root: Path,
    state_root: Path,
) -> int:
    worker_ids = default_worker_ids(args.worker_count)
    batch_id = batch_id_from_run(args.run_id, args.run_attempt)
    prepared = prepare_batch(
        source_root=source_root,
        config_path=Path(args.config),
        target_ref=args.target_ref,
        source_sha=args.source_sha,
        worker_ids=worker_ids,
        batch_id=batch_id,
        orchestrator_run_id=args.run_id,
        orchestrator_run_attempt=args.run_attempt,
        worker_runtime_budget_seconds=args.worker_runtime_budget_seconds,
    )
    committed_paths = write_prepared_batch(prepared, state_root=state_root)
    _print_json(
        {
            "batch_id": batch_id,
            "committed_paths": committed_paths,
            "expected_workers": prepared.manifest["expected_worker_identities"],
            "manifest_path": prepared.manifest["manifest_path"],
        }
    )
    return 0


def _handle_validate_run_settings(args: argparse.Namespace) -> int:
    payload = validate_run_settings(
        worker_count=args.worker_count,
        max_parallel_workers_raw=args.max_parallel_workers,
        worker_runtime_seconds_raw=args.worker_runtime_seconds,
    )
    _print_json(payload)
    return 0


def _handle_validate_manifest(args: argparse.Namespace, state_root: Path) -> int:
    manifest = load_manifest(args.batch_id, state_root=state_root)
    validate_manifest_payload(manifest)
    _print_json({"batch_id": args.batch_id, "state": "valid"})
    return 0


def _handle_initialize_worker_statuses(
    args: argparse.Namespace, state_root: Path
) -> int:
    payload = initialize_worker_statuses(
        batch_id=args.batch_id,
        worker_id=args.worker_id,
        state_root=state_root,
        metadata_output_path=Path(args.metadata_path).resolve(),
    )
    _print_json(payload)
    return 0


def _handle_bootstrap_worker_metadata(args: argparse.Namespace) -> int:
    payload = bootstrap_worker_metadata(
        batch_id=args.batch_id,
        worker_id=args.worker_id,
        target_ref=args.target_ref,
        source_sha=args.source_sha,
        run_id=args.run_id,
        run_attempt=args.run_attempt,
        metadata_output_path=Path(args.metadata_path).resolve(),
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
        metadata_output_path=Path(args.metadata_output).resolve(),
        max_runtime_seconds=args.max_runtime_seconds,
    )
    _print_json(payload)
    return 0


def _handle_finalize_worker_statuses(
    args: argparse.Namespace,
    state_root: Path,
) -> int:
    written_paths = finalize_worker_statuses(
        state_root=state_root,
        metadata_path=Path(args.metadata_path).resolve(),
        output_commit_sha=args.output_commit_sha,
        push_retry_count=args.push_retry_count,
        fallback_conclusion=args.fallback_conclusion,
        fallback_failure_reason=args.fallback_failure_reason,
    )
    _print_json({"written_paths": written_paths})
    return 0


def _handle_download_worker_metadata(args: argparse.Namespace) -> int:
    payload = download_worker_metadata(
        repo=args.repo,
        run_id=args.run_id,
        token=args.token,
        output_path=Path(args.output_path),
        artifact_name=args.artifact_name,
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
    payload = aggregate_batch(batch_id=args.batch_id, state_root=state_root)
    _print_json(payload)
    return 0


def _handle_write_done_marker(args: argparse.Namespace, state_root: Path) -> int:
    manifest = load_manifest(args.batch_id, state_root=state_root)
    done_payload = json.loads(
        Path(args.done_payload_path).resolve().read_text(encoding="utf-8")
    )
    written_path = write_done_marker(
        state_root=state_root,
        manifest=manifest,
        done_marker_payload=done_payload,
        aggregate_commit_sha=args.aggregate_commit_sha,
    )
    _print_json({"written_path": written_path})
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
    return {
        "batch-id": lambda: print(batch_id_from_run(args.run_id, args.run_attempt))
        or 0,
        "commit-paths": lambda: _configure_command_logging(args.log_level)
        or _print_json(
            {
                "commit_sha": commit_paths(
                    state_root,
                    paths=args.paths,
                    message=args.message,
                )
            }
        )
        or 0,
        "configure-git": lambda: configure_actor(state_root) or 0,
        "finalize-worker-statuses": lambda: _handle_finalize_worker_statuses(
            args,
            state_root,
        ),
        "head-sha": lambda: print(current_head_sha(state_root)) or 0,
        "prepare-automation-worktree": lambda: prepare_automation_worktree(
            source_root,
            worktree_path=state_root,
            target_branch=args.target_branch,
            base_ref=args.base_ref,
        )
        or 0,
        "validate-publish-candidate-sizes": lambda: _configure_command_logging(
            args.log_level
        )
        or _print_json(
            validate_publish_candidate_sizes(
                state_root,
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
                    state_root,
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
        "bootstrap-worker-metadata": lambda: _handle_bootstrap_worker_metadata(args),
        "download-worker-metadata": lambda: _handle_download_worker_metadata(args),
        "initialize-worker-statuses": lambda: _handle_initialize_worker_statuses(
            args,
            state_root,
        ),
        "materialize-incomplete-statuses": lambda: (
            _handle_materialize_incomplete_statuses(args, state_root)
        ),
        "orchestrate": lambda: _handle_orchestrate(args, source_root, state_root),
        "validate-run-settings": lambda: _handle_validate_run_settings(args),
        "validate-aggregate": lambda: _handle_validate_aggregate(args, state_root),
        "validate-manifest": lambda: _handle_validate_manifest(args, state_root),
        "worker": lambda: _handle_worker(args, source_root, state_root),
        "write-done-marker": lambda: _handle_write_done_marker(args, state_root),
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
            ("--worker-runtime-seconds", {"default": ""}),
        ],
    )

    orchestrate_parser = subparsers.add_parser("orchestrate")
    _add_root_args(orchestrate_parser)
    _add_arguments(
        orchestrate_parser,
        [
            ("--config", {"required": True}),
            ("--target-ref", {"required": True}),
            ("--source-sha", {"required": True}),
            ("--run-id", {"required": True}),
            ("--run-attempt", {"required": True}),
            ("--worker-count", {"type": int, "default": 18}),
            (
                "--worker-runtime-budget-seconds",
                {"type": int, "default": 19800},
            ),
        ],
    )

    validate_manifest_parser = subparsers.add_parser("validate-manifest")
    _add_root_args(validate_manifest_parser)
    _add_arguments(validate_manifest_parser, [("--batch-id", {"required": True})])

    initialize_status_parser = subparsers.add_parser("initialize-worker-statuses")
    _add_root_args(initialize_status_parser)
    _add_arguments(
        initialize_status_parser,
        [
            ("--batch-id", {"required": True}),
            ("--worker-id", {"required": True}),
            ("--metadata-path", {"required": True}),
        ],
    )

    bootstrap_metadata_parser = subparsers.add_parser("bootstrap-worker-metadata")
    _add_arguments(
        bootstrap_metadata_parser,
        [
            ("--batch-id", {"required": True}),
            ("--worker-id", {"required": True}),
            ("--target-ref", {"required": True}),
            ("--source-sha", {"required": True}),
            ("--run-id", {"required": True}),
            ("--run-attempt", {"required": True}),
            ("--metadata-path", {"required": True}),
        ],
    )

    worker_parser = subparsers.add_parser("worker")
    _add_root_args(worker_parser)
    _add_arguments(
        worker_parser,
        [
            ("--batch-id", {"required": True}),
            ("--worker-id", {"required": True}),
            ("--metadata-output", {"required": True}),
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
            ("--metadata-path", {"required": True}),
            ("--output-commit-sha", {"required": True}),
            ("--push-retry-count", {"type": int, "required": True}),
            ("--fallback-conclusion", {"default": None}),
            ("--fallback-failure-reason", {"default": None}),
        ],
    )

    download_metadata_parser = subparsers.add_parser("download-worker-metadata")
    _add_arguments(
        download_metadata_parser,
        [
            ("--repo", {"required": True}),
            ("--run-id", {"required": True}),
            ("--token", {"required": True}),
            ("--output-path", {"required": True}),
            ("--artifact-name", {"default": WORKER_METADATA_ARTIFACT_NAME}),
        ],
    )

    validate_aggregate_parser = subparsers.add_parser("validate-aggregate")
    _add_root_args(validate_aggregate_parser)
    _add_log_level_argument(validate_aggregate_parser)
    _add_arguments(validate_aggregate_parser, [("--batch-id", {"required": True})])

    aggregate_parser = subparsers.add_parser("aggregate")
    _add_root_args(aggregate_parser)
    _add_log_level_argument(aggregate_parser)
    _add_arguments(aggregate_parser, [("--batch-id", {"required": True})])

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

    write_done_parser = subparsers.add_parser("write-done-marker")
    _add_root_args(write_done_parser)
    _add_arguments(
        write_done_parser,
        [
            ("--batch-id", {"required": True}),
            ("--aggregate-commit-sha", {"required": True}),
            ("--done-payload-path", {"required": True}),
        ],
    )


def _add_git_subcommands(subparsers: Any) -> None:
    batch_id_parser = subparsers.add_parser("batch-id")
    _add_arguments(
        batch_id_parser,
        [
            ("--run-id", {"required": True}),
            ("--run-attempt", {"required": True}),
        ],
    )

    configure_git_parser = subparsers.add_parser("configure-git")
    _add_root_args(configure_git_parser)

    worktree_parser = subparsers.add_parser("prepare-automation-worktree")
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

    head_parser = subparsers.add_parser("head-sha")
    _add_root_args(head_parser)


def build_parser() -> argparse.ArgumentParser:
    """Build the automation CLI parser."""
    parser = argparse.ArgumentParser(description="Domain pipeline automation helpers")
    subparsers = parser.add_subparsers(dest="command", required=True)
    _add_workflow_subcommands(subparsers)
    _add_git_subcommands(subparsers)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the automation CLI."""
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
