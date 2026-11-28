"""Exercise the local prepare, worker, and aggregate handoff boundary."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import sqlite3
import subprocess
import sys
import zipfile
from contextlib import closing
from pathlib import Path

import pytest

from domain_pipeline.aggregate.runner import AggregateBatchRunner
from domain_pipeline.handoff_io import read_yaml, write_yaml
from domain_pipeline.paths import PathLayout
from domain_pipeline.pipeline_run.handoffs import (
    HandoffRequest,
    restore_handoff,
    stage_handoff,
    stage_worker_inputs,
    validate_worker_inputs,
)
from domain_pipeline.prepare.batch_writer import PreparedBatch, PreparedBatchWriter
from domain_pipeline.prepare.config.loader import (
    load_config_without_runtime_credentials,
)
from domain_pipeline.prepare.models import PreparedInputSet, PreparedOutputRows
from domain_pipeline.prepare.planner import PreparationPlanner
from domain_pipeline.prepare.prepare_to_aggregate_manifest import (
    load_prepare_aggregate_manifest_for_batch,
)
from domain_pipeline.prepare.prepare_to_worker_manifest import (
    load_prepare_worker_manifest_for_worker,
)
from domain_pipeline.prepare.source_items import SourceItemHandoff
from domain_pipeline.prepare.sources.jobs import SourceJob
from domain_pipeline.prepare.sources.parser import DomainListParser
from domain_pipeline.worker.cache.repository import CacheRepository
from domain_pipeline.worker.output.rows import REVIEW_OUTPUT_COLUMNS
from domain_pipeline.worker.status.lifecycle import (
    WorkerStatusFailureRequest,
    WorkerStatusFinalizeRequest,
    WorkerStatusIdentity,
    WorkerStatusLifecycle,
    finalize_worker_statuses,
    initialize_worker_statuses,
)
from domain_pipeline.worker.runtime.runner import run_worker
from domain_pipeline.worker.worker_to_aggregate_manifest import (
    finalize_worker_aggregate_handoff,
    load_worker_aggregate_manifest,
    parse_worker_domain_results_jsonl_text,
)
from worker_artifact_correlation import GitHubActionsAPI, correlate_worker

BATCH = "batch-123-attempt-1"
WORKER = "worker-1"


def _assert_json_artifacts_match_declared_members(
    root: Path, declared_members: set[Path]
) -> None:
    """Check that JSON artifacts follow the declared handoff archive layout."""
    actual = {
        path.relative_to(root)
        for path in root.rglob("*")
        if path.is_file() and path.suffix in {".json", ".jsonl"}
    }
    expected = {
        path for path in declared_members if path.suffix in {".json", ".jsonl"}
    }
    assert actual == expected


def _write_prepared_batch(
    prepare_root: Path, *, config_name: str, worker_ids: list[str]
) -> PreparedBatch:
    """Write preparation output for two local source lines."""
    config = load_config_without_runtime_credentials(Path("config") / f"{config_name}.yaml")
    source_config = config["sources"][0]
    source = SourceJob(
        source_id=source_config["id"],
        input_label="local fixture",
        output_stem=config_name,
        lines=["||ads.example.com^\n", "||bad.example.net^\n"],
        config=source_config,
    )
    parser = DomainListParser()
    parsed_source_file = parser.parse_source_file(
        source.lines,
        source_name=source.input_label,
        forced_format=source_config["input"]["format"],
    )
    source_entries = list(parser.entries_from_parsed_source_file(parsed_source_file))
    entries_by_source = {source.source_id: source_entries}
    source_jobs_by_id = {source.source_id: source}
    entries_by_host = {entry.host: entry for entry in source_entries}
    root_plans = PreparationPlanner(source_root=Path("."))._root_plans(
        entries_by_host=entries_by_host,
        source_ids_by_host={
            entry.host: {source.source_id} for entry in source_entries
        },
        manual_routing_by_host={},
        source_jobs_by_id=source_jobs_by_id,
    )
    prepared_inputs = PreparedInputSet(
        config=config,
        source_jobs_by_id=source_jobs_by_id,
        parsed_source_entry_count=len(source_entries),
        entries_by_source=entries_by_source,
        manual_routing_by_host={},
        root_plans=root_plans,
        preparation_outputs=PreparedOutputRows(review_rows=[], terminal_rows=[]),
        parsed_source_files={source.source_id: parsed_source_file},
    )
    writer = PreparedBatchWriter()
    prepared = writer.from_prepared_inputs(
        prepared_inputs=prepared_inputs, worker_ids=worker_ids, batch_id=BATCH
    )
    writer.write(prepared, state_root=prepare_root)
    return prepared


def _prepare_and_restore(tmp_path: Path) -> None:
    """Write and stage actual preparation outputs."""
    prepare_root = tmp_path / "prepare"
    worker_root = tmp_path / "worker"
    aggregate_root = tmp_path / "aggregate"
    _write_prepared_batch(prepare_root, config_name="block", worker_ids=[WORKER])

    worker_staging = tmp_path / "worker-stage"
    worker_ids = json.dumps([WORKER])
    stage_worker_inputs(
        state_root=prepare_root,
        batch_id=BATCH,
        worker_ids_json=worker_ids,
        destination=worker_staging,
    )
    worker_members = PathLayout(prepare_root).prepare_to_worker.members(
        batch_id=BATCH, worker_id=WORKER
    )
    _assert_json_artifacts_match_declared_members(
        worker_staging,
        {Path(WORKER) / member.archive_path for member in worker_members},
    )
    validate_worker_inputs(
        state_root=prepare_root,
        batch_id=BATCH,
        worker_ids_json=worker_ids,
        destination=worker_staging,
    )
    aggregate_staging = tmp_path / "aggregate-stage"
    aggregate_request = HandoffRequest(
        "prepare-aggregate", BATCH, require_runtime=True, config_name="block"
    )
    stage_handoff(
        state_root=prepare_root,
        destination=aggregate_staging,
        request=aggregate_request,
    )
    aggregate_members = PathLayout(prepare_root).prepare_to_aggregator.members(
        batch_id=BATCH
    )
    _assert_json_artifacts_match_declared_members(
        aggregate_staging, {member.archive_path for member in aggregate_members}
    )
    restore_handoff(
        state_root=worker_root,
        source=worker_staging / WORKER,
        request=HandoffRequest(
            "prepare-worker", BATCH, worker_id=WORKER, config_name="block"
        ),
    )
    restore_handoff(
        state_root=aggregate_root, source=aggregate_staging, request=aggregate_request
    )


def test_prepare_worker_stages_and_restores_populated_and_empty_assignments(
    tmp_path: Path,
) -> None:
    """Round-trip each worker's two JSON members into its own state root."""
    assignments = {
        WORKER: {"example.com": "ads.example.com"},
        "worker-2": {"example.net": "bad.example.net"},
        "worker-3": {},
    }
    prepare_root = tmp_path / "prepare"
    staging = tmp_path / "worker-stage"
    config_name = "direct"
    prepared = _write_prepared_batch(
        prepare_root, config_name=config_name, worker_ids=list(assignments)
    )
    manifests = {worker.worker_id: worker.manifest for worker in prepared.worker_manifests}
    worker_ids = json.dumps(list(assignments))
    stage_worker_inputs(
        state_root=prepare_root,
        batch_id=BATCH,
        worker_ids_json=worker_ids,
        destination=staging,
    )
    validate_worker_inputs(
        state_root=prepare_root,
        batch_id=BATCH,
        worker_ids_json=worker_ids,
        destination=staging,
    )

    def files(root: Path) -> dict[Path, bytes]:
        return {
            path.relative_to(root): path.read_bytes()
            for path in root.rglob("*")
            if path.is_file()
        }

    workers_path = Path(".workflow_state") / "batches" / BATCH / "workers"
    member_names = ("runtime-config.json", "worker-identity.json")
    produced = files(prepare_root / workers_path)
    assert set(produced) == {
        Path(worker_id) / name for worker_id in assignments for name in member_names
    }
    for worker_id, roots in assignments.items():
        members = {
            workers_path / worker_id / name: produced[Path(worker_id) / name]
            for name in member_names
        }
        source = staging / worker_id
        restored = tmp_path / "restored" / worker_id
        assert files(source) == members
        restore_handoff(
            state_root=restored,
            source=source,
            request=HandoffRequest(
                "prepare-worker", BATCH, worker_id=worker_id, config_name=config_name
            ),
        )
        assert files(restored) == members
        manifest = load_prepare_worker_manifest_for_worker(
            batch_id=BATCH, worker_id=worker_id, state_root=restored
        )
        assert manifest == manifests[worker_id]
        metadata = manifest.prepared_metadata
        assert set(metadata.delegation_roots) == set(roots)
        assert len(metadata.profiles.delegation) == len(roots)
        assert len(metadata.profiles.host_resolution) == len(roots)
        assert len(metadata.profiles.ip_location) == len(roots)
        for root, input_domain in roots.items():
            root_work = metadata.delegation_roots[root]
            assert root_work.delegation_profile_id == 0
            assert set(root_work.input_domains) == {input_domain}
            input_work = root_work.input_domains[input_domain]
            assert input_work.host_resolution_profile_id == 0
            assert input_work.ip_location_profile_id == 0


def _domain_results_fixture() -> dict[str, list[dict]]:
    """Return closed worker result rows for the prepared input-domain set."""
    return {
        "registrable_domain_results": [
            {
                "registrable_domain": "example.com",
                "disposition": "actionable",
                "delegation_result": {
                    "domain": "example.com",
                    "dns": {
                        "ns_records_exist": True,
                        "ns_nodata": False,
                        "ns_nxdomain": False,
                        "ns_retry_exhausted": False,
                        "ns_lookup_error": False,
                    },
                    "soa": {
                        "soa_exists": False,
                        "soa_absent": False,
                        "soa_retry_exhausted": False,
                        "soa_source": "",
                    },
                    "no_nameservers": False,
                    "nameservers": ["ns1.example.com"],
                    "from_cache": False,
                },
            },
            {
                "registrable_domain": "example.net",
                "disposition": "unactionable",
                "delegation_result": {
                    "domain": "example.net",
                    "dns": {
                        "ns_records_exist": False,
                        "ns_nodata": False,
                        "ns_nxdomain": True,
                        "ns_retry_exhausted": False,
                        "ns_lookup_error": False,
                    },
                    "soa": {
                        "soa_exists": False,
                        "soa_absent": True,
                        "soa_retry_exhausted": False,
                        "soa_source": "",
                    },
                    "no_nameservers": False,
                    "nameservers": [],
                    "from_cache": False,
                },
            },
        ],
        "input_domain_results": [
            {
                "input_domain": "ads.example.com",
                "registrable_domain": "example.com",
                "route": "review",
                "route_code": "host_resolution_to_review_nxdomain",
                "route_reason": "host resolution returned NXDOMAIN",
                "host_resolution_results": [
                    {
                        "host": "ads.example.com",
                        "dns": {
                            "a_exists": False,
                            "a_nodata": False,
                            "a_nxdomain": True,
                            "a_timeout": False,
                            "a_servfail": False,
                        },
                        "addresses": {
                            "canonical_name": None,
                            "ipv4_addresses": [],
                            "ipv6_addresses": [],
                        },
                        "from_cache": False,
                        "detail": "",
                    }
                ],
                "ip_location_results": [],
                "ip_location_policy": None,
            },
            {
                "input_domain": "bad.example.net",
                "registrable_domain": "example.net",
                "route": "unactionable",
                "route_code": "delegation_to_unactionable_ns_nxdomain_soa_absent",
                "route_reason": (
                    "delegation NS query returned NXDOMAIN and SOA was absent"
                ),
                "host_resolution_results": [],
                "ip_location_results": [],
                "ip_location_policy": None,
            },
        ],
    }


@pytest.mark.parametrize("member", ["runtime-config", "worker-identity"])
def test_prepare_worker_loader_rejects_unknown_fields(
    tmp_path: Path, member: str
) -> None:
    """Reject unknown fields in the worker manifest or identity record."""
    _prepare_and_restore(tmp_path)
    worker_root = tmp_path / "worker"
    paths = PathLayout(worker_root).workflow_state
    if member == "runtime-config":
        path = paths.prepare_worker_config_path(batch_id=BATCH, worker_id=WORKER)
        expected_error = "invalid prepare worker configuration"
    else:
        path = paths.prepare_worker_identity_path(batch_id=BATCH, worker_id=WORKER)
        expected_error = "prepare worker identity record mismatch"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["unexpected"] = True
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match=expected_error):
        load_prepare_worker_manifest_for_worker(
            batch_id=BATCH, worker_id=WORKER, state_root=worker_root
        )


def test_restore_rejects_prepare_worker_config_identity_mismatch(
    tmp_path: Path,
) -> None:
    """Worker restore checks its config identity against the workflow input."""
    _prepare_and_restore(tmp_path)
    source = tmp_path / "worker-stage" / WORKER
    restored_root = tmp_path / "mismatched-worker"

    with pytest.raises(ValueError, match="identity mismatch"):
        restore_handoff(
            state_root=restored_root,
            source=source,
            request=HandoffRequest(
                "prepare-worker",
                BATCH,
                worker_id=WORKER,
                config_name="direct",
            ),
        )

    assert not restored_root.exists()


def test_prepare_aggregate_loader_rejects_unknown_fields(
    tmp_path: Path,
) -> None:
    """Reject unknown fields in the prepare-to-aggregate manifest."""
    _prepare_and_restore(tmp_path)
    aggregate_root = tmp_path / "aggregate"
    path = PathLayout(aggregate_root).workflow_state.prepare_aggregate_config_path(
        batch_id=BATCH
    )
    payload = read_yaml(path)
    payload["unexpected"] = True
    write_yaml(path, payload)

    with pytest.raises(ValueError, match="invalid prepare aggregate configuration"):
        load_prepare_aggregate_manifest_for_batch(
            batch_id=BATCH, state_root=aggregate_root
        )


def test_source_item_index_rejects_unknown_fields() -> None:
    """Reject unknown fields in the source-item index."""
    handoff = SourceItemHandoff(
        batch_id=BATCH,
        item_records=(),
        index_payload={
            "batch_id": BATCH,
            "sources": [],
            "valid_source_items_by_registrable_domain": {},
            "valid_source_items_without_extractable_registrable_domain": [],
            "adblock_metadata": [],
            "unexpected": True,
        },
        diagnostic_records=(),
    )

    with pytest.raises(ValueError, match="unexpected|fields|schema"):
        handoff.validate()


def _finish_worker(tmp_path: Path) -> None:
    """Create deterministic worker outputs and finalize the handoff."""
    worker_root = tmp_path / "worker"
    assert initialize_worker_statuses(
        batch_id=BATCH, worker_id=WORKER, state_root=worker_root
    )["conclusion"] == "success"
    manifest = load_prepare_worker_manifest_for_worker(
        batch_id=BATCH, worker_id=WORKER, state_root=worker_root
    )
    paths = manifest.resolve_paths(worker_root)
    assigned_roots = set(manifest.prepared_metadata.delegation_roots)
    assert assigned_roots == {"example.com", "example.net"}
    paths["unactionable"].parent.mkdir(parents=True, exist_ok=True)
    paths["unactionable"].write_text("bad.example.net\n", encoding="utf-8")
    paths["review"].parent.mkdir(parents=True, exist_ok=True)
    with paths["review"].open("w", encoding="utf-8", newline="") as handle:
        review = csv.DictWriter(handle, fieldnames=REVIEW_OUTPUT_COLUMNS)
        review.writeheader()
        review.writerow(
            {
                "host": "ads.example.com",
                "registrable_domain": "example.com",
                "route_code": "host_resolution_to_review_nxdomain",
                "review_reason": "fixture reason",
            }
        )
    paths["domain_results"].parent.mkdir(parents=True, exist_ok=True)
    paths["domain_results"].write_text(
        json.dumps(_domain_results_fixture(), separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    worker_log = manifest.resolve_log_path(worker_root)
    worker_log.parent.mkdir(parents=True, exist_ok=True)
    worker_log.write_text("worker fixture log\n", encoding="utf-8")
    cache_log = PathLayout(worker_root).output.worker_cache_log_path(
        batch_id=BATCH, worker_id=WORKER
    )
    cache_log.write_text("cache fixture log\n", encoding="utf-8")
    cache = CacheRepository.load(paths["cache"])
    cache.close()
    with closing(sqlite3.connect(paths["cache"])) as db:
        db.execute(
            "INSERT INTO delegation_history VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "example.net",
                "fixture",
                0,
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                1,
                "[]",
                "2026-11-22T00:00:00Z",
                "2026-11-23T00:00:00Z",
            ),
        )
        db.commit()
    result = finalize_worker_aggregate_handoff(
        batch_id=BATCH, worker_id=WORKER, state_root=worker_root
    )
    assert (
        result["handoff_finalized"] and result["cache_snapshot_mode"] == "sqlite_backup"
    )
    finalize_worker_statuses(
        WorkerStatusFinalizeRequest(
            identity=WorkerStatusIdentity(BATCH, WORKER, worker_root),
            output_commit_sha="",
            push_retry_count=0,
            fallback_conclusion="success",
        )
    )


@pytest.mark.parametrize("json_value", ["null", "[]", '"text"', "17"])
def test_worker_handoff_rejects_non_object_domain_result_envelope(
    tmp_path: Path, json_value: str
) -> None:
    """Reject valid JSON values that cannot represent a result envelope."""
    _prepare_and_restore(tmp_path)
    worker_root = tmp_path / "worker"
    manifest = load_prepare_worker_manifest_for_worker(
        batch_id=BATCH, worker_id=WORKER, state_root=worker_root
    )
    results_path = manifest.resolve_paths(worker_root)["domain_results"]
    results_path.parent.mkdir(parents=True, exist_ok=True)
    results_path.write_text(f"{json_value}\n", encoding="utf-8")

    with pytest.raises(ValueError):
        finalize_worker_aggregate_handoff(
            batch_id=BATCH, worker_id=WORKER, state_root=worker_root
        )

    handoff_path = PathLayout(worker_root).workflow_state.worker_aggregate_manifest_path(
        batch_id=BATCH, worker_id=WORKER
    )
    assert not handoff_path.exists()


def test_worker_handoff_serializes_domain_results_as_jsonl(
    tmp_path: Path,
) -> None:
    """The worker artifact's domain-results member uses its declared JSONL form."""
    _prepare_and_restore(tmp_path)
    _finish_worker(tmp_path)
    path = PathLayout(tmp_path / "worker").workflow_state.worker_handoff_domain_results_path(
        batch_id=BATCH, worker_id=WORKER
    )

    envelope = parse_worker_domain_results_jsonl_text(
        path.read_text(encoding="utf-8")
    )

    assert [row.registrable_domain for row in envelope.registrable_domain_results] == [
        "example.com",
        "example.net",
    ]


@pytest.mark.parametrize(
    "review_csv",
    [
        "host,registrable_domain\nads.example.com,example.com\n",
        ",".join(REVIEW_OUTPUT_COLUMNS) + "\nads.example.com\n",
        ",".join(REVIEW_OUTPUT_COLUMNS)
        + "\n"
        + ",".join(["value"] * (len(REVIEW_OUTPUT_COLUMNS) + 1))
        + "\n",
    ],
    ids=["wrong-header", "short-row", "extra-cell"],
)
def test_worker_handoff_rejects_malformed_review_csv(
    tmp_path: Path, review_csv: str
) -> None:
    """Finalization rejects malformed review data instead of repairing it."""
    _prepare_and_restore(tmp_path)
    worker_root = tmp_path / "worker"
    status = initialize_worker_statuses(
        batch_id=BATCH, worker_id=WORKER, state_root=worker_root
    )
    assert status["conclusion"] == "success"
    manifest = load_prepare_worker_manifest_for_worker(
        batch_id=BATCH, worker_id=WORKER, state_root=worker_root
    )
    review_path = manifest.resolve_paths(worker_root)["review"]
    review_path.parent.mkdir(parents=True, exist_ok=True)
    review_path.write_text(review_csv, encoding="utf-8")

    with pytest.raises(ValueError, match="invalid CSV"):
        finalize_worker_aggregate_handoff(
            batch_id=BATCH, worker_id=WORKER, state_root=worker_root
        )


@pytest.mark.parametrize(
    "result_kind", ["unactionable", "review", "domain_results"]
)
def test_worker_handoff_rejects_domains_outside_its_assignment(
    tmp_path: Path, result_kind: str
) -> None:
    """Reject every worker result file that reports an unassigned domain."""
    _prepare_and_restore(tmp_path)
    worker_root = tmp_path / "worker"
    manifest = load_prepare_worker_manifest_for_worker(
        batch_id=BATCH, worker_id=WORKER, state_root=worker_root
    )
    paths = manifest.resolve_paths(worker_root)

    if result_kind == "unactionable":
        paths["unactionable"].parent.mkdir(parents=True, exist_ok=True)
        paths["unactionable"].write_text("outside.example.org\n", encoding="utf-8")
    elif result_kind == "review":
        paths["review"].parent.mkdir(parents=True, exist_ok=True)
        with paths["review"].open("w", encoding="utf-8", newline="") as handle:
            review = csv.DictWriter(handle, fieldnames=REVIEW_OUTPUT_COLUMNS)
            review.writeheader()
            review.writerow(
                {
                    "host": "ads.outside.example.org",
                    "registrable_domain": "outside.example.org",
                    "review_reason": "fixture reason",
                }
            )
    else:
        results = _domain_results_fixture()
        outside = results["input_domain_results"][0]
        outside["input_domain"] = "outside.example.org"
        outside["registrable_domain"] = "example.org"
        outside["host_resolution_results"][0]["host"] = "outside.example.org"
        paths["domain_results"].parent.mkdir(parents=True, exist_ok=True)
        paths["domain_results"].write_text(
            json.dumps(results, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

    with pytest.raises(ValueError):
        finalize_worker_aggregate_handoff(
            batch_id=BATCH, worker_id=WORKER, state_root=worker_root
        )


def test_worker_handoff_rejects_duplicate_unactionable_domains(
    tmp_path: Path,
) -> None:
    """Reject duplicate domain values before finalizing the worker result."""
    _prepare_and_restore(tmp_path)
    worker_root = tmp_path / "worker"
    manifest = load_prepare_worker_manifest_for_worker(
        batch_id=BATCH, worker_id=WORKER, state_root=worker_root
    )
    paths = manifest.resolve_paths(worker_root)
    paths["unactionable"].parent.mkdir(parents=True, exist_ok=True)
    paths["unactionable"].write_text("example.net\nexample.net\n", encoding="utf-8")
    paths["domain_results"].parent.mkdir(parents=True, exist_ok=True)
    paths["domain_results"].write_text(
        json.dumps(_domain_results_fixture(), separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="contain duplicates"):
        finalize_worker_aggregate_handoff(
            batch_id=BATCH, worker_id=WORKER, state_root=worker_root
        )


def test_missing_worker_status_fails_success_finalization_cli(tmp_path: Path) -> None:
    """A participating worker cannot pass success finalization without status."""
    _prepare_and_restore(tmp_path)
    worker_root = tmp_path / "worker"
    status_path = PathLayout(worker_root).workflow_state.worker_status_path(
        batch_id=BATCH, worker_id=WORKER
    )
    status_path.unlink(missing_ok=True)
    project = Path(__file__).resolve().parents[1]
    invocation = [
        sys.executable,
        str(project / "src/pipeline_run.py"),
        "finalize-worker-statuses",
        "--state-root",
        str(worker_root),
        "--batch-id",
        BATCH,
        "--worker-id",
        WORKER,
        "--output-commit-sha",
        "",
        "--push-retry-count",
        "0",
        "--fallback-conclusion",
        "success",
    ]

    result = subprocess.run(
        invocation, cwd=project, capture_output=True, text=True, check=False
    )

    assert result.returncode != 0
    assert "worker status file is missing during finalization" in result.stderr


def test_missing_worker_status_is_written_as_failure_on_failure_finalization(
    tmp_path: Path,
) -> None:
    """Failure finalization still records a terminal status when status is absent."""
    _prepare_and_restore(tmp_path)
    worker_root = tmp_path / "worker"
    status_path = PathLayout(worker_root).workflow_state.worker_status_path(
        batch_id=BATCH, worker_id=WORKER
    )
    status_path.unlink(missing_ok=True)

    written_paths = finalize_worker_statuses(
        WorkerStatusFinalizeRequest(
            identity=WorkerStatusIdentity(BATCH, WORKER, worker_root),
            output_commit_sha="",
            push_retry_count=0,
            fallback_conclusion="failure",
            fallback_failure_reason="worker failed before status initialization",
        )
    )

    assert written_paths == [
        PathLayout(worker_root).workflow_state.worker_status_path(
            batch_id=BATCH, worker_id=WORKER
        ).relative_to(worker_root).as_posix()
    ]
    assert read_yaml(status_path)["conclusion"] == "failure"
    assert read_yaml(status_path)["failure_reason"] == (
        "worker failed before status initialization"
    )


def test_missing_prepare_worker_manifest_fails_closed(tmp_path: Path) -> None:
    """A configured worker without its prepared manifest is a handoff failure."""
    worker_root = tmp_path / "worker"
    status = initialize_worker_statuses(
        batch_id=BATCH, worker_id=WORKER, state_root=worker_root
    )

    assert status["conclusion"] == "failure"
    assert "prepare worker configuration is missing" in status["failure_reason"]

    payload = run_worker(
        batch_id=BATCH,
        worker_id=WORKER,
        source_root=Path(__file__).resolve().parents[1],
        state_root=worker_root,
    )
    assert payload["overall_conclusion"] == "failure"
    assert "conclusion" not in payload
    assert "prepare worker configuration is missing" in payload["error_reason"]

    project = Path(__file__).resolve().parents[1]
    invocation = [
        sys.executable,
        str(project / "src/pipeline_run.py"),
        "worker",
        "--source-root",
        str(project),
        "--state-root",
        str(worker_root),
        "--batch-id",
        BATCH,
        "--worker-id",
        WORKER,
    ]
    command_result = subprocess.run(
        invocation, cwd=project, capture_output=True, text=True, check=False
    )
    assert command_result.returncode != 0
    assert json.loads(command_result.stdout)["overall_conclusion"] == "failure"

    handoff = finalize_worker_aggregate_handoff(
        batch_id=BATCH, worker_id=WORKER, state_root=worker_root
    )
    assert handoff["handoff_finalized"] is False
    assert "prepare worker configuration is missing" in handoff["error_reason"]

    status_path = PathLayout(worker_root).workflow_state.worker_status_path(
        batch_id=BATCH, worker_id=WORKER
    )
    assert read_yaml(status_path)["conclusion"] == "failure"


@pytest.mark.parametrize(
    "operation", ["initialize", "finalize", "record_failure", "run"]
)
@pytest.mark.parametrize(
    ("identity_field", "mismatched_value"),
    [("batch_id", "other-batch"), ("worker_id", "other-worker")],
)
def test_worker_status_identity_mismatch_is_never_overwritten(
    tmp_path: Path,
    operation: str,
    identity_field: str,
    mismatched_value: str,
) -> None:
    """Every worker lifecycle path rejects a status for another identity."""
    _prepare_and_restore(tmp_path)
    worker_root = tmp_path / "worker"
    identity = WorkerStatusIdentity(BATCH, WORKER, worker_root)
    initialize_worker_statuses(
        batch_id=BATCH, worker_id=WORKER, state_root=worker_root
    )
    status_path = PathLayout(worker_root).workflow_state.worker_status_path(
        batch_id=BATCH, worker_id=WORKER
    )
    original_payload = read_yaml(status_path)
    mismatched_payload = dict(original_payload)
    mismatched_payload[identity_field] = mismatched_value
    write_yaml(status_path, mismatched_payload)

    if operation == "initialize":
        action = lambda: initialize_worker_statuses(
            batch_id=BATCH, worker_id=WORKER, state_root=worker_root
        )
    elif operation == "finalize":
        action = lambda: finalize_worker_statuses(
            WorkerStatusFinalizeRequest(
                identity=identity,
                output_commit_sha="",
                push_retry_count=0,
                fallback_conclusion="success",
            )
        )
    elif operation == "record_failure":
        action = lambda: WorkerStatusLifecycle().record_failure(
            WorkerStatusFailureRequest(
                identity=identity, failure_reason="fixture failure"
            )
        )
    else:
        action = lambda: run_worker(
            batch_id=BATCH,
            worker_id=WORKER,
            source_root=Path(__file__).resolve().parents[1],
            state_root=worker_root,
        )

    if operation == "run":
        result = action()
        assert result["overall_conclusion"] == "failure"
        assert "conclusion" not in result
        assert result["status_recording_error"]
    else:
        with pytest.raises(ValueError, match="worker status identity mismatch"):
            action()

    assert read_yaml(status_path) == mismatched_payload


def _archive_worker_bundle(worker_bundle: Path) -> bytes:
    """Build the exact staged archive bytes."""
    memory = io.BytesIO()
    with zipfile.ZipFile(memory, "w") as archive:
        for path in sorted(worker_bundle.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(worker_bundle).as_posix())
    payload = memory.getvalue()

    return payload


class LocalAPI(GitHubActionsAPI):
    """Provide local exact-ID Actions responses."""

    def __init__(self, payload: bytes) -> None:
        super().__init__("https://api.github.com", "owner/repo", "fixture-token")
        self.payload = payload

    def step_log(self, job_id: int, number: int) -> bytes:
        assert (job_id, number) == (10, 5)
        return f"2026-11-22T00:00:00.000Z ARTIFACT_RECEIPT 123 {BATCH} {WORKER} 456\n".encode()

    def metadata(self, artifact_id: int) -> dict:
        assert artifact_id == 456
        return {
            "id": 456,
            "name": f"workflow-internal-worker-bundle-{BATCH}-{WORKER}",
            "expired": False,
            "workflow_run": {"id": 123},
            "digest": "sha256:" + hashlib.sha256(self.payload).hexdigest(),
        }

    def artifact_zip(self, artifact_id: int) -> bytes:
        assert artifact_id == 456
        return self.payload


def _correlate_and_restore(tmp_path: Path) -> None:
    """Stage a worker bundle and restore the correlated archive."""
    worker_root = tmp_path / "worker"
    aggregate_root = tmp_path / "aggregate"
    cache_log = PathLayout(worker_root).output.worker_cache_log_path(
        batch_id=BATCH, worker_id=WORKER
    )
    worker_bundle = tmp_path / "worker-bundle"
    worker_request = HandoffRequest("worker-aggregate", BATCH, worker_id=WORKER)
    stage_handoff(
        state_root=worker_root, destination=worker_bundle, request=worker_request
    )
    worker_members = PathLayout(worker_root).worker_to_aggregator.members(
        batch_id=BATCH, worker_id=WORKER
    )
    _assert_json_artifacts_match_declared_members(
        worker_bundle, {member.archive_path for member in worker_members}
    )
    staged_cache = worker_bundle / PathLayout(
        Path(".")
    ).workflow_state.worker_handoff_cache_path(batch_id=BATCH, worker_id=WORKER)
    with closing(sqlite3.connect(staged_cache)) as db:
        assert db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert db.execute("SELECT domain FROM delegation_history").fetchall() == [
            ("example.net",)
        ]
    payload = _archive_worker_bundle(worker_bundle)

    jobs = [
        {
            "name": f"batch / Run workers ({WORKER})",
            "id": 10,
            "status": "completed",
            "conclusion": "success",
            "steps": [
                {
                    "name": "Upload worker bundle",
                    "status": "completed",
                    "conclusion": "success",
                    "number": 4,
                },
                {
                    "name": "Record worker artifact receipt",
                    "status": "completed",
                    "conclusion": "success",
                    "number": 5,
                },
            ],
        }
    ]
    accepted = correlate_worker(LocalAPI(payload), jobs, "123", BATCH, WORKER)
    restored_bundle = tmp_path / "validated-bundle"
    for name, data in accepted.items():
        target = restored_bundle / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    assert (
        restored_bundle / cache_log.relative_to(worker_root)
    ).read_text() == "cache fixture log\n"
    assert (
        hashlib.sha256(
            (restored_bundle / staged_cache.relative_to(worker_bundle)).read_bytes()
        ).digest()
        == hashlib.sha256(staged_cache.read_bytes()).digest()
    )
    restore_handoff(
        state_root=aggregate_root, source=restored_bundle, request=worker_request
    )


def _assert_aggregate(tmp_path: Path) -> None:
    """Run aggregation and verify published data, logs, and cache."""
    aggregate_root = tmp_path / "aggregate"
    outcome = AggregateBatchRunner().run(batch_id=BATCH, state_root=aggregate_root)
    assert outcome["state"] == "aggregated"
    assert outcome["cache_merge_summary"]["merged_cache_count"] == 1
    publish_root = PathLayout(aggregate_root).output.publish_worktree_root()
    assert (publish_root / "output/filtered/block.txt").read_text() == ""
    assert (
        publish_root / "output/unactionable/block.txt"
    ).read_text() == "bad.example.net\n"
    assert (publish_root / "output/filtered/block_easylist.txt").read_text() == ""
    with (publish_root / "output/review/block.csv").open(
        newline="", encoding="utf-8"
    ) as handle:
        assert [
            (row["host"], row["review_reason"]) for row in csv.DictReader(handle)
        ] == [("ads.example.com", "fixture reason")]
    audit = (aggregate_root / outcome["final_debug_paths"]["raw_audit"]).read_text(
        encoding="utf-8"
    )
    audit_rows = [json.loads(line) for line in audit.splitlines()]
    worker_results = _domain_results_fixture()
    expected_audit_rows = [
        *worker_results["registrable_domain_results"],
        *worker_results["input_domain_results"],
    ]
    assert len(audit_rows) == len(expected_audit_rows)
    assert {
        json.dumps(row, sort_keys=True, separators=(",", ":"))
        for row in audit_rows
    } == {
        json.dumps(row, sort_keys=True, separators=(",", ":"))
        for row in expected_audit_rows
    }
    assert (
        "worker fixture log"
        in (aggregate_root / outcome["final_debug_paths"]["runtime_log"]).read_text()
    )
    with closing(
        sqlite3.connect(aggregate_root / outcome["final_state_paths"]["cache"])
    ) as db:
        assert db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert db.execute("SELECT domain FROM delegation_history").fetchall() == [
            ("example.net",)
        ]


def test_local_handoffs_reach_aggregate_success(tmp_path: Path) -> None:
    """Exercise all three handoff directions through aggregate success."""
    _prepare_and_restore(tmp_path)
    _finish_worker(tmp_path)
    _correlate_and_restore(tmp_path)
    _assert_aggregate(tmp_path)


def test_aggregate_loads_worker_results_without_worker_input_manifest(
    tmp_path: Path,
) -> None:
    """Aggregate consumes worker results without restoring worker assignments."""
    _prepare_and_restore(tmp_path)
    _finish_worker(tmp_path)
    _correlate_and_restore(tmp_path)
    aggregate_root = tmp_path / "aggregate"
    paths = PathLayout(aggregate_root).workflow_state
    worker_config = paths.prepare_worker_config_path(
        batch_id=BATCH, worker_id=WORKER
    )
    assert not worker_config.exists()

    manifest = load_worker_aggregate_manifest(
        paths.worker_aggregate_manifest_path(batch_id=BATCH, worker_id=WORKER),
        state_root=aggregate_root,
        batch_id=BATCH,
        worker_id=WORKER,
    )

    assert manifest.handoff_finalized
    assert [row.input_domain for row in manifest.input_domain_results] == [
        "ads.example.com",
        "bad.example.net",
    ]
