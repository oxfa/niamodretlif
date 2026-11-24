"""Focused tests for exact worker artifact receipts and handoffs."""

from __future__ import annotations

import hashlib
import io
import unittest
import zipfile
from pathlib import Path

import pytest
import yaml

from domain_pipeline.aggregate.runner import AggregateBatchRunner
from domain_pipeline.aggregate.cache_merge import AggregateCacheMerger
from domain_pipeline.paths import PathLayout
from domain_pipeline.pipeline_run.format_version import PIPELINE_RUN_FORMAT_VERSION
from domain_pipeline.worker.output.rows import REVIEW_OUTPUT_COLUMNS
from domain_pipeline.worker.worker_to_aggregate_manifest import (
    load_worker_aggregate_manifest_for_worker,
)


from worker_artifact_correlation import (
    CorrelationError,
    GitHubActionsAPI,
    correlate_worker,
    receipt_id,
    select_job,
    validate_archive,
)

RUN = "123"
BATCH = "batch-123-attempt-1"
WORKER = "worker-01"
ARTIFACT = 456


def job(
    worker: str = WORKER,
    *,
    job_id: int = 10,
    upload: str = "success",
    receipt: str = "success",
    conclusion: str = "success",
    upload_number: int = 4,
    receipt_number: int = 5,
) -> dict:
    """Build a completed worker job record."""
    return {
        "name": f"batch / Run workers ({worker})",
        "id": job_id,
        "status": "completed",
        "conclusion": conclusion,
        "steps": [
            {
                "name": "Upload worker bundle",
                "status": "completed",
                "conclusion": upload,
                "number": upload_number,
            },
            {
                "name": "Record worker artifact receipt",
                "status": "completed",
                "conclusion": receipt,
                "number": receipt_number,
            },
        ],
    }


def successful_result_members(
    worker: str = WORKER, *, batch: str = BATCH
) -> dict[str, bytes]:
    """Return every required document in a successful worker result."""
    paths = PathLayout(Path(".")).workflow_state
    return {
        paths.worker_aggregate_manifest_path(batch_id=batch, worker_id=worker).as_posix(): yaml.safe_dump(
            {
                "automation_format_version": PIPELINE_RUN_FORMAT_VERSION,
                "batch_id": batch,
                "worker_id": worker,
                "handoff_finalized": True,
                "cache_present": False,
                "cache_sha256": None,
            }
        ).encode(),
        paths.worker_status_path(batch_id=batch, worker_id=worker).as_posix(): yaml.safe_dump(
            {
                "automation_format_version": PIPELINE_RUN_FORMAT_VERSION,
                "batch_id": batch,
                "worker_id": worker,
                "conclusion": "success",
            }
        ).encode(),
        paths.worker_handoff_unactionable_path(
            batch_id=batch, worker_id=worker
        ).as_posix(): b"",
        paths.worker_handoff_review_path(batch_id=batch, worker_id=worker).as_posix(): (
            ",".join(REVIEW_OUTPUT_COLUMNS) + "\n"
        ).encode(),
        paths.worker_handoff_terminal_path(batch_id=batch, worker_id=worker).as_posix(): (
            b"---\n[]\n"
        ),
        f".debug_artifacts/workers/{batch}/{worker}/logs/worker.log": b"worker log",
    }


def archive_bytes(members: dict[str, bytes]) -> bytes:
    """Encode one archive from canonical member paths and byte payloads."""
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for path, payload in members.items():
            archive.writestr(path, payload)
    return stream.getvalue()


def archive_for(worker: str = WORKER, *, batch: str = BATCH) -> bytes:
    """Build a complete successful result archive for a worker."""
    return archive_bytes(successful_result_members(worker, batch=batch))


def archive_digest(payload: bytes) -> str:
    """Return the artifact API digest representation for archive bytes."""
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def validate_complete_archive(
    payload: bytes, batch_id: str = BATCH, worker_id: str = WORKER
) -> dict[str, bytes]:
    """Validate a fixture archive with the digest required by the API contract."""
    return validate_archive(
        payload, archive_digest(payload), batch_id, worker_id
    )


class FakeAPI(GitHubActionsAPI):
    """Provide deterministic artifact records without network requests."""

    def __init__(self) -> None:
        super().__init__("https://api.github.com", "oxfa/niamodretlif", "fixture-token")
        self.archive = archive_for()
        self.requested: list[tuple] = []

    def step_log(self, job_id: int, number: int) -> bytes:
        """Return a receipt and record the requested job step."""
        self.requested.append(("step", job_id, number))
        return (
            f"2026-11-22T18:45:08.0783380Z ARTIFACT_RECEIPT {RUN} "
            f"{BATCH} {WORKER} {ARTIFACT}\n"
        ).encode()

    def metadata(self, artifact_id: int) -> dict:
        """Return metadata matching the fake artifact."""
        self.requested.append(("metadata", artifact_id))
        return {
            "id": artifact_id,
            "name": f"workflow-internal-worker-bundle-{BATCH}-{WORKER}",
            "expired": False,
            "workflow_run": {"id": int(RUN)},
            "digest": archive_digest(self.archive),
        }

    def artifact_zip(self, artifact_id: int) -> bytes:
        """Return the fake archive and record the download."""
        self.requested.append(("download", artifact_id))
        return self.archive


class CorrelationTests(unittest.TestCase):
    """Exercise receipt and artifact correlation."""

    def test_copied_untouched_job_receipt_uses_exact_id(self) -> None:
        """Test copied untouched job receipt uses exact id."""
        api = FakeAPI()
        files = correlate_worker(api, [job(job_id=99)], RUN, BATCH, WORKER)
        self.assertIn(f".workflow_state/status/{BATCH}/{WORKER}.yaml", files)
        self.assertEqual(
            api.requested, [("step", 99, 5), ("metadata", 456), ("download", 456)]
        )

    def test_artifact_metadata_requires_digest_before_download(self) -> None:
        """Only metadata with a well-formed digest can authorize ZIP validation."""
        for digest_present, digest in (
            (False, None),
            (True, None),
            (True, "sha256:bad"),
            (True, 1),
        ):
            with self.subTest(digest_present=digest_present, digest=digest):
                api = FakeAPI()
                original_metadata = api.metadata

                def metadata(artifact_id: int) -> dict:
                    result = original_metadata(artifact_id)
                    if digest_present:
                        result["digest"] = digest
                    else:
                        result.pop("digest")
                    return result

                api.metadata = metadata
                with self.assertRaisesRegex(CorrelationError, "digest"):
                    correlate_worker(api, [job()], RUN, BATCH, WORKER)
                self.assertEqual(
                    api.requested, [("step", 10, 5), ("metadata", ARTIFACT)]
                )

    def test_rerun_skipping_upload_cannot_select_old_artifact(self) -> None:
        """Test rerun skipping upload cannot select old artifact."""
        api = FakeAPI()
        with self.assertRaises(CorrelationError):
            correlate_worker(
                api,
                [job(upload="skipped", receipt="skipped", conclusion="failure")],
                RUN,
                BATCH,
                WORKER,
            )
        self.assertEqual(api.requested, [])

    def test_failed_job_with_successful_upload_is_rejected(self) -> None:
        """Never accept a worker artifact from a failed worker job."""
        with self.assertRaises(CorrelationError):
            select_job([job(conclusion="failure")], WORKER)

    def test_boolean_ids_and_step_numbers_are_rejected(self) -> None:
        """Booleans and invalid upload/receipt step numbers are rejected."""
        entry = job()
        entry["id"] = True
        with self.assertRaises(CorrelationError):
            select_job([entry], WORKER)
        entry = job()
        entry["steps"][1]["number"] = True
        with self.assertRaises(CorrelationError):
            select_job([entry], WORKER)
        entry = job(upload_number=0)
        with self.assertRaises(CorrelationError):
            select_job([entry], WORKER)
        entry = job(upload_number=5, receipt_number=4)
        with self.assertRaises(CorrelationError):
            select_job([entry], WORKER)
        entry = job(upload_number=4, receipt_number=6)
        with self.assertRaises(CorrelationError):
            select_job([entry], WORKER)
        api = GitHubActionsAPI(
            "https://api.github.com", "oxfa/niamodretlif", "test-token"
        )
        api.json = lambda path: {"total_count": True, "jobs": []}
        with self.assertRaises(CorrelationError):
            api.latest_jobs(RUN)
        api.json = lambda path: {"total_count": 1, "jobs": [{"id": True}]}
        with self.assertRaises(CorrelationError):
            api.latest_jobs(RUN)

    def test_receipt_rejects_duplicate_and_wrong_identity(self) -> None:
        """Test receipt rejects duplicate and wrong identity."""
        line = (
            f"2026-11-22T18:45:08.0783380Z ARTIFACT_RECEIPT {RUN} "
            f"{BATCH} {WORKER} {ARTIFACT}\n"
        ).encode()
        with self.assertRaises(CorrelationError):
            receipt_id(line + line, RUN, BATCH, WORKER)
        for run_id, batch_id, worker_id in (
            ("124", BATCH, WORKER),
            (RUN, "batch-other", WORKER),
            (RUN, BATCH, "worker-02"),
        ):
            with self.subTest(run_id=run_id, batch_id=batch_id, worker_id=worker_id):
                with self.assertRaises(CorrelationError):
                    receipt_id(line, run_id, batch_id, worker_id)
        bogus_prefix = (
            f"unexpected ARTIFACT_RECEIPT {RUN} {BATCH} {WORKER} {ARTIFACT}\n"
        ).encode()
        with self.assertRaisesRegex(CorrelationError, "timestamp prefix"):
            receipt_id(bogus_prefix, RUN, BATCH, WORKER)

    def test_receipt_rejects_impossible_timestamp_values(self) -> None:
        """Calendar and clock fields must form a real UTC timestamp."""
        for timestamp in (
            "2026-13-22T18:45:08.0783380Z",
            "2026-02-29T18:45:08.0783380Z",
            "2026-11-22T25:45:08.0783380Z",
            "2026-11-22T18:45:60.0783380Z",
        ):
            log = (
                f"{timestamp} ARTIFACT_RECEIPT {RUN} {BATCH} "
                f"{WORKER} {ARTIFACT}\n"
            ).encode()
            with self.subTest(timestamp=timestamp):
                with self.assertRaisesRegex(CorrelationError, "timestamp prefix"):
                    receipt_id(log, RUN, BATCH, WORKER)

    def test_receipt_rejects_nonpositive_artifact_ids(self) -> None:
        """Only canonical positive decimal artifact IDs are accepted."""
        for artifact_id in ("0", "-1"):
            log = (
                f"2026-11-22T18:45:08.0783380Z ARTIFACT_RECEIPT {RUN} "
                f"{BATCH} {WORKER} {artifact_id}\n"
            ).encode()
            with self.subTest(artifact_id=artifact_id):
                with self.assertRaises(CorrelationError):
                    receipt_id(log, RUN, BATCH, WORKER)

    def test_missing_step_log_is_incomplete_without_fallback(self) -> None:
        """Test missing step log is incomplete without fallback."""
        api = FakeAPI()

        def missing_log(job_id: int, number: int) -> bytes:
            """Simulate a missing receipt log."""
            raise CorrelationError(f"missing log for {job_id} step {number}")

        api.step_log = missing_log
        with self.assertRaises(CorrelationError):
            correlate_worker(api, [job()], RUN, BATCH, WORKER)
        self.assertEqual(api.requested, [])

    def test_unavailable_exact_artifact_does_not_try_an_older_id(self) -> None:
        """Test unavailable exact artifact does not try an older id."""
        api = FakeAPI()

        def unavailable(artifact_id: int) -> bytes:
            """Simulate an unavailable artifact download."""
            api.requested.append(("download", artifact_id))
            raise CorrelationError("artifact unavailable")

        api.artifact_zip = unavailable
        with self.assertRaises(CorrelationError):
            correlate_worker(api, [job()], RUN, BATCH, WORKER)
        self.assertEqual(
            api.requested, [("step", 10, 5), ("metadata", 456), ("download", 456)]
        )

    def test_duplicate_latest_job_names_are_incomplete(self) -> None:
        """Test duplicate latest job names are incomplete."""
        with self.assertRaises(CorrelationError):
            select_job([job(job_id=10), job(job_id=11)], WORKER)

    def test_rejects_wrong_identity_inside_allowed_status_path(self) -> None:
        """Test rejects wrong identity inside allowed status path."""
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr(
                f".workflow_state/status/{BATCH}/{WORKER}.yaml",
                yaml.safe_dump({"batch_id": BATCH, "worker_id": "worker-02"}),
            )
        with self.assertRaises(CorrelationError):
            validate_complete_archive(stream.getvalue())

    def test_rejects_wrong_state_identity_and_digest(self) -> None:
        """Test rejects wrong state identity and digest."""
        with self.assertRaises(CorrelationError):
            validate_complete_archive(archive_for(batch="batch-123-attempt-2"))
        with self.assertRaises(CorrelationError):
            validate_archive(archive_for(), "sha256:" + "0" * 64, BATCH, WORKER)

    def test_diagnostic_only_bundle_is_rejected(self) -> None:
        """Diagnostic artifacts from failed jobs cannot enter aggregate."""
        path = (
            PathLayout(Path("."))
            .output.worker_cache_log_path(batch_id=BATCH, worker_id=WORKER)
            .as_posix()
        )
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr(path, "cache diagnostic")
        with self.assertRaises(CorrelationError):
            validate_complete_archive(stream.getvalue())

    def test_rejects_wrong_identity_inside_allowed_handoff_state(self) -> None:
        """The state member is identity checked even without a status member."""
        path = (
            PathLayout(Path("."))
            .workflow_state.worker_aggregate_manifest_path(
                batch_id=BATCH, worker_id=WORKER
            )
            .as_posix()
        )
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr(
                path, yaml.safe_dump({"batch_id": BATCH, "worker_id": "worker-02"})
            )
        with self.assertRaises(CorrelationError):
            validate_complete_archive(stream.getvalue())

    def test_pagination_requires_complete_jobs(self) -> None:
        """Test pagination requires complete jobs."""
        api = GitHubActionsAPI(
            "https://api.github.com", "oxfa/niamodretlif", "test-token"
        )
        pages = [job(job_id=i) for i in range(1, 102)]
        api.json = lambda path: {
            "total_count": 101,
            "jobs": pages[:100] if path.endswith("&page=1") else pages[100:],
        }
        self.assertEqual(len(api.latest_jobs(RUN)), 101)
        api.json = lambda path: {"total_count": 1, "jobs": []}
        with self.assertRaises(CorrelationError):
            api.latest_jobs(RUN)


@pytest.mark.parametrize("missing", ["unactionable", "review", "terminal", "cache"])
def test_finalized_archive_missing_declared_data_is_incomplete(missing: str) -> None:
    """Finalized handoffs must include each direct result and declared cache."""
    paths = PathLayout(Path(".")).workflow_state
    members = successful_result_members()
    state_path = paths.worker_aggregate_manifest_path(
        batch_id=BATCH, worker_id=WORKER
    ).as_posix()
    state = yaml.safe_load(members[state_path])
    state.update(
        cache_present=True,
        cache_sha256=hashlib.sha256(b"cache").hexdigest(),
    )
    members[state_path] = yaml.safe_dump(state).encode()
    cache_path = paths.worker_handoff_cache_path(
        batch_id=BATCH, worker_id=WORKER
    ).as_posix()
    members[cache_path] = b"cache"
    missing_path = {
        "unactionable": paths.worker_handoff_unactionable_path(
            batch_id=BATCH, worker_id=WORKER
        ),
        "review": paths.worker_handoff_review_path(
            batch_id=BATCH, worker_id=WORKER
        ),
        "terminal": paths.worker_handoff_terminal_path(
            batch_id=BATCH, worker_id=WORKER
        ),
        "cache": paths.worker_handoff_cache_path(
            batch_id=BATCH, worker_id=WORKER
        ),
    }[missing].as_posix()
    members.pop(missing_path)
    with pytest.raises(CorrelationError):
        validate_complete_archive(archive_bytes(members))


@pytest.mark.parametrize("conclusion", [None, "unknown", 1, "failure"])
def test_status_requires_valid_conclusion(conclusion: object) -> None:
    """Require current worker identity and successful conclusion in status."""
    path = PathLayout(Path(".")).workflow_state.worker_status_path(
        batch_id=BATCH, worker_id=WORKER
    )
    members = successful_result_members()
    members[path.as_posix()] = yaml.safe_dump(
        {
            "automation_format_version": PIPELINE_RUN_FORMAT_VERSION,
            "batch_id": BATCH,
            "worker_id": WORKER,
            "conclusion": conclusion,
        }
    ).encode()
    with pytest.raises(CorrelationError):
        validate_complete_archive(archive_bytes(members))


@pytest.mark.parametrize(
    "changes",
    [
        {"automation_format_version": PIPELINE_RUN_FORMAT_VERSION - 1},
        {"automation_format_version": PIPELINE_RUN_FORMAT_VERSION + 1},
        {"worker_id": "worker-02"},
        {"batch_id": "batch-123-attempt-2"},
    ],
)
def test_status_requires_current_identity_and_format(changes: dict) -> None:
    """Status documents must match the active batch, worker, and format."""
    path = PathLayout(Path(".")).workflow_state.worker_status_path(
        batch_id=BATCH, worker_id=WORKER
    )
    members = successful_result_members()
    status = yaml.safe_load(members[path.as_posix()])
    status.update(changes)
    members[path.as_posix()] = yaml.safe_dump(status).encode()
    with pytest.raises(CorrelationError):
        validate_complete_archive(archive_bytes(members))


def test_unfinalized_handoff_is_rejected() -> None:
    """A worker result must be finalized before aggregate correlation accepts it."""
    paths = PathLayout(Path(".")).workflow_state
    path = paths.worker_aggregate_manifest_path(
        batch_id=BATCH, worker_id=WORKER
    ).as_posix()
    members = successful_result_members()
    state = yaml.safe_load(members[path])
    state["handoff_finalized"] = False
    members[path] = yaml.safe_dump(state).encode()
    with pytest.raises(CorrelationError, match="not finalized"):
        validate_complete_archive(archive_bytes(members))


@pytest.mark.parametrize(
    "changes",
    [
        {"handoff_finalized": "true"},
        {"cache_present": 1},
        {"cache_present": True, "cache_sha256": None},
        {"unexpected": "field"},
    ],
)
def test_handoff_state_requires_valid_shape(changes: dict) -> None:
    """Check archive validation for the given handoff case."""
    paths = PathLayout(Path(".")).workflow_state
    path = paths.worker_aggregate_manifest_path(
        batch_id=BATCH, worker_id=WORKER
    ).as_posix()
    members = successful_result_members()
    state = yaml.safe_load(members[path])
    state.update(changes)
    members[path] = yaml.safe_dump(state).encode()
    with pytest.raises(CorrelationError):
        validate_complete_archive(archive_bytes(members))


@pytest.mark.parametrize("cache_payload", [b"cache", b"corrupted"])
def test_complete_finalized_archive_with_cache_is_accepted(
    cache_payload: bytes,
) -> None:
    """Check archive validation for the given handoff case."""
    paths = PathLayout(Path(".")).workflow_state
    state_path = paths.worker_aggregate_manifest_path(
        batch_id=BATCH, worker_id=WORKER
    ).as_posix()
    members = successful_result_members()
    state = yaml.safe_load(members[state_path])
    state.update(
        cache_present=True,
        cache_sha256=hashlib.sha256(b"cache").hexdigest(),
    )
    members[state_path] = yaml.safe_dump(state).encode()
    cache_path = paths.worker_handoff_cache_path(
        batch_id=BATCH, worker_id=WORKER
    ).as_posix()
    members[cache_path] = cache_payload
    assert set(validate_complete_archive(archive_bytes(members))) == set(members)


@pytest.mark.parametrize(
    ("member", "invalid"),
    [
        ("terminal", b"---\n[broken\n"),
        ("terminal", b"---\n- 42\n"),
        ("terminal", b"---\n- date: 2020-01-01\n"),
        ("review", b"wrong,header\n"),
        ("review", (",".join(REVIEW_OUTPUT_COLUMNS) + "\nshort\n").encode()),
        (
            "review",
            (
                ",".join(REVIEW_OUTPUT_COLUMNS)
                + "\n"
                + ",".join(["x"] * (len(REVIEW_OUTPUT_COLUMNS) + 1))
                + "\n"
            ).encode(),
        ),
        ("unactionable", b"\xff"),
    ],
)
def test_finalized_malformed_data_is_incomplete(member: str, invalid: bytes) -> None:
    """Check archive validation for the given handoff case."""
    paths = PathLayout(Path(".")).workflow_state
    members = successful_result_members()
    member_path = {
        "terminal": paths.worker_handoff_terminal_path(
            batch_id=BATCH, worker_id=WORKER
        ),
        "review": paths.worker_handoff_review_path(
            batch_id=BATCH, worker_id=WORKER
        ),
        "unactionable": paths.worker_handoff_unactionable_path(
            batch_id=BATCH, worker_id=WORKER
        ),
    }[member].as_posix()
    members[member_path] = invalid
    with pytest.raises(CorrelationError):
        validate_complete_archive(archive_bytes(members))


def test_finalized_cache_checksum_mismatch_is_counted_invalid(tmp_path: Path) -> None:
    """A corrupted cache remains an invalid-cache result instead of blocking readiness."""
    layout = PathLayout(tmp_path)
    archive = archive_for()
    for name, data in validate_complete_archive(archive).items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    state = layout.workflow_state
    handoff_path = state.worker_aggregate_manifest_path(
        batch_id=BATCH, worker_id=WORKER
    )
    handoff = yaml.safe_load(handoff_path.read_text(encoding="utf-8"))
    handoff.update(
        cache_present=True, cache_sha256=hashlib.sha256(b"original").hexdigest()
    )
    handoff_path.write_text(yaml.safe_dump(handoff), encoding="utf-8")
    cache = state.worker_handoff_cache_path(batch_id=BATCH, worker_id=WORKER)
    cache.write_bytes(b"corrupted")
    manifest = load_worker_aggregate_manifest_for_worker(
        batch_id=BATCH, worker_id=WORKER, state_root=tmp_path
    )
    assert manifest is not None and manifest.handoff_finalized

    class CacheRunner(AggregateBatchRunner):
        """Expose the cache materialization stage for this integration check."""

        def materialize(self) -> list[Path]:
            """Materialize the validated fixture cache."""
            return self._materialize_worker_cache_payloads(
                batch_id=BATCH, state_root=tmp_path, worker_manifests=[manifest]
            )

    sources = CacheRunner().materialize()
    result = AggregateCacheMerger().merge(
        source_paths=sources, target_path=tmp_path / "merged.sqlite3"
    )
    assert result["invalid_cache_count"] == 1
    assert result["missing_cache_count"] == 0


if __name__ == "__main__":
    unittest.main()
