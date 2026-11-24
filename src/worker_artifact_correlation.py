#!/usr/bin/env python3
# /// script
# dependencies = [
#   "requests>=2.31",
#   "tenacity>=9.0",
#   "dnspython>=2.4",
#   "publicsuffix2>=2.20191221",
#   "PyYAML>=6.0",
#   "pydantic>=2.8,<3",
# ]
# ///
"""Restore worker artifacts only when their latest job records identify them."""

from __future__ import annotations

import argparse
import csv
from datetime import datetime
import hashlib
import http.client
import io
import json
import os
import re
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from domain_pipeline.handoff_io import ensure_csv_field_capacity, validate_yaml_tree
from domain_pipeline.paths import PathLayout
from domain_pipeline.pipeline_run.format_version import PIPELINE_RUN_FORMAT_VERSION
from domain_pipeline.worker.output.rows import REVIEW_OUTPUT_COLUMNS
from domain_pipeline.worker.worker_to_aggregate_manifest import (
    validate_worker_handoff_state,
)

API_VERSION = "2026-03-10"
RECEIPT_MARKER = "ARTIFACT_RECEIPT"
RECEIPT_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]+Z"
)
UPLOAD_STEP = "Upload worker bundle"
RECEIPT_STEP = "Record worker artifact receipt"


class CorrelationError(Exception):
    """Evidence is missing, invalid, or unavailable for a worker."""


class RequestsHaltedError(CorrelationError):
    """Further API requests must stop after a response that may be rate-limited."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        """Decline redirects so credentials remain confined to the API host."""
        return None


class GitHubActionsAPI:
    """Read only current-repository Actions records and exact-ID artifacts."""

    def __init__(self, api_url: str, repository: str, token: str) -> None:
        parsed = urllib.parse.urlparse(api_url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("GitHub API URL must be HTTPS")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise ValueError("invalid repository")
        if not token:
            raise ValueError("GH_TOKEN is required")
        self.base = f"{api_url.rstrip('/')}/repos/{repository}/actions"
        self.token = token
        self._opener = urllib.request.build_opener(_NoRedirect())

    def _get(self, path: str, *, redirected: bool = False) -> bytes:
        request = urllib.request.Request(
            self.base + path,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": API_VERSION,
            },
        )
        try:
            with self._opener.open(request, timeout=60) as response:
                if redirected:
                    raise CorrelationError("expected a download redirect")
                return response.read()
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 429):
                raise RequestsHaltedError(
                    f"GitHub API returned HTTP {exc.code}"
                ) from exc
            if not redirected or exc.code != 302:
                raise CorrelationError(f"GitHub API returned HTTP {exc.code}") from exc
            location = exc.headers.get("Location", "")
            if urllib.parse.urlparse(location).scheme != "https":
                raise CorrelationError("invalid download redirect") from exc
            try:
                # Never forward the repository token to the redirected host.
                with urllib.request.urlopen(location, timeout=60) as response:
                    return response.read()
            except urllib.error.HTTPError as download_error:
                if download_error.code in (403, 429):
                    raise RequestsHaltedError(
                        f"redirected download returned HTTP {download_error.code}"
                    ) from download_error
                raise CorrelationError(
                    "redirected download unavailable"
                ) from download_error
            except (
                urllib.error.URLError,
                TimeoutError,
                OSError,
                http.client.IncompleteRead,
            ) as download_error:
                raise CorrelationError(
                    "redirected download unavailable"
                ) from download_error
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            http.client.IncompleteRead,
        ) as exc:
            raise CorrelationError("GitHub API request unavailable") from exc

    def json(self, path: str) -> Any:
        """Fetch and decode a GitHub API JSON response."""
        try:
            return json.loads(self._get(path))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise CorrelationError("GitHub API returned invalid JSON") from exc

    def latest_jobs(self, run_id: str) -> list[dict[str, Any]]:
        """Retrieve every latest job record for a workflow run."""
        jobs: list[dict[str, Any]] = []
        total: int | None = None
        page = 1
        while total is None or len(jobs) < total:
            result = self.json(
                f"/runs/{run_id}/jobs?per_page=100&filter=latest&page={page}"
            )
            if not isinstance(result, dict) or not isinstance(result.get("jobs"), list):
                raise CorrelationError("invalid jobs listing")
            count = result.get("total_count")
            if (
                not isinstance(count, int)
                or isinstance(count, bool)
                or count < 0
                or (total is not None and total != count)
            ):
                raise CorrelationError("inconsistent jobs listing")
            total = count
            batch = result["jobs"]
            if not batch and len(jobs) < total:
                raise CorrelationError("incomplete jobs listing")
            if any(not isinstance(job, dict) for job in batch):
                raise CorrelationError("invalid job entry")
            jobs.extend(batch)
            page += 1
        if (
            len(jobs) != total
            or any(
                not isinstance(job.get("id"), int) or isinstance(job.get("id"), bool)
                for job in jobs
            )
            or len({job["id"] for job in jobs}) != total
        ):
            raise CorrelationError("ambiguous jobs listing")
        return jobs

    def step_log(self, job_id: int, number: int) -> bytes:
        """Download a specific job step log."""
        return self._get(f"/jobs/{job_id}/steps/{number}/logs", redirected=True)

    def metadata(self, artifact_id: int) -> Any:
        """Fetch metadata for an exact artifact ID."""
        return self.json(f"/artifacts/{artifact_id}")

    def artifact_zip(self, artifact_id: int) -> bytes:
        """Download an archive by exact artifact ID."""
        return self._get(f"/artifacts/{artifact_id}/zip", redirected=True)


def receipt_id(log: bytes, run_id: str, batch_id: str, worker_id: str) -> int:
    """Extract and verify the artifact ID in a worker receipt."""
    try:
        lines = log.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise CorrelationError("invalid receipt log encoding") from exc
    receipts = []
    for line in lines:
        fields = line.split()
        if len(fields) >= 2 and fields[1] == RECEIPT_MARKER:
            if not _valid_receipt_timestamp(fields[0]):
                raise CorrelationError("invalid receipt timestamp prefix")
            receipts.append(fields[1:])
    if len(receipts) != 1 or len(receipts[0]) != 5:
        raise CorrelationError("missing, malformed, or duplicate receipt")
    marker, got_run, got_batch, got_worker, artifact = receipts[0]
    if (marker, got_run, got_batch, got_worker) != (
        RECEIPT_MARKER,
        run_id,
        batch_id,
        worker_id,
    ):
        raise CorrelationError("receipt identity mismatch")
    if not re.fullmatch(r"[1-9][0-9]*", artifact):
        raise CorrelationError("invalid receipt artifact ID")
    return int(artifact)


def _valid_receipt_timestamp(value: str) -> bool:
    """Require the observed UTC prefix shape and valid calendar/time fields."""
    if not RECEIPT_TIMESTAMP.fullmatch(value):
        return False
    try:
        datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return False
    return True


def select_job(jobs: list[dict[str, Any]], worker_id: str) -> tuple[int, int]:
    """Find the completed job and successful receipt step for a worker."""
    name = f"batch / Run workers ({worker_id})"
    matches = [job for job in jobs if job.get("name") == name]
    if (
        len(matches) != 1
        or matches[0].get("status") != "completed"
        or matches[0].get("conclusion") != "success"
    ):
        raise CorrelationError("missing, unfinished, or ambiguous worker job")
    job = matches[0]
    if (
        not isinstance(job.get("id"), int)
        or isinstance(job.get("id"), bool)
        or not isinstance(job.get("steps"), list)
    ):
        raise CorrelationError("invalid worker job")
    selected = []
    for name in (UPLOAD_STEP, RECEIPT_STEP):
        steps = [
            s for s in job["steps"] if isinstance(s, dict) and s.get("name") == name
        ]
        if (
            len(steps) != 1
            or steps[0].get("status") != "completed"
            or steps[0].get("conclusion") != "success"
        ):
            raise CorrelationError(f"{name} did not complete successfully")
        selected.append(steps[0])
    numbers = [step.get("number") for step in selected]
    if any(
        not isinstance(number, int) or isinstance(number, bool) or number < 1
        for number in numbers
    ):
        raise CorrelationError("invalid upload or receipt step number")
    upload_number, receipt_number = numbers
    if receipt_number != upload_number + 1:
        raise CorrelationError("receipt step does not immediately follow upload step")
    return job["id"], receipt_number


def validate_metadata(
    metadata: Any, artifact_id: int, run_id: str, batch_id: str, worker_id: str
) -> str:
    """Verify artifact identity and return its SHA256 digest."""
    expected_name = f"workflow-internal-worker-bundle-{batch_id}-{worker_id}"
    if (
        not isinstance(metadata, dict)
        or type(metadata.get("id")) is not int
        or metadata.get("id") != artifact_id
        or metadata.get("name") != expected_name
        or metadata.get("expired") is not False
    ):
        raise CorrelationError("artifact metadata identity mismatch")
    workflow_run = metadata.get("workflow_run")
    if not isinstance(workflow_run, dict) or str(workflow_run.get("id")) != run_id:
        raise CorrelationError("artifact metadata identity mismatch")
    digest = metadata.get("digest")
    if (
        not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
    ):
        raise CorrelationError("invalid artifact digest")
    return digest


def validate_archive(
    payload: bytes, digest: str, batch_id: str, worker_id: str
) -> dict[str, bytes]:
    """Verify the archive contents and return the allowed files."""
    if f"sha256:{hashlib.sha256(payload).hexdigest()}" != digest:
        raise CorrelationError("artifact digest mismatch")
    members = PathLayout(Path(".")).worker_to_aggregator.members(
        batch_id=batch_id, worker_id=worker_id
    )
    allowed = {member.archive_path.as_posix() for member in members}
    allowed_dirs = {
        parent.as_posix()
        for name in allowed
        for parent in PurePosixPath(name).parents
        if parent.as_posix() != "."
    }
    contents: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            for info in archive.infolist():
                name = info.filename
                mode = info.external_attr >> 16
                if info.is_dir():
                    if name.rstrip("/") not in allowed_dirs:
                        raise CorrelationError("unexpected archive directory")
                    continue
                if name not in allowed or name in contents or stat.S_ISLNK(mode):
                    raise CorrelationError("unexpected or duplicate archive member")
                contents[name] = archive.read(info)
    except (zipfile.BadZipFile, RuntimeError, OSError, EOFError, zlib.error) as exc:
        raise CorrelationError("invalid artifact archive") from exc
    if not contents:
        raise CorrelationError("empty artifact archive")
    _validate_worker_documents(contents, batch_id=batch_id, worker_id=worker_id)
    return contents


def _validate_worker_documents(
    contents: dict[str, bytes], *, batch_id: str, worker_id: str
) -> None:
    """Require successful identity records before restoring a worker result."""
    paths = PathLayout(Path(".")).workflow_state
    state_path = paths.worker_aggregate_manifest_path(
        batch_id=batch_id, worker_id=worker_id
    ).as_posix()
    status_path = paths.worker_status_path(
        batch_id=batch_id, worker_id=worker_id
    ).as_posix()
    required_documents = {state_path, status_path}
    if not required_documents <= contents.keys():
        raise CorrelationError("incomplete worker identity records")
    identities: dict[str, dict[str, Any]] = {}
    for name in required_documents:
        try:
            identity = yaml.safe_load(contents[name])
            validate_yaml_tree(identity)
        except (yaml.YAMLError, UnicodeDecodeError, ValueError) as exc:
            raise CorrelationError("invalid worker state YAML") from exc
        if (
            not isinstance(identity, dict)
            or identity.get("batch_id") != batch_id
            or identity.get("worker_id") != worker_id
        ):
            raise CorrelationError("worker state identity mismatch")
        format_version = identity.get("automation_format_version")
        if (
            not isinstance(format_version, int)
            or isinstance(format_version, bool)
            or format_version != PIPELINE_RUN_FORMAT_VERSION
        ):
            raise CorrelationError("worker state format mismatch")
        identities[name] = identity
    if identities[status_path].get("conclusion") != "success":
        raise CorrelationError("worker status is not successful")
    _validate_handoff_state(
        contents, identities, batch_id=batch_id, worker_id=worker_id
    )


def _validate_handoff_state(
    contents: dict[str, bytes],
    identities: dict[str, dict[str, Any]],
    *,
    batch_id: str,
    worker_id: str,
) -> None:
    """Check handoff metadata and finalized data requirements."""
    paths = PathLayout(Path(".")).workflow_state
    state_path = paths.worker_aggregate_manifest_path(
        batch_id=batch_id, worker_id=worker_id
    ).as_posix()
    try:
        state = validate_worker_handoff_state(
            identities[state_path], batch_id=batch_id, worker_id=worker_id
        )
    except ValueError as exc:
        raise CorrelationError("invalid worker handoff state") from exc
    if not state["handoff_finalized"]:
        raise CorrelationError("worker handoff was not finalized")
    _validate_finalized_contents(
        contents, state, batch_id=batch_id, worker_id=worker_id
    )


def _validate_finalized_contents(
    contents: dict[str, bytes], state: dict[str, Any], *, batch_id: str, worker_id: str
) -> None:
    """Require and validate finalized direct result files."""
    paths = PathLayout(Path(".")).workflow_state
    required = {
        paths.worker_handoff_unactionable_path(
            batch_id=batch_id, worker_id=worker_id
        ).as_posix(),
        paths.worker_handoff_review_path(
            batch_id=batch_id, worker_id=worker_id
        ).as_posix(),
        paths.worker_handoff_terminal_path(
            batch_id=batch_id, worker_id=worker_id
        ).as_posix(),
    }
    cache_path = paths.worker_handoff_cache_path(
        batch_id=batch_id, worker_id=worker_id
    ).as_posix()
    if state["cache_present"]:
        required.add(cache_path)
    elif cache_path in contents:
        raise CorrelationError("unexpected worker cache")
    if not required <= contents.keys():
        raise CorrelationError("incomplete finalized worker handoff")
    terminal_path = paths.worker_handoff_terminal_path(
        batch_id=batch_id, worker_id=worker_id
    ).as_posix()
    review_path = paths.worker_handoff_review_path(
        batch_id=batch_id, worker_id=worker_id
    ).as_posix()
    unactionable_path = paths.worker_handoff_unactionable_path(
        batch_id=batch_id, worker_id=worker_id
    ).as_posix()
    try:
        terminal = yaml.safe_load(contents[terminal_path].decode("utf-8"))
        validate_yaml_tree(terminal)
        if not isinstance(terminal, list) or any(
            not isinstance(row, dict) for row in terminal
        ):
            raise ValueError("terminal rows must be a sequence of mappings")
        ensure_csv_field_capacity(len(contents[review_path]))
        review = csv.DictReader(
            io.StringIO(contents[review_path].decode("utf-8"), newline=""),
            strict=True,
        )
        if review.fieldnames != list(REVIEW_OUTPUT_COLUMNS):
            raise ValueError("invalid review columns")
        for row in review:
            if None in row or any(value is None for value in row.values()):
                raise ValueError("invalid review row")
        contents[unactionable_path].decode("utf-8")
    except (UnicodeDecodeError, yaml.YAMLError, csv.Error, ValueError) as exc:
        raise CorrelationError("invalid finalized worker data") from exc


def correlate_worker(
    api: GitHubActionsAPI,
    jobs: list[dict[str, Any]],
    run_id: str,
    batch_id: str,
    worker_id: str,
) -> dict[str, bytes]:
    """Select and validate the artifact associated with a worker job."""
    job_id, number = select_job(jobs, worker_id)
    artifact_id = receipt_id(api.step_log(job_id, number), run_id, batch_id, worker_id)
    digest = validate_metadata(
        api.metadata(artifact_id), artifact_id, run_id, batch_id, worker_id
    )
    return validate_archive(api.artifact_zip(artifact_id), digest, batch_id, worker_id)


def main() -> int:
    """Restore eligible worker artifacts from the current workflow run."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--worker-ids-json", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    try:
        if not re.fullmatch(r"[1-9][0-9]*", args.run_id) or not re.fullmatch(
            r"batch-[0-9]+-attempt-[0-9]+", args.batch_id
        ):
            raise ValueError("invalid run or batch ID")
        ids = json.loads(args.worker_ids_json)
        if (
            not isinstance(ids, list)
            or not ids
            or any(
                not isinstance(x, str) or not re.fullmatch(r"worker-[0-9]+", x)
                for x in ids
            )
            or len(set(ids)) != len(ids)
        ):
            raise ValueError("invalid expected worker IDs")
        api = GitHubActionsAPI(
            args.api_url, args.repository, os.environ.get("GH_TOKEN", "")
        )
        args.destination.mkdir(parents=True, exist_ok=True)
        if any(args.destination.glob("workflow-internal-worker-bundle-*")):
            raise ValueError("destination contains existing worker bundles")
        try:
            jobs = api.latest_jobs(args.run_id)
        except CorrelationError as exc:
            for worker in ids:
                print(
                    f"INCOMPLETE {worker}: jobs listing unavailable ({exc})",
                    file=sys.stderr,
                )
            return 1
        incomplete_workers: list[str] = []
        for index, worker in enumerate(ids):
            try:
                files = correlate_worker(api, jobs, args.run_id, args.batch_id, worker)
            except RequestsHaltedError as exc:
                for remaining_worker in ids[index:]:
                    print(
                        f"INCOMPLETE {remaining_worker}: requests stopped ({exc})",
                        file=sys.stderr,
                    )
                    incomplete_workers.append(remaining_worker)
                break
            except CorrelationError as exc:
                print(f"INCOMPLETE {worker}: {exc}", file=sys.stderr)
                incomplete_workers.append(worker)
                continue
            root = (
                args.destination
                / f"workflow-internal-worker-bundle-{args.batch_id}-{worker}"
            )
            root.mkdir()
            for name, data in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            print(f"ACCEPTED {worker}")
        if incomplete_workers:
            print(
                "Worker artifact correlation incomplete for: "
                + ", ".join(incomplete_workers),
                file=sys.stderr,
            )
            return 1
        return 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"Correlation setup failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
