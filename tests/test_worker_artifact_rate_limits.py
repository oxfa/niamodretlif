"""Regression coverage for stopping correlation after a denied request."""

from __future__ import annotations

import sys
import urllib.error
from collections.abc import Callable
from email.message import Message
from pathlib import Path
from types import SimpleNamespace

import pytest

import worker_artifact_correlation as correlation


@pytest.mark.parametrize("response", [(403, False), (403, True), (429, False), (429, True)])
def test_denied_request_stops_remaining_workers_but_keeps_accepted_bundle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    response: tuple[int, bool],
    correlation_args: Callable[[str], list[str]],
) -> None:
    """Avoid more requests after a response that could indicate rate limiting."""
    status, redirected = response
    requests: list[str] = []

    def open_response(_request: object, **_kwargs: object) -> None:
        """Simulate an API response or download redirect."""
        requests.append("api")
        if redirected:
            headers = Message()
            headers["Location"] = "https://example.invalid/artifact"
            raise urllib.error.HTTPError(
                "https://api.github.com/fixture", 302, "Found", headers, None
            )
        raise urllib.error.HTTPError(
            "https://api.github.com/fixture", status, "Denied", Message(), None
        )

    def denied_download(*_args: object, **_kwargs: object) -> None:
        """Simulate a denied signed download."""
        requests.append("download")
        raise urllib.error.HTTPError(
            "https://example.invalid/artifact", status, "Denied", Message(), None
        )

    def correlate(
        api: correlation.GitHubActionsAPI, _jobs: object, _run: str, _batch: str, worker: str
    ) -> dict[str, bytes]:
        """Exercise the denied request while correlating a worker."""
        if worker == "worker-01":
            return {"accepted.txt": b"kept"}
        api.step_log(2, 5)
        raise AssertionError("the denied request should not return")

    monkeypatch.setattr(
        sys,
        "argv",
        correlation_args('["worker-01", "worker-02", "worker-03"]'),
    )
    monkeypatch.setenv("GH_TOKEN", "fixture-token")
    monkeypatch.setattr(
        correlation.urllib.request,
        "build_opener",
        lambda *_a, **_k: SimpleNamespace(open=open_response),
    )
    monkeypatch.setattr(correlation.urllib.request, "urlopen", denied_download)
    monkeypatch.setattr(correlation.GitHubActionsAPI, "latest_jobs", lambda *_a: [])
    monkeypatch.setattr(correlation, "correlate_worker", correlate)

    assert correlation.main() == 1
    assert requests == (["api", "download"] if redirected else ["api"])
    bundle = tmp_path / "workflow-internal-worker-bundle-batch-123-attempt-1-worker-01"
    assert (bundle / "accepted.txt").read_bytes() == b"kept"
    captured = capsys.readouterr()
    assert "ACCEPTED worker-01" in captured.out
    assert "INCOMPLETE worker-02" in captured.err
    assert "INCOMPLETE worker-03" in captured.err


@pytest.mark.parametrize("redirected", [False, True], ids=["api", "download"])
def test_missing_artifact_does_not_stop_other_workers(
    monkeypatch: pytest.MonkeyPatch,
    redirected: bool,
    correlation_args: Callable[[str], list[str]],
) -> None:
    """An ordinary 404 remains a worker-local failure."""
    requests: list[str] = []

    def open_response(_request: object, **_kwargs: object) -> None:
        """Simulate an API response or download redirect."""
        requests.append("api")
        if redirected:
            headers = Message()
            headers["Location"] = "https://example.invalid/artifact"
            raise urllib.error.HTTPError(
                "https://api.github.com/fixture", 302, "Found", headers, None
            )
        raise urllib.error.HTTPError(
            "https://api.github.com/fixture", 404, "Not Found", Message(), None
        )

    def missing_download(*_args: object, **_kwargs: object) -> None:
        """Simulate a missing signed download."""
        requests.append("download")
        raise urllib.error.HTTPError(
            "https://example.invalid/artifact", 404, "Not Found", Message(), None
        )

    def correlate(
        api: correlation.GitHubActionsAPI, _jobs: object, _run: str, _batch: str, _worker: str
    ) -> dict[str, bytes]:
        """Exercise the denied request while correlating a worker."""
        api.step_log(2, 5)
        raise AssertionError("the missing request should not return")

    monkeypatch.setattr(
        sys,
        "argv",
        correlation_args('["worker-01", "worker-02"]'),
    )
    monkeypatch.setenv("GH_TOKEN", "fixture-token")
    monkeypatch.setattr(
        correlation.urllib.request,
        "build_opener",
        lambda *_a, **_k: SimpleNamespace(open=open_response),
    )
    monkeypatch.setattr(correlation.urllib.request, "urlopen", missing_download)
    monkeypatch.setattr(correlation.GitHubActionsAPI, "latest_jobs", lambda *_a: [])
    monkeypatch.setattr(correlation, "correlate_worker", correlate)

    assert correlation.main() == 1
    assert requests == (["api", "download", "api", "download"] if redirected else ["api", "api"])


def test_rate_limited_job_listing_marks_all_workers_incomplete(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    correlation_args: Callable[[str], list[str]],
) -> None:
    """Test rate limited job listing marks all workers incomplete."""
    requests: list[str] = []

    def open_response(_request: object, **_kwargs: object) -> None:
        """Simulate an API response or download redirect."""
        requests.append("api")
        raise urllib.error.HTTPError(
            "https://api.github.com/fixture", 429, "Too Many Requests", Message(), None
        )

    monkeypatch.setattr(
        sys,
        "argv",
        correlation_args('["worker-01", "worker-02"]'),
    )
    monkeypatch.setenv("GH_TOKEN", "fixture-token")
    monkeypatch.setattr(
        correlation.urllib.request,
        "build_opener",
        lambda *_a, **_k: SimpleNamespace(open=open_response),
    )

    assert correlation.main() == 1
    assert requests == ["api"]
    output = capsys.readouterr().err
    assert "INCOMPLETE worker-01" in output
    assert "INCOMPLETE worker-02" in output
