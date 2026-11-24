"""Regression tests for incomplete and rate-limited artifact API responses."""

from __future__ import annotations

import http.client
import sys
import time
import urllib.error
from collections.abc import Callable
from email.message import Message
from types import SimpleNamespace

import pytest

import worker_artifact_correlation as correlation


class TruncatedResponse:
    """Response fixture whose body is incomplete."""

    def __enter__(self) -> TruncatedResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        """Simulate an interrupted response body."""
        # Valid JSON ensures decoding cannot mask an incorrectly returned partial body.
        raise http.client.IncompleteRead(b"{}", 5)


@pytest.mark.parametrize("redirected", [False, True], ids=["api", "download"])
def test_truncated_response_is_classified_as_incomplete(
    monkeypatch: pytest.MonkeyPatch, redirected: bool
) -> None:
    """Both API bodies and signed-download bodies must fail closed per worker."""

    def open_response(_request: object, **_kwargs: object) -> TruncatedResponse:
        """Simulate the API response or its download redirect."""
        if redirected:
            headers = Message()
            headers["Location"] = "https://example.invalid/signed-download"
            raise urllib.error.HTTPError(
                "https://api.github.com/fixture", 302, "Found", headers, None
            )
        return TruncatedResponse()

    api = correlation.GitHubActionsAPI(
        "https://api.github.com", "oxfa/niamodretlif", "fixture-token"
    )
    monkeypatch.setattr(api, "_opener", SimpleNamespace(open=open_response))
    monkeypatch.setattr(
        correlation.urllib.request, "urlopen", lambda *_a, **_k: TruncatedResponse()
    )

    expected_error = (
        "redirected download unavailable" if redirected else "GitHub API request unavailable"
    )
    with pytest.raises(correlation.CorrelationError, match=expected_error):
        if redirected:
            api.step_log(1, 5)
        else:
            api.json("/jobs/1/steps/5/logs")


def test_rate_limit_stops_or_waits_before_another_worker_request(
    monkeypatch: pytest.MonkeyPatch, correlation_args: Callable[[str], list[str]]
) -> None:
    """A 429 Retry-After must prevent immediate follow-on API requests."""
    jobs = [
        {
            "name": f"batch / Run workers (worker-{index:02d})",
            "id": index,
            "status": "completed",
            "conclusion": "success",
            "steps": [
                {
                    "name": correlation.UPLOAD_STEP,
                    "status": "completed",
                    "conclusion": "success",
                    "number": 4,
                },
                {
                    "name": correlation.RECEIPT_STEP,
                    "status": "completed",
                    "conclusion": "success",
                    "number": 5,
                },
            ],
        }
        for index in (1, 2)
    ]
    now = [0.0]
    request_times: list[float] = []

    class StopAfterSecondRequest(Exception):
        """Stop the test if an unexpected follow-on request occurs."""

    def open_response(_request: object, **_kwargs: object) -> None:
        """Simulate the API response or its download redirect."""
        request_times.append(now[0])
        if len(request_times) > 1:
            raise StopAfterSecondRequest
        headers = Message()
        headers["Retry-After"] = "60"
        raise urllib.error.HTTPError(
            "https://api.github.com/fixture", 429, "Too Many Requests", headers, None
        )

    args = correlation_args('["worker-01", "worker-02"]')
    with monkeypatch.context() as scoped:
        scoped.setattr(sys, "argv", args)
        scoped.setenv("GH_TOKEN", "fixture-token")
        scoped.setattr(
            correlation.urllib.request,
            "build_opener",
            lambda *_a, **_k: SimpleNamespace(open=open_response),
        )
        scoped.setattr(correlation.GitHubActionsAPI, "latest_jobs", lambda *_a: jobs)
        scoped.setattr(time, "monotonic", lambda: now[0])
        scoped.setattr(time, "sleep", lambda seconds: now.__setitem__(0, now[0] + seconds))
        try:
            assert correlation.main() == 1
        except StopAfterSecondRequest:
            assert len(request_times) > 1

    assert request_times
    if len(request_times) > 1:
        assert request_times[1] - request_times[0] >= 60
