"""Regression tests for artifact API failures and recovery."""

from __future__ import annotations

import http.client
import sys
import time
import urllib.error
from collections.abc import Callable
from email.message import Message
from io import BytesIO
from types import SimpleNamespace
from urllib.request import Request

import pytest

import worker_artifact_correlation as correlation


@pytest.mark.parametrize(
    ("method", "args", "path", "redirected"),
    [
        ("step_log", (123, 19), "/jobs/123/steps/19/logs", True),
        ("metadata", (456,), "/artifacts/456", False),
        ("artifact_zip", (456,), "/artifacts/456/zip", True),
    ],
)
def test_bad_gateway_retries_same_api_get(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    args: tuple[int, ...],
    path: str,
    redirected: bool,
) -> None:
    api = correlation.GitHubActionsAPI(
        "https://api.github.com", "oxfa/niamodretlif", "fixture-token"
    )
    calls: list[tuple[str, str, str | None]] = []
    waits: list[float] = []
    location = "https://example.invalid/download"
    downloads: list[str] = []

    def open_response(request: Request, **_kwargs: object) -> BytesIO:
        calls.append(
            (request.get_method(), request.full_url, request.get_header("Authorization"))
        )
        if len(calls) == 1:
            raise urllib.error.HTTPError(
                request.full_url, 502, "Bad Gateway", Message(), None
            )
        assert waits == [1]
        if redirected:
            headers = Message()
            headers["Location"] = location
            raise urllib.error.HTTPError(request.full_url, 302, "Found", headers, None)
        return BytesIO(b'{"id":456}')

    def download(url: str, **_kwargs: object) -> BytesIO:
        downloads.append(url)
        return BytesIO(b"downloaded bytes")

    monkeypatch.setattr(api, "_opener", SimpleNamespace(open=open_response))
    monkeypatch.setattr(correlation.urllib.request, "urlopen", download)
    monkeypatch.setattr(time, "sleep", waits.append)

    expected = b"downloaded bytes" if redirected else {"id": 456}
    assert getattr(api, method)(*args) == expected
    assert calls == [("GET", api.base + path, "Bearer fixture-token")] * 2
    assert waits == [1]
    assert downloads == ([location] if redirected else [])


def test_persistent_bad_gateway_reports_the_failed_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = correlation.GitHubActionsAPI(
        "https://api.github.com", "oxfa/niamodretlif", "fixture-token"
    )
    requests: list[str] = []
    waits: list[float] = []

    def unavailable(request: Request, **_kwargs: object) -> None:
        requests.append(request.full_url)
        raise urllib.error.HTTPError(
            request.full_url, 502, "Bad Gateway", Message(), None
        )

    monkeypatch.setattr(api, "_opener", SimpleNamespace(open=unavailable))
    monkeypatch.setattr(time, "sleep", waits.append)

    with pytest.raises(
        correlation.CorrelationError, match=r"HTTP 502 for /artifacts/456/zip"
    ):
        api.artifact_zip(456)
    assert requests == [api.base + "/artifacts/456/zip"] * 2
    assert waits == [1]


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
