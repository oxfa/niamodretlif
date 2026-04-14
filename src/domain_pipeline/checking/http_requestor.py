"""Shared HTTP GET retry logic for RDAP and geo providers."""

from __future__ import annotations

import dataclasses
import email.utils
import time
from collections.abc import Callable, Collection
from typing import Any

import requests
from tenacity import RetryCallState
from tenacity import Retrying
from tenacity import retry_if_exception_type
from tenacity import stop_after_attempt
from tenacity import wait_exponential

TransportErrorFactory = Callable[[str, requests.RequestException], BaseException]
StatusErrorFactory = Callable[[str, requests.Response], BaseException]
RetryLogger = Callable[[BaseException, float, int, int], None]


@dataclasses.dataclass(frozen=True)
# pylint: disable=too-many-instance-attributes
class HTTPRetryPolicy:
    """Policy for retryable HTTP GET behavior."""

    max_attempts: int
    retryable_status_codes: frozenset[int]
    retry_after_status_codes: frozenset[int] = dataclasses.field(
        default_factory=frozenset
    )
    status_delay_overrides: dict[int, float] = dataclasses.field(default_factory=dict)
    backoff_multiplier: float = 0.5
    backoff_min: float = 0.5
    backoff_max: float = 30.0
    retry_after_cap_seconds: int = 120


class HTTPRequester:
    """Execute GET requests with caller-defined retry behavior."""

    # pylint: disable=too-many-instance-attributes

    def __init__(
        self,
        *,
        session: Any,
        timeout: float,
        retry_policy: HTTPRetryPolicy,
        retryable_exceptions: Collection[type[BaseException]],
        transport_error_factory: TransportErrorFactory,
        status_error_factory: StatusErrorFactory,
        retry_logger: RetryLogger | None = None,
        sleep: Callable[[float], Any] = time.sleep,
    ) -> None:
        self.session = session
        self.timeout = timeout
        self.retry_policy = retry_policy
        self.retryable_exceptions = tuple(retryable_exceptions)
        self.transport_error_factory = transport_error_factory
        self.status_error_factory = status_error_factory
        self.retry_logger = retry_logger
        self.sleep = sleep

    def request(
        self, method: str, url: str, *, log_name: str, **kwargs: Any
    ) -> requests.Response:
        """Send one HTTP request with the configured retry policy."""

        def perform_request() -> requests.Response:
            request_method = getattr(self.session, method)
            try:
                response = request_method(url, timeout=self.timeout, **kwargs)
            except requests.RequestException as exc:
                raise self.transport_error_factory(log_name, exc) from exc
            if response.status_code in self.retry_policy.retryable_status_codes:
                raise self.status_error_factory(log_name, response)
            return response

        return Retrying(
            retry=retry_if_exception_type(self.retryable_exceptions),
            stop=stop_after_attempt(self.retry_policy.max_attempts),
            wait=self._wait_seconds,
            before_sleep=self._before_sleep,
            sleep=self.sleep,
            reraise=True,
        )(perform_request)

    def get(self, url: str, *, log_name: str, **kwargs: Any) -> requests.Response:
        """GET one URL with the configured retry policy."""
        return self.request("get", url, log_name=log_name, **kwargs)

    def post(self, url: str, *, log_name: str, **kwargs: Any) -> requests.Response:
        """POST one URL with the configured retry policy."""
        return self.request("post", url, log_name=log_name, **kwargs)

    def _before_sleep(self, retry_state: RetryCallState) -> None:
        """Emit one retry log entry if the caller requested it."""
        exc = retry_state.outcome.exception() if retry_state.outcome else None
        next_sleep = retry_state.next_action.sleep if retry_state.next_action else 0.0
        if exc is not None and self.retry_logger is not None:
            self.retry_logger(
                exc,
                next_sleep,
                retry_state.attempt_number,
                self.retry_policy.max_attempts,
            )

    def _wait_seconds(self, retry_state: RetryCallState) -> float:
        """Return the next retry delay for one failed request."""
        exc = retry_state.outcome.exception() if retry_state.outcome else None
        response = getattr(exc, "response", None)
        status_code = getattr(response, "status_code", None)
        if isinstance(status_code, int):
            override = self.retry_policy.status_delay_overrides.get(status_code)
            if override is not None:
                return override
            if status_code in self.retry_policy.retry_after_status_codes:
                retry_after_seconds = self._retry_after_seconds(response)
                if retry_after_seconds is not None:
                    return float(retry_after_seconds)
        return float(
            wait_exponential(
                multiplier=self.retry_policy.backoff_multiplier,
                min=self.retry_policy.backoff_min,
                max=self.retry_policy.backoff_max,
            )(retry_state)
        )

    def _retry_after_seconds(self, response: object) -> int | None:
        """Return a bounded Retry-After delay when present."""
        headers = getattr(response, "headers", {})
        retry_after_value = headers.get("retry-after")
        if retry_after_value is None:
            return None
        try:
            retry_after_seconds = int(retry_after_value)
        except ValueError:
            try:
                retry_after_at = email.utils.parsedate_to_datetime(retry_after_value)
            except (TypeError, ValueError, IndexError):
                return None
            retry_after_seconds = int(retry_after_at.timestamp() - time.time())
        return max(
            0, min(retry_after_seconds, self.retry_policy.retry_after_cap_seconds)
        )
