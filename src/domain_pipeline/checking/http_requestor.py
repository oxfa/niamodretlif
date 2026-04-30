"""Shared HTTP GET retry logic for geo providers."""

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
    status_fallback_wait_seconds: dict[int, tuple[float, ...]] = dataclasses.field(
        default_factory=dict
    )
    backoff_multiplier: float = 0.5
    backoff_min: float = 0.5
    backoff_max: float = 30.0
    retry_after_cap_seconds: int = 120


@dataclasses.dataclass(frozen=True)
# pylint: disable=too-many-instance-attributes
class HTTPRetryEvent:
    """Structured debug-only retry wait decision."""

    log_name: str
    status_code: int | None
    attempt_number: int
    max_attempts: int
    wait_seconds: float
    wait_source: str
    retry_after_raw: str | None
    retry_after_seconds: float | None
    fallback_seconds: tuple[float, ...] | None
    fallback_index: int | None
    exception_type: str


RetryObserver = Callable[[HTTPRetryEvent], None]


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
        self,
        method: str,
        url: str,
        *,
        log_name: str,
        retry_policy: HTTPRetryPolicy | None = None,
        retry_observer: RetryObserver | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Send one HTTP request with the configured retry policy."""
        active_retry_policy = retry_policy or self.retry_policy

        def perform_request() -> requests.Response:
            request_method = getattr(self.session, method)
            try:
                response = request_method(url, timeout=self.timeout, **kwargs)
            except requests.RequestException as exc:
                raise self.transport_error_factory(log_name, exc) from exc
            if response.status_code in active_retry_policy.retryable_status_codes:
                raise self.status_error_factory(log_name, response)
            return response

        return Retrying(
            retry=retry_if_exception_type(self.retryable_exceptions),
            stop=stop_after_attempt(active_retry_policy.max_attempts),
            wait=lambda retry_state: self._wait_seconds(
                retry_state,
                log_name=log_name,
                retry_policy=active_retry_policy,
            ),
            before_sleep=lambda retry_state: self._before_sleep(
                retry_state,
                log_name=log_name,
                retry_policy=active_retry_policy,
                retry_observer=retry_observer,
            ),
            sleep=self.sleep,
            reraise=True,
        )(perform_request)

    def get(
        self,
        url: str,
        *,
        log_name: str,
        retry_policy: HTTPRetryPolicy | None = None,
        retry_observer: RetryObserver | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """GET one URL with the configured retry policy."""
        return self.request(
            "get",
            url,
            log_name=log_name,
            retry_policy=retry_policy,
            retry_observer=retry_observer,
            **kwargs,
        )

    def post(
        self,
        url: str,
        *,
        log_name: str,
        retry_policy: HTTPRetryPolicy | None = None,
        retry_observer: RetryObserver | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """POST one URL with the configured retry policy."""
        return self.request(
            "post",
            url,
            log_name=log_name,
            retry_policy=retry_policy,
            retry_observer=retry_observer,
            **kwargs,
        )

    def _before_sleep(
        self,
        retry_state: RetryCallState,
        *,
        log_name: str,
        retry_policy: HTTPRetryPolicy,
        retry_observer: RetryObserver | None,
    ) -> None:
        """Emit one retry log entry if the caller requested it."""
        exc = retry_state.outcome.exception() if retry_state.outcome else None
        next_sleep = retry_state.next_action.sleep if retry_state.next_action else 0.0
        event = self._wait_decision(
            retry_state,
            log_name=log_name,
            retry_policy=retry_policy,
        )
        event = dataclasses.replace(event, wait_seconds=float(next_sleep))
        if exc is not None and self.retry_logger is not None:
            self.retry_logger(
                exc,
                next_sleep,
                retry_state.attempt_number,
                retry_policy.max_attempts,
            )
        if retry_observer is not None:
            retry_observer(event)

    def _wait_seconds(
        self,
        retry_state: RetryCallState,
        *,
        log_name: str = "",
        retry_policy: HTTPRetryPolicy | None = None,
    ) -> float:
        """Return the next retry delay for one failed request."""
        return self._wait_decision(
            retry_state,
            log_name=log_name,
            retry_policy=retry_policy or self.retry_policy,
        ).wait_seconds

    def _wait_decision(
        self,
        retry_state: RetryCallState,
        *,
        log_name: str,
        retry_policy: HTTPRetryPolicy,
    ) -> HTTPRetryEvent:
        """Return the next retry wait decision with provenance."""
        exc = retry_state.outcome.exception() if retry_state.outcome else None
        response = getattr(exc, "response", None)
        status_code = getattr(response, "status_code", None)
        retry_after_raw = None
        retry_after_seconds = None
        if isinstance(status_code, int):
            override = retry_policy.status_delay_overrides.get(status_code)
            if override is not None:
                return self._retry_event(
                    retry_state,
                    log_name=log_name,
                    retry_policy=retry_policy,
                    status_code=status_code,
                    wait_seconds=float(override),
                    wait_source="status_delay_override",
                    retry_after_raw=None,
                    retry_after_seconds=None,
                    fallback_seconds=None,
                    fallback_index=None,
                    exc=exc,
                )
            if status_code in retry_policy.retry_after_status_codes:
                retry_after_raw, retry_after_seconds = self._retry_after_decision(
                    response,
                    retry_policy=retry_policy,
                )
                if retry_after_seconds is not None:
                    return self._retry_event(
                        retry_state,
                        log_name=log_name,
                        retry_policy=retry_policy,
                        status_code=status_code,
                        wait_seconds=float(retry_after_seconds),
                        wait_source="retry_after_header",
                        retry_after_raw=retry_after_raw,
                        retry_after_seconds=float(retry_after_seconds),
                        fallback_seconds=None,
                        fallback_index=None,
                        exc=exc,
                    )
            fallback_waits = retry_policy.status_fallback_wait_seconds.get(status_code)
            if fallback_waits:
                fallback_index = min(
                    retry_state.attempt_number - 1,
                    len(fallback_waits) - 1,
                )
                return self._retry_event(
                    retry_state,
                    log_name=log_name,
                    retry_policy=retry_policy,
                    status_code=status_code,
                    wait_seconds=float(fallback_waits[fallback_index]),
                    wait_source="status_fallback",
                    retry_after_raw=retry_after_raw,
                    retry_after_seconds=(
                        None
                        if retry_after_seconds is None
                        else float(retry_after_seconds)
                    ),
                    fallback_seconds=tuple(float(value) for value in fallback_waits),
                    fallback_index=fallback_index,
                    exc=exc,
                )
        wait_seconds = float(
            wait_exponential(
                multiplier=retry_policy.backoff_multiplier,
                min=retry_policy.backoff_min,
                max=retry_policy.backoff_max,
            )(retry_state)
        )
        return self._retry_event(
            retry_state,
            log_name=log_name,
            retry_policy=retry_policy,
            status_code=status_code if isinstance(status_code, int) else None,
            wait_seconds=wait_seconds,
            wait_source="exponential_backoff",
            retry_after_raw=retry_after_raw,
            retry_after_seconds=retry_after_seconds,
            fallback_seconds=None,
            fallback_index=None,
            exc=exc,
        )

    @staticmethod
    def _retry_event(
        retry_state: RetryCallState,
        *,
        log_name: str,
        retry_policy: HTTPRetryPolicy,
        status_code: int | None,
        wait_seconds: float,
        wait_source: str,
        retry_after_raw: str | None,
        retry_after_seconds: float | None,
        fallback_seconds: tuple[float, ...] | None,
        fallback_index: int | None,
        exc: BaseException | None,
    ) -> HTTPRetryEvent:
        """Build one immutable retry observer event."""
        return HTTPRetryEvent(
            log_name=log_name,
            status_code=status_code,
            attempt_number=retry_state.attempt_number,
            max_attempts=retry_policy.max_attempts,
            wait_seconds=wait_seconds,
            wait_source=wait_source,
            retry_after_raw=retry_after_raw,
            retry_after_seconds=retry_after_seconds,
            fallback_seconds=fallback_seconds,
            fallback_index=fallback_index,
            exception_type=type(exc).__name__ if exc is not None else "",
        )

    def _retry_after_decision(
        self,
        response: object,
        *,
        retry_policy: HTTPRetryPolicy,
    ) -> tuple[str | None, int | None]:
        """Return raw and capped Retry-After seconds when usable."""
        headers = getattr(response, "headers", {})
        retry_after_value = headers.get("retry-after")
        if retry_after_value is None:
            retry_after_value = headers.get("Retry-After")
        if retry_after_value is None:
            return None, None
        try:
            retry_after_seconds = int(retry_after_value)
        except ValueError:
            try:
                retry_after_at = email.utils.parsedate_to_datetime(retry_after_value)
            except (TypeError, ValueError, IndexError):
                return str(retry_after_value), None
            retry_after_seconds = int(retry_after_at.timestamp() - time.time())
        return str(retry_after_value), max(
            0, min(retry_after_seconds, retry_policy.retry_after_cap_seconds)
        )

    def _retry_after_seconds(self, response: object) -> int | None:
        """Return a bounded Retry-After delay when present."""
        return self._retry_after_decision(
            response,
            retry_policy=self.retry_policy,
        )[1]
