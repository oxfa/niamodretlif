"""HTTP request retry logic owned by ip location providers."""

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
class HTTPRetryStatusPolicy:
    """Status-code policy for retryable HTTP responses."""

    retryable_status_codes: frozenset[int]
    retry_after_status_codes: frozenset[int] = dataclasses.field(
        default_factory=frozenset
    )
    status_delay_overrides: dict[int, float] = dataclasses.field(default_factory=dict)
    status_fallback_wait_seconds: dict[int, tuple[float, ...]] = dataclasses.field(
        default_factory=dict
    )
    retry_after_cap_seconds: int = 120


@dataclasses.dataclass(frozen=True)
class HTTPRetryBackoff:
    """Exponential backoff bounds for retryable HTTP requests."""

    backoff_multiplier: float = 0.5
    backoff_min: float = 0.5
    backoff_max: float = 30.0


@dataclasses.dataclass(frozen=True)
class HTTPRetryPolicy:
    """Policy for retryable HTTP request behavior."""

    max_attempts: int
    status: HTTPRetryStatusPolicy
    backoff: HTTPRetryBackoff = dataclasses.field(default_factory=HTTPRetryBackoff)


@dataclasses.dataclass(frozen=True)
class HTTPRetryAttempt:
    """Retry attempt position for observer events."""

    attempt_number: int
    max_attempts: int


@dataclasses.dataclass(frozen=True)
class HTTPRetryWaitDecision:
    """Wait-decision details for observer events."""

    status_code: int | None
    wait_seconds: float
    wait_source: str
    retry_after_raw: str | None = None
    retry_after_seconds: float | None = None
    fallback_seconds: tuple[float, ...] | None = None
    fallback_index: int | None = None


@dataclasses.dataclass(frozen=True)
class HTTPRetryEvent:
    """Structured debug-only retry wait decision."""

    log_name: str
    attempt: HTTPRetryAttempt
    wait: HTTPRetryWaitDecision
    exception_type: str

    @property
    def status_code(self) -> int | None:
        """Return the failed response status code when available."""
        return self.wait.status_code

    @property
    def attempt_number(self) -> int:
        """Return the one-based retry attempt number."""
        return self.attempt.attempt_number

    @property
    def max_attempts(self) -> int:
        """Return the maximum attempts from the active retry policy."""
        return self.attempt.max_attempts

    @property
    def wait_seconds(self) -> float:
        """Return the selected retry wait duration."""
        return self.wait.wait_seconds

    @property
    def wait_source(self) -> str:
        """Return where the retry wait duration came from."""
        return self.wait.wait_source

    @property
    def retry_after_raw(self) -> str | None:
        """Return the raw Retry-After header when present."""
        return self.wait.retry_after_raw

    @property
    def retry_after_seconds(self) -> float | None:
        """Return the parsed Retry-After delay when usable."""
        return self.wait.retry_after_seconds

    @property
    def fallback_seconds(self) -> tuple[float, ...] | None:
        """Return configured status fallback waits when used."""
        return self.wait.fallback_seconds

    @property
    def fallback_index(self) -> int | None:
        """Return the selected status fallback index when used."""
        return self.wait.fallback_index


@dataclasses.dataclass(frozen=True)
class HTTPRetryEventBuildRequest:
    """Context needed to build one immutable retry observer event."""

    retry_state: RetryCallState
    log_name: str
    retry_policy: HTTPRetryPolicy
    wait: HTTPRetryWaitDecision
    exception: BaseException | None


RetryObserver = Callable[[HTTPRetryEvent], None]


@dataclasses.dataclass(frozen=True)
class HTTPRequesterConfig:
    """Request retry settings shared by all calls for one HTTP requester."""

    timeout: float
    retry_policy: HTTPRetryPolicy
    retryable_exceptions: Collection[type[BaseException]]


@dataclasses.dataclass(frozen=True)
class HTTPRequestErrorFactories:
    """Factories that adapt transport and status failures to retry exceptions."""

    transport: TransportErrorFactory
    status: StatusErrorFactory


@dataclasses.dataclass(frozen=True)
class HTTPRetryHooks:
    """Optional side-effect hooks used by retry execution."""

    retry_logger: RetryLogger | None = None
    sleep: Callable[[float], Any] = time.sleep


@dataclasses.dataclass(frozen=True)
class HTTPRequestOptions:
    """Per-request retry options."""

    log_name: str
    retry_policy: HTTPRetryPolicy | None = None
    retry_observer: RetryObserver | None = None


class HTTPRequester:
    """Execute HTTP requests with caller-defined retry behavior."""

    def __init__(
        self,
        *,
        session: Any,
        config: HTTPRequesterConfig,
        error_factories: HTTPRequestErrorFactories,
        retry_hooks: HTTPRetryHooks | None = None,
    ) -> None:
        self.session = session
        self.config = config
        self.error_factories = error_factories
        self.retry_hooks = retry_hooks or HTTPRetryHooks()

    def request(
        self,
        method: str,
        url: str,
        *,
        options: HTTPRequestOptions,
        **kwargs: Any,
    ) -> requests.Response:
        """Send one HTTP request with the configured retry policy."""
        active_retry_policy = options.retry_policy or self.config.retry_policy

        def perform_request() -> requests.Response:
            request_method = getattr(self.session, method)
            try:
                response = request_method(url, timeout=self.config.timeout, **kwargs)
            except requests.RequestException as exc:
                raise self.error_factories.transport(options.log_name, exc) from exc
            if (
                response.status_code
                in active_retry_policy.status.retryable_status_codes
            ):
                raise self.error_factories.status(options.log_name, response)
            return response

        return Retrying(
            retry=retry_if_exception_type(tuple(self.config.retryable_exceptions)),
            stop=stop_after_attempt(active_retry_policy.max_attempts),
            wait=lambda retry_state: self._wait_seconds(
                retry_state,
                log_name=options.log_name,
                retry_policy=active_retry_policy,
            ),
            before_sleep=lambda retry_state: self._before_sleep(
                retry_state,
                log_name=options.log_name,
                retry_policy=active_retry_policy,
                retry_observer=options.retry_observer,
            ),
            sleep=self.retry_hooks.sleep,
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
            options=HTTPRequestOptions(
                log_name=log_name,
                retry_policy=retry_policy,
                retry_observer=retry_observer,
            ),
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
            options=HTTPRequestOptions(
                log_name=log_name,
                retry_policy=retry_policy,
                retry_observer=retry_observer,
            ),
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
        event = dataclasses.replace(
            event,
            wait=dataclasses.replace(event.wait, wait_seconds=float(next_sleep)),
        )
        if exc is not None and self.retry_hooks.retry_logger is not None:
            self.retry_hooks.retry_logger(
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
            retry_policy=retry_policy or self.config.retry_policy,
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
            status_policy = retry_policy.status
            override = status_policy.status_delay_overrides.get(status_code)
            if override is not None:
                return self._retry_event(
                    HTTPRetryEventBuildRequest(
                        retry_state=retry_state,
                        log_name=log_name,
                        retry_policy=retry_policy,
                        wait=HTTPRetryWaitDecision(
                            status_code=status_code,
                            wait_seconds=float(override),
                            wait_source="status_delay_override",
                        ),
                        exception=exc,
                    )
                )
            if status_code in status_policy.retry_after_status_codes:
                retry_after_raw, retry_after_seconds = self._retry_after_decision(
                    response,
                    retry_policy=retry_policy,
                )
                if retry_after_seconds is not None:
                    return self._retry_event(
                        HTTPRetryEventBuildRequest(
                            retry_state=retry_state,
                            log_name=log_name,
                            retry_policy=retry_policy,
                            wait=HTTPRetryWaitDecision(
                                status_code=status_code,
                                wait_seconds=float(retry_after_seconds),
                                wait_source="retry_after_header",
                                retry_after_raw=retry_after_raw,
                                retry_after_seconds=float(retry_after_seconds),
                            ),
                            exception=exc,
                        )
                    )
            fallback_waits = status_policy.status_fallback_wait_seconds.get(status_code)
            if fallback_waits:
                fallback_index = min(
                    retry_state.attempt_number - 1,
                    len(fallback_waits) - 1,
                )
                return self._retry_event(
                    HTTPRetryEventBuildRequest(
                        retry_state=retry_state,
                        log_name=log_name,
                        retry_policy=retry_policy,
                        wait=HTTPRetryWaitDecision(
                            status_code=status_code,
                            wait_seconds=float(fallback_waits[fallback_index]),
                            wait_source="status_fallback",
                            retry_after_raw=retry_after_raw,
                            retry_after_seconds=(
                                None
                                if retry_after_seconds is None
                                else float(retry_after_seconds)
                            ),
                            fallback_seconds=tuple(
                                float(value) for value in fallback_waits
                            ),
                            fallback_index=fallback_index,
                        ),
                        exception=exc,
                    )
                )
        wait_seconds = float(
            wait_exponential(
                multiplier=retry_policy.backoff.backoff_multiplier,
                min=retry_policy.backoff.backoff_min,
                max=retry_policy.backoff.backoff_max,
            )(retry_state)
        )
        return self._retry_event(
            HTTPRetryEventBuildRequest(
                retry_state=retry_state,
                log_name=log_name,
                retry_policy=retry_policy,
                wait=HTTPRetryWaitDecision(
                    status_code=status_code if isinstance(status_code, int) else None,
                    wait_seconds=wait_seconds,
                    wait_source="exponential_backoff",
                    retry_after_raw=retry_after_raw,
                    retry_after_seconds=retry_after_seconds,
                ),
                exception=exc,
            )
        )

    @staticmethod
    def _retry_event(request: HTTPRetryEventBuildRequest) -> HTTPRetryEvent:
        """Build one immutable retry observer event."""
        return HTTPRetryEvent(
            log_name=request.log_name,
            attempt=HTTPRetryAttempt(
                attempt_number=request.retry_state.attempt_number,
                max_attempts=request.retry_policy.max_attempts,
            ),
            wait=request.wait,
            exception_type=(
                type(request.exception).__name__
                if request.exception is not None
                else ""
            ),
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
            0, min(retry_after_seconds, retry_policy.status.retry_after_cap_seconds)
        )

    def retry_after_seconds(self, response: object) -> int | None:
        """Return a bounded Retry-After delay when present."""
        return self._retry_after_decision(
            response,
            retry_policy=self.config.retry_policy,
        )[1]
