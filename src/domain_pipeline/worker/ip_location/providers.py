"""IP-location providers and policy evaluation for usable lookup results."""

from __future__ import annotations

import dataclasses
import logging
import time
from typing import Any, Protocol

import requests

from domain_pipeline.worker.ip_location.constants import (
    IP_LOCATION_PROVIDER_GEOJS as PROVIDER_GEOJS,
    IP_LOCATION_PROVIDER_IPINFO_LITE as PROVIDER_IPINFO_LITE,
)
from domain_pipeline.worker.ip_location.http_requestor import (
    HTTPRequestErrorFactories,
    HTTPRequester,
    HTTPRequesterConfig,
    HTTPRetryBackoff,
    HTTPRetryHooks,
    HTTPRetryPolicy,
    HTTPRetryStatusPolicy,
)
from domain_pipeline.worker.ip_location.policy import is_iso_subdivision_code

logger = logging.getLogger(__name__)

IP_LOCATION_STATUS_OK = "ok"
IP_LOCATION_STATUS_CACHE_HIT = "cache_hit"
IP_LOCATION_STATUS_RATE_LIMITED = "rate_limited"
IP_LOCATION_STATUS_REQUEST_FAILED = "request_failed"
IP_LOCATION_STATUS_INVALID_PAYLOAD = "invalid_payload"
IP_LOCATION_FAILURE_REASON_MISSING_API_TOKEN = "missing_api_token"
IP_LOCATION_FAILURE_REASON_ACCESS_DENIED = "access_denied"
IP_LOCATION_FAILURE_REASON_RATE_LIMITED = "rate_limited"
IP_LOCATION_FAILURE_REASON_INVALID_PAYLOAD = "invalid_payload"
IP_LOCATION_FAILURE_REASON_REQUEST_FAILED = "request_failed"
GEOJS_BULK_CHUNK_SIZE = 100
IPINFO_LITE_BULK_CHUNK_SIZE = 1000


class RetryableIPLocationLookupError(requests.RequestException):
    """Raised for transient IP-location HTTP failures that should be retried."""

    def __init__(
        self,
        message: str,
        *,
        response: requests.Response | None = None,
        original_exception: requests.RequestException | None = None,
    ) -> None:
        super().__init__(message)
        self.response = response
        self.original_exception = original_exception


class FatalIPLocationCredentialError(RuntimeError):
    """Raised when an IP-location provider rejects required credentials."""

    def __init__(self, message: str, *, failure_reason: str) -> None:
        super().__init__(message)
        self.failure_reason = failure_reason


@dataclasses.dataclass(frozen=True)
class IPLocationResult:
    """IP-location result for one IP address."""

    ip: str
    provider: str
    country_code: str
    region_code: str
    region_name: str
    status: str
    failure_reason: str = ""

    @property
    def usable(self) -> bool:
        """Return whether this result contains usable IP-location data."""
        return self.status in {IP_LOCATION_STATUS_OK, IP_LOCATION_STATUS_CACHE_HIT}


@dataclasses.dataclass(frozen=True)
class LocationPolicyDecision:
    """Decision taken for a host after evaluating all resolved IPs."""

    status: str
    reason: str
    matched_ips: list[str]
    rejected_ips: list[str]


class IPLocationProvider(Protocol):
    """Protocol for pluggable IP-location providers."""

    provider_name: str

    def lookup_ip(self, ip: str) -> IPLocationResult:
        """Return an IP-location record for one IP."""
        raise NotImplementedError

    def lookup_ips(self, ips: list[str]) -> list[IPLocationResult]:
        """Return IP-location records for multiple IPs in input order."""
        raise NotImplementedError


def normalize_country_code(value: str) -> str:
    """Normalize a country code for comparisons."""
    return value.strip().upper()


def normalize_region_code(value: str) -> str:
    """Normalize a subdivision code for comparisons."""
    return value.strip().upper()


def normalize_region_name(value: str) -> str:
    """Normalize one region name for exact policy comparisons."""
    return " ".join(value.strip().split()).casefold()


def normalize_ip_location_lists(payload: dict[str, Any]) -> dict[str, list[str]]:
    """Normalize include/exclude country and region lists."""
    countries = [
        normalize_country_code(value) for value in payload.get("countries", [])
    ]
    region_codes: list[str] = []
    region_names: list[str] = []
    for value in payload.get("regions", []):
        candidate = str(value).strip()
        if is_iso_subdivision_code(candidate):
            region_codes.append(normalize_region_code(candidate))
        else:
            region_names.append(normalize_region_name(candidate))
    return {
        "countries": countries,
        "region_codes": region_codes,
        "region_names": region_names,
    }


def _string_field(payload: object, key: str) -> str:
    """Return a string field from a JSON-like mapping."""
    if not isinstance(payload, dict):
        return ""
    value = payload.get(key)
    return value if isinstance(value, str) else ""


class RequestsIPLocationProvider:
    """Base class for HTTP JSON IP-location providers."""

    provider_name = ""
    MAX_RETRY_ATTEMPTS = 3

    def __init__(self, timeout: float = 5.0, session: Any = None) -> None:
        self.timeout = timeout
        self.session: Any = session or requests.Session()
        self._requestor = HTTPRequester(
            session=self.session,
            config=HTTPRequesterConfig(
                timeout=self.timeout,
                retry_policy=HTTPRetryPolicy(
                    max_attempts=self.MAX_RETRY_ATTEMPTS,
                    status=HTTPRetryStatusPolicy(
                        retryable_status_codes=frozenset({429, 500, 502, 503, 504}),
                        retry_after_status_codes=frozenset({429}),
                    ),
                    backoff=HTTPRetryBackoff(
                        backoff_multiplier=0.1,
                        backoff_min=0.1,
                        backoff_max=1.0,
                    ),
                ),
                retryable_exceptions=(RetryableIPLocationLookupError,),
            ),
            error_factories=HTTPRequestErrorFactories(
                transport=self._build_retryable_ip_location_transport_error,
                status=self._build_retryable_ip_location_status_error,
            ),
            retry_hooks=HTTPRetryHooks(sleep=self._sleep_for_retry),
        )

    @staticmethod
    def _sleep_for_retry(seconds: float) -> None:
        """Sleep for one retry interval using the stage-local time module."""
        time.sleep(seconds)

    @staticmethod
    def _build_retryable_ip_location_transport_error(
        log_name: str, exc: requests.RequestException
    ) -> RetryableIPLocationLookupError:
        """Create one retryable IP-location transport error."""
        return RetryableIPLocationLookupError(
            f"{log_name} request failed: {exc}",
            original_exception=exc,
        )

    @staticmethod
    def _build_retryable_ip_location_status_error(
        log_name: str, response: requests.Response
    ) -> RetryableIPLocationLookupError:
        """Create one retryable IP-location HTTP-status error."""
        return RetryableIPLocationLookupError(
            f"{log_name} returned HTTP {response.status_code}",
            response=response,
        )

    def _get_json(self, url: str, *, log_name: str, **kwargs: Any) -> object:
        """GET one provider URL and retry transient lookup failures."""
        response = self._requestor.get(url, log_name=log_name, **kwargs)
        response.raise_for_status()
        return response.json()

    def _post_json(self, url: str, *, log_name: str, **kwargs: Any) -> object:
        """POST one provider URL and retry transient lookup failures."""
        response = self._requestor.post(url, log_name=log_name, **kwargs)
        response.raise_for_status()
        return response.json()

    def _rate_limited_result(
        self, ip: str, response: object | None
    ) -> IPLocationResult:
        """Return one exhausted-rate-limit result for a provider lookup."""
        del response
        return IPLocationResult(
            ip=ip,
            provider=self.provider_name,
            country_code="",
            region_code="",
            region_name="",
            status=IP_LOCATION_STATUS_RATE_LIMITED,
            failure_reason=IP_LOCATION_FAILURE_REASON_RATE_LIMITED,
        )

    def _request_failed_result(
        self,
        ip: str,
        *,
        failure_reason: str = IP_LOCATION_FAILURE_REASON_REQUEST_FAILED,
    ) -> IPLocationResult:
        """Return one generic request-failed result for a provider lookup."""
        return IPLocationResult(
            ip=ip,
            provider=self.provider_name,
            country_code="",
            region_code="",
            region_name="",
            status=IP_LOCATION_STATUS_REQUEST_FAILED,
            failure_reason=failure_reason,
        )

    def _invalid_payload_result(self, ip: str) -> IPLocationResult:
        """Return one invalid-payload result for a provider lookup."""
        return IPLocationResult(
            ip=ip,
            provider=self.provider_name,
            country_code="",
            region_code="",
            region_name="",
            status=IP_LOCATION_STATUS_INVALID_PAYLOAD,
            failure_reason=IP_LOCATION_FAILURE_REASON_INVALID_PAYLOAD,
        )

    def _failure_reason_for_exception(
        self, exc: requests.RequestException | ValueError
    ) -> str:
        """Return the normalized provider failure reason for one exception."""
        response = getattr(exc, "response", None)
        if getattr(response, "status_code", None) == 429:
            return IP_LOCATION_FAILURE_REASON_RATE_LIMITED
        return IP_LOCATION_FAILURE_REASON_REQUEST_FAILED

    def _raise_if_fatal_credential_error(
        self, exc: requests.RequestException | ValueError
    ) -> None:
        """Raise a fatal credential error when the exception proves one."""
        del exc

    def _handle_lookup_exception(
        self,
        ip: str,
        exc: requests.RequestException | ValueError,
        *,
        provider_label: str,
    ) -> IPLocationResult:
        """Map one provider exception into the normalized IP-location result surface."""
        self._raise_if_fatal_credential_error(exc)
        logger.warning("%s lookup failed for %s: %s", provider_label, ip, exc)
        response = getattr(exc, "response", None)
        if getattr(response, "status_code", None) == 429:
            return self._rate_limited_result(ip, response)
        return self._request_failed_result(
            ip, failure_reason=self._failure_reason_for_exception(exc)
        )

    def lookup_ip(self, ip: str) -> IPLocationResult:
        """Return a provider-specific lookup result for one IP."""
        raise NotImplementedError

    def lookup_ips(self, ips: list[str]) -> list[IPLocationResult]:
        """Return IP-location results for multiple IPs using sequential lookups."""
        return [self.lookup_ip(ip) for ip in ips]


class IPInfoLiteProvider(RequestsIPLocationProvider):
    """IPinfo Lite implementation with country-only data and batch/lite support."""

    provider_name = PROVIDER_IPINFO_LITE

    def __init__(
        self,
        timeout: float = 5.0,
        session: Any = None,
        token: str = "",
    ) -> None:
        super().__init__(timeout=timeout, session=session)
        self.token = token

    def _result_from_payload(self, ip: str, payload: object) -> IPLocationResult:
        """Build one normalized IP-location result from an IPinfo Lite payload."""
        if not isinstance(payload, dict):
            logger.debug("IPinfo Lite lookup for %s returned an invalid payload", ip)
            return self._invalid_payload_result(ip)
        country_code = normalize_country_code(_string_field(payload, "country_code"))
        if not country_code:
            logger.debug("IPinfo Lite lookup for %s returned no country_code", ip)
            return self._invalid_payload_result(ip)
        return IPLocationResult(
            ip=ip,
            provider=self.provider_name,
            country_code=country_code,
            region_code="",
            region_name="",
            status=IP_LOCATION_STATUS_OK,
        )

    def _failure_reason_for_exception(
        self, exc: requests.RequestException | ValueError
    ) -> str:
        """Return an IPinfo-specific failure reason for authentication failures."""
        response = getattr(exc, "response", None)
        if getattr(response, "status_code", None) in {401, 403}:
            if self.token:
                return IP_LOCATION_FAILURE_REASON_ACCESS_DENIED
            return IP_LOCATION_FAILURE_REASON_MISSING_API_TOKEN
        return super()._failure_reason_for_exception(exc)

    def _raise_if_fatal_credential_error(
        self, exc: requests.RequestException | ValueError
    ) -> None:
        """Raise fatal IPinfo credential errors for HTTP auth failures."""
        response = getattr(exc, "response", None)
        status_code = getattr(response, "status_code", None)
        if status_code not in {401, 403}:
            return
        if self.token:
            raise FatalIPLocationCredentialError(
                f"IPinfo Lite API token was rejected by the provider with HTTP {status_code}",
                failure_reason=IP_LOCATION_FAILURE_REASON_ACCESS_DENIED,
            ) from exc
        raise FatalIPLocationCredentialError(
            "IPinfo Lite API token is missing or was not sent; set "
            "IP_LOCATION_IPINFO_TOKEN or ip_location.token",
            failure_reason=IP_LOCATION_FAILURE_REASON_MISSING_API_TOKEN,
        ) from exc

    def lookup_ip(self, ip: str) -> IPLocationResult:
        token_suffix = f"?token={self.token}" if self.token else ""
        url = f"https://api.ipinfo.io/lite/{ip}{token_suffix}"
        logger.debug("IPinfo Lite lookup for %s", ip)
        try:
            payload = self._get_json(url, log_name=f"IPinfo Lite lookup for {ip}")
        except (requests.RequestException, ValueError) as exc:
            return self._handle_lookup_exception(ip, exc, provider_label="IPinfo Lite")
        result = self._result_from_payload(ip, payload)
        logger.debug(
            "IPinfo Lite lookup for %s -> country=%s",
            ip,
            result.country_code or "(none)",
        )
        return result

    def lookup_ips(self, ips: list[str]) -> list[IPLocationResult]:
        """Return IPinfo Lite results with documented batch/lite chunking."""
        if not ips:
            return []
        if len(ips) == 1:
            return [self.lookup_ip(ips[0])]

        results: list[IPLocationResult] = []
        for start in range(0, len(ips), IPINFO_LITE_BULK_CHUNK_SIZE):
            chunk = ips[start : start + IPINFO_LITE_BULK_CHUNK_SIZE]
            results.extend(self._lookup_ip_chunk(chunk))
        return results

    def _lookup_ip_chunk(self, chunk: list[str]) -> list[IPLocationResult]:
        """Return one batch/lite chunk in input order."""
        token_suffix = f"?token={self.token}" if self.token else ""
        url = f"https://api.ipinfo.io/batch/lite{token_suffix}"
        logger.debug("IPinfo Lite bulk lookup for %d IPs", len(chunk))
        try:
            payload = self._post_json(
                url,
                log_name=f"IPinfo Lite bulk lookup for {len(chunk)} IPs",
                json=chunk,
            )
        except (requests.RequestException, ValueError) as exc:
            self._raise_if_fatal_credential_error(exc)
            response = getattr(exc, "response", None)
            if getattr(response, "status_code", None) == 429:
                return [self._rate_limited_result(ip, response) for ip in chunk]
            logger.warning(
                "IPinfo Lite bulk lookup failed for %s: %s", ",".join(chunk), exc
            )
            failure_reason = self._failure_reason_for_exception(exc)
            return [
                self._request_failed_result(ip, failure_reason=failure_reason)
                for ip in chunk
            ]

        if not isinstance(payload, dict):
            logger.debug(
                "IPinfo Lite bulk lookup for %s returned an invalid payload",
                ",".join(chunk),
            )
            return [self._invalid_payload_result(ip) for ip in chunk]

        results: list[IPLocationResult] = []
        for ip in chunk:
            if ip not in payload:
                logger.debug(
                    "IPinfo Lite bulk lookup for %s omitted IP %s", ",".join(chunk), ip
                )
                results.append(self._invalid_payload_result(ip))
                continue
            results.append(self._result_from_payload(ip, payload[ip]))
        return results


class IPLocationJSProvider(RequestsIPLocationProvider):
    """IPLocationJS implementation for region-name-aware lookups."""

    provider_name = PROVIDER_GEOJS

    def lookup_ip(self, ip: str) -> IPLocationResult:
        url = f"https://get.geojs.io/v1/ip/ip_location/{ip}.json"
        logger.debug("IPLocationJS lookup for %s", ip)
        try:
            payload = self._get_json(url, log_name=f"IPLocationJS lookup for {ip}")
        except (requests.RequestException, ValueError) as exc:
            return self._handle_lookup_exception(ip, exc, provider_label="IPLocationJS")
        return self._result_from_payload(ip, payload)

    def lookup_ips(self, ips: list[str]) -> list[IPLocationResult]:
        """Return IPLocationJS results for multiple IPs with conservative chunking."""
        if not ips:
            return []
        if len(ips) == 1:
            return [self.lookup_ip(ips[0])]

        results: list[IPLocationResult] = []
        for start in range(0, len(ips), GEOJS_BULK_CHUNK_SIZE):
            chunk = ips[start : start + GEOJS_BULK_CHUNK_SIZE]
            results.extend(self._lookup_ip_chunk(chunk))
        return results

    def _lookup_ip_chunk(self, chunk: list[str]) -> list[IPLocationResult]:
        query_value = ",".join(chunk)
        logger.debug("IPLocationJS bulk lookup for %d IPs", len(chunk))
        try:
            payload = self._get_json(
                "https://get.geojs.io/v1/ip/ip_location.json",
                log_name=f"IPLocationJS bulk lookup for {len(chunk)} IPs",
                params={"ip": query_value},
            )
        except (requests.RequestException, ValueError) as exc:
            response = getattr(exc, "response", None)
            if getattr(response, "status_code", None) == 429:
                return [self._rate_limited_result(ip, response) for ip in chunk]
            logger.warning(
                "IPLocationJS bulk lookup failed for %s: %s", query_value, exc
            )
            failure_reason = self._failure_reason_for_exception(exc)
            return [
                self._request_failed_result(ip, failure_reason=failure_reason)
                for ip in chunk
            ]

        if not isinstance(payload, list):
            logger.debug(
                "IPLocationJS bulk lookup for %s returned an invalid payload",
                query_value,
            )
            return [self._invalid_payload_result(ip) for ip in chunk]

        payloads_by_ip: dict[str, list[object]] = {}
        for row in payload:
            row_ip = _string_field(row, "ip")
            if row_ip:
                payloads_by_ip.setdefault(row_ip, []).append(row)

        results: list[IPLocationResult] = []
        for ip in chunk:
            matching_rows = payloads_by_ip.get(ip, [])
            if not matching_rows:
                logger.debug(
                    "IPLocationJS bulk lookup for %s omitted IP %s", query_value, ip
                )
                results.append(self._invalid_payload_result(ip))
                continue
            results.append(self._result_from_payload(ip, matching_rows.pop(0)))
        return results

    def _result_from_payload(self, ip: str, payload: object) -> IPLocationResult:
        """Build one normalized IPLocationJS result from one payload object."""
        if not isinstance(payload, dict):
            logger.debug("IPLocationJS lookup for %s returned an invalid payload", ip)
            return self._invalid_payload_result(ip)
        result = IPLocationResult(
            ip=ip,
            provider=self.provider_name,
            country_code=normalize_country_code(_string_field(payload, "country_code")),
            region_code="",
            region_name=_string_field(payload, "region"),
            status=IP_LOCATION_STATUS_OK,
        )
        logger.debug(
            "IPLocationJS lookup for %s -> country=%s region=%s",
            ip,
            result.country_code or "(none)",
            result.region_name or "(none)",
        )
        return result


def build_ip_location_provider(
    provider_name: str,
    *,
    timeout: float,
    token: str = "",
    session: Any = None,
) -> IPLocationProvider:
    """Instantiate one inferred IP-location provider."""
    if provider_name == PROVIDER_IPINFO_LITE:
        return IPInfoLiteProvider(timeout=timeout, session=session, token=token)
    if provider_name == PROVIDER_GEOJS:
        return IPLocationJSProvider(timeout=timeout, session=session)
    raise ValueError(f"unsupported effective ip location provider {provider_name!r}")


def _ip_location_value_matches(
    result: IPLocationResult,
    countries: set[str],
    region_codes: set[str],
    region_names: set[str],
) -> bool:
    country_match = bool(countries) and result.country_code in countries
    region_code_match = bool(region_codes) and result.region_code in region_codes
    region_name_match = bool(region_names) and (
        normalize_region_name(result.region_name) in region_names
    )
    return country_match or region_code_match or region_name_match


def _ip_location_result_is_usable(result: IPLocationResult) -> bool:
    """Return whether one IP-location result should participate in policy matching."""
    return result.usable


@dataclasses.dataclass(frozen=True)
class IPLocationPolicyCriteria:
    """Normalized include/exclude criteria for one ip-location policy."""

    match_scope: str
    include_countries: set[str]
    include_region_codes: set[str]
    include_region_names: set[str]
    exclude_countries: set[str]
    exclude_region_codes: set[str]
    exclude_region_names: set[str]

    @property
    def has_include_rules(self) -> bool:
        """Return whether the policy has any positive match criteria."""
        return bool(
            self.include_countries
            or self.include_region_codes
            or self.include_region_names
        )


@dataclasses.dataclass(frozen=True)
class IPLocationPolicyMatchState:
    """Matched and rejected IPs after evaluating policy criteria."""

    matched_ips: list[str]
    rejected_ips: list[str]


def _ip_location_policy_criteria(policy: dict[str, Any]) -> IPLocationPolicyCriteria:
    """Return normalized include/exclude criteria for one policy payload."""
    include = normalize_ip_location_lists(policy["include"])
    exclude = normalize_ip_location_lists(policy["exclude"])
    return IPLocationPolicyCriteria(
        match_scope=str(policy["match_scope"]),
        include_countries=set(include["countries"]),
        include_region_codes=set(include["region_codes"]),
        include_region_names=set(include["region_names"]),
        exclude_countries=set(exclude["countries"]),
        exclude_region_codes=set(exclude["region_codes"]),
        exclude_region_names=set(exclude["region_names"]),
    )


def _log_ip_location_policy_evaluation(
    criteria: IPLocationPolicyCriteria,
    result_count: int,
) -> None:
    """Log the normalized criteria used for one policy evaluation."""
    logger.debug(
        "IpLocation policy evaluation: match_scope=%s results=%d include_countries=%s "
        "include_region_codes=%s include_region_names=%s exclude_countries=%s "
        "exclude_region_codes=%s exclude_region_names=%s",
        criteria.match_scope,
        result_count,
        sorted(criteria.include_countries) or "(none)",
        sorted(criteria.include_region_codes) or "(none)",
        sorted(criteria.include_region_names) or "(none)",
        sorted(criteria.exclude_countries) or "(none)",
        sorted(criteria.exclude_region_codes) or "(none)",
        sorted(criteria.exclude_region_names) or "(none)",
    )


def _ip_location_decision(
    status: str,
    reason: str,
    matched_ips: list[str],
    rejected_ips: list[str],
    *,
    failed_ips: list[str] | None = None,
) -> LocationPolicyDecision:
    """Build and log one IP-location policy decision."""
    if failed_ips is None:
        logger.debug(
            "IpLocation policy decision: status=%s reason=%s matched=%s rejected=%s",
            status,
            reason,
            matched_ips or "(none)",
            rejected_ips or "(none)",
        )
    else:
        logger.debug(
            "IpLocation policy decision: status=%s reason=%s failed_ips=%s",
            status,
            reason,
            failed_ips,
        )
    return LocationPolicyDecision(status, reason, matched_ips, rejected_ips)


def evaluate_ip_location_policy(
    ip_location_results: list[IPLocationResult],
    policy: dict[str, Any],
) -> LocationPolicyDecision:
    """Evaluate a source-local policy after the selected provider yields usable data."""
    criteria = _ip_location_policy_criteria(policy)
    _log_ip_location_policy_evaluation(criteria, len(ip_location_results))
    if not ip_location_results:
        raise ValueError(
            "evaluate_ip_location_policy requires at least one ip location result"
        )
    comparable_results = _comparable_ip_location_results(ip_location_results, criteria)
    match_state = _ip_location_policy_match_state(comparable_results, criteria)
    return _ip_location_policy_decision_from_matches(criteria, match_state)


def _comparable_ip_location_results(
    ip_location_results: list[IPLocationResult],
    criteria: IPLocationPolicyCriteria,
) -> list[IPLocationResult]:
    """Return usable results that can participate in policy matching."""
    comparable_results = [
        result
        for result in ip_location_results
        if _ip_location_result_is_usable(result)
    ]
    if not comparable_results:
        raise ValueError(
            "evaluate_ip_location_policy requires at least one usable ip location result"
        )
    if criteria.match_scope == "all_ips" and len(comparable_results) != len(
        ip_location_results
    ):
        raise ValueError(
            "all_ips ip location policy requires usable ip location results for every resolved IP"
        )
    return comparable_results


def _ip_location_policy_match_state(
    comparable_results: list[IPLocationResult],
    criteria: IPLocationPolicyCriteria,
) -> IPLocationPolicyMatchState:
    """Return matched and rejected IPs for one normalized policy."""
    matched_ips: list[str] = []
    rejected_ips: list[str] = []
    for result in comparable_results:
        accepted = _ip_location_result_accepted(result, criteria)
        if accepted:
            matched_ips.append(result.ip)
        else:
            rejected_ips.append(result.ip)
    return IPLocationPolicyMatchState(matched_ips, rejected_ips)


def _ip_location_result_accepted(
    result: IPLocationResult,
    criteria: IPLocationPolicyCriteria,
) -> bool:
    """Return whether one IP-location result satisfies include/exclude criteria."""
    in_include = _ip_location_value_matches(
        result,
        criteria.include_countries,
        criteria.include_region_codes,
        criteria.include_region_names,
    )
    in_exclude = _ip_location_value_matches(
        result,
        criteria.exclude_countries,
        criteria.exclude_region_codes,
        criteria.exclude_region_names,
    )
    include_accepted = True if not criteria.has_include_rules else in_include
    accepted = include_accepted and not in_exclude
    logger.debug(
        "IpLocation policy check: ip=%s provider=%s country=%s region_code=%s "
        "region_name=%s include=%s exclude=%s accepted=%s",
        result.ip,
        result.provider,
        result.country_code or "(none)",
        result.region_code or "(none)",
        result.region_name or "(none)",
        include_accepted,
        in_exclude,
        accepted,
    )
    return accepted


def _ip_location_policy_decision_from_matches(
    criteria: IPLocationPolicyCriteria,
    match_state: IPLocationPolicyMatchState,
) -> LocationPolicyDecision:
    """Return the final policy decision from matched/rejected IP state."""
    if criteria.match_scope == "all_ips":
        if match_state.rejected_ips:
            return _ip_location_decision(
                "rejected",
                "one_or_more_ips_rejected",
                match_state.matched_ips,
                match_state.rejected_ips,
            )
        return _ip_location_decision(
            "accepted", "all_ips_matched", match_state.matched_ips, []
        )

    if match_state.matched_ips:
        return _ip_location_decision(
            "accepted",
            "at_least_one_ip_matched",
            match_state.matched_ips,
            match_state.rejected_ips,
        )
    return _ip_location_decision(
        "rejected", "no_ips_matched", [], match_state.rejected_ips
    )
