"""IP geolocation providers and geo policy evaluation for usable geo results."""

from __future__ import annotations

import dataclasses
import logging
import re
import time
from typing import Any, Protocol

import requests

from domain_pipeline.checking.http_requestor import HTTPRequester, HTTPRetryPolicy
from domain_pipeline.settings.constants import (
    GEO_PROVIDER_GEOJS as PROVIDER_GEOJS,
    GEO_PROVIDER_IP2LOCATION_IO as PROVIDER_IP2LOCATION_IO,
    GEO_PROVIDER_IPINFO_LITE as PROVIDER_IPINFO_LITE,
    GEO_PROVIDER_IPWHOIS as PROVIDER_IPWHOIS,
    GEO_PROVIDER_IP_API as PROVIDER_IP_API,
)

logger = logging.getLogger(__name__)

SUPPORTED_PROVIDERS = {
    PROVIDER_IPWHOIS,
    PROVIDER_IP_API,
    PROVIDER_IPINFO_LITE,
    PROVIDER_GEOJS,
    PROVIDER_IP2LOCATION_IO,
}
GEO_STATUS_OK = "ok"
GEO_STATUS_CACHE_HIT = "cache_hit"
GEO_STATUS_RATE_LIMITED = "rate_limited"
GEO_STATUS_REQUEST_FAILED = "request_failed"
GEO_STATUS_INVALID_PAYLOAD = "invalid_payload"
GEO_STATUS_PROVIDER_FAILURE = "provider_failure"
ISO_REGION_RULE_PATTERN = re.compile(r"^[A-Z]{2}-[A-Z0-9]{1,3}$")
GEOJS_BULK_CHUNK_SIZE = 100
IPINFO_LITE_BULK_CHUNK_SIZE = 1000


class RetryableGeoLookupError(requests.RequestException):
    """Raised for transient geo HTTP failures that should be retried."""

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


@dataclasses.dataclass(frozen=True)
class IPGeoResult:
    """Geolocation result for one IP address."""

    ip: str
    provider: str
    country_code: str
    region_code: str
    region_name: str
    status: str
    retry_after_seconds: float | None = None

    @property
    def usable(self) -> bool:
        """Return whether this result contains usable geo data."""
        return self.status in {GEO_STATUS_OK, GEO_STATUS_CACHE_HIT}


@dataclasses.dataclass(frozen=True)
class GeoPolicyDecision:
    """Decision taken for a host after evaluating all resolved IPs."""

    status: str
    reason: str
    matched_ips: list[str]
    rejected_ips: list[str]


class IPGeoProvider(Protocol):
    """Protocol for pluggable geolocation providers."""

    provider_name: str

    def lookup_ip(self, ip: str) -> IPGeoResult:
        """Return a geo record for one IP."""
        raise NotImplementedError

    def lookup_ips(self, ips: list[str]) -> list[IPGeoResult]:
        """Return geo records for multiple IPs in input order."""
        raise NotImplementedError


class HTTPSession(Protocol):
    """Minimal HTTP session protocol used by geo providers."""

    def get(
        self, url: str | bytes, *, timeout: float | None = None, **kwargs: Any
    ) -> Any:
        """Return a response-like object for one GET request."""


def normalize_country_code(value: str) -> str:
    """Normalize a country code for comparisons."""
    return value.strip().upper()


def normalize_region_code(value: str) -> str:
    """Normalize a subdivision code for comparisons."""
    return value.strip().upper()


def normalize_region_name(value: str) -> str:
    """Normalize one region name for exact policy comparisons."""
    return " ".join(value.strip().split()).casefold()


def normalize_geo_lists(payload: dict[str, Any]) -> dict[str, list[str]]:
    """Normalize include/exclude country and region lists."""
    countries = [
        normalize_country_code(value) for value in payload.get("countries", [])
    ]
    region_codes: list[str] = []
    region_names: list[str] = []
    for value in payload.get("regions", []):
        candidate = str(value).strip()
        if ISO_REGION_RULE_PATTERN.fullmatch(candidate.upper()):
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


class RequestsIPGeoProvider:
    """Base class for simple HTTP JSON IP geo providers."""

    provider_name = ""
    MAX_RETRY_ATTEMPTS = 3

    def __init__(self, timeout: float = 5.0, session: Any = None) -> None:
        self.timeout = timeout
        self.session: Any = session or requests.Session()
        self._requestor = HTTPRequester(
            session=self.session,
            timeout=self.timeout,
            retry_policy=HTTPRetryPolicy(
                max_attempts=self.MAX_RETRY_ATTEMPTS,
                retryable_status_codes=frozenset({429, 500, 502, 503, 504}),
                retry_after_status_codes=frozenset({429}),
                backoff_multiplier=0.1,
                backoff_min=0.1,
                backoff_max=1.0,
            ),
            retryable_exceptions=(RetryableGeoLookupError,),
            transport_error_factory=self._build_retryable_geo_transport_error,
            status_error_factory=self._build_retryable_geo_status_error,
            sleep=self._sleep_for_retry,
        )

    @staticmethod
    def _sleep_for_retry(seconds: float) -> None:
        """Sleep for one retry interval using the stage-local time module."""
        time.sleep(seconds)

    @staticmethod
    def _build_retryable_geo_transport_error(
        log_name: str, exc: requests.RequestException
    ) -> RetryableGeoLookupError:
        """Create one retryable geo transport error."""
        return RetryableGeoLookupError(
            f"{log_name} request failed: {exc}",
            original_exception=exc,
        )

    @staticmethod
    def _build_retryable_geo_status_error(
        log_name: str, response: requests.Response
    ) -> RetryableGeoLookupError:
        """Create one retryable geo HTTP-status error."""
        return RetryableGeoLookupError(
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

    def _retry_after_seconds(self, response: object) -> float | None:
        """Return one provider-specific retry-after value when present."""
        retry_after_seconds = (
            self._requestor._retry_after_seconds(  # pylint: disable=protected-access
                response
            )
        )
        if retry_after_seconds is None:
            return None
        return float(retry_after_seconds)

    def _rate_limited_result(self, ip: str, response: object | None) -> IPGeoResult:
        """Return one exhausted-rate-limit result for a provider lookup."""
        return IPGeoResult(
            ip=ip,
            provider=self.provider_name,
            country_code="",
            region_code="",
            region_name="",
            status=GEO_STATUS_RATE_LIMITED,
            retry_after_seconds=self._retry_after_seconds(response),
        )

    def _request_failed_result(self, ip: str) -> IPGeoResult:
        """Return one generic request-failed result for a provider lookup."""
        return IPGeoResult(
            ip=ip,
            provider=self.provider_name,
            country_code="",
            region_code="",
            region_name="",
            status=GEO_STATUS_REQUEST_FAILED,
        )

    def _handle_lookup_exception(
        self,
        ip: str,
        exc: requests.RequestException | ValueError,
        *,
        provider_label: str,
    ) -> IPGeoResult:
        """Map one provider exception into the normalized geo result surface."""
        logger.warning("%s lookup failed for %s: %s", provider_label, ip, exc)
        response = getattr(exc, "response", None)
        if getattr(response, "status_code", None) == 429:
            return self._rate_limited_result(ip, response)
        return self._request_failed_result(ip)

    def lookup_ip(self, ip: str) -> IPGeoResult:
        """Return a provider-specific lookup result for one IP."""
        raise NotImplementedError

    def lookup_ips(self, ips: list[str]) -> list[IPGeoResult]:
        """Return geo results for multiple IPs using sequential single-IP lookups."""
        return [self.lookup_ip(ip) for ip in ips]


class IPWhoisProvider(RequestsIPGeoProvider):
    """HTTPS-backed ipwhois.io implementation."""

    provider_name = PROVIDER_IPWHOIS

    def lookup_ip(self, ip: str) -> IPGeoResult:
        url = f"https://ipwho.is/{ip}"
        logger.debug("IPWhois lookup for %s", ip)
        try:
            payload = self._get_json(url, log_name=f"IPWhois lookup for {ip}")
        except (requests.RequestException, ValueError) as exc:
            return self._handle_lookup_exception(ip, exc, provider_label="IPWhois")

        if not isinstance(payload, dict):
            logger.debug("IPWhois lookup for %s returned an invalid payload", ip)
            return IPGeoResult(
                ip, self.provider_name, "", "", "", GEO_STATUS_INVALID_PAYLOAD
            )
        if payload.get("success") is False:
            logger.debug("IPWhois lookup for %s reported provider failure", ip)
            return IPGeoResult(
                ip, self.provider_name, "", "", "", GEO_STATUS_PROVIDER_FAILURE
            )
        result = IPGeoResult(
            ip=ip,
            provider=self.provider_name,
            country_code=normalize_country_code(_string_field(payload, "country_code")),
            region_code=normalize_region_code(_string_field(payload, "region_code")),
            region_name=_string_field(payload, "region"),
            status=GEO_STATUS_OK,
        )
        logger.debug(
            "IPWhois lookup for %s -> country=%s region=%s region_name=%s",
            ip,
            result.country_code or "(none)",
            result.region_code or "(none)",
            result.region_name or "(none)",
        )
        return result


class IPAPIProvider(RequestsIPGeoProvider):
    """ip-api.com implementation for free JSON lookups."""

    provider_name = PROVIDER_IP_API

    def _retry_after_seconds(self, response: object) -> float | None:
        """Return the ip-api cooldown window when exposed on 429 responses."""
        headers = getattr(response, "headers", {})
        ttl_value = headers.get("x-ttl")
        if ttl_value is None:
            return super()._retry_after_seconds(response)
        try:
            return float(ttl_value)
        except ValueError:
            return super()._retry_after_seconds(response)

    def lookup_ip(self, ip: str) -> IPGeoResult:
        url = f"http://ip-api.com/json/{ip}?fields=status,countryCode,region,regionName"
        logger.debug("ip-api lookup for %s", ip)
        try:
            payload = self._get_json(url, log_name=f"ip-api lookup for {ip}")
        except (requests.RequestException, ValueError) as exc:
            return self._handle_lookup_exception(ip, exc, provider_label="ip-api")

        if not isinstance(payload, dict):
            logger.debug("ip-api lookup for %s returned an invalid payload", ip)
            return IPGeoResult(
                ip, self.provider_name, "", "", "", GEO_STATUS_INVALID_PAYLOAD
            )
        if _string_field(payload, "status").lower() != "success":
            logger.debug("ip-api lookup for %s reported provider failure", ip)
            return IPGeoResult(
                ip, self.provider_name, "", "", "", GEO_STATUS_PROVIDER_FAILURE
            )
        result = IPGeoResult(
            ip=ip,
            provider=self.provider_name,
            country_code=normalize_country_code(_string_field(payload, "countryCode")),
            region_code=normalize_region_code(_string_field(payload, "region")),
            region_name=_string_field(payload, "regionName"),
            status=GEO_STATUS_OK,
        )
        logger.debug(
            "ip-api lookup for %s -> country=%s region=%s region_name=%s",
            ip,
            result.country_code or "(none)",
            result.region_code or "(none)",
            result.region_name or "(none)",
        )
        return result


class IPInfoLiteProvider(RequestsIPGeoProvider):
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

    def _result_from_payload(self, ip: str, payload: object) -> IPGeoResult:
        """Build one normalized geo result from an IPinfo Lite payload."""
        if not isinstance(payload, dict):
            logger.debug("IPinfo Lite lookup for %s returned an invalid payload", ip)
            return IPGeoResult(
                ip, self.provider_name, "", "", "", GEO_STATUS_INVALID_PAYLOAD
            )
        return IPGeoResult(
            ip=ip,
            provider=self.provider_name,
            country_code=normalize_country_code(_string_field(payload, "country_code")),
            region_code="",
            region_name="",
            status=GEO_STATUS_OK,
        )

    def lookup_ip(self, ip: str) -> IPGeoResult:
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

    def lookup_ips(self, ips: list[str]) -> list[IPGeoResult]:
        """Return IPinfo Lite results with documented batch/lite chunking."""
        if not ips:
            return []
        if len(ips) == 1:
            return [self.lookup_ip(ips[0])]

        results: list[IPGeoResult] = []
        for start in range(0, len(ips), IPINFO_LITE_BULK_CHUNK_SIZE):
            chunk = ips[start : start + IPINFO_LITE_BULK_CHUNK_SIZE]
            results.extend(self._lookup_ip_chunk(chunk))
        return results

    def _lookup_ip_chunk(self, chunk: list[str]) -> list[IPGeoResult]:
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
            response = getattr(exc, "response", None)
            if getattr(response, "status_code", None) == 429:
                return [self._rate_limited_result(ip, response) for ip in chunk]
            logger.warning(
                "IPinfo Lite bulk lookup failed for %s: %s", ",".join(chunk), exc
            )
            return [self._request_failed_result(ip) for ip in chunk]

        if not isinstance(payload, dict):
            logger.debug(
                "IPinfo Lite bulk lookup for %s returned an invalid payload",
                ",".join(chunk),
            )
            return [
                IPGeoResult(
                    ip, self.provider_name, "", "", "", GEO_STATUS_INVALID_PAYLOAD
                )
                for ip in chunk
            ]

        results: list[IPGeoResult] = []
        for ip in chunk:
            if ip not in payload:
                logger.debug(
                    "IPinfo Lite bulk lookup for %s omitted IP %s", ",".join(chunk), ip
                )
                results.append(
                    IPGeoResult(
                        ip, self.provider_name, "", "", "", GEO_STATUS_INVALID_PAYLOAD
                    )
                )
                continue
            results.append(self._result_from_payload(ip, payload[ip]))
        return results


class GeoJSProvider(RequestsIPGeoProvider):
    """GeoJS implementation for region-name-aware lookups."""

    provider_name = PROVIDER_GEOJS

    def lookup_ip(self, ip: str) -> IPGeoResult:
        url = f"https://get.geojs.io/v1/ip/geo/{ip}.json"
        logger.debug("GeoJS lookup for %s", ip)
        try:
            payload = self._get_json(url, log_name=f"GeoJS lookup for {ip}")
        except (requests.RequestException, ValueError) as exc:
            return self._handle_lookup_exception(ip, exc, provider_label="GeoJS")
        return self._result_from_payload(ip, payload)

    def lookup_ips(self, ips: list[str]) -> list[IPGeoResult]:
        """Return GeoJS results for multiple IPs with conservative chunking."""
        if not ips:
            return []
        if len(ips) == 1:
            return [self.lookup_ip(ips[0])]

        results: list[IPGeoResult] = []
        for start in range(0, len(ips), GEOJS_BULK_CHUNK_SIZE):
            chunk = ips[start : start + GEOJS_BULK_CHUNK_SIZE]
            results.extend(self._lookup_ip_chunk(chunk))
        return results

    def _lookup_ip_chunk(self, chunk: list[str]) -> list[IPGeoResult]:
        query_value = ",".join(chunk)
        logger.debug("GeoJS bulk lookup for %d IPs", len(chunk))
        try:
            payload = self._get_json(
                "https://get.geojs.io/v1/ip/geo.json",
                log_name=f"GeoJS bulk lookup for {len(chunk)} IPs",
                params={"ip": query_value},
            )
        except (requests.RequestException, ValueError) as exc:
            response = getattr(exc, "response", None)
            if getattr(response, "status_code", None) == 429:
                return [self._rate_limited_result(ip, response) for ip in chunk]
            logger.warning("GeoJS bulk lookup failed for %s: %s", query_value, exc)
            return [self._request_failed_result(ip) for ip in chunk]

        if not isinstance(payload, list):
            logger.debug(
                "GeoJS bulk lookup for %s returned an invalid payload", query_value
            )
            return [
                IPGeoResult(
                    ip, self.provider_name, "", "", "", GEO_STATUS_INVALID_PAYLOAD
                )
                for ip in chunk
            ]

        payloads_by_ip: dict[str, list[object]] = {}
        for row in payload:
            row_ip = _string_field(row, "ip")
            if row_ip:
                payloads_by_ip.setdefault(row_ip, []).append(row)

        results: list[IPGeoResult] = []
        for ip in chunk:
            matching_rows = payloads_by_ip.get(ip, [])
            if not matching_rows:
                logger.debug("GeoJS bulk lookup for %s omitted IP %s", query_value, ip)
                results.append(
                    IPGeoResult(
                        ip, self.provider_name, "", "", "", GEO_STATUS_INVALID_PAYLOAD
                    )
                )
                continue
            results.append(self._result_from_payload(ip, matching_rows.pop(0)))
        return results

    def _result_from_payload(self, ip: str, payload: object) -> IPGeoResult:
        """Build one normalized GeoJS result from one payload object."""
        if not isinstance(payload, dict):
            logger.debug("GeoJS lookup for %s returned an invalid payload", ip)
            return IPGeoResult(
                ip, self.provider_name, "", "", "", GEO_STATUS_INVALID_PAYLOAD
            )
        result = IPGeoResult(
            ip=ip,
            provider=self.provider_name,
            country_code=normalize_country_code(_string_field(payload, "country_code")),
            region_code="",
            region_name=_string_field(payload, "region"),
            status=GEO_STATUS_OK,
        )
        logger.debug(
            "GeoJS lookup for %s -> country=%s region=%s",
            ip,
            result.country_code or "(none)",
            result.region_name or "(none)",
        )
        return result


def _nested_string_field(payload: object, *keys: str) -> str:
    """Return one nested string field from a JSON-like mapping."""
    current = payload
    for key in keys:
        if not isinstance(current, dict):
            return ""
        current = current.get(key)
    return current if isinstance(current, str) else ""


class IP2LocationIOProvider(RequestsIPGeoProvider):
    """IP2Location.io implementation for authenticated region-capable lookups."""

    provider_name = PROVIDER_IP2LOCATION_IO

    def __init__(
        self,
        timeout: float = 5.0,
        session: Any = None,
        token: str = "",
    ) -> None:
        super().__init__(timeout=timeout, session=session)
        self.token = token

    def lookup_ip(self, ip: str) -> IPGeoResult:
        url = f"https://api.ip2location.io/?ip={ip}"
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        logger.debug("IP2Location.io lookup for %s", ip)
        try:
            payload = self._get_json(
                url,
                log_name=f"IP2Location.io lookup for {ip}",
                headers=headers,
            )
        except (requests.RequestException, ValueError) as exc:
            return self._handle_lookup_exception(
                ip, exc, provider_label="IP2Location.io"
            )

        if not isinstance(payload, dict):
            logger.debug("IP2Location.io lookup for %s returned an invalid payload", ip)
            return IPGeoResult(
                ip, self.provider_name, "", "", "", GEO_STATUS_INVALID_PAYLOAD
            )
        result = IPGeoResult(
            ip=ip,
            provider=self.provider_name,
            country_code=normalize_country_code(_string_field(payload, "country_code")),
            region_code=normalize_region_code(
                _nested_string_field(payload, "region", "code")
            ),
            region_name=(
                _string_field(payload, "region_name")
                or _nested_string_field(payload, "region", "name")
            ),
            status=GEO_STATUS_OK,
        )
        logger.debug(
            "IP2Location.io lookup for %s -> country=%s region=%s region_name=%s",
            ip,
            result.country_code or "(none)",
            result.region_code or "(none)",
            result.region_name or "(none)",
        )
        return result


def build_geo_provider(
    provider_name: str,
    *,
    timeout: float,
    token: str = "",
    session: Any = None,
) -> IPGeoProvider:
    """Instantiate the configured geolocation provider."""
    if provider_name == PROVIDER_IPWHOIS:
        return IPWhoisProvider(timeout=timeout, session=session)
    if provider_name == PROVIDER_IP_API:
        return IPAPIProvider(timeout=timeout, session=session)
    if provider_name == PROVIDER_IPINFO_LITE:
        return IPInfoLiteProvider(timeout=timeout, session=session, token=token)
    if provider_name == PROVIDER_GEOJS:
        return GeoJSProvider(timeout=timeout, session=session)
    if provider_name == PROVIDER_IP2LOCATION_IO:
        return IP2LocationIOProvider(timeout=timeout, session=session, token=token)
    raise ValueError(f"unsupported geo.provider {provider_name!r}")


def _geo_value_matches(
    result: IPGeoResult,
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


def _geo_result_is_usable(result: IPGeoResult) -> bool:
    """Return whether one geo result should participate in geo matching."""
    return result.usable


def _geo_decision(
    status: str,
    reason: str,
    matched_ips: list[str],
    rejected_ips: list[str],
    *,
    failed_ips: list[str] | None = None,
) -> GeoPolicyDecision:
    """Build and log one geo policy decision."""
    if failed_ips is None:
        logger.debug(
            "Geo policy decision: status=%s reason=%s matched=%s rejected=%s",
            status,
            reason,
            matched_ips or "(none)",
            rejected_ips or "(none)",
        )
    else:
        logger.debug(
            "Geo policy decision: status=%s reason=%s failed_ips=%s",
            status,
            reason,
            failed_ips,
        )
    return GeoPolicyDecision(status, reason, matched_ips, rejected_ips)


def evaluate_geo_policy(
    geo_results: list[IPGeoResult],
    policy: dict[str, Any],
) -> GeoPolicyDecision:
    """Evaluate a source-local policy after the selected provider yields usable geo data."""
    match_scope = str(policy["match_scope"])
    include = normalize_geo_lists(policy["include"])
    exclude = normalize_geo_lists(policy["exclude"])
    include_countries = set(include["countries"])
    include_region_codes = set(include["region_codes"])
    include_region_names = set(include["region_names"])
    exclude_countries = set(exclude["countries"])
    exclude_region_codes = set(exclude["region_codes"])
    exclude_region_names = set(exclude["region_names"])
    has_include_rules = bool(
        include_countries or include_region_codes or include_region_names
    )

    logger.debug(
        "Geo policy evaluation: match_scope=%s results=%d include_countries=%s "
        "include_region_codes=%s include_region_names=%s exclude_countries=%s "
        "exclude_region_codes=%s exclude_region_names=%s",
        match_scope,
        len(geo_results),
        sorted(include_countries) or "(none)",
        sorted(include_region_codes) or "(none)",
        sorted(include_region_names) or "(none)",
        sorted(exclude_countries) or "(none)",
        sorted(exclude_region_codes) or "(none)",
        sorted(exclude_region_names) or "(none)",
    )

    if not geo_results:
        raise ValueError("evaluate_geo_policy requires at least one geo result")

    comparable_results = [
        result for result in geo_results if _geo_result_is_usable(result)
    ]
    if not comparable_results:
        raise ValueError("evaluate_geo_policy requires at least one usable geo result")

    matched_ips: list[str] = []
    rejected_ips: list[str] = []
    for result in comparable_results:
        in_include = _geo_value_matches(
            result,
            include_countries,
            include_region_codes,
            include_region_names,
        )
        in_exclude = _geo_value_matches(
            result,
            exclude_countries,
            exclude_region_codes,
            exclude_region_names,
        )
        include_accepted = True if not has_include_rules else in_include
        accepted = include_accepted and not in_exclude

        logger.debug(
            "Geo policy check: ip=%s provider=%s country=%s region_code=%s "
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
        if accepted:
            matched_ips.append(result.ip)
        else:
            rejected_ips.append(result.ip)

    if match_scope == "all_ips":
        if rejected_ips:
            return _geo_decision(
                "rejected",
                "one_or_more_ips_rejected",
                matched_ips,
                rejected_ips,
            )
        return _geo_decision("accepted", "all_ips_matched", matched_ips, [])

    if matched_ips:
        return _geo_decision(
            "accepted",
            "at_least_one_ip_matched",
            matched_ips,
            rejected_ips,
        )
    return _geo_decision("rejected", "no_ips_matched", [], rejected_ips)
