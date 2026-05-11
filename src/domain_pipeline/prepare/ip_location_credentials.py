"""Prepare-stage IP-location credential validation."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from collections.abc import Callable
from typing import Any

import requests

from domain_pipeline.worker.ip_location.constants import (
    IP_LOCATION_PROVIDER_IPINFO_LITE,
)

logger = logging.getLogger(__name__)

IP_LOCATION_CREDENTIAL_VALIDATION_IP = "1.1.1.1"
IPINFO_LITE_CREDENTIAL_VALIDATION_URL = (
    f"https://api.ipinfo.io/lite/{IP_LOCATION_CREDENTIAL_VALIDATION_IP}"
)
HTTPGet = Callable[..., Any]


@dataclass(frozen=True)
class CredentialValidationRequest:
    """Inputs needed for one provider credential validation probe."""

    source_id: str
    token: str
    timeout: float
    get: HTTPGet


@dataclass(frozen=True)
class ProviderCredentialProbe:
    """Provider-specific credential probe registered by provider name."""

    provider_name: str
    validation_url: str
    runtime_env_var: str
    token_query_parameter: str
    expected_payload_field: str

    def validation_url_for_token(self, token: str) -> str:
        """Return the provider validation URL for one credential token."""
        return f"{self.validation_url}?{self.token_query_parameter}={token}"

    def validate(self, request: CredentialValidationRequest) -> None:
        """Run one non-retried credential probe and fail only on auth rejection."""
        try:
            response = request.get(
                self.validation_url_for_token(request.token),
                timeout=request.timeout,
            )
        except requests.RequestException as exc:
            logger.warning(
                "%s credential validation probe was inconclusive for source %s: %s",
                self.provider_name,
                request.source_id,
                _safe_exception_summary(exc),
            )
            return
        status_code = int(getattr(response, "status_code", 0))
        if status_code in {401, 403}:
            raise ValueError(
                "ip_location credential validation rejected source "
                f"{request.source_id!r} for provider {self.provider_name} "
                f"with HTTP {status_code}"
            )
        if status_code == 200:
            self._log_inconclusive_success_payload(
                response,
                source_id=request.source_id,
            )

    def _log_inconclusive_success_payload(
        self, response: Any, *, source_id: str
    ) -> None:
        """Log inconclusive success payloads without making preparation fatal."""
        try:
            payload = response.json()
        except ValueError as exc:
            logger.warning(
                "%s credential validation response was not JSON for source %s: %s",
                self.provider_name,
                source_id,
                _safe_exception_summary(exc),
            )
            return
        if not isinstance(payload, dict) or not isinstance(
            payload.get(self.expected_payload_field), str
        ):
            logger.warning(
                "%s credential validation payload was inconclusive for source %s",
                self.provider_name,
                source_id,
            )


class IPLocationCredentialValidator:
    """Validate configured IP-location provider credentials before worker handoff."""

    def __init__(
        self,
        *,
        get: HTTPGet | None = None,
        provider_probes: tuple[ProviderCredentialProbe, ...] | None = None,
    ) -> None:
        self.get = get or requests.Session().get
        self.provider_probes = {
            probe.provider_name: probe
            for probe in (provider_probes or DEFAULT_PROVIDER_CREDENTIAL_PROBES)
        }

    def validate_config(self, config: dict[str, Any]) -> None:
        """Validate each distinct configured IP-location credential once."""
        checked_credentials: set[tuple[str, str]] = set()
        for source in config.get("sources", []):
            if not isinstance(source, dict):
                continue
            if not source.get("enabled", True):
                continue
            credential_key = self.validate_source(
                source,
                checked_credentials=checked_credentials,
            )
            if credential_key:
                checked_credentials.add(credential_key)

    def validate_source(
        self,
        source: dict[str, Any],
        *,
        checked_credentials: set[tuple[str, str]] | None = None,
    ) -> tuple[str, str] | None:
        """Validate one source and return the credential key when a probe ran."""
        if not source.get("enabled", True):
            return None
        ip_location = source.get("ip_location", {})
        if not isinstance(ip_location, dict) or not ip_location.get("enabled"):
            return None
        provider_name = str(ip_location.get("effective_provider", ""))
        provider_probe = self.provider_probes.get(provider_name)
        if provider_probe is None:
            return None
        token = _token_for_ip_location(ip_location, provider_probe=provider_probe)
        credential_key = (provider_name, token)
        if not token or (
            checked_credentials is not None and credential_key in checked_credentials
        ):
            return None
        provider_probe.validate(
            CredentialValidationRequest(
                source_id=str(source.get("id", "")),
                token=token,
                timeout=float(ip_location.get("timeout", 5.0)),
                get=self.get,
            )
        )
        return credential_key


def _token_for_ip_location(
    ip_location: dict[str, Any], *, provider_probe: ProviderCredentialProbe
) -> str:
    """Return the token source that runtime would use for an IP-location provider."""
    config_token = str(ip_location.get("token", "")).strip()
    if config_token:
        return config_token
    return os.environ.get(provider_probe.runtime_env_var, "").strip()


def _safe_exception_summary(exc: BaseException) -> str:
    """Return non-secret exception context for credential validation logs."""
    response = getattr(exc, "response", None)
    status_code = getattr(response, "status_code", None)
    if status_code is not None:
        return f"{type(exc).__name__}(status_code={status_code})"
    return type(exc).__name__


DEFAULT_PROVIDER_CREDENTIAL_PROBES = (
    ProviderCredentialProbe(
        provider_name=IP_LOCATION_PROVIDER_IPINFO_LITE,
        validation_url=IPINFO_LITE_CREDENTIAL_VALIDATION_URL,
        runtime_env_var="IP_LOCATION_IPINFO_TOKEN",
        token_query_parameter="token",
        expected_payload_field="country_code",
    ),
)
