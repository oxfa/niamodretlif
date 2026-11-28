"""Focused env-only credential validation for worker IP-location profiles."""

from __future__ import annotations

import pytest

from domain_pipeline.worker.ip_location.constants import IP_LOCATION_PROVIDER_IPINFO_LITE
from domain_pipeline.worker.ip_location.policy import IPLocationConfigPolicy


def test_ip_location_token_field_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IP_LOCATION_IPINFO_TOKEN", raising=False)

    with pytest.raises(ValueError, match="ip_location.token is unsupported"):
        IPLocationConfigPolicy().validate_provider_credentials(
            {
                "enabled": True,
                "effective_provider": IP_LOCATION_PROVIDER_IPINFO_LITE,
                "token": "config-secret",
            },
            source_label="source",
        )


def test_ipinfo_credentials_are_read_from_environment_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {
        "enabled": True,
        "effective_provider": IP_LOCATION_PROVIDER_IPINFO_LITE,
    }
    monkeypatch.delenv("IP_LOCATION_IPINFO_TOKEN", raising=False)
    with pytest.raises(ValueError, match="requires IP_LOCATION_IPINFO_TOKEN"):
        IPLocationConfigPolicy().validate_provider_credentials(
            payload, source_label="source"
        )

    monkeypatch.setenv("IP_LOCATION_IPINFO_TOKEN", "runtime-secret")
    IPLocationConfigPolicy().validate_provider_credentials(
        payload, source_label="source"
    )
