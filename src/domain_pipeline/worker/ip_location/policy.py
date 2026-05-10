"""IP-location config validation policy owner."""

from __future__ import annotations

import os
import re
from typing import Any

from domain_pipeline.worker.ip_location.constants import (
    IP_LOCATION_PROVIDER_GEOJS,
    IP_LOCATION_PROVIDER_IPINFO_LITE,
)

ISO_SUBDIVISION_CODE_PATTERN = re.compile(r"^[A-Z]{2}-[A-Z0-9]{1,3}$")


def is_iso_subdivision_code(value: str) -> bool:
    """Return whether one value looks like an ISO subdivision code."""
    return bool(ISO_SUBDIVISION_CODE_PATTERN.fullmatch(value.strip().upper()))


class IPLocationConfigPolicy:
    """Validate IP-location provider selection, credentials, and region rules."""

    def requires_region_lookup(self, ip_location_payload: dict[str, Any]) -> bool:
        """Return whether the policy requires region-capable IP-location lookup."""
        policy = ip_location_payload.get("policy", {})
        include = policy.get("include", {})
        exclude = policy.get("exclude", {})
        return bool(include.get("regions", []) or exclude.get("regions", []))

    def effective_provider_name(self, ip_location_payload: dict[str, Any]) -> str:
        """Return the effective IP-location provider for one normalized payload."""
        if self.requires_region_lookup(ip_location_payload):
            return IP_LOCATION_PROVIDER_GEOJS
        return IP_LOCATION_PROVIDER_IPINFO_LITE

    def inject_effective_fields(self, ip_location_payload: dict[str, Any]) -> None:
        """Inject effective IP-location fields into a normalized payload."""
        ip_location_payload["requires_region_lookup"] = self.requires_region_lookup(
            ip_location_payload
        )
        ip_location_payload["effective_provider"] = self.effective_provider_name(
            ip_location_payload
        )

    def validate_provider_credentials(
        self, ip_location_payload: dict[str, Any], *, source_label: str
    ) -> None:
        """Validate runtime credential requirements for one source."""
        if not bool(ip_location_payload.get("enabled")):
            return
        if (
            str(ip_location_payload.get("effective_provider", ""))
            != IP_LOCATION_PROVIDER_IPINFO_LITE
        ):
            return
        if os.environ.get("IP_LOCATION_IPINFO_TOKEN", "").strip():
            return
        if str(ip_location_payload.get("token", "")).strip():
            return
        raise ValueError(
            f"{source_label} ip location requires "
            "IP_LOCATION_IPINFO_TOKEN or ip_location.token because "
            "effective_provider resolved to ipinfo_lite"
        )

    def validate_ip_locationjs_region_rules(
        self, ip_location_payload: dict[str, Any], *, source_label: str
    ) -> None:
        """Validate region rules for IPLocationJS-backed lookups."""
        if (
            str(ip_location_payload.get("effective_provider", ""))
            != IP_LOCATION_PROVIDER_GEOJS
        ):
            return
        policy = ip_location_payload.get("policy", {})
        for bucket_name in ("include", "exclude"):
            bucket = policy.get(bucket_name, {})
            for value in bucket.get("regions", []):
                candidate = str(value).strip()
                if is_iso_subdivision_code(candidate):
                    raise ValueError(
                        f"{source_label} ip_location.policy.{bucket_name}.regions contains "
                        f"ISO-style code {candidate!r}, but IPLocationJS-backed region lookup "
                        "supports region names only"
                    )
