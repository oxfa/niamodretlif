"""Geo config validation policy owner."""

from __future__ import annotations

import os
import re
from typing import Any

from domain_pipeline.worker.geo.constants import (
    GEO_PROVIDER_GEOJS,
    GEO_PROVIDER_IPINFO_LITE,
)

ISO_REGION_RULE_PATTERN = re.compile(r"^[A-Z]{2}-[A-Z0-9]{1,3}$")


class GeoConfigPolicy:
    """Validate geo provider selection, credentials, and region rules."""

    def requires_region_lookup(self, geo_payload: dict[str, Any]) -> bool:
        """Return whether the policy requires region-capable geo lookup."""
        policy = geo_payload.get("policy", {})
        include = policy.get("include", {})
        exclude = policy.get("exclude", {})
        return bool(include.get("regions", []) or exclude.get("regions", []))

    def effective_provider_name(self, geo_payload: dict[str, Any]) -> str:
        """Return the effective geo provider for one normalized geo payload."""
        if self.requires_region_lookup(geo_payload):
            return GEO_PROVIDER_GEOJS
        return GEO_PROVIDER_IPINFO_LITE

    def inject_effective_fields(self, geo_payload: dict[str, Any]) -> None:
        """Inject effective geo fields into a normalized geo payload."""
        geo_payload["requires_region_lookup"] = self.requires_region_lookup(geo_payload)
        geo_payload["effective_provider"] = self.effective_provider_name(geo_payload)

    def validate_provider_credentials(
        self, geo_payload: dict[str, Any], *, source_label: str
    ) -> None:
        """Validate runtime credential requirements for one source."""
        if not bool(geo_payload.get("enabled")):
            return
        if str(geo_payload.get("effective_provider", "")) != GEO_PROVIDER_IPINFO_LITE:
            return
        if os.environ.get("GEO_IPINFO_TOKEN", "").strip():
            return
        if str(geo_payload.get("token", "")).strip():
            return
        raise ValueError(
            f"{source_label} geo requires GEO_IPINFO_TOKEN or geo.token because "
            "effective_provider resolved to ipinfo_lite"
        )

    def validate_geojs_region_rules(
        self, geo_payload: dict[str, Any], *, source_label: str
    ) -> None:
        """Validate region rules for GeoJS-backed lookups."""
        if str(geo_payload.get("effective_provider", "")) != GEO_PROVIDER_GEOJS:
            return
        policy = geo_payload.get("policy", {})
        for bucket_name in ("include", "exclude"):
            bucket = policy.get(bucket_name, {})
            for value in bucket.get("regions", []):
                candidate = str(value).strip()
                if ISO_REGION_RULE_PATTERN.fullmatch(candidate.upper()):
                    raise ValueError(
                        f"{source_label} geo.policy.{bucket_name}.regions contains "
                        f"ISO-style code {candidate!r}, but GeoJS-backed region lookup "
                        "supports region names only"
                    )
