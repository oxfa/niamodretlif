"""DNS config validation policy owner."""

from __future__ import annotations

import ipaddress
import math
from typing import Any

from domain_pipeline.worker.dns.constants import SYSTEM_DNS_NAMESERVER


class DNSConfigPolicy:
    """Validate DNS resolver literals, weights, timing, and removed fields."""

    def normalize_resolver_literal(self, value: str, *, field_name: str) -> str:
        """Return one normalized DNS resolver endpoint literal."""
        stripped = value.strip()
        if not stripped:
            raise ValueError(
                f"{field_name} entries must be non-empty IP addresses or "
                "'system_resolver'"
            )
        if stripped == SYSTEM_DNS_NAMESERVER:
            return SYSTEM_DNS_NAMESERVER
        try:
            return str(ipaddress.ip_address(stripped))
        except ValueError as exc:
            raise ValueError(
                f"{field_name} entries must be valid IPv4/IPv6 addresses "
                f"or 'system_resolver' (got {value!r})"
            ) from exc

    def validate_resolver_weights(
        self, values: list[Any], *, field_name: str
    ) -> list[Any]:
        """Validate all-or-none resolver weights."""
        weighted_count = sum(entry.weight is not None for entry in values)
        if weighted_count not in (0, len(values)):
            raise ValueError(
                f"{field_name} weight must be provided for every resolver "
                "or omitted for every resolver"
            )
        return values

    def validate_timeout(self, value: float) -> float:
        """Return a normalized positive DNS timeout."""
        if not math.isfinite(value) or value <= 0:
            raise ValueError("dns.timeout must be finite and positive")
        return float(value)

    def validate_retry_backoff_base_seconds(self, value: float) -> float:
        """Return a normalized positive DNS retry backoff base delay."""
        if not math.isfinite(value) or value <= 0:
            raise ValueError(
                "dns.retry_backoff_base_seconds must be finite and positive"
            )
        return float(value)
