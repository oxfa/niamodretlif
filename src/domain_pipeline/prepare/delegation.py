"""Prepare/runtime helpers for delegation-root compatibility."""

from __future__ import annotations

import json
from typing import Any

from domain_pipeline.worker.dns import delegation_dns_profile


def delegation_behavior_payload(dns_config: dict[str, Any]) -> dict[str, Any]:
    """Return DNS behavior that affects one live delegation NS lookup."""
    delegation_config = dict(dns_config["delegation"])
    return {
        **delegation_dns_profile(dns_config),
        "retry_attempts": delegation_config["retry_attempts"],
    }


def delegation_behavior_fingerprint(dns_config: dict[str, Any]) -> str:
    """Return a deterministic compatibility key for delegation root grouping."""
    return json.dumps(
        delegation_behavior_payload(dns_config),
        sort_keys=True,
        separators=(",", ":"),
    )
