"""Worker runtime contracts and payload types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from domain_pipeline.routing.types import ResultRoute
from domain_pipeline.prepare.models import PreparedProvenance
from domain_pipeline.prepare.sources.parser import ParsedDomainEntry
from domain_pipeline.worker.delegation.lookup import DelegationResult
from domain_pipeline.worker.host_resolution.lookup import HostResolutionResult
from domain_pipeline.worker.ip_location.providers import (
    LocationPolicyDecision,
    IPLocationResult,
)


@dataclass(frozen=True)
class RuntimeProvenance:
    """Runtime ordering and source-field overrides for one parsed host item."""

    sequence: int
    total: int
    source: PreparedProvenance = field(default_factory=PreparedProvenance)


@dataclass(frozen=True)
class WorkerSourceContext:
    """Worker-local source identity, config, and output grouping context."""

    source_id: str
    input_label: str
    output_stem: str
    config: dict[str, Any]


@dataclass(frozen=True)
class ParsedHostItem:
    """Normalized parsed host with runtime context and output provenance overrides."""

    source_context: WorkerSourceContext
    entry: ParsedDomainEntry
    provenance: RuntimeProvenance


@dataclass(frozen=True)
class CompletedResultEvidence:
    """Stage evidence attached to one terminal host result."""

    delegation_result: DelegationResult | None = None
    host_resolution_result: HostResolutionResult | None = None
    ip_location_results: list[IPLocationResult] = field(default_factory=list)
    ip_location_policy: LocationPolicyDecision | None = None
    ip_location_attempts: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class DelegationRootWorkItem:
    """One root-level delegation lookup with host-level fanout items."""

    registrable_domain: str
    delegation_source_context: WorkerSourceContext
    items: tuple[ParsedHostItem, ...]
    delegation_behavior_fingerprint: str


@dataclass(frozen=True)
class HostResolutionWorkItem:
    """Item emitted by delegation for optional host-resolution processing."""

    parsed: ParsedHostItem
    delegation_result: DelegationResult


@dataclass(frozen=True)
class IpLocationWorkItem:
    """Item emitted by host resolution for IP-location processing."""

    parsed: ParsedHostItem
    delegation_result: DelegationResult
    host_resolution_result: HostResolutionResult
    pipeline_result_code: str


@dataclass(frozen=True)
class CompletedHostResult:
    """Terminal result emitted to the writer boundary."""

    source_context: WorkerSourceContext
    entry: ParsedDomainEntry
    pipeline_result_code: str
    route: ResultRoute
    row: dict[str, Any]
    evidence: CompletedResultEvidence = field(default_factory=CompletedResultEvidence)
