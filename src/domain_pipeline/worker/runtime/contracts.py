"""Worker runtime contracts and payload types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from domain_pipeline.routing import ResultRoute
from domain_pipeline.prepare.sources.parser import ParsedDomainEntry
from domain_pipeline.worker.delegation import DelegationResult
from domain_pipeline.worker.host_resolution import HostResolutionResult
from domain_pipeline.worker.ip_location import LocationPolicyDecision, IPLocationResult


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
    sequence: int
    total: int
    manual_filter_pass: bool = False
    manual_add: bool = False
    source_id_override: str | None = None
    source_input_label_override: str | None = None
    source_ids: tuple[str, ...] = ()
    source_input_labels: tuple[str, ...] = ()


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
    """Item emitted by host resolution for ip location processing."""

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
    delegation_result: DelegationResult | None = None
    host_resolution_result: HostResolutionResult | None = None
    ip_location_results: list[IPLocationResult] = field(default_factory=list)
    ip_location_policy: LocationPolicyDecision | None = None
    ip_location_attempts: list[dict[str, Any]] = field(default_factory=list)
