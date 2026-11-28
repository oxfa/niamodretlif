"""Worker runtime contracts and payload types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from domain_pipeline.routing.route_codes import RouteCode, StageRouteTransition
from domain_pipeline.routing.types import ResultRoute
from domain_pipeline.prepare.sources.parser import DomainEntry
from domain_pipeline.worker.delegation.lookup import DelegationResult
from domain_pipeline.worker.host_resolution.lookup import HostResolutionResult
from domain_pipeline.worker.ip_location.providers import (
    IPLocationResult,
    LocationPolicyDecision,
)


@dataclass(frozen=True)
class RuntimeItemPosition:
    """Stable worker ordering for one assigned input domain."""

    sequence: int
    total: int


@dataclass(frozen=True)
class RuntimeManualRouting:
    """Manual-input route flags for one assigned input domain."""

    manually_selected_for_filtered: bool = False
    manually_added: bool = False


@dataclass(frozen=True)
class ParsedInputDomain:
    """One normalized source-blind input-domain assignment."""

    entry: DomainEntry
    position: RuntimeItemPosition
    manual_routing: RuntimeManualRouting = field(default_factory=RuntimeManualRouting)
    host_resolution_profile: dict[str, Any] | None = None
    ip_location_profile: dict[str, Any] | None = None


@dataclass(frozen=True)
class CompletedResultEvidence:
    """Stage evidence attached to one input-domain route."""

    delegation_result: DelegationResult | None = None
    host_resolution_results: list[HostResolutionResult] = field(default_factory=list)
    host_resolution_result: HostResolutionResult | None = None
    ip_location_results: list[IPLocationResult] = field(default_factory=list)
    ip_location_policy: LocationPolicyDecision | None = None


@dataclass(frozen=True)
class DelegationRootWorkItem:
    """One root-level delegation lookup with input-domain fanout items."""

    registrable_domain: str
    delegation_profile: dict[str, Any]
    items: tuple[ParsedInputDomain, ...]


@dataclass(frozen=True)
class HostResolutionWorkItem:
    """Input-domain item emitted for optional host-resolution processing."""

    parsed: ParsedInputDomain
    delegation_result: DelegationResult
    delegation_transition: StageRouteTransition


@dataclass(frozen=True)
class IpLocationWorkItem:
    """Input-domain item emitted for IP-location processing."""

    parsed: ParsedInputDomain
    delegation_result: DelegationResult
    host_resolution_result: HostResolutionResult
    host_resolution_results: list[HostResolutionResult]
    host_resolution_transition: StageRouteTransition


@dataclass(frozen=True)
class RegistrableDomainResult:
    """One root-level delegation result and its application disposition."""

    registrable_domain: str
    disposition: str
    delegation_result: DelegationResult


@dataclass(frozen=True)
class CompletedInputDomainResult:
    """Terminal result emitted for one assigned input domain."""

    entry: DomainEntry
    route: ResultRoute
    route_code: RouteCode
    route_reason: str
    row: dict[str, Any]
    evidence: CompletedResultEvidence = field(default_factory=CompletedResultEvidence)
