"""Focused coverage for source-blind worker assignment and result collections."""

from __future__ import annotations

import json
from operator import setitem
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from domain_pipeline.paths import PathLayout
from domain_pipeline.prepare.config.models import DNSECSConfig, DNSQueryRateLimitConfig
from domain_pipeline.prepare.prepare_to_worker_manifest import (
    PreparedRuntimeMetadata,
    WorkerRuntimeStageConcurrencyAdaptiveSpec,
)
from domain_pipeline.prepare.sources.parser import DomainEntry
from domain_pipeline.routing.policies import HostResolutionRoutingPolicy
from domain_pipeline.routing.route_codes import RouteCode
from domain_pipeline.worker.delegation.lookup import (
    DelegationDnsEvidence,
    DelegationResult,
    DelegationSoaEvidence,
)
from domain_pipeline.worker.host_resolution.lookup import (
    HostResolutionAddressEvidence,
    HostResolutionDnsEvidence,
    HostResolutionResult,
)
from domain_pipeline.worker.ip_location.providers import (
    IPLocationProvider,
    IPLocationResult,
)
from domain_pipeline.worker.output.writer import ResultOutputWriter
from domain_pipeline.worker.runtime import executor, lookup_services
from domain_pipeline.worker.runtime.capacity import (
    DNSStageCapacityGroup,
    RuntimeDNSCapacityGroups,
    discover_dns_capacity_groups,
)
from domain_pipeline.worker.runtime.contracts import (
    CompletedResultEvidence,
    RegistrableDomainResult,
)
from domain_pipeline.worker.runtime.dns_factory import RuntimeDNSChecker
from domain_pipeline.worker.runtime.loading import RuntimeItemLoader
from domain_pipeline.worker.runtime.results import (
    CompletedResultRequest,
    build_completed_result,
)
from domain_pipeline.worker.runtime.runner import run_worker
from domain_pipeline.worker.worker_to_aggregate_manifest import (
    WorkerDomainResultsEnvelope,
    parse_worker_domain_results_jsonl_text,
    validate_worker_domain_results,
)


BATCH_ID = "batch-123-attempt-1"
WORKER_ID = "worker-1"
CONFIG_NAME = "fixture"


def _delegation_profile() -> dict[str, Any]:
    return {
        "dns_query": {
            "default_resolvers": [{"resolver": "system_resolver", "weight": None}],
            "timeout": 5.0,
            "retry_backoff_base_seconds": 1.0,
            "query_rate_limit": DNSQueryRateLimitConfig().model_dump(mode="json"),
        },
        "delegation": {
            "resolvers": None,
            "timeout": None,
            "query_rate_limit": None,
            "retry_attempts": 3,
        },
    }


def _host_resolution_profile(
    *, resolver: str, resolve_www: bool, weight: int | None = None
) -> dict[str, Any]:
    return {
        "resolvers": [{"resolver": resolver, "weight": weight}],
        "timeout": 5.0,
        "retry_backoff_base_seconds": 1.0,
        "query_rate_limit": DNSQueryRateLimitConfig().model_dump(mode="json"),
        "retry_attempts": 3,
        "ecs": DNSECSConfig().model_dump(mode="json"),
        "resolve_www_for_registrable_domain": resolve_www,
    }


def _manual_routing(
    *, added: bool = False, selected: bool = False
) -> dict[str, Any]:
    return {
        "manual_routing": {
            "manually_selected_for_filtered": selected,
            "manually_added": added,
        }
    }


def _profiled_worker_metadata() -> dict[str, Any]:
    host_and_ip = {
        **_manual_routing(),
        "host_resolution_profile_id": 0,
        "ip_location_profile_id": 0,
    }
    return {
        "profiles": {
            "delegation": [_delegation_profile()],
            "host_resolution": [
                _host_resolution_profile(
                    resolver="8.8.8.8", resolve_www=True, weight=2
                ),
                _host_resolution_profile(resolver="system_resolver", resolve_www=False),
            ],
            "ip_location": [
                {
                    "timeout": 5.0,
                    "cache_ttl_days": 7,
                    "policy": {
                        "enabled": True,
                        "match_scope": "any_ip",
                        "include": {"countries": ["CN"], "regions": []},
                        "exclude": {"countries": [], "regions": []},
                    },
                    "requires_region_lookup": False,
                    "effective_provider": "ipinfo_lite",
                }
            ],
        },
        "delegation_roots": {
            "example.net": {
                "delegation_profile_id": 0,
                "input_domains": {"manual.example.net": _manual_routing(added=True)},
            },
            "example.com": {
                "delegation_profile_id": 0,
                "input_domains": {
                    "example.com": host_and_ip,
                    "selected.example.com": _manual_routing(selected=True),
                    "hostonly.example.com": {
                        **_manual_routing(),
                        "host_resolution_profile_id": 1,
                    },
                    "added.example.com": _manual_routing(added=True),
                    "disabled.example.com": _manual_routing(),
                    "ads.example.com": host_and_ip,
                },
            },
        },
    }


def _write_worker_handoff(state_root: Path, metadata: dict[str, Any]) -> Path:
    paths = PathLayout(state_root).workflow_state
    identity = {"batch_id": BATCH_ID, "worker_id": WORKER_ID}
    config_path = paths.prepare_worker_config_path(**identity)
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        json.dumps(
            {
                **identity,
                "config_name": CONFIG_NAME,
                "runtime_spec": {
                    "cache": {
                        "delegation_ttl_days": {"actionable": 7, "unactionable": 1},
                        "host_resolution_ttl_days": {
                            "resolved": 7,
                            "nodata": 1,
                            "nxdomain": 1,
                        },
                    },
                    "runtime": {
                        "stage_concurrency": {
                            "minimums": {
                                "delegation": 1,
                                "host_resolution": 1,
                                "ip_location": 1,
                            },
                            "adaptive": WorkerRuntimeStageConcurrencyAdaptiveSpec(
                                enabled=False
                            ).model_dump(mode="json"),
                        }
                    },
                },
                "prepared_metadata": metadata,
            }
        ) + "\n",
        encoding="utf-8",
    )
    paths.prepare_worker_identity_path(**identity).write_text(
        json.dumps(identity) + "\n", encoding="utf-8"
    )
    return paths.worker_domain_results_path(config_name=CONFIG_NAME, **identity)


def _root_row() -> dict[str, object]:
    return {
        "registrable_domain": "example.com",
        "disposition": "actionable",
        "delegation_result": {
            "domain": "example.com",
            "dns": {
                "ns_records_exist": True,
                "ns_nodata": False,
                "ns_nxdomain": False,
                "ns_retry_exhausted": False,
                "ns_lookup_error": False,
            },
            "soa": {
                "soa_exists": False,
                "soa_absent": False,
                "soa_retry_exhausted": False,
                "soa_source": "",
            },
            "no_nameservers": False,
            "nameservers": ["ns1.example.com"],
            "from_cache": False,
        },
    }


def _input_row(input_domain: str = "example.com") -> dict[str, object]:
    return {
        "input_domain": input_domain,
        "registrable_domain": "example.com",
        "route": "filtered",
        "route_code": "host_resolution_to_filtered_skipped",
        "route_reason": "host resolution was skipped",
        "host_resolution_results": [],
        "ip_location_results": [],
        "ip_location_policy": None,
    }


def _envelope(input_domain: str = "example.com") -> dict[str, object]:
    return {
        "registrable_domain_results": [_root_row()],
        "input_domain_results": [_input_row(input_domain)],
    }


def test_runtime_loader_shares_profile_bodies_across_source_blind_work() -> None:
    payload = _profiled_worker_metadata()
    metadata = PreparedRuntimeMetadata.model_validate(payload)
    loader = RuntimeItemLoader(prepared_metadata=metadata)

    first, second = loader.delegation_work_items()
    assert (first.registrable_domain, second.registrable_domain) == (
        "example.com",
        "example.net",
    )
    items = loader.all_input_domains()
    assert [item.entry.host for item in items] == [
        "added.example.com",
        "ads.example.com",
        "disabled.example.com",
        "example.com",
        "hostonly.example.com",
        "selected.example.com",
        "manual.example.net",
    ]
    assert [(item.position.sequence, item.position.total) for item in items] == [
        (index, 7) for index in range(7)
    ]
    assert loader.expected_input_domains_by_root() == {
        "example.com": {item.entry.host for item in items[:6]},
        "example.net": {"manual.example.net"},
    }
    assert loader.delegation_work_items()[0] is first
    assert all(not hasattr(item, "source_context") for item in items)

    added, ads, disabled, apex, hostonly, selected, terminal_manual = items
    assert first.delegation_profile is second.delegation_profile
    assert ads.host_resolution_profile is apex.host_resolution_profile
    assert ads.ip_location_profile is apex.ip_location_profile
    for settings, expected in (
        (first.delegation_profile, payload["profiles"]["delegation"][0]),
        (ads.host_resolution_profile, payload["profiles"]["host_resolution"][0]),
        (ads.ip_location_profile, payload["profiles"]["ip_location"][0]),
        (hostonly.host_resolution_profile, payload["profiles"]["host_resolution"][1]),
    ):
        assert json.loads(json.dumps(settings, default=dict)) == expected
    assert hostonly.ip_location_profile is None
    assert added.manual_routing.manually_added
    assert selected.manual_routing.manually_selected_for_filtered
    assert terminal_manual.manual_routing.manually_added
    for item in (added, disabled, selected, terminal_manual):
        assert item.host_resolution_profile is None
        assert item.ip_location_profile is None
    with pytest.raises(TypeError):
        setitem(cast(Any, first.delegation_profile), "dns_query", {})


@pytest.mark.parametrize(
    ("stage", "path", "replacement"),
    [
        ("delegation", ("dns_query", "timeout"), 10.0),
        ("delegation", ("dns_query", "default_resolvers", 0), {}),
        ("delegation", ("dns_query", "default_resolvers", 0, "weight"), 3),
        ("host_resolution", ("ecs", "enabled"), True),
        (
            "host_resolution",
            ("query_rate_limit", "providers", "google_public_dns", "qps_per_worker"),
            1.0,
        ),
        ("ip_location", ("policy", "include", "countries"), ["US"]),
        ("ip_location", ("policy", "include", "countries", 0), "US"),
    ],
    ids=[
        "delegation-settings",
        "delegation-resolvers",
        "delegation-resolver-entry",
        "host-ecs",
        "host-provider-limit",
        "ip-location-policy",
        "ip-location-countries",
    ],
)
def test_runtime_loader_shared_profile_settings_are_read_only(
    stage: str, path: tuple[str | int, ...], replacement: object
) -> None:
    metadata = PreparedRuntimeMetadata.model_validate(_profiled_worker_metadata())
    loader = RuntimeItemLoader(prepared_metadata=metadata)
    first = loader.delegation_work_items()[0]
    ads = next(item for item in first.items if item.entry.host == "ads.example.com")
    profile: Any = {
        "delegation": first.delegation_profile,
        "host_resolution": ads.host_resolution_profile,
        "ip_location": ads.ip_location_profile,
    }[stage]
    for key in path[:-1]:
        profile = profile[key]

    with pytest.raises(TypeError):
        setitem(profile, path[-1], replacement)


def test_run_worker_routes_shared_profile_references(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result_path = _write_worker_handoff(tmp_path, _profiled_worker_metadata())
    delegation_calls: list[tuple[str, str]] = []
    host_calls: list[tuple[str, str]] = []
    ip_calls: list[tuple[str, tuple[str, ...]]] = []
    loaders: list[RuntimeItemLoader] = []

    def record_loader(**kwargs: Any) -> RuntimeItemLoader:
        assert isinstance(kwargs["prepared_metadata"], PreparedRuntimeMetadata)
        loader = RuntimeItemLoader(**kwargs)
        loaders.append(loader)
        return loader

    def discover_capacity(loader: RuntimeItemLoader) -> RuntimeDNSCapacityGroups:
        assert loaders == [loader]
        capacity = discover_dns_capacity_groups(loader)
        assert capacity.delegation == (
            DNSStageCapacityGroup("system_resolver", 60.0, 10, 32),
        )
        assert capacity.host_resolution == (
            DNSStageCapacityGroup("google_public_dns", 30.0, 5, 16),
            DNSStageCapacityGroup("system_resolver", 60.0, 10, 32),
        )
        return capacity

    async def delegation(
        checker: RuntimeDNSChecker, domain: str, **_: Any
    ) -> DelegationResult:
        delegation_calls.append((domain, checker.delegation_resolver_key()))
        if domain == "example.net":
            return DelegationResult(
                domain=domain,
                dns=DelegationDnsEvidence(ns_nxdomain=True),
                soa=DelegationSoaEvidence(soa_absent=True),
            )
        return DelegationResult(
            domain=domain,
            dns=DelegationDnsEvidence(ns_records_exist=True),
            nameservers=["ns1.example.com"],
        )

    async def host_resolution(
        checker: RuntimeDNSChecker, host: str, **_: Any
    ) -> HostResolutionResult:
        host_calls.append((host, checker.host_resolution_resolver_key()))
        return HostResolutionResult(
            host=host,
            dns=HostResolutionDnsEvidence(a_exists=True),
            addresses=HostResolutionAddressEvidence(
                ipv4_addresses={
                    "example.com": ["192.0.2.1"],
                    "www.example.com": ["192.0.2.1", "192.0.2.2"],
                    "ads.example.com": ["192.0.2.3"],
                    "hostonly.example.com": ["192.0.2.4"],
                }[host]
            ),
        )

    async def ip_location(
        provider: IPLocationProvider, ips: list[str]
    ) -> list[IPLocationResult]:
        ip_calls.append((provider.provider_name, tuple(ips)))
        return [
            IPLocationResult(
                ip=ip,
                provider=provider.provider_name,
                country_code="US" if ip == "192.0.2.3" else "CN",
                region_code="",
                region_name="",
                status="ok",
            )
            for ip in ips
        ]

    monkeypatch.setattr(executor, "RuntimeItemLoader", record_loader)
    monkeypatch.setattr(executor, "discover_dns_capacity_groups", discover_capacity)
    monkeypatch.setattr(lookup_services, "lookup_delegation_async", delegation)
    monkeypatch.setattr(lookup_services, "lookup_host_resolution_async", host_resolution)
    monkeypatch.setattr(lookup_services, "lookup_ip_locations_async", ip_location)
    monkeypatch.setenv("IP_LOCATION_IPINFO_TOKEN", "fixture-token")

    outcome = run_worker(
        batch_id=BATCH_ID, worker_id=WORKER_ID, source_root=tmp_path, state_root=tmp_path
    )

    assert outcome["overall_conclusion"] == "success", outcome
    assert len(loaders) == 1
    envelope = parse_worker_domain_results_jsonl_text(
        result_path.read_text(encoding="utf-8")
    )
    assert {
        row.registrable_domain: row.disposition
        for row in envelope.registrable_domain_results
    } == {"example.com": "actionable", "example.net": "unactionable"}
    input_results = {row.input_domain: row for row in envelope.input_domain_results}
    assert {domain: row.route_code for domain, row in input_results.items()} == {
        "added.example.com": RouteCode.MANUALLY_ADDED_TO_FILTERED_ACTIONABLE,
        "ads.example.com": RouteCode.IP_LOCATION_TO_REVIEW_POLICY_REJECTED,
        "disabled.example.com": RouteCode.HOST_RESOLUTION_TO_FILTERED_SKIPPED,
        "example.com": RouteCode.IP_LOCATION_TO_FILTERED_POLICY_ACCEPTED,
        "hostonly.example.com": RouteCode.HOST_RESOLUTION_TO_FILTERED_RESOLVES,
        "selected.example.com": RouteCode.MANUALLY_SELECTED_FOR_FILTERED_TO_FILTERED,
        "manual.example.net": RouteCode.DELEGATION_TO_UNACTIONABLE_NS_NXDOMAIN_SOA_ABSENT,
    }
    assert {
        domain: [result.host for result in row.host_resolution_results]
        for domain, row in input_results.items()
        if row.host_resolution_results
    } == {
        "ads.example.com": ["ads.example.com"],
        "example.com": ["example.com", "www.example.com"],
        "hostonly.example.com": ["hostonly.example.com"],
    }
    system_key = "system_resolver|ecs=off|timeout=5.0|retry_backoff_base_seconds=1"
    google_key = "8.8.8.8|ecs=off|timeout=5.0|retry_backoff_base_seconds=1"
    assert sorted(delegation_calls) == [
        ("example.com", system_key),
        ("example.net", system_key),
    ]
    assert sorted(host_calls) == [
        ("ads.example.com", google_key),
        ("example.com", google_key),
        ("hostonly.example.com", system_key),
        ("www.example.com", google_key),
    ]
    assert sorted(ip_calls) == [
        ("ipinfo_lite", ("192.0.2.1", "192.0.2.2")),
        ("ipinfo_lite", ("192.0.2.3",)),
    ]


def test_run_worker_writes_empty_assignment_results(tmp_path: Path) -> None:
    result_path = _write_worker_handoff(
        tmp_path,
        {
            "profiles": {"delegation": [], "host_resolution": [], "ip_location": []},
            "delegation_roots": {},
        },
    )

    outcome = run_worker(
        batch_id=BATCH_ID, worker_id=WORKER_ID, source_root=tmp_path, state_root=tmp_path
    )

    assert outcome["overall_conclusion"] == "success", outcome
    envelope = parse_worker_domain_results_jsonl_text(
        result_path.read_text(encoding="utf-8")
    )
    assert envelope.registrable_domain_results == []
    assert envelope.input_domain_results == []


def test_result_envelope_rejects_source_attribution_fields() -> None:
    payload = _envelope()
    payload["input_domain_results"][0]["source_id"] = "source-a"  # type: ignore[index]

    with pytest.raises(ValidationError, match="extra_forbidden"):
        parse_worker_domain_results_jsonl_text(json.dumps(payload))


def test_result_validation_requires_exact_coverage_and_psl_root() -> None:
    envelope = WorkerDomainResultsEnvelope.model_validate(_envelope("ads.example.com"))

    validate_worker_domain_results(
        expected_input_domains_by_root={
            "example.com": {"ads.example.com"}
        },
        envelope=envelope,
    )

    with pytest.raises(ValueError, match="registrable root does not match"):
        validate_worker_domain_results(
            expected_input_domains_by_root={"example.com": {"example.org"}},
            envelope=WorkerDomainResultsEnvelope.model_validate(
                {
                    "registrable_domain_results": [_root_row()],
                    "input_domain_results": [_input_row("example.org")],
                }
            ),
        )


def test_result_envelope_rejects_public_suffix_validation_route() -> None:
    payload = {
        "registrable_domain_results": [_root_row()],
        "input_domain_results": [
            {
                **_input_row(),
                "route": "review",
                "route_code": "input_validation_to_review_public_suffix",
                "route_reason": "input is a public suffix rather than a registrable host",
            }
        ],
    }

    with pytest.raises(
        ValidationError,
        match="input-domain route does not match its terminal route code",
    ):
        WorkerDomainResultsEnvelope.model_validate(payload)


def test_writer_emits_only_the_two_closed_result_collections(
    tmp_path: Path,
) -> None:
    writer = ResultOutputWriter(
        output_spec={
            "unactionable": str(tmp_path / "unactionable-input-domains" / "worker.txt"),
            "review": str(tmp_path / "review-results-by-input-domain" / "worker.csv"),
            "domain_results": str(tmp_path / "domain-results.jsonl"),
        },
        expected_input_domains_by_root={"example.com": {"example.com"}},
    )
    delegation = DelegationResult(
        domain="example.com",
        dns=DelegationDnsEvidence(ns_records_exist=True),
        soa=DelegationSoaEvidence(),
        nameservers=["ns1.example.com"],
    )
    writer.add_root_result(
        RegistrableDomainResult(
            registrable_domain="example.com",
            disposition="actionable",
            delegation_result=delegation,
        )
    )
    writer.add(
        build_completed_result(
            CompletedResultRequest(
                entry=DomainEntry("example.com", "example.com"),
                route_transition=HostResolutionRoutingPolicy().skipped(),
                evidence=CompletedResultEvidence(delegation_result=delegation),
            )
        )
    )

    writer.write()
    payload = parse_worker_domain_results_jsonl_text(
        (tmp_path / "domain-results.jsonl").read_text(encoding="utf-8")
    )

    assert set(payload.model_dump(mode="json")) == {
        "registrable_domain_results",
        "input_domain_results",
    }
    assert payload.input_domain_results[0].input_domain == "example.com"
