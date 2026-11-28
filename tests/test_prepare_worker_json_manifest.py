"""Profile tables in real worker manifests."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from domain_pipeline.prepare.assignment import (
    WorkerAssignmentPlanner,
    WorkerManifestBuildRequest,
)
from domain_pipeline.prepare.config.loader import load_config_without_runtime_credentials
from domain_pipeline.prepare.delegation import (
    effective_delegation_profile,
    effective_host_resolution_profile,
    effective_ip_location_profile,
)
from domain_pipeline.prepare.models import (
    PreparedInputDomainPlan,
    PreparedManualRouting,
    PreparedRootPlan,
)
from domain_pipeline.prepare.prepare_to_worker_manifest import (
    PreparedDelegationProfile,
    PreparedRuntimeMetadata,
    WorkerRuntimeHostResolutionProfile,
    WorkerRuntimeIpLocationProfile,
    load_prepare_worker_manifest_for_worker,
    write_prepare_worker_handoff,
)

PROFILE_MODELS = {
    "delegation": PreparedDelegationProfile,
    "host_resolution": WorkerRuntimeHostResolutionProfile,
    "ip_location": WorkerRuntimeIpLocationProfile,
}


@pytest.fixture
def profile_values() -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    config = load_config_without_runtime_credentials(Path("config/direct.yaml"))
    source = config["sources"][0]
    return config, {
        "delegation": effective_delegation_profile(source),
        "host_resolution": effective_host_resolution_profile(source),
        "ip_location": effective_ip_location_profile(source),
    }


def test_projection_and_json_round_trip(
    tmp_path: Path, profile_values: tuple[dict[str, Any], dict[str, dict[str, Any]]]
) -> None:
    config, values = profile_values

    def plan(root: str, host: dict[str, Any]) -> PreparedRootPlan:
        inputs = {
            name: PreparedInputDomainPlan(
                name, PreparedManualRouting(), host, values["ip_location"]
            )
            for name in (root, "ads." + root)
        }
        manual = f"manual.{root}"
        inputs[manual] = PreparedInputDomainPlan(
            manual, PreparedManualRouting(manually_added=True)
        )
        return PreparedRootPlan(root, delegation_profile=values["delegation"], input_domains=inputs)

    host = values["host_resolution"]
    reversed_host = {**host, "resolvers": host["resolvers"][::-1]}
    roots = {
        "worker-01": {"example.net": plan("example.net", reversed_host), "example.com": plan("example.com", host)},
        "worker-02": {"example.org": plan("example.org", reversed_host)},
        "worker-03": {},
    }
    batch = "batch-123-attempt-1"
    planner = WorkerAssignmentPlanner()

    def build(mapping):
        request = WorkerManifestBuildRequest(config, batch, list(roots), mapping)
        return planner.build_worker_manifests(request)

    workers = build(roots)
    first, second, empty = [w.manifest.prepared_metadata.model_dump(mode="json") for w in workers]
    assert {k: len(v) for k, v in first["profiles"].items()} == {
        "delegation": 1, "host_resolution": 2, "ip_location": 1,
    }
    assert second["profiles"]["host_resolution"] == first["profiles"]["host_resolution"][1:]
    assert first["profiles"]["host_resolution"][0]["resolvers"] == (
        first["profiles"]["host_resolution"][1]["resolvers"][::-1]
    )
    org = second["delegation_roots"]["example.org"]
    assert org["input_domains"]["example.org"]["host_resolution_profile_id"] == 0
    assert empty == {"profiles": {k: [] for k in values}, "delegation_roots": {}}
    assert build({k: dict(reversed(tuple(v.items()))) for k, v in roots.items()}) == workers
    for worker in workers:
        path, identity = write_prepare_worker_handoff(worker.manifest, state_root=tmp_path)
        assert (path.name, identity.name) == ("runtime-config.json", "worker-identity.json")
        text = path.read_text(encoding="utf-8")
        payload = json.loads(text)
        assert text == json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        assert set(payload) == {"batch_id", "worker_id", "config_name", "runtime_spec", "prepared_metadata"}
        metadata = payload["prepared_metadata"]
        assert set(metadata["delegation_roots"]) == set(roots[worker.worker_id])
        for root, data in metadata["delegation_roots"].items():
            assert set(data) == {"delegation_profile_id", "input_domains"}
            expected = roots[worker.worker_id][root]
            profiles = metadata["profiles"]
            delegation = profiles["delegation"][data["delegation_profile_id"]]
            assert delegation == PreparedDelegationProfile.model_validate(
                expected.delegation_profile
            ).model_dump(mode="json")
            assert set(data["input_domains"]) == set(expected.input_domains)
            for domain, item in expected.input_domains.items():
                row = data["input_domains"][domain]
                assert row["manual_routing"] == {
                    "manually_added": item.manual_routing.manually_added,
                    "manually_selected_for_filtered": item.manual_routing.manually_selected_for_filtered,
                }
                fields = {"manual_routing"}
                for stage in ("host_resolution", "ip_location"):
                    value = getattr(item, f"{stage}_profile")
                    if value is None:
                        continue
                    field = f"{stage}_profile_id"
                    fields.add(field)
                    assert profiles[stage][row[field]] == PROFILE_MODELS[stage].model_validate(
                        value
                    ).model_dump(mode="json")
                assert set(row) == fields
        assert load_prepare_worker_manifest_for_worker(
            batch_id=batch, worker_id=worker.worker_id, state_root=tmp_path
        ) == worker.manifest


@pytest.mark.parametrize("problem, message", [
    (True, "host_resolution_profile_id"), ("0", "host_resolution_profile_id"),
    (0.0, "host_resolution_profile_id"), (-1, "host_resolution_profile_id"),
    (None, "host_resolution_profile_id"), (1, "host_resolution_profile_id"),
    ("duplicate", "duplicate.*host_resolution"), ("unused", "unused.*host_resolution"),
    ("ip_only", "requires host resolution"), ("manual", "manual input domains cannot carry"),
    ("wrong_root", "input domain does not match"), ("token", "profiles.ip_location.0.token"),
])
def test_rejects_invalid_compact_assignments(
    profile_values: tuple[dict[str, Any], dict[str, dict[str, Any]]],
    problem: object,
    message: str,
) -> None:
    _, values = profile_values
    manual = {"manually_selected_for_filtered": False, "manually_added": False}
    item = {"manual_routing": manual, "host_resolution_profile_id": 0, "ip_location_profile_id": 0}
    root = {"delegation_profile_id": 0, "input_domains": {"example.com": item}}
    metadata = {"profiles": {k: [dict(v)] for k, v in values.items()},
                "delegation_roots": {"example.com": root}}
    PreparedRuntimeMetadata.model_validate(metadata)
    hosts = metadata["profiles"]["host_resolution"]
    if problem in {"duplicate", "unused"}:
        hosts.append(dict(hosts[0]))
        if problem == "unused":
            hosts[1]["timeout"] += 1
    elif problem == "ip_only":
        del item["host_resolution_profile_id"]
    elif problem == "manual":
        manual["manually_added"] = True
    elif problem == "wrong_root":
        root["input_domains"] = {"example.org": item}
    elif problem == "token":
        metadata["profiles"]["ip_location"][0]["token"] = "fixture"
    else:
        item["host_resolution_profile_id"] = problem
    with pytest.raises(ValidationError, match=message):
        PreparedRuntimeMetadata.model_validate(metadata)


@pytest.mark.parametrize(
    "field",
    [
        "runtime_spec.runtime.stage_concurrency.adaptive",
        "runtime_spec.cache.delegation_ttl_days.actionable",
        "prepared_metadata.profiles.host_resolution.0.resolvers.0.weight",
        "prepared_metadata.profiles.host_resolution.0.query_rate_limit.providers.system_resolver",
        "prepared_metadata.profiles.host_resolution.0.ecs.enabled",
    ],
)
def test_loader_rejects_missing_effective_settings(
    tmp_path: Path,
    profile_values: tuple[dict[str, Any], dict[str, dict[str, Any]]],
    field: str,
) -> None:
    config, values = profile_values
    adaptive = config["runtime"]["stage_concurrency"]["adaptive"]
    adaptive["enabled"] = False
    config["cache"]["delegation_ttl_days"]["actionable"] = 11
    host = values["host_resolution"]
    host["query_rate_limit"]["providers"]["system_resolver"]["qps_per_worker"] = 41.0
    root = "example.com"
    plan = PreparedRootPlan(
        root,
        delegation_profile=values["delegation"],
        input_domains={
            root: PreparedInputDomainPlan(
                root, PreparedManualRouting(), host, values["ip_location"]
            )
        },
    )
    batch_id = "batch-123-attempt-1"
    worker_id = "worker-01"
    request = WorkerManifestBuildRequest(
        config, batch_id, [worker_id], {worker_id: {root: plan}}
    )
    prepared = WorkerAssignmentPlanner().build_worker_manifests(request)[0].manifest
    path, _ = write_prepare_worker_handoff(prepared, state_root=tmp_path)
    load_args = {"state_root": tmp_path, "batch_id": batch_id, "worker_id": worker_id}
    assert load_prepare_worker_manifest_for_worker(**load_args) == prepared

    payload = json.loads(path.read_text(encoding="utf-8"))
    parent = payload
    *parts, key = field.split(".")
    for part in parts:
        parent = parent[int(part)] if isinstance(parent, list) else parent[part]
    del parent[key]
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match=rf"{re.escape(field)}: field is required"):
        load_prepare_worker_manifest_for_worker(**load_args)
