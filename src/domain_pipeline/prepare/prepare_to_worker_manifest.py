"""Prepare-owned manifests consumed by worker jobs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    ValidationError,
    model_validator,
)

from domain_pipeline.config_namespace import CONFIG_NAMESPACE_PATTERN
from domain_pipeline.prepare.config.models import (
    DNSECSConfig,
    DNSQueryRateLimitConfig,
    DNSResolverConfig,
)
from domain_pipeline.handoff_io import (
    read_strict_json,
    write_compact_json,
    write_json,
)
from domain_pipeline.paths.layout import PathLayout
from domain_pipeline.prepare.stage_concurrency import (
    RuntimeStageConcurrencyAdaptiveConfig,
)
from domain_pipeline.prepare.sources.parser import DomainListParser, InputFileFormat
from domain_pipeline.worker.ip_location.constants import (
    IP_LOCATION_PROVIDER_GEOJS,
    IP_LOCATION_PROVIDER_IPINFO_LITE,
)


class PrepareWorkerModel(BaseModel):
    """Base prepare-to-worker manifest model that rejects unknown fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class WorkerOutputSpec(PrepareWorkerModel):
    """Repo-relative per-worker publish-snapshot and internal-state paths."""

    result_root: str
    unactionable: str
    review: str
    domain_results: str
    cache: str

    def resolve_paths(self, state_root: Path) -> dict[str, Path]:
        """Return resolved per-worker paths rooted at one pipeline-run workspace root."""
        return {
            "result_root": state_root / Path(self.result_root),
            "unactionable": state_root / Path(self.unactionable),
            "review": state_root / Path(self.review),
            "domain_results": state_root / Path(self.domain_results),
            "cache": state_root / Path(self.cache),
        }


class WorkerRuntimeRootDNSQueryProfile(PrepareWorkerModel):
    """Effective shared DNS settings used by one root delegation profile."""

    default_resolvers: list[DNSResolverConfig]
    timeout: float
    retry_backoff_base_seconds: float
    query_rate_limit: DNSQueryRateLimitConfig


class WorkerRuntimeDelegationDNSProfile(PrepareWorkerModel):
    """Effective delegation-stage overrides for one root profile."""

    resolvers: list[DNSResolverConfig] | None
    timeout: float | None
    query_rate_limit: DNSQueryRateLimitConfig | None
    retry_attempts: int


class PreparedDelegationProfile(PrepareWorkerModel):
    """Source-blind effective DNS settings for one registrable-root query."""

    dns_query: WorkerRuntimeRootDNSQueryProfile
    delegation: WorkerRuntimeDelegationDNSProfile


class PreparedManualRoutingProfile(PrepareWorkerModel):
    """Source-blind manual routing flags for one input domain."""

    manually_selected_for_filtered: StrictBool
    manually_added: StrictBool

    @model_validator(mode="after")
    def _validate_mutually_exclusive_flags(self) -> "PreparedManualRoutingProfile":
        if self.manually_selected_for_filtered and self.manually_added:
            raise ValueError("input domain cannot be manually selected and added")
        return self


class WorkerRuntimeHostResolutionProfile(PrepareWorkerModel):
    """Fully effective host-resolution settings for one input domain."""

    resolvers: list[DNSResolverConfig]
    timeout: float
    retry_backoff_base_seconds: float
    query_rate_limit: DNSQueryRateLimitConfig
    retry_attempts: int
    ecs: DNSECSConfig
    resolve_www_for_registrable_domain: bool


class WorkerRuntimeIpLocationMatchList(PrepareWorkerModel):
    """IP-location include/exclude country and region values."""

    countries: list[str]
    regions: list[str]


class WorkerRuntimeLocationPolicyProfile(PrepareWorkerModel):
    """Effective IP-location policy with no credential input."""

    enabled: bool
    match_scope: Literal["all_ips", "any_ip"]
    include: WorkerRuntimeIpLocationMatchList
    exclude: WorkerRuntimeIpLocationMatchList


class WorkerRuntimeIpLocationProfile(PrepareWorkerModel):
    """Effective credential-free IP-location settings for one input domain."""

    timeout: float
    cache_ttl_days: int
    policy: WorkerRuntimeLocationPolicyProfile
    requires_region_lookup: bool
    effective_provider: Literal[
        IP_LOCATION_PROVIDER_IPINFO_LITE,
        IP_LOCATION_PROVIDER_GEOJS,
    ]


class PreparedRuntimeProfiles(PrepareWorkerModel):
    """Worker-local tables of distinct effective stage settings."""

    delegation: list[PreparedDelegationProfile]
    host_resolution: list[WorkerRuntimeHostResolutionProfile]
    ip_location: list[WorkerRuntimeIpLocationProfile]


def profile_value_key(profile: PrepareWorkerModel) -> str:
    """Compare complete normalized profile values without reordering arrays."""
    return json.dumps(
        profile.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


ProfileId = Annotated[int, Field(strict=True, ge=0)]


class PreparedInputDomainWork(PrepareWorkerModel):
    """One unique source-blind input domain and the routes it can execute."""

    manual_routing: PreparedManualRoutingProfile
    host_resolution_profile_id: ProfileId | None = None
    ip_location_profile_id: ProfileId | None = None

    @model_validator(mode="after")
    def _validate_stage_profiles(self) -> "PreparedInputDomainWork":
        if (
            "host_resolution_profile_id" in self.model_fields_set
            and self.host_resolution_profile_id is None
        ):
            raise ValueError("host_resolution_profile_id must be omitted when disabled")
        if (
            "ip_location_profile_id" in self.model_fields_set
            and self.ip_location_profile_id is None
        ):
            raise ValueError("ip_location_profile_id must be omitted when disabled")
        if self.ip_location_profile_id is not None and self.host_resolution_profile_id is None:
            raise ValueError("ip_location_profile_id requires host resolution")
        if (
            self.manual_routing.manually_selected_for_filtered
            or self.manual_routing.manually_added
        ) and (
            self.host_resolution_profile_id is not None
            or self.ip_location_profile_id is not None
        ):
            raise ValueError("manual input domains cannot carry host/IP profiles")
        return self


class PreparedDelegationRootWork(PrepareWorkerModel):
    """One atomic root assignment with its unique input-domain work."""

    delegation_profile_id: ProfileId
    input_domains: dict[str, PreparedInputDomainWork]

    @model_validator(mode="after")
    def _validate_input_domains(self) -> "PreparedDelegationRootWork":
        if not self.input_domains:
            raise ValueError("delegation root must assign at least one input domain")
        return self


class PreparedRuntimeMetadata(PrepareWorkerModel):
    """Canonical source-blind root-to-input-domain worker work manifest."""

    profiles: PreparedRuntimeProfiles
    delegation_roots: dict[str, PreparedDelegationRootWork]

    @model_validator(mode="after")
    def _validate_assignment(self) -> "PreparedRuntimeMetadata":
        parser = DomainListParser()
        tables = {
            "delegation": self.profiles.delegation,
            "host_resolution": self.profiles.host_resolution,
            "ip_location": self.profiles.ip_location,
        }
        used: dict[str, set[int]] = {stage: set() for stage in tables}

        def record_profile(stage: str, index: int, owner: str) -> None:
            if index >= len(tables[stage]):
                raise ValueError(f"{owner!r}: {stage}_profile_id {index} is out of range")
            used[stage].add(index)

        for root_key, root_work in self.delegation_roots.items():
            parsed_root = parser.parse_source_item(
                root_key, file_format=InputFileFormat.PLAIN
            )
            if (
                parsed_root is None
                or parsed_root.error_reason is not None
                or len(parsed_root.targets) != 1
                or parsed_root.targets[0].error_reason is not None
                or parsed_root.targets[0].host != root_key
                or parsed_root.targets[0].registrable_domain != root_key
            ):
                raise ValueError(
                    f"delegation_roots key is not a registrable domain: {root_key!r}"
                )
            record_profile("delegation", root_work.delegation_profile_id, root_key)
            for input_domain, work in root_work.input_domains.items():
                parsed_input = parser.parse_source_item(
                    input_domain, file_format=InputFileFormat.PLAIN
                )
                if (
                    parsed_input is None
                    or parsed_input.error_reason is not None
                    or len(parsed_input.targets) != 1
                    or parsed_input.targets[0].error_reason is not None
                    or parsed_input.targets[0].host != input_domain
                    or parsed_input.targets[0].registrable_domain != root_key
                ):
                    raise ValueError(
                        "input domain does not match its registrable root: "
                        f"{input_domain!r} under {root_key!r}"
                    )
                if work.host_resolution_profile_id is not None:
                    record_profile("host_resolution", work.host_resolution_profile_id, input_domain)
                if work.ip_location_profile_id is not None:
                    record_profile("ip_location", work.ip_location_profile_id, input_domain)
        for stage, table in tables.items():
            if len({profile_value_key(profile) for profile in table}) != len(table):
                raise ValueError(f"duplicate profile in {stage} table")
            if len(used[stage]) != len(table):
                unused = sorted(set(range(len(table))) - used[stage])
                raise ValueError(f"unused profile IDs in {stage} table: {unused}")
        return self

    def to_manifest_payload(self) -> dict[str, Any]:
        """Serialize the assignment, omitting only disabled stage references."""
        payload = self.model_dump(mode="json")
        for root in payload["delegation_roots"].values():
            for domain in root["input_domains"].values():
                if domain["host_resolution_profile_id"] is None:
                    domain.pop("host_resolution_profile_id")
                if domain["ip_location_profile_id"] is None:
                    domain.pop("ip_location_profile_id")
        return payload


class WorkerRuntimeDelegationTTLSpec(PrepareWorkerModel):
    """Delegation cache TTLs persisted in worker manifests."""

    actionable: int = 7
    unactionable: int = 1


class WorkerRuntimeHostResolutionTTLSpec(PrepareWorkerModel):
    """Host-resolution cache TTLs persisted in worker manifests."""

    resolved: int | None = None
    nodata: int = 1
    nxdomain: int = 1


class WorkerRuntimeCacheSpec(PrepareWorkerModel):
    """Canonical runtime cache settings persisted in one worker manifest."""

    cache_file: str
    baseline_cache_file: str = ""
    delegation_ttl_days: WorkerRuntimeDelegationTTLSpec = Field(
        default_factory=WorkerRuntimeDelegationTTLSpec
    )
    host_resolution_ttl_days: WorkerRuntimeHostResolutionTTLSpec = Field(
        default_factory=WorkerRuntimeHostResolutionTTLSpec
    )

    @model_validator(mode="after")
    def _validate_cache_paths(self) -> "WorkerRuntimeCacheSpec":
        if not self.cache_file.strip():
            raise ValueError("runtime cache_file is required")
        return self


class WorkerRuntimeStageConcurrencyMinimumsSpec(PrepareWorkerModel):
    """Worker-local async stage concurrency minimums in worker manifests."""

    delegation: int
    host_resolution: int
    ip_location: int


class WorkerRuntimeStageConcurrencyAdaptiveSpec(RuntimeStageConcurrencyAdaptiveConfig):
    """Adaptive worker-local stage concurrency settings in worker manifests."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class WorkerRuntimeStageConcurrencySpec(PrepareWorkerModel):
    """Worker-local stage concurrency settings in worker manifests."""

    minimums: WorkerRuntimeStageConcurrencyMinimumsSpec
    adaptive: WorkerRuntimeStageConcurrencyAdaptiveSpec = Field(
        default_factory=WorkerRuntimeStageConcurrencyAdaptiveSpec
    )


class WorkerRuntimeSettingsSpec(PrepareWorkerModel):
    """Canonical runtime settings persisted in worker manifests."""

    stage_concurrency: WorkerRuntimeStageConcurrencySpec


class WorkerRuntimeSpec(PrepareWorkerModel):
    """Prepare-owned runtime config for one worker execution."""

    config_name: str
    cache: WorkerRuntimeCacheSpec
    runtime: WorkerRuntimeSettingsSpec
    output_spec: WorkerOutputSpec
    debug_log_path: str

    def to_runtime_payload(
        self,
        *,
        source_root: Path,
        state_root: Path,
    ) -> dict[str, Any]:
        """Return the runtime config payload with paths resolved for execution."""
        payload = {
            "config_name": self.config_name,
            "cache": self.cache.model_dump(mode="json"),
            "runtime": self.runtime.model_dump(mode="json"),
            "output_spec": {
                key: str(path.resolve())
                for key, path in self.output_spec.resolve_paths(state_root).items()
            },
            "debug_log_path": str(
                (state_root / Path(self.debug_log_path)).resolve()
            ),
        }
        cache_payload = payload["cache"]
        cache_file = str(cache_payload.get("cache_file", "")).strip()
        baseline_cache_file = str(cache_payload.get("baseline_cache_file", "")).strip()
        if cache_file:
            cache_payload["cache_file"] = str((state_root / Path(cache_file)).resolve())
        if baseline_cache_file:
            cache_payload["baseline_cache_file"] = str(
                (source_root / Path(baseline_cache_file)).resolve()
            )
        return payload


class PrepareWorkerManifest(PrepareWorkerModel):
    """Persisted prepare-to-worker runtime manifest."""

    batch_id: str
    worker_id: str
    runtime_spec: WorkerRuntimeSpec
    prepared_metadata: PreparedRuntimeMetadata

    def resolve_paths(self, state_root: Path) -> dict[str, Path]:
        """Return resolved worker output paths for this manifest."""
        return self.runtime_spec.output_spec.resolve_paths(state_root)

    def resolve_log_path(self, state_root: Path) -> Path:
        """Return the resolved worker debug log path persisted in this manifest."""
        return state_root / Path(self.runtime_spec.debug_log_path)


def write_prepare_worker_handoff(
    manifest: PrepareWorkerManifest, *, state_root: Path
) -> list[Path]:
    """Write one source-blind worker-work manifest and its identity record."""
    paths = PathLayout(state_root).workflow_state
    config_path = paths.prepare_worker_config_path(
        batch_id=manifest.batch_id, worker_id=manifest.worker_id
    )
    runtime = manifest.runtime_spec.model_dump(mode="json")
    runtime.pop("config_name")
    runtime.pop("output_spec")
    runtime.pop("debug_log_path")
    runtime["cache"].pop("cache_file")
    runtime["cache"].pop("baseline_cache_file")
    write_compact_json(
        config_path,
        {
            "batch_id": manifest.batch_id,
            "worker_id": manifest.worker_id,
            "config_name": manifest.runtime_spec.config_name,
            "runtime_spec": runtime,
            "prepared_metadata": manifest.prepared_metadata.to_manifest_payload(),
        },
    )
    identity_path = paths.prepare_worker_identity_path(
        batch_id=manifest.batch_id, worker_id=manifest.worker_id
    )
    write_json(
        identity_path,
        {
            "batch_id": manifest.batch_id,
            "worker_id": manifest.worker_id,
        },
    )
    return [config_path, identity_path]


def load_prepare_worker_manifest_for_worker(
    *,
    batch_id: str,
    worker_id: str,
    state_root: Path,
) -> PrepareWorkerManifest:
    """Load the designated worker's source-blind JSON work manifest."""
    layout = PathLayout(state_root)
    paths = layout.workflow_state
    config_path = paths.prepare_worker_config_path(
        batch_id=batch_id, worker_id=worker_id
    )
    if not config_path.is_file():
        raise FileNotFoundError(
            f"prepare worker configuration is missing: {config_path}"
        )
    payload = read_strict_json(config_path)
    if not isinstance(payload, dict) or set(payload) != {
        "batch_id",
        "worker_id",
        "config_name",
        "runtime_spec",
        "prepared_metadata",
    }:
        raise ValueError(f"invalid prepare worker configuration {config_path}")
    if payload["batch_id"] != batch_id or payload["worker_id"] != worker_id:
        raise ValueError("prepare worker configuration identity mismatch")
    identity = read_strict_json(
        paths.prepare_worker_identity_path(batch_id=batch_id, worker_id=worker_id)
    )
    if (
        not isinstance(identity, dict)
        or identity
        != {
            "batch_id": batch_id,
            "worker_id": worker_id,
        }
    ):
        raise ValueError("prepare worker identity record mismatch")
    config_name = payload["config_name"]
    if not isinstance(config_name, str) or not CONFIG_NAMESPACE_PATTERN.fullmatch(
        config_name
    ):
        raise ValueError("prepare worker config_name is required")
    runtime = _worker_runtime_with_paths(
        payload["runtime_spec"],
        batch_id=batch_id,
        worker_id=worker_id,
        config_name=config_name,
    )
    try:
        manifest = PrepareWorkerManifest.model_validate(
            {
                "batch_id": batch_id,
                "worker_id": worker_id,
                "runtime_spec": runtime,
                "prepared_metadata": payload["prepared_metadata"],
            }
        )
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(part) for part in error.get('loc', ())) or 'manifest'}: "
            f"{error.get('msg', 'validation failed')}"
            for error in exc.errors()
        )
        raise ValueError(
            f"invalid prepare worker configuration {config_path}: {details}"
        ) from exc
    _require_effective_fields(manifest.runtime_spec, "runtime_spec")
    _require_effective_fields(
        manifest.prepared_metadata.profiles, "prepared_metadata.profiles"
    )
    return manifest


def _require_effective_fields(value: object, path: str) -> None:
    """Reject omitted effective fields even when the model provides defaults."""
    if isinstance(value, BaseModel):
        for name in type(value).model_fields:
            field_path = f"{path}.{name}"
            if name not in value.model_fields_set:
                raise ValueError(f"{field_path}: field is required")
            _require_effective_fields(getattr(value, name), field_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _require_effective_fields(item, f"{path}.{index}")


def _worker_runtime_with_paths(
    runtime: Any, *, batch_id: str, worker_id: str, config_name: str
) -> dict[str, Any]:
    """Validate worker configuration and restore its derived paths."""
    if not isinstance(runtime, dict) or set(runtime) != {"cache", "runtime"}:
        raise ValueError("invalid prepare worker runtime fields")
    cache = runtime.get("cache")
    if not isinstance(cache, dict) or set(cache) != {
        "delegation_ttl_days",
        "host_resolution_ttl_days",
    }:
        raise ValueError("invalid prepare worker cache fields")
    runtime["config_name"] = config_name
    # Derive paths from the validated identities, rather than trusting handoff paths.
    relative = PathLayout(Path("."))
    wp = relative.worker_paths(
        batch_id=batch_id, worker_id=worker_id, config_name=config_name
    )
    try:
        runtime["cache"]["cache_file"] = wp.cache.as_posix()
        runtime["cache"]["baseline_cache_file"] = (
            relative.workflow_state.runtime_cache_path().as_posix()
        )
        runtime["output_spec"] = {
            name: getattr(wp, name).as_posix()
            for name in (
                "result_root",
                "unactionable",
                "review",
                "domain_results",
                "cache",
            )
        }
        runtime["debug_log_path"] = wp.debug_log.as_posix()
    except (KeyError, TypeError) as exc:
        raise ValueError("invalid prepare worker runtime configuration") from exc
    return runtime
