"""Prepare-owned manifests consumed by worker jobs."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from domain_pipeline.config_namespace import CONFIG_NAMESPACE_PATTERN
from domain_pipeline.handoff_io import (
    read_csv,
    read_json,
    read_yaml,
    write_csv,
    write_json,
    write_yaml,
)
from domain_pipeline.paths.layout import PathLayout
from domain_pipeline.pipeline_run.format_version import (
    PIPELINE_RUN_FORMAT_VERSION,
    has_current_pipeline_run_format,
)
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
    terminal_rows: str
    cache: str

    def resolve_paths(self, state_root: Path) -> dict[str, Path]:
        """Return resolved per-worker paths rooted at one pipeline-run workspace root."""
        return {
            "result_root": state_root / Path(self.result_root),
            "unactionable": state_root / Path(self.unactionable),
            "review": state_root / Path(self.review),
            "terminal_rows": state_root / Path(self.terminal_rows),
            "cache": state_root / Path(self.cache),
        }


class PreparedDelegationRootMetadata(PrepareWorkerModel):
    """Worker-local settings selected for one registrable-domain check."""

    delegation_config_source_id: str
    delegation_behavior_fingerprint: str

    @model_validator(mode="after")
    def _validate_root_metadata(self) -> "PreparedDelegationRootMetadata":
        if not self.delegation_config_source_id:
            raise ValueError("delegation root delegation_config_source_id is required")
        if not self.delegation_behavior_fingerprint:
            raise ValueError(
                "delegation root delegation_behavior_fingerprint is required"
            )
        return self


class PreparedRuntimeMetadata(PrepareWorkerModel):
    """Root-owned prepared metadata consumed by the worker runtime fast path."""

    delegation_roots: dict[str, PreparedDelegationRootMetadata]

    @model_validator(mode="after")
    def _validate_delegation_root_keys(self) -> "PreparedRuntimeMetadata":
        for root_key in self.delegation_roots:
            if not root_key:
                raise ValueError(
                    "delegation_roots key must be a non-empty registrable domain"
                )
        return self

    def to_runtime_payload(self) -> dict[str, Any]:
        """Return a mutable runtime payload preserving the current metadata shape."""
        return copy.deepcopy(self.model_dump())


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


class WorkerRuntimeInputConfig(PrepareWorkerModel):
    """Source input config persisted in worker manifests."""

    type: Literal["file", "url"]
    location: str
    format: str = "auto"
    label: str = ""


class WorkerRuntimeFetchConfig(PrepareWorkerModel):
    """Source fetch config persisted in worker manifests."""

    request_timeout: float = 30.0


class WorkerRuntimeIpLocationMatchList(PrepareWorkerModel):
    """IP-location include/exclude country and region values in worker manifests."""

    countries: list[str] = Field(default_factory=list)
    regions: list[str] = Field(default_factory=list)


class WorkerRuntimeLocationPolicyConfig(PrepareWorkerModel):
    """IP-location policy config persisted in worker manifests."""

    enabled: bool = False
    match_scope: Literal["all_ips", "any_ip"] = "all_ips"
    include: WorkerRuntimeIpLocationMatchList = Field(
        default_factory=WorkerRuntimeIpLocationMatchList
    )
    exclude: WorkerRuntimeIpLocationMatchList = Field(
        default_factory=WorkerRuntimeIpLocationMatchList
    )


class WorkerRuntimeIPLocationConfig(PrepareWorkerModel):
    """Effective IP-location settings persisted after config normalization."""

    enabled: bool = False
    timeout: float = 5.0
    cache_ttl_days: int = 7
    token: str = ""
    policy: WorkerRuntimeLocationPolicyConfig = Field(
        default_factory=WorkerRuntimeLocationPolicyConfig
    )
    requires_region_lookup: bool = False
    effective_provider: str = IP_LOCATION_PROVIDER_IPINFO_LITE

    @model_validator(mode="after")
    def _validate_effective_provider(self) -> "WorkerRuntimeIPLocationConfig":
        if self.effective_provider not in {
            IP_LOCATION_PROVIDER_IPINFO_LITE,
            IP_LOCATION_PROVIDER_GEOJS,
        }:
            raise ValueError("effective_provider must be ipinfo_lite or geojs")
        return self


class WorkerRuntimeOutputConfig(PrepareWorkerModel):
    """Source output config persisted in worker manifests."""

    directory: str = "output"


class WorkerRuntimeSourceConfig(PrepareWorkerModel):
    """Effective source settings persisted in one prepare-to-worker manifest."""

    id: str
    enabled: bool = True
    input: WorkerRuntimeInputConfig
    fetch: WorkerRuntimeFetchConfig = Field(default_factory=WorkerRuntimeFetchConfig)
    dns_query: dict[str, Any] = Field(default_factory=dict)
    delegation: dict[str, Any] = Field(default_factory=dict)
    host_resolution: dict[str, Any] = Field(default_factory=dict)
    ip_location: WorkerRuntimeIPLocationConfig = Field(
        default_factory=WorkerRuntimeIPLocationConfig
    )
    output: WorkerRuntimeOutputConfig = Field(default_factory=WorkerRuntimeOutputConfig)


class WorkerRuntimeSpec(PrepareWorkerModel):
    """Prepare-owned runtime config for one worker execution."""

    config_name: str
    cache: WorkerRuntimeCacheSpec
    runtime: WorkerRuntimeSettingsSpec
    sources: list[WorkerRuntimeSourceConfig]
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
            "version": 2,
            "config_name": self.config_name,
            "cache": self.cache.model_dump(mode="json"),
            "runtime": self.runtime.model_dump(mode="json"),
            "sources": [source.model_dump(mode="json") for source in self.sources],
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
        for source in payload["sources"]:
            output_payload = source.get("output", {})
            directory = str(output_payload.get("directory", "")).strip()
            if directory:
                output_payload["directory"] = str(
                    (state_root / Path(directory)).resolve()
                )
            output_payload["terminal_rows_file"] = str(
                (state_root / Path(self.output_spec.terminal_rows)).resolve()
            )
        return payload


class PrepareWorkerManifest(PrepareWorkerModel):
    """Persisted prepare-to-worker runtime manifest."""

    automation_format_version: int
    batch_id: str
    worker_id: str
    runtime_spec: WorkerRuntimeSpec
    prepared_metadata: PreparedRuntimeMetadata

    @field_validator("automation_format_version", mode="before")
    @classmethod
    def _validate_format_version(cls, value: Any) -> int:
        if not has_current_pipeline_run_format(value):
            raise ValueError("unsupported prepare worker handoff format version")
        return value

    def resolve_paths(self, state_root: Path) -> dict[str, Path]:
        """Return resolved worker output paths for this manifest."""
        return self.runtime_spec.output_spec.resolve_paths(state_root)

    def resolve_log_path(self, state_root: Path) -> Path:
        """Return the resolved worker debug log path persisted in this manifest."""
        return state_root / Path(self.runtime_spec.debug_log_path)


def write_prepare_worker_handoff(
    manifest: PrepareWorkerManifest, *, state_root: Path
) -> list[Path]:
    """Write runtime configuration and assigned root metadata separately."""
    paths = PathLayout(state_root).workflow_state
    config_path = paths.prepare_worker_config_path(
        batch_id=manifest.batch_id, worker_id=manifest.worker_id
    )
    roots_path = paths.prepare_worker_roots_path(
        batch_id=manifest.batch_id, worker_id=manifest.worker_id
    )
    runtime = manifest.runtime_spec.model_dump(mode="json")
    runtime.pop("config_name")
    runtime.pop("output_spec")
    runtime.pop("debug_log_path")
    runtime["cache"].pop("cache_file")
    runtime["cache"].pop("baseline_cache_file")
    for source in runtime["sources"]:
        source.pop("output")
    write_yaml(
        config_path,
        {
            "automation_format_version": manifest.automation_format_version,
            "batch_id": manifest.batch_id,
            "worker_id": manifest.worker_id,
            "config_name": manifest.runtime_spec.config_name,
            "runtime_spec": runtime,
        },
    )
    write_csv(
        roots_path,
        (
            "registrable_domain",
            "delegation_config_source_id",
            "delegation_behavior_fingerprint",
        ),
        [
            {"registrable_domain": domain, **metadata.model_dump()}
            for domain, metadata in sorted(
                manifest.prepared_metadata.delegation_roots.items()
            )
        ],
    )
    identity_path = paths.prepare_worker_identity_path(
        batch_id=manifest.batch_id, worker_id=manifest.worker_id
    )
    write_json(
        identity_path,
        {
            "automation_format_version": manifest.automation_format_version,
            "batch_id": manifest.batch_id,
            "worker_id": manifest.worker_id,
        },
    )
    return [config_path, roots_path, identity_path]


def load_prepare_worker_manifest_for_worker(
    *,
    batch_id: str,
    worker_id: str,
    state_root: Path,
) -> PrepareWorkerManifest:
    """Load the designated worker's YAML configuration and assigned roots."""
    layout = PathLayout(state_root)
    paths = layout.workflow_state
    config_path = paths.prepare_worker_config_path(
        batch_id=batch_id, worker_id=worker_id
    )
    if not config_path.is_file():
        raise FileNotFoundError(
            f"prepare worker configuration is missing: {config_path}"
        )
    payload = read_yaml(config_path)
    if not isinstance(payload, dict) or set(payload) != {
        "automation_format_version",
        "batch_id",
        "worker_id",
        "config_name",
        "runtime_spec",
    }:
        raise ValueError(f"invalid prepare worker configuration {config_path}")
    if not has_current_pipeline_run_format(payload["automation_format_version"]):
        raise ValueError("unsupported prepare worker handoff format version")
    if payload["batch_id"] != batch_id or payload["worker_id"] != worker_id:
        raise ValueError("prepare worker configuration identity mismatch")
    identity = read_json(
        paths.prepare_worker_identity_path(batch_id=batch_id, worker_id=worker_id)
    )
    if (
        not isinstance(identity, dict)
        or not has_current_pipeline_run_format(
            identity.get("automation_format_version")
        )
        or identity
        != {
            "automation_format_version": PIPELINE_RUN_FORMAT_VERSION,
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
    roots = _load_assigned_roots(
        paths.prepare_worker_roots_path(batch_id=batch_id, worker_id=worker_id)
    )
    try:
        return PrepareWorkerManifest.model_validate(
            {
                "automation_format_version": payload["automation_format_version"],
                "batch_id": batch_id,
                "worker_id": worker_id,
                "runtime_spec": runtime,
                "prepared_metadata": {"delegation_roots": roots},
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


def _worker_runtime_with_paths(
    runtime: Any, *, batch_id: str, worker_id: str, config_name: str
) -> dict[str, Any]:
    """Validate worker configuration and restore its derived paths."""
    if not isinstance(runtime, dict) or set(runtime) != {"cache", "runtime", "sources"}:
        raise ValueError("invalid prepare worker runtime fields")
    cache = runtime.get("cache")
    sources = runtime.get("sources")
    if not isinstance(cache, dict) or set(cache) != {
        "delegation_ttl_days",
        "host_resolution_ttl_days",
    }:
        raise ValueError("invalid prepare worker cache fields")
    if not isinstance(sources, list) or any(
        not isinstance(source, dict) or "output" in source for source in sources
    ):
        raise ValueError("invalid prepare worker source fields")
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
        for source in runtime["sources"]:
            source["output"] = {"directory": wp.output_directory.as_posix()}
        runtime["output_spec"] = {
            name: getattr(wp, name).as_posix()
            for name in (
                "result_root",
                "unactionable",
                "review",
                "terminal_rows",
                "cache",
            )
        }
        runtime["debug_log_path"] = wp.debug_log.as_posix()
    except (KeyError, TypeError) as exc:
        raise ValueError("invalid prepare worker runtime configuration") from exc
    return runtime


def _load_assigned_roots(path: Path) -> dict[str, dict[str, str]]:
    """Read and validate the assigned root table."""
    roots: dict[str, dict[str, str]] = {}
    parser = DomainListParser()
    for row in read_csv(
        path,
        (
            "registrable_domain",
            "delegation_config_source_id",
            "delegation_behavior_fingerprint",
        ),
    ):
        domain = row.pop("registrable_domain")
        if not domain or domain in roots:
            raise ValueError("invalid or duplicate assigned root")
        parsed = parser.parse_source_item(domain, file_format=InputFileFormat.PLAIN)
        if (
            parsed is None
            or parsed.error_reason is not None
            or len(parsed.targets) != 1
            or parsed.targets[0].error_reason is not None
            or parsed.targets[0].host != domain
            or parsed.targets[0].registrable_domain != domain
        ):
            raise ValueError(f"assigned root is not a valid registrable domain: {domain!r}")
        roots[domain] = row
    return roots
