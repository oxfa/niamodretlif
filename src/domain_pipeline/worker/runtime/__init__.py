"""Worker runtime public API with deferred imports to avoid prepare cycles."""

from __future__ import annotations

from importlib import import_module
from typing import Any

_EXPORTS = {
    "CompletedInputDomainResult": "contracts",
    "DelegationRootWorkItem": "contracts",
    "HostResolutionWorkItem": "contracts",
    "IpLocationWorkItem": "contracts",
    "ParsedInputDomain": "contracts",
    "RegistrableDomainResult": "contracts",
    "RuntimeManualRouting": "contracts",
    "RuntimeDNSCheckerFactory": "dns_factory",
    "PipelineExecutor": "executor",
    "run_prepared_pipeline_async": "executor",
    "RuntimeItemLoader": "loading",
    "RuntimeQueueSet": "queues",
    "WorkerBatchRunner": "runner",
    "run_prepared_pipeline": "runner",
    "run_worker": "runner",
    "DelegationStage": "stages",
    "HostResolutionStage": "stages",
    "IpLocationStage": "stages",
}

__all__ = list(_EXPORTS)


def __getattr__(name: str) -> Any:
    """Import a public runtime object only when the package API needs it."""
    module_name = _EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = import_module(f"{__name__}.{module_name}")
    value = getattr(module, name)
    globals()[name] = value
    return value
