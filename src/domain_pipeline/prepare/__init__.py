"""Prepare-step owners for workflow batch input planning."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from domain_pipeline.prepare.assignment import (
        PreparedBatchPlanningInputs,
        PreparedWorkerManifest,
        WorkerAssignmentPlanner,
    )
    from domain_pipeline.prepare.batch_writer import (
        PreparedBatch,
        PreparedBatchWriter,
        prepare_batch,
        write_prepared_batch,
    )
    from domain_pipeline.prepare.models import (
        MANUAL_ADD_SOURCE_ID,
        PreparedHostEntry,
        PreparedInputSet,
        PreparedRootPlan,
    )
    from domain_pipeline.prepare.planner import PreparationPlanner

_EXPORT_MODULES = {
    "MANUAL_ADD_SOURCE_ID": "domain_pipeline.prepare.models",
    "PreparedBatch": "domain_pipeline.prepare.batch_writer",
    "PreparedBatchPlanningInputs": "domain_pipeline.prepare.assignment",
    "PreparedBatchWriter": "domain_pipeline.prepare.batch_writer",
    "PreparedWorkerManifest": "domain_pipeline.prepare.assignment",
    "PreparationPlanner": "domain_pipeline.prepare.planner",
    "PreparedHostEntry": "domain_pipeline.prepare.models",
    "PreparedInputSet": "domain_pipeline.prepare.models",
    "PreparedRootPlan": "domain_pipeline.prepare.models",
    "WorkerAssignmentPlanner": "domain_pipeline.prepare.assignment",
    "prepare_batch": "domain_pipeline.prepare.batch_writer",
    "write_prepared_batch": "domain_pipeline.prepare.batch_writer",
}

__all__ = [
    "MANUAL_ADD_SOURCE_ID",
    "PreparedBatch",
    "PreparedBatchPlanningInputs",
    "PreparedBatchWriter",
    "PreparedWorkerManifest",
    "PreparationPlanner",
    "PreparedHostEntry",
    "PreparedInputSet",
    "PreparedRootPlan",
    "WorkerAssignmentPlanner",
    "prepare_batch",
    "write_prepared_batch",
]


def __getattr__(name: str) -> Any:
    """Load curated prepare-package exports only when callers request them."""
    module_name = _EXPORT_MODULES.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value
