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
        MANUALLY_ADDED_SOURCE_ID,
        MANUALLY_SELECTED_FOR_FILTERED_SOURCE_ID,
        PreparedInputSet,
        PreparedManualRouting,
        PreparedRootPlan,
    )
    from domain_pipeline.prepare.planner import PreparationPlanner

_EXPORT_MODULES = {
    "MANUALLY_ADDED_SOURCE_ID": "domain_pipeline.prepare.models",
    "MANUALLY_SELECTED_FOR_FILTERED_SOURCE_ID": "domain_pipeline.prepare.models",
    "PreparedBatch": "domain_pipeline.prepare.batch_writer",
    "PreparedBatchPlanningInputs": "domain_pipeline.prepare.assignment",
    "PreparedBatchWriter": "domain_pipeline.prepare.batch_writer",
    "PreparedWorkerManifest": "domain_pipeline.prepare.assignment",
    "PreparationPlanner": "domain_pipeline.prepare.planner",
    "PreparedInputSet": "domain_pipeline.prepare.models",
    "PreparedManualRouting": "domain_pipeline.prepare.models",
    "PreparedRootPlan": "domain_pipeline.prepare.models",
    "WorkerAssignmentPlanner": "domain_pipeline.prepare.assignment",
    "prepare_batch": "domain_pipeline.prepare.batch_writer",
    "write_prepared_batch": "domain_pipeline.prepare.batch_writer",
}

__all__ = [
    "MANUALLY_ADDED_SOURCE_ID",
    "MANUALLY_SELECTED_FOR_FILTERED_SOURCE_ID",
    "PreparedBatch",
    "PreparedBatchPlanningInputs",
    "PreparedBatchWriter",
    "PreparedWorkerManifest",
    "PreparationPlanner",
    "PreparedInputSet",
    "PreparedManualRouting",
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
