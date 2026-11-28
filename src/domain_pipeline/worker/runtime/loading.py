"""Load source-blind root and input-domain assignments for worker runtime."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from domain_pipeline.prepare.sources.parser import DomainEntry
from domain_pipeline.worker.runtime.contracts import (
    DelegationRootWorkItem,
    ParsedInputDomain,
    RuntimeItemPosition,
    RuntimeManualRouting,
)

if TYPE_CHECKING:
    from domain_pipeline.prepare.prepare_to_worker_manifest import (
        PreparedRuntimeMetadata,
    )


def _freeze_profile_settings(value: Any) -> Any:
    """Freeze the nested objects and arrays of a materialized profile."""
    if isinstance(value, dict):
        return MappingProxyType(
            {key: _freeze_profile_settings(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_freeze_profile_settings(item) for item in value)
    return value


class RuntimeItemLoader:
    """Resolve validated assignments to runtime items with shared profile settings."""

    def __init__(self, *, prepared_metadata: PreparedRuntimeMetadata) -> None:
        profiles = prepared_metadata.profiles
        # Work items share one immutable runtime value per validated profile.
        delegation_profiles = [
            _freeze_profile_settings(profile.model_dump(mode="json"))
            for profile in profiles.delegation
        ]
        host_profiles = [
            _freeze_profile_settings(profile.model_dump(mode="json"))
            for profile in profiles.host_resolution
        ]
        ip_profiles = [
            _freeze_profile_settings(profile.model_dump(mode="json"))
            for profile in profiles.ip_location
        ]
        roots = prepared_metadata.delegation_roots
        total_domains = sum(len(root.input_domains) for root in roots.values())
        sequence = 0
        self._work_items: list[DelegationRootWorkItem] = []
        for registrable_domain, root in sorted(roots.items()):
            items: list[ParsedInputDomain] = []
            for input_domain, domain in sorted(root.input_domains.items()):
                host_profile_id = domain.host_resolution_profile_id
                ip_profile_id = domain.ip_location_profile_id
                manual_routing = domain.manual_routing
                items.append(
                    ParsedInputDomain(
                        entry=DomainEntry(
                            host=input_domain, registrable_domain=registrable_domain
                        ),
                        position=RuntimeItemPosition(
                            sequence=sequence, total=total_domains
                        ),
                        manual_routing=RuntimeManualRouting(
                            manually_selected_for_filtered=(
                                manual_routing.manually_selected_for_filtered
                            ),
                            manually_added=manual_routing.manually_added,
                        ),
                        host_resolution_profile=(
                            host_profiles[host_profile_id]
                            if host_profile_id is not None
                            else None
                        ),
                        ip_location_profile=(
                            ip_profiles[ip_profile_id]
                            if ip_profile_id is not None
                            else None
                        ),
                    )
                )
                sequence += 1

            self._work_items.append(
                DelegationRootWorkItem(
                    registrable_domain=registrable_domain,
                    delegation_profile=delegation_profiles[root.delegation_profile_id],
                    items=tuple(items),
                )
            )

    def delegation_work_items(self) -> list[DelegationRootWorkItem]:
        """Return one work item for every assigned root and its input domains."""
        return list(self._work_items)

    def expected_input_domains_by_root(self) -> dict[str, set[str]]:
        """Return the exact root-to-domain assignment expected from this worker."""
        return {
            work_item.registrable_domain: {item.entry.host for item in work_item.items}
            for work_item in self._work_items
        }

    def all_input_domains(self) -> list[ParsedInputDomain]:
        """Return every input-domain item in deterministic worker order."""
        return [item for work_item in self._work_items for item in work_item.items]
