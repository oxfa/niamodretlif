"""Worker runtime item loading from prepared metadata."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from domain_pipeline.prepare.delegation import delegation_behavior_fingerprint
from domain_pipeline.prepare.models import PreparedProvenance
from domain_pipeline.prepare.sources.parser import (
    ParsedDomainEntry,
    ParsedInputSemantics,
)
from domain_pipeline.worker.runtime.contracts import (
    DelegationRootWorkItem,
    ParsedHostItem,
    RuntimeProvenance,
    WorkerSourceContext,
)


def _entry_from_payload(
    *,
    registrable_domain: str,
    public_suffix: str,
    payload: dict[str, Any],
) -> ParsedDomainEntry:
    return ParsedDomainEntry(
        host=str(payload["host"]),
        registrable_domain=registrable_domain,
        semantics=ParsedInputSemantics(
            input_name=str(payload["input_name"]),
            public_suffix=public_suffix,
            is_public_suffix_input=False,
            input_kind=str(payload["input_kind"]),
            apex_scope=str(payload["apex_scope"]),
            source_format=str(payload["source_format"]),
        ),
    )


def _source_context_from_config(
    source: dict[str, Any], *, config_name: str
) -> WorkerSourceContext:
    return WorkerSourceContext(
        source_id=str(source["id"]),
        input_label=str(
            source.get("input", {}).get("label") or source["input"]["location"]
        ),
        output_stem=config_name,
        config=source,
    )


class RuntimeItemLoader:
    """Build worker-local host items and root-level delegation work."""

    def __init__(
        self,
        *,
        config: dict[str, Any],
        prepared_metadata: dict[str, Any] | None = None,
    ) -> None:
        self.config = config
        self.prepared_metadata = prepared_metadata

    def _prepared_payload(self) -> dict[str, Any]:
        """Return the required prepared worker metadata payload."""
        if self.prepared_metadata is None:
            raise ValueError("prepared metadata is required for worker runtime")
        return self.prepared_metadata

    def source_contexts(self) -> list[WorkerSourceContext]:
        """Return worker-local source contexts for prepared workflow mode."""
        return [
            _source_context_from_config(
                source, config_name=str(self.config["config_name"])
            )
            for source in self.config["sources"]
            if source.get("enabled", True)
        ]

    def _prepared_roots(self) -> dict[str, Any]:
        """Return root-owned prepared metadata for worker runtime mode."""
        roots = self._prepared_payload().get("delegation_roots")
        if not isinstance(roots, dict) or not roots:
            raise ValueError("prepared metadata delegation_roots must not be empty")
        return roots

    def _prepared_item_payloads(
        self,
    ) -> list[tuple[WorkerSourceContext, ParsedDomainEntry, dict[str, Any]]]:
        """Flatten root-owned prepared host entries into worker-local item payloads."""
        source_contexts = {
            source_context.source_id: source_context
            for source_context in self.source_contexts()
        }
        item_payloads: list[
            tuple[WorkerSourceContext, ParsedDomainEntry, dict[str, Any]]
        ] = []
        for registrable_domain, root_payload in self._prepared_roots().items():
            if not isinstance(root_payload, dict):
                raise ValueError(
                    "prepared metadata delegation root "
                    f"{registrable_domain!r} must be an object"
                )
            public_suffix = str(root_payload["public_suffix"])
            entries = root_payload.get("host_entries")
            if not isinstance(entries, list) or not entries:
                raise ValueError(
                    "prepared metadata delegation root "
                    f"{registrable_domain!r} host_entries must not be empty"
                )
            for item in entries:
                if not isinstance(item, dict):
                    raise ValueError(
                        "prepared metadata delegation root "
                        f"{registrable_domain!r} host entry must be an object"
                    )
                source_id = str(item["source_id"])
                source_context = source_contexts.get(source_id)
                if source_context is None:
                    raise ValueError(
                        "prepared host entry "
                        f"{item.get('host', '')!r} references unknown source "
                        f"{source_id!r}"
                    )
                entry = _entry_from_payload(
                    registrable_domain=str(registrable_domain),
                    public_suffix=public_suffix,
                    payload=item,
                )
                item_payloads.append((source_context, entry, item))
        return item_payloads

    def runtime_items(self) -> list[ParsedHostItem]:
        """Build worker-local items that seed the delegation input queue."""
        item_payloads = self._prepared_item_payloads()
        total = len(item_payloads)
        return [
            ParsedHostItem(
                source_context=source_context,
                entry=entry,
                provenance=RuntimeProvenance(
                    sequence=index,
                    total=total,
                    source=PreparedProvenance(
                        manually_selected_for_filtered=bool(
                            provenance["manually_selected_for_filtered"]
                        ),
                        manually_added=bool(provenance["manually_added"]),
                        source_id_override=provenance["source_id_override"],
                        source_input_label_override=provenance[
                            "source_input_label_override"
                        ],
                        source_ids=tuple(provenance["source_ids"]),
                        source_input_labels=tuple(provenance["source_input_labels"]),
                    ),
                ),
            )
            for index, (source_context, entry, provenance) in enumerate(item_payloads)
        ]

    def delegation_work_items(
        self,
    ) -> tuple[list[DelegationRootWorkItem], list[ParsedHostItem]]:
        """Return root-level delegation work plus non-root terminal host items."""
        items = self.runtime_items()
        source_contexts = {
            source_context.source_id: source_context
            for source_context in self.source_contexts()
        }
        items_by_root: dict[str, list[ParsedHostItem]] = defaultdict(list)
        terminal_items: list[ParsedHostItem] = []
        for item in items:
            if (
                item.entry.semantics.is_public_suffix_input
                or not item.entry.registrable_domain
            ):
                terminal_items.append(item)
                continue
            items_by_root[item.entry.registrable_domain].append(item)

        root_metadata = self._prepared_roots()
        work_items: list[DelegationRootWorkItem] = []
        for registrable_domain, root_items in sorted(
            items_by_root.items(),
            key=lambda current: (current[1][0].provenance.sequence, current[0]),
        ):
            ordered_items = tuple(
                sorted(root_items, key=lambda item: item.provenance.sequence)
            )
            delegation_config_source_id, fingerprint = self._delegation_root_metadata(
                registrable_domain=registrable_domain,
                ordered_items=ordered_items,
                root_metadata=root_metadata,
            )
            delegation_source_context = source_contexts.get(delegation_config_source_id)
            if delegation_source_context is None:
                raise ValueError(
                    "delegation root "
                    f"{registrable_domain!r} references unknown source "
                    f"{delegation_config_source_id!r}"
                )
            source_fingerprint = delegation_behavior_fingerprint(
                delegation_source_context.config
            )
            if fingerprint != source_fingerprint:
                raise ValueError(
                    "delegation root "
                    f"{registrable_domain!r} behavior fingerprint does not match "
                    f"source {delegation_config_source_id!r}"
                )
            work_items.append(
                DelegationRootWorkItem(
                    registrable_domain=registrable_domain,
                    delegation_source_context=delegation_source_context,
                    items=ordered_items,
                    delegation_behavior_fingerprint=fingerprint,
                )
            )
        return work_items, terminal_items

    def _delegation_root_metadata(
        self,
        *,
        registrable_domain: str,
        ordered_items: tuple[ParsedHostItem, ...],
        root_metadata: dict[str, Any],
    ) -> tuple[str, str]:
        """Return selected source id and behavior fingerprint for one root."""
        _ = ordered_items
        metadata = root_metadata.get(registrable_domain)
        if not isinstance(metadata, dict):
            raise ValueError(
                "prepared metadata missing delegation root " f"{registrable_domain!r}"
            )
        return (
            str(metadata["delegation_config_source_id"]),
            str(metadata["delegation_behavior_fingerprint"]),
        )
