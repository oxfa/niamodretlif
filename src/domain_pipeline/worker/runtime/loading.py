"""Load source-blind root and input-domain assignments for worker runtime."""

from __future__ import annotations

from typing import Any

from domain_pipeline.prepare.sources.parser import (
    DomainEntry,
    DomainListParser,
    InputFileFormat,
)
from domain_pipeline.worker.runtime.contracts import (
    DelegationRootWorkItem,
    ParsedInputDomain,
    RuntimeItemPosition,
    RuntimeManualRouting,
)

ROOT_FIELDS = frozenset({"delegation_profile", "input_domains"})
DELEGATION_PROFILE_FIELDS = frozenset({"dns_query", "delegation"})
DNS_QUERY_PROFILE_FIELDS = frozenset(
    {"default_resolvers", "timeout", "retry_backoff_base_seconds", "query_rate_limit"}
)
DELEGATION_DNS_PROFILE_FIELDS = frozenset(
    {"resolvers", "timeout", "query_rate_limit", "retry_attempts"}
)
MANUAL_ROUTING_FIELDS = frozenset(
    {"manually_selected_for_filtered", "manually_added"}
)
HOST_RESOLUTION_PROFILE_FIELDS = frozenset(
    {
        "resolvers",
        "timeout",
        "retry_backoff_base_seconds",
        "query_rate_limit",
        "retry_attempts",
        "ecs",
        "resolve_www_for_registrable_domain",
    }
)
IP_LOCATION_PROFILE_FIELDS = frozenset(
    {
        "timeout",
        "cache_ttl_days",
        "policy",
        "requires_region_lookup",
        "effective_provider",
    }
)


def _mapping(value: Any, *, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be an object")
    return value


def _require_fields(
    payload: dict[str, Any], *, expected: frozenset[str], path: str
) -> None:
    if set(payload) != expected:
        missing = sorted(expected - set(payload))
        unknown = sorted(set(payload) - expected)
        raise ValueError(
            f"{path} fields mismatch: missing={missing} unknown={unknown}"
        )


def _parsed_plain_domain(domain: str, *, parser: DomainListParser) -> DomainEntry:
    if not isinstance(domain, str) or not domain:
        raise ValueError("assigned input-domain key must be a nonempty string")
    normalized = parser.normalize(domain)
    if normalized != domain:
        raise ValueError(f"assigned input domain is not normalized: {domain!r}")
    parsed = parser.parse_source_item(domain, file_format=InputFileFormat.PLAIN)
    if parsed is None or parsed.error_reason is not None or len(parsed.targets) != 1:
        raise ValueError(f"assigned input domain is not PSL-valid: {domain!r}")
    target = parsed.targets[0]
    if target.error_reason is not None:
        raise ValueError(f"assigned input domain is not PSL-valid: {domain!r}")
    return DomainEntry(host=target.host, registrable_domain=target.registrable_domain)


class RuntimeItemLoader:
    """Build source-blind worker items from the canonical root-keyed manifest."""

    def __init__(
        self,
        *,
        config: dict[str, Any],
        prepared_metadata: dict[str, Any] | None = None,
    ) -> None:
        self.config = config
        self.prepared_metadata = prepared_metadata
        self._work_items: list[DelegationRootWorkItem] | None = None

    def _prepared_payload(self) -> dict[str, Any]:
        if self.prepared_metadata is None:
            raise ValueError("prepared metadata is required for worker runtime")
        return self.prepared_metadata

    def _prepared_roots(self) -> dict[str, Any]:
        payload = self._prepared_payload()
        if set(payload) != {"delegation_roots"}:
            raise ValueError("prepared metadata has unsupported fields")
        roots = payload.get("delegation_roots")
        if not isinstance(roots, dict):
            raise ValueError("prepared metadata delegation_roots must be an object")
        return roots

    def delegation_work_items(self) -> list[DelegationRootWorkItem]:
        """Return one work item for every assigned root and its input domains."""
        if self._work_items is not None:
            return list(self._work_items)

        parser = DomainListParser()
        work_items: list[DelegationRootWorkItem] = []
        all_domains: set[str] = set()
        total_domains = sum(
            len(_mapping(root, path=f"delegation_roots.{key}").get("input_domains", {}))
            for key, root in self._prepared_roots().items()
        )
        sequence = 0
        for registrable_domain, root_payload_value in sorted(
            self._prepared_roots().items()
        ):
            if not isinstance(registrable_domain, str) or not registrable_domain:
                raise ValueError("prepared metadata root key must be a nonempty string")
            root_payload = _mapping(
                root_payload_value,
                path=f"delegation_roots.{registrable_domain}",
            )
            _require_fields(
                root_payload, expected=ROOT_FIELDS, path=f"delegation_roots.{registrable_domain}"
            )
            root_entry = _parsed_plain_domain(registrable_domain, parser=parser)
            if root_entry.registrable_domain != registrable_domain:
                raise ValueError(
                    f"assigned root is not its own PSL registrable domain: {registrable_domain!r}"
                )

            delegation_profile = _mapping(
                root_payload["delegation_profile"],
                path=f"delegation_roots.{registrable_domain}.delegation_profile",
            )
            _require_fields(
                delegation_profile,
                expected=DELEGATION_PROFILE_FIELDS,
                path=f"delegation_roots.{registrable_domain}.delegation_profile",
            )
            dns_query = _mapping(
                delegation_profile["dns_query"],
                path=f"delegation_roots.{registrable_domain}.delegation_profile.dns_query",
            )
            delegation = _mapping(
                delegation_profile["delegation"],
                path=f"delegation_roots.{registrable_domain}.delegation_profile.delegation",
            )
            _require_fields(
                dns_query,
                expected=DNS_QUERY_PROFILE_FIELDS,
                path=f"delegation_roots.{registrable_domain}.delegation_profile.dns_query",
            )
            _require_fields(
                delegation,
                expected=DELEGATION_DNS_PROFILE_FIELDS,
                path=f"delegation_roots.{registrable_domain}.delegation_profile.delegation",
            )

            input_domains_value = root_payload["input_domains"]
            input_domains = _mapping(
                input_domains_value,
                path=f"delegation_roots.{registrable_domain}.input_domains",
            )
            if not input_domains:
                raise ValueError(
                    f"assigned root {registrable_domain!r} has no input domains"
                )
            parsed_domains: list[ParsedInputDomain] = []
            for input_domain, domain_payload_value in sorted(input_domains.items()):
                if input_domain in all_domains:
                    raise ValueError(
                        f"input domain is assigned to more than one root: {input_domain!r}"
                    )
                all_domains.add(input_domain)
                entry = _parsed_plain_domain(input_domain, parser=parser)
                if entry.registrable_domain != registrable_domain:
                    raise ValueError(
                        "assigned input domain does not match its full-PSL root: "
                        f"{input_domain!r} -> {entry.registrable_domain!r}, "
                        f"assignment={registrable_domain!r}"
                    )

                domain_payload = _mapping(
                    domain_payload_value,
                    path=(
                        f"delegation_roots.{registrable_domain}.input_domains."
                        f"{input_domain}"
                    ),
                )
                allowed_domain_fields = {"manual_routing"}
                if "host_resolution_profile" in domain_payload:
                    allowed_domain_fields.add("host_resolution_profile")
                if "ip_location_profile" in domain_payload:
                    allowed_domain_fields.add("ip_location_profile")
                _require_fields(
                    domain_payload,
                    expected=frozenset(allowed_domain_fields),
                    path=(
                        f"delegation_roots.{registrable_domain}.input_domains."
                        f"{input_domain}"
                    ),
                )
                manual_routing = _mapping(
                    domain_payload["manual_routing"],
                    path=f"input_domains.{input_domain}.manual_routing",
                )
                _require_fields(
                    manual_routing,
                    expected=MANUAL_ROUTING_FIELDS,
                    path=f"input_domains.{input_domain}.manual_routing",
                )
                if any(type(value) is not bool for value in manual_routing.values()):
                    raise ValueError(
                        f"input_domains.{input_domain}.manual_routing flags must be booleans"
                    )
                host_profile = None
                if "host_resolution_profile" in domain_payload:
                    host_profile = _mapping(
                        domain_payload["host_resolution_profile"],
                        path=f"input_domains.{input_domain}.host_resolution_profile",
                    )
                    _require_fields(
                        host_profile,
                        expected=HOST_RESOLUTION_PROFILE_FIELDS,
                        path=f"input_domains.{input_domain}.host_resolution_profile",
                    )
                ip_profile = None
                if "ip_location_profile" in domain_payload:
                    ip_profile = _mapping(
                        domain_payload["ip_location_profile"],
                        path=f"input_domains.{input_domain}.ip_location_profile",
                    )
                    _require_fields(
                        ip_profile,
                        expected=IP_LOCATION_PROFILE_FIELDS,
                        path=f"input_domains.{input_domain}.ip_location_profile",
                    )
                    if host_profile is None:
                        raise ValueError(
                            f"input_domains.{input_domain} has IP location without host resolution"
                        )

                parsed_domains.append(
                    ParsedInputDomain(
                        entry=entry,
                        position=RuntimeItemPosition(
                            sequence=sequence,
                            total=total_domains,
                        ),
                        manual_routing=RuntimeManualRouting(
                            manually_selected_for_filtered=manual_routing[
                                "manually_selected_for_filtered"
                            ],
                            manually_added=manual_routing["manually_added"],
                        ),
                        host_resolution_profile=host_profile,
                        ip_location_profile=ip_profile,
                    )
                )
                sequence += 1

            work_items.append(
                DelegationRootWorkItem(
                    registrable_domain=registrable_domain,
                    delegation_profile={
                        "dns_query": dict(dns_query),
                        "delegation": dict(delegation),
                    },
                    items=tuple(parsed_domains),
                )
            )
        self._work_items = work_items
        return list(work_items)

    def expected_input_domains_by_root(self) -> dict[str, set[str]]:
        """Return the exact root-to-domain assignment expected from this worker."""
        return {
            work_item.registrable_domain: {
                item.entry.host for item in work_item.items
            }
            for work_item in self.delegation_work_items()
        }

    def all_input_domains(self) -> list[ParsedInputDomain]:
        """Return every input-domain item in deterministic worker order."""
        return [
            item
            for work_item in self.delegation_work_items()
            for item in work_item.items
        ]
