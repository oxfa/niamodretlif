# Domain Work and Output Semantics: Implementation Plan

**Status:** Review complete. This plan records the changes needed to align the current implementation with the settled design; implementation changes are outside this review. The earlier pipeline plans remain unchanged.

## 1. Objective and settled direction

Restore the worker’s per-domain processing path present in the implementation tree at commit `3ffa4734e98eecd51dd28812b718a24ac4015c0d`, adapting it to the current source-item mapping and prepare/worker/aggregate handoffs. Preserve the baseline’s root grouping, per-input-domain work, root-result fanout, host-resolution/IP routing, workload-aware balancing, and DNS classification table. Do not restore source identity fields.

The logical transfers are:

- **Prepare → workers (1→N):** assign each registrable domain to one worker and pass its unique valid input domains under that root, plus the effective settings and routing flags needed for those domains. Do not pass source-item records or a domain-to-source association.
- **Prepare → aggregator (1→1):** pass `valid_source_items_by_registrable_domain`, `valid_source_items_without_extractable_registrable_domain`, the separate manually added-domain records, configured output specifications, and preparation results.
- **Workers → aggregator (N→1):** pass one root DNS outcome per assigned registrable domain and one final route outcome per assigned input domain.

Keep the selected physical topology. On a successful run with N configured workers, the interstage set is one combined worker-input artifact, one prepared-batch artifact, and N worker-result artifacts (N+2 total). Each matrix worker may download the combined package and restore only its own assignment directory. Diagnostic/log artifacts are outside that interstage count. A fatal worker error must be shown in the worker job error, fail the matrix, and prevent the aggregate job from starting. The existing matrix uses `fail-fast: false`, so other workers may finish before the failed matrix job concludes.

Settled decisions:

- Use the full Public Suffix List, including ICANN and PRIVATE rules. A strict PSL miss is invalid.
- Keep the two valid source-item collections and their provenance in the prepare-to-aggregator handoff. Items without an extractable registrable domain do not enter root worker assignments.
- Input format controls source parsing. Output format controls rendering; output format must not be used to guess the input grammar.
- Keep valid AdBlock rules with no extractable request host only in AdBlock output. Extract a request host only when the supported source syntax identifies it unambiguously.
- Let each configured filtered-output format determine how eligible target associations are rendered and deduplicated. Preserve source-item provenance in the aggregate mapping until rendering.
- Apply configured source exclusions before building worker assignments or valid source-item output mappings.
- Replace `host_resolution.targets` with the single boolean `resolve_www_for_registrable_domain`. Do not retain old-key aliases or readers.
- Preserve the baseline registrable-domain DNS query/fallback sequence and its actionable, review, and unactionable status mapping.
- Keep credentials in runtime environment variables only; reject `ip_location.token` in config and never serialize credential values into an artifact.
- Preserve the dynamic matrix and fatal-worker/aggregate gate; do not add one workflow step per worker.
- Keep source identity in prepare-owned aggregate data only. Worker inputs, worker result files, and the final merged review output contain no source IDs, labels, paths/URLs, source text, or line numbers.
- Keep this dedicated plan as the implementation reference. Do not update the earlier planning documents as part of this refactor.

## 2. Evidence-based comparison

| Area | Commit `3ffa4734e98eecd51dd28812b718a24ac4015c0d` | Current implementation | Target design |
| --- | --- | --- | --- |
| Worker assignment | Root entries carried actual host entries and manual-routing flags. The balancer assigned roots by descending entry count to the worker with the lowest accumulated entry count. Entries also carried source identifiers and labels. | `PreparedRuntimeMetadata.delegation_roots` is root-keyed but carries only a delegation config source ID and fingerprint. The assigned-roots data has no input hosts. Assignment is balanced by root count. | Restore per-input-domain work and entry-weighted root assignment, using unique normalized input domains as the work count. Keep each root atomic; exclude source identity and source membership. |
| Worker loading and routing | The loader flattened each root’s host entries into runtime items. The delegation stage fanned one root result out to those items, then sent actionable ordinary items to host resolution when enabled; a disabled host-resolution stage used the filtered skipped route. | The loader creates one item whose host is the registrable root. After a nonterminal delegation result, ordinary entries are immediately marked skipped, so host resolution and IP location are not reached. | Load each assigned input domain; query delegation once per root; fan the root result to those domains; then apply host-resolution/IP and manual-routing policies per domain. |
| Delegation DNS classification | NS-first lookup; conditional same-owner SOA fallback on NS NXDOMAIN or retry exhaustion; actionable, review, and unactionable outcomes are selected by the lookup result and routing table. | `lookup.py` and `routing/policies.py` match the baseline; the changed stage code no longer sends actionable outcomes through ordinary host resolution. | Keep the baseline DNS status mapping and restore the baseline downstream stage routing. |
| Host-resolution names | Used the configurable target selector. | The same selector model is present. The executor resolves the input host and can also append configured subdomains for any input with a registrable domain, including an input that is already a subdomain. | Resolve the input itself. Add `www.<root>` only when the input equals its registrable root and `resolve_www_for_registrable_domain` is true. |
| Worker and review outputs | The worker TXT projection used the row’s host. | The TXT projection uses the registrable domain; internal review and unactionable paths say registrable-domain scope, and worker review rows carry source identifiers. The final review schema also retains source identifiers. | Emit outcomes at input-domain scope. Publish input-domain values in unactionable/review outputs and remove source identity from worker rows and the final merged review output. |
| Aggregation | Worker terminal routes distinguished filtered, review, and unactionable results. | Filtered rendering excludes only roots in the unactionable set and does not join each source target to its input-domain route. | Join each target association to its input-domain route. Only the filtered route is eligible; the configured output format determines rendering. |
| Source parsing/output | The selected baseline predates the current source-item index and multi-format aggregate renderer. | AdBlock target extraction can treat an unanchored domain-shaped pattern as a request host. Auto format detection is file-wide; UNKNOWN/MIXED inputs produce diagnostics without valid item records. Public-suffix-only target associations and AdBlock no-target items are distinct in the item index. | Extract only unambiguous request hosts. Define handling for auto/explicit input formats, no-target items, public-suffix-only associations, and AdBlock metadata separately. |
| Workflow handoff | The baseline already used a dynamic worker matrix, but used a single prepared-batch artifact and an aggregate job with `always()`. | `.github/workflows/_pipeline-run-batch.yml` stages one combined worker-input artifact, one prepared-batch artifact, and one result bundle per matrix worker. The aggregate job needs both preparation and the worker matrix and has no job-level failure override. The matrix uses `fail-fast: false`; its final worker step reports a fatal error. | Keep the existing dynamic topology. The successful interstage set remains N+2; worker failure fails the matrix and the aggregate job is skipped. |

The baseline comparison is against the implementation tree at the specified commit, not a claim that the commit introduced those behaviors. Prepared assignment and loader differences are in `assignment.py` and `loading.py`; the routing regression is in `runtime/stages.py`. A direct diff also shows `worker/runtime/executor.py` unchanged and `worker/host_resolution/lookup.py` changed only by a local-variable rename. `worker/delegation/lookup.py` and `routing/policies.py` match the baseline. The dynamic matrix itself already existed at the baseline; the selected topology changes the artifact split and the aggregate failure gate. The current workflow’s aggregate job declares `needs: [prepare_run, run_workers]` without an override; GitHub Actions skips a dependent job when a needed job fails unless a status condition overrides that behavior ([GitHub Actions: Using jobs in a workflow](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-jobs)).

The current source-item index retains target associations with the normalized host and nullable registrable domain, and keeps no-target AdBlock items separately. A strict PSL miss is recorded as an error, not as a valid no-target item. Current aggregation, however, adds valid associations with no registrable domain directly to the eligible set while filtering mapped items only by root-level unactionable status. Therefore the target design must distinguish a valid public-suffix-only association with no worker route from an actual no-target rule and must use per-input-domain routes for mapped associations.

The current AdBlock parser checks a domain-shaped pattern before requiring the domain anchor. Thus an unanchored rule such as `example.com` can be treated as a request-host target, then rendered as a plain or hosts entry. The Adblock Plus guide explains that unanchored patterns may match anywhere in a request, that leading `||` anchors a filter to a domain, and that regex filters use slash delimiters; it also documents `$third-party` as an option ([Adblock Plus: How to write filters](https://help.adblockplus.org/adblock-plus-help-center/how-to-write-filters)). This supports requiring unambiguous host syntax before creating an association. The two user-provided regex rules are valid no-target acceptance cases under the supported AdBlock grammar and must be retained in AdBlock output.

The current parser treats `input.format: auto` as one file-wide format decision. It does not parse UNKNOWN/MIXED files line by line; the source-item builder records diagnostics and skips their item records. Auto detection also ignores cosmetic rules, so a cosmetic-only file is UNKNOWN. The target contract below keeps that no-guessing behavior: explicitly set `input.format: adblock` for ambiguous domain-shaped AdBlock rules or cosmetic-only AdBlock files. Never infer AdBlock input syntax from the filtered output format.

Current preparation creates a public-suffix review and terminal row solely because a valid PSL-matching target has no registrable domain. The source-item index separately classifies that target association as valid and the aggregate renderer currently makes it output-eligible without a worker route. The target contract removes that review/terminal outcome when missing registrable root is the only condition: the valid public-suffix-only association has no root DNS or host route, but remains eligible for format-specific rendering unless excluded.

The current review schema includes `source_id` and `source_input_label`, and preparation review rows use that schema before aggregate merging. The final review projection must therefore be redesigned as source-blind, not merely the worker result rows.

Credential handoff is another confirmed contract conflict. `prepare/assignment.py` currently copies each selected source config into the worker runtime spec, the worker IP-location model accepts `ip_location.token`, and both prepare validation and worker lookup prefer that configured token over the environment token. Thus, if a source config supplies a token, the current assignment path copies it into the worker artifact. The direct config says to provide the token through the environment, while the sample currently permits an explicitly configured token. The target contract below removes this accepted config path: credentials are runtime environment values and never worker-manifest fields. This finding concerns the behavior allowed by the current config and serialization path; it does not claim that an artifact currently contains a credential.

The current `input.format: auto` path stores the detected whole-file format in source/item metadata, not the literal `auto` setting. The target contract retains that effective parsed format because the aggregate renderer needs it to distinguish AdBlock records; it does not retain a redundant pair without a consumer. Current manual-input validation also rejects a host listed both as manually excluded and as manually added or manually selected, and preparation applies the exclusion before retaining source entries. Preserve that rule so excluded hosts cannot re-enter through manual routing. The AdBlock network-filter parser currently emits at most one request-host target per filter; the format-rendering rule below applies to any multiple target associations the supported item formats produce and does not require expanding AdBlock grammar.

For no-root inputs, current preparation records a public-suffix entry for review/terminal handling, while aggregation directly renders an unmatched manual addition whose registrable domain is null. The target contract removes a no-root-only review/terminal outcome for both kinds of PSL-valid input: neither has a worker route, and both remain eligible by valid target status. This aligns preparation review semantics with the aggregate’s route-free output handling and avoids reporting an input for review while also emitting it.

## 3. Canonical prepare-to-worker contract

Replace the root-only assigned-roots payload and source-indexed runtime configuration with one canonical source-blind worker-work manifest inside the existing combined input artifact. Use a root-keyed mapping so each root remains atomic and its child work is explicit. The profile bodies below are schematic effective settings, not source records:

~~~yaml
delegation_roots:
  example.com:
    delegation_profile:
      dns_query: {} # effective root-query settings
      delegation: {} # effective delegation settings
    input_domains:
      example.com:
        manual_routing:
          manually_selected_for_filtered: false
          manually_added: false
        host_resolution_profile: {} # include only when this route uses the stage
        ip_location_profile: {} # include only when this route reaches the stage
      ads.example.com:
        manual_routing:
          manually_selected_for_filtered: false
          manually_added: false
        host_resolution_profile: {}
        ip_location_profile: {}
~~~

`input_domains` contains unique normalized hosts from valid source target associations, plus unmatched manually added hosts that have a registrable domain. A matched manual selection/addition is already represented by its source target association. An unmatched `manually_selected_for_filtered` entry remains a preparation-owned review/terminal row; it does not create worker work. The root itself appears there only when it is an input. The worker manifest contains no source IDs, labels, file paths/URLs, original item text, host-to-source membership, or source-specific output paths/formats.

Build the worker manifest from an allowlist of effective runtime settings rather than copying a source config. Credentials are environment-only: prepare validation and worker lookup both use `IP_LOCATION_IPINFO_TOKEN`; never serialize a token. Remove `ip_location.token` from the accepted config and worker schemas, and fail validation if a config still supplies it rather than silently dropping it. Update the sample’s current comment that permits an explicit config token.

Resolve effective settings before serializing work. Check profile agreement against every non-excluded source association before collapsing duplicate input hosts; current preparation retains the first source ID when hosts are merged, which otherwise loses evidence needed for this check.

- For every registrable root, require one effective delegation profile across the source associations and manual inputs under that root, because delegation is queried once per root.
- For each ordinary input domain, repeated associations must agree on whether host resolution is enabled. If disabled, the domain takes the baseline skipped-to-filtered route and unused host/IP settings do not create conflicts. If enabled, repeated associations must agree on the effective host-resolution settings; when the input equals its registrable root, `resolve_www_for_registrable_domain` is part of those settings because it changes the queried-name set.
- For a host-resolution-enabled domain, repeated associations must also agree on whether IP location is enabled. Compare the remaining effective IP-location settings only when that stage is enabled and reachable.
- Manually selected/added domains bypass host resolution and IP location after the root result; compare only their root delegation profile. If root delegation is actionable, apply the established manual filtered route; if the root result is review or unactionable, it takes precedence.
- Different ordinary input domains under one root may use different host/IP profiles. Do not reject them because unrelated source settings differ.
- Unmatched manual-only entries need only the shared root delegation profile; the existing config contract requires enabled sources to agree on that behavior. Do not select a source profile by iteration order.
- Do not compare source output settings in worker profile equality; aggregate owns those settings.

Balance roots by the number of unique input domains beneath each root: sort largest work count first, then assign each root to the worker with the smallest accumulated input-domain count, using stable root and worker-ID tie-breaks. This preserves root atomicity and restores workload-aware balancing while weighting the deduplicated unit the worker actually processes.

## 4. Prepare-to-aggregator contract

Keep the source-item index as the authority for source content and provenance:

- `valid_source_items_by_registrable_domain` maps each registrable domain to original valid items and their target associations. Each association retains its normalized target host and its registrable domain.
- `valid_source_items_without_extractable_registrable_domain` contains (a) valid PSL-matching target associations whose registrable domain is null and (b) valid source items with no extractable request host, including supported AdBlock rules. Keep the two cases distinguishable by association ID and reason.
- Strict PSL misses and source-syntax errors appear in neither valid collection.
- Keep recognized AdBlock metadata in its separate metadata collection. It is not a valid target association or a no-target rule, and is rendered only for AdBlock output.
- Preserve the effective parsed file format in source/item records: use the explicitly configured format when one is selected, and the detected whole-file format when `input.format: auto`. This is the format the renderer needs to distinguish AdBlock items; do not store a redundant configured/effective pair without a consumer. UNKNOWN/MIXED files remain diagnostics with no valid records. For ambiguous domain-shaped AdBlock rules and cosmetic-only AdBlock files, require `input.format: adblock`. Do not reparse a mixed/unknown file under a guessed line grammar.
- Apply manual source exclusions before building either valid collection or any worker assignment. An excluded association is not eligible for output.
- Preserve the manual-input conflict rule: a host cannot be listed both in `manually_excluded_from_sources` and in `manually_added` or `manually_selected_for_filtered`. An excluded source host must not re-enter the worker set or filtered output through a manual route.
- Keep manual-only `manually_added_domains`, excluded hosts, output specifications, and preparation-owned review/terminal records as separate prepare-to-aggregator fields. A manual addition does not become a source item solely because it was added. A matched addition retains its source-item association and carries the manual route flag only in worker work.
- An unmatched manually added host with a registrable domain becomes worker input and is rendered only if its final route is filtered. A PSL-valid manual addition with no registrable domain has no root to classify and no worker route; keep it eligible for output-format-specific rendering without a preparation review or terminal route solely for the missing root. A matched manual addition with no registrable domain follows the same rule through its source association. An unmatched `manually_selected_for_filtered` host remains a preparation-owned review/terminal row rather than becoming an addition or a worker input.
- Keep source IDs, labels, original text, and line numbers in the aggregate source-item records as provenance. Do not copy them into the worker manifest or published review output.

AdBlock target extraction is conservative: a supported domain-anchored network filter such as `||host^` yields a request-host association; a domain-shaped unanchored pattern, a regex rule, or a cosmetic rule scope does not establish a request host. When the source syntax is valid, such no-target rules belong in the no-extractable-domain collection. Under `auto`, use the existing file-wide detection; set `input.format: adblock` for ambiguous domain-shaped rules and cosmetic-only files. The filtered output format never changes input validity.

A valid public-suffix-only target has no registrable domain and therefore no worker route. It does not create a preparation review row or terminal route solely because the root is absent. Keep it in the no-extractable-domain collection and let output format determine how it is rendered. A valid no-target AdBlock item has no target association; it is retained only when the selected filtered output is AdBlock.

## 5. Worker result contract and aggregate semantics

Each worker-result artifact carries closed, source-blind result rows:

1. **Registrable-domain DNS outcome:** exactly one root result for each assigned registrable domain, carrying the root, its actionable/review/unactionable disposition, and the existing typed delegation evidence.
2. **Input-domain outcome:** exactly one final route per assigned input domain, carrying `input_domain`, its registrable domain, the filtered/review/unactionable route and reason, plus evidence for stages actually run. Include no source IDs, labels, paths/URLs, source text, or line numbers.

Serialize these as two closed collections in the existing worker-result handoff: `registrable_domain_results` and `input_domain_results`. Validate each collection against its row schema and reject unknown fields. Do not add another artifact or an assignment-roster handoff.

Use worker-local paths such as `unactionable-input-domains/<config>.txt` and `review-results-by-input-domain/<config>.csv`. The unactionable list contains each input-domain value routed unactionable, including subdomains under an unactionable root. Review rows are per input domain and contain the input host, outcome, and reason. The published merged review output follows the same source-blind schema, including preparation-owned rows; remove source identity and input-file details when projecting those rows. Keep file diagnostics separate from the review output.

Build the configured final unactionable output from the per-input-domain outcomes across worker results: include each unique input domain whose final route is unactionable, including source-backed subdomains under an unactionable root and registrable manual-only inputs. Do not publish only the root DNS outcome as the domain value.

Validate completeness without adding a worker-assignment roster to the prepare-to-aggregator handoff:

- Each worker validates its results locally against its own worker manifest before it can complete successfully: no missing/duplicate root outcomes, no missing/duplicate input-domain routes, and no unknown root/domain.
- Validate that each input domain’s registrable domain under the full PSL equals the root assignment key. Reject unknown result fields, including source-attribution fields, rather than allowing them through generic result dictionaries.
- Aggregate derives the global expected roots and input-domain set from `valid_source_items_by_registrable_domain` plus unmatched manual additions with a registrable domain. Exclude `valid_source_items_without_extractable_registrable_domain`, which contains no-root associations and no-target items and has no worker routes. Require exactly one root outcome per expected root and one final route per expected input domain across all worker results; reject duplicates, omissions, and unexpected results.
- For root results routed review or unactionable, every input domain under that root must have the same terminal route. For an actionable root, input domains may finish at different routes under their own host/IP policies.
- The aggregate does not need to know which worker owned a root: local ownership is checked by the worker, and global uniqueness/completeness is checked by aggregate. Do not reconstruct assignments or introduce a new roster artifact.

Filtered output is built by joining source-item target associations to the corresponding final input-domain route:

- A mapped association is eligible only when its input-domain route is `filtered`. Review and unactionable routes are excluded.
- A valid public-suffix-only association has no worker route; it remains eligible by source validity unless excluded and is rendered according to the configured format.
- A PSL-valid manual addition with no registrable domain also has no worker route and remains eligible for format-specific rendering, without a preparation review or terminal route solely for the absent root. Registrable manual additions require a filtered input-domain route. Unmatched manually selected entries remain in preparation review/terminal output and are not rendered as additions.
- For AdBlock output, preserve an original target rule only when every association on that item is eligible. If a supported multi-target item is only partly eligible, omit that whole original rule rather than emit a changed rule with broader/narrower meaning. Preserve valid no-target AdBlock rules and recognized metadata only in AdBlock output. Do not expand the supported AdBlock grammar solely to create multi-target filters; apply this rule wherever a supported item format does produce multiple target associations.
- For plain/hosts output, render each eligible target association as a host line. Do not convert AdBlock exception filters to plain/hosts entries.
- Deduplicate rendered lines only at the final output boundary. Keep item and target-association provenance intact through eligibility and format-specific rendering.
- Render manually added domains only when their final input-domain route is filtered. They remain separate from source associations and use the same output-format renderer.

## 6. Target worker behavior

1. Perform one baseline registrable-domain DNS classification for each assigned root: query NS first; run SOA fallback only for NS NXDOMAIN or retry exhaustion; reuse a same-owner SOA from the NS response when present.
2. Fan the root result out to every assigned input domain under it. A root-level review or unactionable outcome terminates each of those domains at that same route, before manual routing. This preserves the baseline order of checks.
3. For an actionable root, route manually selected/added domains to filtered without host/IP checks. Route ordinary domains to host resolution when enabled; if host resolution is disabled, use the baseline skipped-to-filtered route.
4. Resolve each input domain itself. Only when the input equals its registrable domain and `resolve_www_for_registrable_domain` is true, also resolve `www.<root>`. A specific subdomain input resolves only itself; do not add the root or its `www` host to a subdomain input.
5. Combine the selected DNS-name results under the original input-domain identity. Union and deduplicate their IPv4/IPv6 addresses; any usable address makes the combined result resolved. If none has an address, preserve the existing combination precedence: timeout, SERVFAIL, NXDOMAIN, NODATA, then unknown. Send the combined result to IP location only when its status is `resolved` and IP location is enabled. A `resolved` result with IP location disabled uses the existing host-resolution-to-filtered route; a result without usable addresses uses the existing host-resolution review route.
6. Emit one final route for every input domain, including manual routes and disabled stages. Carry route attribution and resolution evidence on the original input domain.
7. An unrecoverable worker error fails that worker with a detailed error surfaced in the workflow. The matrix job fails, and the dependent aggregate job does not start. Preserve the existing matrix behavior in which other workers are allowed to finish.

## 7. DNS classification: preserve the baseline rule

Preserve the core lookup sequence and route mapping from the implementation tree at commit `3ffa4734e98eecd51dd28812b718a24ac4015c0d`. Apply it once per registrable domain, then fan the root’s actionable, review, or unactionable outcome to its assigned input domains. This is the user’s final decision and replaces the earlier provisional binary rule that treated every result other than a proven absence as actionable.

| NS result | SOA handling | Baseline disposition |
| --- | --- | --- |
| NS records returned | No SOA query | Actionable; continue to host-resolution/manual/disabled-stage routing. |
| NS query returns NoAnswer/NODATA (NOERROR, RCODE 0, with no NS RRset) | No SOA query | Actionable under the baseline application policy. |
| Successful NS answer contains no nameservers | No SOA query | Unactionable under the baseline application route for an empty answer. |
| NS NXDOMAIN (RCODE 3) with same-owner SOA in the response authority | Reuse that SOA | Actionable. |
| NS NXDOMAIN without same-owner authority SOA | Query SOA; exact-owner SOA answer | Actionable. |
| NS NXDOMAIN without same-owner authority SOA | SOA returns NXDOMAIN, NODATA, or no exact-owner SOA RRset | Unactionable. |
| NS NXDOMAIN without same-owner authority SOA | SOA retries are exhausted | Review. |
| NS retryable lookup exhausts its retry budget | Query SOA | SOA present: actionable; SOA absent or SOA retries exhausted: review. |
| NS lookup returns another handled DNS/socket error | No SOA fallback | Review. |
| Unexpected error during SOA fallback | No route classification | Fail the worker; do not convert the exception into actionable, review, or unactionable. |

Keep DNS facts distinct from application routes. RCODE 3 is NXDOMAIN and RCODE 0 is NOERROR. NODATA is not a separate RCODE; it is inferred from the response context. The baseline’s NS NODATA → actionable and empty successful NS answer → unactionable mappings are application rules, not RFC claims that the owner or its subdomains are resolvable. Preserve the existing typed delegation evidence and route code/reason; do not add raw DNS-message serialization, a second evidence schema, or stored answer/authority payloads solely to explain the route.

Relevant references are [RFC 2308 §2.1](https://www.rfc-editor.org/rfc/rfc2308.html#section-2.1), [§2.2](https://www.rfc-editor.org/rfc/rfc2308.html#section-2.2), and [§3](https://www.rfc-editor.org/rfc/rfc2308.html#section-3); [RFC 1034 §3.1](https://www.rfc-editor.org/rfc/rfc1034.html#section-3.1), [§3.6](https://www.rfc-editor.org/rfc/rfc1034.html#section-3.6), and [§6.2.4](https://www.rfc-editor.org/rfc/rfc1034.html#section-6.2.4); and [RFC 1035 §4.1.1](https://www.rfc-editor.org/rfc/rfc1035.html#section-4.1.1). These standards define DNS response semantics, not the application’s outcome labels.

## 8. Configuration and implementation constraints

For each source’s existing `host_resolution` block, the target configuration is:

~~~yaml
sources:
  - id: direct
    host_resolution:
      enabled: true
      resolve_www_for_registrable_domain: true
~~~

Use `true` as the default and set the value explicitly in configuration samples. The root input resolves itself and, when enabled, `www.<root>`. A subdomain input resolves only itself. Remove `targets`, `input_host`, `root_domain`, and `subdomains` from strict models, active configs, samples, fixtures, docs, and runtime readers. Do not accept those keys as aliases or fallbacks.

Validate each handoff against its exact required field set and batch, worker, and config identity; reject missing or unknown fields. Do not serialize or require a shared pipeline-format marker. Do not add old-shape readers, fallbacks, aliases, or parallel contracts. Remove the serialized IP-location token field from both source and worker schemas; only the runtime environment supplies credentials.

Keep implementation in the existing `prepare`, `worker`, `aggregate`, and workflow owners unless code evidence shows a cohesive independent package is needed. Apply SOLID where OOP reduces coupling or gives a clear single responsibility; apply KISS/YAGNI when a SOLID decomposition would be more complex than the behavior. Do not create a class or package for each field or output file. If a new package is genuinely needed, justify its responsibility and dependency boundary and follow REP, CCP, CRP, ADP, SDP, and SAP.

## 9. Implementation sequence and verification scope

1. **Preflight.** Recheck exact owners, callers, configuration, tests, docs, artifact paths, and dirty paths for the planned changes. The baseline comparison is in Section 2. If implementation changes `.github/`, directly read every file under that tree before editing.
2. **Configuration and contracts.** Add `resolve_www_for_registrable_domain` with its selected default; remove the selector model and all old-key references. Remove `ip_location.token` from accepted config and worker schemas, keep `IP_LOCATION_IPINFO_TOKEN` as the sole runtime credential input, and correct the sample documentation. Validate handoffs by exact field sets and their batch, worker, and config identities without a shared pipeline-format marker. The worker manifest must be built from an allowlist of effective fields.
3. **Prepare data.** Apply exclusions; parse source items according to each input format; build both valid source-item collections and separate manual/preparation data. Resolve effective root/domain profiles against all source associations before deduplicating worker domains. Construct the source-blind root-to-input-domain assignments and balance by unique input-domain count. Include only unmatched registrable manual additions as worker-only inputs; preserve PSL-valid manual additions without registrable domains as aggregate-rendered inputs with no worker result, and unmatched manual selections as preparation review/terminal rows.
4. **Worker runtime.** Replace source-indexed runtime config and root-only inputs with the canonical manifest. Restore root lookup fanout, manual routes, ordinary host-resolution/IP routing, selected-name aggregation, and exactly one final route per input domain.
5. **Worker results and aggregate.** Emit one root outcome and one per-input-domain route per assignment using closed source-blind result rows; validate local completeness and the PSL-derived root association. Validate global aggregate coverage without an assignment roster. Join source associations by registrable domain plus normalized input domain; render source items and manual additions according to filtered output format; project a source-blind final review file; rename the worker output directories to input-domain scope.
6. **Workflow handoffs.** Preserve the combined input package, prepared-batch package, dynamic worker matrix, one result bundle per worker, empty-assignment lifecycle, detailed worker error, and aggregate dependency gate. Keep the successful interstage count at N+2. Do not add per-worker workflow steps.
7. **Remove obsolete contracts.** Update affected callers, schemas, config samples, docs, and tests. Do not change earlier plan documents. Remove root-only worker output projections, source identity from worker/review outputs, and all old-key or old-shape acceptance paths.

Plan implementation checks against these contracts: (a) format-aware parsing and rendering, including the supplied regex examples, explicit AdBlock parsing for ambiguous/cosmetic-only input, unanchored domain-shaped filters, public-suffix-only associations, metadata, and strict PSL misses; (b) exclusions, supported multi-target items, manual additions, and source-blind final review; (c) pre-dedup profile conflicts and route-aware profile equivalence; (d) root-to-domain serialization, unique-domain balancing, and empty assignments; (e) baseline NS/SOA query sequence and every listed route; (f) actionable-root fanout, manual/disabled routes, the root/www/subdomain name set, and combined host-result precedence; (g) exactly-one local/global root and input-domain outcomes; (h) fatal worker error reporting and aggregate job gating; and (i) rejection of config-supplied credentials and absence of credential values from handoff artifacts while prepare and worker obtain runtime credentials from the environment. These checks belong to implementation; this document review ran no implementation tests.

## 10. DNS decision resolved

Preserve the core registrable-domain DNS lookup and status mapping from commit `3ffa4734e98eecd51dd28812b718a24ac4015c0d`, as specified in Section 7. This is the final decision. Keep root-result fanout, source-blind input-domain results, the selected `www` behavior, and the prepare/worker/aggregate artifact topology described elsewhere in this plan.

