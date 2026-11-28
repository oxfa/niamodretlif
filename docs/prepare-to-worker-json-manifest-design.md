# Prepare to Worker JSON Manifest

**Status** · Implemented. This document defines the Prepare to Worker payload and validation contract. The [artifact handoff plan](pipeline-artifact-handoffs.md) covers archive layout and workflow wiring. The [domain work and output plan](pipeline-domain-work-and-output-plan.md) supplies the assignment, routing, and output requirements. This JSON contract supersedes its inline profile layout.

## 1. Contract and scope

Prepare assigns each registrable domain and all its unique normalized input domains to one worker. The balancer weighs each group by its input domain count. Prepare checks agreement on effective settings across the source associations, including associations that collapse to the same input. Worker work contains eligible inputs and registrable manual additions. A registrable domain appears as an input only when it is itself assigned. [Preparation](../src/domain_pipeline/prepare/planner.py#L361) · [Assignment](../src/domain_pipeline/prepare/assignment.py#L164)

The new manifest represents the same work as one compact JSON document per worker. It stores each distinct effective delegation, host resolution, and IP location profile once in that worker's manifest. The root and input records reference those profiles. The fields are limited to effective runtime settings and domain assignments. Source identities, paths and URLs, original items, source membership, and credentials stay outside the manifest. `config_name` names the batch configuration and is already used to derive worker paths. Credentials come from the worker environment.

The combined worker input artifact packs one directory per configured worker, including workers with empty assignments. Each matrix job restores its designated directory. The prepared batch and worker result artifacts keep their existing roles. Prepare and Aggregate own source provenance and rendering. Fatal worker failures propagate through the existing job failure gate.

## 2. Files and document fields

The two required members for each worker live under `.workflow_state/batches/<batch_id>/workers/<worker_id>/`. [Member declaration](../src/domain_pipeline/paths/layout.py#L345)

- `runtime-config.json` is a single UTF-8 JSON object. Write compact JSON with deterministic object key order and one trailing newline. Its exact top-level fields are `batch_id`, `worker_id`, `config_name`, `runtime_spec`, and `prepared_metadata`.
- `worker-identity.json` keeps its two fields, `batch_id` and `worker_id`. Restore and the manifest loader compare it with the requested worker and batch. Restore also compares `config_name` in the runtime manifest with the requested config. [Identity checks](../src/domain_pipeline/pipeline_run/handoffs.py#L198)

`runtime_spec` carries `cache` and `runtime`. `cache` carries `delegation_ttl_days` and `host_resolution_ttl_days`. `runtime.stage_concurrency` carries the existing `minimums` and `adaptive` settings. The worker derives output, log, and cache paths through `PathLayout` using the validated identities. The baseline cache path is resolved under the source root and the worker output and overlay paths under the state root. [Runtime shaping](../src/domain_pipeline/prepare/prepare_to_worker_manifest.py#L408) · [Path derivation](../src/domain_pipeline/prepare/prepare_to_worker_manifest.py#L533)

| Object | Fields |
| --- | --- |
| `prepared_metadata` | Required `profiles` and `delegation_roots`. |
| `profiles` | Three required arrays: `delegation`, `host_resolution`, and `ip_location`. An unused stage has an empty array. |
| `delegation_roots` | Object keyed by registrable domain. Each value requires `delegation_profile_id` and `input_domains`. |
| `input_domains` | Object keyed by input domain. Each value requires `manual_routing` and can contain `host_resolution_profile_id` and `ip_location_profile_id`. |
| `manual_routing` | Required booleans `manually_selected_for_filtered` and `manually_added`. |

A profile ID is the zero-based index in that stage's array. `delegation_profile_id` selects an entry in `profiles.delegation`, while `host_resolution_profile_id` and `ip_location_profile_id` select from their respective arrays. Omit an optional reference when its stage does not apply. An empty worker has `delegation_roots: {}` and three empty arrays. It has the usual identity, runtime settings, and result lifecycle.

Reuse the existing typed effective profile definitions, including their resolver and policy types. Delegation retains its `dns_query` and `delegation` objects, host resolution retains its DNS settings and `resolve_www_for_registrable_domain`, and IP location retains its provider, policy, timeout, and TTL fields. Nullable values such as delegation overrides or a resolver weight are part of those profiles. Only absent optional **references** are omitted. Shared fields can still occur in different types of profiles. The tables deduplicate complete stage profiles. [Profile definitions](../src/domain_pipeline/prepare/prepare_to_worker_manifest.py#L67)

### Example manifest

This complete example uses illustrative settings and is expanded for reading. Both roots refer to delegation profile `0`. The `example.com` and `ads.example.com` inputs share host and IP profile `0`. `cdn.example.com` has host resolution disabled. `manual.example.net` is a manual addition.

~~~json
{
  "batch_id": "batch-123-attempt-1",
  "worker_id": "worker-01",
  "config_name": "fixture",
  "runtime_spec": {
    "cache": {
      "delegation_ttl_days": {"actionable": 7, "unactionable": 1},
      "host_resolution_ttl_days": {"resolved": 7, "nodata": 1, "nxdomain": 1}
    },
    "runtime": {
      "stage_concurrency": {
        "minimums": {"delegation": 20, "host_resolution": 20, "ip_location": 8},
        "adaptive": {
          "enabled": true,
          "delegation_enabled": true,
          "host_resolution_enabled": true,
          "supervisor_interval_seconds": 1.0,
          "busy_scale_up_after_seconds": 5.0,
          "idle_scale_down_after_seconds": 5.0,
          "pressure_window_seconds": 5.0,
          "queue_pressure_ratio": 0.8,
          "max_concurrency_multiplier": 4,
          "scale_up_step": 1,
          "scale_down_step": 1
        }
      }
    }
  },
  "prepared_metadata": {
    "profiles": {
      "delegation": [
        {
          "dns_query": {
            "default_resolvers": [{"resolver": "system_resolver", "weight": null}],
            "timeout": 5.0,
            "retry_backoff_base_seconds": 1.0,
            "query_rate_limit": {
              "enabled": true,
              "providers": {
                "system_resolver": {"qps_per_worker": 60.0, "burst": 10, "max_pending": 32},
                "google_public_dns": {"qps_per_worker": 30.0, "burst": 5, "max_pending": 16},
                "quad9_ecs_public_dns": {"qps_per_worker": 30.0, "burst": 5, "max_pending": 16},
                "cloudflare_public_dns": {"qps_per_worker": 12.0, "burst": 2, "max_pending": 8},
                "opendns_public_dns": {"qps_per_worker": 12.0, "burst": 2, "max_pending": 8},
                "controld_unfiltered_public_dns": {"qps_per_worker": 12.0, "burst": 2, "max_pending": 8},
                "dns_sb_public_dns": {"qps_per_worker": 12.0, "burst": 2, "max_pending": 8},
                "unrecognized_resolver": {"qps_per_worker": 12.0, "burst": 2, "max_pending": 8}
              }
            }
          },
          "delegation": {"resolvers": null, "timeout": null, "query_rate_limit": null, "retry_attempts": 3}
        }
      ],
      "host_resolution": [
        {
          "resolvers": [{"resolver": "system_resolver", "weight": null}],
          "timeout": 5.0,
          "retry_backoff_base_seconds": 1.0,
          "query_rate_limit": {
            "enabled": true,
            "providers": {
              "system_resolver": {"qps_per_worker": 60.0, "burst": 10, "max_pending": 32},
              "google_public_dns": {"qps_per_worker": 30.0, "burst": 5, "max_pending": 16},
              "quad9_ecs_public_dns": {"qps_per_worker": 30.0, "burst": 5, "max_pending": 16},
              "cloudflare_public_dns": {"qps_per_worker": 12.0, "burst": 2, "max_pending": 8},
              "opendns_public_dns": {"qps_per_worker": 12.0, "burst": 2, "max_pending": 8},
              "controld_unfiltered_public_dns": {"qps_per_worker": 12.0, "burst": 2, "max_pending": 8},
              "dns_sb_public_dns": {"qps_per_worker": 12.0, "burst": 2, "max_pending": 8},
              "unrecognized_resolver": {"qps_per_worker": 12.0, "burst": 2, "max_pending": 8}
            }
          },
          "retry_attempts": 3,
          "ecs": {"enabled": false, "subnet": "", "scope_prefix_length": 0},
          "resolve_www_for_registrable_domain": true
        }
      ],
      "ip_location": [
        {
          "timeout": 5.0,
          "cache_ttl_days": 7,
          "policy": {
            "enabled": true,
            "match_scope": "any_ip",
            "include": {"countries": ["CN"], "regions": []},
            "exclude": {"countries": [], "regions": []}
          },
          "requires_region_lookup": false,
          "effective_provider": "ipinfo_lite"
        }
      ]
    },
    "delegation_roots": {
      "example.com": {
        "delegation_profile_id": 0,
        "input_domains": {
          "ads.example.com": {
            "manual_routing": {"manually_selected_for_filtered": false, "manually_added": false},
            "host_resolution_profile_id": 0,
            "ip_location_profile_id": 0
          },
          "cdn.example.com": {
            "manual_routing": {"manually_selected_for_filtered": false, "manually_added": false}
          },
          "example.com": {
            "manual_routing": {"manually_selected_for_filtered": false, "manually_added": false},
            "host_resolution_profile_id": 0,
            "ip_location_profile_id": 0
          }
        }
      },
      "example.net": {
        "delegation_profile_id": 0,
        "input_domains": {
          "manual.example.net": {
            "manual_routing": {"manually_selected_for_filtered": false, "manually_added": true}
          }
        }
      }
    }
  }
}
~~~

## 3. Build profiles from the assigned work

1. Use the existing planner to validate eligibility, exclusions, manual inputs, and agreement on effective settings. Use the existing balancer to assign whole root plans. Build the profile tables after those decisions during assignment projection. [Assignment projection](../src/domain_pipeline/prepare/assignment.py#L271)
2. Traverse roots and each root's inputs in lexical order. Within each stage, compare complete normalized typed values using compact JSON with sorted object keys as the equality key. Preserve array order, resolver weights, nullable values, and the full effective policy. Store a value on its first encounter in that stage's array. Use the resulting index in the assignment. Emit only entries reached by this traversal.
3. Use the full selected host resolution profile for table equality. Prepare's existing conflict check ignores the `www` flag for repeated associations for the same subdomain. The selected profile still retains the flag, since the same table also serves registrable domain inputs where the flag affects DNS. Preserve the existing stage adapters for resolver settings and IP policy.

These arrays are local to a worker. Identical effective settings from different sources share an index. Each worker directory can be restored and validated on its own, which is the reason to keep the tables beside that worker's assignments.

## 4. Validate and use the manifest

**Decode and restore.** Decode the two JSON members in the prepare to worker restore branch and check their expected identities before copying either file. Reject duplicate object keys during decoding, including nested keys, and reject numbers that are nonfinite after decoding. Python's default JSON decoder keeps the last value for a repeated key, so checking the decoded mapping alone cannot detect duplicates. Apply the same decoding rules in the worker manifest loader. Keep the existing archive member and path checks. [Restore branch](../src/domain_pipeline/pipeline_run/handoffs.py#L198) · [Python decoder behavior](https://docs.python.org/3.12/library/json.html#repeated-names-within-an-object)

**Validate before execution.** Use the shared worker manifest loader for the typed contract. Check required and allowed fields. The manifest supplies effective runtime settings and profile bodies explicitly, including nullable fields and fields with defaults in operator configuration. Every reference is a JSON integer in range for its stage. Zero is valid. Reject booleans, strings, floats, negatives, null references, and references to missing entries. Reject duplicate normalized profiles within a stage table and unused entries. An IP reference requires a host reference. A manual input carries neither reference, and its two flags are mutually exclusive. Retain full PSL validation, nonempty input maps for assigned roots, and unique normalized input domain keys across the worker. An invalid assignment uses the existing worker failure path. [Manifest loader](../src/domain_pipeline/prepare/prepare_to_worker_manifest.py#L445)

**Resolve shared settings in the worker loader.** Pass the validated metadata to worker execution. Materialize each profile once per load and let work items refer to those shared settings as read-only values. Existing adapters can make local configuration copies where needed. Use one loaded assignment for expected result coverage and runtime setup. The profile IDs are local file references. DNS cache keys, resolver identities, rate limit keys, IP cache keys, and result identities continue to use their existing inputs. Capacity discovery uses effective profile values of assigned work. [Runtime entry](../src/domain_pipeline/worker/runtime/runner.py#L274) · [Capacity discovery](../src/domain_pipeline/worker/runtime/capacity.py#L75)

**Route work by domain.** Classify each registrable domain once using the established NS/SOA policy and apply the result to each assigned input. Terminal delegation outcomes take precedence over manual routes. Under an actionable root, manual routes go to filtered and ordinary inputs take their configured stages. Host resolution queries the input itself and also queries `www.<root>` only when the input equals its registrable domain and its profile enables the flag. In the example, if the root is actionable, the `example.com` input resolves both names and `ads.example.com` resolves itself. They share settings and remain separate work items. An input's combined, deduplicated addresses go to IP location when it is enabled and addresses exist. Worker and aggregate result coverage still use root and input domain keys. [Routing](../src/domain_pipeline/worker/runtime/stages.py#L88) · [Name selection](../src/domain_pipeline/worker/host_resolution/lookup.py#L583) · [Local result coverage](../src/domain_pipeline/worker/worker_to_aggregate_manifest.py#L310)

## 5. Cutover and verification

Implement a single contract in the existing owners. Assignment builds the tables and references. The manifest writer and shared loader own JSON serialization and validation. The path layout and prepare to worker restore branch adopt `runtime-config.json`. Status initialization, runtime, status finalization, and result finalization continue through the shared loader. Staging and restore use the path layout and the workflow uploads and downloads the same directories. Update affected path and CLI fixtures and operational handoff references during implementation.

Replace the prior worker file and inline profile schema in the same cutover. The new handoff consists of the two declared JSON members and their specified field sets, with no format marker, aliases, or fallback readers. A directory containing only the prior worker input fails restore. Operator configuration and other handoffs follow their own format contracts.

Use strict TDD for each changed boundary. Start with focused failing behavior before the implementation change and rerun the affected path after it passes.

- **Projection and equality.** Verify repeated effective values share one index, different effective values remain distinct, and the same logical assignment with permuted insertion order produces the same indices. Compare every resolved root, input, manual flag, and effective setting against the original preparation plans. Include more than one worker so the test establishes that indices resolve within each worker's own manifest.
- **Rejection and identity.** Exercise JSON-only decoding, including rejection of YAML text at the JSON path, duplicate keys, invalid references, unused or duplicate entries, invalid stage combinations, invalid PSL membership, missing required fields, and unknown attribution or credential fields. Keep the restore cases for malformed or mismatched identities and verify that identity rejection occurs before copying members.
- **Entry points and routing.** Stage and restore the exact members for populated and empty assignments. Exercise manual, disabled, host-only, and host-plus-IP work through the worker entry point with controlled DNS and IP outcomes. Verify root fanout, domain-specific `www` selection, separate input routes for shared profiles, and the existing result coverage checks. Verify Aggregate can complete using the prepared-batch and worker-result artifacts.
