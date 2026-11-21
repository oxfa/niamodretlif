# Action Plan: Registrable-Domain Work and Aggregate Filtering

**Status:** implemented.

## Decisions

- This is a pipeline-wide design, not a block-only special case.
- Prepare cleans each source according to its configured format: remove comments, blank lines, and invalid lines. A valid line that is not a domain line is not invalid and remains in the source archive.
- Prepare extracts and deduplicates registrable domains for worker processing.
- Prepare creates one GitHub artifact per configured worker. Each contains only that worker's registrable-domain worklist.
- Workers check NS/SOA actionability for their assigned registrable domains. They do not receive source text or decide how source lines are formatted.
- Prepare separately gives the aggregator a fixed-path archive of cleaned source records and an index from registrable domain to source ordinal and line number(s). The aggregator does not need original filenames or a source-line-to-domain mapping.
- Unmatched manually added domains are handed to aggregation separately and are not appended to that configured-source archive.
- Aggregation uses the root outcomes and index to filter unactionable domain lines, preserves other valid source content, and produces each configured output format.
- Implement the new contract directly; do not add legacy-format readers or fallback compatibility paths.

## Implementation steps

1. **Prepare source records** — complete
   - Add format-aware handling that distinguishes comments/blanks, invalid lines, domain lines, and valid non-domain lines.
   - Keep valid non-domain lines in the cleaned archive.
   - For supported domain patterns, derive the registrable domain and record the source ordinal and line number.

2. **Build worker worklists and aggregator inputs** — complete
   - Deduplicate registrable domains and partition them across the configured workers.
   - Produce exactly one worker artifact per configured worker, including an empty worklist where applicable.
   - Write the cleaned source archive and registrable-domain-to-line index for the aggregator at fixed batch paths.

3. **Run root checks** — complete
   - Have each worker consume only its own registrable-domain artifact.
   - Return NS/SOA outcomes by registrable domain.

4. **Filter and render in aggregation** — complete
   - Load the cleaned source archive and line index.
   - Use unactionable registrable-domain outcomes to filter indexed domain lines.
   - Preserve other valid source lines and render outputs according to each configured format.
   - For a supported line containing multiple targets, remove only unactionable targets as previously decided.

5. **Update GitHub artifact flow** — complete
   - Publish uniquely named worker artifacts and have each worker download only its matching artifact.
   - Keep the source archive and line index on the prepare-to-aggregator path.
   - Make aggregation consume the source archive/index and all worker outcomes.

6. **Validate** — complete
   - Test format-aware removal of comments/invalid lines while preserving valid non-domain lines.
   - Test deduplication and worker partitioning of registrable domains, including empty worker artifacts.
   - Test source line indexing and aggregation filtering for actionable and unactionable roots.
   - Test the configured output formats and the worker/aggregator artifact handoffs.
