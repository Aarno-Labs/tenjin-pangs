# Atomic Co-Update Runtime Audit Plan

Status: design audited 2026-07-17; implementation pending the C materializer.

This is the remaining runtime half of D3.  A static D3 certificate may discharge a
suspected co-write edge only as weak evidence.  It is not production authority for
the atomic rewrite until this test-build audit has run without a finding on a
representative stress or sanitizer test suite.  This document deliberately specifies
the analysis/materializer boundary without requiring C-to-Rust translator work.

## 1. Scope and invariant

For every `atomic_eligibility: certified` global that records a
`co-write-only-direct-endpoints-no-joint-reader` resolution, audit each resolved
suspected pair separately.  The pair is the two edge members, not every member of the
candidate component.  Thus a large option-parser candidate creates several small,
reviewable obligations rather than one artificial 39-global transaction.

The audit asks one concrete question: while a dynamic invocation of a function that
writes both endpoints is open, did another thread access either endpoint?  A positive
answer is an interleaved-update window and is a stop-ship finding for the affected
pair.  It is intentionally conservative: a reported window is evidence to review,
not proof that a source-level invariant was violated.

The audit is not a race detector and does not establish the absence of a window that
the test suite did not execute.

## 2. Analysis-owned audit plan

Extend the certified D3 certificate with a `co_update_audit` object.  It is emitted
even before instrumentation is available so a materializer can reject a production
atomic rewrite unless the plan is `instrumentable` and a matching clean runtime
report is supplied.

```jsonc
{
  "status": "instrumentable",
  "pairs": [{
    "id": "coa-<stable-hash>",
    "candidate": "cand-…",
    "members": ["file.c::left", "file.c::right"],
    "co_write_functions": [{ "function": "file.c::update", "site": { /* Site */ } }],
    "endpoint_accesses": [
      { "member": "file.c::left", "operation": "store", "function": "…", "site": { /* Site */ }, "statement_index": 17 }
    ]
  }]
}
```

`id` is the deterministic hash of the candidate id plus the sorted two member keys.
It is stable across evidence-site ordering.  `endpoint_accesses` includes every
source-mapped, direct load/store/RMW of both endpoints, not just the endpoint being
made atomic.  The existing D3 recipe supplies the certified member's entries; fact
assembly must additionally collect the neighbor entries.

The plan is `blocked` (with one canonical code and witness per pair) if an endpoint
access is indirect, unmapped, or its co-write function has no source location.  A
blocked plan does not revoke the static certificate, but it prevents a production
materialization.  Its explicit status makes that distinction visible rather than
silently treating a missing probe as a clean audit.

## 3. Test-build instrumentation contract

The C materializer emits probes only under `PANGS_CO_UPDATE_AUDIT`:

1. At entry and every exit of each `co_write_function`, call
   `pangs_coa_begin(pair_id)` / `pangs_coa_end(pair_id)`.  The runtime keeps a
   thread-local nesting count, so recursion and nested co-write functions are safe.
2. Immediately before every listed endpoint load, store, or RMW, call
   `pangs_coa_access(pair_id, member_index, access_kind, site_id)`.
3. The runtime records the active thread and depth for each pair.  If an access from a
   different thread occurs while a pair is active, it emits one deduplicated JSONL
   finding containing the pair id, both member keys, active and observing thread ids,
   access kinds, and both source sites.  It must be async-signal-safe: append a fixed
   binary record to a nonblocking pipe or pre-opened file descriptor; JSON conversion
   happens after the test process exits.
4. The test harness converts records to `pangs-atomic-audit.jsonl`; any finding is a
   nonzero audit result.  A clean result names the input manifest SHA-256 and every
   instrumented pair id, so reports cannot be reused for a changed manifest.

The materializer must reject a `blocked` plan, an absent report, a manifest-hash
mismatch, or a report that omits an instrumentable pair whenever production atomics
are requested.  Developers may still emit atomics in an explicitly non-production
experiment, but the manifest must retain that accepted risk.

## 4. Corpus audit of the current static certificates

The 2026-07-17 sibling-corpus remeasurement has 14 static D3 certificates.  All
suspected-edge resolutions occur in two candidate components:

- JPEGoptim O0/O1: the option-parser candidate.  Five certified globals each; their
  resolved pairs are direct co-writes in `parse_arguments`, `wait_for_worker`, and
  `write_markers`/`optimize` paths.  The O1 evidence has source sites; the O0 variant
  has empty co-write evidence sites, so it would be `blocked` by this audit contract
  until the build supplies function source metadata.
- YAPET O0-g: `cats` is certified with the `cats_capacity` and `ncats` pairs.  Its
  co-write evidence likewise needs source locations before runtime probes can be
  inserted.

This is the intended separation: these are useful static candidates, but none becomes
production-ready merely because its suspected edge was statically discharged.

## 5. Implementation and acceptance

1. Add the `co_update_audit` certificate schema and canonicalization, then build its
   per-pair plan in D3 from coupling evidence plus both endpoints' `AccessSite`s.
2. Add fixtures for an instrumentable two-global updater, an unmapped evidence site,
   and an indirect neighbor access.  Assert stable pair ids and that only the latter
   two block the runtime plan.
3. Add the small C runtime and a test materializer fixture.  Exercise one forced
   interleaving (must report) and one single-threaded update (must stay clean).
4. Gate production atomic materialization on a clean, complete report as described
   above.  Record the report identity in the materialization/audit ledger.

The implementation starts with step 1; actual probe insertion is intentionally held
at the C-materializer boundary, which remains outside the current translator scope.
