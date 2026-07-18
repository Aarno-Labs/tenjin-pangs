# Disposition False-Negative Reduction Plan

Status: completed 2026-07-17 (F1–F4 and per-global F5 D3 implemented; sibling corpus
remeasurement completed for all 35 non-Vim modules; the proposed co-update audit was
subsequently retired under the defined-behavior preservation contract).

This plan reduces conservative false negatives in three disposition inputs:

1. access completeness and `omega_load` attribution;
2. violation taint;
3. over-broad coupling groups that formerly blocked atomic eligibility.

The motivating case is jpegoptim's `verbose_mode`. It is a naturally aligned 32-bit
integer with direct loads/stores and one increment, but the current free atomic gate
rejects it because an unrelated high-fanout `optarg` load becomes module-wide Ω, an
unrelated varargs finding taints every global directly accessed by its function, and
function-level co-write union places it in a 39-global coupling group.

The goal is not to make `verbose_mode` pass by special case. The goal is to preserve
fail-closed behavior for genuinely unbounded accesses and relevant analysis
violations while preventing representation compression and weak correlation evidence
from becoming hard semantic blockers.

## 1. Fixed principles

- Artifact-size fallbacks must not change analysis semantics.
- A fact has one meaning. `access_set_complete` must not also encode unrelated audit
  violations or rewrite compatibility.
- Truly module-wide Ω remains a hard blocker.
- A bounded candidate set is not module-wide, even when too large to serialize in
  full.
- An audit finding blocks a global only when it can affect that global's address,
  hide an access, or prevent classification of an access that must be rewritten.
- Function-level co-write does not constrain per-global atomic handling.
- Coupling constrains only strategies that create a joint runtime object or joint
  publication.
- Any unresolved relevance query fails closed and records why.
- Existing source-qualified and bare global keys are unaffected.

## 2. Target fact model

The three questions must be represented separately:

| question | owner | result |
|---|---|---|
| Can analysis bound every possible accessor of this global? | fact assembly | `access_set_complete` |
| Can every bounded access be rewritten with the requested strategy? | D3/D4 eligibility pass | strategy certificate |
| Can a known analysis violation invalidate either conclusion? | violation relevance routing, then D3/D4 | relevant violation witness |
| Does a joint strategy need a multi-global runtime object? | coupling pass, then OnceLock/D4 | hard group and joint-strategy certificate |

`access_set_complete` therefore answers a boundedness question. It does not promise
that every bounded indirect access already has an atomic rewrite recipe.

Because this changes the documented meaning of existing schema-v2 facts, the first
artifact emitted with the new semantics should use schema version 3. Offline
`pangs-dispose` must continue rejecting newer schemas rather than silently applying
schema-v2 policy to schema-v3 facts.

## 3. Access completeness structural fix

Narrow external pointer summaries are a complementary analysis-side refinement: they
can prevent a known pure libc return value from becoming Ω before this fact model is
applied.  See [the libc pointer-summary plan](PLAN_LIBC_POINTER_SUMMARIES.md).
The [ExposedGlobals domain prototype](PLAN_EXPOSED_GLOBALS_DOMAIN.md) separately
preserves whether a remaining Ω pointer can reach no module globals, only globals in
the run's exported-or-address-escaped exposure surface, or every module global.

### 3.1 Replace the overloaded empty-vector convention

Today `ModRef.pointee_globals.is_empty()` can mean either:

- the target is genuinely unbounded; or
- the target has a complete finite set that was omitted from JSON by the high-fanout
  fallback.

The latter already retains complete IDs in the internal field named
`stationarity_pointee_globals`. Fact assembly ignores that field and widens an empty
export vector to every global.

Introduce a shared internal representation:

```rust
pub enum GlobalCandidateSet {
    Finite(Rc<[GlobalId]>),
    ModuleWide,
}
```

Every `GlobalTarget::Unknown` mod/ref row must carry exactly one
`GlobalCandidateSet`. `Finite` is a complete set and may be large. `ModuleWide` means
analysis cannot enumerate a sound finite set. A finite empty set is allowed only for
a row proven not to touch any client-visible global; it is not another spelling of
`ModuleWide`.

Replace `stationarity_pointee_globals` with this general field. During migration,
construct the new enum with this precedence:

1. a non-empty retained ID set becomes `Finite(ids)`;
2. a non-empty legacy `pointee_globals` list is resolved to `Finite(ids)`;
3. a row whose module-global targets are genuinely unbounded (top, int-to-pointer,
   or an external result without retained module-global provenance) becomes
   `ModuleWide`; external/heap memory does not by itself widen a complete finite set
   of module-global candidates;
4. any ambiguous legacy empty row becomes `ModuleWide`.

### 3.2 Centralize affected-global expansion

Add one API helper used by disposition, stationarity, registry analysis, and future
eligibility passes:

```rust
pub enum AffectedGlobals<'a> {
    Finite(&'a [GlobalId]),
    ModuleWide,
}

pub fn affected_globals(&self, row: &ModRef) -> AffectedGlobals<'_>;
```

Remove client-local interpretations of `pointee_globals.is_empty()`, including the
copies in `DispositionFactRows::new` and `registry_access_facts`. This prevents
stationarity, signal/thread reachability, and disposition from drifting.

### 3.3 Keep exports bounded without deleting semantics

The ordinary mod/ref export remains corpus-bounded. For unknown rows, emit:

```jsonc
{
  "global": { "unknown": "omega_load" },
  "candidate_scope": "finite-collapsed", // "finite" | "finite-collapsed" | "module-wide"
  "pointee_global_count": 32,
  "pointee_global_sample": ["all_normal", "..."],
  "pointee_global_hash": "..."
}
```

Small finite sets may continue emitting the full `pointee_globals` list. Large sets
retain all IDs in process but export only count, deterministic sample, and hash.
`module-wide` is explicit and never inferred merely from an empty JSON array.

Update `schemas/modref.schema.json` additively for these fields. Schema-v3 disposition
facts consume the internal enum, never the sample.

### 3.4 Define access completeness precisely

For a defined mutable global `g`, `access_set_complete(g)` is false if any of these
holds:

1. a `ModuleWide` unknown access can reach module globals;
2. `g`'s address escapes to unanalyzed code;
3. in library mode, `g` is exported by the analysis-level exported bit;
4. lowering reports an access-bearing construct for which no access site can be
   represented at all.

A `Finite(ids)` row affects only members of `ids`; it never invalidates an unrelated
global. A finite ambiguous access to `g` is bounded, so it does not by itself make the
set incomplete. D3/D4 must separately decide whether that access has a valid rewrite
recipe.

Violation findings are removed from `access_set_failure`. They are routed separately
as described in §4.

### 3.5 Access-completeness acceptance tests

- A high-fanout row with 32 retained candidates and an abbreviated export affects
  only those 32 candidates.
- A global outside that set remains access-complete.
- A true `ModuleWide` row fails every applicable global.
- A finite empty set does not widen to the module.
- Export sampling, ordering, or threshold changes do not alter disposition facts.
- Registry signal/thread propagation and stationarity use the same affected set.
- The jpegoptim `optarg[strlen(optarg)-1]` row does not fail
  `access_set_complete(verbose_mode)`.

## 4. Violation relevance instead of function-wide quarantine

### 4.1 Current problem

The current rule marks `violation_taint(g)` whenever a function containing any audit
finding has a direct or aliased mod/ref row for `g`. It then uses that bit twice:

- as a universal cascade veto; and
- as a fallback reason for `access_set_complete=false`.

For jpegoptim, a varargs finding around `fprintf` in `my_output_message` taints the
direct scalar load of `verbose_mode`, even though the global's address and loaded
value do not participate in the unsupported pointer operation.

### 4.2 Add relevance classifications

For each `(finding, global)` pair proposed by function-local co-occurrence, classify:

```text
address-relevant
access-shape-relevant
value-only
unrelated
unresolved
```

- `address-relevant`: an affected value reaches the address node of an access to the
  global, the global object, or an alias set containing it.
- `access-shape-relevant`: the finding occurs at or dominates an unclassified access
  that D3/D4 would need to rewrite.
- `value-only`: the global's loaded value reaches the finding, but the finding cannot
  hide or redirect an access. This remains audit evidence but is not automatically a
  disposition veto.
- `unrelated`: no PAG/value-flow/control relevance to an access of the global.
- `unresolved`: analysis cannot answer; fail closed.

Only `address-relevant`, `access-shape-relevant`, and `unresolved` set the hard
`violation_taint` fact. `value-only` and `unrelated` findings are retained in an
analysis diagnostic collection and measurement counts.

### 4.3 First implementation boundary

Implement the initial classifier conservatively:

1. collect the finding's affected values and corresponding PAG nodes;
2. collect address nodes for all access sites of `g` in the containing function;
3. test reachability/intersection through the existing points-to/value-flow graph;
4. treat direct named scalar accesses as independent unless an affected value reaches
   their address/object or the access itself is unclassified;
5. classify missing nodes, truncated traversal, and Ω reachability as `unresolved`.

Do not use source-line distance or “same function” as relevance evidence.

### 4.4 Route violations to strategy passes

Fact assembly emits the relevance result and witness. D3/D4 then fail a certificate
only when the relevant finding can invalidate that strategy's access or rewrite
proof. The cascade retains a top-level hard veto for `unresolved` and known
address-relevant violations.

Remove the violation fallback from `access_set_failure`; otherwise the same evidence
continues to veto twice and the fact remains semantically misleading.

### 4.5 Violation acceptance tests

- An unrelated external-varargs finding in a function with a direct scalar load does
  not taint that global.
- A finding whose affected value reaches an indirect address of `g` remains a hard
  veto.
- A truncated/Ω relevance query remains a hard veto with code
  `violation-relevance-unresolved`.
- Findings remain present in audit artifacts even when disposition relevance is
  `value-only` or `unrelated`.
- `my_output_message` no longer hard-taints `verbose_mode` solely because of its
  `fprintf` finding.

## 5. Coupling: keep it out of per-global atomic eligibility

### 5.1 Original problem

The coupling pass joins every global directly written by the same function. A large
option parser therefore creates a star, and union-find transitively turns weak
function-level correlation into a large hard group. Atomic's singleton-group gate
then rejects every member.

For jpegoptim, `parse_arguments` couples `verbose_mode` to `csv`, while `main`
couples it to `average_count`; transitive union produces a 39-member group without
evidence of a 39-variable consistency invariant.

### 5.2 Final rule

Same-function co-writes are not collected. They neither prove a joint invariant nor
constrain conversion of an eligible scalar global to an atomic. D3 is strictly
per-global and has no hard-group gate, suspected-edge discharge, or dynamic co-update
audit.

Hard `coupling_groups` remain only for strategies that create joint publication or a
joint runtime object. The current producer derives them from compatible OnceLock
publication intervals and shared initialization subtrees. The deprecated
`coupling_candidates` field remains empty for manifest schema compatibility.

Acceptance requires an option parser writing several globals to create no co-write
inventory, while a real common-publication fixture still receives deterministic hard
group evidence for joint OnceLock/Mutex decisions. Members of such a hard group remain
individually eligible for atomic handling.

## 6. Implementation sequence

### F1 — Candidate-set semantics

- Add `GlobalCandidateSet` and construct it at every unknown mod/ref producer.
- Add the central affected-global helper.
- Migrate stationarity, registry facts, and disposition indexing.
- Add bounded export metadata and schema tests.
- Preserve module-wide widening for genuinely unbounded rows.

Acceptance: focused tests pass, ordinary export sizes remain bounded, and changing
the high-fanout threshold does not change disposition facts.

### F2 — Pure access completeness

- Rewrite `DispositionFactRows.access_failure` around the shared candidate semantics.
- Remove violation findings from `access_set_failure`.
- Add separate diagnostics for bounded-but-indirect accesses that D3 must classify.
- Recompute the free gates on Vim and the sibling corpus.

Acceptance: jpegoptim's unrelated high-fanout `optarg` row no longer poisons
`verbose_mode`; true module-wide fixtures still fail closed.

### F3 — Violation relevance

- Add finding-to-access relevance indexing.
- Emit relevance classifications and deterministic witnesses.
- Narrow `violation_taint` to hard-relevant and unresolved cases.
- Update cascade traces and measurement histograms.

Acceptance: the jpegoptim `fprintf` finding remains audited but does not veto the
direct atomic access proof for `verbose_mode`; address-relevant fixtures still veto.

### F4 — Coupling scope

- Remove function-co-write candidate construction.
- Retain only hard common-publication edges for joint strategies.
- Keep atomic eligibility independent of hard groups.

Acceptance: option-parser fixtures emit no candidates, true publication fixtures
remain grouped, and their members can still receive per-global atomic certificates.

### F5 — D3 integration and remeasurement

- Implement or update D3 to consume bounded access sites and relevant violations.
- Require a rewrite recipe for every load, store, RMW, address-taking use, declaration,
  and cross-TU access.
- Require target-guaranteed lock-free atomics for signal-context accesses.
- Rerun Vim, all sibling bitcode, and PHP when available.

Acceptance: every newly eligible global has a complete D3 certificate; free-gate
counts and certified counts are reported separately.

## 7. Required measurements

### 2026-07-17 sibling-corpus remeasurement

The expanded sibling corpus includes the newly added `exe-pure-O0.bc`.  Excluding the
two Vim modules and PHP, all 35 modules completed with `--dispose`.  The OpenSSL
measurement required a larger scratch volume: it took 310.34 seconds, peaked at
32.97 GiB RSS, and emitted 3.0 GiB of ordinary raw-analysis artifacts before the
disposition pair.

Across the 35 completed modules: 1,687 mutable definition globals were considered;
202 chose `immutable`, 14 chose `atomic`, and 1,471 remained `unhandled`.  The static
D3 certificates are the five JPEGoptim globals (`average_count`,
`compress_err_count`, `decompress_err_count`, `verbose_mode`, `worker_count`) in both
O0 and O1, and four YAPET O0-g globals (`cat.catcolorspace`, `cats_capacity`,
`ncats`, `report_error`).  `exe-pure-O0.bc` has no mutable definition globals.

The remaining dominant access-completeness blocker is genuine module-wide access:
1,578 globals, versus 79 with `external-escape`. The historical run also measured 116
suspected components with 646 co-write edges; that inventory is now retired because it
does not bear on defined-behavior-preserving atomic conversion.

Each corpus run records:

- finite exact, finite collapsed, and module-wide unknown rows;
- globals failed by each category;
- candidate-set fanout p50/p95/max;
- violation relevance counts by classification and finding kind;
- hard joint-strategy group counts and group-size percentiles;
- atomic funnel counts after each condition;
- newly eligible globals and the witness removed relative to the baseline;
- runtime, peak RSS, and artifact-size deltas.

The comparison must be paired by global key. Aggregate improvements alone are not
sufficient: every changed false-to-true fact needs the old witness, new explanation,
and final D3 outcome.

## 8. Soundness review gates

Before enabling the new facts in production policy:

1. Differentially compare old and new affected-global expansion. Every removed
   global/row pair must be justified by a finite retained candidate set.
2. Confirm that no `ModuleWide` row becomes finite merely because its export contains
   a sample.
3. Review every violation kind newly classified `value-only` or `unrelated`; unknown
   kinds default to `unresolved`.
4. Review hard common-publication groups on the synthetic invariant fixtures.
5. Keep an environment-controlled diagnostic mode that emits the full finite
   candidate list and relevance paths for audit runs without expanding default
   artifacts.

## 9. Expected jpegoptim outcome

After F1–F4, `verbose_mode` should have:

- a complete access set because the high-fanout `optarg` load has a finite candidate
  set that excludes it;
- no hard violation taint from the unrelated `fprintf` varargs finding;
- no coupling group or candidate inventory from option-parser co-write alone;
- retained `signal_context_access=true`, which continues to reject mutex;
- retained `word_sized_scalar=true`.

That makes it a D3 candidate, not automatically certified. D3 must still prove all
direct and indirect accesses, rewrite `verbose_mode++` as an atomic RMW, update every
cross-TU declaration/access, and require a lock-free 32-bit target atomic because the
signal handler reads it.
