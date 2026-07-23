# Monotone On-the-Fly Indirect-Call Discovery

**Date:** 2026-07-23  
**Primary implementation:** `crates/pangs-solve/src/andersen.rs`  
**Design context:** `DESIGN_lite.md` §2 D', `PLAN-M1_lite_delta.md` §M1.4b,
`PLAN-M2_lite_delta.md` §M2.0

## 1. Goal

Replace Andersen's current subtractive call-graph refinement loop with one joint,
monotone least-fixed-point computation over:

1. points-to facts;
2. dynamically instantiated indirect-call bindings; and
3. the copy/load/store/GEP/memcpy constraints induced by those bindings.

Today the refiner starts every non-exact indirect callsite with its complete
`FSA ∩ Steensgaard` target envelope, solves that fixed graph from scratch, removes
targets not justified by the resulting Andersen points-to sets, and repeats. Every
completed round is conservative, but broad speculative call bindings can create large
points-to relations and dense copy cycles before being discarded. YAPET is the motivating
case: its broad round-0 call graph contributes hundreds of speculative bindings to the
expensive partition.

The replacement will:

- start with base PAG constraints, boundary seeds, and B2/B1 exact overrides;
- discover a non-exact target only when its function object reaches the call operand;
- add that target's argument/parameter and return/result bindings exactly once;
- resume the existing delta solver without throwing away points-to state;
- stop only when both points-to propagation and target discovery are quiescent.

Version 1 will discover targets in batches at solver-quiescent boundaries. It will not
install per-cell event watchers. This gets the principal benefit—no speculative round-0
bindings and no from-scratch re-solves—without coupling callsite bookkeeping to SCC
representatives. Event-driven discovery remains a possible measured optimization.

## 2. Non-goals

- Do not replace Steensgaard. Its classes remain the sound target envelope, partitioning
  substrate, base-tier answer, and fallback.
- Do not change FSA compatibility, B1/B2 exactness proofs, B3 confined-target semantics,
  external-memory provenance, or field abstraction.
- Do not remove copy-edge delta propagation, incremental memcpy joins, or copy-SCC
  collapse. The new construction must reuse them.
- Do not implement per-partition exhaustion salvage in version 1.
- Do not retain the subtractive implementation permanently. It is a temporary
  differential oracle during migration.
- Do not emit a partial ascending solution under any budget, cap, timeout, cancellation,
  or internal-abort path.

## 3. Fixed-point semantics

Let:

- `E(site)` be the non-exact site's sound Steensgaard target envelope after FSA
  compatibility and B3 confined-target subtraction;
- `X(site)` be a B1/B2 exact override, when one exists;
- `P` be the current points-to relation;
- `T` be the activated indirect-call target relation; and
- `bind(site, f)` be the parameter, return, and external-boundary constraints for calling
  `f` at `site`.

The joint rules are:

```text
P += base PAG constraints and Ω seeds
T += X(site)                                      for exact sites
P += bind(site, f)                                for (site, f) in T
T += (site, f) when f ∈ E(site) and &f ∈ P[operand(site)]
T += (site, f) for all f ∈ E(site) when P[operand(site)] contains a
                                                  fn-ptr-capable external region (§3.2)
```

All rules only add facts. Starting from grounded address-of, direct-call, entry, boundary,
and exact-override facts computes the least fixed point of this positive system. Region
reachability is itself monotone, so the eager unknown-origin rule preserves the positive
character of the system and its termination bound.

The current descending implementation instead starts from `E` and repeatedly applies the
points-to-derived target filter. It can retain a mutually supporting target cycle with no
grounded address flow. The additive construction removes such self-justifying cycles.
That is a precision improvement only if the seed and unknown-origin models are complete;
the seed audit in §8 is therefore a release gate.

### 3.1 Target-set invariants

- Exact sites are pinned to `X(site)`. Discovery never adds to or removes from them.
- Non-exact target sets grow monotonically.
- Every non-exact activated target is a member of `E(site)`.
- `E(site)` remains derived from the Steensgaard result, so the existing M2.0
  `Andersen ⊆ Steensgaard` subset tripwire remains authoritative.
- Function allocation cells inside points-to sets retain their original identities.
  Copy-SCC representatives canonicalize constraint-graph variables only, so SCC collapse
  must not canonicalize function objects before target lookup.

### 3.2 Unknown-origin callees

An absent named function object is not evidence that an unknown-origin operand cannot call
client code. Before switching the default path, audit every producer of
`unknown_callee` and every function-pointer-capable external region.

The conservative version-1 rule is:

- apply the unknown/external call summary from the beginning; and
- for a non-exact site whose origin can denote an internal function without an explicit
  named-object flow, eagerly activate its remaining Steensgaard envelope.

The eager trigger has two detection times:

- **static**: categories identifiable at construction (an operand seeded directly by a
  forged-pointer or boundary region) register their eager bindings in
  `build_base_solve()`;
- **dynamic**: most unknown origins emerge mid-solve, when a function-pointer-capable
  external region cell first appears in `P[operand(site)]`. Target discovery must
  therefore also report region-reachability events, and the outer loop must activate the
  affected site's remaining envelope at the same batch boundary — idempotently, once per
  site.

Such a site gains no additive-callgraph precision and should retain Steensgaard fallback
provenance for its target answer. This is preferable to silently omitting effects of an
internal callback. Note that it is also deliberately *more* conservative than the current
descending path, whose final converged solve equally omits the narrowed-away bindings'
flows and relies on the `unknown_callee` flag alone; the eager bindings additionally
model caller-side argument/return flows of a possible internal callback. Two
consequences:

- eager sites — and facts transitively derived from their bindings, which can reach
  otherwise-unrelated sites — cannot participate in a naive `additive ⊆ subtractive`
  check; §7 splits the differential into two modes for exactly this reason;
- the emitted `unknown_callee` flag becomes load-bearing under additive construction and
  is hardened to the OR of the Steensgaard escape verdict and the Andersen-side
  observation that `P[operand(site)]` contains a function-pointer-capable or universal
  external region.

The audit may prove that some `unknown_callee` categories denote only
foreign code; those may use the external summary without eager internal bindings, but the
proof and category must be recorded in code and tests.

Integer-forged function pointers, inline assembly, exported/library callbacks, external
returns, external storage loads, escaped function parameters, and varargs are mandatory
audit cases.

## 4. Early-exit safety boundary

This is the central correctness change.

Every completed descending round is an over-approximation, so the current
`rounds >= MAX_ROUNDS` exit can still emit a sound—if less precise—answer. A partial
ascending solve is an under-approximation: undiscovered targets have not installed their
flows. No partial result from the new solver is emittable.

Represent completion structurally:

```rust
enum RefinerOutcome {
    Complete(RefinerOutput),
    Exhausted(ExhaustionDiagnostic),
}
```

Only `Complete` contains refined indirect calls, node resolutions, or global points-to
rows. An `Exhausted` value must not contain a `Solve` or any row that `finish_andersen`
could accidentally overlay.

`finish_andersen` already begins with the complete Steensgaard `base` and selectively
overwrites `base.indirect_calls`, `base.nodes`, and `base.node_points_to`. Therefore:

- `Complete`: apply all normal Andersen overlays.
- `Exhausted`: apply no Andersen node or global-points-to overlay; retain the complete
  Steensgaard rows already in `base`.
- On `Exhausted`, non-exact indirect sites retain their Steensgaard answers with
  `fallback: true`.
- B1/B2 exact callsites retain their independently proven exact target lists with
  `fallback: false`. Preserve the current `unknown_callee` semantics unless the B1/B2
  contract is separately changed.
- Never retain node/global facts from the abandoned solve merely because exact bindings
  contributed to them. Other missing bindings could still make those facts incomplete.

This is a whole-tier fallback in version 1. Because the current solver runs all admitted
partitions in one `Solve`, exhaustion discards every Andersen refinement produced by that
solve.

### 4.1 Budgets and caps

- Replace `MAX_ROUNDS`'s graceful-break semantics with exhaustion-to-fallback.
- Count propagation steps cumulatively across every resume of the same `Solve`.
- A step budget, timeout, cancellation, allocation guard, or resume-round cap must all
  return `Exhausted`.
- At a propagation boundary, check joint quiescence before declaring exhaustion. A state
  with an empty points-to worklist but discovered, unbound targets is not complete.
- Provide deterministic injection controls for tests:
  - exhaustion during propagation;
  - exhaustion immediately after target discovery and before activation; and
  - exhaustion after activation but before the resumed propagation completes.

If no production step cap is enabled initially, retain a high joint-resume safety cap, but
route it through the same fallback outcome. Termination is otherwise bounded by the finite
set of `(callsite, envelope target)` pairs and the existing finite cell/offset domain.

### 4.2 Diagnostics and metrics

Exhaustion is a performance defect signal, not a normal precision choice. Emit:

- the limit/reason that fired;
- cumulative propagation steps;
- completed resume phases;
- current worklist and queued-cell counts;
- pending copy-edge seeds and pending points-to deltas;
- known discovered-but-not-yet-activated target pairs and their callsites;
- activated target count;
- SCC passes/nodes collapsed/edges removed;
- memcpy pairs and copy-fact pairs processed.

A mid-propagation target backlog is necessarily incomplete—more targets may be hidden
behind pending facts—so label it `known_unbound_targets`, not `remaining_targets`.

Add a global result/metrics indication that the Andersen tier was abandoned, even though
node rows themselves remain the base-tier rows. Suggested additive fields are:

```text
andersen_complete: bool
andersen_exhaustion_reason: optional enum/string
andersen_steps: integer
andersen_resume_rounds: integer
andersen_activated_targets: integer
andersen_known_unbound_targets: integer
```

Keep existing oversize-fallback metrics distinct: oversize partitions are rejected before
the solve, while exhaustion abandons a solve that began.

## 5. Solver integration

### 5.1 Separate construction from propagation

Refactor `solve_once` into:

1. `build_base_solve()`:
   - allocate one `Solve`;
   - add in-scope PAG constraints;
   - apply Ω/boundary seeds;
   - register exact bindings and statically detectable eager unknown-origin bindings
     (§3.2); dynamically detected unknown origins are activated from the discovery loop;
2. `activate_target(&mut Solve, site, function)`:
   - idempotently record `(site, function)`;
   - add argument-to-parameter copies;
   - add return-to-result copies;
   - apply an external-call summary once when required;
3. `run_with_budget(&mut Solve, &mut Budget)`:
   - resume the existing delta worklist;
   - preserve cumulative counters;
   - report quiescence or exhaustion;
4. `discover_targets(&Solve)`:
   - inspect each non-exact in-scope call operand;
   - canonicalize the operand through `points_to`;
   - map function-object cells to PIR function indices;
   - intersect explicitly with the site's stored `E(site)`;
   - report sites whose operand set newly contains a function-pointer-capable external
     region (§3.2 dynamic eager trigger);
   - return only target pairs and eager sites not previously activated.

The outer loop becomes:

```text
build base solve
activate exact/eager targets
loop:
    run to points-to quiescence, or exhaust
    discover new target pairs and newly unknown-origin sites
    if neither: joint LFP is complete
    if resume cap would fire: exhaust
    activate all new pairs and eager envelopes
```

Batch activation makes the result independent of target enumeration order. Sort target
pairs before activation for deterministic diagnostics and tests.

### 5.2 Reuse delta propagation

`Solve::add_copy` already has the required late-edge behavior:

- canonicalize source and destination;
- seed a new edge once with the source's complete existing facts;
- thereafter propagate only new deltas.

Indirect argument/parameter and return/result bindings must use `add_copy`; do not insert
directly into `succ`.

### 5.3 Canonicalizing dynamic-constraint helpers

Call activation after an SCC collapse can add more than copy edges. In particular,
`apply_external_call_effects` and vararg handling currently append directly to
`solve.stores`. Direct map insertion is safe only before the initial run.

Add idempotent registration helpers for every constraint that may be installed after
propagation begins, at minimum:

```text
add_store(base, value, provenance)
add_load(base, destination)       if needed by future summaries
add_gep(base, offset, destination) if needed by future summaries
add_memcpy(destination, source)    if needed by future summaries
```

Each helper must:

- canonicalize constraint-graph owner cells;
- deduplicate the constraint;
- enqueue the owner even when it has no pending points-to delta;
- cause the complete current owner points-to set to instantiate the newly added
  constraint exactly once; and
- remain valid if the owner was previously collapsed into an SCC representative.

For version 1, external-call summaries are the immediate dynamic-store consumer.
Track per-callsite summary activation so multiple compatible external targets do not
append duplicate boundary effects.

### 5.4 SCC collapse

SCC collapse is compatible with monotone call discovery:

- target lookup calls `Solve::points_to(original_operand)`, which resolves through the
  representative;
- function objects in returned sets are allocation identities and remain uncollapsed;
- late copy bindings already canonicalize old member IDs;
- new call edges contribute to the existing geometric SCC trigger.

Extend the SCC regression fixture so a call operand collapses before its target is
discovered, then verify that activation through the original operand and parameter IDs
still propagates correctly.

No callsite-watcher relocation is needed in the batched implementation. If an event-driven
version is later attempted, watchers must be merged or resolved through representatives.

## 6. Exact overrides and fallback assembly

Build a reusable exact-override patcher for `base.indirect_calls`:

- locate every exact callsite by key;
- replace only its `targets`;
- set `fallback: false`;
- retain the currently defined `unknown_callee` value;
- assert the exact list narrows the FSA/Steensgaard envelope.

Use the same patcher in both successful and exhausted assembly so exact precedence cannot
drift between paths.

Do not treat `targets = ∅ ∧ !unknown_callee ∧ !fallback` as a production error by itself.
The Andersen tier does not carry a callsite-reachability predicate, and a reachable
function can contain an unreachable indirect call whose operand has no grounded
points-to facts. The `mismatched_offsets_do_not_match` fixture also legitimately refines
a broad Steensgaard candidate to an empty set. Missing-grounding detection therefore
belongs in the seed audit and additive/subtractive differential, where reachability and
the source of the strict subset can be examined, rather than in an unconditional emitter
fallback.

For successful runs:

- exact sites emit the pinned exact list;
- in-scope non-exact sites emit activated additive targets;
- uninteresting, oversize, and conservatively eager unknown-origin sites emit their
  Steensgaard target answer with appropriate fallback provenance;
- refined node/global rows overlay the base exactly as today.

For exhausted runs:

- invoke only the exact-override patcher;
- mark every non-exact indirect site as fallback;
- perform no node/global overlay;
- record global Andersen incompleteness diagnostics.

## 7. Temporary subtractive differential

Keep the current descending path behind a test/diagnostic-only switch during migration.
Do not expose it as a permanent client choice.

Eager unknown-origin activation (§3.2) deliberately installs bindings the descending
final solve lacks, so a single-mode comparison would report spurious non-subsets both at
eager sites (envelope answer vs. narrowed answer) and at innocent sites reached by an
eager binding's flows. Run the differential in two modes.

**Mode 1 — pure-LFP oracle comparison** (eager unknown-origin activation disabled).
Compare against a descending run built from the same PIR/PAG, exact overrides, confined
targets, budget, and Steensgaard base, using only descending runs that converged rather
than hitting the round cap. Both paths are then fixed points of the same target-derivation
operator and the additive result is the least one, so these checks are exact, not
heuristic:

- pure-additive non-exact targets must be a subset of descending targets per site — a
  strict subset is a removed ungrounded cycle, a missing seed/summary, or a
  constraint-generation asymmetry between the paths, never noise;
- both must remain subsets of the Steensgaard envelope;
- exact sites must be identical;
- pure-additive node/global allocation sets should narrow the descending semantic sets
  where their representations are directly comparable;
- additive external/unknown flags must not become less conservative without an audited
  provenance reason;
- downstream callgraph, mod/ref, escape, stationarity, disposition, and localization
  artifacts receive subset/soundness-oriented differential checks.

**Mode 2 — default (eager) mode self-checks:**

- per non-exact site, default-mode targets ⊇ pure-mode targets and ⊆ the Steensgaard
  envelope;
- every default-mode fact absent from the pure-mode run traces to an eager activation;
- every eager site carries fallback provenance and the hardened `unknown_callee`
  observation (§3.2).

Every Mode-1 strict target subset is triaged as one of:

1. an ungrounded self-supporting cycle removed by the least fixed point;
2. a missing seed, summary, or activation rule;
3. an expected representation difference with a written justification.

Use the dynamic-trace validation discipline from `DESIGN.md` §9 to catch missing observed
edges on divergent sites. A trace can demonstrate a false negative but cannot prove that
an unobserved edge is infeasible.

Delete the descending implementation after:

- the synthetic soundness suite is complete;
- corpus differentials have been triaged;
- YAPET and Vim have repeated clean runs;
- no unexplained strict subset remains; and
- the additive path has been the default for a stabilization interval.

## 8. Implementation stages

### Stage 0 — Freeze baselines

- Record current subtractive artifacts and profiles for at least:
  - YAPET;
  - Vim;
  - Lua;
  - tmux;
  - OMP/tree;
  - JPEGOptim;
  - SurpriseTalk;
  - the solver fixture suite.
- Preserve call targets, node resolutions, global points-to, downstream disposition
  outputs, wall time, peak RSS, solve rounds, points-to facts, copy facts, memcpy pairs,
  and SCC statistics.

### Stage 1 — Make abandonment safe before changing semantics

- Introduce `RefinerOutcome::{Complete, Exhausted}`.
- Make `finish_andersen` overlay refined facts only for `Complete`.
- Implement the exact-override fallback patcher.
- Add completion/exhaustion metrics and loud diagnostics.
- Add deterministic exhaustion injection.
- Write the quiescent-boundary-with-unbound-targets regression first:
  - discover a target;
  - stop before binding it;
  - assert icalls revert to Steensgaard except exact overrides;
  - assert node resolutions and global points-to remain byte-for-byte base-tier values.
- Add mid-propagation and post-activation exhaustion tests.

This stage may retain the descending solver; its purpose is to establish an API boundary
that makes later incomplete ascending states impossible to emit.

### Stage 2 — Make dynamic constraint installation correct

- Add canonicalizing/deduplicating late-constraint helpers.
- Route external and vararg effects through them.
- Ensure a newly registered store processes the owner's complete current points-to set.
- Add tests for a late-discovered external target after:
  - ordinary quiescence; and
  - SCC collapse of the call operand or an argument node.

### Stage 3 — Implement the additive joint fixed point

- Precompute and store `E(site)` for every in-scope non-exact callsite.
- Maintain separate pinned exact and activated non-exact target sets.
- Build one `Solve`.
- Activate exact targets and statically detectable eager-unknown sites; implement the
  dynamic region-triggered eager activation inside the discovery loop.
- Alternate budgeted propagation and batched target discovery until joint quiescence.
- Implement the hardened `unknown_callee` OR rule (§3.2, §6).
- Add a test/diagnostic switch that disables eager unknown-origin activation (pure-LFP
  mode) for the §7 differential.
- Remove the monotone-shrinkage assertion.
- Add monotone-growth assertions and retain the M2.0 Steensgaard subset tripwire.
- Redefine/report `rounds` as resume phases, or add `resume_rounds` and migrate consumers.

### Stage 4 — Seed and unknown-origin audit

- Trace every PAG omega seed and every `ExternalRegion::may_contain_function_pointer`
  category to its callsite behavior.
- Verify exported/library entry parameters and externally returned callbacks.
- Verify forged pointers and inline assembly cannot silently produce an empty named target
  set without a sound summary or eager envelope.
- Document which unknown categories eagerly bind the envelope and which have a sufficient
  foreign-call summary.
- Treat any unclassified category as eager-envelope fallback.

Stage 4 is a release gate even if its code lands alongside Stage 3.

### Stage 5 — Differential rollout and profiling

- Run additive and subtractive paths on all synthetic fixtures.
- Run the metrics corpus, with YAPET and Vim mandatory.
- Triage every strict per-site target subset.
- Run available dynamic traces on divergent sites.
- Compare wall time, peak RSS, points-to facts, copy edges, SCC passes, collapsed nodes,
  and activated versus envelope target counts.
- Confirm exhaustion is absent under normal corpus settings. Any occurrence is a
  performance bug and blocks deletion of the oracle until understood.

### Stage 6 — Remove the oracle

- Delete the subtractive re-solve loop and diagnostic switch.
- Keep fixed regression fixtures for every triaged divergence.
- Update `DESIGN_lite.md`'s round-0/subtractive description to the joint monotone LFP.
- Update profiler and metrics documentation to define resume phases and exhaustion.

## 9. Required tests

### Fixed-point behavior

- A target available from a direct address-of seed is activated.
- A target discovered only after another indirect call's bindings propagate is activated
  on a later resume.
- Mutually recursive indirect calls with a real seed converge and retain all targets.
- A mutually supporting cycle with no grounded seed does not bootstrap itself.
- Activation order does not change the final semantic result.
- Every `(site, target)` binding is installed at most once.

### Exactness and envelopes

- B1/B2 exact sites remain pinned and never grow through points-to discovery.
- Exact overrides survive whole-tier exhaustion.
- Non-exact additive targets always remain within their per-site Steensgaard envelope.
- B3-confined targets are not rediscovered at non-exact sites.

### Unknown and external behavior

- A callback entering through an exported/library parameter remains sound.
- An external-returned function pointer is summarized or eagerly enveloped as audited.
- An integer-forged call operand cannot produce a falsely precise empty target/effect set.
- A late-discovered external target installs argument stores and result provenance after
  quiescence.
- Duplicate external targets do not duplicate the call-boundary summary.
- A function-pointer-capable region reaching an operand only mid-solve triggers eager
  envelope activation exactly once, with fallback provenance on the emitted answer.
- `unknown_callee` is emitted true when the Andersen operand reaches a
  function-pointer-capable region, even where the Steensgaard verdict alone was false.
- Empty known target sets are covered by differential/seed-audit fixtures so they can be
  distinguished from missing grounding without conflating them with unreachable sites.

### SCC and delta interaction

- A target is discovered through an operand whose variable cell has been SCC-collapsed.
- Late parameter/return copies through old member IDs seed all existing source facts.
- A late store owned by a collapsed argument node processes the representative's complete
  points-to set.
- Function object identities are unchanged by SCC collapse.

### Exhaustion

- Exhaustion during ordinary propagation emits no refined tier output.
- Exhaustion at a quiescent boundary with discovered-but-unbound targets reverts icalls,
  node resolutions, and global points-to together.
- Exhaustion after target activation but before resumed quiescence does the same.
- Exact target outputs survive all exhaustion points.
- Step accounting is cumulative across resumes.
- The diagnostic names the tripped limit and reports pending work and known unbound
  targets.

### Differential

- Pure-mode additive targets are subsets of subtractive targets on every fixture and
  corpus site (comparing only converged descending runs).
- Default-mode targets are supersets of pure-mode targets, remain within the Steensgaard
  envelope, and every difference traces to an eager activation.
- Exact sites are equal across paths and modes.
- All observed dynamic indirect-call pairs remain in the additive result.
- Downstream disposition artifacts contain no unexplained loss of conservative facts.

## 10. Acceptance criteria

The change is ready to become the default when:

1. No code path can construct an emitted result from an incomplete additive `Solve`.
2. Exhaustion reverts every refined output family, while preserving exact callsite
   overrides.
3. Unknown-origin function-pointer categories have explicit, tested conservative
   handling.
4. The joint solver reaches quiescence without a normal-corpus exhaustion.
5. Pure-mode results satisfy `additive ⊆ subtractive ⊆ Steensgaard` per non-exact site,
   and default-mode results satisfy `pure ⊆ default ⊆ Steensgaard` with every difference
   from pure mode attributed to an audited eager activation.
6. Every strict subset on the validation corpus is triaged.
7. Dynamic traces contain no call edge absent from the additive result.
8. SCC collapse and late external-effect tests pass.
9. `cargo test --workspace`, release build, formatting, and clippy pass.
10. YAPET shows a meaningful reduction in speculative target bindings and does not regress
    wall time or peak memory; Vim and the remaining metrics corpus show no material
    regression.

## 11. Deferred per-partition salvage

Whole-tier fallback is intentionally the version-1 policy. If exhaustion becomes common,
salvaging jointly complete partitions is the natural upgrade, but it requires a proven
flow-closure boundary.

Ordinary PAG and indirect-call constraints should stay within Kahlon partitions because
Steensgaard already joins argument/parameter, return/result, assignment, dereference, and
pointee relationships. The current Andersen solver, however, also creates shared dynamic
external-region cells. In particular, a singleton generic external-storage region may be
reachable from seeds associated with otherwise distinct partitions. A simple
`cell → partition` map is insufficient until these dynamic regions are shown not to bridge
partitions, assigned to unioned salvage units, or instantiated per partition with an
equivalent sound abstraction.

If that proof is established, salvage needs:

- a stable cell/representative-to-salvage-unit map;
- per-unit pending worklist, points-to delta, copy-seed, and unbound-target counters;
- SCCs confined to one salvage unit;
- emission only for units at joint LFP;
- Steensgaard fallback for every incomplete unit across all output families.

Do not add this bookkeeping until an exhaustion diagnostic demonstrates that whole-tier
fallback has a real coverage cost.

## 12. Rejected exhaustion strategy

On exhaustion, the solver could activate every remaining Steensgaard-envelope binding and
continue to quiescence. This would recover a sound broad fixed-call-graph result similar
to the old descending round-0 solve and could be tighter than raw Steensgaard.

Reject this as the default failure path: it commits to unbounded additional work precisely
after the resource budget has been exhausted. Returning the already available
Steensgaard base costs essentially nothing, preserves soundness, and turns the event into a
loud coverage/performance defect rather than a possible hang.
