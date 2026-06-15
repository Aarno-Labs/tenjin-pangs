# M1.8 — Validation & Baseline Freeze

This note is the M1.8 acceptance artifact (`PLAN-M1.md` §M1.8, `PLAN-M1_lite_delta.md`
§M1.8). It records the frozen M1 baseline that M2 must beat, the validation evidence
behind it, and the bugs that validation surfaced.

It supersedes the earlier "andersen aliases steens" note in
`notes/m1_5_soundness_statement.md` §Scope: **`--stage andersen` is now a real
partition-scoped, field-sensitive inclusion solver with a stateless CG-refinement loop**
(M1.4b, `crates/pangs-solve/src/andersen.rs`), and is the default CLI stage.

## 1. What shipped in this pass

- **M1.4b — partition-scoped Andersen** (`crates/pangs-solve/src/andersen.rs`). Runs on
  top of Steensgaard: the union-find classes are folded (class ∪ pointee) into Andersen
  partitions, the *interesting* ones (reachable from icall operands, globals, or escape)
  are solved with a field-sensitive inclusion solver (lazy `(object, byte_off)` field
  objects), and a per-partition oversize budget falls back to the Steensgaard answer
  (tagged `tier: steens`). Escape/Ω/unknown-caller verdicts are taken verbatim from
  Steensgaard — Andersen refines points-to only (icall targets, `pointee_globals`).
  - **CG-refinement loop:** stateless rounds, round 0 seeded by FSA ∩ Steensgaard, each
    round recomputing icall targets = FSA ∩ Andersen pts; converges by monotone shrinkage
    (a growth is a hard error). An empty `exact_overrides` seam is wired for M2's B2/B3.
- **Differential ledger** (`pangs differential`, `crates/pangs-api/src/differential.rs`).
- **Dynamic icall trace harness** (`pangs instrument` + `pangs check-traces` +
  `scripts/pangs_trace_runtime.c`).

## 2. Frozen baseline metrics (synthetic)

Committed snapshots under `metrics/<fixture>-<stage>.json` (deterministic fields only;
timing scrubbed). The narrowing across stages is the headline:

| fixture | metric | conservative | steens | andersen |
|---|---|---|---|---|
| `m1_4b/field_sensitive_fnptr` | call_edges | 5 | 2 | 1 |
| | rounds | 0 | 1 | 2 |
| | partition_count | 0 | 10 | 10 |
| `m1_4b/cg_refinement` | call_edges | 11 | 4 | 2 |

- **Rounds-to-convergence:** ≤ 2 on every synthetic fixture (cap is 8; the loop asserts
  ≤ 4 in the solver test suite). 
- **Oversize fallbacks:** 0 under the default 1 MB partition budget; the
  `oversize_budget_falls_back_to_steensgaard` test forces a fallback with budget 0.
- **Partition-size distribution:** recorded in each snapshot (`partition_p50_size`,
  `partition_p95_size`, `partition_max_size`) — the first data for the
  `DESIGN_lite.md` §11.4 mega-component question.

These (coverage, component sizes, partition distribution, rounds, oversize fallbacks) are
the M3 decision-gate inputs of `DESIGN_lite.md` §6.

## 3. Validation evidence

- **Narrowing ledger (mechanical):** `andersen ⊆ steens ⊆ FSA` per icall, asserted in
  `crates/pangs-solve/src/andersen.rs` (`andersen_subset_of_steensgaard_and_terminates_on_suite`)
  and across all PIR fixtures by `pangs differential`
  (`differential_ledger_holds_on_synthetic_suite`). Clean on the whole synthetic suite.
  - Note (not a violation): conservative→steens **coverage moves either direction**
    because the two stages differ in mod/ref *completeness* (syntactic vs aliased-Ω), not
    just call-graph precision. `pangs differential` reports this delta and only fails on
    soundness/monotonicity breaks (subset of targets, steens→andersen coverage).
- **Dynamic icall spot-check:** `pangs instrument` rewrites each indirect call to log
  `(caller, idx, target)`; `check-traces` asserts every observed pair is in the
  andersen edge set (`dynamic_icall_trace_validates_against_andersen`, end-to-end through
  clang-14). The negative path (an observed target outside the edge set ⇒ exit 3) is
  covered by `check_traces_flags_a_target_outside_the_edge_set`.

## 4. Bugs surfaced by M1.8 validation

Running the analysis on real clang-14-lowered bitcode (not just hand-written PIR) exposed
three pre-existing soundness gaps in the lowering/solver — exactly the point of M1.8.

1. **`@`-sigil resolution mismatch — FIXED.** LLVM-lowered PIR referenced functions and
   globals with an `@` sigil (`@hello`) while object keys are bare (`hello`), so the PAG's
   operand→object lookup failed and steens/andersen resolved **no** icall targets on any
   `.bc` (a silent false-negative = corruption risk). Fixed in
   `crates/pangs-pag/src/lib.rs` (`resolve_symbol`: try the operand, then with a leading
   `@` stripped).
2. **Incomplete address-taken scan — FIXED.** The scan only covered store/call operands,
   missing functions whose address is taken only via `select`/`phi`/etc.
   (`world` in a `?:`). Fixed in `crates/pangs-pir/src/llvm_sys.rs`
   (`collect_inst_address_taken` now scans all operands of other instructions).
3. **Indirect-call edge dropped on multi-icall functions — FIXED.** Originally triaged
   (incorrectly) as a Steensgaard over-merge on function-pointers-through-memory. The
   solver was in fact correct; the real cause was a **callsite-key ordinal mismatch**
   between `pangs-pag::add_callsite` (one per-function counter → `…:9:5#1`) and the API
   export's `push_callsite` (per-distinct-loc counter → `…:9:5#0`). Any function with ≥2
   calls at distinct source lines had its second-and-later resolved icall targets dropped
   at the export join `callsite_by_key.get(key)` (silent `else { continue }`) — empty edge
   set, no `unknown_callee`. The "through-memory" framing was a coincidence of the repro
   fixtures, and the loc-dependence (noloc copies resolved fine) was the decisive clue.
   Fixed in `crates/pangs-api/src/lib.rs` (`push_callsite` now uses the same per-caller
   ordinal as pag), with a hard export-layer invariant (every solved icall must map to a
   callsite) as the backstop. Regression: `fixtures/synthetic/m1_4b/two_global_fnptrs.pir.json`
   + `pipeline.rs::two_distinct_loc_icalls_both_appear_in_callgraph`, and the dynamic
   harness `pipeline.rs::dynamic_multi_icall_trace_validates_both_sites`. Full write-up in
   `ju_steens_overmerge_bug.md`.
   - *Still separate:* the const-array `memcpy` shape (`fn table[2]={f,g}; table[0]();`) is
     a distinct M1.1/M1.3 coverage question, not this bug.

## 5. Caveat on full-scale corpus

Per `PLAN-M1.md` §1, full-scale program validation (Vim/PHP) is deferred. With finding #3
now fixed, real-corpus icall coverage on multi-icall functions is no longer understated;
the differential ledger and trace harness remain the tools to quantify coverage at scale.
