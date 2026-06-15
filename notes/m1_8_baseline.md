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
3. **Steensgaard over-merge on function-pointer-through-memory — OPEN (triaged: bug).**
   With ≥2 global function pointers, or a global-fnptr store combined with a
   select-into-local, steens (and the Andersen partition it seeds) drops one icall site's
   targets to empty (a false-negative). Minimal repro lives in
   `.m1_8_tmp`-style PIR bisection; isolated single-icall and pure-select fixtures resolve
   correctly. This is in the Steensgaard unification / PAG memory-indirection handling,
   not in the M1.4b Andersen additions, and is out of M1.8's scope to fix. **Follow-up:
   file against M1.4/M1.3.** Until fixed, `check-traces` will (correctly) flag a violation
   on programs that exercise it — the harness is doing its job.

## 5. Caveat on full-scale corpus

Per `PLAN-M1.md` §1, full-scale program validation (Vim/PHP) is deferred. Finding #3 means
real-corpus icall coverage is currently understated; the differential ledger and trace
harness are the tools to quantify it once #3 is fixed.
