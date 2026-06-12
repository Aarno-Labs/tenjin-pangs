# M1 Lite Delta — changes to `PLAN-M1.md` under `DESIGN_lite.md`

*Not a standalone plan. Read `PLAN-M1.md` first; this file lists only what changes when
implementing the lite design's M1 (`DESIGN_lite.md` §5: A' + C' + D' + CG-refinement
loop). Everything not mentioned here is unchanged, verbatim, including all of §1
standing decisions, §2 output contract (except the named schema deltas below), and the
acceptance/golden-test discipline.*

## 0. Summary of deltas

| | Change |
|---|---|
| **Added** | New step **M1.4b**: partition extraction + partition-scoped Andersen (PIP internals) + the stateless call-graph-refinement outer loop. This is M4 of the full plan pulled into M1, and the only large delta. |
| **Cut** | CastMap recording in M1.3 (tier-E-only artifact); typed-heap-clone input prep in M1.3 (lite cuts clones entirely, not defers them). |
| **Moved** | Lazy field-object materialization `(object, byte_off)` moves from "M2+/tier-E" into M1.4b — lite's Andersen is the field-sensitive consumer of the byte offsets M1.3 already records. |
| **Retargeted** | M1.6 mod/ref and the M1.2-pipeline icall outputs read Andersen's solution instead of Steensgaard's; M1.4's outputs become round-0 seeds. |
| **Unchanged** | M1.0, M1.1 (entire lowering policy table), M1.2 (entire FSA spec — still the soundness envelope), M1.4 internals, M1.5, M1.8 structure, including the synthetic-fixture-first staging and advisory-only cclyzer policy from `PLAN-M1.md`. |

Steps M1.0–M1.2 are identical in scope: the conservative end-to-end pipeline over
synthetic fixtures is still the ★ first-running-analysis milestone and the regression
floor.

## 1. Per-step deltas

### M1.3 PAG construction
- **Drop CastMap recording.** It exists to serve tier-E traversals; lite has none. If
  tier E is ever revived (DESIGN_lite §6 gates), the CastMap is buildable as a separate
  later pass over the frozen PAG without touching M1.3.
- **Drop the typed-heap-clone input prep** ("record the inputs they'll need"). Lite cuts
  clones from the design rather than deferring them to M2; heap objects are plain
  allocation-site objects, full stop.
- **Optionally add the TeaDSA call/return-site filter** (DESIGN.md §4A, last bullet) at
  call-argument/return-value edge generation. Precision-only and cheap (B2-flavor local
  SSA reasoning), so it may also land later with M2; if deferred, leave the edge-builder
  seam for it.
- Everything else — node/edge kinds, byte-offset recording, Ω seeding, `check-pag`,
  and synthetic edge-level golden coverage — unchanged. FactGenerator remains advisory
  only, per `PLAN-M1.md`.

### M1.4 Steensgaard + Ω (internals unchanged; role demoted)
- The step is implemented exactly as written — every edge rule, the bit flood, the
  signature-filter discipline, all fixtures. Only its *position* changes: its icall
  targets and pts become the **round-0 call-graph seed** for M1.4b rather than the
  M1-final answer, and its classes become the partitioner. Escape bits (`ESC`/`EXT`)
  remain authoritative M1 outputs (Andersen refines pts, not the Ω seeds).
- The acceptance items stand, but the "coverage metric moves" requirement transfers to
  M1.4b — at this step it only needs to move relative to M1.2 on synthetic fixtures.

### M1.4b — Partition-scoped Andersen + CG-refinement loop *(new step, 6–9 days)*
The lite design's one real solver (`DESIGN_lite.md` §2 D'). Sits between M1.4 and M1.5;
M1.5 is independent of it and can proceed in parallel.

- **Partition extraction.** Kahlon partitions = the M1.4 union-find classes plus the
  pointer hierarchy above them. *Interesting* partitions: those reachable from icall
  fn-ptr operands, from mutable globals and what they reach, and from escape-relevant
  objects. Counts and size distribution go into `metrics/` (this is also the first data
  for DESIGN.md §11.4's mega-component question).
- **Solver.** Inclusion-based worklist per partition, sequential within, `rayon` across.
  PIP internals: implicit Ω bit-flags in the constraint forms, sparse-bitmap pts sets,
  no classic-optimization zoo. Field sensitivity via **lazy field objects** keyed
  `(object, byte_off)`, materialized on first address-taken use — this is where the
  M1.3 byte offsets get consumed (the full plan deferred that to M2+/tier-E).
- **CG-refinement outer loop** (replaces nothing in this plan — it is M4/tier-E
  machinery that lite never builds): round 0 = direct ∪ (FSA ∩ Steensgaard) icall
  edges; solve all interesting partitions; recompute icall targets = FSA ∩ Andersen
  pts; if the edge set shrank, re-solve. Stateless per round; expect 2–3 rounds; the
  harness asserts monotone shrinkage and fails on growth (a growth is a soundness bug
  by construction). **Design the loop's input to accept an "exact overrides" set
  (icall → targets) that is empty in M1** — that is the seam where M2's B2/B3 results
  plug in without restructuring.
- **Oversize guard (sound fallback).** A per-partition budget (constraints × pts bits);
  a partition exceeding it keeps its Steensgaard-level answer, is tagged `steens` in
  provenance, and is counted in stats. This caps the OOM risk CORAL's baselines hit
  without any soundness cost.
- **Outputs** replace the M1.4-derived ones in the client pipeline: icall targets,
  pointer-aware pts for M1.6, per-edge provenance `tier: "andersen"`.
- **Acceptance:** per-icall targets ⊆ M1.4's targets ⊆ FSA (the narrowing ledger,
  asserted mechanically, not eyeballed); fixtures: struct with two fn-ptr fields
  distinguished (field sensitivity working), CG-refinement fixture where round 2
  provably drops an edge, oversize-fallback fixture; loop terminates ≤4 rounds on the
  synthetic fixture suite; coverage metric moves vs M1.4 on at least one fixture;
  partition stats snapshot committed.

### M1.5 Assumption-violation audit — unchanged
Same detectors, same Ω-taint effect. Note only: with typed clones cut, the
memcpy-over-fn-ptr-aggregates detector is the *sole* guard in that area — do not trim
the detector list to match the smaller object model.

### M1.6 Pointer-aware mod/ref
Unchanged in logic and schema, but reads `pointee` facts from the **M1.4b Andersen
solution** (falling back to Steensgaard classes for oversize-guarded partitions —
provenance already distinguishes them). Ordering: after M1.4b, not after M1.4.

### M1.7 Performance pass
Unchanged method (profile-first), initially on the largest synthetic stress fixture.
Expectation update: Andersen now exists to be profiled; the likely profile order is PAG
build ≥ Andersen ≥ closures ≫ Steensgaard. The PHP-scale budget is deferred until the
full-scale corpus scripts are introduced; when that happens, relax the end-to-end target
from ≤60 s to **≤5 min on PHP** (CORAL's sequential partitioned-Andersen data says
minutes is the honest envelope; if we land ≪60 s anyway, record it and keep the old
budget).

### M1.8 Validation & freeze
Unchanged structure. Two additions:
- The dynamic icall check asserts observed pairs ∈ **Andersen-round-final** edge set
  (the shipping answer), not just the FSA envelope.
- The frozen baseline now includes the partition-size distribution and rounds-to-
  convergence — these are inputs to the DESIGN_lite §6 M3 decision gates.

## 2. Contract/schema deltas (§2 of `PLAN-M1.md`)

- `callgraph.jsonl` `tier` enum gains `andersen` (the enum was already declared open;
  this is additive, no `schema_version` bump).
- `manifest.json` `opts` records the CG-refinement round count and the partition
  budget; `metrics.json` gains partition stats (`count`, `p50/p95/max size`,
  `oversize_fallbacks`, `rounds`).
- CLI: `--stage` gains `andersen` (default once M1.4b lands); `conservative` and
  `steens` remain runnable forever as regression floors, as before.

## 3. Effort & risk deltas

| Step | Δ days | Δ risk | Note |
|---|---|---|---|
| M1.3 | −1 | — | CastMap + clone-prep dropped |
| M1.4b | +6–9 | partition blowup / solver perf | oversize guard makes the failure mode "less precise," never "OOM/unsound" |
| M1.7 | ±0 | — | PHP-scale budget deferred until full-scale corpus scripts exist |
| **Σ** | **24–43 → ~29–51** | | first running analysis still at M1.2, unchanged |

The hard dependency chain becomes 1.0 → 1.1 → {1.2, 1.3} → 1.4 → 1.4b → {1.6, 1.7} →
1.8, with M1.5 free-floating after 1.3 as before. The schedule's shape is preserved:
everything after M1.2 remains a precision/coverage upgrade to a tool that already runs,
and M1.4b inherits that property because its failure mode (oversize fallback) degrades
to M1.4's answer rather than blocking.
