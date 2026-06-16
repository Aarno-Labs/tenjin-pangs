# M2 Lite Delta — changes to `PLAN-M2.md` under `DESIGN_lite.md`

*Not a standalone plan. Read `PLAN-M2.md` first; this file lists only what changes when
implementing the lite design's M2 (`DESIGN_lite.md` §2 B' + §5 milestone 2: B1 + B2
(+ B3 if trivial), no certificate cascade, no tier E, no typed heap clones). Everything
not mentioned here is unchanged. The companion `PLAN-M1_lite_delta.md` already moved
field-object materialization and the CG-refinement loop into M1; M2 builds on that
shipped M1.4b solver, not on the full design's tier stack.*

## 0. Summary of deltas

| | Change |
|---|---|
| **Reduced** | **M2.0** collapses from a 5-tier verdict ledger + per-tier **certificate cascade** + report attribution to a thin **provenance tag + subset-narrowing debug-assert**. Lite has no tier cascade to route between (`DESIGN_lite.md` §0, §1, §2F), and M1 already ships most of the machinery (`Tier` enum; the `andersen ⊆ steens ⊆ FSA` differential ledger). |
| **Re-scoped** | **M2.1** is *not greenfield*: M1.4b already materializes lazy `(object, byte_off)` field cells inside the Andersen solver. M2.1 promotes them to a shared `SubObj` side table, adds the **`(o,⊤)` generalization pair + offset clamping**, and in doing so **fixes a confirmed M1.4b soundness false-negative** (see §1 M2.1). |
| **Re-shaped** | **M2.5** loses certificate check #1 (icall settlement *at the Steensgaard tier*): lite runs Andersen exhaustively, so there is no cheaper tier to "settle" and skip. B1/B2 instead deliver **exact answers that take precedence** (same shape as the existing `exact_overrides` seam). Certificate check #2 (**stationarity for mutability**) is **kept** verbatim — it is the mutability client's flagship output. |
| **Cut** | **M2.6** (typed heap clones + cast filtering) is **removed, not gated**: `DESIGN_lite.md` §2A'/§3 cut clones from the design entirely. Punning is still *detected* and Ω-tainted (M1.5), so this is precision-only. |
| **Added** | A **shared regional def-use walker** over PIR top-level SSA (call-string-parenthesized) is built once and consumed by both M2.2 (B2, backward+forward) and M2.4 (B1, forward). The full plan implies it twice; lite factors it out. |
| **Unchanged** | M2.2 (B2 core walker + exact simple-icall resolution), M2.3 (B3 confined subtraction), M2.4 (B1 InitVal/stationarity tracking), M2.7 validation structure. The KELP/CORAL algorithms and their soundness valves (⊥-poisoning, depth-cap → COMPLEX, safe fallback) are kept exactly. |

The dependency chain becomes **M2.0 → M2.1 → {def-use walker} → {M2.2 → M2.3, M2.4} →
M2.5 → M2.7**. M2.6 is gone. As in the full plan, **M2 can stop early after M2.3**
(exact simple icalls + confined subtraction) and still ship value.

## 1. Per-step deltas

### M2.0 — Verdict provenance + subset tripwire *(reduced: ~0.5–1 day, was 1–2)* — **IMPLEMENTED**
Lite keeps **only** the two load-bearing parts of the full M2.0 and drops the rest:

- **Keep — the subset-narrowing assertion.** "A later/cheaper-exact source may only
  *narrow* an answer; assert the subset relation on every update." This is, verbatim from
  the full plan, *"the cheapest soundness regression tripwire we will ever buy."* It
  already exists in spot form (M1.8's `andersen ⊆ steens ⊆ FSA` differential ledger and
  the `andersen_subset_of_steensgaard_and_terminates_on_suite` solver test). M2.0 lifts it
  into an always-on `debug_assert` at the point an icall's target set is replaced by a
  more-exact source (B2/B1 override, FSA intersection, confined subtraction).
- **Keep — provenance tags, but two not five.** Per `DESIGN_lite.md` §2F: each icall edge
  is tagged `simple` (B2/B1-exact) or `andersen` (`Andersen∩FSA`); plus the already-shipped
  `direct`, `fsa`, and oversize-fallback `steens`. Extend the existing `Tier` enum
  (`crates/pangs-api/src/lib.rs`, currently `Direct|Fsa|Steens|Andersen`) with `Simple`;
  no separate `pangs-verdicts` crate is needed — the `IndirectCallResolution` /
  `CallEdge.tier` records already carry per-site provenance.
- **Cut — the per-tier certificate cascade**, the 5-tier `Verdict { tier, certificate }`
  ledger, settled/unsettled routing, and `pangs report`'s per-tier attribution columns
  *as a cascade view*. (A flat per-provenance count in `pangs report`/`metrics.json` is
  kept — it is the ablation data M2.7 needs, and it is one `group_by`, not a framework.)
- **Acceptance met:** `Tier::Simple` added; flat per-provenance counts
  (`icalls_simple/andersen/steens/fsa/unknown`) in `metrics.json` (+ schema); the subset
  tripwire (`debug_assert_narrows`) wired at the Andersen narrowing point and green across
  the suite, with unit tests confirming it is silent on a valid narrowing and **fires** on
  a planted widening. M1 callgraph/audit goldens unchanged.

> Rationale: the full M2.0 exists to *decide, per query, whether a cheap tier's answer is
> final so the expensive tier can be skipped.* Lite always runs the expensive tier
> (exhaustive partition Andersen), so that decision — and the cascade that implements it —
> has no job. What survives is bookkeeping (provenance) and the soundness tripwire.

### M2.1 — `⊤` generalization + **soundness fix** *(2–4 days, unchanged budget)* — **IMPLEMENTED**
M1.4b already shipped the *precision* half of this (lazy `(object, byte_off)` cells:
`field_of`, `fields: HashMap<(Cell,i64),Cell>` in `crates/pangs-solve/src/andersen.rs`).
M2.1 completes the *soundness* half.

- **Generalization pair (cclyzer §3.3, byte-offset recast) — DONE.** Implemented as
  **collapse-on-non-constant-access** in the solver field model: a constant offset keeps
  its own subobject cell (field sensitivity intact); a non-constant Gep (`byte_off: None`,
  produced by the `gep_dynamic_index` lowering) marks the object `⊤`-accessed and conflates
  its field cells with the whole-object cell, in both directions (`collapse()` in
  `andersen.rs`). This realizes the `(o,⊤)` semantics —
  - a load from `(o, c)` sees values stored to `(o, ⊤)`, and
  - a load from `(o, ⊤)` sees values stored to every `(o, c)` —
  while only touching objects actually indexed by an unknown offset; all-constant objects
  keep full field precision. Sound (a superset), incremental-safe (monotone copy edges, no
  load-time re-firing hazard). Conflating an object's constant fields *among themselves*
  once a `⊤` access exists is marginally coarser than the asymmetric ideal, but matches the
  byte-offset representation's inherent limit (`a[i].x` lowers to a single non-constant
  cumulative offset regardless), so it costs no realizable precision here.
- **This fixed a confirmed M1.4b false negative (corruption-class), not just a precision
  gap.** Before the fix `field_of(o, None)` returned the whole-object cell with *no*
  cross-linking, so a value stored through a dynamic-index GEP was invisible to a
  constant-offset load of the same object. Verified repro (default `--stage andersen`):
  `store alpha` via dynamic-index gep, `load` via constant gep(0), `call` → steens soundly
  yields `{alpha}`, andersen used to yield `∅`; now both yield `{alpha}`. Regression
  fixtures `fixtures/synthetic/m2_1/{dynamic_store_const_load,const_store_dynamic_load}.pir.json`
  (both directions) + solver tests `m2_1_dynamic_store_is_seen_by_constant_load` /
  `m2_1_constant_store_is_seen_by_dynamic_load`; the field-sensitivity precision test
  (`andersen_distinguishes_struct_fn_ptr_fields`) stays green.
- **Acceptance met:** the mixed constant/non-constant-offset soundness fixtures resolve;
  field cells stay demand-populated (no eager blowup); the `andersen ⊆ steens ⊆ FSA`
  narrowing ledger holds (the fix only adds edges that are already present at steens — the
  M2.0 subset tripwire confirms it).

**Deferred from M2.1 to M2.2 (recorded, not dropped):**
- **Shared `SubObj` side table.** The full delta called for promoting the field map into a
  standalone `SubObj: (ObjId, ByteOff) → SubObjId` table owned outside the solver, so the
  M2.2/M2.4 def-use walks and any revived tier D/E consume the *same* field identities. The
  soundness-critical `⊤` semantics now live correctly inside the solver; the extraction is a
  pure refactor whose interface should be defined by its first consumer — the regional
  def-use walker, which does not exist until M2.2. **Do the extraction when the walker
  lands**, co-designing the table with the walker's needs, rather than guessing the shape
  now. Until then the solver's internal `fields`/`collapsed` maps are the single source of
  field identity.
- **Allocation-size offset clamping.** "Offsets clamp to the allocation size where known"
  is a precision/memory guard, **not** a soundness requirement: the `⊤` collapse already
  bounds the pathological case, and the set of distinct constant offsets is finite per
  program (so there is no termination or unbounded-growth risk). It needs type-layout sizes
  plumbed into the solver's object cells, which is best added against a measured need (an
  object whose field-cell count actually blows up). **Deferred until M2.2/M2.5 metrics show
  it pays**; no soundness exposure in the interim.

### Shared prerequisite — regional def-use walker *(folded into M2.2's budget)*
B2 (backward+forward) and B1 (forward) are the *same* traversal over PIR top-level SSA
with call-string parentheses; the raw material exists (PAG `Assign/Load/Store/Gep` edges,
`Param`/`Return` nodes, callsites) but **no walker abstraction does**. Build it once:
`(pir_stmt, tracked_value, ctx_string)` state, paren push on return-into-caller / pop on
call-into-callee, CFL-admissibility on balanced parens, visited-set on the full triple,
context-depth cap (start 8) → COMPLEX/⊥ on overflow. M2.2 and M2.4 are then *policies*
over this walker (different terminal/abort rules), not two engines. This is the real
engineering prerequisite the full plan leaves implicit. It is also the first consumer of
the shared `SubObj` table deferred from M2.1, so **build the walker and extract `SubObj`
together** — the walker's traversal needs (how it asks "what field is this?") define the
table's interface; designing the table earlier would be guesswork.

### M2.2 — B2 simple pointers — unchanged
Algorithm, abort rules, global-variable mode, forward escape check, and acceptance
(KELP Fig.1/Fig.3 patterns; % simple icalls sanity envelope; every simple target ⊆ FSA
or triaged as an FSA soundness bug; dynamic traces ⊆ edges) all stand. **Integration
note:** B2's exact `Simple { targets }` results feed the **already-wired `exact_overrides`
seam** in M1.4b's CG-refinement round-0 seed (`DESIGN_lite.md` §2 D' step 1: round 0 =
direct ∪ (FSA ∩ Steensgaard) **minus B2-resolved icalls**), and tag the edge `simple`.
No new plumbing — the seam was built empty in M1 for exactly this.

### M2.3 — B3 confined subtraction — unchanged, but explicitly conditional
Per `DESIGN_lite.md` §2B', B3 is **kept iff it stays a one-evening delta on B2's
bookkeeping** (`Confined = address-taken f whose every address-taken site ∈
DefUseReachingSites`). Confined functions are subtracted from complex-icall FSA sets and
the Andersen∩FSA round seeds. Drop without regret if it grows teeth. Acceptance unchanged.

### M2.4 — B1 InitVal/stationarity — unchanged algorithm, lite consumption
The forward init-phase walker (Unkel-Lam boundary, ⊥-poisoning on any unknown) is
implemented exactly as written. What changes is *how its outputs are consumed* (see M2.5):
in lite, `InitVal(o, fld)` is **not** routed through a Steensgaard-settlement certificate;
it is (a) an **exact resolver for dispatch-table icalls** (targets = InitVal of the table
object, fed through the same `exact_overrides` seam as B2, tagged `simple`), and (b) the
input to the stationarity verdict. Acceptance fixtures and the ≤2-min-on-PHP budget stand.

### M2.5 — Exact-precedence wiring + stationarity verdict *(re-shaped: 1–2 days, was 2–3)* — **IMPLEMENTED**
The full plan's two certificate checks split under lite:

1. **Icall settlement at Steensgaard (CORAL Eq.1) — CUT.** Its purpose is to certify that
   the cheap tier's answer is final so the expensive tier can be skipped. Lite runs
   exhaustive Andersen on every interesting partition regardless, so there is nothing to
   skip. B1/B2 exact answers instead take **precedence** over the Andersen∩FSA answer for
   the icalls they resolve (precedence, not a between-tier certificate). The subset
   tripwire (M2.0) guards that precedence: an exact answer must be ⊆ the FSA envelope.
2. **Stationarity for mutability — KEPT verbatim.** Global/field `g` is *stationary* iff
   `InitVal/InitStores(g) ≠ ⊥` **and** every writer found by M1.6's pointer-aware mod/ref
   ∈ `InitStores(g)`. Client effect unchanged: stationary globals leave the localization
   payload and may unfreeze components. **The mandatory 20-verdict hand-audit on Vim
   stays** — stationarity FPs corrupt the refactoring; this is the one place lite keeps a
   full-strength certificate because the *client*, not the tier cascade, depends on it.
- **Acceptance:** coverage-metric delta on Vim/PHP (the step where M2 pays); flat
  per-provenance attribution table (M2.0) published; subset assertions green; the
  stationarity hand-audit completed.

**Implementation status:**
- B1/B2 exact-precedence is wired through `Tier::Simple` call edges with the existing
  FSA subset tripwire. B1 InitVal exact dispatch-table resolution is applied after the
  pointer-aware mod/ref pass computes stationarity, so the exact edge is only emitted for
  globals certified stationary by solved mod/ref facts.
- Stationarity verdicts are now materialized per global as
  `StationarityVerdict { complete_initval, stationary, reason, runtime_writers }`.
  Reasons distinguish `stationary`, `conservative_stage`, `incomplete_initval`,
  `exported_global`, `runtime_writer`, and `unknown_runtime_writer`.
- `stationarity.jsonl` is exported and schema-validated, giving the mandatory hand-audit a
  normal artifact with writer witnesses instead of only aggregate metrics. The human
  `pangs report` also prints flat icall provenance counts, confined functions, complete
  InitVal globals, and stationary globals.
- Synthetic coverage exercises the successful stationary table case, runtime writer
  rejection, unknown-runtime-writer rejection, and incomplete/poisoned InitVal fallback.
  Full workspace tests pass with LLVM 14. The real-corpus coverage delta and 20-verdict
  hand audit remain M2.7 validation work, not implementation blockers.

### M2.6 — typed heap clones — **removed**
`DESIGN_lite.md` §2A'/§3 cut typed heap clones from the design (not deferred). Heap
objects stay plain allocation-site objects. If the M3 decision gates (`DESIGN_lite.md`
§6) later show heap-object conflation is what blocks certificates, clones come back as an
*additive* object-domain change behind the frozen PAG — but that is an M3 decision, not an
M2 step. Delete the row from the schedule.

### M2.7 — Validation & freeze — unchanged structure, two trims — **IMPLEMENTED**
- **Keep:** re-run M1.8 dynamic icall validation (every observed pair ∈ edge set — now a
  hard bar, since B1/B2 resolution is *exact*); KELP-style ablation {B2 only, B1 only,
  both} on the corpus using the M2.0 provenance counts; freeze the M2 metrics dashboard.
- **Trim:** the cclyzer++ differential is **advisory/optional** (consistent with M1's
  advisory-only cclyzer policy), not a gate. Drop the typed-clone object-count histogram
  (no clones).

**Implementation status:**
- `Opts` now records the frozen M2 controls: `enable_b1_initval`, `enable_b2_simple`,
  `enable_b3_confined`, and `b2_context_depth`. Defaults keep normal analysis behavior
  unchanged (`true/true/true`, depth 8).
- `pangs m2-ablation <module>` runs four variants through the normal analysis pipeline:
  `m1_baseline` (B1/B2/B3 off), `b2_only`, `b1_only`, and `both`. Each row reports the
  flat icall provenance counts, confined functions, complete InitVal globals, stationary
  globals, localization coverage, call edges, and analysis wall time.
- Synthetic tests cover the ablation switches and CLI JSON output. The existing M1.8
  dynamic icall tests remain in the full suite and validate observed indirect calls
  against Andersen exports after B1/B2 exact precedence.
- The solved-stage CLI exposes `--partition-budget` for `analyze`, `differential`, and
  `m2-ablation`. The default budget is 1,000: on `exe-jq-O1.bc` this keeps the default
  Andersen path to ~36s by falling back 17 oversized partitions. The previous 1,000,000
  default admitted an expensive jq partition and did not finish within an hour.

## 2. Contract/schema deltas

- `callgraph.jsonl` `tier` enum gains `simple` (B2/B1-exact). Additive; the enum was
  declared open in M1 — no `schema_version` bump.
- `metrics.json` gains flat per-provenance icall counts
  (`icalls_simple`, `icalls_andersen`, `icalls_fsa`, …) and B1/B2 coverage stats
  (`simple_icalls`, `confined_functions`, `globals_with_complete_initval`,
  `stationary_globals`). No cascade/certificate fields.
- `manifest.json` `opts` records the M2 controls: B1 enabled, B2 enabled, B3 enabled,
  and the B2 context-depth cap.
- `stationarity.jsonl` records one stationarity verdict per global for the M2.5 audit:
  global key, InitVal completeness, stationary boolean, rejection reason, and runtime
  writer witnesses. B1 `InitVal` slots and B2 `DefUseReachingSites` otherwise remain
  internal pre-analysis tables, surfaced through provenance tags, metrics, and this
  stationarity verdict stream.

## 3. Effort & risk deltas (vs `PLAN-M2.md` §3)

| Step | Lite Δ days | Note |
|---|---|---|
| M2.0 | 1–2 → **0.5–1** | cascade cut; provenance + subset tripwire mostly exist in M1 |
| M2.1 | 2–4 (unchanged) | now also fixes the confirmed non-const-GEP FN; refactor solver onto shared table |
| M2.2 | 4–6 (unchanged) | includes the shared def-use walker (built once, reused by M2.4) |
| M2.3 | 1–2 (unchanged) | conditional on staying a one-evening delta |
| M2.4 | 4–7 (unchanged) | consumes the M2.2 walker; ⊥-poison on any doubt |
| M2.5 | 2–3 → **1–2** | settlement-at-Steensgaard cut; stationarity + exact-precedence kept |
| M2.6 | 3–4 → **0** | removed (lite cuts clones) |
| M2.7 | 2–3 (unchanged) | cclyzer++ differential demoted to advisory |
| **Σ** | **16–27 → ~13–21** | |

**Risk note specific to lite:** the one *new* risk is M2.1's soundness fix changing
existing andersen answers (edges legitimately *appear*). Mitigation: the change can only
move andersen answers *up toward* steens (it adds previously-missing sound flow), so the
`andersen ⊆ steens ⊆ FSA` ledger still bounds it; re-bless affected synthetic goldens
under review and confirm every new edge is also present at the steens tier.
