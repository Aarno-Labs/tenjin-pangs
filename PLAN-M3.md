# M3 Lite Plan — Measure and Decide

*Companion to `DESIGN_lite.md` §5–§6. This replaces the full-design tier-E M3 plan,
which is preserved in `PLAN-M3_tierE_upgrade.md` as the reversible upgrade path.*

## 0. Thesis

PANGS-lite cuts tier E. M3 is therefore not a demand-query implementation milestone.
It is a validation and diagnosis milestone for the already-materialized lite pipeline:
B1/B2 exact answers first, then partition-scoped Andersen with FSA filtering, followed by
client post-passes over the final materialized solution.

The output of M3 is a decision:

- **Ship lite** if localization coverage and component structure are acceptable.
- **Add typed heap clones** if coverage loss is dominated by heap object conflation.
- **Revive tier E** only if coverage loss is dominated by context-insensitive indirect
  call residue that is not already Ω-frozen.

No tier-E query result should be wired into `analyze` during this milestone.

## 1. What Exists From The Tier-E Prototype

Some M3.1–M3.3 work was implemented before this plan was reconciled with
`DESIGN_lite.md`:

- `crates/pangs-solve/src/cfl.rs` implements experimental callee CFL queries:
  field-insensitive, MHS field-sensitive, and dependency-tracked fixpoint modes.
- `pangs query callees` exposes those kernels as a diagnostic surface.
- Fixtures and tests cover value-flow reachability, byte-offset MHS behavior,
  signature filtering, fixpoint discovery, query budgets, and truncation fallback.
- `notes/m3_1_query_kernel.md`, `notes/m3_2_mhs.md`, and `notes/m3_3_fixpoint.md`
  record prototype behavior and corpus smokes.

Keep this code as an isolated experimental upgrade path for now. It should not define
lite M3 acceptance, and it should not feed exported callgraph, mod/ref, escape, or
localization results unless M3's decision gates explicitly graduate the project back to
the full tier-E design.

## 2. Active M3 Scope

M3 answers four practical questions:

1. **Coverage:** How many mutable globals/components are localizable under the lite
   pipeline?
2. **Shape:** Are non-localizable globals concentrated in a few large components or
   spread across many small ones?
3. **Cause:** Which provenance tags and taint reasons block localization?
4. **Decision:** Do the blockers match lite's expected losses, or do they justify a
   targeted upgrade?

The key rule is that M3 should prefer measurement and attribution over new solver work.

## 3. Metrics To Collect

Run the existing lite `analyze` pipeline on selected real programs and collect:

- Mutable globals: total, localizable, non-localizable, and percentage localizable.
- Component distribution: count, p50/p95/max component size, and largest
  non-localizable components.
- Callgraph provenance: `direct`, B2 exact/simple, Andersen/FSA, fallback/unknown, and
  unknown-callee sites.
- Taint reasons: Ω boundary, inline asm or unsupported IR, int↔ptr provenance,
  external calls, unknown caller/callee, non-stationary writes, and memop findings.
- Load-bearing unknowns: unknowns whose removal would split a large component or make a
  blocked mutable global localizable.
- Performance: wall time and peak memory for `analyze`; phase timings already exported
  by the pipeline should be sufficient unless a run is pathological.

Do not use tier-E prototype results as the primary answers. They may be used only as a
diagnostic comparison if the lite outputs indicate context-insensitive icall residue is
the blocker.

## 4. Diagnostic Classification

For each coverage-blocking component or edge, classify the dominant cause:

- **Expected lite success:** B1 dispatch-table stationarity, B2 simple pointer exactness,
  or Andersen/FSA already gives acceptable precision.
- **External/Ω frozen:** the blocker touches external code, unknown callers/callees,
  inline asm, int↔ptr, unsupported IR, or another soundness boundary. More precision
  should not be expected to recover these.
- **Heap object conflation:** imprecision traces to allocation-site objects merging
  unrelated heap shapes or multi-type uses. The lite upgrade is typed heap clones, not
  tier E.
- **Context-insensitive icall residue:** imprecision traces to parameter-passed function
  pointers or return-carried callbacks that are internal and not Ω-frozen. This is the
  only diagnosis that points to reviving `PLAN-M3_tierE_upgrade.md`.
- **Modeling gap:** missing PAG edge, missing pre-analysis case, schema/reporting gap,
  or a solver bug. Fix these before making a design decision.

## 5. Steps

### M3.1 — Corpus Selection And Runbook

Pick a small but representative real-program set. Prefer programs with enough mutable
global structure and indirect calls to exercise the localization client. Document exact
commands, build modes, input bitcode paths, and export directories.

Acceptance:

- runbook committed;
- no measurements required in this text-only rewrite step;
- selected corpus has at least one small fast case and at least one larger case likely
  to stress the callgraph and component structure.

**Implementation status:** runbook committed in `notes/m3_lite_runbook.md`. It records
candidate O1 corpus inputs, release-mode command shapes, export naming conventions,
currently available export/report fields, diagnosis gates, and the next reporting slice.
No measurements have been run for this step.

### M3.2 — Coverage Dashboard

Build or document a repeatable report over existing `analyze` exports. The report should
summarize localization coverage, component sizes, callgraph provenance, and taint reasons
without requiring manual JSONL inspection.

Acceptance:

- one command produces the summary for an export directory;
- fields are stable enough to compare runs;
- report distinguishes exact, Andersen/FSA, fallback, and unknown callgraph edges.

**Implementation status:** `pangs report <export-dir>` now summarizes existing exports
for M3: component-size histogram, largest frozen components, component taint histogram,
call-edge tier histogram, stationarity reason histogram, audit kind/effect histograms,
coverage, fallback counts, and phase timings. This is a reporting-only change over
exported files and does not alter `analyze`.

### M3.3 — Blocking-Edge Attribution

For the largest non-localizable components and blocked mutable globals, emit the
load-bearing edges and reasons that keep them non-localizable. This can be a report
mode over existing exports rather than new analysis logic if the needed provenance is
already present.

Acceptance:

- top blocked components list their dominant taint/provenance reasons;
- indirect-call edges name their producing phase;
- unsupported/Ω reasons are separated from precision-loss reasons.

**Implementation status:** `pangs report <export-dir>` now includes `component blockers`
for the top frozen components. Each entry summarizes outgoing/incoming indirect edges by
tier, unknown callee/caller counts, unknown mod/ref rows touching the component, and
matching audit finding kinds. This is computed entirely from `components.json`,
`callgraph.jsonl`, `modref.jsonl`, and `audit.jsonl`.

### M3.4 — Decision Gate

Apply the `DESIGN_lite.md` §6 gates:

- acceptable coverage → ship lite, stop;
- heap conflation → plan typed heap clones;
- context-insensitive icall residue → consider reviving tier E from
  `PLAN-M3_tierE_upgrade.md`;
- modeling gaps → fix the model and rerun M3.

Acceptance:

- a short decision note records the corpus, numbers, top blockers, and chosen next path;
- any revived tier-E work is explicitly justified by load-bearing, non-Ω, internal
  context-insensitive icall residue.

**Implementation status:** initial smoke/medium measurements are recorded in
`notes/m3_lite_measurements.md`. Five O1 rows initially completed and `exe-lua-O1` timed out
under a 300s cap. The jq/chibicc/gifsicle transitive mod/ref closure cost was traced to
witness-instance duplication and reduced by keying closure payloads on semantic mod/ref facts;
the same fix cleared the lua timeout. The remaining local mod/ref export cost had the same
duplicate-witness shape and now deduplicates by `(func, global, access, via)` while retaining a
representative witness. `notes/m3_lite_measurements.md` now includes the current lite M3
decision table for jpegoptim/parson/jq/chibicc/gifsicle/lua plus a first curl stress sanity
row. Runtime is acceptable on those rows; the blocker profile points to modeling/audit gaps,
not an immediate tier-E/CFL default-path need. A subsequent `exe-tmux-O1` large stress attempt
timed out under the 300s cap before metrics/export. Profiling localized that timeout to
unbounded nested-GEP field materialization in Andersen; the finite-field fix canonicalizes
nested constant field GEPs back to root-relative offsets from the fixed graph's finite offset
vocabulary, while unknown/unseen nested offsets collapse conservatively to the root object.
`exe-tmux-O1` now completes in about 60s wall with under 3s solver time, but it still exports
a large mod/ref surface (~1.2M rows, 190M), so the remaining M3 freeze question is whether to
accept tmux as a scale warning or spend one more slice on export/modref size.

## 6. What To Stop Doing For Lite M3

The following are not active lite work:

- parallel CFL query pools;
- demand `writers()` and `escapes()` queries;
- tier-E query partition bounding;
- CastMap/type shortcuts for query traversal;
- wiring M3.1–M3.3 CFL answers into `analyze`;
- treating tier-E precision as an acceptance requirement.

Those remain valid only under the archived full-design upgrade plan.

## 7. Keep/Toss Summary For Existing M3.1–M3.3 Work

**Keep, isolated:** the CFL solver module, `pangs query callees`, fixtures, tests, notes,
and truncation fallback. They are useful as regression coverage for PAG semantics and as
a ready upgrade experiment.

**Do not extend now:** M3.4–M3.8 from the archived tier-E plan.

**Do not integrate now:** no tier-E output should replace lite callgraph, writer, escape,
or localization answers during M3.
