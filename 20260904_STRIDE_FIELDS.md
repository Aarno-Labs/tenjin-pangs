# Stride Fields: Positive-Weight-Cycle Lanes and Asymmetric Field Overlap

*Implementation guide for a coding agent. Source: `notes/07-dea-pwc.md` (Lei & Sui, SAS 2019,
"DEA"). Read that note and `20260904_FIELD_SENSITIVE_STATUS.md` first. This document is
self-contained for the work items; the design rationale is in the note.*

## 0. Status and goal

Not started. Two changes, in order, each behind a knob and each promoted to default only after
the evaluation in §4 passes:

- **A. PWC lanes (static).** A constant-offset GEP that lies on a copy/GEP cycle in the fixed
  PAG (a *positive-weight cycle*, e.g. `p++` in a loop) is rewritten to an affine lane whose
  modulus is the gcd of the cycle's GEP weights. Both solvers then reuse the existing
  `FieldLocation::Lane` machinery unchanged. Removes the chain of exact field cells that today
  runs through the whole constant-offset vocabulary before collapsing to `Unknown`.
- **B. PWC lanes (dynamic).** Only if A leaves a large chained-derivation residue: detect
  cycles that arise through load/store-added copy edges inside the Andersen solve.
- **C. Asymmetric field overlap.** Replace the bidirectional copy edges between overlapping
  field cells (summary ↔ exact, object ↔ summary) with "a store writes its own cell, a load
  reads the union of overlapping cells". Same soundness, removes sibling-field leakage.

Measured motivation (2026-09-04, default knobs, executable mode): chained field derivation is
96% of GEP pair work on `lib-sqlite-O1` (94 374 of 98 559 pairs) and 55% on
`exe-vim-9.2-O1` (71 909 of 131 148), with 20 123 collapses to `Unknown` on vim. GEP pairs
are 31–41% of all constraint-pair work there. On `exe-tmux-O1` the effect is nil (10 chained).

## 1. Ground rules

- **Version control is `jj`, not git** (`.git` is absent, so tools that probe for git report
  "not a repository"). Start each work item with `jj new -m "<item>"` on top of the current
  change, use `jj diff` / `jj st` to review, and `jj restore <path>` to drop a temporary
  instrumentation edit. Never keep temporary counters or knob defaults in a change that is
  described as final. The root filesystem was at 98% on 2026-09-04 and `/tmp` is on the same
  filesystem: check `df -h /` before writing PAG dumps or analysis outputs, and delete
  outputs between corpus runs.
- Build and run environment (from `notes/m3_lite_runbook.md`):

  ```bash
  export LLVM_SYS_140_PREFIX=/home/brk/tenjin/_local/xj-llvm-14
  export LD_LIBRARY_PATH=/home/brk/tenjin/_local/xj-llvm-14/lib
  cargo build --release -p pangs-cli
  cargo test -p pangs-solve -p pangs-pag        # focused; run the full workspace before promoting
  ```

- Corpus: `/home/brk/pangs-corpus/_out_bc/`. Evaluation set: `exe-tmux-O1` (null case),
  `exe-jq-O1`, `lib-sqlite-O1`, `exe-vim-9.2-O1` (large; several minutes each for the last two).
- Soundness posture (`DESIGN.md` §7): every change must only *narrow* answers. A lane is a
  superset of every exact offset it replaces, and the union-on-load rule reads at least what
  the bidirectional edges read, so both A and C are conservative by construction. Still run
  the ledger checks in §4.
- Record results in `EXPERIMENT_HISTORY.md` and update the "Finite field domain" paragraph
  of `DESIGN_lite.md` §2 D′ when a knob is promoted.

## 2. Work item A: static PWC lanes

### 2.1 Where the code lives

| Concern | Anchor |
|---|---|
| Lane type, `shifted`, `combined` (gcd) | `crates/pangs-pir/src/lib.rs` `GepLane` (~L738) |
| GEP lowering: constant index → `byte_off`, dynamic → `lane` | `crates/pangs-pir/src/llvm_sys.rs` (~L4000–4085) |
| PAG construction entry | `crates/pangs-pag/src/lib.rs` `Pag::from_pir` (L77), `PagOpts` (L14), `EdgeKind::Gep { byte_off, lane }` (L934) |
| `FieldLocation::from_gep`, `add`, `may_alias` | `crates/pangs-solve/src/lib.rs` L1222–1275 |
| Fixed-PAG address proof (fails on any cycle) | `crates/pangs-solve/src/lib.rs` `exact_allocation_addresses` (L1276) |
| Steensgaard GEP rule | `crates/pangs-solve/src/lib.rs` ~L1915 |
| Andersen base constraints (`known_locations`, GEP pre-resolution) | `crates/pangs-solve/src/andersen.rs` `build_base_solve` (~L2826–2870) |
| Andersen `field_of` (vocabulary walk + `Unknown` collapse) | `crates/pangs-solve/src/andersen.rs` L5903 |
| Andersen GEP propagation | `crates/pangs-solve/src/andersen.rs` ~L6730 |
| Profile line to extend | `crates/pangs-solve/src/andersen.rs` ~L2674 ("joint solve done") |
| Knob declarations | `crates/pangs-solve/src/knobs.rs`, `PagOpts` for PAG-level options |

B1/B2 (`crates/pangs-api/src/initval.rs`, `simple.rs`) read PIR, not the PAG, so a PAG-level
rewrite does not touch them. `crates/pangs-solve/src/cfl.rs` is an experimental query
prototype and may treat a lane as unknown; that is acceptable.

### 2.2 Algorithm

Implement as a PAG post-pass `Pag::infer_pwc_lanes(&mut self)` in `crates/pangs-pag/src/lib.rs`,
called at the end of `from_pir` when `PagOpts::pwc_lanes` is true (default true once promoted;
env `PANGS_PAG_PWC_LANES=0` disables for ablation, threaded through the CLI like the other
knobs). Doing it in the PAG makes every consumer (both solvers, the address proof, the
prepartition graph, `dump-pag`, `check-pag`) see one consistent edge set.

1. Build a directed graph over node ids with one edge per `Assign` and `Gep` PAG edge
   (`src → dst`). Ignore Load, Store, Memcpy, AddrOf.
2. Compute SCCs (iterative Tarjan or Kosaraju; the Kosaraju in `collapse_copy_sccs`,
   `andersen.rs` ~L6252, is a good template — vector-indexed, no recursion).
3. For each SCC with at least one *internal* GEP edge (both endpoints in the SCC):
   - `g = gcd` over `|byte_off|` of every internal constant GEP edge, further gcd'ed with the
     `modulus` of every internal lane GEP edge. Skip edges with neither (`Unknown`); they
     stay as they are.
   - If `g == 0` (all internal constant offsets are 0) do nothing: that is not a PWC.
   - Rewrite every internal constant GEP edge `Gep { byte_off: Some(w), lane: None }` to
     `Gep { byte_off: None, lane: Some(GepLane::new(g, w).unwrap()) }`. Internal lane edges
     become `GepLane::new(g, residue)`. Edges leaving or entering the SCC are untouched.
   - Record a PAG metric: `pwc_sccs`, `pwc_gep_edges_rewritten`, and a small histogram of
     `g` (at least the count with `g == 1`), in `PagMetrics`.

Soundness argument to leave in a comment: every cycle weight is an integer combination of the
internal edge weights, so `g` divides every cycle weight; offsets reachable from an entry
offset `e` are all `≡ e (mod g)`, which `Lane { g, · }` denotes. `Lane` is a congruence class in
both directions, a superset of the paper's forward-only stride set, so it is conservative.
Negative weights (`p--`) are covered by the same argument. This is coarser than the paper's
`Strides(e)` (set of cycle weights) but matches the gcd semantics `GepLane::combined` already
uses.

Why nothing else changes: in `field_of`, a base cell at `Lane { g, r }` plus a delta
`Lane { g, w }` gives `Lane { g, r + w }`, and `combined == base_location` when it is the same
residue, so the walk converges in one step. In `exact_allocation_addresses`, `from_gep` turns
the rewritten edge into a `Lane` location; the proof still fails on cycles (see §2.4).

### 2.3 Counters (make permanent)

Add to `Solve` in `andersen.rs` and print in the "joint solve done" profile line:

- `chained_field_derivations`: increments in `field_of` when `base` is a field cell and the
  combined location is in `known_locations` (the `self.field_of(root, combined)` branch).
- `chain_collapses_to_unknown`: increments in the sibling `unknown_field_of(root)` branch.

Struct fields `field_cells_allocated: usize` appear in two structs; anchor the additions on
`new_copy_edges_since_scc` (Solve struct ~L5328 and its initializer ~L5435), which is unique.

### 2.4 Optional extension (skip unless a target needs it)

Extending `exact_allocation_addresses` to certify an SCC whose external producers all name one
root as `Lane { g, entry residue }` would give Steensgaard per-field precision for
`for (e = table; ...; e++)` walks over a global. The census found zero such SCCs in eight
modules (tables are indexed, not walked, at O1), so do not build it now; re-run the census
(§4.1) on any new target first.

### 2.5 Tests

- Unit test in `crates/pangs-pag`: a hand-built PAG with `p = phi(buf, p + 4)` (Assign from
  `buf` and from `p4`, Gep `p → p4` with `byte_off 4`) rewrites the GEP to `Lane { 4, 0 }`; a
  Gep with `byte_off 0` on a cycle is not rewritten; a GEP entering the SCC from outside is
  not rewritten; two internal weights 8 and 12 give modulus 4.
- Solver tests in `andersen.rs` (next to `andersen_distinguishes_struct_fn_ptr_fields`,
  ~L7418) and `lib.rs` (next to `affine_gep_lanes_alias_only_matching_residue_classes`,
  ~L3678) using a synthetic fixture under `fixtures/synthetic/` in the style of
  `field_sensitive_fnptr.pir.json`:
  1. byte walk `for (p = buf; *p; p++)` over an object: after solving, `pts(p)` contains one
     lane cell for the object, `chained_field_derivations == 0`,
     `chain_collapses_to_unknown == 0`.
  2. struct-array walk, element size 24, storing to offset 8 (`e->flags = x`) and loading the
     callback at offset 0: the store's pointee is `Lane { 24, 8 }` and does not alias
     `Exact(0)`; the callback load resolves to exactly the initialized function. With the knob
     off, the same fixture must show the pre-existing `Unknown` behaviour (assert the
     collapse counter is positive) so the ablation is exercised.
- Golden tests under `tests/golden` must be re-baselined only where the diff is a strict
  narrowing; inspect every changed row.

## 3. Work item B: dynamic PWC lanes (conditional)

Trigger: after A, `chained_field_derivations` on sqlite or vim is still more than 10% of
`gep_pairs_processed`. Otherwise skip and record the numbers.

Implementation sketch, all inside `Solve` in `andersen.rs`:

1. In `collapse_copy_sccs`, build a second adjacency that adds, for every established and
   pending GEP constraint `(off, p)` in `geps[n]`/`pending_geps[n]`, an edge `n → p` tagged
   with `off`. Run the same Kosaraju over copy ∪ GEP edges. **Do not merge** cells of an SCC
   that contains a GEP edge; only copy-only SCCs are merged as today.
2. For each SCC containing an internal GEP edge, compute `g` as in §2.2 and rewrite the
   `FieldLocation` of those GEP constraints in place to `Lane { g, off }` (for `Exact(off)`)
   or `Lane { g, residue }` (for lanes). Mark the rewritten constraints pending so they are
   re-seeded from the full points-to set (the existing new-constraint seeding path).
3. The SCC pass is threshold-triggered (`copy_scc_min_edges`, default 4096). Add a cheap
   PWC-only detection that runs once before the first propagation and once after each
   resume round; profile its cost (`scc_nodes_scanned`/`scc_edges_scanned` already exist).
4. Optional subsumption: when a lane cell enters `pts(p)`, congruent exact cells already there
   stay. Leave them; measure first.

Knob: `PANGS_ANDERSEN_PWC_LANES=0` disables. Tests: a fixture where the cycle closes through
memory (`p = *pp; ...; *pp = p + 4`) and A alone does not stop the chain.

## 4. Work item C: asymmetric field overlap

### 4.1 Current behaviour to replace

- `field_of` (~L5903): a newly created cell gets `add_copy` in both directions with every
  existing cell of the same root whose location `may_alias` it, and with the root object when
  the location is `Unknown` and the root was directly accessed.
- `note_direct_access` (~L5968): bridges root object ↔ its `Unknown` summary bidirectionally
  under `PANGS_ANDERSEN_WHOLE_OBJECT_FIELD_BRIDGE`.
- Consequence: a store to `o.f8` flows through the summary into `o.f16` (the spurious target
  of the paper's Fig. 8).

### 4.2 New rule (behind `PANGS_ANDERSEN_ASYMMETRIC_FIELD_OVERLAP=1`)

Define, for a cell `c` with root `r`, `overlap(c) = {c} ∪ { c' ∈ cells(r) : loc(c') may_alias
loc(c) }`, where the root object cell itself is treated as location `Unknown` (a whole-object
access may touch any byte) and the `Unknown` summary overlaps everything of that root.

- **Store** (`*n = q`, ~L6691): for each pointee `o` of `n`, `add_copy(q, o)` only. No fan-out.
- **Load** (`p = *n`, ~L6660): for each pointee `o` of `n`, `add_copy(o', p)` for every
  `o' ∈ overlap(o)`.
- **Late-created cells:** a load processed earlier with pointee `c` must also read a cell
  `c''` of the same root created later that overlaps `c`. Keep
  `loads_by_root: HashMap<Cell /*root*/, Vec<(Cell /*pointee*/, Cell /*dest*/)>>`; when
  `field_of` creates `c''` for root `r`, add `add_copy(c'', dest)` for every recorded
  `(c, dest)` with `c'' may_alias c`. This is the paper's `M_{o.f_i}` bookkeeping and is what
  keeps the rule sound under lazy materialization.
- **Memcpy** (summary cells, ~L5860): a source endpoint reads `overlap(src)`; a destination
  endpoint is written only at its cell. Keep the endpoint bookkeeping used by the
  closed-producer/closed-consumer audits unchanged.
- **External cells:** `field_of` returns the base itself for external cells; keep that, and
  keep the existing Ω/external propagation untouched.
- Remove the bidirectional edges in `field_of` and the bridge in `note_direct_access` only
  when the knob is on; the old path must remain byte-for-byte for ablation until promotion.

Do C after A is promoted, so its measurement is not confounded by chain cells.

### 4.3 Tests

- Fixture: object with fields at 0 and 8, a store to 8, a load through the `Unknown`
  summary (dynamic index), and a load of field 0. Expect: the summary load sees the stored
  value; the field-0 load does not (with the knob on) and does (with the knob off).
- Late-cell test: process a load through the summary before the exact cell at 8 exists, then
  create it via a GEP and store to it; the earlier load's destination must gain the value.
- Re-run the bridge tests (`andersen.rs` ~L7632) under both knob settings; document which
  assertions encode the old symmetric semantics and gate them on the knob.

## 5. Evaluation protocol

### 5.1 Static census (before A, and on any new target)

Dump and count static PWCs. Do this per module and delete the dump immediately; a vim dump
is 257 MB.

```bash
target/release/pangs dump-pag $CORPUS/<m>.bc --build-mode executable > $OUT/<m>.json
python3 pwc_census.py $OUT/<m>.json     # SCCs over assign∪gep edges; see notes/07-dea-pwc.md
rm $OUT/<m>.json
```

The census script from 2026-09-04 was ~80 lines (Tarjan over `assign`/`gep` edges, gcd of
internal `byte_off`s, root-set classification through `addrof`/`assign`/`gep` producers);
rewrite it under `scripts/` so it is kept. After A lands, `PagMetrics.pwc_*` replaces it.

### 5.2 Solver measurements (A, B, C)

For each module in the evaluation set, knob off vs on:

```bash
PANGS_ANDERSEN_PROFILE=1 PANGS_MEMORY_PROFILE=1 \
target/release/pangs analyze $CORPUS/<m>.bc --build-mode executable --stage andersen \
  --out $OUT/<m>-<variant> --validate
```

Record from the "joint solve done" line: `steps`, `pts_facts`, `copy_edges`, `fields`,
`unknown_fields`, `gep_pairs_processed`, `copy_fact_pairs_processed`,
`chained_field_derivations`, `chain_collapses_to_unknown`, plus wall time and peak RSS.

Acceptance for A: on sqlite and vim, chained derivations drop by an order of magnitude,
`fields` and `gep_pairs_processed` drop, no metric rises materially, tmux unchanged. Expect
roughly a third of solve time at most on sqlite/vim; do not expect the paper's 7×.

### 5.3 Narrowing and soundness ledger (every item)

- `target/release/pangs differential $CORPUS/<m>.bc --build-mode executable` for each module:
  must pass with the knob on.
- `cargo test --workspace` including golden files; inspect every re-baselined row.
- Indirect calls: `pangs icall-census` before/after; per-site target sets must be equal or
  subsets, `unknown_callee` never newly set.
- Clients: `pangs report` on both output directories; ModRef unknown rows, per-global
  `written` facts, and the disposition distribution (`HOWTO_MEASURE_DISPOSITION_COVERAGE.md`)
  must not regress. For C specifically, count globals whose `written` witness disappears and
  whose disposition moves up the cascade; that is the precision payoff to report.
- Dynamic check where traces exist: `pangs instrument` + `check-traces` (see `PLAN-M5.md`
  and the runbook) on at least one module.

### 5.4 Promotion

Promote a knob to default only when §5.2 shows the expected gain on at least sqlite and vim,
§5.3 is clean on the whole evaluation set, and the full workspace tests pass. Keep the
ablation value (`=0`) documented in `DESIGN_lite.md` next to the other
`PANGS_ANDERSEN_*` knobs, and add the measured numbers to `EXPERIMENT_HISTORY.md` and
`notes/07-dea-pwc.md`.

## 6. Non-goals

- No change to the exact-address proof, Steensgaard's field classes, receiver payloads, or
  memcpy byte slicing.
- No adoption of the paper's field-index object model, max-field bounds, or wave
  propagation; the byte-offset vocabulary and semi-naive joins stay.
- No per-round SCC detection (item B) unless A's residue measurement demands it.
