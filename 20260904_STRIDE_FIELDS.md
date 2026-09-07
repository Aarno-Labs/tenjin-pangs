# Stride Fields: Positive-Weight-Cycle Lanes and Asymmetric Field Overlap

*Implementation guide for a coding agent. Source: `notes/07-dea-pwc.md` (Lei & Sui, SAS 2019,
"DEA"). Read that note and `20260904_FIELD_SENSITIVE_STATUS.md` first. This document is
self-contained for the work items; the design rationale is in the note.*

## 0. Status and goal

2026-09-07: A is implemented experimentally behind `PANGS_PAG_PWC_LANES=1` and its four-module
evaluation is complete. It is not promoted. The one-hop Steensgaard correction is now
implemented separately, with regression and performance evaluation recorded in
`20260907_ONE_HOP_OFFSET_EVALUATION.md`. B is skipped:
the measured residual exact-chain/GEP ratios are below its 10% trigger. C is implemented
experimentally and evaluated with A held enabled; see
`20260907_ASYMMETRIC_OVERLAP_EVALUATION.md`. Development sequencing has been relaxed to
allow this opt-in experiment before A promotion; promotion gates have not been relaxed.
See `20260907_STRIDE_FIELDS_EVALUATION.md` for A's original ledger. Three work items,
each behind a knob and each promoted to default only after the
evaluation in §5 passes. A includes the bounded domain needed to represent its results; B is
conditional, and C is a separate change evaluated after A:

- **A. PWC lanes (static).** A constant-offset GEP that lies on a copy/GEP cycle in the fixed
  PAG with nonzero net displacement (e.g. `p++` or `p--` in a loop) is rewritten to an affine
  lane. Constant-weight SCCs use the gcd of cycle displacements, computed with node potentials.
  A bounded derived-lane vocabulary preserves shifted entries and member offsets. This aims
  to avoid exact-field chains followed by `Unknown`, without requiring cycle detection to
  establish termination. Andersen gains the new precision; Steensgaard's cycle-rejecting
  address proof is unchanged.
- **B. PWC lanes (dynamic).** Only if A leaves a large chained-derivation residue: detect
  cycles that arise through load/store-added copy edges inside the Andersen solve.
- **C. Asymmetric field overlap.** Replace the bidirectional copy edges between overlapping
  field cells (summary ↔ exact, object ↔ summary) with "a store writes its own cell, a load
  reads the union of overlapping cells". Loads and memcpy sources share persistent overlap-read
  dependencies. Boundary and certificate consumers must use the same read interpretation.

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
- Soundness posture (`DESIGN.md` §7): preserve every concrete behavior under the supported
  program contract. Replacing an exact offset with a lane is a conservative widening, not a
  guarantee that final answers narrow. It can improve precision relative to an old `Unknown`
  collapse or lose precision relative to a short exact cycle. Asymmetric overlap removes
  transitive sibling leakage while retaining direct overlapping writes; it need not read
  every spurious fact the old bidirectional graph carried. Validate correctness independently
  of before/after precision, using §5.3.
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

### 2.2 Static cycle algorithm

Implement as a PAG post-pass `Pag::infer_pwc_lanes(&mut self)` in `crates/pangs-pag/src/lib.rs`,
called at the end of `from_pir` when `PagOpts::pwc_lanes` is true (initially opt-in with
`PANGS_PAG_PWC_LANES=1`; default true only after promotion, with `=0` for ablation, like other
knobs). Doing it in the PAG makes every consumer (both solvers, the address proof, the
prepartition graph, `dump-pag`, `check-pag`) see one consistent edge set.

1. Build a directed graph over node ids with one edge per `Assign` and `Gep` PAG edge
   (`src → dst`). Ignore Load, Store, Memcpy, AddrOf.
2. Compute SCCs (iterative Tarjan or Kosaraju; the Kosaraju in `collapse_copy_sccs`,
   `andersen.rs` ~L6252, is a good template — vector-indexed, no recursion).
3. Process SCCs containing an internal GEP. For an SCC containing only Assign and constant
   GEP edges, give Assign weight zero and compute potentials:
   - Choose a deterministic start node with `h(start) = 0`. Traverse an internal directed
     spanning tree, assigning `h(v) = h(u) + w` when first visiting `v` through `u → v`.
   - Over **all** internal edges, including Assign edges, compute
     `g = gcd(abs(h(u) + w - h(v)))`.
   - If `g == 0`, every cycle has zero net displacement. Leave the SCC unchanged. A cycle
     with `+8` followed by `-8` therefore needs no stride widening.
   - Otherwise rewrite internal nonzero constant GEPs to `Lane { g, w mod g }`. Leave
     zero-offset GEPs exact: they introduce no displacement and need no widening. Leave
     entering and exiting edges unchanged.
4. For an SCC containing existing lanes but no unknown GEP, use a deliberately coarser rule:
   take the gcd of absolute constant weights and **both modulus and absolute residue** of
   every lane edge. Rewrite nonzero constants and lane edges using that modulus and their
   original offset/residue. Including residues ensures every possible edge displacement is
   divisible by `g`. Do not apply the constant-only potential argument to lane edges.
5. For an SCC containing an unknown GEP, skip stride inference for that SCC and retain the
   existing unknown treatment and finite fallback. Record the skip; detecting finite
   subcycles inside such SCCs is a later precision extension.

Use checked wide arithmetic for potentials and residuals, including negative weights and
`i64::MIN`. If the computed modulus cannot be represented by `GepLane`, keep the original
constraints and record a skip. Do not `unwrap` an unchecked lane construction. A skipped
rewrite affects optimization only; §2.3 still bounds field generation.

For constant SCCs, residuals telescope around every cycle, so `g` divides every cycle's
net displacement. The invariant is node-relative: a path from entry node `s` at offset `e`
to node `v` ends at an offset congruent to `e + h(v) - h(s)` modulo `g`. Different nodes
need not have the entry residue. Each rewritten edge also contains its original exact
displacement, which directly establishes conservative transfer. A cycle with `+8` and
`+16` gets modulus 24, not 8; distinct cycles of weights 8 and 12 get modulus 4.

Lanes include both signs and may include unreachable offsets. This is a sound superset of
concrete arithmetic, not DEA's exact forward stride set. Propagation need not converge in
one GEP step: different nodes and entries can require different residues. The bounded
domain below supplies termination even for cycles this pass misses.

### 2.3 Finite exact and derived-lane domain

Keep the fixed exact-offset vocabulary and the per-allocation `Unknown` fallback. Do not
allow replayed GEPs to create arbitrary exact offsets. In particular, adding a class or
location to a memoization table is not itself a bound on that table.

The current `field_of` accepts a composed location only if it is already in
`known_locations` (or unchanged from its base). Registering `Lane(24, 0)` alone therefore
does not preserve a later `+8`: `Lane(24, 8)` may be absent and collapse to `Unknown`.
A must add bounded derived-lane admission as well as rewriting the PAG.

Use one domain helper for root-relative composition and admission:

- An unchanged location reuses its cell. A composed exact location must belong to the
  fixed exact vocabulary; otherwise use that root's `Unknown`.
- Admit newly composed, normalized lanes lazily into a per-root vocabulary with an explicit
  cap. Start the experiment with **256 distinct lane locations per allocation**, including
  directly requested lanes; expose and record the cap for evaluation. This number is a
  tuning choice, not a soundness assumption.
- A lane beyond the cap, unrepresentable arithmetic, or an unknown operand routes to that
  root's `Unknown`. Retain all earlier cells and facts. Never discard an alternative or
  reinterpret an existing cell more narrowly. Future fields must still overlap the summary.
- Use this helper for direct, nested, and dynamically rewritten GEP materialization so no
  path bypasses the cap. Compose lanes using the existing gcd/residue arithmetic; do not
  eagerly enumerate all residues of a modulus.

Each root then has a finite fixed exact vocabulary, at most the configured number of lane
cells, and one unknown summary. Missing cycles, memory-mediated cycles, and late call
bindings cannot create an unbounded location chain. Admission order can affect which lanes
remain precise at the cap; every order must remain conservative and terminate. Use stable
traversal where practical, and test different creation orders without demanding identical
precision after overflow.

The helper should be reusable by the proposed Steensgaard offset fix in
`20260907_STEENS_ONE_HOP_OFFSET_HANDLING.md`. That fix still needs its own persistent GEP
replay and representation of mixed field/summary alternatives. Stride inference does not
solve those obligations, and this work item does not implement that fix.

### 2.4 Counters (make permanent)

Add to `Solve` in `andersen.rs` and print in the "joint solve done" profile line:

- `chained_field_derivations`: counts nontrivial compositions from a field cell admitted as
  exact or lane locations. Split exact and lane counts so successful lane composition is
  not mistaken for residual exact-chain work.
- `chain_collapses_to_unknown`: split by missing exact vocabulary, lane cap, unknown input,
  and arithmetic failure.
- Derived lanes admitted, maximum lanes per root, and roots reaching the cap.

PAG metrics: SCCs examined, nonzero-cycle SCCs, zero-cycle SCCs skipped, lane-containing
SCCs using the coarse rule, unknown/arithmetic skips, rewritten edges, and a modulus
histogram including `g == 1`. Keep the historical census separate: it used edge-weight gcd
and did not distinguish zero-net cycles.

Struct fields `field_cells_allocated: usize` appear in two structs; anchor the additions on
`new_copy_edges_since_scc` (Solve struct ~L5328 and its initializer ~L5435), which is unique.

### 2.5 Steensgaard scope and optional extension

Extending `exact_allocation_addresses` to certify an SCC whose external producers all name one
root as `Lane { g, entry residue }` would give Steensgaard per-field precision for
`for (e = table; ...; e++)` walks over a global. The census found zero such SCCs in eight
modules (tables are indexed, not walked, at O1), so do not build it now; re-run the census
(§5.1) on any new target first. This is separate from carrying shifted field targets through
uncertified GEPs in the one-hop proposal. Static rewriting alone gives no new cyclic address
certificate and must not be advertised as precise Steensgaard pointer-walk support.

### 2.6 Tests

- PAG: `p = phi(buf, p + 4)` rewrites to `Lane(4, 0)`; zero-offset edges stay exact;
  entering/exiting edges remain unchanged; `+8/-8` stays exact; `+8/+16` produces modulus
  24; separate cycles of weights 8 and 12 produce modulus 4. Cover negative cycles,
  multiple entries, existing nonzero-residue lanes, unknown edges, and arithmetic limits.
- Andersen: a byte walk reaches a stable lane without walking the exact vocabulary.
  Retaining an exact entry object alongside the lane is allowed. Do not require zero total
  chained derivations: creating shifted lanes is legitimate work.
- Andersen: a struct-array walk of stride 24 retains member lane 8 separately from member
  lane 0. Use a fixture without whole-object writes that would legitimately bridge them.
  Also start at offset 8 and access member 4, requiring `Lane(24, 12)` absent from the
  fixed PAG vocabulary. Compare with knob-off behavior and report any old summary collapse.
- Domain: force a tiny lane cap; check conservative unknown results for every rejected
  alternative, no cross-root summary, and bounded cell counts. Exercise pointer-increment
  cycles through memory, reordered constraints, and late call bindings with static
  inference disabled or unable to detect the cycle.
- Steensgaard: check termination, conservative writes/targets, and the carrier/location
  invariant. Do not demand precise cyclic lanes while the address proof rejects cycles.
  Any failure exposed by the one-hop defect blocks the affected correctness gate; record
  and fix that dependency rather than weakening the expected concrete facts.
- Goldens: inspect every changed row. Add explicit expected writes and callees to fixtures;
  a smaller answer is not evidence that a disappearing fact was false.

## 3. Work item B: dynamic PWC lanes (conditional)

Trigger: after A, residual **exact-chain** derivations on sqlite or vim are still more than
10% of `gep_pairs_processed`, and profiling attributes substantial work to cycles created
inside the solve. Successful member-lane compositions are not a reason to enable B.
Otherwise skip and record the numbers. B is an optimization; §2.3 remains mandatory with
B off, below detection thresholds, and between detection passes.

Implementation sketch, all inside `Solve` in `andersen.rs`:

1. In `collapse_copy_sccs`, build a second adjacency that adds, for every established and
   pending GEP constraint `(off, p)` in `geps[n]`/`pending_geps[n]`, an edge `n → p` tagged
   with `off`. Run the same Kosaraju over copy ∪ GEP edges. Keep ordinary copy-only SCC
   collapse as an independent pass: belonging to a cycle containing GEPs does not establish
   equal contents, but must not prevent collapse of a true copy-only subcycle.
2. Use §2.2's potential algorithm for constant-only SCCs and its coarse/skip rules for
   lane/unknown SCCs. Rewrite only by a containing lane; never narrow a previously widened
   transfer as SCCs grow. Mark changed constraints pending and reseed from the source's
   full points-to set. Canonicalize and deduplicate constraints after copy-SCC remapping.
   Keep old facts, including old `Unknown` results: this ascending solve cannot retract
   them to recover precision after late detection. All new locations go through §2.3.
3. The SCC pass is threshold-triggered (`copy_scc_min_edges`, default 4096). Add a cheap
   PWC-only detection that runs once before the first propagation and once after each
   resume round; profile its cost (`scc_nodes_scanned`/`scc_edges_scanned` already exist).
4. Keep congruent exact cells already in `pts(p)`. Do not add fact deletion or subsumption
   in this work item. Count detection runs, rewritten constraints, full-set replays, and
   cycles first detected after an unknown collapse, alongside SCC scan costs.

Knob: initially opt-in with `PANGS_ANDERSEN_PWC_LANES=1`; `=0` disables after promotion.
Tests: a cycle through memory (`p = *pp; ...; *pp = p + 4`), a late indirect-call binding
that closes a cycle, and a cycle whose modulus decreases after new edges arrive. Require
full-set replay to preserve all concrete targets. Test with detection below threshold and
disabled: the finite fallback must still terminate. Do not expect B to remove facts that
were already conservatively derived before detection.

## 4. Work item C: asymmetric field overlap

### 4.1 Current behaviour to replace

- `field_of` (~L5903): a newly created cell gets `add_copy` in both directions with every
  existing cell of the same root whose location `may_alias` it, and with the root object when
  the location is `Unknown` and the root was directly accessed.
- `note_direct_access` (~L5968): bridges root object ↔ its `Unknown` summary bidirectionally.
- Consequence: a store to `o.f8` flows through the summary into `o.f16` (the spurious target
  of the paper's Fig. 8).

### 4.2 New rule (behind `PANGS_ANDERSEN_ASYMMETRIC_FIELD_OVERLAP=1`)

Define, for a cell `c` with root `r`, `overlap(c) = {c} ∪ { c' ∈ cells(r) : loc(c') may_alias
loc(c) }`, where the root object cell itself is treated as location `Unknown` (a whole-object
access may touch any byte) and the `Unknown` summary overlaps everything of that root.

- **Store** (`*n = q`, ~L6691): for each pointee `o` of `n`, `add_copy(q, o)` only. No fan-out.
- **Shared read operation:** introduce `read_overlap(cell, destination)`. Register a
  persistent dependency, indexed by allocation root, and add a copy from every currently
  overlapping cell to the destination. Deduplicate dependencies and seed newly installed
  edges from the source's complete facts using the existing copy-edge mechanism.
- **Load** (`p = *n`, ~L6660): for each pointee `o` of `n`, call `read_overlap(o, p)`.
- **Late-created cells:** when any field or summary is created, connect it to every
  registered overlapping read of that root. This applies equally to exact, lane, and
  unknown cells, regardless of creation order. Existing copy edges handle later writes.
- **Memcpy** (summary cells, ~L5860): use `read_overlap` for each source endpoint, with the
  propagation-only memcpy summary as destination; its contents flow to destination endpoint
  cells. The direct Cartesian implementation must register equivalent source reads too.
  Preserve endpoint activation/access guards and whole-object interpretation; this is not
  byte-sliced memcpy. A field created after the memcpy must still reach its destination.
- **Canonicalization:** remap read destinations after copy-SCC collapse, deduplicate merged
  registrations, and replay newly required pairs. Preserve allocation and field identities;
  a canonical value representative is not a replacement allocation root.
- **External cells:** `field_of` returns the base itself for external cells; keep that, and
  keep the existing Ω/external propagation untouched.
- Remove the bidirectional edges in `field_of` and the bridge in `note_direct_access` only
  when the knob is on; the old path must remain byte-for-byte for ablation until promotion.

Here `pts(cell)` records payload written to that cell, while a read obtains the union over
overlapping cells. Overlap is not transitive: exact 0 overlaps Unknown, and Unknown overlaps
exact 8, but a write to exact 8 is not thereby a write to exact 0. This distinction is the
precision gain and must hold outside the propagation loop too.

Audit every consumer that previously relied on summary-copy closure, including closed-producer
and closed-consumer certificates, boundary/escape reachability, receiver payloads, and exported
through-memory facts. Preserve raw endpoint identities for auditing, but update reads and
transfer checks to use the overlap relation. A missing field fact in raw `pts(summary)` cannot
prove a producer closed or a callback unreachable. Keep an unsupported certificate incomplete
until its overlap-aware proof is implemented; conservative boundary traversal must remain
complete. Do not promote C with an unaudited consumer.

Reuse the existing location-overlap semantics and conservative whole-object access model.
Do not infer new byte-width precision from this change. Record dependency counts, overlap
pairs, replay work, and index memory so removing copy edges does not hide a larger read cost.

Do C after A is evaluated and promoted, as a separate change and ablation. B is not a
prerequisite. Hold its setting fixed while measuring C.

### 4.3 Tests

- Fixture: object with fields at 0 and 8, a store to 8, a load through the `Unknown`
  summary (dynamic index), and a load of field 0. Expect: the summary load sees the stored
  value; the field-0 load does not (with the knob on) and does (with the knob off).
- Late-cell test: process a load through the summary before the exact cell at 8 exists, then
  create it via a GEP and store to it; the earlier load's destination must gain the value.
- Repeat the late-cell test with memcpy instead of a load, with memcpy summaries on and off.
  Add the reverse order and a read destination merged by copy-SCC collapse.
- Test both directions of lane/exact overlap, a write through Unknown followed by an exact
  load, and unrelated roots. Keep real whole-object writes visible to all overlapping reads.
- Pass a container containing a callback to an external boundary when its payload is only
  in a field cell. The callback must remain externally reachable. Exercise closed-producer
  and closed-consumer options and receiver payloads together with the new read semantics.
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
internal `byte_off`s, root-set classification through `addrof`/`assign`/`gep` producers).
Keep a maintained script under `scripts/` if dumps are needed, or prefer the new PAG metrics
once available. Label old edge-gcd counts separately from the new cycle-residual counts;
do not silently reinterpret the historical measurements.

### 5.2 Solver measurements (A, B, C)

For each module in the evaluation set, knob off vs on:

```bash
PANGS_ANDERSEN_PROFILE=1 PANGS_MEMORY_PROFILE=1 \
target/release/pangs analyze $CORPUS/<m>.bc --build-mode executable --stage andersen \
  --out $OUT/<m>-<variant> --validate
```

Record from the "joint solve done" line: `steps`, `pts_facts`, `copy_edges`, `fields`,
`unknown_fields`, `gep_pairs_processed`, `copy_fact_pairs_processed`,
`chained_field_derivations` split by exact/lane, `chain_collapses_to_unknown` split by reason,
domain caps and occupancy, overlap-read work for C, plus wall time and peak RSS. Record all
knob settings, admission/fallback metrics, and build mode with each result.

Performance target for A: on sqlite and vim, exact-chain work drops by an order of magnitude
and total field/GEP work falls, with tmux approximately unchanged. Treat this as a hypothesis,
not a correctness invariant. Report increases in derived lanes, memory, solve time, or fallback
sizes and explain the net tradeoff. The old GEP share motivates a possible substantial saving;
it does not establish a wall-time ceiling or guarantee the paper's 7× speedup.

### 5.3 Soundness and precision ledger (every item)

- Run `target/release/pangs differential $CORPUS/<m>.bc --build-mode executable` for each
  module under both configurations. Cross-tier refinement is checked **within** one
  configuration, including the target lattice's unknown/top semantics. Record existing
  failures, including the one-hop write defect, as dependencies; a shared missing fact can
  pass a differential check, so agreement is not an independent soundness proof.
- `cargo test --workspace --all-targets`, including explicit expected writes/targets,
  overflow, replay, and late-cell tests. Inspect every re-baselined golden row.
- Indirect calls: use `pangs icall-census` before/after for target counts and
  `unknown_callee` status, and compare callgraph exports for actual target identities.
  Equal counts do not rule out exchanged targets. Classify added/removed targets.
  A/B may widen or narrow relative to the old configuration;
  justify losses and measure their client cost. Removed targets require evidence that they
  are infeasible, not merely a subset check. For C with the same field domain, narrowing is
  expected, but still does not prove soundness.
- Clients: `pangs report` on both output directories; ModRef unknown rows, per-global
  `written` facts, and the disposition distribution (`HOWTO_MEASURE_DISPOSITION_COVERAGE.md`)
  must be compared in both directions. Every lost real write is a correctness failure;
  extra conservative writes are a coverage cost to report. For C, audit disappearing
  `written` witnesses and resulting disposition improvements against fixture semantics or
  source evidence before counting them as recovered precision.
- Dynamic check where traces exist: `pangs instrument` + `check-traces` (see `PLAN-M5.md`
  and the runbook) on at least one module.

### 5.4 Promotion

Promote a knob to default only when §5.2 demonstrates a worthwhile measured benefit on sqlite
and vim, §5.3's correctness gates pass on the whole evaluation set, precision losses have been
reviewed and recorded, and the full workspace tests pass. Unresolved base-tier soundness
failures are blockers, not acceptable precision tradeoffs. Keep the
ablation value (`=0`) documented in `DESIGN_lite.md` next to the other
`PANGS_ANDERSEN_*` knobs, and add the measured numbers to `EXPERIMENT_HISTORY.md` and
`notes/07-dea-pwc.md`.

## 6. Non-goals

- No cyclic extension of the exact-address proof or implementation of the Steensgaard
  one-hop fix. The bounded domain may be reused there; its replay and mixed-summary
  obligations remain separate.
- No new receiver context abstraction or byte-sliced memcpy. C does include adapting their
  existing content consumers, and the certificate/boundary consumers, to overlap-aware reads.
- No adoption of the paper's field-index object model, max-field bounds, or wave
  propagation; the byte-offset vocabulary and semi-naive joins stay.
- No per-round SCC detection (item B) unless A's residue measurement demands it.
