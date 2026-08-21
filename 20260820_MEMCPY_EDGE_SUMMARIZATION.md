# Per-Site `memcpy` Edge Summarization

## Status

The unconditional opt-in prototype was implemented and evaluated on 2026-08-20 under
`PANGS_ANDERSEN_MEMCPY_EDGE_SUMMARIES=1`. It was promoted to the default on 2026-08-21;
`PANGS_ANDERSEN_MEMCPY_EDGE_SUMMARIES=0` retains the direct join for ablation. Focused
and full-workspace tests pass. Forced
gifsicle admission completes in 119.08 seconds at 2,301,692 KiB peak RSS, representing
16,609,344,880 logical pairs with 6,021 summary edges and zero direct memcpy-pair
iterations. Default admission remains unchanged. Adaptive promotion and a summary-aware
admission model are not implemented; see `EXPERIMENT_HISTORY.md` for the measured result.

This experiment targets the intrinsic source-object × destination-object copy-edge
product created by Andersen's field-insensitive `memcpy` rule. It does not change PAG
construction, prepartition admission, ModRef, or the semantic treatment of copied bytes.
The first implementation was opt-in and had to preserve all client-visible analysis exports.

## 1. Problem statement

For one `memcpy(dst, src)`, the current solver maintains the discovered endpoint sets

```text
D = pts(dst)
S = pts(src)
```

and materializes the complete relation

```text
for d in D:
    for s in S:
        add_copy(s, d)
```

The existing semi-naive join is already incremental: a newly discovered destination is
joined with all sources, and a newly discovered source is joined with the old
destinations. Each logical pair is therefore processed once. The remaining problem is
the final `|S| * |D|` relation itself.

Forced admission of the sole oversized component in `exe-gifsicle-O0.bc` makes this
cost concrete:

| Property | Value |
|---|---:|
| Component nodes | 20,702 |
| Component edges | 21,934 |
| Admission cost proxy | 882,650,472 |
| Default admission budget | 200,000 |
| `memcpy` constraints | 162 |
| Baseline complete run | 1.32 s, with the component rejected |
| Forced run after about four minutes | still incomplete |
| Forced-run points-to facts observed | 169,178,151 |
| Forced-run `memcpy` pairs processed | 4,735,587,846 |
| Forced-run copy-fact pairs processed | 1,016,456,211 |

A 30-second `perf` sample of forced Andersen work attributed 18.59% self time to
`Solve::note_direct_access`, 18.30% to hashing, 16.87% to `HashMap::insert`, 9.38%
to `Solve::field_of`, and 5.77% to hash-table reallocation. The current nested
`memcpy` loop calls `note_direct_access(source)` once per destination/source pair,
which magnifies that constant-factor cost, but removing the redundant call alone does
not remove the Cartesian copy graph.

That sample had no usable user-space callchains. The `field_of` percentage is therefore
solver-wide evidence, not evidence that `memcpy` invokes `field_of`; the current
`memcpy` join does not. It operates on the content cells already present in its operand
points-to sets, as specified below.

The admission budget is therefore avoiding real pathological work. The purpose of this
experiment is to determine whether the same component becomes economically solvable
when complete `memcpy` bicliques are represented symbolically.

## 2. Prior work and the exact delta

This proposal must not be confused with the discarded generic copy-biclique experiment
in `EXPERIMENT_HISTORY.md`.

`PANGS_ANDERSEN_COPY_BICLIQUES=1` grouped ordinary copy sources having literally
identical complete successor sets and rewrote

```text
S x D  =>  S -> synthetic union -> D
```

after copy edges existed. It reduced static copy edges but did not alter `memcpy`'s
dynamic endpoint join. YAPET retained 10,782,185 `memcpy` pairs at O1 and 6,084,000
pairs at O0. The isolated experiment slowed O1 by 5.1% and fully admitted O0 by 1.0%,
so it was discarded.

The proposed change applies the same algebra at a different, load-bearing point: each
`MemcpyJoin` owns a fresh propagation-only cell before endpoint pairs are materialized.
Discovered endpoints connect directly to that cell, and the solver never constructs the
per-site `S x D` edge set.

The broader pointer-region and lazy-copy proposal in `20260730_MEMCPY_HANDLING.md` is
also distinct and remains unimplemented. It changes which copied regions carry pointer
flow. This experiment keeps the current conservative whole-object pointer semantics and
changes only their representation.

## 3. Proposed abstraction

For each deduplicated `MemcpyJoin`, allocate one fresh propagation-only cell `u` and
represent the copy as

```text
for s in S: add_copy(s, u)
for d in D: add_copy(u, d)
```

When endpoints grow:

```text
on new destination d:
    note_direct_access(d)       # matches the current outer destination loop

if S and D are both nonempty:
    activate the join if needed
    connect every endpoint not yet connected
```

No source/destination Cartesian loop remains. Persistent copy edges fall from
`O(|S| * |D|)` to `O(|S| + |D|)` for that site.

A join remains dormant until both endpoint sets are nonempty. While dormant it retains
discovered endpoints but installs no summary copy edges and does not mark a source
directly accessed. This preserves the current solver's empty-side behavior; it is not
merely a scheduling optimization.

The summary is:

- fresh per deduplicated `MemcpyJoin`;
- never shared between copy sites;
- a propagation variable, never an allocation or pointee identity;
- absent from analysis exports and client object domains;
- retained across joint call-graph resume rounds; and
- eligible for ordinary exact copy propagation and copy-SCC handling.

## 4. Equivalence argument

### 4.1 Actual cell granularity

For one PAG `memcpy(dst_operand, src_operand)`, define

```text
S = canonical cells in pts(src_operand)
D = canonical cells in pts(dst_operand)
```

An element of `S` or `D` is the solver content cell of an addressed object. It may be a
root allocation cell or an already materialized allocation-relative exact, lane, or
unknown-offset field cell. It is not an aggregate whose fields the `memcpy` loop then
enumerates. The current loop performs exactly `add_copy(s, d)` for every `s ∈ S` and
`d ∈ D`; it does not call `field_of` and does not pair corresponding field offsets.
The baseline is therefore genuinely field-insensitive at this join. A single summary
cell represents precisely that union relation and would not be valid for a future
field-preserving aggregate-copy rule.

The summary connects the actual endpoint content cell `s` or `d`, not every field below
its root and not an eagerly created unknown-offset cell. Existing field-domain rules
provide the necessary indirect flow:

- `note_direct_access(root)` records whole-object access and, if the root's unknown-offset
  cell already exists, installs the bidirectional root/unknown bridge;
- if that unknown-offset cell is materialized later, `field_of(root, Unknown)` observes
  `direct_accessed` and installs the same bridge then;
- the unknown-offset cell aliases every exact/lane field whose `FieldLocation` may alias
  it, including fields materialized after the unknown cell; and
- `note_direct_access(field_cell)` deliberately does nothing, matching the baseline when
  an operand already points to an allocation-relative subobject.

Consequently, a late may-alias field on an already connected root reaches the summary
through `field ↔ unknown ↔ root → summary` (and symmetrically on a destination).
A late field that the field domain says does not alias the directly copied cell gains no
flow in either representation. If a newly materialized field cell later enters
`pts(src_operand)` or `pts(dst_operand)` itself, it is a new join endpoint and must be
connected by the ordinary endpoint-delta rule.

### 4.2 Fixed-point factoring

For a fixed site, the current constraints are

```text
forall s in S, d in D: pts(s) subseteq pts(d)
```

The summary constraints are

```text
forall s in S: pts(s) subseteq pts(u)
forall d in D: pts(u) subseteq pts(d)
```

These physical summary constraints are installed only after both `S` and `D` are
nonempty. If either side is empty, the baseline relation over real cells is vacuous and
the summary remains dormant; this also preserves the baseline's guarded direct-access
side effects.

At the least fixed point,

```text
pts(u) = union { pts(s) | s in S }
```

and every destination receives that union, exactly as with the complete biclique.
This remains true when source contents grow, endpoints are discovered late, source and
destination endpoint sets overlap, or copy edges participate in cycles. The normal
pending-edge protocol seeds a newly added edge from the source's complete current set;
later facts flow as deltas.

The equivalence depends on these invariants:

1. Once both endpoint sets are nonempty, every canonical content cell discovered in the
   operand points-to sets is connected to the site's summary; a one-sided join remains
   dormant.
2. The summary is unique to the site; cross-site sharing is forbidden. If copy-SCC
   collapse makes two joins' endpoint variables canonically identical, their already
   allocated summary cells remain distinct. That redundancy is equivalent and intentional;
   do not add a post-collapse "deduplication" that shares their summaries.
3. The summary never appears inside a points-to set.
4. External facts and their exact source labels propagate across both summary edges.
5. `note_direct_access` preserves the baseline guards exactly: every newly discovered
   destination is marked immediately, while a source is marked only when at least one
   destination exists. It is never applied to the summary.
6. Late field materialization uses the existing root/unknown/field alias bridges; it does
   not require or permit enumerating a root's fields into the memcpy summary.
7. Canonicalization and SCC collapse preserve the existing non-pointee synthetic-cell
   contract.
8. An exhausted solve exposes no partial refined result; the existing transactional
   Steensgaard fallback remains unchanged.
9. Certificate audits consume the join's complete logical endpoint relation, not the
   physical copy-edge representation chosen for propagation.

## 5. Initial implementation

### 5.1 Experimental knob

Add an opt-in environment knob:

```text
PANGS_ANDERSEN_MEMCPY_EDGE_SUMMARIES=1
```

The default remains the current semi-naive Cartesian join until correctness and corpus
measurements pass. Tests must scrub the knob unless they explicitly exercise it.

### 5.2 Cell role

Reuse the established propagation-only union-cell machinery where possible, but give
`memcpy` summaries an explicit role so they can be diagnosed and excluded from pointee
materialization. If the current representation does not distinguish synthetic roles,
add an internal role table or bitset with at least:

```text
ordinary
copy-union
memcpy-summary
```

The role must grow with `allocate_cell()` and survive canonicalization. It is internal
solver metadata, not a PIR/PAG concept.

### 5.3 `MemcpyJoin`

Extend `MemcpyJoin` with its summary cell in summarized mode:

```rust
struct MemcpyJoin {
    dst: Cell,
    src: Cell,
    summary: Option<Cell>,
    summary_active: bool,
    seen_destinations: HashSet<Cell>,
    seen_sources: HashSet<Cell>,
}
```

`add_memcpy` continues to deduplicate canonical `(dst, src)` endpoint variables. When
the knob is enabled, it allocates one summary cell for the new join. The summary must
not be inserted into either endpoint set or any allocation lookup.

Deduplication occurs only when the logical join is initially registered. Two distinct
joins that later acquire identical canonical endpoints through copy-SCC collapse keep
two summary cells. They may have redundant star graphs, but must retain independent
summary identity, endpoint inventories, metrics, and adaptive state.

### 5.4 Delta processing

Keep endpoint discovery semi-naive. In summarized mode, `memcpy_delta` needs only the
new source and destination vectors; it no longer constructs `all_sources` or
`old_destinations` for a Cartesian join. Each vector contains the canonical addressed
content cells drawn from the PAG operands' points-to sets; do not expand a root into its
materialized fields when connecting the summary.

Preserve the baseline's asymmetric direct-access behavior precisely:

1. Record new sources and destinations in the retained endpoint sets.
2. Mark every new destination directly accessed immediately. The current outer
   destination loop does this even when the source set is empty.
3. If either complete endpoint set is empty, leave the summary dormant: install no
   summary edge and do not mark any source directly accessed.
4. On the first transition to two nonempty endpoint sets, mark all retained sources,
   add every `source -> summary` edge, add every `summary -> destination` edge, and set
   `summary_active`.
5. Once active, mark and connect each newly discovered source, and connect each newly
   discovered destination (which step 2 has already marked).

Deferral loses no source facts: `add_copy` seeds a newly installed edge from the source's
complete current points-to set. It does prevent the summary representation from creating
unknown-field bridge edges for a source that the direct Cartesian rule never actually
uses.

The baseline path remains unchanged behind the disabled knob. The proposed
`note_direct_access(source)` cleanup is permitted only as a guarded idempotence
optimization: hoist it out of a Cartesian inner loop after proving that loop's opposite
dimension is nonempty. Concretely, sources in `all_sources` may be marked once only under
`!new_destinations.is_empty()`, and sources in `new_sources` may be marked once only under
`!old_destinations.is_empty()`. Never hoist source marking above either guard. Add the
empty-side tests below before asserting that this cleanup preserves results.

### 5.5 Interaction with generic biclique factoring

The default-off `PANGS_ANDERSEN_COPY_BICLIQUES` experiment must not refactor an existing
`memcpy` summary into another union layer. Either exclude `memcpy-summary` sources and
destinations from that pass or reject simultaneous use of the two experimental knobs.
Add a focused combination test for the chosen rule.

### 5.6 Closed-producer and closed-consumer certificates

`PANGS_ANDERSEN_CLOSED_PRODUCERS` and `PANGS_ANDERSEN_CLOSED_CONSUMERS` both make
subtractive decisions: a successful proof removes a conservative unknown bit. Their
correctness must therefore be independent of whether a `memcpy` join is represented as
a biclique or as two stars through a summary cell.

Define one read-only logical-endpoint interface over `MemcpyJoin`. After canonicalizing
and deduplicating its retained sets, it exposes:

```text
sources(join)      = seen_sources
destinations(join) = seen_destinations
transfers(join)    = sources(join) × destinations(join)
```

This interface, rather than `copy` adjacency, is the source of truth for every
post-solve audit that needs the logical aggregate-copy relation. At solve quiescence the
seen sets must equal the corresponding final operand points-to sets. Add a debug/test
assertion for that equality after canonicalization; exhaustion never reaches the
certificate phase. Copy-SCC collapse may leave stale cell IDs in the sets, so the
interface must canonicalize them rather than exposing the raw hash sets.

The closed-consumer audit must enumerate every logical `source × destination` transfer
through this interface and verify the named-function fact at the real destination. It
must not infer transfers by walking materialized copy edges: in summarized mode that
would see `source -> summary` and `summary -> destination`, not the logical pair. Missing
join metadata, a non-quiescent endpoint inventory, or an endpoint that cannot be mapped
back to the PAG `memcpy` fails the affected function certificates open; it never permits
clearing `unknown_callers`.

The closed-producer graph retains its current conservative aggregate-copy rule: every
real destination cell affected by a logical join, including its materialized fields, is
incomplete. Discover those destinations through the same logical-endpoint interface.
A `memcpy-summary` cell is outside the declared graph domain of PAG values and
materialized allocation-relative cells. If it nevertheless enters graph construction,
classify it as an unsupported producer (`explicit_open = true`, never a terminal) and
propagate that incompleteness to any dependent real cell. Do not let a summary cell become
a closed root merely because it has incoming propagation edges.

Add internal role assertions so neither certificate mistakes a summary for an allocation,
field, named function, or external region. These checks are soundness guards, not optional
profile diagnostics.

### 5.7 No prepartition change

The prepartition graph continues to contain its existing `memcpy` connectivity edge.
Admission cost and cut-boundary soundness therefore do not change in the first
experiment. The optimization affects work only after a component is admitted.

In particular, gifsicle's oversized component remains rejected at the default `200000`
budget with summaries enabled. The initial experiment can demonstrate only whether
forced admission becomes economical; it must not claim improved default-budget coverage.
If forced admission succeeds, the quadratic proxy becomes a known candidate bottleneck,
because it estimates the unsummarized structural risk and cannot see the cheaper dynamic
join. Recalibrating or making admission summary-aware is a separate follow-up experiment
with its own corpus safety limits; do not silently raise the budget as part of this work.

Likewise, PAG `memcpy` operations, ModRef reads and writes, disposition facts, and audit
findings remain unchanged.

## 6. Adaptive production form

The discarded generic biclique experiment shows that an extra union node can cost more
than it saves for small relations. Unconditional summaries are appropriate for a clean
A/B prototype, but not necessarily for the default implementation.

After the unconditional experiment, add monotone adaptive promotion:

1. Start a site in the current direct semi-naive mode.
2. Track its discovered `|S|`, `|D|`, logical-pair count, and inserted direct edges.
3. Promote when the avoided future/product work exceeds a measured threshold.
4. Allocate one summary and connect every already seen source and destination.
5. Retain already inserted direct edges as harmless redundant constraints.
6. Route every future endpoint through the summary and never demote.

Promotion is monotone: it only adds equivalent constraints. Treat it as an explicit
transactional state transition, not a single unchecked boolean flip:

```text
Direct -> Promoting(summary, source_cursor, destination_cursor) -> Summarized
```

Allocate the summary and retain all existing direct edges on entry to `Promoting`.
Install the source and destination stars idempotently, recording enough cursor/state to
finish safely if execution resumes. Publish `Summarized` only after both retained
endpoint sets are connected. An injected limit or real exhaustion at any intermediate
point exposes no partial refined result: the ordinary Steensgaard fallback wins. If the
test harness resumes the same solve, it must complete the pending promotion before
routing later endpoint deltas.

A simple initial trigger is

```text
|S| * |D| >= PANGS_ANDERSEN_MEMCPY_SUMMARY_MIN_PRODUCT
```

with a conservative default selected from corpus data. The final trigger should compare
actual direct edges with the `|S| + |D|` summarized shape and account for the extra
worklist node. Do not choose a production threshold from gifsicle alone.

## 7. Metrics and diagnostics

The existing `memcpy_pairs_processed` counter must not silently change meaning. Split
the telemetry into:

- `memcpy_logical_pairs_covered`: the Cartesian pairs represented by either path;
- `memcpy_direct_pairs_processed`: pairs actually iterated by the baseline/direct path;
- `memcpy_summary_edges_inserted`: real source/summary and summary/destination edges;
- `memcpy_summary_sites`: joins summarized or promoted;
- `memcpy_summary_cells`: propagation-only cells allocated;
- `memcpy_direct_edges_retained_after_promotion`;
- per-site maxima for `|S|`, `|D|`, logical product, and summary edges; and
- the existing downstream copy-fact, points-to-fact, SCC, field-cell, runtime, and RSS
  counters.

For compatibility, retain `memcpy_pairs_processed` as an explicitly documented alias for
`memcpy_direct_pairs_processed` during the experiment, or version the profiling output.
Never report logical avoided pairs as work actually performed.

Add a profile line for every site crossing a configurable large-product threshold. It
must identify the PAG copy site or endpoint labels, not only internal cell numbers.

## 8. Correctness tests

### 8.1 Focused solver tests

Run each fixture with direct joins and summarized joins and compare complete points-to
solutions:

1. One source and one destination.
2. Multiple sources and one destination.
3. One source and multiple destinations.
4. Multiple sources and destinations: the complete biclique case.
5. Sources discovered before destinations and vice versa.
6. New source contents after both endpoint edges are established.
7. Source and destination endpoint overlap (`memmove`/self-copy shape).
8. Two copy sites with identical endpoints: deduplication follows current semantics.
9. Two distinct sites with overlapping endpoints: summaries remain site-local.
10. External and universal source regions retain exact external-source propagation.
11. Function-pointer contents reach the same indirect-call operands.
12. Summary edges participating in a copy SCC.
13. Call-graph activation adds late endpoint facts across a resume round.
14. Injected exhaustion returns the ordinary complete fallback, never partial refinement.
15. Summary cells never appear as pointees or exported allocation identities.
16. With closed consumers enabled, a function address copied through a multi-source,
    multi-destination join is certified identically in direct and summarized modes.
17. With closed consumers enabled, deliberately suppressing or corrupting one retained
    endpoint in a test hook leaves `unknown_callers` set; the audit fails open.
18. With closed producers enabled, every real destination of an aggregate copy is
    incomplete in both modes, and a summary cell that reaches the producer-graph builder
    is explicitly open.
19. A copied function address behind an external destination retains both the appropriate
    unknown-caller and unknown-callee conservatism with either certificate enabled.
20. A permanently empty source set with a populated destination set marks exactly the
    same destinations directly accessed in both modes, installs no active summary edges,
    and produces identical unknown-field bridges and exported facts.
21. A populated source set with a permanently empty destination set does not mark the
    sources directly accessed in either mode and installs no active summary edges.
22. If the missing side becomes nonempty in a later worklist or call-graph resume round,
    activation connects all retained endpoints and propagates their complete current
    facts; the final direct-access set, unknown-field edges, and points-to solution match
    the direct join.
23. Run the guarded baseline hoist with summaries disabled against the unmodified loop on
    both empty-side fixtures and compare the internal `direct_accessed` set as well as all
    normalized client exports.
24. Materialize an unknown-offset cell only after an already-seen root source and root
    destination have been connected. Verify the late root/unknown bridges propagate
    existing and subsequent field facts identically through direct and summarized joins.
25. Materialize exact and lane fields both before and after the unknown-offset cell and
    verify that precisely the `FieldLocation::may_alias` fields participate in both modes.
26. Materialize an exact field on an already-seen root without making that field an
    operand pointee and verify that summarization invents no per-field memcpy edge or
    flow absent from the baseline.
27. After a field cell is materialized, add that field cell to an operand's points-to set
    in a later delta/resume round. Verify that it is treated as a new endpoint, connected
    to the site summary, and reaches the same destination cells as the direct join.
28. Assert structurally that summarized memcpy processing itself neither calls
    `field_of` nor creates allocation-relative field cells; only ordinary field-domain
    operations may create them.
29. In adaptive mode, inject exhaustion after promotion allocates its summary but before
    either star is complete, and again after each individual star is complete. Existing
    direct edges remain retained, no partial Andersen result or certificate is exported,
    and the caller receives the ordinary complete fallback.
30. Resume the same injected mid-promotion states in a solver-level harness. Promotion
    finishes idempotently before later endpoint deltas, and the final solution matches an
    uninterrupted adaptive solve and the direct baseline.
31. Create two distinct joins that copy-SCC collapse makes canonically identical. Verify
    that they retain two summary cells, produce the baseline solution, and are not merged
    by summary-role or generic biclique machinery.

Tests should compare not just named targets but unknown/external bits and provenance
labels.

### 8.2 Pipeline equivalence

For synthetic aggregate-copy fixtures and selected corpus inputs, require byte-identical
normalized exports between the two modes for:

- call graph;
- global points-to resolutions;
- ModRef rows;
- stationarity;
- audit findings;
- disposition facts and final assignments; and
- validation results.

Metrics and run-option provenance are expected to differ and must be excluded from the
semantic comparison.

### 8.3 Existing experiments

Run tests with hybrid points-to sets, copy-SCC collapse, offline quotient, receiver
payloads, and injected resume/exhaustion controls as applicable. In particular, exercise
the complete certificate matrix:

| Memcpy summaries | Closed producers | Closed consumers |
|---|---|---|
| on | off | off |
| on | on | off |
| on | off | on |
| on | on | on |

The last three rows must include a genuine multi-source, multi-destination aggregate
copy and compare unknown-callee/unknown-caller bits with summaries disabled. Also combine
each certificate with copy-SCC collapse, because canonicalization can rewrite the cell IDs
retained by a join. Experimental combinations that are intentionally unsupported must
fail loudly at option parsing rather than silently changing semantics; summaries plus
either certificate may not be declared unsupported merely to bypass these tests.

## 9. Performance evaluation

### 9.1 Primary pathological case

Use the exact input bytes previously measured:

```text
/home/brk/pangs-corpus/_out_bc/exe-gifsicle-O0.bc
sha256 513bf2a2971252dd7fc615192dd6c1b1c6f8e96f3f78e06f88f152355de5612a
```

Measure release builds pinned to one CPU where practical. Compare:

1. Default budget, summaries off/on.
2. Forced admission with `--partition-budget 900000000`, summaries off/on.
3. A 30-second `perf` profile of each forced arm.

The expected result for comparison 1 is the same admission rejection in both arms. Any
claim that summaries improve gifsicle coverage requires a separately designed
summary-aware admission experiment; it is not an outcome of this plan.

Record wall time, user time, peak RSS, completion status, solver counters, summary
counters, disposition distribution, and the `parse_int@!noloc#7` ModRef row. A faster
solve is useful even if genuine universal provenance leaves that row module-wide.

The first forced experiment must have a predeclared time and memory cap. Report timeout
or resource failure as a result; do not let an uncapped pathological run continue.

### 9.2 Historical regression cases

Re-run the YAPET O0/O1 cases from `EXPERIMENT_HISTORY.md`, including forced admission,
because they motivated both incremental joins and the discarded generic biclique pass.
The new mode must reduce actual `memcpy` pair iteration; unchanged pair volume means the
implementation has repeated the old experiment at the wrong layer.

### 9.3 Standard corpus

Use the established admission-calibration corpus and include programs with:

- no `memcpy`;
- many singleton `memcpy` endpoint sets;
- aggregate and function-pointer copies;
- external/universal endpoints;
- admitted and rejected megacomponents; and
- both O0 and optimized IR.

Report aggregate and geometric-mean wall/RSS changes, timeout/resource changes, semantic
export diffs, sites summarized, and avoided logical products. Separate default-budget
results from forced-admission experiments.

## 10. Acceptance gates

The unconditional prototype may advance to adaptive promotion only if:

1. All focused and workspace tests pass.
2. Normalized client-visible exports are identical on every completed A/B pair.
3. No summary cell appears as a pointee, global, allocation, or external source label.
4. Empty-side and late-activation tests have identical `direct_accessed` sets and
   unknown-field bridge edges. There is no equivalence carve-out for unconditional
   endpoint marking.
5. Late unknown-offset, exact-field, and lane-field materialization produces identical
   field cells, alias bridges, and propagated facts in both modes; the summary creates no
   field cells or field-preserving correspondence of its own.
6. For both closed certificates independently and together, summarized mode clears
   exactly the same unknown-callee and unknown-caller bits as direct mode. Any mismatch
   is a soundness blocker, even when all ordinary points-to exports match.
7. Gifsicle's forced run shows an orders-of-magnitude reduction in direct `memcpy` pair
   iteration and avoids the observed points-to/copy-edge explosion.
8. The experiment either completes the forced case within its cap or identifies a new
   dominant cost with evidence.

Adaptive promotion may become the default only if:

1. Standard-corpus geometric-mean wall time does not regress materially; use 3% as the
   initial review threshold, not an automatic waiver.
2. Aggregate peak RSS does not regress materially; use 5% as the initial threshold.
3. Singleton/small-product sites remain on the direct path unless measurements justify
   their promotion.
4. No new timeout or resource failure appears.
5. The disposition and soundness-validation suites remain unchanged.
6. Exhaustion at every injected `Promoting` checkpoint returns only the complete fallback,
   while solver-level resume completes the same promotion idempotently and reaches the
   uninterrupted fixed point.

If unconditional summaries fix gifsicle but adaptive summaries cannot avoid corpus
regressions, retain the feature as an admission-aware experimental rescue mode rather
than raising the global partition budget.

## 11. Documentation and disposition of results

After measurement:

- record the implementation and all A/B results in `EXPERIMENT_HISTORY.md`;
- update `DESIGN_lite.md` only if the path becomes production behavior;
- update metric descriptions and the admission runbook if counters change;
- if forced gifsicle becomes economical, record explicitly that default admission still
  rejects it and open the cost-proxy recalibration as separate future work;
- delete or clearly mark obsolete experimental knobs if the experiment is discarded;
  and
- do not conflate this representation optimization with the still-separate
  pointer-region/projection work in `20260730_MEMCPY_HANDLING.md`.

The decision should answer three separate questions:

1. Is per-site summary factoring Andersen-equivalent in the implementation?
2. Does it make forced megacomponent admission economically viable?
3. Can an adaptive trigger deliver that benefit without repeating the prior generic
   biclique regression on ordinary inputs?
4. If forced admission is now economical, what measured summary-aware cost model could
   replace or augment the stale quadratic proxy without admitting other pathological
   components indiscriminately?
