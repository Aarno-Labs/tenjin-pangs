# PANGS-lite Experiment History

This file records retrospective measurements, discarded prototypes, and the
implementation chronology behind `DESIGN_lite.md`. It is evidence for design decisions,
not a normative description of the current analysis. Unless stated otherwise, prototype
code described here was removed after evaluation.

See [DESIGN_lite.md](DESIGN_lite.md) for the current architecture, invariants, and
upgrade path.

## Implementation milestones

1. **M1 — sound end-to-end (landed):** A' + C' + D' with joint call-graph discovery,
   Ω taint, violation detection, and the FSA filter supplied correct, coarse input to
   the localization client. The initial metrics were mutable-global localization
   coverage, component-size distribution, and load-bearing unknowns.
2. **M2 — the precision jump (landed):** B1 + B2 + B3 added stationarity,
   exact/simple bindings, confined subtraction, finite field summaries, and narrowing
   ledgers.
3. **M3 — measure and decide (lite selected):** corpus measurements kept Andersen as
   the authoritative final tier. CFL/MHS query kernels were implemented as experimental
   diagnostics and deliberately left disconnected from production results.
4. **M4 — structural megapartition refinements:** independent allocation-relative
   prepartitioning and directional source-closed SCC admission became general admission
   machinery. Receiver-allocation payload summaries with bounded allocation origins
   remain opt-in while their cross-corpus precision/runtime tradeoff is evaluated.

## Chibicc receiver-payload and bounded-origin evaluation

On `exe-chibicc-O1.bc`, enabling receiver-allocation-relative payload summaries plus
bounded allocation origins changed the dominant admitted region and the formerly
unknown macro-handler call as follows:

| Metric | Baseline | Extension enabled |
|---|---:|---:|
| Megapartition vertices | 10,284 | 9,465 |
| Megapartition edges | 12,290 | 11,604 |
| Quadratic cost proxy | 232,151,016 | 199,418,085 |
| Andersen propagation steps | ~3,632 | ~4,754 |
| Indirect calls resolved by Andersen | 0 | 1 |
| Unknown indirect calls | 1 | 0 |

The recovered call in `preprocess2` had exactly the five macro handlers
`base_file_macro`, `counter_macro`, `file_macro`, `line_macro`, and
`timestamp_macro`. Its returned `Macro *` set contained the 50 named macro allocations,
and loading `Macro.handler` narrowed those to the five functions without an external
region.

The size reduction was real but not free: same-process measurements showed about 15%
wall-time and 23% solve-time overhead on this input. The feature therefore remained
opt-in pending evidence that its call-graph and component precision generalize across
the corpus.

## Slap fixed-PAG producer projection

A follow-up to the shared closed-producer certificate tested whether a fixed-PAG memory
projection graph could avoid its dependence on Andersen's materialized memory cells.
The prototype represented memory as `(allocation root, field/lane)` vertices, preserved
known-width aggregate copies, treated an unknown-length copy as an offset-preserving
transfer over the finite queried-field vocabulary, and propagated
`{named function targets, incomplete}` over SCCs.

A module-wide address-only inclusion solve named the projection endpoints and recovered
97 targets for `dispatch_word` plus 105 targets for each `eval_body*` site. It was not a
viable replacement:

- The address solve and projection expansion raised Slap wall time from about 0.84
  seconds to 6.8 seconds, with 45,971 vertices and 518,583 completeness dependencies
  after lane aliases.
- Reusing only admitted Andersen address facts still took about 5.1 seconds and lost
  the 105-target `eval_body*` producer chains at cut boundaries.
- Even with global endpoints, both `eval_body*` certificates remained incomplete
  because `Value.as.xt.fn` shares a tagged-union lane with non-function and unknown
  payload variants. Flow-insensitive lane projection could not use the preceding
  `VAL_XT` test to exclude them.
- Teaching the general inclusion solver to expand unknown-length array copies was much
  worse; the Slap run was stopped after 111 seconds.

The implementation was discarded. A useful successor needs both:

1. demand-driven, call-operand-rooted address-origin discovery, so it never solves all
   module address carriers; and
2. a compositional tagged-variant proof, or an equivalent defined-indirect-call filter,
   before union payload alternatives can be removed.

Copy projection alone was neither fast enough nor precise enough.

## Slap optimistic indirect-call terminal

A subsequent control measured the upper bound of the discriminator-sensitive part. It
restored the module-wide projection graph and, only at an indirect-call query, ignored
the graph's open and non-function alternatives while still requiring a nonempty finite
set of named functions. This was intentionally not a sound certificate: an open producer
could denote an externally supplied function.

The control recovered and selected all 105 named targets at each `eval_body*` callsite
and retained the 97-target `dispatch_word` certificate. This confirmed that the rejected
alternatives were the only remaining local precision obstacle.

It did not improve Slap's disposition coverage: coverage remained 46/50 with the same
four unhandled globals. It also changed `main.combined` from `localize` to `mutex`,
because the newly explicit callees enlarged its access context. In a same-build debug
comparison, wall time increased from 5.23 to 7.07 seconds.

The control was discarded. A real discriminator proof would improve call-graph quality,
but it was not on Slap's disposition critical path. Demand-driven address origins remain
a prerequisite if that work is resumed.

## Slap optimistic closed-consumer upper bound

The indirect-call control above was combined with an optimistic upper bound for
unknown-caller certification. After selecting the finite internal targets at the three
indirect calls, the control removed Steensgaard's escape-derived unknown-caller bit from
those target functions. This models the hoped-for result of a closed-consumer proof, but
not the proof itself: it did not establish that every use of each function address ended
at one of the selected internal calls.

The projection again selected 97 targets for `dispatch_word` and 105 targets for each
`eval_body*` site. Their union contained 105 functions, all of which lost unknown-caller
taint in the control. Slap's disposition coverage improved from 46/50 to 49/50:

- `cli_args`, `frame_save_target`, and `save_buf` changed from `unhandled` to `localize`;
- `main.combined` again changed from `localize` to `mutex` because the explicit callees
  enlarged its access context; and
- `stack` remained unhandled.

For `stack`, resolving the evaluator calls removed its unknown-callee blocker, but three
unknown-caller witnesses remained: `sort_cmp`, `grade_asc`, and `grade_desc`. These are
comparator callbacks passed through external sorting APIs, so they need registry-aware
consumer reasoning rather than the internal-call certificate measured here. `stack`
also retained its independent `derived:external-pointee` Ω escape and incomplete access
set.

The debug run took 6.82 seconds wall time and 308 MiB peak RSS. The prototype was
discarded because both optimistic steps were unsound controls and the module-wide
address solve remained too expensive. The coverage gain does justify pursuing a real,
demand-driven closed-consumer certificate for internal indirect-call targets. External
callback registries are a separate extension if eliminating `stack` becomes the goal.

## Slap closed-consumer certificate

The sound successor to the optimistic unknown-caller control was implemented as a
forward consumer audit over the bounded Andersen solve. It uses the final named-function
facts rather than running one reachability query per function. Internal indirect-call
operands are safe terminals; all external, exported, integerized, opaque-storage, and
externally returned paths remain open. Missing transfers at partition boundaries fail
closed. Boundary traversal includes allocation-relative fields, so an external pointer
to a struct also exposes callbacks stored in its materialized fields.

With only `PANGS_ANDERSEN_CLOSED_CONSUMERS` plus the receiver-payload option enabled, the
certificate independently promoted the bounded call partition and certified 105 of
Slap's 108 address-seeded functions. The run took 5.33 seconds and 308 MiB peak RSS.
Disposition coverage remained 46/50 because the three newly unblocked unknown-caller
paths still had unknown-callee blockers at `eval_body` and `eval_body_fast`.

With both closed-consumer and retained closed-producer certificates enabled, the consumer
result remained 105 functions, `dispatch_word` retained its 97-target producer
certificate, and the two evaluator sites remained producer-incomplete with zero
materialized targets. The final run took 5.09 seconds and 308 MiB peak RSS. The remaining
disposition inventory was therefore unchanged:

- `cli_args`, `frame_save_target`, and `save_buf` were blocked only by
  `unknown-callee-taint`; and
- `stack` was blocked by both `unknown-callee-taint` and the unknown callers associated
  with its external sorting callbacks.

This validates that closed-consumer reasoning is soundly separable and removes the
unknown-caller half of the measured critical path. Reaching the 49/50 optimistic upper
bound still requires a discriminator-sensitive producer proof for the tagged
`eval_body*` operands. Registry-aware sorting callbacks and `stack`'s independent Ω
escape remain separate work.

## Hybrid points-to bitsets

Phase 5 of `20260730_MEMCPY_HANDLING.md` was prototyped independently of the memcpy
model. `PANGS_ANDERSEN_HYBRID_BITSETS=1` retains points-to sets in small vectors and
promotes them to dense bitmaps after 64 facts by default. The threshold can be changed
with `PANGS_ANDERSEN_HYBRID_BITSET_THRESHOLD`; 64--256 performed similarly, while
always-dense storage was worse. `PANGS_ANDERSEN_HYBRID_BITSETS_PROFILE=1` reports the
final storage mix.

All 76 `pangs-solve` tests pass with both representations. Callgraph, ModRef, globals,
audit, and stationarity exports were byte-identical between the untouched and hybrid
solvers for forced full solves of YAPET O0, gifsicle O1, and chibicc O1.

Measured release-build results:

- YAPET O0: four interleaved pairs at threshold 128 reduced mean wall time from
  1.263 s to 0.978 s (-22.6%), mean solve time from 1.161 s to 0.880 s (-24.2%),
  and mean peak RSS from 102,433 KiB to 84,834 KiB (-17.2%). A separate twelve-pair
  threshold-64 run measured a comparable 23.5% wall reduction.
- chibicc O1: two forced-full-admission pairs reduced mean wall time from 5.285 s to
  3.210 s (-39.3%) and mean peak RSS from 219,142 KiB to 144,792 KiB (-33.9%).
- gifsicle O1: two threshold-128 hybrid runs averaged 82.6 s and 404,590 KiB, versus
  101.7 s and 1,115,372 KiB across three untouched runs. Solver/SCC order makes this
  case noisy, so the roughly 19% time reduction is indicative; the roughly 64% memory
  reduction is the stronger result.

At threshold 64, YAPET ended with 3,658 small and 2,250 dense sets; bitmap words
occupied 3.9 MiB. At threshold 128, gifsicle ended with 6,431 small and 3,934 dense
sets; bitmap words occupied 25.4 MiB.

A follow-up converted each vector delta to a temporary bitmap before copy propagation
and used wordwise dense-to-dense union. It did not measurably improve YAPET or gifsicle:
reconstructing the temporary bitmap consumed the union savings. That part was removed.
A useful wordwise implementation would store pending deltas natively as hybrid bitsets.

The retained prototype remains opt-in. Dense sets are indexed by the module-wide cell
ID, so a large, sparse module could allocate much more empty bitmap space than these
corpora. A production default should either validate this shape across the corpus or use
a sparse chunked/Roaring representation for promoted sets.

### Full-corpus forced-admission profile (2026-07-31)

The retained `scripts/profile_hybrid_bitsets_corpus.py` ran every top-level corpus
bitcode except the requested OpenSSL and Vim modules (49 modules, 98 configurations),
with a release binary, executable/library build mode inferred from the filename, and
`--partition-budget 18446744073709551615`. It alternated first-run order by module and
hashed callgraph, ModRef, globals, stationarity, and audit exports. The first 40
configurations used a 30-minute cap and the remaining 58 used a 10-minute cap. The
result JSON records the policy transition and every timeout.

Of 49 pairs, 36 completed successfully, 12 had one or two timeouts, and `lib-curl-O0`
baseline was externally terminated (exit 143) after reaching about 35.4 GiB. The 34
completed pairs with nonzero wall measurements totalled 1,944.18 s baseline versus
1,626.69 s hybrid (-16.3%). Their geometric-mean and median hybrid/baseline ratios were
0.860 and 0.891, respectively; hybrid won 24, lost 3, and tied 7. Across all 36
completed RSS pairs, aggregate peak RSS fell from 19.86 GiB to 12.00 GiB (-39.6%);
the geometric-mean and median ratios were 0.816 and 0.986.

The five client-visible output families were byte-identical for all 36 completed
pairs. Large completed wins included chibicc O0 (58.67 to 28.60 s; 1.48 GiB to
546 MiB), FLAC (37.75 to 20.98 s; 581 to 410 MiB), mbedtls (245.10 to 204.07 s;
1.75 GiB to 1.08 GiB), and zstd (467.35 to 382.84 s; 3.83 GiB to 2.47 GiB).
Several forced-full modules remained pathological under both representations, notably
tmux/cairo/curl/placebo
(high-RSS timeouts). The representation reduces memory substantially in many expensive
completed cases, but it does not by itself remove those propagation pathologies.

### Full-corpus normal-admission profile (2026-07-31)

The same 49-module subset was rerun with the normal `--partition-budget 200000` rather
than forced full admission. The first 30 configurations used a five-minute cap and the
remaining 68 used a one-minute cap. The initial census produced 42 complete pairs; all
five client-visible export families were byte-identical for those pairs.

The 40 completed pairs with nonzero wall measurements totalled 140.72 s baseline versus
136.08 s hybrid (-3.3%). Their geometric-mean and median hybrid/baseline ratios were
0.923 and 0.985. Aggregate peak RSS across all 42 completed pairs was effectively flat:
5.431 GiB baseline versus 5.420 GiB hybrid (-0.2%), with a 1.000 median ratio. The
single-pass timing ratios contained substantial scheduling noise: a repeat changed
Zstandard from an apparent 2x hybrid regression to 6.72 s baseline versus 6.39 s hybrid.

YAPET O1 retained a repeatable benefit (2.07--3.21 s baseline and 75--76 MiB versus
1.26--1.52 s hybrid and 63--65 MiB). Its storage profile had 2,312 small and 855 dense
sets, using about 1.18 MiB of bitmap words. Placebo showed the opposite pattern: repeated
baselines took 52.8--75.1 s, while hybrid runs took 70.3--77.9 s, with essentially
identical 1.03 GiB RSS. Its profile had 24,981 small-vector sets and **zero** dense sets.
It therefore pays linear small-vector operations without receiving bitmap storage or
union benefits. On normally admitted instances, the current representation is broadly
memory-neutral and only selectively faster; a production design should retain a hash or
sparse middle tier between tiny vectors and density-qualified bitmaps.

A follow-up after memoizing the compositional `va_list` forwarder proof completed two
paired iterations for every Lua and SQLite variant. Baseline versus hybrid mean wall/RSS
was 1.34/1.35 s and 139,948/140,062 KiB for executable Lua O0; 0.77/0.76 s and
100,270/100,560 KiB for executable Lua O1; 1.48/1.53 s and 165,430/165,334 KiB for
library Lua O0; 0.99/1.01 s and 124,666/124,628 KiB for library Lua O1; 20.26/20.38 s
and 655,514/655,264 KiB for SQLite O0; and 12.95/12.96 s and 627,738/627,776 KiB for
SQLite O1. Hybrid storage is effectively neutral on these bounded instances, and every
pair had identical hashes for all five client-visible exports.

### Three-tier hybrid points-to sets (2026-07-31)

The hybrid representation now uses a tiny vector (eight members by default), a sparse
`HashSet`, and a density-qualified bitmap. Dense promotion still requires more than 64
members, but additionally requires no more than 128 bitmap address-space bits per member.
An already-dense set demotes to sparse storage before a high-ID insertion could violate
that bound. Environment knobs can override the tiny limit, dense cardinality threshold,
and density bound.

On the same normal-budget 49-module census, the 41 nonzero completed pairs totalled
153.47 s baseline versus 143.73 s hybrid (-6.3%), with a 1.000 median ratio. Aggregate
RSS was 6.419 GiB versus 6.399 GiB (-0.3%). All five client-visible export families were
byte-identical for every completed pair. Absolute times varied materially between census
runs, so the important result is structural: Placebo no longer regressed (34.84 s
baseline versus 33.44 s hybrid, equal RSS), while YAPET O1 retained its benefit
(1.37 s/84 MiB versus 0.92 s/64 MiB). Placebo ended with 24,823 tiny, 158 sparse, and
zero dense sets; YAPET O1 had 2,307 tiny, five sparse, and 928 dense sets. The subsequent
paired Lua/SQLite measurements above likewise showed effectively neutral hybrid cost on
their bounded instances.

Forced-admission spot checks retained the large-instance payoff: YAPET O0 improved from
1.29 s/99 MiB to 1.07 s/84 MiB, chibicc O1 from 5.23 s/193 MiB to 3.96 s/150 MiB, and
gifsicle O1 stayed near 102 s while falling from 1.10 GiB to 500 MiB. This is the intended
disposition: sparse bounded instances avoid linear-vector overhead, while dense expensive
instances still receive bitmap memory savings.

### Compositional `va_list` forwarder memoization (2026-07-31)

The forwarder proof now retains one module-scoped context in both PAG construction and the
client audit scan. Fixed helper contracts are memoized by callee, variadic wrapper format indexes
are memoized separately, and direct calls are screened for carriage of the locally relevant
`va_list` or two distinct fixed parameters before recursively requesting a callee summary.
Potentially relevant recursive SCCs fail closed: an in-progress lookup propagates an explicit
cycle result through the whole active proof rather than being cached as an ordinary negative and
then ignored beside another sink. Tests cover repeated nested wrappers, self and mutual recursion,
and irrelevant recursive calls.

With the normal 200,000 partition budget and baseline points-to sets, release measurements were
1.47 s/165,288 KiB for Lua O0 and 19.34 s/655,292 KiB for SQLite O0, matching the earlier
proof-ablation and pre-regression range. Lua O1 measured 0.95 s/124,528 KiB and SQLite O1
11.93 s/627,956 KiB. The callgraph, ModRef, globals, audit, and stationarity exports for both
O0 modules were byte-identical to the earlier proof-ablation outputs.

### Exact offline Andersen quotient (2026-07-31)

`PANGS_ANDERSEN_OFFLINE_QUOTIENT=1` enables an exact simplification of the initial inclusion
system after eager/exact call bindings are installed and before propagation. It collapses static
copy SCCs; substitutes a generator-free variable whose only predecessor is one copy variable;
and value-numbers generator-free variables with identical nonempty predecessor sets. Address/Ω
seeds, all allocation identities, load and GEP results, function parameters, and call results are
protected as independent or possible late generators. The existing representative map preserves
every original query ID, while cells inside points-to sets remain the original allocation
identities. Profitable sources with exactly the same complete successor set are additionally
factored through a synthetic union variable; that variable is never installed as a pointee.

Broader neighborhood hashing was deliberately not implemented: identical successors do not imply
identical least points-to solutions. Likewise, multi-generator variables are merged only when
their normalized predecessor equations are literally identical, and partial bicliques are not
factored. These restrictions keep this an Andersen-equivalent quotient rather than hybrid
unification.

On YAPET O1, one profiled construction began with 6,977 cells and 1,344 copy edges. The quotient
merged 23 cells in static SCCs, 336 by sole-predecessor substitution, and five by value numbering,
leaving 6,613 representatives. The condensed graph had 948 edges; four exact fanout groups removed
another 218 edges, leaving 730 plus four synthetic variables. Offline construction cost 1.97 ms.
In the matched profile, propagation steps fell from 117,596 to 79,558, copy-fact pairs from
22,096,960 to 14,011,062, load/store/GEP pairs from 492,469/954,555/2,765,298 to
287,663/534,945/1,592,371, and dynamic SCC passes from 14 to 11. Memcpy pair volume was unchanged
at 10,782,185, confirming that this optimization makes the surrounding closure cheaper without
altering the byte-copy relation itself.

Ten interleaved release pairs used baseline hash points-to sets for each requested budget:

| YAPET O1 budget | Baseline wall / solve / RSS | Offline quotient wall / solve / RSS | Change |
| --- | ---: | ---: | ---: |
| 200,000 | 1.484 s / 1.397 s / 79,566 KiB | 1.141 s / 1.053 s / 80,720 KiB | wall -23.1%; solve -24.6%; RSS +1.5% |
| `u64::MAX` | 1.506 s / 1.420 s / 80,735 KiB | 1.264 s / 1.179 s / 77,738 KiB | wall -16.1%; solve -17.0%; RSS -3.7% |

Both budgets reported zero oversize fallbacks and therefore admitted the same O1 problem; the
difference between rows is hash-scheduling noise. Pooling the 20 runs gives a 19.6% wall reduction,
a 20.8% solve-time reduction, and effectively neutral RSS (-1.2%). Callgraph, ModRef, globals,
audit, and stationarity were byte-identical for every paired comparison. Focused tests cover
chains, diamonds, static cycles, independent/late generators, load/store/GEP/memcpy closure,
original client query IDs, and non-pointee synthetic fanout nodes; the full workspace test suite
and formatting checks pass. The prototype remains default-off pending broader corpus evaluation.

YAPET O0 behaves materially differently. Ten interleaved baseline/hash-versus-quotient pairs at
the normal 200,000 budget each took 0.216 s on average, with 64,186 versus 64,253 KiB RSS and
46.23 versus 45.76 ms solver time. Both retain the same 5,876-node oversize fallback. The quotient
does run on the admitted residue (28 substitutions and two fanout groups), but cannot reach the
dominant component and has no measurable end-to-end effect. With full admission (`u64::MAX`), ten
pairs averaged 1.585 s/1.401 s solver/102,942 KiB baseline versus 1.549 s/1.370 s/101,884 KiB
quotient (about 2% in each measure), but with wide 1.09--2.28 s and 1.26--1.75 s wall ranges. This
is not evidence of a reliable win: a representative profile increased steps from 95,949 to 131,103,
copy-fact pairs from 13.88M to 33.50M, and load/store/GEP pairs from 294k/241k/1.50M to
698k/566k/3.20M, despite reducing the initial graph from 1,317 to 717 edges (six static-SCC merges,
443 substitutions, six fanout groups). Memcpy work remains 6.084M pairs. All five client-visible
exports were byte-identical in every pair. The O0 quotient therefore needs targeted profiling or
admission-aware gating before it can be considered a general forced-solve optimization.

### Incremental complete-copy biclique factoring (2026-07-31)

`PANGS_ANDERSEN_COPY_BICLIQUES=1` isolates exact fanout factoring from the broader offline
quotient. Sources are grouped only when their complete nonempty successor sets are identical and
the replacement strictly reduces edges; an `S x D` group becomes `S -> union -> D`. The pass is
rerun after every indirect-call activation batch, including resume rounds after propagation has
already begun. New source-to-union edges therefore receive complete-set seeds under the existing
pending-edge protocol, and later source deltas use ordinary semi-naive propagation. Synthetic
union cells remain propagation-only and never appear as pointee identities. The offline quotient
uses the same extracted pass, preserving its earlier behavior.

On YAPET O1 the isolated pass found four groups, removed 218 edges, and added four union nodes. On
fully admitted YAPET O0 it found six groups, removed 145 edges, and added six nodes. Ten
interleaved release pairs pinned to one CPU used native hybrid deltas in both arms:

| YAPET case | Baseline wall / user / RSS | Bicliques wall / user / RSS | Change |
| --- | ---: | ---: | ---: |
| O1, normal budget | 0.916 s / 0.892 s / 60,530 KiB | 0.963 s / 0.938 s / 60,279 KiB | wall +5.1%, RSS -0.4% |
| O0, `u64::MAX` | 1.077 s / 1.038 s / 77,563 KiB | 1.088 s / 1.051 s / 77,140 KiB | wall +1.0%, RSS -0.5% |

All five client-visible export families were byte-identical in every pair. Focused tests cover
factoring after an already completed propagation, a second callback-like fanout expansion, later
points-to facts traversing the rewired graph, non-pointee union cells, and rejection of partial
fanout overlap. The isolated result is not a YAPET speedup: the edge reduction is real but does
not amortize the extra propagation node and changed worklist/SCC schedule. The switch therefore
remains default-off; its value in the earlier O1 quotient result cannot be separated from the
larger equation simplification without a more controlled propagation schedule.

### Copy-biclique standard-corpus profile (2026-07-31)

With the standard admission budget and hybrid points-to sets disabled,
copy bicliques had very little impact. 
The corpus confirms that exact edge reduction does not offset the
extra union-node propagation and changed SCC schedule under normal admission.
Based on these results, the experiment has been discarded.
It may need a propagation schedule designed to exploit the factored shape.

### Receiver-payload corpus profile after `mem2reg` (2026-08-01)

`scripts/profile_receiver_payloads.py` used a fresh release binary and current
`mem2reg`-transformed inputs, not cached results. It ran all 52 top-level corpus modules
(including OpenSSL and both Vim inputs) at the normal 200,000 budget, plus a forced-full
(`u64::MAX`) chibicc O1 pair. Hybrid points-to sets remained at their standard default
(disabled); all other Andersen experiment variables were scrubbed, and both arms enabled only
profiling while the experimental arm additionally set `PANGS_ANDERSEN_RECEIVER_PAYLOADS=1`.

The prototype is not viable as a general opt-in. Of the 52 standard pairs, 44 completed in both
arms. Across the 43 complete pairs with nonzero wall time, total wall rose from 71.96 to 520.17 s
(+623%; geometric-mean ratio 1.675, median 1.333), and aggregate RSS rose from 5.23 to 54.43 GiB
(+940%; geometric mean 3.44x, median 3.03x). Cairo O1 grew from 4.22 s/288 MiB to 382.70 s/5.96
GiB, YAPET O1 from 1.36 s/82 MiB to 17.31 s/214 MiB, and mbedTLS from 1.08 s/103 MiB to 8.56
s/479 MiB. The receiver arm timed out on Curl O1, FreeType, and Placebo; Vim (both variants),
OpenSSL, and SQLite O0/O1 exposed resource failures or a baseline timeout. The OpenSSL and SQLite
payload arms were terminated when their RSS reached 24 GiB and 22/8.7 GiB respectively, preventing
further host-memory escalation.

Precision also changed broadly: 10 complete pairs changed callgraph output, adding 400,983 and
removing 552 indirect-call edges across 792 changed callsites. ModRef changed in nine pairs,
stationarity in four, audit in three, and globals in one. Receiver summaries were inferred in ten
complete modules; most had incomplete-origin payload rows. The forced-full chibicc O1 pair was the
exceptional performance result (5.51 s/236 MiB baseline versus 1.02 s/174 MiB payload), but it
also changed five indirect edges (one removed) and therefore does not rescue the general design.
Keep this feature disabled pending a bounded-context design and precision validation.

### Per-site Andersen `memcpy` summaries (2026-08-20)

`PANGS_ANDERSEN_MEMCPY_EDGE_SUMMARIES=1` now gives each admitted PAG `memcpy` a fresh,
propagation-only cell and replaces its discovered source/destination biclique with
`source -> summary -> destination` stars. One-sided joins remain dormant so the existing
`note_direct_access` guards are unchanged. Summaries are site-local, never pointee identities,
and remain distinct when later copy-SCC collapse makes two joins canonically identical.
Closed-producer and closed-consumer certificates enumerate the retained logical endpoint sets,
not physical copy adjacency; a summary that surfaces in the producer graph fails open.

Focused tests compare direct and summarized incremental joins, empty endpoint sets, late
activation, late exact/lane/unknown field materialization, external propagation, copy-SCC
canonicalization, and non-pointee identity. The full workspace suite passed (396 tests). A
small function-pointer aggregate fixture produced identical normalized client exports with both
closed certificates enabled. The feature remained opt-in at this stage; adaptive promotion was
not implemented.

On 2026-08-21, a 56-module corpus A/B found essentially neutral typical overhead
(0.996x geometric-mean and 1.006x median wall-time ratios, with unchanged typical RSS)
and byte-identical manifests and audits across all 53 validated pairs. On normal Vim,
the direct join exceeded a 600-second cap while summaries completed in 504.35 seconds;
debug Vim and OpenSSL exceeded the cap in both modes. Summaries were therefore promoted
to the default, with `PANGS_ANDERSEN_MEMCPY_EDGE_SUMMARIES=0` retaining the direct join
for ablation. Single-sample regressions on libplacebo, SQLite O0, and Curl O0 remain
targets for isolated repetition.

The exact gifsicle input was
`/home/brk/pangs-corpus/_out_bc/exe-gifsicle-O0.bc` (SHA-256
`513bf2a2971252dd7fc615192dd6c1b1c6f8e96f3f78e06f88f152355de5612a`). At the normal
200,000 admission budget, direct and summarized runs both rejected the 20,702-node oversized
component. They took 1.48 s/119,976 KiB and 1.51 s/119,664 KiB respectively and emitted
byte-identical disposition manifest/audit artifacts: 11 immutable, five localize, and 80
unhandled globals. The admitted residue activated none of its seven memcpy joins.

With `--partition-budget 900000000`, the summarized solve completed and validated in 119.08 s
at 2,301,692 KiB peak RSS. It performed 1,052,874 worklist steps and ended with 249,791,636
points-to facts, 21,994 copy edges, and 1,654,259,033 copy-fact propagations. Eighty-four of
162 memcpy joins activated. Their final logical relation contained 16,609,344,880 pairs, but
the solver iterated zero direct memcpy pairs and installed only 6,021 summary edges. The fresh
direct arm did not complete in its 30-second cap: at timeout it had reached about 52 million
points-to facts, 357 million memcpy-pair iterations, and 924,348 KiB peak RSS. An earlier
uncapped direct attempt remained incomplete after roughly four minutes and had processed at
least 4.735 billion memcpy pairs.

Forced admission changed disposition precision, as expected from analyzing the formerly rejected
component: 11 immutable, one localize, 15 mutex, and 69 unhandled globals (27/96 handled versus
16/96 at the default budget). `error_count.access_set_complete` became true. The residual
`parse_int@!noloc#7` unknown-load row narrowed from module-wide to a finite candidate containing
only `clp_option_sentinel`; genuine universal provenance remained in its evidence.

A matched 30-second CPU-clock profile showed that the targeted hot spot was removed:
`Solve::note_direct_access` fell from 18.59% self time in the direct profile to 0.68% with
summaries. The summarized profile was instead dominated by `HashMap::insert` (26.33%), hashing
(14.62%), `Solve::run_with_limit` (13.62%), `Solve::field_of` (12.32%), and rehashing (8.48%).
The representation therefore makes this forced megacomponent solvable, but does not make it
cheap and does not improve default-budget coverage. A separate experiment must determine whether
the quadratic admission proxy can be made summary-aware without admitting unrelated pathological
components; the current budget must not simply be raised.

### Callsite-local cut/shortcut rewriting, tiers 1–2 (2026-08-21)

Implemented (then abandoned) `20260821_CUTSHORT.md`: fixed-PAG local-flow, getter, and complete-caller setter
certificates; return/Store cuts; per-callsite copy/load/Store replicas; propagation-only address
chains; baseline-admission preservation for accessors; profile/census knobs; and an explicit
baseline-versus-rewritten differential ledger. The workspace suite passed after implementation.

The 56-module census found 75,215 tier-1 callsites, but only 2,265 had a nonempty parameter-source
set (four modules reached 1% of direct calls on that meaningful measure). Getters covered 1,673
callsites; setters covered 2,194 after excluding constant-only stores. That exclusion fixed a real
Curl O1 widening found by the ledger: removing a null Store had removed direct-access bookkeeping
despite carrying no pointer payload.

Fifty-three three-arm disposition pairs validated; both Vim inputs and OpenSSL exceeded a
180-second cap in every arm. Tier 1 and combined shortcuts respectively measured 0.978x and 0.979x
geometric-mean wall, with 1.000x and 1.003x aggregate peak RSS. The fixed combined arm reduced
copy/load/store/GEP propagation pairs by 13%/11%/20%/24%. It did not change oversize-fallback or
in-scope-icall counts. All completed-pair disposition distributions were identical (1,011/1,795
handled); only tmux O1 and library Curl O1 changed detailed manifests.

The W2 ledger was clean on every completed performance module after extended checks for Curl O0,
libplacebo, and SQLite O0. It found ModRef-row reductions in tmux O1, FreeType, and Zstd and no
widened lattice fact. No persisted instrumented-corpus traces were available, so the mandatory
dynamic-recall gate remains unresolved. Both shortcut knobs stay default-off; the result does not
justify a default without trace recall, repeated timings, or a material flagship
disposition/admission effect.
