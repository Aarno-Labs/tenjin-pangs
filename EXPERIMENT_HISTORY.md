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
