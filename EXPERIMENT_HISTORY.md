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
