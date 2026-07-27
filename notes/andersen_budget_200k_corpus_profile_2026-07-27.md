# Andersen 200k budget corpus profile

Date: 2026-07-27

## Method

The baseline and changed runs covered every `.bc` file in
`/home/brk/pangs-corpus/_out_bc`: 45 modules (24 executables and 21 libraries).
Each module was analyzed once, sequentially, with a release build, the build mode
selected from its `exe-` or `lib-` prefix, the Andersen stage, and `--validate`.
No explicit `--partition-budget` was supplied, so the two runs exercised the
100,000 and 200,000 defaults respectively.

The run retained each export directory, stdout/stderr, outer wall time, and peak
RSS. The complete comparison table is
`/tmp/pangs-corpus-budget-comparison-20260727.tsv`; raw runs are in:

- `/tmp/pangs-corpus-budget-baseline-20260727`
- `/tmp/pangs-corpus-budget-200k-20260727`

## Results

| metric | 100k | 200k | delta |
|---|---:|---:|---:|
| validated modules | 45 | 45 | 0 |
| summed outer wall time | 1,089.38 s | 1,115.52 s | +2.40% |
| summed analysis wall time | 980.40 s | 1,001.45 s | +2.15% |
| summed solve time | 925.96 s | 945.95 s | +2.16% |
| peak RSS | 11,051,784 KiB | 11,051,320 KiB | effectively flat |
| oversize fallbacks | 34 | 34 | 0 |
| modules with a fallback | 33 | 33 | 0 |
| Andersen propagation steps | 1,874,144 | 1,858,441 | -0.84% |
| Andersen icalls | 3,868 | 3,868 | 0 |
| Steensgaard fallback icalls | 13,336 | 13,336 | 0 |
| unknown icalls | 13,336 | 13,336 | 0 |
| call edges | 1,643,170 | 1,643,170 | 0 |
| ModRef rows | 531,616 | 531,616 | 0 |
| globals in rewritable components | 159 / 5,390 | 159 / 5,390 | 0 |

The peak-RSS values are 10.54 GiB in both runs; the maximum came from
`exe-vim-9.2-g-O1.bc`. The largest wall-time rows were OpenSSL
(473.03 s → 492.58 s), Vim O1 (282.04 s → 280.46 s), and Vim-debug O1
(200.50 s → 208.47 s). These are single-run timings, so the small aggregate
increase is not statistically distinguishable from run-to-run noise.

Every callgraph, ModRef, globals, and components artifact was byte-identical
between the two runs. No oversize partition crossed the 100k-to-200k admission
interval. Propagation-step differences therefore reflect schedule/hash-order
variation rather than a changed admitted set.

## Decision

The default is doubled to 200,000 as requested. On this corpus snapshot the
change is behaviorally neutral: it neither improves precision nor introduces an
observed memory cliff. Future precision work should inspect the cost distribution
above 200k or address the structure of the remaining large partitions rather
than incrementing this threshold again without measurement.
