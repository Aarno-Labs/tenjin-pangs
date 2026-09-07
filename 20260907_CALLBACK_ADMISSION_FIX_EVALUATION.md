# Callback admission and empty-result fixes

2026-09-07. Repairs the two issues diagnosed in
`20260907_VIM_CALLBACK_ADMISSION_INVESTIGATION.md`. No experimental flag is promoted.

## Implementation

Admission indexes modeled memory readers/writers by their solved Steensgaard
pointee storage envelope. For each envelope, at most two linear-size dependency
hubs connect all writers to uncertified readers and uncertified writers to
certified readers. Certified region-to-region accesses retain their independent
allocation-relative partitioning. The hubs introduce admission dependencies, not
points-to copies or value unification. Their nodes and edges count toward budgets;
their directed edges participate in SCC predecessor closure. If producer support
does not fit, the ordinary base fallback is retained.

This is not callback-specific: the index covers pointer-capable loads/stores and
memcpy endpoints, and it does not select producers by function-address syntax.
No all-function-address interestingness rule or whole-program forced admission is
used. It relies on the existing conservative Steensgaard storage envelope.

At call-result emission, an empty target set with no external operand and no
trusted empty witness retains the original Steensgaard call record, marked
fallback. This preserves its finite targets, unknown bit and pre-FSA provenance.
An actual external operand still produces unknown. The repair does not interpret
an empty points-to set as proof that a call is impossible.

## Tests

- `cargo test --workspace --all-targets`: passes, including **146 solver tests**.
- PWC=1 / overlap=1 synthetic differential sweep: passes.
- PWC=1 / overlap=1 dynamic indirect-call traces: both pass.
- Both LLVM and PIR regressions pass executable-mode differential checks with
  overlap off/on and PWC=1 (eight checks).
- Initializer regression requires an actual refined `cb` target with fallback
  false, so the empty-result fallback cannot hide an unfixed admission defect.
- Directed SCC regression adds 100 outgoing users: a 1,000-unit budget still
  admits the initializer and callback; a one-unit budget explicitly falls back.
- Reverse-direction regression covers an uncertified helper store feeding a
  certified caller load. Existing disjoint-region partition tests still pass.
- Null-callback semantic regression requires finite base fallback. A separate
  external-operand control verifies that genuine unknown is not cleared.

Both previous known-defect LLVM fixtures moved to `fixtures/synthetic/m1_4` and
have PIR counterparts in the ordinary differential sweep.

## Vim census and analysis

Original, unmodified input:
`/home/brk/pangs-corpus/_out_bc/exe-vim-9.2-O1.bc`, SHA-256
`d29a9471def3dad7f747b65f74ebfcdf2154212f8407d7a1193574ad6dcd448a`.
Executable mode, PWC=1, overlap=1, default admission/certificate controls.
Artifacts: `/tmp/pangs-callback-admission-fix.F37sHM/`.
Frozen evaluation binary: `pangs-eval`, SHA-256
`8a8f5d4494e30f55a7e7a93d8fcc33f9cfa71c7d33d506cd0e7b3ae49ee414cb`.
Subsequent source changes add tests/comments/formatting, not solver semantics.

The census has 2,099 sites and **206 unknowns**, down from 232. All 26 affected
sites lose the spurious unknown bit:

- 20 have one genuinely refined target and fallback=false.
- Six (`json_find_end` #1/#3 and `json_decode_all` #1/#3/#8/#10) retain the
  finite `channel_fill` base target and fallback=true.

Three other sites leave fallback: `ExpandGenericExt` #2/#12 narrow from 50 to
12 targets each, and `call_func` #28 retains one target. Total fallback sites
are 212. These are census counts/status comparisons, not a whole-callgraph
target-identity equivalence claim.

Compact disposition analysis completes with validation enabled. Andersen reports
complete, one oversize fallback (largest component now 243,352, previously
234,236), and zero Andersen-coarser-than-Steens nodes (previously 20).

Census wall time is 78.22 s, peak RSS 3,722,460 KiB. Compact disposition analysis
is 88.84 s, peak RSS 6,780,376 KiB. Previous fixed-escape disposition runs were
99.28–101.68 s and about 6,742,000 KiB. These are shared-machine observations,
not a controlled speedup result; differential/testing work overlaps the runs.

## Full differential and client impact

The full three-tier Vim differential **passes** with overlap=1: exit 0, 465.02 s,
peak RSS 4,048,396 KiB. Its existing informational note about the conservative
tier lacking aliased ModRef is not a violation. The former 26 `icall_unknown`
violations are gone; there are no other differential violations.

With overlap=0, the census also has 2,099 sites and 206 unknowns, with the same
target counts, fallback and unknown statuses as overlap=1. Sixteen pre-FSA/FSA
diagnostic rows differ; this is not full census identity. That census took 87.56 s,
peak RSS 3,723,600 KiB. The full three-tier Vim differential was run with overlap
on, not repeated with overlap off.

Against the previous fixed-escape `vim-final/pangs-manifest.json`, 2,180 full global
records change. Changes are confined to these derived fact fields:

| Field | Changed globals |
| --- | ---: |
| `atomic_eligibility` | 2,070 |
| `localization` | 23 |
| `phase_stationarity` | 21 |
| `violation_relevance` | 2,159 |

All other global fact fields, including writes and escape, are identical. These
counts include certificate/evidence changes, not necessarily Boolean changes.
Exactly **21 dispositions change, all from `unhandled` to `localize`**; no
disposition moves in the opposite direction. They include `did_init_locales`,
`locales`, completion-helper state, `varnamebuf`, and `varnamebuflen`.
This evaluates analysis/disposition, not execution of transformed Vim.

Canonical full-global-record SHA-256 is now
`be7ea21acf3b9a4e6fe5405f4a655722917288dc1c71a4118301641bbc4b9421`, versus
`69da63143560ede822cf75e92436c5980fe41709689ee2e78866b9ec3b95ec8a` before.
`globals-diff.json` records changed global keys and before/after dispositions;
`facts-change-counts.json` records the derived-field comparison.
