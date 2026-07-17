# Disposition Coverage with Optional Global Source Files

Date: 2026-07-16

This note records the disposition rerun for all 29 non-Vim, non-PHP bitcode siblings
in `/home/brk/pangs-corpus/_out_bc` after making a global's defining source file
optional. Inputs include optimization variants and duplicate/demo artifacts, so totals
are inventory counts rather than a population estimate.

## Method

Each input was analyzed and disposed in one process with the release binary, Andersen,
export validation, no overrides, and `/home/brk/pangs-corpus` as the repository root.
`exe-*` used executable/application mode and `lib-*` used library mode:

```bash
target/release/pangs analyze INPUT.bc \
  --stage andersen \
  --build-mode executable-or-library \
  --dispose \
  --repo-root /home/brk/pangs-corpus \
  --no-overrides \
  --out OUTPUT \
  --validate
```

All 29 runs completed and validated. Outputs are in
`/tmp/pangs-disposition-siblings-20260716-optional-file`.

## Results

`no file` counts disposition globals whose `meta.file` is `null`. `imm` and `unh` are
the `immutable` and `unhandled` cascade results. No row selected `once-lock`, `atomic`,
`mutex`, or `localize`, and no row emitted an unkeyed global.

| input | globals | no file | imm | unh | groups | grouped | atomic gate | mutex gate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `exe-OMP__tree-O0` | 83 | 83 | 6 | 77 | 3 | 36 | 0 | 0 |
| `exe-b2-hashmap_tree-O0` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `exe-chibicc-O0` | 142 | 14 | 4 | 138 | 5 | 31 | 0 | 0 |
| `exe-chibicc-O1` | 130 | 14 | 0 | 130 | 7 | 41 | 0 | 0 |
| `exe-curl-O0` | 75 | 0 | 16 | 59 | 6 | 26 | 0 | 0 |
| `exe-curl-O1` | 77 | 0 | 15 | 62 | 7 | 36 | 0 | 0 |
| `exe-gifsicle-O0` | 96 | 96 | 1 | 95 | 9 | 67 | 0 | 0 |
| `exe-gifsicle-O1` | 90 | 90 | 4 | 86 | 8 | 75 | 0 | 0 |
| `exe-jpegoptim-O0` | 44 | 44 | 1 | 43 | 1 | 39 | 0 | 0 |
| `exe-jpegoptim-O1` | 43 | 0 | 1 | 42 | 1 | 39 | 0 | 0 |
| `exe-jq-O0` | 12 | 12 | 3 | 9 | 0 | 0 | 0 | 0 |
| `exe-jq-O1` | 9 | 9 | 2 | 7 | 0 | 0 | 0 | 0 |
| `exe-lua-O0` | 6 | 6 | 1 | 5 | 0 | 0 | 0 | 0 |
| `exe-lua-O1` | 2 | 2 | 0 | 2 | 1 | 2 | 0 | 0 |
| `exe-sbase_cal-O0` | 2 | 2 | 0 | 2 | 1 | 2 | 0 | 0 |
| `exe-tmux-O0` | 111 | 0 | 10 | 101 | 10 | 43 | 0 | 0 |
| `exe-tmux-O1` | 103 | 0 | 8 | 95 | 12 | 47 | 0 | 0 |
| `exe-tree-O0` | 83 | 83 | 6 | 77 | 3 | 36 | 0 | 0 |
| `lib-curl-O0` | 45 | 0 | 3 | 42 | 2 | 10 | 0 | 0 |
| `lib-curl-O1` | 41 | 0 | 3 | 38 | 2 | 10 | 0 | 0 |
| `lib-lua-O0` | 4 | 0 | 1 | 3 | 0 | 0 | 0 | 0 |
| `lib-lua-O1` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `lib-openssl-4.1.0-O1` | 226 | 226 | 24 | 202 | 25 | 86 | 0 | 0 |
| `lib-parson-O0` | 5 | 0 | 0 | 5 | 1 | 2 | 0 | 0 |
| `lib-parson-O1` | 5 | 0 | 0 | 5 | 1 | 2 | 0 | 0 |
| `lib-small-g-O0` | 6 | 6 | 0 | 6 | 2 | 4 | 0 | 0 |
| `lib-sqlite-O0` | 53 | 0 | 9 | 44 | 1 | 7 | 0 | 0 |
| `lib-sqlite-O1` | 40 | 0 | 3 | 37 | 1 | 22 | 0 | 0 |
| `lib-stage_demo-O0` | 3 | 3 | 0 | 3 | 0 | 0 | 0 | 0 |

Aggregate inventory:

- 1,536 defined mutable globals: 846 source-mapped and 690 source-less.
- Zero unkeyed globals and zero key collisions.
- 121 `immutable` (7.9%) and 1,415 `unhandled` (92.1%).
- Source-mapped: 73 `immutable` / 773 `unhandled`.
- Source-less: 48 `immutable` / 642 `unhandled`; these 48 decisions were previously
  impossible when a source file was mandatory.
- 109 coupling groups containing 663 member occurrences.
- Both free D3/D4 funnels remain at zero eligible atomic and mutex candidates.

Using the old source-file rule, the same inventory would have treated all 690
source-less globals as unkeyed/unhandled and could have selected at most the 73
source-mapped immutable globals: 4.8% of the full inventory. The optional-file rule
raises actionable coverage to 7.9%, a gain of 48 globals (65.8% more actionable
globals), without manufacturing any D3/D4 eligibility.

The sibling corpus does not promise stable cross-build uniquification, although its
LLVM symbol spellings produced no collisions in this run. The production pipeline's
mandatory deterministic static-variable uniquification remains the stability
precondition for using bare keys across reruns and downstream tools.
