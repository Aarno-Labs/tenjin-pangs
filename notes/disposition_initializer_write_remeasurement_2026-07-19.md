# Static-initializer write remeasurement

Date: 2026-07-19

## Scope and method

This measures the disposition effect of separating static-initializer stores from
runtime writes. The comparable disposition corpus is every non-Vim sibling in
`/home/brk/pangs-corpus/_out_bc` except OpenSSL: 41 modules, all freshly analyzed and
validated. Each used the release CLI, Andersen, no overrides, the filename-implied
executable/library mode, and `/home/brk/pangs-corpus` as the repository root:

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

Artifacts and per-run time/RSS records are retained under
`/tmp/pangs-disposition-initwrites-20260719`. The pre-change comparison uses the
hardened D4 manifests: `/tmp/pangs-d4-remeasurement-20260718`, with its three
superseding manifests from `/tmp/pangs-d4-hardening-20260718`.

OpenSSL was deliberately excluded as requested. Both Vim bitcode variants are outside
the historical sibling-disposition corpus. An additional attempt to include
`exe-vim-9.2-O1.bc` was killed twice by the kernel at about 29.9 GB peak RSS (exit 137,
163--176 seconds), so no Vim result is mixed into the validated totals.

## Overall coverage

The 41 modules contain 1,823 mutable definition globals. The correction changes 114
`written` facts from true to false. Of those, 98 now pass the immutable cascade guard;
the remaining 16 still fail the global `violation_taint` guard.

| disposition | hardened D4 baseline | initializer-aware | delta |
|---|---:|---:|---:|
| immutable | 180 | 278 | +98 |
| atomic | 14 | 14 | 0 |
| mutex | 1 | 0 | -1 |
| unhandled | 1,628 | 1,531 | -97 |
| **total** | **1,823** | **1,823** | **0** |

The one mutex loss is a strengthening, not a regression: YAPET O0 `options` was the
only final mutex disposition, and it is now correctly classified as immutable because
its only store is static initialization. YAPET O1 `options` similarly moves from
unhandled to immutable. The 14 atomic dispositions are unchanged.

Overall handled coverage rises from 195/1,823 (10.7%) to 292/1,823 (16.0%), a gain of
97 final handled globals or 5.3 percentage points.

## Modules affected

Only these 14 modules have a corrected `written` fact. `new immutable` is the net
increase in that module; the difference from `written corrected` is exactly the rows
still blocked by violation taint.

| module | globals | written corrected | immutable before | immutable after | new immutable |
|---|---:|---:|---:|---:|---:|
| `exe-OMP__tree-O0` | 83 | 22 | 6 | 28 | 22 |
| `exe-chibicc-O0` | 142 | 4 | 4 | 5 | 1 |
| `exe-curl-O0` | 75 | 1 | 29 | 30 | 1 |
| `exe-curl-O1` | 77 | 1 | 27 | 28 | 1 |
| `exe-gifsicle-O0` | 96 | 6 | 1 | 4 | 3 |
| `exe-gifsicle-O1` | 90 | 1 | 5 | 6 | 1 |
| `exe-jq-O0` | 12 | 1 | 3 | 4 | 1 |
| `exe-tmux-O0` | 111 | 19 | 11 | 30 | 19 |
| `exe-tmux-O1` | 103 | 14 | 10 | 23 | 13 |
| `exe-tree-O0` | 83 | 22 | 6 | 28 | 22 |
| `exe-yapteaparprfotci-O0-g` | 13 | 1 | 1 | 2 | 1 |
| `exe-yapteaparprfotci-O1-g` | 12 | 1 | 1 | 2 | 1 |
| `lib-cairo-O1-g` | 123 | 8 | 47 | 49 | 2 |
| `lib-sqlite-O0` | 53 | 13 | 10 | 20 | 10 |
| **total** |  | **114** |  |  | **98** |

## Takeaway

Static initialization was a material immutable false-negative source. Correcting it
adds substantially more handled globals than D3 and D4 combined on this corpus, while
leaving their eligibility sets stable. Store-edge ownership makes the correction
structural: indirect initializer stores are excluded, runtime stores remain
conservative, and the legacy `never_written` analysis output is unchanged.
