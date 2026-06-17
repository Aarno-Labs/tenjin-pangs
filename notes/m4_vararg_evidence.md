# M4 Vararg Evidence

Date: 2026-06-16

## Setup

Release CLI:

```bash
LLVM_SYS_140_PREFIX=/home/brk/tenjin/_local/xj-llvm-14 \
LD_LIBRARY_PATH=/home/brk/tenjin/_local/xj-llvm-14/lib \
cargo build --release -p pangs-cli
```

Corpus rows were analyzed with `--stage andersen --validate`. Executables used
`--build-mode executable`; `lib-parson-O1.bc` used `--build-mode library`.

Outputs:

- M4.1 taxonomy-only run: `/tmp/pangs-m4-vararg/`
- M4.2 direct-internal safe-vararg suppression run: `/tmp/pangs-m4-vararg-m42/`

## Result

The split taxonomy is useful, but the first M4.2 semantic suppression does not move this
corpus. All observed direct internal vararg function-pointer findings still have visible
vararg consumption in the callee body and therefore remain conservatively tainted.

| row | M4.1 vararg findings | M4.2 vararg findings | rewritable M4.1 | rewritable M4.2 |
|---|---:|---:|---:|---:|
| `exe-jpegoptim-O1` | 53 | 53 | 0/48 | 0/48 |
| `lib-parson-O1` | 0 | 0 | 0/5 | 0/5 |
| `exe-jq-O1` | 110 | 110 | 5/14 | 5/14 |
| `exe-chibicc-O1` | 95 | 95 | 0/133 | 0/133 |
| `exe-gifsicle-O1` | 50 | 50 | 1/93 | 1/93 |
| `exe-lua-O1` | 100 | 100 | 0/5 | 0/5 |
| `exe-curl-O1` | 249 | 249 | 16/80 | 16/80 |
| `exe-tmux-O1` | 637 | 637 | 0/107 | 0/107 |

M4.2 release wall times:

| row | wall seconds |
|---|---:|
| `exe-jpegoptim-O1` | 0.17 |
| `lib-parson-O1` | 0.05 |
| `exe-jq-O1` | 3.89 |
| `exe-chibicc-O1` | 2.38 |
| `exe-gifsicle-O1` | 1.74 |
| `exe-lua-O1` | 6.41 |
| `exe-curl-O1` | 4.16 |
| `exe-tmux-O1` | 63.84 |

## M4.2 Audit Histograms

| row | external | internal unmodeled | indirect |
|---|---:|---:|---:|
| `exe-jpegoptim-O1` | 24 | 29 | 0 |
| `lib-parson-O1` | 0 | 0 | 0 |
| `exe-jq-O1` | 19 | 91 | 0 |
| `exe-chibicc-O1` | 9 | 86 | 0 |
| `exe-gifsicle-O1` | 20 | 28 | 2 |
| `exe-lua-O1` | 22 | 78 | 0 |
| `exe-curl-O1` | 99 | 150 | 0 |
| `exe-tmux-O1` | 31 | 606 | 0 |

Affected values are all solved-flow `value:` findings in these rows; no row currently has
syntactic `function:` vararg findings after deduplication.

## Largest Frozen Components With Vararg Taint

| row | members | mutable globals | vararg taint kinds |
|---|---:|---:|---|
| `exe-jpegoptim-O1` | 121 | 47 | external, internal-unmodeled |
| `exe-jq-O1` | 636 | 10 | external, internal-unmodeled |
| `exe-chibicc-O1` | 213 | 84 | external, internal-unmodeled |
| `exe-gifsicle-O1` | 284 | 90 | external, internal-unmodeled, indirect |
| `exe-lua-O1` | 694 | 5 | external, internal-unmodeled |
| `exe-curl-O1` | 304 | 75 | external, internal-unmodeled |
| `exe-tmux-O1` | 1261 | 86 | external, internal-unmodeled |

`lib-parson-O1` has no vararg-tainted frozen component.

## Interpretation

The dominant class is `fnptr_varargs_internal_unmodeled`, especially in tmux
(`606/637`) and chibicc (`86/95`). M4.2's safe direct-internal rule is still worth
keeping because it is sound and covered by fixtures, but the real corpus does not contain
many internal variadic wrappers that never consume their varargs.

The next vararg-specific lever is M4.3: narrow, explicit summaries for known consuming
vararg callees whose ABI behavior is understood. Tmux's top witnesses include allocation
and error/reporting wrappers such as `xmalloc`, `xcalloc`, `xrealloc`, and
`xreallocarray`; curl has many `tool_setopt*` and tracing/configuration wrappers. Those
should be investigated from source before any summary is admitted.
