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
- M4.3 focused summary rerun for curl/tmux: `/tmp/pangs-m4-vararg-m43/`

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

## M4.3 Callee Detail Evidence

`audit.jsonl` now carries an optional detector-specific `detail` field. For vararg audit
findings this records the direct callee, which makes summary candidates mechanical instead
of inferred from caller witnesses.

Focused detail rerun before summaries:

| row | top callee details |
|---|---|
| `exe-curl-O1` | `tool_setopt=84`, `warnf=38`, `curl_mfprintf=27`, `curl_msnprintf=19`, `curl_easy_getinfo=19`, `curl_easy_setopt=14`, `errorf=13`, `easysrc_addf=12`, `curl_maprintf=11` |
| `exe-tmux-O1` | `log_debug=230`, `cmdq_error=84`, `xasprintf=76`, `format_add=47`, `xsnprintf=36`, `cmdq_print=28`, `fatalx=26` |

The first summary table admits only inspected formatting/logging wrappers:

- tmux: `log_debug`, `cmdq_error`, `cmdq_print`, `fatalx`, `xasprintf`, `xsnprintf`,
  `format_add`, `cfg_add_cause`
- curl: `warnf`, `errorf`, `notef`, `helpf`, `easysrc_addf`, `curl_mprintf`,
  `curl_mfprintf`, `curl_msnprintf`, `curl_maprintf`, `curlx_dyn_addf`

Source rationale:

- tmux `log_debug`/`fatalx` forward to `log_vwrite`, which formats into strings with
  `vasprintf` and writes text to the log.
- tmux `cmdq_error`/`cmdq_print` format messages for command output/error paths.
- tmux `xasprintf`/`xsnprintf` forward to bounded string-formatting wrappers.
- curl `warnf`/`errorf`/`notef`/`helpf` forward to `voutf`/`vfprintf`.
- curl `curl_m*printf`, `easysrc_addf`, and `curlx_dyn_addf` format into streams,
  strings, or dynamic string buffers.

Explicit non-summary cases:

- `tool_setopt` and `curl_easy_setopt` remain conservative. Curl's setopt path has
  option-specific cases that store callback function pointers.
- `curl_easy_getinfo` remains conservative pending source-specific modeling of output
  pointer writes.

Focused M4.3 result:

| row | before summaries | after summaries | rewritable before | rewritable after |
|---|---:|---:|---:|---:|
| `exe-curl-O1` | 254 | 117 | 16/80 | 16/80 |
| `exe-tmux-O1` | 637 | 101 | 0/107 | 0/107 |

Remaining callee details after summaries:

| row | remaining dominant details |
|---|---|
| `exe-curl-O1` | `tool_setopt=84`, `curl_easy_getinfo=19`, `curl_easy_setopt=14` |
| `exe-tmux-O1` | `environ_set=11`, `control_write=11`, `cmdq_format=7`, screen-write formatting helpers, external libc/libevent varargs |

M4.3 substantially reduces audit noise and component taint detail, but it does not change
rewritable coverage in the focused rows. The remaining curl blockers are real callback/output
vararg APIs, and tmux is still frozen by other taints plus a small residue of vararg
boundaries.
