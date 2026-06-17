# M4 Vararg Decision

Date: 2026-06-17

## Setup

M4.5 reran the O1 decision corpus with the current release CLI:

```bash
LLVM_SYS_140_PREFIX=/home/brk/tenjin/_local/xj-llvm-14 \
LD_LIBRARY_PATH=/home/brk/tenjin/_local/xj-llvm-14/lib \
cargo build --release -p pangs-cli
```

Rows were analyzed with `--stage andersen --validate`. Executable rows used
`--build-mode executable`; `lib-parson-O1` used `--build-mode library`.

Output directory:

- `/tmp/pangs-m4-vararg-m45/`

## Result

| row | vararg findings | external | internal unmodeled | indirect | rewritable | wall seconds | export size |
|---|---:|---:|---:|---:|---:|---:|---:|
| `exe-jpegoptim-O1` | 53 | 24 | 29 | 0 | 0/48 | 0.18 | 844K |
| `lib-parson-O1` | 0 | 0 | 0 | 0 | 0/5 | 0.05 | 232K |
| `exe-jq-O1` | 110 | 19 | 91 | 0 | 5/14 | 3.62 | 8.6M |
| `exe-chibicc-O1` | 95 | 9 | 86 | 0 | 0/133 | 2.33 | 4.6M |
| `exe-gifsicle-O1` | 50 | 20 | 28 | 2 | 1/93 | 1.72 | 3.7M |
| `exe-lua-O1` | 100 | 22 | 78 | 0 | 0/5 | 6.10 | 14M |
| `exe-curl-O1` | 117 | 33 | 84 | 0 | 16/80 | 3.96 | 10M |
| `exe-tmux-O1` | 101 | 31 | 70 | 0 | 0/107 | 61.04 | 193M |

Compared with the M4.2 baseline, M4.3's known-benign summaries substantially reduced audit
noise in curl and tmux:

| row | M4.2 vararg findings | M4.5 vararg findings | rewritable M4.2 | rewritable M4.5 |
|---|---:|---:|---:|---:|
| `exe-curl-O1` | 249 | 117 | 16/80 | 16/80 |
| `exe-tmux-O1` | 637 | 101 | 0/107 | 0/107 |

The other corpus rows are unchanged from M4.2 for rewritable coverage. M4.4's indirect
vararg filtering is covered by synthetic tests, but the only observed corpus indirect
vararg findings are the two gifsicle sites, and they remain conservative under the complete
target-set rule.

## Decision

Freeze M4 for the lite track and move to the next blocker class.

The implemented M4 work is still worth keeping:

- taxonomy makes vararg findings actionable instead of one broad bucket;
- direct internal body modeling is sound and covered;
- name-specific summaries remove large amounts of curl/tmux audit noise;
- indirect filtering has a conservative complete-target rule and synthetic coverage.

However, M4 does not improve mutable-global rewritable coverage on this corpus. Continuing
to add vararg summaries would mostly reduce explanation noise, not unlock the current
largest frozen components. The remaining high-volume cases are real opaque or
source-specific APIs:

- curl `tool_setopt`, `curl_easy_setopt`, and `curl_easy_getinfo`;
- tmux screen/control/status formatting boundaries;
- jq/chibicc/lua project-local formatting/error helpers with visible vararg consumption.

Those are better handled only if a downstream client needs cleaner audit reports for a
specific project. For the M4 milestone, the sound modeling gains are complete enough.

## Next Work

Move on from varargs. The next milestone should target a non-vararg blocker visible in the
M3/M4 decision data, likely one of:

- unknown global/modref precision;
- pointer-int or inline-asm boundary reduction where source patterns are narrow;
- export/report scalability for very large rows such as tmux, if client usage needs JSONL
  exports rather than in-memory results.
