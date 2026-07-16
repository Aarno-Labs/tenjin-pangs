# M3/M4 Sibling Bitcode Measurements

Date: 2026-07-16

This note records the current lite-track M3 dashboard and M4 vararg evidence for every
non-Vim `.bc` sibling in `/home/brk/pangs-corpus/_out_bc/`. PHP is deliberately not part
of this pass. The inputs include optimization variants and small synthetic/demo rows, so
aggregate counts are inventory totals, not a population estimate.

## Method

The current release CLI analyzed every row with Andersen and export validation. `exe-*`
rows used executable mode and `lib-*` rows used library mode:

```bash
target/release/pangs analyze INPUT.bc \
  --stage andersen \
  --build-mode executable-or-library \
  --out /tmp/pangs-m3-m4-siblings-20260716/INPUT-andersen \
  --validate
```

All 29 rows completed successfully. The columns below use the current export meanings:
`globals` is the client-visible analyzed global count; `mutable rw` is
`in_rewritable_components/mutable_globals_total`; `A/S/U` is
Andersen/Steensgaard/unknown indirect-call sites. Times come from the manifest and
`metrics.json`, excluding some final validation overhead.

## M3 Dashboard

| input | mode | funcs | globals | mutable rw | components p50/p95/max | max frozen (mutable) | icalls A/S/U | oversize (max) | wall / analysis / solve ms | modref rows |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `exe-OMP__tree-O0` | executable | 181 | 89 | 0/52 | 9 1/10/164 | 164 (50) | 1/2/2 | 3 (5,012) | 133 / 75 / 34 | 1,364 |
| `exe-b2-hashmap_tree-O0` | executable | 49 | 15 | 0/0 | 2 1/1/48 | 48 (0) | 0/0/0 | 1 (1,256) | 18 / 7 / 2 | 7 |
| `exe-chibicc-O0` | executable | 348 | 145 | 0/83 | 6 1/2/342 | 342 (62) | 0/1/1 | 2 (16,333) | 186 / 133 / 53 | 3,236 |
| `exe-chibicc-O1` | executable | 221 | 151 | 0/81 | 8 1/2/213 | 213 (60) | 0/1/1 | 3 (11,017) | 224 / 164 / 92 | 3,934 |
| `exe-curl-O0` | executable | 405 | 111 | 0/78 | 9 1/3/393 | 393 (70) | 1/0/1 | 6 (18,664) | 421 / 346 / 259 | 3,474 |
| `exe-curl-O1` | executable | 320 | 116 | 0/51 | 13 1/3/304 | 304 (48) | 0/1/1 | 5 (7,891) | 267 / 209 / 152 | 2,426 |
| `exe-gifsicle-O0` | executable | 522 | 110 | 0/92 | 30 1/1/492 | 492 (91) | 4/117/117 | 3 (32,413) | 519 / 413 / 234 | 6,781 |
| `exe-gifsicle-O1` | executable | 333 | 121 | 1/90 | 48 1/1/284 | 284 (89) | 5/202/203 | 2 (14,015) | 332 / 249 / 138 | 5,429 |
| `exe-jpegoptim-O0` | executable | 123 | 52 | 0/45 | 4 1/1/120 | 120 (45) | 0/14/14 | 2 (2,487) | 47 / 24 / 11 | 497 |
| `exe-jpegoptim-O1` | executable | 129 | 53 | 0/44 | 9 1/1/121 | 121 (44) | 0/14/14 | 2 (1,339) | 35 / 16 / 7 | 420 |
| `exe-jq-O0` | executable | 851 | 74 | 6/8 | 43 1/1/809 | 809 (8) | 0/7/7 | 5 (69,588) | 693 / 498 / 242 | 10,139 |
| `exe-jq-O1` | executable | 709 | 73 | 5/8 | 71 1/1/636 | 636 (8) | 0/8/8 | 4 (26,647) | 426 / 283 / 167 | 4,325 |
| `exe-lua-O0` | executable | 1,103 | 52 | 0/6 | 8 1/1/1,096 | 1,096 (5) | 1/17/17 | 1 (48,290) | 645 / 513 / 340 | 6,925 |
| `exe-lua-O1` | executable | 715 | 51 | 0/5 | 22 1/1/694 | 694 (5) | 1/64/64 | 1 (25,564) | 485 / 356 / 216 | 9,343 |
| `exe-sbase_cal-O0` | executable | 40 | 4 | 0/2 | 5 1/1/36 | 36 (2) | 0/0/0 | 0 (0) | 8 / 3 / 1 | 60 |
| `exe-tmux-O0` | executable | 1,591 | 360 | 0/82 | 28 1/1/1,564 | 1,564 (72) | 8/40/42 | 6 (97,640) | 4,872 / 4,135 / 3,114 | 18,803 |
| `exe-tmux-O1` | executable | 1,315 | 364 | 0/80 | 55 1/1/1,261 | 1,261 (76) | 8/49/51 | 7 (45,132) | 3,250 / 2,570 / 1,741 | 15,781 |
| `exe-tree-O0` | executable | 181 | 89 | 0/52 | 9 1/10/164 | 164 (50) | 1/2/2 | 3 (5,012) | 132 / 74 / 33 | 1,364 |
| `lib-curl-O0` | library | 2,497 | 158 | 0/45 | 47 1/1/2,449 | 2,449 (29) | 335/872/1,168 | 3 (134,863) | 8,237 / 7,728 / 6,748 | 22,814 |
| `lib-curl-O1` | library | 1,808 | 169 | 0/41 | 68 1/1/1,739 | 1,739 (28) | 383/1,273/1,617 | 5 (57,357) | 5,342 / 4,933 / 4,109 | 18,701 |
| `lib-lua-O0` | library | 1,072 | 50 | 0/4 | 8 1/1/1,065 | 1,065 (4) | 1/17/17 | 1 (47,492) | 600 / 476 / 305 | 16,706 |
| `lib-lua-O1` | library | 703 | 49 | 0/3 | 22 1/1/682 | 682 (3) | 1/64/64 | 1 (25,298) | 460 / 337 / 195 | 9,334 |
| `lib-openssl-4.1.0-O1` | library | 15,497 | 6,032 | 0/168 | 1,013 1/1/14,436 | 14,436 (130) | 204/2,558/2,708 | 40 (414,181) | 238,247 / 209,669 / 154,147 | 75,268 |
| `lib-parson-O0` | library | 168 | 5 | 0/5 | 10 1/1/159 | 159 (5) | 60/0/60 | 1 (4,824) | 34 / 19 / 7 | 264 |
| `lib-parson-O1` | library | 147 | 5 | 0/5 | 41 1/1/107 | 107 (5) | 133/0/133 | 1 (2,304) | 24 / 11 / 5 | 402 |
| `lib-small-g-O0` | library | 14 | 6 | 0/6 | 5 1/4/7 | 7 (2) | 1/0/1 | 0 (0) | 2 / 1 / 0 | 16 |
| `lib-sqlite-O0` | library | 3,335 | 297 | 0/80 | 38 1/2/3,295 | 3,295 (52) | 11/249/249 | 6 (246,721) | 17,060 / 15,910 / 13,617 | 40,365 |
| `lib-sqlite-O1` | library | 2,169 | 286 | 0/75 | 60 1/2/2,106 | 2,106 (58) | 11/720/720 | 4 (151,161) | 15,610 / 14,214 / 11,255 | 58,930 |
| `lib-stage_demo-O0` | library | 1 | 3 | 0/1 | 1 1/1/1 | 1 (1) | 0/0/0 | 0 (0) | 1 / 0 / 0 | 1 |

Only three rows retain any rewritable globals: jq O0 (`6/8`), jq O1 (`5/8`), and
gifsicle O1 (`1/90`). Across the inventory there are 12 rewritable occurrences out of
1,292 mutable occurrences, but O0/O1 pairs and duplicate tree artifacts make that sum
unsuitable as a coverage rate. Large frozen components remain the norm and usually
contain nearly every mutable global in their row.

The main stress rows all complete. OpenSSL is the outlier at 238 seconds of manifest
wall time (287 seconds including export validation), 8.0 million call edges, and 2,708
unknown icall sites. SQLite O0/O1 take 17/16 seconds; tmux O0/O1 take 4.9/3.3 seconds;
library curl O0/O1 take 8.2/5.3 seconds.

### Stationarity

| input | complete InitVal | stationary / tracked |
|---|---:|---:|
| `exe-OMP__tree-O0` | 32 | 35/89 |
| `exe-b2-hashmap_tree-O0` | 0 | 1/15 |
| `exe-chibicc-O0` | 24 | 62/145 |
| `exe-chibicc-O1` | 29 | 63/151 |
| `exe-curl-O0` | 34 | 0/111 |
| `exe-curl-O1` | 35 | 56/116 |
| `exe-gifsicle-O0` | 8 | 8/110 |
| `exe-gifsicle-O1` | 8 | 8/121 |
| `exe-jpegoptim-O0` | 3 | 7/52 |
| `exe-jpegoptim-O1` | 3 | 7/53 |
| `exe-jq-O0` | 13 | 19/74 |
| `exe-jq-O1` | 14 | 18/73 |
| `exe-lua-O0` | 10 | 7/52 |
| `exe-lua-O1` | 10 | 4/51 |
| `exe-sbase_cal-O0` | 2 | 2/4 |
| `exe-tmux-O0` | 42 | 39/360 |
| `exe-tmux-O1` | 44 | 36/364 |
| `exe-tree-O0` | 32 | 35/89 |
| `lib-curl-O0` | 38 | 16/158 |
| `lib-curl-O1` | 47 | 19/169 |
| `lib-lua-O0` | 9 | 7/50 |
| `lib-lua-O1` | 9 | 4/49 |
| `lib-openssl-4.1.0-O1` | 784 | 364/6,032 |
| `lib-parson-O0` | 0 | 0/5 |
| `lib-parson-O1` | 0 | 0/5 |
| `lib-small-g-O0` | 0 | 0/6 |
| `lib-sqlite-O0` | 72 | 38/297 |
| `lib-sqlite-O1` | 58 | 30/286 |
| `lib-stage_demo-O0` | 0 | 2/3 |

Across the inventory, 1,360 tracked globals have complete InitVal evidence and 887 of
9,090 are stationary. Stationarity verdict reasons are `incomplete_initval=7,400`,
`stationary=887`, `unknown_runtime_writer=777`, `runtime_writer=14`, and
`exported_global=12`.

## M4 Vararg Evidence

| input | vararg total | external | internal unmodeled | indirect | mutable rw |
|---|---:|---:|---:|---:|---:|
| `exe-OMP__tree-O0` | 68 | 65 | 3 | 0 | 0/52 |
| `exe-b2-hashmap_tree-O0` | 4 | 4 | 0 | 0 | 0/0 |
| `exe-chibicc-O0` | 100 | 10 | 90 | 0 | 0/83 |
| `exe-chibicc-O1` | 95 | 9 | 86 | 0 | 0/81 |
| `exe-curl-O0` | 124 | 32 | 92 | 0 | 0/78 |
| `exe-curl-O1` | 117 | 33 | 84 | 0 | 0/51 |
| `exe-gifsicle-O0` | 66 | 29 | 35 | 2 | 0/92 |
| `exe-gifsicle-O1` | 50 | 20 | 28 | 2 | 1/90 |
| `exe-jpegoptim-O0` | 67 | 38 | 29 | 0 | 0/45 |
| `exe-jpegoptim-O1` | 53 | 24 | 29 | 0 | 0/44 |
| `exe-jq-O0` | 82 | 25 | 57 | 0 | 6/8 |
| `exe-jq-O1` | 110 | 19 | 91 | 0 | 5/8 |
| `exe-lua-O0` | 93 | 21 | 72 | 0 | 0/6 |
| `exe-lua-O1` | 100 | 22 | 78 | 0 | 0/5 |
| `exe-sbase_cal-O0` | 3 | 1 | 2 | 0 | 0/2 |
| `exe-tmux-O0` | 105 | 32 | 73 | 0 | 0/82 |
| `exe-tmux-O1` | 101 | 31 | 70 | 0 | 0/80 |
| `exe-tree-O0` | 68 | 65 | 3 | 0 | 0/52 |
| `lib-curl-O0` | 584 | 5 | 579 | 0 | 0/45 |
| `lib-curl-O1` | 572 | 3 | 569 | 0 | 0/41 |
| `lib-lua-O0` | 82 | 15 | 67 | 0 | 0/4 |
| `lib-lua-O1` | 87 | 14 | 73 | 0 | 0/3 |
| `lib-openssl-4.1.0-O1` | 896 | 8 | 888 | 0 | 0/168 |
| `lib-parson-O0` | 1 | 0 | 1 | 0 | 0/5 |
| `lib-parson-O1` | 0 | 0 | 0 | 0 | 0/5 |
| `lib-small-g-O0` | 1 | 1 | 0 | 0 | 0/6 |
| `lib-sqlite-O0` | 1,061 | 28 | 1,027 | 6 | 0/80 |
| `lib-sqlite-O1` | 1,150 | 22 | 1,114 | 14 | 0/75 |
| `lib-stage_demo-O0` | 0 | 0 | 0 | 0 | 0/1 |

The inventory contains 5,840 M4 vararg findings: 5,240 internal-unmodeled (`89.7%`),
576 external (`9.9%`), and 24 indirect (`0.4%`). Indirect vararg findings occur only
in gifsicle and sqlite. The broader audit histogram is led by internal-unmodeled varargs
(`5,240`), function-pointer `ptrtoint` (`2,835`), and external varargs (`576`).

These results reinforce the existing M4 freeze decision: internal vararg evidence is
numerically dominant, but rows with hundreds or thousands of such findings generally
still have zero rewritable globals and also carry large unknown-global/unknown-callee
surfaces. Additional name-specific vararg summaries would mostly reduce explanation
volume rather than recover the large frozen components.

## Decision Read

- The lite pipeline scales across the available sibling inventory; OpenSSL is slow but
  completes within five minutes including validation.
- Rewritable coverage outside jq is effectively zero. This is not explained by varargs
  alone: large unknown-global, unknown-callee, and pointer-int surfaces coexist in the
  dominant frozen components.
- O1 usually reduces runtime and component size, but can increase residual unknown icall
  counts substantially (notably gifsicle, Lua, library curl, and sqlite). Optimization
  sensitivity therefore remains a first-class corpus variable.
- The next useful precision investigation remains unknown-global/modref attribution and
  boundary provenance, not broader M4 vararg summarization.
