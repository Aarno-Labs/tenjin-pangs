# M3 Lite Measurements

Date: 2026-06-16

This note records the first `DESIGN_lite.md` M3 measurement pass. It uses only the lite
`analyze` pipeline (`--stage andersen`) and `pangs report`; the experimental tier-E CFL
query prototype was not run and does not feed these results.

## Command

Release binary:

```bash
LLVM_SYS_140_PREFIX=/home/brk/tenjin/_local/xj-llvm-14 \
LD_LIBRARY_PATH=/home/brk/tenjin/_local/xj-llvm-14/lib \
cargo build --release -p pangs-cli
```

Per input:

```bash
LLVM_SYS_140_PREFIX=/home/brk/tenjin/_local/xj-llvm-14 \
LD_LIBRARY_PATH=/home/brk/tenjin/_local/xj-llvm-14/lib \
timeout 300s target/release/pangs analyze \
  /home/brk/pangs-corpus/_out_bc/<input>.bc \
  --build-mode executable \
  --stage andersen \
  --out /tmp/pangs-m3-lite/<input>-andersen \
  --validate

target/release/pangs report /tmp/pangs-m3-lite/<input>-andersen
```

## Results

| input | status | funcs | globals | call edges | mutable rewritable | icalls simple | icalls andersen | icalls steens | icalls unknown | oversize fallbacks | max fallback size | max component | max frozen component | analysis s | solve s | transitive modref s |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `exe-jpegoptim-O1` | ok | 129 | 317 | 605 | 0/48 | 0 | 0 | 14 | 14 | 6 | 1339 | 121 | 121 | 0.21 | 0.01 | 0.10 |
| `lib-parson-O1` | ok | 147 | 44 | 399 | 4/5 | 0 | 0 | 132 | 0 | 5 | 2304 | 107 | 107 | 0.02 | 0.00 | 0.01 |
| `exe-jq-O1` | ok | 709 | 1313 | 6436 | 5/14 | 0 | 0 | 8 | 8 | 17 | 26647 | 636 | 636 | 22.88 | 0.19 | 19.51 |
| `exe-chibicc-O1` | ok | 221 | 956 | 2657 | 0/133 | 0 | 0 | 1 | 1 | 10 | 11017 | 213 | 213 | 21.67 | 0.09 | 19.28 |
| `exe-gifsicle-O1` | ok | 333 | 646 | 4199 | 1/93 | 0 | 4 | 203 | 203 | 10 | 14015 | 284 | 284 | 29.07 | 0.17 | 27.55 |
| `exe-lua-O1` | timeout 300s before closure fix | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - |

Export/report directories for completed rows are under `/tmp/pangs-m3-lite/`.

## Component Blockers

Largest frozen components from `pangs report`:

| input | largest frozen component | mutable globals in largest frozen | dominant taints | blocker summary |
|---|---:|---:|---|---|
| `exe-jpegoptim-O1` | 121 funcs | 47 | `unknown_global=67`, `fnptr_varargs=53`, `unknown_callee=14` | outgoing `steens=170`, incoming `steens=156`, unknown callees 14, unknown modrefs 68 |
| `lib-parson-O1` | 107 funcs | 5 | `unknown_global=149`, `fnptr_ptrtoint=6` | outgoing `steens=132`, incoming `steens=132`, unknown modrefs 165 |
| `exe-jq-O1` | 636 funcs | 10 | `unknown_global=1006`, `fnptr_varargs=115`, `fnptr_ptrtoint=37` | outgoing `steens=42`, incoming `steens=34`, unknown callees 8, unknown modrefs 1008 |
| `exe-chibicc-O1` | 213 funcs | 84 | `unknown_global=207`, `fnptr_varargs=100`, `fnptr_ptrtoint=14` | outgoing `steens=6`, incoming `steens=5`, unknown callees 1, unknown modrefs 250 |
| `exe-gifsicle-O1` | 284 funcs | 90 | `unknown_global=379`, `unknown_callee=203`, `fnptr_varargs=54` | outgoing `steens=2543 andersen=11`, incoming `steens=2340 andersen=11`, unknown callees 203, unknown modrefs 399 |

## Initial Read

- Coverage is acceptable only on `lib-parson-O1` in this first set. `exe-jq-O1` retains
  some coverage (`5/14`), while jpegoptim/chibicc/gifsicle are effectively blocked by
  large frozen components.
- The dominant blocker is not obviously tier-E-style context sensitivity. The largest
  frozen components are dominated by `unknown_global`, unknown mod/ref rows, vararg
  function-pointer audit taints, int-punning audit taints, and unknown callees.
- `exe-gifsicle-O1` has the strongest icall-residue signal in this batch: 203 unknown
  indirect-call sites and thousands of Steensgaard indirect edges in the largest frozen
  component. It still also has heavy unknown-global/modref taint, so tier E would not be
  the first thing to reach for without deeper attribution.
- Runtime is dominated by transitive mod/ref closure on the larger completed rows.
  Andersen solve itself is small (`0.09s` to `0.19s` on jq/chibicc/gifsicle), while
  transitive mod/ref takes about `19s` to `28s`.
- `exe-lua-O1` initially timed out under the 300s cap on the normal lite analysis path,
  but the transitive closure fix below cleared that timeout.

## Transitive Mod/Ref Closure Investigation

The initial jq/chibicc/gifsicle runs exposed a closure-specific cost, not an Andersen solve
cost. The old transitive mod/ref API materialized one closure row per witness instance,
using `(global, access, via, witness)` as the payload key. The local rows in these corpus
inputs are almost all unique only because of witness suffixes; the semantic mod/ref facts
collapse heavily if keyed by `(global, access, via)`.

Observed expansion from the first exports:

| input | local modref rows | unique facts without witness | old per-function closure rows | per-function closure rows without witness |
|---|---:|---:|---:|---:|
| `exe-jq-O1` | 933,767 | 301 | 23,021,064 | 111,816 |
| `exe-chibicc-O1` | 660,228 | 443 | 22,124,911 | 39,816 |
| `exe-gifsicle-O1` | 423,204 | 352 | 27,156,869 | 39,375 |

The closure now keys payloads by `(global, access, via)` and retains the lexicographically
first witness as a deterministic diagnostic representative. Local `analysis.modrefs()` and
`modref.jsonl` are unchanged; only the transitive `analysis.modref(func)` API avoids
materializing duplicate witness instances.

Rerun output directory: `/tmp/pangs-m3-lite-modref-facts/`.

| input | old analysis s | new analysis s | old transitive modref s | new transitive modref s | local modref rows |
|---|---:|---:|---:|---:|---:|
| `exe-jq-O1` | 22.88 | 4.05 | 19.51 | 0.073 | 933,767 |
| `exe-chibicc-O1` | 21.67 | 2.60 | 19.28 | 0.036 | 660,228 |
| `exe-gifsicle-O1` | 29.07 | 1.64 | 27.55 | 0.057 | 423,204 |
| `exe-lua-O1` | timeout 300s | 5.33 | unknown | 0.079 | 1,437,754 |

After this change, transitive closure is no longer the dominant cost on these rows. The
remaining cost is in earlier local mod/ref generation and export/validation wall time. The
same fix also cleared the earlier `exe-lua-O1` 300s timeout: the rerun completed with status
0 under `/tmp/pangs-m3-lite-modref-facts/exe-lua-O1-andersen`.

## Local Mod/Ref Row Investigation

The remaining local `modref.jsonl` size was also mostly witness-instance duplication. Local
rows now use the same semantic fact identity as transitive closure: `(func, global, access,
via)`, with one deterministic representative witness retained for diagnostics. This preserves
the sound mod/ref fact while avoiding one exported row per duplicate witness suffix.

Rerun output directory: `/tmp/pangs-m3-lite-local-modref-facts/`.

| input | old local rows | new local rows | old modref size | new modref size | old wall s | new wall s | old analysis s | new analysis s |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `exe-jq-O1` | 933,767 | 60,238 | 109M | 7.2M | 17.06 | 3.60 | 4.05 | 2.51 |
| `exe-chibicc-O1` | 660,228 | 33,861 | 75M | 4.0M | 11.78 | 2.23 | 2.60 | 1.64 |
| `exe-gifsicle-O1` | 423,204 | 21,760 | 54M | 2.8M | 7.55 | 1.55 | 1.64 | 1.11 |
| `exe-lua-O1` | 1,437,754 | 106,899 | 164M | 13M | 23.02 | 5.62 | 5.33 | 4.02 |

After local deduplication, export/validation no longer dominates the medium rows nearly as
strongly. Lua remains the largest medium case in this set, but completes comfortably under
the 300s cap.

## First Stress Sanity Check

`exe-curl-O1` was run after local deduplication as a first larger input before attempting
sqlite/tmux-sized rows.

Command output directory: `/tmp/pangs-m3-lite-local-modref-facts/exe-curl-O1-andersen/`.

| input | funcs | globals | call edges | mutable rewritable | icalls andersen | icalls steens | icalls unknown | oversize fallbacks | max fallback size | max component | max frozen component | wall s | analysis s | solve s | transitive modref s | local modref rows |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `exe-curl-O1` | 320 | 1944 | 2265 | 16/80 | 0 | 1 | 1 | 26 | 7891 | 304 | 304 | 3.79 | 2.59 | 0.21 | 0.022 | 76,530 |

The runtime behavior holds on this first larger row. The blocker profile is still dominated
by modeling/audit issues rather than solver time: the largest frozen component has
`unknown_global=86`, `fnptr_varargs=268`, `fnptr_ptrtoint=14`, `inline_asm=1`, and only one
unknown indirect callsite.

## Large Stress Attempt

`exe-tmux-O1` was then tried as the first sqlite/tmux-sized executable row:

```bash
LLVM_SYS_140_PREFIX=/home/brk/tenjin/_local/xj-llvm-14 \
LD_LIBRARY_PATH=/home/brk/tenjin/_local/xj-llvm-14/lib \
timeout 300s target/release/pangs analyze \
  /home/brk/pangs-corpus/_out_bc/exe-tmux-O1.bc \
  --build-mode executable \
  --stage andersen \
  --out /tmp/pangs-m3-lite-local-modref-facts/exe-tmux-O1-andersen \
  --validate
```

Initial result: timed out with exit status 124 and no metrics/export files were produced.

`perf` and opt-in `PANGS_ANDERSEN_PROFILE=1` instrumentation localized the timeout to the
first Andersen fixed-graph solve. The pre-fix profile showed a finite-looking scope
(`5448` in-scope nodes, `1721` in-scope edges, `4` in-scope icalls), but the solve never
converged because cyclic nested GEPs could materialize an unbounded chain of synthetic field
cells (`fields` grew by about `5000` every `10000` worklist steps).

The fix makes Andersen's field abstraction finite without collapsing ordinary non-zero GEPs.
Nested constant GEPs from an already-materialized field are canonicalized back to
`root + combined_offset` when that offset is part of the fixed graph's finite offset
vocabulary; zero-offset casts remain precise. Nested unknown offsets, overflowing offset
arithmetic, or combined offsets outside that finite vocabulary collapse conservatively back to
the root object. Regression coverage includes both the cyclic field-growth case
(`fixtures/synthetic/m1_4b/cyclic_nested_gep.pir.json`) and a container-of-style negative
offset case that still resolves precisely.

Fixed `exe-tmux-O1` result:

| input | funcs | globals | call edges | mutable rewritable | icalls andersen | icalls steens | icalls unknown | oversize fallbacks | max fallback size | max component | max frozen component | wall s | analysis s | solve s | transitive modref s | local modref rows | modref size |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `exe-tmux-O1` | 1315 | 3237 | 10848 | 0/107 | 4 | 53 | 51 | 18 | 45132 | 1261 | 1261 | 59.43 | 42.61 | 2.73 | 0.356 | 1,221,727 | 190M |

The large row now completes, but it exposes a new scale concern: even after semantic local
deduplication, tmux exports a very large mod/ref surface. The solver itself is no longer the
timeout bottleneck on this row.

## M3 Lite Decision Table

This table uses the current local-dedup exports under
`/tmp/pangs-m3-lite-local-modref-facts/`.

| input | funcs | globals | wall s | analysis s | solve s | transitive modref s | local modref rows | mutable rewritable | icalls andersen | icalls steens | icalls unknown | oversize fallbacks | max fallback size |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `exe-jpegoptim-O1` | 129 | 317 | 0.17 | 0.08 | 0.01 | 0.001 | 3,706 | 0/48 | 0 | 14 | 14 | 6 | 1,339 |
| `lib-parson-O1` | 147 | 44 | 0.03 | 0.01 | 0.00 | 0.000 | 290 | 4/5 | 0 | 132 | 0 | 5 | 2,304 |
| `exe-jq-O1` | 709 | 1,313 | 3.60 | 2.51 | 0.22 | 0.035 | 60,238 | 5/14 | 0 | 8 | 8 | 17 | 26,647 |
| `exe-chibicc-O1` | 221 | 956 | 2.23 | 1.64 | 0.09 | 0.012 | 33,861 | 0/133 | 0 | 1 | 1 | 10 | 11,017 |
| `exe-gifsicle-O1` | 333 | 646 | 1.55 | 1.11 | 0.18 | 0.027 | 21,760 | 1/93 | 4 | 203 | 203 | 10 | 14,015 |
| `exe-lua-O1` | 715 | 787 | 5.62 | 4.02 | 0.42 | 0.038 | 106,899 | 0/5 | 1 | 64 | 64 | 13 | 25,564 |
| `exe-curl-O1` | 320 | 1,944 | 3.79 | 2.59 | 0.21 | 0.022 | 76,530 | 16/80 | 0 | 1 | 1 | 26 | 7,891 |
| `exe-tmux-O1` | 1,315 | 3,237 | 59.43 | 42.61 | 2.73 | 0.356 | 1,221,727 | 0/107 | 4 | 53 | 51 | 18 | 45,132 |

Largest frozen component/blocker summary:

| input | max component | max frozen component | dominant taints in largest frozen component | largest component blockers |
|---|---:|---:|---|---|
| `exe-jpegoptim-O1` | 121 | 121 | `fnptr_varargs=53`, `unknown_global=17`, `unknown_callee=14`, `setjmp_longjmp=1` | outgoing `steens=170`, incoming `steens=156`, unknown callees 14, unknown modrefs 18 |
| `lib-parson-O1` | 107 | 107 | `unknown_global=41`, `fnptr_ptrtoint=6` | outgoing `steens=132`, incoming `steens=132`, unknown modrefs 52 |
| `exe-jq-O1` | 636 | 636 | `unknown_global=217`, `fnptr_varargs=115`, `fnptr_ptrtoint=37`, `unknown_callee=8` | outgoing `steens=42`, incoming `steens=34`, unknown callees 8, unknown modrefs 217 |
| `exe-chibicc-O1` | 213 | 213 | `fnptr_varargs=100`, `unknown_global=65`, `fnptr_ptrtoint=14`, `unknown_callee=1` | outgoing `steens=6`, incoming `steens=5`, unknown callees 1, unknown modrefs 72 |
| `exe-gifsicle-O1` | 284 | 284 | `unknown_callee=203`, `unknown_global=118`, `fnptr_varargs=54`, `fnptr_ptrtoint=19` | outgoing `steens=2543 andersen=11`, incoming `steens=2340 andersen=11`, unknown callees 203, unknown modrefs 128 |
| `exe-lua-O1` | 694 | 694 | `unknown_global=319`, `fnptr_varargs=109`, `unknown_callee=64`, `fnptr_ptrtoint=48` | outgoing `steens=4336 andersen=8`, incoming `steens=4272 andersen=8`, unknown callees 64, unknown modrefs 321 |
| `exe-curl-O1` | 304 | 304 | `fnptr_varargs=268`, `unknown_global=86`, `fnptr_ptrtoint=14`, `inline_asm=1` | outgoing `steens=5`, incoming `steens=4`, unknown callees 1, unknown modrefs 88 |
| `exe-tmux-O1` | 1261 | 1261 | `fnptr_varargs=637`, `unknown_global=564`, `unknown_callee=49`, `fnptr_ptrtoint=37` | outgoing `steens=2879 andersen=10`, incoming `steens=2830 andersen=10`, unknown callees 49, unknown modrefs 580 |

Decision read:

- Runtime is acceptable for lite M3 on the smoke/medium rows and curl. The tmux-sized row now
  completes after the finite-field fix, but it is large enough (`~60s`, `190M` modref export)
  that M3 should not claim broad large-module scaling without more export/modref work.
- The coverage failures are still dominated by modeling/audit envelopes: unknown globals,
  unknown mod/ref facts, varargs, ptrtoint/inttoptr, inline asm, setjmp/longjmp, and broad
  Steensgaard fallback partitions.
- Tier-E/CFL is not justified as the next default implementation step from this table. The
  only row with a strong unknown-icall signal is gifsicle, and even that row is heavily mixed
  with unknown-global/modref and audit taints. jq/chibicc/curl have very small unknown-icall
  residue relative to their frozen-component blockers.

## Next

The immediate next step is to decide whether M3 freezes with tmux as a known large-row scale
warning, or whether to do one more export/modref-size slice before freezing.

The main remaining design question is still coverage, not raw runtime: the largest frozen
components in the first pass were dominated by unknown globals, unknown mod/ref facts, vararg
function-pointer taints, int-punning taints, and unknown callees.
