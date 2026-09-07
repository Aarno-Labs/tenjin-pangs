# Stride-fields evaluation (2026-09-07)

## Configuration

Release CLI built with LLVM 14. Initial profiling runs used `analyze <input> --build-mode executable
--stage andersen --validate`, `PANGS_ANDERSEN_PROFILE=1`, and the corpus under
`/home/brk/pangs-corpus/_out_bc/`.  The enabled variant additionally set
`PANGS_PAG_PWC_LANES=1`; its effective derived-lane cap was 256 (the default, with no cap
override).  Off runs have no lane-domain cap.  Logs and compact summaries are retained in
`/tmp/pangs-stride-a/`; large Vim export directories were deleted after recording hashes.

| input | SHA-256 | off/on wall ms | off → on GEP pairs | off → on exact chains | on lane chains | off → on fields | off → on steps | peak RSS KiB off/on |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| exe-tmux-O1 | `bbf315…ab80d64` | 3241 / 3347 | 443 / 468 | 6 / 6 | 2 | 8491 / 8491 | 64600 / 79264 | 300612 / 300708 |
| exe-jq-O1 | `218daa…03ccfa` | 780 / 697 | 19720 / 9399 | 11906 / 1757 | 1907 | 4122 / 2650 | 86000 / 21602 | not collected |
| lib-sqlite-O1 | `159d8b…38caa87` | 8179 / 8034 | 90142 / 1094 | 86603 / 96 | 368 | 25294 / 5158 | 104690 / 32546 | 959748 / 961312 |
| exe-vim-9.2-O1 | `d29a94…dcd448a` | 230533 / 207829 | 138089 / 2827 | 76407 / 32 | 800 | 51726 / 39595 | 284859 / 190377 | 3418336 / 3418248 |

Wall times are single sequential measurements and are noisy.  The primary result is the large
reduction in exact chained derivations and GEP pair work for SQLite and Vim.  Tmux is the required
null case and regressed slightly in this one run. Peak RSS is the maximum reported
`hwm_kib` across all logged phases, not an intermediate solver snapshot. Unrelated builds
were active on the machine, so these runs do not establish a repeatable wall-time speedup.

Input SHA-256s (all files under `/home/brk/pangs-corpus/_out_bc/`):

```text
bbf31503609213a2dd908dc880032c673f1b165739681f2dc3d741551ab80d64  exe-tmux-O1.bc
218daa6fab58e4e553b55de450bad9b597bfe2c23f765559540bd7338a03ccfa  exe-jq-O1.bc
159d8b4cc4cf72705b6b2c44f2d27c7c9fcdeec39a475961cde411cfb38caa87  lib-sqlite-O1.bc
d29a9471def3dad7f747b65f74ebfcdf2154212f8407d7a1193574ad6dcd448a  exe-vim-9.2-O1.bc
```

Parent validation used a frozen copy of the evaluated release binary in
`/tmp/pangs-stride-final.myu2Gp/pangs-eval`, with `LD_LIBRARY_PATH` set to
`/home/brk/tenjin/_local/xj-llvm-14/lib`. Disposition pairs explicitly set
`PANGS_PAG_PWC_LANES=0` or `1` and `PANGS_ANDERSEN_PWC_LANE_CAP=256`, then ran:

```text
analyze <input> --build-mode executable --stage andersen --dispose --manifest-only
  --repo-root /home/brk/pangs-corpus --mode application --no-overrides --validate --out <variant-dir>
```

Differential validation used `differential <input> --build-mode executable` in both
configurations. These final correctness jobs partly overlapped; their wall times are excluded
from the performance table. Final source changes after the frozen build add tests, formatting,
and exported reproducibility metadata; the production inference/domain behavior is the same.

## Correctness and client ledger

- All eight differential cases passed: enabled and disabled configurations for tmux, SQLite,
  jq, and Vim. Each reported `differential: ok`. The disabled Vim check took about 22 minutes
  and the final enabled SQLite check took several minutes. These diagnostic runs were much
  more expensive than ordinary analysis; their concurrent, unprofiled timings are not used
  to claim a performance gain or identify a regression's cause.
- Direct off/on export comparisons found byte-identical globals, callgraph, and ModRef rows for
  all four modules. Vim's retained summary records identical SHA-256 hashes for all three.
- Manifest-only disposition comparisons completed for all four modules: `.globals` arrays
  (facts, witnesses, and dispositions) were identical.  Histograms off/on were tmux
  `atomic=22 immutable=12 unhandled=69`, SQLite `atomic=3 localize=3 unhandled=34`, and jq
  `immutable=1 mutex=4 unhandled=4`, and Vim `immutable=212 localize=20 unhandled=3459`.
- Dedicated corpus trace validation was not run: no suitable corpus trace files were located
  in the workspace. Both synthetic instrumented indirect-call tests passed in a separate
  `PANGS_PAG_PWC_LANES=1 cargo test -p pangs-cli --test pipeline dynamic_` run.

## Tests and implementation checks

`cargo test --workspace --all-targets` passed on the final source. An earlier full run
exposed the expected normalized-manifest golden hash change; the golden now asserts the new
default PWC metadata explicitly, and the targeted and full reruns passed.
Focused checks passed for the PWC SCC tests, manifest validation, and affected crates. Coverage
includes residual-gcd positive/negative cycles, zero cycles, existing-lane coarse handling,
unknown/arithmetic skips, a two-node GEP/Assign SCC with entering/exiting edges, bounded lane
overflow, late field creation, and lane sibling isolation.

The final release CLI builds successfully. A validated export smoke test with
`PANGS_PAG_PWC_LANES=1 PANGS_ANDERSEN_PWC_LANE_CAP=3` confirms both normal analysis and
disposition manifests record enablement and the effective cap of 3.

`cargo fmt --check` still reports only pre-existing formatting drift outside this work:
`pangs-clients/src/lib.rs:4464`, `pangs-pag/src/lib.rs:3527,3701,5041,5154`, and
`pangs-pag/tests/pag.rs:424`.

## Decision

Work item A remains experimental and opt-in.  Work item B is skipped: residual exact-chain/GEP
work is `96/1094 = 8.78%` on SQLite and `32/2827 = 1.13%` on Vim, below the 10% trigger.  Work
item C is gated on A promotion and was not started. The four-module static/client ledger above
is complete, but A cannot be promoted while the documented one-hop Steensgaard field-offset
soundness defect remains unresolved. No claim of whole-corpus soundness follows from these four
modules or their cross-tier agreement.
