M1.7 perf baseline on real corpus modules

Environment:
- repo: `/home/brk/pangs`
- corpus: `~/pangs-corpus/_out_bc`
- pangs build: `target/release/pangs`
- stage: `steens`
- build mode: `executable`
- benchmark runner: `scripts/m1_7_corpus_bench.sh`
- hyperfine runs: `3`

Command shape:
- `target/release/pangs analyze <module> -o <out> --stage steens --build-mode executable --validate`

Observed on June 14, 2026 after the first M1.7 timing + closure pass, measured in
release mode:

1. `exe-jq-O0.bc`
   - single-run `pipeline wall`: `490 ms`
   - `metrics.analysis_wall_us`: `206224`
   - `pag_build_us`: `68793`
   - `solve_us`: `51462`
   - `transitive_modref_us`: `34200`
   - `components_us`: `662`
   - hyperfine mean: `519.2 ms ± 6.7 ms`

2. `exe-lua-O0.bc`
   - single-run `pipeline wall`: `419 ms`
   - `metrics.analysis_wall_us`: `219268`
   - `pag_build_us`: `37446`
   - `solve_us`: `35089`
   - `transitive_modref_us`: `117233`
   - `components_us`: `801`
   - hyperfine mean: `435.1 ms ± 3.3 ms`

3. `exe-gifsicle-O0.bc`
   - single-run `pipeline wall`: `289 ms`
   - `metrics.analysis_wall_us`: `140280`
   - `pag_build_us`: `27194`
   - `solve_us`: `44399`
   - `transitive_modref_us`: `46612`
   - `components_us`: `466`
   - hyperfine mean: `316.4 ms ± 8.9 ms`

Interpretation:
- `components` is negligible.
- `transitive_modref` is still a major cost on `lua`.
- `solve` and `transitive_modref` are comparable on `gifsicle`; neither should be
  ignored.
- `jq` is more balanced across PAG build, solve, and transitive closure.
- `analysis_wall_us` is lower than end-to-end `pipeline wall` and hyperfine because it
  excludes some CLI/process/export overhead; the outer wall is recorded in
  `manifest.json.wall_ms` and surfaced via `pangs report`.

Policy note:
- earlier debug-build measurements were intentionally discarded as optimization
  baselines; they were only useful to sanity-check the timing plumbing.

Reproduction:
- `LLVM_SYS_140_PREFIX=/home/brk/tenjin/_local/xj-llvm-14 LD_LIBRARY_PATH=/home/brk/tenjin/_local/xj-llvm-14/lib RUNS=3 scripts/m1_7_corpus_bench.sh`
- defaults target `jq`, `lua`, and `gifsicle`
- outputs land in `ju_out/m1_7/`
