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

Observed on June 14, 2026 after the M1.7 timing pass, the API closure optimization,
and the solver identity/storage optimization, measured in release mode. The numbers
below are the current post-optimization baseline.

1. `exe-jq-O0.bc`
   - single-run `pipeline wall`: `470 ms`
   - `metrics.analysis_wall_us`: `182861`
   - `pag_build_us`: `64411`
   - `solve_us`: `58019`
   - `transitive_modref_us`: `7494`
   - `components_us`: `623`
   - hyperfine mean: `491.3 ms ± 8.2 ms`
   - transitive mod/ref delta vs previous release baseline: `34200 us -> 7494 us`
   - solve delta vs previous release baseline: `51462 us -> 58019 us`

2. `exe-lua-O0.bc`
   - single-run `pipeline wall`: `314 ms`
   - `metrics.analysis_wall_us`: `123198`
   - `pag_build_us`: `37499`
   - `solve_us`: `35461`
   - `transitive_modref_us`: `20132`
   - `components_us`: `799`
   - hyperfine mean: `341.4 ms ± 5.3 ms`
   - transitive mod/ref delta vs previous release baseline: `117233 us -> 20132 us`
   - solve delta vs previous release baseline: `35089 us -> 35461 us`

3. `exe-gifsicle-O0.bc`
   - single-run `pipeline wall`: `260 ms`
   - `metrics.analysis_wall_us`: `109241`
   - `pag_build_us`: `28220`
   - `solve_us`: `48519`
   - `transitive_modref_us`: `10957`
   - `components_us`: `433`
   - hyperfine mean: `275.7 ms ± 1.3 ms`
   - transitive mod/ref delta vs previous release baseline: `46612 us -> 10957 us`
   - solve delta vs previous release baseline: `44399 us -> 48519 us`

Interpretation:
- the closure rewrite substantially reduced `transitive_modref_us` on all three modules
- the solver ID-based refactor reduced end-to-end wall time on all three modules, even
  though `solve_us` itself only improved materially on `gifsicle`
- `components` is still negligible
- `solve` remains the dominant internal phase on `gifsicle`
- `lua` is no longer closure-dominated; its remaining cost is split across PAG build,
  solve, and transitive closure
- `jq` is still more balanced, but its end-to-end wall improved enough that the
  optimization should be kept despite the smaller internal solver win
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
