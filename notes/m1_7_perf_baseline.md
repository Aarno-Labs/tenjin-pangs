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
release mode. The numbers below are the current post-optimization baseline.

1. `exe-jq-O0.bc`
   - single-run `pipeline wall`: `537 ms`
   - `metrics.analysis_wall_us`: `207877`
   - `pag_build_us`: `74206`
   - `solve_us`: `62388`
   - `transitive_modref_us`: `9723`
   - `components_us`: `964`
   - hyperfine mean: `575.8 ms ± 25.2 ms`
   - transitive mod/ref delta vs previous release baseline: `34200 us -> 9723 us`

2. `exe-lua-O0.bc`
   - single-run `pipeline wall`: `397 ms`
   - `metrics.analysis_wall_us`: `160851`
   - `pag_build_us`: `43358`
   - `solve_us`: `43673`
   - `transitive_modref_us`: `29078`
   - `components_us`: `1167`
   - hyperfine mean: `391.5 ms ± 9.1 ms`
   - transitive mod/ref delta vs previous release baseline: `117233 us -> 29078 us`

3. `exe-gifsicle-O0.bc`
   - single-run `pipeline wall`: `303 ms`
   - `metrics.analysis_wall_us`: `146427`
   - `pag_build_us`: `34055`
   - `solve_us`: `78012`
   - `transitive_modref_us`: `11627`
   - `components_us`: `671`
   - hyperfine mean: `311.3 ms ± 4.1 ms`
   - transitive mod/ref delta vs previous release baseline: `46612 us -> 11627 us`

Interpretation:
- the SCC/payload-interning rewrite substantially reduced `transitive_modref_us` on all
  three modules
- `components` is still negligible
- `solve` is now the dominant internal phase on `gifsicle`
- `lua` is no longer overwhelmingly closure-bound, though `transitive_modref` remains
  material
- `jq` remains more balanced, and the outer wall measurements were noisy enough that it
  should be rerun on a quieter machine before drawing stronger conclusions from its
  hyperfine mean
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
