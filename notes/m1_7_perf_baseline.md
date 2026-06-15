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
the solver identity/storage optimization, and the deduplicated solver worklist,
measured in release mode. The numbers below are the current post-optimization
baseline.

1. `exe-jq-O0.bc`
   - single-run `pipeline wall`: `497 ms`
   - `metrics.analysis_wall_us`: `189458`
   - `pag_build_us`: `76302`
   - `solve_us`: `51444`
   - `transitive_modref_us`: `7654`
   - `components_us`: `666`
   - hyperfine mean: `490.3 ms ± 7.3 ms`
   - transitive mod/ref delta vs previous release baseline: `34200 us -> 7494 us`
   - solve delta vs previous release baseline: `51462 us -> 51444 us`

2. `exe-lua-O0.bc`
   - single-run `pipeline wall`: `307 ms`
   - `metrics.analysis_wall_us`: `114493`
   - `pag_build_us`: `36535`
   - `solve_us`: `27265`
   - `transitive_modref_us`: `21669`
   - `components_us`: `708`
   - hyperfine mean: `332.3 ms ± 0.9 ms`
   - transitive mod/ref delta vs previous release baseline: `117233 us -> 20132 us`
   - solve delta vs previous release baseline: `35089 us -> 27265 us`

3. `exe-gifsicle-O0.bc`
   - single-run `pipeline wall`: `237 ms`
   - `metrics.analysis_wall_us`: `86460`
   - `pag_build_us`: `27616`
   - `solve_us`: `23168`
   - `transitive_modref_us`: `11660`
   - `components_us`: `461`
   - hyperfine mean: `258.1 ms ± 5.7 ms`
   - transitive mod/ref delta vs previous release baseline: `46612 us -> 10957 us`
   - solve delta vs previous release baseline: `44399 us -> 23168 us`

Interpretation:
- the closure rewrite substantially reduced `transitive_modref_us` on all three modules
- the solver ID-based refactor plus worklist dedup reduced end-to-end wall time on all
  three modules
- `components` is still negligible
- `solve` is no longer overwhelmingly dominant on `gifsicle`, though it remains one of
  the two largest internal buckets
- `lua` is no longer closure-dominated; its remaining cost is split across PAG build,
  solve, and transitive closure
- `jq` is still more balanced and saw little solver-phase movement from the last pass
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
