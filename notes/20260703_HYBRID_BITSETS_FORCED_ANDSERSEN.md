
Scope: 52 top-level bitcodes, excluding two Vim and one OpenSSL module, leaving 49 modules / 98 configurations. All used a release build, forced full admission, and matched baseline/hybrid settings.

| Metric | Baseline | Hybrid | Change |
|---|---:|---:|---:|
| Completed-pair wall time | 1,944.18 s | 1,626.69 s | −16.3% |
| Summed peak RSS | 19.86 GiB | 12.00 GiB | −39.6% |
| Wall-time geomean ratio | — | 0.860 | −14.0% |
| Wall-time median ratio | — | 0.891 | −10.9% |
| RSS geomean ratio | — | 0.816 | −18.4% |

Of 49 pairs:

- 36 completed successfully.
- Hybrid was faster in 24, slower in 3, and tied in 7.
- The three regressions were tiny subsecond modules and likely timing noise.
- 13 pairs were incomplete under the timeout policy.
- All five client-visible exports were hash-identical for every completed pair.

Notable results:

| Module | Baseline | Hybrid |
|---|---:|---:|
| chibicc O0 | 58.67 s / 1.48 GiB | 28.60 s / 546 MiB |
| gifsicle O0 | 358.13 s / 2.50 GiB | 309.65 s / 1.26 GiB |
| jq O0 | 236.26 s / 2.98 GiB | 216.42 s / 1.27 GiB |
| FLAC | 37.75 s / 581 MiB | 20.98 s / 410 MiB |
| mbedtls | 245.10 s / 1.75 GiB | 204.07 s / 1.08 GiB |
| zstd | 467.35 s / 3.83 GiB | 382.84 s / 2.47 GiB |
| YAPET O0 | 1.82 s / 106 MiB | 1.36 s / 87 MiB |
| YAPET O1 | 1.97 s / 95 MiB | 1.04 s / 68 MiB |

The main conclusion is that hybrid bitsets provide a broad, substantial memory improvement and a meaningful runtime improvement, but do not fix propagation/scheduling pathologies:

- Lua and SQLite remained low-memory, CPU-bound timeouts.
- tmux, Cairo, curl, Freetype, and Placebo remained high-memory forced-admission timeouts.
- Placebo’s observed live RSS fell from roughly 37 GiB to 6.53 GiB, despite both timing out.
- Libcurl O0 remained especially pathological: approximately 35.4 GiB baseline versus 21.9 GiB hybrid.

The reusable resumable harness is [profile_hybrid_bitsets_corpus.py](/home/brk/pangs/scripts/profile_hybrid_bitsets_corpus.py:1), and the summarized results are recorded in [EXPERIMENT_HISTORY.md](/home/brk/pangs/EXPERIMENT_HISTORY.md:213). Raw measurements are currently at `/tmp/pangs-hybrid-bitsets-corpus-20260731.json`.

`cargo fmt --all -- --check` and the harness help path pass. The working-copy description is `Prototype hybrid Andersen points-to bitsets and corpus profile`.
