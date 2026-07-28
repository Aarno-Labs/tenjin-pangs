Pending Ideas/Tasks

# Performance/Precision Tuning

## Forced Andersen costs

There are 30 non-Vim/non-OpenSSL bitcode artifacts with a current-policy oversize fallback. `exe-jq-O0.bc` has two; every other artifact has one.

I benchmarked the release analyzer in executable mode with:

- Current policy: partition budget 200,000, including provenance promotion.
- Forced Andersen: budget `u64::MAX`.
- Three runs for completed solves; values below are median wall times.
- Slow forced solves were terminated after 30 seconds. Four modules with large baseline runtimes received an extended 90-second run.

### Forced solves that completed

| Module | Max fallback nodes | Current | Forced | Impact |
|---|---:|---:|---:|---:|
| `exe-chibicc-O0.bc` | 13,835 | 0.50s | 35.94s | 71.9× |
| `exe-chibicc-O1.bc` | 8,608 | 0.42s | 5.01s | 11.9× |
| `exe-curl-O0.bc` | 13,351 | 1.14s | 7.55s | 6.6× |
| `exe-curl-O1.bc` | 5,012 | 0.93s | 7.78s | 8.4× |
| `exe-jq-O1.bc` | 22,640 | 1.33s | 23.59s | 17.7× |
| `exe-lua-O1.bc` | 17,986 | 0.75s | 23.63s | 31.5× |
| `exe-surprisetalk__slap-O0.bc` | 5,086 | 0.36s | 0.45s | 1.2× |
| `exe-yapteaparprfotci-O0-g.bc` | 5,828 | 0.13s | 1.41s | 10.8× |
| `lib-flac-O1-g.bc` | 10,213 | 0.71s | 2.31s | 3.3× |
| `lib-ksba-O0-g.bc` | 24,052 | 1.48s | 11.32s | 7.6× |
| `lib-ksba-O1-g.bc` | 10,853 | 1.00s | 2.30s | 2.3× |
| `lib-lua-O1.bc` | 17,799 | 0.85s | 24.58s | 28.9× |
| `lib-mbedtls-O1-g.bc` | 8,371 | 0.94s | 0.99s | 1.1× |
| `lib-parson-O0.bc` | 3,726 | 0.06s | 0.12s | 2.0× |
| `lib-tfpsacrypto-O1-g.bc` | 16,091 | 1.83s | 6.46s | 3.5× |

### Forced solves that did not complete within the cutoff

| Module | Max fallback nodes | Current | Forced lower bound | Minimum slowdown |
|---|---:|---:|---:|---:|
| `exe-gifsicle-O0.bc` | 20,433 | 0.81s | >30s | >37× |
| `exe-gifsicle-O1.bc` | 8,457 | 0.40s | >30s | >75× |
| `exe-jq-O0.bc`¹ | 49,991 | 3.29s | >30s | >9.1× |
| `exe-lua-O0.bc` | 36,538 | 1.27s | >30s | >23.6× |
| `exe-tmux-O0.bc` | 75,524 | 15.25s | >90s | >5.9× |
| `exe-tmux-O1.bc` | 31,862 | 6.95s | >30s | >4.3× |
| `lib-cairo-O1-g.bc` | 31,793 | 3.87s | >30s | >7.8× |
| `lib-curl-O0.bc` | 98,941 | 15.53s | >90s | >5.8× |
| `lib-curl-O1.bc` | 41,112 | 9.69s | >30s | >3.1× |
| `lib-freetype-O1.bc` | 42,487 | 4.88s | >30s | >6.1× |
| `lib-lua-O0.bc` | 35,987 | 1.35s | >30s | >22.2× |
| `lib-placebo-O1-g.bc` | 51,716 | 30.84s | >90s | >2.9× |
| `lib-sqlite-O0.bc` | 127,876 | 17.17s | >90s | >5.2× |
| `lib-sqlite-O1.bc` | 81,243 | 10.18s | >30s | >2.9× |
| `lib-zstd-O1-g.bc` | 41,090 | 2.32s | >30s | >12.9× |

¹ `exe-jq-O0.bc` has two oversize fallback partitions.

The result is fairly decisive: Tree and JPEGOptim were cheap because the current promotion already admits all their partitions. Across the actual fallback population, forcing Andersen is usually expensive. Only Slap and mbedTLS are essentially free; even among completed solves, slowdowns reach 72×, and half the modules fail to finish within 30 seconds.

The raw benchmark results are retained in `/tmp/pangs-oversize-force-bench.2pYTwa`. The working copy remains clean.

# Other Features

## Localization of address-taken compound literal initialized globals

For example, 

```c
static Scope *scope = &(Scope){};
```

in `chibicc/parse.c`.

A closure-aware localization proof should be able to say:

  - put the scope pointer in the context;
  - put an initially zeroed Scope backing object in the same context;
  - initialize the pointer to that context-owned backing object;
  - rewrite all uses of scope through the context.

