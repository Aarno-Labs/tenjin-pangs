# Curl indirect-call audit — 2026-08-24

## Scope

This audit reruns the current split B1/B2 provenance on the four curl corpus modules at
curl commit `fdb8a789d2b446b77bd7cdd2eff95f6cbc814cf4` (2025-06-04):

- `exe-curl-{O0,O1}.bc`, analyzed as executables;
- `lib-curl-{O0,O1}.bc`, analyzed as libraries;
- an additional `llvm-link` of each executable/library pair, analyzed as one executable to
  approximate KELP's closed, self-contained-program assumption.

The checked-in JSONL and summary files are the raw census artifacts. The linked bitcode is
reproducible with LLVM 14:

```bash
llvm-link exe-curl-O0.bc lib-curl-O0.bc -o /tmp/pangs-curl-linked-O0.bc
llvm-link exe-curl-O1.bc lib-curl-O1.bc -o /tmp/pangs-curl-linked-O1.bc
```

## Exact-preanalysis result

| module | icalls | B1 InitVal | B2 simple | confined functions |
|---|---:|---:|---:|---:|
| exe curl O0 | 2 | 0 | 0 | 0 |
| exe curl O1 | 2 | 0 | 0 | 0 |
| libcurl O0, library semantics | 1,207 | 0 | 0 | 0 |
| libcurl O1, library semantics | 1,658 | 0 | 0 | 0 |
| linked curl O0, executable semantics | 1,209 | 0 | 0 | 0 |
| linked curl O1, executable semantics | 1,660 | 0 | 0 | 0 |

The M2 ablation on each of the four original modules confirms zero marginal callgraph
effect: baseline, B2-only, B1-only, and both have identical `call_edges`, tier counts, and
unknown counts. B1 is nevertheless active: for libcurl it reports 112 complete/24 stable
globals at O0 and 121 complete/34 stable globals at O1. It simply certifies no icall.

## Operand shapes

| libcurl operand bucket | O0 sites | O0 share | O1 sites | O1 share |
|---|---:|---:|---:|---:|
| dispatch-table/global load | 929 | 77.0% | 1,288 | 77.7% |
| unclassified memory | 155 | 12.8% | 231 | 13.9% |
| parameter dereference | 66 | 5.5% | 81 | 4.9% |
| parameter passed directly | 53 | 4.4% | 55 | 3.3% |
| other | 4 | 0.3% | 3 | 0.2% |

The dominant class is not an ordinary immutable dispatch table. In O0, 927 of the 929
global-load sites have the allocator callback signatures and one concrete default target.
Source inspection identifies curl's process-wide replaceable allocator hooks:
`Curl_cmalloc`, `Curl_cfree`, `Curl_crealloc`, `Curl_cstrdup`, and `Curl_ccalloc`.
`curl_global_init_mem()` can overwrite all five from caller-supplied callbacks. The PIR marks
all five globals exported and mutable.

This explains why library-mode exact resolution would be wrong: an external library client
can install an arbitrary compatible callback. PANGS therefore retains Ω at those sites. B2
also rejects an exported global before walking its stores (`global_is_never_address_taken`),
independently of the selected build mode.

## Closed-world linked result

| linked module | sites | finite | finite share | finite singleton | singleton share | Ω |
|---|---:|---:|---:|---:|---:|---:|
| O0 | 1,209 | 974 | 80.6% | 933 | 77.2% | 235 |
| O1 | 1,660 | 1,336 | 80.5% | 1,295 | 78.0% | 324 |

The high closed-world singleton yield is real, but it comes from Andersen, not B2. In the
linked O0 run, 927 allocator-hook sites become finite singleton answers because no reachable
call installs replacements. B2 still resolves zero sites because its exported-global rule is
syntactic and deliberately more conservative than the executable reachability model.

Under ordinary library semantics the contrast is equally sharp:

| library module | finite | finite share | Ω | silent |
|---|---:|---:|---:|---:|
| O0 | 39 | 3.2% | 1,168 | 0 |
| O1 | 41 | 2.5% | 1,617 | 0 |

## Comparison with KELP

KELP's Table 1 used a 168-KLoC Curl benchmark with 989 indirect calls. It reports 276
single-callee sites under MLTA and 855 under full KELP, while Figure 7 reports a very high
simple-icall share for Curl. The present corpus is not the same benchmark: its curl revision,
feature configuration, and site counts differ, and the KELP paper assumes a closed,
self-contained program.

The comparable conclusions are therefore:

1. **PANGS B2 does not reproduce KELP's Curl simple-icall yield:** 0 sites in every tested
   build and scope.
2. **The overall closed-world phenomenon mostly reproduces:** about 80.5% of sites become
   finite and 77–78% become finite singletons, but through exhaustive Andersen.
3. **The apparent discrepancy in this corpus is dominated by curl's replaceable allocator globals.** They
   look like simple global loads locally, are legitimately open under library semantics, and
   become singleton defaults under the linked executable's closed-world reachability.
4. This audit does not establish that PANGS B2 is defective in its stated conservative
   semantics. It does show that its exported-global rule prevents it from capturing the
   dominant Curl pattern in this corpus, so the current B2 cannot serve as a reproduction
   of KELP's evaluation result.

## Soundness gate

`fn_gate.sh` passes on the four original modules: exact L1 accounting, zero silent sites,
and no unlowered constant-expression operand names. The linked runs also contain zero silent
sites; their temporary bitcode was not retained in this directory.
