# Andersen admission calibration

## Measurement

The admission profiler isolates one interesting partition at a time, forcibly
admits it over a Steensgaard baseline, and records:

- structural counts and the old `nodes * (nodes + edges)` proxy;
- actual Andersen work (worklist pops, inserted points-to facts/copy edges,
  constraint-pair expansions, field cells, and SCC scan work);
- whether normalized callgraph targets, ModRef rows, or globals rows differ
  from the Steensgaard client exports.

Callgraph `tier` is deliberately ignored: changing only `steens` to `andersen`
is provenance relabeling, not a different target answer.

The cheap census has a dedicated solver-level CLI path and stops before
Andersen propagation and API client construction:

```sh
systemd-run --user --scope -p MemoryMax=40G \
  scripts/profile_andersen_admission.py \
    --pangs target/release/pangs \
    --corpus /home/brk/pangs-corpus/_out_bc \
    --output /tmp/andersen-admission-census-no-trials-20260727.jsonl \
    --census-output /tmp/andersen-admission-census-20260727.jsonl \
    --census-only --jobs 2
```

The corpus contains 45 modules and 290,148 interesting partitions. Of these:

- 119 exceed the 200,000 quadratic proxy;
- 85 also fit the old promotion envelope (`nodes <= 4096`,
  `edges <= 4096`, and no `inttoptr` seed).

The 85 promotion candidates are not concentrated in one example. Vim accounts
for 35, OpenSSL for 15, and 25 other modules account for the remaining 35.

## Isolated trials

Before client construction on Vim made further exact counterfactuals
prohibitively repetitive, the profiler completed 448 unique isolated trials:

- 430 controls at or below the 200,000 old proxy;
- 18 partitions above the proxy and inside the old promotion envelope.

At the 200,000 measured-work dividing line:

| Population | Count |
| --- | ---: |
| Proxy-expensive, actually at or below budget | 10 |
| Proxy-expensive, actually above budget | 8 |
| Proxy-cheap, actually above budget | 0 |

Six of the 18 boundary partitions changed a client-visible answer. Three were
actually cheap and three were actually expensive. Examples:

| Module/root | Old proxy | Actual work | Client-visible difference |
| --- | ---: | ---: | --- |
| `jpegoptim-O1` / 1973 | 326,934 | 3,516 | yes |
| `b2-hashmap_tree-O0` / 2241 | 2,426,917 | 12,996 | yes |
| `surprisetalk__slap-O0` / 21952 | 896,325 | 43,009 | yes |
| `jpegoptim-O0` / 3683 | 5,293,989 | 489,671 | yes |
| `OMP__tree-O0` / 9955 | 25,944,204 | 7,035,720 | yes |

The actual-work total is deterministic in definition but can vary modestly
with hash iteration order because SCC timing changes; this does not affect the
orders-of-magnitude distinctions above.

## Decision

The measurement rejects the premise that the proxy-expensive, cheap, relevant
population is close to one. It also shows that the current provenance promotion
is too broad: it admits both the 3.5k-work JPEGOptim partition and multi-million
work OMP/tree partitions solely because both fit the same node/edge caps.

Simple edge-count estimators are not adequate. For example,
`nodes + edges + loads*nodes + geps*stores` admits the four ~223k Curl
partitions but rejects the 13k-work `b2-hashmap_tree` partition and the
13k-work large `pure` partition. The missing predictor is Steensgaard-class
pointee fanout: the same number of load/store/GEP constraints can join against
very different numbers of possible objects.

The next cheap calibration step is therefore to add per-partition
Steensgaard-fanout terms (copy-source pointee population, load/store/GEP base
pointee population, and memcpy endpoint cross-products) to the structural
census and re-run the isolated sample. Do not delete
`ANDERSEN_PROVENANCE_PROMOTION_*` or replace the admission proxy with the
currently available counts yet. Transactional metering remains the fallback
if the fanout-aware estimator misprices meaningful populations in both
directions.
