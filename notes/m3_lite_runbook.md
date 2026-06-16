# M3 Lite Runbook

Date: 2026-06-16

This runbook follows `PLAN-M3.md` under `DESIGN_lite.md`: M3 measures the lite pipeline
and decides whether to ship it, add typed heap clones, or revive the archived tier-E
upgrade plan. It does not use the experimental M3.1-M3.3 CFL query prototype as an
analysis answer.

## Corpus

Available real-program bitcode inputs live under:

```bash
/home/brk/pangs-corpus/_out_bc/
```

Initial candidate set:

| role | input | reason |
|---|---|---|
| smoke | `exe-jpegoptim-O1.bc` | small executable; fast sanity check |
| smoke | `lib-parson-O1.bc` | small library with known indirect-call structure |
| medium | `exe-lua-O1.bc` | enough function-pointer structure to stress provenance |
| medium | `exe-jq-O1.bc` | larger executable; previously useful for query stress |
| medium | `exe-chibicc-O1.bc` | compiler-shaped control/callgraph structure |
| larger | `lib-sqlite-O1.bc` | larger library; likely useful for component distribution |
| larger | `exe-gifsicle-O1.bc` | image tool with nontrivial global state |
| stress | `exe-curl-O1.bc` or `lib-curl-O1.bc` | larger networking code; use after dashboard smoke |
| stress | `exe-tmux-O1.bc` | larger executable; use after dashboard smoke |

Prefer O1 first because it is closer to expected client usage and avoids optimizing
debug-only overhead. Use O0 only when comparing optimization sensitivity.

## Commands

Build the release CLI before collecting timings:

```bash
LLVM_SYS_140_PREFIX=/home/brk/tenjin/_local/xj-llvm-14 \
LD_LIBRARY_PATH=/home/brk/tenjin/_local/xj-llvm-14/lib \
cargo build --release -p pangs-cli
```

Run lite analysis with the default `andersen` stage and executable build mode:

```bash
LLVM_SYS_140_PREFIX=/home/brk/tenjin/_local/xj-llvm-14 \
LD_LIBRARY_PATH=/home/brk/tenjin/_local/xj-llvm-14/lib \
target/release/pangs analyze \
  /home/brk/pangs-corpus/_out_bc/<input>.bc \
  --build-mode executable \
  --stage andersen \
  --out /tmp/pangs-m3-lite/<input>-andersen \
  --validate
```

Summarize an export directory with the current report command:

```bash
target/release/pangs report /tmp/pangs-m3-lite/<input>-andersen
```

Suggested output naming:

```text
/tmp/pangs-m3-lite/<basename>-andersen/
/tmp/pangs-m3-lite/<basename>-steens/        # optional comparison
/tmp/pangs-m3-lite/<basename>-conservative/  # optional regression floor
```

## Existing Export Data

The current exports already contain the main M3 inputs:

- `metrics.json`: function/global/callgraph counts, icall tier counts, partition sizes,
  oversize fallback counts, mutable-global coverage, and phase timings.
- `components.json`: component members, mutable globals in each component, frozen bit,
  and taint reasons.
- `callgraph.jsonl`: call edges with `kind` and `tier`.
- `globals.jsonl`: mutable/const/stationary/escape/never-written facts.
- `stationarity.jsonl`: B1 InitVal/stationarity verdicts and runtime writers.
- `audit.jsonl`: unsupported/boundary findings that can induce Ω taint.
- `manifest.json`: command options, input hash, and pipeline wall time.

`pangs report` prints the M3 dashboard over existing exports: coverage, icall tier
counts, call-edge tier histograms, oversize fallbacks, audits, stationarity reasons,
component-size histograms, largest frozen components, component taint histograms, and
phase timings. It does not yet identify load-bearing edges inside blocked components.

## Metrics To Record

For each corpus input, record:

- mutable globals rewritable / total;
- component count and p50/p95/max member count;
- largest frozen components by member count and mutable-global count;
- taint reason histogram from `components.json`;
- icall site counts by tier from `metrics.json` and `callgraph.jsonl`;
- unknown-callee and oversize-fallback counts;
- stationarity verdict counts and top runtime-writer reasons;
- audit finding counts by kind/effect;
- wall time and phase timings.

## Diagnosis Rules

Use `DESIGN_lite.md` §6 gates:

- acceptable coverage and component shape: ship lite;
- blockers dominated by allocation-site heap conflation: plan typed heap clones;
- blockers dominated by internal, non-Ω, context-insensitive function-pointer residue:
  consider reviving `PLAN-M3_tierE_upgrade.md`;
- blockers caused by unsupported IR, inline asm, int↔ptr, unknown external boundaries, or
  unknown callers/callees: classify as Ω-frozen rather than precision-recoverable;
- blockers caused by missing provenance or unclear reports: improve reporting before
  changing solver design.

## Next Implementation Slice

Add blocking-edge attribution over existing export files:

- for top frozen components, list incoming/outgoing indirect edges by tier;
- list unknown-callee edges and unknown mod/ref rows that touch the component;
- connect component taints back to audit findings or unknown rows where possible;
- keep this as a reporting-only change unless missing provenance makes that impossible.

This should be a client/export reporting change only. It should not run the experimental
tier-E CFL query prototype and should not change `pangs analyze` behavior.
