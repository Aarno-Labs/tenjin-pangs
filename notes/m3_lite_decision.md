# M3 Lite Decision

Date: 2026-06-16

## Decision

Freeze lite M3 as the default path. Do not revive tier-E/CFL for the default `analyze`
pipeline.

The M3 result is:

- runtime is viable on smoke/medium rows and one tmux-sized row;
- the remaining coverage losses are dominated by modeling/audit envelopes, not a clear
  context-sensitive query need;
- large JSONL export remains a known scale caveat, especially `modref.jsonl` on tmux-sized
  programs.

## Evidence

Measurements are recorded in `notes/m3_lite_measurements.md`. The current decision table uses
the lite `--stage andersen` pipeline after three fixes landed during M3:

1. transitive mod/ref closure deduplicates by semantic mod/ref fact instead of witness
   instance;
2. local mod/ref export deduplicates by `(func, global, access, via)` while retaining a
   representative witness;
3. Andersen nested-GEP handling uses a finite root-relative offset vocabulary, avoiding
   unbounded synthetic field chains while preserving known nested constant offsets.

Representative runtime rows:

| input | wall s | analysis s | solve s | transitive modref s | modref rows | mutable rewritable |
|---|---:|---:|---:|---:|---:|---:|
| `lib-parson-O1` | 0.03 | 0.01 | 0.00 | 0.000 | 290 | 4/5 |
| `exe-jq-O1` | 3.60 | 2.51 | 0.22 | 0.035 | 60,238 | 5/14 |
| `exe-gifsicle-O1` | 1.55 | 1.11 | 0.18 | 0.027 | 21,760 | 1/93 |
| `exe-lua-O1` | 5.62 | 4.02 | 0.42 | 0.038 | 106,899 | 0/5 |
| `exe-curl-O1` | 3.79 | 2.59 | 0.21 | 0.022 | 76,530 | 16/80 |
| `exe-tmux-O1` | 59.43 | 42.61 | 2.73 | 0.356 | 1,221,727 | 0/107 |

`exe-tmux-O1` is the strongest scaling warning. It now completes after the finite-field fix,
and the solver is not the dominant cost, but export/analysis around a 190M mod/ref JSONL file
is still expensive.

## Blocker Read

The largest frozen components are dominated by:

- unknown globals and unknown mod/ref facts;
- vararg function-pointer audit taints;
- ptrtoint/inttoptr audit taints;
- inline asm and setjmp/longjmp where present;
- broad Steensgaard fallback partitions on some rows.

The table does not justify tier-E as the next default investment. `exe-gifsicle-O1` has the
strongest unknown-icall residue, but it is still mixed with unknown-global/modref and audit
taints. `jq`, `chibicc`, and `curl` have small unknown-icall residue relative to their frozen
component blockers.

## Caveats

M3 should not claim broad large-module scaling. The current evidence supports smoke/medium
rows plus one tmux-sized row. Large modules may still expose expensive export or mod/ref
surfaces.

The JSONL artifacts are useful for auditability, but client integrations are expected to use
in-memory results where possible. Export-size reduction is therefore not an M3 blocker, but it
is a clear follow-up if large exported artifacts become part of normal client workflows.

## Follow-Up

The next milestone should not begin by reviving tier-E. Better candidates are:

- modeling/audit improvements for unknown globals, varargs, pointer-int punning, inline asm,
  and setjmp/longjmp;
- export ergonomics or summarized mod/ref output if JSONL artifacts become a client-facing
  hot path;
- one additional sqlite-sized measurement only if a broader large-module scaling claim is
  needed.
