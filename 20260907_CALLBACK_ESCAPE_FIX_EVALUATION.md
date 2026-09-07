# Allocation escape fix and Vim evaluation

Follow-up: `20260907_VIM_CALLBACK_ADMISSION_INVESTIGATION.md` traces the retained
26 mismatches. All arise at empty-target fallback, not external operand provenance.
An admission control recovers 20 missing callbacks; six remain consistent with
null/unreachable callback paths and the empty-result policy.

2026-09-07. Fixes the republished aggregate callback defect described in
`20260907_CALLBACK_ESCAPE_REPRODUCTION.md`. PWC and asymmetric overlap remain opt-in.

## Change and validation

Steensgaard now records a distinct `allocation_escape` obligation for real escape
boundaries and reachable storage. When such a location class is processed, its
allocation-relative region identities extend the root-wide field escape inventory.
This works without an exact-address certificate and replays after late UF joins.
New fields inherit that inventory, and late field contents inherit the ordinary
external/escape facts through existing one-hop propagation.

The synthetic `esc` bit introduced solely by pushing an external pointer identity
through its pointee does **not** imply this new obligation. Propagating every `esc`
bit to all fields made the independent-local-address control unnecessarily unknown;
that prototype was rejected. The final distinction preserves both that control and
the external-payload-only-in-field-0 control. A real boundary encountered on an
already externally tagged allocation still upgrades the obligation.

Replay is keyed by the monotone count of represented field regions. A surviving UF
class retains its own frontier; a union that introduces new regions changes the
count. The existing root inventory avoids revisiting already-covered fields and
preserves first-witness provenance. No raw field contents are merged by this fix.

`cargo test --workspace --all-targets` passes, including **142 solver tests**. Coverage
includes the seven semantic cases (the original six plus a real boundary on the
mixed external/local pointer), a boundary applied before allocation identity arrives,
a second late allocation root, a late-created field and pointee, and an unrelated
root that remains unaffected. Both PIR and LLVM reproductions now pass differential
checks with C off and on and PWC enabled. The repaired PIR is part of the ordinary
synthetic differential sweep, not an excluded known-failure fixture.

## Vim protocol

Artifacts: `/tmp/pangs-vim-escape-fix.s4jWOX/`, frozen binaries `pangs-before` and
`pangs-final`. `pangs-after` is the initial correct but slower implementation before
skipping redundant provenance accumulation for already-covered roots.
Input: `/home/brk/pangs-corpus/_out_bc/exe-vim-9.2-O1.bc`.
Both configurations use PWC=1, asymmetric overlap=1, default cap 256, executable
mode, Andersen stage, default admission/certificate controls, and LLVM 14.
The paired compact analysis uses `--dispose --manifest-only --validate --repo-root
/home/brk/pangs-corpus --mode application --no-overrides` with separate outputs.
Two before/final pairs use the same shared machine; a separate differential check
overlaps parts of the measurements. Treat timings as diagnostics, not repeatable
speedup estimates. Hash iteration/worklist order also varies across processes.

The post-fix full three-tier differential and stage-specific callback census are
recorded below. Compare exact unknown-callsite keys, target counts,
global facts/witnesses, and dispositions separately; a smaller unknown count alone
is not proof of correctness.

The initial implementation spent 56.179 s in Steensgaard (145.44 s end to end), despite
almost unchanged worklist counts. Re-unioning large provenance sets into roots whose
entire field inventory was already escaped dominated runtime. Checking the existing
root-wide witness first restored Steensgaard to 10.076 s on the first final run,
versus 9.381 s before the fix. This optimization does not change escape/unknown facts;
the initial and final implementations produce identical full Vim global records.

## Callback and client impact

**The 26 Vim mismatches remain.** The initial fix's two stage-specific censuses contain
2,099 sites each, with 206 Steensgaard unknowns and 232 Andersen unknowns. Every census
row is identical to its pre-fix counterpart, including callsite keys, target counts,
unknown/fallback markers, and FSA counts. This is not a target-identity export comparison.
The extra Andersen unknowns are the identical JSON decoding and xdl callsites recorded
in the earlier experiment. Fixing the semantic reproducer therefore does not by itself
resolve Vim's observed failure; the remaining provenance path needs independent diagnosis.

The full three-tier check on the initial correct fix finishes in 618.50 s (exit 3)
with exactly those same 26 `icall_unknown` violations and no other violation category.
The subsequent performance-only root-coverage check avoids redundant provenance
unions, not escape facts; full global records also match the optimized binary. This
is a failed Vim soundness/monotonicity gate, not a claim of a successful differential.

Vim's full global disposition records, including facts and witnesses, are exactly
identical before, initial fix, and optimized fix (canonical SHA-256
`69da63143560ede822cf75e92436c5980fe41709689ee2e78866b9ec3b95ec8a`). No writes,
escapes, dispositions, or witnesses in those records changed. Both paired analyses
report Andersen complete, one unchanged oversize fallback of size 234,236, and 20
Andersen-coarser-than-Steens nodes. Neither experimental flag is promoted.

Executable SHA-256: before
`a69c686f1504a798b4359ba8a1235376dd956394d8412ef80b48a6702709a1d0`, initial fix
`7d89a9df05ab7d54adb64c17856388d2e0694c066376a6ec13e7b22a5218b441`, optimized fix
`cf5572a2092ae9f43650e84429b6b51b2635a5839843e41d0eae501b289fe881`.
Input SHA-256: `d29a9471def3dad7f747b65f74ebfcdf2154212f8407d7a1193574ad6dcd448a`.

## Wall time and memory

| Run | Before wall s | Optimized fix wall s | Before Steens s | Optimized Steens s |
|---|---:|---:|---:|---:|
| First pair | 114.88 | 99.28 | 9.381 | 10.076 |
| Repeat pair | 106.47 | 101.68 | 9.971 | 10.217 |

End-to-end times are lower in these two pairs, but do not establish a speedup: the
Steens phase is slightly slower, and worklist ordering and concurrent shared-machine
load vary. The defensible conclusion is a small observed Steens cost (0.25–0.70 s)
and no observed end-to-end regression. Peak RSS is effectively unchanged: before
6,743,180 / 6,743,020 KiB, optimized 6,742,320 / 6,742,468 KiB (about 6.43 GiB).
The initial unoptimized correction's 145.44 s is not the retained implementation.
