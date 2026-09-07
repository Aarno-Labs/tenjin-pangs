# Asymmetric field overlap: experimental endpoint

2026-09-07. Implemented behind `PANGS_ANDERSEN_ASYMMETRIC_FIELD_OVERLAP=1`
(`true` also enables; unset or `0` disables). Default remains off. Work item C was
developed before A promotion, without relaxing either feature's promotion gates.
The Steensgaard prerequisite is a separate jj change; its correctness and overhead
are recorded in `20260907_ONE_HOP_OFFSET_EVALUATION.md`.

## Implementation and audit

Stores write raw cells. Loads register persistent root-relative reads over directly
overlapping cells, including late-created fields, without transitive overlap closure.
Raw allocation identity survives content SCC canonicalization. Both memcpy algorithms
read sources and write destinations conservatively at whole-object granularity.
Value queries stay raw; certificates use overlap-aware memory reads and boundary
traversal enumerates fields even when the root cell itself has no contents.

Receiver payload summaries union directly overlapping synthetic payload locations
within each receiver root. Their inventory survives propagation-state compaction and
participates in boundary traversal and aggregate global exports. C plus receiver
summaries conservatively retains unknown status and disables completeness certificates:
the full synthetic producer proof is not implemented. This is a precision limitation,
not permission to omit reachable callbacks. The consumer checklist is in
`20260907_ASYMMETRIC_OVERLAP_AUDIT.md`.

Regression coverage includes sibling isolation, late reads, root/Unknown writes,
unrelated roots, lane/exact reads both ways, SCC destination remapping, both memcpy
algorithms with exact endpoints and late source fields, exported-field callbacks,
external containers, and receiver payload global export with root isolation.
Existing receiver and closed-consumer tests retain their off-mode assertions as well.
All 139 solver-library tests pass. `cargo test --workspace --all-targets` passes.
Disposition metadata
records the effective C flag, and its golden change was checked to be metadata-only;
the normal manifest schema also accepts the explicit flag.

The two LLVM runtime indirect-call trace tests and the synthetic differential suite
also pass with both experimental flags enabled. Normal manifest smoke runs with C=0
and C=1 validate successfully and report `asymmetric_field_overlap_enabled` false and
true respectively.

Final certificate review added an exact-endpoint memcpy regression and aligned both
producer incompleteness and consumer audits with C's allocation-root copy projection,
including the missing-metadata fail-open path. This optional-certificate correction
postdates the frozen timing executable; the paired corpus commands leave both
certificate options off, so their executed semantics are unchanged. It is covered by
the final source test suite rather than retroactively claimed as frozen-binary coverage.

## Paired experiment

Frozen executable: `/tmp/pangs-overlap-20260907.G6uKZW/pangs-c-eval`.
Logs and compact manifests are in the same directory, named `<module>.c0` / `.c1`.
Both sides use the corrected Steensgaard implementation, PWC lanes **on**, lane cap
256, executable mode, Andersen stage, and otherwise default solver options.
The analyze command uses `--dispose --manifest-only --validate --repo-root
/home/brk/pangs-corpus --mode application --no-overrides` and writes separate outputs.
Inputs are `/home/brk/pangs-corpus/_out_bc/{module}.bc`.
LLVM 14 libraries are supplied through
`LD_LIBRARY_PATH=/home/brk/tenjin/_local/xj-llvm-14/lib`.

SHA-256: executable `581c1744e0b61f1df88f62c1bf048bfa019a49a33f94ea2841e1cce86454924a`;
tmux `bbf31503609213a2dd908dc880032c673f1b165739681f2dc3d741551ab80d64`;
jq `218daa6fab58e4e553b55de450bad9b597bfe2c23f765559540bd7338a03ccfa`;
SQLite `159d8b4cc4cf72705b6b2c44f2d27c7c9fcdeec39a475961cde411cfb38caa87`;
Vim `d29a9471def3dad7f747b65f74ebfcdf2154212f8407d7a1193574ad6dcd448a`.

Wall times below are single runs on a shared machine. The differential sweep overlaps
part of the timing sweep, so these are diagnostic observations, **not controlled
speedup estimates**. No timing claim should combine this experiment with A's older
baseline, which lacks the one-hop correction.

| Module | Wall seconds off → on | Peak RSS KiB off → on | Andersen steps off → on | Copy fact pairs off → on |
|---|---:|---:|---:|---:|
| tmux O1 | 9.64 → 8.89 | 548,028 → 548,824 | 114,450 → 28,626 | 220,961 → 9,493 |
| jq O1 | 1.11 → 0.82 | 147,608 → 147,504 | 123,179 → 17,040 | 229,814 → 9,640 |
| SQLite O1 | 18.02 → 19.87 | 1,443,936 → 1,443,768 | 16,974 → 16,325 | 3,236 → 1,804 |
| Vim O1 | 150.56 → 120.92 | 6,742,576 → 6,742,500 | 162,920 → 242,050 | 74,812 → 54,235 |

| Module, C enabled | Read dependencies | Installed overlap pairs | Late replay pairs | Live index entries | Estimated index capacity bytes |
|---|---:|---:|---:|---:|---:|
| tmux O1 | 102 | 2,802 | 14 | 102 | 8,320 |
| jq O1 | 66 | 259 | 15 | 66 | 4,608 |
| SQLite O1 | 277 | 1,204 | 7 | 277 | 17,024 |
| Vim O1 | 3,546 | 32,380 | 101 | 3,545 | 216,064 |

The capacity estimate covers the read-index containers, not total allocator overhead
or the resulting copy graph. Counts are recorded before propagation-state release.
Vim's cumulative dependency count exceeds its live entries by one because read
destinations are deduplicated after SCC remapping. Its measured solver time rises
slightly (37.029 → 37.910 s), while solver postprocessing falls (7.252 → 1.440 s).
The overall wall reduction therefore must not be described as a solver speedup.

All eight analyses report `andersen_complete=true`. Each retains one oversize
fallback; its maximum size is unchanged within each pair: tmux 35,786, jq 24,236,
SQLite 94,341, Vim 234,236. The Andersen-coarser-than-Steens diagnostic is zero on
the first three and 20 on Vim in both modes. Completion does not mean those fallback
partitions were refined. No lane-cap collapse occurs in any paired run.

| Module | Points-to facts off → on | Copy edges off → on | Fields off → on | GEP pairs off → on |
|---|---:|---:|---:|---:|
| tmux O1 | 34,841 → 25,916 | 8,323 → 9,927 | 8,604 → 8,604 | 533 → 466 |
| jq O1 | 133,797 → 23,739 | 6,962 → 5,107 | 2,727 → 2,727 | 8,791 → 8,791 |
| SQLite O1 | 15,768 → 15,054 | 15,578 → 14,979 | 5,706 → 5,706 | 414 → 414 |
| Vim O1 | 117,373 → 97,790 | 27,741 → 54,915 | 41,519 → 40,905 | 2,182 → 2,543 |

Unknown fields are unchanged (325, 47, 84, 532 respectively). Exact/lane chained
derivations are tmux 9/3 → 6/2, jq 1,688/1,742 unchanged, SQLite 48/188 unchanged,
and Vim 54/449 → 79/840. Derived lanes admitted are 57, 137, 338, and 1,695 → 1,081;
maximum per-root occupancy is 3, 5, 5, and 15 respectively, unchanged within pairs.

## Correctness ledger and promotion

For tmux, jq, and SQLite, full disposition global records (including facts and
witnesses), synthetic/unkeyed globals, coupling groups, and override reports match
exactly across off/on. Run metadata differs as intended. Disposition equality alone
does not establish callgraph or callback equivalence.

Separate ordinary validated exports for those three modules also match as canonical
JSON objects in `callgraph.jsonl`, `modref.jsonl`, `globals.jsonl`, `audit.jsonl`,
`stationarity.jsonl`, and `functions.jsonl`: this checks actual target identities and
witnesses in both directions, not merely histogram or count equality. The paired
icall censuses separately match target counts and unknown/fallback status at all 57
tmux, 10 jq, and 2,266 SQLite sites.

All six off/on tier-differential cases for those modules pass. The four known one-hop
defect modules (Lemon, Lemon-nostatic, tree, OMPtree) also pass in both C configurations
with PWC enabled, providing eight additional checks of the retained prerequisite.

Vim's full disposition global records and all supporting sections likewise match
exactly (streamed one 1.1 GiB manifest at a time). Full Vim callgraph/ModRef identity
exports were not repeated; this remains a promotion gate, not evidence inferred from
disposition equality. The current Vim tier-differential result is recorded below.
A full retained-candidate 59-module sweep, controlled repeated
timing, and the receiver completeness proof remain outside the completed gates.
Neither A nor C is promoted on the strength of smaller solver sets alone.

**Current blocker:** Vim C=0's full differential finishes in 593.84 s (exit 3), with
26 `icall_unknown` additions at Andersen relative to Steensgaard: JSON decoding sites
plus `xdl_call_hunk_func`, `xdl_emit_diffrec`, and `xdl_emit_hunk_hdr`. It reports no
other violation category. This is present with asymmetric overlap disabled; it cannot
be attributed to C. The old summary prototype's single xdl discrepancy must not be
substituted for this retained-candidate result. A's earlier frozen baseline passed Vim,
so the intervening prerequisite requires investigation rather than a claim that the
entire discrepancy was already present in that baseline.

The redundant full C=1 three-tier run was stopped after the C=0 failure; a targeted
Steens/Andersen C=1 census checks the exact unknown-call markers without redoing the
expensive conservative tier. This is not a completed C=1 full differential pass.
The targeted C=1 comparison finishes with 2,099 sites per stage and reproduces
**the identical 26 added unknown-callsite keys** from the C=0 full differential.
Thus the observed marker discrepancy persists in both modes; C does not fix it.
Do not suppress Andersen's unknown marker merely to satisfy the lattice check:
`operand_unknown` records reachable external function-pointer-capable regions. The
external-flow parity between the two solvers remains a soundness/monotonicity gate.

Next investigation: reproduce one affected callback with a semantic fixture that
distinguishes an escaped aggregate, an external pointer stored in just one field,
and an external allocation-location identity followed by a shifted load. Existing
escape closure already covers fields and late pointees. A raw `set_ext(Exact0)`
assertion is not proof of a whole-allocation boundary and was not retained as a test.
Loss of a storage-identity external envelope during shifting is a hypothesis, not
the established cause of the 26 corpus discrepancies; no blanket sibling `ext`
propagation was applied.

Follow-up: `20260907_CALLBACK_ESCAPE_REPRODUCTION.md` now gives a semantic reproducer
and controls. Publishing the aggregate address through memory defeats the exact-address
escape hook: the owner escapes but its field-8 callback does not. This confirms a
specific missing allocation escape envelope, not blanket sibling `ext` propagation,
and has not yet been traced to all 26 Vim sites. No fix is included with the reproducer.
