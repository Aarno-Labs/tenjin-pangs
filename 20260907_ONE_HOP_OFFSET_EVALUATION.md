# One-hop offset prerequisite: evaluation

Implemented, 2026-09-07; not a promotion decision. This change addresses the base-tier prerequisite for
the asymmetric-overlap endpoint; it does not enable asymmetric overlap.

## Baseline

The frozen pre-change executable is
`/tmp/pangs-stride-final.myu2Gp/pangs-eval` (static PWC implementation, before the
one-hop correction). Current paired artifacts and logs are in
`/tmp/pangs-overlap-20260907.G6uKZW/`. LLVM 14 libraries are supplied through
`LD_LIBRARY_PATH=/home/brk/tenjin/_local/xj-llvm-14/lib`.

With `PANGS_PAG_PWC_LANES=0`, `differential --build-mode executable` reproduces
exactly 32 missing `written_globals`: 1 each in `exe-lemon-O0` and
`exe-lemon-nostatic-O0`, and 15 each in `exe-tree-O0` and `exe-OMP__tree-O0`.
These are the documented prerequisite failures, not acceptable precision losses.

Baseline compact disposition analyses completed for those four modules and
`exe-tmux-O1`, `exe-jq-O1`, `lib-sqlite-O1`, and `exe-vim-9.2-O1`. All use
executable build mode, Andersen stage, `--dispose --manifest-only --validate`,
`--repo-root /home/brk/pangs-corpus --mode application --no-overrides`, and PWC off.
The `lib-sqlite-O1` executable-mode choice matches the stride experiment; a
whole-corpus library-mode check is a separate validation configuration.

## Implementation obligations

Uncertified GEPs subscribe to source pointee classes and replay after class
growth. Field identities and ordinary allocation alternatives survive joins.
An unbound placeholder is not an ordinary summary and must not be equated with
a nonzero shifted result before its producers arrive. A mixed summary/field
class must retain the ordinary alternative **and** explicitly cover each shifted
field root; reusing the old class alone misses the same writes.

Exact shifts use a fixed vocabulary; derived lanes have a finite per-root cap.
Overflow goes to the allocation's Unknown region. Region widths, external/null
content flow, and the carrier/location invariant remain conservative. Cross-root
UF joins are real unification and are not described as independent inclusion sets.

The companion `20260907_ASYMMETRIC_OVERLAP_AUDIT.md` records the downstream C
consumer audit, including whole-object memcpy and certificate obligations.

## First conservative candidate (not promoted)

The first release correction eliminates all 32 known write discrepancies. Its
restored client regression passes for both Steensgaard and Andersen. After adding
effective late-binding, mixed-summary, zero/negative/lane, finite-cycle, and lane-cap
payload tests, the full workspace suite passes (129 solver-library tests).

Naive summary replay caused a severe tmux slowdown: it repeated the allocation
inventory for every GEP subscription. Batching destinations and represented roots
removed that Cartesian product. The batched tmux diagnostic finished in 7.38 s;
Steensgaard's own profile was 466 ms, with 336,550 replayed transfers and 1,265,666
region shifts. These are diagnostic single runs, not repeatable performance claims.

The conservative whole-object interpretation also has avoidable-looking precision
costs. In both Lemon builds, `append_str.empty_xjtr_0` and
`tplt_open.templatename_xjtr_0` move from immutable to localize, with a new write
witness in `Action_add`. Source inspection (`sqlite/tool/lemon.c` lines 621–638,
3766, and 3927, plus the input's lowered `Action_add` at line 1730) shows
`Action_add` mutating action records, not those static character arrays: these
are conservative aliases, not recovered concrete writes. `azDefine_xjtr_0`
was already written and loses localization through `unknown-callee-taint`.
Tmux loses nine immutable option-list dispositions, and SQLite loses two localize
dispositions. No written=true → false transition occurs in these inspected modules.

In the retained candidate, ordinary allocation
address-of objects start at root-relative Exact(0), rather than treating every
nonzero GEP from a known allocation base as a whole-object operation. All GEP paths
must retain persistent shifting, and genuinely unknown arithmetic must still use
Unknown. Merely relabeling a legacy field-insensitive summary Exact(0) is unsound.

## Retained root-relative implementation

Ordinary allocation objects start at Exact(0), with persistent displacement replay.
Per-root Unknown subsumption and an exact nonzero self-cycle shortcut avoid needless
walks through the finite vocabulary. Replay frontiers are invalidated by structural
growth, not content-only changes. A global processed-pair cache was rejected because
it consumed excessive memory. Root-local field inventories replace whole-map scans.

The frozen `pangs-self-cycle` candidate passes the four known defective modules'
differential checks: all 32 missing-write discrepancies are eliminated. Ten focused
one-hop tests pass, including late producers after a drained worklist, mixed summaries,
negative/lane shifts, finite cycles, and a lane-cap test observing an actual late write.
The pointer-ModRef client regression now runs at both Steensgaard and Andersen tiers.

Correctness is not free: diagnostic PWC-off runs of this candidate took 15.53 s on
tmux (Steensgaard 6.35 s, peak RSS 548,084 KiB) and 44.57 s on SQLite (Steensgaard
12.81 s, peak RSS 1,443,416 KiB). These shared-machine single runs are not directly
comparable speedup estimates. Earlier naive replay/cache prototypes were substantially
worse and are not the implementation being retained. Performance remains a promotion
concern; do not attribute prerequisite overhead or gains to asymmetric overlap.

The broader sweep of an earlier summary prototype passed 55 modules, but that is
**not** a completed sweep of the retained implementation. jq O0's `unknown_callers`
mismatch for `match_at` reproduces in the frozen original baseline and the retained
candidate: it is pre-existing. The earlier prototype also exposed a Vim O1
`xdl_call_hunk_func` unknown-callee discrepancy. The retained candidate with PWC on
and asymmetric overlap off now reports 26 Andersen unknown-call additions relative
to Steensgaard (JSON decoding and xdl sites), after 593.84 s. A's earlier baseline
passed Vim: this intervening prerequisite remains under soundness/monotonicity review,
even though it fixes the known writes. See the C evaluation's exact ledger. No
whole-corpus green, default-promotion, or merge-readiness claim is made.
