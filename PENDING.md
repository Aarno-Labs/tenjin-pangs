Pending Ideas/Tasks

# Performance/Precision Tuning

########################################

## promote asymmetric field overlap with per-read hubs

### Decision to make

Determine whether `PANGS_ANDERSEN_ASYMMETRIC_FIELD_OVERLAP` should become default-on while
retaining `PANGS_ANDERSEN_ASYMMETRIC_FIELD_OVERLAP=0` as a documented rollback and ablation.
This plan evaluates the current contents-only implementation, including one propagation-only hub
per persistent `(allocation root, read location)`. It does not evaluate removing the opt-out or
claim that asymmetric overlap fixes Steensgaard megapartitions; the feature changes only
Andersen's interpretation of field contents.

With the feature enabled, stores continue to write one raw cell. A load reads the union of cells
that directly overlap its addressed location. Every overlapping source feeds the location hub
once, every read destination receives from the hub once, and a field created after the read adds
one source-to-hub edge. The hub is propagation-only and must never become an allocation identity
or a member of a points-to set. Memcpy remains conservatively whole-object.

### Evidence already available

The following results may be reused only if their binary and input hashes still match the
candidate being promoted. Otherwise rerun the corresponding gate.

- `ju_out/asymmetric_overlap_reevaluation_20260908/REPORT.md` compares C=0/C=1 on 57 primary
  modules with PWC lanes enabled. Fifty-three modules are identical in all seven exported
  families. Only figlet O0, jpegoptim O0/O1, and Speex O0 change. Their changes are confined to
  ModRef and derived component taints, introduce no access identity, preserve final indirect-call
  semantics, and have source-level explanations consistent with removing sibling-field
  contamination.
- `ju_out/per_read_overlap_hubs_20260908/REPORT.md` shows that the hub candidate is byte-identical
  to the prior C=1 implementation in `functions.jsonl`, `globals.jsonl`, `callgraph.jsonl`,
  `modref.jsonl`, `stationarity.jsonl`, `audit.jsonl`, and `components.json` on all 57 primary
  modules. Relative to the direct-fanout C=1 implementation, aggregate copy edges fall 48.4%,
  copy-fact pairs 50.0%, physical overlap edges 66.1%, and late replay edges 82.8%.
- Five-pair hub timings turn the former direct-fanout regressions into improvements: mbedx509
  wall/solver fall 17.0%/26.6%, Cairo 9.2%/12.1%, and SurpriseTalk wall falls 9.1%. SQLite is
  neutral. Vim is also best classified as neutral, but its five-pair run overlapped a background
  OpenSSL analysis and should be repeated cleanly.
- Hub points-to facts rise 28.0% in aggregate, concentrated in mbedx509 and SurpriseTalk. Observed
  RSS rises 5.3% on mbedx509 and is flat on Cairo, SQLite, and Vim. This is a retained resource
  risk to measure, not a semantic failure.
- The hub candidate's OpenSSL disposition run validates and finishes in 16m29s at 18,759,672 KiB
  peak RSS. Its three-tier differential finishes in 32m50s at 21,270,132 KiB and passes. Results
  are in `ju_out/per_read_overlap_hubs_20260908/openssl-supplement/`.
- The older debug-Vim C=1 disposition exit 2 was `No space left on device`, not an analysis or
  validation failure. Its icall census and differential passed. Debug Vim has not yet received
  the complete hub-candidate supplement below.
- The full workspace suite, feature fixtures, synthetic differential tests, and two instrumented
  LLVM indirect-call tests pass. The old globally-forced C=1 workspace run had one CLI test that
  hard-coded disabled effective-setting metadata; that expectation must change during the
  default-on rehearsal.

### Freeze the experiment

1. Start from a clean jj commit containing the per-read hubs. Build one release executable in an
   isolated target directory and copy or otherwise freeze it for the entire experiment. Record:

   - jj commit and change IDs;
   - executable SHA-256;
   - `rustc`, Cargo, and LLVM versions;
   - input SHA-256 for every bitcode module;
   - hostname, CPU affinity, date, and effective environment settings.

2. Use `/home/brk/pangs-corpus/_out_bc` as the corpus. The primary set is the same 57 modules used
   by the 2026-09-08 reevaluation: exclude `exe-vim-9.2-g-O1.bc` and
   `lib-openssl-4.1.0-O1.bc`, then run those two as the large-module supplement. Save the exact
   sorted module list in the result directory.

3. Hold every non-C choice fixed in the primary comparison:

   ```text
   PANGS_PAG_PWC_LANES=1
   PANGS_ANDERSEN_PWC_LANE_CAP=256
   --integer-pointer-policy=conservative
   receiver payload summaries unset
   closed-producer and closed-consumer certificates unset
   ```

   Compare explicit `PANGS_ANDERSEN_ASYMMETRIC_FIELD_OVERLAP=0` and `=1`; never use an unset
   value for this portion. Supply LLVM 14 through
   `LD_LIBRARY_PATH=/home/brk/tenjin/_local/xj-llvm-14/lib` when required. Select executable or
   library build mode from the artifact under test.

4. Preflight at least 30 GiB of free space. Keep compact ledgers, logs, metrics, fingerprints, and
   explained row diffs permanently. Full Vim/OpenSSL exports are regenerable and should be deleted
   after their hashes and comparison results are durable. Never run timing samples concurrently
   with another PANGS analysis.

### Gate 1: current-candidate semantic and soundness closure

For every primary module and both explicit C values, run a validated full Andersen export with
profiling enabled. The command shape is:

```text
PANGS_PAG_PWC_LANES=1
PANGS_ANDERSEN_PWC_LANE_CAP=256
PANGS_ANDERSEN_ASYMMETRIC_FIELD_OVERLAP=<0-or-1>
PANGS_ANDERSEN_PROFILE=1
PANGS_MEMORY_PROFILE=1
target/release/pangs analyze <module.bc> --out <arm-directory> \
  --stage andersen --build-mode <executable-or-library> \
  --integer-pointer-policy conservative --validate
```

Collect exact canonical hashes and row counts for `functions.jsonl`, `globals.jsonl`,
`callgraph.jsonl`, `modref.jsonl`, `stationarity.jsonl`, `audit.jsonl`, and `components.json`.
Also collect an icall census for each arm and compare target identities, `unknown_callee`, and
fallback status—not merely target counts.

For every off/on difference:

- classify added and removed access identities, named globals, unknown rows, call targets,
  writes, escapes, component taints, and dispositions;
- inspect the source/LLVM and the emitted witnesses for every removed real write, callback, or
  target;
- reject an unexplained narrowing; a smaller answer is not by itself soundness evidence;
- confirm Steensgaard partition count, largest partition, oversize-fallback count and maximum,
  and lane-cap behavior are invariant. These are controls, not expected benefits.

Run `pangs differential` under both explicit C values on all 57 modules. The candidate passes
only if it introduces no new differential category or row. The known jq O0 and FLAC O1 failures
may be waived only if C=0 and C=1 reproduce exactly the same rows and evidence; record them as
pre-existing base-tier issues rather than silently treating the sweep as passing.

Run the compact validated disposition export, icall census, and C=1 three-tier differential on
debug Vim with the hub binary. OpenSSL's completed hub results may satisfy its correctness and
resource gate if the hashes match; otherwise rerun OpenSSL asynchronously with a two-hour limit
per command. OpenSSL should not delay analysis of the primary results, but it must finish before
the default is merged.

Finally run:

```text
cargo test --workspace --all-targets
PANGS_ANDERSEN_ASYMMETRIC_FIELD_OVERLAP=1 \
  cargo test -p pangs-cli --test pipeline dynamic_
```

All feature fixtures must continue to cover sibling isolation, both creation orders, pending and
established loads, exact/lane overlap in both directions, Unknown/root writes, unrelated roots,
late fields, SCC-remapped destinations, both memcpy implementations, external containers, and
receiver payload root isolation.

### Gate 2: interaction and certificate closure

Rerun the four semantic-change modules—figlet O0, jpegoptim O0/O1, and Speex O0—with the hub
candidate in paired C=0/C=1 configurations under each of:

1. PWC disabled;
2. PWC enabled with `--integer-pointer-policy=assume-tags`;
3. PWC enabled with receiver payload summaries plus closed-producer and closed-consumer
   certificates.

Require validation, differential success relative to the recorded baseline, exact disposition
comparison, icall identity comparison, and the same explained semantic delta as the primary run.
This rerun is necessary because the previous interaction matrix used the direct-fanout C=1
implementation.

There is also one independent promotion blocker: when C and receiver payload summaries are both
enabled, completeness certificates are currently disabled because the overlap-aware synthetic
producer proof is unfinished. Resolve it in one of two explicit ways:

- implement the producer/completeness proof, add negative and positive fixtures, and run the
  receiver/certificate configuration across the primary corpus; or
- run that configuration across the primary corpus, quantify every lost certificate and changed
  disposition, and record a deliberate decision that the default may reduce precision for users
  of the receiver experiment.

Do not infer safety from the four changed modules alone. Positive callback reachability and
unchanged aggregate exports do not prove that a completeness certificate remains valid.

### Gate 3: clean performance and resource measurements

Use compact validated disposition manifests so export I/O does not dominate the solver. For each
arm, discard one warm-up, then run five measured repetitions with alternating order and fixed CPU
affinity. No other PANGS job may run during the set. Measure:

- wall, user, system, and solver time;
- peak RSS and phase high-water marks;
- steps, points-to facts, copy edges, and copy-fact pairs;
- load, store, GEP, and memcpy pairs;
- fields and unknown fields;
- overlap hubs, source edges, destination edges, physical overlap edges, late replay edges, index
  roots/entries, and estimated index capacity;
- lane admissions, maximum lanes per root, cap hits, oversize fallbacks, and maximum fallback.

The required workloads are mbedx509 O1, Cairo O1, SurpriseTalk O0, SQLite O1, and regular Vim O1.
They cover the hub-storage outlier, former fanout outliers, the SQLite neutral case, and the large
Vim case. Add any new whole-corpus outlier with at least a 2x step/copy-work increase or a 10% RSS
increase.

Use medians and retain every sample. A stable wall-time regression of 5% or more, an RSS regression
of 10% or more, or a new pathological work outlier blocks promotion pending explanation and a
repeat. Small sub-second workloads need an absolute-time/noise analysis rather than a percentage
alone. The 28% aggregate hub-fact increase is acceptable only if the per-module RSS and completion
envelopes remain bounded.

Run one clean adjacent or alternating C=0/C=1 compact OpenSSL pair asynchronously. Five OpenSSL
repetitions are not required, but record its wall time, solver time, peak RSS, hub/work counters,
and completion. Compare it with the already observed hub C=1 envelope of 16m29s and 18.76 GiB;
investigate a material regression rather than averaging it into the smaller corpus.

### Gate 4: rehearse the actual default

On a separate candidate commit, change the API and CLI default to enabled and update the effective
setting metadata and manifest goldens. Then prove all three configuration paths:

- unset/default output is byte-identical to explicit C=1;
- explicit environment `=0` is byte-identical to the frozen C=0 arm;
- explicit API `false` remains honored when there is no environment override.

Run `cargo test --workspace --all-targets` with no override, plus focused CLI pipeline and manifest
validation with unset, `=0`, and `=1`. Inspect every golden change; the effective setting is the
only metadata change expected solely from flipping the default. Repeat a small representative
export set containing one unchanged module and all four semantic-change modules to ensure the
default route does not differ from the explicitly enabled route.

### Promotion rule and deliverables

Promote only if all four gates close:

- every analysis completes and validates;
- there is no unexplained lost write, callback, target, or access identity;
- current-candidate differential results add no failure beyond exactly reproduced and explicitly
  waived baseline issues;
- the receiver/certificate limitation is fixed or its measured client impact is explicitly
  accepted;
- controlled timing and memory remain within the stated thresholds;
- unset defaults, explicit enablement, and explicit disablement produce the intended identical
  pairs; and
- the workspace, feature, interaction, trace, and manifest suites pass.

Write a durable `ju_out/<date>-asymmetric-overlap-promotion/REPORT.md` containing the frozen
protocol, hashes, completion ledger, exact semantic diffs, differential waivers, interaction and
certificate results, all timing samples, aggregate and per-module work/RSS tables, and the final
go/no-go decision. If promoted, update `DESIGN_lite.md` and `EXPERIMENT_HISTORY.md`, but keep and
document `PANGS_ANDERSEN_ASYMMETRIC_FIELD_OVERLAP=0` for at least one release cycle. Removing the
knob is a later decision requiring soak evidence; it is not part of this evaluation.

########################################

## evaluate source-closed SCC admission for globals and modref queries

########################################

## potential mid-tier designs

  More generally, for:

  *p = x;
  y = *q;

  propagating g’s provenance from x to y requires a conservative answer about whether p and q can address overlapping storage. Those
  pointers may derive from stack or heap allocations unrelated to g.

  This creates three possibilities:

  - Use the Steensgaard memory envelope: cheap and conservative, but potentially inherit the same contamination.
  - Solve all supporting address identities precisely: potentially recreate Andersen’s expensive closure.
  - Refine only the supporting memory relationships encountered by selected queries: the promising compromise.

  So I would qualify “avoids solving unrelated allocation identities” as avoids solving identities outside the query’s dependency closure.
  Supporting container identities can become relevant even though they are not disposition subjects.

  There is precedent for budgeted demand refinement with conservative fallback in SUPA. But SUPA constructs its supporting value-flow
  graph using an Andersen pre-analysis; its results do not establish that building an adequate graph from SQLite’s Steensgaard envelope
  will be cheap.

  My assessment of the proposed variants is:

   Variant                             Perspective
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Allocation-origin-only inclusion    Useful coarser domain, but solving it exhaustively can still incur dense memory joins.
  ──────────────────────────────────  ────────────────────────────────────────────────────────────────────────────────────────────────────
   Named-global provenance             Best fit for disposition’s output domain; needs supporting memory identities and explicit
                                       unknowns.
  ──────────────────────────────────  ────────────────────────────────────────────────────────────────────────────────────────────────────
   Small sets with overflow            Useful resource control. A small universal cap may send the dominant alternatives straight back to
                                       Steensgaard.
  ──────────────────────────────────  ────────────────────────────────────────────────────────────────────────────────────────────────────
   Demand-driven CFL                   A possible engine for the hard memory dependencies. Its implementation and proof burden make it a
                                       later step.
  ──────────────────────────────────  ────────────────────────────────────────────────────────────────────────────────────────────────────
   Bounded per-origin propagation      Best initial experiment, with shared graph construction and cached supporting queries.

  These are complementary choices about representation, scheduling, and resource limits; they do not automatically form a strict precision
  hierarchy between Steensgaard and Andersen.

  The negative-answer contract matters more than the set representation.

  I would give each query three outcomes:

  - Excluded: a completed conservative proof rules out the queried effect.
  - May: the abstraction admits the effect; retain it. This need not imply a feasible runtime execution.
  - Incomplete: a budget, unsupported transfer, or unresolved dependency prevents exclusion; retain the baseline answer.

  An unfinished ascending computation cannot supply an exclusion merely because it has not yet discovered g.

  “Only that global falls back” is achievable when proofs are independently scoped. If several globals share an incomplete summary, every
  query depending on that uncertainty must account for it. Independent completed proofs can survive; dependent partial results cannot.

  The proof must cover relevant indirect-call bindings, aggregate copies, captured pointers in escaping containers, external contracts,
  and integer-forged flows. Starting from the original PAG and named allocations is essential: reconstructing provenance solely from the
  unified megroot has already lost the distinctions being sought.

  Disposition needs more than the three headline booleans.

  The strongest first payoff is probably proving some globals both unwritten and unescaped, which can unlock immutable.

  For the other strategies, DISPOSITION.md:60 requires more:

  - once-lock needs writer/read information and publication reasoning.
  - atomic no longer depends on this proof: it reflects an atomic declaration created by
    the upstream source-to-source transform.
  - mutex additionally needs call-graph reentrancy checks.
  - localize still needs sound rewrite-boundary and call-graph information.

  Also, “can a runtime value reach g’s storage?” should usually be formulated as can a runtime write target g? A constant store counts as
  mutation, and pointer provenance in g’s contents is different from provenance of &g.

  Consequently, I would collect relevant access-site identities alongside the booleans. That allows completed queries to remove false
  (access site, global) associations from ModRef, rather than merely improving an isolated escape flag.

  A disposition-focused pass may deliver useful gains while leaving the 602,949-edge callgraph coarse. Reducing that graph requires
  additional function-target or boundary proofs.

  I would structure the first experiment as follows.

  1. Select globals whose disposition failures are attributable to coarse escape or access attribution, prioritizing those with few other
     blockers.

  2. Reuse the existing isolation graph and root certificates. Add demand refinement at ambiguous memory transfers, with shared indexes
     rather than eager store–load Cartesian expansion.

  3. Retain root identity, summarize offsets conservatively, and preserve field distinctions only where needed to separate supporting
     memory flows.

  4. Bound preprocessing, query work, and total work. Materialize completed per-global effect summaries before client fact assembly,
     preserving disposition as a deterministic consumer.

  5. Validate against complete solves on tractable inputs and inject exhaustion during dependency discovery and propagation. Every
     interrupted proof must retain its baseline effects.

  The go/no-go measurement should be newly certified facts and improved dispositions per unit of total analysis cost, together with
  completion and fallback rates. Smaller internal sets or fewer replay operations would be supporting evidence.

  This is worth pursuing because it can recover useful facts without splitting the megroot itself. Its decisive test is whether the memory
  dependencies behind blocked SQLite globals are substantially smaller—or easier to summarize—than the closure that defeated Andersen.

########################################

## offline constraint graph simplification for Andersen speedup

The opt-in quotient ( `PANGS_ANDERSEN_OFFLINE_QUOTIENT=1` )  now implements four exact transformations:

  1. Early static copy-SCC collapse.
  2. Single-predecessor substitution for protected-safe, unseeded variables.
  3. Hash-consing generator-free variables with literally identical predecessor equations.
  4. Exact profitable fanout factoring through non-pointee synthetic union cells.

TODO: whole-corpus evaluation

########################################

## update precision/disposition coverage/timing snapshot

codex resume 01a04f61-54b9-7f01-b6bb-f473df290b14

• Completed all 448 requested executions: 56 corpus modules × 8 revisions, with a 900-second per-module timeout and a 42 GB cgroup memory limit.

  For an apples-to-apples comparison, these tables use the 53 modules that completed on every revision.

  ### Analysis precision

  Lower counts generally indicate better precision, although soundness fixes can deliberately add edges.

   Revision    Call edges    External-caller edges    Logical ModRef    ModuleWide
  ━━━━━━━━━━  ━━━━━━━━━━━━  ━━━━━━━━━━━━━━━━━━━━━━━  ━━━━━━━━━━━━━━━━  ━━━━━━━━━━━━
   oqtpm        1,070,769                   14,282           306,315        10,252
  ──────────  ────────────  ───────────────────────  ────────────────  ────────────
   upywv        1,066,324                   14,282           283,976        10,288
  ──────────  ────────────  ───────────────────────  ────────────────  ────────────
   rwtsu          305,578                   12,107           251,554         8,418
  ──────────  ────────────  ───────────────────────  ────────────────  ────────────
   umtxk          353,431                   12,300           241,743         7,743
  ──────────  ────────────  ───────────────────────  ────────────────  ────────────
   mrtoo          353,423                   12,300           241,629         7,743
  ──────────  ────────────  ───────────────────────  ────────────────  ────────────
   lsswv          416,316                   12,328           269,640         9,755
  ──────────  ────────────  ───────────────────────  ────────────────  ────────────
   vpxsw          410,966                   12,188           337,159       311,882
  ──────────  ────────────  ───────────────────────  ────────────────  ────────────
   nqtnw          411,361                   12,580           337,159       311,152

  rwtsu has the smallest call graph, while mrtoo has the smallest logical ModRef relation. The large ModuleWide increase appears between lsswv and vpxsw.

  Relative to vpxsw, nqtnw:

  - Restores 392 net external-caller edges.
  - Converts 730 ModRef rows from ModuleWide to finite scope.
  - Does not change the logical ModRef set.
  - Does not change any disposition decision.

  ### Disposition coverage

   Revision          Handled    Coverage
  ━━━━━━━━━━  ━━━━━━━━━━━━━━━  ━━━━━━━━━━
   oqtpm         722 / 2,064      34.98%
  ──────────  ───────────────  ──────────
   upywv         997 / 2,064      48.30%
  ──────────  ───────────────  ──────────
   rwtsu       1,223 / 2,064      59.25%
  ──────────  ───────────────  ──────────
   umtxk       1,077 / 1,795      60.00%
  ──────────  ───────────────  ──────────
   mrtoo       1,011 / 1,795      56.32%
  ──────────  ───────────────  ──────────
   lsswv         717 / 1,795      39.94%
  ──────────  ───────────────  ──────────
   vpxsw         566 / 1,795      31.53%
  ──────────  ───────────────  ──────────
   nqtnw         566 / 1,795      31.53%

  The disposition universe changes between rwtsu and umtxk, so counts should accompany percentage comparisons across that boundary.

  ### Performance

   Revision    Wall sum    Paired wall geo-ratio vs oqtpm    RSS geo-ratio    Largest common-module RSS
  ━━━━━━━━━━  ━━━━━━━━━━  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  ━━━━━━━━━━━━━━━  ━━━━━━━━━━━━━━━━━━━━━━━━━━━
   oqtpm       184.32 s                            1.000×           1.000×                   2033.7 MiB
  ──────────  ──────────  ────────────────────────────────  ───────────────  ───────────────────────────
   upywv       150.70 s                            0.934×           0.998×                   1926.6 MiB
  ──────────  ──────────  ────────────────────────────────  ───────────────  ───────────────────────────
   rwtsu       217.14 s                            1.138×           0.939×                    915.3 MiB
  ──────────  ──────────  ────────────────────────────────  ───────────────  ───────────────────────────
   umtxk       277.15 s                            1.305×           0.956×                    955.8 MiB
  ──────────  ──────────  ────────────────────────────────  ───────────────  ───────────────────────────
   mrtoo       272.52 s                            1.275×           0.945×                    954.9 MiB
  ──────────  ──────────  ────────────────────────────────  ───────────────  ───────────────────────────
   lsswv       370.79 s                            1.551×           1.164×                   3042.2 MiB
  ──────────  ──────────  ────────────────────────────────  ───────────────  ───────────────────────────
   vpxsw       257.42 s                            1.362×           1.166×                   1529.9 MiB
  ──────────  ──────────  ────────────────────────────────  ───────────────  ───────────────────────────
   nqtnw       255.53 s                            1.358×           1.165×                   1531.1 MiB

  nqtnw shows no measurable regression against vpxsw: wall sum improved 0.7%, paired RSS was effectively unchanged, and libplacebo improved from 43.82 s to 41.90 s.

  Completion caveats:

  - OpenSSL completed on oqtpm and upywv; all later revisions hit 900 seconds.
  - Both Vim artifacts fail validation on vpxsw and nqtnw with the same Andersen/Steensgaard ModRef-envelope assertion.
  - No run hit the 42 GB limit. Maximum observed RSS was 20.70 GiB for OpenSSL on upywv.

  Full tables and per-module results:

  - /tmp/pangs-multirev-corpus/SUMMARY.md
  - /tmp/pangs-multirev-corpus/summary.json
  - /tmp/pangs-multirev-corpus/corpus-results.json

  The release binaries, analysis exports, and temporary jj workspaces were removed; retained results occupy 7.7 MB instead of 151 MB. The main working copy remains
  unchanged.


## `PANGS_POINTER_MODREF_HIGH_FANOUT_LIMIT`

what does it buy, what does it cost?

see also `ju_out/separate_storage_identity_sqlite_20260826/`

## Forced Andersen costs

from `codex resume 019fa467-f7e4-7010-b463-465971a8408f`:

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
