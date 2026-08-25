# External-policy Phase-0 census

Date: 2026-08-24

Status: measured; the external-principal policy fails the Phase-0 stop gate

This is the pre-implementation census required by
[`20260824_EXTERNAL_POLICY.md`](20260824_EXTERNAL_POLICY.md). The census runs the current strict
analysis and computes diagnostic counterfactuals. It does not narrow a points-to set, ModRef row,
escape fact, access set, or disposition result.

## Result

Do not implement the semantic `ExternalPolicy::Conventional` phases as currently designed. The
primary graduation metric is zero: no global becomes mutex-eligible through a complete,
accessor-disjoint reentry certificate. The proposed policy therefore fails §10.3 before policy
plumbing or semantic narrowing is added.

The census revealed a separate forged-pointer channel and the follow-up instrumentation now
evaluates it group-wise. The result is also negative for the first plausible certificate grammar:
none of the 651 relevant `IntToPtr` seeds is an exact pointer-derived/null case after the literal
lossless round trips already handled by the PAG are removed. A larger forged-pointer project would
therefore need a new proof for integer tags or pointer arithmetic, not just group-wise accounting.

## Instrumentation

The new `pangs external-policy-census` command emits one JSON report containing:

- finite external ModRef rows, strict candidates, external sources, and whether
  source-to-candidate correlation exists;
- automatically derived external principals, retained callbacks, alternating external/internal
  control closure, callback `TransMod`, and completeness blockers;
- every accessor-reachable unknown call used by D4 and the ideal reentry counterfactual;
- every strict `ModuleWide` row, its forged-pointer seed witnesses, poison count, overlap, and
  leave-one-row-out client counterfactual; the common module-wide global identity set is emitted
  once at report level;
- the LLVM integer-expression trace for each relevant `IntToPtr`, including pointer origins,
  constants, operations, and fail-closed blockers;
- connected forged-pointer groups over both shared ModRef support and circular forged provenance
  at pointer origins, plus per-group, remove-all, and accepted-group client counterfactuals.

The ordinary `Analysis::run` path is unchanged. Diagnostic points-to materialization is enabled
only by `Analysis::run_with_external_policy_census`. `--callback-closure` performs a second,
targeted solve only for principals used by D4-failing globals. Closure bodies are serialized once
per principal; callsite and D4 rows reference the principal instead of duplicating the closure.

The runner and aggregator are in
[`metrics/external_policy_census/`](metrics/external_policy_census/README.md).

## Corpus coverage

The cheap core census completed 54 of 56 modules in `~/pangs-corpus/_out_bc`. Two modules exceeded
the 600-second per-module limit:

- `exe-vim-9.2-O1`
- `lib-openssl-4.1.0-O1`

Separate required focused runs covered linked curl O0/O1; the corpus sweep covered libcurl O0/O1,
parson O0/O1, ksba O0/O1, YAPET O0/O1, and JPEGoptim O0/O1. The missing modules cannot alter the
zero result in that required representative set, but they remain a full-corpus coverage limitation
and are not counted as negative evidence.

## Finite external effects

| measure | result |
|---|---:|
| finite external ModRef rows | 25,520 |
| one external source | 25,317 (99.20%) |
| multiple external sources | 203 (0.80%) |
| rows requiring unavailable source/candidate correlation | 66 (0.26%) |

The 25,317 single-source rows are already as precise as the proposed principal separation for
this question: their ideal candidate set equals their strict candidate set. For a multi-source
row the current artifact records the union of sources and the union of candidates, not the
relation between them. The census therefore reports those 66 rows as unavailable instead of
inventing a narrowing. This is the same information boundary that made a finite-row efficacy
claim impossible before implementation; importantly, finite rows do not change
`access_set_complete` today.

Consequently, the census found no finite-effect path to a named final client decision. This is not
a claim that all 66 correlations would be empty; it is a claim that the proposed read-only,
certificate-complete Phase 0 cannot establish such a change, while the independently measurable
D4 channel below has no positive cases.

## D4 reentry result

Across the 54 modules:

| measure | result |
|---|---:|
| globals evaluated | 4,999 |
| globals failing strict `unknown-callee-reentrancy` | 263 in 23 modules |
| distinct unresolved callsites involved in those failures | 1,749 |
| accessor/global-to-unknown-call pairs | 767,047 |
| incomplete control closures in the core pass | 767,045 |
| complete accessor-disjoint pairs | 2 |
| globals newly mutex-eligible | **0** |

The two complete/disjoint pairs are both in `lib-small-g-O0`. Their globals already fail
`access-set-complete`, not `unknown-callee-reentrancy`, so neither is a policy opportunity. No
strict D4 reentry failure had a complete accessor-disjoint closure in the core pass.

The targeted callback pass was run on the required representative cases. “Accessor-reaching” and
“incomplete” are not disjoint categories: a recovered callback path is positive evidence of
reentry, while another missing capability can still make the total closure incomplete.

| input | strict D4 failures | pairs | accessor-reaching | complete/disjoint | newly mutex-eligible |
|---|---:|---:|---:|---:|---:|
| linked curl O1 | 26 | 18,315 | 8,078 | 0 | 0 |
| JPEGoptim O0 | 35 | 435 | 0 | 0 | 0 |
| JPEGoptim O1 | 34 | 423 | 0 | 0 | 0 |
| YAPET O1-g | 10 | 948 | 105 | 0 | 0 |
| ksba O0-g | 8 | 24 | 3 | 0 | 0 |
| ksba O1-g | 5 | 15 | 13 | 0 | 0 |
| parson O0 | 4 | 95 | 0 | 0 | 0 |
| parson O1 | 4 | 253 | 0 | 0 | 0 |

The callback closure is semantically necessary: it recovered thousands of concrete reentry
relationships in linked curl. It did not yield a certificate because principal identity or the
callback/capability inventory remained incomplete. Thus an effect-only certificate would have
made precisely the unsound control inference identified in review finding F2.

Callback enrichment also exceeded 900 seconds for linked curl O0 and libcurl O0/O1. Linked curl
O1 completed, but this cost is already incompatible with the proposed 1.10× graduation bound.
That performance result reinforces the value failure; it is not the reason for the zero decision
count.

## `ModuleWide` attribution

| measure | result |
|---|---:|
| modules with a `ModuleWide` row | 15 |
| `ModuleWide` rows | 16,254 |
| `Mod` / `Ref` rows | 5,171 / 11,083 |
| rows supported by `IntToPtr` | 16,254 |
| rows supported by inline-assembly exposure | 0 |
| unattributed rows | 0 |
| poisoned global occurrences, distinct within each module | 6,006 |
| leave-one-row-out newly access-complete globals | 0 |
| leave-one-row-out newly mutex-eligible globals | 0 |

There were 61 opaque inline-assembly exposures, all in `lib-zstd-O1-g`, but zero inline-assembly
`ModuleWide` rows. This corrects a premise in F1 and in the design document: in the current code,
`ViolationExposure::ModuleWide` disables per-global address-exposure filtering but still produces
a finite `GlobalCandidateSet`. Only `external_universal`, represented by an Andersen
`ForgedPointer` region seeded from `OmegaSeedKind::IntToPtr`, constructs the `ModuleWide` lattice
element.

The row count substantially overstates the recoverable prize. Within every affected module,
multiple `ModuleWide` rows overlap on the same module-wide global set, so removing any one row
alone makes no global access-complete. YAPET O0-g is a compact example: 89 `IntToPtr` rows poison
17 globals, but every leave-one-row-out counterfactual changes zero client decisions.

This does not prove that a group-wise forged-provenance refinement has zero value. It says the
honest successor must reason about the overlapping `IntToPtr` rows as a group and establish a real
provenance bound; external-principal separation cannot claim these 6,006 poisoned global
occurrences because §9 correctly rejects forged provenance.

## Group-wise forged-pointer follow-up

The follow-up uses a read-only proof grammar. It accepts only a pointer-width, default-address-space
`ptrtoint` origin propagated through `phi`, `select`, or `freeze`, optionally joined with integer
zero. Memory loads, call results, parameters, non-zero integers, width changes, cycles, and integer
arithmetic fail closed. Exact universal sources at a pointer origin become graph edges rather than
immediate blockers: otherwise a seed would reject itself merely because its own forged region
flowed back to the origin. The connected components therefore close over both seed-to-ModRef
support and seed-to-origin dependencies.

| measure | result |
|---|---:|
| relevant `IntToPtr` seeds | 651 |
| provenance-connected groups | 61 |
| exact pointer-derived/null seeds | **0** |
| exact pointer-derived/null groups | **0** |
| rows in exact-certifiable groups | **0** |
| seeds classified non-zero-integer | 578 |
| seeds with other unbounded input | 73 |
| remove-every-`ModuleWide` upper bound: newly access-complete globals | 1,950 |
| remove-every-`ModuleWide` upper bound: newly mutex-eligible globals | **0** |

Grouping is materially different from row counting. The 16,254 rows collapse to 61 components.
Fourteen affected modules have one component; `lib-placebo-O1-g` has 47 after circular origin
dependencies collapse the 213 components obtained from row overlap alone. `lib-usb-O0` similarly
collapses from seven row-overlap groups to one. This validates the group construction while still
producing no certificate.

The source expressions explain the zero. Literal `p -> ptrtoint -> inttoptr -> q` round trips are
already recognized and removed before `OmegaSeedKind::IntToPtr` is emitted. Among the residual
seeds, blockers overlap but are dominated by 578 non-zero integer constants, 394 additions, 64
subtractions, 60 memory loads, 15 call results, and 11 function parameters. This is real integer
punning, not an unimplemented copy/`phi` propagation case.

Two deliberately weaker upper bounds were also measured:

- 129 seeds are finite non-zero constant candidates. Only two whole groups qualify: the `{0,2}`
  tag in gifsicle O0 and the matching YAPET O0-g case. Treating those values as non-addresses would
  remove 228 rows and make 97 globals access-complete, but still make zero globals mutex-eligible.
  This requires a target/link-layout non-alias argument that bitcode provenance does not provide.
- An aggregator-only optimistic profile admits one pointer origin plus additive constants without
  proving the exact expression tree. It identifies 362 seeds, 45 groups, and 87 rows, all within
  `lib-placebo-O1-g`. Two remaining unbounded groups keep the module poisoned, so it changes zero
  access-completeness and zero mutex decisions. It is an upper bound, not a certificate.

Even the impossible remove-all counterfactual produces zero new mutex decisions. The 1,950
access-completeness changes are blocked downstream by strict reentry or other mutex conditions.
Thus the currently measurable benefit is diagnostic access-set precision, not a final disposition
gain. Curl—linked or library, O0 or O1—has no `ModuleWide` row, so this extension cannot affect the
curl/KELP comparison.

## Decision

The pre-implementation stop gate is decisive:

1. finite external effects are almost entirely single-source and already conventional-shaped;
2. the residual 66 multi-source rows lack the relation needed for a complete certificate and do
   not affect access completeness;
3. callback-closed reentry analysis changes reachability facts but produces zero complete,
   accessor-disjoint D4 opportunities and zero final mutex decisions;
4. all measured `ModuleWide` rows belong to the separately excluded forged-pointer channel;
5. the group-wise follow-up finds zero exact provenance-certifiable groups and zero final mutex
   gains even under the remove-all upper bound.

Retain the instrumentation for reproducibility, but do not proceed to policy plumbing or semantic
phases 1–6. Do not add a group-wise forged-pointer semantic overlay under the current proof
grammar. A successor would first need a concrete soundness argument for non-zero tags or
pointer-plus-integer arithmetic and a client metric other than mutex eligibility; the group and
counterfactual instrumentation can evaluate that proposal before adding a new lattice/domain
mechanism.
