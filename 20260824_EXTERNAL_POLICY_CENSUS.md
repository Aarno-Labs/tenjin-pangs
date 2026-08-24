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

The census does reveal a separate opportunity: forged-pointer provenance accounts for every
observed strict `ModuleWide` ModRef row. That is evidence for evaluating a provenance-bounded
`IntToPtr` successor, not for weakening the external-code policy's certificate rules.

## Instrumentation

The new `pangs external-policy-census` command emits one JSON report containing:

- finite external ModRef rows, strict candidates, external sources, and whether
  source-to-candidate correlation exists;
- automatically derived external principals, retained callbacks, alternating external/internal
  control closure, callback `TransMod`, and completeness blockers;
- every accessor-reachable unknown call used by D4 and the ideal reentry counterfactual;
- every strict `ModuleWide` row, its forged-pointer seed witnesses, poison count, overlap, and
  leave-one-row-out client counterfactual; the common module-wide global identity set is emitted
  once at report level.

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

## Decision

The pre-implementation stop gate is decisive:

1. finite external effects are almost entirely single-source and already conventional-shaped;
2. the residual 66 multi-source rows lack the relation needed for a complete certificate and do
   not affect access completeness;
3. callback-closed reentry analysis changes reachability facts but produces zero complete,
   accessor-disjoint D4 opportunities and zero final mutex decisions;
4. all measured `ModuleWide` rows belong to the separately excluded forged-pointer channel.

Retain the instrumentation for reproducibility, but do not proceed to policy plumbing or semantic
phases 1–6. If another experiment follows, scope it explicitly to group-wise `IntToPtr`
provenance and measure final client decisions before adding a new lattice/domain mechanism.
