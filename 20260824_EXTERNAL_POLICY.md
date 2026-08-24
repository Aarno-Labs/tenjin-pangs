# External-Code Policy: Design and Implementation Plan

Date: 2026-08-24

Status: proposed for review; no implementation has begun

## 0. Decision summary

Add one pipeline-wide selector, orthogonal to `BuildMode`:

```text
--external-policy strict          # default; current behavior
--external-policy conventional    # explicit precision-for-assumptions opt-in
```

`BuildMode::{Library, Executable}` continues to describe the program boundary: which functions
may have callers outside the analyzed module and which globals may be named or written from that
boundary.

`ExternalPolicy::{Strict, Conventional}` describes how opaque code behaves after data or control
crosses the boundary:

- `strict` is exactly the current analysis behavior;
- `conventional` assumes that separately identified external principals do not silently share
  unrelated component capabilities or unexpectedly reenter unrelated component APIs.

The pipeline exports one result under the selected policy. It does not ask downstream clients to
choose between strict and conventional target sets.

The conventional result is implemented as a **certified narrowing overlay on the strict result**:

```text
conventional(query) =
    narrow(strict(query), complete query-appropriate external-principal certificate)
    otherwise strict(query)
```

It is not implemented as another unknown-pointer lattice, another context domain joined into
Steensgaard classes, or another reachability query for oversize partitions.

Before semantic implementation, a read-only opportunity census must demonstrate that ideal
external-principal separation would change actual client decisions. If it does not, stop after
the census and do not add the policy.

## 1. Motivation

The curl/KELP investigation separates three questions that the current boundary model can make
look like one:

1. **Who may enter the analyzed code?** A linked executable can be rooted at `main`; a library has
   unknown callers at its public entries.
2. **What target may an indirect call invoke?** A public allocator setter means a library callback
   slot can contain a client-supplied function, not only its initializer.
3. **Which finite effects are relevant to which component state?** An installed allocator invoked
   with only a size argument remains an unknown callee, but that does not imply a pointer-derived
   write to every global.

The first question belongs to `BuildMode`. The second must remain open whenever the program
contains a real external installation path. Current Andersen already does much of the third
question correctly: external regions are provenance-separated, an unknown callee contributes no
implicit transitive ModRef rows, and finite global candidates are filtered by per-global address
exposure. The residual hypothesis is narrower: principal-to-candidate correlation may be lost
inside otherwise finite rows, component taint may ignore the finite effect envelope, and D4 treats
every accessor-reachable unknown callee as a possible callback into every accessor without a
principal-specific control argument.

The intended library result is therefore often:

```text
target:  concrete defaults plus an abstract compatible external function
effects: bounded to the selected external principal's certified capability set
```

It is not a closed-world singleton disguised as a library result.

## 2. Historical constraints

This proposal follows two rejected experiments:

- [`PLAN_EXPOSED_GLOBALS_DOMAIN.md`](PLAN_EXPOSED_GLOBALS_DOMAIN.md) added
  `None < ForeignOnly < ExposedGlobals < Universal` to solver classes. One `inttoptr` source
  contaminated an 8,493-node oversize Steensgaard class, lost four existing atomic certificates,
  and produced only two additional access-complete globals with no compelling policy gain.
- [`PLAN_DOMAIN_ONLY_FALLBACK.md`](PLAN_DOMAIN_ONLY_FALLBACK.md) attempted to recover precision
  inside oversize classes with a multi-source field-sensitive CFL/MHS query. Exact history was
  OOM-killed at 33.15 GiB; bounded histories either truncated or reduced rows without recovering
  any target certificate.

These results impose non-negotiable constraints:

1. **No policy domain on Steensgaard classes.** A coarse union class must not be the storage unit
   for external-principal identity or a conventional/strict lattice.
2. **No oversize recovery in v1.** If Andersen does not admit the relevant partition, the result
   stays strict. Coverage loss is preferable to another pushdown-reachability experiment.
3. **No new Universal joins.** Enabling `conventional` must never widen a fact relative to the
   current strict baseline or remove an existing strict certificate.
4. **No row-count success criterion.** Fewer or narrower finite ModRef rows are not sufficient.
   The work must change stationarity, policy-scoped violation relevance, disposition, or another
   named client decision.
5. **No expensive discovery before fallback.** The implementation must know from existing solve
   metadata whether a certificate is available. It may not launch an unbounded query to discover
   that the answer is unavailable.
6. **Effect and control obligations are separate.** An effect envelope may scope global-specific
   unknown effects, but it cannot answer whether an opaque callee can reenter an accessor while a
   prospective mutex is held. D4 requires an explicit, complete control/reentry certificate.

## 3. Goals

1. Preserve current behavior exactly under the default `strict` policy.
2. Offer one explicit, automatically applied opt-in for conventional external-code behavior.
3. Keep build mode and external policy independent.
4. Produce one internally consistent result for all downstream clients.
5. Reuse external-origin provenance already materialized by admitted Andersen partitions.
6. Narrow only with a complete, query-local certificate; otherwise retain strict.
7. Retain Ω or an abstract external target at every genuinely open callback site.
8. Close every external effect envelope over the transitive effects of all retained internal
   callbacks.
9. Scope unknown-global and general unknown-callee effect relevance to the policy-selected effect
   envelope.
10. Discharge D4 `unknown-callee-reentrancy` only with a complete callback/control closure that is
    disjoint from the relevant accessor set.
11. Make every changed result attributable to a principal, capability or callback flow, and policy
    rule.
12. Reject the feature if an opportunity census predicts or evaluation demonstrates no useful
    client-level payoff.

## 4. Non-goals

- No callback annotations, trusted summary files, library-specific configuration, or semantic
  symbol-name classification such as “allocator” or “comparator.”
- No profile-guided target prediction and no use of runtime traces as proof of absence.
- No weakening of direct stores, explicit pointer flow, exported library entry semantics,
  exported writable data, or detected forged-pointer behavior.
- No parallel strict and conventional artifact families for downstream selection.
- No context-sensitive Steensgaard analysis.
- No CFL/MHS, pushdown, or demand fallback for rejected Andersen partitions.
- No claim that an unknown installed callback has the default target.
- No attempt in the first semantic version to improve every B1/B2 or call-graph result. The first
  targets are callback-closed external effects and the D4 reentry decision that currently blocks
  per-global mutex eligibility at accessor-reachable unknown calls.

## 5. The two independent axes

The supported matrix is:

| build mode | `strict` | `conventional` |
|---|---|---|
| `library` | open ABI and current opaque behavior | same open ABI with certified principal-local effects and reentry closure |
| `executable` | current executable roots and current opaque behavior | same executable roots with certified principal-local effects and reentry closure |

Orthogonality means:

```text
ExternalPolicy does not alter the analysis-level export set.
ExternalPolicy does not remove an analyzed store or call.
ExternalPolicy does not make an exported writable library global private.
ExternalPolicy does not remove an unknown externally installable function target.
ExternalPolicy may narrow only facts introduced by opaque external behavior.
```

Consequently, a public allocator setter remains reachable in both library policies. Its store
keeps the callback slot externally configurable. Conventional policy can bound the effects of
invoking the installed callback, but cannot resolve that callback to `malloc` alone.

## 6. Policy semantics

### 6.1 `strict`

`strict` is the behavior of the tree at commit `317a907f` (`Memoize B2 whole-module safety
checks`). Existing PAG seeds, external regions, exposed-global filtering, unknown-caller rules,
ModRef candidates, escape facts, violation taint, and call-graph Ω guards remain unchanged.

Strict is the base solve even when `conventional` is selected. This provides a stable fallback
and makes policy monotonicity directly testable.

### 6.2 `conventional`

Current strict behavior already provides provenance-specific external regions, argument-reachable
opaque-call effects, no implicit transitive ModRef for unknown callees, and address-exposure
filtering of finite global candidates. Those are baseline mechanisms, not conventional-policy
gains.

Conventional adds one narrower assumption bundle:

> Opaque code associated with one automatically identified external principal uses component
> capabilities supplied to that principal. Distinct principals do not silently share unrelated
> component capabilities or unexpectedly reenter unrelated component APIs unless analyzed
> dataflow connects them.

This is intentionally less conservative than strict. It is selected once by the pipeline owner,
recorded in artifacts, and applied uniformly.

Under this assumption:

1. Storage reachable from pointer arguments may still be read, written, and retained.
2. Function pointers supplied externally may still be retained and invoked.
3. Explicit pointer flow between external principals merges their capability sets.
4. For a **finite** strict external-effect row, a candidate global belongs to a principal only
   when retained provenance correlates that principal with the candidate.
5. A candidate whose only support comes from a different, unshared principal may be removed from
   that finite row under conventional policy.
6. `ModuleWide` rows are never narrowed in v1.
7. Direct external calls to exported APIs and direct external writes to exported data remain
   possible in library mode.
8. Forged pointers, unclassified pointer operations, incomplete correlation, and explicit shared
   flow retain strict behavior.
9. Unknown call targets remain unknown.
10. An external principal may invoke every internal callback supplied to or retained by that
    principal, plus every internal function reachable from those callbacks through the final
    concrete call graph.
11. An external principal does not spontaneously invoke arbitrary exported APIs that were not
    supplied to it as callbacks. This is the non-reentry half of the conventional assumption.

Rules 4 and 5 are the effect delta. Rules 10 and 11 define the separate control/reentry delta. The
other rules preserve existing visible behavior and define the strict fallback boundary.

### 6.3 External principals

Do not use one principal per callsite by default. Derive the coarsest stable identity available
without annotations:

| boundary source | principal key |
|---|---|
| direct call to an external declaration | canonical external symbol |
| callback loaded from a completely recovered storage root | callback storage/provenance root |
| multiple callsites using the same recovered callback slot | the same callback principal |
| unknown callback provenance | one shared unknown-callback principal |
| unknown library callers | one shared client-world principal |
| executable entry environment | executable-entry principal |

This keeps state bounded and avoids manufacturing independence from mere callsite identity.

Two principals merge when existing analyzed flow passes a component pointer or callback between
them. If principal identity or sharing is incomplete, no conventional certificate is issued for
the affected query.

The conventional assumption still permits a callback implementation and a library client to
share state in reality. Treating separately identified principals as non-sharing is the explicit
policy choice, not a static proof about unavailable code.

## 7. External control graph and certificates

The conventional assumption has two independent products:

1. an **effect certificate** answers which globals an external principal may read or modify;
2. a **reentry certificate** answers which internal functions that principal may invoke while an
   opaque call is active.

An effect certificate cannot substitute for a reentry certificate.

### 7.1 External control graph

Construct a bipartite graph after the final concrete call graph is available:

```text
internal function ──known direct/indirect call──▶ internal function
internal function ──opaque callsite─────────────▶ external principal
external principal ──retained callback─────────▶ internal function
```

The principal-to-function edges include every internal function pointer supplied to or retained
by the principal. Multiple callsites for the same principal contribute to the same callback set.
The closure therefore includes callbacks passed at another callsite to the same direct external
symbol or recovered callback-storage principal.

Do not add edges from a principal to every exported API under conventional policy. The absence of
those spontaneous reentry edges is the explicit control assumption. Library exports remain
top-level unknown-caller entries under `BuildMode::Library`; top-level entry and reentry during an
active opaque call are separate relations.

If callback retention, principal identity, or any graph edge is incomplete, the affected control
query receives no reentry certificate.

### 7.2 Callback-closed effect envelope

An external principal's effect envelope must include both its pointer capabilities and the
effects of every internal callback it can invoke:

```text
CallbackClosure(P) =
    internal functions reachable from retained_callbacks(P)
    through the final concrete call graph

EffectEnvelope(P) =
    effects through pointer capabilities supplied to P
    ∪ union(TransMod(f) for f in CallbackClosure(P))
```

The closure is mandatory. Without it, the analysis could remove a global that the principal
reaches only by invoking a callback it was handed.

If a callback in the closure reaches an unresolved callee, the closure follows the corresponding
function-to-principal edge and then that principal's retained callbacks. This alternating
function/principal reachability continues to a fixed point. Missing identity or callback
inventory fails closed; it does not terminate the traversal optimistically.

### 7.3 Effect certificate

The strict solve remains authoritative. An effect certificate is a query-local proof that, under
the conventional assumption and callback closure above, a strict finite candidate is unrelated to
the principals reaching the query.

Illustrative internal form:

```rust
struct ExternalEffectCertificate {
    query_node: NodeId,
    strict_candidates: SharedGlobalSet,
    principal_candidates: SharedPrincipalCandidateMap,
    retained_callbacks: SharedPrincipalFunctionMap,
    callback_transitive_effects: SharedPrincipalGlobalMap,
    conventional_candidates: SharedGlobalSet,
    complete: bool,
    blockers: Vec<ExternalEffectBlocker>,
    witnesses: Vec<String>,
}
```

`principal_candidates` retains the relation between each principal and the globals it may
designate or affect. Independent source and candidate lists are insufficient. The callback fields
prove that every retained internal callback's transitive effects were added before narrowing.

### 7.4 Reentry certificate

D4 mutex eligibility needs a separate certificate for one accessor set and one unresolved
callsite reachable while the prospective lock is held:

```rust
struct ExternalReentryCertificate {
    callsite: CallsiteId,
    principal: ExternalPrincipalId,
    accessors: SharedFunctionSet,
    retained_callbacks: SharedFunctionSet,
    reachable_internal_functions: SharedFunctionSet,
    complete: bool,
    accessor_reentry: Option<FunctionPathWitness>,
    blockers: Vec<ExternalControlBlocker>,
}
```

The certificate succeeds only when the external-control closure is complete and
`reachable_internal_functions` is disjoint from the global's accessor set. An intersection is a
known reentry path and fails mutex eligibility. Missing principal or callback completeness retains
the current `unknown-callee-reentrancy` failure.

Under conventional policy, D4 changes from:

```text
any accessor-reachable unknown callee => fail
```

to:

```text
known accessor-to-accessor path => fail
unknown call with no complete reentry certificate => fail
complete external-control closure reaches an accessor => fail
complete external-control closure reaches no accessor => clear this D4 blocker
```

The Ω call edge remains in every case.

### 7.5 Common eligibility requirements

An effect or reentry certificate requires:

1. Every relevant Andersen partition was admitted and completed.
2. Every external source and opaque call has a complete principal identity.
3. Principal-to-candidate correlation is complete for an effect certificate.
4. Every internal function pointer retained by each reachable principal is completely enumerated.
5. Retained callbacks are closed over the final concrete call graph.
6. Effect certificates include `TransMod` for the entire callback/control closure.
7. No `ForgedPointer`, unclassified universal source, or strict-fallback marker reaches the
   effect query.
8. No unsupported transfer loses principal, candidate, or callback correlation.
9. Explicit principal sharing and the alternating function/principal graph have reached a fixed
   point.
10. Every conventional effect candidate is a subset of the strict candidate set.

The certificate proves completeness of modeled flow under the conventional assumption; it does
not prove that unavailable code obeys the assumption. Failure of any requirement returns the
strict answer. There is no partial certificate.

### 7.6 Storage and oversize behavior

Do not attach the policy domain to Steensgaard classes or every PAG node. Build effect
certificates for finite external ModRef queries and reentry certificates for D4 unknown-callee
paths. Intern callback/effect sets and memoize control closures by principal.

Rejected, truncated, or oversize partitions retain strict behavior. V1 performs no recovery
query and does not instantiate `PLAN_DOMAIN_ONLY_FALLBACK.md` under another name.

```text
no admitted complete Andersen/control provenance
    => no conventional certificate
    => strict result
```

## 8. Unknown targets, effects, and reentry

The call graph, effect graph, and external-control graph answer different questions:

```text
call graph:       may this site invoke an unknown external target?
effect graph:     which globals may that principal affect, including callback TransMod?
control graph:    which internal functions may it invoke while the opaque call is active?
```

An installed callback remains Ω/external-compatible in the call graph. A finite effect
certificate may scope unknown-global or general violation relevance. It must not clear D4's
`unknown-callee-reentrancy`; only the reentry certificate in §7.4 can do that.

The principal's effect envelope is always callback-closed before it is used for global-specific
relevance. An unknown row with a finite complete candidate set does not freeze globals outside
that set, but any global in the transitive effects of a retained callback remains relevant.

A component-level summary may remain frozen for clients that require a fully concrete call graph.
D4 and other per-global clients consume the specific certificate their contract requires. The
pipeline computes all facts under one policy; clients do not choose a target universe.

## 9. Automatic strict fallback

Known evidence that defeats the conventional assumption prevents certificate issuance:

- `inttoptr`, integer-derived function pointers, or other forged-address provenance;
- inline assembly with pointer operands/results or a memory clobber;
- unclassified pointer-producing or pointer-consuming PIR operations;
- lost provenance at a field, memcpy, call/return, or partition boundary;
- weak/interposable definitions when replacement is admitted by the build model;
- recognized dynamic loading or symbol lookup;
- explicit dataflow joining external principals;
- incomplete enumeration of callbacks supplied to or retained by a reachable principal;
- an incomplete concrete call graph or unavailable transitive ModRef for the callback closure;
- failure to reach a fixed point in the alternating internal-function/external-principal graph;
- partition rejection, truncation, or budget exhaustion.

Fallback is query-local when existing provenance identifies the affected query. If the
implementation cannot determine the affected scope without another analysis, it uses strict for
the whole module and records why.

Fallback must be cheap: it is a metadata check, not a recovery computation.

## 10. Opportunity census before implementation

The prior domain experiments changed internal rows without producing useful decisions. This plan
therefore begins with a read-only counterfactual census over current strict analysis artifacts.

### 10.1 Required questions

For each external-effect query, report:

- strict candidate globals;
- retained external-region/source provenance;
- proposed principal identity or the reason it is unavailable;
- retained internal callbacks and whether their inventory is complete;
- callback/control closure and the `TransMod` globals it adds to the effect envelope;
- ideal callback-closed conventional candidate globals assuming complete principal separation;
- whether the relevant partition was admitted;
- which client blockers would remain after ideal narrowing.

For each unresolved callsite reachable from a candidate global's accessor set, report:

- the external principal or the reason identity is unavailable;
- retained callbacks and the alternating callback/control closure;
- whether that closure is complete;
- whether it intersects the accessor set, including a path witness when it does;
- whether D4 `unknown-callee-reentrancy` would clear under the ideal conventional policy;
- whether the global would then become mutex-eligible or another guard would still fail.

For each strict `ModuleWide` ModRef row, report:

- its seed-kind support: `OmegaSeedKind::IntToPtr`, `ViolationExposure::ModuleWide` from inline
  assembly, or both;
- the originating instruction or exposure witness;
- the number and identities of globals that receive a module-wide poison from that row;
- how many of those globals are poisoned exclusively by that row versus also poisoned by another
  `ModuleWide` row;
- which client decisions would become newly reachable in an optimistic leave-one-row-out
  counterfactual where that row alone ceased to be `ModuleWide` and every other strict fact stayed
  unchanged.

Aggregate:

- queries with multiple external sources but separable principals;
- queries already as precise as the proposed policy;
- queries blocked by forged/universal provenance;
- queries in rejected or oversize partitions;
- effect candidates restored by callback `TransMod` closure;
- accessor-reachable unknown callsites with complete versus incomplete callback/control closure;
- complete closures that reach an accessor versus complete closures disjoint from all accessors;
- D4 failures that the ideal conventional policy would clear;
- globals that would become mutex-eligible after that D4 change;
- `ModuleWide` rows and distinct poisoned globals by seed kind, including the overlap between
  `IntToPtr` and inline-assembly exposure;
- exclusively poisoned globals and counterfactual client decisions attributable to each
  `ModuleWide` row, so row counts do not overstate the recoverable prize;
- globals that would become stationary after finite writer-candidate narrowing;
- B1/B2 sites whose prerequisites would change;
- disposition candidates that would change after effect relevance is scoped or D4 reentry is
  certified;
- candidates still blocked by another writer, unknown caller, audit finding, or localization
  failure.

Expected access-completeness result: **zero newly access-complete globals**. Today
`access_set_complete` fails only for a module-wide unknown ModRef, an Ω-escaped address, or a
library-mode export. Finite unknown rows do not defeat it. The only current module-wide ModRef
sources are forged/universal pointer provenance and module-wide violation exposure, both of which
block conventional certification. The census records access-completeness transitions as a
negative control: any nonzero transition falsifies this premise or reveals a separate behavior
change and must be explained before proceeding. It is not graduation credit.

The `ModuleWide` census measures an opportunity deliberately outside this proposal rather than an
opportunity for external-principal separation. If its overlap-aware client prize materially
exceeds the finite-row or D4 prize, the review should identify provenance-bounded narrowing of
forged or inline-assembly rows as the likely successor experiment. That successor requires its own
sound provenance argument and must not be smuggled into the conventional external policy.
If external-principal separation misses its graduation threshold while this leave-one-row-out
upper bound passes it, the Phase 0 conclusion must be “do not implement this policy; propose the
provenance-bounded `ModuleWide` successor.”

### 10.2 Implementation constraints

The census may add diagnostic provenance that is discarded after reporting, but it must not alter
solver facts or client exports. It must use existing admitted Andersen regions, the final concrete
call graph, current transitive ModRef, and current strict results. It may compute ordinary graph
closures over those artifacts, but it must not run a new context-sensitive points-to query.

### 10.3 Stop gate

Before semantic work begins, review the census and set a numerical graduation threshold. The
primary positive opportunity is a global that becomes mutex-eligible because a complete,
accessor-disjoint reentry certificate removes its only D4 unknown-callee blocker. Stop if:

- ideal context separation changes no final client decision;
- no D4 failure has a complete accessor-disjoint control closure, or every such global still
  fails another mutex/disposition guard;
- nearly all opportunities lie in rejected partitions;
- the remaining blockers dominate the same globals;
- or the only gains reproduce the two-global/no-decision outcome of the exposed-global
  prototype.

The policy type and CLI flag should not be landed merely because plumbing is easy.

## 11. Shared policy architecture

Build-mode predicates are currently duplicated across PAG, solver, API, B2, CLI, and disposition.
Centralize them before adding semantic narrowing.

The lowest common owner should expose:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalPolicy {
    Strict,
    Conventional,
}

pub struct BoundaryPolicy {
    build_mode: BuildMode,
    external_policy: ExternalPolicy,
    callable_entries: BitSet,
    externally_writable_globals: BitSet,
}
```

`BoundaryPolicy` owns structural entry/export decisions. Separate post-solve
`ExternalControlGraph`, `ExternalEffectCertificates`, and `ExternalReentryCertificates` products
own conventional closure and narrowing. Keeping them separate avoids suggesting that a pre-solve
policy object can know admitted Andersen provenance or that an effect proof establishes a control
property.

Required structural queries include:

```text
is_unknown_caller(function)
is_externally_writable(global)
is_entry_root(function)
is_explicit_export(symbol)
```

Required post-solve queries include:

```text
effect_candidates(node_or_callsite)
retained_callbacks(principal)
callback_closure(principal)
reentry_certificate(callsite, accessor_set)
unknown_effect_relevant(callsite, global)
unknown_global_relevant(modref, global)
certificate_blockers(query)
```

`pangs-pag` is the likely owner of the canonical enums and structural policy because
`pangs-solve` and `pangs-api` already depend on it. Certificate construction belongs with the
Andersen result or API effect materialization, whichever can reuse existing provenance without
copying it. The D4 consumer remains in `pangs-clients`; it receives a completed reentry result and
must not reconstruct external-control assumptions locally.

## 12. Initial semantic scope

The first landed conventional behavior is deliberately narrow:

1. conventional candidate sets for pointer-derived external ModRef rows;
2. callback-closed effect envelopes, including transitive ModRef of every retained internal
   callback in the alternating control closure;
3. global-specific relevance for unknown-global and general unknown-callee effects;
4. D4 reentry certificates for accessor-reachable unresolved callees, allowing the current
   `unknown-callee-reentrancy` blocker to clear only when the complete closure is accessor-disjoint;
5. audit provenance and metrics for every narrowing, D4 decision, or fallback.

The following remain strict in v1:

- Steensgaard solve facts;
- partition admission and fallback;
- exact B1/B2 call-target production;
- callback target Ω decisions;
- whole-component clients that require a fully known call graph.

After v1 demonstrates client-level value, a separately reviewed phase may allow B1 stationarity or
B2 escape predicates to consume complete effect certificates. It must preserve the same strict
fallback and must not make a public library setter exact.

## 13. CLI, API, and artifact contract

### 13.1 CLI

Every command that constructs a production analysis accepts:

```text
--external-policy <strict|conventional>
```

Default: `strict`. Do not add an environment-only switch.

At minimum, inventory `analyze`, `differential`, `icall-census`, `m2-ablation`, solver-backed
queries, PAG workflows, and disposition-producing commands. Startup logging includes both axes:

```text
pangs analyze stage=Andersen build_mode=Library external_policy=Strict
```

### 13.2 API

Add `external_policy: ExternalPolicy` to analysis options with a serde default of `Strict`. Use one
canonical enum or a re-export, not divergent API/PAG definitions.

No production solver path may receive `BuildMode` while silently defaulting a different external
policy. Temporary adapters are allowed only inside the implementation stack.

### 13.3 Artifacts

New artifacts record:

```json
{
  "build_mode": "library",
  "external_policy": "conventional",
  "external_policy_fallbacks": 3
}
```

- Add `opts.external_policy` to the manifest schema.
- Keep it optional in schema version 1 for preserved artifacts; absence means historical strict.
- Include the policy in summaries, stable-comparison normalization, cache keys, and disposition
  run metadata.
- Export aggregate fallback counts and reason counts.
- Do not multiply `Tier` into strict/conventional variants. Tier records algorithmic provenance;
  external policy is run-level provenance.

## 14. Implementation plan

Each phase is independently reviewable and should be one or more focused `jj` commits.

### Phase 0 — opportunity census only

1. Inventory existing external-region and source provenance at ModRef address nodes and unknown
   callsites.
2. Add diagnostic-only principal grouping using §6.3.
3. Attribute every strict `ModuleWide` row to `IntToPtr`,
   `ViolationExposure::ModuleWide` from inline assembly, or both, and compute overlap-aware
   poisoned-global and leave-one-row-out client upper bounds.
4. Inventory every internal function pointer supplied to each principal and record whether that
   callback inventory is complete.
5. Build the diagnostic alternating control closure over the final concrete call graph and add
   callback `TransMod` to each ideal effect envelope.
6. Compute ideal counterfactual finite-effect, effect-relevance, and D4 reentry outcomes without
   changing exports.
7. Run the census on the evaluation set in §17.
8. Record the upper bound, the separately excluded `ModuleWide` prize, and remaining blockers in
   this document or a dated companion report.
9. Set a numerical D4/client-decision graduation threshold or reject the proposal.

No flag or semantic policy lands in this phase.

### Phase 1 — policy plumbing and structural centralization

Proceed only if Phase 0 passes.

1. Add `ExternalPolicy::{Strict, Conventional}` with default `Strict`.
2. Plumb CLI, API, manifests, summaries, and cache keys.
3. Introduce the shared structural `BoundaryPolicy`.
4. Remove duplicate `is_exported_func`/`is_exported_global` interpretations.
5. Initially execute strict behavior for both policy values.
6. Prove normalized strict output is byte-identical to the pre-policy baseline.

### Phase 2 — certificate construction

1. Build principal identities from existing admitted Andersen external regions.
2. Compute explicit principal sharing from already materialized pointer flow.
3. Enumerate retained internal callbacks and build the alternating external control graph to a
   fixed point over the final concrete call graph.
4. Close every principal effect envelope over `TransMod` of the complete callback/control closure.
5. Construct effect certificates only for requested external-effect queries and reentry
   certificates only for accessor-reachable unknown callsites requested by D4.
6. Reject certificates on every §7.5 or §9 blocker.
7. Intern candidate, callback, effect, and control sets; memoize closures by principal and solved
   graph version.
8. Export diagnostics, but do not yet change client facts.
9. Compare measured effect and reentry certificates with the Phase 0 upper bound.

### Phase 3 — conventional finite ModRef effects

1. Under conventional policy, apply complete certificates to pointer-derived external ModRef and
   their finite global candidate sets.
2. Preserve every named pointee and direct/derived analyzed access.
3. Preserve strict rows for ineligible queries.
4. Never narrow a `ModuleWide` row in v1.
5. Leave Steensgaard, oversize fallback, access-completeness facts, and call-target Ω unchanged.
6. Add strict-superset and no-widening differential checks.

### Phase 4 — scoped effect relevance and D4 reentry

1. Preserve unknown call edges in the call graph.
2. Compute global-specific general unknown-callee effect relevance only from callback-closed effect
   certificates.
3. Scope finite complete unknown-global rows to their candidate globals.
4. Pass complete reentry certificates to D4 and clear `unknown-callee-reentrancy` only when the
   reachable internal-function set is disjoint from the global's accessor set.
5. Keep D4 strict when the reentry certificate is absent or incomplete, or when its closure reaches
   an accessor. Never use an effect certificate alone to clear D4.
6. Keep whole-component clients frozen when their contract requires a concrete call graph.
7. Update disposition to consume both policy-selected effect relevance and the distinct D4 reentry
   result produced by the pipeline.

### Phase 5 — evaluate and decide whether to graduate

1. Run the full strict/conventional × library/executable matrix.
2. Audit every changed client decision.
3. Run historical YAPET and JPEGoptim regression gates.
4. Measure time, memory, certificate coverage, and fallbacks.
5. Remove the semantic implementation if the predeclared graduation threshold is not met.

### Phase 6 — optional B1/B2 consumption

This phase requires a separate review after Phase 5.

1. Identify exact B1/B2 prerequisites changed by complete effect certificates.
2. Ensure policy-selected effects are available before the relevant exactness decision.
3. Preserve public-setter, unknown-target, FSA, and Ω guards.
4. Add strict-versus-conventional target-envelope differential tests.
5. Land only if it changes measured exact resolution without creating silent or out-of-envelope
   targets.

## 15. Required regression fixtures

Use LLVM-derived fixtures where practical and hand-written PIR for solver-domain corner cases.

1. **Public setter:** exported library setter stores a function-pointer parameter into a private
   slot. Both policies retain the external target.
2. **No-pointer callback:** unknown callback receives scalars only. Conventional does not make an
   unrelated private global relevant when a complete certificate exists.
3. **Pointer argument:** passing `&g` keeps `g` in both effect envelopes.
4. **Shared callback slot:** two invocation sites loading the same recovered slot use one
   principal.
5. **Unknown callback provenance:** sites use the shared unknown-callback principal and receive no
   unsupported separation.
6. **Explicit principal sharing:** analyzed pointer flow merges two principal capability sets.
7. **Unknown library callers:** exported entries remain open under both policies.
8. **Exported data:** exported writable library global remains externally writable.
9. **External function result:** function-capable result retains an abstract external target.
10. **External data result:** no narrowing without complete provenance and principal identity.
11. **Forged pointer:** `inttoptr` prevents certification but does not widen strict.
12. **Unsupported operation:** lost provenance prevents certification.
13. **Oversize partition:** no recovery query runs; conventional equals strict for that query.
14. **Finite unknown row:** scoped unknown-global taint affects candidates only.
15. **Direct retained callback effect:** a callback supplied to a principal directly modifies
    `g`; `g` remains in that principal's effect envelope through callback `TransMod`.
16. **Transitive retained callback effect:** a supplied callback reaches another internal function
    that modifies `g`; `g` remains in the callback-closed effect envelope.
17. **Callback reenters accessor:** an accessor-reachable unknown callee retains a callback whose
    control closure reaches an accessor; D4 continues to fail with a path witness.
18. **Callback closure is disjoint:** a complete retained-callback closure reaches no accessor;
    conventional clears only the D4 unknown-callee blocker.
19. **Incomplete callback inventory:** an unclassified function-pointer transfer prevents both
    effect and reentry certification and preserves strict behavior.
20. **Nested principal closure:** a retained callback calls a second opaque principal that invokes
    its own retained callback; both control and effect closures reach the alternating fixed point.
21. **Unknown callee:** Ω remains while unrelated general effect relevance clears only with a
    callback-closed effect certificate.
22. **No silent icall:** every callsite retains a concrete or Ω edge in all four policy/build cells.
23. **Strict compatibility:** strict normalized exports match the pre-policy fixtures.
24. **Policy cache isolation:** effect, reentry, and B2 caches cannot cross policy runs or graph
    versions.

## 16. Differential invariants

Within each build mode:

```text
strict effect candidates       ⊇ conventional effect candidates
strict escape possibilities    ⊇ conventional escape possibilities
strict taint relevance         ⊇ conventional taint relevance
strict analyzed stores         = conventional analyzed stores
strict exported entry set      = conventional exported entry set
strict externally writable set = conventional externally writable set
```

For every conventional narrowing:

```text
conventional_candidates ⊆ strict_candidates
complete_certificate = true
certificate_blockers = []
EffectEnvelope(P) ⊇ union(TransMod(f) for f in CallbackClosure(P))
```

For every conventional D4 decision at an unresolved call:

```text
clear unknown-callee-reentrancy
    iff complete_reentry_certificate
    and reachable_internal_functions ∩ accessors = ∅
```

An incomplete callback inventory, principal identity, concrete call closure, or transitive ModRef
closure must yield the strict D4 failure and strict effect answer.

If a query lacks a certificate:

```text
conventional(query) = strict(query)
```

Within each policy, the existing solver relation remains mandatory:

```text
Andersen ⊆ Steensgaard ⊆ conservative
```

No policy may violate the call-graph invariant:

```text
every indirect callsite has at least one concrete edge or an explicit Ω edge
```

## 17. Evaluation and graduation

Required inputs:

1. linked curl O0/O1 executable from the 2026-08-24 B2 investigation;
2. libcurl and curl library modules;
3. parson and ksba exported-setter cases;
4. YAPET O0-g, including the four historically lost certificates;
5. JPEGoptim O0/O1, including all ten historical certificates;
6. the indirect-call census corpus;
7. the disposition coverage corpus.

Report:

- eligible and rejected effect and reentry certificates by blocker;
- admitted versus oversize opportunity counts;
- strict versus conventional ModRef candidate fanout;
- `ModuleWide` rows by `IntToPtr`/inline-assembly seed kind, their overlap-aware poisoned-global
  counts, and client decisions blocked exclusively by each row;
- retained callbacks per principal and callback/control closure sizes;
- effect candidates contributed by callback `TransMod` closure;
- globals newly stationary;
- access-completeness transitions, expected to be zero and treated as a negative control;
- global-specific unknown-effect relevance changes;
- accessor-reachable unresolved calls split into incomplete closure, accessor-reaching closure, and
  complete accessor-disjoint closure;
- D4 `unknown-callee-reentrancy` failures cleared;
- globals newly mutex-eligible after all other D4 and disposition guards;
- final B1/B2, disposition, and other client decisions;
- concrete-only, concrete+Ω, and Ω-empty callsites;
- analysis wall time and peak RSS;
- byte-normalized strict compatibility;
- differential invariant violations.

The Phase 0 review sets the numerical value threshold before semantic code exists. Its primary
value metric is the number of globals that become mutex-eligible because a complete,
accessor-disjoint reentry certificate clears the only remaining D4 unknown-callee blocker. At
minimum, a graduated implementation must:

- change at least one named final mutex/disposition client decision in a representative library;
- show a material corpus-wide decision gain, not merely fewer diagnostic rows;
- retain every strict historical certificate;
- produce zero differential and silent-icall violations;
- avoid any MHS/domain-only fallback;
- keep geometric-mean wall and RSS overhead at or below 1.10× strict, with no unexplained module
  above 1.25×.

An access-completeness transition does not count toward the value threshold unless the premise
above is first shown to be wrong and the newly discovered channel is separately reviewed.

If it fails, discard the semantic phases. Policy plumbing need not survive a failed experiment
unless another approved consumer requires it.

## 18. Code and contract surfaces

Expected implementation surfaces:

- `crates/pangs-pag/src/lib.rs` and `knobs.rs`: canonical policy types and structural boundary
  derivation;
- `crates/pangs-solve/src/andersen.rs` and `lib.rs`: retained external-region provenance and
  principal/callback inputs, without a new Steensgaard domain;
- `crates/pangs-api/src/lib.rs`, `differential.rs`, and `icall_census.rs`: external control graph,
  callback-closed effect certificates, finite ModRef materialization, effect relevance, metrics,
  and policy differentials;
- `crates/pangs-clients/src/lib.rs`: D4 consumes completed reentry certificates when evaluating
  `unknown-callee-reentrancy`; it does not infer external effects or control closure itself;
- `crates/pangs-api/src/simple.rs` and `initval.rs`: unchanged in v1 except structural policy
  plumbing; optional Phase 6 consumers;
- `crates/pangs-cli/src/main.rs` and `knobs.rs`: uniform option and census commands;
- `crates/pangs-dispose` and `crates/pangs-manifest`: run-policy validation and provenance;
- `schemas/manifest.schema.json` and summary schemas: additive artifact fields;
- `metrics/icall_census/` and measurement HOWTOs: policy-aware evaluation.

## 19. Risks and mitigations

### The opportunity is already captured by current external-region filtering

The exposed-global prototype suggests this is plausible. Phase 0 measures the counterfactual
client outcome before policy plumbing or solver work.

### Principal separation is still an assumption

Correct. The flag is an explicit run-level assumption, not a static proof about missing code.
Automatic grouping makes the assumption reproducible and avoids per-library configuration.

### Principal metadata collapses in coarse analysis

Do not recover it. Lack of complete admitted Andersen provenance means strict behavior.

### A callback reaches a global omitted from the principal's direct capability set

Close the effect envelope over transitive ModRef of every internal function in the complete
alternating callback/control closure. If callback inventory or closure is incomplete, issue no
effect certificate.

### Effect narrowing is mistaken for a non-reentry proof

Keep `ExternalEffectCertificate` and `ExternalReentryCertificate` as different types and API
queries. D4 accepts only the latter and requires a complete accessor-disjoint closure.

### Unknown-callee taint erases every effect gain

Phase 0 predicts general effect relevance and the separate D4 control outcome. Phase 4 scopes
effect relevance while preserving Ω and uses a reentry certificate for D4. If neither changes a
final client decision, reject the feature.

### Per-query certificates become expensive

Build them only for existing external-effect and D4 queries, intern sets, memoize principal
closures by solved graph version, and never launch a points-to recovery traversal. Enforce the
graduation performance bounds.

### Conventional becomes a hidden route to exact targets

V1 does not alter exact call-target tiers. Optional B1/B2 consumption requires separate review,
and public setters plus abstract external targets remain blockers.

## 20. Review decisions

The following must be approved before Phase 0 implementation:

1. Public names: `strict` and `conventional`.
2. The external-principal grouping in §6.3.
3. The conventional non-sharing/non-reentry assumption in §6.2.
4. The v1 scope: finite ModRef correlation, callback-closed effects, scoped effect relevance, and
   D4 reentry certificates.
5. The rule that effect envelopes include callback-closure `TransMod` before any narrowing.
6. The rule that only a complete, accessor-disjoint reentry certificate can clear D4
   `unknown-callee-reentrancy`.
7. The rule that rejected/oversize partitions receive no recovery attempt.

After Phase 0, review must approve a numerical client-decision threshold before Phase 1 begins.
