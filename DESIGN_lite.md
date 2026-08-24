# PANGS-lite: A Simplicity-First Alternative Design

*Companion to `DESIGN.md`. Same goals, clients, soundness posture, and scale target
(≤1 MLoC C); this document describes the design point that maximizes simplicity while
keeping the performance and coverage loss measurably small. The two documents share
terminology — read `DESIGN.md` §1–2 first for goals, paper sources, and the
FN-corruption/FP-coverage asymmetry that licenses everything cut here.*

Retrospective measurements, discarded prototypes, and the implementation chronology
live in [EXPERIMENT_HISTORY.md](EXPERIMENT_HISTORY.md); this document describes the
current architecture and its forward-looking constraints.

## 0. The thesis

The full design routes queries through five tiers with certificate checks between each,
and maintains three solver technologies (union-find Steensgaard, partition Andersen,
demand-driven CFL-reachability). Its own scale note (§1) concedes that at ≤1 MLoC,
tier D "likely graduates from optional relief valve to affordable default." PANGS-lite
finishes that thought: **if partition-scoped Andersen runs on everything interesting
anyway, the residue-routing tiers and the certificate cascade stop paying rent.** Cut
tier E (the single largest component), cut the per-tier certificate plumbing, cut typed
heap clones, and let one exhaustive solver answer every query that B1/B2 didn't answer
exactly.

The bet is safe to take because of the client asymmetry (`DESIGN.md` §7): every cut
converts to *coverage loss, never corruption*. The soundness skeleton — Ω, violation
taint, FSA envelope, safe fallbacks — survives intact, and the cut precision is
recoverable later behind a stable interface (§5 below).

## 1. Architecture

```
                 ┌────────────────────────────────────────────────────────────┐
                 │  A'. PAG construction (parallel per function/module)       │
  LLVM IR ──────▶│  partial SSA · byte-offset Gep · plain alloc-site objects  │
                 │  Ω boundary · violation detection · call/return-site filter│
                 └──────────────┬─────────────────────────────────────────────┘
                                ▼   (graph frozen: read-only from here on)
                 ┌────────────────────────────────────────────────────────────┐
                 │  B'. Pre-analyses: B1 InitVal/stationarity · B2 simple ptrs│
                 └──────────────┬─────────────────────────────────────────────┘
                                ▼
                 ┌────────────────────────────────────────────────────────────┐
                 │  C'. Steensgaard — base answer + first escape bits         │
                 └──────────────┬─────────────────────────────────────────────┘
                                ▼
                 ┌────────────────────────────────────────────────────────────┐
                 │  D'. Partition-scoped Andersen (PIP internals), exhaustive │
                 │      prepartition graph · directional SCC admission        │
                 │      receiver payloads + bounded origins · joint CG LFP    │
                 └──────────────┬─────────────────────────────────────────────┘
                                ▼
                 ┌────────────────────────────────────────────────────────────┐
                 │  F. Clients + disposition over the materialized solution   │
                 └────────────────────────────────────────────────────────────┘
```

No authoritative tier E. Experimental CFL query prototypes exist behind the query CLI,
but they do not feed analysis, disposition, or transformation artifacts. No certificate
checks run between production phases: B2's exact answers take precedence, everything
else reads D's solution, and FSA intersection is applied once as a final
soundness-preserving filter on icall results. That final filter is a no-op in practice:
the FSA test that removes targets runs inside C', during Steensgaard binding, and the
envelope D' activates from is already FSA-closed (`20260823_ICALL_AUDIT.md` §3.5). It is
retained as a cheap invariant, not as a source of precision. Receiver-allocation-relative payload
summaries and their bounded allocation-origin analysis are currently opt-in D'
extensions (`PANGS_ANDERSEN_RECEIVER_PAYLOADS`); they are described below because their
object domain, fallback semantics, and admission dependencies are part of the intended
portable design even while corpus validation continues.

## 2. Phase details (deltas from `DESIGN.md` §4)

### A'. PAG construction
**Kept:** byte-offset Geps with lazy `(object, byte_off)` field materialization, extended
with normalized affine lanes for dynamic sequential indices; the
constant-indexed fn-ptr-array carve-out (dispatch tables); the PIP Ω boundary model with
implicit bits; **assumption-violation detection → Ω-taint** (non-negotiable — it is what
makes per-component soundness auditable); the TeaDSA call/return-site filter
(instruction-local SSA validity filtering on call-argument/return-value edges — cheap,
and its precision is frozen into the graph for every downstream phase).

Variadic boundaries fail closed unless their consumption is explicit. In addition to
positionally recognized `va_arg` operations and constant `%n`-free calls to the standard
`printf` family, PAG construction recognizes internal `vfprintf` forwarding wrappers.
The wrapper proof requires the fixed format parameter to reach `vfprintf` unchanged,
every `va_list` to have matched `va_start`/`va_end` roots, exactly one list to be forwarded,
and every list-derived pointer use to be part of that construction, destruction, or call.
Each wrapper call is then safe only when its actual format is a decodable constant with a
supported, `%n`-free conversion sequence. Unknown formats, `va_copy`, other consumers,
escaping list aliases, and unfamiliar dataflow retain the ordinary Ω boundary and audit.

The exact-name external summary registry is deliberately small and shape checked. In
addition to safe format consumers, it can classify an external as pure/constant-returning,
read-only over client state, or returning an interior alias of a particular argument.
Implemented examples include `__ctype_get_*` accessors, the glibc ctype tables, and standard
byte/string search routines such as `strchr`. Standard `free` is also recognized when a direct
external call has exactly one integer-ABI-class argument, a non-variadic void signature, and no
result. Its argument is a non-capturing terminal: the call produces no pointer flow and has no
client-state Mod/Ref effect. A module-defined `free`, an indirect or unresolved call, or a name
match with the wrong call shape retains the normal Ω effects. This summary trusts the standard
library contract and does not model either statically linked replacements from unanalyzed
translation units or dynamic interposition. Other unlisted calls retain the normal Ω effects.
Known positional variadic bindings are modeled only when the callee's consumption is visible;
otherwise function-pointer actuals and other pointer-bearing tail arguments fail closed.

**Cut:**
- **Typed heap clones** (cclyzer use-based back-propagation). v1 uses plain
  allocation-site objects. This deletes the back-propagation pass, the clone/site-object
  duality, and the union/type-punning conservatism dial (`DESIGN.md` §8) in one stroke.
  Precision add-on, not soundness: punning events are still *detected* and Ω-tainted.
- **Minimal CastMap.** It exists to serve tier-E traversals; no tier E, no CastMap.

### B'. Pre-analyses
**Kept — these are the best precision-per-line in either design:**
- **B1 InitVal/stationarity (CORAL Stage Zero).** Flagship output of the mutability
  client (stationary global ⇒ no localization needed) and the settler for
  dispatch-table icalls. ~Few hundred lines of regional forward def-use tracking.
- **B2 simple pointers (KELP).** Regional SSA walks resolving an icall operand exactly when
  its every producer is reachable without passing through memory. Safe fallback discipline
  unchanged. KELP reports ~⅓ of icalls resolved this way; **that yield does not reproduce
  here.** On the 2026-08-23 corpus (`20260823_ICALL_AUDIT.md` §6) the exact pre-analyses
  together settled **6 of 19,719** indirect callsites, all six in one module. Whether B2 is
  correctly conservative on this corpus or defective is unresolved. Exact edges now carry
  distinct `Tier::B1Initval` and `Tier::B2Simple` provenance, with separate
  `icalls_b1_initval` and `icalls_b2_simple` counters; `icalls_simple` remains their combined
  compatibility counter. The recorded six-site corpus result predates that split and must be
  rerun before the sites can be attributed and B2's place decided.

**Kept:** B3 confined-function subtraction falls out of B2's bookkeeping. Functions whose
every address flow was consumed by an exact simple chain are removed from non-exact
candidate envelopes, while an exact B2 binding to such a function remains pinned. Since
B3's input is B2's exact resolutions, its measured effect on that corpus is also nil:
`confined_functions` was **0** on every module.

B1 now emits more than an initializer target set. Its production certificate records the
publication boundary, initialization subtree and writers, readers/observations, and
decisive failure evidence. Static initializer stores are not runtime writers. Absence-only
initialization may therefore be stationary, while thread writers, signal reachability,
recursion, `atexit`, unresolved effects, or a post-publication write fail closed. This
certificate is fact input to disposition, not a terminal strategy decision.

### C'. Steensgaard, demoted to base solver
A sequential numeric-ID union-find with type/signature compatibility filtering. Its
*only* jobs are (a) a conservative structural summary used to bound D', (b) the first
wave of escape bits, and (c) the complete base-tier answer used wherever D' cannot
refine. It settles no query by certificate. D' no longer has to use a Steensgaard
equivalence class verbatim as its admission unit: it builds an independent constraint
prepartition graph and uses Steensgaard at cut boundaries.

Its partition boundary is allocation-field aware when the fixed PAG independently proves
an address root. Constant GEP offsets get distinct synthetic storage classes. LLVM
lowering preserves a dynamic sequential index as an affine byte lane
`residue + k * modulus`, so an unknown element of an array of structs retains its known
member offset. Lanes join only locations whose congruences may overlap. A genuinely
unstructured dynamic byte offset gets one summary joined only to the materialized fields
of that same allocation. Unknown-root GEPs retain ordinary field-insensitive unification.
Synthetic global-field
classes carry their owning-global membership so they seed interesting partitions and
contribute to aggregate escape/write facts. Andersen consumes the same root-relative
address proof to seed a field directly at a partition boundary instead of requiring the
base-address partition to be co-admitted. This allocation-relative vocabulary is derived
from PAG operations and byte offsets, not LLVM pointee types, so it remains compatible
with an opaque-pointer front end.

### D'. The one real solver
Partition-scoped, inclusion-based, PIP internals (implicit-Ω constraint forms and
per-variable points-to sets). Every interesting partition (one reachable from
client-relevant pointers: icall operands, mutable globals and what they reach, or
escape-relevant objects) is considered without certificate-residue routing; the admission
policy below decides whether Andersen or the Steensgaard fallback supplies its answer.
The current implementation runs admitted regions in one sequential solve. The
implementation keeps the optimization surface narrow, but profiles of dense promoted
regions justified two general mechanisms: semi-naive constraint joins and
threshold-triggered collapse of strongly connected copy variables.

**Partition admission and fallback:**

Steensgaard supplies the complete base-tier answer everywhere. D' independently builds a
prepartition graph from the actual inclusion constraints, with synthetic vertices for
allocation-relative fields. Weak components are the ordinary admission unit. An
interesting component is admitted to Andersen when its quadratic cost proxy fits the
configured budget. An oversize component remains at its Steensgaard answer, and the
result records the number and largest size of such fallbacks. Provenance separation also
permits a bounded promotion: a sparse, medium-sized component that exceeds the old cost
proxy may still be admitted when its node and edge counts fit fixed caps and it contains
no integer-forged/universal external source.

For an indirect call stranded in an oversize weak component, D' may instead admit a
bounded, source-closed slice of the directed condensation graph. It starts at the call
operand's SCC and closes over predecessor SCCs, because every excluded predecessor would
be a missing producer. Outgoing dependencies may cross the cut: their consumers retain
the complete Steensgaard summary when refined and base facts are merged. If the closed
slice exceeds its budget or contains a disallowed universal source, the whole site keeps
the ordinary fallback. Complete Andersen facts overwrite only admitted nodes, so omission
by the refiner is conservative.

**Receiver-allocation-relative payload summaries (experimental):**

Many generic containers are context-insensitive precisely at the interface that stores
and retrieves pointer payloads. D' recognizes a deliberately narrow structural pattern
without using function names or LLVM aggregate types:

- the first pointer parameter acts as a receiver;
- another pointer parameter can flow to a store through receiver-reachable memory; or
- a receiver-reachable load can flow to the function's pointer return.

The same analysis lifts these operations through thin direct wrappers. A wrapper that
returns the direct callee result inherits its regions; one that dereferences that result
before returning a nested payload records its own load location instead. A family is
enabled only when at least one member is observed on two independently certified receiver
allocation roots, which avoids treating every method-like function as a context family.

For a summarized direct call, the payload cell is keyed by
`(receiver allocation root, FieldLocation)`. Thus two receiver allocations do not share a
generic value slot, and constant-offset members such as a map entry's key and value remain
distinct. D' replaces only the matching payload actual/formal and return/result bindings;
receiver, key, and control bindings remain context-insensitive. A call is summarized only
when its receiver has one independently exact allocation root selected within the
16-context limit. Uncertified receivers, unselected roots, and excess contexts retain the
ordinary unsummarized function body. This is a bounded object-sensitive summary for a
common container idiom, not general call-string or object sensitivity.

Receiver payload cells are also vertices in the prepartition graph. Store-side
dependencies flow into the cell and loads flow out. Allocation-field initializer
components needed to populate a payload are marked interesting and considered for
admission under their own budgets; they are not weakly unioned into the call operand's
megacomponent merely because they support the result.

**Bounded allocation-origin certification (experimental):**

Payload stores need a more discriminating seed than the carrier's Steensgaard class.
An independent positive dataflow analysis computes, for every PAG value,
`{ allocation roots, complete }`. `AddrOf` introduces a root; address-preserving
assignment (including phi/select and flattened direct call/return bindings) and GEP copy
roots forward. Loads and unsupported producers prevent completeness. Null is the complete
empty set. At most 64 roots are retained per value; seeing another root sets
`complete = false` rather than silently truncating the abstract value.

A complete row seeds exactly its named allocation roots into the receiver-relative
payload cell. An incomplete row seeds all retained positive roots plus a distinct
receiver-payload external region. The unknown bit therefore remains sound without
copying the carrier's entire contaminated Steensgaard points-to class into every
receiver context. The external token propagates through normal Andersen constraints and
is interpreted as unknown at consumers; it never certifies a finite target set.

The abstract domain is separable from receiver summarization: it is implemented as an
independent PAG pass and can serve other clients. The current option nevertheless wires
it only into receiver summaries and exposes no separate origin-analysis flag. Receiver
summarization supplies its current precision payoff by giving those facts a contextual
destination. Conversely, receiver summaries remain sound without a complete origin proof
because incomplete or overflowing rows explicitly carry the local unknown region.

**Shared closed-producer certificates (experimental):**

An indirect-call operand may retain Steensgaard's unknown-callee bit even after Andersen
finds only named function objects. With `PANGS_ANDERSEN_CLOSED_PRODUCERS` enabled, D'
constructs one producer graph shared by every in-scope indirect call. Its vertices are PAG
values and materialized allocation-relative memory cells. Assignments and GEPs preserve
producers; solved stores feed their possible destination cells; solved loads consume their
possible source cells. Direct-call parameter and return summaries require no separate
syntax because PAG construction has already flattened those bindings into assignments.
Aggregate copies make their affected destination cells incomplete: the copy transfers
contents at whole-object granularity, so a certificate cannot attribute a destination field
to one source field. Certifying field-preserving memcpy requires the width-aware projection
summary of `20260730_MEMCPY_HANDLING.md` and is left for a later extension.

The graph is condensed into SCCs once. A component is incomplete when it contains an
external-region producer, depends on an incomplete component, or forms an ungrounded
producer cycle. Exact allocation-address certificates are accepted as closed address
terminals even when field-aware partitioning placed their carrier outside the admitted
slice. Each callsite query is then a constant-time component lookup plus enumeration of
the operand's Andersen pointees. The Steensgaard unknown bit is removed only when the
component is complete, the pointee set is nonempty, and every pointee is a named function
object. External regions, non-function objects, empty sets, and unsupported producers
retain the original fallback.

The prototype needs Andersen's materialized memory cells to connect loads and stores. It
therefore permits a bounded promotion of a non-forged indirect-call partition, capped at
8,192 nodes and 8,192 edges, despite rejection by the quadratic admission proxy. Larger
or integer-forged partitions retain normal admission and fallback behavior. This
supporting promotion is an implementation limitation of the prototype, not a requirement
of the certificate abstraction; a future fixed-PAG memory-projection graph could remove
that dependency. The discarded fixed-PAG projection trials in
[EXPERIMENT_HISTORY.md](EXPERIMENT_HISTORY.md) show that a useful successor also needs
demand-driven address origins and discriminator-sensitive producer proofs.

**Closed-consumer certificates (experimental):**

Unknown incoming callers are the forward dual of unknown indirect callees. Steensgaard
marks a function unknown-caller when its unified function-object class escapes, but the
class may contain a callback whose concrete address uses all terminate at internal
indirect calls. With `PANGS_ANDERSEN_CLOSED_CONSUMERS` enabled, D' audits the completed
Andersen facts for each named function address and removes the Steensgaard unknown-caller
bit only when every represented consumer is internal.

The proof is shared rather than per-function. It visits the materialized named-function
facts once and checks their fixed PAG transfers:

- an indirect-call operand is a safe terminal, regardless of whether other alternatives
  at that operand remain unknown;
- internal assignments, direct-call bindings, loads, stores, and memcpy joins must
  preserve each named-function fact at every modeled destination;
- external and vararg arguments, exported or opaque storage, pointer/integer escape,
  unsupported function-address arithmetic, external regions, and returns from functions
  that still have unknown callers are open terminals; the sole argument of a recognized standard
  `free` call is the exception, including pointer contents reachable only through the destroyed
  container; and
- an address producer or transfer omitted at an admission boundary makes that function
  uncertifiable.

Boundary reachability follows pointer contents transitively and includes materialized
allocation fields, so passing a struct containing a callback to external code is open
even when the callback is not in the root object's field-sensitive contents. The proof
does not run an address solve for the whole module and does not perform one traversal per
callback. Boundary reachability is one linear multi-source traversal; transfer auditing
is bounded by the fixed PAG edges and the memcpy endpoint pairs already represented by
the solve.

Like the closed-producer prototype, it permits the bounded non-forged indirect-call
partition promotion when enabled, but the two certificates are otherwise independent.
A function address consumed at an unresolved internal indirect call can be certified as
having no external caller without proving that the call operand contains only that
finite family. The function's existing escape diagnostics remain available; only the
complete unknown-caller fact is narrowed.

**Call graph via monotone on-the-fly discovery:**

1. Build one persistent solve from base PAG constraints, Ω seeds, and pinned B1/B2
   exact bindings.
2. Propagate to quiescence, then discover function objects reaching each non-exact
   icall operand within its FSA-compatible coarse envelope.
3. Install each newly grounded argument/parameter and return/result binding once, using
   copy-edge delta propagation to seed the edge from the source's existing facts.
4. Resume the same solve until both propagation and target discovery are quiescent.

The target domain is a small lattice, not just a set: a coarse `unknown_callee` is top
over all remaining address-taken, signature-compatible functions, even when its
diagnostic `targets` list does not enumerate them. Ordinarily that top value activates
the remaining conservative envelope. With receiver payload summaries enabled, discovery
first solves the contextual operand: named function objects activate only their
corresponding targets, while a receiver-payload or other external region activates the
full envelope and preserves unknown fallback. This permits a contextual solution to
replace a coarse unknown with a finite named set without violating the refinement order.

A resource limit cannot emit a partial ascending solve: the entire Andersen tier falls
back to the complete Steensgaard result, while independently proven exact callsite
answers survive. The old stateless descending construction remains only as a temporary
differential oracle during the migration
(`20260723_MONOTONE_OTF_CG_PLAN.md`).

**Measured consequence: `unknown_callee` tracks Steensgaard's verdict, not admission.**
Under default knobs `unknown_callee` and `fallback` agree on nearly every indirect-call row
of the 2026-08-23 corpus census — all 19,719 pre-fix, and 12,986 of 13,022 (99.7%) after
the constant-expression lowering fix. Both largely reduce to Steensgaard's unknown-callee
verdict: a site whose Steensgaard class reached an external region is activated eagerly over
its whole envelope and retains fallback provenance, and nothing in the default pipeline
clears the bit — Andersen narrowing the target set does not narrow the Ω marker.
`PANGS_ANDERSEN_DISABLE_EAGER_UNKNOWN=1` confirms the direction of the dependence: it
changes `fallback` substantially (`exe-tmux-O0` 42 → 18) and leaves `unknown_callee`
untouched at 42.

So the Ω population is not primarily an admission-budget or partition-scope effect — 39
oversize-fallback partitions were recorded corpus-wide against 12,583 Ω sites — it is
Steensgaard's boundary verdict carried through unchanged. The closed-producer certificate
below is the mechanism intended to clear it; see §4 for the measurement showing how little
it currently recovers.

**Finite field domain:**

A constant-offset GEP lazily materializes `(root_object, Exact(byte_offset))`. A GEP with
dynamic sequential indices materializes
`(root_object, Lane { modulus, residue })`, denoting offsets congruent to `residue` modulo
`modulus`; multiple dynamic strides compose with their greatest common divisor. Thus
`table[*].fn` and `table[*].used` remain separate when their member offsets occupy
disjoint lanes, while a constant element address aliases the appropriate lane. Each root
also has at most one fully unknown-offset summary, which aliases every materialized
location for that root; a whole-object access is likewise bridged to that summary, and
**materializes it when absent**. Both access families that bypass field cells — a direct
load/store through the object, and a bulk-copy endpoint — install that bridge, so an
aggregate copy delivers its contents to the destination's fields at whole-object
granularity. `PANGS_ANDERSEN_WHOLE_OBJECT_FIELD_BRIDGE` disables it (`0`) or selects one
family (`access`, `copy`) for ablation. Until 2026-08-24 the bridge fired only when a
dynamic GEP had already created the summary, so an object whose GEPs all had constant
offsets exchanged nothing between its root cell and its fields; the consequences are
recorded in [EXPERIMENT_HISTORY.md](EXPERIMENT_HISTORY.md).
Nested GEPs canonicalize to a root-relative exact offset or lane only when that location
occurs in the fixed PAG's finite location vocabulary. Other nested or recursive locations
route to the root's unknown summary rather than creating an unbounded field-of-field
chain. Receiver payload summaries reuse this same `Exact`/`Lane`/`Unknown`
`FieldLocation` domain; they do not introduce a second layout model.

C' uses the same exact/lane/unknown distinction for independently rooted GEPs. Its classes
are intentionally coarser than D's inclusion sets, but field contents no longer merge
their complete aggregate containers merely because corresponding fields exchange a value.

**Semi-naive constraint processing:**

For each canonical pointer variable `n`, the solver retains both its complete points-to
set `pts(n)` and the unpropagated addition `Δpts(n)`. Constraints likewise distinguish
established relations from newly installed relations:

- An established copy edge `n → p` consumes only `Δpts(n)`. A new copy edge is seeded
  once from the complete `pts(n)` before becoming established.
- Established loads, stores, and GEPs join only with `Δpts(n)`. A newly installed
  load/store/GEP joins once with the complete `pts(n)` and then becomes established.
  This full-set seed is required because on-the-fly call-target activation can add a
  constraint after `n` has otherwise reached quiescence.
- A `memcpy(dst, src)` remembers the destination and source objects it has already
  joined. Growth is processed as the two disjoint rectangles
  `new_dst × all_src` and `old_dst × new_src`, so each required object pair is visited
  once. The join relates *root objects*; the destination's field cells receive the
  contents through the whole-object summary bridge above, not through the join itself.

A bulk copy's prepartition endpoints are both synthetic storage regions, so — unlike every
other memory edge, which contributes a value node — its two address carriers are unioned
into that component explicitly. Without it the carriers' producers sit in an uninteresting
partition, are dropped from the admitted solve, and the copy is solved with an empty
endpoint set, which no amount of field modelling can repair.
`PANGS_ANDERSEN_MEMCPY_PREPARTITION_CARRIERS=0` restores the older behaviour for ablation.

The Andersen solver summarizes memcpy edges by default. Set
`PANGS_ANDERSEN_MEMCPY_EDGE_SUMMARIES=0` to restore the direct Cartesian join for
ablation. Each admitted memcpy receives a fresh propagation-only cell;
once both endpoint sets are nonempty, sources point to the summary and the summary points
to destinations. Logical endpoint sets remain explicit for closed-producer and
closed-consumer audits, and one-sided joins retain the direct rule's access guards. The
summary is never a pointee or allocation identity. Prepartitioning and its quadratic
admission proxy are unchanged, so the option can improve forced-solve economics but does
not admit a component rejected at the normal budget.

This changes scheduling, not the least fixed point. Every constraint/pointee pair that
the ordinary full-rescan worklist would evaluate is still evaluated: either when the
pointee first enters the owner's delta, or during the new-constraint full-set seed.
Facts and constraints are monotone, and deduplication can therefore discard repeated
evaluations without discarding a possible result.

Copy-SCC collapse needs one deliberate exception to the normal delta rule. Mutual copy
inclusion makes every member of a copy SCC have equal contents at the fixed point, so
the members can be represented by one canonical variable. The merge can, however,
place a constraint formerly owned by one member beside a pointee formerly known only
to another member. Those are new semantic join pairs even though neither input is
globally new. After a non-trivial collapse, the solver therefore:

1. unions the members' points-to facts and condenses the copy graph;
2. merges and deduplicates both established and pending load/store/GEP constraints;
3. marks all merged complex constraints pending and reseeds each affected
   representative from its complete state once; and
4. resumes ordinary delta propagation after that replay.

The conservative replay is what makes SCC collapse compatible with incremental joins;
replaying only the pre-collapse deltas would be an under-approximation. Profiling
counters separately record copy-fact, memcpy, load, store, and GEP pairs so a reduction
in Cartesian work can be distinguished from changes elsewhere in the pipeline.

### F. Clients as post-passes
With an exhaustive materialized solution, every client is a scan, not a query engine:

- **Call graph:** joint fixed-point edges; each icall edge tagged `B1-initval-exact`,
  `B2-simple-exact`, or `Andersen∩FSA`.
- **Mod/ref and writers:** direct accesses are syntactic; pointer-aware load/store,
  `memcpy`, and `memset` accesses expand through the materialized points-to relation.
  Before consulting that relation, an independent allocation-root certificate recognizes
  addresses derived from one global or local alloca through arbitrary-offset GEPs and
  same-root assignments. It settles only the storage root of that access: mixed-root
  joins, loads, calls, and integer conversions remain solver queries, and field contents
  still participate in pointer, escape, and indirect-call analysis.
  Rows distinguish direct, aliased, finite-unknown, and universal-unknown provenance.
  Transitive mod/ref closes over the final direct and indirect call graph. When a local
  or transitive expansion exceeds its configured high-fanout bound, the concrete rows
  collapse to an explicit conservative unknown row rather than being truncated.
  Aggregate-memory and other audit findings retain finite global-flow candidates when
  the solver proves them; violation relevance is then attributed to those candidates
  instead of poisoning unrelated globals. Universal or assumption-tainted flow remains
  module-wide.
- **Escape and immutability:** Ω bits from C'/D' are narrowed per allocation by an
  independent address-flow proof when Steensgaard has merged unrelated storage.
  Address isolation and write isolation are separate facts: a known runtime write does
  not by itself make the allocation's address externally reachable. Certified
  initializer/callback-table aggregate copies and allocation provenance may establish
  immutable contents without treating arbitrary runtime aggregate memory as precise.
- **Globals localization:** the one-`Context` rewrite graph from `DESIGN.md` §7 starts
  from functions containing runtime references that materialize a global's address or
  value, closes backward over their internal callers, and records the exact rewritten
  functions and call sites. This rewrite-root inventory is deliberately independent of
  mod/ref attribution: when a caller passes `&g` to a generic pointer-taking helper, the
  caller's expression is rewritten to `&ctx->g`; the helper neither needs a context
  parameter nor has to recover `g` as a singleton memory-effect target. LLVM lowering
  collects roots recursively through constant operands, while static initializer
  references remain a separate obligation. Ordinary outbound external calls do not
  connect or freeze the slice.
  Unknown incoming callers and unresolved alternative callees block only when they
  intersect a required signature rewrite. A global whose address is captured in a
  static aggregate initializer also blocks until source-level aggregate-initializer
  rewriting exists, because localization would replace its link-time-stable address
  with a runtime local address. Components remain diagnostics, not the eligibility gate.
- **Disposition:** the fact vector is routed by the policy stage in `DISPOSITION.md`.
  The default cascade selects the first independently applicable strategy among
  `immutable`, `once-lock`, `atomic`, `mutex`, and application-only `localize`, falling
  back to `unhandled` with accumulated witnesses. Coupling-group support, overrides,
  accepted-risk records, source-materialization recipes, and the marker inventory are
  emitted in the shared manifest. Violation taint gates the four access-property
  strategies. Localization may ignore hard `fnptr_varargs_internal_unmodeled`
  diagnostics when no other hard finding remains and its independent verdict is OK,
  under the supported-program contract in
  `20260818_LOCALIZATION_VIOLATION_TAINT_v3.md`. Localization consumes only globals
  assigned `localize`; the older mutability lattice is a reporting summary, not the
  strategy decision procedure.

Post-passes over one materialized result are also far easier to test than interleaved
demand queries: golden-file the whole solution on small inputs, diff across changes.

### Validation invariants

The transformation-facing result is guarded by checks at several independent levels:

- Debug refinement tripwires compare indirect-call results in the target lattice.
  With a finite coarse result they require
  `Andersen.targets ⊆ Steensgaard.targets ⊆ FSA`; with coarse `unknown_callee`,
  Steensgaard is top and a finite Andersen target absent from its diagnostic target list
  is legal. Exact B2 answers are checked against their envelopes separately.
- The temporary subtractive construction can run as a differential oracle for the
  monotone additive call-graph fixed point. Any additive target outside the descending
  result is a defect unless the descending row was unknown, in which case its omitted
  named targets are represented by top.
- Injected exhaustion tests abandon propagation, discovery, and activation at their
  quiet boundaries and require indirect calls, node resolutions, and global points-to
  facts to revert together. Independently proven exact sites remain exact.
- The `differential` command compares conservative, Steensgaard, and Andersen artifacts;
  emitted schemas are validated; LLVM callsite instrumentation plus `check-traces`
  detects dynamically observed callees absent from the static envelope.
- The synthetic receiver-container regression checks field matching, receiver separation,
  complete multi-origin rows, cap overflow, incomplete-origin propagation, and refinement
  of a coarse unknown call to a named target. Wrapper lifting, nested projections, and
  context-limit fallback belong in the same suite as the experiment graduates.

These checks are not precision certificates between production tiers. They are
soundness-regression tripwires around the one authoritative lite pipeline.

## 3. What is cut, and what each cut costs

| Cut | Complexity removed | Cost, per the papers |
|---|---|---|
| Tier E (CFL engine: grammar, MHS offset stacks, shortcuts, CastMap, memo caches, dependency-driven CG fixpoint) | The single largest component — KallGraph's core is 2.1K SLOC *on top of* SVF, and our version generalized it to a query algebra. Estimated ⅓–½ of total system complexity. | The ~20% icall residue that needed context-sensitivity stays at Andersen∩FSA precision. See §4 for why the coverage hit is likely small. |
| Per-tier certificate cascade | Settled/unsettled routing, certificate checks ×4, downward query flow | Some work D' does was provably unnecessary (already settled). At this scale, wasted solver-seconds; the routing logic cost more in complexity than it saved in compute. |
| Typed heap clones + conservatism dial | Back-propagation pass, clone⁄site duality, per-client mode switch | Heap objects coarser by type. Hurts heap-heavy alias precision; mutable-*globals* client is the least heap-dependent client we have. |
| KallGraph per-query parallelism | Read-only query pool, shared caches | None at this scale — `DESIGN.md` §1 already called it "overkill insurance" below 1 MLoC. Kahlon partitions leave a clean parallelization seam, but the current D' solve is sequential. |

**Not cut, anywhere:** Ω boundary model, int↔ptr violation detection → Ω-taint, FSA
envelope, KELP safe-fallback discipline, byte-offset field sensitivity. Bounded domains
always pair retained positive facts with an explicit incomplete/unknown bit and route
overflow to a conservative fallback. Soundness is the hard constraint, subject to the
explicit supported-program contracts below. One policy exception does not clear Ω or
violation taint: `localize` may filter the single internal-unmodeled-vararg finding kind
as specified in `20260818_LOCALIZATION_VIOLATION_TAINT_v3.md`.

For localization, the supported program must not invoke a callback after passing that
callback, directly or through an aggregate, as a variadic actual to an internal vararg
consumer whose consumption is unmodeled. Such a hidden invocation can retain the old ABI
after the callback's signature is context-threaded. The existing vararg Ω-seed → escape
→ `unknown_callers` → planner-blocker chain remains a regression guard, but it is not a
proof obligation for programs outside this contract.

`ptrtoint` validation is use-sensitive and fails closed. A raw integer address is exempt from the
Ω seed only when its complete SSA use graph terminates in supported comparisons, or when it is one
operand of a subtraction paired with another same-width `ptrtoint`. LLVM erases the distinction
between source-level pointer subtraction and subtraction of two explicitly integerized addresses.
Lite therefore adopts the supported-program contract that this paired shape represents ordinary C
pointer difference and is not being used to encode a callable address for reconstruction locally
or across an unanalyzed boundary. Under C's defined-execution semantics the former already implies
operands within one array object, so recovering a common allocation root in LLVM IR adds complexity
without strengthening the contract needed by the current points-to, mod/ref, call-graph, and
disposition clients. Mixed raw-address uses and unmatched conversions retain the normal violation
and Ω treatment. A narrower exception recognizes a literal `ptrtoint`/`inttoptr` SSA round trip as
an address-preserving assignment when the integer and pointer widths match, both conversions use
the same integral pointer address space, and every use of the intermediate integer is one of those
compatible reconstructions. The PAG then copies the original pointer into the reconstructed value
without either integer-conversion Ω seed. Missing target or conversion metadata, arithmetic,
integer storage, width or address-space changes, non-integral pointers, and externally sourced
integers all retain the fail-closed behavior. Function-pointer conversion findings are still
emitted when the preserved incoming pointer may actually denote a function; ordinary data-pointer
round trips do not acquire that label merely from the conversion syntax.

This contract has a narrow theoretical soundness hole: low-level code may deliberately compute a
relative function-address integer and later reconstruct and call the function, either locally or
after communicating the integer outside the analyzed module. Treating that subtraction as harmless
can hide an indirect callee or unknown incoming caller and thereby invalidate context-threading or
localization. Numeric layout leakage, address hashing, and other integer-only observations are
outside the supported clients and are not reasons to retain provenance recovery. Supporting
integer-encoded callbacks would require frontend/source semantics or reinstating a stricter
provenance-sensitive mode; bare LLVM `ptrtoint`/`sub` shape cannot distinguish the two idioms.

External calls remain Ω boundaries by default.  A small exact-name summary may replace
that boundary only when it encodes a documented, auditable pointer transfer; unlisted
or shape-mismatched calls remain Ω.

The inclusion solver represents Ω as provenance-separated abstract regions rather than
one absorbing object. Executable entry arguments, generic external storage, values written
through each client/external call boundary, external returns, unknown results, and
integer-forged pointers have distinct identities. Each region initially denotes itself;
ordinary copy/store/load/GEP constraints may add named allocations or other regions to its
contents. Merely passing unrelated pointer arguments to the same external call does not
equate those pointer values. This preserves every external origin while preventing argv,
external returns, and unrelated client addresses from aliasing solely because all crossed an
Ω boundary. Integer-forged pointers retain a separate universal marker and therefore never
narrow module-wide mod/ref.

Boundary seeding is build-mode aware. Executable mode treats `main` and its entry arguments
as the program boundary while retaining callbacks whose addresses flow to external code.
Library mode additionally treats exported functions as unknown-caller entries and exported
global addresses as externally reachable; an explicit export set overrides the defaults.

Finite pointee-class enumeration is additionally filtered by a per-global address-exposure bit.
A global is unexposed only when the storage-root proof accounts for every producer and every use of
its symbol or derived address. GEP and same-root-or-null local assignments may preserve the root;
direct load/store address operands (including the load/store representation of `atomicrmw` and
`cmpxchg`) consume it safely. The sole argument of a recognized standard `free` call is also a safe
terminal. `free` does not capture, publish, or propagate that address; under the defined-C contract,
an execution of `free(&global)` is undefined and need not be diagnosed or compensated for. Memcpy
and memset operands, mixed or cross-function joins, stores as a value, all other calls, returns,
`ptrtoint`, initializer capture, export, unsupported producers, and unknown operations expose every
root they can carry. Thus every admitted use of an unexposed global address is proven
non-capturing and non-publishing; class-unification side effects alone do not justify including the
global in a finite `pointee_globals` set. Universal external rows bypass the filter. Inline
assembly with modeled operands seeds Ω only from its pointer-capable operands and results, so
globals whose address-flow closure is disjoint remain filtered. Assembly that embeds symbol
references or otherwise has no bounded modeled storage operand records module-wide violation
exposure and bypasses the filter. When candidates are removed, `pointee_globals_unfiltered`
retains the original class envelope for differential checks.
Post-filter node resolutions also carry non-authoritative `pointee_provenance` diagnostics. The
solver accumulates whether the surviving class involved direct address flow, scalar/unknown
payload flow, by-value aggregate binding, memory merging, or call/return merging, then adds the
finite-external or universal-origin classification. High-fanout ModRef rows append these labels to
their detail string; unknown external rows do the same. When filtering changed the class envelope,
the detail also reports `prefilter_pointee_count` and `address_filtered_count`. The labels diagnose
where precision was lost; they are intentionally excluded from every soundness guard and
eligibility predicate.

Pointer payload is classified independently of ABI class. LLVM lowering records each stable PIR
value as proven non-pointer, pointer, pointer-bearing aggregate, or unknown; the PAG carries that
kind on value nodes. Assign/load/store and internal call/return constraints enter the pointer
solvers only when their payload may contain a pointer. The memory-access edge itself is retained
for scalar loads and stores, so ModRef and mutation clients do not lose the access. Aggregate SSA
carriers conservatively union their pointer-bearing fields while proven scalar fields contribute no
pointer constraint. Pointer-width integers loaded from memory, passed through ABI parameters, or
produced by calls and aggregate operations remain unknown because they may be ABI-coerced
aggregate carriers. Missing metadata, opaque aggregates, pointer vectors, external boundaries,
integer-forged pointers, and other type-punned cases likewise keep the conservative behavior.
Known direct `byval` calls use a fresh copy object plus a memory-payload copy instead of equating
the caller's aggregate address with the callee parameter. Indirect by-value bindings remain
conservative until a target-specific synthetic-copy representation is available.

## 4. The residual risk, named

The principal cut precision remains general tier-E context-sensitivity, which CORAL's
finding III says parameter-passed function pointers need. Receiver-relative payload
summaries recover one frequent object-sensitive container pattern, but do not distinguish
arbitrary calls, receiver state not expressible in the finite field domain, recursion,
or receivers without a certified allocation root.

This section previously argued the remaining coverage hit would be small, on two grounds:
that parameter-passed function pointers are Ω-frozen through external code regardless of
analysis precision, and that dispatch-table icalls settle at B1-InitVal plus the
array carve-out. **The 2026-08-23 corpus census
([`20260823_ICALL_AUDIT.md`](20260823_ICALL_AUDIT.md),
`metrics/icall_census/`) contradicts both.** Measured over the 32 `-O0` modules
(2,027 indirect callsites), classified by how the callsite's function-pointer operand is
produced:

| operand provenance | sites | share | Ω | finite |
|---|---:|---:|---:|---:|
| dispatch table (load from a global) | 1183 | 58.4% | 91.7% | 8.3% |
| receiver deref (`obj->handler`) | 362 | 17.9% | 100.0% | 0.0% |
| unclassified memory | 323 | 15.9% | 100.0% | 0.0% |
| parameter-passed | 118 | 5.8% | 44.9% | 55.1% |
| materialized `&f` in frame | 19 | 0.9% | 0.0% | 100.0% |

1. **Parameter-passed icalls are the best-resolved non-trivial class, not an Ω-frozen
   one.** 55% carry a finite target set. The qsort/signal/pthread shapes are real but
   are not what dominates this population; most parameter-passed function pointers on
   this corpus are internal wrappers. The old claim's *premise* was wrong, so its
   conclusion — that tier E could not have rescued them — is unsupported. The practical
   stake is nevertheless small, because the class is only 5.8% of sites.
2. **Dispatch tables dominate but do not settle.** They are 58% of sites and 92% of them
   remain Ω. B1-InitVal plus the array carve-out is not, in fact, sufficient for them.
   One observed failure mode is a `global_load` operand whose points-to set comes back
   with *no* function pointees at all, while a structurally similar site in the same
   function resolves — so this is a bounded, shape-dependent defect rather than a
   categorical limit.
3. **A third class the old text did not name: receiver deref.** `obj->handler` dispatch is
   the second-largest population (18%) and the worst resolved (0% finite). It has no
   dispatch table and no parameter-passed operand, so neither of the old arguments
   covered it. It is precisely the shape the receiver-allocation-relative payload
   summaries in §2 D′ target, which makes graduating that experiment — not tier E, and
   not typed heap clones — the indicated response.

Together the dispatch-table and receiver-deref classes are 76% of `-O0` sites and ~94% Ω
between them. Precision work that does not address those two is not addressing the
residue.

Two calibrations keep this from being read as a bigger indictment than it is.

**Not all Ω is avoidable.** A substantial share is correct conservatism that no precision
work should remove. `lib-parson` is 60/60 Ω because it holds
`static JSON_Malloc_Function parson_malloc = malloc;` behind an exported
`json_set_allocation_functions()`; in library mode that hook genuinely can hold any
caller-supplied function, so Ω is the right answer. Ω rate also varies with build mode and
with module mix far more than with any uniform property of the analysis. Any goal phrased
as "reduce Ω" therefore needs a denominator that first excludes justified Ω; otherwise it
rewards making a sound answer merely look better.

**The closed-producer certificate does not currently recover this.** It is the mechanism
designed to clear the retained unknown bit, and a spot check with
`PANGS_ANDERSEN_CLOSED_PRODUCERS=1` moved almost nothing: parson 60 Ω → 60, tree 19 → 17,
tmux 42 → 41, libusb and fribidi unchanged. Whether that reflects a limitation of the
prototype's bounded promotion, the aggregate-copy incompleteness rule, or the genuine
openness of these producers is unresolved. Graduating it on the strength of the
`unknown ≡ fallback` identity alone would be unwarranted.

The genuine exposure is `DESIGN.md` §11.4's mega-component risk: if the imprecise
residue merges load-bearing components, coverage collapses. Independent prepartitioning
and source-closed SCC slices reduce how much of such a component must be solved.
Receiver-relative payloads remove some generic-container bridges, while bounded origins
avoid importing the carrier's entire Steensgaard class through each bridge. Their risks
are precision loss at the explicit context/origin caps and additional work to admit
allocation-field support components; both are visible in profiling and fail closed.

Receiver payloads plus bounded origins reduced chibicc's dominant region and resolved its
macro-handler call, but added enough runtime to remain opt-in pending broader-corpus
validation. The measured counts and recovered targets are recorded in
[EXPERIMENT_HISTORY.md](EXPERIMENT_HISTORY.md).

Disposition inventory is source-actionable rather than identical to the solver's object
inventory. Compiler-generated unnamed compound-literal objects stay in the PAG and all
baseline semantic analyses. A literal uniquely referenced by one named global initializer
becomes a member of that global's storage closure: hazard/completeness facts fold into the
owner, and a transformation must handle the closure as a unit. Ownerless or shared
synthetic objects remain diagnostic records outside the actionable coverage denominator.
This is a client-layer ownership projection only; it does not remove objects or edges from
A′–D′.

## 5. Upgrade path (why the simplification is reversible)

Nothing in lite forecloses the full design:

- The frozen PAG **is** the graph tier E would traverse; A' omits only the CastMap,
  which can be built in a later pass without touching A'.
- Experimental field-insensitive and MHS field-sensitive callee-query kernels,
  dependency-tracked call-graph discovery, signature filtering, and bounded/truncated
  fallback already exist behind `pangs query`. They are prototypes, not soundness
  authorities. Promoting them would require production fallback assembly, validation
  against the Andersen/FSA envelopes, and integration with every downstream fact—not
  merely switching the call-graph exporter.
- B2-exact-first + FSA-filter-last is already the interface shape a demand tier slots
  behind: "refine this set of residual facts" — residual icalls, residual
  `writers()` targets — with lite's answers as the sound default when a query is not
  refined.
- Typed heap clones are an additive object-domain change: clones join the PAG alongside
  site objects (the full design's conservative mode), invisible to the solver loop.
- Receiver payload inference depends only on PAG value flow, root-relative byte
  locations, and function signatures. It does not inspect typed-pointer element types,
  so an LLVM 15+ front end can preserve the design by emitting the same finite layout
  vocabulary from DataLayout plus operation metadata. The bounded-origin pass is already
  pointer-type agnostic.

**Future upgrade gates:**
- Localization coverage on Vim/PHP acceptable to the client → ship lite, stop.
- Coverage limited by *dispatch-table icalls that do not resolve* (diagnosable: the
  operand is a load from a global and its points-to set is empty or Ω-marked) → this is
  the largest measured class (§4) and is a defect in existing machinery, not a missing
  tier. Fix before considering any tier upgrade.
- Coverage limited by *receiver-deref icalls* (diagnosable: the operand is a load through
  an object reachable from a formal parameter) → graduate the receiver-payload summaries
  of §2 D′; this is the second-largest measured class and the abstraction already exists.
- Coverage limited by *heap object conflation* (diagnosable: imprecise facts trace to
  multi-type allocation sites) → add typed clones, not tier E.
- Coverage limited by *context-insensitive icall residue merging components*
  (diagnosable: load-bearing FP edges trace to parameter-passed fn ptrs that are not
  Ω-frozen) → build tier E as the refinement pass, i.e., graduate to `DESIGN.md`.
  **The 2026-08-23 census does not currently support this gate**: parameter-passed
  operands are 5.8% of `-O0` sites and are already 55% resolved, so tier E is the
  lowest-yield of the four.

The provenance tags (§2F) are what make these diagnoses mechanical rather than
forensic: every coverage-blocking edge names the phase that produced it. The operand
provenance census (`pangs icall-census`) is the complementary instrument: the tags say
which phase produced an edge, the census says which *program shape* defeated it.
