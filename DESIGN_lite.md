# PANGS-lite: A Simplicity-First Alternative Design

*Companion to `DESIGN.md`. Same goals, clients, soundness posture, and scale target
(≤1 MLoC C); this document describes the design point that maximizes simplicity while
keeping the performance and coverage loss measurably small. The two documents share
terminology — read `DESIGN.md` §1–2 first for goals, paper sources, and the
FN-corruption/FP-coverage asymmetry that licenses everything cut here.*

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
recoverable later behind a stable interface (§6 below).

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
                 │  C'. Steensgaard — partitions + first escape bits ONLY     │
                 └──────────────┬─────────────────────────────────────────────┘
                                ▼
                 ┌────────────────────────────────────────────────────────────┐
                 │  D'. Partition-scoped Andersen (PIP internals), exhaustive │
                 │      over admitted interesting partitions; joint CG LFP    │
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
soundness-preserving filter on icall results.

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
byte/string search routines such as `strchr`. A name match with the wrong call shape is not
a proof: unlisted or mismatched calls retain the normal Ω effects. Known positional
variadic bindings are modeled only when the callee's consumption is visible; otherwise
function-pointer actuals and other pointer-bearing tail arguments fail closed.

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
- **B2 simple pointers (KELP).** ~⅓ of icalls resolved exactly, for free, with regional
  SSA walks. Safe fallback discipline unchanged.

**Kept:** B3 confined-function subtraction falls out of B2's bookkeeping. Functions whose
every address flow was consumed by an exact simple chain are removed from non-exact
candidate envelopes, while an exact B2 binding to such a function remains pinned.

B1 now emits more than an initializer target set. Its production certificate records the
publication boundary, initialization subtree and writers, readers/observations, and
decisive failure evidence. Static initializer stores are not runtime writers. Absence-only
initialization may therefore be stationary, while thread writers, signal reachability,
recursion, `atexit`, unresolved effects, or a post-publication write fail closed. This
certificate is fact input to disposition, not a terminal strategy decision.

### C'. Steensgaard, demoted to partitioner
A sequential numeric-ID union-find with type/signature compatibility filtering. Its
*only* jobs are (a) **Kahlon partitions** to scope D' (the reason exhaustive
field-sensitive Andersen doesn't OOM — CORAL's baselines did, at 128 GB, on
OpenSSL-sized inputs), (b) the first wave of escape bits, and (c) the complete base-tier
answer used wherever D' cannot refine. It settles no query by certificate.

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
base-address partition to be co-admitted.

### D'. The one real solver
Partition-scoped, inclusion-based, PIP internals (implicit-Ω constraint forms and
per-variable points-to sets). Every interesting partition (one reachable from
client-relevant pointers: icall operands, mutable globals and what they reach, or
escape-relevant objects) is considered without certificate-residue routing; the admission
policy below decides whether Andersen or the Steensgaard fallback supplies its answer.
The current implementation runs admitted partitions in one sequential solve;
partition-level parallelism remains a clean future seam because Kahlon partitions are
flow-closed. The implementation keeps the optimization surface narrow, but profiles of
dense promoted partitions
justified two general mechanisms: semi-naive constraint joins and threshold-triggered
collapse of strongly connected copy variables.

**Partition admission and fallback:**

Steensgaard supplies the complete base-tier answer for every partition. An interesting
partition is admitted to Andersen when its quadratic cost proxy fits the configured
budget. An oversize partition remains at its Steensgaard answer, and the result records
the number and largest size of such fallbacks. Provenance separation also permits a
bounded promotion: a sparse, medium-sized partition that exceeds the old cost proxy may
still be admitted when its node and edge counts fit fixed caps and it contains no
integer-forged/universal external source. Larger or forged partitions retain the ordinary
fallback. Complete Andersen facts overwrite only admitted partitions, so omission by the
refiner is conservative.

**Call graph via monotone on-the-fly discovery:**

1. Build one persistent solve from base PAG constraints, Ω seeds, and pinned B1/B2
   exact bindings.
2. Propagate to quiescence, then discover function objects reaching each non-exact
   icall operand within its `FSA ∩ Steensgaard` envelope.
3. Install each newly grounded argument/parameter and return/result binding once, using
   copy-edge delta propagation to seed the edge from the source's existing facts.
4. Resume the same solve until both propagation and target discovery are quiescent.

Unknown-origin operands retain conservative Steensgaard fallback provenance and activate
the remaining envelope when the origin may denote client code. A resource limit cannot
emit a partial ascending solve: the entire Andersen tier falls back to the complete
Steensgaard result, while independently proven exact callsite answers survive. The old
stateless descending construction remains only as a temporary differential oracle during
the migration (`20260723_MONOTONE_OTF_CG_PLAN.md`).

**Finite field domain:**

A constant-offset GEP lazily materializes `(root_object, Exact(byte_offset))`. A GEP with
dynamic sequential indices materializes
`(root_object, Lane { modulus, residue })`, denoting offsets congruent to `residue` modulo
`modulus`; multiple dynamic strides compose with their greatest common divisor. Thus
`table[*].fn` and `table[*].used` remain separate when their member offsets occupy
disjoint lanes, while a constant element address aliases the appropriate lane. Each root
also has at most one fully unknown-offset summary, which aliases every materialized
location for that root; a direct whole-object access is likewise bridged to that summary.
Nested GEPs canonicalize to a root-relative exact offset or lane only when that location
occurs in the fixed PAG's finite location vocabulary. Other nested or recursive locations
route to the root's unknown summary rather than creating an unbounded field-of-field
chain.

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
  once.

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

- **Call graph:** joint fixed-point edges; each icall edge tagged `B2-exact` or
  `Andersen∩FSA` (two provenance tags instead of five tiers').
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
- **Globals localization:** the one-`Context` rewrite graph from `DESIGN.md` §7 closes
  backward over internal callers of accessors and records the exact rewritten functions
  and call sites. Ordinary outbound external calls do not connect or freeze the slice.
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
  emitted in the shared manifest. Violation taint gates every strategy unless an
  explicit accepted-risk override is recorded. Localization consumes only globals assigned
  `localize`; the older mutability lattice is a reporting summary, not the strategy
  decision procedure.

Post-passes over one materialized result are also far easier to test than interleaved
demand queries: golden-file the whole solution on small inputs, diff across changes.

### Validation invariants

The transformation-facing result is guarded by checks at several independent levels:

- Debug subset tripwires require `Andersen ⊆ Steensgaard ⊆ FSA` at every narrowed
  indirect-call site; exact B2 answers are checked against their envelopes separately.
- The temporary subtractive construction can run as a differential oracle for the
  monotone additive call-graph fixed point. Any additive target outside the descending
  result is a defect.
- Injected exhaustion tests abandon propagation, discovery, and activation at their
  quiet boundaries and require indirect calls, node resolutions, and global points-to
  facts to revert together. Independently proven exact sites remain exact.
- The `differential` command compares conservative, Steensgaard, and Andersen artifacts;
  emitted schemas are validated; LLVM callsite instrumentation plus `check-traces`
  detects dynamically observed callees absent from the static envelope.

These checks are not precision certificates between production tiers. They are
soundness-regression tripwires around the one authoritative lite pipeline.

## 3. What is cut, and what each cut costs

| Cut | Complexity removed | Cost, per the papers |
|---|---|---|
| Tier E (CFL engine: grammar, MHS offset stacks, shortcuts, CastMap, memo caches, dependency-driven CG fixpoint) | The single largest component — KallGraph's core is 2.1K SLOC *on top of* SVF, and our version generalized it to a query algebra. Estimated ⅓–½ of total system complexity. | The ~20% icall residue that needed context-sensitivity stays at Andersen∩FSA precision. See §4 for why the coverage hit is likely small. |
| Per-tier certificate cascade | Settled/unsettled routing, certificate checks ×4, downward query flow | Some work D' does was provably unnecessary (already settled). At this scale, wasted solver-seconds; the routing logic cost more in complexity than it saved in compute. |
| Typed heap clones + conservatism dial | Back-propagation pass, clone⁄site duality, per-client mode switch | Heap objects coarser by type. Hurts heap-heavy alias precision; mutable-*globals* client is the least heap-dependent client we have. |
| KallGraph per-query parallelism | Read-only query pool, shared caches | None at this scale — `DESIGN.md` §1 already called it "overkill insurance" below 1 MLoC. Kahlon partitions leave a clean parallelization seam, but the current D' solve is sequential. |

**Not cut, anywhere:** Ω boundary model, int↔ptr provenance rules, violation
detection → Ω-taint, FSA envelope, KELP safe-fallback discipline, byte-offset field
sensitivity. Soundness is the hard constraint and is untouched.

`ptrtoint` validation is use-sensitive and fails closed. A raw integer address is exempt from the
Ω seed only when its complete SSA use graph terminates in supported comparisons, or when it is one
operand of a paired subtraction whose source pointers have exactly one common structural
provenance root. The latter produces a relocation-invariant relative offset: translating the
common allocation changes both operands equally and leaves their modular difference unchanged, so
the offset may subsequently be stored, returned, or passed through integer wrappers. Distinct or
unknown roots, mixed raw-address uses, arbitrary memory-loaded pointer provenance, and unmatched
conversions retain the normal violation and Ω treatment. This proof is isolated in the PIR LLVM
front end's pointer-integer-use module rather than distributed through individual clients.

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
A global is unexposed only when every modeled use of its symbol is the address operand of a direct
load/store (including the load/store representation of `atomicrmw` and `cmpxchg`); GEPs, address
copies, stores as a value, calls, returns, `ptrtoint`, initializer capture, export, and unknown
operations all expose it. An unexposed object cannot be the target of another pointer because its
address never exists as a program value, so class-unification side effects alone do not justify
including it in a finite `pointee_globals` set. Universal external rows bypass the filter, as do
modules containing inline assembly without a complete value-flow certificate. When candidates are
removed, `pointee_globals_unfiltered` retains the original class envelope for differential checks.
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

The cut precision is tier-E context-sensitivity, which CORAL's finding III says
parameter-passed function pointers need. Two reasons to expect a small coverage hit
*for this client*:

1. The canonical parameter-passed cases — qsort comparators, signal handlers,
   pthread_create thunks — pass through **external code and are Ω-frozen regardless of
   analysis precision.** Tier E could not have rescued them either.
2. The icalls that shape the localization client's component structure are **dispatch
   tables** (PHP opcode handlers, Vim command tables), and those settle at
   B1-InitVal + array-carve-out level, which lite keeps.

The genuine exposure is `DESIGN.md` §11.4's mega-component risk: if the imprecise
residue merges load-bearing components, coverage collapses. This is empirical and cheap
to measure through corpus coverage, component/rewrite-slice size, and the provenance of
the false edges that are load-bearing.

## 5. Historical milestones and current status

1. **M1 — sound end-to-end (landed):** A' + C' + D' with joint CG discovery, Ω taint,
   violation detection, FSA filter. Correct (coarse) input for the localization client.
   Metric from day one: fraction of mutable globals localizable, plus the
   component-size distribution and which unknowns are load-bearing.
2. **M2 — the precision jump (landed):** B1 + B2 + B3, including stationarity,
   exact/simple bindings, confined subtraction, finite field summaries, and the
   narrowing ledgers.
3. **M3 — measure and decide (lite selected):** corpus measurements kept Andersen as
   the authoritative final tier. CFL/MHS query kernels were implemented as experimental
   diagnostics and then deliberately left disconnected from production results.

## 6. Upgrade path (why the simplification is reversible)

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

**Future upgrade gates:**
- Localization coverage on Vim/PHP acceptable to the client → ship lite, stop.
- Coverage limited by *heap object conflation* (diagnosable: imprecise facts trace to
  multi-type allocation sites) → add typed clones, not tier E.
- Coverage limited by *context-insensitive icall residue merging components*
  (diagnosable: load-bearing FP edges trace to parameter-passed fn ptrs that are not
  Ω-frozen) → build tier E as the refinement pass, i.e., graduate to `DESIGN.md`.

The provenance tags (§2F) are what make these diagnoses mechanical rather than
forensic: every coverage-blocking edge names the phase that produced it.
