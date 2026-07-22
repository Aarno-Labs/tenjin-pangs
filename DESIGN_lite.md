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
                 │      over interesting partitions; outer CG-refinement loop │
                 └──────────────┬─────────────────────────────────────────────┘
                                ▼
                 ┌────────────────────────────────────────────────────────────┐
                 │  F. Clients: post-passes over the materialized solution    │
                 └────────────────────────────────────────────────────────────┘
```

No tier E. No certificate checks between phases: B2's exact answers take precedence,
everything else reads D's solution, and FSA intersection is applied once as a final
soundness-preserving filter on icall results.

## 2. Phase details (deltas from `DESIGN.md` §4)

### A'. PAG construction
**Kept:** byte-offset Geps with lazy `(object, byte_off)` field materialization; the
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

**Conditional:** B3 (confined functions) falls out of B2 nearly for free; keep it iff it
remains a one-evening delta on B2's bookkeeping. Drop without regret otherwise.

### C'. Steensgaard, demoted to partitioner
Same lock-free union-find with type/signature compatibility filtering, but its *only*
jobs are (a) **Kahlon partitions** to scope D' (the reason exhaustive field-sensitive
Andersen doesn't OOM — CORAL's baselines did, at 128 GB, on OpenSSL-sized inputs), and
(b) the first wave of escape bits. It settles no queries and produces no certificates.
~200 lines.

### D'. The one real solver
Partition-scoped, inclusion-based, PIP internals (implicit-Ω constraint forms, sparse
bitmaps, no classic-optimization zoo — PIP measured that the representation wins beat
all of OVS/cycle-detection/difference-propagation at this granularity). Run **by
default on every interesting partition** (those reachable from client-relevant
pointers: icall operands, mutable globals and what they reach, escape-relevant
objects), not on a residue. Partitions solve independently across the core pool;
sequential cache-friendly worklist within.

**Call graph via outer-loop refinement** (replaces KallGraph's on-the-fly fixpoint with
dependency-driven re-analysis):

1. **Round 0 seed:** direct calls + (FSA ∩ Steensgaard) for icalls, minus B2-resolved
   icalls (exact) and B3-confined functions. Sound over-approximation by construction.
2. Solve all interesting partitions in parallel against this *fixed* call graph.
3. Recompute icall targets from solved fn-ptr pts; intersect with FSA. The graph
   shrinks monotonically and stays sound (round k's graph over-approximates ⇒ round
   k's pts over-approximate ⇒ round k+1's graph still over-approximates reality).
4. Re-solve; stop when the call graph stops shrinking. Expect 2–3 rounds.

Each round is **stateless** — no dependency tracking, no query re-analysis bookkeeping,
no memo caches. At ≤1 MLoC, re-running a parallel partition solve twice costs minutes.
That trade (redundant work for statelessness) is the heart of the lite design.

### F. Clients as post-passes
With an exhaustive materialized solution, every client is a scan, not a query engine:
- **Call graph:** final round's edges; each icall edge tagged `B2-exact` or
  `Andersen∩FSA` (two provenance tags instead of five tiers').
- **writers(o):** scan stores whose pointer pts includes `o` — the demand query becomes
  a table lookup. Mutability lattice (`never-written` → `stationary` (B1) →
  `thread-confined` → `shared`) computed in one pass.
- **Escape:** Ω bits from C'/D', narrowed per allocation by an independent address-flow proof
  when Steensgaard has merged unrelated storage. Address isolation and write isolation are
  separate certificates: a known runtime write does not by itself make the allocation's address
  externally reachable.
- **Globals localization:** unchanged from `DESIGN.md` §7 — transitive mod/ref over the
  final call graph, Ω-derived unknown-caller/callee taint, component verdicts.

Post-passes over one materialized result are also far easier to test than interleaved
demand queries: golden-file the whole solution on small inputs, diff across changes.

## 3. What is cut, and what each cut costs

| Cut | Complexity removed | Cost, per the papers |
|---|---|---|
| Tier E (CFL engine: grammar, MHS offset stacks, shortcuts, CastMap, memo caches, dependency-driven CG fixpoint) | The single largest component — KallGraph's core is 2.1K SLOC *on top of* SVF, and our version generalized it to a query algebra. Estimated ⅓–½ of total system complexity. | The ~20% icall residue that needed context-sensitivity stays at Andersen∩FSA precision. See §4 for why the coverage hit is likely small. |
| Per-tier certificate cascade | Settled/unsettled routing, certificate checks ×4, downward query flow | Some work D' does was provably unnecessary (already settled). At this scale, wasted solver-seconds; the routing logic cost more in complexity than it saved in compute. |
| Typed heap clones + conservatism dial | Back-propagation pass, clone⁄site duality, per-client mode switch | Heap objects coarser by type. Hurts heap-heavy alias precision; mutable-*globals* client is the least heap-dependent client we have. |
| KallGraph per-query parallelism | Read-only query pool, shared caches | None at this scale — `DESIGN.md` §1 already called it "overkill insurance" below 1 MLoC. Partition-level parallelism in D' remains. |

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
to measure — M1 on Vim answers it in days (see §6 gates).

## 5. Milestones

1. **M1 — sound end-to-end:** A' + C' + D' with the CG-refinement loop, Ω taint,
   violation detection, FSA filter. Correct (coarse) input for the localization client.
   Metric from day one: fraction of mutable globals localizable, plus the
   component-size distribution and which unknowns are load-bearing.
2. **M2 — the precision jump:** B1 + B2 (+B3 if trivial). Per KELP/CORAL this is the
   largest precision gain per engineering hour in either design.
3. **M3 — measure and decide:** coverage on Vim and PHP against the M3 gates below.

## 6. Upgrade path (why the simplification is reversible)

Nothing in lite forecloses the full design:

- The frozen PAG **is** the graph tier E would traverse; A' omits only the CastMap,
  which can be built in a later pass without touching A'.
- B2-exact-first + FSA-filter-last is already the interface shape a demand tier slots
  behind: "refine this set of residual facts" — residual icalls, residual
  `writers()` targets — with lite's answers as the sound default when a query is not
  refined.
- Typed heap clones are an additive object-domain change: clones join the PAG alongside
  site objects (the full design's conservative mode), invisible to the solver loop.

**Decision gates at M3:**
- Localization coverage on Vim/PHP acceptable to the client → ship lite, stop.
- Coverage limited by *heap object conflation* (diagnosable: imprecise facts trace to
  multi-type allocation sites) → add typed clones, not tier E.
- Coverage limited by *context-insensitive icall residue merging components*
  (diagnosable: load-bearing FP edges trace to parameter-passed fn ptrs that are not
  Ω-frozen) → build tier E as the refinement pass, i.e., graduate to `DESIGN.md`.

The provenance tags (§2F) are what make these diagnoses mechanical rather than
forensic: every coverage-blocking edge names the phase that produced it.
