# PANGS: A Scalable Hybrid Pointer Analysis & Call Graph Module for LLVM IR

*Design proposal synthesizing cclyzer (SAS'16), KallGraph (S&P'25), KELP (USENIX Sec'24),
CORAL (OOPSLA'23), PIP (2026), and Canary (Cai dissertation ch. 4).
Per-paper reading notes live in `notes/`.*

## 1. Goals and constraints

**Clients.** Call graph (incl. indirect calls), variable/object **mutability**, and
**escape status**, over LLVM IR (C code only), feeding automated C→safe-Rust conversion.
The **primary client today** is a source-to-source refactoring that *localizes mutable
globals*: it threads a context struct through every caller→callee chain that transitively
accesses mutable globals, rewriting call sites and callees in unison (see §7).

**Requirements distilled from the conversation:**
1. Scale far beyond the current cclyzer-based Datalog analysis (which is precise but
   exhaustive and single-strand). Target envelope: **~1 MLoC codebases** (Vim ≈ 500 KLoC
   good, PHP ≈ 1 MLoC great). The Linux kernel is explicitly out of scope.
2. Constant-factor scalability from parallelism on large-ish core counts (KallGraph-style).
3. Algorithmic efficiency gains, not just parallelism (staging, demand-drivenness,
   bootstrapping, summaries).
4. No Soufflé. Implementation in Rust; Datalog only if a Rust-native engine actually
   parallelizes (see §8).
5. Soundness posture appropriate for *transformation*: for the globals-localization
   client, **false-positive edges only reduce refactoring coverage (safe), while
   false-negative edges corrupt translated code (unacceptable, and often silently)** —
   precision buys coverage, soundness is the hard constraint. §7 develops this and the
   "would soundiness suffice?" question.
6. No incrementality requirement. Mutability has a cheap conservative fallback answer, so
   the mutability client is precision-opportunistic, not correctness-critical.

**Scale note.** The ≤1 MLoC target sits exactly in the range the papers measured: CORAL
analyzed Vim (416 KLoC) in ~15 min and PHP (1.3 MLoC) in ~66 min *sequentially*; KELP's
cheap stages run in seconds there; KallGraph-style parallel queries are overkill insurance
at this size. Two consequences: (a) the tiered design below should land comfortably in
single-digit minutes on a many-core box, leaving precision headroom; (b) tiers are kept
anyway — not for survival but because the certificates they produce are what lets us
*trust* edges (§7) — however tier D (partitioned Andersen) likely graduates from "optional
relief valve" to "affordable default", since at this scale even sequential CORAL ran it on
every program. Caution: exhaustive *field-sensitive* Andersen still OOM'd (128 GB) on
OpenSSL-sized programs in CORAL's baselines, so "1 MLoC is small" does not mean the naive
approach works; the staging still carries its weight.

**Why the current approach hits a wall.** cclyzer's precision comes from a *huge* abstract
object domain (typed heap clones × recursive field subobjects × array indices) joined
exhaustively by global inclusion rules. Datalog evaluates this bottom-up for *all* pointers
at uniform precision. Both CORAL and KELP measured the core fact motivating a redesign:
**most pointers don't need the expensive treatment, and the expensive machinery should only
ever see the residue.** Meanwhile KallGraph showed the other half: exhaustive solvers have
interleaved read/write phases that parallelize poorly (consistent with Soufflé's failure to
parallelize the extended analysis), whereas **demand-driven queries over a read-only graph
parallelize embarrassingly**.

## 2. What each paper contributes to the hybrid

| Source | What we take | What we deliberately drop |
|---|---|---|
| cclyzer | Object abstraction: typed abstract objects, allocation-site+type heap cloning (use-based back-propagation for malloc wrappers), field subobjects, vtable/array-index precision *where types are known* | Global exhaustive Datalog solving; eager materialization of all subobjects |
| KallGraph | Read-only program assignment graph (PAG) + parallel per-query demand-driven CFL-reachability; byte-offset Gep model with cumulative-offset stack; object-level minimal CastMap; on-the-fly call-graph fixpoint with dependency-driven re-analysis | Strict array-insensitivity (we make it configurable); SVF dependency |
| KELP | Simple/complex pointer dichotomy via regional SSA def-use tracking; **confined-function subtraction** shrinking the candidate space of the fallback analysis; safe-fallback discipline | Type-analysis (MLTA) as the final fallback — we fall back to FSA-filtered demand queries instead |
| CORAL | The cocktail: Stage-0 init-value pre-analysis; **result-oriented precision certificates** (pts ⊆ InitVal ∨ singleton); Steensgaard→Andersen bootstrapping over Kahlon partitions; expensive analysis only for the residue; **stationary = immutable-after-init**, which is directly one of our outputs | Sequential implementation; SUPA stage III (we use KallGraph-style queries instead) |
| PIP | Ω-node model of external/escaped memory with **implicit (bit-flag) representation**; sound incomplete-program handling; provenance-correct ptrtoint/inttoptr; escape computed *inside* the fixpoint for ~free | Field-insensitivity; per-file-only scope (we use Ω at whole-program boundary *and* optionally per-module) |
| Canary | Bottom-up compositional construction of a sparse value-flow graph with per-function transfer summaries; escape-set (EspObj/Pted) fixpoint interleaved with edge discovery; lazy guard recording | SMT path-sensitivity and concurrency machinery (phase-2 option, not core) |

Three **synergies** make this more than a pile of parts:

- **S1 (CORAL × mutability client).** CORAL's stationarity check exists to certify icall
  precision — but "object/field unchanged after initialization" is *literally the
  immutability fact* the C→Rust converter needs to choose `&T` vs `&mut T`. One Stage-0
  pre-analysis feeds both the call-graph pipeline and the mutability output.
- **S2 (PIP × escape client).** PIP's escaped-bit (`Ω ⊒ {x}`) exists for soundness under
  incompleteness — but it *is* the escape-status output, computed as a monotone bit during
  constraint solving. Monotone bits are also trivially thread-safe (idempotent OR), which
  matters for the parallel solver. PIP's int↔ptr handling also closes the exact
  ptrtoint/inttoptr soundness hole KallGraph reported.
- **S3 (Steensgaard partitions × demand queries).** CORAL uses Kahlon partitions to scope
  Andersen runs; KallGraph runs unscoped global CFL queries. Combining them: each demand
  query's traversal can be confined to the (usually small) union of partitions touching the
  query's variables — an *algorithmic* bound on per-query work, multiplied by KallGraph's
  per-query parallelism.

## 3. Architecture overview

```
                 ┌────────────────────────────────────────────────────────────┐
                 │  A. PAG construction (parallel per function/module)        │
  LLVM IR ──────▶│  partial SSA · byte-offset Gep · typed objects ·           │
                 │  heap-clone back-propagation · Ω boundary · CastMap        │
                 └──────────────┬─────────────────────────────────────────────┘
                                ▼   (graph frozen: read-only from here on)
                 ┌────────────────────────────────────────────────────────────┐
                 │  B. Stage-0 pre-analyses (parallel, all cheap & regional)  │
                 │  B1 init-value tracking (InitVal per object·field)         │
                 │  B2 simple/complex pointer classification (KELP)           │
                 │  B3 confined-function set                                  │
                 └──────────────┬─────────────────────────────────────────────┘
                                ▼
                 ┌────────────────────────────────────────────────────────────┐
                 │  C. Tier-1 global solve: parallel Steensgaard + Ω flags    │
                 │  → partitions, cheap pts, escape bits, certificates        │
                 └──────────────┬─────────────────────────────────────────────┘
                                ▼ residue only
                 ┌────────────────────────────────────────────────────────────┐
                 │  D. Tier-2: partition-scoped Andersen (parallel partitions)│
                 │  inclusion-based, PIP implicit-Ω, certificates again       │
                 └──────────────┬─────────────────────────────────────────────┘
                                ▼ residue only
                 ┌────────────────────────────────────────────────────────────┐
                 │  E. Tier-3: demand-driven CFL queries (parallel per query) │
                 │  on-the-fly CG fixpoint w/ dependency re-analysis          │
                 └──────────────┬─────────────────────────────────────────────┘
                                ▼
                 ┌────────────────────────────────────────────────────────────┐
                 │  F. Clients: call graph · mutability · escape · (aliases)  │
                 └────────────────────────────────────────────────────────────┘
```

Every tier ends with the same **certificate check** (CORAL): a query (icall, object
mutability, escape fact) is *settled* at tier *k* if the tier-*k* answer is provably as
precise as any later tier could be (singleton, ⊆ InitVal, or no-write-found). Only
unsettled queries flow downward. Expected volume, calibrated by the papers' measurements:
B2 settles ~35% of icalls exactly (KELP), C settles ~55% of the rest (CORAL I₁), D another
~25% (CORAL I₂), leaving <20% for the expensive tier E — which is itself parallel.

## 4. Phase details

### A. PAG construction
- One pass over bitcode (after `mem2reg`); functions processed in parallel; results
  appended to per-shard arenas, then frozen. Node kinds: SSA values, abstract objects,
  Gep nodes. Edge kinds: `Assign`, `Store`, `Load`, `Gep{byte_off | unknown}`,
  call/return placeholders (resolved on the fly in tier E / iterated in C–D).
- **Object abstraction (cclyzer, adapted):** globals/functions, stack allocs (typed),
  heap allocs per site; *typed heap clones* `o_{i,T}` created by use-based back-propagation
  at casts — but, following KallGraph's minimal-CastMap insight, only for *non-trivial*
  casts (a cheap local look-ahead filters the `void*` round-trips through memcpy-like code).
  Field addressing uses **byte offsets** (KallGraph: robust across LLVM's struct flattening,
  unions, anonymous structs) rather than eagerly materialized subobject nodes; field
  subobjects are materialized lazily, keyed `(object, byte_off)`, only when something
  addresses them. Array handling: `o[c]`/`o[*]` distinction (cclyzer) **enabled only for
  constant-indexed fixed-size arrays of function pointers** — C dispatch tables, common in
  exactly our target programs (PHP opcode handlers, Vim command tables) — **monolithic
  otherwise** (CORAL found this is where it pays; KallGraph found full array sensitivity
  unnecessary even for kernels). C++/vtable machinery from cclyzer is dropped entirely.
- **Boundary model (PIP):** exported/imported symbols seed Ω; external calls, escaped
  function params, ptrtoint/inttoptr wired per PIP's rules. Ω is implicit from day one:
  two bits per node, `points-to-external` and `escaped`.
- **Call/return-site filtering (TeaDSA, FMCAD'19):** when wiring call-argument and
  return-value edges, filter facts by *instruction-local* validity — cheap SSA def-use
  reasoning (the same flavor as B2) decides whether a fact can hold *at that call/return
  instruction*, rather than exporting the function-level summary wholesale. TeaDSA showed
  most interprocedural precision loss in flow-insensitive analyses is local imprecision
  leaking through call/return edges; filtering there bought up to 25% fewer aliases at
  negligible cost. Since the filter is applied at edge generation, the precision is baked
  into the frozen PAG and benefits every downstream tier (C, D, and E) for free.

### B. Stage-0 pre-analyses (all regional/sparse, all parallel)
- **B1 InitVal (CORAL Stage Zero):** forward def-use tracking of each newly created object
  during its initialization phase (until its reference is stored into another object),
  field-sensitive, context-sensitive via CFL parens. Output: `InitVal(o, fld) ⊆ Funcs`
  for function-pointer fields, and more generally `InitStores(o, fld)` for *all* fields —
  the generalization is what makes B1 double as the immutability pre-analysis (S1).
  Cost in CORAL: ~1.5 min / 718 KLoC, 4.2% of total.
- **B2 simple-pointer classification (KELP):** backward+forward SSA def-use tracking per
  icall (and, generalized, per interesting pointer). Anything whose value passes through a
  `Load` or escapes into memory read elsewhere is *complex*; the rest are resolved exactly,
  now, for free. Safe fallback on asm/dlopen/unknown flows.
- **B3 confined functions (KELP):** address-taken functions whose every address-taken site
  was consumed by B2-resolved simple chains can never appear at complex icalls — subtract
  them from every later candidate set (and from FSA filters in tier E).

### C. Tier-1: parallel Steensgaard with Ω
- Unification over the frozen PAG: lock-free union-find (path-halving + rank CAS — standard
  concurrent disjoint-set), edges processed by a sharded work-stealing pool. Near-linear,
  embarrassingly parallel, gives:
  - cheap points-to for the certificate check (settles stationary-field icalls, CORAL I₁);
  - **Kahlon partitions** for tier D scoping and tier E search-space bounds (S3);
  - first wave of escape bits (anything unified into an Ω-reaching class).
- Function-signature compatibility filtering during unification (CORAL does this) prevents
  the classic Steensgaard collapse from polluting fn-ptr classes.

### D. Tier-2: partition-scoped Andersen
- For each *interesting* partition (those containing unsettled queries' variables), run an
  inclusion-based worklist solver **restricted to the partition's constraints** plus the
  pointers above it in the Steensgaard hierarchy (Kahlon bootstrapping; CORAL measured ~⅓
  of program statements touched, total). Partitions are independent → run them across the
  core pool; within a partition, the solver is the classic sequential worklist (small, cache-friendly).
- Solver internals take PIP wholesale: implicit-Ω constraint forms, PIP doubled-up-pointee
  avoidance, sparse-bitmap pts sets. (PIP's measurement that IP+PIP beats every classic
  solver optimization — OVS, cycle-detection variants, difference propagation — at this
  granularity tells us not to over-engineer the solver.)
- Certificates re-checked; escape/mutability facts upgraded; remaining residue → tier E.

### E. Tier-3: demand-driven CFL-reachability queries
- KallGraph's machinery, generalized from "icall resolution" to a small query algebra over
  the same grammar (their final rules, Appendix A):
  - **callees(icall)** / **callsites(fn)** — forward F-reachability from a function's
    address node (their direction: per address-taken function, which both bounds work and
    parallelizes by the numerous side);
  - **writers(o[, byte-range])** — alias closure of `o`'s address, collecting `Store`s:
    this is the *mutability* query for objects unsettled by B1/C/D;
  - **escapes(o)** — alias closure intersected with Ω-flagged sinks / fork-passed values
    (Canary's EspObj rule for the thread dimension, PIP's Ω for the module dimension).
- Implementation notes lifted from KallGraph: cumulative byte-offset stack (MHS) instead of
  paired Geps; object-level CastMap (built minimal in phase A); type-based `Shortcut` edges
  to skip long store/load chains soundly; FSA as a *final intersection filter* on icall
  results (they note demand answers can exceed FSA; intersecting is free soundness-preserving
  precision). **New here:** traversals carry the partition bound from S3 — a visited-set
  scoped to the query's partition union, typically far smaller than the global PAG.
- **On-the-fly call graph fixpoint (KallGraph §5.4):** start from the direct-call graph +
  tiers B–D settled icalls; iterate queries, tracking `DepiCalls[f]`/`DepFuncs[f]`; re-run
  only queries whose dependent icalls gained targets. Converges in a handful of rounds.
- Parallelism: queries are independent jobs over the read-only PAG (<30 MB/thread working
  state in KallGraph); per-query memoized summaries (visited node→state caches) are shared
  via a concurrent map as a *cache*, not a correctness dependency.

### F. Clients
- **Call graph:** union of tier-settled results, every edge tagged with the tier that
  settled it (useful for downstream confidence and for debugging precision regressions).
- **Globals-localization support** (primary client; full treatment in §7): per-function
  transitive mod/ref of mutable globals; the caller↔callee bipartite graph with
  unknown-caller/unknown-callee nodes derived from Ω facts; component taint verdicts.
- **Mutability**, per object/field (and derived per C variable):
  1. `never-written` (no store reaches it at all) → `const`/immutable;
  2. `stationary` (writes ⊆ initialization phase, B1 certificate) → immutable-after-init →
     Rust `&T` after construction, or `Box::new(...)`-then-freeze patterns;
  3. `thread-confined mutable` (writers exist but object never escapes its thread/frame) →
     `&mut T` / owned;
  4. `shared mutable` (residue) → `Cell/RefCell/Mutex` candidates.
  Tiers C–E only ever *refine* a fact downward in this lattice. Since mutability has a
  cheap conservative fallback, every tier of this client is opportunistic — but note the
  payoff specific to the localization client: a **stationary global** (B1 certificate)
  needs no localization at all (it is a legal immutable `static` in Rust after init, or a
  candidate for `const`-ification), shrinking both the context struct and the rewrite set.
- **Escape**, per object: `frame-local` / `escapes-to-heap-or-caller` (address outlives
  frame) / `escapes-module` (Ω bit) / `escapes-thread` (EspObj-style, if/when concurrency
  matters). The first two drive Rust ownership placement; the bits come from C/D for free,
  with tier-E queries for the precision-critical residue.

## 5. Parallelism strategy (cross-cutting)

| Phase | Unit of parallelism | Coordination |
|---|---|---|
| A | function / module | append-only sharded arenas; freeze barrier |
| B1–B3 | object (B1), icall/pointer (B2), function (B3) | read-only PAG; results into concurrent maps |
| C | edge batches | lock-free union-find (CAS) |
| D | partition | none between partitions; sequential within |
| E | query | read-only PAG; shared memo cache (best-effort); per-round barrier for CG fixpoint |

Two principles, both validated by the papers: (1) **all heavy phases read a frozen graph
and write only thread-local or monotone state** — this is precisely what KallGraph
identifies as the reason exhaustive frameworks don't parallelize and demand-driven ones do;
(2) **monotone bit facts (escape, points-to-external) commute**, so they need no locking
discipline at all.

This also explains the Soufflé failure in retrospect, without needing to autopsy it:
semi-naive evaluation parallelizes *within* a rule's delta, but the structure-sensitive
rule set has long chains of small mutually recursive deltas (object creation → type
propagation → subobject creation → more points-to → more objects), serializing on
stratum/iteration barriers with tiny per-iteration work. The design above has no analogous
global iteration: tiers C–D iterate locally, tier E iterates only the small CG-fixpoint
outer loop.

## 6. Precision configuration (what sensitivity, where)

- **Field sensitivity:** everywhere, via byte offsets (KallGraph model + cclyzer's typed
  filtering at subobject materialization). This is non-negotiable for mutability — per-field
  `&`/`&mut` decisions are the payoff.
- **Flow sensitivity:** *not* in the global tiers (CORAL's empirical case: stationary
  pointers make it mostly redundant) — but B1 is flow-sensitive within initialization
  phases, and SSA gives flow-sensitivity for top-level values for free. Optional phase-2:
  Canary-style per-function flow-sensitive summaries with strong updates as an upgrade of
  tier D (see §9).
- **Context sensitivity:** CFL call-string matching inside B1/B2 and tier-E traversals
  (valid-paren paths), i.e., context-sensitive *where the question is asked*, never as a
  global k-CFA blowup. CORAL's finding III says parameter-passed fn ptrs need this; their
  stage-III analog is exactly our tier E.
- **Heap cloning:** allocation-site + type (cclyzer back-propagation) but minimal-CastMap-
  filtered. No deep context-sensitive heap cloning in v1.

## 7. Primary client: localization of mutable globals

**The client's model.** A bipartite caller↔callee graph with designated *unknown-caller*
and *unknown-callee* nodes. Rewriting a function's signature (to accept the context
struct) requires rewriting every call site in unison; therefore any connected component
that touches an unknown node is frozen — we cannot edit call sites in third-party code,
and we must not change the ABI of function pointers that flow to unknown call sites.

**What the analysis must supply**, in order of correctness-criticality:

1. **Sound icall edges within the program** (FN here is the silent killer: a missed icall
   edge means the callee's signature changes while that call site keeps the old ABI — a
   miscompile, not a compile error; missed *direct* edges at least fail loudly at compile
   time).
2. **Sound "touches-unknown" classification.** This maps exactly onto the Ω machinery
   (§4A, PIP): *unknown-callee* = any icall whose function-pointer pts includes Ω, plus
   any call to external code; *unknown-caller* = any function whose address escapes to Ω
   (passed to qsort/pthread_create/signal in third-party or libc code, stored where
   external code can read it, exported from a library build). The escaped-bit is computed
   inside the tier-C/D fixpoint for free, and it is monotone — exactly the right shape for
   a "must not rewrite" taint.
3. **Transitive mod/ref of mutable globals per function** — direct accesses are syntactic;
   accesses through pointers into globals need the points-to tiers; the transitive closure
   runs over the call graph from (1).
4. Precision, everywhere above, because **FP edges merely merge components and spread
   unknown-taint further — lost coverage, never corruption**. Precision converts directly
   into "fraction of globals localized," which is the client's success metric.

This asymmetry (FN = corruption, FP = coverage loss) is why the tier structure earns its
keep even at 1 MLoC: tier-1 (FSA ∩ Steensgaard + Ω taint) already yields a *correct* tool
with modest coverage on day one; every later tier only splits components and removes
taint, increasing coverage with zero correctness risk — each improvement is separately
testable by re-running the refactoring and the program's test suite.

**Would soundiness suffice?** Probably — but make it *audited* soundiness rather than
hoped-for soundiness. Concretely: enumerate the assumptions under which our icall edges
and escape bits are complete (no int↔ptr round-trips of function pointers, no memcpy of
function-pointer fields we failed to model, no inline asm touching code pointers, no
dlsym-style reflection, call signatures match targets per C UB rules). Each assumption is
*cheaply detectable* as a syntactic/IR-level event at PAG-construction time. Then, instead
of asserting global soundness, **propagate any detected violation as Ω-taint on the
objects/functions involved** — the component containing the violation becomes
"touches-unknown" and is frozen, and every *other* component keeps a genuine soundness
guarantee. This converts the soundiness gamble into per-component soundness: the FSA
envelope (sound for icalls modulo fn-ptr type punning, which is precisely one of the
detected events) intersected with the demand-driven results gives the defensible edge set,
and the violations list doubles as a refactoring-exclusion report a human can review.
The one residual gamble soundiness would take — "most FN edges are innocuous" — buys
little here, because the cost of a bad rewrite (silent ABI corruption surfacing at
runtime) is so much larger than the cost of freezing one more component.

## 8. Soundness inventory (explicit, since output drives code transformation)

- Incomplete programs / libraries / dlopen: sound via Ω (PIP). This is *stronger* than
  cclyzer, KELP, CORAL, KallGraph defaults.
- int↔ptr: sound via PIP's provenance rules (fixes KallGraph's known FN source).
- Unions / type punning: single-type-per-lifetime assumption inherited from cclyzer for
  typed clones — but because clones are *additional* objects alongside the untyped site
  object, a conservative mode can keep the untyped object's flows too; mutability/escape
  clients should use conservative mode, call-graph precision metrics can use cclyzer mode.
  This dial must be explicit in the API.
- Inline asm, setjmp, varargs: safe-fallback to "unknown ⇒ Ω-tainted" (KELP discipline:
  fallback must only ever *add* targets/writers).
- KallGraph-paper caveat to inherit deliberately: prefer `-O0`/`-O1` IR for analysis;
  optimized IR erases semantics (their Table 2 discussion). For a source-to-source client
  this is doubly natural since the rewrite targets unoptimized source anyway.

## 9. Implementation in Rust

- **Core engine: hand-rolled, not Datalog.** The hot loops (union-find, partition Andersen,
  CFL traversal) are each ~hundreds of lines and have well-understood optimal data
  structures; PIP's result (two bit-flags beat the entire classic-optimization literature)
  argues the wins come from *representation choices* a Datalog engine can't express.
  Concretely: u32-indexed node arenas; CSR adjacency for the frozen PAG; sparse bitmaps
  (roaring or hibitset) for pts sets; `rayon` for phase A/B/E pools + work-stealing in C;
  `dashmap`-style concurrent memo caches in E.
- **Datalog where it earns its keep:** the *derived-relation* layer (B3 confinement, client
  fact aggregation, the certificate bookkeeping, C→Rust-specific queries the team will keep
  inventing) is naturally relational and small relative to core points-to. **Ascent**
  (Rust-native, compiles rules to Rust, has a parallel mode, supports lattices — the
  mutability lattice of §4F fits) embedded over the core engine's output relations is the
  pragmatic choice; differential-datalog adds incrementality but is heavier. This keeps the
  team's existing cclyzer rule-thinking usable without putting Datalog in the hot path.
- **Reuse opportunities:** KallGraph is open source (github.com/seclab-ucr/KallGraph,
  2.1K SLOC over Unias/SVF) — worth mining for CFL rule tests and Gep-offset edge cases
  even though we won't take the SVF dependency. PIP's artifact (jlm) documents the Ω rule
  set precisely (their Fig. 7).
- **Testing:** differential testing against the existing cclyzer extension on small inputs
  (where it still runs) for precision; against FSA for icall soundness envelope;
  dynamic-trace validation (KallGraph/KELP/CORAL all did fuzz-trace FN checks — cheap to
  replicate with AFL++ on a few benchmarks, and the right standard of evidence for a tool
  that feeds a transpiler).

## 10. Phasing / milestones

1. **M1 — PAG + tier C + escape bits.** Frozen graph, parallel Steensgaard, Ω flags,
   assumption-violation detection (§7). Already produces a *correct* end-to-end input for
   the globals-localization client: sound (coarse) call graph via FSA∩Steensgaard,
   Ω-derived unknown-caller/callee taint, transitive global mod/ref, `never-written`
   mutability for the easy majority. Benchmark targets: Vim and PHP plus whatever the
   current analysis chokes on; success metric from day one is the client's coverage
   (fraction of mutable globals localizable), not abstract pts-set sizes.
2. **M2 — B1/B2/B3 + certificates.** Stationarity (immutability-after-init), simple-icall
   exact resolution, confined subtraction. This is the largest single precision jump per
   engineering hour (KELP: +33% of icalls exactly; CORAL: 55% certified at Steensgaard).
3. **M3 — tier E queries + on-the-fly CG fixpoint.** KallGraph grammar with byte-offset
   MHS, writers()/escapes() query forms, partition-bounded traversal, parallel query pool.
4. **M4 — tier D partition Andersen.** Slots between C and E to shrink E's load; measure
   whether it pays once E exists (CORAL says yes at ~25% of icalls; with E parallel it may
   matter less — keep it optional and data-driven).
5. **M5 (optional) — Canary-style flow-sensitive function summaries** replacing/augmenting
   D where strong updates matter (e.g., reuse-heavy buffers confusing mutability), and
   thread-escape (EspObj) if the C→Rust pipeline starts caring about `Send/Sync` decisions.
   **Summary-minimality invariant (TeaDSA):** a function's summary mentions only objects
   reachable from its formals, returns, and the globals it actually uses; caller-side
   objects are resolved lazily at the call site, never copied into callee summaries.
   TeaDSA's oversharing result shows violating this (DSA's top-down foreign-object
   copying) dominates runtime in compositional analyses — up to 96% of it — and that
   dropping the copying loses nothing (their Theorem 1). Globals deserve particular care
   here: for our globals-heavy client they are the dominant oversharing source if
   summaries are built naively.

## 11. Open questions for discussion

*(Resolved by discussion so far: scale target ≤1 MLoC, Linux excluded; C only;
no incrementality; primary client and its conservatism requirements — see §7.)*

1. **Query volume for mutability** — downgraded but not gone. At ≤1 MLoC, and with
   mutability having a cheap conservative fallback, tier-E mutability queries can be run
   only for refactoring-relevant objects (mutable globals and what they reach). Still
   worth instrumenting at M1 to confirm the residue after B1/C certificates is small.
2. **Granularity of `escapes-to-caller`** (frame escape) — derivable from PAG reachability
   without points-to in many cases (SROA-style reasoning); decide whether it lives in B or
   C. Matters mostly for the later C→Rust ownership clients, not for globals localization.
3. **Unknown-caller criterion under whole-program builds.** When the analyzed program is a
   complete executable, "unknown caller" shrinks to: address-taken functions flowing into
   external code (callbacks registered with libc/third-party libs) and anything
   Ω-tainted. When it is a library, every exported function is an unknown-caller. The
   client presumably knows which build mode it is in — the analysis should take this as an
   input flag rather than guessing.
4. **Component granularity vs. coverage.** If a few mega-components (e.g., everything
   reachable from a central dispatch table) dominate and happen to touch one unknown, the
   client's coverage collapses even with a perfect analysis. Worth an early empirical
   look (M1, on Vim/PHP) at the component-size distribution and at *which* unknowns are
   load-bearing — it may motivate client-side mitigations (e.g., shim wrappers that
   preserve old ABI at the boundary of a component, letting the interior be rewritten)
   that change what the analysis needs to report (boundary edges, not just taint bits).
