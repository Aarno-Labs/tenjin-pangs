# M2 Implementation Plan — Stage-0 pre-analyses & precision certificates

*Companion to `DESIGN.md` §4B/§10-M2. Prerequisite: M1 complete (PIR, PAG, Steensgaard+Ω,
running client pipeline with metrics). This milestone delivers the largest precision jump
per engineering hour: exact resolution of "simple" indirect calls (KELP), the
confined-function subtraction (KELP), initialization-value tracking (CORAL Stage Zero),
and the certificate framework that decides, per query, whether a cheap tier's answer is
already final. It also upgrades mutability from `never-written` to `stationary`
(immutable-after-init), which lets the localization client skip stationary globals
entirely.*

## 0. Headline

**Running at all times.** Every step plugs into the M1 pipeline behind a flag and is
measured by the same client coverage metric. Expected effect, calibrated from the papers:
~⅓ of indirect calls resolved *exactly* by M2.2 (KELP measured 34.5% "simple" icalls on
Linux and 33% average across 20 programs); a further large fraction *certified* at the
Steensgaard tier by M2.5 (CORAL certified 55.6% of icalls at its equivalent tier);
stationary globals identified by M2.4+M2.5 drop out of the localization payload.

**Estimated effort: 16–27 working days.** Hard chain: M2.0 → M2.1 → {M2.2 → M2.3, M2.4}
→ M2.5 → M2.7; M2.6 is gated/optional.

## 1. Background the implementor needs (self-contained)

### 1.1 Partial SSA, and why def-use chains are almost free
After `mem2reg`, LLVM IR splits values into **top-level variables** (SSA virtual
registers and global *names*; each has exactly one definition; def-use edges are explicit
and exact) and **address-taken memory** (alloca'd objects, heap, global *contents*;
accessed only via `load`/`store`). Tracking a value through top-level variables is
trivial graph-walking. The expensive part of pointer analysis is only the indirect hop:
*which loads see which stores* — i.e., reasoning about memory. M2's whole strategy
(following KELP and CORAL) is: **walk the free SSA edges as far as they go, and treat any
crossing into memory as a boundary** — either abort (B2), or specially handle the one
memory pattern that's cheap (object initialization, B1; simple globals, B2-globals).

### 1.2 KELP's classification (paper: "Unleashing the Power of Type-Based Call Graph
Construction by Using Regional Pointer Information", USENIX Security 2024)
- A function pointer is **simple** if (a) its value never derives from a memory load
  (no `p = *q` anywhere in its def-use ancestry), and (b) its value is never stored into
  memory that other pointers might read (no escape into the indirect world).
  Exception: a *global variable* used as a function pointer can be handled
  flow-insensitively even though it is memory — if the global's address never escapes and
  it is only ever assigned directly (stores where the pointer operand is the global's
  name), the icall's targets are simply *every value ever stored to it*.
- An **icall is simple** if its function-pointer operand is simple. Simple icalls are
  resolved *exactly* by the def-use walk — no points-to needed, no type matching.
- A function is **confined** if every place its address is taken is consumed by some
  simple chain. Confined functions can *never* be targets of complex icalls, so they are
  subtracted from every later candidate set. (KELP: 23.9% of address-taken functions on
  Linux; 76.3% of address-taken functions are address-taken exactly once.)

### 1.3 CORAL's Stage Zero (paper: "A Cocktail Approach to Practical Call Graph
Construction", OOPSLA 2023)
- An object's **initialization phase** runs from its creation until *its own reference is
  first stored into another object* (after that, other code can reach it; before that,
  only the creating code can). This is Unkel & Lam's "stationary field" boundary.
- **InitVal(o, fld)** = the set of values (for us: store statements and, for fn-ptr
  fields, function addresses) written into field `fld` of object `o` *during its
  initialization phase*. Computable by a cheap forward def-use walk per object — sparse,
  regional, context-sensitive via call-string parentheses.
- A function pointer is **stationary** if it is never re-assigned after initialization.
  CORAL's trick is to never detect stationarity directly (expensive); instead it checks,
  *after* a cheap points-to tier runs, the **result-oriented certificate**:

  > icall through `v0 := *p` is *settled* if for every object `o ∈ pts(p)`:
  > `pts(v0)` is a singleton, or `pts(v0) = InitVal(o, fld)`.

  If the cheap tier's answer already equals the init-values, no more-precise tier can do
  better (the values were all assigned during init; flow/context sensitivity adds
  nothing). CORAL Eq. 1/2. The same logic certifies **stationarity for mutability**: a
  global/field is stationary if every writer the points-to tier can find is one of its
  init-phase stores.
- Soundness valve: if an object's InitVal could not be fully collected (its init phase
  crossed an unknown — external call, asm, indirect call we can't see through), mark
  InitVal as ⊥(unknown); ⊥ never certifies anything. This guarantees the certificate
  machinery can only *fail to settle*, never settle wrongly.

## 2. Steps

### M2.0 — Certificate & verdict framework (1–2 days)
A small `pangs-verdicts` module: every query (icall, global-mutability, escape) gets a
ledger entry `Verdict { answer, tier: Direct|FSA|Simple|SteensCert|…, certificate:
Option<CertKind> }`. Tiers may only *narrow* answers; a debug assertion enforces the
subset relation on every update (this is the cheapest soundness regression tripwire we
will ever buy). `pangs report` gains per-tier attribution columns.
**Acceptance:** M1 outputs reproduce bit-for-bit through the new ledger.

### M2.1 — Lazy field-subobject table (2–4 days)
B1/B2 need field distinctions; M1's PAG recorded byte offsets but treated objects
monolithically. Add a side table `SubObj: (ObjId, ByteOff) → SubObjId`, materialized on
first touch, plus the **generalization pair** for unknown offsets (cclyzer §3.3, recast
in byte offsets):
- each object has one `(o, ⊤)` "unknown-offset" subobject;
- a load from `(o, c)` must also see values stored to `(o, ⊤)`; a load from `(o, ⊤)` must
  see values stored to every `(o, c)`;
- offsets are clamped to the allocation size where known; a Gep whose cumulative offset
  is non-constant maps to `(o, ⊤)`.
Nothing recomputes Steensgaard here — this table is *only* consumed by M2's def-use walks
(and later by tiers D/E). **Acceptance:** unit fixtures covering nested structs, arrays of
structs, unions, flexible array members; table is demand-populated (assert no eager blowup
on PHP).

### M2.2 — B2: simple-pointer def-use tracker + exact icall resolution (4–6 days)
The core walker, used backward then forward. State: `(pir_stmt, tracked_value,
ctx_string)`. Context sensitivity = call-string parentheses: traversing a return edge into
caller-of-`f` at call site `k` appends `(_k`; traversing into a call at site `k` appends
`)_k`; a path is admissible if its parens balance (CFL-reachability, Reps-style). Cap
context depth (start: 8) with overflow → classify complex (safe).

Backward phase from each icall's fn-ptr operand, over PIR:
```
p = &f            → FOUND target f; record this address-taken *site*
p = q | phi/select → continue into each source
p = &q->fld (Gep) → continue into q, tracking (value, fld) via SubObj
p = call f(...)   → continue into f's return statements   [paren push]
param of f at cs  → continue into actual at cs            [paren pop]
p = *q            → COMPLEX, abort this icall
p = global G      → enter the global-variable mode (below)
anything unknown (asm operand, vararg, external, inttoptr) → COMPLEX
```
Global mode (flow-insensitive, KELP §4.2 "Handling Global Variables"): admissible iff
`G`'s address is never taken (`&G` never flows anywhere except as the direct pointer
operand of stores/loads — checkable from the PAG in O(uses)); then targets = values of
all `store X, G` statements, each X resolved by the same backward walk. Otherwise COMPLEX.

Forward phase (escape check, run for each candidate-simple chain): from each found
address-taken site, walk *forward* over the same edge kinds; if the tracked value is
stored through a pointer (`*p = v` where `p` is not a never-address-taken global), or
passed to external/vararg/asm — COMPLEX. (Rationale: a value that enters arbitrary memory
could reach this icall via loads we refused to track.)

Output per icall: `Simple { targets, sites }` or `Complex`. Record the union of all
reached address-taken sites in `DefUseReachingSites`. **Resolved simple icalls bypass FSA
entirely** in the client (provenance tag `simple`).

**Acceptance:** fixture suite incl. the KELP paper's Fig. 1/Fig. 3 patterns transcribed to
C; on Vim/PHP report % simple icalls (sanity envelope from KELP Table 1: 20–80% across
programs, avg ~33% — flag if we're way outside); every simple-resolved target set is ⊆
the M1 FSA set *or* the discrepancy is triaged (an FSA *miss* found here means our FSA
compat rules have a soundness bug — that check is the point); dynamic icall traces (M1.8
harness) remain ⊆ our edges.

### M2.3 — B3: confined-function subtraction (1–2 days)
`Confined = { f | address-taken, and every address-taken site of f ∈ DefUseReachingSites }`.
Subtract `Confined` from: FSA candidate sets of complex icalls, tier-C
(Steensgaard∩FSA) sets, and later tier-D/E candidate filters. **Acceptance:** target-set
size reduction reported per program (KELP: confined ≈ 24–32% of address-taken functions);
subset-only assertion (M2.0) stays green; spot-check 10 confined functions by hand on Vim.

### M2.4 — B1: initialization-value tracking (4–7 days)
Forward walker per *tracked object creation*: all globals (their initializer is init
phase by definition — plus dynamic init stores before escape), heap allocation sites, and
address-taken locals that the mutability client cares about. Per object `o`, maintain the
reference-set `R` (top-level variables currently holding `&o` or `&o.fld`) and walk
forward in def-use order:
```
p = &o                  → R += p
p = q (q∈R) | phi       → R += p
p = &q->fld (q∈R)       → R += (p, fld)
*p = v   (p∈R @ fld)    → InitStores(o,fld) += this store; if v resolves to &f
                           (backward B2-walk), InitVal(o,fld) += f
*p = q   (q∈R)          → o's reference escaped into another object: END of init
                           phase for o; stop the walk
call f(.., q∈R, ..)     → continue into f's body (paren-matched), tracking the formal
return q∈R              → continue at call sites (paren-matched)
q∈R passed to external / asm / vararg / icall-with-unsettled-targets
                        → InitVal(o,*) := ⊥ (unknown); stop
```
Notes for the implementor: (a) the walk is *sparse* — only statements reachable in
def-use order from the creation site are touched (CORAL measured ~1.5 min per 718 KLoC
total); (b) settled-simple icalls (M2.2) *may* be walked through, an example of tier
synergy; (c) loops don't need fixpointing — the walk is over def-use edges, not control
flow, and `R` only grows; (d) multiple init writes to the same field are normal and fine
(branch-dependent init), they just make `InitVal` a set.

**Acceptance:** fixtures: global tables of fn ptrs (the C analog of CORAL Fig. 1(a)/(c)),
malloc-then-populate-then-publish (init ends at publish), init crossing a helper function
(paren matching), init aborted by external call (⊥). Metrics: % of globals with complete
(non-⊥) InitVal; wall time (budget: ≤2 min on PHP single-threaded; per-object walks are
embarrassingly parallel if needed).

### M2.5 — Certificates wired into the pipeline (2–3 days)
Two certificate checks, both run against tier-C (Steensgaard) results:
1. **Icall settlement (CORAL Eq. 1):** for each still-unsettled icall through `p`:
   settled-at-C iff `targets_C(icall)` is a singleton, or for every object `o` that
   `find(p)`'s class can contain, `InitVal(o, fld) ≠ ⊥` and `targets_C(icall) ⊆
   InitVal(o, fld)`. (Steensgaard's class-granularity makes "every object in the class"
   the sound reading.)
2. **Stationarity (mutability/localization):** global `g` (or field) is *stationary* iff
   `InitVal/InitStores(g) ≠ ⊥` and every writer found by M1.6's pointer-aware mod/ref is
   ∈ `InitStores(g)`. Client effect: stationary globals leave the localization payload
   (they can remain globals — immutable after init — or be `const`-ified), shrinking
   context structs and possibly *unfreezing components* (a component whose only unknown
   contact was via a stationary global's accesses may become rewritable).
**Acceptance:** coverage metric delta on Vim/PHP (this is the step where M2 pays);
per-tier attribution table published; subset assertions green; 20 stationary verdicts
hand-audited on Vim (stationarity FPs corrupt the refactoring — this audit is mandatory).

### M2.6 — (Gated) typed heap clones with minimal cast filtering (3–4 days)
Only if M2.5 metrics show heap-object conflation is what's blocking certificates (symptom:
unsettled icalls/mutability whose pts contain big untyped `malloc` blobs from wrapper
functions like `xmalloc`). Mechanism (cclyzer "HEAP-BP" + KallGraph "minimal CastMap"):
when untyped heap object `o_i` (alloc site `i`) flows — per tier-C classes — to a cast to
pointer-of-T, create clone `o_{i,T}`; field operations only materialize subobjects on
clones whose T matches. Skip casts that are *local round-trips* (value cast to `void*`
and back along one def-use chain with no intervening memory hop — detect with a bounded
B2-style look-ahead). Clones are *additional* objects: the untyped `o_i` and its flows
remain, so this is a precision refinement, not a soundness gamble (conservative mode per
DESIGN §8 holds automatically).
**Acceptance:** the motivating unsettled queries settle; object-count growth bounded
(report clones/site histogram); no client regressions.

### M2.7 — Validation & freeze (2–3 days)
- Re-run M1.8 dynamic icall validation; **every observed (callsite,target) must be in the
  edge set** — simple-icall resolution is exact, so any dynamic miss here is a real bug.
- Differential vs cclyzer++ where it runs: our settled icalls ⊆ its targets (it's
  precision-comparable on smalls).
- KELP-style ablation on our corpus: coverage with {B2 only, B1+cert only, both} — tells
  us (and the eventual paper/readme) where the value is.
- Freeze M2 metrics dashboard.

## 3. Effort & risk summary

| Step | Est. days | Risk | Mitigation |
|---|---|---|---|
| M2.0 | 1–2 | low | — |
| M2.1 | 2–4 | union/offset corner cases | fixture-first; clamp-to-⊤ default |
| M2.2 | 4–6 | walker termination/blowup | visited-set on (stmt,value,ctx); depth caps → COMPLEX |
| M2.3 | 1–2 | low | — |
| M2.4 | 4–7 | init-end detection subtleties | Unkel-Lam boundary exactly as specified; ⊥ on any doubt |
| M2.5 | 2–3 | stationarity FPs (client-corrupting) | mandatory hand-audit; ⊥-poisoning; subset assertions |
| M2.6 | 0 or 3–4 | object blowup | gated by measurement; histogram cap |
| M2.7 | 2–3 | — | — |
| **Σ** | **16–27** | | |

**Where M2 can stop early:** after M2.3 the milestone already ships value (exact simple
icalls + confined subtraction). B1/certificates (M2.4–M2.5) are the second half and can
land as a follow-up if scheduling demands.
