# M4 Implementation Plan — Tier D: partition-scoped inclusion-based (Andersen) solving

*Companion to `DESIGN.md` §4D/§10-M4. Prerequisites: M1–M3. This tier slots **between**
Steensgaard (tier C) and the demand-driven queries (tier E): an exhaustive, field-
sensitive, inclusion-based points-to solve — but never whole-program: each run is scoped
to one Steensgaard partition's constraint slice, and partitions run in parallel. Its
purpose is to settle (via the M2 certificates) a large chunk of the residue that tier C's
equivalence-class coarseness leaves behind, so tier E sees fewer and smaller queries —
and to provide an exhaustive answer-of-record where per-query analysis is the wrong shape
(e.g., "writers of every global at once").*

## 0. Headline — and the go/no-go gate

**M4 is conditional.** DESIGN §10 marks it "data-driven": with M3's parallel queries in
hand, M4 only pays if M3.7 metrics show (a) the post-C residue is large (many unsettled
queries), or (b) individual tier-E queries are slow because Steensgaard classes are too
coarse to bound them, or (c) clients keep asking exhaustive questions (all-globals
mod/ref at object granularity) that amortize poorly over per-object queries. CORAL's
data says it will pay (its Andersen stage settled 25.2% of icalls, and removing it OOM'd
the next stage on 12/20 programs); our situation differs (tier E is parallel and
partition-bounded), so: **run the gate first** (M4.0, ~1 day of reading M3 metrics), and
be genuinely willing to skip the milestone.

**Estimated effort if green-lit: 12–20 working days.**

## 1. Background the implementor needs (self-contained)

### 1.1 Andersen in one paragraph
Inclusion-based points-to: every pointer p has a set `pts(p)`; constraints are
`p ⊇ {o}` (address-of), `p ⊇ q` (copy), `p ⊇ *q` (load), `*p ⊇ q` (store). Solve by
worklist: when `pts(q)` grows, propagate along copy edges; loads/stores become new copy
edges as their pointee sets populate (`*p ⊇ q` ⇒ for each `o ∈ pts(p)`, add edge
`q → o's content var`). Cubic worst case; in practice dominated by set operations —
hence sparse bitmaps and (classically) cycle collapsing. Unlike Steensgaard (which
*unifies* and loses direction), inclusion keeps `x = y` from contaminating y with x's
pointees.

### 1.2 Why partitions make this affordable (Kahlon's bootstrapping, used by CORAL)
Steensgaard's result is a sound over-approximation; in particular, **a pointer's
Andersen-level points-to facts can only be influenced by constraints over pointers in
its own Steensgaard partition, plus pointers whose pointee-classes sit *above* it in the
class points-to hierarchy** (something must be able to point *to* your cell to affect
what flows into it). So: to get exact Andersen answers for the pointers in partition P,
slice the constraint system to P's members + that upward closure, and solve the slice.
Slices are small (CORAL: stage II touched ~⅓ of program statements *in total* across all
needed partitions) and independent → parallel. We additionally *select* which partitions
to solve at all: only those containing variables of unsettled ledger queries.

### 1.3 Field sensitivity by byte offset, and the positive-weight-cycle (PWC) trap
Field-sensitive inclusion constraints add `p ⊇ q + off` (Gep). The classic failure mode
(cclyzer §2, Pearce): imprecision creates cycles with net-positive offset, deriving
fields beyond any real object (`i.y.y.y…`) — divergence or garbage. Our containment, all
three pieces mandatory:
1. offsets are concrete bytes resolved at lowering; each object knows its allocation
   size where static; **any derived offset ≥ size, or with unknown component, saturates
   to the `(o, ⊤)` subobject** (M2.1's table is reused — tiers D and E must share it so
   certificates compare like with like);
2. subobjects are created only via the table (no algebra on symbolic offsets);
3. the generalization pair from M2.1 (loads from `(o,c)` also see `(o,⊤)` stores and
   vice versa) is enforced as two extra propagation rules — that's the soundness glue
   once saturation exists.
PWCs then can't diverge (offsets are bounded by saturation); they only cost precision,
which is the right failure direction.

### 1.4 Ω in inclusion form (PIP, the part to copy carefully)
Tier C carried two monotone bits per class. In tier D they become per-variable flags with
PIP's inference rules (PIP Fig. 7, adapted): `p ⊒ Ω` ("p may point to anything external/
escaped") and `Ω ⊒ {x}` ("x escaped"). Key rules: flags propagate along copy edges
*instead of* materializing pointee sets (TransΩ); a store through a ⊒Ω pointer marks the
stored value's pointees escaped; a load through a ⊒Ω pointer yields a ⊒Ω result; escaped
objects' content vars are ⊒Ω. PIP's headline measurement is worth internalizing: this
implicit representation was worth 15× over explicit external-pointee sets and made the
classic solver optimizations unnecessary — **so implement the flags before reaching for
cycle elimination etc., not after.** PIP's "prefer implicit pointees" refinement (drop
explicit pointees that are subsumed by flags, skip subsumed edge insertions) is a small
add-on; take rules 1–4 of their PIP section as written.

### 1.5 What "settling" means here
Tier D's output feeds the same M2.5 certificates, now at object granularity: icalls
settle by Eq. 1 against `pts_D`; stationarity by `writers_D(g) ⊆ InitStores(g)`; taint by
object-granular escape flags. Everything still unsettled after D is tier E's (smaller)
residue.

## 2. Steps

### M4.0 — Go/no-go gate (1 day)
Read M3.7 metrics against §0's three criteria; write a one-paragraph decision with
numbers. If no-go: file the decision in `metrics/`, close the milestone, revisit when a
bigger corpus or new client changes the data.

### M4.1 — Constraint slicing (3–5 days)
From the frozen PAG + tier-C classes: (a) constraint extraction (PAG edges → the four
constraint forms, with byte offsets); (b) partition selection from the unsettled-query
ledger; (c) upward-closure computation over the class points-to DAG (§1.2); (d) slice
materialization as compact index-remapped constraint systems. **Acceptance:** slice-size
histogram on Vim/PHP (expect heavy skew: many tiny slices, a few big ones — CORAL's ⅓
figure as sanity bound); a `pangs dump-slice` debugging artifact; unit fixtures where the
slice provably contains all constraints affecting a target pointer (hand-checked).

### M4.2 — Sequential field-sensitive solver with Ω flags (4–6 days)
The worklist solver per §1.1+§1.3+§1.4 on one slice: u32-indexed vars, sparse-bitmap pts
sets (`roaring` or hand-rolled hibitset — benchmark both on a big slice), LRF (least-
recently-fired) worklist order, the two flags with PIP propagation, saturating offsets
through the shared subobject table. *No cycle elimination in v1* (per §1.4; revisit only
with profiles). **Acceptance:** fixture parity with tier E on overlap queries (same
question ⇒ tier-D answer ⊆ tier-C and =tier-E modulo documented precision differences
— in particular E is context-insensitive too, so answers should usually coincide;
investigate every mismatch, one of the two engines has a bug); PWC fixtures (mutually
recursive structs, linked-list cursors) terminate with sane sets.

### M4.3 — Parallel partition execution + ledger wiring (2–4 days)
`rayon` over slices (no cross-slice communication by construction); big-slice-first
scheduling to avoid tail latency; certificate re-checks (M2.5 logic, object-granular
inputs) and ledger updates with `tier: AndersenPart` provenance. **Acceptance:** bit-
identical results parallel vs sequential; residue-into-E reduction measured (the number
that justifies M4's existence — publish it next to the M4.0 prediction); end-to-end wall
time still within the M1.7 budget.

### M4.4 — Exhaustive client modes (2–3 days)
Where the per-query shape was awkward, expose tier-D's exhaustive sets directly:
all-globals object-granular mod/ref in one pass (upgrade of M1.6); per-component alias
summaries for the localization client's boundary reporting (DESIGN §11.4's shim-wrapper
investigation needs exactly this). **Acceptance:** client consumes tier-D mod/ref; diff
vs M1.6 published; coverage delta recorded.

### M4.5 — Validation & freeze (2 days)
Dynamic traces still ⊆ edges; differential D-vs-E agreement stats over the full residue
(not just fixtures); dashboard freeze with per-tier attribution now spanning
Direct/FSA/Simple/SteensCert/AndersenPart/CFL.

## 3. Effort & risk summary

| Step | Est. days | Risk | Mitigation |
|---|---|---|---|
| M4.0 | 1 | skipping the gate under momentum | written decision required |
| M4.1 | 3–5 | unsound slicing (missing influencing constraints) | closure rule from §1.2 implemented conservatively; fixtures; when in doubt, widen the slice |
| M4.2 | 4–6 | PWC divergence / Ω-rule transcription errors | saturation-by-construction; PIP rules transcribed as a table with one test each |
| M4.3 | 2–4 | low | determinism test |
| M4.4 | 2–3 | low | — |
| M4.5 | 2 | — | — |
| **Σ (if green-lit)** | **12–20** | | |

**Interaction with M2.6 (typed heap clones):** if both exist, clones multiply tier-D's
object domain. Keep the conservative mode (untyped object retained) and watch slice-size
histograms; if a slice blows up, the per-slice fallback is to demote that slice's answer
to tier C and let tier E handle its queries — the ledger's ⊆ discipline makes this safe
and automatic.
