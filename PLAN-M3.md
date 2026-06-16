# M3 Implementation Plan — Demand-driven CFL queries & on-the-fly call-graph fixpoint

*Companion to `DESIGN.md` §4E/§10-M3. Prerequisites: M1 (PAG, Steensgaard+Ω) and at least
M2.0–M2.3 (verdict ledger, subobject table, simple/confined sets). This milestone builds
tier E: precise, parallel, per-query analysis for the residue the cheap tiers couldn't
certify — indirect-call targets, object writers (mutability), and escape refinement —
plus the bootstrapped fixpoint that lets indirect-call resolution and call-graph
construction feed each other soundly.*

## 0. Headline

**What exists at the end:** `pangs query callees|writers|escapes`, a parallel query pool
over the frozen PAG, and an on-the-fly call-graph iteration that starts from *no* assumed
icall edges and converges in a few rounds. Tier-E answers replace tier-C answers wherever
they're narrower (ledger-enforced ⊆). Calibration from KallGraph (the paper this tier
reimplements): pruned 75–90% of type-based icall targets on kernels; per-query state
<30 MB; near-linear scaling to 80 threads. Our inputs are 20–50× smaller than theirs.

**Estimated effort: 18–30 working days.** Hard chain: M3.1 → M3.2 → M3.3 → M3.4 →
M3.6 → M3.7; M3.5 (writers/escapes) follows M3.2 and can proceed in parallel with M3.3–4.

## 1. Background the implementor needs (self-contained)

### 1.1 The idea: alias analysis as grammar-constrained graph reachability
The PAG has four value-relevant edge kinds (M1.3): `Assign` (copies, casts, phi/select,
param/ret bindings), `Store` (`*x = q`: q —Store→ x's pointee position), `Load`
(`p = *y`), `Gep{off}` (field/array addressing, byte offset or ⊤). A *value flows* from
node a to node b iff there's a path whose edge labels form a string in a context-free
language — the CFL formalization (Reps) of Andersen-style propagation. Intuition for the
two core productions:

- Two pointers are **memory aliases** (`I-Alias`) if you can walk *backward* along value
  flow from one to a common source and *forward* to the other:
  `I-Alias → F̄ I-Alias F | ε` (where `F` is forward value-flow, `F̄` its mirror).
- A value **flows through memory** when a `Store` into some pointer x pairs with a `Load`
  from a pointer y that is an I-Alias of x:
  `F → ( Assign | Store I-Alias Load )*`.

Resolving an icall = asking: from the node holding `&f` (a function's address), does `F`
reach the function-pointer operand of some icall? Running this *per address-taken
function* (forward) rather than per icall (backward) is KallGraph's choice and ours: the
queries are numerous (= parallel work units) and each is small.

### 1.2 Fields: byte offsets and the cumulative-offset stack (KallGraph §5.3, the part
that's easy to get wrong)
Naive field-sensitive CFL pairs each positive `Gep_{+off}` with a matching negative one.
Real LLVM code breaks pairing (zero-offset Geps used as casts; `(X+Y, −Z)` arithmetic
where Z=X+Y). KallGraph's fix, which we adopt wholesale: **treat every Gep as an Assign
that adds a signed byte offset to a running counter, and only require the counter to be
zero at the moments that semantically mean "same cell": when pairing a Store with a Load
(entering/leaving memory).** Because Store…Load pairs nest, the counter must be a *stack*
(one counter per memory level), called the **memory-history stack (MHS)**:

- traversing `Store` pushes a fresh 0; traversing the matching `Load` requires top==0 and
  pops (then restores on backtrack);
- traversing `Gep{off}` adjusts the *top* counter by ∓off (sign depends on direction);
  `Gep{⊤}` sets the top counter to ⊤, and ⊤ satisfies the ==0 check (sound, imprecise);
- `Assign` edges don't touch the stack.

### 1.3 The traversal, concretely (adaptation of KallGraph Alg. 1)
A query is a DFS over (node, phase, MHS) where phase ∈ {S_f, S_b} — "currently in F" vs
"currently in F̄" (you enter S_b when you start walking backward to find aliases, i.e.
after traversing a Store; you return to S_f via a matching forward Load):

```
fn go(cur, phase, mhs, out):
    dependence_checks(cur, phase)            # see §1.4
    if phase==S_f and cur is an icall fn-ptr operand and mhs.is_empty(): out += cur
    if phase==S_f and cur is a Store-target sink we care about: out += cur   # writers()
    for e in edges(cur) matching phase:      # forward kinds in S_f, mirrored in S_b,
        ...                                  # plus the phase transitions:
    # S_f: Assign→, Gep{off}→ (top -= off), Store→ (push 0; recurse S_f at the stored-to
    #      pointer node *in S_b* to find aliases — this is the F̄ I-Alias F expansion),
    #      Load→ allowed iff top==0 (pop, recurse, push back)
    # S_b: mirrors (Assign←, Gep← with top += off, Load← pushes, Store← iff top==0),
    #      and at any point may flip to S_f (the I-Alias midpoint)
```
Memoize on `(node, phase, mhs.top)` per query (full-stack memoization is unsound to
share across different stack tails; top-of-stack memoization is the standard practical
compromise — document it and validate in M3.7). Visited-set + memo keep each query small.

Two deliberate v1 simplifications relative to KallGraph, both sound:
- **No type shortcuts** (`Shortcut_f` etc. — their Unias inheritance). These are
  accelerators that skip long Store…Load chains by type matching; at ≤1 MLoC we likely
  don't need them. Gated step M3.8 if profiles disagree.
- **Casts are plain Assign edges** (no CastMap consultation). The object-level CastMap
  from M1.3 stays recorded for M2.6/M4/precision work; ignoring it here only loses
  precision, never soundness.
- **Context-insensitive**, like KallGraph. (Mixing the field-CFL with a second
  call-string CFL is formally undecidable and practically hairy; our context sensitivity
  lives in B1/B2 where the walks are simple. Revisit only with evidence.)

### 1.4 On-the-fly call graph without a bootstrap CG (KallGraph §5.4)
Queries must traverse *interprocedural* Assign edges (arg→param, ret→callsite), but for
call sites that are themselves unresolved icalls those edges don't exist yet — circular.
KallGraph's solution, which we adopt:
- Round 0 edge set: direct calls + tiers B/C-settled icalls (we start ahead of KallGraph
  here — they start truly empty).
- Run all pending queries. During traversal, `dependence_checks` records, per queried
  function f: `DepiCalls[f]` = unresolved icalls whose argument/return positions f's
  walk touched (i.e., f's answer *depends on* that icall's resolution).
- After the round: icalls that gained targets cause exactly the dependent functions
  (`hasNewCallees`/`hasNewCallers` via the Dep maps) to be re-queried next round.
- Iterate to fixpoint. KallGraph converged in ≤4 rounds on kernels; expect 2–3 here.
This is monotone (target sets only grow during the fixpoint; the *final* sets then
replace coarser tier answers, which is where the precision shows up).

### 1.5 Query forms beyond icalls
All three clients ride the same traversal with different sources/sinks:
- **callees**: source = function-address node per unsettled address-taken function
  (minus confined, M2.3); sinks = icall fn-ptr operands with empty MHS. FSA-compat and
  signature filters applied at sink (intersection is free soundness-preserving precision).
- **writers(o[, off])**: source = `o`'s object node (or subobject); sinks = pointer
  operands of `Store`s reached with top==0 — i.e., "stores through pointers that alias
  &o.off". Used for mutability residue: stationarity checks (M2.5) that tier C couldn't
  certify because Steensgaard's classes were too coarse.
- **escapes(o)**: same traversal; sinks = Ω-flagged nodes, external-call argument
  positions, vararg sinks. Refines M1's class-granular escape bits to object granularity
  — used to *un-taint* components whose unknown-contact was a Steensgaard artifact.

## 2. Steps

### M3.1 — Query kernel: single-threaded, icalls only, no MHS (3–5 days)
Field-*insensitive* first cut (`Gep` treated as `Assign`): implement the S_f/S_b DFS,
visited/memo structure, sink collection, against the existing round-0 call graph (no
fixpoint yet — unresolved icall boundaries are treated as Ω, i.e. sound and coarse).
**Purpose:** get the traversal shape, memoization, and testing harness right before
offsets and rounds multiply the state space. **Acceptance:** fixture suite (hand-built
PAGs with known answers, incl. the aliasing-through-two-levels-of-memory pattern); on
Vim: answers ⊆ tier-C answers for every settled comparison point; per-query node-visit
histograms published.

**Implementation status:** initial `pangs_solve::query_callees_field_insensitive` and
`query_all_callees_field_insensitive` kernel is in place as an internal API. It runs one
source-function query at a time over `(node, phase)` states, treats GEP/memcpy as
assignment-like edges, collects indirect-call operand sinks, and reports per-query
visited-state/worklist metrics. Focused fixtures cover direct assignment, store/load,
two-level memory, independent global function-pointer slots, and the intentional
field-insensitive over-approximation that M3.2's MHS is expected to narrow. The
`pangs query callees` CLI exposes the current kernel for inspection. A synthetic-suite
ledger test asserts M3.1 answers stay inside the Steensgaard envelope, and
`notes/m3_1_query_kernel.md` records the first real-corpus query histogram.

### M3.2 — MHS / byte-offset field sensitivity (3–5 days)
Add the offset stack per §1.2, with `⊤` saturation and the subobject table (M2.1) for
sink interpretation. **This step has the highest unit-test density of the project**;
transcribe as fixtures: KallGraph's unpaired-Gep cases (`(X, nothing)`, `(X+Y, −Z)`),
nested struct copies, container_of-style negative offsets, zero-offset Gep-as-cast.
**Acceptance:** fixtures green; on Vim/PHP icall target sets shrink vs M3.1 (record
deltas); no dynamic-trace violations (M1.8 harness).

**Implementation status:** initial MHS mode is in place for callee queries. `pangs query
callees` defaults to `--mode field-sensitive`, with `--mode field-insensitive` retained
for M3.1 comparison. Fixtures cover field narrowing, two-level memory, unknown-offset
top saturation on store and load sides, negative-offset arithmetic, zero-offset GEP
casts, concrete-offset mismatch rejection, and nested field memory; the synthetic-suite
ledger checks M3.1 and M3.2 answers against the Steensgaard envelope. The first corpus
smoke is recorded in `notes/m3_2_mhs.md`.

### M3.3 — Dependency-tracked CG fixpoint (3–5 days)
Implement §1.4: Dep maps recorded during traversal, per-round re-query scheduling,
convergence detection, round metrics (queries run, new edges, rounds). **Acceptance:**
converges ≤5 rounds on Vim/PHP; final icall sets ⊆ every earlier tier (ledger asserts);
ablation number recorded: edges that round-0 (tiers B/C-seeded) missed and the fixpoint
found — this measures what the bootstrap-free design buys us.

**Implementation status:** initial dependency-tracked callee fixpoint is available as
`pangs query callees --mode field-sensitive-fixpoint`. It rebuilds the MHS query graph
each round with synthetic Assign-shaped arg→param and ret→result bindings for newly
discovered indirect targets, skips imported/external target bindings, applies ABI/FSA
signature filtering when PIR signatures are available, and schedules queries from
callsite argument/result dependencies and callee-return dependencies. Focused fixtures
cover argument-driven discovery, return-driven discovery, and incompatible-signature
rejection. Signature-aware M3.1/M3.2/M3.3 query answers are checked against the synthetic
suite's Steensgaard/FSA envelope. The all-query path now skips non-address-materialized
function objects, uses top-of-stack MHS memoization, and reports automatic 25k query-budget
truncation. Initial release-mode corpus smokes complete on jpegoptim/parson/jq/chibicc/lua,
but jq/chibicc/lua require truncation, so M3.3 is not yet ready for adoption into the main
`analyze` callgraph export. See `notes/m3_3_fixpoint.md`.

### M3.4 — Parallel query pool (2–4 days)
`rayon` over pending queries per round; PAG and all M1/M2 outputs are frozen/read-only;
per-query arena reset between queries (allocation discipline matters more than
parallelism here); optional shared memo cache behind a feature flag (concurrent map,
*cache semantics only* — results must be identical with it off; test exactly that).
**Acceptance:** linear-ish scaling plot to ≥16 cores on PHP; identical outputs
parallel-vs-sequential (bit-for-bit) with the shared cache off *and* on.

### M3.5 — writers() and escapes() queries (3–5 days)
Per §1.5, sharing the M3.2 kernel. Batching note: one traversal from object `o` settles
*all* its fields' writer sets at once (collect (sink, top-offset) pairs) — don't run
per-field queries. Wire into the ledger: stationarity certificates re-checked with
object-granular writers (settles what tier C's class granularity couldn't); component
taint re-derived with object-granular escape (may un-taint components). **Acceptance:**
coverage metric delta on Vim/PHP (this is M3's client payoff step); hand-audit 20
newly-stationary / newly-untainted verdicts (same mandatory-audit policy as M2.5);
queries-per-second and residue-size metrics.

### M3.6 — Steensgaard partition bounding (2–3 days, gated by measurement)
The DESIGN §2-S3 optimization: a per-query node filter derived from tier-C classes (a
traversal can never reach nodes whose points-to class is disjoint from the query's class
closure). **Implement only if M3.4's profiles show queries touching large graph
fractions** — at our scale the visited-set may already bound everything. If implemented:
prove the invariant first on paper (one page: every CFL production preserves
class-reachability), then enable per-query with a debug mode that runs both bounded and
unbounded and asserts equal answers. **Acceptance:** the assertion mode green over the
full corpus query load; speedup recorded.

### M3.7 — Validation & freeze (3–4 days)
- Dynamic icall traces (Vim/coreutils test suites): observed ⊆ ours, now against tier-E
  final edges — the strictest version of the check yet.
- **Memoization soundness probe:** rerun a 1% query sample with memoization disabled,
  assert identical answers (guards the top-of-stack-memo compromise from §1.3).
- Precision dashboard vs the literature's metrics so regressions are comparable:
  % single-target icalls, avg targets/icall, max target set (KallGraph Table 1 format).
- Client end-to-end: coverage, component counts, taint reasons. Freeze.

### M3.8 — (Gated) accelerators: type shortcuts / CastMap consultation (0 or 3–5 days)
Only if M3.4/M3.6 profiling shows long Store…Load chain traversals dominating. Implement
KallGraph §5.1/§5.5 shortcuts then: precompute, per struct-type+offset, edges that jump
from "stored into field (T,off) somewhere" to "loaded from field (T,off) somewhere",
guarded by the object-level CastMap (only cast pairs that survive the M2.6 look-ahead
filter). Soundness argument and tests come with it; skip by default.

## 3. Effort & risk summary

| Step | Est. days | Risk | Mitigation |
|---|---|---|---|
| M3.1 | 3–5 | traversal correctness | fixtures-first; compare vs tier C |
| M3.2 | 3–5 | **MHS subtleties (the milestone's core risk)** | dense fixtures from KallGraph's counterexamples; ⊤-saturation defaults |
| M3.3 | 3–5 | fixpoint termination bookkeeping | monotone-only updates; round cap + alarm |
| M3.4 | 2–4 | cache-coherence "optimizations" breaking determinism | cache-off equality test in CI |
| M3.5 | 3–5 | un-tainting FPs (client-corrupting) | mandatory hand-audit; ledger ⊆ asserts |
| M3.6 | 0 or 2–3 | unsound bounding | paper proof + dual-run assert mode |
| M3.7 | 3–4 | — | — |
| M3.8 | 0 or 3–5 | premature optimization | profile gate |
| **Σ** | **18–30** | | |

**Relationship to M4:** after M3.7's metrics exist, evaluate DESIGN §10-M4's question —
whether a partitioned Andersen tier between C and E still pays. M3's residue sizes and
query times are exactly the data that decision needs.
