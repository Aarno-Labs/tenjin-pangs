# M5 Implementation Plan — (Optional) Flow-sensitive function summaries & thread escape

*Companion to `DESIGN.md` §10-M5. Prerequisites: M1–M3 (M4 optional). This milestone is
**explicitly conditional** — it exists to fix two specific deficits if (and only if) the
earlier milestones' metrics exhibit them. It adds (a) Canary-style bottom-up,
flow-sensitive, per-function summaries with strong updates, upgrading mutability
precision where flow-insensitive smearing is the blocker; and (b) a thread-escape
analysis (Canary's EspObj fixpoint) for when the C→Rust pipeline starts making
`Send`/`Sync`/`Mutex` decisions.*

## 0. Headline — and the symptoms that justify building this

Build M5a (summaries) only if the ledger shows a material population of mutability
queries stuck at "shared mutable" whose hand-audited cause is **flow-insensitive
smearing**, typically one of:
- *reuse patterns:* a buffer/struct written in phase 1, fully reinitialized in phase 2 —
  flow-insensitive `writers()` cannot separate the phases, so stationarity fails even
  though each phase is init-then-freeze;
- *kill-needed cases:* `p = &a; *p = x; p = &b; *p = y` — without strong updates, `a`
  appears written by the second store too;
- *B1 ⊥-poisoning:* init phases that cross code B1's def-use walk refuses (loops carrying
  the reference through memory and back), where a flow-sensitive intra-procedural pass
  would track them fine.
Quantify first: count ledger entries per symptom (the M2.5/M3.5 hand-audits already
produce this taxonomy). If the count is small or the client's coverage isn't bottlenecked
there, **skip M5a**.

Build M5b (thread escape) only when a client actually consumes thread-confinement facts.
None of the current localization work does; the C→Rust ownership stage will.

**Estimated effort if green-lit: M5a 14–22 days; M5b 5–8 days. Independent of each other.**

## 1. Background the implementor needs (self-contained)

### 1.1 The compositional (bottom-up) architecture — Canary ch. 4 of the Cai dissertation
Process functions in **reverse topological order of the call graph** (the M3 fixpoint
call graph; SCCs collapsed and iterated internally to a local fixpoint). For each
function, run an **intra-procedural, flow-sensitive points-to dataflow**; at call sites,
do not descend — apply the callee's precomputed **transfer summary** `Trans(F)`. Each
function is summarized once, used everywhere; functions at the same call-graph level
parallelize (rayon over levels).

State per function:
- top-level SSA values: one global (per-function) binding `PG_top : v → set of (obj,
  cond?)` — flow-insensitivity is fine here because SSA *is* flow-sensitivity for
  registers;
- address-taken memory: per-program-point maps `IN_ℓ / OUT_ℓ : (obj, fld) → pts`,
  propagated over the CFG in reverse post-order until fixpoint (standard iterative
  dataflow; merge = set union at join points).

Transfer rules (the LLVM-relevant subset; offsets via the shared M2.1 subobject table):
```
p = alloca / &g    : PG_top[p] = {o}
p = q (casts, phi) : PG_top[p] ∪= PG_top[q]      (phi: union of incoming)
p = &q->off        : PG_top[p] ∪= subobj(PG_top[q], off)
*x = q             : let T = PG_top[x]
                     if |T| == 1 and strong_update_ok(T.0):
                         OUT[T.0] = PG_top[q]            # STRONG update (kill)
                     else: for o in T: OUT[o] ∪= PG_top[q]  # weak
p = *y             : PG_top[p] ∪= ⋃ { IN[o] | o ∈ PG_top[y] }
call f(a1..an)     : apply Trans(f)  (below)
```
**`strong_update_ok(o)`** — the conditions an implementor must not improvise (each one's
violation is a soundness bug):
1. `o` is a *singleton concrete* object: not a heap site that can allocate repeatedly
   into the same abstract object along a path (allocation in a loop/recursion ⇒ no), not
   the `(o, ⊤)` unknown-offset subobject, not a summarized formal (see Trans below) that
   may bind to several actuals;
2. the store's pointer pts is exactly `{o}` (already checked);
3. `o` is not Ω/external.
When in doubt, weak-update — it only costs precision.

### 1.2 Function summaries `Trans(F)`
Before analyzing `F`, introduce **auxiliary formals** for memory reachable from its
parameters (the dissertation's "transformation at line 3": for each pointer parameter,
synthetic names for `*param`, `*param->fld`, … up to a small depth k, default 2;
deeper ⇒ summarized weakly). Analyze `F` with these as unknown-but-named inputs.
`Trans(F)` then records, in terms of formal-in names:
- *mod set:* which `(formal-derived cell, off)` are possibly/definitely written
  (definitely-written on all paths ⇒ the caller may strong-update through the summary;
  possibly ⇒ weak);
- *pts effects:* for each written cell, the symbolic set of values stored (formals,
  globals, new allocation sites of F);
- *return:* symbolic pts of return value;
- *escape effects:* formal-derived cells passed onward to Ω/external/escaping positions.
At a call site, substitute actuals' pts for formal names. SCCs: iterate members' summaries
to a local fixpoint (start from ⊥-effects, monotone growth, terminates because the
symbolic domain is finite given depth-k).

This is deliberately the *simple* end of compositional analysis (no path guards — see
§1.4). If a callee's behavior exceeds the symbolic domain (e.g., writes through a global
table of pointers), fall back to a coarse "havoc set" summary: weakly-update everything
in the relevant Steensgaard classes — sound, and the ledger's ⊆ discipline confines the
damage to that call site.

### 1.3 What M5a outputs
Per-function, per-cell **phase-aware write facts** strong enough to re-run stationarity
certificates flow-sensitively: "after program point ℓ (the publish/escape point computed
à la B1), no writes to (g, off) occur on any path" — checked on the summarized dataflow
rather than the global flow-insensitive writer set. Ledger entries upgrade from
`SharedMutable` to `Stationary` with provenance `tier: FlowSummary`. (Same mandatory
hand-audit policy as M2.5/M3.5 — these verdicts gate source rewrites.)

### 1.4 Path guards — recorded, not solved (explicitly out of scope unless forced)
Canary annotates value-flow edges with branch-condition *guards* and lets an SMT solver
judge path realizability per query, lazily. That machinery (plus its
semi-decision-procedure filters) is large. M5a v1 must **not** include it; if audited
false "mutable" verdicts trace to infeasible paths (e.g., `if (init_done)` idioms), first
try the cheap special case (recognize boolean once-flags by pattern), and only then
discuss guards+SMT as an M6.

### 1.5 M5b: thread escape (Canary's EspObj/Pted fixpoint, simplified to our need)
Goal: classify objects `thread-confined` vs `thread-shared`, for `Send/Sync/Mutex`
decisions. Over the M3 value-flow facts:
```
EspObj := objects whose address flows into a thread-spawn argument
          (pthread_create arg, or any Ω sink — conservatively shared)
repeat:
    if *x = q with pts(x) ∩ EspObj ≠ ∅:  EspObj ∪= pts(q)     # stored into shared
    Pted(o) := pointers that may point to o (tier-D sets or tier-E alias closure)
until no growth
```
The loop exists because each new shared object exposes new stores (Canary calls this the
cyclic dependence problem); it's a monotone fixpoint over object sets — small and fast.
Output: per-object thread-escape bit + the store/load sites that witness sharing
(the witnesses matter: the C→Rust stage will want to know *where* synchronization is
needed, not just that it is).

## 2. Steps

### M5.0 — Gate & symptom census (1–2 days)
Tabulate unsettled mutability ledger entries by the §0 symptom taxonomy (the audit notes
from M2.5/M3.5/M4 are the raw data; extend the audit sample if thin). Written go/no-go
per sub-milestone with numbers, filed in `metrics/`.

### M5a.1 — Auxiliary-formal transformation & summary domain (3–5 days)
The §1.2 formal-derived-cell naming, depth-k expansion, summary data model, substitution
at call sites, havoc fallback. Fixtures: out-parameter init (`init(&x)` patterns —
*the* C idiom this exists for), nested out-params, summary applied under two different
actuals, SCC pair. **Acceptance:** summaries round-trip on fixtures; havoc-fallback rate
reported on Vim (if most calls havoc, the domain depth/shape is wrong — stop and rethink
before proceeding).

### M5a.2 — Intra-procedural flow-sensitive solver (4–6 days)
§1.1 dataflow with strong updates; `strong_update_ok` implemented exactly as specified,
each condition unit-tested with a would-be-unsound fixture. Bottom-up driver over
call-graph SCC condensation, parallel across levels. **Acceptance:** strong-update
fixtures (kill patterns) produce the precise answer; weak-update fallbacks logged with
reasons; wall-time budget: full bottom-up pass ≤ tier-D's runtime on PHP (it should be
cheaper — Canary built VFGs 70–500× faster than exhaustive SVF-based tools).

### M5a.3 — Phase-aware stationarity re-certification (3–5 days)
§1.3: recompute publish points (reuse B1's escape boundary), check "no writes after
publish" on the summarized dataflow, upgrade ledger verdicts, re-derive client coverage.
**Acceptance:** the M5.0 symptom population shrinks by a measured amount (publish the
before/after); mandatory hand-audit of 20 upgrades; dynamic write-logging spot check on
Vim (instrument stores to 20 sampled globals during the test suite; observed writes must
fall in the predicted init phase).

### M5a.4 — Validation & freeze (2–3 days)
Determinism, ⊆-ledger asserts across all tiers, dashboard freeze, and an honest writeup:
what M5a settled that M2–M4 couldn't, per engineering day spent (this feeds the decision
on whether guard/SMT work would ever be worth it).

### M5b.1 — Thread-escape fixpoint (3–5 days)
§1.5 over existing facts; pthread_create/thrd_create/clone recognized in PIR (extend the
external-function model table); witness recording. **Acceptance:** fixtures (shared via
spawn arg; shared via store-into-shared; confined despite address-taken); report on an
actually-threaded corpus program (Vim is mostly single-threaded — add e.g. tmux or an
nginx module to the corpus for this step).

### M5b.2 — Client wiring (2–3 days)
Expose per-object `thread_escape: {confined, shared(witnesses), unknown}` in the output
schema, versioned for the future ownership client. **Acceptance:** schema reviewed with
whoever owns the C→Rust ownership stage; round-trip test.

## 3. Effort & risk summary

| Step | Est. days | Risk | Mitigation |
|---|---|---|---|
| M5.0 | 1–2 | building M5 on vibes | written census gate |
| M5a.1 | 3–5 | summary domain too weak (havoc everywhere) | havoc-rate checkpoint with stop rule |
| M5a.2 | 4–6 | **unsound strong updates** | conditions as spec'd, each with adversarial fixture |
| M5a.3 | 3–5 | verdict FPs corrupting rewrites | hand-audit + dynamic write-logging |
| M5a.4 | 2–3 | — | — |
| M5b.1 | 3–5 | external thread-API modeling gaps | model table + Ω default |
| M5b.2 | 2–3 | low | — |
| **Σ (both, if green-lit)** | **19–30** | | |

**The standing principle across M2–M5,** worth restating because M5 is where it's most
tempting to violate: every tier may only narrow ledger answers, every narrowing that
gates a source rewrite gets hand-audited at sample size ≥20, and any analysis component
that can't prove a fact must degrade to the previous tier's answer rather than guess.
