# ONCELOCK: Phase-Based Stationarity Certificates for Mutable Globals

*Extension proposal for PANGS (`DESIGN.md`) / PANGS-lite (`DESIGN_lite.md`). Origin: the
init-function recovery idea in Unias (Li et al., "A Hybrid Alias Analysis and Its
Application to Global Variable Protection in the Linux Kernel", USENIX Sec'23),
generalized from a flow-insensitive call-graph fixpoint over `__init` labels to
flow-sensitive **per-global quiescence points** with source-insertable publication sites.
Shares all terminology, soundness posture, and the FN-corruption/FP-coverage asymmetry of
the parent documents; read `DESIGN.md` §1 and §7 first. Output flows through the
disposition manifest: this pass produces the `facts.phase_stationarity` payload of
`pangs-manifest.json`, and the policy stage of `DISPOSITION.md` owns strategy choice and
client delivery.*

## 0. Problem and intent

**The gap.** B1 stationarity (CORAL Stage Zero) certifies "writes ⊆ initialization
phase" using an *object-centric* init window: track a newly created object from its
allocation point until its reference is stored into other memory. Globals have no
allocation point — they exist before `main`, their addresses are link-time constants
available to every function — so the window is ill-defined and B1 cannot certify them
(except the degenerate `never-written` case, which the cheaper tier already handles).
Consequently a *runtime-populated-once* global — a dispatch table filled by registration
calls, an option table populated from argv/config, a computed lookup table — falls to
`shared mutable`, and the localization client threads it through the context struct,
rewriting every call chain from `main` to every access. Dispatch tables sit at the center
of the call graph, so this single classification miss inflates the rewrite set more than
almost any other global could.

**The fix.** Supply the missing init window from the call-graph/CFG side: for each global
`g`, find the earliest source statement boundary `P` in `main` (or its spine) after which
no write to `g` can ever execute, and which every later observation of `g` provably
follows. `P` is exactly where the C→Rust conversion inserts `G.set(value).unwrap()` on a
`static G: OnceLock<T>`; every read site downstream of `P` reads the static with **zero
signature changes**, and only the (enumerated, small, `main`-rooted) init-phase writer
subtree needs local rewiring.

**Why we believe the payoff is large.** Unias found 42% of Linux-kernel globals are
write-free after initialization; populate-once-at-startup is the most common lifecycle
for globals in mature C programs (registration loops, config parsing, computed tables,
locale/terminal setup) — and Vim/PHP-class programs are exactly the demographic. Each
certified global is removed from the localization problem *entirely*: no context-struct
slot, no call-chain rewrites on read paths. Per the house asymmetry, every failure to
certify is coverage loss, never corruption.

**Placement.** A post-pass in phase F of the lite pipeline (client scans over the
materialized solution). It consumes only facts the pipeline already computes; it adds no
new pointer analysis and no new soundness surface. It refines the mutability lattice's
`stationary` tier (`DESIGN.md` §4F): `phase-stationary` is a new certificate form for
that tier, applicable to globals where B1's object-centric certificate is not. The pass
emits facts only; whether a certified global actually becomes a `OnceLock` is decided by
the disposition cascade (`DISPOSITION.md` §1).

## 1. Design

### 1.1 Terminology

| Term | Meaning |
|---|---|
| **statement boundary** | A point between two top-level statements of a function body (incl. inside compound statements: top of a branch arm, after a loop). The only candidate insertion points — never CFG edges, so **no edge splitting**, compatible with source-level refactoring. |
| **spine** | `main`, plus functions spliced into it by spine descent (§1.6). |
| **TransMod(f) / TransRef(f)** | Transitive may-write / may-read sets of globals per function, over the final call graph, derived from the pointer analysis (already computed for the localization client, `DESIGN.md` §7 item 3). |
| **WritableAfter(p)** | Set of globals writable by any execution from boundary `p` onward (§1.2). |
| **Q(g)** | Quiescent region of `g`: `{p : g ∉ WritableAfter(p)}`. Successor-closed by construction. |
| **observation of g** | Any way `g`'s value can be seen: a read (attributed to its call sites on the spine), or a *pseudo-read* (§1.4). |
| **publication point P(g)** | The chosen statement boundary where `set()` is inserted. Must satisfy the certificate (§1.3). |
| **publication interval** | The contiguous dominator-chain interval of valid choices for `P(g)`; reported even when a specific `P` is chosen. |
| **init subtree of g** | The functions containing pre-`P` writes/reads of `g`, i.e., the rewrite worklist (§4.2). |

### 1.2 The quiescence dataflow

Over the spine's CFG at statement-boundary granularity, one backward union dataflow:

```
gen(s)            = directWrites(s) ∪ TransMod(callees(s))     for statement s
WritableAfter(p)  = ⋃ { gen(s) : s reachable from p }
```

Implemented as a standard backward fixpoint (`WritableAfter[p] = gen(succ) ∪
WritableAfter[succ]` joined over successors); converges in a pass or two since it is
monotone set union over a single function's CFG. `directWrites` and `TransMod` come from
the pointer analysis (writes through pointers into `g` are included — this is *not*
syntactic). `callees(s)` uses the final call graph, so icall sites contribute the union
over resolved targets; icalls with Ω in their target set contribute ⊤ (all globals),
which correctly poisons everything after an unknown call.

Note what is *absent*: any notion of "the main loop." An init loop in the prologue
(`for (i = 0; i < n; i++) register_cmd(...)`, the argv-parsing `while`) keeps `g` in
`WritableAfter` throughout the loop and drops it at the loop exit — a statement boundary.
A `main` with no syntactic loop at all (event-library callback style, git-style argv
dispatch) is handled identically: only reachability to write sites is measured.

### 1.3 The publication-point certificate (single-P, v1)

`g` is **phase-stationary with publication point P** iff:

1. **P ∈ Q(g)** — no write to `g` is reachable from `P`; and
2. **P dominates every observation of `g` not routed through the init-phase local** —
   i.e., every path from program entry to a non-routed observation passes through `P`.

Observations *before* `P` are legal: they are classified pre-`P` and routed through the
under-construction local by the rewrite (§4.2). This gives placement freedom: the valid
choices of `P` form a contiguous interval on the spine's dominator chain, from the first
quiescent spine boundary down to just before the first non-routed observation. **Choose
the earliest valid P** — it minimizes the pre-`P` routing set. Report the whole interval
(an empty interval is itself the failure diagnosis: writes never quiesce, or an
observation precedes quiescence).

Merge points recover almost everything an edge-based (frontier) formulation would give:
`Q(g)` is successor-closed, so where both arms of a config `if` finish initializing `g`,
the join after the `if` is in `Q(g)` and is a statement boundary. A read *between* one
arm's early quiescence and the join simply lands in the pre-`P` routing bucket — and it
is located in the spine itself, the cheapest possible place to reroute.

The inserted `G.set(v).unwrap()` doubles as a **runtime assertion of the certificate**:
if the analysis were wrong about single execution of `P`, the second `set` panics loudly
(never silently re-initializes); if a read raced ahead of `set`, `get().unwrap()` panics
at the read site. Both failures are noisy, per the "corruption must never be silent"
posture.

### 1.4 Observations and pseudo-reads

The observation set of `g`, all expressed as spine statement boundaries:

- **Attributed reads:** every spine statement `s` with `g ∈ TransRef(callees(s))`, plus
  direct reads of `g` in the spine itself.
- **Escape pseudo-reads:** every spine statement where the address of a `g`-reading
  function escapes to Ω (registering a signal handler, passing a callback to a library,
  `atexit` of a reader). External code may invoke the reader at any time after that
  point, so `P` must *dominate the registration*, not the eventual read. Escape sites
  are already known from the Ω machinery.
- **Spawn pseudo-reads:** every thread-spawn statement whose entry function has
  `g ∈ TransRef` — the thread may read concurrently with everything after the spawn.

This unification is what makes the reader side sound with no concurrency reasoning: every
channel by which `g`'s value can be observed is either a call-graph-attributed read or a
registration/spawn event at a known spine point, and dominance by `P` covers all of them.

### 1.5 Kill rules

`g` gets **no certificate** — regardless of frontiers — if any of:

1. **Ω-escaped writer:** any function with `g ∈ TransMod` whose address escapes to Ω
   (callback/signal-handler/atexit writers can run at any time). Note `atexit` handlers
   that write `g` are caught here: the handler's address escapes to libc.
2. **Thread writer:** `g` is in the transitive mod set of any spawned thread's entry
   function. (v1 ignores joins; a join-aware refinement is possible later. Single-threaded
   targets — Vim, PHP-CLI — lose nothing.)
3. **Violation taint:** any writer or `g` itself carries assumption-violation taint
   (inline asm, setjmp/longjmp on relevant paths, int↔ptr events) — inherited unchanged
   from the Ω-taint discipline of `DESIGN.md` §7.
4. **Recursive main:** `main` has in-edges in the call graph (legal in C). All spine
   ordering reasoning breaks; certify nothing.
5. **Unknown-call poisoning before quiescence** is not a separate rule — Ω-target icalls
   contribute ⊤ to `gen` (§1.2) and naturally prevent quiescence until after them.

All five are lookups against bits the pipeline already computes. The same bits (thread
visibility, Ω-escaped address, violation taint) are additionally surfaced as first-class
facts in the disposition manifest (`DISPOSITION.md` §2), where other strategies'
eligibility checks reuse them.

### 1.6 Spine descent

If `main` is a shell (`main() { setup_locale(); run(); }`), every global is writable from
the call to `run()` and no in-`main` frontier exists. Descend: if a single call site
`c → f` dominates `g`'s writability, and `f` has no other call sites (or all other call
sites are provably dead / in already-quiescent positions), splice `f`'s statement-level
CFG in place of `c` and re-run the dataflow. Iterate to a small depth bound (default 4).
The uniqueness condition is the soundness condition: a function called from exactly one
once-reachable site executes as if inlined there. This handles the near-universal
`main → app_main → loop` idiom (Vim: `main → vim_main2`).

After descent, `P` may live inside a spine function other than `main` — the schema names
the containing function explicitly (§2).

### 1.7 Library / no-main mode (v2)

With no `main` (or when init lives outside it — PHP's module lifecycle: `MINIT` once,
then the request loop), the spine roots and their ordering contract become an **input**:
the client designates entry functions and asserts ordering ("`php_module_startup`
completes before any request executes"). Each such assertion is recorded in the audited
soundness inventory (`DESIGN.md` §8) like any other assumption. No designation ⇒ certify
nothing (coverage loss, never corruption). This extends the existing build-mode flag of
`DESIGN.md` §11.3.

This mode is **deferred to v2**. v1 certifies only executable-mode analyses with a real
`main` spine. If the analyzed program is in library/no-main mode, v1 emits
`no-entry-spine` for every otherwise-candidate global and does not accept manual ordering
assertions. The v2 work item is the input format, audit plumbing, and validation for
designated roots/order contracts.

### 1.8 Deliberately out of scope for v1 (and the gate for v2)

**Multi-point placement.** The single-P criterion fails on mode-split mains:

```c
if (daemon_mode) { load_daemon_overrides(&tbl); daemon_loop(); }   /* writes + reads */
else             { run_once(); }                                    /* reads          */
```

No single boundary is both after the arm-local writes and dominating the other arm's
reads. The generalization — one `set()` per arm; obligation becomes "every path to a
non-routed observation passes through exactly one insertion point, each after all writes
on its path" — is still pure source insertion and keeps the `.unwrap()` assertion. It is
deferred because its value is measurable before it is built: v1 counts, for free, the
globals with `Q(g) ≠ ∅` but no valid single `P` (reason code `no-single-P`). Build v2
iff that count is material on Vim/PHP (§6).

**Library/no-main roots and ordering assertions**, **join-aware thread reasoning**,
**grouped/conditional publication**, and **partial stationarity (per-field phase
certificates)** are likewise deferred; see §7.

## 2. Output facts (the manifest's `phase_stationarity` payload)

*This pass no longer emits a standalone JSON document — the original schema_version-1
form is superseded.* The per-global payload below is embedded verbatim as
`facts.phase_stationarity` in `pangs-manifest.json` (schema v2, `DISPOSITION.md` §3).
Global identity, linkage, and type spelling live in the manifest record's `key`/`meta`;
the entry-spine description lives in the manifest's run header; the coupling-group id is
a sibling fact (`facts.coupling_group`) from the shared coupling post-pass (§2.3).
Coordinates inside the payload are same-run evidence, never identity (`DISPOSITION.md`
§3.1). Stable field names; additive evolution only.

### 2.1 Per-global payload

```jsonc
// inside a pangs-manifest.json global record (DISPOSITION.md §3.2):
//   { "key": "src/commands.c::cmd_table",
//     "meta": { "linkage": "internal", "type": "struct cmd_entry [512]" },
//     "facts": { "phase_stationarity": <this object>,
//                "coupling_group": "grp-cmd", ... },
//     "disposition": { ... } }
{
  "verdict": "phase-stationary",     // "phase-stationary" | "not-certified"
  // ---- present iff verdict == "phase-stationary" ----
  "certificate": {
    "publication_function": "main",  // may be a spine function after descent
    "publication_point": { "file": "src/main.c", "line": 88, "col": 5,
                           "after_stmt": "parse_rc_file(rcpath(argv));" },
    "publication_interval": {        // full valid range, for client flexibility
      "earliest": { "file": "src/main.c", "line": 88 },
      "latest":   { "file": "src/main.c", "line": 102 }
    },
    "spine_descent_path": [],        // call sites spliced, outermost first
    "kill_rules_checked": ["omega-writer", "thread-writer",
                            "violation-taint", "recursive-main"],
    "assumptions": []                // per-global extra assumptions, if any
  },
  "writers": [                       // ALL provably pre-P; the rewrite worklist
    { "function": "register_cmd", "site": { "file": "src/commands.c", "line": 31 },
      "kind": "via-pointer" },       // "direct" | "via-pointer"
    { "function": "register_cmd", "site": { "file": "src/commands.c", "line": 32 },
      "kind": "direct" }
  ],
  "init_subtree": [                  // functions needing local rewiring, with the
    { "function": "init_builtin_cmds",     // spine call sites that reach them
      "spine_call_sites": [{ "file": "src/main.c", "line": 86 }] },
    { "function": "parse_rc_file",
      "spine_call_sites": [{ "file": "src/main.c", "line": 87 }] },
    { "function": "register_cmd", "spine_call_sites": [] }   // interior node
  ],
  "readers": {
    "pre_p": [                       // route through the local
      { "function": "register_cmd", "site": { "file": "src/commands.c", "line": 30 } }
    ],
    "post_p_functions_count": 143,   // unchanged signatures; count + sample only
    "post_p_sample": ["execute", "complete_cmd", "show_help"],
    "both_phase": []                 // functions read-reachable from both phases:
                                     // the awkward bucket, listed exhaustively
  },
  "observations": {                  // pseudo-reads that constrained P
    "escape_sites": [],              // e.g., signal handler registration of a reader
    "spawn_sites": []
  },
  // ---- present iff verdict == "not-certified" ----
  "failure": null                    // see §2.2 reason codes
}
```

### 2.2 Failure reason codes (`failure.reasons`, list)

Failure codes are **routing input for the disposition cascade** (`DISPOSITION.md` §1),
not terminal verdicts: a global this pass cannot certify falls through to the next
strategy in the cascade, and the witness tells that strategy where to look first.

| Code | Meaning | Cascade-visible implication |
|---|---|---|
| `never-quiescent` | `g ∈ WritableAfter(p)` for all spine `p` (written in/under the steady state) | genuinely mutable here; routes onward — an always-incremented counter with this code is the canonical `atomic` candidate |
| `observation-before-quiescence` | `Q(g) ≠ ∅` but an observation precedes every quiescent point and can't be routed | possibly rescuable by routing more reads; site list attached |
| `no-single-P` | `Q(g) ≠ ∅`, observations exist in never-rejoining branches | **the v2 gate counter** (§1.8) |
| `omega-writer` / `thread-writer` / `violation-taint` / `recursive-main` | kill rules §1.5 | frozen; report names the offending function/site |
| `spine-descent-exhausted` | wrapper nesting deeper than bound / non-unique call sites | raise bound or designate spine manually |
| `no-entry-spine` | v1 executable-mode spine is unavailable (no `main` / library mode) | v2: provide entry-spine input |

Every failure record carries the *witness* (the site/function that triggered it) so the
diagnosis is mechanical, matching the provenance-tag philosophy of `DESIGN_lite.md` §6.

### 2.3 Co-quiescence groups (detection moved to the shared coupling component)

Coupled globals (e.g., `cmd_table` + `cmd_count`, whose readers assume mutual
consistency) matter beyond this pass: the same co-write evidence gates atomic
eligibility and sets mutex granularity. Detection therefore lives in the shared coupling
post-pass (`DISPOSITION.md` §6, work item D2b), which uses this pass's publication
intervals (overlap) and init subtrees (intersection) as part of its clustering evidence.
This pass *consumes* group ids (`facts.coupling_group`): certified members of one group
should publish as **one `OnceLock<Struct>` at one `P`** — a reader seeing new
`cmd_count` with old `cmd_table` becomes unrepresentable. Group disposition resolution
(weakest member wins, overrides) belongs to the policy stage, not here.

### 2.4 Report artifacts

- **Quiescence profile:** all globals sorted by publication point (or failure), i.e., a
  timeline of `main` showing where each global settles. Feeds the `DESIGN.md` §11.4-style
  "which unknowns/writes are load-bearing" review, and makes almost-stationary globals
  (single late writer) visible as manual-refactor candidates.
- **Gate counters** (§6) emitted unconditionally.

## 3. Implementation plan

### 3.1 Inputs

| Input | Producer |
|---|---|
| Final call graph incl. icall targets, Ω-target icalls | D' outer loop (lite §2) |
| `TransMod` / `TransRef` per function | localization client (`DESIGN.md` §7 item 3) |
| Writer/reader *sites* per global (store/load with pts ∋ g) | F post-pass `writers(o)` scan |
| Ω escape bits, escaped-function-address sites | A'/C'/D' Ω machinery |
| Violation taint | A' detection |
| Thread-spawn sites + entry functions | A' (pthread_create et al. modeling) |
| Coupling-group ids | shared coupling post-pass (`DISPOSITION.md` §6, work item D2b) |
| Statement-boundary CFG + insertable boundary map for spine functions | **new lowering/PIR metadata** — O1 below, from `-O0`/`-O1` debug locations |
| Global source metadata (`translation_unit`, linkage, type spelling) | **new lowering/PIR metadata** — needed by the §2 schema and refactoring consumer |

The v1 implementation is allowed to extend `pangs-pir` and LLVM lowering. In fact, it
must: reconstructing statement boundaries from the current linear `Func.body` alone is
not a sound basis for the branch, loop, dominance, and spine-descent cases in this
document.

### 3.2 Work items

- **O1 — lowering/PIR statement-boundary CFG (~300–500 lines).** Extend LLVM lowering
  and `pangs-pir` with statement-boundary records for `main` and descent candidates:
  group IR instructions by debug-location statement, preserve successor/predecessor
  relationships at statement-boundary granularity, and verify each boundary maps to a
  unique `(file, line, col)` insertion point. Macro-expanded statements: take the
  expansion site; if a boundary is ambiguous (multiple statements per line, non-monotone
  locations), mark it non-insertable — `P` selection simply skips it. This is a required
  v1 input, not a best-effort API-side reconstruction. Depends on `-O0`/`-O1` IR with
  debug info; builds lacking the required debug/CFG metadata emit no certificates.
- **O1b — global metadata lowering (~100 lines).** Extend PIR globals with the type
  spelling and linkage category consumed by §2. Missing metadata is represented
  explicitly (`null`/`unknown`) only where the refactoring can tolerate it; otherwise the
  affected global is not certified.
- **O2 — quiescence dataflow (~150 lines).** `gen` per statement from
  direct writes + `TransMod(callees)`; backward union fixpoint; per-global earliest
  quiescent boundary. Represent `WritableAfter` as bitsets over the (small) set of
  client-relevant globals only.
- **O3 — observation sets + P selection (~250 lines).** Attributed reads via
  `TransRef(callees)`; escape/spawn pseudo-reads from Ω and spawn-site inputs; dominator
  tree on the statement CFG; compute the publication interval; choose earliest valid
  insertable `P`; partition readers pre/post/both.
- **O4 — kill rules (~100 lines).** Five lookups (§1.5) against existing bits; attach
  witnesses.
- **O5 — spine descent (~200 lines).** Unique-call-site check, statement-CFG splicing,
  re-run O2/O3, depth bound, record descent path.
- **O6 — facts emission + reports (~150 lines).** §2 payload handed to the manifest
  assembler (`DISPOSITION.md` work item D1), quiescence profile, gate counters.
  Co-quiescence clustering moved out to the shared coupling post-pass (D2b); this pass
  only exports publication intervals and init subtrees as clustering evidence.
- **O7 (v2, gated) — multi-point placement.** Only if the `no-single-P` counter is
  material at the §6 measurement.
- **O8 (v2) — library/no-main entry spines.** Add the input format, audited ordering
  assumptions, and schema population for designated lifecycle roots.

Order: O1/O1b → O2 → O4 → O3 → O6, with O5 inserted once O2/O3 are stable (it only
re-runs them on a spliced CFG). The certificate computation remains a post-pass in F; the
new source-boundary and global-metadata facts are produced by lowering/PIR before A' and
do not change A'–D' solver semantics. Rough total: ~1.3k lines, no new dependencies.

### 3.3 Cost at runtime

Negligible relative to the pipeline: one function's CFG (plus ≤4 spliced callees),
bitset dataflow over it, a dominator tree, and set operations sized by
`|client-relevant globals| × |spine statements|`. Microseconds-to-milliseconds at the
1 MLoC target.

### 3.4 Testing and validation

1. **Unit CFG tests:** hand-written mains covering: init loop before steady loop;
   branchy init with merge-point `P`; read-between-quiescence-and-merge (must land
   pre-`P`); mode-split (must emit `no-single-P`, not a wrong certificate); wrapper main
   (descent); signal-handler reader (escape pseudo-read constrains `P`); atexit writer
   (killed); recursive main (killed).
2. **Golden files:** full schema output on small programs, diffed across changes
   (matches the lite testing idiom, `DESIGN_lite.md` §2F).
3. **Dynamic certificate check (the load-bearing one):** instrument test builds to log
   every store to certified globals with a flag flipped at `P` (compile-time injection of
   a marker call at `P`'s source location — which also exercises the insertion-point
   mapping end-to-end). Run the program's own test suite + AFL++ fuzzing per the
   `DESIGN.md` §9 plan. **Any post-P store to a certified global is a soundness bug**,
   triaged with the same seriousness as a missed icall edge. This replicates Unias's
   field-granularity FN audit, which is the right standard of evidence for output that
   drives transformation.
4. **Cross-check vs. B1:** objects certified stationary by both B1 (object-centric) and
   this pass (phase-centric) must agree; disagreements are free regression tests for
   whichever is wrong.

## 4. How the refactoring consumes the schema

### 4.1 Target shape (C→Rust)

Per certified group (§2.3):

```rust
static CMD: OnceLock<CmdTables> = OnceLock::new();   // group struct: table + count

fn main() {
    let mut cmd = CmdTables::default();      // the init-phase local
    init_builtin_cmds(&mut cmd);             // init subtree: &mut parameter added
    parse_rc_file(&mut cmd, rcpath());
    CMD.set(cmd).unwrap();                   // inserted at P; unwrap = certificate assert
    main_loop();                             // post-P world: signatures untouched
}

fn execute(name: &str) {                     // arbitrary depth, unchanged signature
    let cmd = CMD.get().unwrap().lookup(name);
    ...
}
```

C→C-stage consumption follows `DISPOSITION.md` §5.3: a global disposed `once-lock` is
exempt from localization **and** receives a no-op publication-marker call planted at `P`
— the only source-anchored fact the Rust rewriter needs, immune to the coordinate drift
the localization rewrite causes. The C→C tool never restructures init code. (The earlier
"purely subtractive" framing is superseded: subtractive, plus the marker.)

### 4.2 Rewrite algorithm (mechanical, driven entirely by schema fields)

1. **Declare** `static G: OnceLock<T>` (or the group struct) at the global's module;
   delete the C global definition.
2. **Materialize the local** at the start of the publication function (or at the top of
   the publication interval): `let mut g_local: T = <static initializer>;`.
3. **Rewire the init subtree** (`init_subtree` field): add a `&mut T` parameter to each
   listed function; rewrite their `writers[*]` sites and `readers.pre_p[*]` sites to go
   through the parameter; update the listed `spine_call_sites` to pass `&mut g_local`.
   The subtree is closed by construction (all pre-`P` accesses are inside it), so this
   step never cascades beyond the listed functions.
4. **Insert publication** by replacing the marker call the C→C stage planted at
   `certificate.publication_point` (`DISPOSITION.md` §5.2) with
   `G.set(g_local).unwrap();`.
5. **Rewrite post-P reads** as `G.get().unwrap()` at each use (or hoist one
   `let g = G.get().unwrap();` per function). No signature changes; `post_p` reads are
   the unenumerated majority by design — any read site not listed in `pre_p`/`both_phase`
   is post-P.
6. **Both-phase readers** (`readers.both_phase`): per-function decision, see §4.3. If
   the bucket is nonempty and the client declines to handle it, *skip this global* —
   certified-but-unconsumed is safe (it just stays in the localization set).

Steps 1–5 touch only: the global's definition site, the enumerated init subtree, the one
publication line, and read expressions — the read-path call graph is never edited. That
is the entire value proposition.

### 4.3 Both-phase readers

A function that reads `g` and is reachable from both pre-`P` and post-`P` call sites
cannot know which copy to read. Options, in preference order:

1. **Push P earlier** within the publication interval so the reader becomes post-P-only
   (the interval in the schema exists for exactly this negotiation).
2. **Parameterize the reader** with `&T` (a small, local signature change — note `&`,
   not `&mut`, so it composes freely), passing `&g_local` pre-P and
   `G.get().unwrap()` post-P.
3. **Decline** (global stays localized). Never guess.

### 4.4 Interaction with the localization client

Certified globals shrink the context struct and — because dispatch tables are
component-shaping — can *split* caller↔callee components that would otherwise merge into
mega-components (`DESIGN.md` §11.4 risk). The quiescence profile should therefore be read
together with the component-size distribution at M3: phase certificates are one of the
mitigations for exactly that risk. If the team prefers uniformity (everything in the
context struct, no statics), the degraded-but-still-useful consumption is: the field
becomes a plain `T` read through `&Ctx` instead of `RefCell<T>`/`Mutex<T>` — each field
demoted from mutable to shared removes `&mut`-borrow conflicts from every function
touching the struct.

### 4.5 Worked example

See §0/§4.1 (`cmd_table`). The instructive negative case: real Vim's `:command` defines
user commands at runtime, so the registration path is reachable from the steady state ⇒
`never-quiescent` with the steady-state call site as witness — correctly refused, whereas
a syntactic "writes only in functions named init_*" heuristic would corrupt. The analysis
distinguishes the two programs; that is the whole point of computing reachability rather
than pattern-matching.

## 5. Additions to the soundness inventory (`DESIGN.md` §8)

- **Entry-spine ordering** (library mode, v2): client-asserted, recorded per run, listed
  in the schema (`entry_spine.assumptions`). v1 does not accept these assumptions and
  certifies only the executable `main` spine.
- **Threads:** thread-written globals are never certified (v1); thread-*read* globals are
  certified only when `P` dominates the spawn (pseudo-read). No memory-model reasoning is
  needed beyond this: `OnceLock` publication is itself a release/acquire pair.
- **Signals/callbacks/atexit:** reader registrations are pseudo-reads; writer
  registrations kill. Both ride on existing Ω facts.
- **Runtime assertions as defense-in-depth:** the inserted `.unwrap()`s convert any
  residual certificate error into a loud panic at the faulting site, never silent
  corruption. (This is a mitigation, not a license to weaken the static side.)
- **`-O0`/`-O1` + debug info** is load-bearing for the statement-boundary CFG and
  insertion-point mapping (O1), not just for analysis fidelity. The build must assert
  that required debug/CFG metadata is present; otherwise phase-stationarity certification
  is disabled for that run.

## 6. Measurements and decision gates (fold into lite M3)

Emit unconditionally, judge on Vim + PHP:

1. **Coverage:** certified globals / client-relevant mutable globals; and the localization
   coverage delta with certificates consumed vs. not. *This is the headline number*,
   now reported inside the disposition distribution of `DISPOSITION.md` §10.
2. **`no-single-P` counter** (with witnesses): gates O7 (multi-point placement, §1.8).
3. **Both-phase bucket sizes:** if persistently large, invest in interval negotiation
   (§4.3 option 1) or reader parameterization tooling.
4. **Spine-descent depth histogram:** validates the default bound of 4.
5. **Dynamic audit result** (§3.4 item 3): must be zero post-P stores; any nonzero is a
   stop-ship soundness bug, not a statistic.

## 7. Open questions

1. **Per-field phase certificates.** A struct global where field `.handlers` quiesces but
   `.stats` never does. The dataflow generalizes (track `(g, byte-range)` — the writer
   sites already carry offsets), but the Rust target shape gets awkward (split the
   struct?). Likely v2+, driven by witnesses from `never-quiescent` failures.
2. **Conditional initialization** (`if (use_crypt) init_crypt_table();` — the global is
   quiescent but possibly never written). `OnceLock` handles it only if readers tolerate
   absence; simplest sound treatment is to publish the (possibly default-valued) local at
   `P` unconditionally. Decide whether default-publication is always acceptable or needs
   a schema flag (`may_be_unwritten`).
3. **Join-aware thread reasoning** (writer thread joined before `P`): real programs do
   parallel init. Deferred; needs happens-before at spine granularity only, so it may be
   cheap. Gate on how many `thread-writer` kills appear with a pre-`P` join witness.
4. **Interval negotiation protocol** between analysis and refactoring: v1 emits the
   interval and the refactoring picks; should the refactoring be able to ask "what would
   the buckets look like at boundary X?" without a re-run? (Cheap to answer: ship the
   per-boundary reader partition for the whole interval if small.)
5. **C→C staging — resolved** in `DISPOSITION.md` §5.3: exemption plus a publication
   marker at `P`; the C→C tool never restructures init code (a C-level rewrite would
   add risk without adding information). The marker — a no-op call whose name embeds
   the global's identity key — is what makes the Rust-side rewrite coordinate-free.
