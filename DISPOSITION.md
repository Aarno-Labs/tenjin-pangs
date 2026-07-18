# DISPOSITION: Per-Global Strategy Assignment and the Client Interface

*Companion to `DESIGN.md`, `DESIGN_lite.md`, and `ONCELOCK.md`. This document specifies
the layer between the PANGS analysis and its consumers, now that there is more than one
consumer and more than one way to handle a global. It defines: the separation of
**facts** (analysis output) from **policy** (strategy choice); the **manifest** schema
that carries both; the **disposition cascade** and its user-override mechanism; and the
**marker contract** by which decisions survive the C→C refactoring into the Rust world.
It also enumerates the required amendments to the other documents (§8).*

## 0. Thesis: facts are computed, dispositions are chosen

The original architecture had one client (localization of all mutable globals, as a C→C
refactoring) and one carve-out (`ONCELOCK.md`, consumed subtractively as an exemption
list). The purview is now:

| Disposition | Rust shape | Consumed by |
|---|---|---|
| `immutable` | `static G: T` | Rust-side rewriter |
| `once-lock` | `static G: OnceLock<T>` (`ONCELOCK.md`) | Rust-side rewriter |
| `atomic` | `static G: AtomicI32` etc. — not a mutable static | Rust-side rewriter (future) |
| `mutex` | `static G: Mutex<T>` | Rust-side rewriter (future) |
| `localize` | field of the threaded context struct | C→C localization tool |
| `unhandled` | left as-is (`static mut` + unsafe, or manual) | nobody; reported |

Exemption-chaining does not scale to this set: a word-sized counter can qualify for both
`atomic` and `mutex`; an override can contradict a certificate; `localize` applies only
to applications while `atomic`/`mutex` also serve libraries. The structural fix is a
strict two-layer split:

- **Facts** — objective, per-global, produced by analysis post-passes, never mention
  dispositions. "Phase-stationary with certificate C", "access set complete",
  "thread-visible", "member of coupling group grp-cmd". A fact is either proven (with
  witness/certificate) or absent; there is no preference in the fact layer.
- **Policy** — a thin, deterministic **disposition stage** that maps each global's fact
  vector through a preference cascade (§1), applies user overrides (§4), resolves
  coupling-group constraints (§6), and records the final disposition *with provenance*
  in the manifest.

Consequences worth making explicit:

1. Clients consume **the disposition assignment**, never each other's exemption lists.
   The localization tool no longer knows or cares *why* a global is exempt.
2. Failure codes stop being terminal. `ONCELOCK.md`'s `never-quiescent` on an
   always-incremented counter is not "goes to localization"; it is routing input for the
   atomics pass, whose first question (word-sized? all writes are RMW?) the witness
   already begins to answer.
3. Adding a strategy = adding a fact-producing post-pass + a cascade entry + a rewriter.
   No existing pass changes.

The analysis core (A′–D′, Ω, the materialized solution) is untouched by all of this;
every fact named in this document is a phase-F scan over facts the pipeline already
computes, in the lite idiom.

## 1. The disposition cascade

The policy stage assigns each client-relevant global the **first applicable** entry:

```
1. immutable   iff  never-written ∧ ¬omega-escaped-address
2. once-lock   iff  phase-stationarity certificate present
3. atomic      iff  atomic-eligibility certificate present
4. mutex       iff  mutex-eligibility certificate present
5. localize    iff  build mode = application ∧ localization verdict OK
6. unhandled   otherwise (with the accumulated failure witnesses)
```

Guard-shape rule: **a strategy backed by an eligibility pass has a certificate-only
guard** — the cascade reads one slot, and the pass's certificate internally requires
its precondition facts (D4's requires `access_set_complete`,
`¬signal_context_access`, and the reentrancy check; D3's analogously) — while
strategies without a pass (`immutable`, `localize`) compose raw facts directly.
Duplicating a pass's preconditions in the cascade guard would create a second,
divergeable definition; the slot's failure codes already say *which* precondition
failed, and that is what `cascade_trace` reports (a mutex skip is
`guard-failed: ["mutex_eligibility"]` or `fact-not-computed`, with the detail in
the slot).

Rationale for the order: **prefer the applicable strategy that encodes the strongest
verified property in the Rust type system.** `immutable` makes illegal writes
unrepresentable; `once-lock` makes re-initialization a loud panic and needs no
per-access synchronization reasoning; `atomic` constrains every access site but
permits torn multi-global invariants; `mutex` is the general fallback with runtime cost
and deadlock surface; `localize` is the most invasive rewrite.

The order is a **preference list over independent applicability predicates**, not a
proof lattice. A certificate for one strategy never implies support for a later
strategy: for example, phase-stationarity does not prove atomic access-shape
compatibility or mutex reentrancy safety. "First applicable" is sound because every
entry evaluates its own guard; order affects preference only.

One fact gates the whole cascade rather than any single entry: **every strategy guard
implicitly conjoins `¬violation_taint`**. A tainted global's fact vector was computed
under violated analysis assumptions, so no certificate about it is trustworthy; it
falls through to `unhandled` with every configured strategy skipped as
`guard-failed: violation_taint`. Any override pinned onto a tainted global is a
contradiction under §4.2 and requires `accept_risk`. If the skip histogram (§10.2)
shows taint dominating the `unhandled` bucket, the remedy is analysis-side (narrow the
violation), never a policy-side exception.

Two knobs, both policy-level (never analysis-level):

- **`localize` vs `mutex` preference.** Applications default to the order above
  (historically `localize` was the whole point; but see the M3 note in §10 — `mutex`
  may become the preferred default if context-struct bloat dominates). Libraries have
  no `localize`; the "applications only" restriction of the original client lives
  *here*, in the cascade config, and nowhere in the analysis.
- **Uniformity mode** (`DESIGN.md` §11.4 discussion): a client may shrink the
  configured order (e.g., `order = ["localize"]` — "no statics at all — everything
  localizes") without touching facts. Earlier strategies are disabled by *omission*:
  the configured order is the exhaustive list of enabled strategies.

Both knobs live in one concrete config, `{ mode, order }` — TOML surface in §4.1, full
semantics (defaults, exhaustiveness, error cases) in `DISPOSITION_PLAN.md` §1.6.

The cascade, its knob settings, and the manifest schema version are recorded in the
manifest header so a run is reproducible from its output.

## 2. The fact vector (replaces the linear mutability lattice)

`DESIGN.md` §4F's lattice (`never-written → stationary → thread-confined → shared`) was
a single client's verdict. The new strategies key off **orthogonal** combinations —
phase-stationarity is independent of thread-visibility (a phase-stationary global read
by threads is precisely the OnceLock case); atomic eligibility is independent of both.
The internal representation becomes a vector of independent facts; the lattice survives
only as a derived reporting summary.

Per-global facts, with producers:

| Fact | Type | Producer | Status |
|---|---|---|---|
| `written` | evidenced bool, *may-written* semantics (witness when true: a write site, or the external escape that prevents ruling writes out — `DISPOSITION_PLAN.md` §1.9) | F `writers(o)` scan | exists (`never_written`) |
| `omega_escaped_address` | evidenced bool (witness when true: the escape site) | Ω machinery | exists |
| `violation_taint` | evidenced bool (witness when true: an address-relevant, access-shape-relevant, or unresolved violation finding) — gates every strategy, §1; value-only/unrelated findings remain diagnostics | A′ relevance routing | built by F3 |
| `thread_visible` | evidenced bool (true iff reachable from any spawn-entry's TransRef/TransMod; witness when true: the spawn site) — **reporting fact, not a guard**: thread visibility alone defeats no strategy (thread readers are a primary OnceLock use case; the thread-*writer* kill rule lives inside the phase-stationarity certificate) | F scan over spawn sites | specified; exported by D1b |
| `signal_context_access` | evidenced bool (true iff accessed under a registered signal handler; witness when true: registration site + accessing function) | F scan over Ω escape sites of handlers | new, cheap |
| `access_set_complete` | evidenced bool (true iff analysis bounds every possible accessor; **witness when false**: module-wide Ω, address escape, or library name reachability) | F scan | built by D1b; bounded indirect/rewrite compatibility is diagnosed separately for D3/D4 |
| `word_sized_scalar` | `{ value, type_spelling?, size_bits?, class?, signed? }` — true iff the type has a matching Rust atomic on the target (`DISPOSITION_PLAN.md` §1.9; the name is historical shorthand, not "pointer-width only") | lowering metadata (O1b) | exists after O1b |
| `phase_stationarity` | certificate slot (null \| certified \| failed+codes+witnesses) | ONCELOCK pass | specified |
| `atomic_eligibility` | certificate slot | D3 access-lowering pass (§9) | implemented |
| `mutex_eligibility` | certificate slot | D4 final-call-graph reentrancy pass (§9) | implemented |
| `coupling_group` | group id | shared coupling analysis (§6) | generalizes ONCELOCK §2.3 |
| `localization` | localization verdict (null \| ok \| blocked+blockers) | existing client (`DESIGN.md` §7) | exists |

Rule of construction: every fact is either derivable from the materialized solution in
one scan, or it does not belong in the vector. Nothing here re-enters the solver.

The concrete JSON/Rust encodings of these types — the evidenced-bool object and its
per-fact evidenced polarity, witness records, the certificate-slot union, the
localization verdict, and cascade skip reasons — are fixed in `DISPOSITION_PLAN.md`
§1.5 and are part of what D1a's golden test freezes. Schema v3 makes unknown mod/ref
candidate scope explicit so an abbreviated finite set cannot be mistaken for module-wide Ω.

## 3. The manifest

One versioned JSON document per analyzed program — **`pangs-manifest.json`,
`schema_version: 3`** — superseding and subsuming `ONCELOCK.md` §2's standalone schema
(which becomes the `facts.phase_stationarity` sub-object; see §8). It is the single
artifact consumed by *both* toolchain stages and referenced by override files.

**Population — "client-relevant global" defined precisely:** `globals[]` contains
**every defined mutable global**: every global with a definition in the analyzed
module whose type is not const-qualified (the existing `GlobalInfo.mutable` bit),
after the existing ignore-list filter, function-scope statics included. Excluded:
`const` globals (nothing to decide — already immutable in source), external
declarations (no defining TU here; not ours to rewrite). Stationary and never-written
globals are *included* — they are precisely the `immutable`/`once-lock` candidates.

The defining-TU path is optional provenance. When it is available and normalizable,
the key is source-qualified; otherwise the globally unique symbol name is the key.
This relies on the translation pipeline's pre-analysis static-variable uniquification
invariant, recorded in the audit ledger, with manifest duplicate-key validation as a
hard-error backstop. `unkeyed_globals` is retained only for the exceptional case where
even the symbol spelling cannot satisfy the key grammar (for example a non-C,
compiler-generated mutable definition); those records carry no facts or disposition
and count as `unhandled`.

### 3.1 Identity and keying (load-bearing for overrides)

Overrides and cross-stage references must survive re-runs and source drift, so globals
are keyed by **qualified symbol identity, never coordinates**:

```
key = [<translation_unit>::]<name>      e.g.  "src/commands.c::cmd_table" or "cmd_table.42"
```

- `translation_unit`, when present, is the *defining* TU path, repo-relative. A global
  without recoverable source-file metadata uses its globally unique symbol name alone;
  the required pre-pass has already renamed same-spelled statics across TUs. The same
  qualified grammar continues to cover **function identities**
  wherever the manifest references them (certificates, witnesses, once-lock
  rewiring) — static functions collide across TUs exactly like globals
  (`DISPOSITION_PLAN.md` §1.1). Qualified keys are a **manifest-layer identity over
  defined symbols only**, derived at fact assembly: the analysis export streams keep
  their raw LLVM identifiers (joined via `meta.llvm_name`), and external
  declarations — which have no defining TU — receive no key, synthetic or otherwise;
  they can be neither disposition subjects nor certificate anchors, and appear in
  witness text by raw name only.
- Statics get no extra qualification beyond that optional file component: the
  translation harness globally uniquifies their names in a pre-pass that runs *before*
  analysis. That ordering is a recorded run assumption, and manifest validation
  asserts key uniqueness (hard error on collision) as the backstop.
- File/line/col coordinates appear in the manifest only inside certificates and witness
  records, as *evidence from this run* — valid for same-run consumers, never used as
  identity, and never referenced by override files.
- A renamed or moved global silently orphans its override; the policy stage reports
  unmatched override keys as errors (§4.3), so drift is loud.

### 3.2 Per-global record

```jsonc
{
  "schema_version": 3,
  "run": {
    "analysis": {                        // analysis-owned (§3.3): provenance fields
      "entry_spine": { ... },            //   (pangs git, input hash, opts) +
      ...                                //   entry spine as ONCELOCK.md §2.1
    },
    "dispose": {                         // dispose-owned; replaced wholesale on every
      "mode": "application",             //   pangs-dispose run ("application"|"library")
      "cascade": ["immutable","once-lock","atomic","mutex","localize"],
      "overrides_file": "pangs-overrides.toml",   // null if none
      "overrides_sha256": "..."          // null if none
    }
  },
  "globals": [
    {
      "key": "src/commands.c::cmd_table",
      "meta": { "linkage": "internal", "type": "struct cmd_entry [512]" },

      "facts": {
        "written": { "value": true,
                     "witness": { "kind": "write-site",
                                  "site": { "file": "src/commands.c", "line": 210 },
                                  "symbol": "src/commands.c::cmd_init" } },
        "omega_escaped_address": { "value": false },
        "violation_taint": { "value": false },
        "thread_visible": { "value": false },
        "signal_context_access": { "value": false },
        "access_set_complete": { "value": true },
        "word_sized_scalar": { "value": false },
        "phase_stationarity": { "status": "certified",
                                "certificate": { /* ONCELOCK.md §2.1 payload:
                                     publication, writers, init_subtree,
                                     readers, observations */ } },
        "atomic_eligibility": { "status": "failed",
                                "codes": ["word-sized-scalar"], "witnesses": [...] },
        "mutex_eligibility": { "status": "certified",
                               "certificate": { /* accessor set + lock recipe */ } },
        "coupling_group": "grp-cmd",
        "localization": { "component": "comp-17", "verdict": "ok", "blockers": [] }
      },

      "disposition": {
        "chosen": "once-lock",           // FINAL result: post-override, post-group,
                                         //   post-demotion
        "cascade_chosen": "once-lock",   // the independent cascade result — a pure
                                         //   function of (facts, config) only
        "provenance": "cascade",         // "cascade" | "override" | "override-accepted-risk"
                                         // | "group-constraint" (§6) | "demoted" (§5.3)
                                         // — explains chosen ≠ cascade_chosen;
                                         //   "cascade" ⇒ they are equal
        "cascade_trace": [               // relative to cascade_chosen ONLY: why each
          { "strategy": "immutable",     //   configured entry before it was skipped
            "reason": { "kind": "guard-failed", "failed": ["written"] } }
        ],
        "override": null                 // §4: echo of the applied override record, if any
      }
    }
  ],
  "unkeyed_globals": [                   // analysis-owned diagnostic collection (§3
    { "llvm_name": "non-C-name!",        //   population rule): exceptional mutable
      "witness": { "kind": "invalid-symbol-name" } }      // definitions with no valid key
  ],
  "coupling_groups": [ { "id": "grp-cmd", "members": [...], "evidence": {...},
                         "strategy_support": {          // analysis-owned, from D2b:
                           "once_lock": { /* common-P certificate or absent-with-
                                             witness; DISPOSITION_PLAN.md D2b */ },
                           "mutex": { /* shared-lock reentrancy certificate */ }
                         },
                         "group_disposition": "once-lock",
                         "group_provenance": "cascade",  // "cascade" | "override" |
                                                         //   "override-accepted-risk"
                         "override": null } ],           // echo of an applied GROUP pin —
                                                         //   the only place it is echoed
  "coupling_candidates": [],             // deprecated compatibility field
  "override_report": { ... },            // §4.3; dispose-owned
  "materialization": { ... }             // §5: C→C-tool-owned — marker inventory (§5.2)
                                         //   and demotion records (§5.3); absent until
                                         //   that stage runs
}
```

Field discipline (inherited from the lite provenance philosophy): additive evolution
only; every boolean fact carries a witness on its *evidenced* polarity (the direction
that demands proof — `DISPOSITION_PLAN.md` §1.5 fixes the polarity per fact and which
facts are cascade-guard conjuncts vs. reporting-only); `null` means *not computed*,
and is distinct from a present-but-failed certificate — the cascade treats `null` as
"skip this entry" and the gap is visible in `cascade_trace`.

### 3.3 Stage ownership and re-runs

The manifest flows strictly forward through three stages, each owning named sections:

| Stage | Owns |
|---|---|
| analysis | `run.analysis`; `globals[].key`, `.meta`, `.facts`; `unkeyed_globals`; `coupling_groups[].{id, members, evidence, strategy_support}` |
| `pangs-dispose` | `run.dispose`; `globals[].disposition`; `coupling_groups[].group_disposition`; `override_report` |
| C→C tool | `materialization` (marker inventory §5.2, demotion records §5.3) |

**Re-running a stage regenerates its own sections and deletes every later stage's
sections** (with a warning when it deletes any): re-disposing discards prior
dispositions, the old override report, and any marker inventory or demotion records —
after a re-dispose, the C→C stage must run again before its outputs can be trusted.
Earlier stages' sections are read-only inputs, preserved semantically unchanged —
byte-identical after canonical re-emission (raw input formatting is not retained;
ground rule 4 of `DISPOSITION_PLAN.md` §0). This rule is what makes `pangs-dispose` a
pure function of (analysis-owned sections, config, overrides) and gives the
idempotence test its exact meaning. The same ownership discipline applies to
`pangs-audit.json`: dispose regenerates only records with `source: "override"` and
preserves all others under the same canonical-emission guarantee (deterministic
record ids: `DISPOSITION_PLAN.md` §1.4).

## 4. User overrides

### 4.1 Format

A TOML file (`pangs-overrides.toml`), keyed by §3.1 identity:

```toml
[globals."src/commands.c::cmd_table"]
disposition = "mutex"            # pin a specific strategy
# reason = "..."                 # free text, copied into the manifest

[globals."src/state.c::g_stats"]
disposition = "atomic"
accept_risk = true               # REQUIRED when the pin contradicts facts (§4.2)
# accept_risk pins are recorded in the soundness inventory, not just the manifest

[groups."grp-cmd"]
disposition = "once-lock"        # pin a whole coupling group

[cascade]                        # optional: REPLACES the mode's default order entirely
order = ["immutable", "once-lock", "mutex", "localize"]   # e.g., no atomics anywhere
# exhaustive list: an omitted strategy is disabled, never implicitly appended.
# duplicates, unknown names, "unhandled", or "localize" in library mode = config error.
# full semantics: DISPOSITION_PLAN.md §1.6
```

### 4.2 Validation rules

Two preconditions run before any outcome is considered.

First, **a pin may only name a strategy present in the configured order, or
`unhandled`**. A pin on a strategy omitted from the order is rejected as
`strategy-disabled`, regardless of `accept_risk` — the order is the exhaustive
enablement list (§1), and if overrides could bypass it, a uniformity cap like
"everything localizes" would be unenforceable; `accept_risk` waives evidence, never
policy. The recourse is editing the `[cascade]` order. `unhandled` is the standing
exception: it never appears in the order (implicit last) but is **always pinnable —
an explicit `unhandled` pin is a safe opt-out** (user-directed demotion; its guard is
vacuous), honored with `provenance: "override"`, no `accept_risk` needed, even on a
violation-tainted global. The same applies to group pins. One sharp edge: a *member*
`unhandled` pin that disagrees with the resolved group disposition is still a group
conflict under rule 3 below — opting one member out of a joint `once-lock`/`mutex`
representation would split it, exactly what rule 3 exists to prevent; pin the whole
group instead.

Second, **a pin on a certificate-requiring strategy must have a materialization
recipe, and `accept_risk` cannot waive that**: a `null` slot is rejected as
`strategy-unavailable`, and a failed slot without an attached `recipe`
(`DISPOSITION_PLAN.md` §1.5) is rejected as `no-recipe` — regardless of `accept_risk`
in both cases. Accepted risk waives *evidence* that exists and points the wrong way;
it cannot substitute for computation that never ran, nor conjure a rewrite plan the
pass could not produce: a forced `atomic` with no per-site load/store/RMW
classification, or a forced `once-lock` on a `never-quiescent` global with no
publication point, would be a manifest its rewriter cannot execute. The honorable
accepted-risk case is exactly **"evidence failed, recipe present"** — e.g. a
`thread-writer` kill on a global whose publication payload was still computed. For a
*group* pin the recipe is the group-level certificate (`strategy_support.<strategy>`):
an unsupported group has no common publication point, hence no recipe, hence no
honorable pin. Availability at the policy stage means exactly "slot non-null and
recipe present"; whether a downstream rewriter exists remains a consumer concern
handled by §5.3 demotion.

Past that precondition, the policy stage validates each override against the fact
vector. Three outcomes:

1. **Within certified options** (the pinned strategy's own guard is satisfied by its
   facts/certificate): honored,
   `provenance: "override"`.
2. **Contradicting facts** (e.g., `atomic` for a global with
   `access_set_complete: false`, or any pin on a `violation_taint` global): honored
   **only if** `accept_risk = true`, with `provenance: "override-accepted-risk"` *and*
   a corresponding entry appended to the audited soundness inventory (`DESIGN.md` §8)
   — an accepted-risk pin is an assumption of exactly the same standing as a
   library-mode ordering assertion, and must survive in the same ledger. Without
   `accept_risk`, the override is **rejected** and the cascade result stands.
3. **Group conflict** (pinning one member of a coupling group to a disposition other
   than the resolved group disposition, §6): rejected with the group evidence as
   witness — never silently honored, never silently split, even with `accept_risk`.
   The user's v1 recourse is to pin the whole group. Group-membership overrides are not
   part of the v1 override grammar; adding them later requires an explicit
   accepted-risk record because membership is an analysis fact.

### 4.3 Override report

The manifest's `override_report` lists every override with its outcome
(`honored` / `honored-accepted-risk` / `rejected` + reason /
`rejected-strategy-disabled` / `rejected-strategy-unavailable` / `rejected-no-recipe`
/ `unmatched-key`).
Unmatched
keys and rejections are also process exit-code failures in CI usage: an override file
that no longer matches the program is a drifted artifact and must be loud.

## 5. Stage contract: how decisions reach two worlds

### 5.1 The staging problem

The C→C localization tool rewrites source *before* the C→Rust conversion; Rust-side
consumers therefore cannot trust pre-refactoring coordinates (signatures change, lines
shift), and re-running the analysis on refactored C to recover anchors would be wasteful
and reopen consistency questions. Resolution: **the C→C stage is the materializer of
all source-anchored decisions; the Rust side is coordinate-free.**

### 5.2 Marker contract

The C→C tool consumes the manifest and, besides performing localization for
`localize`-disposed globals, plants **markers** for every Rust-side disposition. Markers
are **no-op function calls, not comments** — c2rust-class translators preserve calls
verbatim but drop or mangle comments — declared in a shipped header
(`pangs_markers.h`) as empty functions with distinctive names:

```c
/* at ONCELOCK publication point P, inserted by the C→C stage: */
pangs_publish__src_commands_c__cmd_table__9f3a01c4();

/* immediately before a marker-needing global's definition — one call site inside a
   dummy constructor-attribute function, or an adjacent no-op declaration record —
   whichever the C→C tool finds robust; the contract is only that the marker's NAME
   carries the identity (spelling per the authoritative grammar,
   DISPOSITION_PLAN.md §1.2: kind "disposition_" + strategy, then the mangled key,
   then the hash suffix): */
pangs_disposition_atomic__src_state_c__g_stats__ab12cd34();
```

- Marker names embed the §3.1 key (mangled: path separators and dots to `_`), so the
  Rust-side rewriter matches on **identity, never position**. Collisions from mangling
  are checked at emission time.
- For `once-lock`, the publication marker is the *only* positional fact the Rust side
  needs; the init-subtree rewiring (`ONCELOCK.md` §4.2 steps 1–3, 5–6) is keyed by
  function identity from the manifest.
- For `atomic`/`mutex`/`immutable`, markers at the definition site are strictly a
  robustness aid — the Rust rewriter primarily matches translated `static` items by
  symbol name; the marker disambiguates when translation renames.
- The C→C tool emits a **marker inventory** (rows of
  `{ key, kind, marker, group?, insertion-site }`, the site being evidence-only per
  §3.1) into the manifest's `materialization` section, closing the loop: the Rust side
  fails loudly on any manifest disposition whose marker is missing from the translated
  source.
- The Rust-side rewriter deletes all marker calls and the marker header as its final
  step; a surviving `pangs_*` symbol in the output is a build error by design.

Cardinality and linkage rules (validated by the `pangs-manifest` inventory helper, D5):

- Marker kinds are exactly two: `publish` (once-lock publication point) and
  `disposition_<strategy>` (definition site, for `immutable`/`atomic`/`mutex`).
- A `once-lock` global gets **exactly one publication marker and no definition
  marker**: the ONCELOCK certificate names a single publication point P — multiple
  publication points are unsupported in v1 (that program shape fails certification as
  `no-single-P`) — and static definitions are matched by symbol name like every other
  strategy's.
- A coupled once-lock group gets **one shared publication marker named by group id**
  (e.g. `pangs_publish__grp_cmd__<hash8>`; the group id occupies the mangled-key slot
  of the `DISPOSITION_PLAN.md` §1.2 grammar). The inventory maps *every member key* to
  that one symbol via the `group` field.
- `immutable`/`atomic`/`mutex` globals get exactly one definition-site marker whose
  embedded strategy must match the manifest disposition; `localize`/`unhandled`
  globals get no markers. No global carries more than one marker.
- Inventory validation: one `publish` row per once-lock global (shared symbol across a
  group's rows); strategy match on every `disposition_*` row; no rows for
  `localize`/`unhandled`; no marker symbol under two keys except group-shared
  `publish`; every row's key present in the manifest; and no `pangs_*` symbol in the
  translated source that is absent from the inventory (orphan markers are a rewriter
  error).
- Linkage: `pangs_markers.h` contains plain `void pangs_…(void);` declarations only;
  the empty definitions live in a single generated `pangs_markers.c` TU, so any number
  of TUs may call any marker with no multiple-definition hazard. Never `static
  inline` (per-TU copies would translate into per-crate-module duplicates, and a
  compiler may elide uncalled inline definitions). Call-site elimination is not a
  concern where it matters: the translator consumes unoptimized source, and all
  markers are deleted before any optimized Rust build exists — the object-code fate of
  the intermediate C is irrelevant to the contract.

### 5.3 What the C→C stage does per disposition

| Disposition | C→C action |
|---|---|
| `localize` | full localization rewrite (unchanged from `DESIGN.md` §7) |
| `once-lock` | exemption from localization + publication marker at P (no restructuring — `ONCELOCK.md` §7.5's exemption-only lean is adopted, plus the marker) |
| `immutable`, `atomic`, `mutex` | exemption + definition-site marker |
| `unhandled` | exemption + report entry (visible manual-work list) |

The C→C tool never makes a disposition decision; it executes the manifest. If it cannot
execute one (e.g., publication point inside a macro expansion it cannot rewrite), it
demotes that global to `unhandled` in its output manifest copy — concretely: it sets
`disposition.chosen = "unhandled"`, `provenance: "demoted"`, and a
`demotion: { from: "<original strategy>", witness: {...} }` record, and lists the
demotion in the `materialization` section, leaving `cascade_chosen` and
`cascade_trace` exactly as the policy stage wrote them —
demotion is always safe (coverage loss, never corruption), promotion is forbidden. If
the failed materialization is a joint `once-lock` or `mutex` representation, the tool
demotes the entire coupling group; it must not leave a partially materialized joint
representation. For `immutable` and `localize`, group membership is policy/layout
advice rather than a joint runtime representation, so an execution failure may demote
only the affected member.

## 6. Coupling groups (shared component)

`ONCELOCK.md` §2.3's co-quiescence groups are one instance of a general fact:
**globals co-written/co-read under an implicit consistency protocol.** Each strategy
consumes it differently:

- `once-lock`: publish the group as one `OnceLock<Struct>` at one P (existing design).
- `atomic`: groups do not constrain this per-global representation rewrite. Defined
  concurrent access to a plain C global already has synchronization, which the atomic
  rewrite retains; unsynchronized read/write concurrency was undefined.
- `mutex`: the group shares one `Mutex<Struct>` — both for consistency and to erase
  lock-ordering hazards between members.
- `localize`: groups suggest struct-field clustering in the context struct (advisory).

Coupling detection lives in a shared F-layer post-pass. Overlapping compatible
publication intervals are hard evidence and are unioned into policy-bearing
`coupling_groups`. Same-function co-writes are not collected: correlation alone does
not justify a joint representation or constrain atomic eligibility. Group IDs use the
`grp-` namespace. The manifest's `coupling_candidates` field is retained empty for
schema compatibility.

The policy stage resolves a group after computing each member's independent strategy
support set and individual cascade result:

1. For each configured strategy, compute `group_support(strategy)`. It requires the
   strategy's own guard to hold for every member, plus any group-specific condition:
   `once-lock` requires the common-publication-point certificate at
   `coupling_groups[].strategy_support.once_lock` — analysis-owned, derived by D2b
   from the members' phase-stationarity certificates (nonempty publication-interval
   intersection in one common publication function; `DISPOSITION_PLAN.md` D2b);
   `atomic` adds no group-specific guard; and `mutex`
   requires the group-level reentrancy certificate at `strategy_support.mutex`
   (reserved, emitted by D4). `unhandled` is always supported. `immutable` and
   `localize` add no group-specific guard beyond every member's ordinary guard.
2. Without a group override, choose the first group-supported strategy in the
   configured cascade. Thus cascade reordering changes preference, never proof. One
   exception preserves atomic's per-global semantics: if only a subset independently
   chose `atomic`, leave the group disposition unset and retain every member's
   independent result rather than demoting the eligible subset.
3. A group override is honored normally only when that strategy is group-supported.
   If it is not, it follows the ordinary contradictory-facts rule: reject it unless
   `accept_risk = true`, in which case record one accepted-risk audit entry whose
   `failures` list identifies every failed member and group-specific guard
   structurally (one `{member, guard, witness}` record each —
   `DISPOSITION_PLAN.md` §1.8 — never free text).
4. A member override is applied only if it agrees with the resolved group disposition;
   otherwise it is a group conflict under §4.2 rule 3.

The result is recorded as `group_disposition`; members inherit it in `chosen` with
`provenance: "group-constraint"` when it differs from their individual cascade
result, which stays visible untouched in `cascade_chosen` — the trace never has to
"explain" the inherited choice (a member whose own cascade picked `immutable` has no
skip reason for it, and needs none: `provenance` plus the group record carry that
explanation; §3.2).

Serialization of a *group* override on member records is fixed as follows: members
keep `override: null` and plain `provenance: "group-constraint"` (or `"cascade"`
when `chosen` happens to equal `cascade_chosen`) — the pin itself is echoed exactly
once, on the group record (`group_provenance: "override"` /
`"override-accepted-risk"` plus its `override` echo, §3.2) and in the
`override_report`. A member's `override` field echoes only *member* pins. Rationale:
echoing a group pin onto N members stores N divergeable copies of one decision; the
provenance chain member → `group_disposition` → group override reconstructs it
losslessly.
For `localize`, membership remains advisory to context-struct field clustering after
the uniform policy assignment; it does not require the C→C tool to materialize one
joint runtime object.

## 7. Soundness matrix

The audited-soundness framework becomes strategy-parametric. A structural gift: every
strategy deletes or retypes the C global, so a **missed access site fails to compile**
in the Rust output — the silent failure classes are all *relational*, not site-level:

| Strategy | Missed site | Relational failure | Silent? | Dynamic audit |
|---|---|---|---|---|
| `immutable` | compile error | missed Ω-escaped write path → UB write to immutable | **silent** — which is why `¬omega_escaped_address` is in the cascade guard | none beyond existing Ω discipline |
| `once-lock` | compile error | post-P write missed → `set` panics; read-before-set → `get` panics | loud | post-P store logging (`ONCELOCK.md` §3.4.3), stop-ship on any hit |
| `atomic` | compile error | incompatible or missed access lowering | no additional relational failure for defined source behavior | none |
| `mutex` | compile error | reentrant access path → deadlock; signal-context access → deadlock/UB | loud-ish (liveness, not corruption) | lock-cycle detection under the program's test suite |
| `localize` | n/a | FN call edge → wrong routing → silent corruption | **silent** | unchanged from `DESIGN.md` §9 |

The silent cells for `immutable` and `localize` get the investment described above.
Atomic eligibility is per-global and requires no co-update audit under the
defined-behavior preservation contract. Accepted-risk overrides (§4.2) add per-global
rows to this matrix in the soundness inventory.

## 8. Amendments required to the other documents

1. **`ONCELOCK.md`** — trim to pure fact production (applied):
   - §2's standalone schema (v1) is superseded; the pass emits the shared
     certificate-slot shape (`DISPOSITION_PLAN.md` §1.5) directly as
     `facts.phase_stationarity` — certified payload
     `{ publication, writers, init_subtree, readers, observations }`, failed variant
     `codes`/`witnesses`/`diagnostics`. Failure reason codes keep their §2.2 meanings
     but are re-described as routing input, not terminal verdicts.
   - §4.4's "consumption is purely subtractive" paragraph is superseded by §5.3 here
     (exemption **plus publication marker**).
   - §2.3 co-quiescence detection moves to the shared coupling component (§6 here);
     the ONCELOCK pass stays per-global while D2b derives the group common-P
     certificate (`strategy_support.once_lock`) from its per-global output. Work item
     O6 shrinks accordingly.
   - The spawn-reachability bit consumed internally is additionally surfaced as the
     first-class reporting fact `thread_visible` (§2 here; not a cascade guard — the
     kill rule is thread-*writer*, inside the certificate).
2. **`DESIGN_lite.md` §2F** — the client list gains the disposition stage as a named
   post-pass, and the sentence "Globals localization: unchanged from `DESIGN.md` §7"
   gains "…consuming the disposition manifest (see `DISPOSITION.md`)". The two
   provenance tags on icall edges are unaffected.
3. **`DESIGN.md` §4F** — the mutability lattice is re-labeled a *reporting summary*
   derived from the fact vector (§2 here); no analysis change.
4. **`DESIGN.md` §7 / §8** — the localization client's input becomes "globals disposed
   `localize`"; the soundness inventory gains the accepted-risk override ledger and the
   per-strategy audit matrix (§7 here).

None of these amendments change A′–D′ or any solver semantics.

## 9. Implementation plan

Work items (D-prefix; O-items are `ONCELOCK.md` §3.2):

- **D1 — manifest + policy stage (~400 lines).** Fact-vector assembly from existing
  scans; cascade evaluation with trace; schema v2 emission; run-header reproducibility
  fields. No new analysis.
- **D2 — override machinery (~250 lines).** TOML parsing, §4.2 validation, override
  report, soundness-inventory append for accepted risks, CI exit-code discipline.
- **D2b — shared coupling post-pass (~200 lines).** Extracted from O6's clustering;
  derives hard common-publication groups, group evidence records, and group disposition
  resolution for joint strategies.
- **D3 — atomic eligibility pass (implemented).** Produces a per-global certificate
  only after scalar-width, bounded-access, relevant-violation, source-mapped
  load/store/RMW recipe, and signal lock-free checks pass. A failed coarse gate emits its
  decisive witness and a bounded `access_lowering: skipped` diagnostic; D3 does not
  enumerate redundant per-access rewrite failures once certification is impossible.
- **D4 — mutex eligibility pass (implemented).** Reuses access-set completeness and
  violation relevance, rejects signal-context access, and checks final-call-graph
  reachability between accessor functions. It emits deterministic call-path witnesses,
  per-global lock recipes, and shared-lock support certificates for coupling groups.
- **D5 — marker contract (~150 lines analysis-side).** Marker name mangling +
  collision check + inventory schema; the insertion itself is C→C-tool work, and the
  consumption is Rust-rewriter work, but the name scheme and inventory format are owned
  here so all three agree.

Order: D1 → D2 → D2b (v1, alongside O-items; D1 is a prerequisite for consuming
ONCELOCK output at all under the new interface), then D3's static certificate and D5
when the C→C tool is ready to consume dispositions. D3 and D4 now populate their
certificate slots; their C/Rust materializers remain future boundary work.

### Testing

- Golden-file the full manifest on the small-program corpus (lite idiom).
- Property test the cascade: for every fact vector in a generated grid,
  `cascade_chosen`'s guard holds and every skipped entry has a recorded reason
  (the trace invariant binds to `cascade_chosen`, not the final `chosen` — §3.2).
- Override matrix tests: each §4.2 outcome × (global pin, group pin, cascade cap,
  unmatched key).
- Round-trip marker test: emit markers into a toy program, translate, verify the Rust
  rewriter matches every inventory entry and the final output contains no `pangs_*`
  symbol.

## 10. Measurements and gates (extends lite M3)

1. **Disposition distribution** — the headline replaces "fraction localizable":
   per-strategy counts and the `unhandled` remainder, on Vim + PHP.
2. **Cascade-skip histogram** — which guard kills how many globals at each level;
   `atomic`/`mutex` slots' *would-be* eligibility (measurable cheaply from the fact
   vector even before D3/D4 exist: word-sized ∧ access-complete counts) gates whether
   D3/D4 are worth building — the same free-counter pattern as
   ONCELOCK's `no-single-P`.
3. **Context-struct pressure with escape valves** — re-evaluate the `DESIGN.md` §11.4
   mega-component risk with `mutex` available: if the globals that bloat the context
   struct are mutex-eligible, tier-E-grade precision buys less than the original M3
   framing assumed. This may flip the `localize`/`mutex` default (§1) for some targets.
4. **Override usage telemetry** — count of honored / accepted-risk / rejected in real
   use; a high accepted-risk rate is a signal that some fact is over-conservative and
   names exactly which one.

These measurements are emitted after policy and override resolution at
`run.dispose.measurement_report`. `disposition_distribution` counts final choices;
`cascade_skip_histogram` retains separate guard-failed and fact-not-computed buckets;
`would_be_eligibility` records cumulative cheap-filter funnels and the D3/D4 gate
counts; `context_struct_pressure` reports localized globals and known/unknown size by
localization component; and `override_usage` summarizes the detailed top-level
`override_report`. The counters observe existing facts only: they do not populate the
reserved eligibility certificate slots.

For corpus-scale diagnostics, `PANGS_DISPOSITION_TIMINGS=1` emits phase checkpoints
to stderr only; it does not alter either canonical artifact.

## 11. Open questions

1. **Cascade position of `atomic` vs `once-lock` for phase-stationary scalars.** Both
   certify; the cascade prefers `once-lock` (stronger property, certificate assertion).
   But a hot-path scalar behind `OnceLock` costs an `Option` check per read where
   `AtomicI32::load(Relaxed)` would not. If profiling shows this matters, the answer is
   a per-global override, not a cascade reorder — revisit only if it is pervasive.
2. **Group support-set intersection** (§6) can discard a strategy supported by only
   some members. A future alternative is to split the group when the evidence shows
   the coupling is write-side only (no reader assumes cross-member consistency).
   That requires a reader-side coupling fact and is deferred until group statistics
   exist; v1 keeps the conservative intersection rule.
3. **Manifest as the sole channel vs. in-source annotations for humans.** Markers are
   machine-facing; should the C→C stage also emit human-readable
   `/* PANGS: once-lock, see manifest */` comments for reviewability of the
   intermediate C, accepting that they are lost downstream? Cheap; leaning yes.
4. **`unhandled` ergonomics.** Today it is a report bucket. Worth deciding whether the
   Rust side should render `unhandled` globals as `static mut` + `unsafe` accessors
   (compiling, greppable, loud) versus refusing to translate — probably a per-run
   policy flag with the loud-but-compiling form as default.
5. **Override granularity below the global.** Per-field dispositions (split a struct:
   `.handlers` immutable, `.stats` atomic) compose with `ONCELOCK.md` §7.1's per-field
   certificates; both are v2+ and should be designed together if the
   `never-quiescent` witnesses point at mixed-lifecycle structs.
