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
3. atomic      iff  atomic-eligibility certificate present            (future pass)
4. mutex       iff  access-set-complete ∧ ¬signal-context-access
                    ∧ reentrancy check passes                          (future pass)
5. localize    iff  build mode = application ∧ localization verdict OK
6. unhandled   otherwise (with the accumulated failure witnesses)
```

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

Two knobs, both policy-level (never analysis-level):

- **`localize` vs `mutex` preference.** Applications default to the order above
  (historically `localize` was the whole point; but see the M3 note in §10 — `mutex`
  may become the preferred default if context-struct bloat dominates). Libraries have
  no `localize`; the "applications only" restriction of the original client lives
  *here*, in the cascade config, and nowhere in the analysis.
- **Uniformity mode** (`DESIGN.md` §11.4 discussion): a client may cap the cascade
  (e.g., "no statics at all — everything localizes") without touching facts.

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
| `written` | bool | F `writers(o)` scan | exists |
| `omega_escaped_address` | bool | Ω machinery | exists |
| `violation_taint` | bool | A′ detection | exists |
| `thread_visible` | bool (reachable from any spawn-entry's TransRef/TransMod) | F scan over spawn sites | exists (promoted from internal kill-rule input to first-class manifest fact) |
| `signal_context_access` | bool (accessed under a registered signal handler) | F scan over Ω escape sites of handlers | new, cheap |
| `access_set_complete` | bool (every access site enumerated; no Ω-tainted path can access `g`) | F scan | mostly exists (it is the ONCELOCK kill-rule conjunction, factored out) |
| `word_sized_scalar` | bool + type spelling | lowering metadata (O1b) | exists after O1b |
| `phase_stationarity` | certificate \| failure codes | ONCELOCK pass | specified |
| `atomic_eligibility` | certificate \| failure codes | future pass (§9 D3) | reserved slot |
| `mutex_eligibility` | certificate \| failure codes | future pass (§9 D4) | reserved slot |
| `coupling_group` | group id | shared coupling analysis (§6) | generalizes ONCELOCK §2.3 |
| `localization` | component verdict | existing client (`DESIGN.md` §7) | exists |

Rule of construction: every fact is either derivable from the materialized solution in
one scan, or it does not belong in the vector. Nothing here re-enters the solver.

## 3. The manifest

One versioned JSON document per analyzed program — **`pangs-manifest.json`,
`schema_version: 2`** — superseding and subsuming `ONCELOCK.md` §2's standalone schema
(which becomes the `facts.phase_stationarity` sub-object; see §8). It is the single
artifact consumed by *both* toolchain stages and referenced by override files.

### 3.1 Identity and keying (load-bearing for overrides)

Overrides and cross-stage references must survive re-runs and source drift, so globals
are keyed by **qualified symbol identity, never coordinates**:

```
key = <translation_unit>::<name>        e.g.  "src/commands.c::cmd_table"
```

- `translation_unit` is the *defining* TU path, repo-relative, required for
  internal-linkage globals (two `static int verbose;` in different files are distinct
  keys) and retained for external-linkage globals for uniformity (their `name` is
  already unique program-wide).
- Function-scope statics get no extra qualification: the translation harness uniquifies
  their names in a pre-pass that runs *before* the analysis, so every static's name is
  TU-unique by the time PANGS sees it. That ordering is a recorded run assumption, and
  fact assembly asserts key uniqueness (hard error on collision) as the backstop.
- File/line/col coordinates appear in the manifest only inside certificates and witness
  records, as *evidence from this run* — valid for same-run consumers, never used as
  identity, and never referenced by override files.
- A renamed or moved global silently orphans its override; the policy stage reports
  unmatched override keys as errors (§4.3), so drift is loud.

### 3.2 Per-global record

```jsonc
{
  "schema_version": 2,
  "run": {
    "mode": "application",               // "application" | "library"
    "cascade": ["immutable","once-lock","atomic","mutex","localize"],
    "overrides_file": "pangs-overrides.toml",   // null if none
    "entry_spine": { ... }               // as ONCELOCK.md §2.1
  },
  "globals": [
    {
      "key": "src/commands.c::cmd_table",
      "meta": { "linkage": "internal", "type": "struct cmd_entry [512]" },

      "facts": {
        "written": true,
        "omega_escaped_address": false,
        "violation_taint": false,
        "thread_visible": false,
        "signal_context_access": false,
        "access_set_complete": true,
        "word_sized_scalar": false,
        "phase_stationarity": { /* ONCELOCK certificate or failure, verbatim */ },
        "atomic_eligibility": null,      // pass not yet built; null ≠ failed
        "mutex_eligibility": null,
        "coupling_group": "grp-cmd",
        "localization": { /* component verdict, existing client */ }
      },

      "disposition": {
        "chosen": "once-lock",
        "provenance": "cascade",         // "cascade" | "override" | "override-accepted-risk"
                                         // | "group-constraint" (§6)
        "cascade_trace": [               // why each earlier entry was skipped
          { "strategy": "immutable", "skipped": "written" }
        ],
        "override": null                 // §4: echo of the applied override record, if any
      }
    }
  ],
  "coupling_groups": [ { "id": "grp-cmd", "members": [...], "evidence": {...},
                         "group_disposition": "once-lock" } ],
  "override_report": { ... }             // §4.3
}
```

Field discipline (inherited from the lite provenance philosophy): additive evolution
only; every negative fact carries a witness; `null` means *not computed*, and is
distinct from a present-but-failed certificate — the cascade treats `null` as
"skip this entry" and the gap is visible in `cascade_trace`.

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

[cascade]                        # optional: reorder/cap the default cascade
order = ["immutable", "once-lock", "mutex", "localize"]   # e.g., no atomics anywhere
```

### 4.2 Validation rules

The policy stage validates each override against the fact vector. Three outcomes:

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
(`honored` / `honored-accepted-risk` / `rejected` + reason / `unmatched-key`). Unmatched
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
pangs_publish__src_commands_c__cmd_table();

/* immediately before a marker-needing global's definition — one call site inside a
   dummy constructor-attribute function, or an adjacent no-op declaration record —
   whichever the C→C tool finds robust; the contract is only that the marker's NAME
   carries the identity: */
pangs_disposition__atomic__src_state_c__g_stats();
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
- The C→C tool emits a **marker inventory** (key → marker symbol) appended to the
  manifest, closing the loop: the Rust side fails loudly on any manifest disposition
  whose marker is missing from the translated source.
- The Rust-side rewriter deletes all marker calls and the marker header as its final
  step; a surviving `pangs_*` symbol in the output is a build error by design.

### 5.3 What the C→C stage does per disposition

| Disposition | C→C action |
|---|---|
| `localize` | full localization rewrite (unchanged from `DESIGN.md` §7) |
| `once-lock` | exemption from localization + publication marker at P (no restructuring — `ONCELOCK.md` §7.5's exemption-only lean is adopted, plus the marker) |
| `immutable`, `atomic`, `mutex` | exemption + definition-site marker |
| `unhandled` | exemption + report entry (visible manual-work list) |

The C→C tool never makes a disposition decision; it executes the manifest. If it cannot
execute one (e.g., publication point inside a macro expansion it cannot rewrite), it
demotes that global to `unhandled` in its output manifest copy with a witness —
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
- `atomic`: a group with >1 member **fails atomic eligibility for all members** —
  independent atomics would introduce torn states that the original single-threaded C
  could never exhibit. This is the one place where the new strategies can *silently
  corrupt semantics* (not memory safety), so the group fact is a hard gate, not advice.
- `mutex`: the group shares one `Mutex<Struct>` — both for consistency and to erase
  lock-ordering hazards between members.
- `localize`: groups suggest struct-field clustering in the context struct (advisory).

Therefore coupling detection moves out of the ONCELOCK work items into a shared
F-layer post-pass: cluster globals by co-occurrence in writer functions/regions and
(where computed) overlapping publication intervals; emit `coupling_groups` with
evidence (the co-writing sites). Detection is heuristic-completeness-asymmetric in the
usual direction: a *missed* group is dangerous only for `atomic` (hence atomic
eligibility must itself re-derive co-write evidence conservatively — its certificate,
not the shared heuristic, is what licenses the rewrite), while a spurious group merely
over-couples a rewrite.

The policy stage resolves a group after computing each member's independent strategy
support set and individual cascade result:

1. For each configured strategy, compute `group_support(strategy)`. It requires the
   strategy's own guard to hold for every member, plus any group-specific condition:
   `once-lock` requires a group certificate naming one common publication point;
   `atomic` is unsupported for a group with more than one member; and `mutex` requires
   the group-level reentrancy certificate emitted by D4. `unhandled` is always
   supported. `immutable` and `localize` add no group-specific guard beyond every
   member's ordinary guard.
2. Without a group override, choose the first group-supported strategy in the
   configured cascade. Thus cascade reordering changes preference, never proof.
3. A group override is honored normally only when that strategy is group-supported.
   If it is not, it follows the ordinary contradictory-facts rule: reject it unless
   `accept_risk = true`, in which case record one accepted-risk audit entry whose
   witness names every failed member and group-specific guard.
4. A member override is applied only if it agrees with the resolved group disposition;
   otherwise it is a group conflict under §4.2 rule 3.

The result is recorded as `group_disposition`; members inherit it with
`provenance: "group-constraint"` when it differs from their individual cascade result.
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
| `atomic` | compile error | missed coupling → torn multi-global invariant | **silent** | co-update logging: instrument test builds to detect interleaved-update windows between suspected-coupled globals (design with D3, §9) |
| `mutex` | compile error | reentrant access path → deadlock; signal-context access → deadlock/UB | loud-ish (liveness, not corruption) | lock-cycle detection under the program's test suite |
| `localize` | n/a | FN call edge → wrong routing → silent corruption | **silent** | unchanged from `DESIGN.md` §9 |

The three silent cells get the investment: `immutable`'s is already guarded by an
existing fact; `localize`'s is the original problem the whole soundness posture exists
for; `atomic`'s coupling audit is a new obligation that ships **with** the atomics pass,
not after it. Accepted-risk overrides (§4.2) add per-global rows to this matrix in the
soundness inventory.

## 8. Amendments required to the other documents

1. **`ONCELOCK.md`** — trim to pure fact production:
   - §2's standalone schema (v1) is superseded; its per-global payload becomes the
     `facts.phase_stationarity` object of the v2 manifest, unchanged in content.
     Failure reason codes are retained verbatim but re-described as routing input, not
     terminal verdicts.
   - §4.4's "consumption is purely subtractive" paragraph is superseded by §5.3 here
     (exemption **plus publication marker**).
   - §2.3 co-quiescence detection moves to the shared coupling component (§6 here);
     the ONCELOCK pass consumes group ids instead of computing them. Work item O6
     shrinks accordingly.
   - Kill-rule bits consumed internally (`thread_visible` etc.) are additionally
     surfaced as first-class manifest facts (§2 here).
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
- **D2b — shared coupling post-pass (~200 lines).** Extracted from O6's clustering,
  generalized to co-write regions; group evidence records; group disposition
  resolution.
- **D3 — atomic eligibility pass (future, size TBD).** Word-sized scalar check, RMW
  site classification (`g++` → `fetch_add` shapes), address-taken compatibility,
  conservative co-write re-derivation (§6), certificate + failure codes into the
  reserved slot. Ships with its co-update dynamic audit (§7).
- **D4 — mutex eligibility pass (future, size TBD).** Access-set completeness reuse,
  reentrancy check (call-graph reachability between access sites), signal-context
  gate, lock-granularity advice from groups.
- **D5 — marker contract (~150 lines analysis-side).** Marker name mangling +
  collision check + inventory schema; the insertion itself is C→C-tool work, and the
  consumption is Rust-rewriter work, but the name scheme and inventory format are owned
  here so all three agree.

Order: D1 → D2 → D2b (v1, alongside O-items; D1 is a prerequisite for consuming
ONCELOCK output at all under the new interface), then D5 when the C→C tool is ready to
consume dispositions, then D3/D4 gated on §10 measurements. v1 cascade with only the
existing passes degenerates gracefully: `immutable` / `once-lock` / `localize` /
`unhandled`, with `atomic`/`mutex` slots present-but-null in every record.

### Testing

- Golden-file the full manifest on the small-program corpus (lite idiom).
- Property test the cascade: for every fact vector in a generated grid, the chosen
  disposition's guard holds and every skipped entry has a recorded reason.
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
   vector even before D3/D4 exist: word-sized ∧ access-complete ∧ singleton-group
   counts) gates whether D3/D4 are worth building — the same free-counter pattern as
   ONCELOCK's `no-single-P`.
3. **Context-struct pressure with escape valves** — re-evaluate the `DESIGN.md` §11.4
   mega-component risk with `mutex` available: if the globals that bloat the context
   struct are mutex-eligible, tier-E-grade precision buys less than the original M3
   framing assumed. This may flip the `localize`/`mutex` default (§1) for some targets.
4. **Override usage telemetry** — count of honored / accepted-risk / rejected in real
   use; a high accepted-risk rate is a signal that some fact is over-conservative and
   names exactly which one.

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
