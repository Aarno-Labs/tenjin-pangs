# DISPOSITION_PLAN: Implementation Plan for the Disposition Layer

*Execution companion to `DISPOSITION.md`. That document specifies **what** the
disposition layer is (facts vs. policy, manifest, cascade, overrides, markers, coupling
groups); this one specifies **how and in what order to build it** — code layout, expanded
work items with acceptance criteria, sequencing against the lite milestones
(`DESIGN_lite.md` §5) and the ONCELOCK work items (`ONCELOCK.md` §3.2), test harnesses,
and the details `DISPOSITION.md` left normative-but-unspecified (identity grammar,
marker mangling, exit codes, ledger format). Audience: implementers, including coding
agents picking up a single work item cold.*

## 0. Scope and ground rules

**In scope (v1):** D1 (manifest + fact assembly + cascade), D2 (overrides), D2b (shared
coupling post-pass), D5 (marker contract), the contract test harnesses, and a
de-risking spike (D0) on marker survival. **Specified but gated (build only when the §7
counters say so):** D3 (atomic eligibility), D4 (mutex eligibility).

Ground rules, restated as implementation invariants — every PR touching this layer is
reviewable against them:

1. **No solver changes.** Everything here is phase-F post-pass or downstream tooling;
   A′–D′ semantics and outputs are frozen inputs. A work item that "needs" a solver
   change is mis-scoped — stop and re-read `DISPOSITION.md` §2's rule of construction.
2. **Facts never contain preferences; policy never computes facts.** The cascade
   evaluator must be a pure function of `(fact vector, config, overrides)` with no
   access to the PAG or solution.
3. **Additive schema evolution only.** Field removal or rename = new schema_version =
   a decision, not a refactor. Unknown fields round-trip (see D1a).
4. **Determinism.** Same inputs ⇒ byte-identical manifest. All collections sorted at
   emission (globals by key, groups by id, traces in cascade order). This is what makes
   golden-file testing and manifest diffing work.
5. **Demotion-only for consumers.** Downstream tools may demote a global to
   `unhandled` (with witness), never promote or reinterpret.
6. **`null` ≠ failed.** A fact slot that was not computed is `null` and skips its
   cascade entry visibly in `cascade_trace`; a computed-but-failed certificate carries
   its failure codes. Conflating these is a bug class the property tests target.

## 1. Normative details (fixing what `DISPOSITION.md` deferred)

### 1.1 Identity key grammar

```
key     := tu-path "::" symbol-name
tu-path := repo-relative path, "/" separators, no leading "./",
           as spelled at the *defining* TU
```

Example: `src/commands.c::cmd_table`. Function-scope statics need no extra
qualification: the translation harness uniquifies their names in a pre-pass, so by the
time PANGS sees the program every static's name is TU-unique. Two prerequisites this
leans on: (a) the uniquification pre-pass runs **before** analysis, so manifest keys
match what the C→C tool and translator see — recorded as a run assumption in
`pangs-audit.json`; (b) fact assembly asserts key uniqueness and hard-errors on
collision (the backstop if (a) is ever violated or the harness's scheme changes). Path
normalization (case, symlinks, build-dir prefixes) happens once, in lowering, against a
configured repo root — nowhere else.

### 1.2 Marker name mangling

```
marker      := "pangs_" kind "__" mangled-key "__" hash8
kind        := "publish" | "disposition_" strategy
mangled-key := key with every byte outside [A-Za-z0-9] replaced by "_"
hash8       := lowercase hex FNV-1a-32 of the *raw* key bytes
```

Example: `pangs_publish__src_commands_c__cmd_table__9f3a01c4`. The hash suffix makes
the lossy mangling injective in practice; D5 still emits a hard error on collision
(paranoia is cheap here). The codec lives in one shared crate (§2) — analysis, C→C
tool, and Rust rewriter must never reimplement it.

### 1.3 `pangs-dispose` exit codes

| Code | Meaning |
|---|---|
| 0 | success; all overrides honored or none present |
| 1 | internal error / malformed input |
| 2 | override problems: any `rejected` or `unmatched-key` outcome (§4.3 of `DISPOSITION.md`); manifest still written, with the override report |
| 3 | schema version of input manifest newer than this tool supports |

CI treats 2 as failure by policy; the manifest-plus-report is still produced so the
failure is diagnosable from artifacts alone.

### 1.4 Soundness ledger format

The "audited soundness inventory" becomes a machine artifact, `pangs-audit.json`,
emitted alongside the manifest: a list of assumption records
`{ id, kind, scope (global key | run), source ("analysis" | "override" | "entry-spine"),
text, witness? }`. Accepted-risk overrides (D2) append `kind: "accepted-risk"` records.
The human-readable inventory sections in `DESIGN.md` §8 remain the catalog of *kinds*;
the JSON is the per-run instantiation.

## 2. Code layout

New crates in the PANGS workspace (names final unless the workspace has conflicting
conventions):

| Crate | Contents | Depended on by |
|---|---|---|
| `pangs-manifest` | schema v2 serde types (`Key`, `Meta`, `Facts`, `PhaseStationarity`, `Disposition`, `CascadeTrace`, `CouplingGroup`, `RunHeader`, `OverrideReport`, `AuditRecord`), key grammar + parser (§1.1), marker codec (§1.2), schema-version constants | analysis, `pangs-dispose`, C→C tool, Rust rewriter — **the one shared dependency; keep it std+serde only** |
| `pangs-dispose` | the policy stage: cascade evaluator, override machinery, group disposition resolution, report + ledger emission. Library + thin CLI | CI, users |
| (existing analysis crate, phase F) | fact-assembly post-pass, coupling post-pass (D2b), marker-inventory schema checks | — |

Design point worth locking in: **the policy stage is re-runnable offline.**
`pangs-dispose` reads a manifest (using only its `facts`/`meta`/run header, discarding
any prior `disposition` blocks), applies cascade + overrides, and rewrites the
manifest. Changing an override never requires re-analysis; the run header records both
the analysis provenance and the dispose-time config, so a manifest is always
self-describing. The analysis binary calls the same library in-process for the initial
emission — one code path, two invocation modes.

## 3. Work items

### D0 — marker-survival spike (~1 day, do first)

The riskiest external assumption in the whole design is `DISPOSITION.md` §5.2's claim
that no-op marker calls survive C→Rust translation robustly. Verify before building on
it: toy C program with `pangs_*` marker calls (extern declarations in a header, empty
definitions in one TU) → run the project's actual C→Rust translator → confirm the calls
appear in the Rust output, attributable by name, deletable mechanically. Also test the
awkward placements: marker as last statement of a block, marker inside a
macro-adjacent line, marker in a TU compiled with different flags.
**Exit criterion:** a written note in this file's §8 recording what survived and any
placement rules the C→C tool must obey. If the spike *fails*, the fallback (source-map
emission by the C→C tool, `DISPOSITION.md` §5.2's alternative) gets promoted before D5
is built — that decision reverses cheaply now and expensively later.

### D1 — manifest, fact assembly, cascade (~400 lines + crate scaffolding)

Split for independent landing:

- **D1a — `pangs-manifest` crate (~300 lines).** Types + serde for the §3 schema of
  `DISPOSITION.md`; key parser/formatter with the §1.1 grammar (property test:
  parse∘format = id); marker codec (§1.2) with collision detection; unknown-field
  preservation on round-trip (`#[serde(flatten)] extra: Map<String, Value>` on every
  record type — an older `pangs-dispose` must not strip fields written by a newer
  analysis). Golden test: a checked-in v2 manifest round-trips byte-identically.
- **D1b — fact assembly (phase-F post-pass, ~200 lines).** One scan assembling the
  `DISPOSITION.md` §2 vector per client-relevant global. New-but-cheap facts built
  here: `signal_context_access` (reader/writer functions whose addresses flow to
  signal-registration sites — the Ω escape-site scan already walks these);
  `access_set_complete` (factored from the ONCELOCK kill-rule conjunction so both
  consumers share one definition); `thread_visible` (promotion of the existing
  spawn-reachability bit); `word_sized_scalar` (from O1b type metadata).
  `phase_stationarity` and `coupling_group` are wired in when O6/D2b land — until
  then the slots are `null`, which the cascade already tolerates (ground rule 6).
- **D1c — cascade evaluator (in `pangs-dispose`, ~150 lines).** Pure function:
  `fn dispose(&Facts, &CascadeConfig) -> (Disposition, Vec<CascadeSkip>)`. Guards
  exactly as `DISPOSITION.md` §1; config = ordered strategy list + per-strategy
  enable/cap; `unhandled` is always the implicit last entry and cannot be configured
  away. Every skip records `{strategy, reason}` where reason names the failing guard
  or `fact-not-computed`.

**Acceptance:** golden manifest for a hand-built fact fixture; property test over a
generated grid of fact vectors (all boolean combinations × certificate
present/absent/null) asserting (a) chosen strategy's guard holds, (b) every earlier
strategy has a recorded skip reason, (c) determinism.

### D2 — override machinery (~250 lines, in `pangs-dispose`)

TOML format per `DISPOSITION.md` §4.1 (serde + `toml`). Validation per §4.2, in this
order per override: key resolution (§1.1 grammar; unmatched ⇒ `unmatched-key`) →
group-conflict check (§4.2 rule 3) → fact-support check (is the pinned strategy's guard
satisfied?) → outcome (`honored` / `honored-accepted-risk` / `rejected`). Group pins
resolve before member pins so a member pin conflicting with a group pin is reported
against the group, with both records in the report. Accepted risks append to
`pangs-audit.json` (§1.4). Cascade-reorder blocks (`[cascade]`) are validated for
unknown strategy names and applied globally before any per-global evaluation.

**Acceptance:** the override matrix test — each §4.2 outcome × {global pin, group pin,
cascade cap, unmatched key, missing accept_risk, accept_risk present} — plus exit-code
assertions (§1.3), plus idempotence: re-running `pangs-dispose` on its own output with
the same overrides is a byte-level no-op.

### D2b — shared coupling post-pass (~200 lines, phase F)

v1 evidence, deliberately simple and precision-asymmetric (a spurious group
over-couples a rewrite; a missed group is dangerous only to D3, which re-derives its
own evidence):

1. **Co-write evidence:** two globals both directly written by the same function, in
   the same region when region info is available (v1: same function suffices).
2. **ONCELOCK evidence** (for certified globals): publication-interval overlap ∧
   init-subtree intersection — exported by O6 exactly for this.

Cluster by union-find over evidence edges; group id = `"grp-" + hash8(smallest member
key)` (stable across runs, ground rule 4); emit `coupling_groups` with the evidence
edges as witnesses. Config: an evidence-strength threshold, default permissive, so
tightening is a data-driven follow-up rather than a redesign.

**Acceptance:** unit fixtures (the `cmd_table`+`cmd_count` pair; two unrelated globals
written by one utility function — expected to over-group at default threshold, test
documents this as intended); determinism of ids under member reordering.

### D5 — marker contract (~150 lines analysis-side + harness)

Consumes D0's placement rules. Deliverables: (a) marker codec already in D1a — this
item adds the **marker inventory** schema (key → marker symbol → kind) appended to the
manifest by the C→C tool and *validated* by a `pangs-manifest` helper the Rust rewriter
calls (every disposition needing a marker has one; no orphan markers); (b) generation
of `pangs_markers.h` from a manifest (`pangs-dispose --emit-marker-header`):
declarations + empty definitions guarded so multiple inclusion and single-definition
both work; (c) the round-trip harness (§5).

**Acceptance:** the round-trip test — toy program + manifest → mock C→C materializer
plants markers → real translator → fixture rewriter matches every inventory entry,
deletes all `pangs_*` symbols, output greps clean.

### D3 — atomic eligibility (gated; build iff the §7 counter is material)

Specified now so the gate counter measures the right thing; sized when scheduled.
Certificate requires **all** of: `word_sized_scalar`; `access_set_complete`; every
access site classifiable as load, store, or a recognized RMW shape (`g++`, `g += k`,
`g = g op k` — classified on IR, emitted per-site so the rewriter knows
`load(Relaxed)` vs `fetch_add`); no address-taken use incompatible with retyping
(`&g` never flows beyond directly-lowered access — reuse the pts scan); **conservative
co-write re-derivation** independent of D2b (`DISPOSITION.md` §6): any other global
written in the same function within the same statement region ⇒ potential invariant
⇒ fail with witness (over-strict is correct here; the failure witness feeds the
threshold discussion). Ships **with** its co-update dynamic audit (instrument
suspected-coupled pairs; interleaved-update window ⇒ report) — the audit is part of
the item, not a follow-up, because atomic coupling is the one silent-corruption cell
(`DISPOSITION.md` §7).

### D4 — mutex eligibility (gated)

Certificate: `access_set_complete`; ¬`signal_context_access`; reentrancy check — build
the "may access g" function set, fail if any member can reach another member through
the final call graph while holding the would-be lock (v1 approximation: any call path
between two access-containing functions ⇒ fail with the path as witness; refine to
lock-scope granularity only if the counter says it matters). Granularity advice from
D2b groups. Dynamic audit: lock-cycle detection under the program's test suite.

## 4. Sequencing

```
D0 spike ──────────────────────────────┐
D1a manifest crate ──▶ D1b facts ──▶ D1c cascade ──▶ D2 overrides
        │                   ▲                │
        │                   │ (fills slots)  ├──▶ D2b coupling ──▶ (O6 consumes ids)
        └──▶ (O6 targets    │                │
             manifest)   O1–O5/O6 ───────────┴──▶ D5 markers ◀── D0 rules
                                                       │
                                              round-trip harness
                                                       │
                                          M3 measurement ──▶ gate D3 / D4
```

Against the lite milestones: D1a/D1c have **zero analysis dependencies** and can be
built immediately. D1b needs M1 facts only (`written`, Ω bits, spawn reachability) —
the manifest ships at M1 with `phase_stationarity`/`coupling_group` null and a
degenerate but useful cascade (`immutable`/`localize`/`unhandled`). M2+O-items fill
the `once-lock` slot; D2b can land any time after D1b. D5 waits for D0 and for the
C→C tool to be ready to consume dispositions — until then the round-trip harness's
mock materializer (§5) stands in. This ordering means **the disposition layer is never
the blocker**: each analysis improvement lights up cascade entries in an
already-shipping manifest.

One deliberate resequencing vs. naive reading of `DISPOSITION.md` §9: O6 (ONCELOCK
emission) should target the manifest from the start — do **not** build the standalone
schema-v1 emitter and then port it. If O6 lands before D1a, D1a is blocking it;
schedule accordingly (D1a is small and has no dependencies, so this costs nothing).

## 5. Contract test harnesses

The real C→C tool and Rust rewriter are separate codebases on their own schedules; the
contract must be testable without them:

- **Mock C→C materializer (~150 lines, test-only):** reads a manifest, performs *only*
  the marker planting and exemption bookkeeping of `DISPOSITION.md` §5.3 on a toy C
  program (no localization rewriting), emits the marker inventory and a demotion case
  (one global whose publication point it pretends it cannot rewrite). This pins the
  §5.3 semantics — especially demotion-with-witness — as executable truth.
- **Fixture Rust rewriter (~200 lines, test-only):** consumes translated toy output +
  manifest, performs the `once-lock` rewrite of `ONCELOCK.md` §4.2 on the fixture,
  validates the marker inventory, deletes markers. Not production tooling — its job is
  to fail the build when someone changes the manifest or marker contract without
  updating both sides.
- Both harnesses live in the PANGS repo and run in CI; the production tools import
  `pangs-manifest` and inherit the same golden fixtures, so contract drift is caught
  at the source.

## 6. Testing strategy (consolidated)

| Layer | Test | Introduced by |
|---|---|---|
| schema | round-trip byte-identity; unknown-field preservation; version-gate error (§1.3 code 3) | D1a |
| key/marker codecs | parse∘format property; mangling collision fixture | D1a |
| cascade | fact-grid property test (guard holds, skips recorded, deterministic) | D1c |
| overrides | outcome matrix × override kinds; exit codes; idempotence | D2 |
| coupling | fixtures incl. documented over-grouping; id stability | D2b |
| contract | mock-materializer + fixture-rewriter round trip; demotion path | D5 |
| ledger | accepted-risk append + uniqueness of record ids | D2 |
| end-to-end | golden `pangs-manifest.json` + `pangs-audit.json` on the small-program corpus, diffed on every change (lite idiom) | D1b onward |

Plus the measurement side (not tests, but built with the code): the would-be
eligibility counters (§7) are emitted from D1b's fact vector from day one.

## 7. Gates for D3/D4 (measured free, decided at M3)

From the fact vector alone, before either pass exists:

- **atomic would-be count:** `word_sized_scalar ∧ access_set_complete ∧
  singleton coupling group ∧ disposed localize/unhandled` — an overcount of what D3
  could certify (no RMW-shape or address-compat check yet), which is the correct
  direction for a build/no-build gate.
- **mutex would-be count:** `access_set_complete ∧ ¬signal_context_access ∧ disposed
  localize/unhandled`, reported alongside the context-struct pressure metric
  (`DISPOSITION.md` §10.3) since mutex's main payoff is relieving exactly that.

Judge on Vim + PHP at M3, per `DESIGN_lite.md` §6's gate style: material counts ⇒
schedule D3/D4; negligible ⇒ record the numbers and close the slots (they remain
`null`, which the schema and cascade already handle).

## 8. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Marker calls don't survive the translator (whole §5 contract collapses) | D0 spike first; documented fallback = C→C-emitted source map; decision recorded here |
| Key instability across runs (path spelling, harness rename scheme drifting) breaks overrides | grammar + normalization fixed in §1.1, owned by lowering; uniqueness asserted at fact assembly; parse/format property tests; `unmatched-key` is loud by design |
| Schema churn while O6 and the C→C tool are being written against it | D1a lands first and freezes v2 via golden tests; additive-only rule; unknown-field preservation protects mixed-version tooling |
| Coupling heuristic too permissive/strict | advisory for all consumers except D3, which re-derives; threshold is config; over-grouping documented in tests as intended v1 behavior |
| Policy/facts separation erodes under deadline pressure (facts computed inside the cascade "just this once") | ground rule 2 is PR-reviewable: `pangs-dispose` has no dependency on the analysis crates — enforce with a workspace dependency lint |
| Two consumers reimplement contract pieces and drift | single `pangs-manifest` crate (§2); contract harnesses in CI (§5) |

*(D0 findings to be recorded here when the spike runs.)*
