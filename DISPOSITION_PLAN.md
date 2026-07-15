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
   a decision, not a refactor. Unknown fields survive parse/canonicalize/emit (see
   D1a).
4. **Determinism.** Emission uses one canonical pretty-JSON encoding: record fields in
   schema order; flattened unknown fields in lexical order; globals by key; groups by
   id; traces in cascade order; a trailing newline; and no dependence on hash-map
   iteration. Arbitrary input whitespace and object-key order need not be preserved.
   Canonicalizing the same semantic input produces byte-identical output, and a second
   canonicalization is a byte-level no-op. This is what makes golden-file testing and
   manifest diffing work.
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
marker      := "pangs_" kind "__" mangled-id "__" hash8
kind        := "publish" | "disposition_" strategy
mangled-id  := (key | group-id) with every byte outside [A-Za-z0-9] replaced by "_"
hash8       := lowercase hex FNV-1a-32 of the *raw* key (or group-id) bytes
```

Example: `pangs_publish__src_commands_c__cmd_table__9f3a01c4`. A coupled once-lock
group's shared publication marker is named by its **group id**, not a member key
(`pangs_publish__grp_cmd__<hash8>`, hash over the raw group-id bytes); all other
markers are named by global key. Cardinality and inventory-validation rules are in
`DISPOSITION.md` §5.2. The hash suffix makes the lossy mangling injective in practice;
D5 still emits a hard error on collision (paranoia is cheap here). The codec lives in
one shared crate (§2) — analysis, C→C tool, and Rust rewriter must never reimplement
it.

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

Record ids are deterministic:
`id = "ar-" + hash8(canonical JSON of { kind, scope, source, text })`, using the same
FNV-1a-32 as §1.2. Two distinct records hashing to the same id after generation is a
hard error (which also catches emitting the same assumption twice). Ownership on
re-run follows `DISPOSITION.md` §3.3: `pangs-dispose` deletes and regenerates exactly
the `source: "override"` records and preserves `analysis`/`entry-spine` records
byte-for-byte, so the D2 idempotence test covers this artifact too.

### 1.5 Fact and certificate encodings (schema v2, frozen by D1a's golden)

These shapes complete `DISPOSITION.md` §2/§3.

**Evidenced bool** — every boolean fact:

```jsonc
{ "value": <bool>, "witness": <Witness> }   // witness present iff value is the
                                            // fact's *blocking* polarity
```

Blocking polarity per fact (the direction that removes strategies): `written`,
`omega_escaped_address`, `violation_taint`, `thread_visible`, `signal_context_access`
block when **true**; `access_set_complete` blocks when **false**. Fact assembly
asserts the witness-iff-blocking invariant; the schema validator re-checks it.

**Witness:**

```jsonc
{ "kind": "<registry string>",
  "site":   { "file": "...", "line": 1, "col": 1?, "function": "..."? }?,  // this-run
  "symbol": "<function or value key>"?,                                    // evidence,
  "note":   "<free text>"? }                                               // never identity
```

`kind` is an open string registry (additive evolution: consumers tolerate unknown
kinds). Initial entries: `write-site`, `escape-site`, `violation-finding`,
`spawn-reachability`, `signal-registration`, `omega-access-path`.

**word_sized_scalar:**

```jsonc
{ "value": <bool>, "type_spelling": "<C spelling>"?, "size_bits": <int>? }
// type_spelling and size_bits present iff value is true
```

**Certificate slot** (`phase_stationarity`, `atomic_eligibility`, `mutex_eligibility`):

```jsonc
  null                                                       // not computed
| { "status": "certified", "certificate": { ... } }          // pass-specific payload
| { "status": "failed",
    "codes": ["never-quiescent", ...],                       // ≥1, pass-owned registry
    "witnesses": [ <Witness>, ... ] }
```

The certified `phase_stationarity` payload is `ONCELOCK.md` §2's per-global object
verbatim; D3/D4 define their payloads when built. Failure-code registries are owned by
the producing pass.

**Localization verdict:**

```jsonc
  null                                                       // client didn't run
| { "component": "<component id>",
    "verdict": "ok" | "blocked",
    "blockers": [ { "code": "<registry>", "witness": <Witness> }, ... ] }
// blockers non-empty iff blocked; initial code registry: unknown-caller-taint,
// unknown-callee-taint, frozen-component
```

The cascade guard "localization verdict OK" is `verdict == "ok"`.

**Cascade skip reason** (`cascade_trace[].reason`):

```jsonc
  { "kind": "guard-failed", "failed": ["<guard name>", ...] }  // every failing conjunct,
                                                               // in the strategy's
                                                               // documented guard order
| { "kind": "fact-not-computed", "fact": "<fact name>" }
```

Guard names are the fact names of the strategy's conjuncts (`DISPOSITION.md` §1) plus
`violation_taint`, the implicit conjunct of every guard: a tainted global skips every
configured entry with `guard-failed: ["violation_taint", ...]` and lands on
`unhandled`. `cascade_trace` covers exactly the configured order — a strategy disabled
by config appears nowhere in the trace (the order itself is recorded in
`run.dispose`).

Rust-side these are `EvidencedBool`, `Witness`, `WordSizedScalar`,
`CertificateSlot<C>` (an `Option` around a two-variant `status`-tagged enum),
`Localization`, and `SkipReason` in `pangs-manifest`, each carrying the
`#[serde(flatten)]` unknown-field map like every other record type (D1a).

### 1.6 Cascade configuration

```
CascadeConfig { mode: application | library, order: [strategy, ...] }
```

- **`order` is exhaustive**: the complete list of enabled strategies, evaluated left
  to right. A strategy not listed is disabled for the run — nothing is implicitly
  appended. "Capping the cascade" means supplying a shorter list; uniformity mode
  "everything localizes" is `order = ["localize"]`. (The earlier "per-strategy
  enable/cap" phrasing is retired: enablement *is* list membership.)
- **Defaults** when no `[cascade]` block is present: application =
  `["immutable", "once-lock", "atomic", "mutex", "localize"]`; library = the same
  without `localize`.
- `unhandled` is the implicit last entry and may not be listed. Duplicates and unknown
  strategy names are config errors. `localize` under `mode = library` is a config
  error — the applications-only rule is enforced loudly here, never skipped silently.
- Strategies whose producing pass has not run **may** be listed (the defaults include
  `atomic`/`mutex` from day one): a `null` fact slot skips per-global as
  `fact-not-computed` (ground rule 6), keeping the default order stable across pass
  availability.
- An invalid `[cascade]` block exits with code **1**, not 2: it poisons every
  disposition rather than a single key, so no manifest is written and there is no
  silent fallback to the default order.

### 1.7 Re-run semantics

`DISPOSITION.md` §3.3 fixes stage ownership of manifest sections. Operationally for
`pangs-dispose`:

- **reads** only analysis-owned sections: `run.analysis`,
  `globals[].{key, meta, facts}`, `coupling_groups` minus `group_disposition`;
- **discards and regenerates**: `run.dispose` (wholesale — no stale dispose-time
  config survives), every `disposition` block, every `group_disposition`,
  `override_report`;
- **drops** any `materialization` section with a stderr warning — a stale marker
  inventory or demotion record must not survive a re-dispose; the C→C stage runs
  again;
- in `pangs-audit.json`, regenerates `source: "override"` records only (§1.4).

The D2 idempotence test is therefore exact: `pangs-dispose` on its own output with the
same config and overrides is a byte-level no-op across both artifacts, and changing
only the overrides file changes only dispose-owned content.

## 2. Code layout

New crates in the PANGS workspace (names final unless the workspace has conflicting
conventions):

| Crate | Contents | Depended on by |
|---|---|---|
| `pangs-manifest` | schema v2 serde types (`Key`, `Meta`, `Facts`, `PhaseStationarity`, `Disposition`, `CascadeTrace`, `CouplingGroup`, `RunHeader`, `OverrideReport`, `AuditRecord`), key grammar + parser (§1.1), marker codec (§1.2), schema-version constants, canonical JSON read/write | analysis, `pangs-dispose`, C→C tool, Rust rewriter — **the one shared dependency; keep it std+serde+serde_json only** |
| `pangs-dispose` | the policy stage: cascade evaluator, override machinery, group disposition resolution, report + ledger emission. Library + thin CLI | CI, users |
| (existing analysis crate, phase F) | fact-assembly post-pass, coupling post-pass (D2b), marker-inventory schema checks | — |

Design point worth locking in: **the policy stage is re-runnable offline.**
`pangs-dispose` reads a manifest using only its analysis-owned sections, applies
cascade + overrides, and rewrites the manifest under the §1.7 / `DISPOSITION.md` §3.3
ownership rules. Changing an override never requires re-analysis; the run header
records both the analysis provenance (`run.analysis`) and the dispose-time config
(`run.dispose`), so a manifest is always self-describing. The analysis binary calls
the same library in-process for the initial emission — one code path, two invocation
modes.

Naming note: the repo already ships an unrelated artifact called the "PANGS manifest"
(`schemas/manifest.schema.json`, `schema_version: 1` — the analysis *export* index of
files + hashes). The disposition manifest is a different document with its own version
counter; its JSON Schema lands as `schemas/disposition-manifest.schema.json`, and
prose should say "export manifest" vs. "disposition manifest" wherever both are in
scope.

## 3. Work items

### D1 — manifest, fact assembly, cascade (~400 lines + crate scaffolding)

Split for independent landing:

- **D1a — `pangs-manifest` crate (~300 lines).** Types + serde for the §3 schema of
  `DISPOSITION.md`; key parser/formatter with the §1.1 grammar (property test:
  parse∘format = id); marker codec (§1.2) with collision detection; unknown-field
  preservation on canonical round-trip (`#[serde(flatten)] extra: BTreeMap<String,
  Value>` on every record type — an older `pangs-dispose` must not strip fields written
  by a newer analysis). All tools use the crate's canonical JSON writer rather than
  calling `serde_json` emission directly. Golden test: a checked-in canonical v2
  manifest parses and re-emits byte-identically; a deliberately non-canonical fixture
  canonicalizes once and is byte-identical on the second pass.
- **D1b — fact assembly (phase-F post-pass, ~200 lines + lowering plumbing below).**
  One scan assembling the `DISPOSITION.md` §2 vector per client-relevant global.
  New-but-cheap facts built here: `signal_context_access` (reader/writer functions
  whose addresses flow to signal-registration sites — the Ω escape-site scan already
  walks these); `access_set_complete` (factored from the ONCELOCK kill-rule
  conjunction so both consumers share one definition); `thread_visible` (spawn-entry
  TransRef/TransMod reachability); `word_sized_scalar` (from O1b type metadata).
  `phase_stationarity` and `coupling_group` are wired in when O6/D2b land — until
  then the slots are `null`, which the cascade already tolerates (ground rule 6).

  **Repository readiness (audited 2026-07-15):** D1b is *not* pure assembly over
  currently exported facts. `GlobalInfo` (`crates/pangs-api/src/lib.rs`) today
  carries only `is_const`/`mutable`/`stationary`/`never_written`/`escape` — no
  linkage, no C type spelling or size, and no spawn-reachability, signal-context, or
  access-completeness scans exist anywhere in phase F yet — and keys are raw symbol
  names from lowering (`value_name`), not the §1.1 TU-qualified grammar. D1b
  therefore includes lowering/pangs-api plumbing (still zero solver changes, ground
  rule 1), split so it lands safely:
  - **D1b-pre (lowering, land first and alone):** TU-qualified keys per §1.1
    (defining-TU capture + path normalization at the `pangs-pir` boundary) — this
    renames every key in every existing export stream, so it is one atomic change
    with a full golden-file refresh; plus `linkage` and C type spelling / size
    metadata on globals (the O1b dependency, pulled forward into `meta` and
    `word_sized_scalar`).
  - **D1b proper:** the three new F scans and the assembly pass, as above.

  Revised estimate: ~200 lines assembly + ~250 lines lowering plumbing.
- **D1c — cascade evaluator (in `pangs-dispose`, ~150 lines).** Pure function:
  `fn dispose(&Facts, &CascadeConfig) -> (Disposition, Vec<CascadeSkip>)`. Guards
  exactly as `DISPOSITION.md` §1 (including the implicit `¬violation_taint` conjunct
  on every guard) and are evaluated independently — support for one strategy never
  implies support for another; config = `CascadeConfig` per §1.6; `unhandled` is
  always the implicit last entry and cannot be configured away. Every skip records
  `{strategy, reason}` with the §1.5 `SkipReason` shape (every failing conjunct, or
  `fact-not-computed`).

**Acceptance:** golden manifest for a hand-built fact fixture; property test over a
generated grid of fact vectors (all boolean combinations × certificate
present/absent/null) asserting (a) chosen strategy's guard holds, (b) every earlier
strategy has a recorded skip reason, (c) determinism.

### D2 — override machinery (~250 lines, in `pangs-dispose`)

TOML format per `DISPOSITION.md` §4.1 (serde + `toml`). Validation per §4.2, in this
order per override: key resolution (§1.1 grammar; unmatched ⇒ `unmatched-key`) →
group-conflict check (§4.2 rule 3) → independent fact-support check (is the pinned
strategy's own guard satisfied?) → outcome (`honored` /
`honored-accepted-risk` / `rejected`). Group pins resolve before member pins using the
group-support intersection algorithm in `DISPOSITION.md` §6. A member pin that differs
from the resolved group disposition is rejected even with `accept_risk`; group pins
whose group guard fails use the ordinary accepted-risk rule. Both records appear in
the report. Accepted risks append to
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

Policy resolution is separate from clustering: compute each member's independent
support set, intersect those sets, apply the group-specific guards from
`DISPOSITION.md` §6, then select the first supported configured strategy (or validate
the group override). Never compare enum ordinals or infer support from an earlier
certificate. Joint `once-lock`/`mutex` materialization failure demotes the whole group;
`immutable`/`localize` materialization failure may demote only the affected member.

**Acceptance:** unit fixtures (the `cmd_table`+`cmd_count` pair; two unrelated globals
written by one utility function — expected to over-group at default threshold, test
documents this as intended); determinism of ids under member reordering; a
group-resolution matrix covering empty/non-empty support intersections, reordered
cascades, missing common OnceLock publication, multi-member atomic rejection, group
pins with and without `accept_risk`, and conflicting member pins. The mock materializer
also verifies whole-group demotion for a failed joint `once-lock`/`mutex` rewrite and
member-only demotion for `immutable`/`localize`.

### D5 — marker contract (~150 lines analysis-side + harness)

Deliverables: (a) marker codec already in D1a — this
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
| schema | canonical round-trip byte-identity; one-pass normalization of non-canonical input; unknown-field preservation; version-gate error (§1.3 code 3) | D1a |
| key/marker codecs | parse∘format property; mangling collision fixture | D1a |
| cascade | fact-grid property test (guard holds, skips recorded, deterministic) | D1c |
| overrides | outcome matrix × override kinds; exit codes; idempotence | D2 |
| coupling | fixtures incl. documented over-grouping; id stability; support-intersection and override matrix | D2b |
| contract | mock-materializer + fixture-rewriter round trip; joint-group and member-only demotion paths | D5 |
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
| Translator not available to this repo (D0 cannot run at all) | D0 marked blocked with what's needed from the project owner; D5 is the only dependent item; everything else proceeds |
| Key instability across runs (path spelling, harness rename scheme drifting) breaks overrides | grammar + normalization fixed in §1.1, owned by lowering; uniqueness asserted at fact assembly; parse/format property tests; `unmatched-key` is loud by design |
| Schema churn while O6 and the C→C tool are being written against it | D1a lands first and freezes v2 via golden tests; additive-only rule; unknown-field preservation protects mixed-version tooling |
| Coupling heuristic too permissive/strict | advisory for all consumers except D3, which re-derives; threshold is config; over-grouping documented in tests as intended v1 behavior |
| Policy/facts separation erodes under deadline pressure (facts computed inside the cascade "just this once") | ground rule 2 is PR-reviewable: `pangs-dispose` has no dependency on the analysis crates — enforce with a workspace dependency lint |
| Two consumers reimplement contract pieces and drift | single `pangs-manifest` crate (§2); contract harnesses in CI (§5) |

*(D0 findings to be recorded here when the spike runs.)*
