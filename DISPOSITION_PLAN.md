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
   A′–D′ semantics are frozen inputs. Precisely: no solver-*semantic* changes —
   constraint generation, propagation, and every existing output bit stay untouched —
   while **additive output/postprocessing plumbing is allowed** (extra provenance
   fields, targeted points-to materialization for D1b); that is how witnesses are
   produced at all. A work item that "needs" a semantic solver
   change is mis-scoped — stop and re-read `DISPOSITION.md` §2's rule of construction.
2. **Facts never contain preferences; policy never computes facts.** The cascade
   evaluator must be a pure function of `(fact vector, config, overrides)` with no
   access to the PAG or solution.
3. **Additive schema evolution only.** Field removal or rename = new schema_version =
   a decision, not a refactor. Unknown fields survive parse/canonicalize/emit (see
   D1a).
4. **Determinism.** Emission uses one canonical pretty-JSON encoding: record fields in
   schema order; flattened unknown fields in lexical order; globals by key; groups by
   id; traces in cascade order; audit-ledger records by `id`; override-report entries
   by (scope kind, key, requested strategy); certificate failure `codes` lexically;
   witness lists by the canonical witness key (§1.5); coupling evidence edges by
   (kind, members) and their `sites` by (file, line, col); a trailing newline; and no
   dependence on hash-map iteration. Arbitrary input whitespace and object-key order need not be preserved.
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

Examples: `src/commands.c::cmd_table` when source metadata is available, and bare
`cmd_table.42` when it is not. Statics need no extra qualification: the translation
harness globally uniquifies their names in a pre-pass, so by the time PANGS sees the
program every static's name is program-unique. Two prerequisites this
leans on: (a) the uniquification pre-pass runs **before** analysis, so manifest keys
match what the C→C tool and translator see — recorded as a run assumption in
`pangs-audit.json`; (b) fact assembly asserts key uniqueness and hard-errors on
collision (the backstop if (a) is ever violated or the harness's scheme changes). Path
normalization happens once, in lowering, against the configured repo root — nowhere
else — by the algorithm below.

**Normalization algorithm.** Load-bearing: changing it later orphans every override
file, so it is fixed here. Keys are a pure function of (DI metadata, `repo_root`) —
lexical throughout, with exactly one filesystem-touching step:

1. `repo_root` is absolutized and `realpath`'d **once** at analysis start; the
   resolved form is what `run.analysis.repo_root` records.
2. The source path is assembled per DWARF rules: `DIFile.filename` if absolute,
   otherwise `DIFile.directory` joined with it. A still-relative result (relative
   compilation directory) is unresolvable → step 5.
3. The assembled path is normalized **lexically only**: separators to `/`, `.`
   segments dropped, `..` segments collapsed against their lexical parent, **no case
   folding, no per-file `realpath`** — keys must match the path spelling the C→C
   tool and translator see in the build tree, and per-file symlink resolution would
   tie keys to the analysis machine's filesystem state instead. A build that spells
   paths through an in-repo symlink gets keys as stable as that spelling (the §8
   key-instability risk row covers drift).
4. The `repo_root` prefix is stripped — trying the resolved form first, then the
   as-given absolute form, to tolerate a root reached via symlink. The remainder is
   `tu-path`.
5. A path that ends up outside `repo_root`, cannot be absolutized, or contains a
   literal `::` is omitted from a global key; the globally unique symbol name remains
   usable. A function in this state still cannot anchor a source-level certificate.

`symbol-name` must match `[A-Za-z0-9_.$]+` — C identifiers plus LLVM/uniquifier
decorations, colon-free by construction. `tu-path` may contain a single `:` but never
`::` (step 5), so a qualified key parses unambiguously at its **last** `::`; a bare
key is the symbol alone. Fact assembly validates the available components.

Decisions the grammar previously left open:

- **The grammar covers all symbol identities *in the manifest*, functions included —
  and only defined symbols ever receive one.** Certificates, witnesses, and the
  once-lock rewiring are keyed by function identity, and internal-linkage (static)
  functions collide across TUs exactly like globals do. One grammar, one parser,
  both symbol kinds. But the qualified key is a **manifest-layer identity, derived
  at fact assembly** from (DI defining file, symbol name) — it does not replace the
  raw LLVM names (`FuncInfo.key` / `GlobalInfo.key`) that the existing analysis
  export streams use; those identifiers stay as they are, and manifest records carry
  the raw name alongside (`meta.llvm_name`) as the this-run join key back to the
  streams — evidence, never identity. **External declarations get no qualified key
  and no synthetic grammar**: they have no defining TU, cannot be disposition
  subjects or certificate anchors (both require rewriting a definition we own), and
  where a witness needs to mention one (`pthread_create`, a libc sink) its `symbol`
  field carries the raw name as free evidence text.
- **`repo_root` is an explicit lowering input** (CLI flag / config, no default
  guessing), recorded in `run.analysis.repo_root` so key derivation is reproducible
  from the manifest alone. **Scope: mandatory only for commands that emit
  disposition artifacts** (the manifest/ledger emission path errors without it);
  every other command — the existing analyze/export/metrics surface, whose loader
  takes only an input path today — is unchanged, avoiding CLI and fixture churn for
  runs that never mint keys.
- **The defining-TU path comes from DI metadata** (`DIGlobalVariable` /
  `DISubprogram` file), the same source D1b-pre already names for type spelling.
  Today's lowering emits `file: None` for every global
  (`crates/pangs-pir/src/llvm_sys.rs`, `bump_missing_debug_location("global")`) —
  capturing it is part of the D1b-pre scope, not a new discovery.
- **A global with no DI defining file uses its globally unique symbol name as its
  cross-tool identity.** This is not a synthetic placeholder: it is the name produced
  by the mandatory pre-analysis uniquification pass and consumed by downstream tools.
  `meta.file` remains optional provenance. `unkeyed_globals` is reserved for a mutable
  definition whose symbol itself violates the manifest grammar. A *function* with no
  DI file is still handled conservatively where source identity is needed: it cannot
  anchor a source-level certificate.

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

### 1.3 `pangs-dispose` CLI contract: I/O and exit codes

**Input.** `pangs-dispose <export-dir | manifest-path>`: the directory form resolves
`<dir>/pangs-manifest.json`. The soundness ledger is located as the **sibling
`pangs-audit.json` next to the manifest** by default, overridable with
`--audit <path>`; the manifest never embeds a ledger path (embedded paths go stale
when exports are copied). A **missing ledger is exit code 1**, never auto-created:
analysis emission always writes it (at minimum the run-assumption records, §1.1), so
absence means an incomplete or hand-pruned export, and inventing an empty ledger
would silently discard the claim that analysis-sourced assumptions were ever
recorded.

**Initial emission.** `pangs analyze` gains an **opt-in `--dispose` flag** (with
`--repo-root`, and optionally `--mode`, `--overrides`/`--no-overrides`, `--out`):
one run does analysis → fact assembly → in-process policy stage (§2's "one code
path, two invocation modes") → atomic pair emission. Without `--dispose`, `analyze`
is byte-identical to today — no new required flags, no fixture churn (the §1.1
repo-root scope rule). `--dispose` without `--repo-root` is exit 1. No separate
analysis+emission command: offline `pangs-dispose` already covers every re-run
case, and a second analysis entry point would duplicate the `analyze` surface.

**Overrides selection.** Both explicit and discovered, with explicit winning:
`--overrides <path>` if given (pointing at a missing file ⇒ exit 1 — an explicit
request must be satisfiable); otherwise the sibling `pangs-overrides.toml` next to
the manifest is auto-discovered *if present*; otherwise no overrides (a valid run).
`--no-overrides` suppresses auto-discovery (baselines, idempotence harnesses);
combining it with `--overrides` is a usage error. `run.dispose.overrides_file`
records the resolved path (null when none) and `overrides_sha256` the content hash,
so a manifest states exactly which override set produced it — the reproducibility
anchor for the idempotence test. One consequence to know: with `--out <dir>`, a
*later* rerun on the output directory will not auto-discover the original overrides
file (it is not copied); the recorded `overrides_file`/`overrides_sha256` make that
loud — rerunning with a different effective override set changes `run.dispose`
visibly rather than silently.

**Output.** Default is **in-place rewrite of both artifacts**; `--out <dir>` writes
the pair elsewhere and leaves the inputs untouched. The pair is replaced via
temp-file + rename in the target directory: ledger renamed first, manifest last —
the manifest is the commit point. Two renames are not jointly atomic; the crash
window leaves a new ledger beside an old manifest, which the next run overwrites
wholesale (both are pure functions of their inputs, §1.7), and no individual file is
ever observable torn.

**Export-index interaction.** The disposition artifacts live in the export directory
but are **excluded from the export manifest's `files` index** (`manifest.json`,
`schemas/manifest.schema.json`): that index carries sha256es of the immutable
analysis streams, and indexing artifacts that `pangs-dispose` rewrites offline would
stale it by design.

**Exit codes.**

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

```jsonc
{ "id": "ar-…", "kind": "accepted-risk" | "run-assumption" | ...,
  "scope":   { "kind": "run" }
           | { "kind": "global", "key": "src/state.c::g_stats" }
           | { "kind": "group",  "key": "grp-cmd" },      // typed — group-level
                                                          //   accepted-risk records
                                                          //   (DISPOSITION.md §6) need it
  "source": "analysis" | "override" | "entry-spine",
  "text": "...", "witness": <Witness>?,
  "failures": [ <GuardFailure>, ... ]? }               // structured multi-failure
                                                       //   evidence (§1.8); sorted by
                                                       //   (member, guard, canonical
                                                       //   witness key)
```

Accepted-risk overrides (D2) append `kind: "accepted-risk"` records — one per
honored pin. A group pin produces a single `scope.kind: "group"` record whose
`failures` list identifies **every failed member and guard structurally** (one
`GuardFailure` each — never encoded into free-text `note`); a global pin
contradicting several facts uses the same field with the global's own key as
`member`. The `failures` list participates in the record's deterministic id hash
like every other field.
The human-readable inventory sections in `DESIGN.md` §8 remain the catalog of *kinds*;
the JSON is the per-run instantiation.

**Relationship to the existing `audit.jsonl`: augments, never replaces.** The export
directory's `audit.jsonl` (`schemas/audit.schema.json`) is the stream of per-site
Ω-taint *findings* — things the analysis detected in the program. `pangs-audit.json`
is the ledger of *assumptions* — things a human or a run configuration asserted and
must remain accountable for. Findings stay in `audit.jsonl` untouched; ledger
witnesses may reference findings by their site/kind, and the two artifacts share no
records. The ledger's JSON Schema lands as `schemas/disposition-audit.schema.json`,
beside `schemas/disposition-manifest.schema.json` (§2 naming note).

Record ids are deterministic:
`id = "ar-" + first 32 hex chars of SHA-256(canonical JSON of the record with the
"id" field omitted)` — **every semantic field hashes**, `witness` and `failures`
included, so records differing only in evidence get distinct ids. 128 bits, because
audit inventories can reach tens of thousands of records
on a 1 MLoC target and a 32-bit id's birthday bound would make hard-error collisions
an avoidable operational nuisance. (Marker names keep the §1.2 FNV hash8: that
namespace is far smaller, the mangled key carries most of the identity, and D5's
emission-time collision check backstops it.) Two distinct records with the same id
after generation is still a hard error — it also catches emitting the same assumption
twice. Ownership on re-run follows `DISPOSITION.md` §3.3: `pangs-dispose` deletes and
regenerates exactly the `source: "override"` records and preserves
`analysis`/`entry-spine` records semantically unchanged — byte-identical after
canonical re-emission — so the D2 idempotence test covers this artifact too.

### 1.5 Fact and certificate encodings (schema v2, frozen by D1a's golden)

These shapes complete `DISPOSITION.md` §2/§3.

**Evidenced bool** — every boolean fact:

```jsonc
{ "value": <bool>, "witness": <Witness> }   // witness present iff value is the
                                            // fact's *evidenced* polarity
```

Every boolean fact declares an **evidenced polarity** — the direction that demands
proof — and, separately, whether it is a **guard fact** (a conjunct of some cascade
guard, `DISPOSITION.md` §1) or a **reporting fact** (routing/measurement input only;
no cascade entry reads it). Evidenced polarity per fact: `written`,
`omega_escaped_address`, `violation_taint`, `signal_context_access`, and
`thread_visible` are evidenced when **true**; `access_set_complete` when **false**.
Guard facts: all of the above **except `thread_visible`**, which is a reporting fact —
thread visibility alone defeats no strategy (thread *readers* are a primary OnceLock
use case; the thread-*writer* kill rule lives inside the phase-stationarity
certificate where it belongs). Guard facts feed the cascade either directly
(`written`, `omega_escaped_address`, `violation_taint` — the fact-composed guards) or
as an eligibility pass's certificate preconditions (`access_set_complete`,
`signal_context_access` → D4; `DISPOSITION.md` §1's certificate-only guard rule).
Fact assembly asserts the witness-iff-evidenced
invariant; the schema validator re-checks it.

**Witness:**

```jsonc
{ "kind": "<registry string>",
  "site":   { "file": "...", "line": 1, "col": 1?, "function": "..."? }?,  // this-run
  "symbol": "<function or value key>"?,                                    // evidence,
  "note":   "<free text>"? }                                               // never identity
```

`kind` is an open string registry (additive evolution: consumers tolerate unknown
kinds). Initial entries: `write-site`, `escape-site`, `violation-finding`,
`spawn-reachability`, `signal-registration`, `omega-access-path`, `external-escape`,
`missing-debug-metadata`, `unnormalizable-path`, `invalid-symbol-name`.

**Canonical witness key** — the one ordering/tiebreak rule for witnesses everywhere
(ground rule 4 sorting, §1.9's "lexicographically smallest witness" selection): the
tuple `(kind, site.file, site.line, site.col, symbol, note)` compared
lexicographically, with absent fields ordering before present ones.

**word_sized_scalar:**

```jsonc
{ "value": <bool>,
  "type_spelling": "<C spelling, outermost typedef name if any>"?,
  "size_bits": <int>?,
  "class": "integer" | "boolean" | "enum" | "pointer"?,
  "signed": <bool>? }               // integer/enum only
// all optional fields present iff value is true (semantics: §1.9)
```

**Certificate slot** (`phase_stationarity`, `atomic_eligibility`, `mutex_eligibility`):

```jsonc
  null                                                       // not computed
| { "status": "certified", "certificate": { ... } }          // pass-specific payload C
| { "status": "failed",
    "codes": ["never-quiescent", ...],                       // ≥1, pass-owned registry
    "witnesses": [ <Witness>, ... ],                         // per-code witnesses
    "recipe": { ... }?,                                      // optional: same shape as
                                                             //   the certified payload,
                                                             //   attached when the pass
                                                             //   could compute the
                                                             //   rewrite plan despite
                                                             //   the failure — gates
                                                             //   accept_risk (§4.2)
    "diagnostics": { ... }? }                                // optional pass-owned extras
                                                             // (e.g. rescuable site lists)
```

The `recipe` field is what separates **"evidence failed"** from **"rewrite plan
absent"**: a kill-rule failure (say `thread-writer`) can still carry a full
publication payload if P selection ran, and an accepted-risk pin is executable only
then. A `never-quiescent` failure has no publication point to attach, so no recipe —
and no pin can be honored, `accept_risk` or not. Passes MAY attach recipes on
failure; they are never required to.

The producing pass emits this slot shape **directly** — there is no wrapping of a
pass-native document, and no nested verdict fields. For `phase_stationarity` the
certified payload `C` is the whole ONCELOCK success content,
`{ publication, writers, init_subtree, readers, observations }` (`ONCELOCK.md` §2.1 —
its former inner `certificate` object is renamed `publication`); the failed variant
carries the §2.2 reason codes as `codes`, their per-code witnesses as `witnesses`, and
any richer evidence (site lists) under `diagnostics`. D3/D4 define their payloads when
built. Failure-code and `diagnostics` registries are owned by the producing pass.

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
`unhandled`. `cascade_trace` is defined **relative to `cascade_chosen` only** — the
independent cascade result, a pure function of (facts, config) with no override or
group input (`DISPOSITION.md` §3.2). It records exactly the attempted-and-skipped
entries: the configured strategies strictly before `cascade_chosen`, in configured
order (all configured strategies when `cascade_chosen` is `unhandled`). Entries
after `cascade_chosen` are never attempted (first-applicable) and do not appear;
neither do strategies disabled by config (the order itself is recorded in
`run.dispose`). Neither `cascade_chosen` nor the final `chosen` is a trace entry.
When overrides, group constraints, or downstream demotion make `chosen` differ from
`cascade_chosen`, the trace does **not** explain the difference — `provenance`, the
`override` echo, the group record, and the `demotion` record do; the trace would
otherwise be asked to justify a strategy that never failed a guard.

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
- **`mode` defaults from the analysis build mode** recorded in `run.analysis.opts`:
  `executable` → `application`, `library` → `library`. An explicit `--mode` flag may
  *narrow* `application` → `library` (e.g. to forbid `localize` for a binary that
  will be librarified); widening `library` → `application` is a config error — the
  analysis ran without a `main` spine and `localize`'s premises don't hold.
- `unhandled` is the implicit last entry and may not be listed. Duplicates and unknown
  strategy names are config errors. `localize` under `mode = library` is a config
  error — the applications-only rule is enforced loudly here, never skipped silently.
- **The order also bounds overrides**: a pin may only name a listed strategy — pins on
  omitted strategies are `rejected-strategy-disabled` regardless of `accept_risk`
  (`DISPOSITION.md` §4.2). Exception: `unhandled` is never listed but always pinnable
  (safe opt-out).
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

### 1.8 Concrete shared-record shapes (completing schema v2)

Typing rule for D1a: **shared records are strongly typed now; pass-owned certificate
payloads are typed envelopes around opaque values.** Concretely, the certificate-slot
envelope (`status`/`codes`/`witnesses`) is typed, while `certificate` and
`diagnostics` interiors are `serde_json::Value` in v1 code — the JSON Schema does not
validate their interior, the producing pass's document (`ONCELOCK.md` §2 for
phase-stationarity) stays normative, and each landing pass promotes its payload to a
typed struct without changing the JSON shape (no `schema_version` bump). Everything
below is a shared record and is fixed here:

```jsonc
// run.analysis — mirrors the existing export-manifest header fields
{ "pangs_git": "...", "llvm_version": "...", "input_path": "...",
  "input_sha256": "...", "opts": { /* analysis Opts, as today */ },
  "repo_root": "...",                       // §1.1; key derivation input
  "target_triple": "x86_64-unknown-linux-gnu",
  "data_layout": "e-m:e-p270:32:32-...",    // verbatim LLVM data layout string
  "supported_atomic_widths": [8, 16, 32, 64],  // derived at lowering (§1.9)
  "entry_spine": { ... } }                  // ONCELOCK.md §2.1; null in library mode

// GuardFailure — shared structured evidence for multi-failure records
// (accepted-risk ledger records §1.4, override-report entries below);
// lists sorted by (member, guard, canonical witness key §1.5)
{ "member": "src/foo.c::g", "guard": "violation_taint", "witness": <Witness> }

// globals[].meta
{ "linkage": "internal" | "external",
  "type_spelling": "<C spelling>" | null,   // DI-derived (§1.1, D1b-pre)
  "size_bits": <int> | null,
  "align_bits": <int> | null,               // effective ABI alignment (D1b-pre)
  "llvm_name": "<raw LLVM symbol>",         // this-run join key to the analysis
                                            //   export streams (§1.1) — evidence,
                                            //   never identity
  "file": "..." | null, "line": <int> | null }   // evidence, never identity

// override_report
{ "entries": [
    { "scope": "global" | "group" | "cascade",
      "key": "<global key | group id | null for cascade blocks>",
      "requested": "<strategy | order list>",
      "accept_risk": <bool>,
      "outcome": "honored" | "honored-accepted-risk" | "rejected"
               | "rejected-strategy-disabled" | "rejected-strategy-unavailable"
               | "rejected-no-recipe" | "unmatched-key",
      "reason": "<free text>" | null,
      "witness": <Witness>?,
      "failures": [ <GuardFailure>, ... ]? } ],   // same shared shape and sort as
                                                  //   the ledger records (§1.4)
  "counts": { "honored": n, "honored_accepted_risk": n, "rejected": n,
              "rejected_strategy_disabled": n, "rejected_strategy_unavailable": n,
              "rejected_no_recipe": n, "unmatched_key": n } }

// unkeyed_globals[] — analysis-owned diagnostics (§1.1: no key ⇒ not in globals[])
{ "llvm_name": "<raw LLVM symbol>", "witness": <Witness> }

// coupling_groups[].evidence and coupling_candidates[].evidence — typed edges
[ { "kind": "co-write" | "oncelock-interval",
    "strength": "hard" | "suspected",
    "members": ["<key>", "<key>"],
    "sites": [ <Site>, ... ] } ]

// coupling_groups[].strategy_support.once_lock — the D2b common-P certificate
  { "supported": true,
    "publication_function": "<function key>",
    "common_interval": { "earliest": <Site>, "latest": <Site> },
    "common_p": <Site> }
| { "supported": false, "witness": <Witness> }   // names the first failing condition

// materialization — C→C-tool-owned (DISPOSITION.md §3.3)
{ "tool": { "name": "...", "version": "..." },
  "marker_inventory": [
    { "key": "<global key>", "kind": "publish" | "disposition_<strategy>",
      "marker": "<symbol>", "group": "<group id>" | null,
      "insertion": <Site> } ],                   // evidence-only
  "demotions": [ { "key": "<global key>", "from": "<strategy>",
                   "witness": <Witness> } ] }

// globals[].disposition.demotion — mirror of the demotions entry, on the record
{ "from": "<strategy>", "witness": <Witness> }
```

`Site` is the witness site object from §1.5 (`{ file, line, col?, function? }`).

### 1.9 Fact-production rules (D1b normative — not to be inferred)

- **`written`** is *may-written*: `value = !never_written` from the solved solution,
  which today is also false when the object's storage escapes externally
  (`crates/pangs-solve/src/lib.rs`, `never_written = !escape_external ∧ no store
  reaches the class`). The witness is a concrete write site when one exists
  (`kind: "write-site"`), otherwise the escape that prevents ruling writes out
  (`kind: "external-escape"`). The `immutable` guard's `¬written ∧
  ¬omega_escaped_address` is therefore partially redundant — accepted; redundancy in
  a soundness guard is free.
- **`violation_taint(g)`**: direct or bounded-aliased function-local co-occurrence
  proposes a `(finding, g)` pair; it does not prove relevance. Each pair is classified
  `address-relevant`, `access-shape-relevant`, `value-only`, `unrelated`, or
  `unresolved`. Only the first two and fail-closed `unresolved` set this fact.
  Exact affected-value/address-node identity and exact indirect-access-site identity
  are positive evidence. Direct named scalar accesses are independent for the modeled
  function-pointer/boundary finding kinds unless the finding names their object;
  unknown kinds and indirect paths that require unavailable reachability information
  are `unresolved`. Every classification remains in `facts.violation_relevance`, with
  deterministic witnesses; module-wide access rows remain boundedness failures rather
  than turning same-function co-occurrence into relevance.
- **`access_set_complete(g)`** is a pure boundedness fact, evaluated in this order
  with the first failing condition as witness: (a) no `ModuleWide` unknown-access
  modref row can reach module globals (a retained `Finite` candidate set affects only
  its members and remains bounded even when abbreviated in exports); (b)
  `¬omega_escaped_address(g)`; (c) `g` is not **exported** — precisely the
  analysis-level exported bit (`is_exported_global`: external linkage ∧ default
  visibility ∧ the run's `exports` config under its build mode), *not* raw external
  linkage alone and *not* escape — an exported global is nameable by client code
  the analysis never sees, so its access set cannot be complete in library mode;
  (b) and (c) deliberately partition the exposure surface: (b) = address escaped
  (any mode), (c) = reachable by name (library builds); and (d) lowering did not
  report an access-bearing construct for which no access site can be represented at
  all. Bounded indirect accesses and violation findings are routed separately to
  D3/D4 and do not change this fact. When several sites
  fail one condition, the witness is the lexicographically smallest witness key
  (determinism, ground rule 4).
- **`word_sized_scalar(g)`** — the name is historical shorthand; the actual
  predicate is "has a matching Rust atomic type on the target":
  - **Widths**: `size_bits ∈ run.analysis.supported_atomic_widths` (captured at
    lowering by the conservative rule in D1b-pre — all of {8, 16, 32, 64} on the
    mainstream x86-64/aarch64 targets), **not** "exactly pointer width".
    Additionally `align_bits` — the *effective ABI* alignment D1b-pre records, not
    LLVM's often-zero explicit attribute — must equal `size_bits` (natural
    alignment; a packed placement disqualifies; atomics require it).
  - **Missing inputs fail closed**: absent type spelling, size, alignment, or
    target atomic-width support ⇒ `value: false`. Never guessed, never defaulted.
  - **Qualifying type classes**, after peeling `typedef`/`const`/`volatile`/
    `restrict` DI wrappers: integers (`DW_ATE_signed`/`unsigned`/`*_char`) →
    `AtomicIN`/`AtomicUN`; `_Bool` (`DW_ATE_boolean`) → `AtomicBool`; enums
    (`DW_TAG_enumeration_type`) via their underlying integer width — included in
    the fact (they widen the M3 gate counter in the overcount direction, which is
    correct for a build/no-build gate; whether D3 certifies enum retyping is D3's
    call); data and function pointers (`DW_TAG_pointer_type`) → `AtomicPtr`.
    Floats and everything else: `false` (no stable Rust atomic).
  - **Reconstruction from DI**: `type_spelling` is the *outermost* name as written
    (the typedef name when one exists — that is the spelling the rewriter must
    reproduce); `signed` comes from the `DW_ATE` encoding of the fully-resolved
    base type (enums: their underlying type; pointers/booleans: absent); `class`
    records which rule fired so the §7 gate counter can be broken down without
    re-parsing spellings.
- **`localization(g)`** — assembled from `ComponentInfo` (`compute_components`),
  stated exactly because it feeds a cascade guard:
  - A global may appear in the `mutable_globals` of **several** components (each
    component collects its members' modref targets). The verdict is the
    conjunction: `verdict: "ok"` iff `g` appears in at least one component and
    **every** containing component has `frozen: false` (which in the current code
    is `taint.is_empty()`). Note this is deliberately stricter than the existing
    `in_rewritable_components` metric, which counts membership in *any* non-frozen
    component — localizing `g` rewrites all its accessors, so every containing
    component must be rewritable.
  - `component` field: the lexicographically smallest containing component id
    (evidence, not identity).
  - `blockers`: the categories in the union of the frozen containing components'
    `taint` entries, mapped by kind — `unknown_caller` → `unknown-caller-taint`,
    `unknown_callee` → `unknown-callee-taint`, everything else (`unknown_global`
    and all audit-taint kinds such as `inline_asm`, `fnptr_ptrtoint`) →
    `frozen-component` with the original taint kind preserved in the blocker
    witness's `note` and the taint's witness key parsed into its `site`. To keep
    artifacts corpus-bounded, emit one canonical representative witness per blocker
    code and record the number of summarized taint entries as `evidence_count` in
    that blocker's extension map; blockers are sorted by the canonical witness key.
  - `g` in no component at all ⇒ `localization: null` (the client did not cover
    it; surfaces as `fact-not-computed` in the trace rather than a fabricated
    verdict).
- **Spawn / signal-registration API registries.** A registry entry carries its
  calling convention, so extensions are well-defined:
  `{ name, kind: "spawn" | "signal", entry: {"arg": i} | {"pointee_of_arg": i} }`
  (0-based argument indices). Built-in defaults:

  | name | kind | entry operand |
  |---|---|---|
  | `pthread_create` | spawn | `arg 2` (`start_routine`) |
  | `thrd_create` | spawn | `arg 1` (`func`) |
  | `signal` | signal | `arg 1` (`handler`) |
  | `sigaction` | signal | `pointee_of_arg 1` (handler inside `*act`) |

  Extensible via analysis opts (recorded in `run.analysis.opts`); never silently
  hardcoded elsewhere. Evaluation rules:
  - **Recognition runs over final-call-graph edges** to a registry function —
    indirect calls that resolve to one count the same as direct calls. An indirect
    call with an Ω/unknown-callee edge needs no special case: its function-pointer
    arguments already Ω-escape under the boundary rules, so Ω conservatism covers
    whatever it might have registered.
  - **Entry/handler set at a site** = every function object in the solved pts of the
    designated operand; for `pointee_of_arg`, every function object reachable
    through the operand's pointees (v1: any function in the pts of memory reachable
    from the struct pointer — covers both `sa_handler` and `sa_sigaction` without
    field discrimination). `SIG_DFL`/`SIG_IGN` integer constants are not handlers.
  - **Multiple resolved targets are all treated as entries/handlers** (union).
  - **Points-to materialization is targeted.** The normal solver result does not
    retain per-node pts sets (`node_points_to` is optional and populated only by
    special entry points today); D1b materializes function-object target sets
    **only for registry-site operands and the memory reachable from
    `pointee_of_arg` operands** — never an all-node export. Additive plumbing under
    ground rule 1's semantic/output distinction.
  - **Unresolved operand** (pts contains the Ω/unknown element): the entry set
    conservatively expands to the resolved targets **∪ every function whose address
    Ω-escapes** — that is exactly what the Ω element denotes, so this is the model's
    own answer, not an ad-hoc widening. Dependent facts then take their evidenced
    polarity (`thread_visible`/`signal_context_access` true for the affected
    globals) with the registration site as witness (kind
    `spawn-reachability`/`signal-registration`, note recording the unresolved
    operand). The over-approximation lands in the safe direction: it blocks `mutex`
    and widens reporting, never certifies.

  A *missing* registry entry still cannot corrupt: an entry function or handler
  passed to an unrecognized external is Ω-escaped by the existing boundary rules, so
  the miss degrades to conservatism (`omega_escaped_address` / kill rules), not to a
  false certificate. The registries only *refine*.

## 2. Code layout

New crates in the PANGS workspace (names final unless the workspace has conflicting
conventions):

| Crate | Contents | Depended on by |
|---|---|---|
| `pangs-manifest` | schema v2 serde types (`Key`, `Meta`, `Facts`, `PhaseStationarity`, `Disposition`, `CascadeTrace`, `CouplingGroup`, `RunHeader`, `OverrideReport`, `AuditRecord`), key grammar + parser (§1.1), marker codec (§1.2), schema-version constants, canonical JSON read/write | analysis, `pangs-dispose`, C→C tool, Rust rewriter — **the one shared dependency; keep it std+serde+serde_json+sha2 only** (`sha2` earns its slot: §1.4 audit ids) |
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
  One scan assembling the `DISPOSITION.md` §2 vector per client-relevant global —
  population per `DISPOSITION.md` §3: every defined mutable global (the existing
  `GlobalInfo.mutable` bit, post ignore-list, function-scope statics included;
  stationary/never-written included). Missing source-file metadata produces a bare
  globally unique key; only invalid symbol spellings are diverted to `unkeyed_globals`.
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
  linkage, no C type spelling or size, **no definition-vs-declaration bit**, and no
  spawn-reachability, signal-context, or access-completeness scans exist anywhere in
  phase F yet — and keys are raw symbol names from lowering (`value_name`), not the
  §1.1 TU-qualified grammar. D1b
  therefore includes lowering/pangs-api plumbing (still zero solver changes, ground
  rule 1), split so it lands safely:
  - **D1b-pre (lowering, land first and alone):** capture the *inputs* for §1.1
    manifest keys — DI defining-file path (normalized against `repo_root` at the
    `pangs-pir` boundary) and `linkage` on defined functions and globals, plus C
    type spelling / size metadata on globals (the O1b dependency, pulled forward
    into `meta` and `word_sized_scalar`); **plus `align_bits` on globals** — the
    *effective ABI alignment* from the data layout
    (`LLVMABIAlignmentOfType`-style), never LLVM's explicit alignment attribute
    alone, which is legitimately 0/unspecified; **plus target capture on the run
    header** — `run.analysis.target_triple`, the verbatim `data_layout` string, and
    `supported_atomic_widths` derived at lowering by the conservative rule
    `{8, 16, 32} ∪ {64 iff pointer width ≥ 64 bits}` (undercounting widths can only
    turn `word_sized_scalar` false — the sound direction; per-target refinement is
    an additive follow-up); **plus an `is_definition` bit on globals**,
    which does not exist today — `collect_globals`
    (`crates/pangs-pir/src/llvm_sys.rs`) lowers every module global with no
    declaration/definition split (functions get an `LLVMIsDeclaration` check;
    globals never did), so PIR `Global` and `GlobalInfo` gain the bit from
    `LLVMIsDeclaration(global) == 0`. The §3 population rule ("every *defined*
    mutable global") keys off it; without it, external declarations would leak into
    `globals[]`. **No mass key rename**: existing export streams keep their raw
    LLVM identifiers (§1.1) — the qualified key is derived at fact assembly, so
    D1b-pre is additive metadata columns and the golden-file churn is additive too,
    not a whole-stream rewrite. External declarations receive
    `is_definition: false`, `file: null`, and are otherwise unaffected throughout. The type-spelling source is **LLVM DI metadata**
    (`DIGlobalVariable` → `DIType` chain), which O1's `-O0`/debug-info requirement
    already guarantees — LLVM types alone cannot supply typedef names, struct tags,
    or signedness, and `word_sized_scalar` needs signedness to pick `AtomicI32` vs
    `AtomicU32`. Missing DI ⇒ `null` spelling ⇒ `word_sized_scalar` is false, per
    O1b's explicit-null-never-guess posture.
  - **D1b proper:** the three new F scans and the assembly pass, as above; **plus
    the provenance plumbing the §1.9 witnesses require**, which the current API does
    not retain (confirmed in-scope here; additive throughout, and recording *why* a
    bit was set changes no solver semantics — ground rule 1 holds):
    - `omega_escaped_address: true` needs an escape-site witness, but the solver
      exports only a class-level `escape_external` bit (`GlobalResolution`) and
      `GlobalInfo` only an `EscapeStatus` — solver postprocessing records, per
      escaped manifest global, one external-boundary event from which the escape is
      derivable, picked as the lexicographically smallest witness key (§1.9's
      determinism tiebreak).
    - `violation_taint` needs each finding's containing function, which every
      emission site already knows (it feeds `audit_taints`) but `Finding` does not
      store — `Finding` gains a `function` field (serde-default, additive).
    - escape-based `written: true` (§1.9's `external-escape` witness) reuses the
      same recorded boundary event as the Ω escape witness.

  Revised estimate: ~200 lines assembly + ~250 lines lowering plumbing + ~150 lines
  provenance plumbing (API fields + solver postprocessing).
- **D1c — cascade evaluator (in `pangs-dispose`, ~150 lines).** Pure function:
  `fn cascade(&Facts, &CascadeConfig) -> (Strategy, Vec<CascadeSkip>)` — producing
  `cascade_chosen` and its trace, nothing else; the final `chosen` is layered on
  afterwards by override application (D2), group resolution (D2b), and, downstream,
  demotion — none of which touch this function's output. Guards
  exactly as `DISPOSITION.md` §1 (including the implicit `¬violation_taint` conjunct
  on every guard) and are evaluated independently — support for one strategy never
  implies support for another; config = `CascadeConfig` per §1.6; `unhandled` is
  always the implicit last entry and cannot be configured away. Every skip records
  `{strategy, reason}` with the §1.5 `SkipReason` shape (every failing conjunct, or
  `fact-not-computed`).

**Acceptance:** golden manifest for a hand-built fact fixture; property test over a
generated grid of fact vectors (all boolean combinations × certificate
present/absent/null) asserting (a) `cascade_chosen`'s guard holds, (b) every
*configured* strategy earlier than `cascade_chosen` has a recorded skip reason and no
other entries appear (§1.5 trace rule — the invariant binds `cascade_trace` to
`cascade_chosen`, never to the final `chosen`), (c) determinism.

### D2 — override machinery (~250 lines, in `pangs-dispose`)

TOML format per `DISPOSITION.md` §4.1 (serde + `toml`). Validation per §4.2, in this
order per override: key resolution (§1.1 grammar; unmatched ⇒ `unmatched-key`) →
**enablement check** (pinned strategy absent from the configured order ⇒
`rejected-strategy-disabled` regardless of `accept_risk`; `unhandled` is exempt —
always pinnable, always honored as a safe opt-out, including for group pins; a
*member* `unhandled` pin disagreeing with the resolved group disposition still falls
to the rule-3 group conflict below) →
group-conflict check (§4.2 rule 3) → **availability check** (certificate-requiring
strategies: slot `null` ⇒ `rejected-strategy-unavailable`; slot failed with no
attached `recipe` (§1.5) ⇒ `rejected-no-recipe`; both regardless of `accept_risk` —
accepted risk waives evidence, it cannot substitute for computation that never ran
nor conjure a rewrite plan the pass could not produce; group pins check the
group-level certificate `strategy_support.<strategy>` instead; whether a downstream
rewriter exists remains a consumer concern handled by demotion) → independent
fact-support check (is the pinned strategy's own guard satisfied?) → outcome
(`honored` / `honored-accepted-risk` / `rejected`). Group pins resolve before member pins using the
group-support intersection algorithm in `DISPOSITION.md` §6. A member pin that differs
from the resolved group disposition is rejected even with `accept_risk`; group pins
whose group guard fails use the ordinary accepted-risk rule. Both records appear in
the report. Accepted risks append to
`pangs-audit.json` (§1.4). Cascade-reorder blocks (`[cascade]`) are validated for
unknown strategy names and applied globally before any per-global evaluation.

**Acceptance:** the override matrix test — each §4.2 outcome × {global pin, group pin,
cascade cap, unmatched key, missing accept_risk, accept_risk present} — including the
strategy-unavailable rows (null slot pinned with and without `accept_risk`; both
reject), the recipe rows (failed slot *with* recipe + `accept_risk` ⇒ honored as
accepted-risk; failed slot *without* recipe ⇒ rejected `no-recipe` even with
`accept_risk`; group variant against `strategy_support`), the strategy-disabled rows
(omitted-from-order strategy pinned with and
without `accept_risk`; both reject; global and group variants), and the `unhandled`
pin rows (global pin honored, group pin honored, member pin conflicting with the
resolved group disposition rejected as a rule-3 group conflict) — plus exit-code
assertions (§1.3), plus idempotence: re-running `pangs-dispose` on its own output
with the same overrides is a byte-level no-op.

### D2b — shared coupling post-pass (~200 lines, phase F)

Evidence is divided by the strength of the semantic claim:

1. **Suspected co-write evidence:** two globals directly written by the same function.
   This is retained for measurement and D3, but is not a policy group.
2. **Hard ONCELOCK evidence** (for certified globals): publication-interval overlap ∧
   init-subtree intersection — read directly from the O1–O5 per-global certificates.
   Ownership, to be unambiguous: **D2b consumes O1–O5 output; O6 consumes D2b's
   group ids** (for reports and the manifest hand-off). O6 exports nothing that D2b
   needs.

Run separate union-find instances by strength. Emit hard components as
`coupling_groups` with `grp-` IDs; only these populate `facts.coupling_group` and
constrain policy. Emit suspected components as `coupling_candidates` with disjoint
`cand-` IDs. Co-writes from one function use a star rooted at the smallest member;
both evidence classes retain only successful union edges. Evidence records carry an
explicit `strength`, and manifest validation rejects suspected evidence in a hard
group or hard evidence in a candidate component. This preserves identical
connectivity without a quadratic manifest while preventing weak correlation from
becoming a hard semantic blocker.

**Group strategy-support derivation (analysis-owned; closes the common-P gap).** D2b
also computes, per group, the group-specific certificates `DISPOSITION.md` §6 step 1
consumes, stored as `coupling_groups[].strategy_support`:

- `strategy_support.once_lock` — the **common-P certificate**, derived purely from
  the members' `phase_stationarity` certificates: every member certified ∧ same
  `publication.publication_function` after identical spine descent ∧ nonempty
  intersection of the members' publication intervals ∧ at least one insertable
  boundary inside the intersection. Present as the intersected interval + chosen
  common P; absent with a witness naming the first failing condition otherwise.
- `strategy_support.mutex` — reserved slot, `null` until D4 emits the group
  reentrancy certificate.

No new analysis: interval intersection over per-member certificates is a scan, per
`DISPOSITION.md` §2's rule of construction. This fixes the pipeline **run order** as
O1–O5 (per-global certificates) → D2b (clustering + support derivation) → fact
assembly (attaches `coupling_group` ids and emits `coupling_groups`) →
`pangs-dispose`; work-item *landing* order in §4 is unchanged.

Policy resolution is separate from clustering: compute each member's independent
support set, intersect those sets, apply the group-specific guards from
`DISPOSITION.md` §6, then select the first supported configured strategy (or validate
the group override). Never compare enum ordinals or infer support from an earlier
certificate. Joint `once-lock`/`mutex` materialization failure demotes the whole group;
`immutable`/`localize` materialization failure may demote only the affected member.

**Acceptance:** unit fixtures (the `cmd_table`+`cmd_count` pair; two unrelated globals
written by one utility function — expected to over-group in v1, test
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
of the marker artifacts from a manifest (`pangs-dispose --emit-markers <dir>`), **two
outputs** per `DISPOSITION.md` §5.2's linkage contract: `pangs_markers.h` with plain
declarations only (include-anywhere safe) and `pangs_markers.c` with the empty
definitions (compiled and linked exactly once); (c) the round-trip harness (§5).

**Acceptance:** the round-trip test — toy program + manifest → mock C→C materializer
plants markers → real translator → fixture rewriter matches every inventory entry,
deletes all `pangs_*` symbols, output greps clean.

### D3 — atomic eligibility (gated; build iff the §7 counter is material)

Specified now so the gate counter measures the right thing; sized when scheduled.
Certificate requires **all** of: `word_sized_scalar`; `access_set_complete`; every
access site classifiable as load, store, or a recognized RMW shape (`g++`, `g += k`,
`g = g op k` — classified on IR, emitted per-site so the rewriter knows
`load(Relaxed)` vs `fetch_add`); no address-taken use incompatible with retyping
(`&g` never flows beyond directly-lowered access — reuse the pts scan); no hard
multi-member coupling group; and a structured resolution for every incident suspected
coupling edge. Same-function co-write alone is not a veto: D3 must either establish
independence from the access/dependency structure or fail with an unresolved-coupling
witness. Ships **with** its co-update dynamic audit (instrument
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
the `once-lock` slot; D2b can land any time after D1b (its ONCELOCK evidence input
and `strategy_support.once_lock` derivation simply stay empty/`null` until O1–O5
exist — note the within-run pipeline order is O1–O5 → D2b → fact assembly →
`pangs-dispose`, which is independent of this landing order). D5 waits for D0 and for
the C→C tool to be ready to consume dispositions — until then the round-trip
harness's mock materializer (§5) stands in. This ordering means **the disposition layer is never
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

### M3 measurements (partial)

Vim 9.2 (`b4ddc6c11e95`, Clang/LLVM 14, `-g -O1`, application mode) was measured
on 2026-07-16. The run produced 3,204 keyed mutable globals and no unkeyed globals;
1,340 disposed `immutable` and 1,864 `unhandled`. The free gate funnels were:

| gate | candidate disposition | shape/safety input | access complete | eligible |
|---|---:|---:|---:|---:|
| atomic | 1,864 | 1,035 word-sized scalars; 0 singleton-group survivors | 0 | 0 |
| mutex | 1,864 | 0 signal-context-safe survivors | 0 | 0 |

All 3,204 access sets failed on `omega-access-path`, so Vim alone provides no case
for scheduling D3 or D4. The decision remains open until the required PHP measurement
is available. Corpus-scale validation also recorded 68 coupling groups (1,181 grouped
globals) represented by 1,113 proof-forest edges; the optimized disposition portion
completed in about 89 seconds (13.1 seconds fact indexing, 75.1 seconds phase facts,
13 milliseconds coupling) within the analysis run's 23.2 GB peak RSS.

## 8. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Marker calls don't survive the translator (whole §5 contract collapses) | D0 spike first; documented fallback = C→C-emitted source map; decision recorded here |
| Translator and production Rust rewriter not available to this repo (D0 cannot run; D5's final validation can't use the real rewriter) | blocked pending commands/repositories/flags from the project owner (record here when known); the §5 fixture rewriter stands in for D5 testing; D5 is the only dependent item; everything else proceeds |
| Key instability across runs (path spelling, harness rename scheme drifting) breaks overrides | grammar + normalization fixed in §1.1, owned by lowering; uniqueness asserted at fact assembly; parse/format property tests; `unmatched-key` is loud by design |
| Schema churn while O6 and the C→C tool are being written against it | D1a lands first and freezes v2 via golden tests; additive-only rule; unknown-field preservation protects mixed-version tooling |
| Coupling heuristic too permissive/strict | advisory for all consumers except D3, which re-derives; threshold is config; over-grouping documented in tests as intended v1 behavior |
| Policy/facts separation erodes under deadline pressure (facts computed inside the cascade "just this once") | ground rule 2 is PR-reviewable: `pangs-dispose` has no dependency on the analysis crates — enforce with a workspace dependency lint |
| Two consumers reimplement contract pieces and drift | single `pangs-manifest` crate (§2); contract harnesses in CI (§5) |

*(D0 findings to be recorded here when the spike runs.)*
