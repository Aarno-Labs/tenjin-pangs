# Simplifying `20260805_SIG_ATOMIC_T_HANDLING.md`

*Review note. The subject document is correct and unusually careful; this note argues
that roughly half of it is defending positions that the other half already holds. Each
cut below states what it removes, what it costs, and — where the cut changes a safety
argument rather than only an implementation — the argument that licenses it.*

## 0. What the core actually is

Strip the note to its load-bearing claim and it is four sentences:

1. An aligned integer global is a word-sized scalar whether or not debug metadata
   preserved its source spelling.
2. A `volatile` access may be lowered to a `Relaxed` atomic when the object is a
   `sig_atomic_t` flag, all of whose accesses are direct whole-object loads/stores, on
   a target where that width's load/store is lock-free.
3. "Is a signal flag" means a *resolved* signal registration has an exhibitable
   direct-call path to a `Via::Direct` access — a positive path, never a widened one.
4. `Relaxed` loses `volatile`'s access-count and relative-order guarantees; that is
   harmless only if no observer can correlate the flag with anything else, which is
   what handler-observer confinement establishes.

Everything else in the document is either mechanism for those four, or defense against
misconfiguration. The seven cuts below leave all four intact.

## S1. Delete `RegistryShape` and the three-valued resolution machinery (§D.1–D.6)

**Remove:** `RegistryShape`, `ParamShape`, the ABI-class/value-kind split table and its
asymmetric failure polarities, the config-load entry-consistency check, `UnresolvedReason`
as a set, `--strict-registry`, the `registry-shape-mismatch` audit kind, and the ~10 tests
serving them. **Keep:** the exact-name entry for `__sysv_signal`, the `external_only`
declaration precondition, and today's `RegistryEntryResolution.unresolved: bool`
(`pangs-api/src/lib.rs:434`, already `external || !targeted`).

**Why it does not cost soundness.** Shape checking's stated job is to stop a name
collision from being read as libc's `signal`. But:

- `AbiClass` cannot separate a pointer from an integer (§D.1 says so), so the check's
  real discriminating power is arity + `vararg` + `cc` — and arity is only doing work
  against a program that declares its own external three-argument `signal`.
- A false positive is conservative in every *restricting* consumer, which §D.5's own
  table establishes: `phase_stationarity` keeps its widening, `mutex` loses eligibility,
  `atomic` tightens its lock-free gate.
- A false positive is *not* conservative for the permitting conjunct — but the permitting
  conjunct does not read the registration. It reads the certified positive path: the
  operand's precise pointees must contain a function with a direct-call chain to a
  `Via::Direct` access on this flag. For a spurious `signal` to admit a volatile access,
  its argument 1 would have to point at a function that directly writes the candidate
  flag. That is not a misconfiguration, it is a signal handler.

So the shape check defends the permitting direction against a case the path requirement
already excludes, and defends the restricting direction in the direction that is already
safe. Once it goes, §D.5's three-valued outcome collapses back onto the two-valued
resolution the code already computes, and §D.6's diagnostic taxonomy has nothing to
report.

**Cost:** a program with an unrelated external `signal`/`sigaction` symbol loses `mutex`
eligibility on whatever its argument points to. Precision, one strategy, pathological
input. **Recovered by:** nothing needed; if it is ever observed, an arity check on the
entry operand's index is five lines and needs no type.

**Retain from §D:** rule 11 (recognizing an alias never relaxes the Ω boundary) and the
D.5 asymmetry as *prose* — dropping a registration is unsafe for restricting consumers,
so a registration the tool cannot fully resolve stays a registration. That is one
sentence, and it is already how the code behaves.

## S2. Delete F1 — it is subsumed by F2

This is the largest structural cut and the only one that changes a safety argument.

**Remove:** the sole-candidate condition, `signal_flag_pattern.sole_candidate`, the
`signal-flag-not-sole` code, the requirement that F1 "run *after* all per-global
evaluation, as a whole-program pass", and the validator's whole-program "at most one
global carries `signal_flag_pattern`" check (the one clause that forces per-global
validation to know about every other global).

**The argument.** The hazard F1 names is: `Relaxed` does not preserve relative order
between two objects, and the note's example is a handler writing `flag_a = 1; flag_b = 1;`
observed in the other order by the main loop. Ask who can observe such a reordering.

- The interrupted thread's own code cannot: it is the thread doing the writes.
- Another thread cannot observe anything `volatile` protected — the note establishes this
  itself: `volatile` never ordered a volatile access against a non-volatile one and
  emitted no fences, so anything a second thread could see was already unordered.
- The only remaining asynchronous observer is a signal handler.

A handler that reads or writes the flag is, by definition, in `A ∩ H`. F2 requires every
member of `A ∩ H` to access **no static- or thread-storage object other than the flag**.
So a handler that could correlate the flag with a second object — another flag, a data
buffer, a sequence counter — fails F2 and the flag does not certify. The note's own
example fails F2 on both flags, with no appeal to F1.

The converse cases are all vacuous:

- *Main writes both flags, one handler reads one.* The handler cannot compare, because it
  reads only its own flag; comparing would require touching the second, which F2 forbids.
- *Two flags, disjoint confined handlers.* Neither handler can see the other's object.
  Between the two handler invocations there is no program-order relation to preserve —
  the two deliveries are independent events whose interleaving was already unconstrained.
- *Flag plus an ordinary object published by the main loop.* Same as the first case: the
  observer that would notice the reordering must read both, and F2 rejects it.

F2 therefore closes (ii) on its own, and F1 restates a special case of it at
whole-program granularity.

**Cost:** none identified. **Gain beyond simplicity:** coverage. A module with two
independently confined flags certifies both, where F1 rejects both and, per §E, "does not
pick a winner". D7's falsifier — "a second corpus module with two flags is a reason to
revisit F1" — is answered before it is observed.

**If a second reader is unconvinced:** keeping F1 costs one counter and one validator
clause, so retaining it as belt-and-braces is cheap. What should *not* survive either way
is F1's framing as a load-bearing pattern condition co-equal with F2, because that framing
is what forces the whole-program pass and the cross-global validator clause. Demote it to
a diagnostic if it is kept.

## S3. Delete the `--target-profile` configuration surface (§E)

**Remove:** `--target-profile` entirely, and with it: narrowing, evidence bundles,
fixture-hash and toolchain-envelope validation of bundles, the `target-profile-narrowed`
ledger record, `signal_lock_free.source`, `target_profile.source` /`narrowed_from` /
`evidence_bundle`, the provenance-agreement clauses in §4's value coupling (the most
intricate clauses in the freeze), and ~6 tests.

**Keep:** the arch-keyed table with exactly one row (`x86_64 → [8,16,32,64]`), absent →
empty → fail closed; `lock_free_load_store_widths` as a distinct list from
`supported_atomic_widths` (D2 is right and cheap); `run.analysis.target_profile` as a
reproducibility record of *which row was used*.

**Why.** The mechanism exists so an operator can add an arch without a code change, while
being prevented from *asserting* lock-freedom. But the note also requires that a row is
admissible only if the in-tree codegen regression covers it — and a bundle's honesty is
enforced by comparing it against that same in-tree fixture. So the config path's happy
case is "operator re-runs the in-tree regression and pastes its output", which is
observationally the same act as adding a row in a patch, minus review, plus a validator
that the note concedes "a determined operator can fabricate". Deleting the path makes the
rule structural: **the only way to add a row is to add it next to its regression.** For a
gate whose failure mode is silent handler deadlock, that is the stronger position, and it
removes a config surface, a provenance enum, and a set of cross-field validator clauses
whose entire purpose is detecting laundering between two sources that no longer exist.

**Cost:** an operator on an unlisted arch must patch the table rather than pass a flag.
The corpus is 100% `x86_64`; the note itself ships one row for this reason.

## S4. Move `resolved_signal_context_access` into the certificate

**Remove:** the new `Facts` slot, its `#[serde(default)]` / "required at v5 but not
parse-required" analysis, the `resolved ⇒ signal_context_access` validator invariant, the
v4→v5 two-part fact-delta discussion, and golden class A (a diff on **every global in
every manifest** for a fact nothing reads until Phase 3).

**Keep:** the value, the witness, and — critically — the query that computes it. It moves
into `signal_flag_pattern.observers[]`, which already carries `{ function, via }` per
observer and only needs the path and registration site added.

**Why.** §C makes exactly this decision for `signal_atomic_type`, with exactly this
reasoning: one consumer, so carry it in the certificate and hold v5's fact-layer surface
to the `word_sized_scalar` change alone; promote when a second consumer appears (D1). The
note then applies the opposite rule one section later, citing `DISPOSITION.md` §1's
guard-shape rule — but that rule says the *reverse* for certificate-backed strategies:
"a strategy backed by an eligibility pass has a certificate-only guard … the pass's
certificate internally requires its precondition facts". `atomic` is such a strategy; D3
is such a pass. The signal-path requirement is a D3 precondition, like the reentrancy
check inside D4, and the cascade never reads it.

Applying D1's own rule uniformly shrinks the v5 fact-layer delta to one field
(`word_sized_scalar`), which is the change §3's version-negotiation machinery was built
to manage.

**Cost, honestly:** (a) Phase 2's crispest acceptance signal was "the fact flips
false → true"; it becomes "the registration resolves and the certified path is found",
observable through the same query's test but not through a manifest diff. (b) A future
measurement funnel wanting the count pays a v6 promotion. Both are the price D1 already
accepted for `signal_atomic_type`.

**Not cut:** rule 17 / D8. The discipline — a permitting fact is computed by its own
positive-path query, never by filtering `registry_access_facts`, because `ModuleWide`
originates in the handler's transitive summary — is the sharpest observation in the note
and is unaffected by where the result is stored. Keep the rule, keep the code comment it
mandates, keep the `ModuleWide` fact-provenance test.

## S5. Stop duplicating the width, and shrink §4's value coupling

The certificate currently carries the width four times (`recipe.declaration.size_bits`,
`.align_bits`, `signal_atomic_type.width`, `.align`, `signal_lock_free.width`) and then
spends a validator clause per copy proving they agree. That is a validator defending
against the emitter contradicting itself.

**Emit it once.** `recipe.declaration` owns width, alignment, class, and signedness.
`signal_atomic_type` carries `{ typedef, typedef_chain, volatile }` — the type evidence
and nothing derivable. `signal_lock_free` carries `{ required, operations }` plus the
width if a reader genuinely wants a self-contained proof object (then it is the one
duplication, with the one clause).

**The surviving value coupling** is what is not derivable from a single source:

```text
target_guaranteed == true
declaration.size_bits ∈ target_profile.lock_free_load_store_widths
operations == ["load", "store"]
typedef ∈ typedef_chain  ∧  typedef ∈ RECOGNIZED_SIGNAL_TYPEDEFS
volatile == true  ∧  declaration.scalar_class == "integer"
declaration.linkage == "internal"        (M.8)
recipe.ordering == "relaxed"
signal_flag_pattern.handler_accesses_confined == true  ∧  observers non-empty
```

Eight clauses instead of roughly twenty-five, with the whole-program clause gone by S2 and
the provenance block gone by S3. **Keep unchanged:** the presence coupling
(`volatile_semantics` ⟺ `signal_atomic_type` ⟺ `signal_flag_pattern` ⟺
`signal_lock_free.required`), the `volatile_semantics ⇒ certified` clause, the
`P`-absent-is-invalid rule, and §4's structural consequence that a failed signal-flag
proof has `recipe: null` and is therefore unpinnable under `no-recipe`. That consequence
does more work than any validator clause and costs nothing.

## S6. Decide the alias clause instead of measuring it (§E)

**Remove:** the module-wide `alias_`-taint fallback, the corpus census that chooses
between it and the inventory, the two parallel test sets with one `#[ignore]`d, and the
Phase 3 gate on that census.

**Decide:** land `LoweringStats::alias_exposed_globals` and hoist
`constant_symbol_name(LLVMAliasGetAliasee(...))` above the interposability check in
`collect_alias_map` (`pangs-pir/src/llvm_sys.rs:3566`). The change is a few lines, and the
note's own analysis of the fallback — any external alias anywhere in the module, even to
an unrelated function, disables the feature module-wide — makes the outcome of the census
close to foregone. Rule 18 is satisfied by adding the fact, which is the honest fix it
asks for.

**Keep:** the two properties the note attaches to the inventory (resolution stays
separated from modelling, so nothing about points-to or Ω moves; an unresolvable aliasee
records nothing rather than everything) — and, since the second is now a real gap rather
than a fallback-covered one, one clause: an `alias_unresolved:` taint blocks signal-flag
mode for the module. That is the blunt rule applied to the narrow case that needs it.

## S7. One name for the type spelling (§A, §5)

`ScalarTypeEvidence.display_name` is diagnostic only — M.0/M.3 establish that no stage
consumes `recipe.declaration.type_spelling`. Define `type_spelling = typedef_chain[0]`
(falling back to the terminal type's name) and delete `display_name` as a separate
concept, along with §5's "the two MUST NOT be conflated" rule and the two tests pinning
their divergence. The certificate's `typedef` field remains what it is: the recognized
standard name, matched anywhere in the chain. **Keep** the rejection of a "first *public*
typedef" rule and the fail-closed-on-truncation property; both are one sentence each.

## What must not be cut

Listed so the next round of simplification does not reach for them:

- **D6** — volatile admission requires a *resolved* registration. It is what makes
  `sig_atomic_t`'s guarantee the operative reason the object is volatile.
- **F2** — now the sole pattern condition, and after S2 it carries the whole of (ii).
- **Rule 17 / D8** — the permitting fact comes from its own positive-path query.
- **M.8** — internal linkage only; and the alias back door it names (S6 closes it).
- **M.7 step 1** — the exhaustive reference inventory. The laundered-pointer case
  (`&G as *const _ as *const i32`) passes count, residue, and `rustc`, and silently reads
  the atomic non-atomically. Count is a cross-check; the inventory is the gate.
- **M.1** — the C→C stage never removes `volatile`.
- **The lock-free gate as a list distinct from `supported_atomic_widths`** (D2), and
  unknown target → not lock-free.
- **The no-elision residual**: the codegen regression and one ledger record stating that
  it is a quality-of-implementation property, not a guarantee.
- **The v5-lands-complete-and-dormant rule.** Two contracts calling themselves v5 is a
  worse outcome than any complexity saved by staging the freeze.

## Resulting shape

| Part | Before | After |
|---|---|---|
| §A type evidence | walker + `display_name` rule + divergence tests | walker, one name |
| §B `word_sized_scalar` | unchanged | unchanged (the one real fact-layer change) |
| §C `signal_atomic_type` | unchanged | unchanged, minus duplicated width/align |
| §D registry | shapes, 4-reason sets, strict flag, ledger kind, config validation | one entry, `external_only`, existing `unresolved` bool |
| §E admission | 9 conjuncts incl. F1; profile config; alias fork | 8 conjuncts; fixed table; alias inventory |
| §E fact | new `Facts` slot + version negotiation | certificate payload |
| Schema §4 | ~25 coupling clauses | presence coupling + 8 value clauses |
| Validation scope | per-global + whole-program | per-global only |

Implementation sequence keeps its four phases and its dependency structure — Phases 1 and
2 independent, 3 needing both — but Phase 1 stops carrying a producer for a fact nothing
reads, Phase 2 becomes a table entry plus a corpus regression, and Phase 3 loses the
census fork and the whole-program pass. My estimate is that the note itself drops from
~2800 lines to ~1200, and the implementation loses six subsystems: shape checking,
strict-registry, evidence bundles, profile narrowing, the fallback/inventory fork, and the
whole-program F1 pass.

## S8. Collapse the mode into one tagged `atomic_mode` (second round)

Applied after S1–S7, once it was established that **v5 need not preserve v4
payloads**. That premise is what turns extension into deletion.

**Remove:** `signal_lock_free` entirely; `recipe.volatile_semantics`;
`signal_atomic_type` and `signal_flag_pattern` as certificate siblings; the
four-way presence coupling; the `volatile_semantics present ⇒ certified` clause;
the `signal_lock_free.width` null carve-out; and all of §3's version negotiation
(the dual-invariant validator, the `schema_version` parameter on
`Facts::validate`, the reader/document matrix).

**Replace with** one internally-tagged object at certificate level:

```
atomic_mode
├── kind: "plain"        — no members
├── kind: "signal_safe"  — probe, operations
└── kind: "signal_flag"  — probe, operations, type_evidence, certified_path,
                           handler_accesses_confined, observers
```

**Why the three deleted members were not carrying information.**
`signal_lock_free.required` was a copy of `facts.signal_context_access`;
`target_guaranteed` is `true` in every certificate where it means anything, since
a false value means the global failed `signal-atomic-not-lock-free` and produced
no certificate at all; `width` was `recipe.declaration.size_bits`. The object also
emitted `{required: false, width: null}` on every ordinary atomic — an inhabited
state asserting nothing. `kind` carries the first, the variant's existence carries
the second, the declaration carries the third.

**The structural win.** The three states the design has were previously encoded as
*pairs* — (`signal_lock_free.required`, `volatile_semantics` present) — whose
fourth combination the presence coupling existed to forbid. One discriminant makes
that state unrepresentable rather than detected. And because `Certificate::Failed`
has no certificate-level payload, a certificate-level `atomic_mode` makes rule 18
("a signal-flag atomic exists only as a complete certified proof") a property of
the type rather than a rule to enforce. This is why the discriminant must *not*
live in `recipe`, which exists on the failed variant too.

**A latent hole this surfaced, and fixed.** Making `operations` a required member
of both signal variants exposed that D2's narrowing — switching the signal gate to
a load/store width list — would have certified a signal-context *RMW* recipe
against a proof of something weaker, because the gate fires for every
signal-context global and not only signal-flag ones. The repair is the **probe**:
`(arch, widths, operations)` plus the regression backing it, with the rule that
one probe covers every operation the recipe emits, and no combining of probes. v1
ships `x86_64.ldst.v1` and `x86_64.rmw.v1`, so nothing on the current corpus loses
coverage, and D2's "a later RMW extension cannot silently reuse a load/store-only
proof" stops being a comment and becomes a checkable clause.

**Two consequential follow-ons.** `run.analysis.target_profile` becomes
`target_probes`, a reproducibility record no validator reads — which deletes the
present/absent/invalid three-row rule. And the probe table moves to **Phase 1**,
because `signal_safe` is a required v5 variant with a required probe member, so
the table is part of the contract §1 requires Phase 1 to land whole; the
"out of `atomic`" corpus movement moves to Phase 1 with it, leaving Phase 3
one-directional.

**Net:** presence coupling 4 clauses → 0; value coupling ~25 → ~13, of which
exactly one reads outside the certificate; §3 deleted; one field where four
stood.

## Risk register

1. **S2 (F1) is the one cut that changes a safety argument.** The claim is that F2's
   confinement already excludes every observer that could witness a reordering. It should
   be read adversarially by someone other than its author; the cheap hedge is keeping F1
   as a diagnostic counter while removing its whole-program validator clause.
2. **S1 widens what counts as a signal registration.** The corpus regression the note
   already requires for Phase 2 covers it: expected movement is `mutex` losses and
   `once-lock` gains, and anything else is a defect to explain.
3. **S4 removes a manifest-visible Phase 2 signal.** Replace it with an assertion in the
   fact-provenance test rather than dropping the check.
4. **S3 makes an unlisted arch a patch rather than a flag.** Correct posture for this
   gate; worth stating in `Non-goals` so it is not re-litigated as an oversight.
5. **S8 moves the gate switch to Phase 1**, so the coverage correction it may cause
   lands with the schema change rather than with the signal-flag feature. The
   Phase-1 acceptance predicate now permits exactly one kind of outward movement
   (`Certified → Failed[signal-atomic-not-lock-free]`, signal-context globals
   only) and expects it to be empty on an all-`x86_64` corpus. A non-empty result
   is a finding to report, not a threshold to widen.
6. **S8 assumes no consumer needs to distinguish "no lock-free claim required"
   from "no mode recorded".** `kind: "plain"` states the first and the second is
   unrepresentable, which is the intent — but a future genuinely-optional variant
   would reopen it (D4b's falsifier).
