# Handling `volatile sig_atomic_t` Globals

## Status

Design proposal. Nothing here is implemented yet. Reviewed against the working
tree on 2026-08-05; the `file:line` anchors are navigation aids verified at that
revision, not a stable interface.

The load-bearing claim is §E's: that replacing `volatile` with a `Relaxed` atomic
preserves what the source relied on. It does **not** do so on its own —
`Relaxed` permits transformations `volatile` forbids — and the condition that
makes it sound is stated as an admission conjunct (F2), not as commentary.

Two asymmetries recur and are stated once here:

- **Permitting vs. restricting facts.** A fact that *restricts* (kills a
  strategy, tightens a gate) is conservative when widened; a fact that *permits*
  is conservative only when narrowed. A permitting conjunct may never be
  discharged by a restricting fact's widening query (rule 14).
- **An over-broad registry entry is conservative in every consumer; an
  over-broad lock-free width is the silent-deadlock gate.** They therefore get
  opposite treatment: the registry is an ordinary extensible name table (§D),
  while the lock-free width table has no configuration surface at all (§E).

The simplification rationale for this revision — which conditions were removed,
and the arguments licensing each removal — is recorded in
[20260806_SIG_ATOMIC_T_SIMPLIFICATION.md](20260806_SIG_ATOMIC_T_SIMPLIFICATION.md).
That note is the record of *why* the design is shaped this way; this note is the
design.

## Executive summary

In `exe-apg_bore-O0.bc`, the only unhandled actionable global is:

```c
static volatile sig_atomic_t g_interrupted_xjtr_0 = 0;
```

The pipeline rejects it for two independent reasons, and misses a related fact:

1. LLVM debug metadata describes the type as an unnamed outer `volatile` node
   around the named `sig_atomic_t` typedef. PANGS reads a spelling only from the
   outer node, records none, and therefore makes `word_sized_scalar` false even
   though it correctly recovers a signed, aligned 32-bit integer.
2. Even with that fixed, atomic access recipe construction rejects every LLVM
   volatile load and store categorically.
3. Clang lowers the source call `signal(2, handler)` to a direct call to
   `__sysv_signal`, which the default registry does not recognize, so PANGS
   reports `signal_context_access: false` and treats registration as an
   unresolved external effect elsewhere in the analysis.

The correction has four parts:

1. Preserve structured qualified-type evidence — typedef names and qualifiers —
   rather than only the outer DWARF type name (§A).
2. Stop making source type spelling a prerequisite for the semantic
   `word_sized_scalar` fact; materializability is a separate question (§B).
3. Keep rejecting arbitrary volatile accesses, but admit a narrowly certified
   `volatile sig_atomic_t` access mode when every access lowers to
   target-guaranteed lock-free atomics (§C, §E).
4. Recognize `__sysv_signal` as a signal registration, so the async-signal
   context and lock-free guard are real inputs to the certificate (§D).

The expected disposition for this global is then `atomic`, not `unhandled`: on
the observed APG bore module, coverage 25/26 → 26/26 and the atomic count 1 → 2,
assuming the detailed access recipe passes unchanged.

Three of the four parts are **not** local to this global:

- Part 2 changes the meaning of a published fact — `word_sized_scalar` has a
  schema invariant, a cascade-adjacent role, and a measurement funnel
  (`DISPOSITION.md` §10.2) — so it is a schema change.
- Part 4 changes module-wide facts: a newly recognized registration stops being
  an unresolved external effect for *every* global's phase analysis, so other
  globals' `phase_stationarity` results may move in the same run.
- Part 3 is the only genuinely narrow part, and the one that must fail closed.

The single-global coverage claim is therefore a consequence to verify, not the
acceptance criterion; the criterion is the whole corpus disposition distribution
(§"Tests and acceptance criteria").

## Observed case

The declaration is in
`/home/brk/xj-res/apg__bore/c_13_run_cclzyerpp_analysis/src/search.nolines.i`:

```c
static volatile sig_atomic_t g_interrupted_xjtr_0 = 0;

static void sigint_handler_xjtr_0(int sig)
{
    (void)sig;
    g_interrupted_xjtr_0 = 1;
}
```

Ordinary code resets the flag during initialization and polls it while searching.
All emitted LLVM accesses are volatile 32-bit loads or stores, and the bitcode
retains the relevant storage facts:

```llvm
@g_interrupted_xjtr_0 = internal global i32 0, align 4, !dbg !206

!207 = distinct !DIGlobalVariable(name: "g_interrupted_xjtr_0", type: !208, ...)
!208 = !DIDerivedType(tag: DW_TAG_volatile_type, baseType: !209)
!209 = !DIDerivedType(tag: DW_TAG_typedef, name: "sig_atomic_t",   baseType: !210)
!210 = !DIDerivedType(tag: DW_TAG_typedef, name: "__sig_atomic_t", baseType: !24)
!24  = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
```

PIR lowering nevertheless produces `"type_spelling": null` alongside correct
`size_bits: 32`, `align_bits: 32`, `scalar_class: "integer"`, `signed: true`,
`initializer_ir: "i32 0"`, and the manifest reports:

```json
"word_sized_scalar": { "value": false },
"atomic_eligibility": { "status": "failed", "codes": ["word-sized-scalar"] }
```

The declaration is therefore rejected before detailed access lowering runs.

## What `sig_atomic_t` does and does not prove

The C signal API gives `sig_atomic_t` a specific role: an object of that integer
type can be accessed as an atomic entity in the presence of an asynchronous
signal, and declaring it volatile is the conventional portable signal-flag idiom
because execution can change it outside the ordinary control flow the compiler
sees.

This does **not** make `sig_atomic_t` equivalent to a C11 `_Atomic` object: it
provides no inter-thread synchronization protocol, implies no acquire/release
ordering for other memory, makes no compound operation atomic, does not justify
accepting every volatile object, and does not prove that an arbitrary
target/library representation can be replaced with a non-lock-free atomic
implementation inside a signal handler. Hence a dedicated signal-flag
certificate, not a rule treating either `volatile` or all typedef-sized integers
as atomic.

## Current rejection path

**1. The outer qualifier hides the type spelling.** `di_type_details`
(`crates/pangs-pir/src/llvm_sys.rs:532`) calls `di_type_name(metadata)` only on
the top-level node, and a `DW_TAG_volatile_type` node has no name, so
`type_spelling` becomes `None`. The scalar classifier `di_type_class`
(`llvm_sys.rs:545`) instead follows operand 3 recursively to the signed `int`
basic type — hence no spelling alongside correct integer/signedness facts. Any
qualified typedef can lose its spelling this way.

**2. `word_sized_scalar` mixes semantics and materialization.** It
(`crates/pangs-clients/src/lib.rs:2322`) currently requires:

```text
type spelling exists
width is nonzero and in target.supported_atomic_widths
align_bits == size_bits          (equality, not sufficiency)
scalar class exists
integer/enum signedness is known
```

Only the last four establish the machine-level scalar property; the spelling
serves a source rewrite recipe, and its absence does not make an aligned `i32`
non-scalar. The false fact also drops the known width, class, and signedness from
the manifest, because `Facts::validate`
(`crates/pangs-manifest/src/lib.rs:430`) *requires* detail presence to match the
boolean exactly — so retaining partial evidence is a schema change, not a
field-population change.

**3. Detailed atomic lowering rejects all volatile sites.**
`atomic_access_recipe` (`crates/pangs-clients/src/lib.rs:1879`) rejects a site
whenever `site.volatile` is true, with `volatile-access: "volatile C access
cannot be replaced by an ordinary Rust atomic"`. Correct for unknown volatile
storage — memory-mapped I/O, externally observed memory, other access contracts
ordinary atomics do not preserve — but too broad for a proven standard signal
flag.

**4. Signal registration is present under a different symbol.** The lowered call
is `@__sysv_signal(i32 2, void (i32)* @sigint_handler_xjtr_0)`, and the built-in
list in `effective_registry_apis` (`crates/pangs-api/src/lib.rs:4177`) contains
`pthread_create`, `thrd_create`, `signal`, and `sigaction` only. So the handler
is not classified through the signal registry; `g_interrupted` incorrectly has
`signal_context_access: false`; the atomic certificate does not demand its signal
lock-free gate; mutex eligibility is not rejected for the most direct reason; and
phase analysis retains an unresolved external effect at registration
(`crates/pangs-clients/src/phase_stationarity.rs:716,757,772` — only a *modeled*
registry callsite escapes the `has_unknown` widening). Accepting the atomic
strategy without repairing this would produce the desired answer without proving
the signal context that makes the answer safety-sensitive.

Two properties of this registry constrain the repair:

- **It is not the Ω external-summary registry.** It is the spawn/signal fact
  registry consumed by the F-layer disposition scans and by
  `registry_target_labels`. Recognizing `__sysv_signal` does not relax the Ω
  boundary at that call: the call remains an external effect for points-to,
  mod/ref, and escape. Only the spawn/signal fact and the phase-analysis
  unresolved-effect widening change.
- **It is name-keyed, and its error directions are not symmetric.** A false
  positive is conservative in every consumer — a spurious `signal_context_access`
  kills `mutex` and tightens `atomic`'s lock-free gate. A false *negative* is not
  conservative at all for those same two consumers, which is why a registration
  the analysis cannot fully resolve stays a registration (§D).

The registry is already extensible without code changes via `pangs
--registry-config` (`crates/pangs-cli/src/main.rs:53,726`), which merges or
replaces entries by name. Phase 2 validates through that flag on the bore module
before the entry is hardcoded, so the fact-level consequences are observed
independently.

## Proposed design

### A. Preserve structured source-type evidence

Replace the one-name view of a debug type with a bounded walk that records the
derived-type chain:

```rust
struct ScalarTypeEvidence {
    type_spelling: Option<String>,
    typedef_chain: Vec<String>,
    qualifiers: TypeQualifiers,          // is_const, is_volatile, is_restrict, is_atomic
    class: Option<ScalarTypeClass>,
    signed: Option<bool>,
}
```

The walk starts at the `DIGlobalVariable` type, records qualifier tags rather
than discarding them, records every named typedef in outer-to-inner order, stops
at the existing recursion bound, derives class and signedness from the terminal
scalar type, and fails closed on malformed metadata or cycles. For the bore flag:
`type_spelling: "sig_atomic_t"`, `typedef_chain: ["sig_atomic_t",
"__sig_atomic_t"]`, `qualifiers.is_volatile: true`, `class: integer`,
`signed: true`.

`type_spelling` is defined **positionally**, with no notion of a "public" name:

```text
type_spelling =
  typedef_chain[0]                     if the chain is non-empty
  else the terminal scalar type's own name, if it has one
  else None                            (anonymous enum, nameless base type)
```

The outermost typedef is the name the declaration site used: under
`typedef sig_atomic_t my_flag_t;` it is `my_flag_t`, and `__sig_atomic_t` shows
only if the programmer wrote it. A "first *public* typedef" rule is rejected
because operationalizing it requires guessing at naming convention (no leading
double underscore, no underscore-plus-capital), which misfires on legitimate
project typedefs and makes the spelling depend on identifier style.

This is the same `type_spelling` the PIR and API globals already carry; the walk
populates it in cases that previously yielded `None`, and adds the chain and
qualifiers beside it. There is no second name concept. The certificate's
`typedef` field (§C) is a different thing — the *recognized standard* name,
matched anywhere in the chain — and §"Schema v5" §5 states the distinction.

Three properties keep consumers from over-reading this shape:

- A truncated or cyclic walk yields **no evidence at all**; there is no
  partially-populated form. Evidence comes only from positive debug metadata.
- `TypeQualifiers` is **accumulated over the whole chain**, so `is_volatile`
  means "volatile appears somewhere between the variable and the terminal scalar
  type" — the conservative reading for admission (§C/§E), and deliberately
  insufficient to reconstruct a declaration.
- The evidence is **not a rewrite recipe**: nothing here licenses reassembling a
  declaration by string concatenation.

`is_atomic` is an immediate rejection — a C11 `_Atomic` global lowers to atomic
IR operations, not volatile ones, and is a different case with a different
recipe. `is_const` on a mutable global definition is contradictory evidence and
likewise fails closed.

### B. Separate scalar eligibility from source materializability

Redefine `word_sized_scalar.value` to mean only:

```text
known scalar class
known required signedness
nonzero supported width
align_bits == size_bits          (unchanged from today)
```

Do not require `type_spelling`. Preserve the observed `size_bits`, `class`, and
`signed` even when the boolean is false, and record the decisive failure in a new
`codes` array (closed vocabulary and emission order frozen in §"Schema v5" §2).

**Keep the alignment condition as strict equality.** Relaxing it to "ABI
alignment sufficient for the width" newly admits over-aligned globals
(`__attribute__((aligned(64))) int`), whose declarations a materializer must then
preserve or justify dropping; that widening moves the eligibility population in a
way this note's corpus assertions cannot attribute, and belongs in its own change.

Rewritability stays in `source_materialization`
(`crates/pangs-clients/src/lib.rs:1310`), which keys on `meta.file`/`meta.line`
and returns `blocked` with `declaration-source-unmapped` when absent. Unchanged.

A missing **type spelling** does not block: per M.0/M.3 no stage consumes
`recipe.declaration.type_spelling`. Record its absence as a certificate
diagnostic instead:

```json
{ "type_evidence": { "spelling_recovered": false,
                     "detail": "qualified debug type carries no outer name" } }
```

A spelling-free scalar passing every other gate is therefore certified *and*
materializable — a real coverage gain Phase 1's acceptance criterion expects. The
`sig_atomic_t` path still requires positive typedef evidence; it must not infer
signal safety from an aligned integer.

Two consumers move with the redefinition: `Facts::validate`'s detail/value
invariant (`pangs-manifest/src/lib.rs:430`) and `SCHEMA_VERSION`
(`pangs-manifest/src/lib.rs:12`, → **5**); and the `not_word_sized` counter
(`pangs-clients/src/lib.rs:452`) plus the would-be-eligibility funnel of
`DISPOSITION.md` §10.2, whose historical values in
`notes/disposition_atomic_perglobal_remeasurement_2026-07-17.md` and siblings
stop being comparable — the re-measurement note must say so rather than silently
re-baselining.

### C. Add a signal-atomic type fact

Signal-atomic `type_evidence` is a **type fact**, derived from debug type
metadata alone; target
capability and program context are admission conditions (§E), and mixing them
reproduces the fact/policy conflation §B corrects. Derive it only when:

```text
typedef chain contains the implementation's standard sig_atomic_t typedef
qualifier chain includes volatile
qualifier chain includes neither _Atomic nor const
scalar class is integer
width and alignment are known and mutually consistent
```

Payload (normative placement in §"Schema v5" §4). It is the `type_evidence`
member of the certificate's `atomic_mode` object; width and alignment are **not**
repeated here — they live once, in `recipe.declaration`:

```json
{ "typedef": "sig_atomic_t",
  "typedef_chain": ["sig_atomic_t", "__sig_atomic_t"],
  "volatile": true }
```

Recognition allows platform-internal typedefs beneath the public `sig_atomic_t`,
but the public name must be present unless a frontend supplies an equivalent
explicit semantic tag. Do not maintain an open-ended heuristic list of names
resembling `sig_atomic_t`.

**What recognition is and is not.** This is a string match against a typedef
chain, so a user's own `typedef int sig_atomic_t;` passes it. **Safety does not
depend on the typedef being authentic**: what makes the rewrite correct is the
enumerated §E conjuncts — integer scalar of a lock-free width, whole-object
direct loads and stores only, complete access set, proven signal participation,
handler-observer confinement, internal linkage, ordinary storage. A shadowing
typedef satisfying all of those describes an object the transformation handles
correctly. The typedef match is an **intent signal**, not a proof obligation.

Provenance narrows accidental recognition and is cheap (`DW_TAG_typedef` nodes
carry a file; `RepoRoots::relative_source` distinguishes repo-local from external
paths). Reject only on positive contrary evidence:

```text
typedef declared outside the analyzed repository  -> accepted (system header)
typedef file unknown or unrecorded                -> accepted (no contrary evidence)
typedef positively declared inside the repository -> rejected, code
                                                     signal-typedef-shadowed
```

The fact is carried **inside the certificate's `atomic_mode` object**, its only
consumer, which holds the schema-v5 fact-layer surface to the
`word_sized_scalar` change alone. Promotion to a fact slot when a second consumer
appears is schema v6 (D1).

### D. Recognize `__sysv_signal` as a signal registration

Add one exact-name entry to the built-in table, with the same entry operand as
`signal` (handler in argument 1):

```jsonc
{ "name": "signal",        "kind": "signal", "entry": { "arg": 1 } }
{ "name": "__sysv_signal", "kind": "signal", "entry": { "arg": 1 } }
{ "name": "sigaction",     "kind": "signal", "entry": { "pointee_of_arg": 1 } }
```

Candidates such as `bsd_signal` are added the same way, each with a regression
fixture. `RegistryApi`, `RegistryEntryResolution`, and `resolve_registry_entries`
are otherwise unchanged.

**A declaration precondition, not a signature check.** The entry applies only when
the callee is an **external declaration**. A *defined internal* function named
`signal` is not libc's, and the analysis already models its body; if that function
forwards to libc, the inner call is itself a name match against an external
declaration. This precondition is silent — nothing is unverified, so a diagnostic
would be noise.

**No signature shape checking.** An earlier revision proposed a `RegistryShape`
type checked against `Callsite.sig` and `Node.value_kind`. It is not worth its
surface:

- `AbiClass` cannot distinguish a pointer from an integer — both `int` and
  `void (*)(int)` are `AbiClass::Integer` (`pangs-pir/src/lib.rs:640`), and under
  opaque pointers no LLVM type inspection recovers the difference. The check's
  real discriminating power is arity, `vararg`, and `cc`.
- Its stated job is to stop a name collision from being read as libc's `signal`.
  But a false positive is conservative in **every** consumer that reads
  `signal_context_access`: phase analysis keeps its widening, `mutex` loses
  eligibility, `atomic` tightens its lock-free gate.
- The one consumer for which a false positive would *not* be conservative — §E's
  volatile admission — does not read the registration at all. It reads the
  certified positive access path (§E): the operand's *precise* pointees must
  contain a function with a direct-call chain to a `Via::Direct` access on this
  flag. For a spurious `signal` to admit a volatile access, its argument 1 would
  have to point at a function that directly writes the candidate flag. That is
  not a misconfiguration; that is a signal handler.

Should a collision ever be observed, the minimal repair is an arity check on the
entry operand's index, which needs no type representation.

**Resolution stays two-valued, and a mismatch is never a deletion.** Dropping a
signal registration is not uniformly conservative:

| Consumer | Effect of dropping the registration | Direction |
|---|---|---|
| `phase_stationarity` | keeps the `has_unknown` widening | safe |
| `mutex_eligibility` | loses the `signal-context-access` rejection | **unsafe** |
| `atomic_eligibility` | skips the signal lock-free gate | **unsafe** |
| §E volatile admission | conjunct fails, access rejected | safe |

So a name match on an external declaration **is** a registration, and the only
remaining question is whether its handler operand resolves — which
`resolve_registry_entries` already answers as
`unresolved: external || !targeted` (`crates/pangs-api/src/lib.rs:4303`). An
unresolved registration still sets `signal_context_access` and still widens
every restricting consumer; it does **not** satisfy §E's admission conjunct,
which requires a resolved registration with a certified path. Volatile admission
is the one place the fact *permits*, so it takes the strict reading.

**How an unresolved registration widens — frozen:**

```text
handlers(unresolved registration) = precise targets ∪ { f : f.address_taken ∧ ¬f.external }
```

Existing behavior (`crates/pangs-clients/src/lib.rs:777-783, 838-841`); the
widened set is `address_taken_entries`, *chained onto* the precise targets rather
than replacing them. Frozen here because F2 consumes it. **All internal
functions** is strictly wider and buys nothing, since a function whose address
was never taken cannot be a registration operand. **FSA-compatible functions**
(`void (*)(int)`) would be tighter and remains a defensible future refinement.

After this fix, accesses reachable from `sigint_handler_xjtr_0` set
`signal_context_access: true`; the atomic certificate must then require and
record target-guaranteed lock-free operations for the width, and mutex must
remain unavailable because a signal handler cannot safely take the proposed
mutex.

The fix also has a module-wide effect that must be measured rather than assumed
benign: the registration becomes a modeled registry call in phase analysis, so
globals whose `phase_stationarity` previously failed on that unresolved effect
may now certify and move to `once-lock`. Record the distribution after Phase 2
and again after Phase 3 so the two effects are attributable separately.

### E. Permit only certified signal-flag volatile accesses

Keep the existing `volatile-access` failure as the default. In
`atomic_access_recipe`, allow a volatile site only when every one of the
following holds:

```text
the global has positive signal-atomic type evidence                (§C)
the global has a certified positive access path from a resolved
  signal registration                                              (below)
the global has internal linkage                                    (M.8)
the global is ordinary storage: no section, not thread-local,
  not alias-exposed                                                (below)
one target probe covers this module's arch, the declaration's
  width, and every operation the recipe emits                      (below)
every access satisfies the ordinary atomic recipe constraints
the access set is complete and every site is in the admitted operation set
every function that both accesses this global and may run as
  a handler accesses no other static-storage object            (F2, below)
```

F2 is the *pattern condition*, derived under "Why dropping `volatile` is
admissible". It is not hygiene: `Relaxed` does not preserve access count or
relative order, and the argument that this is harmless holds only for a flag
whose sole role is to convey signal arrival.

The resolved-registration conjunct is what makes the C standard's `sig_atomic_t`
guarantee the *operative* reason the object is volatile, rather than an
incidental type choice in front of some other access contract; §C alone would
admit a `volatile sig_atomic_t` no handler ever touches. Requiring it costs a
flag polled only from ordinary code, which fails closed to today's behavior. It
is **not** an MMIO-exclusion test — nothing stops a handler from touching a
memory-mapped register — so MMIO and special-section storage are excluded by the
ordinary-storage predicate instead.

#### Ordinary-storage predicate

For v1, admission additionally requires:

```text
is_definition == true ∧ constant initializer present   (already required by D3)
linkage == internal                                    (M.8)
no explicit section attribute                          (needs a new PIR fact)
not thread-local                                       (needs a new PIR fact)
not alias-exposed                                      (needs a new PIR fact)
```

Phase 3 adds `section: Option<String>` and `thread_local: bool` to
`pangs_pir::Global`, both `#[serde(default)]`. Thread-local is not merely an MMIO
concern: a `__thread volatile sig_atomic_t` is a per-thread flag, and lowering it
to a plain `static AtomicI32` would merge every thread's copy into one.

**Aliases need a new fact.** `collect_alias_map`
(`crates/pangs-pir/src/llvm_sys.rs:3566`) applies the interposability check
*before* resolving the aliasee, so an external-linkage alias is dropped without
its aliasee ever being computed:

```rust
for alias in aliases {
    let alias_key = value_name(*alias);
    if !is_non_interposable_alias(*alias) {           // Private | Internal only
        lowering.bump_tainted(format!("alias_interposable:{alias_key}"));
        continue;                                     // ← aliasee never inspected
    }
    let Some(target) = constant_symbol_name(LLVMAliasGetAliasee(*alias)) else { … };
    …
}
```

Nothing records that this alias pointed at *this* global — the taint string names
the alias, not its target — so "no external-linkage alias targets the global" is
not a predicate over any fact that exists (rule 15). Nor does `bump_tainted` gate
anything: it writes `LoweringStats::tainted_counts`, a metrics counter
(`crates/pangs-pir/src/lib.rs:479`) read only by assertions in
`crates/pangs-pir/tests/llvm_lowering.rs`. `violation_taint` is unrelated —
module-wide it is `module_violation_tainted`, testing for inline assembly
(`crates/pangs-solve/src/lib.rs:1222`); per-global it comes from violation
findings (`crates/pangs-clients/src/lib.rs:209-210`). This matters because M.8
rejects external linkage to prevent mixed atomic/non-atomic access across a TU
boundary, and an external-linkage alias re-exports that storage under another
name — the same hazard through a back door.

**The fix — decided, not measured: an alias-exposure inventory in PIR.** Move
`constant_symbol_name(LLVMAliasGetAliasee(*alias))` above the interposability
check; when it names a known global and the alias is not internal-linkage, record
it in a new `LoweringStats` field
`alias_exposed_globals: BTreeMap<String, BTreeSet<String>>` (`#[serde(default)]`).
The §E clause becomes `alias_exposed_globals.get(key).is_none()`. Two properties:
**resolution is separated from modelling** — the alias is still dropped from
`AliasMap` exactly as today, so nothing about points-to, escape, or the Ω
boundary moves; and **an unresolvable aliasee counts as exposure of nothing, not
of everything** — `constant_symbol_name` returning `None` adds no entry.

That second property is a real gap rather than a conservative default, so it is
closed bluntly and narrowly: **an `alias_unresolved:` lowering taint blocks
signal-flag mode for every global in the module.** A module-wide fallback keyed on
*any* `alias_`-prefixed taint was considered and rejected — it would disable the
feature whenever a module contains an ordinary external alias to an unrelated
function, and the inventory is a few lines. What must **not** happen is a third
option: a target-specific predicate no fact can evaluate, which an implementer
would most plausibly discharge by writing `false`.

The registry work is a hard prerequisite: without it the bore flag has
`signal_context_access: false` and is correctly rejected. That is the desired
failure mode — the idiom is admitted only where the analysis can see the signal
context that gives it meaning.

#### The certified positive access path

`signal_context_access` is one `EvidencedBool`
(`crates/pangs-manifest/src/lib.rs:400`, `DISPOSITION.md` §2), true for resolved
*and* unresolved registrations alike, and computed by a widening query. It is
exactly right as a **restricting** fact and unusable as a permitting one.

`signal_context_access` comes from `transitive_accesses`, whose per-payload target
set is `AffectedGlobals::ModuleWide` whenever the access is through a pointer with
no finite candidate set (`crates/pangs-api/src/lib.rs:2093-2096`), and
`registry_access_facts` then sets the mask on **every global in the module**
(`crates/pangs-clients/src/lib.rs:848-852`). **Cloning that computation for the
permitting conjunct would be a soundness hole**: one handler with an unresolved
transitive effect would satisfy §E's conjunct for every global in the module for
free. `ModuleWide` is **orthogonal to `unresolved`** — it comes from the handler's
own transitive summary, not from the registration operand — so restricting to
resolved registrations does not avoid it. The restriction must be on the access
path.

**Certified positive access path.** True for a global `g` only when there exists
a path `f₀ → f₁ → … → fₙ` (n ≥ 0) where `f₀` is a **precise** target of a
**resolved** signal registration (not a member of §D's widening); every edge is
a `Stmt::CallDirect` to a defined internal function; and `fₙ` contains an
`AccessSite` on `g` with `via == Via::Direct`. Everything weaker is rejected:

| Provenance | Sets `signal_context_access` | Satisfies the §E conjunct |
|---|---|---|
| `Via::Direct` site, direct-call path from a precise resolved target | yes | **yes** |
| `Via::Aliased` / `Via::Unknown` site (pointer access, finite candidate set) | yes | no — a *may* set is not positive proof |
| `AffectedGlobals::ModuleWide` | yes | **no** — the case the rule exists for |
| any indirect-call edge on the path | yes | no — the call graph over-approximates exactly there |
| target from the address-taken widening | yes | no — the widening is a guess at who the handler is |

The direct-call restriction keeps the evidence exhibitable: the witness *is* the
path, and a reviewer can read it in the source. **This costs less than it
appears**: the admitted access set already requires `via == Via::Direct` at every
site, since `atomic_access_recipe` fails `address-access-not-lowerable` otherwise
(`crates/pangs-clients/src/lib.rs:1891`). The rule aligns the *conjunct* with a
restriction the *recipe* already enforced. For bore the path has length zero —
`sigint_handler_xjtr_0` is a precise target of the resolved `signal(2, …)` and
contains a `Via::Direct` store to the flag.

**An API gap this exposes.** `AffectedGlobals::Finite` is returned both for
`GlobalTarget::Name(g)` — one element, exact — and for `GlobalTarget::Unknown(_)`
with a finite candidate set, which may also be one element
(`crates/pangs-api/src/lib.rs:2091-2097`), so the tiers are indistinguishable
through `transitive_accesses`. The conjunct must therefore be computed from
`access_sites_for_global` (`crates/pangs-api/src/lib.rs:2012`), which carries
`via` and `func` per site, walked backwards over direct-call edges to the
registration targets — **a different query, not a filtered version of the old
one** (D8).

The predicate is **existential over resolved registrations**, not universal: a
global reached by one resolved and three unresolved registrations is admissible,
because one resolved registration fully supplies the positive proof and
additional unresolved ones widen the handler set without undermining evidence
that already exists.

**Where the result lives.** In the certificate, as
`atomic_mode.certified_path`, not as a new fact slot. `atomic` is a
certificate-backed strategy, so `DISPOSITION.md` §1's guard-shape rule puts this
inside the pass's certificate — the cascade reads one slot, and D3 internally
requires its preconditions, exactly as D4 does for reentrancy. This is the same
call D1 makes for the type evidence, applied uniformly, and it holds the v5
fact-layer delta to `word_sized_scalar` alone. Promotion to a fact slot when a
second consumer appears is schema v6.

**Witness determinism**: record the resolved registration with the lowest
callsite id, and among paths from it the shortest, ties broken by callee order
within each caller. `signal_context_access` keeps its existing first-wins
witness and is otherwise untouched — same semantics, same widening computation,
same consumers.

#### Admitted operations

Admit only direct whole-object loads; direct whole-object stores; comparisons and
control flow consuming a load; and stores of values representable by the selected
atomic type. No address-based, field, bulk-memory, inline-assembly, or unknown
access.

Do not initially admit volatile read-modify-write expressions;
increment/decrement or compound assignment; accesses through escaped pointers;
mismatched-width or partial accesses; `memcpy`, `memset`, or byte-wise access;
general volatile objects lacking `sig_atomic_t` evidence; or objects that may be
memory-mapped I/O.

The certificate marks the mode with one tagged object (normative nesting in
§"Schema v5" §4). There is no second place where the mode is recorded:

```json
{ "recipe": { "ordering": "relaxed", … },
  "atomic_mode": { "kind": "signal_flag",
                   "probe": "x86_64.ldst.v1",
                   "operations": ["load", "store"],
                   … } }
```

Relaxed ordering matches the flag's narrow role: it communicates a scalar stop
condition and does not publish other memory. A future case that uses the flag to
publish payload state needs a separate synchronization proof and must not inherit
acquire/release semantics from this rule. The materializer lowers the declaration
and every certified access as one consistent atomic representation, never mixing
volatile raw accesses and atomic accesses to the same storage.

#### The lock-free gate needs a real target fact

The existing gate reads `target.supported_atomic_widths`, which
`module_target_info` (`crates/pangs-pir/src/llvm_sys.rs:407`) computes as
`[8, 16, 32]` plus 64 when the pointer is 64-bit — a pointer-width heuristic that
asserts 8/16/32-bit atomics on every target regardless of whether the target has
them, and says nothing about lock-freedom versus an `__atomic_*` libcall. Using
it as the async-signal safety gate (`crates/pangs-clients/src/lib.rs:1113,1217`)
states a guarantee the value does not carry.

The replacement is a **target probe**: a triple of `(arch, widths, operations)`
backed by a checked-in codegen regression, named by id, which the certificate
cites. The operation set is part of the probe rather than an assumption about it,
because lock-freedom is not uniform across operations — Rust exposes
`target_has_atomic_load_store` separately from `target_has_atomic` precisely
because load/store lock-freedom is much more widely satisfied than lock-free RMW.
A certificate is admissible only when **one** probe covers every operation its
recipe emits, so a load/store proof can never be silently reused for an RMW
recipe. `supported_atomic_widths` is untouched.

That coverage rule closes a hole this design had while the gate was a width list.
The signal gate fires for every signal-context global, not only signal-flag ones,
so narrowing it to a load/store guarantee would have certified a signal-context
*RMW* recipe against a proof of something weaker. With probes the mismatch is a
rejection rather than a silent widening, and v1 ships an RMW probe for `x86_64`
so the current corpus does not lose coverage to the repair.

Replacing both lists with one profile would be a cliff: `word_sized_scalar` reads
`supported_atomic_widths` (`crates/pangs-clients/src/lib.rs:2337`), the coarse
gate for every global, so an unlisted triple would zero atomic eligibility
module-wide — undetectable by the bore regression, which is
`x86_64-unknown-linux-gnu`. The deeper reason is the failure modes:

| Fact | If it is wrong | Detected by |
|---|---|---|
| `supported_atomic_widths` | the recipe names a Rust atomic type that does not exist for the width | **compile error** in the Rust output — `DISPOSITION.md` §7's structural gift |
| a target probe | a signal handler takes a lock, or an access is not indivisible | **nothing** — silent deadlock or torn access at runtime |

Migrating `supported_atomic_widths` is a **separate, evidence-gated follow-up**:
derive the probe table, diff it against the heuristic across the triples the
corpus contains, then decide. Agreement makes it a rename that can land any time;
disagreement is a bug report about the general atomic recipe and deserves its own
note.

#### Target probes

**Key.** The normalized architecture component of `TargetInfo.triple`, already
captured (`crates/pangs-pir/src/llvm_sys.rs:412`). Lock-freedom is an ISA
property, so vendor, OS, and environment are ignored; normalization is the arch
component plus a small alias map (`amd64`, `x86_64h` → `x86_64`). An absent or
unparsable triple resolves to no probe, hence no signal-context atomic.

**Rows in v1: exactly two, both `x86_64`.**

| id | arch | widths | operations |
|---|---|---|---|
| `x86_64.ldst.v1` | `x86_64` | 8, 16, 32, 64 | `load`, `store` |
| `x86_64.rmw.v1` | `x86_64` | 8, 16, 32, 64 | `load`, `store`, `rmw` |

Everything else is absent → fail closed. The corpus is 71 modules and 100%
`x86_64-*-linux-*`, and a row no test exercises is a liability. A signal-flag
certificate always cites `x86_64.ldst.v1`, since §E admits loads and stores only;
`x86_64.rmw.v1` exists so an ordinary signal-context global with an RMW recipe
keeps the coverage it has today, under a proof that actually covers RMW. The arch
omissions are decisions: `arm`/`thumb`, where 64-bit lock-free load/store depends
on sub-arch (`ldrexd`) the arch component does not determine; `riscv32`/`riscv64`,
where atomics come from the `A` extension, a feature rather than an implication of
the arch string; and 32-bit x86, where 64-bit lock-free load/store needs i586+
(`cmpxchg8b`/x87), so `i386` and `i686` cannot share a row.

**A certificate cites exactly one probe.** Two probes are never combined to cover
an operation set between them: a proof assembled from parts is a proof no single
regression asserts.

**CPU features are not consulted.** A probe lists only widths lock-free on the
arch's *baseline* subtarget; enabling features can add lock-freedom but never
remove it, so ignoring them errs closed, and an arch with an ambiguous baseline
gets no probe rather than an optimistic one. Per-function `target-features`
attributes are deliberately not read: they are per-function, frequently absent in
`-O0` bitcode, and would make a module-global fact depend on which function
carried an attribute.

**Authority** is the Rust target definition, not LLVM's, since the consumer is
generated Rust: `rustc --print cfg --target <triple>`, reading
`target_has_atomic_load_store` for a load/store probe and `target_has_atomic` for
an RMW one. Check the table in with the rustc version it was derived from, plus a
test that re-derives it when `rustc` is available and skips otherwise.

**The table has no configuration surface.** There is no `--target-profile` flag,
no narrowing, and no evidence-bundle mechanism. A probe is admissible **only** if
the codegen regression below covers it, and the regression is in-tree; so the only
way to add a probe is to add it beside its regression, in a reviewed patch. A
configuration path whose honest use is "re-run the in-tree regression and paste
its output" is the same act with the review removed, and for a gate whose failure
mode is a silent handler deadlock, "audited" is not a substitute for "tested".
If the regression fails for a probe, the probe is removed, every certificate
citing it stops being emittable, and signal-context atomics on that target fall
back to `unhandled`.

**Reproducibility.** Record the resolution in `run.analysis` (analysis-owned
under `DISPOSITION.md` §3.3), so a manifest names what was available to it. This
is a run record, **not a validator operand**: no per-global clause reads it, and
its absence is not a validation failure.

```json
"target_probes": {
  "triple": "x86_64-unknown-linux-gnu", "arch": "x86_64",
  "available": ["x86_64.ldst.v1", "x86_64.rmw.v1"],
  "supported_atomic_widths": [8, 16, 32, 64]
}
```

**The bore case.** `x86_64-unknown-linux-gnu` normalizes to `x86_64`, the flag's
recipe emits loads and stores at 32 bits, and `x86_64.ldst.v1` covers it. No
corpus module exercises the empty default; the fail-closed path is asserted by a
synthetic fixture with an unlisted triple.

#### Why dropping `volatile` is admissible, and what remains assumed

`volatile` gives three things; `Relaxed` (LLVM `monotonic`) gives the first,
gives the third only as a compiler property, and does not give the second:

| | `volatile` | `Relaxed` / `monotonic` |
|---|---|---|
| **(i)** indivisibility of a width-appropriate access | not guaranteed by C; supplied here by `sig_atomic_t` + the lock-free gate | guaranteed |
| **(ii)** preservation of access *count* and of relative order among qualified accesses | guaranteed | **not** guaranteed — RLE, DSE, store-to-load forwarding and coalescing are all permitted |
| **(iii)** no *unbounded* elision — the access is re-executed on each loop iteration | guaranteed | not an abstract-machine guarantee; in LLVM, LICM hoisting and promotion require `isUnordered()`, which `monotonic` is not |

`volatile` never provided inter-thread ordering: it does not order a volatile
access against non-volatile ones and emits no fences, so anything a second thread
could observe was already unordered in the C source. The only same-thread
observer that can see (ii) is a signal handler, because delivery is synchronous
on the interrupted thread and therefore sees program order.

**The argument that closes (ii): signal-arrival refinement.** For a flag whose
sole role is to convey *that* a signal arrived, each permitted transformation is
behavior-refining. Two loads collapsed into one: the source execution in which
the signal was delivered after both loads is legal — delivery timing is
unconstrained — and produces exactly the transformed behavior. A store deleted by
a later store to the same flag: the same argument with the roles swapped.
Store-to-load forwarding, coalescing, and reordering against ordinary accesses:
the same again, since the observer that would distinguish them is the handler,
which F2 confines. Each removes executions that all correspond to a legal source
execution with different arrival timing — so (ii) is recoverable, and **only**
for a flag with that role, which the pattern condition makes checkable rather
than assumed.

The argument does not extend to *unbounded* elision: a load hoisted out of a
polling loop yields an execution in which the signal is never observed at all,
which is not "delivered later" but "never delivered". That is (iii), the one
genuine residual.

**F2. Handler-observer confinement** — a hard conjunct of certification. Let `A`
be the functions containing an enumerated access to the flag — known exactly,
since access-set completeness is already a conjunct and every site is
`Via::Direct` or the recipe already failed — and `H` the handler set over **all**
registrations: precise targets for resolved ones, plus §D's frozen widening for
unresolved ones. Require that every function in `A ∩ H` accesses no object with
static or thread storage duration other than the flag. Failure code
`signal-handler-access-not-confined`, witnessed by the function and the offending
object.

The two sets over-approximate in **opposite directions**: `H` is widened (more
candidate handlers ⇒ harder to pass), while `A` is the recipe's own exact,
`Via::Direct` site list. A widened `A` would be unsound, with the same
`ModuleWide` hazard as above, so `A` must be evaluated against
`access_sites_for_global`, never the registry's transitive mask. The "accesses no
other static-storage object" half is the one place a widened set is *safe*, being
a restrictive test: `ModuleWide` there means "may touch everything", which fails
F2 and rejects, so that half can read the ordinary transitive summary.

The intersection makes this sound and affordable: a function that never touches
the flag cannot correlate its order with anything, and a function not in `H`
cannot run as a handler. For functions in both, F2 is C11 §7.14.1.1p5 restated —
a handler referring to any static-storage object other than by assigning to a
`volatile sig_atomic_t` is already undefined behavior — so the condition rejects
only programs that were broken before translation.

**Why F2 is the only pattern condition.** An earlier revision added F1: at most
one certified flag per program, because with two, the interrupted code can
observe an ordering the compiler no longer preserves — `flag_a = 1; flag_b = 1;`
in a handler, read in the other order by the main loop. F2 already excludes that
program: the handler writes two static-storage objects, so it fails confinement
on both flags. The general argument:

- A reordering of the flag's accesses is observable only by an execution that
  *reads the flag*.
- The only asynchronous observer is a signal handler (the interrupted thread does
  the writes; other threads were already unordered, per the paragraph above).
- A handler that reads or writes the flag is in `A ∩ H`, and F2 forbids it from
  touching any other static-storage object — so it cannot correlate the flag with
  anything else.

The converse cases are vacuous. *Main writes both flags, one handler reads one*:
comparing would require the handler to touch the second, which F2 forbids. *Two
flags with disjoint confined handlers*: neither handler can see the other's
object, and between two independent deliveries there is no program order to
preserve. *Flag plus an ordinary object published by ordinary code*: again the
observer must read both, and F2 rejects it. So F2 subsumes F1, at finer
granularity — two independently confined flags in one module both certify, where
F1 rejected both without picking a winner.

**The single residual assumption.** After F2, exactly one thing is assumed: *a
`monotonic` load or store inside a loop is re-executed on each iteration — the
compiler does not hoist, sink, or promote it out.* C11 §7.17.3 and the Rust
memory model only say a relaxed store *should* become visible in finite time, so
this is a quality-of-implementation property; in LLVM it holds because LICM's
hoist and promotion paths require `isUnordered()`. Reducing the residual to this
one statement is the point: it is a property a codegen regression can assert, per
probe, in both directions. It is still an assumption, and belongs in the
audited soundness inventory (`DESIGN.md` §8); Phase 4's dynamic SIGINT test
exercises it.

Two hard requirements follow for the materializer: it must not "optimize" a
certified access back to a plain non-atomic read even when it can prove the flag
loop-invariant in its own view of the program (the handler write is invisible to
that proof); and it must not substitute a `Cell`, a plain `static mut` read, or
an `UnsafeCell`-based shim for the atomic representation.

**The rejected alternative** — keep admission broad and extend the assumption to
cover the execution and ordering of every admitted access — would require
asserting, per target and opt level, that no permitted monotonic transformation
ever fires on a certified access: a universally quantified claim over an
optimizer, unfalsifiable by any finite regression, reopened by every LLVM
upgrade. F2 instead makes the permitted transformations harmless by construction
and leaves one existentially checkable property behind.

#### Audit contract for the no-elision assumption

**Who records it.** `AuditRecord::regenerate_id`
(`crates/pangs-manifest/src/lib.rs:1392`) hashes the whole record, so its content
must be deterministic — and analysis, which emits the ledger, does not know what
Rust toolchain will compile the output. So **analysis emits the envelope** from a
checked-in evidence table (repo constants, so the id is stable), and **the Rust
stage enforces it**, comparing the actual toolchain against the recorded envelope
before rewriting and failing loudly when outside (M.7 gives it the channel).

**Record shape.** No audit-schema change is required: `kind` is a free string and
the schema is `additionalProperties: true`, so the payload rides in
`AuditRecord.extra`. One run-scoped record, emitted only when at least one global
certifies in signal-flag mode, plus one `scope: global` record per such global.
Rows are self-contained and do not cross-reference.

```jsonc
{
  "id": "ar-…",                                  // content hash, per §1.4
  "kind": "signal-flag-codegen-assumption",
  "scope": { "kind": "run" },
  "source": "analysis",
  "text": "Certified signal-flag atomics assume the Rust backend does not hoist, sink, or promote a Relaxed atomic load or store out of a loop, and lowers load/store of the certified width without a library call. Bounded transformations that Relaxed permits (redundant-load elimination, dead-store elimination, coalescing) are not assumed against; certification requires the F2 confinement condition, under which they are behavior-refining. This is a quality-of-implementation property, not an abstract-machine guarantee.",
  "envelope": {
    "probe": "x86_64.ldst.v1",
    "triple": "x86_64-unknown-linux-gnu", "arch": "x86_64",
    "widths": [32], "operations": ["load", "store"],
    "rustc_min": "1.XX.0", "llvm_major": [17, 18, 19],
    "opt_levels": ["0", "1", "2", "3"]
  }
}
```

`envelope.probe` is the id a certificate cites, so the chain reads certificate →
ledger record → the in-tree regression that gates the probe's existence. An
opaque id nobody can follow would be worse than none; this one names the artifact
an auditor re-runs.

**Declared scope, and no extrapolation.** The assumption is asserted for exactly
`{probes} × {widths in the probe} × {rustc ≥ floor, LLVM in list} × {opt levels}`
and nothing else. A toolchain outside it is outside the audited envelope, and the
Rust stage refuses.

**Codegen regression, per probe.** A probe can be compiled for without being
runnable on, so the per-probe gate is an artifact check and execution is a
host-only addition. The audited property is *absence of unbounded elision*, not
preservation of access count, so the assertions are positional. For every declared
probe × width × opt level, compile fixtures and assert:

1. **No library call.** No reference to any `__atomic_*` symbol, and no call in
   the loop other than the fixture's own opaque `work()`/`step()`.
2. **Load not hoisted or promoted.** Fixture: a polling loop reading the flag. At
   `--emit=llvm-ir -C opt-level=3`, at least one `load atomic monotonic` of the
   flag appears in the loop body, and the loop's exit condition still depends on a
   value loaded inside the loop — not one loaded in the entry block or carried by
   a phi from before the loop.
3. **Store not sunk or coalesced out of a loop.** Fixture: a loop storing to the
   flag each iteration with an opaque call between. At least one
   `store atomic monotonic` appears in the loop body, and none has migrated to
   the exit block.
4. **Store not deleted across a call.** Fixture: `flag = 1; work(); flag = 0;`.
   Both stores survive. This is the bounded-DSE boundary: deletion of the first
   store *with nothing in between* is permitted and not asserted against;
   deletion across a call that may deliver a signal is not.
5. **Asm cross-check** on probes where the loop structure is recognizable: a
   memory operand naming the static appears between the loop label and its
   backedge, for both fixtures.

An RMW probe adds one assertion — the fetch-and-modify fixture lowers to a single
locked instruction with no `__atomic_*` reference — and asserts nothing about
elision, which is a load/store property this design does not extend to RMW.

Then, host-only, the Phase 4 SIGINT test: a hoisted load makes the loop never
terminate, so the property is observed rather than inspected. It is a liveness
test and must run under a timeout, where a hang is a failure.

**What this does not do.** None of it *proves* the QoI property; it detects
regression in the toolchains under test, and the ledger record says so in its own
`text`.

### F. Distinguish semantic certification from already-safe source

The source is already using the C-prescribed signal-flag idiom, which does not by
itself tell the Rust materializer what representation to emit. The disposition
remains `atomic`, but its certificate says why the volatile source is admitted
and how it must be translated.

A new `signal-atomic` disposition is not proposed: its storage/action is still
atomic, and adding a strategy would expand the cascade, schema, overrides,
measurements, and materializer surface. A certificate mode under `atomic`
suffices unless later cases need materially different policy or output.

## Schema v5: normative freeze

Everything above is design rationale; this section is the contract. The JSON in
earlier sections is illustrative and, where it disagrees with this section,
wrong. MUST/MUST NOT are normative; the field paths are exact.

The v5 **fact-layer** delta is one field: `word_sized_scalar`. Everything else
new lives inside the `atomic_eligibility` certificate payload.

### 1. Encoding conventions

Already the manifest's conventions, restated so the new fields do not invent
alternatives.

- **v5 is defined once, in Phase 1.** The *entire* v5 contract —
  `word_sized_scalar` and every signal-flag payload and validator rule below —
  lands with the version bump in Phase 1, **dormant**: types, schema definitions,
  and validator rules all present, the signal-flag rules vacuously satisfied
  because nothing emits the `signal_flag` variant until Phase 3, which then
  changes emission only. This is what keeps Phase 1 independently shippable. **A
  partially-introduced v5, in which two incompatible contracts both call
  themselves v5, is forbidden.**
- **Absence, not null, for optional detail.** Every *new* optional detail field
  uses `#[serde(skip_serializing_if)]`
  (`crates/pangs-manifest/src/lib.rs:321-328`); `null` is reserved for a *slot*
  meaning "not computed" (the certificate slots and `coupling_group`). A new
  field MUST NOT be emitted as an explicit `null`.
- **v5 does not preserve v4 payloads.** No consumer reads a v4 manifest, so v5
  is free to remove and restructure — and it does: `signal_lock_free` is
  deleted, not extended (§4). Objects still retain `#[serde(flatten)] Extra` and
  `additionalProperties: true` so an unknown field round-trips, which is forward
  tolerance, not backward compatibility.
- **Vocabulary.** Field names `snake_case`, failure codes `kebab-case`, matching
  the existing vocabulary (`volatile-access`, `word-sized-scalar`). New enums are
  closed: an unlisted value is invalid, not forward-compatible.

### 2. `facts.word_sized_scalar`

| Field | v4 | v5 |
|---|---|---|
| `value` | bool, required | unchanged |
| `type_spelling` | present iff `value` | **optional, independent of `value` in both directions** |
| `size_bits` | present iff `value` | required iff `value` is true; optional when false |
| `class` | present iff `value` | required iff `value` is true; optional when false |
| `signed` | present iff `value` | required when `value` is true and `class ∈ {integer, enum}`; otherwise optional |
| `codes` | — | **new**: `Vec<String>`, required non-empty iff `value` is false |

The invariant replacing `crates/pangs-manifest/src/lib.rs:429-441`:

```text
value == true   ⇒  size_bits present ∧ size_bits ≥ 1
                ∧  class present
                ∧  (class ∈ {integer, enum} ⇒ signed present)
                ∧  codes absent or empty
value == false  ⇒  codes present ∧ non-empty
detail fields MAY be present when value is false   (the v4 prohibition is deleted)
type_spelling is constrained by neither direction
```

`codes` reuses the certificate-slot noun rather than `diagnostics`, which is
already an opaque `Value` on `Certificate::Failed`. **Closed vocabulary**,
emitted in exactly this evaluation order, deduplicated, and **not sorted** —
fixed evaluation order is what the existing `codes` arrays do, and it keeps
golden diffs stable:

```text
unknown-scalar-class
unknown-signedness
zero-width
unsupported-atomic-width
unknown-alignment
under-aligned
over-aligned
```

The alignment codes are split rather than named `insufficient-alignment` because
the gate is strict equality and therefore rejects **over**-alignment too:
`over-aligned` means the equality gate, whose relaxation §B defers to a separate
change; `under-aligned` means a packed or exotic declaration;
`unknown-alignment` covers `align_bits: None`, which today falls into the same
silent bucket because `None != Some(width)`.

`meta.type_spelling` is unchanged and remains required-but-nullable. When both
are present they are the same string; neither gates `value`.

### 3. Version handling

**There is one live contract.** No consumer reads a v4 manifest, so
`Facts::validate` takes no `schema_version` parameter and there is no
dual-invariant path: a document is validated against §2 or refused by the
existing version gate (`crates/pangs-manifest/src/lib.rs:903-904`). v4 fixtures
are regenerated, not grandfathered — a fixture validated under rules nothing
emits is a test of a dead contract.

One rule survives, and it is about stage consistency within a run rather than
compatibility across versions: **`pangs-dispose` never reads or writes `schema_version`.** It
parses a `Manifest`, fills its own sections, and re-serializes, preserving
whatever version the input declared — so a v5 dispose fed a v4 analysis manifest
today emits a document *labelled v4* containing v5-shaped dispose sections. Since
`DISPOSITION.md` §3.3 requires earlier stages' sections to survive semantically
unchanged, a stage MUST NOT silently upgrade or inherit:

```text
a stage that preserves an earlier stage's sections MUST require
schema_version == its own SCHEMA_VERSION, and MUST fail with
"re-run analysis" otherwise
```

That is a v5 requirement, not current behavior, and needs its own test.

### 4. Atomic certificate payload: exact nesting

```text
facts.atomic_eligibility
├── status: "certified"
└── certificate
    ├── recipe
    │   ├── declaration { size_bits, align_bits, scalar_class, signed,
    │   │                 linkage, initializer_ir, type_spelling? }
    │   ├── accesses[]
    │   ├── cross_tu { … }
    │   └── ordering: "relaxed"
    ├── source_materialization { status, code?, detail? }
    └── atomic_mode                        ← the sole mode discriminant
        │
        ├── kind: "plain"                  — not signal-context accessed.
        │                                    No further members.
        │
        ├── kind: "signal_safe"            — signal-context accessed, ordinary
        │   ├── probe: "x86_64.rmw.v1"       (non-volatile) accesses
        │   └── operations: ["load", "store", "rmw"]
        │
        └── kind: "signal_flag"            — signal-context accessed, volatile
            ├── probe: "x86_64.ldst.v1"      accesses admitted under §E
            ├── operations: ["load", "store"]
            ├── type_evidence
            │   ├── typedef: "sig_atomic_t"
            │   ├── typedef_chain: ["sig_atomic_t", "__sig_atomic_t"]
            │   └── volatile: true
            ├── certified_path
            │   ├── registration { callsite, file, line }
            │   ├── handler: "sigint_handler_xjtr_0"
            │   ├── path: ["sigint_handler_xjtr_0"]   // f₀ … fₙ, direct-call only
            │   └── access { via: "direct", file, line }
            ├── handler_accesses_confined: bool                   (F2)
            └── observers[]                                       (witness: A ∩ H)
                ├── function: "sigint_handler_xjtr_0"
                └── via: "resolved" | "address-taken-widening"
```

**One tagged object replaces four coupled fields.** A previous draft spread the
mode across `recipe.volatile_semantics`, `signal_atomic_type`,
`signal_flag_pattern`, and `signal_lock_free.required`, and then spent a four-way
biconditional making them agree. A single discriminant makes "mode asserted,
proof absent" unrepresentable rather than detected. **There is no presence
coupling in v5**; it was the cost of encoding one fact four times.

**`signal_lock_free` is deleted, not moved.** Its three members were a duplicated
fact, a constant, and a copy: `required` was `facts.signal_context_access`;
`target_guaranteed` is `true` in every certificate where it means anything, since
a false value means the global failed `signal-atomic-not-lock-free` and produced
no certificate; and `width` was `recipe.declaration.size_bits`. It also emitted
`{required: false, width: null}` on every ordinary atomic — an inhabited state
asserting nothing. `kind` carries the first, the variant's existence carries the
second, and the declaration carries the third.

**Width, alignment, class, and signedness are emitted once**, in
`recipe.declaration`, and `atomic_mode` re-states none of them. A validator that
re-checks copies of one number is defending against the emitter contradicting
itself, which is better prevented than detected.

**`operations` is a member of the mode, not of the probe reference**, because it
states what *this recipe* emits; the probe states what the target guarantees. The
admission rule is that one probe covers the operations — which is checkable, and
is what stops a load/store proof from being reused for an RMW recipe.

Two further placement rules are load-bearing:

- **Signal-flag proofs are certified-only, structurally.** `Certificate::Failed`
  (`crates/pangs-manifest/src/lib.rs:350`) has `codes`, `witnesses`, `recipe`,
  and `diagnostics` and **no certificate-level payload**, so a failed slot has
  nowhere to put `atomic_mode` at all. Rule 18 — a signal-flag atomic exists only
  as a complete certified proof — therefore stops being a rule someone must
  enforce and becomes a property of the type. This is why the discriminant lives
  at certificate level and not in `recipe`: `recipe` is a field on the failed
  variant too, so a mode marker there would be representable on the failed path
  and would need a clause forbidding it. Normatively: **a global whose admission
  required signal-flag mode and did not certify gets `recipe: null`.** That is
  already the behavior — `atomic_access_recipe` returns `(None, failures)`
  whenever any failure was recorded (`crates/pangs-clients/src/lib.rs:1992`), and
  the coarse gate sets `recipe: None` on its own path.

  The consequence is intended: per `DISPOSITION.md` §4.2 an `atomic` pin on such
  a slot is rejected `no-recipe`, **unwaivable by `accept_risk`**, so "you cannot
  override your way into an unproven signal-handler atomic" is structural rather
  than a policy rule someone must remember. Every failure code reachable in
  signal-flag mode — `signal-atomic-not-lock-free`, `volatile-access`,
  `address-access-not-lowerable`, `access-site-unmapped`, the `rmw-*` codes,
  `signal-flag-external-linkage`, `signal-handler-access-not-confined` — means
  the rewrite cannot be executed correctly, so none is §4.2's honorable "evidence
  failed, recipe present" case. The confinement code belongs in that list because
  it looks like advisory hygiene, and waiving it would override the condition
  that makes dropping `volatile` sound at all (rule 12).

  Suppression stays diagnosable through `diagnostics`, which is opaque and
  load-bearing for nothing:

  ```json
  { "signal_flag": { "status": "recipe-withheld",
                     "reason": "signal-flag mode requires certification" } }
  ```

- **The mode is read from the certificate, not the recipe.** M.5's rewrite
  instruction is `atomic_mode.kind`; `recipe` carries the accesses and the
  ordering, which is what the materializer needs positionally. Splitting the mode
  across both is what created the coupling this section no longer has.

- **Value coupling.** With one discriminant there is nothing left to check about
  *presence*; what remains is that the variant's own members are the ones that
  licensed admission. The validator MUST require:

  ```text
  the mode agrees with the fact layer          (the one cross-section clause)
    kind ∈ {signal_safe, signal_flag}  ⟺  facts.signal_context_access.value

  the operation claim is backed                (both signal variants)
    probe ∈ KNOWN_PROBES
    operations non-empty, and exactly the operation kinds recipe.accesses emits
    every member of operations is covered by probe, at recipe.declaration.size_bits

  signal-flag mode's admission conjuncts are reflected
    operations                        == ["load", "store"]
    recipe.ordering                   == "relaxed"
    recipe.declaration.scalar_class   == "integer"
    recipe.declaration.linkage        == "internal"                  (M.8)
    type_evidence.volatile            == true
    type_evidence.typedef             ∈ type_evidence.typedef_chain
    type_evidence.typedef             ∈ RECOGNIZED_SIGNAL_TYPEDEFS   ( = {"sig_atomic_t"} )
    certified_path present  ∧  certified_path.access.via == "direct"
    handler_accesses_confined         == true
    observers                         non-empty
  ```

  `KNOWN_PROBES` and `RECOGNIZED_SIGNAL_TYPEDEFS` are closed constants in
  `pangs-manifest`, so both are local checks. The fact-layer clause is the only
  one reading outside the certificate, and it is kept because its failing
  direction is the unsafe one: a `plain` claim on a signal-context global skips
  the probe requirement entirely.

  Clauses that would re-check one producer against itself are deliberately
  absent: `align_bits == size_bits` belongs to `word_sized_scalar`, which is
  already a conjunct of every atomic certificate, and the width appears in
  exactly one place, so there is nothing to compare it to.

  The pattern boolean is written out rather than implied by the variant's
  presence so a certificate can be audited against the source without re-deriving
  why `Relaxed` needed it. `observers` carries the witness that makes F2 auditable
  at all: F2 is a claim about a specific set of functions (`A ∩ H`), and a
  certificate asserting it without naming them is checkable only by the analysis
  that produced it. It is non-empty because `certified_path` already names a
  handler that accesses the global. `certified_path.access.via` is recorded
  explicitly, so a reader can see the rejection rule was applied rather than
  assume it.

  **Every clause is per-global, and all but one are per-certificate.** Nothing in
  v5 requires a validator to compare two globals, and nothing requires it to read
  the run header: `run.analysis.target_probes` is a reproducibility record, not a
  validator operand, so its absence is never a validation failure and the
  present/absent rules an earlier draft needed are gone with it. Only
  `facts.signal_context_access` is threaded in, the same way `Manifest::validate`
  already reaches a global's facts.

  The rejected alternative — giving `Certificate::Failed` a proof-envelope field
  so a partial proof could be recorded — would add a second separately-validated
  shape whose only reachable content is a partial proof of something that did not
  hold, for a case §4.2 already refuses to honor.

- **Scope.** All of the above constrains the two signal variants only; ordinary
  atomic, mutex, and once-lock slots keep §4.2's honorable accepted-risk case.
- **`kind` is a closed enum with three members and no default.** An ordinary
  atomic certificate carries `{"kind": "plain"}`, not an absent object: the mode
  is always stated, so "no mode recorded" is not a state a reader must interpret.
- `operations` is a closed set (`load`, `store`, `rmw`), emitted in that order.
  Extending it bumps the schema and requires a probe that covers the addition.
- `source_materialization` is **unchanged**: `status` remains
  `"source-mapped" | "blocked"`, `code` required iff blocked, and
  `declaration-source-unmapped` its only code. Spelling absence is a certificate
  diagnostic, not a status (M.0).
- `certificate.type_evidence` is a new optional diagnostic object: advisory,
  carrying no invariant, and MUST NOT be read by any guard.

### 5. Ordering, determinism, and two names that are not one name

- `typedef_chain` is in **outer-to-inner declaration order**, neither sorted nor
  deduplicated: it is a path, and its order is the evidence.
- `type_evidence.typedef` is the **recognized standard typedef** — the name
  that licensed the certificate — and MUST be a member of `typedef_chain`, but is
  *not* necessarily `typedef_chain[0]`: under `typedef sig_atomic_t my_flag_t;`
  the chain is `["my_flag_t", "sig_atomic_t", "__sig_atomic_t"]` and recognition
  matches at position 1.
- `type_spelling` (§A) is positionally `typedef_chain[0]`. The two coincide only
  when the declaration names the standard typedef directly — the common case and
  the bore case — and MUST NOT be conflated: one answers "what did the source
  say", the other "what proved this certificate".
- When exactly one chain member is a recognized standard name, `typedef` is that
  member; two cannot occur, since recognition matches a single spelling.
- Exceeding `DEBUG_TYPE_RECURSION_LIMIT` yields **no certificate**, never a
  truncated chain. Same for cycles and malformed metadata.
- `certified_path.path` is the shortest direct-call path from the resolved
  registration with the lowest callsite id, ties broken by callee order within
  each caller. Specified because a handler can reach a flag by several chains, and
  an arbitrary choice would churn manifests across unrelated inlining changes.
- `codes`, `operations`, `typedef_chain`, and `observers` are deterministic under
  re-emission; a golden diff that reorders any of them is a defect.

### 6. Freeze points, and an honest note about rigor

| Artifact | Change |
|---|---|
| `schemas/disposition-manifest.schema.json` | the `word_sized_scalar` `oneOf` (lines 139-166) *is* the v4 invariant and must be replaced by §2; `signal_lock_free`'s definition **removed**; a discriminated `atomic_mode` definition added (`oneOf` on `kind`, so each variant's required members are schema-enforced); `run.analysis.target_probes` added as optional |
| `crates/pangs-manifest/src/lib.rs` | `SCHEMA_VERSION = 5`; `WordSizedScalar.codes: Vec<String>` with `#[serde(default, skip_serializing_if = "Vec::is_empty")]`; `AtomicMode` as an internally-tagged enum, replacing `signal_lock_free`; `KNOWN_PROBES` beside `RECOGNIZED_SIGNAL_TYPEDEFS`; one validator for the §4 value coupling; `Facts::validate` keeps its current signature |
| `crates/pangs-pir/src/lib.rs` | `Global.type_evidence: Option<ScalarTypeEvidence>` with `#[serde(default)]`, matching every other optional field there (lines 158-183), so existing PIR fixtures parse and re-serialize unchanged; plus `section` and `thread_local` in Phase 3 |
| `crates/pangs-api/src/lib.rs:142` | `GlobalInfo` mirrors the same optional fields |
| `schemas/globals.schema.json` | **unaffected, deliberately** — `additionalProperties: false` over a fixed key set, no type fields at all; it is not the type channel and MUST NOT gain one |
| D1a golden manifests | regenerated; the permitted diff is classified per global in §7 |

`type_spelling`, `scalar_class`, and `signed` are **retained** on the PIR and API
globals, not replaced; when `type_evidence` is present they are its projections.
No consumer is forced to migrate.

The honest note: certified certificate payloads are entirely unconstrained in the
JSON schema today — `certificate` requires only `status` and `certificate`
(`schemas/disposition-manifest.schema.json:167-186`), so `recipe`, `ordering`,
and `signal_lock_free` have never been schema-frozen, being held only by golden
files and the emitter at `crates/pangs-clients/src/lib.rs:1283`. Constraining the
signal-flag additions is therefore *new* rigor, justified by the asymmetry stated
in §Status: these fields gate a silent failure, and the JSON schema is the only
artifact a non-Rust consumer can check. The rest of the payload stays as it is.

### 7. The permitted golden diff

| Class | Condition | Permitted change |
|---|---|---|
| **A** | every manifest | `schema_version` 4 → 5 in the header. No per-global change follows from the bump alone |
| **B** | `word_sized_scalar` was already true | **nothing changes** |
| **C** | was false, still false | gains non-empty `codes`; gains the `size_bits`/`class`/`signed` detail that v4 suppressed |
| **D** | false → true, still fails atomic later | class C's detail, plus `value: true`; `atomic_eligibility.codes` changes from `["word-sized-scalar"]` to the later decisive code; `diagnostics` changes from `access_lowering: skipped` to an observed-site count. Disposition unchanged |
| **E** | false → true, now certifies | class D's changes, plus `atomic_eligibility` Failed → Certified with recipe and `source_materialization`; `cascade_chosen`/`chosen` → `atomic`; `cascade_trace` shortens; `run.dispose.measurement_report` moves |

Class D is the bore flag's own Phase-1 diff: it clears the coarse gate and fails
on `volatile-access` instead.

The review rule is attribution, not line count: **every changed line must be
attributable to its global's class, and every global must be in a class its facts
justify.** Two defect signals a plausible-looking diff can carry: a class-B
global changing at all, and a class-E global whose `word_sized_scalar` was false
for a reason other than a missing spelling. Aggregate consistency is separate:
`not_word_sized` must decrease by exactly |D| + |E|, and `measurement_report` may
move only if |E| > 0.

## Materialization contract

`DISPOSITION.md` §5.3 already assigns `atomic` its stage split — the C→C tool
does **exemption + definition-site marker**, and nothing else. This section makes
the rest concrete rather than adding a stage.

### M.0 "Certified but blocked" is a decided policy, not a new one

1. **The separation already exists.** `atomic_source_materialization`
   (`crates/pangs-clients/src/lib.rs:1310`) returns
   `{ status: "blocked", code: "declaration-source-unmapped" }` inside a
   certified payload today, and `DISPOSITION.md` §9's D4 entry states the same
   rule for mutex: static certification is distinct from source readiness.
2. **The cascade guard is certificate-only.** Slot 3 reads one thing: is
   `atomic_eligibility` certified. A certified slot whose
   `source_materialization.status` is `blocked` still selects `atomic`.
3. **Execution failure is corrected downstream**, by C→C demotion (§5.3) or
   Rust-stage loud failure (M.7) — never by weakening the certificate.
4. **Therefore blocked materialization MUST NOT be folded back into the
   certification guard**, which would create a second, divergeable definition of
   atomic eligibility.

Consequently there is no `declaration-type-unspelled` blocked code. Under M.1–M.3
a certified atomic with a null `type_spelling` is fully executable: the C→C stage
plants a marker needing only the symbol and coordinates (already covered by
`declaration-source-unmapped`), and the Rust stage derives the atomic type from
`scalar_class`/`signed`/`size_bits`. Nothing consumes
`recipe.declaration.type_spelling`; it is emitted for diagnosis only.

### M.1 Which stage removes `volatile`

**The Rust stage. The C→C stage MUST NOT touch the declaration or any access.**
The C→C output still compiles and runs as C, so removing `volatile` there would
strip the flag's no-cache property from a program with no atomic in its place — a
real miscompilation window between the two stages, for a global whose entire
point is being written asynchronously. The C→C tool's only job is to make the
decision findable:

```c
/* C→C output — declaration and every access byte-identical to the input */
#include "pangs_markers.h"
static volatile sig_atomic_t g_interrupted = 0;

__attribute__((constructor)) static void pangs__mark_g_interrupted(void) {
    pangs_disposition_atomic__src_search_c__g_interrupted__ab12cd34();
}
```

The Rust stage is coordinate-free (`DISPOSITION.md` §5.1) and matches by symbol
identity, with the marker as the disambiguator when translation renamed the item.

### M.2 Before and after

```c
static volatile sig_atomic_t g_interrupted = 0;

static void sigint_handler(int sig) { (void)sig; g_interrupted = 1; }

static int search(void) {
    while (work_remaining()) {
        if (g_interrupted) return 1;
        step();
    }
    return 0;
}
```

Translated Rust, before the rewrite — the C `volatile` accesses arrive as
`read_volatile`/`write_volatile` calls on the static's address, which is the
property that makes them findable:

```rust
static mut g_interrupted: __sig_atomic_t = 0;

unsafe extern "C" fn sigint_handler(_sig: c_int) {
    ::core::ptr::write_volatile(&mut g_interrupted as *mut __sig_atomic_t, 1);
}

unsafe fn search() -> c_int {
    while work_remaining() != 0 {
        if ::core::ptr::read_volatile(&g_interrupted as *const __sig_atomic_t) != 0 {
            return 1;
        }
        step();
    }
    0
}
```

After the rewrite:

```rust
static g_interrupted: ::core::sync::atomic::AtomicI32 =
    ::core::sync::atomic::AtomicI32::new(0);

unsafe extern "C" fn sigint_handler(_sig: c_int) {
    g_interrupted.store(1, ::core::sync::atomic::Ordering::Relaxed);
}

unsafe fn search() -> c_int {
    while work_remaining() != 0 {
        if g_interrupted.load(::core::sync::atomic::Ordering::Relaxed) != 0 {
            return 1;
        }
        step();
    }
    0
}
```

`static mut` becomes plain `static`: atomics carry interior mutability, and
dropping `mut` turns every missed access into a compile error rather than a
silent survival — the structural gift `DISPOSITION.md` §7 relies on.

### M.3 Type mapping

Keyed on `recipe.declaration.{scalar_class, signed, size_bits}`:

| `scalar_class` | `signed` | `size_bits` | Rust type |
|---|---|---|---|
| `integer` | true | 8 / 16 / 32 / 64 | `AtomicI8` / `I16` / `I32` / `I64` |
| `integer` | false | 8 / 16 / 32 / 64 | `AtomicU8` / `U16` / `U32` / `U64` |
| `enum` | per `signed` | as above | as the integer rows |
| `boolean` | — | 8 | `AtomicBool` |
| `pointer` | — | — | **out of scope in v1** — a signal flag is an integer, and `AtomicPtr<T>` needs a pointee type this recipe does not carry |

`size_bits` must be covered by the cited probe, which D3 guarantees; a
mismatch is a rewriter error, not a demotion. All paths are written fully
qualified (`::core::sync::atomic::…`) so the rewriter never manages `use`
statements or collides with an existing import.

### M.4 Initializer

`recipe.declaration.initializer_ir` is a typed LLVM constant (`i32 0` for the
bore flag), and `AtomicI32::new` is `const fn`, so the result is valid in a
`static`.

**Translation is bit-vector semantics, not decimal copying.** LLVM prints integer
constants with a *signed* interpretation of the type's bit width, so
`unsigned char x = 255;` appears as `i8 -1`; copying that decimal into
`AtomicU8::new(-1)` does not compile, and a naive `abs`-style repair would
silently produce `1`.

```text
1. parse "iN <decimal>"  ->  (N, signed value v)
2. require N == recipe.declaration.size_bits
3. bits := v reduced mod 2^N        (two's-complement pattern, N bits)
4. emit the literal in the TARGET type's signedness:
     AtomicIN::new(<bits interpreted as signed N-bit>)
     AtomicUN::new(<bits interpreted as unsigned N-bit>)
```

| `initializer_ir` | `signed` | Emitted |
|---|---|---|
| `i32 0` | true | `AtomicI32::new(0)` |
| `i32 -1` | true | `AtomicI32::new(-1)` |
| `i8 -1` | **false** | `AtomicU8::new(255)` |
| `i8 -1` | true | `AtomicI8::new(-1)` |
| `i32 -2147483648` | true | `AtomicI32::new(-2147483648)` |
| `i32 -2147483648` | false | `AtomicU32::new(2147483648)` |
| `zeroinitializer` | either | `AtomicIN::new(0)` / `AtomicUN::new(0)` |

**Boolean initialization.** A C `_Bool` global has `scalar_class: "boolean"` but
is stored as `i8`, so both spellings are accepted and every other bit pattern
rejected — `AtomicBool::new` takes a `bool` and has no representation for
anything else:

```text
"i1 false" | "i8 0" | "zeroinitializer"  ->  AtomicBool::new(false)
"i1 true"  | "i8 1"                      ->  AtomicBool::new(true)
any other value at boolean class         ->  rewriter error
```

`undef` and `poison` are rejected: a C definition always has an initializer, so
their appearance means the recipe and the module disagree. An address-valued,
aggregate, or non-constant initializer cannot reach this path, since D3's coarse
gate requires a scalar class and an empty storage closure.

### M.5 Access rewrite forms

The recipe's `accesses` entries carry C coordinates, which the Rust stage does
not use; it matches structurally, on uses of the identified static:

```text
read_volatile(&G as *const T)          ->  G.load(Ordering::Relaxed)
read_volatile(&raw const G)            ->  G.load(Ordering::Relaxed)
write_volatile(&mut G as *mut T, v)    ->  G.store(v, Ordering::Relaxed)
write_volatile(&raw mut G, v)          ->  G.store(v, Ordering::Relaxed)
plain read of G                        ->  G.load(Ordering::Relaxed)
plain assignment G = v                 ->  G.store(v, Ordering::Relaxed)
```

The ordering comes from `recipe.ordering`, which is `"relaxed"` and MUST NOT be
inferred. Both `&raw` and `as *const`/`as *mut` spellings are accepted because
translator versions differ. The surrounding `unsafe` block is left alone: an
access that no longer needs it is a lint, not an error.

Anything else naming the static — an address taken into a variable, a cast, a
pointer passed to a function, a `memcpy` — is a rewriter error. D3's recipe
already rejects those shapes, so encountering one means the recipe and the
translated source disagree, which must be loud.

### M.6 Marker interaction

1. Read `materialization.marker_inventory`; find the `disposition_atomic` row for
   the key and confirm its embedded strategy matches the manifest disposition.
2. Resolve the row to the translated `static` item — by symbol name normally, by
   the marker when translation renamed it.
3. Rewrite declaration and accesses.
4. Delete the marker call, the generated constructor wrapper, and the
   `pangs_markers.h` include.

A surviving `pangs_*` symbol is a build error by design, and a manifest `atomic`
disposition whose marker is absent from the translated source is a loud failure —
both existing `DISPOSITION.md` §5.2 rules, inherited unchanged.

### M.7 Validation and failure

**The primary check is an exhaustive reference inventory**, not a count. A
count-plus-residue check does not catch a translated form that launders the
address:

```rust
let p = &g_interrupted as *const _ as *const i32;
let v = ::core::ptr::read_volatile(p);
```

That reference is not one of M.5's forms, so it is not rewritten and the count is
unaffected; the surviving `read_volatile` does not syntactically name the static,
so a residue check misses it; and it **compiles**, because the raw-pointer cast
erases the type distinction that was supposed to be the safety net. The result
reads the atomic non-atomically — soundness rule 5 violated silently. So the rule
is closure over references, not detection of known-bad ones:

1. **Inventory.** Enumerate *every* path-expression reference to the static item
   in the translated crate and classify each. After rewriting, the only permitted
   references are receivers of `load`/`store` calls with the frozen ordering.
   Every other reference — `&G`, `addr_of!(G)`, a cast, an argument, a mention in
   another item's initializer, any other method — is a build failure naming the
   site. Unknown classification is failure, never default-allow.
2. **Macro and `cfg` closure.** A reference the rewriter cannot see is not one it
   may ignore: if it operates before macro expansion, any macro invocation whose
   token stream mentions the symbol and which it cannot expand is a failure, and
   `cfg`-disabled code mentioning the symbol is likewise a failure, since another
   feature set would compile it. c2rust output is macro-light in practice, which
   makes this cheap, not unnecessary.
3. **Count cross-check.** Rewritten site count equals `recipe.accesses.len()` —
   retained because it catches the opposite error: the inventory catches
   references the *analysis* did not classify, the count catches accesses the
   *rewriter* did not find.
4. **Type.** The static's type is the mapped atomic type and the item is no
   longer `static mut`.
5. **Marker.** The inventory row is consumed and the symbol is gone.
6. **The compiler, as a backstop for the type-visible subset only.** Anything
   expecting `i32` where `AtomicI32` now sits fails to typecheck; raw-pointer
   paths defeat it, which is why check 1 is mandatory.

**Demotion.** `DISPOSITION.md` §5.3 gives the demotion channel to the C→C tool,
which owns a manifest section. The Rust stage owns none, so it cannot demote:

| Stage | Failure | Behavior |
|---|---|---|
| C→C | cannot plant the marker (definition inside an unrewritable macro) | ordinary §5.3 demotion to `unhandled` |
| Rust | unmappable type, untranslatable or out-of-range initializer, unclassifiable reference, unexpandable macro mentioning the symbol, count mismatch, missing marker, toolchain outside the recorded envelope | **loud build failure** |

The operator's recourse for a Rust-stage failure is to pin the global
`disposition = "unhandled"`, which §4.2 always permits without `accept_risk`, and
re-run. Giving the Rust stage its own demotion channel would mean giving it a
manifest section, reopening `DISPOSITION.md` §3.3's stage-ownership rule.

### M.8 External linkage is rejected in signal-flag mode

**Layout compatibility is not the question.** If one TU is translated and another
is not, the storage is accessed as a Rust atomic from one side and as a
`volatile sig_atomic_t` — a *non-atomic* access — from the other. Rust's memory
model, inherited from C++20, makes conflicting atomic and non-atomic access to
the same location a data race and therefore undefined behavior
(`std::sync::atomic` module documentation); identical layout only guarantees the
two sides disagree about the same bytes. For a signal flag the concurrent case is
not a corner — asynchronous access from outside ordinary control flow is the
object's entire purpose. Soundness rule 5 applies across a TU boundary just as
within one.

A layout argument would also be overstated on its own terms: `AtomicI32`
guarantees that its alignment equals its *size*, not that it matches
`align_of::<i32>()`. The two coincide for admitted globals only because
`word_sized_scalar` requires `align_bits == size_bits`, and the general claim
fails exactly where a cross-TU argument would matter most: on 32-bit x86,
`AtomicI64` is 8-byte aligned while `i64` is 4-byte aligned.

**v1 rule.** Signal-flag mode requires **internal linkage**; an external-linkage
global fails with `signal-flag-external-linkage` and its decisive witness. The
gate is `global.meta.linkage`, which the recipe already reads for
`cross_tu.required` (`crates/pangs-clients/src/lib.rs:1276`). This is
deliberately redundant with `access_set_complete`, which fails on library-mode
name reachability: neither subsumes the other — an executable module can define
an externally visible global whose accesses are all locally visible — and for a
gate whose failure mode is silent UB, the redundancy is the point.

**`global.meta.linkage` is not sufficient on its own**, which is why §E carries a
separate alias clause: an `__attribute__((alias))` definition with external
linkage re-exports an internal global under a second name, so the symbol is
externally accessible while `linkage` still reads `internal`. The alias-exposure
inventory in §E closes it.

Lifting the restriction requires a **whole-program certificate**: proof that
every TU accessing the symbol is transformed in one run, so no non-atomic
accessor survives. No such certificate exists, and v1 does not reason about a
half-translated program. The bore flag is `static`, so the restriction costs
nothing for the motivating case.

## Soundness rules

1. Missing or incomplete typedef/qualifier metadata never proves
   `signal_atomic_type`.
2. A generic volatile access remains a hard atomic-eligibility failure.
3. A signal-context atomic must cite one probe covering the declaration's width
   and **every** operation its recipe emits; a library-based fallback is
   forbidden in an async-signal handler, and an arch with no probe is not
   lock-free. Probes are never combined to cover an operation set between them.
4. Every access to the global must be enumerated and lowered; an incomplete
   access set fails closed.
5. No mixed atomic/non-atomic or atomic/volatile representation is emitted —
   **including across a translation-unit boundary**. Conflicting atomic and
   non-atomic access to the same storage is undefined behavior under Rust's
   memory model, and identical layout does not make it defined (M.8).
6. Width, alignment, and signedness must match the declaration and every access.
7. A name-matched external declaration in the registry **is** a registration; an
   operand the solver cannot resolve downgrades it to unresolved rather than
   deleting it. Only a *resolved* registration with a certified positive path may
   satisfy a permitting conjunct.
8. Unknown handler targets or unknown signal-context accesses retain the
   appropriate conservative facts, and "conservative" is direction-dependent: for
   a *restricting* fact it means widening (`signal_context_access` sets every
   global on a `ModuleWide` effect, which is correct); for a *permitting*
   conjunct it means the opposite — no widened, aliased, or may-set access path
   may establish it.
9. The certificate provides scalar atomicity only. It does not certify
   publication of unrelated memory and does not model the interleaving between
   handler and interrupted code; it certifies that each individual access remains
   indivisible. It is **not** the whole of what the source relied on — the source
   also relied on `volatile`'s preservation of access count and relative order,
   which rule 12 discharges.
10. Volatile admission requires proven signal-handler participation, evidenced by
    at least one *resolved* registration. Type evidence alone never admits a
    volatile access, and neither does an unresolved registration.
11. Recognizing a registration alias never relaxes the Ω boundary at that call:
    it adds spawn/signal facts and removes a phase-analysis unresolved-effect
    widening, leaving every points-to, mod/ref, and escape consequence unchanged.
12. `Relaxed` does not preserve the number or relative order of accesses;
    redundant-load elimination, dead-store elimination, store-to-load forwarding,
    and coalescing are all permitted on `monotonic`. Certification therefore
    requires F2 — handler-observer confinement for every function that both
    accesses the flag and may run as a handler — under which every such
    transformation is behavior-refining, because the only observer that could
    distinguish them is a handler that F2 forbids from touching anything else,
    and signal arrival timing is unconstrained. Without the pattern, dropping
    `volatile` is unsound, not merely optimistic.
13. The only residual assumption in signal-flag mode is the absence of
    *unbounded* elision: a `monotonic` load or store in a loop is re-executed
    each iteration. It is asserted per probe by positional codegen
    assertions on both the load and store side, never by access-count equality,
    which would reject a legal RLE and accept a store sunk past a loop.
14. Every conjunct that *permits* something requires a finite, exhibitable
    positive path: an exact global root (`Via::Direct`), reached from a precise
    target of a resolved registration over direct-call edges only.
    `AffectedGlobals::ModuleWide`, a finite may-set, an aliased or unknown
    access, an indirect call edge, and a target drawn from the address-taken
    widening each set the restrictive fact and none of them satisfies the
    permitting conjunct.
15. Every conjunct in an admission predicate must be evaluable from a fact that
    exists, and the note must name it. A clause phrased over a relation the
    pipeline does not compute — "no external-linkage alias targets the global",
    when the alias's target is never resolved — is worse than an absent clause:
    it reads as a guard, is cited as one, and an implementer will most plausibly
    discharge it by evaluating it to `false`. Where the fact does not exist, the
    design must either add it or state the blunter fact that stands in for it.
16. The redefined `word_sized_scalar` never becomes a certificate by itself. It
    is a coarse gate; certification still requires the complete access recipe,
    and source readiness never feeds back into the certification guard (M.0).
17. The C→C stage never removes `volatile` or alters an access: between the two
    stages the program must remain a correct C program, and a declaration
    stripped of `volatile` before an atomic exists in its place is not one.
18. A signal-flag atomic exists only as a complete certified proof. There is no
    partial, failed, or overridden form: a failed proof emits no recipe, and no
    override can supply one. This is enforced by shape rather than by a check —
    `atomic_mode` is a certificate-level member and `Certificate::Failed` has no
    certificate-level payload, so a partial form is unrepresentable.

## Amendments required to other documents

Nothing here touches A′–D′ or any solver semantics; the changes are confined to
PIR lowering, the F-layer fact scans, and the manifest schema.

1. **`DISPOSITION.md` §2 (fact table)** — no fact is added. The `word_sized_scalar` row loses "type
   spelling exists" and gains the statement that detail fields survive a false
   value, becoming a machine-level fact with materializability split out. The
   `signal_context_access` row is unchanged, but gains two sentences: that it is
   a *restricting* fact computed by a widening query and therefore never
   discharges a permitting conjunct, and that the `atomic` certificate's mode
   variant must agree with it — the one place a certificate reads a sibling fact.
   §1's guard-shape rule gains the general statement (rule 14).
2. **`DISPOSITION.md` §3 / §3.2** — `schema_version: 5` per the freeze above: the
   detail/value coupling invariant is replaced, `word_sized_scalar` gains
   `codes`, and the `atomic_eligibility` certificate **replaces**
   `signal_lock_free` with the tagged `atomic_mode`. v5 is not backward
   compatible with v4 payloads and does not claim to be; the schema-v4 sentence
   in §2 is replaced rather than extended, and §3.3's stage-ownership rule gains
   the exact-version requirement.
3. **`DISPOSITION.md` §3.2 / §3.3 (`run.analysis`)** — the run header gains
   `target_probes`, optional, documented explicitly as a reproducibility record
   that no validator reads, so a reader does not take its absence for a defect or
   its presence for a guarantee.
4. **`DISPOSITION.md` §7 (soundness matrix)** — the `atomic` row's "no additional
   relational failure for defined source behavior" needs a signal-flag
   qualification: what makes the substitution behavior-preserving is F2 plus the
   unconstrained timing of signal arrival (rule 12), and what remains assumed is
   only the absence of unbounded elision (rule 13) — the first as a stated
   precondition of the row, the second as a recorded assumption. Add the
   dynamic-audit cell (Phase 4's SIGINT test) and the per-row codegen assertions.
   **`DESIGN.md` §8** takes the same assumption in its audited soundness
   inventory, phrased as the single residual, not as "volatile is replaced by
   Relaxed".
5. **`DISPOSITION_PLAN.md` §1.5** — the evidenced/certificate encodings D1a's
   golden test freezes; the scalar failure-diagnostic vocabulary belongs there,
   not only here. `source_materialization`'s code list is unchanged.
6. **`DISPOSITION.md` §5.3 (stage actions)** — the `atomic` row is unchanged, but
   the section describes demotion as though every materialization failure had a
   channel. It should state that the Rust-side rewriter owns no manifest section,
   therefore fails loudly rather than demoting, and that the `unhandled` pin is
   the operator's recourse (M.7). A pre-existing gap this feature surfaces.
7. **Audit ledger kinds** — `signal-flag-codegen-assumption` (§E). Analysis-
   sourced, so `DISPOSITION.md` §3.3's rule applies (dispose regenerates only
   `source: "override"` records). **No change to
   `schemas/disposition-audit.schema.json` is required**: `kind` is a free string
   and the schema is `additionalProperties: true`. Document the kind in
   `DISPOSITION_PLAN.md` §1.4 alongside the deterministic-id rule.
8. **`pangs-pir` lowering docs (`LoweringStats`)** — `alias_exposed_globals` is a
   *fact*, not a metric, and belongs documented apart from the `*_counts` maps
   beside it. Add a sentence stating that `tainted_counts`, `skipped_counts`, and
   `modeled_counts` are observability counters read by no guard — with the one
   exception that an `alias_unresolved:` taint blocks signal-flag mode (§E).
9. **`DESIGN_lite.md` §2A** — the registry paragraph describes only the Ω
   external-summary registry. Add one sentence distinguishing the spawn/signal
   disposition registry (name-keyed, conservative-on-false-positive, no Ω
   effect), so a reader does not infer that adding `__sysv_signal` summarizes an
   external call.
10. **`HOWTO_MEASURE_DISPOSITION_COVERAGE.md` and the `notes/disposition_*`
    baselines** — `not_word_sized` and the would-be-eligibility counters change
    meaning at Phase 1; the re-measurement note must say so rather than
    re-baselining silently.

## Implementation sequence

Phases 1 and 2 are independent; Phase 3 depends on both, because its admission
conjunction names a fact from each.

### Phase 1: diagnostics and type normalization

- Add a bounded qualified-type walker in `pangs-pir`; preserve typedef chains and
  qualifiers in PIR/API metadata, populating `type_spelling` from
  `typedef_chain[0]`.
- Split `word_sized_scalar` from source spelling/materialization, keeping the
  alignment condition at equality, and emit granular scalar failure diagnostics
  with partial evidence retained.
- Record spelling absence as a certificate diagnostic, **not** a
  `source_materialization` block (M.0); `declaration-source-unmapped` keeps its
  meaning and remains the only blocked code.
- Bump `SCHEMA_VERSION` to 5 and land the **complete** freeze — not only the
  parts Phase 1 exercises: `word_sized_scalar.codes`; `AtomicMode` with all three
  variants and its discriminated schema definition; `KNOWN_PROBES`; the §4 value
  coupling validator; the exact-version requirement for stages that preserve
  earlier sections; and regenerated goldens. Phase 1 emits only
  `{"kind": "plain"}` and `{"kind": "signal_safe", …}` — the latter wherever a
  signal-context global certifies today, carrying the probe that covers its
  existing recipe.
- Land the probe table and its codegen regressions, and switch the signal gate
  (`crates/pangs-clients/src/lib.rs:1113,1217`) from `supported_atomic_widths`
  onto probe coverage. This belongs here, not in Phase 3: `signal_safe` is a
  required v5 variant with a required probe member, so the table is part of the
  contract §1 requires Phase 1 to land whole, and it depends on nothing in
  Phases 2–3. `supported_atomic_widths` and its derivation are untouched, and the
  regression lands *before* the probe it justifies, RMW included.
- The `signal_flag` variant ships **dormant**: nothing emits it until Phase 3, so
  its clauses are unreachable rather than vacuously true. A test asserts exactly
  that — the validator is live, every Phase-1 manifest passes it, and a
  hand-written `signal_flag` fixture with a broken member is rejected.

This phase makes the manifest accurately say that `g_interrupted` is an aligned
signed 32-bit scalar while still rejecting its volatile access recipe. The
`atomic` slot is `failed` with `recipe: null`, so a user cannot reach `atomic` by
overriding either — `DISPOSITION.md` §4.2's `no-recipe` rejection applies and is
not waivable by `accept_risk`.

### Phase 2: registry correctness

- Validate first with `--registry-config` on the bore module: no code change,
  observable fact delta. Then add `__sysv_signal` to the built-in table.
- Confirm the handler resolves to `sigint_handler_xjtr_0`, and that
  `bore_search_cleanup`'s restore call
  (`signal(2, g_prev_sigint_handler_xjtr_0)`) remains an unresolved registration
  that still widens — the motivating example exercises both outcomes in one
  module.
- Confirm `g_interrupted` becomes signal-context-accessed, and that mutex is
  rejected by `signal-context-access` independently of its existing reentrancy
  result.
- Record the corpus disposition distribution before and after: recognizing the
  registration also removes a phase-analysis unresolved effect, which can move
  unrelated globals into `once-lock`.

No schema change, no `Facts` field, and no new query lands here. This phase
repairs facts required by the eventual atomic proof and must land before the
special volatile admission.

### Phase 3: narrow signal-flag atomic recipe

- Emit the `signal_flag` variant. The probe table, the gate switch, and the
  codegen regressions landed in Phase 1; nothing about the target model changes
  here.
- Emit the `signal-flag-codegen-assumption` ledger records from the checked-in
  evidence table, and add the Rust-stage toolchain-envelope check. These are
  signal-*flag* obligations — Phase 1's `signal_safe` certificates rest on probe
  coverage alone, since the no-elision assumption is a property of replacing
  `volatile`, which only this variant does.
- Add `section: Option<String>` and `thread_local: bool` to `pangs_pir::Global`
  (both `#[serde(default)]`) and surface them through the API, so the
  ordinary-storage predicate is checkable at all.
- Land `LoweringStats::alias_exposed_globals` and the reordering of
  `collect_alias_map`, plus the `alias_unresolved:` module block (§E). The clause
  must be backed by a fact that exists (rule 15).
- Add signal-atomic type-evidence certification, including typedef provenance.
- Land the **certified positive access path** query: walk
  `access_sites_for_global` back over direct-call edges to the precise targets of
  resolved registrations, recording the path as the witness. It is **not** a
  filtered copy of `registry_access_facts` — that version would inherit
  `AffectedGlobals::ModuleWide` and mark every global positively
  signal-accessed — and a code comment at the query should say so, because the
  filtered-copy version is the obvious implementation and looks right.
- Add the F2 check and emit the `signal_flag` variant: group the recipe's access list
  by enclosing function to get `A`, intersect it with the registry target set
  including §D's widening to get `A ∩ H`, and query each survivor's
  static-storage access set. It is an admission conjunct, not a diagnostic — a
  failure yields `recipe: null`. F2 is per-global; no whole-program pass is
  required anywhere in this feature.
- Thread it into atomic access recipe construction, gated on the full §E
  conjunction — including the certified path, **not** `signal_context_access`;
  the permissive-looking fact is the wrong one.
- Admit only direct whole-object volatile loads/stores, on internal-linkage
  globals only (M.8), and emit the `certified-signal-flag` recipe mode with its
  operation set. **No schema or validator change belongs in this phase** — both
  landed in Phase 1. If Phase 3 finds it needs one, that is a defect in the
  freeze, to be fixed before Phase 1 ships rather than by amending a released v5.
- Record the no-elision assumption in the audited soundness inventory per §E's
  audit contract, with the run-scoped and per-global records.

### Phase 4: end-to-end materialization

- C→C: confirm `atomic` globals reach the definition-site marker path with the
  declaration and every access byte-identical to the input.
- Rust: type mapping (M.3), initializer translation (M.4), the access forms in
  M.5, marker consumption and deletion (M.6).
- Land M.7's **exhaustive reference inventory** — the load-bearing check, and the
  one piece of Phase 4 that is not mechanical: enumerate every path-expression
  reference to the static, classify each, permit only receivers of `load`/`store`
  with the frozen ordering, and treat unknown classification as failure. Include
  the macro and `cfg` closure. A count-and-residue implementation instead passes
  the laundered-pointer case, compiles, and silently reads the atomic
  non-atomically — soundness rule 5 violated with every check green.
- Land the remaining M.7 checks as what they are: **count** as a cross-check,
  **type**, **marker consumption**, and the compiler as a backstop for the
  type-visible subset only.
- Land the loud-failure behavior with the `unhandled` override as the documented
  recourse — the Rust stage owns no manifest section and cannot demote.
- Compile and run signal-interruption tests under the transformed program, and
  add dynamic confirmation that SIGINT changes the flag and terminates the search
  path without locks or allocation in the handler — the test that exercises the
  no-elision assumption.

## Tests and acceptance criteria

### PIR and metadata tests

- Lower `static volatile sig_atomic_t flag;` from real LLVM bitcode: the typedef
  chain includes `sig_atomic_t`, and `volatile`, integer class, signedness,
  width, and alignment survive. Cover nested `const volatile` qualifiers and
  multiple typedef layers.
- `type_spelling` is `typedef_chain[0]`: `sig_atomic_t` for the direct
  declaration, `my_flag_t` under `typedef sig_atomic_t my_flag_t;`,
  `__sig_atomic_t` only when the source names it directly. With no typedef it is
  the terminal type's name (`int`); with an anonymous enum it is absent.
- Under `typedef sig_atomic_t my_flag_t;` the certificate's `typedef` is
  `sig_atomic_t` while `type_spelling` is `my_flag_t`, asserted separately so a
  regression cannot collapse them.
- Malformed and over-depth metadata fail without certification.

### Scalar-fact tests

- An aligned supported integer with missing spelling is a semantic word-sized
  scalar and — given a source-mapped declaration and a clean access recipe —
  certifies `atomic` with `source_materialization: source-mapped`, carrying only
  a `type_evidence` diagnostic.
- A certified global whose declaration has no file/line is certified with
  `source_materialization: blocked`, and the cascade still chooses `atomic`; a
  test asserts the cascade does not consult materialization status (M.0).
- Unsupported width, unknown class, and unknown signedness receive distinct
  codes. Alignment codes are distinguished: `align < size` → `under-aligned`,
  `align > size` (e.g. `__attribute__((aligned(64))) int`) → `over-aligned`,
  absent alignment → `unknown-alignment`; no case emits a code implying the wrong
  direction.
- Partial evidence remains visible when the boolean is false, and `codes` is
  non-empty exactly then.

### Schema tests

- A v5 document with `value: false` and no `codes` is rejected; one with detail
  present at `value: false` is accepted. A v5 document is refused by a v4 reader
  through the existing version gate, and a v4 document is refused by a v5 reader
  the same way — there is no dual-invariant path to test.
- A stage that preserves earlier sections refuses a document whose
  `schema_version` differs from its own, rather than re-emitting under the
  input's version.
- **The mode is a discriminated union at the schema level**: a `signal_flag`
  object missing any required member is rejected by
  `schemas/disposition-manifest.schema.json` alone, before the Rust validator
  runs. A `plain` object carrying a `certified_path` is rejected as an
  unexpected member of its variant. There is no combination of members that
  half-asserts the mode, which is the property that replaced the presence
  coupling — asserted by construction, i.e. by there being no such test to write.
- Each §4 **value** coupling clause is rejected independently, one test per
  clause, on a payload well-formed except for a single wrong value: `probe` not
  in `KNOWN_PROBES`; `operations` containing a kind the probe does not cover;
  `operations` disagreeing with what `recipe.accesses` emits; `operations` ≠
  `["load","store"]` in `signal_flag`; `typedef` not in `typedef_chain`;
  `typedef` not in `RECOGNIZED_SIGNAL_TYPEDEFS`; `volatile: false`;
  `scalar_class` ≠ `"integer"`; `linkage: "external"`; `ordering` ≠ `"relaxed"`;
  `certified_path.access.via` ≠ `"direct"`; `handler_accesses_confined: false`;
  `observers` empty.
- **The fact-layer clause, both directions**: `kind: "plain"` on a global with
  `signal_context_access: true` is rejected (the unsafe direction — it skips the
  probe requirement), and `kind: "signal_safe"` on a global with
  `signal_context_access: false` is rejected too.
- **`run.analysis.target_probes` is not a validator operand**: a manifest with
  signal-flag certificates and no `target_probes` block is **valid**, asserted so
  that nobody reintroduces the cross-section read.
- The dormant-contract test: a Phase-1 manifest carries only `plain` and
  `signal_safe` modes and passes the full validator, which is demonstrably live
  (a hand-built bad `signal_flag` payload in the same run is rejected).
- Golden classification (§7): a fixture corpus with one global of each class B–E
  regenerates with exactly the permitted changes, and the two defect signals are
  asserted to fail — a class-B global perturbed by one field, and a class-E
  global whose prior failure code was `unsupported-atomic-width` rather than a
  missing spelling. Aggregate: `not_word_sized` decreases by exactly |D| + |E|,
  and `measurement_report` is byte-identical when |E| = 0.
- A signal-flag global that fails any check has `recipe: null` and a
  `diagnostics.signal_flag.status: "recipe-withheld"` record. An `atomic` pin on
  that slot is rejected `no-recipe` **with** `accept_risk = true`, not merely
  without it. An ordinary atomic, mutex, or once-lock slot is unaffected, proving
  the rule is scoped.
- A failed slot cannot carry `atomic_mode` — asserted as a type-level property
  (`Certificate::Failed` has no such member) rather than as a validator test, and
  the schema is checked to reject a hand-written failed slot that adds one.
- Re-emission is byte-identical: `codes`, `operations`, `typedef_chain`, and
  `observers` ordering is stable across runs.

### Registry tests

- `signal`, `__sysv_signal`, and `sigaction` identify their handlers.
- A *defined internal* function named `signal` is not a registration
  (`external_only`); an internal wrapper named `signal` forwarding to libc still
  yields a registration, recognized at the inner external call.
- An unresolved registration (operand external or untargeted) still sets
  `signal_context_access`, still leaves `phase_stationarity`'s unknown effect in
  place, and widens to precise targets ∪ internal address-taken functions; a
  function that is neither is not made signal-context-accessed. A
  `volatile sig_atomic_t` behind only such a registration stays rejected.
- Bore's restore call is the regression fixture for the unresolved case: it is
  unresolved on every run and must not disturb the resolved registration's
  facts.
- A global reached by both a resolved and an unresolved registration is
  **admitted** (the existential predicate), and its certified path witnesses the
  lowest-callsite-id resolved registration, stably and independently of how many
  unresolved ones exist.

**Certified-path provenance tests** — the sharpest in the note, because the
failure they guard against is silent and total (a permitting conjunct true for
every global).

- **The `ModuleWide` case.** A handler with one unanalyzable pointer store (so
  its transitive summary is `ModuleWide`) plus a `Via::Direct` store to the flag:
  every global gets `signal_context_access: true`, and **exactly one** — the flag
  — has a certified positive path; an unrelated `volatile sig_atomic_t` in the
  same module is not admitted. Asserted as a count, so the test fails loudly if
  the query is ever reimplemented as a filtered copy of `registry_access_facts`.
- The same fixture with a **fully resolved** registration still yields exactly
  one positive global, pinning that `ModuleWide` is orthogonal to `unresolved`.
- A handler whose only access to the flag is through a pointer with a finite
  two-element candidate set has no certified path; the flag is not admitted and
  also fails `address-access-not-lowerable`, so the two rejections agree.
- A path `handler → helper → flag` over `CallDirect` edges is accepted with
  witness `path: [handler, helper]`; the same shape with an indirect middle edge
  is rejected even when the call graph resolves it to exactly one callee.
- A handler reached **only** through the address-taken widening sets
  `signal_context_access` and yields no certified path.
- Witness determinism: two direct-call paths of different lengths record the
  shorter; equal lengths record callee-order-first; the manifest is
  byte-identical across runs.
- Every certified path implies `signal_context_access` on the same global,
  checked over the whole corpus as an invariant rather than a fixture.

### Atomic-recipe tests

- Direct volatile loads/stores of certified `sig_atomic_t` succeed; an ordinary
  `volatile int` still fails `volatile-access`; a `volatile sig_atomic_t`
  **never accessed in signal context** still fails `volatile-access`; a
  `volatile _Atomic`-qualified or `const volatile` chain fails.
- A repo-local `typedef int sig_atomic_t;` used as a signal flag fails
  `signal-typedef-shadowed`; the same declaration with the typedef in a system
  header succeeds; an unrecorded typedef file succeeds (polarity rule).
- A `__thread volatile sig_atomic_t` flag fails, and so does a flag with an
  explicit `section` attribute.
- An internal global re-exported by an external-linkage alias fails, closing the
  M.8 back door. The fixture must be an actual
  `@pub_alias = alias i32, ptr @g_flag` with external linkage, not a hand-written
  PIR fixture asserting the fact: the defect was that `collect_alias_map` never
  resolves such an alias's target
  (`crates/pangs-pir/src/llvm_sys.rs:3573`), so a fixture starting from the fact
  would pass against the broken lowering. An external alias to an unrelated
  *function* does **not** reject, and `alias_exposed_globals` names the flag only
  in the aliased case.
- An alias whose aliasee is not a resolvable constant symbol blocks signal-flag
  mode for the whole module via the `alias_unresolved:` taint.
- A `volatile sig_atomic_t` on an arch with no probe fails
  `signal-atomic-not-lock-free`; an unknown triple fails the same way rather than
  inheriting a default width list. Both need a synthetic fixture with an unlisted
  triple, since the corpus is entirely `x86_64`.
- **Probe coverage is per-operation and probes do not combine**: a
  signal-context global whose recipe emits RMW certifies citing `x86_64.rmw.v1`
  and is **rejected** when only `x86_64.ldst.v1` is available; a fixture claiming
  `x86_64.ldst.v1` for an RMW recipe is rejected by the validator even though
  both probes exist in the table. This is the clause that keeps a load/store
  proof from being reused, and it has no analogue in the old width-list gate.
- A non-signal global's atomic eligibility is **unchanged** by the probe table: a
  fixture on an unlisted triple still certifies `atomic` with
  `{"kind": "plain"}` through `supported_atomic_widths`, proving the two are not
  coupled.
- Address escape, indirect access, partial-width access, bulk memory access, and
  volatile RMW all fail.
- An **external-linkage** `volatile sig_atomic_t` satisfying every other conjunct
  fails `signal-flag-external-linkage`, in both executable and library mode,
  including when `access_set_complete` is true — the case the redundancy exists
  for. An ordinary external-linkage atomic is unaffected.
- A signal flag used as a payload-publication protocol gains no acquire/release
  claim from this certificate.
- **F2**: a handler that assigns the flag *and* touches any other static-storage
  object fails `signal-handler-access-not-confined`, witnessed by the function
  and the offending object; a handler touching only the flag plus locals and
  parameters passes. That failing case is already UB in C, so the test doubles as
  a diagnostic for a pre-existing source bug.
- **F2's two sets widen in opposite directions**, both halves on one fixture: a
  handler with a `ModuleWide` transitive summary must not thereby put every
  global into `A` (which comes from `access_sites_for_global` and stays exact),
  while F2's second half *does* read the widened summary and correctly fails.
- **F2 is scoped to `A ∩ H`**, pinned by three fixtures: (a) an internal
  address-taken function touching many statics but never the flag — in `H`, not
  `A` — **passes**; (b) an ordinary caller polling the flag and writing other
  statics but never address-taken — in `A`, not `H` — **passes**, the common case
  that would reject nearly every real program if the scoping were wrong; (c) an
  internal address-taken function that both polls the flag and touches another
  static — in both — **fails**.
- **F2 subsumes the two-flag ordering hazard**, pinned by two fixtures: a handler
  writing two `volatile sig_atomic_t` flags fails confinement on **both**, with
  no whole-program condition involved; and two flags with *disjoint* confined
  handlers **both certify** in one module, which the removed sole-flag condition
  would have rejected.
- **An unresolved registration does not block certification.** A fixture
  mirroring bore — one resolved `signal(2, handler)` plus a restore call whose
  operand comes from an external return — still certifies. Its companion fixture
  asserts the unresolved registration still widens `H`, pulling in an
  address-taken flag-poller so that F2 then fails.
- An `atomic` override on a Phase-1-state global (failed slot, `recipe: null`) is
  rejected `no-recipe` even with `accept_risk = true`.

### Codegen and audit-envelope tests

- For every declared probe × width × opt level `{0,1,2,3}`: no `__atomic_*`
  reference; a `load atomic monotonic` remains in the polling loop body with the
  exit condition depending on it; a `store atomic monotonic` remains in the
  storing loop's body with none migrated to the exit block; both stores of
  `flag = 1; work(); flag = 0;` survive. An RMW probe adds the single-locked-
  instruction assertion and asserts nothing about elision.
- The assertions are positional, not count-based, proven by a negative test: a
  fixture with two adjacent loads and nothing between them, legally collapsed to
  one, **passes**.
- A probe whose codegen regression is absent or failing is rejected by the probe
  table's own test — evidence and probe land together, and there is no
  configuration path by which a probe can exist without one.
- Ledger records are deterministic (two runs produce byte-identical `ar-` ids),
  appear only when a global certifies in signal-flag mode, and carry one
  `scope: global` row per such global.
- The Rust stage refuses a toolchain outside the recorded envelope — below the
  rustc floor, unlisted LLVM major, or a triple with no row — and fails loudly.
- The host SIGINT test runs under a timeout, so a hoisted load fails as a hang
  rather than hanging CI indefinitely.

### Materialization tests

These extend `DISPOSITION.md` §9's round-trip marker harness, which already
validates the repository boundary with a fixture translator.

- The M.2 before/after program is a golden fixture: C source → C→C output →
  fixture-translated Rust → rewritten Rust, diffed at each step. The C→C output's
  declaration and access lines are byte-identical to the input; only the include
  and the marker constructor are added.
- Both `&raw` and `as *const`/`as *mut` spellings rewrite identically.
- Signed and unsigned widths map per M.3; a `pointer` class is rejected.
- Initializer bit-vector semantics: `i8 -1` emits `AtomicU8::new(255)` at
  `signed: false` and `AtomicI8::new(-1)` at `signed: true`; `i32 -2147483648`
  emits both forms correctly; an `iN` whose width differs from `size_bits` fails;
  a non-constant initializer, `undef`, and `poison` fail.
- Boolean initialization: `i8 0`/`i1 false`/`zeroinitializer` →
  `AtomicBool::new(false)`, `i8 1`/`i1 true` → `true`, and `i8 2` at boolean
  class **fails** rather than being coerced.
- The laundered-pointer case is rejected: `&G as *const _ as *const i32` followed
  by `read_volatile(p)` fails the reference inventory, even though it passes the
  count check, passes a residue scan for `read_volatile(&G)`, and compiles.
- Every non-`load`/`store` reference fails the inventory: `&G`, `addr_of!(G)`,
  passing `G` as an argument, mentioning `G` in another item's initializer.
- **The inventory is asserted to be the gate, not a redundant one**: a fixture
  constructed to pass count, type, marker, and `rustc` while failing only the
  inventory must fail the build. Without this test, an implementation that
  quietly skipped step 1 would show a fully green suite.
- A macro invocation mentioning the symbol that the rewriter cannot expand fails;
  so does a `cfg`-disabled reference. Count mismatch and missing marker each fail
  the build rather than demoting.
- The rewritten output contains no `pangs_*` symbol, and a deliberately
  un-rewritten access fails to compile, confirming the `static mut` → `static`
  safety net.

### APG bore regression

For `exe-apg_bore-O0.bc` in executable/application mode, with Andersen and no
overrides:

- `g_interrupted_xjtr_0` has `signal_context_access: true` and a certified
  positive path, witnessed by the zero-length path `["sigint_handler_xjtr_0"]`
  with `via: "direct"`;
- **no other global in the module** has a certified positive path, asserted as a
  count. The module has a second, unresolvable registration
  (`bore_search_cleanup`'s `signal(2, g_prev_sigint_handler_xjtr_0)`), so this is
  a live check that the widening does not leak into the permitting conjunct;
- its type evidence names `sig_atomic_t` and records `volatile`;
- its atomic certificate is certified in signal-flag mode;
- its chosen disposition is `atomic`;
- `unhandled` decreases from 1 to 0, `atomic` increases from 1 to 2, and overall
  disposition coverage increases from 25/26 to 26/26.

These are regression assertions only after the detailed access recipe and
materializer both pass; they must not be obtained by overriding failed guards.

### Corpus-level acceptance

The bore assertions are necessary, not sufficient — two of the three parts change
facts for every module, so acceptance is on the corpus distribution.

- After Phase 1 the distribution **may legitimately move**, in one direction and
  for one reason: a global whose sole atomic failure was `word-sized-scalar`
  caused by a missing spelling, and which passes every remaining gate including
  the access recipe, now certifies and chooses `atomic`. The predicate is on
  *cause*, not count:

  ```text
  permitted:  atomic_eligibility Failed[word-sized-scalar] → Certified,
              with no other fact or code changing
  permitted:  Certified → Failed[signal-atomic-not-lock-free], only for a global
              with signal_context_access: true whose recipe's operations are not
              covered by any probe — the gate switch correcting an unbacked claim
  defect:     any other global moving OUT of a strategy
  defect:     any global moving IN for any other reason
  defect:     any change to a global whose word_sized_scalar was already true
              and whose signal_context_access is false
  ```

  The second permitted movement is expected to be **empty** on the current
  corpus: it is entirely `x86_64`, and both probes cover 8/16/32/64. A non-empty
  result means a signal-context global emits an operation neither probe covers,
  which is a finding to report rather than absorb — the old gate was asserting
  lock-freedom for it on a pointer-width heuristic.

  A certified global whose `source_materialization` is `blocked` still counts as
  `atomic` (M.0); its execution is the materializer's problem, corrected by
  demotion if it arises. The bore flag does not move at Phase 1 — it reaches the
  detailed recipe and fails on `volatile-access`.
- After Phase 2, any global that moves is either newly `signal_context_access`
  (expected: loses `mutex`, tightens `atomic`) or newly `once-lock` from the
  removed unresolved effect (expected: strictly more precise). Any other movement
  is a defect to explain before Phase 3 lands. Phase 2 changes no schema and no
  manifest field of its own.
- After Phase 3, movement is **one-directional**: *into* `atomic` for a certified
  signal flag, and nothing else. The gate switch already happened at Phase 1, so
  a global moving *out* at Phase 3 is a defect, as is any movement by a global
  without `signal_context_access`.
- Phase 3 must report an **F2 census**, because confinement is the conjunct most
  likely to make the feature inert unnoticed: per module, the number of
  signal-flag candidates, and per candidate the size of `A ∩ H` and whether every
  member is confined. A corpus in which *most* candidates are rejected by F2
  means either the widening is too coarse or real handlers routinely touch other
  statics, and either finding should be resolved before Phase 4 rather than
  absorbed as low coverage.

## Non-goals

- Treating all volatile integers as safe atomics.
- Modeling memory-mapped I/O through Rust atomics.
- Turning `sig_atomic_t` into a general thread-synchronization primitive.
- Inferring the typedef from symbol names, use patterns, or integer width alone.
- Accepting non-lock-free atomic implementations in signal context.
- Supporting arbitrary compound operations in the first implementation.
- Weakening access-set completeness or Ω handling to improve this result.
- Relaxing the `align_bits == size_bits` condition; over-aligned scalars are a
  separate change with a separate population.
- Replacing `supported_atomic_widths`, or populating the target profile with
  arches no test exercises.
- Making the lock-free width table configurable at all: a new arch is a patch
  beside its codegen regression, not a flag.
- Signature-shape checking in the spawn/signal registry, which `AbiClass` cannot
  perform meaningfully and which no consumer needs (§D).
- Admitting `_Atomic` globals, which are a different lowering with a different
  recipe.
- Signal flags with external linkage, absent a whole-program certificate that
  every accessing TU is transformed (M.8).

## Decisions

No design question here is open. Each decision is normative and carries its
**falsifier** — the observation that must be made before it may be changed.

**D1. Typedef/qualifier evidence and the certified signal path live inside the
`atomic_eligibility` certificate** (paths frozen in §"Schema v5" §4), not as
first-class facts, holding the v5 fact-layer surface to the `word_sized_scalar`
change alone. `atomic` is a certificate-backed strategy, so `DISPOSITION.md` §1's
guard-shape rule puts its preconditions inside the pass.
*Falsifier:* a second consumer of either. Promotion to a fact slot is then schema
v6, additive, and forced by nothing else.

**D2. `supported_atomic_widths` is unchanged; the signal gate moves to
regression-backed probes, and a certificate cites exactly one.** The general
list's failure mode is a Rust compile error, the signal gate's a silent handler
deadlock; only the second warrants authoritative evidence, and replacing both
would zero the coarse atomic gate on any unlisted triple. A probe carries its
operation set because lock-freedom is not uniform across operations, which is
also what makes the gate's narrowing safe for signal-context RMW recipes rather
than a silent weakening of their proof.
*Falsifier:* the probe table and the pointer-width heuristic
(`llvm_sys.rs:407`) disagreeing for a width on a triple the corpus contains. That
is a bug report about the general atomic recipe and gets its own note; it does
not retroactively justify migrating both lists here.

**D3. Missing source spelling blocks nothing.** It makes `word_sized_scalar` true
and is recorded as a certificate diagnostic, since no stage consumes
`recipe.declaration.type_spelling` (M.0, M.3).
*Falsifier:* a materializer stage that genuinely requires the C spelling — which
would be a change to M.3's type mapping, not a discovery about this fact.

**D4. The no-elision property gets an audit contract, not a guarantee**: a
declared envelope of probes × widths × rustc floor × LLVM majors × opt levels, a
per-probe codegen regression that is a precondition for the probe existing, a
ledger record whose own text states the limit, and a Rust-stage check refusing
toolchains outside the envelope. The table has no configuration surface, so
"the probe exists" and "the regression covers it" cannot come apart, and the
certificate cites the probe by the id the ledger record names.
*Falsifier:* a codegen regression failure for a probe. The response is mechanical
and already specified — remove the probe, every certificate citing it stops being
emittable, signal-context atomics on that target fall back to `unhandled`. No
manual override.

**D4b. The certificate carries one tagged `atomic_mode`, and `signal_lock_free`
is deleted.** Its members were a duplicated fact (`required`), a value that is
`true` wherever it is meaningful (`target_guaranteed`), and a copy of
`recipe.declaration.size_bits` (`width`); and the mode itself was spread across
four fields kept in agreement by a four-way biconditional. One discriminant makes
the disagreeing states unrepresentable instead of detected, and — because
`Certificate::Failed` has no certificate-level payload — makes rule 18 a property
of the type rather than a rule to enforce. v5 is not backward compatible with v4
payloads, which is what makes deletion available rather than only extension.
*Falsifier:* a consumer that needs to distinguish "no lock-free claim required"
from "no mode recorded". There is none — `kind: "plain"` states the first and the
second does not exist — but a future variant that is genuinely optional would
reopen it.

**D5. Signal aliases are unconditional exact-name registry entries, with an
`external_only` precondition and no signature shape check.** `AbiClass` cannot
distinguish a pointer from an integer, so a shape check reduces to arity; a false
positive is conservative in every consumer that reads `signal_context_access`;
and the one non-conservative consumer, §E's volatile admission, does not read the
registration but the certified positive path, which a spurious entry cannot
manufacture. `--registry-config` covers the per-target case.
*Falsifier:* an observed program where an unrelated external `signal`/`sigaction`
symbol costs a global its `mutex` eligibility. The response is an arity check on
the entry operand's index — five lines, no type representation — not a
`RegistryShape` subsystem.

**D6. Signal-handler participation is a hard conjunct of volatile admission**,
satisfied only by a *resolved* registration with a certified positive access
path. It establishes that the `sig_atomic_t` guarantee is the operative reason
the object is volatile; MMIO and special-section storage are excluded separately
by the ordinary-storage predicate.
*Falsifier:* a corpus program with an otherwise-certifiable
`volatile sig_atomic_t` rejected solely because its registration alias is
unrecognized, *and* for which `--registry-config` is impractical. Both halves
must hold — the documented recourse existing is what makes the strict reading
affordable.

**D7. `volatile` is replaced by `Relaxed` *plus* handler-observer confinement
(F2), and F2 is the only pattern condition.** `Relaxed` supplies indivisibility
and (as an LLVM property) absence of unbounded elision, but not `volatile`'s
preservation of access count and relative order. F2 makes the permitted
transformations behavior-refining rather than merely unlikely, by establishing
that no observer can correlate the flag with anything else — signal arrival
timing being unconstrained. A sole-flag-per-program condition (F1) was
considered and removed: the program it excludes, a handler writing two flags,
already fails F2 on both, and F1 additionally rejected two independently confined
flags for no reason. Removing it also removes the only whole-program pass and the
only cross-global validator clause in the design.
*Falsifier:* an execution in which a reordering of a certified flag's accesses is
observed by something other than a handler that touches a second static-storage
object — i.e. a counterexample to F2's subsumption argument. Failing that, a
corpus program rejected solely by F2 where the pattern is nonetheless
demonstrably safe; such a program is already undefined behavior under C11
§7.14.1.1p5, and the right response is to fix the source.

**D8. A permitting conjunct is computed by its own query, not by filtering a
restricting one** (rule 14). The certified positive path requires a `Via::Direct`
access reached over direct-call edges from a precise target of a resolved
registration; restricting `registry_access_facts` to resolved registrations is
*not* sufficient on its own, because `ModuleWide` originates in the handler's
transitive summary rather than in the registration operand. The rejected
alternative is the obvious implementation and would make the conjunct true for
every global in any module containing one handler with an unanalyzable pointer
store, silently deleting it.
*Falsifier:* a module where the flag's handler reaches it only through a pointer
or an indirect call, so the path requirement rejects a genuine signal flag. This
is bounded: `atomic_access_recipe` already requires `Via::Direct` at every
admitted site (`crates/pangs-clients/src/lib.rs:1891`), so such a global could
not have certified regardless — the falsifier must show the *conjunct* is the
binding constraint, not the recipe.

The remaining unknowns are measurements, not decisions, and are enumerated under
§"Corpus-level acceptance": whether other modules contain `volatile sig_atomic_t`
globals, and how far the Phase 2 registry fix moves `phase_stationarity` results
module-wide.

The standing tie-breaker, should a question arise this note did not anticipate:
retain the current `volatile-access` failure. The goal is to recognize one
well-defined standard idiom with positive evidence, not to broaden atomic
eligibility by assumption.
