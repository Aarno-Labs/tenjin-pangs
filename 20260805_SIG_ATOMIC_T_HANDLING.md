# Handling `volatile sig_atomic_t` Globals

## Status

Design proposal. Nothing here is implemented yet. Reviewed against the working
tree on 2026-08-05; the `file:line` anchors are navigation aids verified at that
revision, not a stable interface.

The load-bearing claim is §E's: that replacing `volatile` with a `Relaxed` atomic
preserves what the source relied on. It does **not** do so on its own —
`Relaxed` permits transformations `volatile` forbids — and the condition that
makes it sound is stated as an admission conjunct (F2), not as commentary.

One asymmetry recurs and is stated once here. **Permitting vs. restricting
facts.** A fact that *restricts* (kills a strategy, tightens a gate) is
conservative when widened; a fact that *permits* is conservative only when
narrowed. A permitting conjunct may never be discharged by a restricting fact's
widening query (rule 11).

Rationale for rejected alternatives is recorded only where the rejected shape is
the *obvious* implementation and would look correct — §E's filtered-copy access
query, the materializer's count-and-residue reference check, and the removed
whole-program sole-flag condition. Everything else that was considered and cut is
simply absent; a design note is not a changelog.

Two pieces of adjacent work were deliberately **not** folded into this feature
and are enumerated in §"Spun-off work": the unbacked lock-free width heuristic
that the general atomic recipe uses, and the `atomic` strategy's materialization
contract. Neither is a prerequisite.

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

The correction has three parts:

1. Preserve structured qualified-type evidence — typedef names and qualifiers —
   rather than only the outer DWARF type name, and project the recovered spelling
   into the existing `type_spelling` (§A). This alone clears the coarse gate;
   `word_sized_scalar` keeps its current definition (§B).
2. Recognize `__sysv_signal` as a signal registration, so the async-signal
   context is a real input to the certificate (§D).
3. Keep rejecting arbitrary volatile accesses, but admit a narrowly certified
   `volatile sig_atomic_t` access mode (§C, §E).

The expected disposition for this global is then `atomic`, not `unhandled`: on
the observed APG bore module, coverage 25/26 → 26/26 and the atomic count 1 → 2,
assuming the detailed access recipe passes unchanged.

Two of the three parts are **not** local to this global:

- Part 2 changes module-wide facts: a newly recognized registration stops being
  an unresolved external effect for *every* global's phase analysis, so other
  globals' `phase_stationarity` results may move in the same run.
- Part 3 carries the only schema change — the `atomic` certificate's payload, and
  with it a version bump. **No fact changes**, so the fact layer, its validator,
  and the disposition measurement funnels are untouched.
- Part 3 is also the only genuinely narrow part, and the one that must fail
  closed.

The single-global coverage claim is therefore a consequence to verify, not the
acceptance criterion; the criterion is the whole corpus disposition distribution
(§"Corpus-level acceptance").

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

## Corpus population

Measured before Phase 1 rather than assumed, because the design's cost is only
justified by how many globals it can reach. Nine distinct
`volatile sig_atomic_t` declarations across five projects:

| Project | Declaration(s) | Linkage | Disposition under this design |
|---|---|---|---|
| apg_bore | `g_interrupted` | internal | candidate — the motivating case |
| libusb | `do_exit` | internal | candidate; F2 depends on build config (below) |
| openssl | `intr_signal` | internal | candidate — `recsig` writes it and nothing else |
| gavinhoward_bc | `bc_history_inlinelib`, `sig`, `sig_lock`, `sig_pop`, `status` | **external** | all rejected by M.3 |

Four findings, each of which changed a decision in this note:

1. **The feature is not a one-global special case.** Three internal-linkage
   candidates in three unrelated programs. Earlier drafts left the feature's
   reach as an open unknown to be settled after implementation; it is a `grep`,
   and it should have been settled first. (Phase 1's *own* movement is a separate
   and still-small quantity — see §"Corpus-level acceptance" — because a volatile
   flag does not move until Phase 3.)
2. **M.3 is the largest coverage limiter** — five of nine declarations, all of
   bc's. That is the price of refusing external linkage without a whole-program
   certificate, and it is now a measured price rather than an assumed-small one.
   bc is also the multi-flag program F1 would have been aimed at, and it is
   rejected before F2 is ever consulted.
3. **libusb is why F2 is transitive.** Its handler reaches the flag through
   `request_exit`, one direct call down, which the earlier `A ∩ H` scoping did
   not examine. In the `DPFP_THREADED` build that helper also signals a
   semaphore, so the corrected F2 rejects it. That build is genuinely undefined
   under C11 §7.14.1.1p5 — `exit_semaphore` is an ordinary static referred to
   from a handler — so this rejection costs nothing; F2 rejects some *defined*
   programs too, but not this one. The ordinary build certifies.
4. **All three candidates use the save/restore idiom**, whose restore call
   (`signal(sig, saved_handler)`) has a loaded operand and is therefore an
   unresolved registration. So `H`'s widening is live in **every** real instance,
   not as a corner case — which is why the FSA narrowing (§D) is a required part
   of the design rather than the "defensible future refinement" an earlier draft
   called it. Without it, transitive F2 over every address-taken internal
   function rejects all three.

This table is the Phase-1 baseline. A candidate appearing outside it, or one of
these four failing to behave as stated, is a finding to explain rather than
absorb.

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

**2. The coarse gate then fails on the missing spelling.** `word_sized_scalar`
(`crates/pangs-clients/src/lib.rs:2322`) requires:

```text
type spelling exists
width is nonzero and in target.supported_atomic_widths
align_bits == size_bits          (equality, not sufficiency)
scalar class exists
integer/enum signedness is known
```

The bore flag satisfies the last four and fails the first, so the whole rejection
traces to defect 1. (Whether the spelling condition belongs in this fact at all is
a separate question — the last four establish the machine-level scalar property
and an absent spelling does not make an aligned `i32` non-scalar — but answering
it is not needed here, and §B explains why it is deferred.)

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
`signal_context_access: false`; mutex eligibility is not rejected for the most
direct reason; and phase analysis retains an unresolved external effect at
registration (`crates/pangs-clients/src/phase_stationarity.rs:716,757,772` —
only a *modeled* registry callsite escapes the `has_unknown` widening).
Accepting the atomic strategy without repairing this would produce the desired
answer without proving the signal context that makes the answer
safety-sensitive.

Two properties of this registry constrain the repair:

- **It is not the Ω external-summary registry.** It is the spawn/signal fact
  registry consumed by the F-layer disposition scans and by
  `registry_target_labels`. Recognizing `__sysv_signal` does not relax the Ω
  boundary at that call: the call remains an external effect for points-to,
  mod/ref, and escape. Only the spawn/signal fact and the phase-analysis
  unresolved-effect widening change.
- **It is name-keyed, and its error directions are not symmetric.** A false
  positive is conservative in every consumer — a spurious `signal_context_access`
  kills `mutex` and tightens `atomic`'s gate. A false *negative* is not
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
    qualifiers: TypeQualifiers,          // is_const, is_volatile, is_atomic
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
because operationalizing it requires guessing at naming convention, which
misfires on legitimate project typedefs and makes the spelling depend on
identifier style.

This is the same `type_spelling` the PIR and API globals already carry; the walk
populates it in cases that previously yielded `None`, and adds the chain and
qualifiers beside it. There is no second name concept: §C recognizes a signal
flag by testing the *chain*, and the certificate records the chain, so no
"recognized name" field is introduced anywhere.

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

### B. Recover the spelling; do not redefine the fact

§A's walker is the whole fix for the coarse gate. `word_sized_scalar`
(`crates/pangs-clients/src/lib.rs:2322`) requires a type spelling among its five
conditions, and the bore flag fails **only** that one — width, alignment, class,
and signedness are already recovered correctly. Once the walk reports
`type_spelling: "sig_atomic_t"` from the typedef beneath the `volatile` node, the
fact becomes true on its existing definition and the global reaches detailed
access lowering, where it fails on `volatile-access` until §E.

**No fact changes meaning. This feature does not touch the manifest's fact
layer.** A global whose debug metadata yields no spelling at all continues to
fail the coarse gate exactly as it does today; that is unchanged behavior, not a
new rejection.

An earlier draft went further — drop the spelling requirement from
`word_sized_scalar` entirely, preserve `size_bits`/`class`/`signed` when the
boolean is false, and add a closed `codes` vocabulary for the decisive failure.
That is a real improvement and it is **deferred to its own change**, because it
is a different change addressing a different population:

- Its beneficiaries are globals with **no recoverable spelling at all** —
  anonymous or nameless terminal types, absent metadata — which is disjoint from
  the qualified-typedef population this feature repairs. Nothing here needs it:
  §C requires positive typedef evidence before it will recognize a signal flag,
  so signal-flag mode always has a spelling and never exercises the spelling-free
  path.
- It changes the meaning of a published fact carrying a schema invariant
  (`Facts::validate`'s detail/value coupling,
  `crates/pangs-manifest/src/lib.rs:430`), a cascade-adjacent role, and a
  measurement funnel (`DISPOSITION.md` §10.2). The `not_word_sized` counter
  (`crates/pangs-clients/src/lib.rs:452`) and the baselines in
  `notes/disposition_atomic_perglobal_remeasurement_2026-07-17.md` and siblings
  would stop being comparable and would need an explicit re-baselining note.
- Bundled, the two make the Phase-1 corpus diff unattributable: every global
  gaining `codes` and newly-visible partial detail would be noise around the
  handful whose spelling was actually recovered.

Kept separate, this feature's Phase-1 predicate is as tight as it gets: a global
may move **only** if its declared type is a qualified typedef whose spelling the
walk now recovers, and each movement is attributable to that global's own typedef
chain. The separate change, when it is written, owns the population above, the
`codes` vocabulary, the alignment-code split, and the re-baselining note.

**This splitting rule is applied uniformly in this note**, and is the reason the
lock-free width repair is also spun off (§"Spun-off work"): a change that moves a
gate for a population this feature does not serve makes this feature's corpus
diff unreadable, whatever its independent merit.

Rewritability stays in `source_materialization`
(`crates/pangs-clients/src/lib.rs:1310`), which keys on `meta.file`/`meta.line`
and returns `blocked` with `declaration-source-unmapped` when absent. Unchanged.

### C. Signal-flag type evidence

Signal-flag type evidence is a **type fact**, derived from debug type metadata
alone; target capability and program context are admission conditions (§E), and
mixing them reproduces the fact/policy conflation §B corrects. Derive it only
when:

```text
typedef chain contains a member of RECOGNIZED_SIGNAL_TYPEDEFS  ( = {"sig_atomic_t"} )
qualifier chain includes volatile
qualifier chain includes neither _Atomic nor const
scalar class is integer
width and alignment are known and mutually consistent
```

The evidence recorded in the certificate is the chain itself and nothing else
(normative placement in §"Schema v5"):

```json
{ "typedef_chain": ["sig_atomic_t", "__sig_atomic_t"] }
```

There is no `typedef: "sig_atomic_t"` field naming which member licensed
recognition, and no `volatile: true` field. `RECOGNIZED_SIGNAL_TYPEDEFS` has one
member, so the first would be a constant; and the variant does not exist unless
the qualifier chain included `volatile`, so the second is one too. The chain is
the evidence; the variant's existence is the claim. Recognition allows
platform-internal typedefs beneath the public name, but the public name must be
present unless a frontend supplies an equivalent explicit semantic tag. Do not
maintain an open-ended heuristic list of names resembling `sig_atomic_t`.

**What recognition is and is not.** This is a string match against a typedef
chain, so a user's own `typedef int sig_atomic_t;` passes it. **Safety does not
depend on the typedef being authentic**: what makes the rewrite correct is the
enumerated §E conjuncts — integer scalar of a lock-free width, whole-object
direct loads and stores only, complete access set, proven signal participation,
handler-observer confinement, internal linkage, ordinary storage. A shadowing
typedef satisfying all of those describes an object the transformation handles
correctly. The typedef match is an **intent signal**, not a proof obligation, and
therefore carries no provenance test: an earlier draft rejected repo-local
typedef declarations, which is a guard on an intent signal and defends nothing
the §E conjuncts do not already defend.

The evidence is carried **inside the certificate's `signal_flag` object**, its
only consumer, which holds the schema-v5 fact-layer surface to zero. Promotion to
a fact slot when a second consumer appears is schema v6 (D1).

### D. Recognize `__sysv_signal` as a signal registration

Add one exact-name entry to the built-in table, with the same entry operand as
`signal` (handler in argument 1):

```jsonc
{ "name": "signal",        "kind": "signal", "entry": { "arg": 1 } }
{ "name": "__sysv_signal", "kind": "signal", "entry": { "arg": 1 } }
{ "name": "sigaction",     "kind": "signal", "entry": { "pointee_of_arg": 1 } }
```

Candidates such as `bsd_signal` are added the same way, each with a regression
fixture. `RegistryEntryResolution` and `resolve_registry_entries` are otherwise
unchanged.

**A declaration precondition.** The entry applies only when the callee is an
**external declaration**. A *defined internal* function named `signal` is not
libc's, and the analysis already models its body; if that function forwards to
libc, the inner call is itself a name match against an external declaration. This
precondition is silent — nothing is unverified, so a diagnostic would be noise.

#### Shapes are internal and built-in only

The three signal entries carry a **shape** — arity and non-varargness, checked
against `Callsite.sig`:

```text
BUILTIN_SIGNAL_SHAPES         (a private constant in pangs-api)
  signal          arity 2, not vararg
  __sysv_signal   arity 2, not vararg
  sigaction       arity 3, not vararg
```

A signal entry carries a second, unrelated signature fact: the **handler
envelope** consumed by §E's `H_f2` narrowing. The shape describes the
*registration function*; the envelope describes the *handler* it may install, and
`sigaction`'s is a two-element set. They live beside each other in the same
private table but are never conflated, and their error directions differ — an
over-broad shape costs precision, an over-narrow envelope is unsound.

Four properties define the mechanism, and the first two are what make it cheap:

- **It is not a field on `RegistryApi`.** The shapes live in a separate private
  table keyed by name, so `RegistryApi` — the type `--registry-config`
  deserializes — is genuinely unchanged and there is no serde field that could
  leak into the configuration schema by accident. `RegistryShape` as a public,
  configurable type is a non-goal until a real user-defined alias needs one.
- **User-provided entries stay unchecked**, retaining exactly their current
  conservative behavior. This is not an oversight to be tidied later. A built-in
  entry is applied to every module without the operator asserting anything, so
  the analysis is the party making the claim and should check what it can; a
  `--registry-config` entry *is* the operator's assertion about their own
  program, and that channel already means "I know my target". The asymmetry
  follows from who is claiming what.
- **A user entry replacing a built-in by name replaces its shape too** — that is,
  the replacement is unchecked. This is the escape hatch: an operator whose
  platform declares `signal` with a shape the table does not expect re-declares
  the entry and gets the unchecked path, with no code change and no new flag.
- **Arity and vararg only.** `AbiClass` cannot distinguish a pointer from an
  integer — both `int` and `void (*)(int)` are `AbiClass::Integer`
  (`pangs-pir/src/lib.rs:640`) — and under opaque pointers no LLVM type
  inspection recovers the difference, so parameter *types* are not available to
  check and never will be through this channel. Calling convention is
  deliberately excluded: `cc` variation on these three libc names is a
  portability trap rather than a discriminator.

**Scope: signal entries only.** `pthread_create` and `thrd_create` stay unshaped.
The reason is not that spawn collisions are less likely but that the two failure
directions differ. Dropping a spurious *signal* registration loses only
restricting facts, and the cost of keeping one is the documented over-conservatism
D6's falsifier names (a global losing `mutex` eligibility to an unrelated
`signal` symbol); the one consumer for which a false positive would *not* be
conservative, §E's volatile admission, is independently protected by the
certified-path requirement. Dropping a spurious *spawn* registration instead
weakens a certificate — phase-stationarity's thread-writer kill rule — with no
independent backstop, for no observed benefit. If a spawn-name collision is ever
observed, the extension is one more row in the same private table.

**A shape mismatch is not a registration.** This is the one place a name match is
refused, and it must be read against the never-delete rule below, which it does
not contradict:

| Situation | What it means | Treatment |
|---|---|---|
| built-in name, shape matches, operand unresolved | it **is** libc's `signal`; we do not know the handler | registration, unresolved (never deleted) |
| built-in name, shape mismatches | it is **not** libc's `signal` — a different function wearing the name | not a registration, with a diagnostic |
| user-configured name, any shape | the operator asserted it | registration, unchecked |

Deleting on operand unresolution would discard a real registration; declining on
shape mismatch discards one that was never there. The residual risk is the table
being wrong for some platform: bounded by three names whose shapes are fixed by
C89 and POSIX and stable across targets, made visible by the diagnostic rather
than silent, and recoverable through `--registry-config`. That combination is why
the check can afford to be refusing rather than merely marking.

**Resolution stays two-valued, and an unresolved operand is never a deletion.**
Dropping a signal registration is not uniformly conservative:

| Consumer | Effect of dropping the registration | Direction |
|---|---|---|
| `phase_stationarity` | keeps the `has_unknown` widening | safe |
| `mutex_eligibility` | loses the `signal-context-access` rejection | **unsafe** |
| `atomic_eligibility` | skips the signal lock-free gate | **unsafe** |
| §E volatile admission | conjunct fails, access rejected | safe |

So a name match on an external declaration of the expected shape **is** a
registration, and the only remaining question is whether its handler operand
resolves — which
`resolve_registry_entries` already answers as
`unresolved: external || !targeted` (`crates/pangs-api/src/lib.rs:4303`). An
unresolved registration still sets `signal_context_access` and still widens
every restricting consumer; it does **not** satisfy §E's admission conjunct,
which requires a resolved registration with a certified path. Volatile admission
is the one place the fact *permits*, so it takes the strict reading.

**How an unresolved registration widens — two sets, frozen:**

```text
H_fact(u) = precise targets ∪ { f : f.address_taken ∧ ¬f.external }
H_f2(u)   = precise targets ∪ { f : f.address_taken ∧ ¬f.external
                                    ∧ ∃ s ∈ envelope(u.api) : fsa_compatible(f, s) }
```

`H_fact` is existing behavior (`crates/pangs-clients/src/lib.rs:777-783,
838-841`), unchanged: the widened set is `address_taken_entries`, *chained onto*
the precise targets rather than replacing them, and it is what
`signal_context_access` is computed from. **All internal functions** is strictly
wider and buys nothing, since a function whose address was never taken cannot be
a registration operand.

`H_f2` is the same set intersected with the FSA signature envelope, and is used
**only** by F2.

**The envelope is a property of the registry entry, not a constant.** This is the
one place where getting it wrong is unsound rather than imprecise, because
narrowing a restricting test's domain is the permissive direction:

```text
envelope(signal)        = { void (int) }
envelope(__sysv_signal) = { void (int) }
envelope(sigaction)     = { void (int),  void (int, siginfo_t *, void *) }
envelope(anything else) = ⊥            → no narrowing; fall back to H_fact
```

`sigaction` needs both shapes because `struct sigaction`'s first member is a
union: `sa_handler` is `void (int)`, and `sa_sigaction` — selected by `SA_SIGINFO`
in `sa_flags` — is the three-argument form. A hardcoded `void (*)(int)` envelope
would exclude a genuine `sa_sigaction` handler from `H_f2`, and F2 would then
certify a flag without ever examining the function that may actually run as its
handler. The union is taken **unconditionally**, not conditioned on proving which
member is live: recovering `SA_SIGINFO` from the `sa_flags` store is a real
analysis for a narrowing this design does not need, and an unproven flag would
have to fall back to the union anyway.

Under opaque pointers the three-argument shape is `void (i32, ptr, ptr)`;
`siginfo_t *` and `void *` are indistinguishable and nothing here depends on
telling them apart.

**`⊥` means no narrowing, not no certification.** A signal-kind entry with no
declared envelope — any entry supplied through `--registry-config`, or a future
built-in added without one — contributes its unnarrowed `H_fact` widening to
`H_f2`. That is sound (a wider domain makes F2 harder to pass) and degrades
gracefully into today's behavior rather than refusing outright. It also keeps the
user-configuration story consistent: an operator-supplied entry is unchecked and
conservative in the registry (§D), and unnarrowed and conservative here.

Three things make the `H_fact`/`H_f2` split necessary rather than cosmetic:

- **F2 degrades badly over `H_fact`.** Every candidate in the corpus has a
  save/restore idiom whose restore call is an unresolved registration, so the
  widened set is live in every real instance. F2's relevance filter (`H_g`,
  below) prunes candidates that cannot reach the flag, so the exposure is not
  simply "every address-taken function is checked" — it is narrower and worse:
  **any single candidate with a `ModuleWide` transitive summary may reach every
  global, joins `H_g` for every flag in the module, and fails.** In a module the
  size of openssl or libusb, at least one address-taken function with an
  unanalyzable pointer store is close to certain. FSA narrowing cuts the
  candidate pool to functions that could actually be a handler for the API that
  registered them, which is what keeps that near-certainty from making the gate
  inert.
- **Narrowing is sound only against a complete envelope.** A registration operand
  is an ordinary indirect function-pointer value, and FSA compatibility is already
  the pipeline's soundness-preserving filter on exactly that (`DESIGN_lite.md`
  §2F: FSA intersection is applied as a final filter on icall results). A function
  incompatible with **every** shape the API can accept cannot be reached through
  that operand, so `H_f2` remains an over-approximation of the true handler set —
  but only if `envelope(api)` lists every such shape. That is why the envelope is
  per-entry, why `sigaction` carries two shapes, and why an entry with no declared
  envelope narrows nothing (rule 10). No new machinery is introduced; this is the
  existing
  envelope applied to a new consumer.
- **No published fact moves.** Narrowing is the *permissive* direction for a
  restricting test, so it may not be applied to `signal_context_access`, which
  keeps `H_fact` and its current values everywhere. The narrowing is confined to
  a conjunct this feature introduces, so it can regress nothing — which is also
  why it needs no measurement phase of its own.

An FSA-narrowed `signal_context_access` would be a real precision improvement and
is **not** taken here: it would move a published fact, restore `mutex`
eligibility for globals that currently lose it, and require its own corpus
diff — §B's splitting rule again.

After this fix, accesses reachable from `sigint_handler_xjtr_0` set
`signal_context_access: true`, and mutex remains unavailable because a signal
handler cannot safely take the proposed mutex.

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
the global has signal-flag type evidence                          (§C)
the global has internal linkage                                   (M.3)
the global is ordinary storage: no section, not thread-local,
  no aliased global in the module                                 (below)
the module's arch and the declaration's width are in
  SIGNAL_FLAG_LOCK_FREE                                           (below)
every access satisfies the ordinary atomic recipe constraints
the access set is complete and every site is in the admitted operation set
the handler analysis yields a certified registration              (below)
every h ∈ H_g is transitively confined to this flag alone         (F2, below)
```

F2 is the *pattern condition*, derived under "Why dropping `volatile` is
admissible". It is not hygiene: `Relaxed` does not preserve access count or
relative order, and the argument that this is harmless holds only for a flag
whose sole role is to convey signal arrival.

The certified-registration conjunct is what makes the C standard's `sig_atomic_t`
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
is_definition == true ∧ constant initializer present   (already required by the
                                                        atomic eligibility pass)
linkage == internal                                    (M.3)
no explicit section attribute                          (needs a new PIR fact)
not thread-local                                       (needs a new PIR fact)
module has no aliased global                           (needs a new PIR fact)
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
not a predicate over any fact that exists (rule 12). Nor does `bump_tainted` gate
anything: it writes `LoweringStats::tainted_counts`, a metrics counter
(`crates/pangs-pir/src/lib.rs:479`) read only by assertions in
`crates/pangs-pir/tests/llvm_lowering.rs`. `violation_taint` is unrelated —
module-wide it is `module_violation_tainted`, testing for inline assembly
(`crates/pangs-solve/src/lib.rs:1222`); per-global it comes from violation
findings (`crates/pangs-clients/src/lib.rs:209-210`). This matters because M.3
rejects external linkage to prevent mixed atomic/non-atomic access across a TU
boundary, and an external-linkage alias re-exports that storage under another
name — the same hazard through a back door.

**The fix — one module-level bool.** Move
`constant_symbol_name(LLVMAliasGetAliasee(*alias))` above the interposability
check. Set a new `LoweringStats::alias_exposes_global: bool` (`#[serde(default)]`)
when any non-internal alias resolves to a known **global**, *or* when any
aliasee fails to resolve at all. The §E clause is `!alias_exposes_global`.

Three properties:

- **Resolution is separated from modelling** — the alias is still dropped from
  `AliasMap` exactly as today, so nothing about points-to, escape, or the Ω
  boundary moves.
- **An unresolvable aliasee sets the bool**, so the gap is closed by the same
  fact rather than by a second rule; there is no `alias_unresolved:` special case.
- **A function alias does not set it.** Blocking the feature on *any*
  `alias_`-prefixed taint was rejected for exactly this reason — external aliases
  to unrelated functions are ordinary — and this is the cheapest predicate that
  distinguishes them.

A per-global `BTreeMap<String, BTreeSet<String>>` inventory would be more precise
and is not worth its surface: it buys signal-flag mode in a module that contains
an aliased *global* unrelated to the flag, which no corpus module exhibits. What
must **not** happen is a third option: a clause no fact can evaluate, which an
implementer would most plausibly discharge by writing `false`.

The registry work (§D) is a hard prerequisite: without it the bore flag has
`signal_context_access: false` and is correctly rejected. That is the desired
failure mode — the idiom is admitted only where the analysis can see the signal
context that gives it meaning.

#### Handler analysis: `A`, `H`, `H_g`, the certified registration, and F2

The certified access path and F2 need overlapping inputs, and are computed by
**one pass**, not two queries. Every set below is per-module except `A` and
`H_g`, which are per-flag:

```text
A    =  functions containing an admitted access site on the flag
        (from access_sites_for_global; exact, every site via == Via::Direct)

H    =  registry handler targets over ALL registrations, FSA-narrowed
        (precise targets for resolved ones, plus §D's H_f2 widening
         for unresolved ones)

R    =  { f ∈ H : f is a PRECISE target of a RESOLVED registration }

H_g  =  { h ∈ H : transitive_accesses(h) MAY contain g }     ← F2's domain
```

The pass yields three things: the certified registration (below), the F2 verdict,
and `H_g`, recorded as `observers` — the set F2 was actually evaluated over.
Recording the module-wide `H` there would name functions F2 never examined, which
is worse for an auditor than naming none. Membership is recorded as bare function
identities: how each observer entered `H` (precise resolved target vs. the
address-taken widening) is re-derivable from the module's registration facts, and
F2 checks every member identically regardless.

**The certified registration.** The conjunct holds for a global `g` when there
exists a path `f₀ → f₁ → … → fₙ` (n ≥ 0) where `f₀ ∈ R`, every edge is a
`Stmt::CallDirect` to a defined internal function, and `fₙ ∈ A`. Everything
weaker is rejected:

| Provenance | Sets `signal_context_access` | Satisfies the §E conjunct |
|---|---|---|
| `Via::Direct` site, direct-call path from a member of `R` | yes | **yes** |
| `Via::Aliased` / `Via::Unknown` site (pointer access, finite candidate set) | yes | no — a *may* set is not positive proof |
| `AffectedGlobals::ModuleWide` | yes | **no** — the case the rule exists for |
| any indirect-call edge on the path | yes | no — the call graph over-approximates exactly there |
| target from the address-taken widening | yes | no — the widening is a guess at who the handler is |

**Why this is its own query and not a filtered `signal_context_access`.**
`signal_context_access` is one `EvidencedBool`
(`crates/pangs-manifest/src/lib.rs:400`, `DISPOSITION.md` §2), true for resolved
*and* unresolved registrations alike, computed by a widening query. It comes from
`transitive_accesses`, whose per-payload target set is
`AffectedGlobals::ModuleWide` whenever the access is through a pointer with no
finite candidate set (`crates/pangs-api/src/lib.rs:2093-2096`), and
`registry_access_facts` then sets the mask on **every global in the module**
(`crates/pangs-clients/src/lib.rs:848-852`). Cloning that computation for the
permitting conjunct would be a soundness hole: one handler with an unresolved
transitive effect would satisfy §E's conjunct for every global in the module for
free. `ModuleWide` is **orthogonal to `unresolved`** — it comes from the handler's
own transitive summary, not from the registration operand — so restricting to
resolved registrations does not avoid it. The restriction must be on the access
path, which is why `A` is built from `access_sites_for_global`
(`crates/pangs-api/src/lib.rs:2012`), carrying `via` and `func` per site, and
walked backwards over direct-call edges (D2). This is the one place in the design
where the obvious implementation is the wrong one, and a code comment at the query
should say so.

`AffectedGlobals::Finite` is returned both for `GlobalTarget::Name(g)` — one
element, exact — and for `GlobalTarget::Unknown(_)` with a finite candidate set,
which may also be one element (`crates/pangs-api/src/lib.rs:2091-2097`), so the
tiers are indistinguishable through `transitive_accesses` in any case.

**This costs less than it appears.** The admitted access set already requires
`via == Via::Direct` at every site, since `atomic_access_recipe` fails
`address-access-not-lowerable` otherwise (`crates/pangs-clients/src/lib.rs:1891`).
The rule aligns the *conjunct* with a restriction the *recipe* already enforced.
For bore the path has length zero — `sigint_handler_xjtr_0` is a precise target
of the resolved `signal(2, …)` and contains a `Via::Direct` store to the flag.

The predicate is **existential over resolved registrations**, not universal: a
global reached by one resolved and three unresolved registrations is admissible,
because one resolved registration fully supplies the positive proof and
additional unresolved ones widen `H` without undermining evidence that already
exists.

**What is recorded, and its determinism.** The certificate carries the triple
`{ callsite, file, line, handler: f₀, accessor: fₙ }` — not the intermediate
path, which is recomputable from the fixed call graph and whose storage would
force a shortest-path tie-breaking rule for no consumer. Determinism: the
resolved registration with the lowest callsite id, then the lowest accessor
function id. `signal_context_access` keeps its existing first-wins witness and is
otherwise untouched — same semantics, same widening computation, same consumers.

**F2. Handler-observer confinement** — a hard conjunct of certification:

```text
F2(g)  ≡  ∀ h ∈ H_g :  transitive_static_accesses(h) ⊆ { g }
```

Failure code `signal-handler-access-not-confined`, witnessed by the offending
function and object.

**Both halves read the same may-summary, and both err toward rejection.** A
handler enters `H_g` when its transitive access set *may* contain `g`, and is
then required to touch nothing else. Widening the membership test adds functions
to be checked; widening the confinement test makes them harder to pass. So
`AffectedGlobals::ModuleWide` is doubly safe: it may contain `g`, so the handler
enters `H_g`, and it may touch everything, so it fails. One query, one direction,
no place where an over-approximation helps a global certify.

**The relevance filter is per-flag, and it is not optional.** F2 ranging over the
module-wide `H` would make two disjoint flags mutually exclusive — certifying
`flag_a` would examine `handler_b`, see `flag_b`, and reject — which contradicts
both the F1-subsumption argument below and the design's claim that two
independently confined flags in one module both certify. `H_g` is what makes
F2 a statement about `g` rather than about the module.

**But the filter must be transitive, not syntactic.** An earlier revision
computed relevance as `A ∩ H`, intersecting the handler set with functions that
*syntactically* contain an access site, and libusb's `do_exit` walks straight
through the resulting hole:

```c
static void sighandler(int signum) { request_exit(1); }
static void request_exit(sig_atomic_t code) {
    do_exit = code;
    semaphore_give(exit_semaphore);   /* threaded build: a second static */
}
```

`request_exit` is in `A` but is not address-taken, so not in `H`; `sighandler` is
in `H` but contains no access site, so not in `A`. Their intersection is empty and
the earlier condition passed vacuously — while the handler's *execution* writes
both the flag and another static, which is exactly the correlation F2 exists to
forbid. Under `H_g`, `sighandler`'s transitive set contains `do_exit`, so it is
examined and fails on `exit_semaphore`. The observer is a handler **execution**,
not a handler function, so both the relevance test and the confinement test have
to close over what that execution can reach.

The correction also makes F2 cheaper: `H_g` and the confinement check are two
reads of one transitive summary, with no grouping of recipe sites by enclosing
function. `A` is still computed, but now serves only the certified registration.

Two scoping properties keep F2 from rejecting every real program. A function that
cannot run as a handler is never examined, so an ordinary main-loop poller may
touch as many statics as it likes; and `H` is FSA-narrowed (§D), without which
every address-taken internal function is a candidate and any one of them with a
`ModuleWide` summary joins `H_g` for every flag in the module.

**F2 is not C11 §7.14.1.1p5 restated, and it is not free.** The C rule is the
inspiration, and much of what F2 rejects is indeed already undefined behavior —
libusb's threaded build refers to `exit_semaphore`, an ordinary static, from a
handler, which is exactly what §7.14.1.1p5 forbids. But the two conditions are
**incomparable**, in both directions:

- **F2 is stricter where it matters most.** C permits a handler to assign to
  *any number* of `volatile sig_atomic_t` objects; the exception is not limited
  to one. A handler doing `flag_a = 1; flag_b = 1;` is defined C, and F2 rejects
  it — for both flags. That is a deliberate coverage cost, and the reason is the
  transformation, not the standard: two flags written by one handler are exactly
  the correlation `Relaxed` no longer preserves (below), so admitting them would
  make the substitution unsound even though the source was legal.
- **F2 is laxer in one narrow respect.** C's exception is *assignment*-specific,
  so a handler that merely **reads** the certified flag is already undefined,
  while F2 permits it provided the handler touches nothing else. Nothing in the
  correctness argument needs a read to be forbidden — a handler reading only the
  flag correlates it with nothing — so F2 does not inherit that restriction.

So the honest statement is that **F2 is a transformation-specific noninterference
condition inspired by the C restriction**, not a restatement of it, and "it only
rejects programs that were already broken" is a claim this design does not get to
make. What can be said is narrower and still useful: a large fraction of F2's
rejections *are* pre-existing UB and are worth surfacing as such, and the
remainder — multi-flag handlers — are legal programs the transformation
deliberately declines, with `unhandled` as their outcome.

**Why F2 is the only pattern condition.** An earlier revision added F1: at most
one certified flag per program, because with two, the interrupted code can
observe an ordering the compiler no longer preserves — `flag_a = 1; flag_b = 1;`
in a handler, read in the other order by the main loop. F2 already excludes that
program: the handler writes two static-storage objects, so it fails confinement
on both flags. The general argument:

- A reordering of the flag's accesses is observable only by an execution that
  *reads the flag*.
- The only **asynchronous** observer is a signal handler execution — asynchronous
  meaning it may interleave at an arbitrary point in ordinary execution. Which
  side performs the writes is irrelevant and the argument does not depend on it:
  admitted accesses occur on both sides in every corpus candidate (handlers set
  the flag, ordinary code polls it, and bore's initialization also clears it).
  Other threads are not observers here because `volatile` never ordered the flag
  against anything they could see, so they were already unordered — see below.
- A handler execution that reads or writes the flag has the flag in its
  transitive access set, hence is in `H_g` by construction, and F2 forbids that
  set from containing any other static-storage object — so it cannot correlate
  the flag with anything else. The transitive reading is load-bearing at exactly
  this step: under the earlier `A ∩ H` scoping it was simply false whenever the
  access sat one call below the handler, and F1's subsumption argument failed
  with it.

The converse cases are vacuous. *Main writes both flags, one handler reads one*:
comparing would require the handler to touch the second, which F2 forbids. *Two
flags with disjoint confined handlers*: neither handler can see the other's
object, and between two independent deliveries there is no program order to
preserve — and, concretely, `handler_b ∉ H_flag_a`, so certifying `flag_a` never
examines it. *Flag plus an ordinary object published by ordinary code*: again the
observer must read both, and F2 rejects it. So F2 subsumes F1, at finer
granularity — two independently confined flags in one module both certify, where
F1 rejected both without picking a winner. This is also the property that fails
if `H_g`'s relevance filter is ever dropped in favour of the module-wide `H`:
disjoint flags would become mutually exclusive, which is F1 reintroduced by
accident and strictly worse, since it would reject both rather than pick one. It is recorded here because F1 is a
plausible-looking condition someone will re-propose, and because removing it
removed the design's only whole-program pass and only cross-global validator
clause.

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

Relaxed ordering matches the flag's narrow role: it communicates a scalar stop
condition and does not publish other memory. A future case that uses the flag to
publish payload state needs a separate synchronization proof and must not inherit
acquire/release semantics from this rule. The materializer lowers the declaration
and every certified access as one consistent atomic representation, never mixing
volatile raw accesses and atomic accesses to the same storage.

#### Lock-free width: a checked-in constant, not the existing heuristic

The existing signal gate reads `target.supported_atomic_widths`, which
`module_target_info` (`crates/pangs-pir/src/llvm_sys.rs:407`) computes as
`[8, 16, 32]` plus 64 when the pointer is 64-bit — a pointer-width heuristic that
asserts 8/16/32-bit atomics on every target regardless of whether the target has
them, and says nothing about lock-freedom versus an `__atomic_*` libcall. Using
it as an async-signal safety gate (`crates/pangs-clients/src/lib.rs:1113,1217`)
states a guarantee the value does not carry. **That is a real defect, it predates
this feature, it affects every signal-context global rather than signal-flag ones,
and repairing it is spun off (§"Spun-off work") under §B's splitting rule.**

Signal-flag mode does not rely on it. It carries its own closed constant:

```text
SIGNAL_FLAG_LOCK_FREE : arch -> widths          (load and store only)
  x86_64 -> { 8, 16, 32, 64 }        (only 32 is exercised: sig_atomic_t is int
                                      on every target in the corpus)
```

- **Key.** The normalized architecture component of `TargetInfo.triple`, already
  captured (`crates/pangs-pir/src/llvm_sys.rs:412`). Lock-freedom is an ISA
  property, so vendor, OS, and environment are ignored; normalization is the arch
  component plus a small alias map (`amd64`, `x86_64h` → `x86_64`). An absent,
  unparsable, or unlisted arch fails closed.
- **One row in v1.** The corpus is 71 modules and 100% `x86_64-*-linux-*`, and a
  row no test exercises is a liability. The arch omissions are decisions:
  `arm`/`thumb`, where 64-bit lock-free load/store depends on sub-arch (`ldrexd`)
  the arch component does not determine; `riscv32`/`riscv64`, where atomics come
  from the `A` extension, a feature rather than an implication of the arch
  string; and 32-bit x86, where 64-bit lock-free load/store needs i586+
  (`cmpxchg8b`/x87), so `i386` and `i686` cannot share a row.
- **Load and store only.** The table makes no RMW claim because §E admits no RMW
  operation. A later RMW extension adds its own table with its own regression;
  the two are never combined to cover an operation set between them.
- **CPU features are not consulted.** The row lists only widths lock-free on the
  arch's *baseline* subtarget; enabling features can add lock-freedom but never
  remove it, so ignoring them errs closed, and an arch with an ambiguous baseline
  gets no row rather than an optimistic one. Per-function `target-features`
  attributes are deliberately not read: they are per-function, frequently absent
  in `-O0` bitcode, and would make a module-global fact depend on which function
  carried an attribute.
- **Authority** is the Rust target definition, not LLVM's, since the consumer is
  generated Rust: `rustc --print cfg --target <triple>`, reading
  `target_has_atomic_load_store`.
- **No configuration surface.** There is no flag, no narrowing, and no
  evidence-bundle mechanism. A row is admissible **only** if the in-tree codegen
  regression below covers it, so the only way to add an arch is to add it beside
  its regression, in a reviewed patch. A configuration path whose honest use is
  "re-run the in-tree regression and paste its output" is the same act with the
  review removed, and for a gate whose failure mode is a silent handler deadlock,
  "audited" is not a substitute for "tested".

**The certificate records no target member.** The arch and width are properties
of the run and the declaration, not of the mode: the width lives once in
`recipe.declaration.size_bits`, and the arch appears in the ledger record (below)
and in `run.analysis`. The auditable chain is certificate → ledger record →
in-tree regression, and it does not need an id in the certificate to be followed.

**The bore case.** `x86_64-unknown-linux-gnu` normalizes to `x86_64`, the flag's
recipe emits loads and stores at 32 bits, and the row covers it. No corpus module
exercises the empty default; the fail-closed path is asserted by a synthetic
fixture with an unlisted triple.

#### Why dropping `volatile` is admissible, and what remains assumed

`volatile` gives three things; `Relaxed` (LLVM `monotonic`) gives the first,
gives the third only as a compiler property, and does not give the second:

| | `volatile` | `Relaxed` / `monotonic` |
|---|---|---|
| **(i)** indivisibility of a width-appropriate access | not guaranteed by C; supplied here by `sig_atomic_t` + the lock-free row | guaranteed |
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

**The single residual assumption.** After F2, exactly one thing is assumed: *a
`monotonic` load or store inside a loop is re-executed on each iteration — the
compiler does not hoist, sink, or promote it out.* C11 §7.17.3 and the Rust
memory model only say a relaxed store *should* become visible in finite time, so
this is a quality-of-implementation property; in LLVM it holds because LICM's
hoist and promotion paths require `isUnordered()`. Reducing the residual to this
one statement is the point: it is a property a codegen regression can assert, in
both directions. It is still an assumption, and belongs in the audited soundness
inventory (`DESIGN.md` §8); Phase 4's dynamic SIGINT test exercises it.

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

**Record shape.** No audit-schema change is required: `kind` is a free string and
the schema is `additionalProperties: true`, so the payload rides in
`AuditRecord.extra`. `AuditRecord::regenerate_id`
(`crates/pangs-manifest/src/lib.rs:1392`) hashes the whole record, so its content
is drawn from repo constants and the module's own target facts, keeping the id
stable. One run-scoped record, emitted only when at least one global certifies in
signal-flag mode, plus one `scope: global` record per such global. Rows are
self-contained and do not cross-reference.

```jsonc
{
  "id": "ar-…",                                  // content hash, per §1.4
  "kind": "signal-flag-codegen-assumption",
  "scope": { "kind": "run" },
  "source": "analysis",
  "text": "Certified signal-flag atomics assume the Rust backend does not hoist, sink, or promote a Relaxed atomic load or store out of a loop, and lowers load/store of the certified width without a library call. Bounded transformations that Relaxed permits (redundant-load elimination, dead-store elimination, coalescing) are not assumed against; certification requires the F2 confinement condition, under which they are behavior-refining. This is a quality-of-implementation property, not an abstract-machine guarantee, and it is asserted by the in-tree codegen regression for this arch rather than proven.",
  "context": {
    "triple": "x86_64-unknown-linux-gnu", "arch": "x86_64",
    "widths": [32], "operations": ["load", "store"],
    "regression": "tests/codegen/signal_flag_x86_64"
  }
}
```

`context` names the artifact an auditor re-runs. It is **not** a machine-checked
envelope: an earlier draft added `rustc_min`, an LLVM-major allowlist, and opt
levels, plus a Rust-stage check refusing any toolchain outside them. That is
dropped, because the enforcement is not what makes the property true and its
practical failure mode is builds refusing on a newer toolchain that is fine. The
in-tree regression runs on whatever toolchain is present, which is the actual
detector; the assumption is one every Rust program that polls an atomic in a loop
already depends on. See D4's falsifier for what would reopen this.

**Codegen regression, per arch row.** The audited property is *absence of
unbounded elision*, not preservation of access count, so the assertions are
positional. For the declared arch at opt levels `{0,1,2,3}` (one width — elision
is one LICM code path and does not vary with the integer width), compile fixtures
and assert:

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

**The v5 fact-layer delta is empty.** Every change lives inside the
`atomic_eligibility` certificate payload; `Facts`, its validator, and its schema
definition are untouched. The version bump exists because that payload is
restructured incompatibly (§4), not because any fact moved.

**The bump lands in Phase 3, not Phase 1.** Phase 1 is the §A walker and changes
no schema at all; it moves values on existing fields under unchanged invariants.
There is therefore no dormant contract, no "v5 must land whole" requirement, and
no window in which two shapes both call themselves v5 — the version changes in
the same phase that changes the payload.

### 1. Encoding conventions

Already the manifest's conventions, restated so the new fields do not invent
alternatives.

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

### 2. The fact layer, unchanged

`facts.word_sized_scalar` keeps its v4 definition exactly: five conditions
including `type_spelling`, and `Facts::validate`'s detail/value coupling
(`crates/pangs-manifest/src/lib.rs:429-441`) requiring detail presence to match
the boolean. No `codes` array, no partial-detail retention, no change to
`meta.type_spelling`, which remains required-but-nullable. §B states what a later
change would do here and why it is not this one.

What moves is what the *walker* reports into that unchanged field:
`type_spelling` is now populated for a qualified typedef where it previously came
back `None`. That is a value change on an existing field with an unchanged
contract — visible in goldens (§6 class C/D), invisible to every validator.

`facts.signal_context_access` is likewise unchanged, and gains one reader: §4's
value coupling requires the certificate's mode variant to agree with it.

### 3. Version handling

**There is one live contract.** No consumer reads a v4 manifest, so
`Facts::validate` keeps its current signature, there is no dual-invariant path,
and a document is either validated or refused by the existing version gate
(`crates/pangs-manifest/src/lib.rs:903-904`). v4 fixtures are regenerated, not
grandfathered.

A **stage-consistency defect this bump makes reachable** is spun off rather than
fixed here (S3): `pangs-dispose` never reads or writes `schema_version`, so a v5
dispose fed a v4 analysis manifest emits a document *labelled v4* containing
v5-shaped dispose sections. It is a pre-existing gap in `DISPOSITION.md` §3.3's
stage-ownership rule, it is not specific to this feature, and it has its own
test. It is nonetheless the one spun-off item with an ordering constraint:
**Phase 3 must not ship before S3 lands**, because the version bump is what makes
the mismatch reachable in practice.

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
    └── signal_flag?                       ← ABSENT unless admitted under §E
        ├── typedef_chain: ["sig_atomic_t", "__sig_atomic_t"]         (§C)
        ├── registration                                              (§E)
        │   ├── callsite, file, line
        │   ├── handler:  "sigint_handler_xjtr_0"   // f₀ ∈ R
        │   └── accessor: "sigint_handler_xjtr_0"   // fₙ ∈ A
        └── observers: ["sigint_handler_xjtr_0"]    // H_g, F2's domain
```

**One optional object replaces four coupled fields.** A previous draft spread the
mode across `recipe.volatile_semantics`, `signal_atomic_type`,
`signal_flag_pattern`, and `signal_lock_free.required`, and then spent a four-way
biconditional making them agree. **There is no presence coupling in v5**; it was
the cost of encoding one fact four times. Presence *is* the discriminant: the
object exists exactly when the §E conjunction held, so "mode asserted, proof
absent" is unrepresentable rather than detected.

**It is an optional member, not a tagged union.** A draft made this an
`atomic_mode` enum with a `plain` variant, on the reasoning that "no mode
recorded" should not be a state a reader interprets. With one non-plain variant
that reasoning does not bite: absence has exactly one meaning, and `plain` is a
tag carrying no information on every atomic in the corpus. A discriminant earns
its keep at two or more informative variants — which is S1's problem, since a
`signal_safe` mode would arrive with a probe reference. Introducing the union
there is additive and S1 bumps the schema anyway; introducing it here is
generality bought for a change that has not been written.

**`signal_lock_free` is deleted, not moved.** Its three members were a duplicated
fact, a constant, and a copy: `required` was `facts.signal_context_access`;
`target_guaranteed` is `true` in every certificate where it means anything, since
a false value means the global produced no certificate; and `width` was
`recipe.declaration.size_bits`. It also emitted `{required: false, width: null}`
on every ordinary atomic — an inhabited state asserting nothing.

**The same principle is applied to the new object, not just the old field.**
`signal_flag` records no `volatile: true`, no `typedef: "sig_atomic_t"` naming
which chain member licensed recognition, no `operations: ["load","store"]`, no
`handler_accesses_confined: true`, no `access.via: "direct"`, and no target id.
Each would be a constant wherever the object exists, and a validator clause
checking a constant defends against the emitter contradicting itself, which is
better prevented than detected. What remains is exactly the three things that
vary and that an auditor cannot re-derive from the certificate alone: the typedef
chain, which registration was certified, and which functions F2 was evaluated
over.

**Width, alignment, class, and signedness are emitted once**, in
`recipe.declaration`, and `signal_flag` re-states none of them.

Two further placement rules are load-bearing:

- **Signal-flag proofs are certified-only, structurally.** `Certificate::Failed`
  (`crates/pangs-manifest/src/lib.rs:350`) has `codes`, `witnesses`, `recipe`,
  and `diagnostics` and **no certificate-level payload**, so a failed slot has
  nowhere to put `signal_flag` at all. Rule 14 — a signal-flag atomic exists only
  as a complete certified proof — therefore stops being a rule someone must
  enforce and becomes a property of the type. This is why the object lives at
  certificate level and not in `recipe`: `recipe` is a field on the failed
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
  `address-access-not-lowerable`, `access-site-unmapped`,
  `signal-flag-external-linkage`, `signal-handler-access-not-confined` — means
  the rewrite cannot be executed correctly, so none is §4.2's honorable "evidence
  failed, recipe present" case. The confinement code belongs in that list because
  it looks like advisory hygiene, and waiving it would override the condition
  that makes dropping `volatile` sound at all (rule 8).

  Suppression stays diagnosable through `diagnostics`, which is opaque and
  load-bearing for nothing:

  ```json
  { "signal_flag": { "status": "recipe-withheld",
                     "reason": "signal-flag mode requires certification" } }
  ```

- **The mode is read from the certificate, not the recipe.** The materializer's
  rewrite instruction is the presence of `signal_flag`; `recipe` carries the
  accesses and the ordering, which is what it needs positionally.

- **Value coupling.** Presence needs no checking, since presence is the claim.
  What remains is six clauses, all conditioned on `signal_flag` being present:

  ```text
  the mode agrees with the fact layer          (the one cross-section clause)
    signal_flag present  ⇒  facts.signal_context_access.value

  signal-flag mode's admission conjuncts are reflected
    typedef_chain ∩ RECOGNIZED_SIGNAL_TYPEDEFS   ≠ ∅
    recipe.ordering                              == "relaxed"
    recipe.declaration.scalar_class              == "integer"
    recipe.declaration.linkage                   == "internal"        (M.3)
    registration present  ∧  observers non-empty
  ```

  `RECOGNIZED_SIGNAL_TYPEDEFS` is a closed constant in `pangs-manifest`, so that
  clause is local. The fact-layer clause is the only one reading outside the
  certificate, and only its unsafe direction is a rule: a `signal_flag` object on
  a non-signal global would mean the certified registration was fabricated. The
  converse — a signal-context global with no `signal_flag` object — is the
  ordinary, correct state for every signal-context global with non-volatile
  accesses, and asserts nothing.

  `ordering`, `scalar_class`, and `linkage` are checked despite being emitter
  outputs because the *materializer* reads them and a wrong value there is
  silent; `registration`/`observers` are checked for presence because they are
  the audit evidence and an empty one would make F2 uncheckable. `observers` is
  necessarily non-empty in a certified payload: the certified registration's
  `handler` reaches an admitted access site, so its transitive access set
  contains the flag and it is a member of `H_g`.

  **Every clause is per-global, and all but one are per-certificate.** Nothing in
  v5 requires a validator to compare two globals, and nothing requires it to read
  the run header.

- **Scope.** All of the above constrains the `signal_flag` object only; ordinary
  atomic, mutex, and once-lock slots keep §4.2's honorable accepted-risk case.
  An ordinary atomic certificate simply omits it.
- `source_materialization` is **unchanged**: `status` remains
  `"source-mapped" | "blocked"`, `code` required iff blocked, and
  `declaration-source-unmapped` its only code. Spelling absence is not a status:
  `word_sized_scalar` keeps requiring a spelling (§B), so a certified atomic
  always has one, and there is no `declaration-type-unspelled` code.

### 5. Ordering and determinism

- `typedef_chain` is in **outer-to-inner declaration order**, neither sorted nor
  deduplicated: it is a path, and its order is the evidence.
- Exceeding `DEBUG_TYPE_RECURSION_LIMIT` yields **no certificate**, never a
  truncated chain. Same for cycles and malformed metadata.
- `registration` is the resolved registration with the lowest callsite id, then
  the lowest accessor function id. Specified because a handler can reach a flag
  by several chains, and an arbitrary choice would churn manifests across
  unrelated inlining changes. The intermediate call path is **not** recorded: it
  is recomputable from the fixed call graph, and storing it would force a
  shortest-path tie-breaking rule no consumer needs.
- `observers` is a set, so it is emitted **sorted by function identity**;
  `typedef_chain` is a path and keeps declaration order. Both, with `codes`, are
  deterministic under re-emission, and a golden diff that reorders any of them is
  a defect.

### 6. The permitted golden diff

**Phase 1** (walker only, no schema change, no header change):

| Class | Condition | Permitted change |
|---|---|---|
| **B** | `word_sized_scalar` was already true | none |
| **C** | was false, and the walk recovers no spelling | none — the global still fails `word-sized-scalar`, with the same value and no new detail |
| **D** | spelling recovered; still fails atomic later | `word_sized_scalar.value` false → true with its `type_spelling`, `size_bits`, `class`, `signed` now populated per the **unchanged** v4 invariant; `atomic_eligibility.codes` changes from `["word-sized-scalar"]` to the later decisive code; `diagnostics` changes from `access_lowering: skipped` to an observed-site count. Disposition unchanged |
| **E** | spelling recovered; now certifies | class D's changes, plus `atomic_eligibility` Failed → Certified with recipe and `source_materialization`; `cascade_chosen`/`chosen` → `atomic`; `cascade_trace` shortens; `run.dispose.measurement_report` moves |

Class D is the bore flag's own Phase-1 diff: it clears the coarse gate and fails
on `volatile-access` instead. Class C is the population §B defers — visibly
inert here, which is the point of deferring it. There is no class touching every
manifest, because Phase 1 does not bump the schema.

**Phase 3** (schema bump + signal-flag mode):

| Class | Condition | Permitted change |
|---|---|---|
| **F** | every manifest | `schema_version` 4 → 5 in the header; every atomic certificate's `signal_lock_free` **removed** with nothing in its place. **No fact changes**, and no per-global change follows from the bump alone |
| **G** | an admitted signal flag | class F, plus `atomic_eligibility` Failed[`volatile-access`] → Certified with a `signal_flag` object; `chosen` → `atomic`; ledger records appear |

The review rule is attribution, not line count: **every changed line must be
attributable to its global's class, and every global must be in a class its facts
justify.** Three defect signals a plausible-looking diff can carry: a class-B or
class-C global changing at all in Phase 1, a class-D or class-E global whose
declared type is *not* a qualified typedef (nothing else can have recovered a
spelling), and any `word_sized_scalar` detail appearing at `value: false`, which
would mean the deferred redefinition leaked in. Aggregate consistency is
separate: `not_word_sized` must decrease by exactly |D| + |E|, and
`measurement_report` may move at Phase 1 only if |E| > 0.

### 7. Freeze points, and an honest note about rigor

| Artifact | Change |
|---|---|
| `schemas/disposition-manifest.schema.json` | the `word_sized_scalar` `oneOf` (lines 139-166) is **untouched**; `signal_lock_free`'s definition **removed**; an optional `signal_flag` definition added, with all three members required when the object is present |
| `crates/pangs-manifest/src/lib.rs` | `SCHEMA_VERSION = 5`; `signal_lock_free` removed and `signal_flag: Option<SignalFlagCertificate>` added to the certified payload, skipped when `None`; `RECOGNIZED_SIGNAL_TYPEDEFS`; one validator for the §4 value coupling. `Facts` and `Facts::validate` are unchanged |
| `crates/pangs-pir/src/lib.rs` | `Global.type_evidence: Option<ScalarTypeEvidence>` with `#[serde(default)]`, matching every other optional field there (lines 158-183), so existing PIR fixtures parse and re-serialize unchanged; plus `section` and `thread_local` in Phase 3; `LoweringStats::alias_exposes_global` |
| `crates/pangs-api/src/lib.rs:142` | `GlobalInfo` mirrors the same optional fields |
| `schemas/globals.schema.json` | **unaffected, deliberately** — `additionalProperties: false` over a fixed key set, no type fields at all; it is not the type channel and MUST NOT gain one |
| D1a golden manifests | regenerated; the permitted diff is classified per global in §6 |

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

## Materialization

`DISPOSITION.md` §5.3 already assigns `atomic` its stage split — the C→C tool
does **exemption + definition-site marker**, and nothing else.

**Most of what a materializer needs here is not specific to this feature.** Type
mapping from `recipe.declaration`, initializer translation from
`initializer_ir`, the access rewrite forms, marker consumption, and the
post-rewrite validation are the contract for translating *any* `atomic`-disposed
global; that contract does not exist yet and is not this note's to write (see
§"Spun-off work"). This section states only what is specific: which stage removes
`volatile`, why external linkage is rejected, and the three requirements this
feature places on that contract.

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

The C `volatile` accesses arrive in translated Rust as `read_volatile` /
`write_volatile` calls on the static's address, which is the property that makes
them findable. After the rewrite:

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

### M.3 External linkage is rejected in signal-flag mode

**Layout compatibility is not the question.** If one TU is translated and another
is not, the storage is accessed as a Rust atomic from one side and as a
`volatile sig_atomic_t` — a *non-atomic* access — from the other. Rust's memory
model, inherited from C++20, makes conflicting atomic and non-atomic access to
the same location a data race and therefore undefined behavior
(`std::sync::atomic` module documentation); identical layout only guarantees the
two sides disagree about the same bytes. For a signal flag the concurrent case is
not a corner — asynchronous access from outside ordinary control flow is the
object's entire purpose. Soundness rule 4 applies across a TU boundary just as
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
externally accessible while `linkage` still reads `internal`. The
`alias_exposes_global` bool in §E closes it.

Lifting the restriction requires a **whole-program certificate**: proof that
every TU accessing the symbol is transformed in one run, so no non-atomic
accessor survives. No such certificate exists, and v1 does not reason about a
half-translated program. The bore flag is `static`, so the restriction costs
nothing for the motivating case.

### M.4 What this feature requires of the atomic materialization contract

Three requirements, stated here because they are consequences of §E's argument
and will not be re-derived by whoever writes that contract:

1. **No re-optimization back to a plain read.** The materializer must not
   "optimize" a certified access to a non-atomic read even when it can prove the
   flag loop-invariant in its own view of the program: the handler write is
   invisible to that proof. Nor may it substitute a `Cell`, a `static mut` read,
   or an `UnsafeCell` shim for the atomic representation.
2. **The ordering is read, never inferred.** It comes from `recipe.ordering`,
   which is `"relaxed"`. A signal flag used as a payload-publication protocol
   gains no acquire/release claim from this certificate.
3. **Post-rewrite validation must be closure over references, not a count plus a
   residue scan.** This is the one place the obvious implementation is unsound,
   so it is stated in full below.

**The reference-inventory requirement.** A count-plus-residue check does not
catch a translated form that launders the address:

```rust
let p = &g_interrupted as *const _ as *const i32;
let v = ::core::ptr::read_volatile(p);
```

That reference is not one of the expected rewrite forms, so it is not rewritten
and the count is unaffected; the surviving `read_volatile` does not syntactically
name the static, so a residue check misses it; and it **compiles**, because the
raw-pointer cast erases the type distinction that was supposed to be the safety
net. The result reads the atomic non-atomically — soundness rule 4 violated
silently. So the rule is:

> Enumerate *every* path-expression reference to the static item in the
> translated crate and classify each. After rewriting, the only permitted
> references are receivers of `load`/`store` calls with the frozen ordering.
> Every other reference — `&G`, `addr_of!(G)`, a cast, an argument, a mention in
> another item's initializer, any other method — is a build failure naming the
> site. Unknown classification is failure, never default-allow. A reference the
> rewriter cannot see is not one it may ignore: a macro invocation whose token
> stream mentions the symbol and which it cannot expand is a failure, and
> `cfg`-disabled code mentioning the symbol is likewise a failure, since another
> feature set would compile it.

A rewritten-site count equal to `recipe.accesses.len()` is retained as a
*cross-check*, not the gate: the inventory catches references the analysis did
not classify, the count catches accesses the rewriter did not find, and the
compiler is a backstop for the type-visible subset only.

**Demotion.** `DISPOSITION.md` §5.3 gives the demotion channel to the C→C tool,
which owns a manifest section. The Rust stage owns none, so it cannot demote: a
C→C failure (marker unplantable, e.g. a definition inside an unrewritable macro)
is an ordinary §5.3 demotion to `unhandled`, while any Rust-stage failure is a
loud build failure whose operator recourse is a `disposition = "unhandled"` pin,
which §4.2 always permits without `accept_risk`.

## Soundness rules

1. Missing or incomplete typedef/qualifier metadata never proves signal-flag type
   evidence.
2. A generic volatile access remains a hard atomic-eligibility failure.
3. Every access to the global must be enumerated and lowered; an incomplete
   access set fails closed. Width, alignment, and signedness must match the
   declaration and every access.
4. No mixed atomic/non-atomic or atomic/volatile representation is emitted —
   **including across a translation-unit boundary**. Conflicting atomic and
   non-atomic access to the same storage is undefined behavior under Rust's
   memory model, and identical layout does not make it defined (M.3).
5. A signal-flag atomic requires an arch and width listed in
   `SIGNAL_FLAG_LOCK_FREE`, which is backed by an in-tree codegen regression and
   has no configuration surface. A library-based (`__atomic_*`) fallback is
   forbidden in an async-signal handler, and an arch with no row is not lock-free.
6. An external declaration matching a registry name **is** a registration; for a
   built-in signal entry it must also match that entry's internal shape, since a
   different arity means a different function rather than an unresolvable one. An
   operand the solver cannot resolve downgrades a registration to unresolved
   rather than deleting it. Only a *resolved* registration with a certified
   positive path may satisfy a permitting conjunct.
7. Unknown handler targets or unknown signal-context accesses retain the
   appropriate conservative facts, and "conservative" is direction-dependent: for
   a *restricting* fact it means widening (`signal_context_access` sets every
   global on a `ModuleWide` effect, which is correct); for a *permitting*
   conjunct it means the opposite — no widened, aliased, or may-set access path
   may establish it.
8. `Relaxed` does not preserve the number or relative order of accesses;
   redundant-load elimination, dead-store elimination, store-to-load forwarding,
   and coalescing are all permitted on `monotonic`. Certification therefore
   requires F2 — transitive handler-observer confinement for every function that
   may run as a handler *and* may reach this flag (`H_g`) — under which every
   such transformation is behavior-refining, because the only observer that could
   distinguish them is a handler execution that F2 forbids from touching anything
   else,
   and signal arrival timing is unconstrained. Without the pattern, dropping
   `volatile` is unsound, not merely optimistic.
9. The only residual assumption in signal-flag mode is the absence of *unbounded*
   elision: a `monotonic` load or store in a loop is re-executed each iteration.
   It is asserted by positional codegen assertions on both the load and store
   side, never by access-count equality, which would reject a legal RLE and
   accept a store sunk past a loop.
10. Narrowing the domain of a *restricting* test is the permissive direction and
    is sound only against a complete envelope. `H_f2` may exclude an
    address-taken function only when that function is FSA-incompatible with
    **every** handler shape its registering API can install — both members of
    `sigaction`'s `sa_handler`/`sa_sigaction` union, not just the two-argument
    one. A registry entry with no declared envelope narrows nothing.
11. Every conjunct that *permits* something requires a finite, exhibitable
    positive path: an exact global root (`Via::Direct`), reached from a precise
    target of a resolved registration over direct-call edges only.
    `AffectedGlobals::ModuleWide`, a finite may-set, an aliased or unknown
    access, an indirect call edge, and a target drawn from the address-taken
    widening each set the restrictive fact and none of them satisfies the
    permitting conjunct.
12. Every conjunct in an admission predicate must be evaluable from a fact that
    exists, and this note must name it. A clause phrased over a relation the
    pipeline does not compute — "no external-linkage alias targets the global",
    when the alias's target is never resolved — is worse than an absent clause:
    it reads as a guard, is cited as one, and an implementer will most plausibly
    discharge it by evaluating it to `false`. Where the fact does not exist, the
    design must either add it or state the blunter fact that stands in for it.
13. The certificate provides scalar atomicity only. It does not certify
    publication of unrelated memory and does not model the interleaving between
    handler and interrupted code. Recognizing a registration alias never relaxes
    the Ω boundary at that call: it adds spawn/signal facts and removes a
    phase-analysis unresolved-effect widening, leaving every points-to, mod/ref,
    and escape consequence unchanged.
14. The C→C stage never removes `volatile` or alters an access: between the two
    stages the program must remain a correct C program, and a declaration
    stripped of `volatile` before an atomic exists in its place is not one.
15. A signal-flag atomic exists only as a complete certified proof. There is no
    partial, failed, or overridden form: a failed proof emits no recipe, and no
    override can supply one. This is enforced by shape rather than by a check —
    `signal_flag` is a certificate-level member and `Certificate::Failed` has no
    certificate-level payload, so a partial form is unrepresentable.

## Amendments required to other documents

Nothing here touches A′–D′ or any solver semantics; the changes are confined to
PIR lowering, the F-layer fact scans, and the manifest schema.

1. **`DISPOSITION.md` §2 (fact table)** — **no row changes.** No fact is added,
   and `word_sized_scalar` keeps its definition including the spelling condition
   (§B). The `signal_context_access` row gains two sentences: that it is a
   *restricting* fact computed by a widening query and therefore never discharges
   a permitting conjunct, and that the `atomic` certificate's mode variant must
   agree with it — the one place a certificate reads a sibling fact. §1's
   guard-shape rule gains the general statement (rule 11).
2. **`DISPOSITION.md` §3 / §3.2** — `schema_version: 5` per the freeze above.
   The fact layer and its detail/value coupling invariant are untouched; the sole
   change is that the `atomic_eligibility` certificate **replaces**
   `signal_lock_free` with the optional `signal_flag` object. v5 is not backward
   compatible with v4 payloads and does not claim to be; the schema-v4 sentence
   in §2 is replaced rather than extended. §3.3's stage-ownership rule also needs
   an exact-version requirement, but that amendment belongs to S3, which owns the
   defect and lands before this bump ships.
3. **`DISPOSITION.md` §7 (soundness matrix)** — the `atomic` row's "no additional
   relational failure for defined source behavior" needs a signal-flag
   qualification: what makes the substitution behavior-preserving is F2 plus the
   unconstrained timing of signal arrival (rule 8), and what remains assumed is
   only the absence of unbounded elision (rule 9) — the first as a stated
   precondition of the row, the second as a recorded assumption. Add the
   dynamic-audit cell (Phase 4's SIGINT test) and the codegen assertions.
   **`DESIGN.md` §8** takes the same assumption in its audited soundness
   inventory, phrased as the single residual, not as "volatile is replaced by
   Relaxed".
4. **`DISPOSITION_PLAN.md` §1.5** — the certificate encodings D1a's golden test
   freezes gain `signal_flag`. The evidenced-bool encodings and
   `source_materialization`'s code list are unchanged, and no scalar
   failure-diagnostic vocabulary is added (§B).
5. **`DISPOSITION.md` §5.3 (stage actions)** — the `atomic` row is unchanged, but
   the section describes demotion as though every materialization failure had a
   channel. It should state that the Rust-side rewriter owns no manifest section,
   therefore fails loudly rather than demoting, and that the `unhandled` pin is
   the operator's recourse (M.4). A pre-existing gap this feature surfaces.
6. **Audit ledger kinds** — `signal-flag-codegen-assumption` (§E). Analysis-
   sourced, so `DISPOSITION.md` §3.3's rule applies (dispose regenerates only
   `source: "override"` records). **No change to
   `schemas/disposition-audit.schema.json` is required**: `kind` is a free string
   and the schema is `additionalProperties: true`. Document the kind in
   `DISPOSITION_PLAN.md` §1.4 alongside the deterministic-id rule.
7. **`pangs-pir` lowering docs (`LoweringStats`)** — `alias_exposes_global` is a
   *fact*, not a metric, and belongs documented apart from the `*_counts` maps
   beside it. Add a sentence stating that `tainted_counts`, `skipped_counts`, and
   `modeled_counts` are observability counters read by no guard, and that the new
   bool is not one of them.
8. **`DESIGN_lite.md` §2A** — the registry paragraph describes only the Ω
   external-summary registry. Add one sentence distinguishing the spawn/signal
   disposition registry (name-keyed, conservative-on-false-positive, no Ω
   effect), so a reader does not infer that adding `__sysv_signal` summarizes an
   external call.
9. **`HOWTO_MEASURE_DISPOSITION_COVERAGE.md` and the `notes/disposition_*`
   baselines** — **no amendment.** `not_word_sized` and the would-be-eligibility
   counters keep their meaning, so historical values stay comparable and only
   their *values* move, by the attributable amount in §6. This is the direct
   payoff of deferring §B; the separate change inherits the re-baselining
   obligation.

## Implementation sequence

Phases 1 and 2 are independent; Phase 3 depends on both, because its admission
conjunction names a fact from each. Phase 4 depends on the spun-off atomic
materialization contract and is not required to measure Phases 1–3.

### Phase 1: type normalization

- Add a bounded qualified-type walker in `pangs-pir`; preserve typedef chains and
  qualifiers in PIR/API metadata, populating `type_spelling` from
  `typedef_chain[0]`.
- **Do not touch `word_sized_scalar`, `Facts`, `Facts::validate`, or the schema
  version** (§B). The only fact-layer effect is that `type_spelling` is populated
  where the walk now recovers it; the invariant it satisfies is the v4 one,
  unchanged. `declaration-source-unmapped` keeps its meaning and remains the only
  blocked `source_materialization` code.
- Regenerate goldens; the permitted diff is §6's Phase-1 table.

This phase makes the manifest accurately say that `g_interrupted` is an aligned
signed 32-bit scalar while still rejecting its volatile access recipe. The
`atomic` slot is `failed` with `recipe: null`, so a user cannot reach `atomic` by
overriding either — `DISPOSITION.md` §4.2's `no-recipe` rejection applies and is
not waivable by `accept_risk`.

### Phase 2: registry correctness

- Validate first with `--registry-config` on the bore module: no code change,
  observable fact delta. Then add `__sysv_signal` to the built-in table.
- Land `BUILTIN_SIGNAL_SHAPES` and the mismatch diagnostic (§D). Note the
  ordering wrinkle: the validation run above goes through the *unchecked* user
  path, so promoting the entry to a built-in newly subjects bore's
  `__sysv_signal(i32, ptr)` call to the arity-2 check. Confirm the promoted entry
  still resolves — a fact delta between the config run and the built-in run would
  mean the shape table is wrong, and it is the one thing the config-first
  validation cannot observe.
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

- **Prerequisite: S3 has landed.** Phase 3 does not implement the exact-version
  requirement for stages that preserve earlier sections; that is S3's, and this
  phase is the one that makes its absence reachable, so it must already be in
  before the bump ships.
- Bump `SCHEMA_VERSION` to 5: `Certificate::Certified` gains
  `signal_flag: Option<SignalFlagCertificate>` with
  `#[serde(skip_serializing_if = "Option::is_none")]`, plus its schema definition
  (all members required when the object is present), `RECOGNIZED_SIGNAL_TYPEDEFS`,
  the §4 value coupling validator, `signal_lock_free` deleted, and regenerated
  goldens. **Not** a tagged `AtomicMode` enum — §4 states why, and S1 introduces
  the discriminant when it has a second informative mode.
- Add `section: Option<String>` and `thread_local: bool` to `pangs_pir::Global`
  (both `#[serde(default)]`) and surface them through the API, so the
  ordinary-storage predicate is checkable at all.
- Land `LoweringStats::alias_exposes_global` and the reordering of
  `collect_alias_map` (§E). The clause must be backed by a fact that exists
  (rule 12).
- Add signal-flag type-evidence certification (§C).
- Land `SIGNAL_FLAG_LOCK_FREE` and its codegen regression. The regression lands
  *before* the row it justifies. The existing signal gate's
  `supported_atomic_widths` read is **not** touched (§"Spun-off work").
- Land the per-API handler envelopes beside the shape table, `sigaction`'s with
  both union members (§D), and the **handler analysis** as one pass producing
  `A`, the FSA-narrowed `H`, the per-flag `H_g`, the
  certified registration, and the F2 verdict. It is **not** a filtered copy of
  `registry_access_facts` — that version would inherit
  `AffectedGlobals::ModuleWide` and mark every global positively
  signal-accessed — and a code comment at the query should say so, because the
  filtered-copy version is the obvious implementation and looks right. F2 is an
  admission conjunct, not a diagnostic: a failure yields `recipe: null`. F2 is
  per-global; no whole-program pass is required anywhere in this feature.
- Thread it into atomic access recipe construction, gated on the full §E
  conjunction — including the certified registration, **not**
  `signal_context_access`; the permissive-looking fact is the wrong one.
- Admit only direct whole-object volatile loads/stores, on internal-linkage
  globals only (M.3), and emit the `signal_flag` variant.
- Emit the `signal-flag-codegen-assumption` ledger records and record the
  no-elision assumption in the audited soundness inventory.

### Phase 4: end-to-end materialization

Depends on the spun-off atomic materialization contract; the assertions specific
to this feature are:

- C→C: the declaration and every access are **byte-identical** to the input, with
  only the marker include and constructor added (M.1).
- Rust: the M.2 before/after program round-trips through the fixture translator
  and the rewriter.
- The reference inventory (M.4) is the gate, with the laundered-pointer case
  rejected.
- Compile and run signal-interruption tests under the transformed program: SIGINT
  changes the flag and terminates the search path, with no locks or allocation in
  the handler — the test that exercises the no-elision assumption, under a
  timeout so a hoisted load fails as a hang rather than hanging CI.

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
- Under `typedef sig_atomic_t my_flag_t;` the flag still certifies: recognition
  tests the *chain*, not `type_spelling`, and the certificate records the chain.
- Malformed and over-depth metadata fail without certification.

### Scalar-fact tests

- A `volatile`-qualified aligned integer typedef becomes `word_sized_scalar:
  true` where it was false, through spelling recovery alone — asserted alongside
  the PIR test so the fact-level consequence of §A is pinned, not inferred.
- **The fact's definition is unchanged**, pinned in both directions: an aligned
  supported integer whose debug metadata yields *no* spelling is still
  `word_sized_scalar: false`, and its record still carries no `size_bits`,
  `class`, or `signed` detail. This is the deferred population (§B), and the test
  exists so that deferral is a decision the suite records rather than an omission
  someone later reads as a bug.
- No `codes` array appears on any `word_sized_scalar` record, and
  `Facts::validate` rejects one that carries detail at `value: false` — the v4
  invariant, still live.
- A certified global whose declaration has no file/line is certified with
  `source_materialization: blocked`, and the cascade still chooses `atomic`; a
  test asserts the cascade does not consult materialization status.

### Schema tests

- A v5 document is refused by a v4 reader through the existing version gate, and
  a v4 document is refused by a v5 reader the same way — there is no
  dual-invariant path to test, and no `word_sized_scalar` behavior to test either,
  since §2 changes nothing there.
- (S3 owns the test that a stage preserving earlier sections refuses a document
  whose `schema_version` differs from its own. It is named here only so its
  absence from this suite reads as a boundary rather than a gap.)
- **The object is all-or-nothing at the schema level**: a `signal_flag` object
  missing any required member is rejected by
  `schemas/disposition-manifest.schema.json` alone, before the Rust validator
  runs. There is no combination of members that half-asserts the mode, which is
  the property that replaced the presence coupling — asserted by construction,
  i.e. by there being no such test to write.
- Each §4 **value** coupling clause is rejected independently, one test per
  clause, on a payload well-formed except for a single wrong value:
  `typedef_chain` containing no recognized name; `ordering` ≠ `"relaxed"`;
  `scalar_class` ≠ `"integer"`; `linkage: "external"`; `registration` absent;
  `observers` empty.
- **The fact-layer clause**: a `signal_flag` object on a global with
  `signal_context_access: false` is rejected. Its converse is asserted *not* to
  be a rule: a signal-context global with **no** `signal_flag` object is valid,
  being the ordinary state of every signal-context global with non-volatile
  accesses.
- A failed slot cannot carry `signal_flag` — asserted as a type-level property
  (`Certificate::Failed` has no such member) rather than as a validator test, and
  the schema is checked to reject a hand-written failed slot that adds one.
- Re-emission is byte-identical: `codes`, `typedef_chain`, and `observers`
  ordering is stable across runs.

### Registry tests

- `signal`, `__sysv_signal`, and `sigaction` identify their handlers.
- A *defined internal* function named `signal` is not a registration
  (`external_only`); an internal wrapper named `signal` forwarding to libc still
  yields a registration, recognized at the inner external call.
- **Shape check, built-in only.** An external declaration `int signal(int)` —
  right name, wrong arity — is **not** a registration and emits the mismatch
  diagnostic; the flag behind it is not admitted. A vararg declaration of the
  same name is rejected the same way. A correctly-shaped `sigaction` (arity 3) is
  a registration and an arity-2 one is not.
- **A shape mismatch is refused, an unresolved operand is not.** One fixture
  carries both: a wrong-arity `signal` (dropped, no `signal_context_access`
  contribution) and a correctly-shaped `signal` whose handler operand comes from
  an external return (kept, unresolved, still widening). The two outcomes must be
  distinguishable in the diagnostics.
- **User entries stay unchecked**: a `--registry-config` entry naming an arity-1
  `my_register_handler` is honored with no shape check, and a config entry
  **replacing** `signal` by name disables the built-in shape check for that name
  — the documented escape hatch, asserted so a later "tidy-up" that applies
  built-in shapes to user entries fails the suite.
- **Spawn entries are unshaped**: an external `pthread_create` with an unexpected
  arity is still a spawn registration, so `thread_visible` and
  phase-stationarity's thread-writer kill are unaffected. This is the scope
  decision in D6, pinned so that extending shapes to spawn names is a deliberate
  act rather than a refactor's side effect.
- An unresolved registration (operand external or untargeted) still sets
  `signal_context_access`, still leaves `phase_stationarity`'s unknown effect in
  place, and widens to precise targets ∪ internal address-taken functions; a
  function that is neither is not made signal-context-accessed. A
  `volatile sig_atomic_t` behind only such a registration stays rejected.
- Bore's restore call is the regression fixture for the unresolved case: it is
  unresolved on every run and must not disturb the resolved registration's facts.
- A global reached by both a resolved and an unresolved registration is
  **admitted** (the existential predicate), and its certificate witnesses the
  lowest-callsite-id resolved registration, stably and independently of how many
  unresolved ones exist.

### Handler-analysis tests

The sharpest in the note, because the failure they guard against is silent and
total (a permitting conjunct true for every global).

- **The `ModuleWide` case.** A handler with one unanalyzable pointer store (so
  its transitive summary is `ModuleWide`) plus a `Via::Direct` store to the flag:
  every global gets `signal_context_access: true`, and **exactly one** — the flag
  — has a certified registration; an unrelated `volatile sig_atomic_t` in the
  same module is not admitted. Asserted as a count, so the test fails loudly if
  the query is ever reimplemented as a filtered copy of `registry_access_facts`.
- The same fixture with a **fully resolved** registration still yields exactly
  one positive global, pinning that `ModuleWide` is orthogonal to `unresolved`.
- A handler whose only access to the flag is through a pointer with a finite
  two-element candidate set has no certified registration; the flag is not
  admitted and also fails `address-access-not-lowerable`, so the two rejections
  agree.
- A path `handler → helper → flag` over `CallDirect` edges is accepted, recording
  `handler: handler, accessor: helper`; the same shape with an indirect middle
  edge is rejected even when the call graph resolves it to exactly one callee.
- A handler reached **only** through the address-taken widening sets
  `signal_context_access` and yields no certified registration.
- Witness determinism: two resolved registrations record the lower callsite id;
  two accessors record the lower function id; the manifest is byte-identical
  across runs.
- Every certified registration implies `signal_context_access` on the same
  global, checked over the whole corpus as an invariant rather than a fixture.
- **F2**: a handler that assigns the flag *and* touches any other static-storage
  object fails `signal-handler-access-not-confined`, witnessed by the function
  and the offending object; a handler touching only the flag plus locals and
  parameters passes. Use an ordinary (non-`sig_atomic_t`) static as the offending
  object, so the fixture is also undefined under C11 §7.14.1.1p5 and the test
  doubles as a diagnostic for a pre-existing source bug. The multi-flag case is a
  separate fixture below, and is *not* pre-existing UB — the two must not be
  conflated into one "F2 catches broken programs" test.
- **F2 is transitive — the libusb shape is the regression.** A handler that
  accesses no static itself but calls a non-address-taken helper writing both the
  flag and a second static **fails**. This is the exact case the earlier `A ∩ H`
  scoping passed vacuously (helper in `A` not `H`, handler in `H` not `A`), so
  the fixture is written from libusb's `sighandler → request_exit` shape and
  named for it. Its sibling — the same helper writing *only* the flag —
  certifies, pinning that the transitivity is not simply rejecting everything.
- **`A` stays exact while F2's summary may widen**, both halves on one fixture: a
  handler with a `ModuleWide` transitive summary must not thereby put every
  global into `A` (which comes from `access_sites_for_global`), while F2 *does*
  read the widened summary and correctly fails.
- **F2 is scoped to `H_g`**, pinned by four fixtures, all behind a `signal`
  registration (envelope `{ void (int) }`): (a) an address-taken function whose
  signature is **outside the envelope**, touching many statics — excluded from
  `H` by the narrowing — **passes**; (b) an ordinary caller polling
  the flag and writing other statics but never address-taken — not in `H` —
  **passes**, the common case that would reject nearly every real program if the
  scoping were wrong; (c) an address-taken `void (*)(int)` handler that touches
  other statics but **cannot reach this flag** — in `H`, not in `H_g` —
  **passes**; (d) the same function once it also reaches the flag — in `H_g` —
  **fails**. Fixtures (c) and (d) are the relevance filter, and differ only in
  whether the handler touches `g`.
- **The handler envelope is per-API, and `sigaction` carries both shapes.** The
  sharpest test here, because the failure is silent certification. Fixture: an
  unresolved `sigaction` registration plus an address-taken
  `void (int, siginfo_t *, void *)` function that touches a second static and
  whose summary may reach the flag. It **must** be in `H_g` and F2 **must**
  fail. Under a hardcoded `void (*)(int)` envelope the function is excluded, F2
  passes vacuously, and the flag certifies with a genuine `sa_sigaction` handler
  never examined — so the test is written to fail against that envelope
  specifically.
- The two-argument companion: the same fixture with a `void (int)` handler fails
  identically, proving both envelope members are live rather than one shadowing
  the other. And an address-taken `int (void)` function — compatible with neither
  shape — is excluded and the flag certifies, proving the narrowing still narrows.
- **An entry with no declared envelope narrows nothing**: a `--registry-config`
  signal entry with an unresolved operand contributes the full `H_fact` widening
  to `H_f2`, so an address-taken function of any signature that may reach the flag
  enters `H_g` and F2 fails. Asserted so the `⊥` fallback is the conservative
  direction rather than an unnarrowed set quietly becoming an empty one.
- **`H_g` membership uses may-semantics**: a handler whose transitive summary is
  `ModuleWide` enters `H_g` for **every** flag in the module and fails F2 for
  every one of them. Asserted so that nobody "optimizes" membership into a
  must-set, which would let an unanalyzable handler escape the check entirely —
  the one direction in which widening helps a global certify.
- **The FSA narrowing is load-bearing, and is asserted to be**: a fixture with an
  unresolved `signal` registration plus an address-taken function outside that
  API's envelope whose summary is `ModuleWide` certifies under `H_f2` and
  **fails** under `H_fact` —
  because under `H_fact` that function joins `H_g` (its `ModuleWide` summary may
  contain the flag) and then fails confinement. The `ModuleWide` summary is the
  point of the fixture: with a precise summary the relevance filter would have
  excluded the function anyway and the narrowing would be untested. Without this
  test the narrowing looks like an optimization and would be dropped by anyone
  simplifying the two handler sets back into one.
- **The two handler sets do not leak into each other**: on the same fixture,
  `signal_context_access` is computed from `H_fact` and its value is
  **unchanged** from the pre-narrowing baseline. A golden assertion, because
  narrowing the published fact is the tempting cleanup and it is the permissive
  direction on a restricting fact.
- **F2 subsumes the two-flag ordering hazard**, pinned by two fixtures: a handler
  writing two `volatile sig_atomic_t` flags is in both `H_flag_a` and `H_flag_b`
  and fails confinement on **both**, with no whole-program condition involved;
  and two flags with *disjoint* confined handlers **both certify** in one module,
  which the removed sole-flag condition would have rejected. The second fixture
  is the direct regression for the relevance filter: with F2 ranging over the
  module-wide `H`, `handler_b` would be examined while certifying `flag_a` and
  both flags would fail. Assert both certifications, not merely one.
- **An unresolved registration does not block certification.** A fixture
  mirroring bore — one resolved `signal(2, handler)` plus a restore call whose
  operand comes from an external return — still certifies. Its companion fixture
  asserts the unresolved registration still widens `H`, pulling in an
  address-taken flag-poller — which, because it reaches the flag, joins `H_g` and
  makes F2 fail.

### Atomic-recipe tests

- Direct volatile loads/stores of a certified `sig_atomic_t` succeed; an ordinary
  `volatile int` still fails `volatile-access`; a `volatile sig_atomic_t`
  **never accessed in signal context** still fails `volatile-access`; a
  `volatile _Atomic`-qualified or `const volatile` chain fails.
- A repo-local `typedef int sig_atomic_t;` used as a genuine signal flag
  **certifies** — recognition is an intent signal and safety comes from the §E
  conjuncts (§C). The test exists so the removed provenance check is not
  reintroduced as a bug fix.
- A `__thread volatile sig_atomic_t` flag fails, and so does a flag with an
  explicit `section` attribute.
- An internal global re-exported by an external-linkage alias fails, closing the
  M.3 back door. The fixture must be an actual
  `@pub_alias = alias i32, ptr @g_flag` with external linkage, not a hand-written
  PIR fixture asserting the fact: the defect was that `collect_alias_map` never
  resolves such an alias's target (`crates/pangs-pir/src/llvm_sys.rs:3573`), so a
  fixture starting from the fact would pass against the broken lowering. An
  external alias to an unrelated *function* does **not** set
  `alias_exposes_global`; an alias whose aliasee is not a resolvable constant
  symbol **does**.
- A `volatile sig_atomic_t` on an arch with no `SIGNAL_FLAG_LOCK_FREE` row fails
  `signal-atomic-not-lock-free`; an unknown or unparsable triple fails the same
  way rather than inheriting a default width list. Both need a synthetic fixture
  with an unlisted triple, since the corpus is entirely `x86_64`.
- A non-signal global's atomic eligibility is **unchanged** by the new table: a
  fixture on an unlisted triple still certifies `atomic` with
  no `signal_flag` object, through `supported_atomic_widths`, proving the two are not
  coupled and that the spun-off repair is genuinely spun off.
- Address escape, indirect access, partial-width access, bulk memory access, and
  volatile RMW all fail.
- An **external-linkage** `volatile sig_atomic_t` satisfying every other conjunct
  fails `signal-flag-external-linkage`, in both executable and library mode,
  including when `access_set_complete` is true — the case the redundancy exists
  for. An ordinary external-linkage atomic is unaffected.
- A signal flag used as a payload-publication protocol gains no acquire/release
  claim from this certificate.
- An `atomic` override on a Phase-1-state global (failed slot, `recipe: null`) is
  rejected `no-recipe` even with `accept_risk = true`. An ordinary atomic, mutex,
  or once-lock slot is unaffected, proving the rule is scoped.

### Codegen and audit tests

- For the declared arch at opt levels `{0,1,2,3}`: no `__atomic_*` reference; a
  `load atomic monotonic` remains in the polling loop body with the exit
  condition depending on it; a `store atomic monotonic` remains in the storing
  loop's body with none migrated to the exit block; both stores of
  `flag = 1; work(); flag = 0;` survive.
- The assertions are positional, not count-based, proven by a negative test: a
  fixture with two adjacent loads and nothing between them, legally collapsed to
  one, **passes**.
- A `SIGNAL_FLAG_LOCK_FREE` row whose codegen regression is absent or failing is
  rejected by the table's own test — evidence and row land together, and there is
  no configuration path by which a row can exist without one.
- Ledger records are deterministic (two runs produce byte-identical `ar-` ids),
  appear only when a global certifies in signal-flag mode, and carry one
  `scope: global` row per such global.

### APG bore regression

For `exe-apg_bore-O0.bc` in executable/application mode, with Andersen and no
overrides:

- `g_interrupted_xjtr_0` has `signal_context_access: true` and a certified
  registration whose `handler` and `accessor` are both
  `sigint_handler_xjtr_0`;
- **no other global in the module** has a certified registration, asserted as a
  count. The module has a second, unresolvable registration
  (`bore_search_cleanup`'s `signal(2, g_prev_sigint_handler_xjtr_0)`), so this is
  a live check that the widening does not leak into the permitting conjunct;
- its `typedef_chain` names `sig_atomic_t`;
- its atomic certificate is certified in signal-flag mode;
- its chosen disposition is `atomic`;
- `unhandled` decreases from 1 to 0, `atomic` increases from 1 to 2, and overall
  disposition coverage increases from 25/26 to 26/26.

These are regression assertions only after the detailed access recipe passes;
they must not be obtained by overriding failed guards.

### Corpus-level acceptance

The bore assertions are necessary, not sufficient — the registry repair changes
facts for every module — so acceptance is on the corpus distribution.

- **After Phase 1**, the distribution may move in exactly one direction with
  exactly one cause: a global whose sole atomic failure was `word-sized-scalar`
  caused by a spelling the §A walk now recovers, and which passes every remaining
  gate including the access recipe, certifies and chooses `atomic`. The predicate
  is on *cause*, not count:

  ```text
  permitted:  atomic_eligibility Failed[word-sized-scalar] → Certified, for a
              global whose declared type is a qualified typedef and whose
              spelling the §A walk now recovers, with no other fact changing
  defect:     any global moving OUT of a strategy — Phase 1 removes no gate
  defect:     any global moving IN for any other reason
  defect:     any change to a global whose word_sized_scalar was already true
  defect:     any word_sized_scalar record gaining codes or partial detail —
              that is the deferred redefinition leaking in (§B)
  defect:     any schema_version change — Phase 1 does not bump it
  ```

  Because the spelling gain is confined to qualified typedefs, and a
  `volatile`-qualified one still fails `volatile-access` at the detailed recipe,
  the movement is expected to be **small and possibly empty** — the bore flag
  itself does not move, it reaches class D. That near-inertness is the deliberate
  result of splitting §B out: what remains is attributable per-global to a
  typedef chain a reviewer can read.

- **After Phase 2**, any global that moves is either newly `signal_context_access`
  (expected: loses `mutex`, tightens `atomic`) or newly `once-lock` from the
  removed unresolved effect (expected: strictly more precise). Any other movement
  is a defect to explain before Phase 3 lands. Phase 2 changes no schema and no
  manifest field of its own.

- **After Phase 3**, movement is **one-directional**: *into* `atomic` for a
  certified signal flag, and nothing else. A global moving *out* is a defect, as
  is any movement by a global without `signal_context_access`. The schema bump
  removes `signal_lock_free` from every atomic certificate and nothing else.
  The expected movement is enumerated in advance by §"Corpus population": bore's
  `g_interrupted`, openssl's `intr_signal`, and libusb's `do_exit` in its
  non-threaded configuration. Fewer means a conjunct is over-tight and the F2
  census says which; more means a candidate the pre-Phase-1 sweep missed, which
  is a finding about the sweep.

- Phase 3 must report an **F2 census**, because confinement is the conjunct most
  likely to make the feature inert unnoticed: per module, the number of
  signal-flag candidates, and per candidate the size of `H_g` and whether every
  member is transitively confined. Report `|H|` beside `|H_g|`: a candidate whose
  `H_g` equals the module-wide `H` means some handler has a `ModuleWide` summary
  and the relevance filter bought nothing, which is the shape that makes the
  feature inert. A corpus in which *most* candidates are rejected by F2
  means either the widening is too coarse or real handlers routinely touch other
  statics, and either finding should be resolved before Phase 4 rather than
  absorbed as low coverage.

## Non-goals

- Treating all volatile integers as safe atomics.
- Modeling memory-mapped I/O through Rust atomics.
- Turning `sig_atomic_t` into a general thread-synchronization primitive.
- Inferring the typedef from symbol names, use patterns, or integer width alone;
  equally, testing where the typedef was *declared* — provenance guards an intent
  signal and defends nothing the §E conjuncts do not (§C).
- Accepting non-lock-free atomic implementations in signal context.
- Supporting arbitrary compound operations in the first implementation.
- Weakening access-set completeness or Ω handling to improve this result.
- Redefining `word_sized_scalar`, or relaxing its `align_bits == size_bits`
  condition. Both are worthwhile and deferred to their own change (§B).
- Repairing `supported_atomic_widths` or the general signal lock-free gate
  (§"Spun-off work"), or populating `SIGNAL_FLAG_LOCK_FREE` with arches no test
  exercises.
- Making the lock-free width table configurable at all: a new arch is a patch
  beside its codegen regression, not a flag.
- Machine-enforcing a toolchain envelope for the no-elision assumption (D4).
- Writing the `atomic` strategy's general materialization contract
  (§"Spun-off work").
- A **public** `RegistryShape` configuration surface. Shapes are a private table
  covering the three built-in signal entries; user-provided entries stay
  unchecked, and promotion waits for a real user-defined alias that needs one
  (§D).
- Shape-checking the spawn entries, or checking parameter *types* anywhere —
  `AbiClass` cannot distinguish a pointer from an integer, so arity and vararg
  are the whole of the available discriminating power (§D).
- Admitting `_Atomic` globals, which are a different lowering with a different
  recipe.
- Signal flags with external linkage, absent a whole-program certificate that
  every accessing TU is transformed (M.3).

## Spun-off work

Two adjacent changes are deliberately **not** in this note. Both are real, both
are independently justified, and folding either in would make this feature's
corpus diff unreadable — §B's splitting rule, applied to itself.

**S1. The general signal lock-free gate is unbacked.** The existing gate reads
`target.supported_atomic_widths` (`crates/pangs-clients/src/lib.rs:1113,1217`), a
pointer-width heuristic (`llvm_sys.rs:407`) that asserts 8/16/32-bit atomics on
every target and says nothing about lock-freedom versus an `__atomic_*` libcall.
It therefore states, for every signal-context global, a guarantee the value does
not carry. Repairing it is a change of population (every signal-context global,
not just volatile signal flags), of direction (it can *remove* certificates a
global has today — the only coverage-losing movement anywhere near this area),
and of scope (it must cover RMW recipes, which this feature admits none of).
Its own note owns: a regression-backed table with per-operation coverage, whether
`supported_atomic_widths` should be replaced or merely superseded at this gate,
the corpus diff of table-versus-heuristic across the triples present, and the
certificate member that records the result. Introducing an `atomic_mode`
discriminant there is additive, and S1 bumps the schema anyway.

**S2. The `atomic` strategy has no materialization contract.** Type mapping from
`recipe.declaration`, initializer translation from `initializer_ir` (including
LLVM's signed printing of unsigned constants — `i8 -1` must become
`AtomicU8::new(255)`, not `AtomicU8::new(-1)` and not `1`), the access rewrite
forms for both `&raw` and `as *const` spellings, marker consumption, and the
post-rewrite validation apply to *every* `atomic`-disposed global and exist
nowhere. M.4 states the three requirements this feature places on that contract;
the contract itself is a separate note, and Phase 4 depends on it.

**S3. `pangs-dispose` preserves an earlier stage's `schema_version` verbatim.**
It parses a `Manifest`, fills its own sections, and re-serializes without reading
or writing the version, so a v5 dispose fed a v4 analysis manifest emits a
document labelled v4 containing v5-shaped dispose sections — contradicting
`DISPOSITION.md` §3.3's requirement that earlier sections survive semantically
unchanged. The rule it needs is that a stage preserving earlier sections MUST
require `schema_version == its own SCHEMA_VERSION` and fail with "re-run
analysis" otherwise. This is a pre-existing gap, not something this feature
introduces, and it belongs with the stage-ownership rule rather than in a
`sig_atomic_t` note.

S1 and S2 are not prerequisites for Phases 1–3, which is the property that made
splitting them affordable. **S3 is the exception**: the v5 bump is what makes its
mismatch reachable in practice, so S3 must land before Phase 3 ships. It is spun
off for ownership, not for sequencing.


## Decisions

No design question here is open. Each decision is normative and carries its
**falsifier** — the observation that must be made before it may be changed.

**D1. Typedef evidence and the certified registration live inside the
`atomic_eligibility` certificate** (paths frozen in §"Schema v5" §4), not as
first-class facts, holding the v5 fact-layer delta to zero. `atomic` is a
certificate-backed strategy, so `DISPOSITION.md` §1's guard-shape rule puts its
preconditions inside the pass.
*Falsifier:* a second consumer of either. Promotion to a fact slot is then schema
v6, additive, and forced by nothing else.

**D2. A permitting conjunct is computed by its own query, not by filtering a
restricting one** (rule 11). The certified registration requires a `Via::Direct`
access reached over direct-call edges from a precise target of a resolved
registration; restricting `registry_access_facts` to resolved registrations is
*not* sufficient on its own, because `ModuleWide` originates in the handler's
transitive summary rather than in the registration operand. The rejected
alternative is the obvious implementation and would make the conjunct true for
every global in any module containing one handler with an unanalyzable pointer
store, silently deleting it. F2 and the path conjunct share one pass because they
share `A` and `H`.
*Falsifier:* a module where the flag's handler reaches it only through a pointer
or an indirect call, so the path requirement rejects a genuine signal flag. This
is bounded: `atomic_access_recipe` already requires `Via::Direct` at every
admitted site (`crates/pangs-clients/src/lib.rs:1891`), so such a global could
not have certified regardless — the falsifier must show the *conjunct* is the
binding constraint, not the recipe.

**D3. This feature recovers the spelling; it does not redefine
`word_sized_scalar`, and Phase 1 bumps no schema.** The bore flag fails that fact
on the spelling condition alone, so §A's walker clears it without touching the
fact's definition, its validator invariant, or its measurement funnel. Dropping
the spelling requirement outright would serve a *disjoint* population — globals
with no recoverable spelling at all — that this feature never reaches, since §C
requires positive typedef evidence before recognizing a signal flag.
*Falsifier:* a `volatile sig_atomic_t` in the corpus whose typedef chain is
present but whose spelling the positional rule still fails to recover. That would
mean §A's walk is incomplete, and the repair is in the walk, not in the fact.

**D4. The no-elision property gets an audit record and an in-tree regression, not
a machine-enforced envelope.** The ledger record states the limit in its own
text, the codegen regression asserts the property positionally on whatever
toolchain is present, and the lock-free table has no configuration surface, so
"the arch is admitted" and "the regression covers it" cannot come apart. An
earlier draft added a declared envelope of rustc floor × LLVM majors × opt levels
plus a Rust-stage check refusing anything outside it; that is dropped, because
enforcement is not what makes the property true, an LLVM-major allowlist goes
stale by construction, and the practical failure mode is a build refusing on a
newer toolchain that is fine. The assumption is one every Rust program polling an
atomic in a loop already depends on.
*Falsifier:* a codegen regression failure, or an observed toolchain that hoists a
`monotonic` load out of a loop. The response to the first is mechanical — remove
the arch row, every certificate citing it stops being emittable, signal-flag
atomics on that target fall back to `unhandled`. The second would justify
reinstating the envelope, and would be a finding about the Rust backend far
larger than this feature.

**D5. The certificate records only what varies and cannot be re-derived.**
`signal_lock_free` is deleted (a duplicated fact, a constant, and a copy), and
the replacing `signal_flag` object does not reintroduce the same shape. Two
grounds for omission, and both are applied:

- *Constant wherever the object exists* — `volatile: true`, `typedef` naming the
  matched chain member, `operations`, `handler_accesses_confined`, `access.via`,
  any target id. A validator clause checking a constant defends only against the
  emitter contradicting itself.
- *Varies, but re-derivable* — `observers[].via`, which recorded whether each
  observer entered `H` as a precise resolved target or through the address-taken
  widening. It genuinely varies, but it is recoverable from the module's
  registration facts and the function's address-taken bit, F2 treats every member
  of `H_g` identically regardless of provenance, and no validator or consumer
  reads it. `observers` is therefore a sorted list of function identities.

What remains — the typedef chain, the certified registration, and the `H_g`
membership list — is the evidence an auditor cannot reconstruct from the
certificate alone. Because `Certificate::Failed` has no
certificate-level payload, this also makes rule 15 a property of the type rather
than a rule to enforce.
*Falsifier:* a second informative mode, which S1's `signal_safe` would be. That
is when a discriminant starts carrying information and the optional object should
become a tagged union — additively, in the change that introduces the second
mode, not in advance of it.

**D6. Signal aliases are exact-name registry entries with an `external_only`
precondition and an internal, built-in-only shape check.** The shape is arity and
non-varargness, held in a private table keyed by name rather than as a field on
`RegistryApi`, so the configuration schema gains nothing; parameter types are not
checkable at all, since `AbiClass` cannot distinguish a pointer from an integer.
User-provided entries retain their current unchecked, conservative behavior,
because a `--registry-config` entry is the operator's own assertion about their
own program while a built-in is a claim the analysis makes unprompted — and a
user entry replacing a built-in by name is the escape hatch for a platform whose
declaration differs. A mismatch means a different function, so the call is not a
registration; that is consistent with never deleting on an *unresolved operand*,
which is a registration whose handler is unknown. Spawn entries stay unshaped:
dropping one would weaken phase-stationarity's thread-writer kill with no
independent backstop, where dropping a spurious signal registration loses only
restricting facts.
*Falsifier, for the private-table decision:* a user-defined registration alias
whose name collides with an unrelated symbol in the same program, so the operator
needs a shape they cannot express. The response is then to promote `RegistryShape`
into the config schema — the mechanism already exists and only its visibility
changes.
*Falsifier, for the check itself:* an observed platform declaring one of the three
names with an unexpected arity, costing a genuine registration. The diagnostic
makes this visible rather than silent, and the immediate recourse is
`--registry-config`; a second occurrence would argue for marking the mismatch
unresolved instead of declining it.

**D7. Signal-handler participation is a hard conjunct of volatile admission**,
satisfied only by a *resolved* registration with a certified positive access
path. It establishes that the `sig_atomic_t` guarantee is the operative reason
the object is volatile; MMIO and special-section storage are excluded separately
by the ordinary-storage predicate, and the typedef match is an intent signal
carrying no provenance test of its own (§C).
*Falsifier:* a corpus program with an otherwise-certifiable
`volatile sig_atomic_t` rejected solely because its registration alias is
unrecognized, *and* for which `--registry-config` is impractical. Both halves
must hold — the documented recourse existing is what makes the strict reading
affordable.

**D8. `volatile` is replaced by `Relaxed` *plus* handler-observer confinement
(F2), and F2 is the only pattern condition.** `Relaxed` supplies indivisibility
and (as an LLVM property) absence of unbounded elision, but not `volatile`'s
preservation of access count and relative order. F2 makes the permitted
transformations behavior-refining rather than merely unlikely, by establishing
that no observer can correlate the flag with anything else — signal arrival
timing being unconstrained. F2 is evaluated **transitively, over the handlers that may
reach this flag** (`H_g`): the observer is a handler execution, so relevance and
confinement must both close over what that execution reaches. An
intersection-scoped form (`A ∩ H`) passed vacuously whenever the access sat one
direct call below the handler — libusb's `do_exit` — and a module-wide form
(all of `H`) makes two disjoint flags mutually exclusive, reintroducing F1 by
accident and in its worst form. A sole-flag-per-program condition (F1) was
considered and removed: the program it excludes, a handler writing two flags,
already fails F2 on both, and F1 additionally rejected two independently confined
flags for no reason. Removing it also removed the only whole-program pass and the
only cross-global validator clause in the design.
F2 is inspired by C11 §7.14.1.1p5 but is neither implied by it nor implies it:
it rejects a handler assigning to two `volatile sig_atomic_t` objects, which the
standard permits, and it allows a handler to read the certified flag, which the
standard's assignment-specific exception does not. The first is a deliberate
coverage cost — that program is exactly the correlation `Relaxed` stops
preserving — and its outcome is `unhandled`.
*Falsifier:* an execution in which a reordering of a certified flag's accesses is
observed by something other than a handler that touches a second static-storage
object — i.e. a counterexample to F2's subsumption argument. Failing that, a
corpus program rejected solely by F2 where the pattern is nonetheless
demonstrably safe. Triage that case by which side of the incomparability it falls
on: if the handler refers to an ordinary static, the source is undefined and the
response is to fix it; if it assigns to a second `volatile sig_atomic_t`, the
source is fine and the finding is a real coverage cost, to be answered by a
per-flag noninterference argument rather than by relaxing F2.

**D9. The alias hazard is closed by one module-level bool, not a per-global
inventory.** `alias_exposes_global` is set by any non-internal alias resolving to
a known global, and by any unresolvable aliasee, so the gap and the hazard are
closed by the same fact. A `BTreeMap<String, BTreeSet<String>>` would buy
signal-flag mode in a module containing an aliased global unrelated to the flag;
a taint-prefix check would lose it in a module containing an ordinary external
alias to a function. Neither trade is worth its surface.
*Falsifier:* a corpus module containing both an aliased global and an otherwise
certifiable signal flag. The repair is then the inventory, which is a few lines
and does not change any other clause.

The remaining unknowns are measurements, not decisions. The population question
is now answered — §"Corpus population" — leaving one: how far the Phase 2
registry fix moves `phase_stationarity` results module-wide.

The standing tie-breaker, should a question arise this note did not anticipate:
retain the current `volatile-access` failure. The goal is to recognize one
well-defined standard idiom with positive evidence, not to broaden atomic
eligibility by assumption.
