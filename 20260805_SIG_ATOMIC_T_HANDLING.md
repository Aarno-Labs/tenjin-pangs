# Handling `volatile sig_atomic_t` Globals

## Status

Design proposal. Nothing here is implemented yet. Reviewed against the working
tree on 2026-08-05; the `file:line` anchors are navigation aids verified at that
revision, not a stable interface.

The load-bearing claim is §E's: that replacing `volatile` with a `Relaxed` atomic
preserves what the source relied on. It does **not** do so on its own —
`Relaxed` permits transformations `volatile` forbids — and the conditions that
make it sound are stated as admission conjuncts (F1, F2), not as commentary.

Two asymmetries recur and are stated once here:

- **Permitting vs. restricting facts.** A fact that *restricts* (kills a
  strategy, tightens a gate) is conservative when widened; a fact that *permits*
  is conservative only when narrowed. A permitting fact may never be computed by
  a restricting fact's widening query (rule 17, D8).
- **Config surfaces are not symmetric.** An over-broad registry entry is
  conservative in every consumer; an over-broad lock-free width is the
  silent-deadlock gate. They get different permission models (§D.4, §E).

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
4. Recognize shape-checked libc spellings such as `__sysv_signal` as signal
   registries, so the async-signal context and lock-free guard are real inputs to
   the certificate (§D).

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
- **It is name-only today**, and its error directions are not symmetric. A false
  positive is conservative in every consumer — a spurious `signal_context_access`
  kills `mutex` and tightens `atomic`'s lock-free gate. A false *negative* is not
  conservative at all for those same two consumers, which is why §D.5 resolves a
  shape mismatch to an *unresolved registration* rather than to "not a
  registration".

The registry is already extensible without code changes via `pangs
--registry-config` (`crates/pangs-cli/src/main.rs:53,726`), which merges or
replaces entries by name. Phase 2 should be validated through that flag on the
bore module before any entry is hardcoded, so the fact-level consequences are
observed independently of the alias-table design.

## Proposed design

### A. Preserve structured source-type evidence

Replace the one-name view of a debug type with a bounded walk that records the
derived-type chain:

```rust
struct ScalarTypeEvidence {
    display_name: Option<String>,
    typedef_names: Vec<String>,
    qualifiers: TypeQualifiers,          // is_const, is_volatile, is_restrict, is_atomic
    class: Option<ScalarTypeClass>,
    signed: Option<bool>,
}
```

The walk starts at the `DIGlobalVariable` type, records qualifier tags rather
than discarding them, records every named typedef in outer-to-inner order, stops
at the existing recursion bound, derives class and signedness from the terminal
scalar type, and fails closed on malformed metadata or cycles. For the bore flag:
`display_name: "sig_atomic_t"`, `typedef_names: ["sig_atomic_t",
"__sig_atomic_t"]`, `qualifiers.is_volatile: true`, `class: integer`,
`signed: true`.

`display_name` is defined **positionally**, with no notion of a "public" name:

```text
display_name =
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

Three properties keep consumers from over-reading this shape:

- A truncated or cyclic walk yields **no evidence at all**; there is no
  partially-populated form. Evidence comes only from positive debug metadata.
- `TypeQualifiers` is **accumulated over the whole chain**, so `is_volatile`
  means "volatile appears somewhere between the variable and the terminal scalar
  type" — the conservative reading for admission (§C/§E), and deliberately
  insufficient to reconstruct a declaration.
- `display_name` is therefore **evidence, not a rewrite recipe**: nothing here
  licenses reassembling a declaration by string concatenation.

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

`signal_atomic_type` is a **type fact**, derived from type evidence alone; target
capability and program context are admission conditions (§E), and mixing them
reproduces the fact/policy conflation §B corrects. Derive it only when:

```text
typedef chain contains the implementation's standard sig_atomic_t typedef
qualifier chain includes volatile
qualifier chain includes neither _Atomic nor const
scalar class is integer
width and alignment are known and mutually consistent
```

Payload (normative placement in §"Schema v5" §4; no `status` of its own):

```json
{ "typedef": "sig_atomic_t",
  "typedef_chain": ["sig_atomic_t", "__sig_atomic_t"],
  "volatile": true, "width": 32, "align": 32 }
```

Recognition allows platform-internal typedefs beneath the public `sig_atomic_t`,
but the public name must be present unless a frontend supplies an equivalent
explicit semantic tag. Do not maintain an open-ended heuristic list of names
resembling `sig_atomic_t`.

**What recognition is and is not.** This is a string match against a typedef
chain, so a user's own `typedef int sig_atomic_t;` passes it. **Safety does not
depend on the typedef being authentic**: what makes the rewrite correct is the
enumerated §E conjuncts — integer scalar of a lock-free width, whole-object
direct loads and stores only, complete access set, resolved signal participation,
internal linkage, ordinary storage. A shadowing typedef satisfying all of those
describes an object the transformation handles correctly. The typedef match is an
**intent signal**, not a proof obligation.

Provenance narrows accidental recognition and is cheap (`DW_TAG_typedef` nodes
carry a file; `RepoRoots::relative_source` distinguishes repo-local from external
paths). Same polarity discipline as registry shapes — reject only on positive
contrary evidence:

```text
typedef declared outside the analyzed repository  -> accepted (system header)
typedef file unknown or unrecorded                -> accepted (no contrary evidence)
typedef positively declared inside the repository -> rejected, code
                                                     signal-typedef-shadowed
```

The fact is carried **inside `atomic_eligibility`'s certificate payload**, its
only consumer, which holds the schema-v5 fact-layer surface to the
`word_sized_scalar` change alone. Promotion to a fact slot when a second consumer
appears is schema v6 (D1).

### D. Recognize shape-checked signal aliases

Extend the exact registry with known ABI/library spellings, beginning with
`__sysv_signal` on the observed glibc target (same shape as `signal`: handler in
argument 1). A name match alone is not proof, so prefer a small alias table with
documented shapes and regression fixtures over fuzzy matching; candidates such as
`bsd_signal` are added the same way.

#### D.1 What "shape" can actually mean here

`RegistryApi` (`crates/pangs-api/src/lib.rs:419`) expresses only name, kind, and
entry operand, so the check needs a representation. Available evidence:

| Source | Gives |
|---|---|
| `pag::Callsite.sig` (`crates/pangs-pag/src/lib.rs:602`) | `cc`, `vararg`, per-param `AbiClass`, return `AbiClass` |
| `pir::Func` (`crates/pangs-pir/src/lib.rs:130`) | the declaration's own `sig`, plus `external` |
| `pag::Node.value_kind` (`crates/pangs-pag/src/lib.rs:481`) | `ValueKind`: `Pointer` / `PointerAggregate` / `NonPointer` / `Unknown` |

The constraint that shapes the design: **ABI class cannot distinguish a pointer
from an integer.** `AbiClass` is `Integer | Sse | X87 | Fp128 | Void | Byval |
Sret` (`pangs-pir/src/lib.rs:640`), and both `int` and `void (*)(int)` are
`Integer`; under opaque pointers no LLVM type inspection recovers the difference
either. Pointer-ness comes from `ValueKind` (`DESIGN_lite.md` §3). `Signature`
gives arity, cc, vararg, and gross class; neither source alone suffices.

#### D.2 Representation

`RegistryShape` is an optional field on `RegistryApi`, expressible for built-in
*and* user entries:

```rust
pub struct RegistryApi {
    pub name: String,
    pub kind: RegistryKind,
    pub entry: RegistryEntryOperand,
    #[serde(default)]
    pub shape: Option<RegistryShape>,   // None = unchecked (today's behavior)
}

pub struct RegistryShape {
    pub params: Vec<ParamShape>,        // positional, exact arity
    pub ret: ParamShape,
    #[serde(default)] pub vararg: bool,
    #[serde(default = "default_cc")] pub cc: String,
    #[serde(default = "default_true")] pub external_only: bool,
}

#[serde(rename_all = "snake_case")]
pub enum ParamShape { Integer, PointerLike, Any, Void }
```

**Every `ParamShape` decomposes into two independent checks**, with different
sources, availability, and failure behavior:

| Component | Source | Availability | On mismatch |
|---|---|---|---|
| **ABI class** | `Callsite.sig`: `sig.params[i].class()`, `sig.ret`, `sig.params.len()`, `sig.vararg`, `sig.cc` | **always** — `Callsite.sig` is a `Signature`, not an `Option` (`pangs-pag/src/lib.rs:601`), and `Signature.ret` is a plain `AbiClass` (`pangs-pir/src/lib.rs:599`) | hard `ShapeMismatch`; no `Unknown` state to be lenient about |
| **Value kind** | `pag.nodes[args[i]].value_kind`; `pag.nodes[result].value_kind` for the return | arguments: node exists but `value_kind` is `#[serde(default)]` and may be `Unknown`. **Return: only when `Callsite.result` is `Some`** | rejects only on positive contrary evidence |

```text
Integer      A: class == Integer        V: ¬proven(Pointer | PointerAggregate)
PointerLike  A: class == Integer        V: ¬proven(NonPointer)
Any          A: class == Integer        V: (none)
Void         A: class == Void           V: (none — a void position has no value)
```

`Unknown` never causes a mismatch, and an **absent** result node is treated as
`Unknown` (value-kind half skipped, ABI half still runs). Without that polarity
the value-kind half would degrade into a type system and silently drop
registrations; applying the same leniency to the ABI half would discard evidence
that is always present and never uncertain.

So the return is **not** uniformly best-effort: its ABI half is always decisive —
`Void` is the only shape whose ABI class is not `Integer`, and a spec expecting
`Void` that observes `Integer` mismatches on every call, discarded result or not
— while only pointer classification depends on the result node.

**`RegistryEntryResolution` gains a reason set**, since the existing boolean
(`crates/pangs-api/src/lib.rs:433-438`) cannot distinguish a shape mismatch from
an incomplete operand, which §D.5 requires:

```rust
pub struct RegistryEntryResolution {
    pub kind: RegistryKind,
    pub targets: Vec<FuncId>,
    #[serde(default)]
    pub unresolved_reasons: BTreeSet<UnresolvedReason>,   // empty ⇒ resolved
}

#[serde(rename_all = "kebab-case")]
pub enum UnresolvedReason { ShapeMismatch, OperandExternal, OperandUntargeted, OperandAbsent }

impl RegistryEntryResolution {
    pub fn unresolved(&self) -> bool { !self.unresolved_reasons.is_empty() }
}
```

**A set, not an enum**, because the reasons co-occur and picking a winner would
make the diagnostic depend on evaluation order. **Empty means resolved**, so a
future added reason makes previously resolved entries unresolved — the safe
direction. **`unresolved` is a method**, so no consumer can construct a
resolution claiming precision while carrying a reason; the widening at
`crates/pangs-clients/src/lib.rs:838-841` is unchanged since it widens on any
reason. Consumers widen identically on every reason; the distinction is for
diagnostics and §D.6.

#### D.3 The three entries

```jsonc
{ "name": "signal",        "kind": "signal", "entry": { "arg": 1 },
  "shape": { "params": ["integer", "pointer_like"], "ret": "pointer_like" } }

{ "name": "__sysv_signal", "kind": "signal", "entry": { "arg": 1 },
  "shape": { "params": ["integer", "pointer_like"], "ret": "pointer_like" } }

{ "name": "sigaction",     "kind": "signal", "entry": { "pointee_of_arg": 1 },
  "shape": { "params": ["integer", "pointer_like", "pointer_like"],
             "ret": "integer" } }
```

`sigaction`'s difference is carried by `entry`, not `shape`: the handler is a
field of a struct the argument points to, which is a points-to query, not a
signature property. So shape does **not** check `struct sigaction`'s layout and
cannot — a wrong-layout struct yields wrong pointees, which the solver still
treats as possible handlers.

**Arity separates the two families**, checked against `sig.params.len()`: two
parameters versus three. **No family discrimination may rest on the return** —
both return `AbiClass::Integer` (`sigaction` returns `int`; `signal` returns
`__sighandler_t`, a pointer, returned in the same register class on x86-64), so
the ABI half agrees on both, and the value-kind half that would distinguish them
vanishes when the result is discarded, which is the common spelling.

Shape never inspects `entry`, so a `sigaction` entry wrongly declared
`{ "arg": 1 }` matches its shape and resolves the wrong operand. The defense is a
**registry-entry consistency check at config load**:

```text
entry index is within params.len()
the ParamShape at the entry index is PointerLike
kind is Signal or Spawn — a registration operand is always pointer-bearing
```

An entry failing this is a config error, rejected at load with the entry named,
like the `[cascade]` config errors in `DISPOSITION.md` §4.1.

#### D.4 Evaluation order, and who is checked

1. **Name match** against the effective registry.
2. **Declaration check** (`external_only`, default true): the callee must be an
   external declaration. A *defined internal* function named `signal` is not
   libc's and the entry does not apply — the analysis already models that body.
   A precondition, not a shape check; its failure is **silent** (§D.6).
3. **Shape match**, per D.2. Failure adds `ShapeMismatch`, the only step whose
   failure emits a diagnostic record.
4. **Handler-operand resolution**, per `resolve_registry_entries`
   (`crates/pangs-api/src/lib.rs:4302-4313`). Failure adds `OperandExternal`,
   `OperandUntargeted`, or `OperandAbsent`. Not new; listed because resolution is
   the conjunction of all four steps, not the first three.

Steps 3 and 4 are independent and both run: the outcome is the union of their
reasons. Step 4 cannot be skipped when 3 fails, because the widened target set
still needs the operand's pointees (§D.5). The same applies on the indirect path,
where `registry_spec` is consulted with a solved target name
(`crates/pangs-api/src/lib.rs:4242,4279`) and the callsite signature used is that
indirect callsite's.

User-configured entries **are** shape checked, because `effective_registry_apis`
(`lib.rs:4198-4205`) merges by name with the user entry *replacing* the built-in,
so an unchecked user entry for `signal` would launder the built-in's shape away:

- `shape: None` on a **new** name is unchecked, preserving today's behavior, and
  records an audit note: it asserts a registration the tool cannot verify. This
  permission does **not** extend to `--target-profile` (§Status).
- A user entry **replacing a built-in name** inherits the built-in shape unless
  it supplies its own. Replacement retargets `entry` or `kind`; it does not
  silently disable verification.

#### D.5 The mismatch outcome is not "no match"

Dropping a signal registration is not uniformly conservative:

| Consumer | Effect of dropping the registration | Direction |
|---|---|---|
| `phase_stationarity` | keeps the `has_unknown` widening | safe |
| `mutex_eligibility` | loses the `signal-context-access` rejection | **unsafe** |
| `atomic_eligibility` | skips the signal lock-free gate | **unsafe** |
| §E volatile admission | conjunct fails, access rejected | safe |

So the resolution is three-valued:

```text
name ∧ declaration ∧ shape ∧ operand-complete
                                → resolved registration, targets from points-to
name ∧ declaration ∧ ¬(shape ∧ operand-complete)
                                → registration with non-empty
                                  unresolved_reasons (§D.2),
                                  targets = the operand's pointees if any
¬name ∨ ¬declaration            → not a registration
```

**The fourth conjunct is load-bearing.** `resolve_registry_entries` already
computes `unresolved: external || !targeted` (`pangs-api/src/lib.rs:4303`), a
property of the operand's points-to result, independent of name, declaration, and
shape. `name ∧ declaration ∧ shape → resolved` is wrong in the unsafe direction:
shape checking is the part being added, and an implementer would naturally write
it last and treat its success as resolution.

The reasons stay distinct in the diagnostic: shape mismatch means *this is
probably not the API we think it is*; operand incompleteness means *this is the
API, and we cannot see who the handler is*.

| Reason | Source | Meaning | `targets` |
|---|---|---|---|
| `shape-mismatch` | §D.2 | name matched, signature did not; the entry is suspect | operand pointees, if any |
| `operand-external` | `external` (`lib.rs:4302`) | the operand's points-to reaches an external boundary; the handler may be defined outside the module | non-empty but **incomplete** |
| `operand-untargeted` | `!targeted` (`lib.rs:4310`) | no targeted points-to for the operand label; the target set is unavailable rather than incomplete | empty |
| `operand-absent` | `callsite.args.get(arg_index)` is `None` | no argument at the entry index | empty |

`operand-absent` is folded into `operand-untargeted` by the current code (both
arrive through `is_some_and` returning false) but is named separately because it
indicates an arity problem shape checking should have caught first; reaching it
with shape checking live is a defect in the shape check, and the distinct reason
makes that visible.

**`operand-external` matters most**: its `targets` list is non-empty, so it is
the one unresolved reason that looks resolved. Two mechanisms would be unsound if
it were treated as resolved — **F2's handler set `H`** would omit handlers
defined outside the module and pass by not looking, and
**`resolved_signal_context_access`** would rest on a partial view of who the
handler is.

The middle case widens in every consumer: phase analysis keeps its unknown
effect, `signal_context_access` is set, and the unresolved bit ensures nothing is
narrowed on its basis. One exception: an unresolved registration sets the fact
but **does not satisfy §E's admission conjunct**, which requires a resolved
registration — volatile admission is the one place the fact *permits*, so it
takes the strict reading.

**How an unresolved registration widens — frozen:**

```text
handlers(unresolved registration) = precise targets ∪ { f : f.address_taken ∧ ¬f.external }
```

Existing behavior (`crates/pangs-clients/src/lib.rs:777-783, 838-841`); the
widened set is `address_taken_entries`, *chained onto* the precise targets rather
than replacing them.
Frozen here because the three-valued outcome makes it reachable in a new way.
**All internal functions** is strictly wider and buys nothing, since a function
whose address was never taken cannot be a registration operand.
**FSA-compatible functions** (`void (*)(int)`) would be tighter but is exactly
wrong for the shape-mismatch sub-case, where the signature evidence is what
failed; it remains a defensible future refinement for the operand-unknown
sub-case only.

This bounds the retrofit risk: adding shapes to the existing `signal`/`sigaction`
entries can only downgrade a registration to unresolved, never delete it. The
corpus regression is still required; its worst case is precision loss.

#### D.6 Diagnostic

**Only a shape mismatch on an external declaration emits a record. A failed
declaration check is silent, and so is every operand-side unresolved reason.**

The declaration check is a precondition: an internally defined function named
`signal` is a different function whose body the analysis models, so nothing is
unverified and a record would be noise that `--strict-registry` would fail the
build over. Nothing is lost — if that function forwards to libc, the inner call
is itself a name match against an external declaration.

The emitting record goes to the audit ledger (`pangs-audit.json`), alongside
accepted-risk overrides and library-mode ordering assertions, because it is the
same kind of thing: an external the tool was told about and could not verify.

```jsonc
{ "kind": "registry-shape-mismatch",
  "name": "signal",
  "callsite": "…", "site": { "file": "…", "line": 210 },
  "expected": { "params": ["integer", "pointer_like"], "ret": "pointer_like",
                "vararg": false, "cc": "ccc", "external": true },
  "observed": { "params": ["integer", "integer"], "ret": "integer",
                "vararg": false, "cc": "ccc", "external": true,
                "arg_value_kinds": ["non_pointer", "non_pointer"] },
  "outcome": "unresolved-registration" }
```

A mismatch on a **built-in** name means the target's libc does not look like the
table thinks it does — the drift an alias table must not hide. Warning by default
(a program may legitimately declare its own external `signal`), non-zero exit
under `--strict-registry`, following `DISPOSITION.md` §4.3.

**The operand reasons emit no ledger record**: they report analysis imprecision
on a correctly recognized API — the normal condition of a whole-program analysis
with an Ω boundary, already conservative in every consumer — and a row per
occurrence would bury the mismatch records that demand attention. (Bore would
emit one every run for its `signal(2, g_prev_sigint_handler_xjtr_0)` restore
call, which is correct C.) They stay visible through `unresolved_reasons`, so
`--registry-report` can show them per callsite, and a rejected
`volatile sig_atomic_t` names the reason in its `atomic_eligibility` witness.
`--strict-registry` covers `ShapeMismatch` only: failing a build because the
solver could not resolve a function pointer would make the flag unusable on
exactly the programs it audits.

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
the global has a positive signal_atomic_type certificate           (§C)
the global has resolved_signal_context_access: true                (below)
the global has internal linkage                                    (M.8)
the global is ordinary storage: no section, not thread-local,
  not alias-exposed                                                (below)
lock-free load and store of the width are target-guaranteed        (below)
every access satisfies the ordinary atomic recipe constraints
the access set is complete and every site is in the admitted operation set
it is the program's only signal-flag candidate                 (F1, below)
every function that both accesses this global and may run as
  a handler accesses no other static-storage object            (F2, below)
```

F1 and F2 are the *pattern conditions*, derived under "Why dropping `volatile` is
admissible". They are not hygiene: `Relaxed` does not preserve access count or
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

**Ordinary-storage predicate.** For v1, admission additionally requires:

```text
is_definition == true ∧ constant initializer present   (already required by D3)
linkage == internal                                    (M.8)
no explicit section attribute                          (needs a new PIR fact)
not thread-local                                       (needs a new PIR fact)
not alias-exposed                                      (needs a new PIR fact,
                                                        or the module-wide
                                                        fallback; see below)
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
not a predicate over any fact that exists (rule 18). Nor does `bump_tainted` gate
anything: it writes `LoweringStats::tainted_counts`, a metrics counter
(`crates/pangs-pir/src/lib.rs:479`) read only by assertions in
`crates/pangs-pir/tests/llvm_lowering.rs`. `violation_taint` is unrelated —
module-wide it is `module_violation_tainted`, testing for inline assembly
(`crates/pangs-solve/src/lib.rs:1222`); per-global it comes from violation
findings (`crates/pangs-clients/src/lib.rs:209-210`). This matters because M.8
rejects external linkage to prevent mixed atomic/non-atomic access across a TU
boundary, and an external-linkage alias re-exports that storage under another
name — the same hazard through a back door.

**The fix: an alias-exposure inventory in PIR.** Move
`constant_symbol_name(LLVMAliasGetAliasee(*alias))` above the interposability
check; when it names a known global and the alias is not internal-linkage, record
it in a new `LoweringStats` field
`alias_exposed_globals: BTreeMap<String, BTreeSet<String>>` (`#[serde(default)]`).
The §E clause becomes `alias_exposed_globals.get(key).is_none()`. Two properties:
**resolution is separated from modelling** — the alias is still dropped from
`AliasMap` exactly as today, so nothing about points-to, escape, or the Ω
boundary moves; and **an unresolvable aliasee counts as exposure of nothing, not
of everything** — `constant_symbol_name` returning `None` adds no entry, a gap
covered by the fallback rather than by pretending the inventory saw it.

**Fallback if the PIR field is deferred.** Block signal-flag mode for **every**
global in a module whose `lowering.tainted_counts` contains any `alias_`-prefixed
key. Implementable today, fails closed, and costly: `is_non_interposable_alias`
accepts only `Private` and `Internal` linkage, so any external alias in the
module — including an ordinary one to an unrelated function — disables the
feature module-wide. The choice is a coverage measurement, made by Phase 3's
census of corpus modules carrying such a key: near zero ships the blunt rule,
otherwise the inventory lands. What must **not** happen is a third option: a
target-specific predicate no fact can evaluate, which an implementer would most
plausibly discharge by writing `false`.

The registry work is a hard prerequisite: without it the bore flag has
`signal_context_access: false` and is correctly rejected. That is the desired
failure mode — the idiom is admitted only where the analysis can see the signal
context that gives it meaning.

#### The conjunct needs a fact the manifest does not yet have

`signal_context_access` is one `EvidencedBool`
(`crates/pangs-manifest/src/lib.rs:400`, `DISPOSITION.md` §2), true for resolved
*and* unresolved registrations alike, so D3 cannot read the distinction the
conjunct requires; the witness does not settle it either, since the producer uses
`or_insert_with` (`crates/pangs-clients/src/lib.rs:882-887`) and keeps whichever
registration came first in callsite order. Add a sibling fact:

| Fact | Semantics |
|---|---|
| `signal_context_access` | **unchanged.** True if *any* signal registration, resolved or not, reaches the global — "reaches" in the widening sense, including module-wide. Restricting consumers (mutex rejection, atomic's lock-free gate) keep reading exactly this. |
| `resolved_signal_context_access` | **new.** True iff at least one **resolved** registration has a *certified positive access path* (below) to the global. Evidenced polarity true; the witness is the resolving registration site, the handler, and the path. |

```text
admit volatile  ⇐  resolved_signal_context_access.value == true
```

#### Provenance: why "reaches" is not good enough for a permitting fact

`signal_context_access` comes from `transitive_accesses`, whose per-payload target
set is `AffectedGlobals::ModuleWide` whenever the access is through a pointer with
no finite candidate set (`crates/pangs-api/src/lib.rs:2093-2096`), and
`registry_access_facts` then sets the mask on **every global in the module**
(`crates/pangs-clients/src/lib.rs:848-852`). Correct for a restrictive fact.
**Cloning that computation for the permitting fact would be a soundness hole**:
one handler with an unresolved transitive effect would satisfy §E's conjunct for
every global in the module for free.

`ModuleWide` is **orthogonal to `unresolved`** — it comes from the handler's own
transitive summary, not from the registration operand — so restricting the new
fact to resolved registrations does not avoid it. The restriction must be on the
access path.

**Certified positive access path.** True for a global `g` only when there exists
a path `f₀ → f₁ → … → fₙ` (n ≥ 0) where `f₀` is a **precise** target of a
**resolved** signal registration (not a member of §D.5's widening); every edge is
a `Stmt::CallDirect` to a defined internal function; and `fₙ` contains an
`AccessSite` on `g` with `via == Via::Direct`. Everything weaker is rejected:

| Provenance | Sets `signal_context_access` | Sets `resolved_signal_context_access` |
|---|---|---|
| `Via::Direct` site, direct-call path from a precise resolved target | yes | **yes** |
| `Via::Aliased` / `Via::Unknown` site (pointer access, finite candidate set) | yes | no — a *may* set is not positive proof |
| `AffectedGlobals::ModuleWide` | yes | **no** — the case the rule exists for |
| any indirect-call edge on the path | yes | no — the call graph over-approximates exactly there |
| target from the address-taken widening | yes | no — the widening is a guess at who the handler is |

The direct-call restriction keeps the evidence exhibitable: the witness *is* the
path, and a reviewer can read it in the source.

**This costs less than it appears**: the admitted access set already requires
`via == Via::Direct` at every site, since `atomic_access_recipe` fails
`address-access-not-lowerable` otherwise (`crates/pangs-clients/src/lib.rs:1891`).
The rule aligns the *fact* with a restriction the *recipe* already enforced. For
bore the path has length zero — `sigint_handler_xjtr_0` is a precise target of
the resolved `signal(2, …)` and contains a `Via::Direct` store to the flag.

**An API gap this exposes.** `AffectedGlobals::Finite` is returned both for
`GlobalTarget::Name(g)` — one element, exact — and for `GlobalTarget::Unknown(_)`
with a finite candidate set, which may also be one element
(`crates/pangs-api/src/lib.rs:2091-2097`), so the tiers are indistinguishable
through `transitive_accesses`. The new fact must therefore be computed from
`access_sites_for_global` (`crates/pangs-api/src/lib.rs:2012`), which carries
`via` and `func` per site, walked backwards over direct-call edges to the
registration targets — a different query, not a filtered version of the old one.

The predicate is **existential over resolved registrations**, not universal: a
global reached by one resolved and three unresolved registrations is admissible,
because one resolved registration fully supplies the positive proof and
additional unresolved ones widen the handler set without undermining evidence
that already exists.

**Witness determinism**: record the resolved registration with the lowest
callsite id, so the value is stable in goldens. `signal_context_access` keeps its
existing first-wins witness.

**Why this is a fact and `signal_atomic_type` is not**: this is a *guard
conjunct*, and `DISPOSITION.md` §1's guard-shape rule puts guard inputs in the
fact vector; burying one inside a certificate payload would make the guard
unreadable from the fact layer. Validator invariant:

```text
resolved_signal_context_access.value == true  ⇒  signal_context_access.value == true
```

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

The recipe marks the mode explicitly (fields shown together for readability;
normative nesting in §"Schema v5" §4 — `volatile_semantics` belongs to `recipe`,
`signal_lock_free` sits at certificate level):

```json
{ "ordering": "relaxed",
  "volatile_semantics": "certified-signal-flag",
  "signal_lock_free": { "required": true, "width": 32,
                        "operations": ["load", "store"],
                        "target_guaranteed": true, "source": "builtin" } }
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

The narrow scope makes the needed fact cheap: the admitted operation set is loads
and stores only, so the claim is *lock-free load and store of width W* — the
property Rust exposes as `target_has_atomic_load_store`, much more widely
satisfied than lock-free RMW. So **add** `lock_free_load_store_widths` for this
gate and leave `supported_atomic_widths` alone; the certificate records the
operation set it claims, so a later RMW extension cannot silently reuse a
load/store-only proof.

Replacing both lists with a profile defaulting to empty would be a cliff:
`word_sized_scalar` reads `supported_atomic_widths`
(`crates/pangs-clients/src/lib.rs:2337`), the coarse gate for every global, so an
unlisted triple would zero atomic eligibility module-wide — undetectable by the
bore regression, which is `x86_64-unknown-linux-gnu`. The deeper reason is the
failure modes:

| Fact | If it is wrong | Detected by |
|---|---|---|
| `supported_atomic_widths` | the recipe names a Rust atomic type that does not exist for the width | **compile error** in the Rust output — `DISPOSITION.md` §7's structural gift |
| `lock_free_load_store_widths` | a signal handler takes a lock, or an access is not indivisible | **nothing** — silent deadlock or torn access at runtime |

Migrating `supported_atomic_widths` is a **separate, evidence-gated follow-up**:
derive the profile, diff it against the heuristic across the triples the corpus
contains, then decide. Agreement makes it a rename that can land any time;
disagreement is a bug report about the general atomic recipe and deserves its own
note.

#### Profile specification

**Key.** The normalized architecture component of `TargetInfo.triple`, already
captured (`crates/pangs-pir/src/llvm_sys.rs:412`). Lock-free load/store is an ISA
property, so vendor, OS, and environment are ignored; normalization is the arch
component plus a small alias map (`amd64`, `x86_64h` → `x86_64`). An absent or
unparsable triple resolves to no profile.

**Rows in v1: exactly one.** `x86_64 -> [8, 16, 32, 64]`; everything else absent
→ empty → fail closed. The corpus is 71 modules and 100% `x86_64-*-linux-*`, and
a row no test exercises is a liability. The omissions are decisions:
`arm`/`thumb`, where 64-bit lock-free load/store depends on sub-arch (`ldrexd`)
the arch component does not determine; `riscv32`/`riscv64`, where atomics come
from the `A` extension, a feature rather than an implication of the arch string;
and 32-bit x86, where 64-bit lock-free load/store needs i586+
(`cmpxchg8b`/x87), so `i386` and `i686` cannot share a row.

**CPU features are not consulted.** A row lists only widths lock-free on the
arch's *baseline* subtarget; enabling features can add lock-freedom but never
remove it, so ignoring them errs closed, and an arch with an ambiguous baseline
gets no row rather than an optimistic one. Per-function `target-features`
attributes are deliberately not read: they are per-function, frequently absent in
`-O0` bitcode, and would make a module-global fact depend on which function
carried an attribute.

**Authority** is the Rust target definition, not LLVM's, since the consumer is
generated Rust:
`rustc --print cfg --target <triple> | grep target_has_atomic_load_store`. Check
the table in with the rustc version it was derived from, plus a test that
re-derives it when `rustc` is available and skips otherwise.

**Configuration — narrowing or evidence, never assertion.** A `--target-profile`
JSON file, merged by normalized arch key, may only **narrow** (remove widths from
a built-in row, or the row entirely) or supply a row with a validating **evidence
bundle**. Asserting a new width or arch row by hand is **rejected**, with no
accepted-risk escape: for a gate whose failure is silent, "audited" is not a
substitute for "tested" (§Status). Narrowing needs no evidence, since it can only
move globals toward `unhandled`, and appends an informational
`target-profile-narrowed` ledger record.

An **evidence bundle** is the recorded output of the same codegen regression,
naming per `(arch, width, opt level)` the toolchain identity, the assertions that
passed, and a hash of the fixture source and compiler invocation. The analyzer
admits the row only when the bundle's fixture hash matches the in-tree fixture,
its toolchain fields fall inside the declared envelope, and every
`(width, operation)` claimed appears with all assertions passing — it is checked
as a record *of this regression*, not trusted as a document. The honest limit: a
determined operator can fabricate one. The goal is preventing an *accidental*
assertion of lock-freedom through a config edit, and the ledger names the bundle
so an auditor can re-run it.

**Reproducibility.** Record the resolution in `run.analysis` (analysis-owned
under `DISPOSITION.md` §3.3):

```json
"target_profile": {
  "triple": "x86_64-unknown-linux-gnu", "arch": "x86_64", "source": "builtin",
  "lock_free_load_store_widths": [8, 16, 32, 64],
  "supported_atomic_widths": [8, 16, 32, 64]
}
```

`source` is `"builtin"`, `"builtin+narrowed"`, or `"evidence-bundle"`; a narrowed
row adds `narrowed_from`, an evidence-bundle row adds
`evidence_bundle: { id, sha256, fixture_sha256 }`. Narrowing does not change the
provenance of the widths that remain, so a narrowed row's certificates still
report `source: "builtin"`. `signal_lock_free` carries `source` so a certificate
is self-describing without consulting the run header; §4's value coupling
requires the two to agree.

**The bore case.** `x86_64-unknown-linux-gnu` normalizes to `x86_64` → `[8, 16,
32, 64]`, and the 32-bit flag passes. No corpus module exercises the empty
default; the fail-closed path is asserted by a synthetic fixture with an unlisted
triple.

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
for a flag with that role, which the pattern conditions make checkable rather
than assumed.

The argument does not extend to *unbounded* elision: a load hoisted out of a
polling loop yields an execution in which the signal is never observed at all,
which is not "delivered later" but "never delivered". That is (iii), the one
genuine residual.

**The pattern conditions**, hard conjuncts of certification:

- **F1. Sole certified flag.** The program admits at most **one** global into
  signal-flag mode. With two, the ordering between them becomes unobserved by the
  compiler while the interrupted code can still observe it — `flag_a = 1;
  flag_b = 1;` in a handler, read in the other order by the main loop, is a real
  pattern that (ii) protects and `Relaxed` does not. One flag makes the ordering
  question vacuous rather than argued. Failure code `signal-flag-not-sole`, on
  every candidate; the design does not pick a winner.
- **F2. Handler-observer confinement.** Let `A` be the functions containing an
  enumerated access to the flag — known exactly, since access-set completeness is
  already a conjunct and every site is `Via::Direct` or the recipe already failed
  — and `H` the handler set over **all** registrations: precise targets for
  resolved ones, plus §D.5's frozen widening for unresolved ones. Require that
  every function in `A ∩ H` accesses no object with static or thread storage
  duration other than the flag. Failure code
  `signal-handler-access-not-confined`, witnessed by the function and the
  offending object.

  The two sets over-approximate in **opposite directions**: `H` is widened (more
  candidate handlers ⇒ harder to pass), while `A` is the recipe's own exact,
  `Via::Direct` site list. A widened `A` would be unsound, with the same
  `ModuleWide` hazard as above, so F2 must be evaluated against
  `access_sites_for_global`, never the registry's transitive mask. The "accesses
  no other static-storage object" half is the one place a widened set is *safe*,
  being a restrictive test: `ModuleWide` there means "may touch everything",
  which fails F2 and rejects, so that half can read the ordinary transitive
  summary.

  The intersection makes this sound and affordable: a function that never touches
  the flag cannot correlate its order with anything, and a function not in `H`
  cannot run as a handler. For functions in both, F2 is C11 §7.14.1.1p5 restated
  — a handler referring to any static-storage object other than by assigning to a
  `volatile sig_atomic_t` is already undefined behavior — so the condition
  rejects only programs that were broken before translation.

**Why there is no "reject all unresolved registrations" condition.** It would
contradict §D's mixed-case rule and reject this note's own motivating case:
`bore_search_cleanup` restores the previous handler with
`signal(2, g_prev_sigint_handler_xjtr_0)`, whose operand is a function pointer
read from a global holding an external function's return value — unresolvable in
principle, and ordinary correct C. The widening already discharges closure:
unknown external targets cannot access the flag (internal linkage per M.8, and
its address never escapes — already an atomic-recipe conjunct), and §D.5's
widening covers the internal ones, so `H` is a sound over-approximation with the
unresolved registration in it.

Both conditions are checkable from facts this design already computes: F1 is a
count over the candidate set; `A` is the recipe's access list grouped by
enclosing function; `H` is `registry_access_facts`' target set with the widening
at `crates/pangs-clients/src/lib.rs:838-841`.

**The bore case, checked.** F1: one `volatile sig_atomic_t` in the module. `A` =
`{sigint_handler_xjtr_0, bore_search_init, bore_search_file, bore_search_dir,
bore_search}`. `H` = `{sigint_handler_xjtr_0}` ∪ the internal address-taken set;
the four `bore_search*` functions have external linkage and so are not in the
widening. `A ∩ H` = `{sigint_handler_xjtr_0}`, whose body is `(void)sig;
g_interrupted_xjtr_0 = 1;` — no other static object. F2 holds.

**The single residual assumption.** After F1 and F2, exactly one thing is
assumed: *a `monotonic` load or store inside a loop is re-executed on each
iteration — the compiler does not hoist, sink, or promote it out.* C11 §7.17.3
and the Rust memory model only say a relaxed store *should* become visible in
finite time, so this is a quality-of-implementation property; in LLVM it holds
because LICM's hoist and promotion paths require `isUnordered()`. Reducing the
residual to this one statement is the point: it is a property a codegen
regression can assert, per profile row, in both directions. It is still an
assumption, and belongs in the audited soundness inventory (`DESIGN.md` §8);
Phase 4's dynamic SIGINT test exercises it.

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
upgrade. F1 and F2 instead make the permitted transformations harmless by
construction and leave one existentially checkable property behind.

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
  "text": "Certified signal-flag atomics assume the Rust backend does not hoist, sink, or promote a Relaxed atomic load or store out of a loop, and lowers load/store of the certified width without a library call. Bounded transformations that Relaxed permits (redundant-load elimination, dead-store elimination, coalescing) are not assumed against; certification requires the F1/F2 flag pattern, under which they are behavior-refining. This is a quality-of-implementation property, not an abstract-machine guarantee.",
  "envelope": {
    "triple": "x86_64-unknown-linux-gnu", "arch": "x86_64",
    "widths": [32], "operations": ["load", "store"],
    "rustc_min": "1.XX.0", "llvm_major": [17, 18, 19],
    "opt_levels": ["0", "1", "2", "3"],
    "evidence": "codegen-regression:signal_flag_codegen"
  }
}
```

**Declared scope, and no extrapolation.** The assumption is asserted for exactly
`{profile rows} × {widths in the row} × {rustc ≥ floor, LLVM in list} × {opt
levels}` and nothing else. A toolchain outside it is outside the audited
envelope, and the Rust stage refuses.

**Codegen regression, per profile row.** A row can be compiled for without being
runnable on, so the per-row gate is an artifact check and execution is a host-only
addition. The audited property is *absence of unbounded elision*, not
preservation of access count, so the assertions are positional. For every declared
row × width × opt level, compile fixtures and assert:

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
5. **Asm cross-check** on rows where the loop structure is recognizable: a memory
   operand naming the static appears between the loop label and its backedge, for
   both fixtures.

Then, host-only, the Phase 4 SIGINT test: a hoisted load makes the loop never
terminate, so the property is observed rather than inspected. It is a liveness
test and must run under a timeout, where a hang is a failure.

**The coupling that makes this enforceable:** a profile row is admissible **only**
if the codegen regression covers it, whether it comes from the built-in table or
an evidence bundle. A row without evidence is not a row — the concrete meaning of
"defaulting to empty", and why v1 ships exactly `x86_64`. If the regression fails
for a row, the row is removed, the width stops being lock-free-certified, and
signal flags on that target fall back to `unhandled`. Configuration can narrow or
supply fresh evidence, never re-add a width the regression rejected.

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

### 1. Encoding conventions

Already the manifest's conventions, restated so the new fields do not invent
alternatives.

- **v5 is defined once, in Phase 1.** The *entire* v5 contract —
  `word_sized_scalar`, `resolved_signal_context_access`, and every signal-flag
  payload and validator rule below — lands with the version bump in Phase 1,
  **dormant**: types, schema definitions, and validator rules all present, the
  signal-flag rules vacuously satisfied because nothing emits
  `volatile_semantics` until Phase 3, which then changes emission only. This is
  what keeps Phase 1 independently shippable. **A partially-introduced v5, in
  which two incompatible contracts both call themselves v5, is forbidden.**
- **Absence, not null, for optional detail.** Every *new* optional detail field
  uses `#[serde(skip_serializing_if)]`
  (`crates/pangs-manifest/src/lib.rs:321-328`); `null` is reserved for a *slot*
  meaning "not computed" (the certificate slots and `coupling_group`). A new
  field MUST NOT be emitted as an explicit `null`. **Carve-out:**
  `signal_lock_free.width` is already `integer | null` in v4 and keeps that
  encoding when `required == false`; in signal-flag mode it is required and
  non-null regardless.
- **Additive only.** Every object retains `#[serde(flatten)] Extra` and
  `additionalProperties: true`, so an unknown field round-trips. v5 adds fields;
  it renames and removes none.
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

### 2b. `facts.resolved_signal_context_access`

A new `EvidencedBool` with evidenced polarity **true**, added to `Facts`, to the
schema's `facts.required`, and to `evidenced_bool_true`. Required at v5; absent
at v4, which the version-parameterized validator accommodates.

```text
value == true   ⇒  witness present (resolving registration site + handler + path)
value == true   ⇒  signal_context_access.value == true
witness selection: the resolved registration with the lowest callsite id;
                   among paths from it, the shortest, ties broken by
                   callee order within each caller
```

The witness carries the **certified positive access path** (§E), not merely the
registration, because a witness naming only the registration would be satisfied
identically by a module-wide widening and by a real handler store:

```jsonc
"witness": {
  "registration": { "callsite": …, "file": …, "line": … },
  "handler": "sigint_handler_xjtr_0",
  "path": ["sigint_handler_xjtr_0"],          // f₀ … fₙ, direct-call edges only
  "access": { "via": "direct", "file": …, "line": … }
}
```

`via` is recorded explicitly and MUST be `"direct"`, so a reader can see the
rejection rule was applied rather than assume it. The shortest-path tie-break is
specified because a handler can reach a flag by several direct-call chains, and
an arbitrary choice would churn manifests across unrelated inlining changes.

`signal_context_access` is untouched — same semantics, widening-based
computation, first-wins witness, and consumers. The new fact is additive,
computed by a *different query*, and read by exactly one guard.

### 3. Version negotiation and fixture behavior

The v4 → v5 fact-layer delta has two parts: `word_sized_scalar`'s invariant
changes (**weaker** than v4 for `value: true`, **stronger** for `value: false`,
where codes are newly required), and `resolved_signal_context_access` is a **new
required fact** that v4 documents do not carry at all. The second is easy to lose
because it is additive and usually `false` at Phase 1, but it changes the parse
surface, the schema's `facts.required`, and the golden diff for every global
(§7, class A). Existing fixtures therefore do not uniformly pass, and
grandfathering them into a vaguer rule would destroy their value as tests.

- `Facts::validate` gains a `schema_version` parameter, threaded from
  `Manifest::validate` (`crates/pangs-manifest/src/lib.rs:903`, which today calls
  `global.facts.validate()` with no version). Documents declaring v4 are checked
  against the **v4 invariant exactly**, including the detail prohibition; v5
  documents against §2.
- Emission is always at `SCHEMA_VERSION`; the dual-invariant path is read-only.

| Reader | Document | Result |
|---|---|---|
| v4 | v5 | refused by the existing version gate (`lib.rs:904`) |
| v5 | v4 | accepted, validated under v4 rules; `resolved_signal_context_access` deserializes to its `#[serde(default)]` value |
| v5 | v5 | validated under §2 |

**Why the new fact needs `#[serde(default)]`.** No `EvidencedBool` in `Facts`
carries a serde default today (`crates/pangs-manifest/src/lib.rs:400-407`), so a
bare required field would make every v4 document fail to *parse*, before the
version-parameterized validator ever runs. `EvidencedBool::default()` is
`{ value: false }` with no witness, the correct reading of a v4 document. The
cost: "required at v5" cannot mean parse-time rejection, since a v5 document
omitting the field is indistinguishable after deserialization from one carrying
`value: false`. The requirement therefore binds **emitters**, pinned by the
schema's `facts.required` (which a non-Rust consumer checks) and by the goldens.
The residual — a hand-written v5 manifest omitting the field reads as `false` —
is fail-closed, because this is a permitting fact and `false` denies.

One further rule: **`pangs-dispose` never reads or writes `schema_version`.** It
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
    │   ├── declaration { … unchanged … }
    │   ├── accesses[]
    │   ├── cross_tu { … }
    │   ├── ordering: "relaxed"
    │   └── volatile_semantics: "certified-signal-flag"      ← new
    ├── source_materialization { status, code?, detail? }
    ├── signal_lock_free
    │   ├── required: bool
    │   ├── width: integer          (non-null in signal-flag mode; §1 carve-out)
    │   ├── target_guaranteed: bool
    │   ├── operations: ["load", "store"]                     ← new
    │   └── source: "builtin" | "evidence-bundle" | "none"    ← new
    ├── signal_atomic_type                                    ← new
    │   ├── typedef: "sig_atomic_t"
    │   ├── typedef_chain: ["sig_atomic_t", "__sig_atomic_t"]
    │   ├── volatile: true
    │   ├── width: integer
    │   └── align: integer
    └── signal_flag_pattern                                   ← new
        ├── sole_candidate: bool                              (F1)
        ├── handler_accesses_confined: bool                   (F2)
        └── observers[]                                       (witness: A ∩ H)
            ├── function: "sigint_handler_xjtr_0"
            └── via: "resolved" | "address-taken-widening"
```

Placement is load-bearing, not stylistic:

- **Signal-flag recipes are certified-only.** `Certificate::Failed`
  (`crates/pangs-manifest/src/lib.rs:350`) has `codes`, `witnesses`, `recipe`,
  and `diagnostics` and no certificate-level payload, so a failed slot has
  nowhere to put `signal_atomic_type` or `signal_lock_free`. Normatively: **a
  global whose admission required signal-flag mode and did not certify gets
  `recipe: null`.** This is already the behavior — `atomic_access_recipe` returns
  `(None, failures)` whenever any failure was recorded
  (`crates/pangs-clients/src/lib.rs:1992`), and the coarse gate sets
  `recipe: None` on its own path — stated as a rule rather than left an accident.

  The consequence is intended: per `DISPOSITION.md` §4.2 an `atomic` pin on such
  a slot is rejected `no-recipe`, **unwaivable by `accept_risk`**, so "you cannot
  override your way into an unproven signal-handler atomic" is structural rather
  than a policy rule someone must remember. Every failure code reachable in
  signal-flag mode — `signal-atomic-not-lock-free`, `volatile-access`,
  `address-access-not-lowerable`, `access-site-unmapped`, the `rmw-*` codes,
  `signal-flag-external-linkage`, `signal-flag-not-sole`,
  `signal-handler-access-not-confined` — means the rewrite cannot be executed
  correctly, so none is §4.2's honorable "evidence failed, recipe present" case.
  The two pattern codes belong in that list because they look like advisory
  hygiene, and waiving them would override the conditions that make dropping
  `volatile` sound at all (rule 15).

  Suppression stays diagnosable through `diagnostics`, which is opaque and
  load-bearing for nothing:

  ```json
  { "signal_flag": { "status": "recipe-withheld",
                     "reason": "signal-flag mode requires certification" } }
  ```

- **`volatile_semantics` lives in `recipe`** because the recipe is the
  materializer's input and the mode is a rewrite instruction (M.5).
- **`signal_atomic_type` and `signal_lock_free` live at certificate level**, as
  proof properties rather than rewrite instructions. A failure carries its reason
  in `codes`/`witnesses`, never as a partial proof object.
- **Presence coupling**, checked on the certified payload, plus a clause closing
  the failed path:

  ```text
  recipe.volatile_semantics == "certified-signal-flag"
    ⟺  signal_atomic_type present
    ⟺  signal_flag_pattern present
    ⟺  signal_lock_free.required == true

  and:  volatile_semantics present anywhere  ⇒  the slot is certified
  ```

- **Value coupling.** Presence alone would permit a certificate whose lock-free
  proof is for a different width than the declaration, or whose
  `target_guaranteed` is false, or whose typedef is not one this design
  recognizes. The validator MUST additionally require, with
  `W := recipe.declaration.size_bits`:

  ```text
  widths agree
    signal_atomic_type.width          == W
    signal_atomic_type.align          == W
    recipe.declaration.align_bits     == W
    signal_lock_free.width            == W        (present and non-null)
    W ∈ run.analysis.target_profile.lock_free_load_store_widths

  the lock-free proof is affirmative
    signal_lock_free.required         == true
    signal_lock_free.target_guaranteed == true
    signal_lock_free.operations       == ["load", "store"]
    signal_lock_free.source           ∈ {"builtin", "evidence-bundle"}   never "none"

  the certificate's provenance agrees with the profile that supplied W
    let P := run.analysis.target_profile          (present; see the P-absent rule)
    signal_lock_free.source == "builtin"
      ⟺  P.source ∈ {"builtin", "builtin+narrowed"}
    signal_lock_free.source == "evidence-bundle"
      ⟺  P.source == "evidence-bundle"
    P.source == "builtin+narrowed"   ⇒  P.narrowed_from present
    P.source == "evidence-bundle"    ⇒  P.evidence_bundle present

  the type evidence is the one that licensed admission
    signal_atomic_type.volatile       == true
    signal_atomic_type.typedef        ∈ signal_atomic_type.typedef_chain
    signal_atomic_type.typedef        ∈ RECOGNIZED_SIGNAL_TYPEDEFS       ( = {"sig_atomic_t"} )
    recipe.declaration.scalar_class   == "integer"

  the mode's other admission conjuncts are reflected
    recipe.declaration.linkage        == "internal"                      (M.8)
    recipe.ordering                   == "relaxed"
    facts.resolved_signal_context_access.value == true

  the flag pattern held                                                  (F1/F2)
    signal_flag_pattern.sole_candidate            == true
    signal_flag_pattern.handler_accesses_confined == true
    signal_flag_pattern.observers                 non-empty
  ```

  The pattern booleans are written out rather than implied by the object's
  presence so a certificate can be audited against the source without
  re-deriving why `Relaxed` needed them. `observers` carries the witness that
  makes F2 auditable at all: F2 is a claim about a specific set of functions
  (`A ∩ H`), and a certificate asserting it without naming them is checkable only
  by the analysis that produced it. It is non-empty because
  `resolved_signal_context_access` already guarantees a resolved registration
  reaching the global.

  F1 is a whole-program property, so the validator MUST also check globally:
  **at most one global in the manifest carries `signal_flag_pattern`**. A
  per-global check cannot catch two certificates that each claim to be sole.

  The alignment relation is `align == width` throughout, matching the
  `word_sized_scalar` gate §B leaves at equality.

  The **provenance clause** cross-checks deliberate redundancy: the mapping from
  `P.source` to `signal_lock_free.source` is total, which is what makes the
  certificate self-describing, but derivable-and-unchecked redundancy diverges.
  The failure it admits is the one the evidence-bundle mechanism exists to
  prevent — a certificate reporting the weaker, in-tree-and-reviewed provenance
  for a width that exists only because someone supplied a bundle, with the run
  header naming that bundle being exactly what the reader was told they need not
  consult. The reverse direction points an auditor at a bundle that does not
  exist. The clause is per-row because a profile row has exactly one provenance;
  if that changes, `signal_lock_free.source` must become per-width and this clause
  must be revisited rather than reinterpreted. `RECOGNIZED_SIGNAL_TYPEDEFS` is a
  closed constant in `pangs-manifest`.

  Two clauses are cross-section — the target profile lives in `run.analysis`,
  and `resolved_signal_context_access` is a sibling fact — so the profile must be
  threaded into per-global validation the same way `schema_version` is (§3);
  `Manifest::validate` already holds both.

  **`run.analysis.target_profile` is optional, and its absence is not a
  validation failure**, because every clause naming it sits inside the
  signal-flag coupling, which fires only when `recipe.volatile_semantics` is
  present. The clauses are unreachable at Phase 1, not vacuously true:

  ```text
  volatile_semantics absent   ⇒  P unconstrained (absent at Phase 1, present after)
  volatile_semantics present  ∧  P absent   ⇒  INVALID  ("signal-flag certificate
                                                          without a target profile")
  volatile_semantics present  ∧  P present  ⇒  the width clauses above apply
  ```

  The middle row makes a profile-less signal-flag certificate a validation error
  rather than a passed check over a missing operand. `P` is
  `Option<TargetProfile>` in Rust and optional in JSON, so a Phase-1 manifest is
  valid v5 without it and a Phase-3 signal-flag manifest cannot be valid without
  it — one validator, one contract, the profile's presence is data.

  Together these prevent a volatile-admitting recipe from shipping without the
  proof that admitted it, or with a proof of something adjacent to it. The
  rejected alternative — giving `Certificate::Failed` a proof-envelope field so
  the coupling could hold on both paths — would add a second separately-validated
  shape whose only reachable content is a partial proof of something that did not
  hold, for a case §4.2 already refuses to honor.

- **Scope.** All of the above constrains *signal-flag mode only*; ordinary
  atomic, mutex, and once-lock slots keep §4.2's honorable accepted-risk case.
- **Absence is the default.** `volatile_semantics` is a closed enum with one v5
  member; ordinary lowering omits the field rather than encoding `"none"`, so
  every v4 recipe is already valid v5.
- `signal_lock_free.operations` and `.source` are required when
  `required == true`, optional otherwise (a non-signal global's existing
  `{required: false, …}` object is unchanged, `null` width included).
  `operations` is exactly `["load", "store"]` in that order; extending it to RMW
  bumps the schema.
- `source_materialization` is **unchanged**: `status` remains
  `"source-mapped" | "blocked"`, `code` required iff blocked, and
  `declaration-source-unmapped` its only code. Spelling absence is a certificate
  diagnostic, not a status (M.0).
- `certificate.type_evidence` is a new optional diagnostic object: advisory,
  carrying no invariant, and MUST NOT be read by any guard.

### 5. Ordering, deduplication, truncation

- `typedef_chain` is in **outer-to-inner declaration order**, neither sorted nor
  deduplicated: it is a path, and its order is the evidence.
- `signal_atomic_type.typedef` is the **recognized standard typedef** — the name
  that licensed the certificate — and MUST be a member of `typedef_chain`, but is
  *not* necessarily `typedef_chain[0]`: under `typedef sig_atomic_t my_flag_t;`
  the chain is `["my_flag_t", "sig_atomic_t", "__sig_atomic_t"]` and recognition
  matches at position 1.
- `display_name` in the PIR-side `ScalarTypeEvidence` is a different name with a
  different rule (positionally `typedef_chain[0]`, §A). The two coincide only
  when the declaration names the standard typedef directly — the common case and
  the bore case — and MUST NOT be conflated: one answers "what did the source
  say", the other "what proved this certificate".
- When exactly one chain member is a recognized standard name, `typedef` is that
  member; two cannot occur, since recognition matches a single spelling.
- Exceeding `DEBUG_TYPE_RECURSION_LIMIT` yields **no certificate**, never a
  truncated chain. Same for cycles and malformed metadata.
- `codes`, `operations`, and `typedef_chain` are deterministic under re-emission;
  a golden diff that reorders any of them is a defect.

### 6. Freeze points, and an honest note about rigor

| Artifact | Change |
|---|---|
| `schemas/disposition-manifest.schema.json` | the `word_sized_scalar` `oneOf` (lines 139-166) *is* the v4 invariant and must be replaced by §2; **`resolved_signal_context_access` added to `facts.properties` and `facts.required`**; narrow definitions added for `signal_atomic_type`, `signal_flag_pattern`, the extended `signal_lock_free`, and `volatile_semantics`; `run.analysis.target_profile` added as optional |
| `crates/pangs-manifest/src/lib.rs` | `SCHEMA_VERSION = 5`; **`Facts.resolved_signal_context_access: EvidencedBool` with `#[serde(default)]`**; `WordSizedScalar.codes: Vec<String>` with `#[serde(default, skip_serializing_if = "Vec::is_empty")]`; version-parameterized `Facts::validate`; one validator for the §4 coupling |
| `crates/pangs-pir/src/lib.rs` | `Global.type_evidence: Option<ScalarTypeEvidence>` with `#[serde(default)]`, matching every other optional field there (lines 158-183), so existing PIR fixtures parse and re-serialize unchanged |
| `crates/pangs-api/src/lib.rs:142` | `GlobalInfo` mirrors the same optional field |
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
signal-flag additions is therefore *new* rigor, justified by the same asymmetry
that governs the target profile: these fields gate a silent failure, and the JSON
schema is the only artifact a non-Rust consumer can check. The rest of the
payload stays as it is.

### 7. The permitted golden diff

| Class | Condition | Permitted change |
|---|---|---|
| **A** | every manifest | `schema_version` 4 → 5; `facts.resolved_signal_context_access` added to every global record with a **computed** value, not a placeholder (v5 and its producer both land in Phase 1) |
| **B** | `word_sized_scalar` was already true | **nothing else changes** |
| **C** | was false, still false | gains non-empty `codes`; gains the `size_bits`/`class`/`signed` detail that v4 suppressed |
| **D** | false → true, still fails atomic later | class C's detail, plus `value: true`; `atomic_eligibility.codes` changes from `["word-sized-scalar"]` to the later decisive code; `diagnostics` changes from `access_lowering: skipped` to an observed-site count. Disposition unchanged |
| **E** | false → true, now certifies | class D's changes, plus `atomic_eligibility` Failed → Certified with recipe and `source_materialization`; `cascade_chosen`/`chosen` → `atomic`; `cascade_trace` shortens; `run.dispose.measurement_report` moves |

Class D is the bore flag's own Phase-1 diff: it clears the coarse gate and fails
on `volatile-access` instead.

Class A's value may be `true` at Phase 1 for globals in modules whose
registrations the registry *already* recognizes — a direct `sigaction`, or a
`signal` not aliased to `__sysv_signal`. That is correct and changes no
disposition, since the fact's only consumer is dormant until Phase 3; a reviewer
seeing `true` should check that the module has a recognized registration, not
that the fact is inert.

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

`size_bits` must equal the width in `signal_lock_free`, which D3 guarantees; a
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
| Rust | unmappable type, untranslatable or out-of-range initializer, unclassifiable reference, unexpandable macro mentioning the symbol, count mismatch, missing marker | **loud build failure** |

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
inventory (or the module-wide fallback) in §E closes it.

Lifting the restriction requires a **whole-program certificate**: proof that
every TU accessing the symbol is transformed in one run, so no non-atomic
accessor survives. No such certificate exists, and v1 does not reason about a
half-translated program. The bore flag is `static`, so the restriction costs
nothing for the motivating case.

## Soundness rules

1. Missing or incomplete typedef/qualifier metadata never proves
   `signal_atomic_type`.
2. A generic volatile access remains a hard atomic-eligibility failure.
3. A signal-context atomic must be target-guaranteed lock-free for exactly the
   operations the recipe emits; a library-based fallback is forbidden in an
   async-signal handler, and an unknown target profile is not lock-free.
4. Every access to the global must be enumerated and lowered; an incomplete
   access set fails closed.
5. No mixed atomic/non-atomic or atomic/volatile representation is emitted —
   **including across a translation-unit boundary**. Conflicting atomic and
   non-atomic access to the same storage is undefined behavior under Rust's
   memory model, and identical layout does not make it defined (M.8).
6. Width, alignment, and signedness must match the declaration and every access.
7. Registry alias recognition is exact and shape checked, and a shape mismatch
   downgrades a registration to unresolved rather than deleting it. Only a
   resolved registration may satisfy a permitting conjunct, and "resolved" is the
   conjunction of **four** conditions — name, declaration, shape, and
   handler-operand completeness — not the first three; an operand whose points-to
   is external, untargeted, or absent is unresolved however well the call matched
   the table, and its non-empty target list is not a precise one.
8. Unknown handler targets or unknown signal-context accesses retain the
   appropriate conservative facts, and "conservative" is direction-dependent: for
   a *restricting* fact it means widening (`signal_context_access` sets every
   global on a `ModuleWide` effect, which is correct); for a *permitting* fact it
   means the opposite — no widened, aliased, or may-set access path may establish
   `resolved_signal_context_access`.
9. The certificate provides scalar atomicity only. It does not certify
   publication of unrelated memory and does not model the interleaving between
   handler and interrupted code; it certifies that each individual access remains
   indivisible. It is **not** the whole of what the source relied on — the source
   also relied on `volatile`'s preservation of access count and relative order,
   which rule 15 discharges.
10. Volatile admission requires proven signal-handler participation, evidenced by
    at least one *resolved* registration. Type evidence alone never admits a
    volatile access, and neither does an unresolved registration.
11. Recognizing a registration alias never relaxes the Ω boundary at that call:
    it adds spawn/signal facts and removes a phase-analysis unresolved-effect
    widening, leaving every points-to, mod/ref, and escape consequence unchanged.
12. The redefined `word_sized_scalar` never becomes a certificate by itself. It
    is a coarse gate; certification still requires the complete access recipe,
    and source readiness never feeds back into the certification guard (M.0).
13. The C→C stage never removes `volatile` or alters an access: between the two
    stages the program must remain a correct C program, and a declaration
    stripped of `volatile` before an atomic exists in its place is not one.
14. A signal-flag atomic exists only as a complete certified proof. There is no
    partial, failed, or overridden form: a failed proof emits no recipe, and no
    override can supply one.
15. `Relaxed` does not preserve the number or relative order of accesses;
    redundant-load elimination, dead-store elimination, store-to-load forwarding,
    and coalescing are all permitted on `monotonic`. Certification therefore
    requires the F1/F2 flag pattern — one candidate per program, and
    handler-observer confinement for every function that both accesses the flag
    and may run as a handler — under which every such transformation is
    behavior-refining because signal arrival timing is unconstrained. Without the
    pattern, dropping `volatile` is unsound, not merely optimistic.
16. The only residual assumption in signal-flag mode is the absence of
    *unbounded* elision: a `monotonic` load or store in a loop is re-executed
    each iteration. It is asserted per profile row by positional codegen
    assertions on both the load and store side, never by access-count equality,
    which would reject a legal RLE and accept a store sunk past a loop.
17. Every fact that *permits* something requires a finite, exhibitable positive
    path: an exact global root (`Via::Direct`), reached from a precise target of
    a resolved registration over direct-call edges only.
    `AffectedGlobals::ModuleWide`, a finite may-set, an aliased or unknown
    access, an indirect call edge, and a target drawn from the address-taken
    widening each set the restrictive fact and none of them sets the permitting
    one.
18. Every conjunct in an admission predicate must be evaluable from a fact that
    exists, and the note must name it. A clause phrased over a relation the
    pipeline does not compute — "no external-linkage alias targets the global",
    when the alias's target is never resolved — is worse than an absent clause:
    it reads as a guard, is cited as one, and an implementer will most plausibly
    discharge it by evaluating it to `false`. Where the fact does not exist, the
    design must either add it or state the blunter fact that stands in for it.

## Amendments required to other documents

Nothing here touches A′–D′ or any solver semantics; the changes are confined to
PIR lowering, the F-layer fact scans, and the manifest schema.

1. **`DISPOSITION.md` §2 (fact table)** — a new `resolved_signal_context_access`
   row, described as a guard conjunct for volatile admission and explicitly *not*
   a replacement for `signal_context_access`, whose row is unchanged. The row
   must state the **provenance restriction**, not just the resolvedness one: a
   row saying "resolved registrations only" would lead directly to the
   filtered-copy defect. §1's guard-shape rule gains the general statement
   (rule 17). The `word_sized_scalar` row loses "type spelling exists" and gains
   the statement that detail fields survive a false value, becoming a
   machine-level fact with materializability split out.
2. **`DISPOSITION.md` §3 / §3.2** — `schema_version: 5` per the freeze above: the
   detail/value coupling invariant is replaced, `word_sized_scalar` gains
   `codes`, and the `atomic_eligibility` certificate gains
   `recipe.volatile_semantics`, the extended `signal_lock_free`,
   `signal_atomic_type`, and `signal_flag_pattern`. The schema-v4 sentence in §2
   gains a v5 clause, and §3.3's stage-ownership rule gains the exact-version
   requirement.
3. **`DISPOSITION.md` §3.2 / §3.3 (`run.analysis`)** — the run header gains
   `target_profile`, **optional**: absent in a manifest with no signal-flag
   certificate, required in one that has any. The optionality must be stated
   where the field is documented, or a reader will take a Phase-1 manifest's
   missing profile for a defect.
4. **`DISPOSITION.md` §7 (soundness matrix)** — the `atomic` row's "no additional
   relational failure for defined source behavior" needs a signal-flag
   qualification: what makes the substitution behavior-preserving is the F1/F2
   pattern plus the unconstrained timing of signal arrival (rule 15), and what
   remains assumed is only the absence of unbounded elision (rule 16) — the first
   as a stated precondition of the row, the second as a recorded assumption. Add
   the dynamic-audit cell (Phase 4's SIGINT test) and the per-row codegen
   assertions. **`DESIGN.md` §8** takes the same assumption in its audited
   soundness inventory, phrased as the single residual, not as "volatile is
   replaced by Relaxed".
5. **`DISPOSITION_PLAN.md` §1.5** — the evidenced/certificate encodings D1a's
   golden test freezes; the scalar failure-diagnostic vocabulary belongs there,
   not only here. `source_materialization`'s code list is unchanged.
6. **`DISPOSITION.md` §5.3 (stage actions)** — the `atomic` row is unchanged, but
   the section describes demotion as though every materialization failure had a
   channel. It should state that the Rust-side rewriter owns no manifest section,
   therefore fails loudly rather than demoting, and that the `unhandled` pin is
   the operator's recourse (M.7). A pre-existing gap this feature surfaces.
7. **Audit ledger kinds** — `registry-shape-mismatch` (§D.6) and
   `signal-flag-codegen-assumption` (§E). Both are analysis-sourced, so
   `DISPOSITION.md` §3.3's rule applies (dispose regenerates only
   `source: "override"` records). **No change to
   `schemas/disposition-audit.schema.json` is required**: `kind` is a free string
   and the schema is `additionalProperties: true`. Document the kinds in
   `DISPOSITION_PLAN.md` §1.4 alongside the deterministic-id rule. Deliberately
   *not* ledger kinds: the operand-side unresolved reasons.
7b. **`DISPOSITION.md` §2 / `pangs-api` docs (registry resolution)** — wherever
   `RegistryEntryResolution.unresolved` is described, the four-conjunct
   definition replaces the three-conjunct one and the `UnresolvedReason`
   vocabulary is named. Most likely to be skipped, because the operand conjunct
   is existing behavior rather than a change — which is why the prose does not
   currently mention it.
7c. **`pangs-pir` lowering docs (`LoweringStats`)** — if the inventory option is
   taken, `alias_exposed_globals` is a *fact*, not a metric, and belongs
   documented apart from the `*_counts` maps beside it. Add a sentence stating
   that `tainted_counts`, `skipped_counts`, and `modeled_counts` are
   observability counters read by no guard.
8. **`DESIGN_lite.md` §2A** — the registry paragraph describes only the Ω
   external-summary registry. Add one sentence distinguishing the spawn/signal
   disposition registry (name-keyed, conservative-on-false-positive, no Ω
   effect), so a reader does not infer that adding `__sysv_signal` summarizes an
   external call.
9. **`HOWTO_MEASURE_DISPOSITION_COVERAGE.md` and the `notes/disposition_*`
   baselines** — `not_word_sized` and the would-be-eligibility counters change
   meaning at Phase 1; the re-measurement note must say so rather than
   re-baselining silently.

## Implementation sequence

Phases 1 and 2 are independent; Phase 3 depends on both, because its admission
conjunction names a fact from each. That independence puts
`resolved_signal_context_access`'s **schema and producer both in Phase 1**, with
Phase 2 changing only its values: splitting them would make Phase 2 unable to
land first, since emitting a changed v5 field requires v5.

### Phase 1: diagnostics and type normalization

- Add a bounded qualified-type walker in `pangs-pir`; preserve typedef chains and
  qualifiers in PIR/API metadata.
- Split `word_sized_scalar` from source spelling/materialization, keeping the
  alignment condition at equality, and emit granular scalar failure diagnostics
  with partial evidence retained.
- Record spelling absence as a certificate diagnostic, **not** a
  `source_materialization` block (M.0); `declaration-source-unmapped` keeps its
  meaning and remains the only blocked code.
- Bump `SCHEMA_VERSION` to 5 and land the **complete** freeze — not only the
  parts Phase 1 exercises: `word_sized_scalar.codes`;
  `resolved_signal_context_access`; the signal-flag payload definitions in
  `schemas/disposition-manifest.schema.json`; the full presence *and* value
  coupling validator, threaded with `schema_version` and
  `run.analysis.target_profile`; the exact-version requirement for stages that
  preserve earlier sections; and regenerated goldens. Threading the profile
  through the validator does **not** mean Phase 1 emits one: the field is
  optional and absent until Phase 3, and every clause naming it is reachable only
  from a signal-flag certificate. A Phase-1 manifest with no `target_profile` is
  valid v5; a signal-flag certificate without one is invalid — the check being
  landed early.
- Land the **producer** for `resolved_signal_context_access` here too: the
  certified-positive-path query of §E, walking `access_sites_for_global` back
  over direct-call edges to the precise targets of resolved registrations and
  recording the path as the witness. It is **not** a filtered copy of
  `registry_access_facts` — that version would inherit
  `AffectedGlobals::ModuleWide` and mark every global positively
  signal-accessed — and a code comment at the query should say so, because the
  filtered-copy version is the obvious implementation and looks right. The fact
  is computed for real from Phase 1 on, and is simply `false` for the bore flag
  until Phase 2 recognizes `__sysv_signal`. Fact-provenance tests land with it.
  (The alternative — schema here, producer in Phase 2, hardcoded `false` between
  — was rejected because a dormant constant in a required field is
  indistinguishable in a golden from a computed one, and it would make Phase 2
  depend on Phase 1.)
- The signal-flag rules ship **dormant**: nothing emits `volatile_semantics`
  until Phase 3, so the clauses guarded by it are unreachable rather than
  vacuously true. A test asserts exactly that — the validator is live, every
  Phase-1 manifest passes it, and a hand-written fixture carrying
  `volatile_semantics` with no `target_profile` is rejected. "Dormant" covers the
  signal-flag certificate payload and its coupling, not
  `resolved_signal_context_access`, which is live from this phase on.

This phase makes the manifest accurately say that `g_interrupted` is an aligned
signed 32-bit scalar while still rejecting its volatile access recipe. The
`atomic` slot is `failed` with `recipe: null`, so a user cannot reach `atomic` by
overriding either — `DISPOSITION.md` §4.2's `no-recipe` rejection applies and is
not waivable by `accept_risk`.

### Phase 2: registry correctness

- Validate first with `--registry-config` on the bore module: no code change,
  observable fact delta. Then add `__sysv_signal` to the built-in table.
- Land `RegistryShape` (§D.2) and the three-valued resolution (§D.5) as a
  separately reviewable step, with shapes for `signal`, `sigaction`, and
  `__sysv_signal`; regress the corpus, where the worst case is a downgrade to
  unresolved rather than a lost fact.
- Replace `RegistryEntryResolution.unresolved: bool` with
  `unresolved_reasons: BTreeSet<UnresolvedReason>` and a derived `unresolved()`,
  populating the operand reasons from the conditions `resolve_registry_entries`
  already computes (`crates/pangs-api/src/lib.rs:4302-4313`). This is a refactor
  of existing behavior into a nameable form, so corpus resolution results must be
  **identical** before and after.
- Add the `registry-shape-mismatch` audit record and `--strict-registry`, scoped
  to `ShapeMismatch` only.
- Confirm the handler resolves to `sigint_handler_xjtr_0` and that
  `bore_search_cleanup`'s restore call carries exactly `OperandExternal` — the
  motivating example exercises both outcomes in one module.
- Confirm `g_interrupted` becomes signal-context-accessed and that
  `resolved_signal_context_access` **flips false → true**. No schema, `Facts`
  field, or new query lands here; Phase 2's entire contribution is that
  recognizing `__sysv_signal` makes the registration resolved, supplying the
  certified positive path the Phase-1 query was already looking for. Phase 2 is
  not complete until the flip is observed.
- Confirm mutex is rejected by `signal-context-access`, independently of its
  existing reentrancy result.
- Record the corpus disposition distribution before and after: recognizing the
  registration also removes a phase-analysis unresolved effect, which can move
  unrelated globals into `once-lock`.

This phase repairs facts required by the eventual atomic proof and must land
before the special volatile admission.

### Phase 3: narrow signal-flag atomic recipe

- Add `lock_free_load_store_widths` from the arch-keyed profile (one row:
  `x86_64`) and **populate** `run.analysis.target_profile`, whose optional field
  and validator clauses landed in Phase 1. Switch **only** the signal gate
  (`crates/pangs-clients/src/lib.rs:1113,1217`) onto it;
  `supported_atomic_widths` and its derivation are untouched. (This is the same
  schema-versus-producer split as `resolved_signal_context_access`, resolved the
  other way: that fact's producer went to Phase 1 so Phase 2 could land first,
  while nothing before Phase 3 can emit a manifest needing a profile. In both
  cases the *contract* is Phase 1's.)
- Land the codegen regression *before* the profile row it justifies: a row is
  admissible only if the regression covers it.
- Emit the `signal-flag-codegen-assumption` ledger records from the checked-in
  evidence table, and add the Rust-stage toolchain-envelope check.
- Add `section: Option<String>` and `thread_local: bool` to `pangs_pir::Global`
  (both `#[serde(default)]`) and surface them through the API, so the
  ordinary-storage predicate is checkable at all.
- Decide the alias clause on measured coverage, first thing in the phase: count
  corpus modules whose `lowering.tainted_counts` has an `alias_`-prefixed key.
  Near zero ships the module-wide fallback (no PIR change); otherwise land
  `LoweringStats::alias_exposed_globals` and the reordering of
  `collect_alias_map`. Either way the clause must be backed by a fact that exists
  (rule 18).
- Add `signal_atomic_type` certification, including typedef provenance.
- Add the F1/F2 checks and emit `signal_flag_pattern`. F1 is a count over the
  candidate set and must therefore run *after* all per-global evaluation, as a
  whole-program pass; F2 groups the recipe's access list by enclosing function to
  get `A`, intersects it with the registry target set including §D.5's widening
  to get `A ∩ H`, and queries each survivor's static-storage access set. Both are
  admission conjuncts, not diagnostics — a failure yields `recipe: null`.
- Thread it into atomic access recipe construction, gated on the full §E
  conjunction — including `resolved_signal_context_access`, **not**
  `signal_context_access`; the two are one word apart and the wrong one is the
  permissive one.
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
- `display_name` is `typedef_chain[0]`: `sig_atomic_t` for the direct
  declaration, `my_flag_t` under `typedef sig_atomic_t my_flag_t;`,
  `__sig_atomic_t` only when the source names it directly. With no typedef it is
  the terminal type's name (`int`); with an anonymous enum it is absent.
- Under `typedef sig_atomic_t my_flag_t;` the certificate's `typedef` is
  `sig_atomic_t` while `display_name` is `my_flag_t`, asserted separately so a
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

- A v4 document validates under v4 rules including the detail prohibition; the
  same document with detail added at `value: false` is rejected as v4 and
  accepted as v5. A v5 document with `value: false` and no `codes` is rejected. A
  v5 document is refused by a v4 reader through the existing version gate.
- A stage that preserves earlier sections refuses a document whose
  `schema_version` differs from its own, rather than re-emitting under the
  input's version.
- The §4 presence coupling is rejected in all three broken directions:
  `volatile_semantics` without `signal_atomic_type`; `signal_atomic_type` without
  the mode; the mode with `signal_lock_free.required: false`.
- Each §4 **value** coupling clause is rejected independently, one test per
  clause, on a payload well-formed except for a single wrong value:
  `signal_atomic_type.width` ≠ declaration width; `align` ≠ width;
  `signal_lock_free.width` ≠ declaration width, or null; a width absent from
  `run.analysis.target_profile.lock_free_load_store_widths`;
  `target_guaranteed: false`; `source: "none"`; `typedef` not in `typedef_chain`;
  `typedef` not in `RECOGNIZED_SIGNAL_TYPEDEFS`; `volatile: false`;
  `scalar_class` ≠ `"integer"`; `linkage: "external"`; `ordering` ≠ `"relaxed"`;
  `resolved_signal_context_access: false`; and each `signal_flag_pattern` boolean
  `false`. Presence coupling alone passes every one of these. (The
  provenance-agreement clause is covered under §"Codegen and audit-envelope
  tests", whose counter-fixture needs a configured profile row.)
- **`run.analysis.target_profile` conditionality**, asserted as a set: a v5
  manifest with no signal-flag certificate and no profile is **valid**; the same
  manifest with a signal-flag certificate and no profile is **rejected**; with
  both, the width clauses apply.
- **The v4 → v5 fact delta is two-part**: a v4 document round-trips through a v5
  reader with `resolved_signal_context_access` defaulted to `{ value: false }`
  and no parse error, and a v5 document omitting the field reads as `false`
  rather than failing. A golden assertion pins that every emitted v5 manifest
  carries it — where "required at v5" actually binds.
- The dormant-contract test: a Phase-1 manifest with no signal-flag payload
  satisfies the full coupling validator vacuously, and the validator is
  demonstrably live (a hand-built bad payload in the same run is rejected).
- Golden classification (§7): a fixture corpus with one global of each class A–E
  regenerates with exactly the permitted changes, and the two defect signals are
  asserted to fail — a class-B global perturbed by one field, and a class-E
  global whose prior failure code was `unsupported-atomic-width` rather than a
  missing spelling. Aggregate: `not_word_sized` decreases by exactly |D| + |E|,
  and `measurement_report` is byte-identical when |E| = 0.
- A **failed** slot carrying `recipe.volatile_semantics` is rejected by the
  fourth presence clause. A signal-flag global that fails any check has
  `recipe: null` and a `diagnostics.signal_flag.status: "recipe-withheld"`
  record. An `atomic` pin on that slot is rejected `no-recipe` **with**
  `accept_risk = true`, not merely without it. An ordinary atomic, mutex, or
  once-lock slot is unaffected, proving the rule is scoped.
- `signal_atomic_type` and `signal_lock_free` never appear in a failed slot's
  `recipe`.
- Re-emission is byte-identical: `codes`, `operations`, and `typedef_chain`
  ordering is stable across runs.

### Registry tests

- `signal`, shape-correct `__sysv_signal`, and `sigaction` identify their
  handlers.
- A same-name external declaration with a wrong shape resolves to an
  **unresolved registration**, not "no registration": `signal_context_access` is
  still set, `phase_stationarity` keeps its unknown effect, and a
  `registry-shape-mismatch` record is emitted. An unresolved registration leaves
  `resolved_signal_context_access` false, so a `volatile sig_atomic_t` behind it
  stays rejected.

**Unresolved-reason tests**, one fixture per reason plus the combination:

- A shape-checked `signal(2, handler)` whose handler operand's points-to reaches
  an external boundary carries `OperandExternal`, is **unresolved despite a
  non-empty `targets` list**, and widens. Its flag is not admitted, and F2's `H`
  includes the address-taken widening rather than only the named targets.
- An operand with no targeted points-to carries `OperandUntargeted` with an empty
  `targets` list; a call with no argument at the entry index carries
  `OperandAbsent` — and, with shape checking live, **both** reasons, the set
  rather than a winner.
- A mismatched shape whose operand is also external carries `ShapeMismatch` and
  `OperandExternal`; exactly one `registry-shape-mismatch` record is emitted, and
  none for the operand reason.
- `--strict-registry` fails on `ShapeMismatch` and not on operand-only reasons.
  Bore is the regression fixture: its restore call carries `OperandExternal` on
  every run and `--strict-registry` must still exit zero.
- `unresolved()` is true iff `unresolved_reasons` is non-empty, checked over the
  whole corpus.
- A global reached by both a resolved and an unresolved registration has both
  facts true and **is admitted** (the existential predicate).
  `resolved_signal_context_access` witnesses the lowest-callsite-id resolved
  registration with its shortest certified path, stably and independently of how
  many unresolved ones exist.
- An unresolved registration widens to precise targets ∪ internal address-taken
  functions; a function that is neither is not made signal-context-accessed.
- A *defined internal* function named `signal` is not a registration
  (`external_only`) and emits no mismatch record; an internal wrapper named
  `signal` forwarding to libc still yields a registration, recognized at the
  inner external call.
- Arguments with `ValueKind::Unknown` never mismatch; a proven `NonPointer` in
  the handler position does.
- A discarded result (`signal(2, h);`) does not fail the return's **value-kind**
  constraint, and `sigaction` is still separated from `signal` by arity on that
  same call — while the return's **ABI** constraint still fires there: a spec
  declaring `ret: "void"` against an observed `AbiClass::Integer` is a
  `ShapeMismatch`. This pair pins the §D.2 split.
- Arity, `vararg`, and `cc` reject on every call regardless of node availability:
  a fixture whose argument nodes are all `Unknown` still fails on wrong arity.
- Config validation rejects, at load and by name, an entry whose `entry` index is
  out of range or whose `ParamShape` there is not `PointerLike`. A user entry
  replacing a built-in inherits its shape; a new name with no shape is unchecked
  and records an audit note.
- Handler global accesses set `signal_context_access`; an unresolved handler
  widens conservatively; `--strict-registry` turns a built-in-name mismatch into
  a non-zero exit.

**Fact-provenance tests** — the sharpest in the note, because the failure they
guard against is silent and total (a permitting fact true for every global).

- **The `ModuleWide` case.** A handler with one unanalyzable pointer store (so
  its transitive summary is `ModuleWide`) plus a `Via::Direct` store to the flag:
  every global gets `signal_context_access: true`, and **exactly one** — the flag
  — gets `resolved_signal_context_access: true`; an unrelated
  `volatile sig_atomic_t` in the same module is not admitted. Asserted as a
  count, so the test fails loudly if the query is ever reimplemented as a
  filtered copy of `registry_access_facts`.
- The same fixture with a **fully resolved** registration still yields exactly
  one positive global, pinning that `ModuleWide` is orthogonal to `unresolved`.
- A handler whose only access to the flag is through a pointer with a finite
  two-element candidate set gets `signal_context_access: true` and
  `resolved_signal_context_access: false`; the flag is not admitted and also
  fails `address-access-not-lowerable`, so the two rejections agree.
- A path `handler → helper → flag` over `CallDirect` edges is accepted with
  witness `path: [handler, helper]`; the same shape with an indirect middle edge
  is rejected even when the call graph resolves it to exactly one callee.
- A handler reached **only** through the address-taken widening sets
  `signal_context_access` and not the permitting fact.
- Witness determinism: two direct-call paths of different lengths record the
  shorter; equal lengths record callee-order-first; the manifest is
  byte-identical across runs.
- `resolved_signal_context_access ⇒ signal_context_access` holds on every corpus
  module, checked as an invariant rather than a fixture.

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
  would pass against the broken lowering.
- Under the module-wide fallback, that fixture rejects **every** global in the
  module, and a module with an unrelated external alias to a *function* also
  rejects — so the fallback's cost is visible in CI. Under the inventory, an
  external alias to an unrelated function does **not** reject and
  `alias_exposed_globals` names the flag only in the aliased case. Whichever
  option Phase 3 selects, the other's tests are `#[ignore]`d rather than deleted.
- An alias whose aliasee is not a resolvable constant symbol is covered by the
  fallback and not by the inventory, asserted as a known inventory gap.
- A `volatile sig_atomic_t` on a target without guaranteed lock-free load/store
  fails `signal-atomic-not-lock-free`; an unknown triple fails the same way
  rather than inheriting a default width list. Both need a synthetic fixture with
  an unlisted triple, since the corpus is entirely `x86_64`.
- A non-signal global's atomic eligibility is **unchanged** by the profile: a
  fixture on an unlisted triple still certifies `atomic` through
  `supported_atomic_widths`, proving the two lists are not coupled.
- Address escape, indirect access, partial-width access, bulk memory access, and
  volatile RMW all fail.
- An **external-linkage** `volatile sig_atomic_t` satisfying every other conjunct
  fails `signal-flag-external-linkage`, in both executable and library mode,
  including when `access_set_complete` is true — the case the redundancy exists
  for. An ordinary external-linkage atomic is unaffected.
- A signal flag used as a payload-publication protocol gains no acquire/release
  claim from this certificate.
- **F1**: two otherwise-certifiable flags fail `signal-flag-not-sole` on **both**
  — no winner — and no `signal_flag_pattern` appears. A manifest hand-edited to
  carry two `signal_flag_pattern` objects is rejected by the validator's
  whole-program check, which the per-global coupling cannot catch.
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
- **An unresolved registration does not block certification.** A fixture
  mirroring bore — one resolved `signal(2, handler)` plus a restore call whose
  operand comes from an external return — still certifies. Its companion fixture
  asserts the unresolved registration still widens `H`, pulling in an
  address-taken flag-poller so that F2 then fails.
- An `atomic` override on a Phase-1-state global (failed slot, `recipe: null`) is
  rejected `no-recipe` even with `accept_risk = true`.

### Codegen and audit-envelope tests

- For every declared profile row × width × opt level `{0,1,2,3}`: no `__atomic_*`
  reference; a `load atomic monotonic` remains in the polling loop body with the
  exit condition depending on it; a `store atomic monotonic` remains in the
  storing loop's body with none migrated to the exit block; both stores of
  `flag = 1; work(); flag = 0;` survive.
- The assertions are positional, not count-based, proven by a negative test: a
  fixture with two adjacent loads and nothing between them, legally collapsed to
  one, **passes**.
- A row whose codegen regression is absent or failing is rejected by the profile
  table's own test — evidence and row land together.
- `--target-profile` narrowing a built-in row is accepted, emits
  `target-profile-narrowed`, and records `narrowed_from`. Asserting a width or
  arch row the built-in table lacks, with no evidence bundle, is **rejected**,
  including with any accepted-risk spelling.
- An evidence bundle is accepted only when its fixture hash matches the in-tree
  fixture, its toolchain is inside the envelope, and every claimed
  `(width, operation)` passed; a stale fixture hash, an out-of-envelope
  toolchain, and a missing assertion each reject it.
- A narrowed row's certificates report `source: "builtin"`; an evidence-bundle
  row's report `"evidence-bundle"` and the run header names the bundle.
- **Provenance disagreement is rejected by the validator**, both directions and
  independently of emission: `signal_lock_free.source: "builtin"` under an
  `evidence-bundle` row is invalid, and so is `"evidence-bundle"` under a
  `builtin` row. The first is provenance laundering and passes every other §4
  clause, so it is asserted with the certificate otherwise fully well-formed.
- `builtin+narrowed` without `narrowed_from`, and `evidence-bundle` without
  `evidence_bundle`, are each rejected; a `builtin+narrowed` row's certificate
  reporting `"builtin"` is **accepted**.
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

- `g_interrupted_xjtr_0` has `signal_context_access: true` and
  `resolved_signal_context_access: true`, the latter witnessed by the zero-length
  path `["sigint_handler_xjtr_0"]` with `via: "direct"`;
- **no other global in the module** has `resolved_signal_context_access: true`,
  asserted as a count. The module has a second, unresolvable registration
  (`bore_search_cleanup`'s `signal(2, g_prev_sigint_handler_xjtr_0)`), so this is
  a live check that the widening does not leak into the permitting fact;
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
  defect:     any global moving OUT of a strategy
  defect:     any global moving IN for any other reason
  defect:     any change to a global whose word_sized_scalar was already true
  ```

  A certified global whose `source_materialization` is `blocked` still counts as
  `atomic` (M.0); its execution is the materializer's problem, corrected by
  demotion if it arises. The bore flag does not move at Phase 1 — it reaches the
  detailed recipe and fails on `volatile-access`.
- After Phase 2, any global that moves is either newly `signal_context_access`
  (expected: loses `mutex`, tightens `atomic`) or newly `once-lock` from the
  removed unresolved effect (expected: strictly more precise). Any other movement
  is a defect to explain before Phase 3 lands.

  Phase 2 also changes `resolved_signal_context_access` values — a manifest diff
  without a disposition diff, since the fact's consumer is still dormant. Every
  flip must be `false → true` and attributable to a registration that became
  resolved; a flip the other way means the registry change *lost* a resolution,
  which no other assertion here would catch.
- After Phase 3, only globals with `signal_context_access: true` may move, in two
  distinguishable directions: *into* `atomic` for a certified signal flag, and
  *out of* `atomic` for a signal-context global that certified under the old
  pointer-width heuristic on an arch the profile does not list. The second is a
  deliberate coverage loss correcting an unbacked claim, and is empty on the
  current all-`x86_64` corpus. Movement by a global without
  `signal_context_access` is a defect, since `supported_atomic_widths` did not
  change.
- Phase 3 must report the **alias-exposure census** (§E) — corpus modules
  carrying an `alias_`-prefixed lowering taint — because it *gates* the choice
  between the module-wide fallback and the PIR inventory; reporting it afterwards
  is worthless.
- Phase 3 must also report a **pattern-condition census**, because F1 and F2 are
  the conjuncts most likely to make the feature inert unnoticed: per module, the
  number of signal-flag candidates (F1 admits only modules with exactly one), and
  per candidate the size of `A ∩ H` and whether every member is confined. A
  module rejected by F1 is expected; a corpus in which *most* candidates are
  rejected by F2 means either the widening is too coarse or real handlers
  routinely touch other statics, and either finding should be resolved before
  Phase 4 rather than absorbed as low coverage.

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
- Admitting `_Atomic` globals, which are a different lowering with a different
  recipe.
- Signal flags with external linkage, absent a whole-program certificate that
  every accessing TU is transformed (M.8).

## Decisions

No design question here is open. Each decision is normative and carries its
**falsifier** — the observation that must be made before it may be changed.

**D1. Typedef and qualifier evidence lives inside the `atomic_eligibility`
certificate** (path frozen in §"Schema v5" §4), not as a first-class
`source_type` fact, holding the v5 fact-layer surface to the `word_sized_scalar`
change alone.
*Falsifier:* a second consumer of the evidence. Promotion to a fact slot is then
schema v6, additive, and forced by nothing else.

**D2. `supported_atomic_widths` is unchanged; the signal gate moves to a
profile-backed `lock_free_load_store_widths`.** The general list's failure mode
is a Rust compile error, the signal gate's a silent handler deadlock; only the
second warrants an authoritative profile, and replacing both would zero the
coarse atomic gate on any unlisted triple.
*Falsifier:* the derived profile and the pointer-width heuristic
(`llvm_sys.rs:407`) disagreeing for a width on a triple the corpus contains. That
is a bug report about the general atomic recipe and gets its own note; it does
not retroactively justify migrating both lists here.

**D3. Missing source spelling blocks nothing.** It makes `word_sized_scalar` true
and is recorded as a certificate diagnostic, since no stage consumes
`recipe.declaration.type_spelling` (M.0, M.3).
*Falsifier:* a materializer stage that genuinely requires the C spelling — which
would be a change to M.3's type mapping, not a discovery about this fact.

**D4. The no-elision property gets an audit contract, not a guarantee**: a
declared envelope of rows × widths × rustc floor × LLVM majors × opt levels, a
per-row codegen regression that is a precondition for the row existing, a ledger
record whose own text states the limit, and a Rust-stage check refusing
toolchains outside the envelope.
*Falsifier:* a codegen regression failure for a row. The response is mechanical
and already specified — remove the row, the width stops being lock-free
certified, signal flags on that target fall back to `unhandled`. No manual
override.

**D5. Signal aliases are unconditional exact-name registry entries, shape
checked**, not triple- or libc-keyed. With shape checking, `external_only`, and
the three-valued outcome, a `__sysv_signal` that is not glibc's fails the shape
and downgrades to unresolved rather than misresolving, and `--registry-config`
covers the per-target case without a second keying scheme.
*Falsifier:* an alias whose signature is *identical* across libcs but whose
meaning differs — the one case shape cannot separate. The response is to
triple-key **that alias** via an additive per-entry `triples: [...]` filter, not
to re-key the table.

**D6. Signal-handler participation is a hard conjunct of volatile admission**,
satisfied only by a *resolved* registration. It establishes that the
`sig_atomic_t` guarantee is the operative reason the object is volatile; MMIO and
special-section storage are excluded separately by the ordinary-storage
predicate. The alternative trades the idiom's defining property for coverage of
programs the analysis cannot see into.
*Falsifier:* a corpus program with an otherwise-certifiable
`volatile sig_atomic_t` rejected solely because its registration alias is
unrecognized, *and* for which `--registry-config` is impractical. Both halves
must hold — the documented recourse existing is what makes the strict reading
affordable.

**D7. `volatile` is replaced by `Relaxed` *plus* a checked flag pattern**
(F1/F2), not by `Relaxed` alone, which supplies indivisibility and (as an LLVM
property) absence of unbounded elision but not `volatile`'s preservation of
access count and relative order. The pattern conditions make the permitted
transformations behavior-refining rather than merely unlikely, by establishing
that the flag's only role is to convey signal arrival — whose timing is
unconstrained.
*Falsifier:* a corpus program rejected solely by F1 (two flags) or F2 (a function
that both polls the flag and may run as a handler, touching another static),
where the pattern is nonetheless demonstrably safe. F2 rejections are weak
falsifiers — such a program is already undefined behavior under C11 §7.14.1.1p5,
and the right response is to fix the source. F1 is the one to watch: it is a
blunt instrument chosen because the ordering question between two flags is hard,
not because two flags are inherently unsafe, so a second corpus module with two
flags is a reason to revisit it.

**D8. A permitting fact is computed by its own query, not by filtering a
restricting one** (rule 17). `resolved_signal_context_access` requires a
certified positive access path; restricting to resolved registrations is *not*
sufficient on its own, because `ModuleWide` originates in the handler's
transitive summary rather than in the registration operand. The rejected
alternative — reuse `registry_access_facts` with a resolved-only filter — is the
obvious implementation and would make the conjunct true for every global in any
module containing one handler with an unanalyzable pointer store, silently
deleting it.
*Falsifier:* a module where the flag's handler reaches it only through a pointer
or an indirect call, so the path requirement rejects a genuine signal flag. This
is bounded: `atomic_access_recipe` already requires `Via::Direct` at every
admitted site (`crates/pangs-clients/src/lib.rs:1891`), so such a global could
not have certified regardless — the falsifier must show the *fact* is the binding
constraint, not the recipe.

The remaining unknowns are measurements, not decisions, and are enumerated under
§"Corpus-level acceptance": whether other modules contain `volatile sig_atomic_t`
globals, and how far the Phase 2 registry fix moves `phase_stationarity` results
module-wide.

The standing tie-breaker, should a question arise this note did not anticipate:
retain the current `volatile-access` failure. The goal is to recognize one
well-defined standard idiom with positive evidence, not to broaden atomic
eligibility by assumption.
