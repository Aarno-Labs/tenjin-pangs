# Handling `volatile sig_atomic_t` Globals

## Status

Design proposal. Nothing in this document is implemented yet.

Reviewed against the working tree on 2026-08-05; the `file:line` anchors below
were verified at that revision and are navigation aids, not a stable interface.

This note records why the current disposition pipeline rejects a canonical
signal flag, and proposes a narrow path that recognizes and safely materializes
that idiom without weakening the existing rejection of arbitrary volatile
storage.

The load-bearing claim is §E's: that replacing `volatile` with a `Relaxed`
atomic preserves what the source relied on. It does **not** do so on its own —
`Relaxed` permits transformations `volatile` forbids — and the conditions that
make it sound are stated as admission conjuncts (F1, F2), not as commentary.
A reader checking one thing should check that.

## Executive summary

In `exe-apg_bore-O0.bc`, the only unhandled actionable global is:

```c
static volatile sig_atomic_t g_interrupted_xjtr_0 = 0;
```

The current pipeline rejects it for two independent reasons:

1. LLVM debug metadata describes the type as an unnamed outer `volatile` node
   around the named `sig_atomic_t` typedef. PANGS reads a type spelling only
   from the outer node, records no spelling, and therefore makes
   `word_sized_scalar` false even though it correctly recovers a signed,
   aligned 32-bit integer.
2. If that metadata problem is fixed, atomic access recipe construction still
   rejects every LLVM volatile load and store categorically.

There is also a related registry miss. Clang lowers the source call to
`signal(2, handler)` as a direct call to `__sysv_signal`, while the default
registry recognizes only `signal` and `sigaction`. Consequently PANGS reports
`signal_context_access: false` for the signal flag and treats registration as
an unresolved external effect elsewhere in the analysis.

The proposed correction has four parts:

1. Preserve structured qualified-type evidence, including typedef names and
   qualifiers, rather than using only the outer DWARF type name.
2. Stop making source type spelling a prerequisite for the semantic
   `word_sized_scalar` fact; source materializability is a separate question.
3. Continue rejecting arbitrary volatile accesses, but admit a narrowly
   certified `volatile sig_atomic_t` access mode when all accesses can be
   lowered to target-guaranteed lock-free atomics.
4. Recognize shape-checked libc spellings such as `__sysv_signal` as signal
   registries so the async-signal context and lock-free guard are real inputs
   to the certificate.

With those changes, the expected disposition for this global is `atomic`, not
`unhandled`. On the observed APG bore module that would move disposition
coverage from 25/26 to 26/26 and the atomic count from one to two, assuming the
detailed access recipe passes unchanged.

Three of the four parts are **not** local to this global, and the plan is sized
accordingly:

- Part 2 changes the meaning of a published fact. `word_sized_scalar` is a
  manifest fact with a schema invariant, a cascade-adjacent role, and a
  measurement funnel built on it (`DISPOSITION.md` §10.2). Redefining it is a
  schema change (§"Amendments required"), not an internal repair.
- Part 4 changes module-wide facts. A newly recognized registration callsite
  stops being an unresolved external effect for *every* global's phase
  analysis, so other globals' `phase_stationarity` results may move in the same
  run.
- Part 3 is the only genuinely narrow part, and it is the one that must fail
  closed.

The single-global coverage claim above is therefore a consequence to verify,
not the acceptance criterion; the acceptance criterion is the whole disposition
distribution on the corpus (§"Tests and acceptance criteria").

## Observed case

The source declaration is in
`/home/brk/xj-res/apg__bore/c_13_run_cclzyerpp_analysis/src/search.nolines.i`:

```c
static volatile sig_atomic_t g_interrupted_xjtr_0 = 0;

static void sigint_handler_xjtr_0(int sig)
{
    (void)sig;
    g_interrupted_xjtr_0 = 1;
}
```

Ordinary code resets the flag during initialization and polls it while doing
search work. All emitted LLVM accesses are volatile 32-bit loads or stores.

The bitcode retains the relevant storage facts:

```llvm
@g_interrupted_xjtr_0 = internal global i32 0, align 4, !dbg !206

!207 = distinct !DIGlobalVariable(
  name: "g_interrupted_xjtr_0",
  type: !208,
  ...)
!208 = !DIDerivedType(tag: DW_TAG_volatile_type, baseType: !209)
!209 = !DIDerivedType(
  tag: DW_TAG_typedef,
  name: "sig_atomic_t",
  baseType: !210)
!210 = !DIDerivedType(
  tag: DW_TAG_typedef,
  name: "__sig_atomic_t",
  baseType: !24)
!24 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
```

PIR lowering currently produces:

```json
{
  "key": "g_interrupted_xjtr_0",
  "type_spelling": null,
  "size_bits": 32,
  "align_bits": 32,
  "scalar_class": "integer",
  "signed": true,
  "initializer_ir": "i32 0"
}
```

The disposition manifest then reports:

```json
"word_sized_scalar": { "value": false },
"atomic_eligibility": {
  "status": "failed",
  "codes": ["word-sized-scalar"]
}
```

The declaration is therefore rejected before detailed access lowering runs.

## What `sig_atomic_t` does and does not prove

The C signal API gives `sig_atomic_t` a specific role: an object of that integer
type can be accessed as an atomic entity in the presence of an asynchronous
signal. Declaring the object volatile is the conventional portable signal-flag
idiom because execution can change it outside the ordinary control flow seen
by the compiler.

This does **not** make `sig_atomic_t` equivalent to a C11 `_Atomic` object:

- it does not provide a general inter-thread synchronization protocol;
- it does not imply acquire/release ordering for other memory;
- it does not make arbitrary compound operations atomic;
- it does not justify accepting every volatile object; and
- it does not prove that an arbitrary target/library representation can be
  replaced with a non-lock-free atomic implementation inside a signal handler.

For this reason the proposal is a dedicated signal-flag certificate, not a
rule that treats either `volatile` or all typedef-sized integers as atomic.

## Current rejection path

### 1. The outer qualifier hides the type spelling

`di_type_details` (`crates/pangs-pir/src/llvm_sys.rs:532`) calls
`di_type_name(metadata)` only on the top-level metadata node. A
`DW_TAG_volatile_type` node has no name, so `type_spelling` becomes `None`.

The scalar classifier `di_type_class` (`llvm_sys.rs:545`) behaves differently:
it recursively follows operand 3 through derived types until it reaches the
signed `int` basic type. That is why PIR simultaneously contains no spelling and
correct integer/signedness facts.

This mismatch is not specific to `sig_atomic_t`. Qualified typedefs can lose
their spelling while retaining their scalar class.

### 2. `word_sized_scalar` mixes semantics and materialization

`word_sized_scalar` (`crates/pangs-clients/src/lib.rs:2322`) currently requires
all of the following:

```text
type spelling exists
width is nonzero and in target.supported_atomic_widths
align_bits == size_bits          (equality, not sufficiency)
scalar class exists
integer/enum signedness is known
```

Only the last four conditions establish the machine-level scalar property.
The type spelling is useful for a source rewrite recipe, but its absence does
not make an aligned `i32` non-scalar. Folding both questions into one boolean
causes an early and misleading `word-sized-scalar` failure.

The false fact also drops the already-known width, class, and signedness from
the manifest, making the rejection harder to diagnose. That suppression is not
incidental: `Facts::validate` (`crates/pangs-manifest/src/lib.rs:430`) *requires*
detail presence to match the boolean exactly, and rejects any manifest carrying
scalar detail alongside `value: false`. Retaining partial evidence is therefore
a schema change, not a field-population change.

### 3. Detailed atomic lowering rejects all volatile sites

`atomic_access_recipe` (`crates/pangs-clients/src/lib.rs:1879`) rejects a site
immediately when `site.volatile` is true:

```text
volatile-access:
  "volatile C access cannot be replaced by an ordinary Rust atomic"
```

That default is correct for unknown volatile storage. Volatile may denote
memory-mapped I/O, externally observed memory, or another access contract that
ordinary atomic operations do not preserve. It is too broad for a proven
standard signal flag, however, because it prevents the disposition intended to
provide a safe translated representation for exactly that access pattern.

### 4. Signal registration is present under a different symbol

The source uses `signal`, but this glibc configuration lowers the call to:

```llvm
call void (i32)* @__sysv_signal(i32 2, void (i32)* @sigint_handler_xjtr_0)
```

The built-in list in `effective_registry_apis`
(`crates/pangs-api/src/lib.rs:4177`) contains `pthread_create`, `thrd_create`,
`signal`, and `sigaction`, but not `__sysv_signal`. As a result:

- the handler is not classified through the signal registry;
- `g_interrupted` incorrectly has `signal_context_access: false`;
- the atomic certificate does not currently demand its signal lock-free gate;
- mutex eligibility is not rejected for the most direct reason; and
- phase analysis retains an unresolved external effect at registration
  (`crates/pangs-clients/src/phase_stationarity.rs:716,757,772`: only a
  *modeled* registry callsite escapes the `has_unknown` widening).

Accepting the atomic strategy without repairing this registry miss would be
the wrong fix: it would produce the desired answer without proving the signal
context that makes the answer safety-sensitive.

Two properties of this registry constrain the repair and are easy to get wrong:

- **It is not the Ω external-summary registry.** It is the spawn/signal fact
  registry consumed by the F-layer disposition scans and by
  `registry_target_labels`. Recognizing `__sysv_signal` does *not* relax the Ω
  boundary at that call; the call remains an external effect for points-to,
  mod/ref, and escape. Only the spawn/signal fact and the phase-analysis
  unresolved-effect widening change.
- **It is name-only today**, and its two error directions are not symmetric. A
  false positive is conservative in every current consumer: a spurious
  `signal_context_access` kills `mutex` and tightens `atomic`'s lock-free gate.
  A false *negative* — a real registration the tool fails to recognize — is not
  conservative at all, for the same two consumers. §D.5 works through this and
  is why shape mismatch resolves to an *unresolved registration* rather than to
  "not a registration". Shape checking is therefore diagnostic hygiene layered
  on a conservative default, not a gate that may delete a fact.

It is also already extensible without code changes: `pangs --registry-config`
(`crates/pangs-cli/src/main.rs:53,726`) merges or replaces entries by name.
Phase 2 should be validated through that flag on the bore module *before* any
entry is hardcoded, so the fact-level consequences are observed independently of
the alias-table design.

## Proposed design

### A. Preserve structured source-type evidence

Replace the one-name view of a debug type with a bounded walk that records the
derived-type chain. A suitable normalized representation is:

```rust
struct ScalarTypeEvidence {
    display_name: Option<String>,
    typedef_names: Vec<String>,
    qualifiers: TypeQualifiers,
    class: Option<ScalarTypeClass>,
    signed: Option<bool>,
}

struct TypeQualifiers {
    is_const: bool,
    is_volatile: bool,
    is_restrict: bool,
    is_atomic: bool,
}
```

The walk should:

1. start at the `DIGlobalVariable` type;
2. record qualifier tags rather than discarding them;
3. record every named typedef in outer-to-inner order;
4. stop at the existing recursion bound;
5. derive class and signedness from the terminal scalar type; and
6. fail closed on malformed metadata or cycles.

For the bore flag, the normalized evidence would be approximately:

```json
{
  "display_name": "sig_atomic_t",
  "typedef_names": ["sig_atomic_t", "__sig_atomic_t"],
  "qualifiers": { "is_volatile": true },
  "class": "integer",
  "signed": true
}
```

`display_name` is defined **positionally**, with no notion of a "public" name:

```text
display_name =
  typedef_chain[0]                     if the chain is non-empty
  else the terminal scalar type's own name, if it has one
  else None                            (anonymous enum, nameless base type)
```

The outermost typedef is the name the *declaration site used* — what the
programmer actually wrote — which is exactly what a display spelling should be.
For the bore flag the chain is `["sig_atomic_t", "__sig_atomic_t"]`, so
`display_name` is `sig_atomic_t`; for
`typedef sig_atomic_t my_flag_t; static volatile my_flag_t g;` it is
`my_flag_t`, again what the source says. The implementation-internal
`__sig_atomic_t` is displayed only if the programmer literally wrote it.

A "first *public* typedef" rule is rejected deliberately. Making it operational
would require defining public lexically — no leading double underscore, no
leading underscore followed by a capital — which is a naming-convention guess,
not a fact: it would misfire on legitimate project typedefs that start with an
underscore, and it would make the emitted spelling depend on identifier style
rather than on the source. Positional is both deterministic and more faithful.

A truncated or cyclic walk yields no evidence at all, hence no `display_name`;
there is no partially-populated form. The analysis must retain the whole typedef
chain for classification rather than relying on any single formatted string.

This representation should be populated only from positive debug evidence.
An integer named similarly in a source comment, symbol name, or IR name is not
enough.

Two properties of this shape need to be stated so downstream consumers do not
over-read it:

- `TypeQualifiers` is **accumulated over the whole chain**, so `is_volatile`
  means "volatile appears somewhere between the variable and the terminal scalar
  type", not "the declaration's outermost qualifier is volatile". That reading is
  the conservative one for *admission* (§C/§E gate on its presence), and it is
  deliberately insufficient to reconstruct a declaration.
- Consequently `display_name` is **evidence, not a rewrite recipe**. The C→C and
  Rust materializers must rewrite from source coordinates plus this structured
  evidence; nothing in this design licenses reassembling a declaration by string
  concatenation of qualifiers and a typedef name.

`is_atomic` is recorded for completeness and is an immediate rejection for this
design. A C11 `_Atomic` global is lowered by clang to atomic IR operations, not
volatile ones; it is a different case with a different recipe, and inheriting the
signal-flag admission would be wrong. `is_const` on a mutable global definition
is contradictory evidence and likewise fails closed.

### B. Separate scalar eligibility from source materializability

Redefine `word_sized_scalar.value` to mean only:

```text
known scalar class
known required signedness
nonzero supported width
align_bits == size_bits          (unchanged from today)
```

Do not require `type_spelling`. Preserve the observed `size_bits`, `class`, and
`signed` fields even when the final boolean is false, and record the decisive
failure in a new `codes` array whose closed vocabulary and emission order are
frozen in §"Schema v5" §2:

```text
unknown-scalar-class
unknown-signedness
zero-width
unsupported-atomic-width
unknown-alignment
under-aligned
over-aligned
```

**Keep the alignment condition as strict equality in this change.** Relaxing it
to "ABI alignment sufficient for the width" is a real semantic widening that has
nothing to do with `sig_atomic_t`: it newly admits over-aligned globals
(`__attribute__((aligned(64))) int`), whose declarations a materializer must then
either preserve or justify dropping. If that widening is wanted, it belongs in
its own change with its own fixtures, because it moves the eligibility population
in a way this note's corpus assertions cannot attribute.

Whether a source declaration can be rewritten belongs in
`source_materialization` (`crates/pangs-clients/src/lib.rs:1310`), which today
keys on `meta.file`/`meta.line` and returns `blocked` with
`declaration-source-unmapped` when they are absent. That code is unchanged and
remains the one that matters: the C→C stage needs coordinates to plant a marker.

A missing **type spelling** is a different matter and does *not* block. Per
M.0 and M.3, no stage consumes `recipe.declaration.type_spelling` — the C→C
stage needs the symbol and coordinates, the Rust stage derives the atomic type
from `scalar_class`/`signed`/`size_bits`. Record its absence as a diagnostic on
the certificate instead:

```json
{ "type_evidence": { "spelling_recovered": false,
                     "detail": "qualified debug type carries no outer name" } }
```

A spelling-free scalar that passes every other gate is therefore certified *and*
materializable. This is a real coverage gain from part 2, not an accounting
artifact, and Phase 1's acceptance criterion is written to expect it.

This separation fixes the general diagnostic problem. The dedicated
`sig_atomic_t` path still requires positive typedef evidence; it must not infer
signal safety merely from an aligned integer.

Two consumers move with the redefinition and must be updated together:

- `Facts::validate`'s detail/value invariant (`pangs-manifest/src/lib.rs:430`)
  and `SCHEMA_VERSION` (`pangs-manifest/src/lib.rs:12`), which goes to **5**.
- The `not_word_sized` counter (`pangs-clients/src/lib.rs:452`) and the
  would-be-eligibility funnel of `DISPOSITION.md` §10.2, whose historical values
  in `notes/disposition_atomic_perglobal_remeasurement_2026-07-17.md` and
  siblings stop being comparable across this change. Say so in the note that
  records the re-measurement rather than silently re-baselining.

### C. Add a signal-atomic type fact

`signal_atomic_type` is a **type fact**, derived from type evidence alone. Keep
target capability and program context out of it; those are admission conditions
(§E), and mixing them reproduces exactly the fact/policy conflation that §B is
correcting. Derive it only when all of these hold:

```text
typedef chain contains the implementation's standard sig_atomic_t typedef
qualifier chain includes volatile
qualifier chain includes neither _Atomic nor const
scalar class is integer
width and alignment are known and mutually consistent
```

Its manifest form should carry the evidence rather than only a boolean. The
normative placement and field list are frozen in §"Schema v5" §4; illustrated
here as the payload object alone, which has no `status` of its own:

```json
{
  "typedef": "sig_atomic_t",
  "typedef_chain": ["sig_atomic_t", "__sig_atomic_t"],
  "volatile": true,
  "width": 32,
  "align": 32
}
```

Recognition should allow platform-internal typedefs beneath the public
`sig_atomic_t`, but the public name must be present unless a frontend supplies
an equivalent explicit semantic tag. Do not maintain an open-ended heuristic
list of names resembling `sig_atomic_t`.

**What recognition is and is not.** Operationally this is a string match against
a typedef chain. A user's own `typedef int sig_atomic_t;` passes it, and the
design must be honest about that rather than implying header authenticity it
does not check.

The load-bearing claim is narrower than it looks: **safety does not depend on
the typedef being the implementation's authentic one.** What makes the rewrite
correct is the enumerated conjuncts — integer scalar of a lock-free width,
whole-object direct loads and stores only, complete access set, resolved signal
participation, internal linkage, ordinary storage. A shadowing typedef that
satisfies all of those describes an object the transformation handles correctly
regardless of which header declared the name. The typedef match is an **intent
signal** — it identifies the idiom — not a proof obligation.

Provenance is still worth recording, to narrow accidental recognition, and it is
cheap: `DW_TAG_typedef` nodes carry a file, and `RepoRoots::relative_source`
already distinguishes repo-local from external paths. Apply it with the same
polarity discipline used for registry shapes — reject only on positive contrary
evidence:

```text
typedef declared outside the analyzed repository  -> accepted (system header)
typedef file unknown or unrecorded                -> accepted (no contrary evidence)
typedef positively declared inside the repository -> rejected, code
                                                     signal-typedef-shadowed
```

This is a precision choice, not the safety argument, and the note says so in
both places so a later reader does not mistake it for one.

Where this fact lives is worth deciding now rather than after D3 consumes it.
It is per-global, objective, witness-bearing, and derived in one scan — the
`DISPOSITION.md` §2 shape of a fact — but its only consumer is the atomic
certificate. The cheaper v1 is to carry it inside `atomic_eligibility`'s
certificate payload and promote it to a first-class fact slot when a second
consumer appears; that keeps the schema-v5 fact-layer surface to the
`word_sized_scalar` change alone. That is the decision, and §"Schema v5" §4
freezes its exact path; promotion to a fact slot would be schema v6.

### D. Recognize shape-checked signal aliases

Extend the exact registry with known ABI/library spellings, beginning with
`__sysv_signal` on the observed glibc target. The entry has the same shape as
`signal`: handler in argument 1.

As with other external summaries, a name match alone is not proof. Prefer a
small alias table with documented shapes and regression fixtures over
unconditional fuzzy matching; candidates such as `bsd_signal` are added the same
way.

#### D.1 What "shape" can actually mean here

`RegistryApi` (`crates/pangs-api/src/lib.rs:419`) expresses only name, kind, and
entry operand, so the check needs a representation. The available evidence at a
callsite is:

| Source | Gives |
|---|---|
| `pag::Callsite.sig` (`crates/pangs-pag/src/lib.rs:602`) | `cc`, `vararg`, per-param `AbiClass`, return `AbiClass` |
| `pir::Func` (`crates/pangs-pir/src/lib.rs:130`) | the declaration's own `sig`, plus `external` |
| `pag::Node.value_kind` (`crates/pangs-pag/src/lib.rs:481`) | `ValueKind`: `Pointer` / `PointerAggregate` / `NonPointer` / `Unknown` |

The constraint that shapes the whole design: **ABI class cannot distinguish a
pointer from an integer.** `AbiClass` is
`Integer | Sse | X87 | Fp128 | Void | Byval | Sret`
(`pangs-pir/src/lib.rs:640`), and both `int` and `void (*)(int)` are `Integer`.
So "a handler operand compatible with `void (*)(int)` at the ABI-class level",
as this note previously put it, is not expressible — and under opaque pointers
no amount of LLVM type inspection recovers it either.

The pointer/non-pointer discrimination therefore has to come from `ValueKind`,
which is exactly the fact `DESIGN_lite.md` §3 introduced for this purpose
("pointer payload is classified independently of ABI class"). The two sources
are complementary and neither alone suffices: `Signature` gives arity, calling
convention, vararg, and gross class; `ValueKind` gives pointer-ness.

#### D.2 Representation

`RegistryShape` is an optional field on `RegistryApi`, so it is expressible for
built-in *and* user entries:

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
pub enum ParamShape {
    Integer,      // AbiClass::Integer, and not a proven pointer
    PointerLike,  // AbiClass::Integer, and may carry a pointer
    Any,          // AbiClass::Integer, no ValueKind constraint
    Void,         // AbiClass::Void  (return position only)
}
```

**Every `ParamShape` decomposes into two independent checks with different
sources and different availability**, and conflating them is what made an earlier
draft call the whole return constraint "best-effort":

| Component | Source | Availability | On mismatch |
|---|---|---|---|
| **ABI class** | `Callsite.sig` — `sig.params[i].class()` for arguments, `sig.ret` for the return, `sig.params.len()` for arity, plus `sig.vararg` and `sig.cc` | **always.** `Callsite.sig` is a `Signature`, not an `Option` (`crates/pangs-pag/src/lib.rs:601`), and `Signature.ret` is a plain `AbiClass` (`crates/pangs-pir/src/lib.rs:599`) | hard `ShapeMismatch`. There is no `Unknown` state to be lenient about |
| **Value kind** | the PAG node — `pag.nodes[args[i]].value_kind`, and `pag.nodes[result].value_kind` for the return | arguments: a node exists, but `value_kind` is `#[serde(default)]` and may be `Unknown`. **Return: only when `Callsite.result` is `Some`** — a discarded result has no node at all | rejects only on positive contrary evidence (below) |

So the return is **not** uniformly best-effort. Its ABI half is always available
and always decisive; only its pointer-classification half depends on the result
node. Concretely, `void`-versus-non-`void` is checkable on every call including
`signal(2, h);`, while "does this return a pointer" is checkable only where the
result is used.

**Polarity rule, and it governs the value-kind half only:** those constraints
reject only on *positive contrary evidence*.

- `Integer` fails only when the node is proven `Pointer` or `PointerAggregate`.
- `PointerLike` fails only when the node is proven `NonPointer`
  (`ValueKind::may_carry_pointer()` is the predicate).
- `Unknown` — the default for older PAG fixtures and for anything the kind
  analysis could not prove — never causes a mismatch.
- An **absent** result node is treated exactly as `Unknown`: the value-kind half
  is skipped, the ABI half still runs.

Without that polarity the value-kind half would degrade into a type system, and
every imprecision in `ValueKind` would silently drop a registration. Applying the
same leniency to the ABI half would be the opposite error — discarding evidence
that is always present and never uncertain.

Written out, with `A` the ABI component and `V` the value-kind component:

```text
Integer      A: class == Integer        V: ¬proven(Pointer | PointerAggregate)
PointerLike  A: class == Integer        V: ¬proven(NonPointer)
Any          A: class == Integer        V: (none)
Void         A: class == Void           V: (none — a void position has no value)
```

Two consequences worth stating because they are easy to misread:

- **`Void` is the only shape whose ABI class is not `Integer`**, and it is fully
  decidable everywhere. A registration spec that expects `Void` in the return and
  observes `Integer` is a mismatch on every call, discarded result or not.
- **The `signal`/`sigaction` non-discrimination survives this refinement, for a
  better-stated reason.** §D.3 says arity carries the discrimination and the
  return does not. That is not because the result node is often missing — it is
  because both return `AbiClass::Integer`: `sigaction` returns `int`, and
  `signal` returns `__sighandler_t`, a pointer, which x86-64 classifies as
  `Integer` in the return register. The ABI half is available on both and simply
  agrees. The value-kind half would distinguish them, and it is exactly the half
  that vanishes when the result is discarded — which is the common spelling. So
  the conclusion is unchanged and the reason is now the true one.

**`RegistryEntryResolution` gains a reason, and `unresolved` becomes derived.**
The existing type carries only a boolean
(`crates/pangs-api/src/lib.rs:433-438`), which cannot distinguish a shape
mismatch from an operand whose points-to is incomplete — §D.5 shows why those
must stay separate:

```rust
pub struct RegistryEntryResolution {
    pub kind: RegistryKind,
    pub targets: Vec<FuncId>,
    #[serde(default)]
    pub unresolved_reasons: BTreeSet<UnresolvedReason>,   // empty ⇒ resolved
}

#[serde(rename_all = "kebab-case")]
pub enum UnresolvedReason {
    ShapeMismatch,
    OperandExternal,
    OperandUntargeted,
    OperandAbsent,
}

impl RegistryEntryResolution {
    pub fn unresolved(&self) -> bool { !self.unresolved_reasons.is_empty() }
}
```

Three properties of this shape are deliberate:

- **A set, not an enum.** The reasons are independent predicates and co-occur
  routinely — a mismatched-shape call whose operand is also external has both.
  Picking a winner would make the diagnostic depend on evaluation order.
- **Empty means resolved**, so the default is the strict reading. A future
  reason added to the enum makes previously-resolved entries unresolved, which is
  the safe direction; a boolean would have to be flipped by hand at every new
  call site.
- **`unresolved` becomes a method, not a field**, so no consumer can construct a
  resolution that claims to be resolved while carrying a reason. Every existing
  read of `entry.unresolved` becomes `entry.unresolved()` mechanically; the
  widening at `crates/pangs-clients/src/lib.rs:838-841` is unchanged, since it
  widens on any reason.

Consumers widen identically on every reason. The distinction is for diagnostics
and for §D.6, which emits a record for exactly one of them.

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

`sigaction` is structurally different, and the difference is already carried by
`entry`, not by `shape`: the handler is a *field* of a struct the argument
points to, which is a points-to query (`PointeeOfArg`), not a signature
property. Shape constrains only the call's own signature. Two consequences worth
stating:

- Shape does **not** check `struct sigaction`'s layout, and cannot. A
  wrong-layout struct yields wrong pointees, which the solver still treats as
  possible handlers — conservative, and outside what a signature check can see.
- **Arity is what separates the two families**, reliably: two parameters versus
  three, checked exactly against `sig.params.len()`, which is always available.
  An earlier draft claimed the return position did it — `signal` returns the
  previous handler and `sigaction` returns `int`. That is wrong, and per §D.2 it
  is wrong for a reason worth keeping straight: **the return's ABI half is
  available on both calls and simply agrees.** `sigaction`'s `int` and `signal`'s
  `__sighandler_t` are both `AbiClass::Integer` — x86-64 returns a pointer in the
  same register class as an integer. The half that *would* distinguish them is
  the value-kind half, and that is the half requiring `Callsite.result`, which
  `signal(2, h);` does not produce.
- **Only the value-kind half of return checking is best-effort.** The ABI half
  runs on every call: a spec expecting `Void` and observing `Integer` is a hard
  mismatch whether or not the result is used. What is conditional is pointer
  classification, which fires only when a result node exists *and* its
  `ValueKind` is a proven contrary. So `RegistryShape.ret` is a real constraint
  in its ABI component and a refinement in its value-kind component — and since
  every registration family this design recognizes returns `Integer`, the
  component that could discriminate is exactly the conditional one. **No family
  discrimination may rest on the return**, which is the operative rule and is
  unchanged.

That same draft claimed shape "catches a config that pairs one name with the
other's entry operand." It does not: `RegistryShape` constrains the callsite
signature and never inspects `entry`, so a `sigaction` entry wrongly declared
`{ "arg": 1 }` matches its shape perfectly and simply resolves the wrong
operand. The real defense is a **registry-entry consistency check at config
load**, which is cheap and belongs there rather than per callsite:

```text
entry index is within params.len()
the ParamShape at the entry index is PointerLike
kind is Signal or Spawn — a registration operand is always pointer-bearing
```

A registry entry failing this is a config error, rejected at load with the
offending entry named, exactly like the `[cascade]` config errors in
`DISPOSITION.md` §4.1. It is the check that would actually have caught the
mispaired-operand case.

#### D.4 Evaluation order, and who is checked

1. **Name match** against the effective registry.
2. **Declaration check** (`external_only`, default true): the callee must be an
   external declaration. A *defined internal* function named `signal` is not
   libc's, and the entry does not apply at all — the analysis already models
   that body. This is a precondition, not a shape check; it runs first because
   it is the cheapest way to exclude the most likely false positive, and its
   failure is **silent** (§D.6): no registration, no record.
3. **Shape match**, per D.2. Failure adds `ShapeMismatch` and is the only step
   whose failure emits a diagnostic record (§D.6).
4. **Handler-operand resolution**, per `resolve_registry_entries`
   (`crates/pangs-api/src/lib.rs:4302-4313`). Failure adds `OperandExternal`,
   `OperandUntargeted`, or `OperandAbsent`. This step is **not new** — it is what
   the implementation already does — and it is listed because an earlier draft of
   §D.5 ended the conjunction at step 3, which would have made a shape-checked
   call with an unresolvable handler operand read as resolved.

Steps 3 and 4 are independent and both run: the outcome is the union of their
reasons, not the first failure. Step 4 in particular cannot be skipped when step
3 fails, because the widened target set still needs the operand's pointees
(§D.5's `targets = the operand's pointees if any`).

Applies identically on the indirect path, where `registry_spec` is consulted
with a *solved target name* (`crates/pangs-api/src/lib.rs:4242,4279`); the
callsite signature used is that indirect callsite's.

User-configured entries **are** shape checked, and must be, because
`effective_registry_apis` (`lib.rs:4198-4205`) merges by name with the user
entry *replacing* the built-in — an unchecked user entry for `signal` would
otherwise launder the built-in's shape away. The rules:

- `shape: None` on a **new** name is unchecked, preserving today's behavior and
  keeping existing configs valid, and records an audit note: it asserts a
  registration the tool cannot verify. This permission does **not** extend to
  `--target-profile`, which forbids hand-asserted rows outright (§E). The
  difference is the error direction: an over-broad registry entry is
  conservative in every consumer, an over-broad lock-free width is not.
- A user entry that **replaces a built-in name** inherits the built-in shape
  unless it supplies its own. Replacement is for retargeting `entry` or `kind`,
  not for silently disabling verification.

#### D.5 The mismatch outcome is not "no match"

A name match with a mismatched shape must not fall through to "not a
registration", because **dropping a signal registration is not uniformly
conservative**:

| Consumer | Effect of dropping the registration | Direction |
|---|---|---|
| `phase_stationarity` | keeps the `has_unknown` widening | safe |
| `mutex_eligibility` | loses the `signal-context-access` rejection | **unsafe** |
| `atomic_eligibility` | skips the signal lock-free gate | **unsafe** |
| §E volatile admission | conjunct fails, access rejected | safe |

So the resolution is three-valued, and the existing type already supports it —
`RegistryEntryResolution` carries an `unresolved` flag today
(`crates/pangs-api/src/lib.rs:434`), which §D.2 replaces with a reason set for
the diagnostic split below:

```text
name ∧ declaration ∧ shape ∧ operand-complete
                                → resolved registration, targets from points-to
name ∧ declaration ∧ ¬(shape ∧ operand-complete)
                                → registration with non-empty
                                  unresolved_reasons (§D.2),
                                  targets = the operand's pointees if any
¬name ∨ ¬declaration            → not a registration
```

**The fourth conjunct is not new, and an earlier draft of this table omitted it.**
`resolve_registry_entries` already computes
`unresolved: external || !targeted` (`crates/pangs-api/src/lib.rs:4303`), which
is a property of the *handler operand's points-to result*, entirely independent
of the name, the declaration, and the shape this note proposes to add. A table
saying `name ∧ declaration ∧ shape → resolved` is therefore not merely
incomplete — it is wrong in the unsafe direction, because shape checking is the
part being *added* and an implementer reading the table would naturally write the
new check as the last conjunct and treat its success as resolution.

**Operand incompleteness has its own reasons, and they are distinct from shape.**
Consumers widen on all of them, but the diagnostic must not conflate them: shape
mismatch means *this is probably not the API we think it is*, while operand
incompleteness means *this is the API, and we cannot see who the handler is* —
opposite conclusions about the program, requiring opposite user responses.

| Reason | Source | Meaning | `targets` |
|---|---|---|---|
| `shape-mismatch` | §D.2's declaration check | the name matched but the signature did not; the entry is suspect | operand pointees, if any |
| `operand-external` | `external` (`lib.rs:4302`) | the operand's points-to reaches an external boundary; the handler may be defined outside the module | non-empty but **incomplete** |
| `operand-untargeted` | `!targeted` (`lib.rs:4310`) | no targeted points-to was computed for the operand label, so the target set is unavailable rather than incomplete | empty |
| `operand-absent` | `callsite.args.get(arg_index)` is `None` | no argument at the entry index | empty |

`operand-absent` is folded into `operand-untargeted` by the current code — both
arrive through `is_some_and` returning false — but it is listed separately
because it indicates an arity problem, which under §D.2's shape checking should
have been caught as a declaration mismatch first. If it is ever reached with
shape checking live, that is a defect in the shape check, and a distinct reason
is what makes it visible.

**`operand-external` is the case that matters most here**, and it is worth being
explicit about why. Its `targets` list is *non-empty* — it names real functions —
so it is the one unresolved reason that looks resolved at a glance. Two of this
note's mechanisms would be unsound if it were treated as resolved:

- **F2's handler set `H`.** A resolved registration contributes its precise
  targets *without* §D.5's widening. If an operand-external registration were
  marked resolved, `H` would silently omit the handlers defined outside the
  module, and F2 — a universal check over `A ∩ H` — would pass by not looking.
  This is the unsound direction for F2, which is the one place in the design that
  needs `H` over-approximated rather than precise.
- **`resolved_signal_context_access`.** §E requires a certified positive path
  from a *precise target of a resolved registration*. An incomplete target list
  admitted as precise would let the permitting fact rest on a partial view of who
  the handler is.

The middle case widens in every consumer: phase analysis keeps its unknown
effect, `signal_context_access` is set, and the unresolved bit ensures nothing
is *narrowed* on its basis. One deliberate exception: an unresolved registration
sets the fact but **does not satisfy §E's admission conjunct**, which requires a
resolved registration — see §E's `resolved_signal_context_access`. Volatile
admission is the one place the fact is used to *permit* something rather than to
restrict it, so it takes the strict reading.

**How an unresolved registration widens — frozen.** "Whatever the operand may
reach" is not implementable; the target set is exactly:

```text
handlers(unresolved registration) = precise targets ∪ { f : f.address_taken ∧ ¬f.external }
```

This is the existing behavior, not a new rule
(`crates/pangs-clients/src/lib.rs:777-783, 838-841`): `address_taken_entries` is
the internal address-taken functions, and the widened set is *chained onto* the
precise targets rather than replacing them. Freezing it here because the
three-valued outcome makes it reachable in a new way.

The two alternatives are rejected for specific reasons:

- **All internal functions** is strictly wider and buys nothing. A function
  whose address was never taken cannot be the operand of a registration, so
  address-taken is already a sound over-approximation — the tighter one is free.
- **FSA-compatible functions** (`void (*)(int)`) would be tighter still, and is
  exactly wrong for the case that produces most unresolved registrations here:
  a *shape mismatch* means the signature evidence is what failed. Narrowing by
  the signature we just declined to trust would let a wrong-shaped registration
  claim precision. It remains a defensible future refinement for the
  operand-unknown sub-case only — where the shape *did* match and only the
  points-to set was incomplete — and must never be applied to the
  shape-mismatch sub-case.

This also bounds the retrofit risk noted above: adding shapes to the existing
`signal`/`sigaction` entries can now only *downgrade* a registration to
unresolved, never delete it. The corpus regression is still required; its worst
case is precision loss, not a lost fact.

#### D.6 Diagnostic

One rule, resolving a contradiction an earlier draft carried: **only a shape
mismatch on an external declaration emits a record. A failed declaration check
is silent, and so is every operand-side unresolved reason** (§D.2's
`UnresolvedReason`; the operand cases are covered at the end of this
subsection).

The declaration check is a precondition, not a verification failure. An
internally *defined* function named `signal` is simply a different function; the
analysis models its body, nothing is unverified, and there is no drift to
report. Emitting a record would be noise, and under `--strict-registry` it would
fail the build for a program that did nothing wrong. Nothing is lost by the
silence: if that internal function is a wrapper that forwards to libc, the inner
call is itself a name match against an external declaration and is recognized
there — which is the right place for it.

So the emitting case is exactly: name matched, callee is an external
declaration, shape did not match. That record goes to the audit ledger
(`pangs-audit.json`) — the same ledger as accepted-risk overrides and
library-mode ordering assertions, because it is the same kind of thing: an
external the tool was told about and could not verify. It carries the expected
and observed shapes so the drift is diagnosable without a rebuild:

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
table thinks it does, which is exactly the drift an alias table must not hide.
It is a warning by default — a program may legitimately declare its own external
`signal` — and a non-zero exit under `--strict-registry`, following
`DISPOSITION.md` §4.3's treatment of drifted override files.

**The operand reasons emit no ledger record**, and the asymmetry is the point.
`registry-shape-mismatch` reports *drift between the tool's table and the
program's declarations* — a claim about the tool's configuration being stale,
which an auditor must see and which `--strict-registry` may reasonably fail the
build over. `operand-external` and `operand-untargeted` report *analysis
imprecision on a correctly recognized API*: the tool's table is right, the call
is a registration, and the solver could not name the handler. That is the normal
condition of a whole-program analysis with an Ω boundary, it is already
conservative in every consumer, and a ledger record per occurrence would bury the
mismatch records that do demand attention. Bore alone would emit one on every run
for its `signal(2, g_prev_sigint_handler_xjtr_0)` restore call, which is correct
C the tool has nothing to say about.

They are still visible: `unresolved_reasons` is on the resolution, so
`--registry-report` (or any diagnostic dump) can show them per callsite, and a
`volatile sig_atomic_t` rejected for want of a resolved registration should name
the reason in its `atomic_eligibility` witness. Diagnosability without a ledger
row is the right level for a precision limit.

`--strict-registry` covers `ShapeMismatch` only, for the same reason: failing a
build because the solver could not resolve a function pointer would make the flag
unusable on exactly the programs it is meant to audit.

After this fix, accesses reachable from `sigint_handler_xjtr_0` must set:

```json
"signal_context_access": { "value": true, ... }
```

The atomic certificate must then require and record target-guaranteed lock-free
operations for the selected width. Mutex must remain unavailable for the same
global because a signal handler cannot safely take the proposed mutex.

The same fix has a second, module-wide effect that must be measured rather than
assumed benign: the registration callsite becomes a modeled registry call in
phase analysis, so globals whose `phase_stationarity` previously failed on that
unresolved effect may now certify and move to `once-lock`. That is a precision
gain in the intended direction, but it means Phase 2 changes the disposition
distribution on its own, before any volatile access is admitted. Record the
distribution after Phase 2 and again after Phase 3 so the two effects are
attributable separately.

### E. Permit only certified signal-flag volatile accesses

Keep the existing `volatile-access` failure as the default. In
`atomic_access_recipe`, allow a volatile site only when every one of the
following holds:

```text
the global has a positive signal_atomic_type certificate           (§C)
the global has resolved_signal_context_access: true                (§D, below)
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

The last two are the *pattern conditions*. They are not hygiene: `Relaxed`
does not preserve access count or relative order, and the argument that this is
harmless holds only for a flag whose sole role is to convey signal arrival.
"Why dropping `volatile` is admissible" below derives them; they are listed here
because they gate admission, not documentation.

The resolved-registration conjunct deserves its own justification, because §C
alone would admit a `volatile sig_atomic_t` that no handler ever touches. It is
the property that makes the C standard's `sig_atomic_t` guarantee the *operative*
reason the object is volatile, rather than an incidental type choice sitting in
front of some other access contract. Requiring it costs a
`volatile sig_atomic_t` polled only from ordinary code — which fails closed to
today's behavior, and is not the idiom this note exists to recognize.

An earlier draft went further and called it "the concrete MMIO-exclusion test."
That was wrong: nothing stops a handler from touching a memory-mapped register,
so signal participation excludes MMIO only by correlation. The non-goals list
"objects that may be memory-mapped I/O" and the design owes it an actual test.

**Ordinary-storage predicate.** For v1, admission additionally requires the
global to be ordinary defined storage:

```text
is_definition == true ∧ constant initializer present   (already required by D3)
linkage == internal                                    (M.8)
no explicit section attribute                          (needs a new PIR fact)
not thread-local                                       (needs a new PIR fact)
not alias-exposed                                      (needs a new PIR fact,
                                                        or the module-wide
                                                        fallback; see below)
```

**All three** of the last clauses need PIR to record facts it currently does not.
There is no `section` or `thread_local` on `pangs_pir::Global`, so Phase 3 adds
`section: Option<String>` and `thread_local: bool`, both `#[serde(default)]`,
matching every other optional field there. The alias clause is the subtler one
and is treated separately below, because an earlier draft asserted it was already
satisfiable by existing facts and it is not.

The thread-local case is not merely an MMIO concern; it is a correctness bug
waiting to happen. A `__thread volatile sig_atomic_t` is a per-thread flag, and
lowering it to a plain `static AtomicI32` would merge every thread's copy into
one. It must be rejected outright, and its absence from the current fact set is
why this predicate is written down rather than assumed.

**Aliases need a new fact after all, and an earlier draft of this paragraph was
wrong twice.** It claimed that `collect_alias_map`
(`crates/pangs-pir/src/llvm_sys.rs:3566`) resolves an alias to
`AliasTarget::Global` so accesses through it are attributed to the global, and
that an interposable alias is tainted by `bump_tainted` and therefore gated by
`violation_taint`. Reading the function:

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

Both halves fail:

1. **There is no target-specific fact to test.** The interposability check runs
   *before* `LLVMAliasGetAliasee`, so an external-linkage alias is dropped
   without its aliasee ever being resolved. Nothing anywhere records that this
   alias pointed at *this* global. The taint string names the **alias**
   (`alias_interposable:@pub_alias`), not its target — and could not name the
   target, since the target was never computed. So "no external-linkage alias
   targets the global" is not a predicate over any fact that exists.
2. **`bump_tainted` gates nothing.** It writes to
   `LoweringStats::tainted_counts`, a `BTreeMap<String, u64>` metrics counter
   (`crates/pangs-pir/src/lib.rs:479`) whose only readers in the tree are
   assertions in `crates/pangs-pir/tests/llvm_lowering.rs`. `violation_taint` is
   an unrelated mechanism: the module-wide half is `module_violation_tainted`,
   which tests for inline assembly (`crates/pangs-solve/src/lib.rs:1222`), and
   the per-global half comes from violation findings
   (`crates/pangs-clients/src/lib.rs:209-210`). Neither reads
   `tainted_counts`.

This matters because M.8 rejects external linkage to prevent mixed
atomic/non-atomic access to the same storage across a translation-unit boundary,
and an external-linkage alias to an internal global re-exports that storage under
another name — the same hazard through a back door, currently invisible.

**The fix: an alias-exposure inventory in PIR.** Resolve the aliasee *before*
applying the interposability check, so the exposure is recorded even when the
alias itself is not modeled:

```rust
for alias in aliases {
    let alias_key = value_name(*alias);
    let target = constant_symbol_name(LLVMAliasGetAliasee(*alias));   // ← moved up
    if let Some(target) = &target {
        if global_names.contains(target) && !is_internal_linkage(*alias) {
            lowering.alias_exposed_globals
                .entry(target.clone()).or_default().insert(alias_key.clone());
        }
    }
    if !is_non_interposable_alias(*alias) { … continue; }             // unchanged
    …
}
```

`alias_exposed_globals: BTreeMap<String, BTreeSet<String>>` is a new
`LoweringStats` field (`#[serde(default)]`, like every other), and the §E clause
becomes `alias_exposed_globals.get(key).is_none()`. Two properties are
deliberate:

- **Resolution is separated from modelling.** The alias is still dropped from
  `AliasMap` exactly as today — the change records *why* before discarding it.
  Nothing about points-to, escape, or the Ω boundary moves, so this is not a
  precision change dressed up as a fact addition.
- **An unresolvable aliasee counts as exposure of nothing, not of everything.**
  If `constant_symbol_name` returns `None` the inventory gains no entry, which
  is unsound if that alias in fact targeted the flag. That case is covered by
  the module-wide fallback below rather than by pretending the inventory saw it.

**Fallback if the PIR field is deferred.** The inventory needs a PIR change, and
Phase 3 already adds two `Global` fields, so it is not free. The sound
alternative available with no schema change is blunt: block signal-flag mode for
**every** global in a module whose `lowering.tainted_counts` contains any key
with an `alias_` prefix. That is implementable today — `tainted_counts` is on
`Pir` — and it fails closed. Its cost is real: `is_non_interposable_alias`
accepts only `Private` and `Internal` linkage, so *any* external alias in the
module, including a perfectly ordinary one to an unrelated function, disables the
feature module-wide.

The choice is a coverage measurement, not a design question, and Phase 3's
acceptance should make it: count corpus modules with an `alias_`-prefixed taint
key. If that count is near zero the blunt rule ships and the inventory is
unnecessary; if it is not, the inventory lands. What must **not** happen is the
third option the earlier draft effectively chose — a target-specific predicate
that no fact can evaluate, which an implementer would most likely resolve by
writing `false` and moving on.

It also makes Phase 2 a hard prerequisite of Phase 3 rather than a courtesy
ordering: without the registry alias, the bore flag has
`signal_context_access: false` and is correctly rejected. That is the desired
failure mode — the idiom is admitted only where the analysis can see the signal
context that gives it meaning.

#### The conjunct needs a fact the manifest does not yet have

`signal_context_access` is one `EvidencedBool`
(`crates/pangs-manifest/src/lib.rs:400`, `DISPOSITION.md` §2), and it is true for
resolved *and* unresolved registrations alike. D3 cannot read the distinction
the conjunct above requires. Worse, the witness does not settle it either: the
producer uses `or_insert_with` (`crates/pangs-clients/src/lib.rs:882-887`), so a
global reached by both a resolved and an unresolved registration keeps whichever
came first in callsite order — an arbitrary choice, not the strongest evidence.

Add a sibling fact:

| Fact | Semantics |
|---|---|
| `signal_context_access` | **unchanged.** True if *any* signal registration, resolved or not, reaches the global — "reaches" in the widening sense, including module-wide. Restricting consumers (mutex rejection, atomic's lock-free gate) keep reading exactly this. |
| `resolved_signal_context_access` | **new.** True iff at least one **resolved** registration has a *certified positive access path* (below) to the global. Evidenced polarity true; the witness is the resolving registration site, the handler, and the path. |

**Admission predicate, exact:**

```text
admit volatile  ⇐  resolved_signal_context_access.value == true
```

#### Provenance: why "reaches" is not good enough for a permitting fact

The two facts differ in more than resolvedness, and an earlier draft of this
section obscured that by using the same word for both. `signal_context_access` is
computed from `transitive_accesses`, whose per-payload target set is
`AffectedGlobals::ModuleWide` whenever the underlying access is through a pointer
with no finite candidate set (`crates/pangs-api/src/lib.rs:2093-2096`), and
`registry_access_facts` then sets the mask on **every global in the module**
(`crates/pangs-clients/src/lib.rs:848-852`).

For the restrictive fact that is correct and deliberate: widening kills `mutex`
and tightens `atomic`'s lock-free gate, both fail-safe directions. **Cloning that
computation for the permitting fact would be a soundness hole.** One handler with
an unresolved transitive effect would mark every global in the module as
positively signal-accessed, and §E's conjunct — whose entire job is to supply
positive evidence that *this* object participates in a real signal handler —
would be satisfied by every global for free, on the strength of a widening.

Note that `ModuleWide` is **orthogonal to `unresolved`**. It comes from the
handler's own transitive access summary, not from the registration operand, so
restricting the new fact to resolved registrations does not avoid it: a perfectly
resolved `signal(2, handler)` whose handler contains one unanalyzable pointer
store would still mark the whole module. The restriction has to be on the access
path, not on the registration.

**Certified positive access path.** `resolved_signal_context_access` is true for
a global `g` only when there exists a path

```text
f₀ → f₁ → … → fₙ    (n ≥ 0)
```

where:

- `f₀` is a **precise** target of a **resolved** signal registration — not a
  member of §D.5's address-taken widening;
- every edge is a `Stmt::CallDirect` to a defined internal function; and
- `fₙ` contains an `AccessSite` on `g` with `via == Via::Direct`.

Everything weaker is rejected as insufficient:

| Provenance | Sets `signal_context_access` | Sets `resolved_signal_context_access` |
|---|---|---|
| `Via::Direct` site, direct-call path from a precise resolved target | yes | **yes** |
| `Via::Aliased` / `Via::Unknown` site (pointer access, finite candidate set) | yes | no — a *may* set is not positive proof that this global is the one touched |
| `AffectedGlobals::ModuleWide` | yes | **no** — this is the case the rule exists for |
| any indirect-call edge on the path | yes | no — the call graph over-approximates exactly there |
| target from the address-taken widening | yes | no — the widening is a conservative guess at who the handler is |

The direct-call restriction on the path is what keeps the evidence finite and
exhibitable: the witness *is* the path, and a reviewer can read it in the source.
An indirect edge would make the claim depend on call-graph precision, which is a
may-relation — over-approximating who the handler calls is safe for a restrictive
fact and unsound for a permitting one, the same asymmetry one level up.

**This costs less than it appears.** The admitted access set already requires
`via == Via::Direct` at every site: `atomic_access_recipe` fails
`address-access-not-lowerable` otherwise (`crates/pangs-clients/src/lib.rs:1891`).
So a global whose handler touches it only through a pointer could never have
certified anyway — the recipe would reject the handler's own access site. The new
rule aligns the *fact* with a restriction the *recipe* already enforced, rather
than adding a new one. For the bore case the path has length zero:
`sigint_handler_xjtr_0` is a precise target of the resolved `signal(2, …)` and
contains a `Via::Direct` store to `g_interrupted_xjtr_0`.

**An API gap this exposes.** A client cannot currently distinguish the tiers
through `transitive_accesses`, because `AffectedGlobals::Finite` is returned both
for `GlobalTarget::Name(g)` — a one-element slice, exact — and for
`GlobalTarget::Unknown(_)` with a finite candidate set, which may also be one
element (`crates/pangs-api/src/lib.rs:2091-2097`). The two are indistinguishable
at the call site. So the new fact must **not** be computed from
`transitive_accesses` at all. It is computed from `access_sites_for_global`
(`crates/pangs-api/src/lib.rs:2012`), which carries `via` and `func` per site,
walked backwards over direct-call edges to the registration targets. That is a
different query, not a filtered version of the old one, and Phase 3 must
implement it as such.

Existential over resolved registrations — *not* universal over all of them. The
mixed case therefore admits: a global reached by one resolved and three
unresolved registrations is admissible. The reasoning is that the conjunct's job
is to supply *positive* proof that this object participates in a real signal
handler, which one resolved registration fully supplies; additional unresolved
registrations widen the handler set but cannot undermine evidence that already
exists. They also cannot weaken the other conjuncts, which are about the type,
the target, and access-set completeness. Blocking on them would fail closed
against nothing.

**Witness determinism.** `resolved_signal_context_access` records the resolved
registration with the lowest callsite id, so the value is stable across runs and
in golden files. `signal_context_access` keeps its existing first-wins witness;
changing it is out of scope and would churn goldens for no consumer.

**Why this is a fact and `signal_atomic_type` is not** (D1 went the other way,
and the difference should not look arbitrary): this is a *guard conjunct*, and
`DISPOSITION.md` §1's guard-shape rule puts guard inputs in the fact vector.
Burying a guard input inside a certificate payload would invert that rule and
make the guard unreadable from the fact layer. `signal_atomic_type` is not a
guard input — it is evidence internal to one certificate — so it stays where D1
put it.

Invariant, checked by the validator:

```text
resolved_signal_context_access.value == true  ⇒  signal_context_access.value == true
```

The initial admitted operation set should be deliberately small:

- direct whole-object loads;
- direct whole-object stores;
- comparisons and control flow consuming a load;
- stores of values representable by the selected atomic type; and
- no address-based, field, bulk-memory, inline-assembly, or unknown access.

Do not initially admit:

- volatile read-modify-write expressions;
- increment/decrement or compound assignment;
- accesses through escaped pointers;
- mismatched-width or partial accesses;
- `memcpy`, `memset`, or byte-wise access to the object;
- general volatile objects lacking `sig_atomic_t` evidence; or
- objects that may be memory-mapped I/O.

The recipe should mark the special lowering mode explicitly. Fields are shown
here beside each other for readability; their normative nesting differs and is
frozen in §"Schema v5" §4 — `volatile_semantics` belongs to `recipe`, while
`signal_lock_free` sits at certificate level:

```json
{
  "ordering": "relaxed",
  "volatile_semantics": "certified-signal-flag",
  "signal_lock_free": {
    "required": true,
    "width": 32,
    "operations": ["load", "store"],
    "target_guaranteed": true,
    "source": "builtin"
  }
}
```

Relaxed ordering matches the narrow role of the flag itself: it communicates a
scalar stop condition and does not publish other memory. A future case that
uses the flag to publish payload state needs a separate synchronization proof;
it must not inherit acquire/release semantics accidentally from this rule.

The materializer should lower the declaration and every certified access as
one consistent atomic representation. It must not mix volatile raw accesses
and atomic accesses to the same storage.

#### The lock-free gate needs a real target fact

The existing gate reads `target.supported_atomic_widths`, which
`module_target_info` (`crates/pangs-pir/src/llvm_sys.rs:407`) computes as
`[8, 16, 32]` plus 64 when the pointer is 64-bit. That is a pointer-width
heuristic with no backend behind it: it asserts 8/16/32-bit atomics on every
target regardless of whether the target has them, and it says nothing about
whether an operation is lock-free or lowered to an `__atomic_*` libcall. Using
it as the async-signal safety gate — which is what
`crates/pangs-clients/src/lib.rs:1113,1217` do today — states a guarantee the
value does not carry. Decision D2 settles this: the current fact is **not**
strong enough, and only the signal gate moves off it.

The narrow scope here makes the required fact cheaper than the general one:

- The admitted operation set is loads and stores only. The claim needed is
  *lock-free load and store of width W*, which is a much weaker and much more
  widely satisfied property than lock-free RMW, and it is the property Rust
  exposes as `target_has_atomic_load_store`.
- So **add** `lock_free_load_store_widths` for this gate and leave
  `supported_atomic_widths` exactly as it is. The certificate records the
  operation set it is claiming (`operations` above), so a later extension to RMW
  cannot silently reuse a load/store-only proof.

#### Why only the new fact is profile-backed

Replacing both lists with a profile that defaults to empty would not "broaden
the corpus diff"; it would be a cliff. `word_sized_scalar` reads
`supported_atomic_widths` (`crates/pangs-clients/src/lib.rs:2337`), which is the
*coarse* gate for every global, so an unlisted triple would zero atomic
eligibility module-wide. Worse, the bore regression could not detect it: bore is
`x86_64-unknown-linux-gnu`, which any plausible table lists.

The deeper reason to treat the two lists differently is that their failure modes
are not in the same risk class:

| Fact | If it is wrong | Detected by |
|---|---|---|
| `supported_atomic_widths` | the recipe names a Rust atomic type that does not exist for the width | **compile error** in the Rust output — `DISPOSITION.md` §7's structural gift |
| `lock_free_load_store_widths` | a signal handler takes a lock, or an access is not indivisible | **nothing** — silent deadlock or torn access at runtime |

A pointer-width heuristic is a defensible stand-in for a property whose
violation fails to compile. It is not a defensible stand-in for a property whose
violation is silent. That asymmetry, not tidiness, is what justifies backing one
list with an authoritative profile and leaving the other alone.

Migrating `supported_atomic_widths` is therefore a **separate, evidence-gated
follow-up**: derive the profile, diff it against the heuristic across the
triples the corpus actually contains, and only then decide. If they never
disagree the migration is a rename that can land at any time; if they do
disagree, that disagreement is a bug report about the general atomic recipe and
deserves its own note rather than being folded into a signal-flag change.

#### Profile specification

**Key.** The normalized architecture component of `TargetInfo.triple`, which is
already captured (`crates/pangs-pir/src/llvm_sys.rs:412`). Lock-free load/store
is an ISA property, so vendor, OS, and environment components are ignored;
normalization is the arch component plus a small alias map (`amd64`, `x86_64h`
→ `x86_64`). An absent or unparsable triple resolves to no profile.

**Rows in v1: exactly one.**

```text
x86_64  ->  [8, 16, 32, 64]
(everything else absent -> empty -> fail closed)
```

The corpus is 71 modules and 100% `x86_64-*-linux-*`. A row that no test
exercises is a liability, not coverage. The omissions are decisions, and the
table should say so inline so a later contributor does not "complete" it:

- `arm`/`thumb` — 64-bit lock-free load/store depends on sub-arch (`ldrexd`),
  which the arch component does not determine.
- `riscv32`/`riscv64` — atomics come from the `A` extension, a feature rather
  than an implication of the arch string.
- 32-bit x86 — 64-bit lock-free load/store needs i586+ (`cmpxchg8b`/x87), so
  `i386` and `i686` cannot share a row.

**CPU features are not consulted.** A row lists only widths lock-free on the
arch's *baseline* subtarget. Enabling features can add lock-freedom but never
remove it, so ignoring them errs closed. This is also why an arch with an
ambiguous baseline gets no row instead of an optimistic one. Per-function
`target-features` attributes in the IR are deliberately not read: they are
per-function, frequently absent in `-O0` bitcode, and would make a
module-global fact depend on which function happened to carry an attribute.

**Authority.** The consumer of this fact is generated Rust, so the authority is
the Rust target definition, not LLVM's:
`rustc --print cfg --target <triple> | grep target_has_atomic_load_store`. Check
the table in with the rustc version it was derived from, and add a test that
re-derives it when `rustc` is available on the machine and skips otherwise.

**Configuration — narrowing or evidence, never assertion.** A `--target-profile`
JSON file, merged by normalized arch key, may do exactly two things:

```text
1. NARROW    remove widths from a built-in row, or remove the row entirely
2. EVIDENCE  supply a row together with a codegen-evidence bundle that validates
```

Asserting a new width or a new arch row by hand is **rejected**, with no
accepted-risk escape.

An earlier draft allowed a hand-written row as an "audited assumption", by
analogy with `--registry-config`. That analogy is wrong, and the reason is the
asymmetry this note keeps returning to: a bad registry entry is conservative in
every consumer, while a bad lock-free width is the silent-deadlock gate. The two
config surfaces look symmetric and must not share a permission model. Recording
an unverifiable claim in the ledger does not make it true; for a gate whose
failure is silent, "audited" is not a substitute for "tested", and it directly
contradicted the evidence requirement in §"Audit contract".

Narrowing needs no evidence and is always allowed: removing widths can only move
globals toward `unhandled`. It appends an informational
`target-profile-narrowed` ledger record, since a deliberate coverage reduction
is worth seeing.

An **evidence bundle** is the recorded output of the same codegen regression,
naming per `(arch, width, opt level)` the toolchain identity, the assertions
that passed, and a hash of the fixture source and compiler invocation. The
analyzer admits the row only when the bundle's fixture hash matches the in-tree
fixture, its toolchain fields fall inside the declared envelope, and every
`(width, operation)` the row claims appears with all assertions passing. The
bundle is not trusted as a document; it is checked as a record *of this
regression*.

The honest limit: a determined operator can fabricate a bundle. Tamper-proofing
against the operator is not the goal — preventing an *accidental* assertion of
lock-freedom through a config edit is. The bundle raises the bar from editing a
JSON list to producing a regression record, and the ledger names the bundle so
an auditor can re-run it.

**Reproducibility.** Record the resolution in `run.analysis` — analysis-owned
under `DISPOSITION.md` §3.3 — so a manifest names the target facts it was
computed under:

```json
"target_profile": {
  "triple": "x86_64-unknown-linux-gnu",
  "arch": "x86_64",
  "source": "builtin",
  "lock_free_load_store_widths": [8, 16, 32, 64],
  "supported_atomic_widths": [8, 16, 32, 64]
}
```

`source` is `"builtin"`, `"builtin+narrowed"`, or `"evidence-bundle"`. A
narrowed row adds `narrowed_from` with the original width list; an
evidence-bundle row adds `evidence_bundle: { id, sha256, fixture_sha256 }`.
Narrowing does not change the provenance of the widths that *remain*, so a
narrowed row's certificates still report `source: "builtin"`.

`signal_lock_free` in the certificate carries `source` alongside its width and
operation set, so an individual certificate is self-describing without a lookup
into the run header. That is only trustworthy if the two cannot disagree, so §4's
value coupling requires the certificate's `source` to be the image of
`P.source` under the mapping above — `builtin` and `builtin+narrowed` both
project to `builtin`, `evidence-bundle` to itself. A certificate reporting the
in-tree provenance for a width that came from a bundle would defeat the audit
trail this section's honest-limit paragraph relies on, and it would do so
specifically for the reader who was told the certificate stands alone.

**The bore case.** `x86_64-unknown-linux-gnu` normalizes to `x86_64`, which
yields `[8, 16, 32, 64]`; the 32-bit flag passes. No corpus module exercises the
empty default, which is worth stating plainly: the fail-closed path is asserted
by a synthetic fixture with an unlisted triple, never by the corpus.

#### Why dropping `volatile` is admissible, and what remains assumed

An earlier draft of this section claimed that a `Relaxed` (LLVM `monotonic`)
access "cannot be fused with adjacent accesses the way a plain load can." **That
is false**, and the error mattered: it treated the whole gap between `volatile`
and `Relaxed` as one quality-of-implementation footnote. LLVM's atomics guide is
explicit that CSE and DSE are permitted for monotonic operations, while
`volatile` is the qualifier that preserves the *number and relative order* of the
operations it qualifies. Those are different guarantees, and the certificate has
to say which of them it is actually replacing.

So enumerate the delta honestly. `volatile` gives three things; `Relaxed` gives
the first, gives the third only as a compiler property, and does not give the
second:

| | `volatile` | `Relaxed` / `monotonic` |
|---|---|---|
| **(i)** indivisibility of a width-appropriate access | not guaranteed by C; supplied here by `sig_atomic_t` + the lock-free gate | guaranteed |
| **(ii)** preservation of access *count* and of relative order among qualified accesses | guaranteed | **not** guaranteed — RLE, DSE, store-to-load forwarding and coalescing are all permitted |
| **(iii)** no *unbounded* elision — the access is re-executed on each loop iteration | guaranteed | not an abstract-machine guarantee; in LLVM, LICM hoisting and promotion require `isUnordered()`, which `monotonic` is not |

Note also what `volatile` never gave: it does not order a volatile access against
*non-volatile* accesses, and it emits no fences, so it never provided
inter-thread ordering. Anything a second thread could observe was already
unordered in the C source. The only same-thread observer that can see (ii) is a
signal handler, because signal delivery is synchronous on the interrupted thread
and therefore sees program order.

**The argument that closes (ii): signal-arrival refinement.** Take the permitted
transformations one at a time, against a flag whose sole role is to convey *that*
a signal arrived:

- Two loads of the flag with no intervening access to it, collapsed into one.
  The source execution in which the signal was delivered *after* both loads is
  always a legal execution — delivery timing is unconstrained — and it produces
  exactly the transformed behavior. So the transformed program's behaviors are a
  subset of the source's.
- A store overwritten by a later store to the same flag, deleted. Same argument
  with the roles swapped: the source execution in which delivery happened outside
  the deleted window is legal and yields the transformed behavior.
- Store-to-load forwarding, coalescing, reordering against ordinary accesses.
  Same argument again; the observer that would have to distinguish them is the
  handler, and F2 below confines what the handler may observe.

Every one of these is *behavior-refining*: it removes possible executions, all of
which correspond to a legal source execution with a slightly later or earlier
arrival. That is why (ii) is recoverable, and it is recoverable **only** for a
flag with that role — which is what the pattern conditions below make a checkable
precondition rather than a description.

The argument does not extend to *unbounded* elision, and cannot: a load hoisted
out of a polling loop yields an execution in which the signal is never observed
at any time, which is not "delivered later" but "never delivered." That is
outcome (iii), and it is the one genuine residual.

**The pattern conditions.** Certification in signal-flag mode additionally
requires, as hard conjuncts, F1 and F2:

- **F1. Sole certified flag.** The program admits at most **one** global into
  signal-flag mode. With two, the ordering between them becomes unobserved by the
  compiler while the interrupted code can still observe it — `flag_a = 1;
  flag_b = 1;` in a handler, read in the other order by the main loop, is a real
  pattern that (ii) protects and `Relaxed` does not. One flag makes the ordering
  question vacuous rather than argued. Failure code `signal-flag-not-sole`, on
  every candidate; the design does not pick a winner.
- **F2. Handler-observer confinement.** Let `A` be the set of functions
  containing an enumerated access to the flag — known exactly, because access-set
  completeness is already a conjunct, and every such site is `Via::Direct` or the
  recipe already failed — and let `H` be the handler set over **all**
  registrations in the program: precise targets for resolved ones, plus §D.5's
  frozen widening `{ f : f.address_taken ∧ ¬f.external }` for unresolved ones.
  Require that every function in `A ∩ H` accesses no object with static or thread
  storage duration other than the flag. Failure code
  `signal-handler-access-not-confined`, witnessed by the function and the
  offending object.

  The two sets take their over-approximation in **opposite directions**, and this
  is deliberate: `H` is widened (more candidate handlers ⇒ more functions to
  check ⇒ harder to pass), while `A` is the recipe's own exact, `Via::Direct`
  site list. A widened `A` would be the unsound direction, and the same
  `ModuleWide` hazard described under §"Provenance" would apply — every global in
  the module would appear in every handler's access set. F2 must therefore be
  evaluated against `access_sites_for_global`, never against the registry's
  transitive mask.

  The "accesses no other static-storage object" half of F2 is the one place a
  widened set is *safe*: it is a restrictive test, so `ModuleWide` there means
  "may touch everything," which fails F2 and rejects. That is the correct
  direction, and it means F2's second half can read the ordinary transitive
  summary without the provenance machinery.

  The intersection is what makes this both sound and affordable. A function that
  never touches the flag cannot correlate the flag's order with anything, so it
  is not an observer of (ii) no matter what else it touches; a function that is
  not in `H` cannot run as a handler at all. Only a function in both can see what
  `volatile` was protecting.

  For the functions that *are* in both, F2 is C11 §7.14.1.1p5 restated — a
  handler that refers to any static-storage object other than by assigning to a
  `volatile sig_atomic_t` is already undefined behavior — so the condition
  rejects only programs that were broken before translation.

**Why there is no "reject all unresolved registrations" condition.** The obvious
way to make F2 checkable is to demand a closed handler set: no unresolved
registration anywhere in the program. That is wrong twice over. It contradicts
§D's mixed-case rule, which admits one resolved registration alongside any number
of unresolved ones and gives the reason. And it would reject this note's own
motivating case: `bore_search_cleanup` restores the previous handler with
`signal(2, g_prev_sigint_handler_xjtr_0)`, whose operand is a function pointer
read from a global holding an *external function's return value* and is therefore
unresolvable in principle, not by a gap in the analysis. Restoring a saved
handler is ordinary, correct C.

The widening already discharges closure without that cost. Unknown external
targets cannot access the flag — it has internal linkage (M.8) and its address
never escapes (already an atomic-recipe conjunct) — and §D.5's widening covers
the internal ones by including every internal address-taken function. So `H` is a
sound over-approximation with the unresolved registration in it, and F2 quantifies
over `A ∩ H` regardless of how the registration resolved.

Both conditions are checkable from facts this design already computes: F1 is a
count over the candidate set; `A` is the recipe's own access list, grouped by
enclosing function; `H` is `registry_access_facts`' target set with the widening
at `crates/pangs-clients/src/lib.rs:838-841`.

**The bore case, checked.** F1: one `volatile sig_atomic_t` in the module. `A` =
`{sigint_handler_xjtr_0, bore_search_init, bore_search_file, bore_search_dir,
bore_search}`. `H` = `{sigint_handler_xjtr_0}` ∪ the internal address-taken set;
the four `bore_search*` functions have external linkage and so are not in the
widening. `A ∩ H` = `{sigint_handler_xjtr_0}`, whose body is `(void)sig;
g_interrupted_xjtr_0 = 1;` — no other static object. F2 holds. This is worth
stating because the pattern conditions are the one part of this design that could
have silently disqualified the case it was written for.

**The single residual assumption.** After F1 and F2, exactly one thing is assumed:
*a `monotonic` load or store inside a loop is re-executed on each iteration —
the compiler does not hoist, sink, or promote it out.* C11 §7.17.3 and the Rust
memory model only say a relaxed store *should* become visible in finite time, so
this is a quality-of-implementation property; in LLVM it holds because LICM's
hoist and promotion paths require `isUnordered()`. Reducing the residual from
"everything `volatile` did" to this one statement is the point of the section:
it is now a property a codegen regression can actually assert, per profile row,
in both directions (load and store), which the audit contract below does.

The residual is still strictly better than what the current pipeline offers this
global (`unhandled` — `static mut` and unsafe), and it is the property every real
signal flag in Rust relies on. But it is an assumption, and it belongs in the
audited soundness inventory (`DESIGN.md` §8) alongside the accepted-risk override
ledger rather than left implicit. Phase 4's dynamic SIGINT test exercises it.

Two consequences for the materializer follow, and both are hard requirements:

- It must not "optimize" a certified access back to a plain non-atomic read even
  when it can prove the flag is loop-invariant in its own view of the program;
  the handler write is invisible to that proof.
- It must not substitute a `Cell`, a plain `static mut` read, or an
  `UnsafeCell`-based shim for the atomic representation.

**The rejected alternative** was the other option: keep admission broad and
extend the assumption to cover the execution and ordering of every admitted
access. That inverts the risk posture the rest of this note argues for. It would
require asserting, per target and per opt level, that *no* permitted monotonic
transformation ever fires on a certified access — a universally quantified claim
over an optimizer, unfalsifiable by any finite regression, and one that would
have to be re-established on every LLVM upgrade. F1 and F2 instead make the permitted
transformations harmless by construction and leave one existentially checkable
property behind.

#### Audit contract for the no-elision assumption

A single SIGINT test on one host cannot establish a quality-of-implementation
property across targets, so the assumption needs a declared scope, a ledger
record, and a regression that runs per profile row.

**Who records it, and determinism.** `AuditRecord::regenerate_id`
(`crates/pangs-manifest/src/lib.rs:1392`) hashes the whole record, so its content
must be deterministic — and the analysis stage, which emits the ledger, does not
know what Rust toolchain will eventually compile the output. The split:

- **Analysis emits the envelope** from a checked-in evidence table, exactly as
  §E's target profile is checked in with the rustc version it was derived from.
  The fields are repo constants, so the id is stable.
- **The Rust stage enforces it**: before rewriting, it compares the actual
  toolchain against the recorded envelope and fails loudly when outside. That is
  the only stage that knows the answer, and M.7 already gives it a loud-failure
  channel.

**Record shape.** No audit-schema change is required: `kind` is a free string and
the schema is `additionalProperties: true`, so the structured payload rides in
`AuditRecord.extra`. One run-scoped record, emitted only when at least one
global certifies in signal-flag mode, plus one `scope: global` record per such
global — matching how accepted-risk pins add per-global rows
(`DISPOSITION.md` §7). Rows are **self-contained and do not cross-reference**;
a ledger line must be readable alone.

```jsonc
{
  "id": "ar-…",                                  // content hash, per §1.4
  "kind": "signal-flag-codegen-assumption",
  "scope": { "kind": "run" },
  "source": "analysis",
  "text": "Certified signal-flag atomics assume the Rust backend does not hoist, sink, or promote a Relaxed atomic load or store out of a loop, and lowers load/store of the certified width without a library call. Bounded transformations that Relaxed permits (redundant-load elimination, dead-store elimination, coalescing) are not assumed against; certification requires the F1/F2 flag pattern, under which they are behavior-refining. This is a quality-of-implementation property, not an abstract-machine guarantee.",
  "envelope": {
    "triple": "x86_64-unknown-linux-gnu",
    "arch": "x86_64",
    "widths": [32],
    "operations": ["load", "store"],
    "rustc_min": "1.XX.0",
    "llvm_major": [17, 18, 19],
    "opt_levels": ["0", "1", "2", "3"],
    "evidence": "codegen-regression:signal_flag_codegen"
  }
}
```

**Declared scope, and no extrapolation.** The assumption is asserted for exactly
the cross product

```text
{profile rows} × {widths in the row} × {rustc ≥ floor, LLVM in list} × {opt levels}
```

and for nothing else. A toolchain outside it is not "probably fine"; it is
outside the audited envelope, and the Rust stage refuses.

**Codegen regression, per profile row.** The governing constraint is that a row
can be *compiled* for without being *runnable* on: cross-targets have no host to
execute on. So the per-row gate must be an artifact check, and execution is a
host-only addition. For every declared profile row × width × opt level, compile
fixtures and assert the following.

What is asserted follows directly from the residual: the audited property is
*absence of unbounded elision*, not preservation of access count. An earlier
draft asserted count equality at IR level, which would have failed on a
legitimate RLE and passed a store sunk past a loop — testing the wrong property
in both directions. The assertions are therefore positional, and they cover the
store side, which the earlier draft omitted entirely.

1. **No library call.** No reference to any `__atomic_*` symbol, and no call in
   the loop other than the fixture's own opaque `work()`/`step()`.
2. **Load not hoisted or promoted.** Fixture: a polling loop reading the flag.
   At `--emit=llvm-ir -C opt-level=3`, at least one `load atomic monotonic` of
   the flag appears in the loop body, and the loop's exit condition still depends
   on a value loaded inside the loop — not on a value loaded in the entry block
   or carried by a phi from before the loop.
3. **Store not sunk or coalesced out of a loop.** Fixture: a loop that stores to
   the flag each iteration with an opaque call between. At least one
   `store atomic monotonic` to the flag appears in the loop body, and none has
   migrated to the loop exit block.
4. **Store not deleted across a call.** Fixture: `flag = 1; work(); flag = 0;`.
   Both stores survive. This is the bounded-DSE boundary: deletion of the first
   store *with nothing in between* is permitted and is not asserted against;
   deletion across a call that may deliver a signal is not.
5. **Asm cross-check** on rows where the loop structure is recognizable: a
   memory operand naming the static appears between the loop label and its
   backedge, for both the load and the store fixtures.

Assertions 2–4 are the operational form of the single residual; nothing here
asserts that a permitted transformation never fires, because F1 and F2 make the
bounded ones harmless and no finite regression could establish the universal
claim.

Then, host-only, the Phase 4 SIGINT test: a hoisted load makes the loop never
terminate, so the property is observed rather than inspected. It is a liveness
test and must run under a timeout, where a hang is a failure.

**The coupling that makes this enforceable:** a target profile row is admissible
**only** if the codegen regression covers it — whether the row comes from the
built-in table or from a `--target-profile` evidence bundle, which is checked
against the same regression. A row without evidence is not a row, which is the
concrete meaning of §E's "defaulting to empty" and the reason v1 ships exactly
`x86_64`. If the regression fails for a row, the row is removed, the width stops
being lock-free-certified, and signal flags on that target fall back to
`unhandled`. Fail closed: configuration can narrow the result or supply fresh
evidence, but cannot re-add a width the regression rejected.

**What this does not do.** None of it *proves* the QoI property; it detects
regression in the toolchains under test, which is what a regression test is for.
The ledger record says so in its own `text`, so an auditor reading the inventory
sees the limit rather than inferring a guarantee.

### F. Distinguish semantic certification from already-safe source

The source program is already using the C-prescribed signal-flag idiom. That
does not by itself tell the downstream Rust materializer what representation to
emit. The disposition should therefore remain `atomic`, but its certificate
should say why the volatile source is admitted and how it must be translated.

An alternative would be a new `signal-atomic` disposition. That is not proposed
initially because its storage/action is still atomic and adding a strategy
would expand the cascade, schema, overrides, measurements, and materializer
surface. A certificate mode under `atomic` is sufficient unless later cases
need materially different policy or output.

## Schema v5: normative freeze

Everything above this point is design rationale; this section is the contract.
The JSON in earlier sections is illustrative and, where it disagrees with this
section, wrong. MUST/MUST NOT are normative; the field paths are exact.

### 1. Encoding conventions

These are already the manifest's conventions; v5 restates them because the new
fields must not invent alternatives.

- **v5 is defined once, in Phase 1.** A schema version is a contract, not a
  changelog. The *entire* v5 contract — `word_sized_scalar`,
  `resolved_signal_context_access`, and every signal-flag payload and validator
  rule in this section — lands with the version bump in Phase 1, **dormant**:
  the types, schema definitions, and validator rules are all present, and the
  signal-flag rules are vacuously satisfied because nothing emits
  `volatile_semantics` until Phase 3. Phase 3 then changes emission only, never
  the contract.

  This is what keeps Phase 1 independently shippable. The alternatives were
  making Phases 1–3 one atomic change, which couples a type-walker to a registry
  fix for no reason, or reserving v6 for the signal payload, which spends a
  second version on a delta that is already fully specified here and forces a
  third invariant set into the version-parameterized validator. Neither is
  acceptable next to defining the contract once. **A partially-introduced v5, in
  which two incompatible contracts both call themselves v5, is forbidden
  outright.**
- **Absence, not null, for optional detail.** Every *new* optional detail field
  uses `#[serde(skip_serializing_if)]`
  (`crates/pangs-manifest/src/lib.rs:321-328`). `null` is reserved for a *slot*
  meaning "not computed" — the certificate slots and `coupling_group`. A new
  field MUST NOT be emitted as an explicit `null`.

  **Carve-out for pre-existing fields.** `signal_lock_free.width` is already
  emitted as `integer | null` in v4 and keeps that encoding when
  `required == false`; changing it would churn every existing manifest for no
  consumer. The convention binds new fields. In signal-flag mode the width is
  required and non-null regardless (§4).
- **Additive only.** Every object retains `#[serde(flatten)] Extra` and
  `additionalProperties: true`, so an unknown field round-trips rather than
  failing. v5 adds fields; it renames and removes none.
- **Vocabulary.** Field names are `snake_case`; failure codes are `kebab-case`,
  matching the existing code vocabulary (`volatile-access`,
  `word-sized-scalar`). New enums are closed: an unlisted value is invalid, not
  forward-compatible.

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

`codes` reuses the certificate-slot noun rather than introducing
`diagnostics`, which is already an opaque `Value` on `Certificate::Failed` and
would collide with a different type under the same name.

The alignment codes are split rather than named `insufficient-alignment`,
because the gate is strict equality and therefore rejects **over**-alignment
too — a single "insufficient" code would misdescribe every
`__attribute__((aligned(64)))` global. The distinction also carries information
the reader needs: `over-aligned` means the equality gate, whose relaxation §B
names as a separate follow-up; `under-aligned` means a packed or exotic
declaration, which is a different conversation. `unknown-alignment` covers
`align_bits: None`, which today falls into the same silent bucket because
`None != Some(width)`.

**Closed code vocabulary**, emitted in exactly this evaluation order,
deduplicated, and **not sorted** — fixed evaluation order is what the existing
`codes` arrays do, and it keeps golden diffs stable:

```text
unknown-scalar-class
unknown-signedness
zero-width
unsupported-atomic-width
unknown-alignment
under-aligned
over-aligned
```

`meta.type_spelling` is unchanged and remains required-but-nullable in the
schema. When both are present they are the same string; neither gates `value`.

### 2b. `facts.resolved_signal_context_access`

A new `EvidencedBool` with evidenced polarity **true**, added to `Facts`, to the
schema's `facts.required` list, and to `evidenced_bool_true` (§E). Required at
v5; absent at v4, which the version-parameterized validator already
accommodates.

```text
value == true   ⇒  witness present (resolving registration site + handler + path)
value == true   ⇒  signal_context_access.value == true
witness selection: the resolved registration with the lowest callsite id;
                   among paths from it, the shortest, ties broken by
                   callee order within each caller
```

The witness carries the **certified positive access path** (§E, "Provenance"),
not merely the registration:

```jsonc
"witness": {
  "registration": { "callsite": …, "file": …, "line": … },
  "handler": "sigint_handler_xjtr_0",
  "path": ["sigint_handler_xjtr_0"],          // f₀ … fₙ, direct-call edges only
  "access": { "via": "direct", "file": …, "line": … }
}
```

The path is in the witness because the fact is a *permitting* one and its
provenance is the whole of its value. A witness naming only the registration
would be satisfied identically by a module-wide widening and by a real handler
store — the two cases this fact exists to separate. `via` is recorded explicitly
and MUST be `"direct"`; the field exists so a reader can see the rejection rule
was applied rather than assume it.

`signal_context_access` is untouched — same semantics, same widening-based
computation, same first-wins witness, same consumers. The new fact is additive,
computed by a *different query* (§E), and read by exactly one guard.

Path determinism matters for goldens: the shortest-path tie-break is specified
above because a handler can reach a flag by several direct-call chains, and an
arbitrary choice would churn manifests across unrelated inlining changes.

### 3. Version negotiation and fixture behavior

**The v4 → v5 fact-layer delta has two parts, not one.** Several earlier passes
of this note described it as though `word_sized_scalar` were the whole of it:

1. `word_sized_scalar`'s invariant changes — **weaker than v4 for
   `value: true`** and **stronger for `value: false`** (codes are newly
   required).
2. `resolved_signal_context_access` is a **new required fact** (§2b), which v4
   documents do not carry at all.

The second is easy to lose because it is additive and its Phase-1 value is
usually `false`, but it changes the parse surface, the schema's `facts.required`
list, and the golden diff for every global (§7, class A). Existing fixtures
therefore do not uniformly pass, and grandfathering them into a vaguer rule would
destroy their value as tests. The freeze is therefore:

- `Facts::validate` gains a `schema_version` parameter, threaded from
  `Manifest::validate` (`crates/pangs-manifest/src/lib.rs:903`, which today
  calls `global.facts.validate()` with no version). Documents declaring v4 are
  checked against the **v4 invariant exactly**, including the detail
  prohibition; documents declaring v5 are checked against §2.
- Emission is always at `SCHEMA_VERSION`. The dual-invariant path is read-only.

| Reader | Document | Result |
|---|---|---|
| v4 | v5 | refused by the existing version gate (`lib.rs:904`) |
| v5 | v4 | accepted, validated under v4 rules; `resolved_signal_context_access` deserializes to its `#[serde(default)]` value |
| v5 | v5 | validated under §2 |

**Why the new fact needs `#[serde(default)]`, and what that costs.** No
`EvidencedBool` in `Facts` carries a serde default today
(`crates/pangs-manifest/src/lib.rs:400-407`), so adding a bare required field
would make every v4 document fail to *parse* — before the version-parameterized
validator that §2b relies on to accommodate them ever runs. The field is
therefore `#[serde(default)]`, and `EvidencedBool::default()` is
`{ value: false }` with no witness, which is the correct reading of a v4
document: it asserts nothing about resolved signal context, and for a fact with
evidenced polarity `true`, `false` carries no claim and needs no witness.

The cost is that "required at v5" cannot mean *parse-time rejection*: a v5
document omitting the field is indistinguishable after deserialization from one
carrying `value: false`. So the requirement binds **emitters**, and is pinned by
the schema's `facts.required` (which a non-Rust consumer checks) and by the
goldens (which assert every v5 manifest emits it). The residual — a hand-written
v5 manifest omitting the field is read as `false` — is fail-closed, because this
is a permitting fact and `false` denies. That asymmetry is why the plain default
is acceptable here and would not be for a restricting fact.

One further rule closes a hazard this review found: **`pangs-dispose` never
reads or writes `schema_version`.** It parses a `Manifest`, fills its own
sections, and re-serializes, preserving whatever version the input declared — so
a v5 dispose fed a v4 analysis manifest today emits a document *labelled v4*
containing v5-shaped dispose sections. Because `DISPOSITION.md` §3.3 requires
earlier stages' sections to survive semantically unchanged, a stage MUST NOT
silently upgrade or silently inherit:

```text
a stage that preserves an earlier stage's sections MUST require
schema_version == its own SCHEMA_VERSION, and MUST fail with
"re-run analysis" otherwise
```

That is a v5 requirement, not a description of current behavior, and it needs
its own test.

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
  and `diagnostics` — and no certificate-level payload. So a failed slot has
  nowhere to put `signal_atomic_type` or `signal_lock_free`, and a failed recipe
  carrying `volatile_semantics` could not satisfy the coupling below. The
  resolution is normative: **a global whose admission required signal-flag mode
  and did not certify gets `recipe: null`.**

  This costs nothing, because it is already the behavior.
  `atomic_access_recipe` returns `(None, failures)` whenever any failure was
  recorded (`crates/pangs-clients/src/lib.rs:1992`), and the coarse gate sets
  `recipe: None` on its own path, so a failed `atomic_eligibility` slot always
  has a null recipe today. This freeze states that as a rule rather than leaving
  it as an implementation accident.

  The consequence is the desired one: per `DISPOSITION.md` §4.2 an `atomic` pin
  on such a slot is rejected `no-recipe`, **unwaivable by `accept_risk`**. So
  "you cannot override your way into an unproven signal-handler atomic" is a
  structural property of the schema, not a policy rule someone has to remember.
  That is also the right outcome on the merits: every failure code reachable in
  signal-flag mode — `signal-atomic-not-lock-free`, `volatile-access`,
  `address-access-not-lowerable`, `access-site-unmapped`, the `rmw-*` codes,
  `signal-flag-external-linkage`, `signal-flag-not-sole`,
  `signal-handler-access-not-confined` — means the rewrite cannot be executed
  correctly. None is §4.2's honorable "evidence failed, recipe present" case, and
  waiving the first would violate soundness rule 3 outright.

  The two pattern codes belong in that list for a reason worth stating: they look
  like advisory hygiene, and a reader who assumes they are waivable would be
  overriding the conditions that make dropping `volatile` sound at all
  (rule 15), not the conditions that make the rewrite convenient.

  Suppression must stay diagnosable, so the failed slot records it in
  `diagnostics` — which is opaque and load-bearing for nothing:

  ```json
  { "signal_flag": { "status": "recipe-withheld",
                     "reason": "signal-flag mode requires certification" } }
  ```

- **`volatile_semantics` still lives in `recipe`**, but for a different reason
  than an earlier draft of this note gave. That draft placed it there so
  `DISPOSITION.md` §4.2's recipe-bearing override path could see it on a *failed*
  slot; per the rule above that path does not exist for atomic, and the
  rationale is withdrawn. It belongs in `recipe` because the recipe is the
  materializer's input and the mode is a rewrite instruction — M.5's access forms
  depend on it.
- **`signal_atomic_type` and `signal_lock_free` live at certificate level.**
  They are proof properties, not rewrite instructions. A failure carries its
  reason in `codes`/`witnesses`, never as a partial proof object.
- **Presence coupling**, checked by the validator on the certified payload, plus
  a clause that closes the failed path:

  ```text
  recipe.volatile_semantics == "certified-signal-flag"
    ⟺  signal_atomic_type present
    ⟺  signal_flag_pattern present
    ⟺  signal_lock_free.required == true

  and:  volatile_semantics present anywhere  ⇒  the slot is certified
  ```

- **Value coupling.** Presence alone enforces almost nothing: it permits a
  signal-flag certificate whose lock-free proof is for a different width than
  the declaration, or whose `target_guaranteed` is false, or whose typedef is
  not one this design recognizes. The validator MUST additionally require, with
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

  Both booleans are required to be `true`, which raises the obvious question of
  why they are booleans at all rather than the mere presence of the object. They
  are written out because the pattern conditions are the part of this design a
  reader is most likely to assume rather than check: a certificate that names
  them individually can be audited against the source without re-deriving why
  `Relaxed` needed them. `observers` carries the witness that makes F2 auditable
  at all — F2 is a claim about a specific set of functions (`A ∩ H`), and a
  certificate asserting it without naming them is not checkable by anything but
  the analysis that produced it. `observers` is non-empty because
  `resolved_signal_context_access` already guarantees at least one resolved
  registration reaching the global; an empty set would mean the two facts
  disagree.

  F1 is a whole-program property, so the validator MUST also check it globally:
  **at most one global in the manifest carries `signal_flag_pattern`**. A
  per-global check cannot catch two certificates that each claim to be sole.

  The alignment relation is `align == width` throughout, matching the
  `word_sized_scalar` gate that §B deliberately left at equality; a certificate
  claiming otherwise contradicts the gate that produced it.

  **The provenance clause is a cross-check on deliberate redundancy.** §E states
  the mapping in prose — narrowing does not change the provenance of the widths
  that remain, so a narrowed row's certificates report `builtin` — and it is a
  *total function* from `P.source` to `signal_lock_free.source`. That makes the
  certificate field derivable, which was the intent: the certificate is
  self-describing so a reader need not consult the run header. But an earlier
  draft of this list checked only that the value was one of two legal strings,
  never that it matched the header, and derivable-but-unchecked redundancy is a
  divergence waiting to happen rather than a cross-check.

  The failure it admits is the specific one the evidence-bundle mechanism exists
  to prevent. §E's honest limit is that an operator can fabricate a bundle, and
  the defense is that doing so leaves a record an auditor can re-run. If a
  certificate may report `source: "builtin"` while its width came from an
  evidence-bundle row, that defense evaporates for anyone reading the
  certificate: the weaker, in-tree-and-reviewed provenance is claimed for a width
  that exists only because someone supplied a bundle, and the run header naming
  the bundle is exactly what they were told they did not need to consult. The
  reverse direction is less dangerous but still wrong — `evidence-bundle` on a
  builtin row points an auditor at a bundle that does not exist.

  The clause is written per-row because a profile row has exactly one provenance:
  §E permits configuration only to narrow a built-in row or to supply a row
  through a bundle, never to mix widths of different origins within one row. If
  that ever changes, `signal_lock_free.source` must become per-width and this
  clause must be revisited rather than reinterpreted.
  `RECOGNIZED_SIGNAL_TYPEDEFS` is a closed constant in `pangs-manifest`, like the
  other closed vocabularies in this freeze.

  Two of these are cross-section checks — the target profile lives in
  `run.analysis`, and `resolved_signal_context_access` is a sibling fact — so
  the profile must be threaded into per-global validation the same way
  `schema_version` is (§3). `Manifest::validate` already holds both.

  **`run.analysis.target_profile` is optional, and its absence is not a
  validation failure.** Phase 1 lands this validator while Phase 3 is what first
  *emits* a profile, so at Phase 1 no manifest has one. That is consistent
  because every clause naming the profile sits inside the signal-flag coupling,
  which fires only when `recipe.volatile_semantics` is present — and nothing
  emits `volatile_semantics` until Phase 3. The clauses are unreachable at Phase
  1, not vacuously true.

  Normatively, with `P := run.analysis.target_profile`:

  ```text
  volatile_semantics absent   ⇒  P unconstrained (absent at Phase 1, present after)
  volatile_semantics present  ∧  P absent   ⇒  INVALID  ("signal-flag certificate
                                                          without a target profile")
  volatile_semantics present  ∧  P present  ⇒  the width clauses above apply
  ```

  The middle row is the one that matters: it makes a profile-less signal-flag
  certificate a validation error rather than a passed check over a missing
  operand. `P` is `Option<TargetProfile>` in Rust and optional in the JSON
  schema, so a Phase-1 manifest is valid v5 without it and a Phase-3 signal-flag
  manifest cannot be valid without it. No conditional-compilation or
  feature-gating of the validator is involved: one validator, one contract, and
  the profile's presence is data.

  Together these are the most important invariant in the freeze: they are what
  prevents a volatile-admitting recipe from shipping without the proof that
  admitted it, or with a proof of something adjacent to it.

  The rejected alternative was giving `Certificate::Failed` a proof-envelope
  field so the coupling could hold on both paths. It would add a second
  separately-validated shape whose only reachable content is a partial proof of
  something that did not hold — a forgeable object on the failure path, for a
  case that §4.2 already refuses to honor.

- **Scope.** All of the above constrains *signal-flag mode only*. Ordinary
  atomic, mutex, and once-lock slots keep §4.2's honorable accepted-risk case
  unchanged; nothing here narrows the general override contract.
- **Absence is the default.** `volatile_semantics` is a closed enum with exactly
  one v5 member; ordinary non-volatile lowering omits the field entirely rather
  than encoding `"none"`. Every v4 recipe is therefore already valid v5.
- `signal_lock_free.operations` and `.source` are required when
  `required == true` and optional otherwise (a non-signal global's existing
  `{required: false, …}` object is unchanged, `null` width included).
  `operations` is a closed vocabulary of exactly `["load", "store"]` in that
  order; extending it to RMW bumps the schema.
- `source_materialization` is **unchanged**: `status` remains
  `"source-mapped" | "blocked"`, `code` is required iff blocked, and
  `declaration-source-unmapped` remains its only code. Spelling absence is a
  certificate diagnostic, not a status (M.0).
- `certificate.type_evidence` is a new optional diagnostic object; it is
  advisory, carries no invariant, and MUST NOT be read by any guard.

### 5. Ordering, deduplication, truncation

- `typedef_chain` is in **outer-to-inner declaration order**. It is not sorted
  and not deduplicated: it is a path, and its order is the evidence.
- `signal_atomic_type.typedef` is the **recognized standard typedef** — the
  name that licensed the certificate — and MUST be a member of `typedef_chain`.
  It is *not* necessarily `typedef_chain[0]`: under
  `typedef sig_atomic_t my_flag_t;` the chain is
  `["my_flag_t", "sig_atomic_t", "__sig_atomic_t"]`, recognition matches
  `sig_atomic_t` at position 1, and that is what `typedef` records.
- `display_name` in the PIR-side `ScalarTypeEvidence` is a different name with a
  different rule — positionally `typedef_chain[0]`, per §A. The two coincide
  only when the declaration names the standard typedef directly, which is the
  common case and the bore case. They MUST NOT be conflated: one answers "what
  did the source say", the other "what proved this certificate".
- When exactly one member of the chain is a recognized standard name, `typedef`
  is that member. Two recognized members cannot occur, since recognition matches
  a single spelling.
- Exceeding `DEBUG_TYPE_RECURSION_LIMIT` yields **no certificate**, never a
  truncated chain. Same for cycles and malformed metadata.
- `codes`, `operations`, and `typedef_chain` are all deterministic under
  re-emission; a golden-file diff that reorders any of them is a defect.

### 6. Freeze points, and an honest note about rigor

| Artifact | Change |
|---|---|
| `schemas/disposition-manifest.schema.json` | the `word_sized_scalar` `oneOf` (lines 139-166) *is* the v4 invariant and must be replaced by §2; **`resolved_signal_context_access` added to `facts.properties` and to `facts.required`**; add narrow definitions for `signal_atomic_type`, `signal_flag_pattern`, the extended `signal_lock_free`, and `volatile_semantics`; `run.analysis.target_profile` added as optional |
| `crates/pangs-manifest/src/lib.rs` | `SCHEMA_VERSION = 5`; **`Facts.resolved_signal_context_access: EvidencedBool` with `#[serde(default)]`** (§2b); `WordSizedScalar.codes: Vec<String>` with `#[serde(default, skip_serializing_if = "Vec::is_empty")]`; version-parameterized `Facts::validate`; one validator for the §4 coupling |
| `crates/pangs-pir/src/lib.rs` | `Global.type_evidence: Option<ScalarTypeEvidence>` with `#[serde(default)]`, matching every other optional field there (lines 158-183), so existing PIR fixtures parse and re-serialize unchanged |
| `crates/pangs-api/src/lib.rs:142` | `GlobalInfo` mirrors the same optional field |
| `schemas/globals.schema.json` | **unaffected, deliberately.** That stream has `additionalProperties: false` over a fixed key set and carries no type fields at all; it is not the type channel and MUST NOT gain one |
| D1a golden manifests | regenerated; the permitted diff is classified per global in §7, not "version plus `codes`" |

`type_spelling`, `scalar_class`, and `signed` are **retained** on the PIR and API
globals, not replaced. When `type_evidence` is present they are its projections.
No consumer is forced to migrate by this change.

The honest note: certified certificate payloads are **entirely unconstrained**
in the JSON schema today — `certificate` requires only `status` and
`certificate` (`schemas/disposition-manifest.schema.json:167-186`), so `recipe`,
`ordering`, and `signal_lock_free` have never been schema-frozen; they are held
only by golden files and by the emitter at
`crates/pangs-clients/src/lib.rs:1283`. Constraining the signal-flag additions
in the schema is therefore *new* rigor rather than consistency with existing
practice. It is justified by the same asymmetry that governs the target profile
(§E): these fields gate a silent failure, and the JSON schema is the only
artifact a non-Rust consumer can check. The rest of the payload stays as it is;
this note does not undertake to retrofit the whole certificate.

### 7. The permitted golden diff

An earlier draft said the golden regeneration diff "must be exactly the version
bump plus `codes` arrays." That is wrong, and it contradicts this note's own
Phase-1 acceptance criterion, which deliberately permits a spelling-free global
to start certifying. Restating it as a per-global classification, because a
reviewer needs a rule they can apply line by line:

| Class | Condition | Permitted change |
|---|---|---|
| **A** | every manifest | `schema_version` 4 → 5; `facts.resolved_signal_context_access` added to every global record with a **computed** value, not a placeholder (v5 and its producer both land in Phase 1, §1) |
| **B** | `word_sized_scalar` was already true | **nothing else changes** |
| **C** | was false, still false | gains non-empty `codes`; gains the `size_bits`/`class`/`signed` detail that v4 suppressed |
| **D** | false → true, still fails atomic later | class C's detail, plus `value: true`; `atomic_eligibility.codes` changes from `["word-sized-scalar"]` to the later decisive code; `diagnostics` changes from `access_lowering: skipped` to an observed-site count. Disposition unchanged |
| **E** | false → true, now certifies | class D's changes, plus `atomic_eligibility` Failed → Certified with recipe and `source_materialization`; `cascade_chosen`/`chosen` → `atomic`; `cascade_trace` shortens; `run.dispose.measurement_report` moves |

Class D is the bore flag's own Phase-1 diff: it clears the coarse gate and fails
on `volatile-access` instead, which is exactly what Phase 1 predicts for it.

Class A's value may be `true` at Phase 1 for globals in modules whose
registrations the registry *already* recognizes — a direct `sigaction`, or a
`signal` not aliased to `__sysv_signal`. That is correct and changes no
disposition: the fact's only consumer is §E's volatile admission, which is
dormant until Phase 3. A reviewer seeing `true` in a Phase-1 golden should check
that the module has a recognized registration, not that the fact is inert.

The review rule is attribution, not line count: **every changed line must be
attributable to its global's class, and every global must be in a class its
facts justify.** Two defect signals are worth naming because a diff can look
plausible while carrying them:

- a class-B global changing at all — its facts did not move, so nothing about it
  should;
- a class-E global whose `word_sized_scalar` was false for a reason *other* than
  a missing spelling. That is the Phase-1 acceptance predicate restated at the
  file level, and it is the one a careless regeneration would hide.

Aggregate consistency is a separate check: `not_word_sized` must decrease by
exactly |D| + |E|, and `measurement_report` may move only if |E| > 0.

## Materialization contract

`DISPOSITION.md` §5.3 already assigns `atomic` its stage split: the C→C tool
does **exemption + definition-site marker**, and nothing else. This section
makes the rest concrete rather than adding a stage.

### M.0 "Certified but blocked" is a decided policy, not a new one

Stated explicitly, because the rest of this note leans on it:

1. **The separation already exists.** `atomic_source_materialization`
   (`crates/pangs-clients/src/lib.rs:1310`) returns
   `{ status: "blocked", code: "declaration-source-unmapped" }` *inside a
   certified payload* today, and `DISPOSITION.md` §9's D4 entry states the same
   rule for mutex: "Static certification remains distinct from source readiness."
   This proposal adds nothing to that mechanism's semantics.
2. **The cascade guard is certificate-only.** Per `DISPOSITION.md` §1's
   guard-shape rule, slot 3 reads one thing: is `atomic_eligibility` certified.
   A certified slot whose `source_materialization.status` is `blocked` still
   selects `atomic`. Materialization readiness is **not** a cascade input.
3. **Execution failure is corrected downstream**, by C→C demotion (§5.3) or
   Rust-stage loud failure (M.7) — never by retroactively weakening the
   certificate.
4. **Therefore blocked materialization MUST NOT be folded back into the
   certification guard.** Doing so would create a second, divergeable definition
   of atomic eligibility, which is exactly what `DISPOSITION.md` §1's
   guard-shape rule exists to prevent.

**A correction this forces.** An earlier draft of §B proposed a new blocked code
`declaration-type-unspelled`, on the reasoning that a certified atomic with a
null `type_spelling` would be "a recipe its materializer cannot execute." Under
the stage split specified in M.1–M.3 that is simply false: the C→C stage plants
a marker and needs only the symbol and source coordinates (already covered by
`declaration-source-unmapped`), and the Rust stage derives the atomic type from
`scalar_class`/`signed`/`size_bits` and never reads the C spelling. Nothing in
the repository consumes `recipe.declaration.type_spelling`; it is emitted for
diagnosis only.

So the spelling is **diagnostic, not blocking**. §B records its absence as a
certificate note, not a `source_materialization` status, and a spelling-free
scalar that passes every other gate is both certified *and* materializable.
Blocking it would have cost real coverage to satisfy a constraint that does not
exist.

### M.1 Which stage removes `volatile`

**The Rust stage. The C→C stage MUST NOT touch the declaration or any access.**

This is not merely contract compliance. The C→C output is a program that still
compiles and runs as C, and removing `volatile` there would strip the flag's
no-cache property from a program that has no atomic in its place — a real
miscompilation window between the two stages, for a global whose entire point is
being written asynchronously. The C→C tool's only job is to make the decision
findable:

```c
/* C→C output — declaration and every access byte-identical to the input */
#include "pangs_markers.h"
static volatile sig_atomic_t g_interrupted = 0;

__attribute__((constructor)) static void pangs__mark_g_interrupted(void) {
    pangs_disposition_atomic__src_search_c__g_interrupted__ab12cd34();
}
```

The Rust stage is coordinate-free (`DISPOSITION.md` §5.1) and matches by symbol
identity, with the marker as the disambiguator when translation renamed the
item (§5.2).

### M.2 Before and after

Source:

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

Translated Rust, before the rewrite. The C `volatile` accesses arrive as
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
dropping `mut` is what turns every missed access into a compile error rather
than a silent survival — the structural gift `DISPOSITION.md` §7 relies on.

### M.3 Type mapping

Keyed on `recipe.declaration.{scalar_class, signed, size_bits}`:

| `scalar_class` | `signed` | `size_bits` | Rust type |
|---|---|---|---|
| `integer` | true | 8 / 16 / 32 / 64 | `AtomicI8` / `I16` / `I32` / `I64` |
| `integer` | false | 8 / 16 / 32 / 64 | `AtomicU8` / `U16` / `U32` / `U64` |
| `enum` | per `signed` | as above | as the integer rows |
| `boolean` | — | 8 | `AtomicBool` |
| `pointer` | — | — | **out of scope in v1** — a signal flag is an integer, and `AtomicPtr<T>` needs a pointee type this recipe does not carry |

`size_bits` must equal the width in `signal_lock_free`, which D3 already
guarantees; a mismatch is a rewriter error, not a demotion. All paths are
written fully qualified (`::core::sync::atomic::…`) so the rewriter never
manages `use` statements or collides with an existing import — the one design
choice here that removes a whole class of failure.

### M.4 Initializer

`recipe.declaration.initializer_ir` is a typed LLVM constant (`i32 0` for the
bore flag). `AtomicI32::new` is `const fn`, so the result is valid in a `static`.

**Translation is bit-vector semantics, not decimal copying.** LLVM prints
integer constants with a *signed* interpretation of the type's bit width, so
`unsigned char x = 255;` appears as `i8 -1`. Copying that decimal into
`AtomicU8::new(-1)` does not compile, and a naive `abs`-style repair would
silently produce `1`. The rule:

```text
1. parse "iN <decimal>"  ->  (N, signed value v)
2. require N == recipe.declaration.size_bits
3. bits := v reduced mod 2^N        (two's-complement pattern, N bits)
4. emit the literal in the TARGET type's signedness:
     AtomicIN::new(<bits interpreted as signed N-bit>)
     AtomicUN::new(<bits interpreted as unsigned N-bit>)
```

Worked cases:

| `initializer_ir` | `signed` | Emitted |
|---|---|---|
| `i32 0` | true | `AtomicI32::new(0)` |
| `i32 -1` | true | `AtomicI32::new(-1)` |
| `i8 -1` | **false** | `AtomicU8::new(255)` |
| `i8 -1` | true | `AtomicI8::new(-1)` |
| `i32 -2147483648` | true | `AtomicI32::new(-2147483648)` |
| `i32 -2147483648` | false | `AtomicU32::new(2147483648)` |
| `zeroinitializer` | either | `AtomicIN::new(0)` / `AtomicUN::new(0)` |

**Boolean initialization**, which the earlier draft left unspecified. A C `_Bool`
global has `scalar_class: "boolean"` but is stored as `i8`, so both spellings
must be accepted and every other bit pattern rejected — `AtomicBool::new` takes a
`bool` and has no representation for anything else:

```text
"i1 false" | "i8 0" | "zeroinitializer"  ->  AtomicBool::new(false)
"i1 true"  | "i8 1"                      ->  AtomicBool::new(true)
any other value at boolean class         ->  rewriter error
```

A `_Bool` holding some other pattern is already outside the language's model;
mapping it silently would be inventing a value. Reject it.

`undef` and `poison` are rejected: a C definition always has an initializer, so
their appearance means the recipe and the module disagree. An address-valued,
aggregate, or non-constant initializer cannot reach this path anyway — D3's
coarse gate requires a scalar class and an empty storage closure.

### M.5 Access rewrite forms

The recipe's `accesses` entries carry C coordinates, which the Rust stage does
not use. It matches structurally, on uses of the identified static:

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
access that no longer needs it is a lint, not an error, and restructuring blocks
would enlarge the diff for no safety gain.

Anything else naming the static — an address taken into a variable, a cast, a
pointer passed to a function, a `memcpy` — is a rewriter error. D3's recipe
already rejects those shapes, so encountering one means the recipe and the
translated source disagree, which is exactly the condition that must be loud.

### M.6 Marker interaction

1. Read `materialization.marker_inventory`; find the `disposition_atomic` row
   for the key and confirm its embedded strategy matches the manifest
   disposition (`DISPOSITION.md` §5.2).
2. Resolve the row to the translated `static` item — by symbol name normally,
   by the marker when translation renamed it.
3. Rewrite declaration and accesses.
4. Delete the marker call, the generated constructor wrapper that held it, and
   the `pangs_markers.h` include.

A surviving `pangs_*` symbol in the output is a build error by design, and a
manifest `atomic` disposition whose marker is absent from the translated source
is a loud failure — both are existing §5.2 rules, inherited unchanged.

### M.7 Validation and failure

**The primary check is an exhaustive reference inventory**, not a count. An
earlier draft used count-plus-residue and claimed the compiler caught the rest.
It does not. Consider a translated form that takes the address and launders it:

```rust
let p = &g_interrupted as *const _ as *const i32;
let v = ::core::ptr::read_volatile(p);
```

That reference is not one of M.5's forms, so it is not rewritten and the count
is unaffected; the surviving `read_volatile` does not syntactically name the
static, so the residue check misses it; and it **compiles**, because the raw-
pointer cast erases the type distinction that was supposed to be the safety net.
The result is a program that reads the atomic non-atomically — soundness rule 5,
violated silently.

So the rule is closure over references, not detection of known-bad ones:

1. **Inventory.** Enumerate *every* path-expression reference to the static item
   in the translated crate and classify each. After rewriting, the only
   permitted references are receivers of `load`/`store` calls with the frozen
   ordering. Every other reference — `&G`, `addr_of!(G)`, a cast, an argument, a
   mention in another item's initializer, any other method — is a build failure
   naming the site. Unknown classification is failure, never a default-allow.
2. **Macro and `cfg` closure.** A reference the rewriter cannot see is not a
   reference it may ignore. If it operates before macro expansion, any macro
   invocation whose token stream mentions the symbol and which it cannot expand
   is a failure; `cfg`-disabled code mentioning the symbol is likewise a failure,
   since another feature set would compile it. c2rust output is macro-light in
   practice, which makes this cheap, not unnecessary.
3. **Count cross-check.** Rewritten site count equals `recipe.accesses.len()`.
   This is retained because it catches the opposite error from the inventory:
   the inventory catches references the *analysis* did not classify, the count
   catches accesses the *rewriter* did not find.
4. **Type.** The static's type is the mapped atomic type and the item is no
   longer `static mut`.
5. **Marker.** The inventory row is consumed and the symbol is gone.
6. **The compiler, as a backstop for the type-visible subset only.** Anything
   expecting `i32` where `AtomicI32` now sits fails to typecheck. Raw-pointer
   paths defeat it, which is precisely why check 1 is mandatory rather than a
   convenience.

**Demotion, and a gap in the existing contract.** `DISPOSITION.md` §5.3 gives
the demotion channel to the C→C tool, which owns a manifest section. The Rust
stage owns none, so it *cannot* demote — it fails the build. That asymmetry is
correct for v1 and should be stated rather than papered over:

| Stage | Failure | Behavior |
|---|---|---|
| C→C | cannot plant the marker (definition inside an unrewritable macro) | ordinary §5.3 demotion to `unhandled` |
| Rust | unmappable type, untranslatable or out-of-range initializer, unclassifiable reference, unexpandable macro mentioning the symbol, count mismatch, missing marker | **loud build failure** |

The operator's recourse for a Rust-stage failure is the documented one: pin the
global `disposition = "unhandled"` in the override file, which §4.2 always
permits without `accept_risk`, and re-run. Giving the Rust stage its own
demotion channel would mean giving it a manifest section, which reopens
`DISPOSITION.md` §3.3's stage-ownership rule; that is a larger change than this
feature needs, and it is deliberately not proposed here.

### M.8 External linkage is rejected in signal-flag mode

An earlier draft of this section said `AtomicI32` has "the same size and
alignment as `i32`", concluded that an externally linked flag stays
layout-compatible with untranslated C, and left it there. Both halves were
wrong, and the conclusion contradicted this note's own soundness rule 5.

**Layout compatibility is not the question.** If one TU is translated and
another is not, the storage is accessed as a Rust atomic from one side and as a
`volatile sig_atomic_t` — a *non-atomic* access — from the other. Rust's memory
model, inherited from C++20, makes conflicting atomic and non-atomic access to
the same location a data race and therefore undefined behavior
(`std::sync::atomic` module documentation). Identical layout does not rescue
that; it only guarantees the two sides disagree about the same bytes. And for a
signal flag the concurrent case is not a corner: asynchronous access from
outside ordinary control flow is the entire purpose of the object. Soundness
rule 5 already forbids a mixed atomic/volatile representation; the draft failed
to notice the rule applies across a TU boundary just as it does within one.

**The alignment claim was also overstated.** `AtomicI32`'s guarantee is that its
alignment equals its *size*, not that it matches `align_of::<i32>()`. The two
coincide for globals this design admits only because `word_sized_scalar`
requires `align_bits == size_bits` — an accident of the gate, not a general
property. The general claim fails exactly where a cross-TU layout argument would
matter most: on 32-bit x86, `AtomicI64` is 8-byte aligned while `i64` is
4-byte aligned.

**v1 rule.** Signal-flag mode requires **internal linkage**. An external-linkage
global fails with `signal-flag-external-linkage` and its decisive witness. The
gate is `global.meta.linkage`, which the recipe already reads for
`cross_tu.required` (`crates/pangs-clients/src/lib.rs:1276`).

This is deliberately redundant with `access_set_complete`, which already fails
on library-mode name reachability. Neither subsumes the other — an executable
module can define an externally visible global whose accesses are all locally
visible — and for a gate whose failure mode is silent UB, the redundancy is the
point.

**`global.meta.linkage` is not sufficient on its own**, which is why §E's
ordinary-storage predicate carries a separate alias clause. An
`__attribute__((alias))` definition with external linkage re-exports an internal
global under a second name, so the symbol is externally accessible while
`linkage` still reads `internal`. That is the identical hazard — an untranslated
TU accessing the same storage non-atomically — reached without ever touching the
field this rule checks. The alias-exposure inventory (or the module-wide
fallback) in §E is what closes it, and it is listed here as well because a reader
auditing M.8 will look for the completeness of *this* gate.

Lifting the restriction requires a **whole-program certificate**: proof that
every TU accessing the symbol is transformed in one run, so no non-atomic
accessor survives. No such certificate exists, and v1 does not undertake to
reason about a half-translated program. The bore flag is `static`, so the
restriction costs nothing for the motivating case.

## Soundness rules

The implementation must preserve the following invariants:

1. Missing or incomplete typedef/qualifier metadata never proves
   `signal_atomic_type`.
2. A generic volatile access remains a hard atomic-eligibility failure.
3. A signal-context atomic must be target-guaranteed lock-free for exactly the
   operations the recipe emits; a library-based fallback is forbidden in an
   async-signal handler. An unknown target profile is not lock-free.
4. Every access to the global must be enumerated and lowered. An incomplete
   access set fails closed.
5. No mixed atomic/non-atomic or atomic/volatile representation is emitted —
   **including across a translation-unit boundary**. Conflicting atomic and
   non-atomic access to the same storage is undefined behavior under Rust's
   memory model, and identical layout does not make it defined. This is why
   signal-flag mode rejects external linkage (M.8).
6. Width, alignment, and signedness must match the declaration and every
   access.
7. Registry alias recognition is exact and shape checked, and a shape mismatch
   downgrades a registration to unresolved rather than deleting it. Only a
   resolved registration may satisfy a permitting conjunct. "Resolved" is the
   conjunction of **four** conditions — name, declaration, shape, and
   handler-operand completeness — not the first three; an operand whose
   points-to is external, untargeted, or absent is unresolved however well the
   call matched the table, and its non-empty target list is not a precise one.
8. Unknown handler targets or unknown signal-context accesses retain the
   appropriate conservative facts. "Conservative" is direction-dependent: for a
   *restricting* fact it means widening (`signal_context_access` sets every
   global on a `ModuleWide` effect, which is correct); for a *permitting* fact it
   means the opposite — no widened, aliased, or may-set access path may establish
   `resolved_signal_context_access`. A permitting fact computed by the
   restricting fact's query is a soundness hole, not an approximation.
9. The certificate provides scalar atomicity only. It does not certify
   publication of unrelated memory, and it does not model the interleaving
   between the handler and the interrupted code — it certifies that each
   individual access remains indivisible. It is **not** true that this is "the
   whole of what the source program was relying on": the source was also relying
   on `volatile`'s preservation of access count and relative order, which
   `Relaxed` does not provide. Rule 15 is what discharges that.
10. Volatile admission requires proven signal-handler participation, evidenced
    by at least one *resolved* registration. Type evidence alone never admits a
    volatile access, and neither does an unresolved registration.
11. Recognizing a registration alias never relaxes the Ω boundary at that call.
    It adds spawn/signal facts and removes a phase-analysis unresolved-effect
    widening; every points-to, mod/ref, and escape consequence of the external
    call is unchanged.
12. The redefined `word_sized_scalar` never becomes a certificate by itself.
    It is a coarse gate; certification still requires the complete access
    recipe. Source readiness is tracked separately and never feeds back into
    the certification guard (M.0).
13. The C→C stage never removes `volatile` or alters an access. Between the two
    stages the program must remain a correct C program, and a declaration
    stripped of `volatile` before an atomic exists in its place is not one.
14. A signal-flag atomic exists only as a complete certified proof. There is no
    partial, failed, or overridden form: a failed signal-flag proof emits no
    recipe, and no override can supply one.
15. `Relaxed` does not preserve the number or relative order of accesses;
    redundant-load elimination, dead-store elimination, store-to-load
    forwarding, and coalescing are all permitted on `monotonic`. Certification
    therefore requires the F1/F2 flag pattern — one candidate per program, and
    handler-observer confinement for every function that both accesses the flag
    and may run as a handler — under which
    every such transformation is behavior-refining because signal arrival timing
    is unconstrained. Without the pattern, dropping `volatile` is unsound, not
    merely optimistic.
16. The only residual assumption in signal-flag mode is the absence of
    *unbounded* elision: a `monotonic` load or store in a loop is re-executed
    each iteration. It is asserted per profile row by positional codegen
    assertions on both the load and the store side, never by access-count
    equality — count equality would reject a legal RLE and accept a store sunk
    past a loop.
17. Every fact that *permits* something requires a finite, exhibitable positive
    path: an exact global root (`Via::Direct`), reached from a precise target of
    a resolved registration over direct-call edges only. `AffectedGlobals::ModuleWide`, a finite may-set, an aliased or unknown access, an indirect
    call edge, and a target drawn from the address-taken widening each set the
    restrictive fact and none of them sets the permitting one.
18. Every conjunct in an admission predicate must be evaluable from a fact that
    exists, and the note must name it. A clause phrased over a relation the
    pipeline does not compute — "no external-linkage alias targets the global",
    when the alias's target is never resolved — is worse than an absent clause:
    it reads as a guard, is cited as one, and an implementer will most plausibly
    discharge it by evaluating it to `false`. Where the fact does not exist, the
    design must either add it or state the blunter fact that stands in for it.

## Amendments required to other documents

Nothing here touches A′–D′ or any solver semantics; the changes are confined to
PIR lowering, the F-layer fact scans, and the manifest schema. The documents
that record those interfaces must move with the code:

1. **`DISPOSITION.md` §2 (fact table)** — a new
   `resolved_signal_context_access` row (§E), described as a guard conjunct for
   volatile admission and explicitly *not* a replacement for
   `signal_context_access`, whose row is unchanged. The row must state the
   **provenance restriction**, not just the resolvedness one: the two facts are
   computed by different queries, and the new one is established only by a
   certified positive access path. The fact table is where an implementer will
   look, and a row saying "resolved registrations only" would lead directly to
   the filtered-copy defect. §1's guard-shape rule should gain the general
   statement (rule 17): a permitting fact may not be computed by a restricting
   fact's widening query. Also the
   `word_sized_scalar` row's
   description loses "type spelling exists" and gains the statement that detail
   fields survive a false value. Its parenthetical currently reads as a pure
   materializability fact; it becomes a machine-level fact with materializability
   split out.
2. **`DISPOSITION.md` §3 / §3.2** — `schema_version: 5`, per the normative
   §"Schema v5" freeze below: the detail/value coupling invariant is replaced,
   `word_sized_scalar` gains `codes`, and the `atomic_eligibility` certificate
   gains `recipe.volatile_semantics`, the extended `signal_lock_free`, and
   `signal_atomic_type`, and `signal_flag_pattern`. The schema-v4 sentence in §2
   gains a v5 clause, and §3.3's stage-ownership rule gains the exact-version
   requirement.
3. **`DISPOSITION.md` §3.2 / §3.3 (`run.analysis`)** — the analysis-owned run
   header gains `target_profile` (§E), **optional**: absent in a manifest with no
   signal-flag certificate, required in one that has any. It is additive and
   analysis-owned, so it does not disturb stage ownership, but it is load-bearing
   for reproducing a `signal_lock_free` claim and must be listed rather than left
   to the schema. The optionality must be stated where the field is documented,
   or a reader will take a Phase-1 manifest's missing profile for a defect.
4. **`DISPOSITION.md` §7 (soundness matrix)** — the `atomic` row's "no additional
   relational failure for defined source behavior" needs a signal-flag
   qualification, and a stronger one than an earlier draft of this note assumed.
   `Relaxed` does not preserve `volatile`'s access count or relative order; what
   makes the substitution behavior-preserving is the F1/F2 flag pattern plus the
   unconstrained timing of signal arrival (§E, rule 15), and what remains assumed
   is only the absence of unbounded elision (rule 16). Both belong in the matrix
   — the first as a stated precondition of the row, the second as a recorded
   assumption rather than a proof. Add the corresponding dynamic-audit cell
   (Phase 4's SIGINT test) and the per-row codegen assertions.
   **`DESIGN.md` §8** takes the same assumption in its audited soundness
   inventory, phrased as the single residual, not as "volatile is replaced by
   Relaxed."
5. **`DISPOSITION_PLAN.md` §1.5** — the evidenced/certificate encodings that
   D1a's golden test freezes; the scalar failure-diagnostic vocabulary belongs
   there, not only here. `source_materialization`'s code list is unchanged.
6. **`DISPOSITION.md` §5.3 (stage actions)** — the table row for `atomic` is
   correct and unchanged, but the section describes demotion as though every
   materialization failure had a demotion channel. It should state that the
   Rust-side rewriter owns no manifest section, therefore fails loudly rather
   than demoting, and that the `unhandled` pin is the operator's recourse
   (§"Materialization contract" M.7). That is a pre-existing gap this feature
   surfaces, not one it creates.
7. **Audit ledger kinds** — `registry-shape-mismatch` (§D.6) and
   `signal-flag-codegen-assumption` (§E). Both are analysis-sourced, so they
   fall under `DISPOSITION.md` §3.3's rule that dispose regenerates only
   `source: "override"` records and preserves the rest. **No change to
   `schemas/disposition-audit.schema.json` is required**: `kind` is a free
   string and the schema is `additionalProperties: true`, so the structured
   payloads validate as-is. The kinds are documented in `DISPOSITION_PLAN.md`
   §1.4 alongside the deterministic-id rule rather than enumerated in the
   schema. Note what is deliberately *not* a ledger kind: the operand-side
   unresolved reasons (§D.6). They report analysis imprecision on a correctly
   recognized API, not drift between the tool and the program, and a row per
   occurrence would bury the mismatch records.
7c. **`pangs-pir` lowering docs (`LoweringStats`)** — if the inventory option is
   taken, `alias_exposed_globals` is a *fact*, not a metric, and belongs
   documented apart from the `*_counts` maps beside it. The distinction is
   load-bearing: this note's earlier draft treated `tainted_counts` as a guard
   because it sits in the same struct as things that are, and nothing in the
   struct's documentation says otherwise. Add a sentence stating that
   `tainted_counts`, `skipped_counts`, and `modeled_counts` are observability
   counters read by no guard.
7b. **`DISPOSITION.md` §2 / `pangs-api` docs (registry resolution)** — wherever
   `RegistryEntryResolution.unresolved` is described, the four-conjunct
   definition of resolution replaces the three-conjunct one, and the
   `UnresolvedReason` vocabulary is named. This is the amendment most likely to
   be skipped, because the operand conjunct is existing behavior rather than a
   change — which is exactly why the prose does not currently mention it.
8. **`DESIGN_lite.md` §2A** — the registry paragraph describes only the Ω
   external-summary registry. Add one sentence distinguishing the spawn/signal
   disposition registry (name-keyed, conservative-on-false-positive, no Ω
   effect), so a future reader does not infer that adding `__sysv_signal`
   summarizes an external call.
9. **`HOWTO_MEASURE_DISPOSITION_COVERAGE.md` and the `notes/disposition_*`
   baselines** — the `not_word_sized` and would-be-eligibility counters change
   meaning at Phase 1; the re-measurement note must say so rather than
   re-baselining silently.

## Implementation sequence

Phases 1 and 2 are independent of each other; Phase 3 depends on both, because
its admission conjunction (§E) names a fact from each.

That independence constrains where `resolved_signal_context_access` lands, and is
the reason it is worth stating up front. Its **schema and producer both belong to
Phase 1**; Phase 2 changes only its values, by making bore's registration
resolved. Splitting it — schema in Phase 1, producer in Phase 2 — would make
Phase 2 unable to land first, since emitting a changed v5 field requires v5. Each
phase below states which side of that line its work falls on, because the fact is
mentioned in all three and a reader tracking it across them should not have to
infer the split.

### Phase 1: diagnostics and type normalization

- Add a bounded qualified-type walker in `pangs-pir`.
- Preserve typedef chains and qualifiers in PIR/API metadata.
- Split `word_sized_scalar` from source spelling/materialization, keeping the
  alignment condition at equality.
- Record spelling absence as a certificate diagnostic, **not** as a
  `source_materialization` block (M.0); `declaration-source-unmapped` keeps its
  existing meaning and remains the only blocked code.
- Bump `SCHEMA_VERSION` to 5 and land the **complete** §"Schema v5" freeze —
  not only the parts Phase 1 exercises (§1: v5 is defined once). Concretely:
  `word_sized_scalar.codes`; `resolved_signal_context_access`; the signal-flag
  payload definitions in `schemas/disposition-manifest.schema.json`; the full
  presence *and* value coupling validator, threaded with `schema_version` and
  `run.analysis.target_profile`; the exact-version requirement for stages that
  preserve earlier sections; and the regenerated goldens.

  Threading `run.analysis.target_profile` through the validator in Phase 1 does
  **not** mean Phase 1 emits one. The field is optional and absent until Phase 3;
  every validator clause naming it is reachable only from a signal-flag
  certificate, which Phase 1 never produces (§4). A Phase-1 manifest carrying no
  `target_profile` is valid v5, and a signal-flag certificate carrying no
  `target_profile` is invalid — which is the check being landed early.
- Land the **producer** for `resolved_signal_context_access` here too, not only
  its schema: the certified-positive-path query of §E, "Provenance". It walks
  `access_sites_for_global` back over direct-call edges to the precise targets of
  resolved registrations and records the path as the witness. It is **not** a
  filtered copy of `registry_access_facts` — that version would inherit
  `AffectedGlobals::ModuleWide` and mark every global in the module positively
  signal-accessed, which is the defect §E's "Provenance" subsection exists to
  prevent. A code comment at the query should say so, because the filtered-copy
  version is the obvious implementation and looks right. The fact is computed for
  real from Phase 1 onward and is simply `false` for the bore flag until Phase 2
  recognizes `__sysv_signal`. The fact-provenance tests land with it.

  The alternative — schema in Phase 1, producer in Phase 2, with a hardcoded
  `false` in between — was rejected for two reasons. A dormant constant occupying
  a required field is indistinguishable in a golden from a computed one, so the
  Phase-2 diff could not be attributed; and it would make Phase 2 depend on Phase
  1, contradicting their stated independence, because emitting a changed v5 field
  requires v5. With the producer here, Phase 2 changes a *value* and nothing else,
  which either order accommodates.
- The signal-flag rules ship **dormant**: nothing emits `volatile_semantics`
  until Phase 3, so the clauses guarded by it are unreachable rather than
  vacuously true. A test asserts exactly that — the coupling validator is live,
  every Phase-1 manifest passes it, and a hand-written fixture carrying
  `volatile_semantics` with no `run.analysis.target_profile` is **rejected**,
  which is what proves the clauses are live rather than skipped.
  Note the precise scope of "dormant": it covers the signal-flag *certificate
  payload and its coupling*, not `resolved_signal_context_access`, which is live
  and computed from this phase on.
- Emit granular scalar failure diagnostics and retain partial evidence.

This phase should make the manifest accurately say that `g_interrupted` is an
aligned signed 32-bit scalar while still rejecting its volatile access recipe.
Note that at this point the `atomic` slot is `failed` with `recipe: null`, so a
user cannot reach `atomic` by overriding either — `DISPOSITION.md` §4.2's
`no-recipe` rejection applies and is not waivable by `accept_risk`. That is the
correct behavior and is worth an explicit test.

### Phase 2: registry correctness

- Validate first with `--registry-config` on the bore module: no code change,
  observable fact delta.
- Then add `__sysv_signal` to the built-in table.
- Land `RegistryShape` (§D.2) and the three-valued resolution (§D.5) as a
  separately reviewable step, with shapes for `signal`, `sigaction`, and
  `__sysv_signal`; regress the corpus, where the worst case is now a downgrade
  to unresolved rather than a lost fact.
- Replace `RegistryEntryResolution.unresolved: bool` with
  `unresolved_reasons: BTreeSet<UnresolvedReason>` and a derived `unresolved()`
  method (§D.2). Populate the operand reasons from the conditions
  `resolve_registry_entries` already computes
  (`crates/pangs-api/src/lib.rs:4302-4313`) — this is a refactor of an existing
  behavior into a nameable form, not a new check, and the corpus resolution
  results must be **identical** before and after it, which is the test that it
  was a pure refactor.
- Add the `registry-shape-mismatch` audit record and `--strict-registry`, scoped
  to `ShapeMismatch` only.
- Confirm the handler target resolves to `sigint_handler_xjtr_0`, and that
  `bore_search_cleanup`'s restore call carries exactly `OperandExternal` — the
  motivating example exercises both outcomes in one module.
- Confirm `g_interrupted` becomes signal-context-accessed, and that
  `resolved_signal_context_access` **flips false → true** for it. No schema, no
  `Facts` field, and no new query lands here: all three are Phase 1's. Phase 2's
  entire contribution to this fact is that recognizing `__sysv_signal` makes the
  registration resolved, which supplies the certified positive path the Phase-1
  query was already looking for. It is the resolved bit that Phase 3 reads, so
  Phase 2 is not complete until the flip is observed.
- Confirm mutex is rejected by `signal-context-access`, independently of its
  existing reentrancy result.
- Record the corpus disposition distribution before and after: recognizing the
  registration also removes a phase-analysis unresolved effect, which can move
  unrelated globals into `once-lock`.

This phase repairs facts required by the eventual atomic proof and must land
before the special volatile admission.

### Phase 3: narrow signal-flag atomic recipe

- Add `lock_free_load_store_widths` from the arch-keyed profile (one row:
  `x86_64`), and **populate** `run.analysis.target_profile` — the optional field
  and its validator clauses landed in Phase 1 (§4); this phase is the first to
  emit a value. Switch **only** the signal gate
  (`crates/pangs-clients/src/lib.rs:1113,1217`) onto it.
  `supported_atomic_widths` and its derivation are untouched.

  This is the same schema-versus-producer split as
  `resolved_signal_context_access`, resolved the other way, and deliberately: the
  fact's producer went to Phase 1 because Phase 2 must be able to land first,
  while the profile's producer belongs here because nothing before Phase 3 can
  emit a manifest that needs one. In both cases the *contract* is Phase 1's.
- Land the codegen regression *before* the profile row it justifies: a row is
  admissible only if the regression covers it (§E).
- Emit the `signal-flag-codegen-assumption` ledger records from the checked-in
  evidence table, and add the Rust-stage toolchain-envelope check.
- Add `section: Option<String>` and `thread_local: bool` to `pangs_pir::Global`
  (both `#[serde(default)]`) and surface them through the API, so the
  ordinary-storage predicate is checkable at all.
- Decide the alias clause on measured coverage, first thing in the phase: count
  corpus modules whose `lowering.tainted_counts` has an `alias_`-prefixed key. If
  that is near zero, ship the module-wide fallback (no PIR change). Otherwise
  land `LoweringStats::alias_exposed_globals` and the reordering of
  `collect_alias_map` so the aliasee is resolved before the interposability
  check (§E). Either way the clause must be backed by a fact that exists —
  the one thing the earlier draft's target-specific predicate was not.
- Add `signal_atomic_type` certification, including typedef provenance.
- Add the F1/F2 pattern checks and emit `signal_flag_pattern`. F1 is a count over
  the candidate set and so must run *after* all per-global evaluation, as a
  whole-program pass. F2 groups the recipe's access list by enclosing function to
  get `A`, intersects it with the registry target set including §D.5's widening
  to get `A ∩ H`, and queries each survivor's static-storage access set. Both are
  admission conjuncts, not diagnostics — a failure yields `recipe: null` like
  every other signal-flag failure.
- Thread it into atomic access recipe construction, gated on the full §E
  conjunction — including `resolved_signal_context_access`, **not**
  `signal_context_access`. The two are one word apart and the wrong one is the
  permissive one (§E, "Provenance"); an earlier draft of this bullet named it.
- Admit only direct whole-object volatile loads/stores, on internal-linkage
  globals only (M.8).
- Emit the explicit `certified-signal-flag` recipe mode with its operation set.
  **No schema or validator change belongs in this phase** — both landed in
  Phase 1. If Phase 3 finds it needs one, that is a defect in this freeze and
  must be fixed here before Phase 1 ships, not by amending a released v5.
- Record the no-elision assumption in the audited soundness inventory per §E's
  audit contract, with the run-scoped and per-global records.

### Phase 4: end-to-end materialization

Per the §"Materialization contract" split — C→C plants the marker and changes
nothing else; the Rust stage retypes and rewrites.

- C→C: confirm `atomic` globals reach the definition-site marker path with the
  declaration and every access byte-identical to the input.
- Rust: type mapping (M.3), initializer translation (M.4), the access forms in
  M.5, marker consumption and deletion (M.6).
- Land M.7's **exhaustive reference inventory** — the load-bearing check, and the
  one piece of Phase 4 that is not mechanical. Enumerate every path-expression
  reference to the static in the translated crate, classify each, and permit only
  receivers of `load`/`store` with the frozen ordering; unknown classification is
  failure, never default-allow. Include the macro and `cfg` closure: an
  unexpandable macro whose tokens mention the symbol, and a `cfg`-disabled
  reference, are both failures.

  An earlier version of this bullet read "the M.7 checks — count, residue,
  marker," which is the superseded formulation M.7 *opens by rejecting*: residue
  scanning is gone, and count is a cross-check that catches the opposite error.
  The distinction is not editorial. A count-and-residue implementation passes the
  laundered-pointer case (`&G as *const _ as *const i32`, then `read_volatile`),
  compiles, and silently reads the atomic non-atomically — soundness rule 5
  violated with every check green. An implementer working from a checklist rather
  than from M.7 would build exactly that.
- Land the remaining M.7 checks as what they are: **count** as a cross-check
  (inventory catches what the *analysis* failed to classify, count catches what
  the *rewriter* failed to find), **type**, **marker consumption**, and the
  compiler as a backstop for the type-visible subset only.
- Land the loud-failure behavior with the `unhandled` override as the documented
  recourse — the Rust stage owns no manifest section and therefore cannot demote
  (M.7's table).
- Compile and run signal-interruption tests under the transformed program.
- Add dynamic confirmation that SIGINT changes the flag and terminates the
  search path without locks or allocation in the handler, which is also the
  test that exercises the no-elision assumption in §E.

## Tests and acceptance criteria

### PIR and metadata tests

- Lower `static volatile sig_atomic_t flag;` from real LLVM bitcode.
- Assert the typedef chain includes `sig_atomic_t`.
- Assert `volatile`, integer class, signedness, width, and alignment survive.
- Cover nested `const volatile` qualifiers and multiple typedef layers.
- `display_name` is `typedef_chain[0]`: `sig_atomic_t` for the direct
  declaration, `my_flag_t` under `typedef sig_atomic_t my_flag_t;`, and
  `__sig_atomic_t` only when the source names it directly.
- With no typedef at all, `display_name` is the terminal type's name (`int`);
  with an anonymous enum it is absent.
- Under `typedef sig_atomic_t my_flag_t;` the certificate's `typedef` is
  `sig_atomic_t` while `display_name` is `my_flag_t` — the two names are
  asserted separately so a regression cannot collapse them.
- Verify malformed and over-depth metadata fail without certification.

### Scalar-fact tests

- An aligned supported integer with missing spelling is a semantic word-sized
  scalar, and — given a source-mapped declaration and a clean access recipe —
  certifies `atomic` with `source_materialization: source-mapped`, carrying only
  a `type_evidence` diagnostic. Spelling absence blocks nothing.
- A certified global whose declaration has no file/line is certified with
  `source_materialization: blocked`, and the cascade still chooses `atomic`
  (M.0). A test asserts the cascade does not consult materialization status.
- Unsupported width, unknown class, and unknown signedness receive distinct
  diagnostic codes.
- Alignment codes are distinguished: `align < size` gives `under-aligned`,
  `align > size` (e.g. `__attribute__((aligned(64))) int`) gives `over-aligned`,
  and absent alignment gives `unknown-alignment`. No case emits a code implying
  the wrong direction.
- Partial evidence remains visible when the boolean is false, and `codes` is
  non-empty exactly then.

### Schema tests

- A v4 document validates under v4 rules, including the detail prohibition; the
  same document with detail added at `value: false` is rejected as v4 and
  accepted as v5.
- A v5 document with `value: false` and no `codes` is rejected.
- A v5 document is refused by a v4 reader through the existing version gate.
- A stage that preserves earlier sections refuses a document whose
  `schema_version` differs from its own, rather than re-emitting it under the
  input's version.
- The §4 presence coupling is rejected in all three broken directions:
  `volatile_semantics` without `signal_atomic_type`; `signal_atomic_type`
  without the mode; and the mode with `signal_lock_free.required: false`.
- Each §4 **value** coupling clause is rejected independently, one test per
  clause — a payload that is well-formed except for a single wrong value:
  `signal_atomic_type.width` ≠ declaration width; `align` ≠ width;
  `signal_lock_free.width` ≠ declaration width, or null; a width absent from
  `run.analysis.target_profile.lock_free_load_store_widths`;
  `target_guaranteed: false`; `source: "none"`; `typedef` not in
  `typedef_chain`; `typedef` not in `RECOGNIZED_SIGNAL_TYPEDEFS`;
  `volatile: false`; `scalar_class` ≠ `"integer"`; `linkage: "external"`;
  `ordering` ≠ `"relaxed"`; `resolved_signal_context_access: false`; and each of
  `signal_flag_pattern`'s booleans `false`.
  Presence coupling alone passes every one of these, which is the point.
  The provenance-agreement clause is covered with the other profile tests under
  §"Codegen and audit-envelope tests", since its counter-fixture needs a
  configured profile row rather than a hand-built certificate — but it is a §4
  clause and this list is not complete without the pointer.
- **`run.analysis.target_profile` conditionality**, three cases: a v5 manifest
  with no signal-flag certificate and no profile is **valid** (the Phase-1
  shape); the same manifest with a signal-flag certificate and no profile is
  **rejected**; with both, the width clauses apply. The first two together are
  what let Phase 1 land the validator before Phase 3 emits a profile, so they
  are asserted as a pair rather than separately.
- **The v4 → v5 fact delta is two-part**, asserted directly because several
  drafts of this note described it as one: a v4 document round-trips through a
  v5 reader with `resolved_signal_context_access` defaulted to
  `{ value: false }` and no parse error, and a v5 document omitting the field
  reads as `false` rather than failing — fail-closed, since the fact permits.
  A golden assertion pins that every emitted v5 manifest *does* carry it, which
  is where "required at v5" actually binds.
- The dormant-contract test: a Phase-1 manifest with no signal-flag payload
  anywhere satisfies the full coupling validator vacuously, and the validator is
  demonstrably live (a hand-built bad payload in the same test run is rejected).
- Golden classification (§7): a fixture corpus containing one global of each
  class A–E regenerates with exactly the permitted changes, and the two named
  defect signals are asserted to fail — a class-B global perturbed by one field,
  and a class-E global whose prior failure code was `unsupported-atomic-width`
  rather than a missing spelling.
- Aggregate consistency: `not_word_sized` decreases by exactly |D| + |E|, and
  `measurement_report` is byte-identical when |E| = 0.
- A **failed** slot carrying `recipe.volatile_semantics` is rejected by the
  fourth clause — the case that motivated making signal-flag recipes
  certified-only.
- A signal-flag global that fails any check has `recipe: null` and a
  `diagnostics.signal_flag.status: "recipe-withheld"` record.
- An `atomic` pin on that slot is rejected `no-recipe` **with**
  `accept_risk = true`, not merely without it.
- An ordinary (non-signal-flag) atomic, mutex, or once-lock slot is unaffected:
  the general accepted-risk path still works, proving the rule is scoped.
- `signal_atomic_type` and `signal_lock_free` never appear in a failed slot's
  `recipe`.
- Re-emission is byte-identical: `codes`, `operations`, and `typedef_chain`
  ordering is stable across runs.

### Registry tests

- `signal`, shape-correct `__sysv_signal`, and `sigaction` identify their
  handlers.
- A same-name external declaration with a wrong shape resolves to an
  **unresolved registration**, not to "no registration": `signal_context_access`
  is still set, `phase_stationarity` keeps its unknown effect, and a
  `registry-shape-mismatch` record is emitted.
- An unresolved registration sets `signal_context_access` but leaves
  `resolved_signal_context_access` false, so a `volatile sig_atomic_t` behind it
  stays rejected.

**Unresolved-reason tests.** The reasons are independent predicates, so each
needs its own fixture and the combination needs one too.

- A shape-checked `signal(2, handler)` whose handler operand's points-to reaches
  an external boundary carries `OperandExternal`, is **unresolved despite a
  non-empty `targets` list**, and widens. This is the case an earlier draft's
  three-conjunct table would have called resolved, and it is asserted directly
  because the resolution *looks* precise: it names real functions.
- The same fixture's flag is not admitted, and F2's `H` includes the
  address-taken widening rather than only the named targets — the two
  consequences §D.5 lists, asserted rather than argued.
- An operand with no targeted points-to carries `OperandUntargeted` with an empty
  `targets` list; a call with no argument at the entry index carries
  `OperandAbsent`. With shape checking live, the second is also a shape mismatch,
  and the resolution carries **both** reasons — the set, not a winner.
- A mismatched shape whose operand is also external carries `ShapeMismatch` and
  `OperandExternal`; exactly one `registry-shape-mismatch` ledger record is
  emitted, and no record is emitted for the operand reason.
- `--strict-registry` fails on `ShapeMismatch` and does **not** fail on a
  resolution whose only reasons are operand-side. Bore is the regression fixture:
  its restore call carries `OperandExternal` on every run, and `--strict-registry`
  must still exit zero.
- `unresolved()` is true iff `unresolved_reasons` is non-empty, checked over the
  whole corpus, so no consumer can observe a resolution that claims precision
  while carrying a reason.
- A global reached by both a resolved and an unresolved registration has both
  facts true and **is admitted** — the existential predicate, asserted directly
  because it is the case the single boolean could not express.
- `resolved_signal_context_access` witnesses the lowest-callsite-id resolved
  registration together with its shortest certified path, stably across runs and
  independent of how many unresolved ones exist.
- An unresolved registration widens to precise targets ∪ internal address-taken
  functions; a function that is neither address-taken nor a precise target is
  not made signal-context-accessed.
- A *defined internal* function named `signal` is not a registration at all
  (`external_only`), and emits no mismatch record — the silent-precondition
  rule, asserted directly because an earlier draft contradicted it.
- An internal wrapper named `signal` that forwards to libc `signal` still yields
  a registration, recognized at the inner external call.
- Arguments with `ValueKind::Unknown` never cause a mismatch (polarity rule);
  a proven `NonPointer` in the handler position does.
- A discarded result (`signal(2, h);` with no result node) does not fail the
  return's **value-kind** constraint — and a `sigaction` entry is still separated
  from `signal` by arity on exactly that call, confirming arity carries the
  discrimination.
- The return's **ABI** constraint still fires on that same discarded-result call:
  a spec declaring `ret: "void"` against an observed `AbiClass::Integer` is a
  `ShapeMismatch`. This is the pair of tests that pins the §D.2 split — the same
  callsite passes one half and fails the other, which no single "best-effort
  return" rule could express.
- Arity, `vararg`, and `cc` are checked from `Callsite.sig` and reject on every
  call regardless of result or argument node availability; a fixture whose
  argument nodes are all `ValueKind::Unknown` still fails on a wrong arity.
- Registry-entry config validation rejects an entry whose `entry` index is out
  of range or whose `ParamShape` at that index is not `PointerLike`, at load
  time, naming the entry.
- A user config entry replacing a built-in name inherits the built-in shape; a
  user entry for a new name with no shape is unchecked and records an audit
  note.
- Handler global accesses set `signal_context_access`.
- An unresolved handler widens conservatively.
- `--strict-registry` turns a built-in-name mismatch into a non-zero exit.

**Fact-provenance tests.** These are the sharpest tests in the note, because the
failure they guard against is silent and total — a permitting fact true for every
global in a module.

- **The `ModuleWide` case.** A handler containing one unanalyzable pointer store
  (so its transitive summary is `AffectedGlobals::ModuleWide`) plus a
  `Via::Direct` store to the flag: every global in the module gets
  `signal_context_access: true`, and **exactly one** — the flag — gets
  `resolved_signal_context_access: true`. An unrelated `volatile sig_atomic_t` in
  the same module is *not* admitted. Asserted as a count, not per-global, so the
  test fails loudly if the query is ever reimplemented as a filtered copy of
  `registry_access_facts`.
- The same fixture with a **fully resolved** registration still yields exactly
  one positive global, pinning that `ModuleWide` is orthogonal to `unresolved`
  and that restricting the fact to resolved registrations does not by itself
  close the hole.
- A handler whose only access to the flag is through a pointer with a finite
  two-element candidate set gets `signal_context_access: true` and
  `resolved_signal_context_access: false` — a may-set is not positive proof.
  The flag is consequently not admitted, and it also fails
  `address-access-not-lowerable` in the recipe, so the two rejections agree.
- A path `handler → helper → flag` over `CallDirect` edges is accepted, and the
  witness records `path: [handler, helper]`. The same shape with an indirect call
  at the middle edge is rejected even when the call graph resolves it to exactly
  one callee.
- A handler reached **only** through §D.5's address-taken widening (no precise
  target) sets `signal_context_access` and not the permitting fact.
- Witness determinism: a flag reachable by two direct-call paths of different
  lengths records the shorter; two of equal length record the callee-order-first,
  and the manifest is byte-identical across runs.
- `resolved_signal_context_access.value == true ⇒ signal_context_access.value ==
  true` holds on every corpus module, checked as an invariant rather than a
  fixture — the implication is cheap and catches a divergence between the two
  queries immediately.

### Atomic-recipe tests

- Direct volatile loads/stores of certified `sig_atomic_t` succeed.
- An ordinary `volatile int` continues to fail with `volatile-access`.
- A `volatile sig_atomic_t` **never accessed in signal context** continues to
  fail with `volatile-access` — the §E conjunction, not the type fact alone,
  is what admits the access.
- A `volatile _Atomic`-qualified or `const volatile` chain fails.
- A repo-local `typedef int sig_atomic_t;` used as a signal flag fails with
  `signal-typedef-shadowed`; the same declaration with the typedef in a system
  header succeeds; an unrecorded typedef file succeeds (polarity rule).
- A `__thread volatile sig_atomic_t` flag fails — the case that would otherwise
  merge per-thread copies into one static.
- A flag with an explicit `section` attribute fails.
- An internal global re-exported by an external-linkage alias fails, closing the
  M.8 back door. The fixture must be an actual `@pub_alias = alias i32, ptr
  @g_flag` with external linkage, not a hand-written PIR fixture asserting the
  fact directly: the whole defect was that `collect_alias_map` never resolves
  such an alias's target (`crates/pangs-pir/src/llvm_sys.rs:3573`), so a fixture
  that starts from the fact would pass against the broken lowering.
- Under the module-wide fallback, the same fixture rejects **every** global in
  the module, and a module with an unrelated external alias to a *function*
  also rejects — asserted so the fallback's cost is visible in CI rather than
  discovered on the corpus.
- Under the inventory, an external alias to an unrelated function does **not**
  reject, and `alias_exposed_globals` names the flag only in the aliased case.
  Whichever option Phase 3 selects, the other option's tests are `#[ignore]`d
  rather than deleted, since the coverage measurement can be revisited.
- An alias whose aliasee is not a resolvable constant symbol
  (`constant_symbol_name` returns `None`) is covered by the fallback and not by
  the inventory — asserted as a known inventory gap, so that selecting the
  inventory does not silently drop it.
- A `volatile sig_atomic_t` on a target without guaranteed lock-free load/store
  fails with `signal-atomic-not-lock-free`; an unknown target triple fails the
  same way rather than inheriting a default width list. Both need a synthetic
  fixture with an unlisted triple — the corpus is entirely `x86_64` and cannot
  exercise the fail-closed path.
- A non-signal global's atomic eligibility is **unchanged** by the profile: a
  fixture on an unlisted triple still certifies `atomic` through
  `supported_atomic_widths`, proving the two lists are not coupled.
- Address escape, indirect access, partial-width access, bulk memory access,
  and volatile RMW all fail.
- An **external-linkage** `volatile sig_atomic_t` that satisfies every other
  conjunct fails with `signal-flag-external-linkage`, in both executable and
  library mode — including when `access_set_complete` is true, which is the case
  the redundancy exists for.
- An ordinary (non-signal-flag) external-linkage atomic is unaffected: the
  restriction is scoped to signal-flag mode.
- A signal flag used as a payload-publication protocol does not gain an
  acquire/release claim from this certificate.
- **F1**: a fixture with two otherwise-certifiable `volatile sig_atomic_t` flags
  fails `signal-flag-not-sole` on **both** — neither is picked as the winner —
  and no `signal_flag_pattern` appears in the manifest. A manifest hand-edited to
  carry two `signal_flag_pattern` objects is rejected by the validator's
  whole-program check, which the per-global coupling cannot catch.
- **F2**: a handler that assigns the flag *and* reads or writes any other
  static-storage object fails `signal-handler-access-not-confined`, witnessed by
  the function and the offending object. A handler touching only the flag plus
  its own locals and parameters passes. This case is already undefined behavior
  in C, so the test doubles as a diagnostic for a pre-existing source bug.
- **F2's two sets widen in opposite directions.** A fixture whose handler has a
  `ModuleWide` transitive summary must **not** thereby put every global into `A`:
  `A` comes from `access_sites_for_global`, so it stays exact. The same fixture's
  F2 second half (does the observer touch another static?) *does* read the
  widened summary and correctly fails, since "may touch everything" is a
  restrictive answer. Both halves asserted on one fixture, because getting the
  directions backwards is the plausible implementation error.
- **F2 is scoped to `A ∩ H`, not to either set alone.** Three fixtures pin the
  intersection: (a) an internal address-taken function that touches many statics
  but never the flag — in `H`, not in `A` — **passes**, since it cannot correlate
  the flag's order with anything; (b) an ordinary caller that polls the flag and
  also writes other statics but is never address-taken — in `A`, not in `H` —
  **passes**, which is the common case and would reject nearly every real program
  if the scoping were wrong; (c) an internal address-taken function that both
  polls the flag and touches another static — in both — **fails**.
- **An unresolved registration does not block certification.** A fixture
  mirroring the bore module — one resolved `signal(2, handler)` plus a restore
  call `signal(2, saved_handler_global)` whose operand comes from an external
  return — still certifies. This is the case an earlier draft of §E would have
  rejected via a handler-set-closure condition; the test exists so no future
  change reintroduces it. The unresolved registration must still widen `H`,
  asserted by the companion fixture where the widening pulls in an
  address-taken flag-poller and F2 then fails.
- An `atomic` override on a Phase-1-state global (failed slot, `recipe: null`)
  is rejected `no-recipe` even with `accept_risk = true`.

### Codegen and audit-envelope tests

- For every declared profile row × width × opt level `{0,1,2,3}`: no
  `__atomic_*` reference; a `load atomic monotonic` of the flag remains in the
  polling loop body and the loop's exit condition depends on it; a
  `store atomic monotonic` remains in the storing loop's body with none migrated
  to the exit block; and both stores of `flag = 1; work(); flag = 0;` survive.
- The assertions are positional, not count-based. A negative test proves it: a
  fixture with two adjacent loads and nothing between them, where the optimizer
  legally collapses them to one, **passes** — the earlier count-equality
  formulation would have failed it, and the property under audit is unbounded
  elision, not access count.
- A row whose codegen regression is absent or failing is rejected by the profile
  table's own test — evidence and row are landed together.
- `--target-profile` narrowing a built-in row is accepted, emits
  `target-profile-narrowed`, and records `narrowed_from`.
- `--target-profile` asserting a width or arch row the built-in table lacks,
  with no evidence bundle, is **rejected** — including with any accepted-risk
  spelling, since none applies here.
- An evidence bundle is accepted only when its fixture hash matches the in-tree
  fixture, its toolchain is inside the envelope, and every claimed
  `(width, operation)` passed; a stale fixture hash, an out-of-envelope
  toolchain, and a missing assertion each reject it.
- A narrowed row's certificates report `source: "builtin"`; an evidence-bundle
  row's report `source: "evidence-bundle"` and the run header names the bundle.
- **Provenance disagreement is rejected by the validator**, in both directions
  and independently of emission: a hand-edited manifest whose
  `signal_lock_free.source` is `"builtin"` under an `evidence-bundle` profile row
  is invalid, and so is `"evidence-bundle"` under a `builtin` row. The first is
  the one that matters — it is provenance laundering, and it passes every other
  clause in §4 — so it is asserted with the certificate otherwise fully
  well-formed.
- `builtin+narrowed` without `narrowed_from`, and `evidence-bundle` without
  `evidence_bundle`, are each rejected; a `builtin+narrowed` row's certificate
  reporting `"builtin"` is **accepted**, pinning that narrowing does not change
  the provenance of the widths that remain.
- The ledger records are deterministic: two runs on the same input produce
  byte-identical `ar-` ids.
- Records appear only when a global certifies in signal-flag mode, and one
  `scope: global` row exists per such global.
- The Rust stage refuses a toolchain outside the recorded envelope (below the
  rustc floor, unlisted LLVM major, or a triple with no row) and fails loudly
  rather than proceeding.
- The host SIGINT test runs under a timeout, so a hoisted load fails as a hang
  rather than hanging CI indefinitely.

### Materialization tests

These extend `DISPOSITION.md` §9's round-trip marker harness, which already
validates the repository boundary with a fixture translator.

- The M.2 before/after program is a golden fixture: C source → C→C output →
  fixture-translated Rust → rewritten Rust, diffed at each step.
- The C→C output's declaration and access lines are byte-identical to the input;
  only the include and the marker constructor are added.
- Both `&raw` and `as *const`/`as *mut` spellings of the volatile accesses
  rewrite identically.
- Signed and unsigned widths map per M.3; a `pointer` class is rejected.
- Initializer bit-vector semantics: `i8 -1` emits `AtomicU8::new(255)` at
  `signed: false` and `AtomicI8::new(-1)` at `signed: true`; `i32 -2147483648`
  emits both signed and unsigned forms correctly; an `iN` whose width differs
  from `size_bits` fails; a non-constant initializer, `undef`, and `poison` fail.
- Boolean initialization: `i8 0`/`i1 false`/`zeroinitializer` give
  `AtomicBool::new(false)`, `i8 1`/`i1 true` give `true`, and `i8 2` at boolean
  class **fails** rather than being coerced.
- The laundered-pointer case is rejected:
  `&G as *const _ as *const i32` followed by `read_volatile(p)` fails the
  reference inventory, even though it passes the count check, passes a
  residue scan for `read_volatile(&G)`, and compiles.
- Every non-`load`/`store` reference to the static fails the inventory: `&G`,
  `addr_of!(G)`, passing `G` as an argument, and mentioning `G` in another
  item's initializer.
- **The inventory is asserted to be the gate, not a redundant one.** A fixture is
  constructed to pass count, type, marker, and `rustc` while failing only the
  inventory; the build must fail. Without this test an implementation that
  quietly skipped step 1 would show a fully green suite, which is precisely how
  the Phase-4 checklist's "count, residue, marker" phrasing would have been
  built and shipped.
- A macro invocation mentioning the symbol that the rewriter cannot expand
  fails; so does a `cfg`-disabled reference.
- Count mismatch and missing marker each fail the build rather than demoting.
- The rewritten output contains no `pangs_*` symbol.
- A deliberately un-rewritten access fails to compile, confirming the
  `static mut` → `static` safety net.

### APG bore regression

For `exe-apg_bore-O0.bc` in executable/application mode, with Andersen and no
overrides:

- `g_interrupted_xjtr_0` has `signal_context_access: true` and
  `resolved_signal_context_access: true`, the latter witnessed by the
  zero-length path `["sigint_handler_xjtr_0"]` with `via: "direct"` — the
  handler's own `g_interrupted_xjtr_0 = 1`;
- **no other global in the module** has `resolved_signal_context_access: true`,
  asserted as a count. The module has a second registration
  (`bore_search_cleanup`'s `signal(2, g_prev_sigint_handler_xjtr_0)`, unresolvable
  because its operand holds an external return), so this is a live check that the
  widening does not leak into the permitting fact rather than a vacuous one;
- its type evidence names `sig_atomic_t` and records `volatile`;
- its atomic certificate is certified in signal-flag mode;
- its chosen disposition is `atomic`;
- `unhandled` decreases from 1 to 0;
- `atomic` increases from 1 to 2; and
- overall disposition coverage increases from 25/26 to 26/26.

The expected distribution change should be treated as a regression assertion
only after the detailed access recipe and materializer both pass; it must not
be obtained by overriding the failed guards.

### Corpus-level acceptance

The bore assertions above are necessary, not sufficient. Two of the three parts
change facts for every module, so acceptance is on the corpus distribution:

- After Phase 1, the distribution **may legitimately move**, in exactly one
  direction and for exactly one reason: a global whose sole atomic failure was
  `word-sized-scalar` caused by a missing spelling, and which passes every
  remaining gate including the access recipe, now certifies and chooses
  `atomic`. That is the coverage this part exists to recover.

  The earlier phrasing of this criterion ("distribution unchanged everywhere")
  was wrong and would have been read as requiring blocked or spelling-free
  materialization to fail D3 certification — contradicting the separation M.0
  restates. The correct predicate is on *cause*, not on the count:

  ```text
  permitted:  atomic_eligibility Failed[word-sized-scalar] → Certified,
              with no other fact or code changing
  defect:     any global moving OUT of a strategy
  defect:     any global moving IN for any other reason
  defect:     any change to a global whose word_sized_scalar was already true
  ```

  A certified global whose `source_materialization` is `blocked` still counts
  as `atomic` here; per M.0 that is the established meaning, and its execution
  is the materializer's problem, corrected by demotion if it arises. The bore
  flag does not move at Phase 1 — it reaches the detailed recipe and fails on
  `volatile-access`, which is what Phase 1's description already predicts.
- After Phase 2, any global that moves is either newly `signal_context_access`
  (expected: loses `mutex`, tightens `atomic`) or newly `once-lock` from the
  removed unresolved effect (expected: strictly more precise). Any *other*
  movement is a defect to explain before Phase 3 lands.

  Phase 2 also changes `resolved_signal_context_access` values, which is a
  manifest diff without a disposition diff: the fact's only consumer is still
  dormant. Every flip must be `false → true` and attributable to a registration
  that became resolved. A flip in the other direction means the registry change
  *lost* a resolution, which the three-valued outcome (§D.5) exists to prevent
  and which no other assertion here would catch — the disposition distribution
  would be unchanged, because nothing reads the fact yet.
- After Phase 3, the only globals that may move are those with
  `signal_context_access: true`. Two directions are permitted and must be
  distinguished: *into* `atomic`, for a certified signal flag; and *out of*
  `atomic`, for a signal-context global that certified under the old
  pointer-width heuristic on an arch the profile does not list. The second is a
  deliberate coverage loss correcting an unbacked claim, and on the current
  corpus it is empty — every module is `x86_64`. Any movement by a global
  without `signal_context_access` is a defect: the coarse gate's
  `supported_atomic_widths` did not change.
- Phase 3 must also report the **alias-exposure census** described in §E — the
  number of corpus modules carrying an `alias_`-prefixed lowering taint — because
  it is the input that decides between the module-wide fallback and the PIR
  inventory. Reporting it after the choice is made is worthless; it gates the
  choice.
- Phase 3 additionally requires a **pattern-condition census** across the corpus,
  because F1 and F2 are the conjuncts most likely to make the whole feature
  inert without anyone noticing. Report, per module: the number of signal-flag
  candidates (F1 admits only modules with exactly one), and for each candidate
  the size of `A ∩ H` and whether every member is confined. A module rejected by
  F1 is expected and fine; a corpus in which *most* candidates are rejected by F2
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
- Admitting `_Atomic` globals, which are a different lowering with a different
  recipe.
- Signal flags with external linkage, absent a whole-program certificate that
  every accessing TU is transformed (M.8).

## Decisions

No design question in this note is open. Each decision below is normative and
carries its **falsifier** — the specific evidence that would reopen it. A
falsifier is not a caveat; it is the observation that must be made before the
decision may be changed, which is what a "working answer" was failing to state.

**D1. Typedef and qualifier evidence lives inside the `atomic_eligibility`
certificate**, at the path frozen in §"Schema v5" §4 — not as a first-class
`source_type` fact. This holds the v5 fact-layer surface to the
`word_sized_scalar` change alone.
*Falsifier:* a second consumer of the evidence. Promotion to a fact slot is then
schema v6, additive, and forced by nothing else.

**D2. `supported_atomic_widths` is unchanged; the signal gate moves to a
profile-backed `lock_free_load_store_widths`.** The general list's failure mode
is a Rust compile error; the signal gate's is a silent handler deadlock. Only
the second warrants an authoritative profile, and replacing both would zero the
coarse atomic gate on any unlisted triple (§E).
*Falsifier:* the derived profile and the pointer-width heuristic
(`llvm_sys.rs:407`) disagreeing for a width on a triple the corpus contains.
That disagreement is a bug report about the general atomic recipe and gets its
own note; it does not retroactively justify migrating both lists here.

**D3. Missing source spelling blocks nothing.** It makes `word_sized_scalar`
true and is recorded as a certificate diagnostic. No stage consumes
`recipe.declaration.type_spelling`: the C→C stage needs the symbol and
coordinates, the Rust stage derives the atomic type from
`scalar_class`/`signed`/`size_bits` (M.0, M.3).
*Falsifier:* a materializer stage that genuinely requires the C spelling. That
would be a change to M.3's type mapping, not a discovery about this fact, and it
would need its own justification for why the mapping is insufficient.

**D4. The no-elision property gets an audit contract, not a guarantee** — a
declared envelope of rows × widths × rustc floor × LLVM majors × opt levels, a
per-row codegen regression that is a precondition for the row existing, a ledger
record whose own text states the limit, and a Rust-stage check that refuses
toolchains outside the envelope (§E).
*Falsifier:* a codegen regression failure for a row. The response is mechanical
and already specified — remove the row, the width stops being lock-free
certified, signal flags on that target fall back to `unhandled`. No manual
override.

**D5. Signal aliases are unconditional exact-name registry entries, shape
checked** (§D), not triple- or libc-keyed. Once shape checking, `external_only`,
and the three-valued outcome exist, a `__sysv_signal` that is not glibc's fails
the shape and downgrades to unresolved rather than misresolving;
`--registry-config` covers the per-target case without a second keying scheme.
*Falsifier:* an alias whose signature is *identical* across libcs but whose
meaning differs — the one case shape cannot separate. The response is to
triple-key **that alias**, not to re-key the table; a per-entry
`triples: [...]` filter is additive and needs no redesign.

**D6. Signal-handler participation is a hard conjunct of volatile admission**
(§E), and only a *resolved* registration satisfies it. It establishes that the
`sig_atomic_t` guarantee is the operative reason the object is volatile; MMIO
and special-section storage are excluded separately by the ordinary-storage
predicate, not by this conjunct. The alternative — admitting a
`volatile sig_atomic_t` with no observed handler participation — trades the
idiom's defining property for coverage of programs the analysis cannot see into.
*Falsifier:* a corpus program with an otherwise-certifiable
`volatile sig_atomic_t` rejected solely because its registration alias is
unrecognized, *and* for which `--registry-config` is impractical. Both halves
must hold: the documented recourse existing is what makes the strict reading
affordable.

**D7. `volatile` is replaced by `Relaxed` *plus* a checked flag pattern**
(§E, F1/F2), not by `Relaxed` alone. `Relaxed` supplies indivisibility and, as an
LLVM property, absence of unbounded elision; it does **not** supply `volatile`'s
preservation of access count and relative order, which permits RLE, DSE,
store-to-load forwarding and coalescing. The pattern conditions make those
transformations behavior-refining rather than merely unlikely, by establishing
that the flag's only role is to convey signal arrival — whose timing is
unconstrained, so a collapsed or deleted access always corresponds to a legal
source execution with different arrival timing. The rejected alternative,
admitting broadly and auditing every access's execution and ordering, requires a
universally quantified claim over an optimizer that no finite regression can
establish and that every LLVM upgrade would reopen.
*Falsifier:* a corpus program whose `volatile sig_atomic_t` is rejected solely by
F1 (two flags) or F2 (a function that both polls the flag and may run as a
handler, touching another static), where the pattern is nonetheless demonstrably
safe. F2 rejections are weak falsifiers at best — such a program is already
undefined behavior under C11 §7.14.1.1p5, and the right response is to fix the
source, not the gate. F1 is the one to watch: it is a blunt instrument chosen
because the ordering question between two flags is hard, not because two flags
are inherently unsafe, and a second corpus module with two flags is a reason to
revisit it.

**D8. A permitting fact is computed by its own query, not by filtering a
restricting one** (§E, "Provenance"; rule 17). `signal_context_access` widens
`AffectedGlobals::ModuleWide` to every global in the module, which is right for a
fact that kills `mutex` and tightens `atomic`. `resolved_signal_context_access`
permits, so it requires a certified positive access path: an exact `Via::Direct`
root reached over direct-call edges from a precise target of a resolved
registration. Restricting to resolved registrations is *not* sufficient on its
own, because `ModuleWide` originates in the handler's transitive summary rather
than in the registration operand. The rejected alternative — reuse
`registry_access_facts` with a resolved-only filter — is the obvious
implementation and would make the conjunct true for every global in any module
containing one handler with an unanalyzable pointer store, which is to say it
would silently delete the conjunct.
*Falsifier:* a module where the flag's handler reaches it only through a pointer
or an indirect call, so the path requirement rejects a genuine signal flag. Note
this is bounded: `atomic_access_recipe` already requires `Via::Direct` at every
admitted site (`crates/pangs-clients/src/lib.rs:1891`), so such a global could
not have certified regardless — the falsifier would have to show the *fact* is
the binding constraint, not the recipe.

The remaining unknowns in this note are measurements, not decisions, and are
enumerated under §"Corpus-level acceptance": whether other modules contain
`volatile sig_atomic_t` globals, and how far the Phase 2 registry fix moves
`phase_stationarity` results module-wide.

The standing tie-breaker, should a question arise that this note did not
anticipate: retain the current `volatile-access` failure. The goal is to
recognize one well-defined standard idiom with positive evidence, not to broaden
atomic eligibility by assumption — and every decision above resolves toward that
default when its falsifier is absent.
