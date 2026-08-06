# Handling `volatile sig_atomic_t` Globals

## Status

Design proposal. Nothing in this document is implemented yet.

Reviewed against the working tree on 2026-08-05; the `file:line` anchors below
were verified at that revision and are navigation aids, not a stable interface.

This note records why the current disposition pipeline rejects a canonical
signal flag, and proposes a narrow path that recognizes and safely materializes
that idiom without weakening the existing rejection of arbitrary volatile
storage.

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

The first public typedef is preferable as the display spelling. The analysis
must retain the whole typedef chain for classification rather than relying on
one formatted string.

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
insufficient-alignment
```

**Keep the alignment condition as strict equality in this change.** Relaxing it
to "ABI alignment sufficient for the width" is a real semantic widening that has
nothing to do with `sig_atomic_t`: it newly admits over-aligned globals
(`__attribute__((aligned(64))) int`), whose declarations a materializer must then
either preserve or justify dropping. If that widening is wanted, it belongs in
its own change with its own fixtures, because it moves the eligibility population
in a way this note's corpus assertions cannot attribute.

Whether a source declaration can be rewritten belongs in
`source_materialization`. That function exists
(`crates/pangs-clients/src/lib.rs:1310`) but today keys **only** on
`meta.file`/`meta.line`. Once the boolean no longer implies a spelling, a
certified atomic with `type_spelling: null` would report `source-mapped` while
its `recipe.declaration.type_spelling` is null — a recipe its materializer
cannot execute. This change must therefore add a second blocked code:

```json
{ "status": "blocked",
  "code": "declaration-type-unspelled",
  "detail": "the machine-level scalar fact is certified, but no source type spelling was recovered" }
```

Without that addition, part 2 converts a loud coarse failure into a silently
unexecutable recipe — the opposite of the intended diagnostic improvement.

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

**Polarity rule, and it is the important one:** every constraint rejects only on
*positive contrary evidence*.

- `Integer` fails only when the argument node is proven `Pointer` or
  `PointerAggregate`.
- `PointerLike` fails only when the node is proven `NonPointer`
  (`ValueKind::may_carry_pointer()` is the predicate).
- `Unknown` — the default for older PAG fixtures and for anything the kind
  analysis could not prove — never causes a mismatch.
- A return constraint is checked against `Callsite.result` only when a result
  node exists; `signal(2, h);` discards its result, and that must not be a
  mismatch.

Without that polarity the check would degrade into a type system, and every
imprecision in `ValueKind` would silently drop a registration.

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
- The return position genuinely separates the two families (`signal` returns the
  previous handler, a pointer; `sigaction` returns `int`), so shape catches a
  config that pairs one name with the other's entry operand.

#### D.4 Evaluation order, and who is checked

1. **Name match** against the effective registry.
2. **Declaration check** (`external_only`, default true): the callee must be an
   external declaration. A *defined internal* function named `signal` is not
   libc's, and the entry does not apply at all — the analysis already models
   that body. This is a precondition, not a shape check, and it runs first
   because it is the cheapest way to exclude the most likely false positive.
3. **Shape match**, per D.2.

Applies identically on the indirect path, where `registry_spec` is consulted
with a *solved target name* (`crates/pangs-api/src/lib.rs:4242,4279`); the
callsite signature used is that indirect callsite's.

User-configured entries **are** shape checked, and must be, because
`effective_registry_apis` (`lib.rs:4198-4205`) merges by name with the user
entry *replacing* the built-in — an unchecked user entry for `signal` would
otherwise launder the built-in's shape away. The rules:

- `shape: None` on a **new** name is unchecked, preserving today's behavior and
  keeping existing configs valid, and records an audit note: it asserts a
  registration the tool cannot verify, the same standing as the `--target-profile`
  rows in §E.
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
`RegistryEntryResolution` carries an `unresolved` flag
(`crates/pangs-api/src/lib.rs:434`):

```text
name ∧ declaration ∧ shape      → resolved registration, targets from points-to
name ∧ declaration ∧ ¬shape     → registration with unresolved: true,
                                  targets = the operand's pointees if any
¬name ∨ ¬declaration            → not a registration
```

The middle case widens in every consumer: phase analysis keeps its unknown
effect, and `signal_context_access` is set for whatever the operand may reach,
with the unresolved bit ensuring nothing is *narrowed* on its basis. One
deliberate exception: an unresolved registration sets the fact but **does not
satisfy §E's `signal_context_access` conjunct**, which requires a resolved
registration. Volatile admission is the one place the fact is used to *permit*
something rather than to restrict it, so it takes the strict reading.

This also bounds the retrofit risk noted above: adding shapes to the existing
`signal`/`sigaction` entries can now only *downgrade* a registration to
unresolved, never delete it. The corpus regression is still required; its worst
case is precision loss, not a lost fact.

#### D.6 Diagnostic

A name match that fails the declaration or shape check emits a
`registry-shape-mismatch` record into the audit ledger (`pangs-audit.json`) —
the same ledger as accepted-risk overrides and library-mode ordering assertions,
because it is the same kind of thing: an external the tool was told about and
could not verify. The record carries the expected and observed shapes so the
drift is diagnosable without a rebuild:

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
the global has a positive signal_atomic_type certificate      (§C)
the global has signal_context_access: true                    (§D)
lock-free load and store of the width are target-guaranteed   (below)
every access satisfies the ordinary atomic recipe constraints
the access set is complete and every site is in the admitted operation set
```

The `signal_context_access` conjunct deserves its own justification, because §C
alone would admit a `volatile sig_atomic_t` that no handler ever touches. The
non-goals list "objects that may be memory-mapped I/O" but offers no test for
that class; proven signal-handler participation is the concrete, already-computed
test. It is the property that makes the C standard's `sig_atomic_t` guarantee the
*operative* reason the object is volatile, rather than an incidental type choice
sitting in front of some other access contract. Requiring it costs a
`volatile sig_atomic_t` polled only from ordinary code — which fails closed to
today's behavior, and is not the idiom this note exists to recognize.

It also makes Phase 2 a hard prerequisite of Phase 3 rather than a courtesy
ordering: without the registry alias, the bore flag has
`signal_context_access: false` and is correctly rejected. That is the desired
failure mode — the idiom is admitted only where the analysis can see the signal
context that gives it meaning.

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
value does not carry. This is open question 2, and the answer is that the
current fact is **not** strong enough.

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

**Configuration.** A `--target-profile` JSON file, merged by normalized arch
key, with the same shape and precedence as `--registry-config`
(`crates/pangs-cli/src/main.rs:726`). Supplying a row the built-in table lacks
asserts a target property the tool cannot verify, so it appends to the audited
soundness inventory with the same standing as a library-mode ordering assertion
or an accepted-risk override (`DISPOSITION.md` §4.2, `DESIGN.md` §8).

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

`signal_lock_free` in the certificate carries `source` alongside its width and
operation set, so an individual certificate is self-describing without a lookup
into the run header.

**The bore case.** `x86_64-unknown-linux-gnu` normalizes to `x86_64`, which
yields `[8, 16, 32, 64]`; the 32-bit flag passes. No corpus module exercises the
empty default, which is worth stating plainly: the fail-closed path is asserted
by a synthetic fixture with an unlisted triple, never by the corpus.

#### Why dropping `volatile` is admissible, and what remains assumed

The source `volatile` is doing two jobs, and the certificate must be explicit
that it discharges both:

1. **Indivisibility of the access.** Delegated to `sig_atomic_t` plus the
   lock-free load/store gate. This part is proven.
2. **Preventing the compiler from caching the flag across the polling loop.**
   This is the job most readers assume `volatile` alone is doing, and it is the
   one an atomic replacement must be argued to preserve. A Rust `Relaxed`
   (LLVM `monotonic`) access is not `isUnordered`, so LICM will not hoist or
   promote it out of the loop, and it cannot be fused with adjacent accesses the
   way a plain load can. In practice the polling loop keeps re-reading.

The honest residual is that (2) is a quality-of-implementation property, not an
abstract-machine guarantee: C11 §7.17.3 and the Rust memory model only say a
relaxed store *should* become visible in finite time, so a conforming compiler
could in principle cache the load. This is strictly better than what the current
pipeline offers for this global (`unhandled`, i.e. `static mut` and unsafe), and
it is the same property every real signal flag in Rust relies on — but it is an
assumption, and it should be recorded in the audited soundness inventory
(`DESIGN.md` §8) alongside the accepted-risk override ledger rather than left
implicit. Phase 4's dynamic SIGINT test is what exercises it.

Two consequences for the materializer follow, and both are hard requirements:

- It must not "optimize" a certified access back to a plain non-atomic read even
  when it can prove the flag is loop-invariant in its own view of the program;
  the handler write is invisible to that proof.
- It must not substitute a `Cell`, a plain `static mut` read, or an
  `UnsafeCell`-based shim for the atomic representation.

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

- **Absence, not null, for optional detail.** Every optional detail field uses
  `#[serde(skip_serializing_if)]` (`crates/pangs-manifest/src/lib.rs:321-328`).
  `null` is reserved for a *slot* meaning "not computed" — the certificate slots
  and `coupling_group`. A new field MUST NOT be emitted as an explicit `null`.
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

**Closed code vocabulary**, emitted in exactly this evaluation order,
deduplicated, and **not sorted** — fixed evaluation order is what the existing
`codes` arrays do, and it keeps golden diffs stable:

```text
unknown-scalar-class
unknown-signedness
zero-width
unsupported-atomic-width
insufficient-alignment
```

`meta.type_spelling` is unchanged and remains required-but-nullable in the
schema. When both are present they are the same string; neither gates `value`.

### 3. Version negotiation and fixture behavior

The v5 invariant is **weaker than v4 for `value: true`** and **stronger for
`value: false`** (codes are newly required). So existing fixtures do not
uniformly pass, and grandfathering them into a vaguer rule would destroy their
value as tests. The freeze is therefore:

- `Facts::validate` gains a `schema_version` parameter, threaded from
  `Manifest::validate` (`crates/pangs-manifest/src/lib.rs:903`, which today
  calls `global.facts.validate()` with no version). Documents declaring v4 are
  checked against the **v4 invariant exactly**, including the detail
  prohibition; documents declaring v5 are checked against §2.
- Emission is always at `SCHEMA_VERSION`. The dual-invariant path is read-only.

| Reader | Document | Result |
|---|---|---|
| v4 | v5 | refused by the existing version gate (`lib.rs:904`) |
| v5 | v4 | accepted, validated under v4 rules |
| v5 | v5 | validated under §2 |

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
    │   ├── width: integer | null
    │   ├── target_guaranteed: bool
    │   ├── operations: ["load", "store"]                     ← new
    │   └── source: "builtin" | "config" | "none"             ← new
    └── signal_atomic_type                                    ← new
        ├── typedef: "sig_atomic_t"
        ├── typedef_chain: ["sig_atomic_t", "__sig_atomic_t"]
        ├── volatile: true
        ├── width: integer
        └── align: integer
```

Placement is load-bearing, not stylistic:

- **`volatile_semantics` lives in `recipe`.** `recipe` is the object shared by
  the certified payload (`certificate.recipe`) and the failed slot
  (`Certificate::Failed.recipe`, `lib.rs:354`). A mode that appeared only on the
  certified path would be invisible to `DISPOSITION.md` §4.2's recipe-bearing
  override path, which reads a *failed* slot's recipe.
- **`signal_atomic_type` and `signal_lock_free` live at certificate level.**
  They are proof properties, not rewrite instructions, and therefore MUST NOT
  appear in a failed slot's recipe. A failure carries its reason in
  `codes`/`witnesses` (`signal-atomic-not-lock-free`, `volatile-access`), never
  as a partial proof object.
- **Three-way presence coupling**, checked by the validator:

  ```text
  recipe.volatile_semantics == "certified-signal-flag"
    ⟺  signal_atomic_type present
    ⟺  (signal_lock_free.required == true ∧ operations == ["load","store"])
  ```

  Any disagreement is invalid. This is the most important invariant in the
  freeze: it is what prevents a volatile-admitting recipe from ever shipping
  without the proof that admitted it.
- **Absence is the default.** `volatile_semantics` is a closed enum with exactly
  one v5 member; ordinary non-volatile lowering omits the field entirely rather
  than encoding `"none"`. Every v4 recipe is therefore already valid v5.
- `signal_lock_free.operations` and `.source` are required when
  `required == true` and optional otherwise (a non-signal global's existing
  `{required: false, …}` object is unchanged). `operations` is a closed
  vocabulary of exactly `["load", "store"]` in that order; extending it to RMW
  bumps the schema.
- `source_materialization` gains the `declaration-type-unspelled` code (§B);
  `status` remains `"source-mapped" | "blocked"`, and `code` is required iff
  blocked.

### 5. Ordering, deduplication, truncation

- `typedef_chain` is in **outer-to-inner declaration order**. It is not sorted
  and not deduplicated: it is a path, and its order is the evidence.
- `typedef` MUST equal `typedef_chain[0]`, which fixes what "the" typedef means.
- Exceeding `DEBUG_TYPE_RECURSION_LIMIT` yields **no certificate**, never a
  truncated chain. Same for cycles and malformed metadata.
- `codes`, `operations`, and `typedef_chain` are all deterministic under
  re-emission; a golden-file diff that reorders any of them is a defect.

### 6. Freeze points, and an honest note about rigor

| Artifact | Change |
|---|---|
| `schemas/disposition-manifest.schema.json` | the `word_sized_scalar` `oneOf` (lines 139-166) *is* the v4 invariant and must be replaced by §2; add narrow definitions for `signal_atomic_type`, the extended `signal_lock_free`, and `volatile_semantics` |
| `crates/pangs-manifest/src/lib.rs` | `SCHEMA_VERSION = 5`; `WordSizedScalar.codes: Vec<String>` with `#[serde(default, skip_serializing_if = "Vec::is_empty")]`; version-parameterized `Facts::validate`; one validator for the §4 coupling |
| `crates/pangs-pir/src/lib.rs` | `Global.type_evidence: Option<ScalarTypeEvidence>` with `#[serde(default)]`, matching every other optional field there (lines 158-183), so existing PIR fixtures parse and re-serialize unchanged |
| `crates/pangs-api/src/lib.rs:142` | `GlobalInfo` mirrors the same optional field |
| `schemas/globals.schema.json` | **unaffected, deliberately.** That stream has `additionalProperties: false` over a fixed key set and carries no type fields at all; it is not the type channel and MUST NOT gain one |
| D1a golden manifests | regenerated; the diff must be exactly the version bump plus `codes` arrays — any other changed line is a bug, and reviewers should be told so |

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
5. No mixed atomic/non-atomic or atomic/volatile representation is emitted.
6. Width, alignment, and signedness must match the declaration and every
   access.
7. Registry alias recognition is exact and shape checked, and a shape mismatch
   downgrades a registration to unresolved rather than deleting it. Only a
   resolved registration may satisfy a permitting conjunct.
8. Unknown handler targets or unknown signal-context accesses retain the
   appropriate conservative facts.
9. The certificate provides scalar atomicity only. It does not certify
   publication of unrelated memory, and it does not model the interleaving
   between the handler and the interrupted code — it certifies that each
   individual access remains indivisible, which is the whole of what the source
   program was relying on.
10. Volatile admission requires proven signal-handler participation. Type
    evidence alone never admits a volatile access.
11. Recognizing a registration alias never relaxes the Ω boundary at that call.
    It adds spawn/signal facts and removes a phase-analysis unresolved-effect
    widening; every points-to, mod/ref, and escape consequence of the external
    call is unchanged.
12. The redefined `word_sized_scalar` never becomes a certificate by itself: a
    global with the machine-level fact and no recoverable source spelling is
    certifiable-but-blocked, never silently materializable.

## Amendments required to other documents

Nothing here touches A′–D′ or any solver semantics; the changes are confined to
PIR lowering, the F-layer fact scans, and the manifest schema. The documents
that record those interfaces must move with the code:

1. **`DISPOSITION.md` §2 (fact table)** — the `word_sized_scalar` row's
   description loses "type spelling exists" and gains the statement that detail
   fields survive a false value. Its parenthetical currently reads as a pure
   materializability fact; it becomes a machine-level fact with materializability
   split out.
2. **`DISPOSITION.md` §3 / §3.2** — `schema_version: 5`, per the normative
   §"Schema v5" freeze below: the detail/value coupling invariant is replaced,
   `word_sized_scalar` gains `codes`, and the `atomic_eligibility` certificate
   gains `recipe.volatile_semantics`, the extended `signal_lock_free`, and
   `signal_atomic_type`. The schema-v4 sentence in §2 gains a v5 clause, and
   §3.3's stage-ownership rule gains the exact-version requirement.
3. **`DISPOSITION.md` §3.2 / §3.3 (`run.analysis`)** — the analysis-owned run
   header gains `target_profile` (§E). It is additive and analysis-owned, so it
   does not disturb stage ownership, but it is load-bearing for reproducing a
   `signal_lock_free` claim and must be listed rather than left to the schema.
4. **`DISPOSITION.md` §7 (soundness matrix)** — the `atomic` row's "no additional
   relational failure for defined source behavior" needs a signal-flag
   qualification: the defined behavior being preserved is `sig_atomic_t`'s, and
   the no-elision property of the replacement is a recorded assumption, not a
   proof. Add the corresponding dynamic-audit cell (Phase 4's SIGINT test).
5. **`DISPOSITION_PLAN.md` §1.5** — the evidenced/certificate encodings that
   D1a's golden test freezes; the new `source_materialization` blocked code
   `declaration-type-unspelled` and the scalar failure-diagnostic vocabulary
   belong there, not only here.
6. **`schemas/disposition-audit.schema.json`** — the `registry-shape-mismatch`
   record (§D.6). It is analysis-sourced, so it falls under `DISPOSITION.md`
   §3.3's rule that dispose regenerates only `source: "override"` records and
   preserves the rest.
7. **`DESIGN_lite.md` §2A** — the registry paragraph describes only the Ω
   external-summary registry. Add one sentence distinguishing the spawn/signal
   disposition registry (name-keyed, conservative-on-false-positive, no Ω
   effect), so a future reader does not infer that adding `__sysv_signal`
   summarizes an external call.
8. **`HOWTO_MEASURE_DISPOSITION_COVERAGE.md` and the `notes/disposition_*`
   baselines** — the `not_word_sized` and would-be-eligibility counters change
   meaning at Phase 1; the re-measurement note must say so rather than
   re-baselining silently.

## Implementation sequence

Phases 1 and 2 are independent of each other; Phase 3 depends on both, because
its admission conjunction (§E) names a fact from each.

### Phase 1: diagnostics and type normalization

- Add a bounded qualified-type walker in `pangs-pir`.
- Preserve typedef chains and qualifiers in PIR/API metadata.
- Split `word_sized_scalar` from source spelling/materialization, keeping the
  alignment condition at equality.
- Add the `declaration-type-unspelled` materialization block so a
  spelling-free certificate cannot claim `source-mapped`.
- Bump `SCHEMA_VERSION` to 5 and land the §"Schema v5" freeze for
  `word_sized_scalar`: the `codes` field, the version-parameterized
  `Facts::validate`, the rewritten `word_sized_scalar` definition in
  `schemas/disposition-manifest.schema.json`, the exact-version requirement for
  stages that preserve earlier sections, and the regenerated goldens.
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
- Add the `registry-shape-mismatch` audit record and `--strict-registry`.
- Confirm the handler target resolves to `sigint_handler_xjtr_0`.
- Confirm `g_interrupted` becomes signal-context-accessed.
- Confirm mutex is rejected by `signal-context-access`, independently of its
  existing reentrancy result.
- Record the corpus disposition distribution before and after: recognizing the
  registration also removes a phase-analysis unresolved effect, which can move
  unrelated globals into `once-lock`.

This phase repairs facts required by the eventual atomic proof and must land
before the special volatile admission.

### Phase 3: narrow signal-flag atomic recipe

- Add `lock_free_load_store_widths` from the arch-keyed profile (one row:
  `x86_64`), record it in `run.analysis.target_profile`, and switch **only** the
  signal gate (`crates/pangs-clients/src/lib.rs:1113,1217`) onto it.
  `supported_atomic_widths` and its derivation are untouched.
- Add `signal_atomic_type` certification.
- Thread it into atomic access recipe construction, gated on the full §E
  conjunction including `signal_context_access`.
- Admit only direct whole-object volatile loads/stores.
- Emit the explicit `certified-signal-flag` recipe mode with its operation set,
  and land the §"Schema v5" §4 three-way coupling validator plus the narrow
  schema definitions for the signal payloads.
- Record the no-elision assumption in the audited soundness inventory.

### Phase 4: end-to-end materialization

- Teach the C/Rust materializer to consume the new recipe mode.
- Verify all source accesses are rewritten consistently.
- Compile and run signal-interruption tests under the transformed program.
- Add dynamic confirmation that SIGINT changes the flag and terminates the
  search path without locks or allocation in the handler.

## Tests and acceptance criteria

### PIR and metadata tests

- Lower `static volatile sig_atomic_t flag;` from real LLVM bitcode.
- Assert the typedef chain includes `sig_atomic_t`.
- Assert `volatile`, integer class, signedness, width, and alignment survive.
- Cover nested `const volatile` qualifiers and multiple typedef layers.
- Verify malformed and over-depth metadata fail without certification.

### Scalar-fact tests

- An aligned supported integer with missing spelling remains a semantic
  word-sized scalar but has blocked source materialization.
- Unsupported width, insufficient alignment, unknown class, and unknown
  signedness receive distinct diagnostic codes.
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
- The §4 three-way coupling is rejected in all three broken directions:
  `volatile_semantics` without `signal_atomic_type`; `signal_atomic_type`
  without the mode; and the mode with `signal_lock_free.required: false` or a
  non-`["load","store"]` operation set.
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
- An unresolved registration does **not** satisfy §E's volatile-admission
  conjunct, so a `volatile sig_atomic_t` behind it stays rejected.
- A *defined internal* function named `signal` is not a registration at all
  (`external_only`), and emits no mismatch record.
- Arguments with `ValueKind::Unknown` never cause a mismatch (polarity rule);
  a proven `NonPointer` in the handler position does.
- A discarded result (`signal(2, h);` with no result node) does not fail the
  return constraint.
- A user config entry replacing a built-in name inherits the built-in shape; a
  user entry for a new name with no shape is unchecked and records an audit
  note.
- Handler global accesses set `signal_context_access`.
- An unresolved handler widens conservatively.
- `--strict-registry` turns a built-in-name mismatch into a non-zero exit.

### Atomic-recipe tests

- Direct volatile loads/stores of certified `sig_atomic_t` succeed.
- An ordinary `volatile int` continues to fail with `volatile-access`.
- A `volatile sig_atomic_t` **never accessed in signal context** continues to
  fail with `volatile-access` — the §E conjunction, not the type fact alone,
  is what admits the access.
- A `volatile _Atomic`-qualified or `const volatile` chain fails.
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
- A signal flag used as a payload-publication protocol does not gain an
  acquire/release claim from this certificate.
- An `atomic` override on a Phase-1-state global (failed slot, `recipe: null`)
  is rejected `no-recipe` even with `accept_risk = true`.

### APG bore regression

For `exe-apg_bore-O0.bc` in executable/application mode, with Andersen and no
overrides:

- `g_interrupted_xjtr_0` has `signal_context_access: true`;
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

- After Phase 1, the disposition distribution is unchanged everywhere.
  `word_sized_scalar` becomes true for strictly more globals, but each newly
  true global must then either certify with a source-mapped recipe or fail with
  a *later*, more specific code — a global that silently starts certifying
  `atomic` on a spelling it cannot rewrite is a defect, not a coverage win.
- After Phase 2, any global that moves is either newly `signal_context_access`
  (expected: loses `mutex`, tightens `atomic`) or newly `once-lock` from the
  removed unresolved effect (expected: strictly more precise). Any *other*
  movement is a defect to explain before Phase 3 lands.
- After Phase 3, the only globals that may move are those with
  `signal_context_access: true`. Two directions are permitted and must be
  distinguished: *into* `atomic`, for a certified signal flag; and *out of*
  `atomic`, for a signal-context global that certified under the old
  pointer-width heuristic on an arch the profile does not list. The second is a
  deliberate coverage loss correcting an unbacked claim, and on the current
  corpus it is empty — every module is `x86_64`. Any movement by a global
  without `signal_context_access` is a defect: the coarse gate's
  `supported_atomic_widths` did not change.

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

## Open questions

1. Should the public manifest add a general structured `source_type` object, or
   keep typedef/qualifier evidence inside the atomic certificate until another
   client needs it?
   *Decided:* inside the certificate, at the path frozen in §"Schema v5" §4;
   promotion to a first-class fact slot would be schema v6. This holds the v5
   fact-layer surface to the `word_sized_scalar` change.
2. Is the current `supported_atomic_widths` target fact strong enough to mean
   lock-free in generated signal-handler code, or should it be renamed and
   backed by an explicit target/backend guarantee?
   *Answered:* no — it is a pointer-width heuristic
   (`llvm_sys.rs:407`). §E adds a profile-backed `lock_free_load_store_widths`
   for this gate and **leaves `supported_atomic_widths` alone**, because the
   general list's failure mode is a compile error while the signal gate's is a
   silent handler deadlock. Migrating the general list is a separate,
   evidence-gated follow-up.
3. Should source spelling absence make `word_sized_scalar` true with
   materialization blocked, or should a second fact make that separation more
   explicit while preserving existing schema semantics?
   *Working answer:* the former, but note it is not schema-preserving either
   way — the current invariant forbids retaining detail on a false value, so
   both options are schema v5.
4. Does the downstream Rust toolchain guarantee the intended signal-handler
   code generation for every target in scope, and how should that guarantee be
   tested?
   *Refined:* the load/store lock-freedom half is answerable from a target
   profile; the no-elision half (§E) is quality-of-implementation and can only
   be recorded as an assumption plus a dynamic test.
5. Should known signal aliases be selected by target triple/libc profile rather
   than exposed as unconditional exact-name registry entries?
   *Working answer:* an unconditional entry, shape checked per §D. Triple-keying
   buys little once the shape check exists: a `__sysv_signal` that is not glibc's
   fails the shape and downgrades to unresolved rather than misresolving, and
   `--registry-config` already covers the per-target case.
6. Should the `signal_context_access` conjunct in §E instead be a *soft* input —
   admitting a `volatile sig_atomic_t` with no observed handler participation
   and recording the weaker evidence? That would cover programs whose
   registration PANGS cannot resolve, at the cost of the only concrete
   MMIO-exclusion test this design has. The recommendation is the hard
   conjunct; this question exists so the trade is a decision rather than an
   omission.

The conservative answer to any unresolved question is to retain the current
`volatile-access` failure. The goal is to recognize one well-defined standard
idiom with positive evidence, not to broaden atomic eligibility by assumption.
