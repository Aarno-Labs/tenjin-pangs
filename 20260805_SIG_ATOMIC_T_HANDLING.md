# Handling `volatile sig_atomic_t` Globals

## Status

Design proposal. Nothing here is implemented yet. This is deliberately the
smallest useful v1: it recognizes one common signal-flag representation on
`x86_64`. It gives up coverage whenever the functions that access the flag are
not equally simple and records the two residual assumptions explicitly. The
corpus contains several source declarations on that architecture; "architecture"
does not mean one declaration, project, or program shape.

The transformation is:

```c
static volatile sig_atomic_t interrupted;
```

to:

```rust
static INTERRUPTED: AtomicI32 = AtomicI32::new(0);
```

with every access lowered using `Ordering::SeqCst`.

The design does not analyze signal registrations or handlers. It treats the
`volatile sig_atomic_t` spelling as evidence of the conventional signal-flag
intent and accepts the small risk that a program used the typedef for some other
access-count-sensitive protocol. It does not relax the requirements that every
access be known, directly rewritable, and represented consistently.

## 1. Motivating case

In `exe-apg_bore-O0.bc`, the remaining unhandled actionable global is:

```c
static volatile sig_atomic_t g_interrupted_xjtr_0 = 0;

static void sigint_handler_xjtr_0(int sig)
{
    (void)sig;
    g_interrupted_xjtr_0 = 1;
}
```

Ordinary code resets the flag during initialization and polls it while
searching. LLVM retains the necessary type and storage facts:

```llvm
@g_interrupted_xjtr_0 = internal global i32 0, align 4, !dbg !206

!208 = !DIDerivedType(tag: DW_TAG_volatile_type, baseType: !209)
!209 = !DIDerivedType(tag: DW_TAG_typedef, name: "sig_atomic_t", baseType: !210)
!210 = !DIDerivedType(tag: DW_TAG_typedef, name: "__sig_atomic_t", baseType: !24)
!24  = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
```

PANGS currently rejects it twice:

1. The outer `volatile` debug node is unnamed, so lowering loses the typedef
   spelling and reports `word_sized_scalar: false` despite recovering a signed,
   aligned 32-bit integer.
2. Atomic recipe construction categorically rejects LLVM volatile loads and
   stores.

The expected result of this proposal is that the global receives an atomic
certificate and the `atomic` disposition. On the observed bore module,
coverage should move from 25/26 to 26/26.

## 2. Scope and deliberate coverage limits

The declaration census includes the following rows:

| Project | Declaration(s) | Linkage | Under v1 |
|---|---|---|---|
| apg_bore | `g_interrupted` | internal | admitted by the measured function-local gate |
| libusb | `do_exit` | internal | admitted in both measured example translation units |
| openssl | `intr_signal` | internal | admitted by the measured function-local gate |
| gavinhoward_bc | `bc_history_inlinelib`, `sig`, `sig_lock`, `sig_pop`, `status` | external | rejected by the internal-linkage gate |

Bc also contains a multi-object signal protocol, which is outside the
single-candidate rule even apart from linkage.

Before choosing the gate, the current lowering counters and raw LLVM
instructions were measured against the available x86-64 modules. `A` is the
candidate's admitted access count, `V` is the module-wide volatile-operation
count, and `U` is the count of other volatile operations directly in a function
that accesses the candidate:

| Module | Candidate | `A` | `V` | `U` | V1 result |
|---|---|---:|---:|---:|---|
| `exe-apg_bore-O0.bc` | `g_interrupted_xjtr_0` | 6 | 6 | 0 | admit |
| libusb `examples/dpfp.c`, compiled `-O0` | `do_exit` | 3 | 3 | 0 | admit |
| libusb `examples/sam3u_benchmark.c`, compiled `-O0` | `do_exit` | 2 | 2 | 0 | admit |
| `lib-openssl-4.1.0-O1.bc` | `intr_signal` | 3 | 223 | 0 | admit |

The available libusb whole-library `linked_module.bc` does not contain either
example's `do_exit`; the census row therefore does not by itself identify one
corpus module. Both source translation units were compiled separately with the
corpus LLVM 14 compiler and measured. Phase 2 must freeze the exact libusb
bitcode artifact that its corpus acceptance test means to exercise. Until then,
the project-level row is evidence that the function-local rule can handle the shape,
not a claim about the whole-library module.

OpenSSL demonstrates why module-wide counting is too coarse: `intr_signal`
accounts for only three of 223 volatile operations, but its access functions,
`read_string_inner` and `recsig`, contain no other volatile operation. The
remaining 220 operations are elsewhere, largely in constant-time cryptographic
code. Function-local closure admits all three intended internal rows without
requiring signal-registration or whole-call-graph analysis.

V1 accepts at most one signal-flag candidate per module and requires that every
LLVM volatile memory access directly in a function that accesses the candidate
also target that candidate. Volatile operations in other functions do not block
admission. This catches a directly co-located multi-object protocol while
avoiding whole-call-graph coherence, per-field dispositions, or joint
policy/materialization.

## 3. Type normalization

### 3.1 Qualified scalar evidence

Replace the current one-name debug-type query with one bounded walk:

```rust
struct ScalarTypeEvidence {
    type_spelling: Option<String>,
    typedef_chain: Vec<String>,
    qualifiers: TypeQualifiers, // is_const, is_volatile, is_atomic
    class: Option<ScalarTypeClass>,
    signed: Option<bool>,
}
```

The walk starts at the `DIGlobalVariable` type, follows derived-type base links,
records named typedefs in outer-to-inner order, accumulates qualifiers, and
derives class and signedness from the terminal scalar type. It uses the existing
debug-type recursion bound.

```text
type_spelling =
    typedef_chain[0]                       if the chain is nonempty
    else the terminal scalar type's name   if present
    else None
```

Malformed metadata, a cycle, or exceeding the recursion bound yields no
`ScalarTypeEvidence`; a partial chain is never emitted. Existing
`type_spelling`, `scalar_class`, and `signed` fields remain as projections so
current consumers need not migrate.

For the motivating declaration the result is:

```text
type_spelling = "sig_atomic_t"
typedef_chain = ["sig_atomic_t", "__sig_atomic_t"]
qualifiers.is_volatile = true
class = integer
signed = true
```

`qualifiers.is_atomic` is preserved as evidence and is an unconditional
rejection at the entry to `atomic_access_recipe`, before ordinary/signal-mode
dispatch. The current PIR discards statement-level atomicity and ordering, and
lowers `atomicrmw`/`cmpxchg` into plain load/store pairs. Without this gate a C11
`_Atomic` global can be certified by the ordinary path with Relaxed ordering,
silently weakening source SeqCst semantics. The failure code is
`source-atomic-unsupported`; the recipe is withheld and an override cannot
waive it.

### 3.2 `word_sized_scalar` is unchanged

This feature does not redefine the published fact. Its existing conditions,
including the spelling requirement and `align_bits == size_bits`, remain intact.
The new walker merely recovers a spelling that was already present beneath a
qualifier node.

`word_sized_scalar` remains a machine-representation fact rather than an access-
semantics certificate. It may be true for an `_Atomic`-qualified scalar while
`atomic_eligibility` fails `source-atomic-unsupported`. The recipe gate closes
the hole without changing the fact's meaning.

Phase 1 therefore changes no manifest schema. A qualified typedef may move from
`word_sized_scalar: false` to `true`; a type with no recoverable spelling remains
false and retains the existing detail/value invariant.

## 4. V1 admission rule

Admission is computed in two steps: provisional candidates, followed by one
function-local gate.

### 4.1 Provisional candidate

A global is a provisional signal-flag candidate only when all of the following
hold:

```text
defined mutable global with a constant initializer
internal linkage
typedef_chain contains the recognized public intent name "sig_atomic_t"
qualifier chain contains volatile
qualifier chain contains neither const nor _Atomic
terminal scalar class is integer and signed
target architecture normalizes to x86_64
size_bits == 32 and align_bits == 32
access_set_complete == true
every access is a direct, whole-object, 32-bit load or store
every access is volatile
every store value is representable by i32
no address escape, pointer-based access, RMW, partial access, bulk access,
  inline assembly access, or unknown access
no explicit section
not thread-local
```

`section: Option<String>` and `thread_local: bool` are added to
`pangs_pir::Global` with `#[serde(default)]` and mirrored by `GlobalInfo`.

The typedef match is an intent check, not an authenticity check. A project-local
typedef named `sig_atomic_t` can pass. Safety comes from the remaining machine,
storage, and access-shape conditions plus the assumptions in §6.

There is no build-mode exception for external linkage. Requiring internal
linkage avoids cross-TU mixed atomic/non-atomic access, symbol interposition,
alias export, and whole-program qualification. Lifting this restriction is
future work.

### 4.2 Function-local volatile gate

The current PIR preserves the volatile bit only on direct `Stmt::GlobalRef`
loads/stores. Add `volatile: bool` with `#[serde(default)]` to `Stmt::Load` and
`Stmt::Store`, populate it from LLVM, and thread it through `AccessSiteKey` and
`AccessSite`. This makes local-, GEP-, pointer-, and MMIO-shaped volatile
instructions visible at their containing function and statement index. The
existing module-level counters remain metrics; admission does not use them.

Let `C` be the set of provisional candidates. The module first requires
`|C| == 1`. For the sole candidate `g`, let `F(g)` be the set of functions
containing an admitted load or store of `g`. The candidate passes only if every
volatile `Stmt::Load` or `Stmt::Store` directly in every function in `F(g)` is
one of `g`'s admitted accesses.

“Directly” is intentional: v1 scans each function body but does not include the
transitive callees of that function. Each candidate access is independently
required to be volatile, direct, and whole-object by §4.1.

Consequences are intentional:

- A second candidate rejects both.
- A volatile aggregate field, local, MMIO access, pointer access, or unrelated
  volatile global in a function in `F(g)` rejects the candidate.
- The same unrelated operation in a function outside `F(g)` does not reject it.
- An unknown or unattributed volatile instruction in `F(g)` rejects it.

This rule detects the most direct multi-object protocol shape: a handler,
poller, or helper that accesses both the flag and another volatile object. It
does not prove that the flag is independent of volatile operations performed
only by other functions; that limitation is explicit in A1.

Failure code:

```text
signal-flag-access-functions-not-closed
```

For `|C| != 1`, the witness reports `candidate_count`. Otherwise it reports the
first offending function, statement index, operation kind, address operand, and
source location when present. It may also report an attributable global, but
attribution is not required to reject the instruction.

### 4.3 Admitted operations

The only admitted memory operations are:

- direct whole-object loads;
- direct whole-object stores of representable `i32` values.

Uses of a loaded `i32` are outside the recipe: replacing the source load with
`AtomicI32::load` produces the same value consumed by the existing translated
expression. Comparisons, integer-preserving casts, and control flow therefore
need no classification, failure code, or witness.

The first implementation does not admit increment/decrement, compound
assignment, atomic or volatile RMW, address-taking, GEP/field access, `memcpy`,
`memset`, byte-wise access, mismatched width, partial access, or inline assembly.

Any failure withholds the recipe. A user override cannot manufacture a recipe
and therefore cannot force this mode through `accept_risk`.

## 5. Lowering and ordering

Every certified access is lowered to a Rust `AtomicI32` operation using
`Ordering::SeqCst`:

```rust
static G_INTERRUPTED: ::core::sync::atomic::AtomicI32 =
    ::core::sync::atomic::AtomicI32::new(0);

G_INTERRUPTED.store(1, ::core::sync::atomic::Ordering::SeqCst);

if G_INTERRUPTED.load(::core::sync::atomic::Ordering::SeqCst) != 0 {
    // ...
}
```

`SeqCst` is chosen instead of `Relaxed` because real `sig_atomic_t` programs can
use several qualified objects in an ordering protocol. V1 rejects those modules,
but retaining the strongest ordering makes the representation safe to extend and
avoids making “just a flag” an implicit lowering assumption. On x86-64 a 32-bit
SeqCst load is ordinarily a plain load; a SeqCst store may require a barrier or
locked instruction. Signal-handler stores are expected to be cold.

The correctness claim is narrow: program-ordered SeqCst operations on converted
objects retain the ordering required of this representation. This note does not
claim that SeqCst universally prevents every ordinary memory operation from
moving across it.

## 6. Residual assumptions

Two assumptions remain and are emitted in the audited soundness inventory for
every run that certifies a v1 signal flag.

### A1. Typedef implies notification-flag intent

The object is assumed to be used as a notification flag, so giving up
`volatile`'s exact access-count guarantee is behavior-refining. `SeqCst` does
not promise that two adjacent loads or stores remain two machine operations.

The object is also assumed not to participate in a cross-object volatile
protocol whose other accesses occur exclusively in different functions. The
function-local gate rejects a second volatile object in a function that
accesses the flag, but deliberately does not inspect transitive callees or
otherwise prove cross-function component closure.

The implementation does not prove signal-handler participation and does not
inspect `signal`, `sigaction`, or handler bodies. The exposure is an unusually
used `volatile sig_atomic_t` whose individual access count is semantically
load-bearing, or a cross-function multi-object protocol not caught by the local
gate. The corpus contains no such scalar disposition subject.

### A2. Backend and target behavior

For x86-64 signed aligned 32-bit load/store:

- Rust emits an inline lock-free atomic operation, not a runtime helper;
- a SeqCst load or store inside a loop is not hoisted, sunk, or promoted out of
  that loop without bound;
- the materializer does not replace a certified access with a plain,
  `read_volatile`, `write_volatile`, `Cell`, or `UnsafeCell` operation.

These are quality-of-implementation properties, not a portable Rust-language
proof. They are covered by the codegen and end-to-end tests in §10.

One deterministic run-scoped audit record lists all globals certified under
these assumptions:

```jsonc
{
  "kind": "signal-flag-assumptions",
  "scope": { "kind": "run" },
  "source": "analysis",
  "text": "Certified volatile sig_atomic_t globals are treated as notification flags and lowered to x86-64 i32 SeqCst atomics. The transformation assumes access count is not semantically load-bearing, that the flag is not part of a cross-object volatile protocol split across functions, and that the tested Rust backend emits inline operations without unbounded loop elision.",
  "context": {
    "arch": "x86_64",
    "width": 32,
    "ordering": "seq_cst",
    "globals": ["src/search.c::g_interrupted"],
    "regression": "tests/codegen/signal_flag_x86_64_i32"
  }
}
```

Global keys are sorted before hashing the record.

## 7. Manifest contract

Phase 2 bumps the disposition manifest to schema v5. The fact layer is
unchanged. The atomic certificate recipe gains explicit mode and ordering:

```text
facts.atomic_eligibility
├── status: "certified"
└── certificate
    ├── recipe
    │   ├── mode: "ordinary" | "signal-flag-v1"
    │   ├── declaration { size_bits, align_bits, scalar_class, signed,
    │   │                 linkage, initializer_ir, type_spelling? }
    │   ├── accesses[]
    │   ├── cross_tu { ... }
    │   └── ordering: "relaxed" | "seq_cst"
    └── source_materialization { status, code?, detail? }
```

For `mode == "signal-flag-v1"`, validation requires:

```text
ordering == "seq_cst"
declaration.size_bits == 32
declaration.align_bits == 32
declaration.scalar_class == "integer"
declaration.signed == true
declaration.linkage == "internal"
```

Ordinary atomic certificates use `mode == "ordinary"` and retain their existing
ordering. The obsolete `signal_lock_free` member is removed; in v1 the supported
arch and width are fixed admission conditions, while width already appears in
the declaration recipe and arch appears in `run.analysis`.

A failed signal-flag attempt has `recipe: null`, ordinary failure codes and
witnesses, and an optional diagnostic explaining which v1 gate failed. There is
no partial signal-flag recipe.

The schema bump must not ship until every stage that preserves earlier manifest
sections rejects an input whose `schema_version` differs from its own and asks
the operator to rerun analysis. In particular, `pangs-dispose` must not emit a
v5-shaped document under a preserved v4 header.

## 8. Materialization

The C→C stage performs the existing `atomic` action: exemption from localization
plus a definition-site marker. It must not remove `volatile` or alter an access;
the intermediate C remains a valid C program.

The Rust stage:

1. matches the translated static by manifest identity and marker;
2. replaces `static mut i32` with `static AtomicI32` and translates the constant
   initializer;
3. rewrites every recipe access to `load` or `store` using the recipe ordering;
4. requires the rewritten-site count to equal `recipe.accesses.len()`;
5. removes the marker artifacts; and
6. compiles the resulting crate, treating any failure as a hard materialization
   failure.

The general atomic materialization contract—initializer parsing, all translated
access spellings, marker consumption, and failure reporting—is shared with
ordinary atomics and remains a prerequisite outside this note.

### Future reference closure

V1 does not include a Rust reference-closure pass. Its residual risk is that the
translator could introduce a reference to the static which both survives the
rewrite and remains compilable after a raw-pointer cast, for example:

```rust
let p = &G_INTERRUPTED as *const AtomicI32 as *const i32;
let x = p.read_volatile();
```

The site-count check and compilation do not prove this absent. Before supporting
more translator shapes, pointer-based source accesses, or more than the three
measured candidates, add a post-rewrite Rust AST pass that resolves every path to
the rewritten static and accepts only receivers of the certified atomic
`load`/`store` operations. Unknown resolution fails closed.

For v1, this gap is an explicit translator-shape assumption. The end-to-end
goldens record the complete translated forms for every admitted corpus candidate,
and any new form is a review finding rather than silently added support.

The Rust stage owns no manifest section and therefore cannot demote a disposition.
A Rust rewrite failure is a loud build failure. The operator may rerun disposition
with an explicit `unhandled` pin.

## 9. Implementation sequence

### Phase 1: qualified type normalization

1. Add the bounded debug-type walker and `ScalarTypeEvidence` to PIR/API globals.
2. Project its results into the existing scalar fields.
3. Add the unconditional `qualifiers.is_atomic` rejection at the entry to
   `atomic_access_recipe`, before ordinary/signal-mode dispatch.
4. Do not change `word_sized_scalar`, `Facts`, `Facts::validate`, or the manifest
   schema version.
5. Regenerate goldens and classify every movement by recovered typedef chain or
   by the newly enforced `_Atomic` rejection.

The motivating flag should move from `word-sized-scalar` failure to the existing
`volatile-access` failure, without yet changing disposition. A currently
certified `_Atomic` global may move to failed `source-atomic-unsupported`; this
is an intentional soundness repair and the only permitted Phase-1 coverage loss.

### Phase 2: signal-flag-v1 eligibility

1. Land the exact-version guard for manifest-preserving stages.
2. Bump the manifest to v5; add recipe `mode` and `seq_cst`; remove
   `signal_lock_free`.
3. Add `section` and `thread_local` lowering facts.
4. Add `volatile` to `Stmt::Load`/`Stmt::Store` and thread it through
   `AccessSiteKey` and `AccessSite`.
5. Implement provisional-candidate checks and the function-local volatile gate.
6. Emit certified recipes and the run-scoped audit record.
7. Regenerate and review manifest goldens.

### Phase 3: materialization

After the general atomic materializer exists:

1. preserve the C declaration/accesses and emit the atomic marker;
2. translate the definition and every recipe site to `AtomicI32`/`SeqCst`;
3. perform the count check, remove markers, and compile;
4. run the end-to-end signal test under a timeout.

Reference closure is not a Phase-3 v1 prerequisite; it remains a future
hardening item after the three measured internal candidates work end to end.

## 10. Tests and acceptance criteria

### Type and fact tests

- Real LLVM lowering of `static volatile sig_atomic_t flag` recovers the typedef
  chain, volatile qualifier, signed integer class, width, and alignment.
- Nested typedefs use the outermost typedef as `type_spelling` while recognition
  searches the whole chain.
- Const, `_Atomic`, malformed, cyclic, and over-depth chains do not certify.
- Both `typedef _Atomic int atomic_int` and bare `_Atomic int` retain their
  machine-shape facts but fail `source-atomic-unsupported` with `recipe: null`,
  through ordinary as well as signal-mode dispatch.
- An already-spelled `_Atomic` typedef that certifies before Phase 1 loses that
  certificate. A spelling newly recovered beneath `DW_TAG_atomic_type` must
  never produce an ordinary atomic certificate.
- A scalar with no recoverable spelling remains `word_sized_scalar: false` with
  the existing detail/value invariant.
- Phase 1 changes no schema version.

### Admission tests

- LLVM lowering fixtures pin `Stmt::Load.volatile` and `Stmt::Store.volatile`
  for direct-global, local-, GEP-, and pointer-addressed operations and pin the
  same value in `AccessSiteKey`/`AccessSite`. Non-volatile twins remain false.
- One internal, aligned i32 `volatile sig_atomic_t` with only direct whole-object
  loads/stores certifies on x86-64.
- External linkage, TLS, explicit section, non-i32 width, unsignedness, bad
  alignment, RMW, address escape, partial/bulk/pointer access, inline assembly,
  or incomplete access set fails with no recipe.
- A module with two otherwise valid candidates rejects both.
- A volatile local, aggregate field, unrelated global, unknown pointer target,
  or MMIO-shaped access in a function that accesses the candidate rejects it
  and identifies the first offending function and statement.
- The same unrelated volatile operation in a function that does not access the
  candidate does not reject it.
- A direct caller or callee containing an unrelated volatile operation does not
  reject unless it also directly accesses the candidate; this pins the v1
  boundary against accidental transitive closure.
- A repo-local typedef named `sig_atomic_t` can certify; typedef authenticity is
  not claimed.
- No signal registration or handler is required; this pins assumption A1 rather
  than accidentally reintroducing handler analysis.

### Schema tests

- V4 and v5 readers reject the other version.
- `signal-flag-v1` with anything other than SeqCst, signed aligned i32, integer
  class, or internal linkage is rejected.
- `ordinary` with the existing relaxed ordering remains valid.
- A failed certificate cannot carry a recipe from a partial signal-flag proof.
- A stale manifest version is rejected by every preserving stage.

### Codegen tests

For x86-64 i32 at the production optimization level and the most aggressive
supported level:

- no `__atomic_*` or other atomic runtime helper is referenced;
- a `load atomic seq_cst` remains in the polling-loop body and controls exit;
- a `store atomic seq_cst` in a loop remains in that loop;
- both stores around an opaque call remain;
- the generated store has the required x86-64 SeqCst barrier/locked behavior.

The test does not require a Relaxed fixture to reorder; a compiler is always
free not to perform a permitted optimization.

### Materialization tests

- Golden the complete C → C→C → translated Rust → rewritten Rust path for every
  admitted corpus candidate.
- Every rewritten site uses `Ordering::SeqCst`.
- Rewritten-site count equals recipe access count.
- The output contains no marker symbols and compiles.
- A deliberately omitted direct access causes the count or compilation check to
  fail.
- Document, but do not yet gate on, the raw-pointer laundering fixture from §8.

### Corpus acceptance

After Phase 1, only globals whose spelling is newly recovered from a qualified
typedef may change fact values. Strategy coverage may decrease only for a global
whose type evidence contains `_Atomic`, which moves to failed
`source-atomic-unsupported` if it was previously accepted. No other strategy may
lose coverage, and a newly recovered `DW_TAG_atomic_type` must not increase
atomic coverage.

After Phase 2, the expected new atomic dispositions are bore's
`g_interrupted`, OpenSSL's `intr_signal`, and libusb's `do_exit` in the exact
example module selected and frozen by the corpus test. OpenSSL must remain
admitted despite its module-wide counts (`A = 3`, `V = 223`) because its two
access functions contain no other volatile operation (`U = 0`). Any additional
candidate is a census finding; any candidate rejected by function-local closure
is a measured coverage cost, not grounds for silently weakening the rule.

The bore regression remains:

```text
unhandled: 1 -> 0
atomic:    1 -> 2
coverage:  25/26 -> 26/26
```

## 11. Non-goals and upgrade path

V1 does not support:

- more than one signal-flag candidate in a module;
- coexistence with another LLVM volatile memory operation in a function that
  directly accesses the candidate;
- external-linkage flags in any build mode;
- aggregate fields or per-field dispositions;
- targets or representations other than x86-64 signed aligned i32;
- RMW, pointer, partial, bulk, or inline-assembly access;
- source `_Atomic` globals until PIR and recipes preserve operation ordering;
- signal registration or handler analysis;
- proving typedef authenticity or notification-only role;
- a general lock-free target table;
- Rust reference closure;
- the general atomic materialization contract.

Add precision only in response to measured rejection:

1. If the cross-function-protocol assumption must be discharged, replace
   function-local closure with a proved call-graph/component coherence rule.
2. If two candidates must convert together, introduce a joint disposition and
   materialization group rather than independent certificates.
3. If external linkage matters, require a whole-program transformed-access
   certificate.
4. If another target matters, add exactly one representation beside codegen
   evidence for that target and operation set.
5. If translator output grows beyond the frozen v1 forms, implement reference
   closure before admitting those forms.

The standing fallback is the existing `volatile-access` failure. Every rejected
shape remains `unhandled` or proceeds to another independently certified
disposition; rejection loses coverage, not correctness.
