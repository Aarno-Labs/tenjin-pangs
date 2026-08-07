# Handling `volatile sig_atomic_t` Globals

## Status

Design proposal. Nothing here is implemented yet. Reviewed against the working
tree on 2026-08-05; the `file:line` anchors are navigation aids verified at that
revision, not a stable interface.

The load-bearing claim is §D's: that replacing `volatile` with a **`SeqCst`**
atomic preserves what the source relied on. `SeqCst` supplies indivisibility and
the ordering `volatile` gave between qualified accesses; what it does not supply
is `volatile`'s guarantee on the *number* of accesses, and §F states plainly what
is assumed in its place rather than burying it.

An earlier revision used `Relaxed`, and consequently needed a handler-confinement
analysis, a two-set handler model, a per-API FSA envelope, and an exhaustive
Rust-side reference inventory to make the ordering argument hold. Choosing the
stronger ordering removes all of it; §"What the SeqCst choice replaces" records
what that costs. The removed machinery is not otherwise described here, because a
design note is not a changelog.

Rationale for rejected alternatives is recorded only where the rejected shape is
the *obvious* implementation and would look correct.

## Executive summary

In `exe-apg_bore-O0.bc`, the only unhandled actionable global is:

```c
static volatile sig_atomic_t g_interrupted_xjtr_0 = 0;
```

The pipeline rejects it for two independent reasons:

1. LLVM debug metadata describes the type as an unnamed outer `volatile` node
   around the named `sig_atomic_t` typedef. PANGS reads a spelling only from the
   outer node, records none, and therefore makes `word_sized_scalar` false even
   though it correctly recovers a signed, aligned 32-bit integer.
2. Even with that fixed, atomic access recipe construction rejects every LLVM
   volatile load and store categorically.

The correction has two parts:

1. Preserve structured qualified-type evidence — typedef names and qualifiers —
   rather than only the outer DWARF type name, and project the recovered spelling
   into the existing `type_spelling` (§A). This alone clears the coarse gate;
   `word_sized_scalar` keeps its current definition (§B).
2. Keep rejecting arbitrary volatile accesses, but admit a narrowly certified
   `volatile sig_atomic_t` access mode, lowered to `SeqCst` (§C, §D, §E).

The expected disposition for this global is then `atomic`, not `unhandled`: on
the observed APG bore module, coverage 25/26 → 26/26 and the atomic count 1 → 2.

Part 2 carries the only schema change — the `atomic` certificate's payload, and
with it a version bump. **No fact changes**, so the fact layer, its validator,
and the disposition measurement funnels are untouched.

The single-global coverage claim is a consequence to verify, not the acceptance
criterion; the criterion is the whole corpus disposition distribution
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
justified by how many globals it can reach. Nine `volatile sig_atomic_t`
declarations across five projects:

| Project | Declaration(s) | Kind | Under this design |
|---|---|---|---|
| apg_bore | `g_interrupted` | internal global | **candidate** |
| libusb | `do_exit` | internal global | **candidate** |
| openssl | `intr_signal` | internal global | **candidate** |
| gavinhoward_bc | `bc_history_inlinelib` | **external** global | admissible in executable mode (§E), then rejected by coherence (§E) |
| gavinhoward_bc | `status`, `sig_pop`, `sig_lock`, `sig` | **fields of `struct BcVm`** | not disposition subjects at all |
| gavinhoward_bc | `extern … bc_history_inlinelib` | declaration, not a definition | not a subject |

Four findings, each of which shaped a decision here:

1. **The feature is not a one-global special case.** Three clean candidates in
   three unrelated programs.
2. **The largest coverage limiter is the absence of per-field disposition, not
   linkage.** Four of bc's five flags are members of the global `vm_data` struct,
   so the disposition subject is the whole aggregate, which is not a scalar.
   `DISPOSITION.md` §11.5's per-field question owns that population. (An earlier
   revision of this note misattributed those four to the external-linkage rule;
   they never reach it.)
3. **Real signal handlers do much more than set a flag.** bc's `bc_vm_sig` writes
   four flags with dependent logic, calls `write()` twice, saves and restores
   `errno`, and `siglongjmp`s out. Our three candidates' one-line handlers are
   luck, not the base rate.
4. **bc implements Dekker's algorithm across the handler boundary**, and it is
   the reason this note specifies `SeqCst` rather than `Relaxed` (§D).

This table is the Phase-1 baseline. A candidate appearing outside it, or one of
these behaving differently, is a finding to explain rather than absorb.

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
implementation. Hence a dedicated certificate, not a rule treating either
`volatile` or all typedef-sized integers as atomic.

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
traces to defect 1.

**3. Detailed atomic lowering rejects all volatile sites.**
`atomic_access_recipe` (`crates/pangs-clients/src/lib.rs:1879`) rejects a site
whenever `site.volatile` is true, with `volatile-access: "volatile C access
cannot be replaced by an ordinary Rust atomic"`. Correct for unknown volatile
storage — memory-mapped I/O, externally observed memory, other access contracts
ordinary atomics do not preserve — but too broad for a proven standard signal
flag.

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
  type" — the conservative reading for admission, and deliberately insufficient
  to reconstruct a declaration.
- The evidence is **not a rewrite recipe**: nothing here licenses reassembling a
  declaration by string concatenation.

`is_atomic` is an immediate rejection — a C11 `_Atomic` global lowers to atomic
IR operations, not volatile ones, and is a different case with a different
recipe. `is_const` on a mutable global definition is contradictory evidence and
likewise fails closed. `is_restrict` is not recorded: nothing reads it.

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
  §C requires positive typedef evidence, so a signal flag always has a spelling.
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
chain.

**This splitting rule is applied uniformly in this note**, and is the reason the
lock-free width repair and the atomic materialization contract are spun off
(§"Spun-off work").

Rewritability stays in `source_materialization`
(`crates/pangs-clients/src/lib.rs:1310`), which keys on `meta.file`/`meta.line`
and returns `blocked` with `declaration-source-unmapped` when absent. Unchanged.

### C. Signal-flag type evidence

Signal-flag type evidence is a **type fact**, derived from debug type metadata
alone; storage and program context are admission conditions (§E). Derive it only
when:

```text
typedef chain contains a member of RECOGNIZED_SIGNAL_TYPEDEFS  ( = {"sig_atomic_t"} )
qualifier chain includes volatile
qualifier chain includes neither _Atomic nor const
scalar class is integer
width and alignment are known and mutually consistent
```

The evidence recorded in the certificate is the chain itself and nothing else:

```json
{ "typedef_chain": ["sig_atomic_t", "__sig_atomic_t"] }
```

There is no field naming which chain member licensed recognition and no
`volatile: true` field. `RECOGNIZED_SIGNAL_TYPEDEFS` has one member, so the first
would be a constant; and the object does not exist unless the qualifier chain
included `volatile`, so the second is one too. The chain is the evidence; the
object's existence is the claim.

**What recognition is and is not.** This is a string match against a typedef
chain, so a user's own `typedef int sig_atomic_t;` passes it. **Safety does not
depend on the typedef being authentic**: what makes the rewrite correct is the
enumerated §E conjuncts plus §F's stated assumptions. A shadowing typedef
satisfying all of those describes an object the transformation handles correctly.
The typedef match is an **intent signal**, not a proof obligation, and therefore
carries no provenance test.

### D. Ordering: why `SeqCst`, and what it costs

`volatile` gives three things. `SeqCst` gives the first two outright and the
third only as a compiler property:

| | `volatile` | `SeqCst` |
|---|---|---|
| **(i)** indivisibility of a width-appropriate access | not guaranteed by C; supplied here by `sig_atomic_t` + the lock-free rule | guaranteed |
| **(ii)** relative order among qualified accesses | guaranteed | guaranteed — a single total order over all `SeqCst` operations, and other memory operations may not migrate across one |
| **(iii)** preservation of access *count*; no unbounded elision | guaranteed | **not** guaranteed — see §F |

**(ii) is the reason this note does not use `Relaxed`, and bc is the proof.**
`BC_SIG_UNLOCK` (`include/status.h:738`) and `bc_vm_sig` together form Dekker's
algorithm across the handler boundary:

```c
/* ordinary code */                        /* handler */
vm->sig_lock = 0;      /* store X */       vm->sig = sig;        /* store Y */
if (vm->sig) BC_JMP;   /* load  Y */       if (!vm->sig_lock)    /* load  X */
                                               BC_JMP;
```

The protocol requires at least one side to observe the other's store, or the
signal is dropped. Under `Relaxed` the store/load pair on each side may be
reordered, both sides can miss, and Ctrl-C silently does nothing. Note this is a
*compiler* reordering, not a hardware one — the handler runs on the interrupted
thread, so x86-64's TSO is irrelevant and "the hardware is strong" does not save
it. `volatile` forbids the reorder via C 5.1.2.3p6; `SeqCst` forbids it by
prohibiting StoreLoad reordering. `Relaxed` does neither.

`SeqCst` is in fact **stronger than `volatile` was** for cross-object ordering:
`volatile` never ordered a volatile access against a non-volatile one and emitted
no fences, whereas a `SeqCst` store carries release semantics. Nothing the source
relied on for ordering is lost.

**Cost.** On x86-64 a `SeqCst` load is a plain `mov`; only the *store* side is a
barrier (`xchg`/`mfence`). Handler stores happen once per signal. A bc-shaped
unlock path would take a barrier per unlock, which is the one place the cost is
not negligible. Acceptable, and named rather than assumed.

**The ordering is load-bearing and must be pinned.** With `SeqCst` doing the work
a handler-confinement analysis previously did, someone later "optimizing" a flag
to `Relaxed` on the grounds that "it's just a flag" silently reintroduces bc's
dropped-signal bug. `recipe.ordering` is therefore `"seq_cst"`, validated
(§"Schema v5"), and the materializer reads it rather than inferring it (M.3).

### E. The admission rule

Keep the existing `volatile-access` failure as the default. In
`atomic_access_recipe`, allow a volatile site only when every one of the
following holds:

```text
the global has signal-flag type evidence                          (§C)
the global's linkage is admissible for the build mode             (below)
the global is ordinary storage: no section, not thread-local      (below)
the module's arch and the declaration's width are lock-free       (below)
every access satisfies the ordinary atomic recipe constraints
the access set is complete and every site is in the admitted operation set
no function mixes this flag with an unadmitted volatile object    (coherence, below)
```

Notably absent, and deliberately: any analysis of signal handlers. §D's ordering
choice makes handler behavior irrelevant to the ordering argument, and
§"What the SeqCst choice replaces" states what that costs.

#### Linkage, by build mode

```text
executable mode:  any linkage
library mode:     internal linkage only     (code: signal-flag-external-linkage)
```

This uses the dichotomy the rest of PANGS already uses (`DESIGN_lite.md` §3's
build-mode-aware boundary seeding; `DISPOSITION.md` §1's application-only
`localize`), and it makes the rule's rationale exact rather than blunt.

The hazard being guarded is **mixed atomic/non-atomic access to one location
across a TU boundary**: if one TU is translated and another is not, the storage is
a Rust atomic on one side and a non-atomic `volatile` access on the other, which
is a data race and undefined behavior under Rust's memory model (inherited from
C++20). Identical layout does not make it defined, and a layout argument would be
overstated anyway — `AtomicI32` guarantees its alignment equals its *size*, not
that it matches `align_of::<i32>()`.

In **executable mode** the analyzed module is the whole program, so there is no
untranslated TU to race with, and external linkage costs nothing. In **library
mode** external callers exist by definition, so internal linkage is required.
The residual in executable mode — runtime symbol interposition, or `dlopen` of
something referencing the executable's symbols — is the standing executable-mode
exposure the rest of PANGS accepts, not one this rule introduces.

In library mode this is deliberately redundant with `access_set_complete`, which
fails on library-mode name reachability; for a gate whose failure mode is silent
UB, redundancy is the point. Library mode additionally requires that no
non-internal alias re-export the global, since `__attribute__((alias))` makes the
symbol externally accessible while `linkage` still reads `internal`. That is
checkable today from `LoweringStats::tainted_counts`, which records
`alias_interposable:` entries — no new PIR fact is needed, at the cost of
over-rejecting a library module containing an unrelated external alias. Executable
mode does not need the check.

#### Ordinary storage

```text
is_definition == true ∧ constant initializer present   (already required)
no explicit section attribute                          (needs a new PIR fact)
not thread-local                                       (needs a new PIR fact)
```

Phase 2 adds `section: Option<String>` and `thread_local: bool` to
`pangs_pir::Global`, both `#[serde(default)]`. Thread-local is the one that
matters: a `__thread volatile sig_atomic_t` is a per-thread flag, and lowering it
to a plain `static AtomicI32` merges every thread's copy into one. The section
check is close to free and excludes memory-mapped storage, for which no atomic
representation is correct.

#### Lock-free width

```text
SIGNAL_FLAG_LOCK_FREE : arch -> widths
  x86_64 -> { 8, 16, 32, 64 }        (only 32 is exercised: sig_atomic_t is int
                                      on every target in the corpus)
```

An arch not listed fails closed (`signal-flag-not-lock-free`). The key is the
normalized architecture component of `TargetInfo.triple`, already captured
(`crates/pangs-pir/src/llvm_sys.rs:412`); lock-freedom is an ISA property, so
vendor, OS, and environment are ignored, and normalization is the arch component
plus a small alias map (`amd64`, `x86_64h` → `x86_64`).

Only `x86_64` is listed because the corpus is 71 modules and 100%
`x86_64-*-linux-*`, and a row no test exercises is a liability. The omissions are
decisions: `arm`/`thumb`, where 64-bit lock-free access depends on a sub-arch the
arch component does not determine; `riscv32`/`riscv64`, where atomics come from
the `A` extension; and 32-bit x86, where 64-bit lock-free access needs i586+.
Baseline subtargets only — enabling CPU features can add lock-freedom but never
remove it, so ignoring them errs closed. **The table has no configuration
surface**: a new arch is a patch beside its codegen regression, not a flag.

This is deliberately *not* the general `supported_atomic_widths` gate, whose
repair is spun off (S1).

#### Coherence: no function mixes representations

The one condition that is about the program rather than the object:

```text
for every function f:
    ¬( f accesses this flag  ∧  f accesses some other volatile-qualified
                                 static-storage object that is not admitted )
```

Failure code `mixed-representation-function`, witnessed by the function and the
offending object.

**What it guards.** `SeqCst` preserves ordering against everything *it* governs.
An object that stays `volatile` after the rewrite is governed by `volatile`
instead, and the ordering *between* the two representations is where both the
C++ and Rust models say least. In practice a `SeqCst` operation is a barrier and
nothing migrates across it, so this is a guard on a formally murky area rather
than a known break — but it is cheap, local, and it is exactly where bc's
handshake lives.

**Why per-function rather than per-module.** All-or-nothing per module was
considered and is strictly coarser: it would reject a module merely for
*containing* an unadmitted flag somewhere unrelated. The per-function form is one
scan over the access sites already enumerated for the recipe, and it rejects
precisely the functions where the two representations meet.

**Both loads and stores count.** bc's hazard is store-then-load on each side, and
the two-flag handler hazard is store-then-store; restricting the check to loads
would miss both.

**A non-volatile static is not an offending object.** `volatile` never ordered a
volatile access against a non-volatile one, so there was no ordering to preserve
and nothing to reject.

**On the corpus.** bore, libusb, and openssl each have one candidate and no other
volatile statics in the accessing functions — all pass. bc's
`bc_history_inlinelib` is admissible in executable mode and is then **rejected**,
because `bc_vm_sig` also accesses `vm->status`, `vm->sig`, and `vm->sig_lock` —
`volatile sig_atomic_t` fields of a struct global, which are not disposition
subjects and therefore stay `volatile`. That is the right answer: bc's handshake
genuinely requires those ordered with each other.

#### Admitted operations

Admit only direct whole-object loads; direct whole-object stores; comparisons and
control flow consuming a load; and stores of values representable by the selected
atomic type. No address-based, field, bulk-memory, inline-assembly, or unknown
access.

Do not admit volatile read-modify-write expressions; increment/decrement or
compound assignment; accesses through escaped pointers; mismatched-width or
partial accesses; `memcpy`, `memset`, or byte-wise access; general volatile
objects lacking `sig_atomic_t` evidence; or objects that may be memory-mapped I/O.

The materializer lowers the declaration and every certified access as one
consistent atomic representation, never mixing volatile raw accesses and atomic
accesses to the same storage.

### F. The residual assumptions, named

Two things are assumed. Both are stated here, recorded in the audited soundness
inventory (`DESIGN.md` §8), and neither is proven.

**F1. The flag's role licenses giving up `volatile`'s access-count guarantee.**
`SeqCst` permits redundant-load elimination and dead-store elimination — two
adjacent `SeqCst` loads with nothing between them may collapse, because the
abstract machine admits an execution in which nothing intervened. For an object
whose sole role is conveying *that* a signal arrived, each such transformation is
behavior-refining: the source execution in which the signal was delivered later
is legal, delivery timing being unconstrained, and produces exactly the
transformed behavior.

That argument holds only for an object with that role, and this design **infers
the role from the typedef rather than proving it**. An earlier revision proved
it, by requiring a certified path from a resolved signal registration and
checking that every possible handler was confined to the flag;
§"What the SeqCst choice replaces" records why that was dropped. The exposure is a
`volatile sig_atomic_t` whose accesses are semantically counted — a spin protocol
where each read matters — which is an unusual use of the typedef and which the
corpus does not contain.

**F2. The backend does not elide accesses without bound.** A `SeqCst` load or
store inside a loop is re-executed on each iteration; the compiler does not
hoist, sink, or promote it out. C11 §7.17.3 and the Rust memory model only say a
store *should* become visible in finite time, so this is a
quality-of-implementation property; in LLVM it holds because LICM's hoist and
promotion paths require `isUnordered()`, which `seq_cst` fails. It is a property
a codegen regression can assert in both directions, which is the point of
reducing the residual to it.

#### Audit contract

No audit-schema change is required: `kind` is a free string and the schema is
`additionalProperties: true`, so the payload rides in `AuditRecord.extra`.
`AuditRecord::regenerate_id` (`crates/pangs-manifest/src/lib.rs:1392`) hashes the
whole record, so its content is drawn from repo constants and the module's own
target facts, keeping the id stable. One run-scoped record, emitted only when at
least one global certifies in signal-flag mode, plus one `scope: global` record
per such global.

```jsonc
{
  "id": "ar-…",
  "kind": "signal-flag-assumptions",
  "scope": { "kind": "run" },
  "source": "analysis",
  "text": "Certified signal-flag atomics assume (1) that the object's sole role is conveying signal arrival, so that the transformations SeqCst permits on access count — redundant-load and dead-store elimination — are behavior-refining; this role is inferred from the sig_atomic_t typedef and volatile qualifier, not proven. And (2) that the Rust backend does not hoist, sink, or promote a SeqCst atomic load or store out of a loop, and lowers load/store of the certified width without a library call. The second is a quality-of-implementation property asserted by the in-tree codegen regression for this arch, not an abstract-machine guarantee.",
  "context": {
    "triple": "x86_64-unknown-linux-gnu", "arch": "x86_64",
    "widths": [32], "ordering": "seq_cst",
    "regression": "tests/codegen/signal_flag_x86_64"
  }
}
```

`context` names the artifact an auditor re-runs. It is **not** a machine-checked
envelope: an earlier draft added a rustc floor, an LLVM-major allowlist, and a
Rust-stage check refusing anything outside them. That is dropped — the
enforcement is not what makes the property true, an LLVM-major allowlist goes
stale by construction, and the in-tree regression runs on whatever toolchain is
present, which is the actual detector.

#### Codegen regression, per arch row

The audited property is absence of *unbounded* elision, not preservation of
access count, so the assertions are positional. For the declared arch at opt
levels `{0,1,2,3}` — one width, since elision is one LICM code path and does not
vary with the integer width — compile fixtures and assert:

1. **No library call.** No reference to any `__atomic_*` symbol, and no call in
   the loop other than the fixture's own opaque `work()`/`step()`.
2. **Load not hoisted or promoted.** Fixture: a polling loop reading the flag. At
   `--emit=llvm-ir -C opt-level=3`, at least one `load atomic seq_cst` of the flag
   appears in the loop body, and the loop's exit condition still depends on a
   value loaded inside the loop — not one loaded in the entry block or carried by
   a phi from before the loop.
3. **Store not sunk or coalesced out of a loop.** Fixture: a loop storing to the
   flag each iteration with an opaque call between. At least one
   `store atomic seq_cst` appears in the loop body, and none has migrated to the
   exit block.
4. **Store not deleted across a call.** Fixture: `flag = 1; work(); flag = 0;`.
   Both stores survive. This is the bounded-DSE boundary: deletion of the first
   store *with nothing in between* is permitted and not asserted against.
5. **StoreLoad ordering survives.** Fixture: bc's handshake shape — a store to
   one flag followed by a load of another, in both orders. Assert the two are not
   reordered and that the store side emits a barrier. This is the assertion that
   catches a regression to `Relaxed`, and it exists because §D's whole ordering
   argument rests on it.

Then, host-only, the Phase 3 SIGINT test: a hoisted load makes the loop never
terminate, so the property is observed rather than inspected. It is a liveness
test and must run under a timeout, where a hang is a failure.

**What this does not do.** None of it *proves* the QoI property; it detects
regression in the toolchains under test, and the ledger record says so.

### G. Distinguish semantic certification from already-safe source

The source is already using the C-prescribed signal-flag idiom, which does not by
itself tell the Rust materializer what representation to emit. The disposition
remains `atomic`, but its certificate says why the volatile source is admitted
and how it must be translated.

A new `signal-atomic` disposition is not proposed: its storage/action is still
atomic, and adding a strategy would expand the cascade, schema, overrides,
measurements, and materializer surface.

## What the SeqCst choice replaces

Recorded because the removed machinery was substantial and someone will ask why
it is not here.

With `Relaxed`, property (ii) of §D's table is lost, and recovering it requires
proving that nothing can observe a reordering of the flag's accesses. That proof
needs the set of possible signal handlers, transitively closed, checked for both
memory confinement and absence of observable effects — which in turn needs the
registration operand resolved or soundly widened, the widening narrowed by a
per-API FSA envelope (including `sigaction`'s `sa_handler`/`sa_sigaction` union),
and a per-flag relevance filter so unrelated handlers do not poison
certification. It also needs an exhaustive Rust-side reference inventory, because
one unrewritten access defeats the argument.

`SeqCst` makes (ii) a property of the lowering rather than of the program, so
none of that is needed. Three consequences, stated honestly:

1. **Coverage increases.** A handler touching several flags now certifies, which
   the confinement condition rejected — including a defined C program, since C11
   §7.14.1.1p5 permits assigning to any number of `volatile sig_atomic_t` objects.
2. **One guarantee is now assumed rather than proven** — F1's role inference. The
   confinement analysis established the flag's role from the program; the typedef
   is weaker evidence.
3. **The ordering becomes load-bearing** (§D), which is why it is pinned and
   validated rather than left as a materializer detail.

The dropped analyses are recoverable if F1 ever proves insufficient: they were
predicates over the fixed PAG and the final call graph, and nothing here
forecloses them.

## Schema v5: normative freeze

Everything above is design rationale; this section is the contract. The JSON in
earlier sections is illustrative and, where it disagrees with this section,
wrong. MUST/MUST NOT are normative; the field paths are exact.

**The v5 fact-layer delta is empty.** Every change lives inside the
`atomic_eligibility` certificate payload; `Facts`, its validator, and its schema
definition are untouched. The version bump exists because that payload is
restructured incompatibly, not because any fact moved.

**The bump lands in Phase 2, not Phase 1.** Phase 1 is the §A walker and changes
no schema at all; it moves values on existing fields under unchanged invariants.

### 1. Encoding conventions

- **Absence, not null, for optional detail.** Every *new* optional detail field
  uses `#[serde(skip_serializing_if)]`
  (`crates/pangs-manifest/src/lib.rs:321-328`); `null` is reserved for a *slot*
  meaning "not computed". A new field MUST NOT be emitted as an explicit `null`.
- **v5 does not preserve v4 payloads.** No consumer reads a v4 manifest, so v5 is
  free to remove and restructure — and it does: `signal_lock_free` is deleted,
  not extended. Objects still retain `#[serde(flatten)] Extra` and
  `additionalProperties: true` so an unknown field round-trips, which is forward
  tolerance, not backward compatibility.
- **Vocabulary.** Field names `snake_case`, failure codes `kebab-case`, matching
  the existing vocabulary. New enums are closed.

### 2. The fact layer, unchanged

`facts.word_sized_scalar` keeps its v4 definition exactly: five conditions
including `type_spelling`, and `Facts::validate`'s detail/value coupling
(`crates/pangs-manifest/src/lib.rs:429-441`) requiring detail presence to match
the boolean. No `codes` array, no partial-detail retention, no change to
`meta.type_spelling`, which remains required-but-nullable.

What moves is what the *walker* reports into that unchanged field:
`type_spelling` is now populated for a qualified typedef where it previously came
back `None`. That is a value change on an existing field with an unchanged
contract — visible in goldens (§5), invisible to every validator.

`facts.signal_context_access` is unchanged and **gains no reader here.** Under
`Relaxed` the certificate had to agree with it; under `SeqCst` admission does not
consult signal context at all, so v5 has **no cross-section validator clause**.

### 3. Version handling

**There is one live contract.** No consumer reads a v4 manifest, so
`Facts::validate` keeps its current signature, there is no dual-invariant path,
and a document is either validated or refused by the existing version gate
(`crates/pangs-manifest/src/lib.rs:903-904`). v4 fixtures are regenerated, not
grandfathered.

A **stage-consistency defect this bump makes reachable** is spun off rather than
fixed here (S3): `pangs-dispose` never reads or writes `schema_version`, so a v5
dispose fed a v4 analysis manifest emits a document labelled v4 containing
v5-shaped dispose sections. It is a pre-existing gap in `DISPOSITION.md` §3.3's
stage-ownership rule. It is the one spun-off item with an ordering constraint:
**Phase 2 must not ship before S3 lands.**

### 4. Certificate payload: exact nesting

```text
facts.atomic_eligibility
├── status: "certified"
└── certificate
    ├── recipe
    │   ├── declaration { size_bits, align_bits, scalar_class, signed,
    │   │                 linkage, initializer_ir, type_spelling? }
    │   ├── accesses[]
    │   ├── cross_tu { … }
    │   └── ordering: "relaxed" | "seq_cst"
    ├── source_materialization { status, code?, detail? }
    └── signal_flag?                      ← ABSENT unless admitted under §E
        └── typedef_chain: ["sig_atomic_t", "__sig_atomic_t"]         (§C)
```

**`signal_flag` is an optional object, not a tagged union.** Presence is the
discriminant: it exists exactly when the §E conjunction held, so "mode asserted,
proof absent" is unrepresentable. A draft made this an `atomic_mode` enum with a
`plain` variant, on the reasoning that "no mode recorded" should not be a state a
reader interprets; with one informative variant that does not bite, and `plain`
is a tag carrying no information on every atomic in the corpus. A discriminant
earns its keep at two or more informative variants — which is S1's problem, since
a lock-free-proof variant would arrive with a probe reference. Introducing the
union there is additive; introducing it here is generality bought for a change
that has not been written.

**`signal_lock_free` is deleted, not moved.** Its three members were a duplicated
fact, a constant, and a copy: `required` was `facts.signal_context_access`;
`target_guaranteed` is `true` in every certificate where it means anything; and
`width` was `recipe.declaration.size_bits`. It also emitted
`{required: false, width: null}` on every ordinary atomic — an inhabited state
asserting nothing.

**The object records only what varies and cannot be re-derived.** No
`volatile: true`, no field naming the matched chain member, no `operations`, no
coherence boolean, no arch or target id — each is a constant wherever the object
exists, and a validator clause checking a constant defends only against the
emitter contradicting itself. Width, alignment, class, and signedness are emitted
once, in `recipe.declaration`.

**`recipe.ordering` becomes a two-valued enum.** Ordinary atomics keep
`"relaxed"`; a signal flag MUST be `"seq_cst"`. This is the one field whose value
the correctness argument rests on (§D).

**Signal-flag proofs are certified-only, structurally.** `Certificate::Failed`
(`crates/pangs-manifest/src/lib.rs:350`) has `codes`, `witnesses`, `recipe`, and
`diagnostics` and **no certificate-level payload**, so a failed slot has nowhere
to put `signal_flag`. Rule 9 therefore stops being a rule someone must enforce
and becomes a property of the type. Normatively: **a global whose admission
required signal-flag mode and did not certify gets `recipe: null`** — already the
behavior, since `atomic_access_recipe` returns `(None, failures)` whenever any
failure was recorded (`crates/pangs-clients/src/lib.rs:1992`).

The consequence is intended: per `DISPOSITION.md` §4.2 an `atomic` pin on such a
slot is rejected `no-recipe`, **unwaivable by `accept_risk`**, so "you cannot
override your way into an unproven signal-flag atomic" is structural rather than a
policy rule someone must remember. Every failure code reachable in signal-flag
mode — `signal-flag-not-lock-free`, `volatile-access`,
`address-access-not-lowerable`, `access-site-unmapped`,
`signal-flag-external-linkage`, `mixed-representation-function` — means the
rewrite cannot be executed correctly, so none is §4.2's honorable "evidence
failed, recipe present" case.

Suppression stays diagnosable through `diagnostics`:

```json
{ "signal_flag": { "status": "recipe-withheld",
                   "reason": "signal-flag mode requires certification" } }
```

**Value coupling.** Three clauses, all local, all conditioned on `signal_flag`
being present:

```text
typedef_chain ∩ RECOGNIZED_SIGNAL_TYPEDEFS   ≠ ∅
recipe.ordering                              == "seq_cst"
recipe.declaration.scalar_class              == "integer"
```

`RECOGNIZED_SIGNAL_TYPEDEFS` is a closed constant in `pangs-manifest`. `ordering`
and `scalar_class` are checked despite being emitter outputs because the
*materializer* reads them and a wrong value there is silent. Linkage is **not**
validated: it is build-mode dependent (§E), and a schema clause would have to
read the run header to evaluate it. Every clause is per-global and
per-certificate; nothing in v5 requires a validator to compare two globals or to
read the run header.

`source_materialization` is **unchanged**: `status` remains
`"source-mapped" | "blocked"`, `code` required iff blocked, and
`declaration-source-unmapped` its only code.

### 5. Ordering, determinism, and the permitted golden diff

- `typedef_chain` is in **outer-to-inner declaration order**, neither sorted nor
  deduplicated: it is a path, and its order is the evidence.
- Exceeding `DEBUG_TYPE_RECURSION_LIMIT` yields **no certificate**, never a
  truncated chain. Same for cycles and malformed metadata.
- `codes` and `typedef_chain` are deterministic under re-emission; a golden diff
  that reorders either is a defect.

**Phase 1** (walker only, no schema change, no header change):

| Class | Condition | Permitted change |
|---|---|---|
| **B** | `word_sized_scalar` was already true | none |
| **C** | was false, and the walk recovers no spelling | none |
| **D** | spelling recovered; still fails atomic later | `word_sized_scalar.value` false → true with its detail populated per the **unchanged** v4 invariant; `atomic_eligibility.codes` changes from `["word-sized-scalar"]` to the later decisive code; `diagnostics` changes from `access_lowering: skipped` to an observed-site count. Disposition unchanged |
| **E** | spelling recovered; now certifies as an ordinary atomic | class D's changes, plus Failed → Certified; `chosen` → `atomic`; `measurement_report` moves |

Class D is the bore flag's own Phase-1 diff: it clears the coarse gate and fails
on `volatile-access` instead.

**Phase 2** (schema bump + signal-flag mode):

| Class | Condition | Permitted change |
|---|---|---|
| **F** | every manifest | `schema_version` 4 → 5; every atomic certificate's `signal_lock_free` removed with nothing in its place. **No fact changes** |
| **G** | an admitted signal flag | class F, plus `atomic_eligibility` Failed[`volatile-access`] → Certified with a `signal_flag` object and `ordering: "seq_cst"`; `chosen` → `atomic`; ledger records appear |

The review rule is attribution, not line count: every changed line must be
attributable to its global's class, and every global must be in a class its facts
justify. Three defect signals: a class-B or class-C global changing at all in
Phase 1; a class-D or class-E global whose declared type is *not* a qualified
typedef; and any `word_sized_scalar` detail appearing at `value: false`, which
would mean the deferred redefinition leaked in. Aggregate: `not_word_sized` must
decrease by exactly |D| + |E|.

### 6. Freeze points

| Artifact | Change |
|---|---|
| `schemas/disposition-manifest.schema.json` | the `word_sized_scalar` `oneOf` (lines 139-166) is **untouched**; `signal_lock_free`'s definition **removed**; an optional `signal_flag` definition added, with `typedef_chain` required when present; `recipe.ordering` becomes a two-valued enum |
| `crates/pangs-manifest/src/lib.rs` | `SCHEMA_VERSION = 5`; `signal_lock_free` removed and `signal_flag: Option<SignalFlagCertificate>` added to the certified payload, skipped when `None`; `RECOGNIZED_SIGNAL_TYPEDEFS`; one validator for the §4 value coupling. `Facts` and `Facts::validate` are unchanged |
| `crates/pangs-pir/src/lib.rs` | `Global.type_evidence: Option<ScalarTypeEvidence>` with `#[serde(default)]`, matching every other optional field there (lines 158-183), so existing PIR fixtures parse unchanged; plus `section` and `thread_local` in Phase 2 |
| `crates/pangs-api/src/lib.rs:142` | `GlobalInfo` mirrors the same optional fields |
| `schemas/globals.schema.json` | **unaffected, deliberately** — `additionalProperties: false` over a fixed key set, no type fields at all; it is not the type channel and MUST NOT gain one |
| D1a golden manifests | regenerated; the permitted diff is classified per global in §5 |

`type_spelling`, `scalar_class`, and `signed` are **retained** on the PIR and API
globals, not replaced; when `type_evidence` is present they are its projections.

The honest note: certified certificate payloads are entirely unconstrained in the
JSON schema today — `certificate` requires only `status` and `certificate`
(`schemas/disposition-manifest.schema.json:167-186`), so `recipe`, `ordering`,
and `signal_lock_free` have never been schema-frozen. Constraining the signal-flag
additions is therefore *new* rigor, justified because `ordering` gates a silent
failure and the JSON schema is the only artifact a non-Rust consumer can check.

## Materialization

`DISPOSITION.md` §5.3 already assigns `atomic` its stage split — the C→C tool
does **exemption + definition-site marker**, and nothing else.

Most of what a materializer needs is not specific to this feature: type mapping
from `recipe.declaration`, initializer translation from `initializer_ir`, the
access rewrite forms, marker consumption, and post-rewrite validation are the
contract for translating *any* `atomic`-disposed global. That contract does not
exist and is not this note's to write (S2). This section states only what is
specific.

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
`write_volatile` calls on the static's address, which is what makes them
findable. After the rewrite:

```rust
static g_interrupted: ::core::sync::atomic::AtomicI32 =
    ::core::sync::atomic::AtomicI32::new(0);

unsafe extern "C" fn sigint_handler(_sig: c_int) {
    g_interrupted.store(1, ::core::sync::atomic::Ordering::SeqCst);
}

unsafe fn search() -> c_int {
    while work_remaining() != 0 {
        if g_interrupted.load(::core::sync::atomic::Ordering::SeqCst) != 0 {
            return 1;
        }
        step();
    }
    0
}
```

`static mut` becomes plain `static`: atomics carry interior mutability, and
dropping `mut` turns every missed access into a compile error rather than a
silent survival — the structural gift `DISPOSITION.md` §7 relies on, and the
reason no separate exhaustive reference inventory is specified here.

### M.3 What this feature requires of the atomic materialization contract

Three requirements, stated here because they are consequences of §D's argument
and will not be re-derived by whoever writes S2:

1. **The ordering is read, never inferred.** It comes from `recipe.ordering`,
   which is `"seq_cst"` for a signal flag. Substituting `Relaxed` reintroduces
   bc's dropped-signal bug (§D), so the rewriter reads the field and a signal
   flag carrying any other value is an error, not a hint.
2. **No re-optimization back to a plain read.** The materializer must not
   "optimize" a certified access to a non-atomic read even when it can prove the
   flag loop-invariant in its own view of the program: the handler write is
   invisible to that proof. Nor may it substitute a `Cell`, a `static mut` read,
   or an `UnsafeCell` shim.
3. **Count cross-check.** Rewritten site count equals `recipe.accesses.len()`.
   The compiler catches everything type-visible once the item is no longer
   `static mut`; the count catches accesses the rewriter did not find. A source
   that laundered the address through a cast could defeat both, but §E's
   admission rule rejects such a source before certification, so the residual is
   a bet on the translator's output shape — worth confirming once against real
   c2rust output for the three candidates, not worth a standing pass.

**Demotion.** `DISPOSITION.md` §5.3 gives the demotion channel to the C→C tool,
which owns a manifest section. The Rust stage owns none, so it cannot demote: a
C→C failure (marker unplantable) is an ordinary §5.3 demotion to `unhandled`,
while any Rust-stage failure is a loud build failure whose operator recourse is a
`disposition = "unhandled"` pin, which §4.2 always permits without `accept_risk`.

## Soundness rules

1. Missing or incomplete typedef/qualifier metadata never proves signal-flag type
   evidence.
2. A generic volatile access remains a hard atomic-eligibility failure.
3. Every access to the global must be enumerated and lowered; an incomplete
   access set fails closed. Width, alignment, and signedness must match the
   declaration and every access.
4. No mixed atomic/non-atomic or atomic/volatile representation is emitted for
   one object — **including across a translation-unit boundary**, which is what
   the build-mode linkage rule guards (§E). Conflicting atomic and non-atomic
   access to the same storage is undefined behavior under Rust's memory model,
   and identical layout does not make it defined.
5. No *function* mixes representations across objects: an admitted flag and an
   unadmitted volatile static may not both be accessed by one function, because
   the ordering between the two representations is where the memory models say
   least (§E, coherence).
6. A signal flag requires an arch and width listed in `SIGNAL_FLAG_LOCK_FREE`,
   which is backed by an in-tree codegen regression and has no configuration
   surface. A library-based (`__atomic_*`) fallback is forbidden, and an arch with
   no row is not lock-free.
7. A signal flag is lowered with `SeqCst` ordering and no other. `Relaxed` does
   not preserve the relative order of accesses to distinct objects, which real
   handshake protocols depend on (§D); the ordering is recorded in the recipe,
   validated in the schema, and read rather than inferred by the materializer.
8. Two things are assumed and neither is proven: that the flag's role licenses
   giving up `volatile`'s access-count guarantee, inferred from the typedef
   (§F1); and that the backend does not elide accesses without bound, asserted by
   positional codegen assertions (§F2). Both are recorded in the audited
   soundness inventory.
9. A signal-flag atomic exists only as a complete certified proof. There is no
   partial, failed, or overridden form: a failed proof emits no recipe, and no
   override can supply one. This is enforced by shape rather than by a check —
   `signal_flag` is a certificate-level member and `Certificate::Failed` has no
   certificate-level payload.
10. The C→C stage never removes `volatile` or alters an access: between the two
    stages the program must remain a correct C program, and a declaration
    stripped of `volatile` before an atomic exists in its place is not one.
11. Every conjunct in an admission predicate must be evaluable from a fact that
    exists, and this note must name it. A clause phrased over a relation the
    pipeline does not compute is worse than an absent clause: it reads as a
    guard, is cited as one, and an implementer will most plausibly discharge it
    by evaluating it to `false`.

## The `__sysv_signal` registry gap — an independent fix

Clang lowers the bore source call `signal(2, handler)` to a direct call to
`__sysv_signal`, which the default registry does not recognize
(`effective_registry_apis`, `crates/pangs-api/src/lib.rs:4177`, contains
`pthread_create`, `thrd_create`, `signal`, and `sigaction` only). So the handler
is not classified through the signal registry, `g_interrupted` incorrectly has
`signal_context_access: false`, mutex eligibility is not rejected for the most
direct reason, and phase analysis retains an unresolved external effect at
registration (`crates/pangs-clients/src/phase_stationarity.rs:716,757,772`).

**This is a real defect and it is no longer a prerequisite for anything here.**
Under `SeqCst`, admission does not consult signal context, so the registry gap
costs this feature nothing. It is documented here because this note found it, and
it should be fixed on its own merits — it changes module-wide facts, so globals
whose `phase_stationarity` previously failed on that unresolved effect may
certify and move to `once-lock`.

The fix is one exact-name entry with the same entry operand as `signal`:

```jsonc
{ "name": "__sysv_signal", "kind": "signal", "entry": { "arg": 1 } }
```

Two properties constrain it. It is **not** the Ω external-summary registry — it is
the spawn/signal fact registry consumed by the F-layer disposition scans, so
recognizing `__sysv_signal` does not relax the Ω boundary at that call; the call
remains an external effect for points-to, mod/ref, and escape. And its error
directions are asymmetric: a false positive is conservative in every consumer,
while a false negative is not, which is why a registration whose handler operand
the solver cannot resolve stays a registration and merely widens
(`unresolved: external || !targeted`, `crates/pangs-api/src/lib.rs:4303`). The
entry applies only when the callee is an external declaration; a *defined
internal* function named `signal` is not libc's, and the analysis already models
its body.

The registry is already extensible without code changes via
`pangs --registry-config` (`crates/pangs-cli/src/main.rs:53,726`), so the entry
can be validated through that flag before being hardcoded.

## Amendments required to other documents

Nothing here touches A′–D′ or any solver semantics; the changes are confined to
PIR lowering, the F-layer fact scans, and the manifest schema.

1. **`DISPOSITION.md` §2 (fact table)** — **no row changes.** No fact is added,
   and `word_sized_scalar` keeps its definition including the spelling condition
   (§B).
2. **`DISPOSITION.md` §3 / §3.2** — `schema_version: 5`. The fact layer and its
   detail/value coupling invariant are untouched; the sole change is that the
   `atomic_eligibility` certificate replaces `signal_lock_free` with the optional
   `signal_flag` object and widens `recipe.ordering` to two values. §3.3's
   stage-ownership rule also needs an exact-version requirement, but that
   amendment belongs to S3.
3. **`DISPOSITION.md` §7 (soundness matrix)** — the `atomic` row's "no additional
   relational failure for defined source behavior" needs a signal-flag
   qualification: the substitution is behavior-preserving under §F1's role
   assumption plus unconstrained signal-arrival timing, and §F2's no-elision
   property remains assumed. Add the dynamic-audit cell (the SIGINT test) and the
   codegen assertions. **`DESIGN.md` §8** takes both assumptions in its audited
   soundness inventory.
4. **`DISPOSITION_PLAN.md` §1.5** — the certificate encodings D1a's golden test
   freezes gain `signal_flag` and the widened `ordering`. No scalar
   failure-diagnostic vocabulary is added (§B).
5. **`DISPOSITION.md` §5.3 (stage actions)** — the `atomic` row is unchanged, but
   the section describes demotion as though every materialization failure had a
   channel. It should state that the Rust-side rewriter owns no manifest section,
   therefore fails loudly rather than demoting, and that the `unhandled` pin is
   the operator's recourse (M.3). A pre-existing gap this feature surfaces.
6. **Audit ledger kinds** — `signal-flag-assumptions` (§F). Analysis-sourced, so
   `DISPOSITION.md` §3.3's rule applies. **No change to
   `schemas/disposition-audit.schema.json` is required**: `kind` is a free string
   and the schema is `additionalProperties: true`. Document the kind in
   `DISPOSITION_PLAN.md` §1.4 alongside the deterministic-id rule.
7. **`DESIGN_lite.md` §2A** — add one sentence distinguishing the spawn/signal
   disposition registry (name-keyed, conservative-on-false-positive, no Ω effect)
   from the Ω external-summary registry, so a reader does not infer that adding
   `__sysv_signal` summarizes an external call.
8. **`HOWTO_MEASURE_DISPOSITION_COVERAGE.md` and the `notes/disposition_*`
   baselines** — **no amendment.** `not_word_sized` and the would-be-eligibility
   counters keep their meaning, so historical values stay comparable and only
   their *values* move, by the attributable amount in §5.

## Implementation sequence

Three phases. The registry fix above is independent of all of them and can land
at any point.

### Phase 1: type normalization

- Add a bounded qualified-type walker in `pangs-pir`; preserve typedef chains and
  qualifiers in PIR/API metadata, populating `type_spelling` from
  `typedef_chain[0]`.
- **Do not touch `word_sized_scalar`, `Facts`, `Facts::validate`, or the schema
  version** (§B). The only fact-layer effect is that `type_spelling` is populated
  where the walk now recovers it.
- Regenerate goldens; the permitted diff is §5's Phase-1 table.

This phase makes the manifest accurately say that `g_interrupted` is an aligned
signed 32-bit scalar while still rejecting its volatile access recipe. The
`atomic` slot is `failed` with `recipe: null`, so a user cannot reach `atomic` by
overriding — `DISPOSITION.md` §4.2's `no-recipe` rejection applies and is not
waivable by `accept_risk`.

### Phase 2: signal-flag admission

- **Prerequisite: S3 has landed** (§3).
- Bump `SCHEMA_VERSION` to 5: `signal_flag: Option<SignalFlagCertificate>` on the
  certified payload with `#[serde(skip_serializing_if = "Option::is_none")]`, its
  schema definition, the two-valued `recipe.ordering`,
  `RECOGNIZED_SIGNAL_TYPEDEFS`, the §4 value-coupling validator,
  `signal_lock_free` deleted, and regenerated goldens. **Not** a tagged
  `atomic_mode` enum — §4 states why, and S1 introduces the discriminant when it
  has a second informative variant.
- Add `section: Option<String>` and `thread_local: bool` to `pangs_pir::Global`
  (both `#[serde(default)]`) and surface them through the API.
- Add signal-flag type-evidence certification (§C).
- Land `SIGNAL_FLAG_LOCK_FREE` and its codegen regression, including assertion 5
  (StoreLoad ordering). The regression lands *before* the row it justifies. The
  general `supported_atomic_widths` gate is **not** touched (S1).
- Land the build-mode linkage rule and the library-mode alias check, reading the
  existing `alias_interposable:` taint rather than adding a PIR fact.
- Land the **coherence** check: one scan over the enumerated access sites,
  grouped by enclosing function, rejecting any function that accesses both this
  flag and an unadmitted volatile static. Loads and stores both count.
- Thread it into atomic access recipe construction, gated on the full §E
  conjunction, and emit the `signal_flag` object with `ordering: "seq_cst"`.
- Emit the `signal-flag-assumptions` ledger records and record both residuals in
  the audited soundness inventory.

### Phase 3: end-to-end materialization

Depends on S2; the assertions specific to this feature are:

- C→C: the declaration and every access are **byte-identical** to the input, with
  only the marker include and constructor added (M.1).
- Rust: the M.2 before/after program round-trips through the fixture translator
  and the rewriter, with `Ordering::SeqCst` at every site.
- Compile and run signal-interruption tests under the transformed program: SIGINT
  changes the flag and terminates the search path, with no locks or allocation in
  the handler — the test that exercises §F2, under a timeout so a hoisted load
  fails as a hang rather than hanging CI.

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
  tests the *chain*, not `type_spelling`.
- Malformed and over-depth metadata fail without certification.

### Scalar-fact tests

- A `volatile`-qualified aligned integer typedef becomes `word_sized_scalar:
  true` where it was false, through spelling recovery alone.
- **The fact's definition is unchanged**, pinned in both directions: an aligned
  supported integer whose debug metadata yields *no* spelling is still
  `word_sized_scalar: false`, and its record still carries no detail. This is the
  deferred population (§B), and the test exists so that deferral is a decision
  the suite records rather than an omission someone later reads as a bug.
- No `codes` array appears on any `word_sized_scalar` record, and
  `Facts::validate` rejects one that carries detail at `value: false`.
- A certified global whose declaration has no file/line is certified with
  `source_materialization: blocked`, and the cascade still chooses `atomic`.

### Schema tests

- A v5 document is refused by a v4 reader through the existing version gate, and
  a v4 document is refused by a v5 reader the same way.
- **The object is all-or-nothing at the schema level**: a `signal_flag` object
  missing `typedef_chain` is rejected by
  `schemas/disposition-manifest.schema.json` alone, before the Rust validator
  runs.
- Each §4 value-coupling clause is rejected independently, one test per clause:
  `typedef_chain` containing no recognized name; `ordering` ≠ `"seq_cst"` on a
  `signal_flag` certificate; `scalar_class` ≠ `"integer"`.
- **`ordering: "relaxed"` with a `signal_flag` object is rejected.** The sharpest
  schema test, because that payload is what a well-meaning "it's just a flag"
  optimization would produce, and §D's entire argument rests on the field.
- An ordinary atomic certificate with `ordering: "relaxed"` and no `signal_flag`
  object is **valid**, proving the constraint is scoped.
- A failed slot cannot carry `signal_flag` — asserted as a type-level property
  (`Certificate::Failed` has no such member) rather than as a validator test, and
  the schema is checked to reject a hand-written failed slot that adds one.
- **`signal_context_access` is not read by the validator**: a `signal_flag`
  certificate on a global with `signal_context_access: false` is **valid**.
  Asserted so nobody reintroduces the cross-section clause the `Relaxed` design
  needed.
- Re-emission is byte-identical: `codes` and `typedef_chain` ordering is stable.

### Admission tests

- Direct volatile loads/stores of a certified `sig_atomic_t` succeed; an ordinary
  `volatile int` still fails `volatile-access`; a `volatile _Atomic`-qualified or
  `const volatile` chain fails.
- A repo-local `typedef int sig_atomic_t;` used as a genuine signal flag
  **certifies** — recognition is an intent signal and safety comes from the §E
  conjuncts (§C). The test exists so a provenance check is not reintroduced as a
  bug fix.
- **A `volatile sig_atomic_t` never touched by any signal handler certifies.**
  Under `SeqCst` there is no signal-participation conjunct, and this test pins
  that deliberately, since the `Relaxed` design required the opposite.
- A `__thread volatile sig_atomic_t` flag fails, and so does a flag with an
  explicit `section` attribute.
- **Build-mode linkage**, four fixtures: an external-linkage flag in executable
  mode **certifies**; the same flag in library mode fails
  `signal-flag-external-linkage`; an internal-linkage flag certifies in both; and
  an internal flag re-exported by an external alias fails in library mode and is
  unaffected in executable mode.
- A `volatile sig_atomic_t` on an arch with no `SIGNAL_FLAG_LOCK_FREE` row fails
  `signal-flag-not-lock-free`; an unknown or unparsable triple fails the same way
  rather than inheriting a default width list. Both need a synthetic fixture with
  an unlisted triple, since the corpus is entirely `x86_64`.
- A non-signal global's atomic eligibility is **unchanged** by the new table: a
  fixture on an unlisted triple still certifies `atomic` through
  `supported_atomic_widths`, proving the two are not coupled and that S1 is
  genuinely spun off.
- Address escape, indirect access, partial-width access, bulk memory access, and
  volatile RMW all fail.
- An `atomic` override on a Phase-1-state global (failed slot, `recipe: null`) is
  rejected `no-recipe` even with `accept_risk = true`. An ordinary atomic, mutex,
  or once-lock slot is unaffected.

### Coherence tests

- **The bc shape is the regression.** A function accessing both an admitted flag
  and an unadmitted `volatile sig_atomic_t` — one that failed admission for any
  reason — fails `mixed-representation-function`, witnessed by the function and
  the offending object. Written from `bc_vm_sig`'s shape and named for it.
- **Stores count, not only loads**: a handler *writing* two flags, one admitted
  and one not, fails. A loads-only implementation passes this fixture wrongly,
  which is why it is separate.
- **Two admitted flags in one function certify.** Both become `SeqCst` atomics,
  their relative order is preserved by the total order, and no confinement
  condition applies. This is the coverage the `Relaxed` design could not have.
- **A module containing an unrelated unadmitted flag does not lose its admitted
  one**, provided no function touches both. This distinguishes the per-function
  rule from the all-or-nothing rule it replaced, and is the fixture that fails if
  someone coarsens it.
- A function accessing an admitted flag and a **non-volatile** static is
  unaffected — `volatile` never ordered against non-volatile, so there is nothing
  to preserve and nothing to reject.

### Codegen and audit tests

- For the declared arch at opt levels `{0,1,2,3}`: no `__atomic_*` reference; a
  `load atomic seq_cst` remains in the polling loop body with the exit condition
  depending on it; a `store atomic seq_cst` remains in the storing loop's body
  with none migrated to the exit block; both stores of
  `flag = 1; work(); flag = 0;` survive.
- **The StoreLoad fixture**: bc's handshake shape compiles without the store and
  the subsequent load of a different flag being reordered, and the store side
  emits a barrier. The same fixture built with `Relaxed` is asserted to be
  *allowed* to reorder — a negative control proving the test discriminates.
- The elision assertions are positional, not count-based, proven by a negative
  test: a fixture with two adjacent loads and nothing between them, legally
  collapsed to one, **passes**.
- A `SIGNAL_FLAG_LOCK_FREE` row whose codegen regression is absent or failing is
  rejected by the table's own test — evidence and row land together.
- Ledger records are deterministic (two runs produce byte-identical `ar-` ids),
  appear only when a global certifies in signal-flag mode, and carry one
  `scope: global` row per such global.

### Materialization tests

- The M.2 before/after program is a golden fixture: C source → C→C output →
  fixture-translated Rust → rewritten Rust, diffed at each step. The C→C output's
  declaration and access lines are byte-identical to the input.
- Every rewritten site carries `Ordering::SeqCst`; a fixture manifest with
  `ordering: "relaxed"` on a `signal_flag` certificate is rejected by the
  rewriter rather than honored.
- Count cross-check: rewritten site count equals `recipe.accesses.len()`.
- The rewritten output contains no `pangs_*` symbol, and a deliberately
  un-rewritten access fails to compile, confirming the `static mut` → `static`
  safety net.

### APG bore regression

For `exe-apg_bore-O0.bc` in executable/application mode, with Andersen and no
overrides:

- `g_interrupted_xjtr_0`'s type evidence names `sig_atomic_t`;
- its atomic certificate is certified with a `signal_flag` object and
  `ordering: "seq_cst"`;
- its chosen disposition is `atomic`;
- `unhandled` decreases from 1 to 0, `atomic` increases from 1 to 2, and overall
  disposition coverage increases from 25/26 to 26/26.

These are regression assertions only after the detailed access recipe passes;
they must not be obtained by overriding failed guards.

### Corpus-level acceptance

- **After Phase 1**, the distribution may move in exactly one direction with
  exactly one cause: a global whose sole atomic failure was `word-sized-scalar`
  caused by a spelling the §A walk now recovers, and which passes every remaining
  gate, certifies and chooses `atomic`. The predicate is on *cause*, not count:

  ```text
  permitted:  atomic_eligibility Failed[word-sized-scalar] → Certified, for a
              global whose declared type is a qualified typedef and whose
              spelling the §A walk now recovers, with no other fact changing
  defect:     any global moving OUT of a strategy — Phase 1 removes no gate
  defect:     any global moving IN for any other reason
  defect:     any change to a global whose word_sized_scalar was already true
  defect:     any word_sized_scalar record gaining codes or partial detail
  defect:     any schema_version change — Phase 1 does not bump it
  ```

  Expected to be small and possibly empty: the bore flag itself does not move, it
  reaches class D.

- **After Phase 2**, movement is one-directional: *into* `atomic` for a certified
  signal flag, and nothing else. The expected set is enumerated in advance by
  §"Corpus population": bore's `g_interrupted`, openssl's `intr_signal`, and
  libusb's `do_exit`. bc's `bc_history_inlinelib` is expected to reach admission
  in executable mode and then fail coherence — a specific prediction, and a
  fixture-worthy finding if it does not hold.
- Report a **coherence census**: per module, the number of admitted candidates
  and the number rejected by `mixed-representation-function`, with the offending
  object named. A corpus in which most candidates die there means the population
  is bc-shaped rather than bore-shaped, which changes the value of the whole
  feature and should be surfaced before Phase 3 rather than absorbed.

## Non-goals

- Treating all volatile integers as safe atomics.
- Modeling memory-mapped I/O through Rust atomics.
- Turning `sig_atomic_t` into a general thread-synchronization primitive.
- Inferring the typedef from symbol names, use patterns, or integer width alone;
  equally, testing where the typedef was *declared*.
- Proving that a certified flag is actually used as a signal flag. Under `SeqCst`
  that is an assumption (§F1), not a conjunct, and the handler analysis that
  would establish it is deliberately absent.
- Accepting non-lock-free atomic implementations.
- Supporting arbitrary compound operations in the first implementation.
- Weakening access-set completeness or Ω handling to improve this result.
- Redefining `word_sized_scalar`, or relaxing its `align_bits == size_bits`
  condition (§B).
- Repairing `supported_atomic_widths` or the general signal lock-free gate (S1),
  or populating `SIGNAL_FLAG_LOCK_FREE` with arches no test exercises.
- Making the lock-free table configurable at all.
- Machine-enforcing a toolchain envelope for the no-elision assumption.
- Writing the `atomic` strategy's general materialization contract (S2).
- Admitting `_Atomic` globals, which are a different lowering.
- Per-field dispositions, which own bc's four `BcVm` members
  (`DISPOSITION.md` §11.5).

## Spun-off work

**S1. The general signal lock-free gate is unbacked.** The existing gate reads
`target.supported_atomic_widths` (`crates/pangs-clients/src/lib.rs:1113,1217`), a
pointer-width heuristic (`llvm_sys.rs:407`) that asserts 8/16/32-bit atomics on
every target and says nothing about lock-freedom versus an `__atomic_*` libcall.
Repairing it is a change of population (every signal-context global), of
direction (it can *remove* certificates a global has today), and of scope (it must
cover RMW recipes, which this feature admits none of). Its own note owns the
regression-backed table, the corpus diff of table-versus-heuristic, and the
certificate member that records the result.

**S2. The `atomic` strategy has no materialization contract.** Type mapping from
`recipe.declaration`, initializer translation from `initializer_ir` (including
LLVM's signed printing of unsigned constants — `i8 -1` must become
`AtomicU8::new(255)`, not `AtomicU8::new(-1)` and not `1`), the access rewrite
forms for both `&raw` and `as *const` spellings, marker consumption, and
post-rewrite validation apply to *every* `atomic`-disposed global and exist
nowhere. M.3 states the three requirements this feature places on that contract;
Phase 3 depends on it.

**S3. `pangs-dispose` preserves an earlier stage's `schema_version` verbatim.**
It parses a `Manifest`, fills its own sections, and re-serializes without reading
or writing the version, so a v5 dispose fed a v4 analysis manifest emits a
document labelled v4 containing v5-shaped dispose sections — contradicting
`DISPOSITION.md` §3.3. The rule it needs is that a stage preserving earlier
sections MUST require `schema_version == its own SCHEMA_VERSION` and fail with
"re-run analysis" otherwise. Pre-existing, but the v5 bump makes it reachable, so
S3 must land before Phase 2 ships.

S1 and S2 are not prerequisites for Phases 1–2.

## Decisions

Each decision is normative and carries its **falsifier** — the observation that
must be made before it may be changed.

**D1. Signal flags are lowered with `SeqCst`, not `Relaxed`.** `Relaxed` does not
preserve the relative order of accesses to distinct objects, and real programs
depend on that order: bc implements Dekker's algorithm across the handler
boundary, where a compiler StoreLoad reorder silently drops the signal (§D).
`SeqCst` makes the ordering a property of the lowering rather than of the
program, which removes the entire handler-confinement apparatus the `Relaxed`
design required. On x86-64 loads stay a plain `mov` and only stores take a
barrier.
*Falsifier:* a profile showing the store-side barrier is material on a hot path.
The answer is then per-global `Release`/`Acquire` with a proof obligation for the
specific pattern, not a blanket downgrade to `Relaxed`.

**D2. Signal-handler participation is not a conjunct.** Under `SeqCst` nothing in
the correctness argument needs to know who the handler is, so the registry, the
resolution machinery, and the handler-set analysis are not consulted. What
remains is §F1's assumption that the typedef implies the role.
*Falsifier:* a corpus program with a `volatile sig_atomic_t` whose access *count*
is semantically load-bearing — a spin protocol where each read matters — that
would be silently broken by redundant-load elimination. That is exactly what F1
assumes away, and observing one would justify reinstating a role proof.

**D3. This feature recovers the spelling; it does not redefine
`word_sized_scalar`, and Phase 1 bumps no schema.** The bore flag fails that fact
on the spelling condition alone, so §A's walker clears it without touching the
fact's definition, its validator invariant, or its measurement funnel. Dropping
the spelling requirement outright would serve a *disjoint* population.
*Falsifier:* a `volatile sig_atomic_t` in the corpus whose typedef chain is
present but whose spelling the positional rule still fails to recover. That would
mean §A's walk is incomplete, and the repair is in the walk, not in the fact.

**D4. Linkage admissibility follows the build-mode dichotomy.** Executable mode
translates the whole program, so no untranslated TU can race with the atomic and
external linkage costs nothing; library mode has external callers by definition
and requires internal linkage plus the alias check. This is the dichotomy the
rest of PANGS uses, and it makes the rule's rationale exact rather than blunt.
*Falsifier:* an executable-mode program whose flag is reached at runtime through
symbol interposition or `dlopen`. That is the standing executable-mode exposure
rather than one this rule introduces, but a concrete instance would argue for
requiring internal linkage everywhere.

**D5. Representation coherence is checked per function, not per module.** An
admitted flag and an unadmitted volatile static accessed by one function is the
one place the memory models say least about ordering, and it is where bc's
handshake lives. Per-module all-or-nothing is strictly coarser: it rejects a
module merely for containing an unrelated unadmitted flag. The per-function form
is one scan over access sites already enumerated for the recipe.
*Falsifier:* a program where the correlation spans functions — one function
touches the flag, another touches the unadmitted object, and a protocol depends
on their order. The per-function check misses it. The repair is a transitive
version over the call graph, which is what the removed handler analysis was; the
falsifier is what would justify paying for it again.

**D6. The certificate records only what varies and cannot be re-derived.**
`signal_lock_free` is deleted (a duplicated fact, a constant, and a copy), and
the replacing `signal_flag` object does not reintroduce the shape: no
`volatile: true`, no field naming the matched chain member, no coherence boolean,
no arch or target id. `ordering` is the exception and lives in `recipe`, because
the materializer reads it and a wrong value there is silent.
*Falsifier:* a second informative variant, which S1's lock-free proof would be.
That is when the optional object should become a tagged union — additively, in
the change that introduces it.

**D7. The no-elision property gets an audit record and an in-tree regression, not
a machine-enforced envelope.** The ledger record states the limit in its own
text, the regression asserts the property positionally on whatever toolchain is
present, and the lock-free table has no configuration surface, so "the arch is
admitted" and "the regression covers it" cannot come apart.
*Falsifier:* a codegen regression failure, or an observed toolchain that hoists a
`seq_cst` load out of a loop. The response to the first is mechanical — remove the
arch row, certificates stop being emittable, signal flags fall back to
`unhandled`. The second would be a finding about the Rust backend far larger than
this feature.

The remaining unknowns are measurements, not decisions: how many candidates die
at coherence, and how far the independent registry fix moves `phase_stationarity`
results module-wide.

The standing tie-breaker, should a question arise this note did not anticipate:
retain the current `volatile-access` failure. The goal is to recognize one
well-defined standard idiom with positive evidence, not to broaden atomic
eligibility by assumption.
