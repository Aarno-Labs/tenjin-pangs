# External and internal varargs contracts: fixing Lemon `templatename`

## 0. Status and goal

**Implemented on 2026-09-05.**  Parts 0, A, B and C1 are in the working tree with fixtures;
the whole-corpus gates and the remaining work are recorded in §9.  The plan text below is
kept as the design record; where a measurement contradicted it, the correction is marked
inline and explained in §9.

The immediate target is
`tplt_open.templatename_xjtr_0` in `exe-lemon-O0`.  On the 2026-09-05 working tree, a
validated executable-mode Andersen run chooses `unhandled` for this global even though the
source object is the fixed string `"lempar.c"` and all source uses are reads.

The proposed fix has four parts.  Part 0 is new: it was found while diagnosing why the
existing variadic proof rejects Lemon's `ErrorMsg`, and it is both the cheapest part and a
precondition for the acceptance gate in §8.2.

0. resolve a constant format string through the zero-offset GEP that Clang emits, so the
   existing `%n`-free proof can fire at all;
1. model `llvm.va_start` and `llvm.va_end` as local `va_list` operations, not unknown
   pointer escapes;
2. add the standard `access(const char *, int)` call to the shared external-call contract
   table; and
3. infer a conservative read/write/capture summary for closed internal variadic consumers
   such as Lemon's `lemon_sprintf`, then use that one summary in both PAG construction and
   certificate/audit assembly.  This part is staged: C1 extends the existing forwarder
   proof and is enough for Lemon; C2 is the general effect engine and is built only if the
   census justifies it.

C1 grew one step beyond its plan during implementation: the same body proof also settles a
variadic function that consumes its own list with no forwarding call at all, which is the
larger population (§5.1) and what allowed the name allowlist of §6.2 to be deleted.

Every failed proof keeps today's boundary.  There is no name-based exemption for
`lemon_sprintf`, no global-specific exception for `templatename`, and no weakening of
`access_set_complete`.  §6 additionally retires the *existing* undeclared name allowlist,
which contradicts that rule today.

## 1. Measured problem

Input:

```text
/home/brk/pangs-corpus/_out_bc/exe-lemon-O0.bc
sha256 6e457af487f97e14cefcfaa9d865c74a8f0d8757e709202b85c5216dfc7811bf
```

Configuration: `--stage andersen --build-mode executable --dispose --no-overrides`, with
the default conservative integer-pointer policy.  The run completed normally.  It had 6,966
partitions, maximum partition size 140, zero oversize fallbacks, one Andersen round, and
80,056 Andersen steps.  This is not an admission-budget problem.

Current `templatename` facts are:

```text
chosen                     unhandled
written                    true
omega_escaped_address      true
access_set_complete         false
violation_taint             false
localization                ctx0001, blocked only by access-set-complete
named ModRef rows           3 (2 ref, 1 mod), in 2 functions
atomic access sites         7
```

The selected completeness witness is:

```text
UnknownOperandEscape:
  val:lemon_sprintf_xjtr_0:%lemon_sprintf_xjtr_0::arraydecay1
```

That value is the address of the local `va_list` object passed to `llvm.va_start` and
`llvm.va_end`; it is not the address of `templatename`.  The escape itself does not depend on
that seed: the address also reaches Ω through the `pathsearch` → `lemon_sprintf` callsite
boundary.  Witness selection reports the intrinsic seed, but removing only that seed leaves
the fact unchanged.  §3.4 makes this an explicit expectation, not a surprise.

Lemon contains two internal variadic functions:

| Function | Direct calls | Shape |
|---|---:|---|
| `ErrorMsg` | 49 | local `va_list` forwarded once to `vfprintf` |
| `lemon_sprintf_xjtr_0` | 10 | local `va_list` forwarded to an internal formatter which consumes `%d`, `%s`, and `%.*s` |

The PAG currently emits 59 `vararg_call_boundary` seeds and four
`unknown_operand_escape` seeds for their two `va_start`/`va_end` pairs.

### 1.1 Why `ErrorMsg` is rejected today

*Confirmed by the implementation: Part 0 alone took Lemon's `vararg_call_boundary` seeds
from 59 to 10, exactly the 49 `ErrorMsg` callsites.*

The `VarargCallProof` was intended to recognize the `ErrorMsg`/`vfprintf` shape.  It does.
Hand-tracing `internal_vfprintf_forwarder_format_index("ErrorMsg")` on the dumped PIR gives
`Some(2)`: one `va_start` root, matching `va_end`, one forwarding sink whose callee is
`vfprintf` with three arguments, confined `va_list` uses, and exactly one fixed parameter that
is an unchanged copy of the forwarded format.

The rejection happens one step later, in `is_benign`, at the *callsite* check
`constant_formats_are_percent_n_free`.  That resolver
(`crates/pangs-pag/src/lib.rs`, `constant_format_bytes`) follows a format operand only through
`Stmt::Assign`, or accepts an operand whose own name contains `@`.  Clang at `-O0` spells every
string constant as a separate zero-offset GEP:

```text
{"kind":"gep","dest":"%tplt_open::tmp3","base":"@.str.139","byte_off":0}
{"kind":"call_direct","callee":"fprintf","args":["…tmp16","%tplt_open::tmp3","%tplt_open::tmp14"]}
```

So the proof never fires on real bitcode.  Counted over the printf-family callsites of three
modules:

| module | operand is `@…` | operand defined by a GEP | other |
|---|---:|---:|---:|
| `exe-lemon-O0` | 0 | 265 | 0 |
| `exe-tree-O0` | 0 | 183 | 3 |
| `exe-gifsicle-O0` | 0 | 70 | 1 |

This has two consequences, and both are load-bearing here.  All 49 `ErrorMsg` seeds are lost
at the last step of an otherwise successful proof.  And `ExternalContractPolicy::Printf`
degrades every pointer variadic actual to `ReadWrite` whenever `safe_format` is false, which
is always — that is where `templatename`'s single Mod row comes from.

### 1.2 Where the Mod row comes from

The source uses of `templatename` are at `lemon_unstatic.c:3644-3684`: `access`,
`pathsearch`, and formatted diagnostic output.  `pathsearch` calls `strlen(name)` and passes
`name` as a `%s` input to `lemon_sprintf`.  None retains or writes it.  The Mod row is
attributed to the `fprintf` at line 4224, whose format operand is the constant
`@.str.139` reached through a GEP, and whose variadic actual is a GEP of `templatename`.
There is no source store to the array.

As a useful differential, Steensgaard assigns both Lemon arrays 137 named rows in 88
functions (58 Mod, 79 Ref).  Andersen narrows `templatename` to three rows but the retained
escape/completeness fact still prevents every rewriting disposition.  Enabling
`PANGS_ANDERSEN_RECEIVER_PAYLOADS` changes none of these facts or dispositions.

## 2. Part 0: resolve a constant format through a zero-offset GEP

### 2.1 Change

In `constant_format_bytes`, follow a GEP as well as an assign.  When the statement that
defines the operand is a `Stmt::Gep`, recurse on its base.  The existing
`direct_constant_format_bytes` then decodes `@.str.139` normally, because that global is
`is_const` and carries an `initializer_ir` byte string.

Keep every other rule fail-closed:

- a non-zero `byte_off` must decode the string from that offset, or return unknown;
- a base that is not a constant global with a decodable initializer returns unknown;
- a load, a cycle, or any other producer returns unknown, as today;
- several possible strings must all be `%n`-free, as today.

### 2.2 Why it is worth doing first

It is a few lines, and it is a precondition for two separate results:

- `is_benign` can accept `ErrorMsg` at its 49 callsites, removing 49 of Lemon's 59
  `vararg_call_boundary` seeds without any new proof machinery;
- the `Printf` policy sharpens pointer variadic actuals to read-only, which removes
  `templatename`'s only Mod row and makes `written` false.  Without this, §8.2's expected
  `immutable` is unreachable even if Parts A, B and C all succeed.

### 2.3 Risk and required measurement

This change makes an existing conservative answer sharper, so it can only remove Mod rows.
That is a soundness-relevant direction: the `%n` check is the only guard.  Part 0 therefore
requires the whole-corpus before/after of §8.3 on its own, not bundled with later parts.
Any Mod row that *appears* is a defect.  Fixtures must cover a constant `%n` format, a
`select`/`phi` between two constants where one contains `%n`, a non-zero offset into a
constant string, a GEP whose base is a mutable global, and a format loaded from memory.

## 3. Part A: lower `va_start`/`va_end` without an escape seed

### 3.1 Rationale

LLVM's `llvm.va_start` and `llvm.va_end` intrinsics operate on caller-provided `va_list`
storage.  They do not publish that storage to an unknown external agent.  Treating their sole
operand like an arbitrary `Stmt::Unknown` operand therefore invents an address escape.

This correction does **not** make an unmodeled variadic call safe.  The separate
`VarargCallBoundary` on pointer-valued tail actuals remains until Part C proves a callee
summary.  Unknown `va_arg` lowering, `va_copy`, unfamiliar target ABIs, escaped list aliases,
and calls through an unresolved variadic function pointer also retain their current fallback.

### 3.2 Representation

Add explicit PIR statements (or an equivalently explicit side table):

```text
VaStart { list, loc }
VaEnd   { list, loc }
```

The PAG treatment is local:

- `VaStart` records a write to the `va_list` storage so mutation clients do not lose a real
  memory effect;
- `VaEnd` may record a read/write of that same local storage conservatively;
- an unproved consumer gives the list's *contents* an opaque `VarArgPayload` region, so a
  pointer extracted from the list can still designate external or caller-owned memory;
- neither statement emits `UnknownOperandEscape`;
- neither statement publishes the list object's own address to Ω; and
- an unrecognized use of the list still emits the existing unknown seed.

The distinction between the list address and its contents is load-bearing.  Simply deleting the
current unknown seed would be unsound: a later unrecognized `va_arg` load could otherwise look
empty.  In the fallback path, stores through an opaque tail pointer must still affect unknown
memory, and the callsite's existing `VarargCallBoundary` must still conservatively cover each
pointer-valued actual.  Part C may replace both pieces only after it proves the actual effects.

Do this independently of positional-`va_arg` recognition.  Positional recognition may add
more precise `Stmt::VarArg` values, but failure to recognize a consumer is not evidence that
the intrinsic itself captures its operand.  Keep the two paths consistent: today the
positional path drops `va_start`/`va_end` entirely and records no write to the list, so decide
once whether both paths record that write and apply the same rule to each.

### 3.3 The payload region must be closed under load

`VarArgPayload` must be an external region that contains itself, so that any number of loads
through it still yields the region.

This is not a theoretical requirement.  On x86-64 a pointer `va_arg` is two levels: load
`overflow_arg_area` or `reg_save_area` out of the list, then load the value out of that.  In
Lemon the extraction also crosses a function: `lemon_sprintf` passes `&ap` to
`lemon_vsprintf` as an ordinary pointer argument, and `lemon_vsprintf` performs 36 GEPs and
25 loads on the list.  If the region covered only the list's own fields, the second load would
return an empty set and a later store through that pointer would become a no-op — a missed
Mod, which is corruption, not coverage loss.

### 3.4 The boundary predicate keys on the statements being removed

`direct_vararg_call_requires_boundary` ends with

```rust
func.external || (!self.positional_vararg_functions.contains(callee)
                  && func.body.iter().any(stmt_consumes_varargs))
```

and `stmt_consumes_varargs` is true only for `Stmt::VarArg` or an `Unknown` whose reason is
`varargs_intrinsic`.  `lemon_sprintf`'s entire body is `alloca, gep, assign,
unknown(va_start), unknown(va_end), call_direct, return`: the two intrinsic statements are the
*only* evidence that it consumes varargs.

If Part A replaces them without updating this predicate, every un-proved internal consumer
silently stops getting a `VarargCallBoundary`.  That fails open.

*This happened.*  The `pangs-pag` copy was updated with the representation, but the second
copy in `pangs-api` was not, and Lemon's audit findings silently fell from 39 to 0 — the
seeds were still emitted, but every `fnptr_varargs_internal_unmodeled` finding disappeared,
and with it one global's `violation_taint`.  The two copies are now one shared
`pangs_pag::stmt_consumes_varargs`.

Required in the same change:

- add the new statement kinds to `stmt_consumes_varargs`;
- merge its two copies — it exists in `crates/pangs-pag/src/lib.rs` and again in
  `crates/pangs-api/src/lib.rs`.  §6 asks for one shared resolver; this predicate belongs in
  the same shared place;
- add a fixture asserting that the `VarargCallBoundary` seed count for an un-proved consumer is
  unchanged across Part A.

### 3.5 Expected effect on Lemon: none

Part A on its own should change no `templatename` fact.  The address also escapes through the
`lemon_sprintf` callsite boundary, so `omega_escaped_address` and `access_set_complete` stay
as they are and only the reported witness text changes.  The Part A gate is therefore the seed
counts, not the fact vector.  Record it that way so the row is not read as a failure.

Code anchors:

- `crates/pangs-pir/src/llvm_sys.rs`: the `callee.starts_with("llvm.va_")` lowering branch;
- `crates/pangs-pir/src/lib.rs`: `Stmt` and input-operand visitors;
- `crates/pangs-pag/src/lib.rs`: `Stmt::Unknown` seeding and `stmt_consumes_varargs`;
- `crates/pangs-api/src/lib.rs`: vararg audit collection.

### 3.6 Soundness fixtures

- canonical local `va_start`/`va_end`, no tail use: no `UnknownOperandEscape` for the list;
- same function with a pointer tail and no proved callee summary: the callsite still has a
  `VarargCallBoundary`;
- two-level extraction — load an area pointer from the list, load a pointer from that, store
  through it: the store is still a Mod against unknown memory;
- `va_copy`, list stored in memory, list returned, list passed to an uncontracted helper, and
  noncanonical intrinsic operand: retain an unknown boundary;
- a real store through a pointer obtained from `va_arg` remains a Mod and prevents a read-only
  summary in Part C.

## 4. Part B: add the POSIX `access` contract

Add this exact-name contract to `crates/pangs-pir/src/lib.rs`:

```text
name          access
fixed params  2
vararg        false
result        Scalar
effects       Read(0)
capture       None
callback      None (implicit in presence in the table)
```

The shape was checked against the module: `access` lowers to
`sig { ret: integer, params: [integer, integer], vararg: false, cc: "ccc" }`, which satisfies
`ExternalCallContract::matches_signature`, so `contract(2, false, Result::Scalar, R0)` drops
straight into the table.

It is the ordinary synchronous POSIX contract: the pathname is read during the call and is
not retained.  As with all entries in the shared table, require an external declaration, the
exact `ccc` ABI shape, and the expected result.  A module-defined replacement, wrong ABI,
indirect call, alias with an unrecognized symbol name, or interposition outside the project's
standard-library assumption fails closed.

Regression tests must cover both consumers of the shared table:

- PAG: a global pathname passed to the exact declaration gets a modeled Ref but no external
  escape; a replacement definition and signature mismatch retain the boundary;
- certificates: the same call does not set `access_set_complete = false`, while a call to an
  unlisted pathname consumer does;
- a write through the pathname before or after the call is still observed normally.

This is independently worthwhile, but it is not expected to solve Lemon by itself because
`templatename` is also a pointer-valued actual at an internal `lemon_sprintf` call, reached
through `pathsearch`.

## 5. Part C: contracts for closed internal variadic consumers

### 5.1 Measured population

Internal variadic functions, counted from `pangs dump-pir` over eight `-O0` modules on
2026-09-05.  "Reaches a `v*` sink" is by direct callee name and is an upper bound on what a
proof would accept; "consumes the list itself" means the body has `va_start`/`va_end` and no
`v*` callee at all.

| module | internal vararg fns | reaches a `v*` sink | consumes the list itself |
|---|---:|---:|---:|
| `exe-lemon-O0` | 2 | 1 (`vfprintf`) | 1 |
| `exe-gifsicle-O0` | 10 | 6 (`verror`, `vfprintf`) | 4 |
| `exe-chibicc-O0` | 6 | 6 (`vfprintf`, `verror_at`) | 0 |
| `exe-jq-O0` | 5 | 1 (`vsnprintf`) | 3 |
| `exe-lua-O0` | 5 | 0 | 5 |
| `exe-tmux-O0` | 26 | 2 (`vasprintf`, `vsnprintf`) | 24 |
| `exe-tree-O0` | 1 | 0 | 0 |
| `lib-fribidi-O0` | 0 | 0 | 0 |

Two readings.  The self-consuming family is the dominant one — about 38 functions in six
modules — so an inference engine has a real population and is not a one-program fix.  And the
`v*` sinks in use are not only `vfprintf`: `vsnprintf`, `vasprintf`, `verror`, and
`verror_at` all appear, while `forwarding_call_arg_indexes` accepts only the literal name
`vfprintf` with exactly three arguments.

The tmux column is understated: 8 of its 24 self-consuming functions are currently short-cut
by the name allowlist of §6, so they never reach a proof at all.

### 5.2 Part C1: extend the existing forwarder proof

Two changes, both inside the existing structure.

First, accept the other standard `v*` sinks.  Give each one a table entry recording its format
parameter index and its `va_list` parameter index, and read the sink contract from that table
instead of the hard-coded `vfprintf`/arity-3 test.

Second, allow the forwarding chain to end at an *internal* fixed-argument consumer whose
`va_list` parameter is proved read-only, instead of requiring an external `v*` terminal.  The
proof already recurses through internal fixed forwarders such as gifsicle's `verror` and
chibicc's `verror_at`; the missing piece is a terminal rule for a function that actually reads
the list.  Use the tail-provenance analysis of §5.3 for that one function only.

C1 covers Lemon: `lemon_sprintf` forwards its list to `lemon_vsprintf`, which is the same
shape as the existing internal-forwarder recursion with an internal terminal in place of
`vfprintf`.  No general effect engine is needed for the stated target.

A body proof also removes the `%n` coupling: when the effect is established inside the callee,
the callsite format need not be constant.  Keep the callsite constant-format check only for
the true external `vfprintf`-family case, where the tail may contain `%n`.

### 5.3 Part C2: the general summary

Build this only if the census of §7 shows a large residue after C1.

Generalize from the special result "safe `%n`-free `vfprintf` forwarder" to a small
function-effect summary:

```text
InternalVarargSummary {
    fixed_effects: [None | Read | Write | ReadWrite],
    tail_pointer_effect: None | Read | Write | ReadWrite,
    result: Void | Scalar | AliasFixedArg(i),
    captures_fixed: bitset,
    captures_tail: bool,
    invokes_fixed_or_tail: bool,
}
```

Initially accept only summaries with no capture and no callback invocation.  The first useful
tail policy is `Read`: it is conservative for a formatter that may ignore some actuals but
never writes through or retains a pointer tail value.

The summary is a property of the visible internal definition.  It is not keyed by source
name.  Cache it per function in the existing proof context and use it at every direct
callsite whose fixed arity and ABI match.  Address-taken callees and callees with unknown
incoming callers may still be summarized for the effects of known direct calls, but the
summary must never be used to claim that their entire function boundary is closed.

**Summary proof.**  Introduce a summary-only representation of "some pointer value extracted
from this `va_list`".  It need not bind a dynamic `va_arg` to an exact callsite position.
Recognize canonical target-specific loads rooted in a matched `va_start` list, including
multiple loads and loads in loops, and give every pointer-valued result one shared
`VarArgTail` provenance.

Provenance is transitive, and this is a soundness requirement, not a precision choice.  A
value loaded through a tail-derived pointer is itself tail-derived.  Otherwise a callee could
load a pointer out of tail-reachable memory and store it into a global without any terminal
rule seeing it.  `Read` therefore means "reads memory reachable from the tail pointer and
captures nothing reachable from it".

Propagate that provenance through assignments, GEPs, loads, and calls to already summarized
internal helpers.  Use the shared external-call table for leaf calls.  Classify every
terminal:

- a load through a tail-derived pointer or a `Read(i)` external argument contributes `Read`;
- a store/memset destination or `Write(i)` argument contributes `Write`;
- storing a tail-derived value into nonlocal memory, returning it, passing it to an
  uncontracted call, `ptrtoint`, inline assembly, or an unknown operation contributes
  `Capture/Unknown` and rejects the summary;
- using it as an indirect-call operand or as a callback argument rejects the summary;
- `va_copy`, unmatched roots, multiple ambiguously related lists, unknown list-derived uses,
  recursion without a quiescent summary, or a resource-limit hit rejects the summary.

Analyze fixed pointer parameters in the same pass.  For Lemon the expected summary is:

```text
lemon_vsprintf(str, format, ap): Write(str), Read(format), Read(vararg-tail), no capture
lemon_sprintf(str, format, ...):  Write(str), Read(format), Read(vararg-tail), no capture
```

The proof should discover that tail strings reach `lemon_addtext` and then only the source
side of `memcpy`; it should also see that no branch implements `%n`.

### 5.4 The callee body after the boundary is removed

Removing a callsite `VarargCallBoundary` does not remove the callee's own accesses.  The body
still loads through the opaque `VarArgPayload` region of Part A.  `access_set_failure` fails a
global when a module-wide ModRef row names it, so a retained payload read that widens to a
module-wide row would clear the escape and still leave `access_set_complete = false`.

Verify this explicitly: after Part C, no new module-wide ModRef row may appear, and the
Lemon gate must check `access_set_complete` and not only `omega_escaped_address`.

## 6. One shared result, and the existing name allowlist

### 6.1 One resolver

Avoid another PAG/certificate split.  Define one resolver, adjacent to the external contract
resolver, which returns either a proved external contract or a proved internal-vararg summary
for a concrete callsite.  Both of these paths must consume it:

- PAG construction: replace `VarargCallBoundary` with the summary's explicit Read/Write
  memory edges and do not add capture/Ω flow;
- API audit and certificate assembly: suppress
  `fnptr_varargs_internal_unmodeled` for exactly the same callsites and use the same effects
  when computing mutation, completeness, and access sites.

The resolver should carry a stable proof-kind/rejection-reason enum for diagnostics.  Do not
re-run a similar but independent recognizer in `pangs-api`.  The duplicated
`stmt_consumes_varargs` of §3.4 moves here too.

### 6.2 Retire `is_known_benign_vararg_callee`

`is_known_benign_vararg_callee` returns benign for 21 hard-coded names — `log_debug`,
`cmdq_error`, `cmdq_print`, `fatalx`, `xasprintf`, `xsnprintf`, `format_add`, `cfg_add_cause`,
`curl_mprintf`, and others — and `is_benign` checks it *before* any proof.  It appears in no
design document and in no audit ledger entry.

This is exactly the unrecorded name allowlist that §7 forbids for future work.  It also hides
the population Part C serves, because 8 of tmux's 24 self-consuming variadic functions never
reach a proof.

Required:

- run the census of §7 with the allowlist disabled, so its numbers describe the real residue;
- delete the allowlist as an acceptance criterion of Part C, once C1/C2 subsume the shapes it
  covers;
- until then, record it in the manifest/audit ledger as a named supported-program assumption,
  so it is visible where every other such assumption is.

## 7. Narrow census before changing policy

Do not restore the removed broad `external-policy-census`.  Add a narrow, temporary or
diagnostic-only `vararg-contract-census` built from PIR plus the final solve.  It should not
change analysis state and should emit one JSONL row per internal variadic callee and one per
callsite with:

- module, function, source location, linkage/export/address-taken status;
- direct/indirect and known/unknown caller counts;
- fixed arity, callsite actual count, and pointer-valued tail positions;
- number of `va_start`, `va_end`, `va_copy`, recognized pointer `va_arg` loads, and unknown
  list-derived operations;
- **which `v*` sink the forwarding chain reaches, and whether that sink is internal or
  external** — this separates C1's population from C2's;
- **whether the callsite format operand was constant-decodable, and by which producer shape**
  — this column would have exposed §1.1 immediately, and is worth keeping permanently;
- existing proof result and an enumerated rejection reason;
- proposed effect summary or the first rejecting terminal;
- constant-format status and `%n` status where the `vfprintf` proof is relevant;
- current `VarargCallBoundary` and `UnknownOperandEscape` seed counts;
- globals reached from those seeds, split into `omega_escaped_address`,
  `access_set_complete=false`, violation-tainted, and finally unhandled;
- disposition transitions under four ablations: Part 0 alone, plus local-intrinsic modeling,
  plus external contracts, plus proved internal summaries.

The seed-to-global attribution should reuse `external_sources`/universal-source provenance;
do not infer impact by globally subtracting aggregate row counts.  Cap retained samples but
emit exact counts.

Run it over all corpus modules.  The questions to answer are:

1. After Part 0, how many intended `vfprintf` forwarders are accepted, and why are any still
   rejected?
2. How many callees are closed read-only-tail consumers like `lemon_sprintf`, and how many of
   those are reached by C1's internal-terminal rule alone?
3. How many contain a real tail-pointer write, capture, callback, unknown call, or `va_copy`?
4. How many globals and unhandled dispositions are reachable only from local
   `va_start`/`va_end` seeds?
5. Does C1 leave a residue large enough to justify C2, or is a user-supplied audited
   contract file a better cost/benefit tradeoff for the remainder?

If only Lemon qualifies beyond C1, retain Parts 0, A, B and C1 and consider an explicit,
hashed `--call-contracts` input instead of a large general inference engine.  Such a file is a
supported-program assumption and must appear in the manifest/audit ledger; it must not be an
unrecorded name allowlist.

## 8. Evaluation and acceptance

### 8.1 Fixtures

In addition to the Part 0/A/B tests above, add internal-vararg fixtures for:

- read-only pointer tail through an internal helper: summary accepted;
- store through a tail pointer (`%n`-like): summary records Write or rejects Read;
- tail pointer stored in a global/heap object: reject;
- pointer *loaded through* a tail pointer and then stored in a global: reject (the §5.3
  transitivity rule);
- tail pointer invoked as a callback: reject;
- dynamic `vfprintf` format and constant `%n`: retain boundary;
- constant `%s` `vfprintf` wrapper reached through a zero-offset GEP: existing proof accepted
  (this is the Part 0 regression);
- `va_copy`, two lists, unmatched `va_end`, escaped list, indirect helper, and recursive helper:
  reject;
- wrong callsite arity/ABI and module-defined replacement for `access`: retain boundary.

For every accepted fixture, assert both PAG seeds/effects and final certificate facts.  Include
the existing external-result soundness fixture (`&g` passed out, later store through an external
result) to ensure that the new resolver has not recreated the certificate/PAG disagreement.

### 8.2 Lemon gates

After each part, rerun the exact baseline command and record independently:

```text
templatename:
  UnknownOperandEscape sources
  VarargCallBoundary sources
  omega_escaped_address
  access_set_complete
  never_written / written witness
  named Mod/Ref rows and functions
  localization verdict
  chosen disposition
```

Expected result per part:

| part | expected change | measured |
|---|---|---|
| 0 | `VarargCallBoundary` 59 → 10 (the 49 `ErrorMsg` sites); Mod row gone; escape and `access_set_complete` unchanged | as expected |
| A | `UnknownOperandEscape` 4 → 0; seed and fact vector otherwise unchanged; witness text changes only | as expected (`vararg_list_payload` 2 seeds added) |
| B | the `access` call becomes a modeled Ref; escape still held by the `lemon_sprintf` sites | as expected (`external_call_boundary` 41 → 37) |
| C | `omega_escaped_address=false`, `access_set_complete=true`, no new module-wide ModRef row, `chosen = immutable` | as expected |

One correction to an earlier draft of this table: Part 0 removes the false Mod row, but
`written` stays true until the escape clears.  `written` is `runtime_written ∨ escape ==
External`, because external storage is may-written whether or not a store is visible.  So
`written = false` arrives with Part C, not with Part 0.

`localize` is still a precision gain if a real write remains, but the source review predicts
immutable.  Note that `immutable` depends on Part 0 as well as Part C: without Part 0 the
`fprintf` Mod row keeps `written` true and the best reachable disposition is `localize`.

Also check `translate_code.newlinestr_xjtr_0` after each part; it shares the selected
`lemon_sprintf` witness and may become localizable even if its write proof remains coarse.

### 8.3 Whole corpus gates

- `cargo test --workspace --all-targets` and complete export validation;
- conservative → Steensgaard → Andersen differential checks for every changed module;
- before/after counts for all Ω seed kinds, unknown and module-wide ModRef rows, named Mod/Ref
  rows, `access_set_complete`, violation taint, and disposition distribution;
- Part 0 is measured on its own, before Parts A–C, because it touches every printf-family
  callsite in the corpus and not only variadic wrappers.  Mod rows may only decrease; any new
  Mod row is a defect;
- wall time, peak RSS, Steensgaard worklist/content ratios, Andersen steps, and partition
  metrics;
- source review for every disposition transition enabled by an inferred internal contract;
- no transition is accepted if the proof has hidden an uncontracted write, capture, callback,
  `%n`, or unknown list use.

Promote only the prove-then-replace path.  Rejection and resource exhaustion must be identical
to today's conservative boundary.

## 9. Implementation results (2026-09-05)

### 9.1 What shipped

| Part | Change | Files |
|---|---|---|
| 0 | `constant_format_bytes` follows a constant-offset GEP to the string it names. A dynamic lane, an unknown offset, a mutable base and an offset past the decoded string all fail closed. | `pangs-pag/src/lib.rs` |
| A | `Stmt::VaStart` / `Stmt::VaEnd` replace the opaque `Unknown` spelling. The PAG records the write (and `va_end`'s read) of the list, and seeds a new `VarargListPayload` Ω kind on the list address when the consumer is not positionally proved. Andersen turns that into a `VarargPayload` external region, Steensgaard marks the pointee class external. Neither marks the list address escaped. | `pangs-pir`, `pangs-pag`, `pangs-solve`, `pangs-api` |
| B | `access` added to the shared external-call contract table as `Read(0)`. | `pangs-pir/src/lib.rs` |
| C1 | A read-only tail audit proved from the callee's body, plus a table of standard `v*printf` sinks in place of the hard-coded `vfprintf` test. | `pangs-pag/src/lib.rs` |
| C1 | §4.3's other half: where a proof replaces the boundary, the callsite now carries an explicit modeled read edge for every pointer-capable tail actual, instead of the effect simply disappearing from mod/ref. | `pangs-pag/src/lib.rs` |
| §6.2 | `is_known_benign_vararg_callee` — the 21-name allowlist — is deleted. | `pangs-pag/src/lib.rs` |
| §3.4/§6.1 | The duplicated `stmt_consumes_varargs` is now one shared `pangs_pag::stmt_consumes_varargs`. | `pangs-pag`, `pangs-api` |

The C1 audit is one function-level analysis with two entry shapes: a variadic function's own
`va_start` list, or a fixed-argument function's `va_list` parameter. It tracks two sets — values
that name the list, and pointers extracted from it — and requires every extracted pointer to be
read and nothing else. It follows internal direct calls by re-entering the callee with the
argument positions that carry a list or a tail pointer, caches each state, rejects recursion,
and stops at a fixed budget of states. A value LLVM proved non-pointer never enters the tail
set, which is what lets an ordinary `%d` or `%.*s` conversion read integers out of the list
without rejecting the function.

### 9.2 Lemon gate

Every expected transition in §8.2 was measured. Final state:

```text
tplt_open.templatename_xjtr_0   immutable   written=false esc=false access_set_complete=true
translate_code.newlinestr_xjtr_0 localize   written=true  esc=false access_set_complete=true
```

Ω seeds, baseline → final: `vararg_call_boundary` 59 → 0, `unknown_operand_escape` 4 → 0,
`external_call_boundary` 41 → 37, `vararg_list_payload` 0 → 2. Audit findings 39 → 0.

The `immutable` verdict was checked against the source, as §8.3 requires. The audit accepts
`lemon_sprintf` because it forwards its list to `lemon_vsprintf`, whose extracted `%s` pointers
(`tmp21`, `tmp34`) reach only `lemon_addtext`, where the parameter is GEP'd, loaded one byte at
a time, and used as a `memcpy` **source**. Nothing writes through it or retains it. The
integer conversions (`tmp13`, `tmp28`, 4-byte loads) never enter the tail set because LLVM
proved them non-pointer. `static char templatename[] = "lempar.c"` is read-only in the source.

### 9.3 Three holes found while implementing C1

All three were found by self-review, not by a failing test, and all now have fixtures:

- **A positionally recognized `va_arg` result is a tail pointer with no load to see.** The
  audit seeded the tail set only from loads through the list, so a `Stmt::VarArg` result could
  be stored into a global unaudited. Every `Stmt::VarArg` destination is now a tail seed.
- **A phi joining the list address with a pointer read out of it lands in both sets**, and the
  list rules are the weaker of the two (a store through the list address is legitimate ABI
  bookkeeping; a store through a tail pointer is not). Such a value now fails the audit closed.
- **Dropping the boundary dropped the read with it.** §4.3 says a proof replaces the boundary
  with the summary's explicit memory edges; the first implementation dropped the seed and added
  nothing, so a callee that reads a global through its variadic tail produced no mod/ref row at
  all — less complete than the boundary it replaced. A proved callsite now emits a modeled read
  edge per pointer-capable tail actual, the same shape an external `Read(i)` contract uses.
  This is a *reason for `ref` rows to increase* in the corpus gate below; `mod` rows may still
  only decrease.

### 9.4 Deleting the name allowlist

The allowlist was asserting an unproved fact, and deleting it moves in the fail-closed
direction. Measured on the two modules it covered:

| module | `fnptr_varargs_internal_unmodeled` with allowlist | without | disposition change |
|---|---:|---:|---|
| `exe-tmux-O0` | 16 | 64 | one global `immutable` → `localize` |
| `exe-curl-O0` | 474 | 767 | none |

The single tmux global loses an `immutable` claim it never had evidence for: the allowlist had
hidden a possible write through a variadic tail. `localize` is still a rewriting disposition,
so the cost is one strategy step, not a lost global. Modules that use none of those names are
unchanged.

### 9.5 What remains

- **C2, the general summary** (`InternalVarargSummary` with `fixed_effects`, `result`,
  `captures_*`): not built. C1 covers the read-only-tail question, which is all the callsite
  boundary needs. C2 becomes worthwhile if the census shows a large residue of callees that
  write through a tail pointer in a bounded, describable way.
- **The `vararg-contract-census` of §7**: not built. The corpus gate in §9.6 answers the
  aggregate questions, but not per-callee rejection reasons. The audit already computes a
  decisive rejecting statement internally; exposing it as a stable enum is the next step and is
  what the census rows need.
- **External contracts for the `v*printf` family**: `vfprintf`, `vsnprintf` and friends are
  recognized as forwarding sinks but still have no entry in the external-call contract table,
  so a call to one remains an ordinary Ω boundary that escapes its own arguments. Adding those
  contracts is independent of this plan and would sharpen wrappers that write into a caller
  buffer.
- **`Stmt::VarArg` in a function that positional recognition lowered but PAG-level admission
  rejected** still produces a value with no incoming edges. That predates this work and is
  unrelated to the `va_list` payload, but it is the same class of question and deserves its own
  check.

### 9.6 Whole-corpus gate

59 `-O0`/`-O1` modules, executable or library mode by name, `--stage andersen --dispose
--no-overrides`. `lib-openssl-4.1.0-O1` timed out in the Part 0 sweep under CPU contention
(it completes when run alone), so the Part 0 comparison is over the 58 modules that completed
in both runs.

**Part 0 measured on its own**, as §2.3 requires:

| metric | base → Part 0 |
|---|---|
| `immutable` | +101 |
| `unhandled` | −98 |
| `once-lock` / `mutex` | +2 / −2 |
| `localize` | −3 (each to `immutable`) |
| `access_set_complete` true | +98 |
| `omega_escaped_address` true | −98 |
| `written` true | −100 |
| `violation_taint` true | −125 |
| `fnptr_varargs_internal_unmodeled` findings | −405 |
| `mod` rows (aliased / unknown) | −633 / −1131 |
| `ref` rows | unchanged |

The gate it had to pass — **no `mod` row increased in any module, and `unhandled` grew in no
module** — holds on all 58. The largest single effect is `exe-chibicc-O0`/`-O1`, where 49
globals per module move `unhandled` → `immutable`: their only apparent write was a `%s` actual
at a `fprintf` whose constant format the resolver could not read.

Two modules move `mutex` → `once-lock` (`exe-OMP__tree-O0`, `exe-tree-O0`): removing a
spurious write let phase stationarity certify, and the cascade prefers the stronger property.

**All parts together**, same 58 modules:

| metric | base → final | note |
|---|---|---|
| `immutable` | +101 | |
| `unhandled` | −101 | |
| `once-lock` / `mutex` | +2 / −2 | |
| `localize` | ±0 | one gained (tmux), one lost to `immutable` (apg_bore) |
| `access_set_complete` true | +102 | |
| `omega_escaped_address` true | −102 | |
| `written` true | −102 | |
| `violation_taint` true | −120 | |
| `mod` rows (aliased / unknown) | −633 / −1187 | no module increased any `mod` row |
| `ref` rows (aliased / unknown) | +310 / +1609 | the modeled reads of §9.3 |
| `fnptr_varargs_internal_unmodeled` | +251 | curl and tmux only; every other module fell |
| `fnptr_varargs_external` | +127 | curl only |

`ref` rows rise for the reason §9.3 gives: a proof now records the read it proved instead of
letting it vanish with the boundary. `mod` rows fall and never rise, which is the gate that
matters. The audit-finding rise is entirely the allowlist deletion — outside curl and tmux
every module's finding count went down, led by `exe-vim-9.2-O1` (−76) and `exe-chibicc-O1`
(−64).

**Two dispositions regressed, both from deleting the allowlist, both fail-closed:**

- `exe-curl-O1`, `curl/src/tool_getparam.c::opt_filestring.redir_protos`: `immutable` →
  `unhandled`. A `curl_mprintf` callsite in `tool_version_info` is a variadic boundary again,
  and its access-shape-relevant taint gates the four access-property strategies. The
  `immutable` claim rested on a hard-coded name, not on evidence.
- `exe-tmux-O0`, one global: `immutable` → `localize`, for the same reason. `localize` is
  still a rewriting disposition, so that one costs a strategy step rather than the global.

Net across the corpus this is +101 `immutable` against those two, and every fact that moved in
the conservative direction moved because a name-based assumption was withdrawn.

### 9.7 Differential ledger

`pangs differential` (conservative → Steensgaard → Andersen) over all 59 modules, baseline
binary against final binary: **identical on every module.** Four modules report a nonzero
count in *both* runs — `exe-jq-O0`/`-O1` (1) and `exe-lemon-O0`/`-nostatic-O0` (5) — and those
are pre-existing coverage differences (`unknown_callers: match_at`; Steensgaard listing
rewritable globals Andersen does not). No monotonicity break was introduced.

`check-pag` reports the same 27 pre-existing `addr_of` complaints on Lemon before and after
(the glibc ctype-table model, unrelated to this work), and `--validate` export validation
passes.
