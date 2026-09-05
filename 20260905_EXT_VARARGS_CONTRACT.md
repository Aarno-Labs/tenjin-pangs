# External and internal varargs contracts: fixing Lemon `templatename`

## 0. Status and goal

Proposal, not implemented.  The immediate target is
`tplt_open.templatename_xjtr_0` in `exe-lemon-O0`.  On the 2026-09-05 working tree, a
validated executable-mode Andersen run chooses `unhandled` for this global even though the
source object is the fixed string `"lempar.c"` and all source uses are reads.

The proposed fix has three parts, in increasing order of effort:

1. model `llvm.va_start` and `llvm.va_end` as local `va_list` operations, not unknown
   pointer escapes;
2. add the standard `access(const char *, int)` call to the shared external-call contract
   table; and
3. infer a conservative read/write/capture summary for closed internal variadic consumers
   such as Lemon's `lemon_sprintf`, then use that one summary in both PAG construction and
   certificate/audit assembly.

Every failed proof keeps today's boundary.  There is no name-based exemption for
`lemon_sprintf`, no global-specific exception for `templatename`, and no weakening of
`access_set_complete`.

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
`llvm.va_end`; it is not the address of `templatename`.  The current closure joins the
unknown intrinsic boundary to pointer-valued variadic actuals and eventually to
`templatename`.

Lemon contains two internal variadic functions:

| Function | Direct calls | Shape |
|---|---:|---|
| `ErrorMsg` | 49 | local `va_list` forwarded once to `vfprintf` |
| `lemon_sprintf_xjtr_0` | 10 | local `va_list` forwarded to an internal formatter which consumes `%d`, `%s`, and `%.*s` |

The PAG currently emits 59 `vararg_call_boundary` seeds and four
`unknown_operand_escape` seeds for their two `va_start`/`va_end` pairs.  The existing
`VarargCallProof` was intended to recognize the `ErrorMsg`/`vfprintf` shape, so its failure
on Lemon should first be exposed as a reasoned rejection and fixed if it is an implementation
gap.  `lemon_sprintf` is outside that proof because it consumes the list itself.

The source uses of `templatename` are at `lemon_unstatic.c:3644-3684`: `access`,
`pathsearch`, and formatted diagnostic output.  `pathsearch` calls `strlen(name)` and passes
`name` as a `%s` input to `lemon_sprintf`.  None retains or writes it.  The current single
Mod row is attributed through the `fprintf` at the error path, not through a source store to
the array.

As a useful differential, Steensgaard assigns both Lemon arrays 137 named rows in 88
functions (58 Mod, 79 Ref).  Andersen narrows `templatename` to three rows but the retained
escape/completeness fact still prevents every rewriting disposition.  Enabling
`PANGS_ANDERSEN_RECEIVER_PAYLOADS` changes none of these facts or dispositions.

## 2. Part A: lower `va_start`/`va_end` without an escape seed

### 2.1 Rationale

LLVM's `llvm.va_start` and `llvm.va_end` intrinsics operate on caller-provided `va_list`
storage.  They do not publish that storage to an unknown external agent.  Treating their sole
operand like an arbitrary `Stmt::Unknown` operand therefore invents an address escape.

This correction does **not** make an unmodeled variadic call safe.  The separate
`VarargCallBoundary` on pointer-valued tail actuals remains until Part C proves a callee
summary.  Unknown `va_arg` lowering, `va_copy`, unfamiliar target ABIs, escaped list aliases,
and calls through an unresolved variadic function pointer also retain their current fallback.

### 2.2 Representation

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
the intrinsic itself captures its operand.

Code anchors:

- `crates/pangs-pir/src/llvm_sys.rs`: the `callee.starts_with("llvm.va_")` lowering branch;
- `crates/pangs-pir/src/lib.rs`: `Stmt` and input-operand visitors;
- `crates/pangs-pag/src/lib.rs`: `Stmt::Unknown` seeding and `stmt_consumes_varargs`;
- `crates/pangs-api/src/lib.rs`: vararg audit collection.

### 2.3 Soundness fixtures

- canonical local `va_start`/`va_end`, no tail use: no `UnknownOperandEscape` for the list;
- same function with a pointer tail and no proved callee summary: the callsite still has a
  `VarargCallBoundary`;
- `va_copy`, list stored in memory, list returned, list passed to an uncontracted helper, and
  noncanonical intrinsic operand: retain an unknown boundary;
- a real store through a pointer obtained from `va_arg` remains a Mod and prevents a read-only
  summary in Part C.

## 3. Part B: add the POSIX `access` contract

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
`templatename` is also a pointer-valued actual at an internal `lemon_sprintf` call.

## 4. Part C: inferred contract for a closed internal variadic consumer

### 4.1 Contract domain

Generalize the existing `VarargCallProof` from the special result “safe `%n`-free
`vfprintf` forwarder” to a small function-effect summary:

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

### 4.2 Summary proof

Introduce a summary-only representation of “some pointer value extracted from this
`va_list`”.  It need not bind a dynamic `va_arg` to an exact callsite position.  Recognize
canonical target-specific loads rooted in a matched `va_start` list, including multiple
loads and loads in loops, and give every pointer-valued result one shared `VarArgTail`
provenance.

Propagate that provenance through assignments, GEPs, and calls to already summarized internal
helpers.  Use the shared external-call table for leaf calls.  Classify every terminal:

- a load through a tail-derived pointer or a `Read(i)` external argument contributes `Read`;
- a store/memset destination or `Write(i)` argument contributes `Write`;
- storing the pointer value into nonlocal memory, returning it, passing it to an uncontracted
  call, `ptrtoint`, inline assembly, or an unknown operation contributes `Capture/Unknown` and
  rejects the summary;
- using it as an indirect-call operand or as a callback argument rejects the summary;
- `va_copy`, unmatched roots, multiple ambiguously related lists, unknown list-derived uses,
  recursion without a quiescent summary, or a resource-limit hit rejects the summary.

Analyze fixed pointer parameters in the same pass.  For Lemon the expected summary is:

```text
lemon_vsprintf(str, format, ap): Write(str), Read(format), Read(vararg-tail), no capture
lemon_sprintf(str, format, ...):  Write(str), Read(format), Read(vararg-tail), no capture
```

The proof should discover that tail strings reach `lemon_addtext` and then only the source
side of `memcpy`; it should also see that no branch implements `%n`.  Because the body proof
establishes the effect directly, callsite formats need not be constant for this summary.

Keep the existing callsite-sensitive `vfprintf` proof.  A `vfprintf` tail may contain `%n`,
so its wrapper is safe only when the actual format can be proved `%n`-free.  Before adding the
new summary engine, make that existing proof return a rejection reason and determine why
Lemon's structurally ordinary `ErrorMsg` wrapper is currently rejected.

### 4.3 One shared result

Avoid another PAG/certificate split.  Define one resolver, adjacent to the external contract
resolver, which returns either a proved external contract or a proved internal-vararg summary
for a concrete callsite.  Both of these paths must consume it:

- PAG construction: replace `VarargCallBoundary` with the summary's explicit Read/Write
  memory edges and do not add capture/Ω flow;
- API audit and certificate assembly: suppress
  `fnptr_varargs_internal_unmodeled` for exactly the same callsites and use the same effects
  when computing mutation, completeness, and access sites.

The resolver should carry a stable proof-kind/rejection-reason enum for diagnostics.  Do not
re-run a similar but independent recognizer in `pangs-api`.

## 5. Narrow census before changing policy

Do not restore the removed broad `external-policy-census`.  Add a narrow, temporary or
diagnostic-only `vararg-contract-census` built from PIR plus the final solve.  It should not
change analysis state and should emit one JSONL row per internal variadic callee and one per
callsite with:

- module, function, source location, linkage/export/address-taken status;
- direct/indirect and known/unknown caller counts;
- fixed arity, callsite actual count, and pointer-valued tail positions;
- number of `va_start`, `va_end`, `va_copy`, recognized pointer `va_arg` loads, and unknown
  list-derived operations;
- existing proof result and an enumerated rejection reason;
- proposed effect summary or the first rejecting terminal;
- constant-format status and `%n` status where the `vfprintf` proof is relevant;
- current `VarargCallBoundary` and `UnknownOperandEscape` seed counts;
- globals reached from those seeds, split into `omega_escaped_address`,
  `access_set_complete=false`, violation-tainted, and finally unhandled;
- disposition transitions under three ablations: local-intrinsic modeling only, plus external
  contracts, plus proved internal summaries.

The seed-to-global attribution should reuse `external_sources`/universal-source provenance;
do not infer impact by globally subtracting aggregate row counts.  Cap retained samples but
emit exact counts.

Run it over all corpus modules.  The questions to answer are:

1. How many internal variadic callees are already intended `vfprintf` forwarders, and why are
   any rejected?
2. How many are closed read-only-tail consumers like `lemon_sprintf`?
3. How many contain a real tail-pointer write, capture, callback, unknown call, or `va_copy`?
4. How many globals and unhandled dispositions are reachable only from local
   `va_start`/`va_end` seeds?
5. Does one inferred-summary shape cover more than Lemon, or is a user-supplied audited
   contract file a better cost/benefit tradeoff?

If only Lemon qualifies, retain Parts A and B and consider an explicit, hashed
`--call-contracts` input instead of a large general inference engine.  Such a file is a
supported-program assumption and must appear in the manifest/audit ledger; it must not be an
unrecorded name allowlist.

## 6. Evaluation and acceptance

### 6.1 Fixtures

In addition to the Part A/B tests, add internal-vararg fixtures for:

- read-only pointer tail through an internal helper: summary accepted;
- store through a tail pointer (`%n`-like): summary records Write or rejects Read;
- tail pointer stored in a global/heap object: reject;
- tail pointer invoked as a callback: reject;
- dynamic `vfprintf` format and constant `%n`: retain boundary;
- constant `%s` `vfprintf` wrapper: existing proof accepted;
- `va_copy`, two lists, unmatched `va_end`, escaped list, indirect helper, and recursive helper:
  reject;
- wrong callsite arity/ABI and module-defined replacement for `access`: retain boundary.

For every accepted fixture, assert both PAG seeds/effects and final certificate facts.  Include
the existing external-result soundness fixture (`&g` passed out, later store through an external
result) to ensure that the new resolver has not recreated the certificate/PAG disagreement.

### 6.2 Lemon gates

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

Expected final result: `omega_escaped_address=false`, `access_set_complete=true`, no aliased
Mod row, and `immutable`.  `localize` is still a precision gain if a real write remains, but
the source review predicts immutable.

Also check `translate_code.newlinestr_xjtr_0` after each part; it shares the selected
`lemon_sprintf` witness and may become localizable even if its write proof remains coarse.

### 6.3 Whole corpus gates

- `cargo test --workspace --all-targets` and complete export validation;
- conservative → Steensgaard → Andersen differential checks for every changed module;
- before/after counts for all Ω seed kinds, unknown and module-wide ModRef rows, named Mod/Ref
  rows, `access_set_complete`, violation taint, and disposition distribution;
- wall time, peak RSS, Steensgaard worklist/content ratios, Andersen steps, and partition
  metrics;
- source review for every disposition transition enabled by an inferred internal contract;
- no transition is accepted if the proof has hidden an uncontracted write, capture, callback,
  `%n`, or unknown list use.

Promote only the prove-then-replace path.  Rejection and resource exhaustion must be identical
to today's conservative boundary.
