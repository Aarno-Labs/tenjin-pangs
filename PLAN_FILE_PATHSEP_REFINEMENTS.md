# `file_pathsep` precision refinements

## Purpose

The OMP/tree disposition run leaves `file_pathsep` unhandled even though its
localization rewrite slice is closed. The immediate blocker is a
`fnptr_ptrtoint` audit at `pathconcat` (`util.nolines.i:3176`), whose affected
value is `%pathconcat::tmp16`, not `file_pathsep` itself.

The relevant source-level behavior is benign pointer arithmetic/comparison:

```c
p = pathnpcat(p, file_pathsep, buf, limit);
p = pathnpcat(p, s, buf, limit);
if (p == limit) break;
```

`pathnpcat(dst, src, start, end)` returns `dst`; it does not return `src`.
It uses `file_pathsep` only as character-set data for `strchr`.

This note describes refinements that can remove the false connection without
weakening the fail-closed transformation contract.

## Current false-positive chain

Today the chain is approximately:

```text
ptrtoint(%pathconcat::tmp16) used for comparison
  -> PAG marks every PtrToInt operand as an escape seed
  -> solver sees the operand's abstract class reach some function address
  -> fnptr_ptrtoint audit is emitted
  -> pathconcat has a high-fanout vaarg/unknown access whose finite candidate
     set includes file_pathsep
  -> relevance fallback treats the audit as unresolved for file_pathsep
  -> violation_taint blocks immutable, once-lock, atomic, mutex, and localize
```

The audit record is evidence that an abstract value reaches *a* function
pointer. It is not evidence that `file_pathsep` is a function pointer, that
the comparison result escapes, or that an external caller can invoke a
function through this value.

## Refinement 1: use-sensitive `ptrtoint`

### Rule

Do not create a pointer-escape seed or function-pointer audit merely because a
pointer is converted to an integer. Classify uses of the integer result.

The conversion is benign when its transitive uses are confined to a supported
non-reifying integer domain, initially:

- integer comparison (`icmp`);
- integer arithmetic/bit operations whose results remain in that domain;
- integer `select`/`phi` joining only values in that domain.

Create an escape seed when the integer can become externally observable or
pointer-reifying, including:

- `inttoptr`;
- store to unknown/external-visible memory;
- return from an externally callable function;
- argument to an unsummarized external or indirect call;
- inline assembly, volatile use, or unsupported integer operation;
- merge with an already escaping or reifying integer value.

The initial implementation may conservatively stop at unsupported operations;
it need not prove arbitrary integer arithmetic harmless.

### Likely implementation scope

- `crates/pangs-pag/src/lib.rs`: replace unconditional `OmegaSeedKind::PtrToInt`
  creation with a post-lowering use classification, or annotate each seed as
  `comparison_only` / `escaping`.
- `crates/pangs-solve/src/{lib.rs,andersen.rs}`: only escaping seeds mark a
  pointee class externally escaped or produce an unknown-store boundary.
- `crates/pangs-api/src/lib.rs`: defer `fnptr_ptrtoint` audit emission until the
  classified conversion is escaping.
- PIR may need a small integer def-use helper; no whole-program call-graph
  change is required.

### Soundness argument

The transformation must preserve observable pointer identity only where the
integer representation can be observed, stored, reified as a pointer, or fed
to unknown code. A value used exclusively in comparisons/arithmetic has no
operation that dereferences it, calls it, exports it, or makes it available to
external code. Replacing a global with a context field can change its address,
but that change is unobservable along this restricted use chain.

The proof obligation is therefore local: every transitive use must remain in
the allowed non-reifying domain. Any missing classification falls back to an
escape seed, preserving the current conservative behavior.

## Refinement 2: exact return/argument summaries for data-pointer helpers

### Rule

Represent the precise relation for helpers such as:

```text
return(pathnpcat(dst, src, start, end)) aliases dst (argument 0)
```

Do not infer a relation to `src` (argument 1) unless the function body or an
explicit summary establishes one. Likewise, model `strchr(s, c)` as returning
null or a pointer within `s`, with no function-pointer or storage effect.

### Likely implementation scope

- First choice: use existing direct internal call argument/return PAG edges in
  `pangs-pag`, then identify why they collapse in this case.
- If the body is unavailable or a compact fix is preferable, add exact-name,
  signature-specific summaries next to the existing libc pointer summaries.
- For internal functions, a small return-alias analysis can recognize
  `return parameter N` and propagate that fact at direct callsites.
- Add fixtures for argument 0 return, argument 1 return, conditional null, and
  unknown return; do not generalize from function name alone.

### Soundness argument

An exact return-alias summary narrows only when every path through the function
returns null or a value derived from the stated parameter. If that proof is
absent, retain the ordinary unknown/points-to result. A summary for `pathnpcat`
is sound because the source body returns `dst`; the summary does not claim that
the returned pointer is valid beyond the C program's existing semantics.

This reduces false connections but never removes an actual function-pointer
flow: a returned function address would fail the return-alias proof or appear
in the established parameter's points-to set.

## Refinement 3: positional varargs binding

### Rule

For a direct call to a defined variadic function, bind each `va_arg(T)` use to
the finite set of actual arguments that can occupy that position under the
function's visible control flow. Do not represent generic `vaarg.addr` as a
pointer to the union of all pointer-shaped arguments in all calls.

When call shape, `va_list` manipulation, ABI lowering, or an indirect target
is not understood, retain the existing opaque varargs boundary.

### Likely implementation scope

- PIR/lowering: retain enough `va_start` / `va_arg` ordering and type
  information to relate a use to a formal vararg position.
- `pangs-pag`: add callsite-to-vararg binding edges for direct, modeled
  definitions; avoid generating the high-fanout generic pointer node in that
  case.
- `pangs-api`: refine the corresponding varargs audit reason so diagnostics
  identify the exact unsupported operation when fallback remains necessary.
- This is medium scope: it touches lowering, PAG construction, and fixtures,
  but not the disposition cascade itself.

### Soundness argument

The binding is a conservative union over all actual arguments permitted at the
observed position and all feasible control-flow paths. It may include too many
actuals, but it must never omit one. Unsupported `va_list` operations leave the
old Ω boundary in place. Therefore the refinement can only split an imprecise
class when the ABI-visible argument mapping is proved.

## Refinement 4: provenance-separated code and data pointers

### Rule

Replace the single existential `reaches_function_pointer` bit with provenance
that distinguishes at least:

- function-address origin;
- data/global/heap/string origin;
- unknown pointer origin.

An `fnptr_ptrtoint` audit should require a concrete provenance path from the
converted operand to function-address origin, not merely membership in an
abstract class that also contains a function address.

### Likely implementation scope

- `pangs-solve`: carry origin bits, predecessor edges, or a compact witness per
  points-to class/node; update class merge and propagation operations.
- `pangs-api`: consume the function-origin witness when deciding whether to emit
  `fnptr_*` findings.
- `pangs-pag`: ensure function objects are tagged at allocation/address nodes.
- Export a bounded explanation path for audits, so a corpus result can be
  diagnosed without reproducing solver internals.

This is larger than a local summary because it changes solver result shape, but
it is reusable for `inttoptr`, callback escapes, aggregate copies, and external
pointer summaries.

### Soundness argument

The refinement does not assume data pointers cannot become function pointers.
It preserves the unknown origin and propagates it conservatively. It merely
requires a witness before declaring a particular data flow function-pointer
relevant. If a cast, union, integer reification, or unknown store can convert
data into code, that operation introduces unknown/function-capable provenance
and keeps the audit live.

## Refinement 5: dataflow-based audit-to-global relevance

### Rule

Do not turn a function-pointer audit into a hard violation for every global in
the same function merely because an unknown/aliased modref candidate set
contains that global. Require one of:

1. the audited operand itself names the global;
2. the audited operand is the address node of an access to that global;
3. a retained provenance path connects the audited operand to that global's
   address/value flow; or
4. a documented hard boundary explicitly carries the audited value to the
   global.

A same-function finite-candidate overlap should be reported as diagnostic,
not disposition-blocking, evidence.

### Likely implementation scope

- `crates/pangs-clients/src/lib.rs`: replace the current `has_indirect =>
  Unresolved` fallback in violation relevance with an intersection/provenance
  query.
- `pangs-api`: expose address-node and provenance information needed by that
  query; most direct-address evidence already exists in `ModRef`.
- Add fixtures where an audit and an unrelated high-fanout access coexist in
  one function, plus fixtures where they genuinely share an address node.

This is a narrow client-side change if existing node identities suffice. It
becomes medium scope only if solver provenance from refinement 4 is required.

### Soundness argument

The source transformation risk is an unmodeled operation on the global being
rewritten, not the mere co-location of two unrelated operations in a function.
Requiring a connecting dataflow path is sound because it weakens the taint only
when the analysis can prove absence of that path within its modeled domain.
Unknown paths still retain a hard boundary rather than silently becoming
unrelated.

## Refinement 6: keep pointer-comparison lowering out of generic escape paths

### Rule

Recognize LLVM/PIR patterns used to lower pointer equality and ordering and
represent them as comparisons, rather than as semantically meaningful integer
escapes. This complements refinement 1: it avoids losing the intent before
use-sensitive classification can see it.

### Likely implementation scope

- PIR lowering: preserve `icmp` use chains around `ptrtoint` where LLVM did not
  retain a pointer comparison directly.
- PAG: consume that representation without inserting a `PtrToInt` escape seed.
- Tests: equality, ordered comparison, mixed arithmetic followed by comparison,
  and an otherwise identical value passed to an external function.

### Soundness argument

The representation is narrowed only for a recognized closed comparison pattern.
Any additional use of the integer exits the pattern and returns to the
conservative `ptrtoint` rule. The transformation can change pointer identity,
but a comparison result that is neither exported nor used to reify a pointer
does not expose the original address.

## Recommended order

1. **Refinement 5** — separates the unrelated `file_pathsep` relevance step;
   small scope and directly testable.
2. **Refinements 1 and 6 together** — fixes both audit emission and solver escape
   behavior for comparison-only conversions.
3. **Refinement 3** — likely removes the `%pathconcat::vaarg.addr` high-fanout
   source that makes relevance difficult.
4. **Refinement 2** — add only after inspecting the precise points-to path for
   `%pathconcat::tmp16`; do not assume the return relation is the culprit.
5. **Refinement 4** — durable infrastructure if similar code/data conflations
   recur across the corpus.

## Validation requirements

Each refinement should have:

- a positive fixture demonstrating the newly accepted benign case;
- a paired negative fixture where the integer escapes, is reified, or reaches a
  real function pointer and must remain blocked;
- an analysis-level assertion on escape status/audit findings;
- a disposition-level assertion that only globals with a proven disconnected
  audit become eligible;
- a corpus remeasurement reporting changed audit counts, Ω escapes, and
  disposition coverage.

No refinement should remove an Ω boundary simply because it improves coverage.
The proof condition is always that the previously modeled escape or
function-pointer path cannot occur in the supported program semantics.
