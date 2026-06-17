# M1.5 Per-Component Soundness Statement

This note records the M1.5 contract implemented by the current `pangs` lite pipeline.
It is the acceptance artifact called for by `PLAN-M1.md` §M1.5.

## Scope

The statement applies to the exported M1 artifacts:

- `audit.jsonl`
- `callgraph.jsonl`
- `components.json`
- `metrics.json`

and to the current analysis stages:

- `conservative`
- `steens`
- `andersen`

The lite track keeps the same soundness posture as `DESIGN.md` §7 and
`DESIGN_lite.md`: when the analysis sees a function-pointer-related assumption
violation, it should convert that case into **coverage loss, never corruption**.

## Operational meaning of a frozen component

`components.json` is built over function components induced by known function-to-function
callgraph edges. A component is marked `frozen: true` iff it has at least one taint row.
Today there are exactly three sources of component taint:

1. `unknown_callee`
   - emitted when a call in the component may target an unresolved or Ω-tainted callee
   - examples: `external_callee`, `omega_fnptr`
2. `unknown_caller`
   - emitted when a function in the component may be called from an escaped external
     context
   - current witness reason in the callgraph is `address_escapes_to_external`
3. M1.5 audit findings
   - exported in `audit.jsonl`
   - mirrored into component taint with `effect = "omega_taint"`

Consumers must treat `frozen: true` as **not eligible for source rewriting**. The
coverage metric already follows that rule: `metrics.in_rewritable_components` counts
only mutable globals that belong to non-frozen components.

## Guarantee for non-frozen components

For any component with `frozen: false`, the current implementation claims:

1. no modeled call in the component has an exported `unknown_callee` edge;
2. no function in the component has an exported `unknown_caller` edge;
3. no local assumption-violation detector fired for the component.

Under the M1 soundness envelope, that means the component is outside every
function-pointer-related uncertainty that the current pipeline knows how to detect and
surface. Operationally:

- direct calls are resolved or excluded by the IR itself;
- indirect-call targets are restricted by the M1.2 FSA compatibility rules, and further
  narrowed in `steens` / `andersen`;
- function escape visible to the Ω machinery has not forced an unknown incoming-call
  boundary for the component;
- none of the audited M1.5 violation patterns were observed locally in the component.

This is a **component-local guarantee**, not a claim that the whole module is sound. If
some other component is frozen, that is acceptable: the client contract is to lose
coverage there, not to upgrade it into a rewritable verdict.

## Detector list reviewed against the implementation

The current code emits the following audit finding kinds:

- `inline_asm`
- `dlopen_dlsym`
- `setjmp_longjmp`
- `fnptr_varargs_external`
- `fnptr_varargs_internal_unmodeled`
- `fnptr_varargs_indirect`
- `fnptr_ptrtoint`
- `fnptr_inttoptr`
- `memcpy_fnptr_aggregate`
- `memset_fnptr_aggregate`

Their current trigger conditions are:

- `inline_asm`
  - any lowered `Unknown` statement whose reason starts with `inline_asm`
- `dlopen_dlsym`
  - direct calls to `dlopen` or `dlsym`
- `setjmp_longjmp`
  - direct calls to `setjmp` or `longjmp`
- `fnptr_varargs_external`
  - all stages: direct calls to external or unresolved vararg callees where a direct
    function symbol is passed through varargs
  - `steens` / `andersen`: local values passed through those varargs whose solved PAG
    class reaches function-pointer space
- `fnptr_varargs_internal_unmodeled`
  - all stages: direct calls to visible internal vararg callees with modeled vararg
    consumption (`va_arg` / `llvm.va_*`) where a direct function symbol is passed
    through varargs
  - `steens` / `andersen`: local values passed through those varargs whose solved PAG
    class reaches function-pointer space
  - visible internal vararg callees with no modeled vararg consumption do not emit this
    audit kind
  - name-specific M4.3 summaries suppress this audit only for inspected formatting/logging
    wrappers whose vararg payload is formatted as text rather than retained as pointers
- `fnptr_varargs_indirect`
  - all stages: indirect vararg callsites where a direct function symbol is passed
    through varargs
  - `steens` / `andersen`: local values passed through varargs whose solved PAG class
    reaches function-pointer space
- `fnptr_ptrtoint`
  - `steens` / `andersen` only
  - a `ptrtoint` operand whose solved PAG class reaches function-pointer space
- `fnptr_inttoptr`
  - `steens` / `andersen` only
  - an `inttoptr` result whose solved PAG class reaches function-pointer space
- `memcpy_fnptr_aggregate`
  - `memcpy` over a locally tracked aggregate value whose type string contains a
    function-pointer field
- `memset_fnptr_aggregate`
  - `memset` over the same locally tracked aggregate class

Vararg audit findings may include optional `detail` metadata such as `callee:log_debug`.
This is evidence for review/reporting, not a separate taint kind. Unknown or unlisted
vararg callees remain conservative by default.

Every emitted finding is exported in `audit.jsonl`, counted in `metrics.audit_findings`,
and mirrored into the owning component’s taint set so the component freezes.

## What this statement does not claim

This note does not claim that the detector list is complete for all possible LLVM/C
function-pointer abuses. It only claims the following M1 behavior:

- if the implementation detects one of the listed assumption-violation events, it
  exports a finding and freezes the affected component;
- components without such taint remain the only ones counted as rewritable coverage;
- therefore a missed precision case degrades to lost coverage where detected, not a
  silent rewrite in a tainted component.

The remaining risk is the ordinary one for audited soundiness: an assumption violation
that exists in the input but is **not** in the current detector set, or is in the set but
escapes the current local trigger. That residual risk is why this statement is
per-component and detector-scoped rather than a blanket whole-program soundness claim.

## Current user-facing surface

There is not yet a separate `pangs audit` CLI subcommand. The current source of truth is:

- `pangs analyze ... --out DIR`
- `DIR/audit.jsonl`
- `DIR/components.json`
- `DIR/metrics.json`

`pangs analyze --validate` now schema-validates those artifacts, so this soundness
statement describes a checked export contract rather than an informal convention.
