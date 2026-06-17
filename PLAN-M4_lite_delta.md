# M4 Lite Delta Plan — Vararg and Boundary Modeling

Date: 2026-06-16

## 0. Decision Context

M3 lite froze the default path as `--stage andersen`, with tier-E/CFL kept out of
`analyze`. The next useful milestone should therefore improve the existing lite model rather
than add a new solver tier.

The strongest repeated blocker class in the M3 decision table is audit/modeling taint:

- `fnptr_varargs` appears heavily in jpegoptim, jq, chibicc, gifsicle, lua, curl, and tmux;
- ptrtoint/inttoptr and inline-asm/setjmp remain separate blockers;
- unknown globals/modrefs dominate several rows;
- residual unknown icalls alone do not justify tier-E as the next default-path investment.

This plan focuses on vararg/function-pointer boundary modeling first because it is prominent
across the corpus and is currently treated as a broad audit taint even when a narrower,
sound envelope may be available.

This plan supersedes the old full `PLAN-M4.md` for the lite track. The old `PLAN-M4.md`
describes a conditional full Andersen milestone from the pre-lite design; this file is the
current follow-up plan from `notes/m3_lite_decision.md`.

## 1. Goal

Reduce unnecessary `fnptr_varargs` component freezing without weakening the sound boundary
model.

The target is not to prove all vararg calls safe. The target is to split the current broad
bucket into:

- **modeled-safe or narrowable cases** where extra vararg operands do not carry function
  pointers, or where their function-pointer flow can be bounded to local/internal targets;
- **true opaque-boundary cases** where a function pointer crosses an ABI boundary that the
  analysis cannot model and must still taint/freeze.

Success means fewer frozen components due to vararg taint, better audit explanations, and no
loss of the existing Ω soundness envelope.

## 2. Current Behavior

Current pieces:

- PAG marks any vararg callsite with `OmegaSeedKind::VarargCallBoundary`.
- Steensgaard applies the vararg boundary by escaping pointees of extra vararg arguments.
- API audit records `fnptr_varargs`:
  - immediately for syntactic function symbols passed in extra vararg positions;
  - deferred through solved node summaries for values whose points-to set reaches function
    pointers.
- Component reporting treats `fnptr_varargs` as an audit taint and helps identify affected
  frozen components.

This is sound, but it over-communicates many cases as one severity:

- direct calls to known internal vararg functions may have visible bodies;
- extra arguments may be non-pointer or pointer-to-data only;
- some vararg functions may be known sink-only/logging-style wrappers;
- some function-pointer extras may be intentionally local and never escape beyond the call;
- external unknown vararg boundaries remain truly opaque.

## 3. Soundness Rules

These rules are load-bearing:

- If an extra vararg argument may carry a function pointer across an unknown external ABI
  boundary, keep the current Ω escape and audit taint.
- Never remove a `fnptr_varargs` finding only because the call target is syntactically known;
  the callee body and ABI behavior must justify narrowing.
- Direct internal vararg calls can be modeled only for effects visible in the PIR body.
  Unmodeled `va_start`/`va_arg`-style behavior must remain conservative.
- Indirect vararg calls keep the current conservative boundary unless every possible target is
  modeled-safe under the same rule.
- Any refinement must be monotone relative to the current behavior: fewer taints are allowed
  only when a replacement model still preserves all escaping function-pointer facts.

## 4. Milestone Slices

### M4.0 — Vararg Evidence Report

Add an audit/report mode or note-producing script that attributes `fnptr_varargs` findings by
callsite shape:

- direct internal callee;
- direct external callee;
- indirect call;
- syntactic function symbol in extra arg;
- value reaching function pointer only through solved flow;
- known libc/compiler boundary name when available.

Acceptance:

- run on the M3 corpus rows;
- record top vararg callsites/components by count and by largest frozen component impact;
- identify whether most taint is direct external, direct internal, or indirect.

Expected output: `notes/m4_vararg_evidence.md`.

Implementation status:

- `scripts/m4_vararg_evidence.sh` summarizes vararg audit kind histograms, affected-value
  prefixes, largest frozen components with vararg taint, and top vararg taint witnesses from
  one or more export directories.
- Corpus rerun is recorded in `notes/m4_vararg_evidence.md`.

### M4.1 — Split Audit Kinds Without Changing Semantics

Refine audit taxonomy while preserving behavior:

- `fnptr_varargs_external`
- `fnptr_varargs_internal_unmodeled`
- `fnptr_varargs_indirect`
- `fnptr_varargs_syntactic_symbol`
- `fnptr_varargs_solved_value`

The exact names can change during implementation, but the point is to separate why the taint
exists.

Acceptance:

- existing `fnptr_varargs` tests continue to pass after updating expected names/summaries;
- `pangs report` clearly shows the split kinds;
- no coverage or callgraph behavior changes yet.

Implementation status:

- Analysis now emits `fnptr_varargs_external`, `fnptr_varargs_internal_unmodeled`, and
  `fnptr_varargs_indirect` according to callsite shape.
- Syntactic-symbol versus solved-value evidence remains visible through the `affected`
  prefix (`function:` versus `value:`) and the M4 evidence script's affected-prefix summary.

### M4.2 — Direct Internal Vararg Body Modeling

Handle direct calls to internal vararg functions with visible bodies.

Approach:

- For direct internal vararg calls, bind fixed parameters as today.
- Introduce a conservative representation for extra vararg actuals only if the PIR/lowering
  exposes a modeled use of the vararg list.
- If the callee body has no modeled vararg consumption, do not force function-pointer extras
  through an opaque external boundary.
- If the callee body contains unknown vararg consumption, inline asm, unknown intrinsics, or
  pointer-int punning that could touch the vararg list, keep or reintroduce the taint.

Acceptance fixtures:

- internal vararg wrapper that never reads varargs does not freeze a function pointer extra;
- internal vararg wrapper that passes the extra value to an external call remains tainted;
- internal vararg wrapper with unmodeled vararg consumption remains tainted;
- external `printf`-style call remains tainted when a function pointer reaches an extra arg.

Implementation status:

- Direct internal vararg calls only keep the opaque vararg boundary when the visible callee
  body contains modeled vararg consumption (`va_arg` / `llvm.va_*` lowering).
- API audit emission follows the same predicate, so modeled-safe internal vararg calls do
  not receive `fnptr_varargs_internal_unmodeled` taint.
- Synthetic tests cover safe no-read internal callees and unsafe `va_arg` callees.
- Corpus rerun showed no coverage change: the observed internal vararg findings still have
  visible vararg consumption and remain conservatively tainted.

### M4.3 — Known Benign Boundary Summaries

Add a small, explicit summary table for known vararg callees whose extra arguments are not
captured as function pointers under the supported ABI model.

Possible initial candidates should be chosen from evidence, not guessed. Examples to
investigate, not pre-approve:

- logging/error functions that consume format arguments but do not store/call them;
- project-local wrappers that forward only non-pointer data;
- compiler/runtime helpers visible in corpus rows.

Acceptance:

- summary entries are narrow and name-specific;
- every entry has a fixture or corpus witness;
- unknown external vararg functions remain conservative by default;
- report output distinguishes "summary-modeled" from "opaque-boundary".

Implementation status:

- Added a narrow name-specific summary table for inspected tmux/curl formatting and logging
  wrappers; see `notes/m4_vararg_evidence.md`.
- Vararg audit rows now include optional `detail` metadata such as `callee:log_debug`.
- Focused curl/tmux rerun reduced vararg findings from `254 -> 117` on curl and
  `637 -> 101` on tmux, with no rewritable-coverage change.
- `tool_setopt`, `curl_easy_setopt`, and `curl_easy_getinfo` remain conservative.

### M4.4 — Indirect Vararg Target Filtering

For indirect vararg calls, consider reducing taint only when all concrete targets are known
and each target is modeled-safe.

Rules:

- if target set contains unknown callee, keep taint;
- if any target is external/opaque, keep taint;
- if all targets are direct internal modeled-safe vararg functions, allow narrowing;
- if the callsite falls back to Steensgaard or oversized partition, keep taint unless the
  Steensgaard envelope itself is entirely modeled-safe.

Acceptance:

- fixture with two safe internal vararg targets narrows;
- fixture with one unsafe target remains tainted;
- fixture with unknown callee remains tainted.

### M4.5 — Corpus Rerun and Decision

Rerun the M3 decision corpus:

- jpegoptim
- parson
- jq
- chibicc
- gifsicle
- lua
- curl
- tmux if time budget permits

Compare:

- audit kind histograms;
- component taint histograms;
- largest frozen component blockers;
- mutable rewritable coverage;
- runtime and export size.

Acceptance:

- `notes/m4_vararg_decision.md` records whether the modeling reduces real blockers;
- if coverage does not move, stop and move to the next blocker class instead of polishing.

## 5. Non-Goals

- Do not revive tier-E/CFL.
- Do not treat vararg calls as safe by default.
- Do not add a large libc summary database.
- Do not hide audit findings merely to improve coverage metrics.
- Do not optimize JSONL export as part of this milestone unless it blocks the corpus rerun.

## 6. Implementation Risks

Main risk: unsoundly suppressing an opaque ABI boundary.

Mitigation:

- stage taxonomy changes before semantic changes;
- keep external and indirect unknown callsites conservative;
- require fixtures for every suppressed taint class;
- preserve Ω escape when any target or vararg use is unmodeled.

Secondary risk: this does not improve coverage much because unknown globals/modrefs dominate.

Mitigation:

- run M4.0 first;
- stop after M4.5 if the actual coverage delta is small;
- choose the next blocker class from measured component blockers, not from intuition.

## 7. Expected Outcome

Best case:

- large `fnptr_varargs` taint counts split into actionable categories;
- internal/benign cases stop freezing components;
- largest frozen components shrink on tmux/curl/jq/lua.

Acceptable case:

- taxonomy shows most vararg taint is truly external/opaque;
- M4 records that varargs are not currently the best coverage lever;
- next work moves to unknown globals/modrefs or pointer-int punning with better evidence.
