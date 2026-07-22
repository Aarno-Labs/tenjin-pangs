# Potential Unknown-Access Refinements

Date: 2026-07-22

## Problem statement

Disposition needs a complete account of the reads and writes that may target each mutable
global. Direct LLVM accesses are easy to identify and, when source mapped, can often be
rewritten mechanically. Indirect accesses are supplied by the pointer-aware ModRef analysis:
the address operand of each load, store, or memory operation is resolved to a set of candidate
global allocations. When the set is large, PANGS stores one finite unknown-access row rather
than expanding it into many named rows. Disposition later treats every member of that finite
candidate set as potentially accessed at the site.

This is sound but can be substantially overapproximating. In Surprisetalk, `sym_count_xjtr_0`
has only two named ModRef rows:

- a direct read in `sym_intern_xjtr_0`; and
- a direct write in `sym_intern_xjtr_0`.

Nevertheless, 61 unrelated finite `omega_load`/`omega_store` rows contain `sym_count_xjtr_0`
in a 37-global candidate set. Call-closure propagation turns those rows into hundreds of
access-site witnesses such as accesses through `val_slots_xjtr_0`'s `Value` parameter.
Disposition therefore reports `Aliased access` or `Unknown access` and cannot construct an
atomic rewrite recipe, even though no source-level alias of `sym_count_xjtr_0` is apparent.

There are two distinct concerns here:

1. **Compact representation is not the cause.** High-fanout collapsing preserves the solver's
   candidate set. Expanding the row would produce the same false candidates at greater cost.
2. **Unknown is not necessarily universal.** These rows have finite candidate sets. They can be
   refined soundly if another analysis proves that a particular global address cannot reach a
   particular access operand. Truly universal pointer origins must continue to retain every
   compatible global.

The objective is not to make disposition optimistic. It is to distinguish an actual possible
alias from a global that entered a broad points-to class through loss of semantic, aggregate,
memory, or interprocedural precision.

## Soundness requirements common to all refinements

Any refinement that removes a global from an access site's candidate set needs a negative
proof: no concrete execution represented by the selected build mode can make the site's
address operand denote that global. Failure to obtain the proof must preserve the existing
candidate.

The proof must account for at least:

- assignments, casts, `phi`, and `select` values;
- constant and dynamic GEPs, including zero and negative offsets;
- pointer spills, reloads, aggregate stores, and memory copies;
- direct-call parameter and return flow;
- indirect calls and unresolved callers;
- global constant initializers and aliases;
- externally visible globals in library mode;
- inline assembly, unsupported LLVM operations, and exception-related flow;
- `ptrtoint`/`inttoptr`, including integer-forged pointers;
- external returns, external stores, and other external provenance regions; and
- unions, byte-oriented accesses, and deliberate type punning.

An unrestricted forged-pointer or equivalent universal origin defeats ordinary address-origin
exclusion. In that case the access must remain module-wide unless a stronger, separately
validated proof applies. A global's address not escaping to an external boundary is not by
itself sufficient: an entirely internal pointer may still alias the global.

## Option 1: address-exposure filtering at class enumeration

The smallest refinement is a per-global bit stating that every use of the global's
address is the address operand of an ordinary direct load or store. Any other use fails the
certificate, including assignment to another pointer, GEP, storage of the address, passage to a
call, return, static initializer capture, integer conversion, export, or unsupported operation.

At the solver's finite pointee-class enumeration site, an unexposed global is removed from
`pointee_globals`. This repairs ModRef, stationarity, escape diagnostics, and future clients at
their common source instead of introducing a disposition-only certificate. Universal rows and
modules with module-wide violation taint cannot use this exclusion. The raw class set remains
available as `pointee_globals_unfiltered` whenever filtering changes an answer.

### Advantages

- Small implementation and validation surface.
- Cheap to compute from LLVM uses or the PAG.
- Directly addresses isolated scalars such as `sym_count_xjtr_0`.
- Easy to explain in a disposition certificate.

### Limitations and risks

- Helps whenever false candidates are closed, even if the global being analyzed is not.
- Rejects common, benign local aliases and helper-function access patterns.
- A PIR-level string-use scan could miss constant expressions or lowering details; the proof
  should be based on exhaustive LLVM uses or explicit PAG edges.
- It is tempting, but unsound, to substitute `omega_escaped_address == false` for this proof.

### Likely scope

Small to medium. It needs one exposure bit per global, filtering at solver class enumeration,
raw-envelope diagnostics, and positive and negative tests.

## Option 2: semantic pointer kinds and typed payload flow

PANGS currently uses ABI classification where pointers and many integers share the `Integer`
class. ABI classification is appropriate for function-signature compatibility, but it is too
coarse to decide which loaded or stored payloads can carry addresses. The PIR could preserve a
separate semantic value kind:

- pointer;
- non-pointer scalar;
- pointer-containing aggregate; or
- unknown.

Memory accesses would still be recorded for all loads and stores. Points-to constraints for
the loaded or stored *payload*, however, would be emitted only for pointer-bearing values.
Unknown, type-punned, or unsupported values would retain conservative pointer flow. Function
signatures would keep ABI classes for FSA while also carrying semantic pointer information for
argument and return binding.

By-value aggregates deserve particular attention. Rather than treating an aggregate as a
collection of undifferentiated integer-class values, each call should bind the aggregate copy
and its pointer-bearing fields with appropriate offsets. This should reduce contamination from
large union-like values without assuming that non-pointer fields are addresses.

### Advantages

- Attacks a likely root cause rather than filtering client output.
- Improves points-to, ModRef, function-pointer analysis, and every disposition client.
- LLVM provides most of the necessary type information before lowering.
- The fail-closed rule is natural: ambiguous types remain pointer-capable.

### Limitations and risks

- Cross-cutting schema and solver change.
- C unions, byte copies, casts, opaque library interfaces, and integer round trips require
  careful conservatism.
- LLVM pointer types describe IR operations, not necessarily all source-level aliasing intent.
- Precise aggregate field handling can increase graph size.
- Typed filtering alone will not recover precision lost through flow-insensitive memory or
  context-insensitive call merges.

### Likely scope

Large. Changes would touch LLVM lowering, PIR serialization, PAG construction, parameter and
return binding, memory constraints, solver tests, and client baselines. It should be introduced
behind metrics that report how many constraints were omitted as proven non-pointer payloads and
how many remained unknown.

## Option 3: global-centric address-flow closure

A broader generalization of the direct-address-only certificate is to follow each global's
address through the program and enumerate all dereference sites reached by that address. The
analysis begins at the global symbol and follows address-preserving flow through:

```text
&global
  -> assignments, casts, phi/select, and GEP
  -> pointer spills and reloads
  -> aggregate fields and copies
  -> internal parameters and returns
  -> dereference sites
```

The result for a global is either:

- **complete**, with an explicit set of possible access sites; or
- **incomplete**, with one or more boundaries that prevented exhaustive tracking.

When the result is complete, disposition can use the enumerated set instead of attributing
unrelated finite unknown rows to that global. A local alias or helper function is not a
failure: it is another address-flow step. Direct-address-only becomes the simplest successful
case rather than the entire policy.

The analysis can be implemented as summaries rather than one full traversal per global.
Functions can summarize which pointer parameters reach loads, stores, returns, other
parameters, or unknown boundaries. Those summaries can be instantiated for many globals with
compact bitsets or shared sets.

### Advantages

- Directly computes the access-set completeness fact needed by atomic, mutex, localization,
  and phase-stationarity clients.
- Handles ordinary aliases and internal helper APIs.
- Produces useful witnesses both for successful accesses and for the first loss of precision.
- Can coexist with the current solver and override only candidates backed by a complete proof.

### Limitations and risks

- Precise memory matching is difficult: an address stored into memory must be connected to all
  relevant reloads without falling back to the same broad points-to class.
- Recursive functions and cyclic data structures require fixpoint summaries.
- Context-insensitive summaries may still merge unrelated actual arguments.
- Per-global traversal would scale poorly without caching or summary sharing.
- If implemented over exactly the same untyped inclusion edges as Andersen, it may reproduce
  the same false candidates and provide little benefit.

### Likely scope

Medium to large. A useful first version could handle SSA flow, local pointer spills, and direct
calls, failing closed at aggregate memory or unresolved calls. Later versions could reuse
allocation provenance, callsite bindings, initializer address dependencies, and compact
`(GlobalId, Access)` sets already present in the analysis.

## Option 4: candidate-specific demand queries

Instead of certifying a whole global, PANGS can validate an individual `(access node, global)`
candidate. The query asks whether `&global` can reach the address operand through a
well-matched path. A useful query must be more precise than ordinary reachability in the
existing Andersen inclusion graph; otherwise it simply restates the candidate set.

Additional precision can come from:

- matched store/load parentheses;
- matched call-argument/parameter and return/callsite edges;
- field-offset compatibility;
- semantic pointer kinds;
- allocation provenance; and
- separated external origins.

This resembles a CFL-reachability or memory-alias query. It can run only for high-fanout rows or
only for globals that disposition would otherwise leave unhandled. Negative answers are usable
only when the query completed without truncation. Budget exhaustion, unsupported edges, or an
unrestricted external origin preserve the original candidate.

### Advantages

- Highest potential precision without globally replacing the solver.
- Cost can be concentrated on disposition-relevant ambiguities.
- Naturally supplies a candidate-level certificate and witness.
- Can distinguish candidates within one broad finite row rather than accepting or rejecting
  the row as a whole.

### Limitations and risks

- Considerable algorithmic complexity.
- Potentially expensive for `sites x candidate globals` without memoization.
- Existing experimental tier-E callee queries are not immediately sufficient; memory access
  validation needs its own sources, sinks, and completeness conditions.
- Truncation and touched-site fallback rules must be visible and auditable.
- Querying the current coarse graph without richer matching or typing will not improve results.

### Likely scope

Large, although an experimental implementation could be isolated. Cache keys should include
the access node, candidate allocation, query mode, and relevant build assumptions. Shared
reverse slices or batched multi-source queries may be preferable to independent pair queries.

## Option 5: layout- and base-object validation

Many candidate globals are incompatible with the structure of an access path. A pointer
derived as field 2 of a `Value` object should normally require a base allocation large and
aligned enough to contain that field. A standalone four-byte scalar cannot serve as the base
of an access at a substantial positive offset.

A validator could intersect candidate sets using:

- allocation size and alignment;
- constant GEP offsets and offset ranges;
- base-object identity;
- access width;
- known aggregate layouts; and
- whether the path has lost layout through a byte cast, unknown GEP, union, or integer
  conversion.

### Advantages

- Especially promising for aggregate-heavy false positives such as `Value` field accesses.
- Cheaper than a full context- or flow-sensitive solver.
- Reuses allocation and GEP metadata already needed elsewhere.
- Can be used inside global-centric or demand-driven proofs.

### Limitations and risks

- Offset-zero accesses often remain ambiguous.
- `container_of`, negative GEPs, unions, flexible arrays, byte buffers, and custom allocators
  require conservative fallbacks.
- Object size alone does not prove type identity in C.
- It is a filter, not a complete alias analysis.

### Likely scope

Medium. The main work is preserving layout provenance through casts and defining exactly which
operations invalidate the proof. Tests must include legitimate negative-offset and byte-cast
idioms so the validator does not silently assume type-safe C.

## Option 6: selective flow- and context-sensitive reanalysis

The most general solver-side option is to reanalyze only the slice responsible for a
high-fanout access using stronger precision:

- sparse flow sensitivity for pointer stores and loads;
- context-sensitive binding for selected internal calls;
- per-call by-value aggregate objects;
- selective heap or stack object cloning; and
- memory SSA or strong updates where uniqueness is proved.

The initial Andersen result supplies the conservative envelope; the selective solve may only
narrow within it. If the reanalysis is incomplete or exceeds its budget, the envelope remains
authoritative.

### Advantages

- Addresses genuine flow- and context-induced merges.
- Potentially reusable for indirect callees and other precision clients.
- Can resolve cases beyond isolated globals or structurally simple address paths.

### Limitations and risks

- Largest implementation and maintenance cost.
- Hardest performance behavior to predict on large corpus members.
- Strong-update and context-selection criteria require their own soundness proofs.
- Considerable overlap with the complexity intentionally omitted from PANGS-lite.

### Likely scope

Very large. This should be justified by residual cases after cheaper semantic and
certificate-based refinements have been measured.

## Client-side versus solver-side application

There are two places to apply a successful refinement.

### Filter ModRef candidates before export

Refining `NodeResolution.pointee_globals` or the finite `global_candidates` set before
high-fanout collapse improves all downstream users and makes diagnostics reflect the best known
answer. This is preferable for semantic pointer kinds, layout validation, and complete demand
queries.

The risk is broad impact: stationarity, escape-related logic, and other clients may have
different completeness requirements. The refined result must therefore carry its proof status
and must remain a conservative points-to answer, not merely a source-rewrite judgment.

### Certify access completeness in disposition

A global-centric analysis can instead produce a client certificate saying that a particular
global's access set is complete. Atomic or localization logic can then ignore coarse ModRef
rows for that global without changing the general solver export.

This isolates risk and directly matches the rewrite question, but duplicates some pointer
reasoning and may leave other clients with avoidable false positives. It is a reasonable first
integration point while a new analysis is being validated.

## Proposed sequence

### Stage 1: filter finite class enumeration by address exposure

Compute the per-global address-exposure bit and remove unexposed globals while enumerating
finite, non-universal solver classes. Preserve the raw class envelope for differential checks,
and bypass the filter for universal external provenance and module-wide violation taint. This
is the first implementation step because corpus measurement shows that false candidates, not
necessarily the globals being classified, are very often address-closed.

### Stage 2: diagnose and preserve provenance

Before changing eligibility, add diagnostics that explain why each candidate global reached a
high-fanout access node. At minimum record whether the path involved:

- direct address flow;
- scalar or unknown payload flow;
- by-value aggregate binding;
- memory merging;
- call/return merging;
- a finite external region; or
- a universal origin.

Run this on `sym_count_xjtr_0` and representative corpus cases. This confirms whether semantic
type loss, aggregate binding, or memory merging is the dominant source and establishes A/B
metrics for candidate-set sizes.

The implemented post-filter diagnostic is `NodeResolution.pointee_provenance`. It accumulates
class-level categories for surviving candidates and is appended to collapsed high-fanout ModRef
details and unknown external rows. Rows changed by filtering also report the pre-filter pointee
count and number removed. It is deliberately explanatory rather than a certificate: class-level
attribution may name more than one contributing mechanism, and no client may use the labels to
remove candidates.

### Stage 3: semantic pointer kinds and by-value aggregate correctness

Preserve pointer-versus-non-pointer semantics separately from ABI classes and stop emitting
pointer-payload constraints for proven scalar values. Model pointer-bearing aggregate fields
and by-value copies explicitly enough to avoid treating every integer-class field as an
address. Unknown and type-punned cases remain conservative.

This is the preferred foundational change because every later certificate or query benefits
from a cleaner graph. Measure changes in PAG size, solver time, ModRef fanout, and disposition
coverage on Surprisetalk plus the established small-to-large profiling corpus.

### Stage 4: general global-centric access-set certificate

Implement a summary-based address-flow closure for disposition. Begin with SSA operations,
constant GEPs, local pointer spills, direct calls, and returns. Fail closed at unresolved
memory, indirect calls, universal external origins, and unsupported operations. The output must
list both the complete access sites and any boundary that prevented completeness.

Use a complete certificate to replace coarse unknown attribution for that global in rewrite
eligibility. Do not limit the implementation to direct-address-only globals, although those
provide useful initial tests.

### Stage 5: layout-aware refinement

Add allocation extent, access width, and GEP-offset validation to the global-centric analysis
and to finite candidate construction. Preserve conservative behavior for unknown offsets,
unions, byte casts, flexible layouts, and `container_of`-style negative paths.

### Stage 6: demand-driven matched-path queries

For globals whose address-flow certificate remains incomplete and whose disposition would
otherwise be unhandled, run a bounded candidate-specific query with matched memory and
interprocedural edges. Cache shared slices and expose truncation explicitly. Only complete
negative answers remove candidates.

### Stage 7: reconsider selective stronger solving

Profile the remaining false positives. Introduce flow- or context-sensitive selective solving
only if a material fraction of important globals remains blocked by genuine solver merges that
the preceding stages cannot resolve.

## Evaluation plan

For each stage, record:

- finite and universal unknown-access row counts;
- candidate fanout distribution before and after refinement;
- number of globals removed from at least one finite candidate set;
- number of globals gaining complete access-set certificates;
- disposition distribution and specific transitions;
- analysis runtime and peak RSS;
- PAG node/edge and solver constraint counts;
- query counts, cache hit rate, and truncations where applicable; and
- differential soundness checks showing that every refined candidate set is a subset of the
  existing conservative envelope.

The initial acceptance target is that `sym_count_xjtr_0` retains its two direct ModRef rows,
loses the unrelated `val_slots_xjtr_0` and other finite unknown witnesses, and becomes eligible
for an atomic rewrite if no independent blocker remains. Regression fixtures must also show
that globals whose addresses are stored, passed, returned, captured by initializers, accessed
through valid aggregate paths, or reachable from universal forged pointers remain attributed.

## Recommendation

Do not treat address-exposure filtering as the final architecture. It is a high-payoff early
refinement, but the general solution should be a cleaner typed PAG combined with an explicit,
auditable access-set completeness proof.

The recommended investment order is therefore:

1. address-exposure filtering at finite class enumeration;
2. provenance diagnostics;
3. semantic pointer kinds and precise by-value aggregate flow;
4. global-centric address-flow closure;
5. layout validation;
6. demand-driven matched-path queries; and
7. selective flow/context sensitivity only if corpus evidence justifies it.

This order improves the shared analysis foundation first, gives disposition a general
certificate rather than an isolation special case, and reserves the highest-complexity solver
features for the residual cases that demonstrably need them.
