# Derived-Address Exposure for Global Storage

Date: 2026-08-20

## Status

Implemented in the current working copy on 2026-08-20. Focused validation, the full workspace
gate, and the Phase 3 curl remeasurement are complete; the wider disposition-corpus gate remains
pending.

Implemented scope:

- `pangs-pag` owns the shared, node-indexed `StorageRoots` certificate, canonical global
  identity, explicit canonical-pointer-null marker, sole-producer `AddrOf` rule, GEP propagation,
  and complete same-root-or-null/same-scope Assign joins.
- Steensgaard, Andersen exact-address recovery, exposure filtering, and API precise-storage
  attribution consume that certificate. The former independent API root fixpoint was removed.
- Exposure classification covers all PAG edge kinds plus calls, cross-scope bindings, rooted
  returns, Ω seeds (including unused exported global objects), initializers, and PIR-level
  `Memset`. `Memcpy` and `Memset` operands remain exposure boundaries in v1.
- API root/`GlobalId` agreement is checked before downstream consumption. Missing or conflicting
  identity restores every narrowed `NodeResolution` to its unfiltered envelope module-wide and
  disables exact attribution for that solve.
- Executable regressions cover canonical-null and all-null joins, unknown and mixed-global joins,
  malformed `AddrOf + Assign`, `AddrOf + Load`, and duplicate-`AddrOf` producers, internal
  call/return boundaries, unused exports,
  direct and derived memcpy/memset writer retention under Steensgaard and Andersen, and a derived
  memset as the sole post-publication writer preventing phase/once-lock certification.

Validated so far:

```text
cargo fmt --all -- --check
cargo check -p pangs-pag -p pangs-solve -p pangs-api
cargo test -p pangs-pag -p pangs-solve -p pangs-api
cargo test -p pangs-api -p pangs-clients -p pangs-dispose
cargo test --workspace
```

The validated Phase 3 run used the unchanged input SHA and retained all 75 manifest keys. It
improved handled coverage from 71/75 (94.67%) to 72/75 (96.00%); the only disposition transition
was `src/tool_getparam.c::findshortopt.singles`, from unhandled to once-lock. Its Ω-escaped-address
fact remained false, violation taint cleared, localization remained `ok`, and its access set
contains the two source-level accesses in `findshortopt`. Artifacts are retained at
`/tmp/pangs-derived-curl-3Glzma` (2.50 seconds, 154548 KiB peak RSS).

Still pending or deliberately manual:

- the wider disposition-corpus gate in Phase 4 and manual audit of any additional transitions;
- promoting the curl-specific absence of unrelated ptr/int, varargs, and inline-assembly
  relevance from a validated artifact check into a compact synthetic regression;
- optional solve metrics proposed in §5.4, which are not required for soundness or artifact
  semantics;
- future relaxation of memcpy/memset exposure, which remains gated on extending their special
  ModRef builders to consume exact-root attribution.

This is a precision repair for the existing address-exposure filter. It does not replace the
PANGS PAG or solver with a new points-to representation. PANGS already distinguishes value-like
nodes from allocation objects and models `AddrOf`, `Load`, `Store`, `Assign`, and `Gep`
separately. That is the relevant semantic distinction behind cclyzer++'s `var_points_to` and
`ptr_points_to` relations.

The defect is narrower: the current negative proof regards any GEP derived from a global symbol
as exposure of the global's address. Common direct array indexing therefore prevents an otherwise
closed global allocation from being removed from broad finite points-to classes. Those false
candidates become false ModRef rows and then hard violation relevance.

## 1. Motivating case

The current validated curl measurement is:

```text
input: /home/brk/pangs-corpus/_out_bc/exe-curl-O0.bc
sha256: 392593ddebef78fc557bef1045622e53e07e72293cd56a0e102d973736d9a8d6
artifacts: /tmp/pangs-disposition-curl-O0-Xpd0Te
analysis: Andersen, executable/application, no overrides, validated
```

The remaining `findshortopt.singles` source is a function-local static pointer array:

```c
const struct LongShort *findshortopt(char letter)
{
  static const struct LongShort *singles[128 - ' '];
  static bool singles_done = FALSE;

  if(!singles_done) {
    for(unsigned int j = 0; j < CURL_ARRAYSIZE(aliases); j++) {
      if(aliases[j].letter != ' ') {
        unsigned char l = (unsigned char)aliases[j].letter;
        singles[l - ' '] = &aliases[j];
      }
    }
    singles_done = TRUE;
  }
  return singles[letter - ' '];
}
```

There are two source-level runtime accesses to the `singles` storage: the element store and the
element load. The current manifest instead reports:

```text
localization.verdict: ok
localization.blockers: []
violation_taint: true
access_set_complete: true
atomic/mutex access_sites_observed: 2739
mutex accessor_functions: 183
```

The ModRef export contains two real `findshortopt` rows and hundreds of false named or finite
unknown rows. A representative unrelated finite row is `parse_filename`'s `memcpy`; its five
retained mutable/global candidates include `findshortopt.singles` even though that function
cannot name the function-local static.

The false ModRef population causes findings at unrelated sites to be classified as
`address-relevant`, including `CURL_UNCONST(nextarg)` at `tool_getparam.c:2928`. The first hard
finding sets `violation_taint`, which is an implicit veto on every disposition, including the
independently successful localization verdict.

## 2. Root cause

`crates/pangs-solve/src/lib.rs::global_address_exposure` currently proves a global unexposed only
when the global symbol is used immediately as the address operand of a direct load or store. Its
edge scan treats all other uses as exposure, including GEP:

```text
obj:global:singles --AddrOf--> sym:global:singles
sym:global:singles --Gep(dynamic index)--> element-address
element-address --Store/Load--> element value
```

The GEP is an address derivation, not an address escape. The element address remains rooted in
the `singles` allocation and is consumed directly by a memory access. Nevertheless, marking the
base symbol exposed retains `singles` in every coarse class containing its global object.

PANGS already has the stronger proof machinery needed to avoid this:

- `pangs-solve::exact_allocation_addresses` seeds allocation roots at `AddrOf`, preserves roots
  through GEP, and preserves an Assign join only when every incoming alternative proves the same
  root. Loads and unsupported/mixed producers stop the proof.
- `pangs-api::precise_storage_addresses` independently applies the same root discipline to
  recover exact global/local storage accesses for ModRef.

The solver filter does not currently consume that derived-root information. The two layers can
therefore disagree: the API recognizes `singles[index]` as a rooted access while solver class
enumeration still labels the allocation exposed and admits it at unrelated access operands.

This is not caused by the compact high-fanout row representation. Expanding those rows would
emit the same false candidates at greater cost.

## 3. Required semantic distinction

For a pointer-valued global or aggregate, keep these relations separate:

```text
address of global storage
    &singles, &singles[i]

pointer payload stored in global storage
    singles[i] == &aliases[j]
```

Storing `&aliases[j]` into `singles[i]` may expose the `aliases` allocation. It does not expose
the address of the `singles` allocation. Loads from `singles[i]` propagate the stored pointer
payload, not the storage address.

The PAG already represents this distinction. The exposure proof must inspect address operands
and derived roots rather than interpreting connectivity in a coarse solver class as evidence
that the storage address escaped.

## 4. Soundness contract

The optimization is a negative proof:

```text
derived_address_unexposed(g)
  => no modeled execution can present the address of g or any subobject of g
     at an access operand outside the explicitly rooted access set
  && every admitted rooted access node is attributed to g by ModRef
```

Failure to prove this retains the existing candidate. No unknown or universal row is narrowed
because the result would be convenient for disposition.

A derived address may remain unexposed only through this closed grammar:

```text
root     ::= AddrOf(global-object) when it is the destination's only value producer
derived  ::= root
           | Gep(derived, constant-or-dynamic-offset)
           | Assign(derived-or-null...) when every non-null producer has the same
             allocation root, at least one producer has that root, every other producer
             is proven canonical null, and every endpoint remains in the same
             semantic function/module scope

safe-use ::= address operand of Load
           | address operand of Store
           | another admitted derived-address operation
```

In v1, an operation is admitted as a safe use only if every downstream access path that models
that operation can attribute the access directly to the proven allocation root. `Load` and
`Store` meet that requirement through the existing rooted-access path. Derived-address
`Memcpy`/`Memset` rows do not: their special ModRef builders currently use exposure-filtered
pointee enumeration rather than the root certificate. Their address operands are therefore
exposure boundaries in v1, even when the operation is otherwise modeled.

Memory width and offset precision are irrelevant to address exposure: a dynamic or unknown GEP
offset is still derived from the same allocation. Width/offset checks remain the responsibility
of access classification and materialization. If the source program computes an out-of-bounds
derived address and dereferences it, the normal defined-behavior assumption applies; this plan
does not use offset reasoning to discard a possible in-bounds alias to a different allocation.

Any of the following is an exposure boundary:

- storing the derived address as a value;
- passing it as an argument to any call, including a resolved internal direct call;
- using it as an indirect-call callee;
- carrying it across a function boundary through an argument, parameter, return, result, or
  other cross-scope Assign binding;
- `PtrToInt`, integer arithmetic, or an `IntToPtr` provenance gap;
- an unknown/unsupported instruction operand or result;
- inline assembly whose operand-local exposure includes the derived address;
- capture by a global initializer;
- exported storage under the selected build mode;
- a mixed-root or incomplete Assign join, where a proven canonical null alternative is complete
  and contributes the empty origin set rather than making the join incomplete;
- use as a source or destination address of modeled `Memcpy`/`Memset` in v1;
- any producer/use absent from the exhaustive PAG operation match.

An `external_universal` or genuinely module-wide origin continues to defeat candidate exclusion.
The implementation must preserve the pre-filter envelope in `pointee_globals_unfiltered` and
the existing differential narrowing assertions.

## 5. Proposed implementation

### 5.1 Compute one shared allocation-root certificate

Compute the shared storage-root result once from the PIR/PAG and thread the same result object
through solving and API ModRef construction:

```rust
let storage_roots = allocation_storage_roots(pir, pag)?;
let exact_addresses = exact_allocation_addresses(pag, &storage_roots);
let global_address_exposed =
    global_address_exposure(pir, pag, &storage_roots);
let precise_storage =
    precise_storage_addresses(pag, global_lookup, &storage_roots)?;
```

Do not add a second points-to solution or recompute an independent root fixpoint in the API.
Standalone solver entry points may construct the certificate internally, but the API pipeline
must use an entry point that accepts and returns or otherwise retains the same `StorageRoots`
instance for ModRef construction. `FieldLocation` remains solver-specific; storage identity
comes only from the shared certificate.

When calculating `FieldLocation` for an Assign join, discard only `ProvenNull` alternatives
before comparing the remaining addresses. One or more same-root non-null alternatives retain
their common root and normal location-merge semantics. An `Unknown` alternative still invalidates
the exact-address result.

Build `global_index_by_root: HashMap<NodeId, usize>` from canonical global object roots. For every
PAG node whose `storage_roots[node]` names a global root, both layers use the same global storage
identity.

### 5.2 Classify every use of a derived address

Replace the direct-symbol-only edge scan with an exhaustive edge-use scan. For each edge:

- `AddrOf`: seeds the root only when it is the destination's sole value producer. If that node
  has any additional value-producing edge—including another `AddrOf`, `Assign`, `Load`, `Gep`, or
  unsupported future producer—the node is `Unknown` and every global named by an incoming
  `AddrOf` is exposed.
- `Gep`: safe only when the destination retains the source's exact root. If the source has a
  global root and the destination has no root or a different root, mark the source global
  exposed.
- `Assign`: safe only when every producer is either the same exact root or proven canonical
  null, at least one producer has that root, and every source and destination has the same
  semantic scope. Null is the complete empty alternative; it is not an unknown root. A
  mixed/incomplete producer set or cross-scope binding marks each known incoming global root
  exposed. In particular, caller-argument → callee-parameter and callee-return → caller-result
  Assign edges are boundaries in v1.
- `Load`: the source is a safe address use. A derived address appearing in any other role is an
  exposure.
- `Store`: the destination is ordinarily a safe address use; a derived address used as the
  stored source value is exposure. The synthetic `Store` emitted for `Stmt::Memset` is an
  exception and must be marked exposed by the PIR statement scan described below.
- `Memcpy`: any derived global address used as a source or destination marks that global
  exposed in v1. `Stmt::Memcpy` lowers to a bare PAG edge without a callsite record, and the
  `MemsetMemcpy` ModRef path enumerates `resolution.pointee_globals`; until that path consumes
  the same exact-root certificate, filtering the root from the pointee class could erase the
  operation's real Mod/Ref row.

The match must have a fail-closed wildcard or compile-time exhaustiveness over `EdgeKind`. Adding
a future edge kind must not silently admit it.

### 5.3 Classify non-edge boundaries

Retain the current callsite, Ω-seed, initializer, and export checks, generalized from direct
symbols to all derived-address nodes:

- scan `Stmt::Memcpy` and `Stmt::Memset` operands in function bodies and global initializers,
  resolve their PAG operand nodes, and mark every exact global root exposed. This is required
  for `Memset`, which lowers to an ordinary `Store` with a synthetic non-pointer source, and
  therefore cannot be distinguished from a normal rooted store by `EdgeKind` alone;
- any derived node used as `callsite.operand` or an argument marks its global exposed in v1,
  regardless of `CallKind`, `external_boundary`, target resolution, or whether a direct callee
  is defined internally;
- any derived node targeted by an Ω seed marks its global exposed;
- an Ω seed on the global object itself also marks it exposed;
- a referenced global in another global's initializer remains exposed;
- exported globals remain exposed according to executable/library build-mode policy;
- after shared-root propagation, any `NodeKind::Return` whose node has a derived global root
  marks that global exposed. There is no v1 exception for internal-only helpers;
- inspect every `Assign` endpoint with a semantic-scope helper over `NodeKind`: function-scoped
  `Value`, `Param`, and `Return` nodes name their function; module/global-init nodes name their
  corresponding non-function scope. If source and destination scopes differ, any known derived
  global root on an incoming endpoint is exposed. This concretely catches internal
  argument→parameter and return→result bindings without requiring a separate return-node summary.

This scope deliberately admits local array indexing but not helper-function address passing.
The latter belongs to the broader global-centric address-flow work described in
`20260722_POTENTIAL_UNKNOWN_ACCESS_REFINEMENT.md`.

The non-edge scan is not a fallback for modeled memory operations: the bare `Memcpy` edge has
no corresponding callsite record. Its fail-closed treatment must therefore live in the edge-use
classification itself.

#### Existing direct-memset path checked

The suspected pre-existing direct-symbol hole is not present for the direct forms covered today.
`push_pointer_memset_modrefs_from_pir` checks `global_lookup.get(dst)` and then
`label_known_global(dst, global_lookup)` before consulting `resolution.pointee_globals`; either
direct match emits a named `Access::Mod` row in the `MemsetMemcpy` phase and continues. The
`PagPointer` walk's `direct_global_symbols` branch therefore suppresses a duplicate, not the only
row.

The existing `steens_memset_modref_exports_direct_aliased_and_unknown_store_rows` fixture covers
both `@DirectDst` and a bitcast constant-expression destination. Its focused test passed on
2026-08-20:

```text
cargo test -p pangs-api --test analysis \
  steens_memset_modref_exports_direct_aliased_and_unknown_store_rows -- --exact
result: 1 passed, 0 failed
```

That test proves raw row presence, but it does not by itself assert the complete downstream
writer contract. Phase 2 strengthens it before changing exposure behavior.

### 5.4 Preserve raw and filtered solver answers

No output schema change is required. Continue to:

- filter only finite, non-universal pointee enumerations;
- emit the original class enumeration in `pointee_globals_unfiltered` when filtering removes a
  candidate;
- include narrowing provenance and run the existing `debug_assert_narrows` checks;
- avoid changing the actual points-to fixpoint or indirect-call targets.

Add counters to `SolveMetrics` only if they are useful for corpus validation and can be added
with serde defaults. Suggested counters are:

```text
global_addresses_unexposed_direct
global_addresses_unexposed_derived
global_addresses_exposed_by_boundary.<reason>
pointee_candidates_removed_by_derived_exposure
```

Metrics must not affect solving or artifact semantics.

### 5.5 Make allocation-root agreement a soundness invariant

The solver and API must not run independent root fixpoints once derived uses can justify
candidate removal. If exposure admits a node as a safe rooted access but
`precise_storage_addresses` does not assign that node to the same global, the API falls through
to class enumeration. That enumeration has already filtered out the global, so the real access
can disappear. Tests alone cannot exclude a target-specific key-normalization mismatch.

Extract one root-only analysis into the lowest non-cyclic shared crate, preferably `pangs-pag`:

```text
allocation_storage_roots(pir, pag)
    -> node-indexed StorageRootState

StorageRoot ::= Global { object_node, pir_global_index, canonical_key }
              | LocalAlloca { object_node }

StorageRootState ::= Unknown
                   | ProvenNull
                   | Root(StorageRoot)
```

The shared pass is the sole authority for allocation identity. It must:

- build the complete value-producer table before assigning any root state. Memory-consumer roles
  such as a `Store` destination or `Load` address are uses, not producers;
- seed a root from `AddrOf` only when its source is a recognized allocation object and it is the
  destination node's sole value producer. An `AddrOf` destination with any additional producer,
  including a duplicate `AddrOf`, is `Unknown`; every global allocation on its incoming
  `AddrOf` edges is forced exposed before candidate filtering;
- classify only the canonical PIR/PAG null constant as `ProvenNull`. Centralize this predicate
  and make `bounded_allocation_origins` consume it too; do not infer null merely from a missing
  root;
- propagate roots through GEP and complete same-root-or-proven-null Assign joins using the
  admitted grammar. Such a join yields the common non-null root; an all-null join yields
  `ProvenNull` and never invents a storage root;
- stop at loads, mixed/incomplete joins, and unsupported producers;
- canonicalize global keys once, accepting the PIR/PAG `@` spelling difference without creating
  two identities;
- return a node-indexed result consumed directly by both `pangs-solve` exposure and
  `pangs-api` precise-storage attribution.

`exact_allocation_addresses` may retain its solver-only offset/lane calculation, but its
allocation-root field must come from the shared result rather than a second root propagation.
Likewise, `precise_storage_addresses` must build `global_bases` and `local_roots` from the shared
result rather than reseeding and iterating independently.

`label_known_global` and `sym:global:` parsing may remain for legacy direct/constant-expression
row recognition, but neither may establish the root certificate for a node whose global was
removed from a finite fallback set.

The null predicate must recognize only the canonical pointer-null operand produced by PIR/PAG
lowering. `undef`, `poison`, integer zero without proven pointer-null lowering, unsupported
rootless nodes, and user values with null-like names remain `Unknown`. If the current label-based
representation cannot enforce that distinction for all valid PIR, add an explicit null marker
to the PAG rather than broadening the label heuristic.

Add an always-on construction check before filtered `NodeResolution` materialization: every
shared `Global` root's PIR ordinal and canonical key must map to exactly one matching `GlobalId`.
A missing mapping forces that PIR global's exposure bit to true; a conflicting or ambiguous
mapping disables exposure filtering for the module. Thus the solver retains the raw candidates
before the API can build ModRef. Afterward, every admitted safe Load/Store address for an
unexposed global must map through `global_bases` to that same ID. A failure of this postcondition
also aborts filtered emission rather than skipping the row. Warnings or debug-only assertions
are insufficient, and silently continuing with the filtered set is forbidden.

This shared helper avoids a dependency from `pangs-solve` back to `pangs-api` while making root
agreement part of the executable proof rather than a follow-up refactor.

## 6. Work plan

### Phase 0 — freeze the false negative

- Add a synthetic PIR/PAG fixture containing:
  - a static array of pointers;
  - dynamic-index GEP stores and loads;
  - pointers to a separate immutable global stored as element payloads;
  - an unrelated pointer-to-integer round trip;
  - unrelated operand-local inline assembly or an equivalent unknown operation.
- Assert the current failure before changing policy:
  - the array enters unrelated finite pointee sets;
  - false ModRef rows appear outside its defining accessor;
  - violation relevance becomes hard;
  - localization is independently `ok` but the final disposition is `unhandled`.
- Retain the current curl artifact directory and input hash as the before snapshot.
- Record independent baseline facts before implementation. In the retained curl artifact,
  `src/tool_getparam.c::findshortopt.singles` has
  `facts.omega_escaped_address.value == false`. This value comes from solver escape state and is
  not produced by `global_address_exposure`.
- Keep the focused direct-memset regression above as an early prerequisite. A failure after the
  implementation is a regression in the existing direct syntactic path, not an expected
  consequence of derived-address filtering.

### Phase 1 — derived-address exposure in `pangs-solve`

- Extract the shared allocation-root pass and canonical global-key normalization into the
  lowest non-cyclic crate.
- Centralize canonical pointer-null recognition and reuse it in the shared root pass and bounded
  allocation origins.
- Make both `exact_allocation_addresses` and `precise_storage_addresses` consume that result;
  remove their independent root seeding/propagation as certificate authorities.
- Pass the shared roots into `global_address_exposure`.
- Implement exhaustive derived-node use classification.
- Implement semantic endpoint-scope classification and explicit rooted-`NodeKind::Return`
  scanning. Cross-scope Assigns and all rooted return nodes are exposure boundaries.
- Add the always-on pre-filter API construction check for safe-use/root/`GlobalId` agreement.
  Missing mappings force the implicated global exposed; conflicts disable the filter module-wide.
- Preserve current direct scalar `Load`/`Store` behavior exactly.
- Treat direct-symbol and derived `Memcpy`/`Memset` operands as exposed. Direct-symbol `Memcpy`
  is already exposed today; the conservative `Memset` exception is intentional and must be
  recorded as a behavior change if a direct-symbol fixture shows a transition.
- Add solver fixtures for a resolved internal direct call receiving `&g[i]` and an internal
  helper returning `&g[i]`. Assert exposure even when `external_boundary == false`, and assert
  both the rooted `Return` scan and cross-scope Assign classification are exercised.
- Add Assign-join fixtures for `{&g[i], null}`, `{null, null}`, `{&g[i], unknown}`, and
  `{&g[i], &h[j]}`. Only the first retains `g`'s root; all-null retains no storage root; the
  latter two expose every known incoming global root.
- Add malformed/non-SSA producer fixtures where one node has `AddrOf(g)` plus `Assign(h)`,
  `AddrOf(g)` plus `Load`, and duplicate `AddrOf` producers. Assert `Unknown`, force every
  incoming AddrOf global exposed, and retain raw fallback candidates.
- Add solver unit tests for filtering and raw-envelope retention.
- Run `cargo test -p pangs-pag -p pangs-solve -p pangs-api` and the solver
  differential/monotonicity tests.

### Phase 2 — ModRef and violation-relevance regression tests

- Add an API test proving that the synthetic array has only its real rooted access sites.
- Add key-format variants (`g` and `@g`) and assert identical shared roots and `GlobalId`
  attribution.
- Inject a missing root-to-`GlobalId` mapping and assert the implicated global is forced exposed;
  inject a conflicting mapping and assert exposure filtering is disabled module-wide.
- Assert that unrelated finite unknown rows exclude the array while retaining genuinely exposed
  candidates.
- Assert that unrelated `PtrToInt`/`IntToPtr`, varargs, and inline-assembly findings are not
  proposed for the array after candidate filtering.
- Assert that an actual finding on an array-derived address remains `address-relevant`.
- Strengthen the direct-symbol `Memset` fixture for both `g`/`@g` spellings and constant-expression
  destinations. For a global written only by that memset, assert exactly one effective Mod
  access, `runtime_written == true`, `never_written == false`, and retention in downstream writer
  sets under both Steensgaard and Andersen. Then add the corresponding derived-address
  `Memcpy`/`Memset` fixtures and assert their source/destination rows are retained.
- Add a disposition regression in which a modeled memory operation is the only post-publication
  writer. Assert that phase stationarity and once-lock cannot succeed by losing that writer.
- Run `cargo test -p pangs-api -p pangs-clients -p pangs-dispose`.

### Phase 3 — curl remeasurement

Rebuild release binaries and rerun the exact disposition runbook on the same bytes:

```text
/home/brk/pangs-corpus/_out_bc/exe-curl-O0.bc
sha256 392593ddebef78fc557bef1045622e53e07e72293cd56a0e102d973736d9a8d6
repo root /home/brk/pangs-corpus/curl
Andersen, executable/application, no overrides, --validate
```

Before interpreting coverage, require identical input SHA, configuration, and global key set.
Compare full artifacts, runtime, and peak RSS.

For `src/tool_getparam.c::findshortopt.singles`, acceptance requires:

- `facts.omega_escaped_address.value` remains equal to its verified baseline value, `false`.
  This is a non-regression check on independent solver escape machinery, not an outcome this
  repair is expected to establish. If it changes, stop and explain that separate escape-state
  transition rather than attributing it to derived-address exposure;
- `violation_taint == false` unless a finding names a real derived address of `singles`;
- the only runtime accessor function is `findshortopt`;
- access sites correspond to the element store and load, plus only explicitly justified
  initializer/runtime sites;
- localization remains `ok` with no blockers;
- the final disposition is handled unless a distinct, newly evidenced guard fails.

Record, but do not preordain, whether the final strategy becomes once-lock, mutex, or localize.
The cascade choice depends on the recovered phase and coupling certificates.

Inspect all other transitions. In particular:

- `aliases` must remain exposed because its element addresses are stored into `singles`;
- `fnames` must retain its aggregate-initializer address dependency;
- callback-bound globals such as `tool_stderr` must not become localizable merely because this
  filter changed;
- any transition for `no_protos`, `str2tls_max.tls_max_array`, or another array-like global must
  have a source-level explanation under the same derived-address rule.

### Phase 4 — corpus and documentation gate

- Run the full workspace test suite.
- Rerun the established small-to-large disposition corpus, recording:
  - distribution changes;
  - candidate-removal counts;
  - access-set completeness changes;
  - violation-taint changes;
  - phase/atomic/mutex certificate changes;
  - runtime and peak RSS.
- Manually audit every newly handled global in at least curl plus one other affected module.
- Update `DISPOSITION.md` and the relevant implementation-status plan only after the behavior is
  validated. Document that GEP derivation does not constitute exposure; escape is determined by
  uses of the derived address.

## 7. Test matrix

### Positive: remain unexposed

- constant-index GEP followed by a load;
- dynamic-index GEP followed by a store;
- chained GEPs within one global allocation;
- same-root `phi`/`select` lowered as Assign alternatives;
- a same-root-plus-canonical-null `phi`/`select`, such as
  `p = cond ? &g[i] : NULL`, followed by a safe load/store;
- same-root Assign chains among ordinary value nodes wholly within one function, excluding
  call bindings and `Return` nodes;
- pointer-valued elements whose payloads point to another global or heap allocation;
- unrelated inline assembly and integer-pointer conversions with disjoint operand flow.

### Negative: must be exposed

- store `&g[i]` into another memory object;
- pass `&g[i]` to any call, including a resolved direct call to an internal helper;
- bind `&g[i]` from a caller argument to an internal callee parameter;
- return `&g[i]` from an internal or externally reachable helper;
- bind a rooted callee `Return` node to a caller result;
- convert `&g[i]` to an integer;
- use `&g[i]` as an unknown-operation or inline-assembly operand;
- merge `&g[i]` with `&h[j]` or an unknown pointer;
- merge `&g[i]` with `undef`, `poison`, an unsupported rootless value, or a null-like user value;
- give one address node an `AddrOf(g)` producer plus any other value producer, even one that
  appears redundant or null;
- capture `&g[i]` in a global initializer;
- use `&g[i]` or `&g` as a modeled memcpy/memset source or destination in v1;
- exported global under library policy;
- universal integer-forged or external pointer access.

### Invariants

- filtered candidates are a subset of the pre-filter envelope;
- universal answers never narrow through this proof;
- direct named ModRef rows are unchanged;
- memcpy/memset ModRef rows for direct or derived global storage are never removed by the v1
  exposure proof;
- indirect-call target sets are unchanged;
- the proof depends on allocation roots, never on type compatibility alone;
- every safe-use address node admitted for an unexposed global has the same global identity in
  the shared certificate and API `global_bases`;
- canonical null is a complete empty origin alternative; no other rootless state is treated as
  null, and an all-null join never acquires a global root;
- an `AddrOf` root is admitted only for a node with exactly one value producer; additional
  producers make it `Unknown` and force all incoming AddrOf globals exposed;
- a missing shared-root-to-`GlobalId` mapping forces the implicated global exposed, while an
  ambiguous mapping disables exposure filtering module-wide, before filtered materialization;
- storing a pointer payload does not expose the containing storage allocation;
- adding an unsupported PAG edge or producer fails closed.

## 8. Performance expectations

The new shared certificate replaces two near-duplicate root fixpoints. Root derivation plus
exposure classification should remain linear in PAG/PIR size:

```text
O(nodes + edges + callsite operands + seeds + initializer refs)
```

Use node-indexed root vectors and global-indexed bitsets/booleans. Do not construct a per-global
graph traversal. Thread one shared root vector through the pipeline rather than cloning or
recomputing it. The solver may retain a separate compact field-location vector, but not another
allocation-root authority.

The downstream effect should reduce ModRef rows, access-site fanout, violation-relevance pairs,
and certificate work. Curl's current 2,739 alleged sites for `findshortopt.singles` provide a
clear performance as well as precision counter.

## 9. Risks and mitigations

### Risk: treating address derivation as harmless after it escapes

Mitigation: classify every use of every derived node, not only the first GEP. Mixed/incomplete
derivations and unknown uses fail closed. All call arguments are boundaries regardless of call
kind or resolution; rooted return nodes and cross-scope Assign bindings are also boundaries.

### Risk: confusing storage with stored pointer payloads

Mitigation: root identity flows only through address-preserving PAG edges. `Load` does not
propagate the storage root into its result, and `Store` treats the source as an escaping address
only when that source independently has a derived-address root.

### Risk: treating an unknown rootless producer as null

Mitigation: represent `ProvenNull` separately from `Unknown` in the shared root state and use one
canonical null predicate across root analyses. Only proven null contributes the complete empty
origin set. Add negative fixtures for `undef`, `poison`, unsupported producers, and null-like
user names; if canonical null cannot be recognized without label ambiguity, add an explicit PAG
marker.

### Risk: pre-seeding AddrOf hides another producer

Mitigation: construct the exhaustive value-producer table before assigning states and never skip
a node merely because an AddrOf pre-pass populated it. Exactly one recognized `AddrOf` may seed
a root. Any sibling producer makes the node `Unknown` and forces incoming AddrOf globals exposed;
tests cover mixed, duplicate, and unsupported producers even if valid LLVM SSA normally excludes
them.

### Risk: divergence between solver and API root analyses

This is a soundness risk: disagreement can make a safe rooted access fall through to an already
filtered pointee class and silently erase its Mod/Ref row.

Mitigation: remove the independent fixpoints in Phase 1. Both consumers use the same shared
`StorageRoots` result and canonical global identity. Enforce the safe-use-to-`global_bases`
agreement before filtering: missing identities force the implicated global exposed and
ambiguous identities disable filtering module-wide. Debug-only assertions and corpus fixtures
are insufficient.

### Risk: accidental narrowing of universal unknowns

Mitigation: retain the current universal/module-wide guard, raw envelopes, and differential
narrowing assertions. Add explicit negative tests for integer-forged pointers and opaque calls.

### Risk: dropping a memcpy/memset writer after filtering its allocation root

The `MemsetMemcpy` access path does not currently consult `precise_storage_addresses`; it builds
rows from the exposure-filtered `resolution.pointee_globals`. Treating its operands as safe
could therefore remove the only writer row for a global. That lost writer would contaminate
phase-stationarity writer sets, D3/D4 access recipes, TransMod/thread-writer reachability, and
transitive Mod/Ref, potentially allowing an unsound once-lock certificate.

Mitigation: v1 treats every modeled memcpy/memset source and destination rooted in a global as
an exposure boundary. Admitting such operands as safe is a separate extension and must land
atomically with root-certificate attribution in the `MemsetMemcpy` ModRef builder, plus tests
covering reads, writes, dynamic derived addresses, and post-publication writers. Only after that
extension may the corresponding negative exposure tests move into the positive matrix.

### Risk: coverage moves for many array globals

Mitigation: treat the corpus diff as an audit queue. A large positive coverage delta is not by
itself acceptance; every transition class needs representative source inspection and stable
negative tests.

## 10. Completion criteria

This plan is complete when:

1. the derived-address grammar and all escape boundaries have executable tests;
2. AddrOf roots require exactly one value producer, and malformed/multiple producers force every
   incoming AddrOf global exposed;
3. null-alternative joins retain a common non-null root only for canonical null, while unknown,
   mixed-root, `undef`, and `poison` alternatives fail closed;
4. solver exposure and API ModRef consume one shared root certificate and canonical global-key
   mapping;
5. the always-on agreement check demonstrably forces exposure for missing mappings and disables
   filtering module-wide for conflicting mappings;
6. solver filtering, API ModRef, and violation relevance agree on the synthetic fixtures;
7. `findshortopt.singles` no longer receives unrelated access or violation witnesses;
8. curl validation passes on unchanged input bytes and its key set is unchanged;
9. genuine address escapes (`aliases`, `fnames`, internal/external call boundaries, rooted
   returns, and callbacks) remain conservative;
10. direct and derived memcpy/memset operands remain exposed and retain all real ModRef rows;
11. a memory-operation-only post-publication writer prevents once-lock certification;
12. the full workspace and corpus gates pass without an unexplained disposition regression; and
13. the measured coverage, runtime, and RSS deltas are recorded alongside retained artifacts.

## 11. Non-goals

- replacing PANGS's PAG with separate global `var_points_to`/`ptr_points_to` tables;
- general context-sensitive or field-sensitive pointer-analysis redesign;
- admitting arbitrary pointer-to-integer round trips;
- following global addresses through helper functions or memory-resident aliases;
- relaxing callback localization boundaries;
- changing cascade order, overrides, or materialization policy;
- treating successful source inspection as a substitute for a machine-checkable negative proof.
