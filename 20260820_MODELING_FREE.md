# Modeling `free`

Date: 2026-08-20

## Status

Implemented.

## 1. Summary

Model a direct call to the external standard function `free` as having no pointer-analysis or
ModRef effect:

```text
free(p):
    no address escape
    no pointer flow
    no global Mod/Ref effect
    no result
```

Keep the callsite for call-graph and audit output, but do not give it the generic external-call
boundary used for unknown external functions. Treat its sole argument as a safe terminal use in
the global-address-exposure proof.

That is the whole model. Do not add lifetime tracking, a deallocation edge, allocation-kind
proofs, undefined-behavior detection, aliases, configuration, or a general external-summary
framework in this patch.

## 2. Motivation

PANGS currently treats `free(p)` like an arbitrary external call. The generic model marks the
allocation passed as `p` externally reachable and propagates that escape through pointer values
stored in the allocation. This is too strong for `free`: freeing a container does not expose the
objects named by pointer fields in that container.

The false escape is visible in the validated `lib-fribidi-O0.bc` result. FriBidi allocates a
linked `FriBidiPairingNode` whose `open` and `close` fields point to `FriBidiRun` objects, then
destroys the pairing nodes:

```c
static FriBidiPairingNode *
pairing_nodes_push(FriBidiPairingNode *nodes,
                   FriBidiRun *open,
                   FriBidiRun *close)
{
  FriBidiPairingNode *node = fribidi_malloc(sizeof(FriBidiPairingNode));
  node->open = open;
  node->close = close;
  node->next = nodes;
  return node;
}

static void
free_pairing_nodes(FriBidiPairingNode *nodes)
{
  while (nodes) {
    FriBidiPairingNode *p = nodes;
    nodes = nodes->next;
    fribidi_free(p);
  }
}
```

The generic external-call effect at `free(p)` escapes the pairing-node allocation and then its
pointer payload. The retained Steensgaard global-escape fact consequently reports FriBidi's
unrelated static `sentinel` as escaping at that call. The source does not pass `sentinel` to
`free`, and `free` does not capture the pairing node or follow `open` and `close` as application
pointers.

## 3. Semantic contract

PANGS assumes defined C behavior. On a defined execution, the argument to `free` is null or is a
value valid for deallocation. The analysis therefore does not need to prove that its imprecise
points-to set contains only heap allocations. In particular, a spurious global candidate in a
coarse points-to set must not restore the generic external effect.

This design makes no claim about object lifetime. Disposition analysis does not currently use
liveness or use-after-free facts, so representing deallocation would add machinery without
improving the result. If PANGS later gains a lifetime analysis, that work can introduce its own
representation without changing this summary's escape semantics.

The trusted contract applies only to a direct call whose callee resolves to an external
declaration named exactly `free` (after the existing optional `@` normalization) and whose call
shape is compatible with the standard function: one pointer argument and no return value. A
module-defined function named `free`, a name match with the wrong shape, and an indirect or
unresolved call continue to use the existing conservative behavior.

The standard-library contract, rather than any replacement implementation, is the analysis
boundary; this excludes both a statically linked `free` supplied by an unanalyzed translation unit
and dynamic interposition. This is the same kind of trusted-library assumption already used by the
existing allocator, `printf`, `scanf`, and libc result models.

## 4. Implementation

### 4.1 Recognize the call in `pangs-pag`

Add one shared classifier next to the existing external-call helpers in
`crates/pangs-pag/src/lib.rs`. In `Stmt::CallDirect` lowering, use it as follows:

```rust
let trusted_free = trusted_free_call(pir, callee, sig, args.len(), dest.is_some());
```

`trusted_free_call` requires an external callee, the exact normalized standard name, exactly one
actual and one `Integer`-class formal, a non-variadic `Void` signature, and no result. PIR's ABI
signature class represents an LLVM pointer as `Integer`, so this is the strongest shape check
available without adding type information to PIR or the PAG. The exact standard name supplies the
pointer-parameter contract; the remaining checks reject extra arguments, varargs, non-integer ABI
parameters, and non-void/result-producing declarations. A name match without this compatible shape
falls back to an ordinary external boundary.

Include `!trusted_free` in the expression that computes `external_boundary`. No new node, edge,
seed, callsite field, or serialized schema is required. The existing callsite remains present,
but `external_boundary` is false and no `OmegaSeedKind::ExternalCallBoundary` is emitted for it.

This automatically prevents both Steensgaard and Andersen from applying their generic external
argument effects. It also keeps `allocation_isolation` from rejecting an allocation solely
because it is passed to `free`, since that proof already consults `callsite.external_boundary`.

### 4.2 Admit the argument in global-address exposure

`crates/pangs-solve/src/lib.rs::global_address_exposure` independently exposes every rooted node
used as any call argument. That is intentionally stricter than the Ω seed and must receive the
same narrow exception.

When scanning callsites, skip the arguments of a direct external `free` call. Continue exposing:

- every indirect-call operand;
- arguments to every other call;
- arguments to a module-defined `free`;
- arguments to unresolved calls.

Use one shared public or crate-visible predicate, or an equivalently small callsite predicate, so
PAG construction and exposure classification cannot disagree about which call is trusted. Do not
introduce a general call-effect enum for this single no-effect summary.

### 4.3 No API or ModRef special case

Do not add a `free` row builder in `pangs-api`. Once the PAG omits the external-boundary seed,
`free` contributes no load/store edge and therefore no Mod/Ref row. This is the desired result.

### 4.4 Amend the normative design contract

The implementation patch must update `DESIGN_lite.md`; these are semantic amendments, not optional
documentation cleanup.

1. In §2A′, add standard `free` to the exact-name, shape-checked external-summary registry beside
   the ctype and byte/string examples. State its complete summary: a compatible direct external
   call is a no-capture terminal for its sole pointer argument, produces no pointer flow, and has
   no client-state Mod/Ref effect. A module-defined, indirect, unresolved, or shape-mismatched call
   retains the ordinary Ω boundary. This keeps one authoritative inventory of trusted externals.
2. In the closed-consumer certificate's open-terminal list, change the rule that all external and
   vararg arguments are open terminals to exempt the sole pointer argument of a recognized trusted
   `free`. The exception applies transitively to pointer contents reachable only through that
   argument: destroying a container does not publish callbacks stored in it. Every other external
   or vararg argument remains open.
3. Replace the finite-pointee-filter exposure rule with one that admits two kinds of terminal use:
   direct storage access and the sole argument of a recognized trusted `free`. Calls still expose
   a rooted global address except for that one enumerated summary. The justification must no longer
   claim that an unexposed global's address never exists as a program value. Instead, it must say
   that every admitted use is proven non-capturing and non-publishing: direct loads/stores consume
   the address as a storage location, while standard `free` does not retain or propagate its
   argument. Under the defined-C contract, an execution of `free(&global)` need not be represented;
   the analysis neither diagnoses nor compensates for that undefined execution.

The differential `pointee_globals_unfiltered` checks, Ω validation, and future reviews should cite
this amended terminal-use contract. Leaving the old absolute statements in place would make the
implementation contradict its validation specification.

## 5. Tests

Add the smallest regressions that establish the contract.

### PAG

- A direct call to an external declaration named `free` remains in `callsites`, has
  `external_boundary == false`, and has no external-call Ω seed.
- A different external pointer-taking function retains its boundary and seed.
- A call to a module-defined function named `free` is not recognized as the trusted external
  summary.
- An external declaration named `free` with an incompatible call shape retains its boundary and
  seed.

### Solver

Use a fixture in which a heap object contains the address of a global and the heap object is
passed to `free`. Assert that `free` does not become an escape source for the global under both
Steensgaard and Andersen. This directly guards against recursively escaping pointer payload from
the freed container.

Add a rooted-address fixture showing that a derived global address used only as the argument to
the trusted `free` call is admitted by `global_address_exposure`. This fixture documents the
defined-behavior assumption; it does not need an invalid-free diagnostic or a heap-validity
proof.

### Corpus check

Re-run the validated FriBidi measurement with the same input bytes and library configuration.
Require:

- `sentinel_xjtr_0.omega_escaped_address == false`, or at minimum no escape source attributed to
  `free_pairing_nodes`'s call to `free` if another independent escape remains;
- no loss of manifest keys;
- no newly unhandled global;
- no unexpected disposition regressions.

The separate path-insensitive possible write to `sentinel` is outside this design and may remain.

## 6. Non-goals

This patch does not:

- model allocation lifetime or use-after-free;
- prove that the argument is null or heap-allocated;
- detect `free(&global)` or any other undefined behavior;
- model `realloc`, C++ destruction, custom deallocators, `cfree`, or allocator aliases;
- summarize indirect calls that resolve to `free`;
- account for statically or dynamically linked replacement implementations;
- change the generic model for any other external function;
- attempt to resolve FriBidi's independent possible-write or localization blockers.

Each of those can be proposed separately if a concrete corpus case justifies it. None is needed
to correct the current false escape from a direct standard `free` call.

## 7. Validation

Run:

```text
cargo fmt --all -- --check
cargo test -p pangs-pag -p pangs-solve -p pangs-api
cargo test --workspace
```

Then repeat the FriBidi disposition command from `HOWTO_MEASURE_DISPOSITION_COVERAGE.md` using:

```text
input:      /home/brk/pangs-corpus/_out_bc/lib-fribidi-O0.bc
stage:      andersen
build mode: library
overrides:  none
validation: enabled
```

Retain the full manifest and audit artifacts and compare the global key set, disposition
distribution, and `sentinel_xjtr_0` facts against the pre-change run.
