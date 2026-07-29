To generalize this properly, PANGS needs a small relational “variant provenance” layer alongside the pointer analysis. Andersen alone cannot express “this payload is a function pointer specifically when its sibling tag equals `VAL_XT`.”

The essential abstraction would be:

```text
(carrier, discriminator projection, discriminator value, payload projection)
    -> {named function targets, open/incomplete bit}
```

For Slap, one fact would resemble:

```text
(Value object, tag@0, VAL_XT, as.xt.fn@24) -> {105 primitive functions}
```

This should be an overlay certificate. The ordinary points-to solution remains conservative and Ω-contaminated; only a guarded indirect-call query uses the relational result.

### 1. Retain scalar control-flow facts

PIR currently preserves the pointer transfers needed by the PAG, but not enough CFG semantics to reconstruct variant guards. We would need to record:

- basic blocks and dominance;
- comparisons of scalar loads against constants;
- branch and switch edge conditions;
- simple predicate wrappers such as `is_callback_kind(tag)`;
- the object projection from which the discriminator was loaded.

At the call, the certificate must establish both that `tag == VAL_XT` dominates the call and that the tested tag belongs to the same object instance as the loaded callback. A test on one object must not refine another object’s payload.

It is probably better to add a compact `ControlFact` side table than turn the pointer-oriented `Stmt` representation into a complete LLVM IR.

### 2. Represent projections without relying on typed pointers

Discriminator and payload fields should be identified using:

```text
allocation/origin + byte offset + access width
```

For arrays, we also need query-relative index correlation:

```text
base + index-expression + member offset
```

The existing `Exact`/`Lane`/`Unknown` field domain can describe which locations may alias, but a lane alone loses the fact that `table[i].tag` and `table[i].callback` use the same `i`. The certificate should preserve equality between SSA index expressions while walking a particular query.

This keeps the implementation opaque-pointer clean: LLVM `DataLayout`, GEP byte offsets, access widths, and SSA identity are sufficient. LLVM struct types or debug information can be optional hints, not correctness requirements.

### 3. Infer variant schemas

LLVM bitcode generally does not say “this is a tagged union.” We would infer candidates starting from guarded payload uses:

1. Find an indirect call through a loaded aggregate projection.
2. Find dominating comparisons or switches over sibling projections.
3. Find constant discriminator values written by the callback’s producers.
4. Check whether discriminator and payload travel together through the program.

This recognizes more than literal C unions:

```c
struct Event {
    enum EventKind kind;
    void (*callback)(void *);
};
```

```c
struct RegistryEntry {
    bool occupied;
    unsigned opcode;
    Handler handler;
};
```

```c
struct Value {
    Tag tag;
    union Payload payload;
};
```

The discriminator could be an enum, boolean, integer range, bit mask, or nested tag. Initially, equality against an integer constant and `switch` cases would cover the most common and safest subset.

### 4. Preserve tag/payload correlation through transfers

The analysis must recognize operations that move an entire variant value:

- SSA aggregate insertion/extraction;
- whole-aggregate loads and stores;
- direct-call arguments and returns;
- `memcpy` with a known sufficient width;
- copies between corresponding allocation-relative projections;
- PHI/select joins.

Each transfer needs one shared copy identity so the tag and payload cannot be recombined independently.

For example:

```c
Value x = array[i];
```

must transfer both:

```text
array[i].tag   -> x.tag
array[i].fn    -> x.fn
```

as one correlated operation. Treating those as unrelated flow-insensitive edges recreates the current problem.

Unknown-length or partial copies need careful treatment:

- a copy known to cover both tag and payload can preserve the relation;
- a copy covering only the payload contaminates the affected variant;
- an unknown-width copy fails the certificate unless its range can be bounded;
- overlapping copy or union-style type punning should normally fail closed.

### 5. Summarize constructors and mutators compositionally

The most tractable first version should recognize constructor-like regions:

```c
Value make_callback(unsigned id, Handler fn) {
    Value v = {0};
    v.tag = CALLBACK;
    v.payload.callback.fn = fn;
    return v;
}
```

Its summary becomes:

```text
return.tag = CALLBACK
return.callback.fn <- argument fn
complete
```

A constructor is certifiable when:

- its temporary object does not escape before initialization;
- the discriminator and relevant payload are both initialized;
- all exits provide a compatible variant;
- no opaque write intervenes.

The same mechanism can summarize setters that atomically establish a new logical variant. Arbitrary independently ordered field mutations are harder: either use a flow-sensitive reaching-definition analysis or mark the affected variant open. Starting with constructor summaries and immutable-after-publication variant objects would likely cover Slap and many AST, event, and interpreter representations.

### 6. Use a per-variant abstract domain

For each discovered schema, the domain could be:

```text
VariantFacts {
    cases: TagValue -> PayloadFacts,
    unknown_tag: bool,
}

PayloadFacts {
    targets: finite set<Function>,
    external: bool,
    non_function: bool,
    incomplete: bool,
}
```

Joining two paths unions their facts within the same tag case:

```text
CALLBACK -> {f, g}
INTEGER  -> non-function payload
```

Crucially, it does not flatten them into:

```text
payload -> {f, g, non-function}
```

At a call guarded by `tag == CALLBACK`, only the `CALLBACK` row is queried.

### 7. Make it demand-driven

The rejected experiment solved variant-like address flow for the entire module and produced 45,971 vertices and more than 500,000 dependencies. That architecture is too expensive.

Instead:

1. Begin at an unresolved indirect-call operand.
2. Find its controlling discriminator guard.
3. Walk backward only through transfers capable of producing that payload.
4. Request sibling discriminator facts along the same transfers.
5. Build and memoize SCC summaries for the encountered slice.
6. Stop at closed constructors, exact addresses, or an open boundary.

Queries that encounter the same containers or helper functions reuse the summary. The state space is bounded by call operands, observed discriminator constants, and fixed PIR projections—not every possible `(object, tag, field)` combination in the module.

### 8. Define conservative contamination rules

A variant case must remain Ω/open if its carrier can be affected by:

- an external or unknown call that may modify it;
- an unknown-offset store overlapping tag or payload;
- pointer/integer reconstruction of the payload;
- exported or opaque storage;
- an unmodelled aggregate copy;
- a partial mutation that breaks tag/payload pairing;
- a guard and payload access that cannot be proven to refer to the same object;
- an admission cut hiding a relevant producer;
- concurrent mutation where stability cannot be established.

Other union members are not themselves contamination once the discriminator relationship is proven. That distinction is the main precision benefit.

### 9. Integrate it as a certificate

The existing closed-producer decision requires a complete producer component, no external/non-function alternatives, and a nonempty named target set ([andersen.rs](/home/brk/pangs/crates/pangs-solve/src/andersen.rs:3828)). The variant certificate would provide an additional way to satisfy those conditions:

```text
ordinary operand producer incomplete
+
dominating guard selects case K
+
case-K producer certificate complete
=
finite indirect-call target set
```

It would then clear `unknown_callee` only for that callsite. The base Andersen facts, Ω propagation, and other clients remain unchanged.

The existing closed-consumer certificate supplies the complementary proof that the selected named functions have no unrepresented incoming callers. Together, those two certificates should allow the context-rewrite planner to localize the three Slap globals without changing its ABI-safety rule.

### 10. Required validation

Important positive tests would cover:

- local tagged-union construction and guarded call;
- values returned through helper constructors;
- whole-object copies and PHIs;
- arrays where tag and callback use the same dynamic index;
- switches with several callback-bearing cases;
- multiple callback fields in one case;
- callback-bearing structs without a C union.

Negative tests should cover:

- guard and callback loaded from different objects;
- unknown or different array indices;
- external mutation between guard and call;
- payload-only `memcpy`;
- uninitialized callback field;
- an unknown-tag producer;
- a valid externally supplied callback;
- discriminator changed without rewriting the payload;
- unsupported bit manipulation or type punning.

The key narrowing invariant remains:

```text
variant-qualified targets ⊆ ordinary FSA/Steensgaard target envelope
```

A supposedly complete certificate must never produce an empty finite set unless the call is proven unreachable.

In implementation terms, this is a moderate architectural addition rather than a tweak to Andersen: compact CFG/predicate metadata in `pangs-pir`, correlated aggregate-transfer facts in `pangs-pag`, and a demand-driven variant-origin certificate in `pangs-solve`. The payoff is broad, though: it applies to interpreters, event loops, protocol state machines, AST visitors, tagged message queues, plugin registries, and callback-bearing object hierarchies—not just Slap’s `Value` type.
