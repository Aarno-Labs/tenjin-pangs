# cclyzer — "Structure-Sensitive Points-To Analysis for C and C++" (Balatsouras & Smaragdakis, SAS 2016)

## What it is
Inclusion-based (Andersen-style) whole-program points-to analysis for LLVM bitcode, written declaratively in Datalog (LogicBlox engine). This is the baseline the user's existing analysis extends.

## Key techniques
1. **Typed abstract objects everywhere.** Every abstract object must have a single type; type info is used to *filter* spurious derivations. Objects: stack/heap alloc per site `ô_i`, type-specialized heap object `ô_{i,T}`, global `ô_g`, field subobject `ô.fld`, array subobject at constant index `ô[c]`, array subobject at unknown index `ô[*]`.
2. **Allocation-site + type abstraction (HEAP-BP rule / use-based back-propagation):** untyped malloc objects spawn a new typed abstract object `ô_{i,T}` whenever the untyped object flows to a cast to T. Handles malloc wrappers (xmalloc) precisely — each typed variant filtered by use.
3. **Field subobjects as first-class abstract objects** (recursive, bounded by the type system). Field accesses only create subobjects when base object's type is known and matches → invariant: only create subobjects whose types we can determine.
4. **Array sensitivity:** distinct objects for constant indices `ô[c]` and unknown index `ô[*]`, related by a *generalization partial order* ⊑ (MATCH/LOAD-II rules): loads from `ô[c]` must also return contents of generalizing objects (`ô[*]`); points-to of less-general is a superset of more-general.
5. **On-the-fly call graph**: call-graph edges derived simultaneously with points-to; indirect calls resolved via the function-pointer's points-to set. Crucial for C++ vtables: vtable = constant array of fn ptrs; array sensitivity keeps per-index points-to sets distinct, so virtual calls resolve precisely.
6. Partial SSA / LLVM model: virtual registers (SSA, set V) vs. memory (alloca'd address-taken vars, globals). Relations: variable points-to (P×O), dereference edges (O×O, only from stores), abstract object types (O⇀T), call-graph edges (L×F).

## Soundness stance
Deliberately not strictly sound (follows Avots et al.): single-type-per-lifetime assumption for concrete objects; unions handled OK if discriminated; custom allocators need modeling. Opts for precision over conservatism.

## Evaluation / scalability data
- Benchmarks: 8 coreutils + 14 PostgreSQL executables (≤1.4MB bitcode). Single-threaded LogicBlox.
- Runtimes ~17–68 s on these *small* programs; creates 1–2 orders of magnitude more abstract objects than Pearce-style (e.g., psql: 460K abstract objects vs 14K), yet resolves 36–58% more variables to a single target.
- NOTE: this is precise but the object explosion (typed variants × field/array subobjects) is exactly what hurts scalability when extended (user's experience: extended cclyzer scales poorly; Souffle failed to parallelize it).

## Relevance to our design
- The *structure-sensitivity* ideas (typed objects, field/array subobjects, back-propagation for malloc wrappers, vtable index precision) are the precision gold standard for C→Rust conversion needs (mutability/escape need field-level precision).
- The cost center: global exhaustive inclusion-based solving over a huge object domain. A hybrid should keep the object abstraction but avoid exhaustive whole-program Andersen via Datalog.
