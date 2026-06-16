# M3.3 callee fixpoint notes

Date: 2026-06-16

M3.3 adds an explicit fixpoint mode for MHS callee queries:

```bash
pangs query callees <module.bc|module.pir.json> --mode field-sensitive-fixpoint
```

## Semantics implemented

- Round 0 runs over the frozen PAG with no synthetic indirect-call bindings.
- When a query discovers an indirect call target, the next round's query graph adds
  Assign-shaped bindings for that concrete target:
  - actual argument nodes flow to the target function's parameter nodes;
  - the target function's return node flows to the call result node.
- Imported/external function targets do not receive synthetic bindings, matching direct
  call lowering.
- The fixpoint is monotone: discovered `(callsite, target)` pairs only grow.
- Scheduling is dependency tracked:
  - queries that touched an unresolved indirect call's argument/result positions are
    rerun when that callsite gains a target;
  - queries that touched a function return node are rerun when an indirect call gains
    that function as a target.

## Synthetic coverage

Focused tests cover:

- argument-dependent discovery: resolving `driver`'s indirect call to `invoke` creates
  the `target -> invoke.param0` binding needed to resolve `invoke`'s nested indirect
  call in round 1.
- return-dependent discovery: resolving `driver`'s indirect call to `choose` creates the
  `choose.ret -> driver.result` binding needed to resolve a second indirect call through
  the returned function pointer in round 1.
- CLI JSON reports fixpoint rounds, new target counts, dependency-bearing queries, and
  final `by_callsite` answers.

This is still a query-kernel surface. The main `analyze` pipeline has not yet adopted
tier-E callee answers or exported them into `callgraph.jsonl`.
