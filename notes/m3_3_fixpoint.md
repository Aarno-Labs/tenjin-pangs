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
- When PIR signatures are available, callsite sinks and synthetic indirect-call bindings
  are filtered through the same ABI/FSA compatibility check used by earlier callgraph
  tiers. The PAG-only helper APIs remain conservative and unfiltered.
- The fixpoint is monotone: discovered `(callsite, target)` pairs only grow.
- All-query reports only run source queries for function objects whose address is
  materialized by an `AddrOf` edge in the PAG. Non-materialized functions cannot reach an
  indirect-call operand and were pure overhead in the all-functions loop.
- MHS duplicate suppression uses the planned `(node, phase, top-offset)` visit key while
  preserving the full stack in the work item for transitions.
- Each query has an automatic 25k state/worklist budget. Over-budget queries are stopped
  and reported with `truncated: true`; the aggregate JSON includes `truncated_queries`.
  Truncated query reports are diagnostic only and are not suitable for tier-E callgraph
  adoption without a sound fallback.
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
- incompatible signature filtering: a raw PAG-only query may see an incompatible function
  address reach an indirect-call operand, while the signature-aware CLI/report path
  rejects the target and does not create fixpoint bindings for it.
- CLI JSON reports fixpoint rounds, new target counts, dependency-bearing queries, and
  final `by_callsite` answers.
- synthetic-suite ledger: signature-aware M3.1, M3.2, and M3.3 answers stay inside the
  Steensgaard/FSA envelope.

## Corpus smoke

Release-mode command shape:

```bash
LLVM_SYS_140_PREFIX=/home/brk/tenjin/_local/xj-llvm-14 \
LD_LIBRARY_PATH=/home/brk/tenjin/_local/xj-llvm-14/lib \
target/release/pangs query callees <module.bc> \
  --build-mode executable \
  --mode field-sensitive-fixpoint
```

O1 corpus results after address-materialized source filtering, top-of-stack MHS
memoization, and the automatic 25k query budget:

| module | callsites | targets | source queries | truncated queries | rounds | new targets | new interproc edges | max visited | wall s |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `exe-jpegoptim-O1` | 0 | 0 | 13 | 0 | 1 | 0 | 0 | 115 | 0.02 |
| `lib-parson-O1` | 132 | 132 | 2 | 0 | 1 | 132 | 0 | 78 | 0.02 |
| `exe-jq-O1` | 0 | 0 | 144 | 5 | 1 | 0 | 0 | 25000 | 0.21 |
| `exe-chibicc-O1` | 0 | 0 | 6 | 5 | 1 | 0 | 0 | 25000 | 0.10 |
| `exe-lua-O1` | 49 | 57 | 188 | 28 | 2 | 57 | 240 | 25000 | 0.28 |

Before source filtering/top-of-stack memoization/budgeting, `exe-jq-O1`, `exe-chibicc-O1`,
and `exe-lua-O1` either timed out or were SIGKILLed. The current guard makes the query
surface observable on these modules, but the truncated rows show M3.3 is not ready to
replace exported callgraph answers on larger corpus inputs.

This is still a query-kernel surface. The main `analyze` pipeline has not yet adopted
tier-E callee answers or exported them into `callgraph.jsonl`.
