# Domain-only fallback for oversize Andersen partitions

Date: 2026-07-17

Status: evaluated; bounded prototype rejected and implementation discarded.

## 1. Motivation

The first `ExposedGlobals` prototype stored one unknown-pointer domain on each
Steensgaard class.  It was feasible but not useful: YAPET's single `inttoptr` seed
joined an 8,493-node oversize class and raised every unknown pointer in that class to
`Universal`, losing four existing atomic certificates.  Full Andersen separates the
flows, but its three fixed-call-graph rounds take about 42 seconds on this module and
materialize up to 1.8 million points-to facts.

The fallback needs only a narrower answer for mod/ref address nodes:

> Can a `Universal` Ω source reach this pointer value through balanced pointer and
> memory flow?

It does not need named allocation sets or refined indirect-call targets.

## 2. Proposed query

For each oversize Andersen partition, run one multi-source field-sensitive CFL/MHS
reachability query seeded by every `inttoptr` node in that partition.  Reuse the
existing M3.2 memory-history rules:

- assignment and address flow preserve the state;
- GEP adjusts the active byte offset;
- store pushes a memory level;
- load closes a level only at a matching offset;
- unknown offsets saturate to top and therefore match conservatively;
- memcpy remains conservative assignment-like flow.

Add frozen Steensgaard indirect-call bindings to the query graph.  Direct-call
bindings are already PAG edges.  A node is Universal-reachable only in forward phase
with an empty memory-history stack.

The query returns a reached-node bitset plus `visited_states`, `max_worklist`, and
`truncated`.  It does not return paths, named pointees, or call targets.

## 3. Safe use of the result

The ordinary `ExposedGlobals` lattice remains:

```text
None < ForeignOnly < ExposedGlobals < Universal
```

For a Steensgaard-external node in an oversize partition:

- if the query reaches it, retain `Universal`;
- if the query completes without reaching it, narrow the class-level fallback to
  `ExposedGlobals`;
- if the query truncates, is unavailable, or encounters an unclassified Universal
  seed, retain the original Steensgaard domain.

This prototype does not attempt `ForeignOnly` narrowing in oversize partitions.
External-call results and address-escaped function parameters remain
`ExposedGlobals`.  `inttoptr` is never weakened at a reached node.  A named-global
list never narrows a Universal result.

The narrowing relies on the MHS query being a sound over-approximation of pointer
value flow.  It must therefore remain opt-in internally until synthetic tests cover
assign, matched and mismatched fields, unknown offsets, direct and indirect call
bindings, and truncation fallback.

## 4. Cost controls

- Run only when Andersen has an oversize partition and at least one Universal seed.
- Traverse all Universal seeds together.
- Use a fixed state budget; exceeding it discards all domain narrowing for the
  affected run.
- Store only visited MHS states and one reached-node bitset.
- Report query metrics in solver diagnostics before considering production use.

## 5. Acceptance gates

The initial gate is deliberately narrow:

1. YAPET O0-g recovers `report_error`, `cat.catcolorspace`, `cats_capacity`, and
   `ncats` as atomic-certified.
2. JPEGoptim O0 and O1 retain all ten existing certificates.
3. Integer-derived synthetic accesses remain module-wide.
4. The full workspace test suite passes.
5. YAPET runtime remains substantially below the 42-second full-Andersen run and the
   query does not truncate.

Only after these pass should the non-Vim, non-PHP sibling corpus be remeasured.  A
failed gate means abandon the implementation commit rather than weakening the
Universal or truncation rules.

## 6. Evaluation

The prototype carried the `ExposedGlobals` lattice from the earlier experiment,
added frozen Steensgaard indirect bindings to a multi-source MHS query, and used a
completed query to narrow oversize Steensgaard nodes not reached from `inttoptr`.
YAPET O0-g was the initial gate.

An exact per-state `Vec` history was OOM-killed after 81.16 seconds at 33.15 GB RSS.
Replacing it with an interned persistent stack bounded memory, but exact reachability
still hit the one-million-state budget. Finite sound over-approximations were then
tested: they retain an exact top suffix and represent a deeper tail by both possible
depth successors when it is exposed.

| history abstraction | visited states | elapsed | peak RSS | result |
|---|---:|---:|---:|---|
| exact copied stack | n/a | 81.16 s | 33.15 GB | OOM-killed |
| exact persistent stack | 1,000,000 | 0.29 s | 113 MB | truncated |
| one exact frame | 34,603 | 0.18 s | 63 MB | completed; 0 target globals recovered |
| two exact frames | 803,214 | 0.37 s | 145 MB | completed; 0 target globals recovered |
| four exact frames | 1,000,000 | 0.55 s | 356 MB | truncated |

The two-frame result reduced module-wide mod/ref rows from 91 to 71, demonstrating
that the query can separate some flows. It did not make `report_error`,
`cat.catcolorspace`, `cats_capacity`, or `ncats` access-complete, so it recovered no
atomic certificate. The one-frame result was broader; the four-frame and exact
results could not complete within the bound.

Conclusion: this bounded domain-only fallback fails its first acceptance gate. The
implementation was discarded without running the broader corpus. A future revisit
would require a proper demand-driven or summarized pushdown-reachability algorithm,
not another stack-depth tuning pass. Universal and truncation semantics were not
weakened to manufacture a positive result.
