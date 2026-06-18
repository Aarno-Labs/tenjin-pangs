# OMP__tree Precision: Field Sensitivity Gate and Next Diagnostics

This note records the June 2026 design conclusion around improving precision on
`exe-OMP__tree-O0.bc`.

## Current conclusion

Do not start with field-sensitive Steensgaard partitioning.

The Phase 0 partition-connectivity diagnostic shows that OMP's largest oversized
partition is not primarily held together by removable constant-GEP joins. On:

```text
/home/brk/pangs-cc2json.bak/ju_cc2json/exe-OMP__tree-O0.bc
```

the largest partition looked like:

```text
partition_max_size=3364
oversize_fallbacks=13
oversize_fallback_max_size=5012

largest partition:
  nodes=3364
  components_without_const_gep=1
  largest_without_const_gep=[3364]
  components_without_const_gep_indirect=10
  largest_without_const_gep_indirect=[3312, 13, 9, 6, 6, 4, 4, 4]
  components_without_any_gep=1
  largest_without_any_gep=[3364]
```

So even an intentionally unsound "remove all GEP joins" probe does not split the
partition. The oversized component is dominated by real load/store/assign connectivity,
not by constant-field artifacts. Field-sensitive Steensgaard remains a plausible future
precision feature, but it is too soundness-sensitive to justify for this case without a
better go signal.

## Near-term precision lever

OMP is small enough that raising Andersen's budget removes fallbacks cheaply:

```text
--partition-budget 100000000
analysis_wall_us ~= 51ms
solve_us ~= 26ms
oversize_fallbacks=0
icalls_andersen=3
icalls_steens=0
```

At `--partition-budget 10000000`, one fallback remains. This suggests the next practical
implementation should be automatic budget escalation for small modules/partitions, plus
threading the budget or autobudget policy through the `cc2json` command path. Clients
should not have to guess this manually.

## If budget escalation is not enough

The next diagnostic should target load/store hubs, not fields.

The broad Steensgaard rules:

```text
store: *p = v  => join(pointee(p), v)
load:  x = *p  => join(x, pointee(p))
```

can create a large real constraint component when `pointee(p)` becomes a hub. For OMP,
the largest partition included many load/store joins:

```text
load=2211
store=603
assign=632
gep_const=553
gep_unknown=347
```

Since removing GEP joins does not split the component, the next question is which memory
cells or store/load patterns make the component constraint-connected.

## Proposed load/store hub diagnostic

Add an opt-in Steensgaard diagnostic for the largest partitions that reports top classes
by:

```text
incoming_load_joins
incoming_store_joins
addr_of_joins
assign_joins
contains_globals
contains_functions
contains_icall_sites
ext/esc bits
```

Example desired output:

```text
root=11221
top_store_hubs:
  class=1234 nodes=1 globals=["sorts"] stores=240 loads=300 fns=7
top_load_hubs:
  class=5678 nodes=12 globals=[] loads=900 stores=2
```

For top hubs, include a few edge witnesses:

```text
load:  owner=read_dir src=%p dst=%x loc=...
store: owner=setup src=%cb dst=%slot loc=...
```

The witness labels should help distinguish:

- real scalar global function-pointer flow, such as `basesort = versort`;
- aggregate field collapse;
- unknown GEP collapse;
- external or ptr-int taint;
- broad memcpy/memset modeling;
- local stack memory that could be promoted or handled by a cheap local pass.

## Graph-cut experiments

Extend the existing partition diagnostic with additional unsound decomposition probes:

```text
without_const_gep
without_unknown_gep
without_indirect_bindings
without_load
without_store
without_load_store
without_external_escape
without_memcpy
```

These are not analysis modes. They are graph-cut experiments to identify which join
families keep the large partition connected.

Interpretation examples:

```text
without_load_store largest=[80, 50, 30]
```

The blocker is load/store interaction.

```text
without_unknown_gep largest=[200]
```

Unknown GEP collapse is the blocker.

```text
without_external_escape largest=[100]
```

Boundary or escape propagation is the blocker.

## Possible fixes after diagnosis

Depending on the hub report:

- Scalar function-pointer globals dominate: use B1/stationarity/simple-global logic to
  resolve those before broad Steens binding.
- Unknown GEP dominates: improve lowering to recover constant offsets, or classify safe
  dynamic array indexing separately.
- Memcpy dominates: add more precise memory-op modeling for affected aggregates.
- External escape dominates: audit whether a boundary seed escapes too many pointees.
- Local stack memory dominates: consider a cheap local SSA/memory-promotion pass before
  PAG construction.

The first deliverable should be diagnostics, not a solver semantics change.
