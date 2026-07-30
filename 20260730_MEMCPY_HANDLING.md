# Sparse and Lazy `memcpy` Handling

## Status

Design sketch for review. Nothing here is implemented.

The proposal separates two questions that the current solver answers with one
field-insensitive rule:

1. Which bytes are read or written by a bulk copy?
2. Which pointer values can become observable through the destination?

The first question belongs to ModRef and disposition and must always be answered.
The second belongs to points-to analysis and usually involves only a sparse subset
of the copied storage.

## Motivation

The current Andersen rule treats a `memcpy` as a contents-copy between every
possible source and destination object:

```text
for destination object od in pts(dst):
    for source object os in pts(src):
        add copy edge os -> od
```

This rule is sound but field-insensitive. It eagerly constructs a Cartesian
product even when the copy moves only character data.

The forced solve of the oversize partition in
`exe-yapteaparprfotci-O0-g.bc` demonstrates the cost:

| Property | Value |
|---|---:|
| Partition nodes | 5,876 |
| Partition edges | 6,306 |
| `memcpy` constraints | 19 |
| Live points-to facts after the solve | about 3.1 million |
| `memcpy` endpoint pairs processed | about 6.1 million |
| Copy-fact pairs processed | about 30 million |

Approximately 86% of the observed large `memcpy` products came from two byte
buffer operations:

```c
memcpy(bs->pos, s, l);
memcpy(cli->option_chars, text, n_option_chars);
```

The copies are not the primary structural cause of the partition: removing
`memcpy` edges leaves a largest component of 5,152 nodes. They are instead a
major propagation amplifier after the component has been admitted.

The complementary motivating case is an array of large structs with only one or
two pointer fields. Such a copy cannot be ignored, but its pointer semantics
should be proportional to the sparse pointer layout rather than the total byte
size or element count.

## Goals

- Preserve every bulk-copy read and write for ModRef and disposition.
- Transfer pointer facts only through storage that may contain an observable
  pointer representation.
- Represent repeated pointer fields in arrays without unrolling every element.
- Avoid eagerly materializing source-object × destination-object copy graphs.
- Fall back to the current whole-object rule whenever the sparse proof is
  incomplete.
- Keep the design independent of typed pointer operands so it can be ported to
  LLVM opaque pointers.
- Do not weaken Steensgaard fallback soundness or the monotone
  Steensgaard-to-Andersen narrowing contract.

## Non-goals

- Recovering arbitrary C source types exactly.
- Proving that all accesses through `char *` are semantically character data.
- Modeling byte-exact values, padding contents, or copy order.
- Optimizing scalar ModRef or eliminating write evidence.
- Treating an incomplete pointer representation as a valid source pointer.

## Core abstraction

### Pointer-bearing storage regions

For each allocation origin, compute a conservative sparse description of the
regions through which a pointer value may be observed:

```text
PointerRegion {
    allocation_origin,
    offset_pattern,        // exact offset or strided offset family
    width,
    provenance,
    contamination,
}
```

An exact struct field has an exact byte offset. A field in an array of structs is
a strided family:

```text
base + k * sizeof(element) + field_offset
```

The description need not prove that a region has a particular C pointer type. It
only needs to conservatively identify storage that:

- receives a pointer-valued store;
- is read by a pointer-valued load;
- is used as a function pointer, GEP base, dereference base, returned pointer, or
  other pointer-consuming value; or
- is contaminated by an access that prevents a narrower classification.

Pointer observability must be transitively closed through copies. A destination
that is copied again and only later loaded as a pointer is still observable.

### Projected copy summaries

A bulk copy produces zero or more pointer projections:

```text
ProjectedCopy {
    source_endpoint,
    destination_endpoint,
    copied_range,
    source_region_pattern,
    destination_region_pattern,
    offset_mapping,
    fallback,
}
```

For a whole-array copy:

```c
struct Item {
    char payload[4096];
    void *owner;
    void (*callback)(void);
};

memcpy(dst, src, sizeof(src));
```

the points-to effect is represented as two strided relations:

```text
dst[k].owner    <- src[k].owner
dst[k].callback <- src[k].callback
```

The payload, scalar fields, and padding remain part of the ModRef range but do
not participate in points-to propagation.

## Classification rules

For every potentially copied destination region:

1. **Not pointer-observable.** Record the read/write effect, but add no
   points-to transfer.
2. **Fully covered pointer region with a corresponding source region.** Add a
   projected copy relation between the regions.
3. **Fully covered pointer region with an unknown source classification.** Mark
   the destination region as receiving an unknown pointer value.
4. **Partially covered pointer representation.** Mark the destination region
   contaminated/unknown if it can later be observed as a pointer.
5. **Unknown layout, offset, extent, origin, or incompatible mapping.** Use the
   current whole-object contents-copy rule.

These rules concern points-to transfer only. Cases 1 through 5 all retain the
ordinary ModRef read and write.

Null-filled `memset` can eventually use the same region inventory: zeroing a
pointer region adds no concrete pointee, while an unknown nonzero fill
contaminates it. That extension is not required for the initial `memcpy`
experiment.

For may-points-to analysis, `memmove` can generally use the same projected
relation as `memcpy`. Source/destination overlap affects byte values and temporal
ordering, but the monotone may relation still includes the copied pointer
values.

## Opaque-pointer-clean metadata

The design must not ask for the pointee type of the `memcpy` operands.

The LLVM 14 implementation may use layout facts that survive opaque pointers:

- allocated types of globals and `alloca`;
- allocation sizes and alignments;
- GEP source element layout and normalized byte offsets;
- load/store widths and whether the SSA value is pointer-valued;
- allocation-relative access paths already computed by PANGS;
- constant or bounded copy lengths; and
- optional debug/source layout metadata when available.

The analysis-facing representation should normalize these into allocation
layouts and byte-offset patterns before building the PAG. Later LLVM versions
can populate the same representation from their GEP, allocation, DataLayout,
debug metadata, or frontend sidecar facts.

Missing metadata is not evidence that a region is byte-only. It selects the
fallback.

## Prepartitioning

The final design should project bulk-copy edges in the prepartition graph as
well as in Andersen:

- a certified byte-only copy contributes no pointer-connectivity edge;
- an exact pointer-field copy connects only the corresponding
  allocation-relative field regions;
- a strided copy connects corresponding field-family regions; and
- an unclassified copy retains the existing whole-object edge.

This may reduce future megapartitions, although it will not by itself dissolve
the current YAPET component because ordinary loads, stores, and constant GEPs
remain its dominant structural bridges.

The ModRef/disposition write ledger must be produced independently of these
pointer-connectivity decisions.

## Lazy materialization

Sparse projection changes the amount of pointer state that can eventually be
required. Laziness controls when that state is materialized.

The solver should initially retain a `ProjectedCopy` relation rather than
adding all concrete source-object × destination-object copy edges. It expands
the relation when:

- a newly discovered endpoint allocation pair can affect a pointer-observable
  destination region; and
- that destination region is demanded by a pointer-consuming operation or by
  a client fact that requires its points-to set.

Demand can be implemented either as:

- a static backward closure from pointer loads, indirect calls, pointer stores,
  pointer returns, and client roots; or
- a dynamic demand propagated backward through projected copies.

The first implementation should prefer a static monotone closure. It is easier
to audit and ensures that a copy chain ending in a pointer load is not
accidentally pruned.

Laziness alone is insufficient. If all destination fields are eventually
demanded, an unprojected lazy whole-object relation reconstructs the same
Cartesian product. Projection is therefore the semantic foundation; laziness
is a subsequent execution optimization.

## Soundness boundary

The sparse rule is justified only when every pointer-observable destination
region affected by the copy is accounted for.

Important conservative cases include:

- a pointer copied bytewise through `char *` and later reconstructed as a
  pointer;
- unions or incompatible layouts;
- an unknown-size copy that may cross into a pointer field;
- a partial overwrite of a pointer representation;
- pointer fields reached through unknown offsets;
- external or forged storage with no bounded allocation origin; and
- copies whose source and destination region correspondence cannot be proven.

Any such case uses an unknown destination pointer fact or the existing
whole-object fallback. A byte-oriented API or `i8 *` operand is not by itself a
reason to suppress pointer transfer.

## Proposed implementation sequence

### Phase 0: profiling

- Attribute `memcpy_pairs_processed`, inserted copy edges, and downstream
  copy-fact pairs to individual PAG copy sites.
- Print endpoint labels, source location, maximum endpoint-set sizes, and
  cumulative expansion.
- Retain the current aggregate counters.

This makes corpus regressions diagnosable without mapping internal cell numbers
back through a PAG dump.

### Phase 1: pointer-region inventory

- Add normalized allocation layout/access metadata to PIR or a sibling analysis
  structure.
- Compute conservative exact and strided pointer-observable regions.
- Close observability transitively through bulk-copy chains.
- Export diagnostic reasons for every classified or rejected region.

No solver behavior changes in this phase.

### Phase 2: eager sparse projection

- Behind an experimental knob, replace a fully certified whole-object
  `memcpy` constraint with eager projected pointer-region constraints.
- Keep current fallback behavior for every unclassified copy.
- Keep prepartitioning unchanged initially so propagation cost can be measured
  independently of partition-shape changes.

This phase should establish semantic equivalence or conservative improvement
before adding laziness.

### Phase 3: prepartition projection

- Use the same certificates to omit byte-only pointer-connectivity edges.
- Connect exact or strided pointer-region vertices instead of whole objects.
- Check that every partition admitted under the new graph still has a sound
  Steensgaard summary at its cut boundaries.

### Phase 4: symbolic/lazy projected copies

- Store projected relations in an endpoint index.
- Materialize only demanded allocation/region pairs.
- Deduplicate equivalent strided relations.
- Add work caps that abandon a relation to the whole-object fallback before a
  pathological Cartesian expansion.

The fallback transition must be monotone and transactional: no partial
under-approximate result may escape.

### Phase 5: solver representation

If copy-fact propagation remains dominant after projection, evaluate sparse or
hybrid bitsets and wordwise delta union in place of per-fact `HashSet<Cell>`
propagation. This is complementary to the modeling change and should be
measured separately.

## Tests

Synthetic fixtures should cover:

1. Byte-buffer copy with no pointer-observable destination: ModRef write remains,
   no pointer transfer is created.
2. Whole struct copy with one pointer field: the field's pointee reaches the
   destination.
3. Array of large structs with two pointer fields: two strided relations are
   created without per-element unrolling.
4. Constant subrange covering one of two pointer fields: only the covered field
   transfers.
5. Dynamic length that may cover a pointer field: conservative transfer or
   fallback.
6. Partial pointer-width copy followed by a pointer load: destination becomes
   unknown.
7. Copy chain through an otherwise byte-only temporary followed by a pointer
   load: transitive observability retains the transfer.
8. Union or incompatible layouts: fallback.
9. Unknown allocation origin: fallback.
10. `memmove` with overlapping source and destination: may-points-to transfer is
    retained.
11. Function-pointer field copy: indirect-call targets remain complete.
12. Opaque-pointer-style PIR with allocation/access metadata but no operand
    pointee type: classification still succeeds.

Every fixture should compare conservative, Steensgaard, and Andersen output and
exercise exhaustion/fallback behavior.

## Corpus evaluation

Primary measurement:

- `exe-yapteaparprfotci-O0-g.bc`, forced admission of root `6354`;
- total wall and solve time;
- live and inserted points-to facts;
- per-site `memcpy` endpoint products;
- downstream copy-fact pairs;
- callgraph, ModRef, global-resolution, and disposition deltas.

The two CLP byte-buffer copies and the two GIF byte copies should be reported
individually. The experiment succeeds only if any suppressed pointer transfer
has a recorded pointer-observability proof.

Regression population should include:

- chibicc and Slap disposition baselines;
- a program dominated by struct copies;
- a program with function-pointer fields copied by `memcpy`;
- a program with unions or partial/unknown copy extents; and
- the existing Andersen admission calibration subset.

Performance and precision changes must be reported separately. In particular,
removing a ModRef write is never an acceptable way to improve points-to
performance.

## Expected disposition

The recommended first experiment is Phase 0 followed by eager sparse projection
for certified byte-only regions and exact pointer fields. It has a small
soundness surface, directly tests the YAPET hypothesis, and provides the
metadata needed for the array-of-large-structs case.

Strided regions should follow once exact-field projection is validated. Lazy
materialization should come after projection, because laziness by itself only
postpones the whole-object Cartesian product.

## Review questions

1. Should pointer observability be computed for all pointer consumers or only
   for the client roots requested by a run?
2. Is a strided field family one Andersen cell, or a symbolic relation over
   allocation-relative element cells?
3. Which partial-pointer-copy cases should introduce an unknown region versus
   immediately selecting whole-object fallback?
4. Can projected copies reuse the existing allocation-relative field cells, or
   do they require a distinct region vocabulary?
5. At what layer should the layout certificate live so PIR remains portable
   across LLVM versions?
6. Should a relation-level work cap fall back locally, or force the entire
   containing partition back to Steensgaard?
