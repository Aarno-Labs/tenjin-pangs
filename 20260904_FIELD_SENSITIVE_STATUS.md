# Field-sensitive analysis: current status

This note summarizes the implemented field-sensitive treatment described by
[`DESIGN_lite.md`](DESIGN_lite.md), as of 2026-09-04.  Here, *field-sensitive*
means **allocation-relative, byte-offset-sensitive memory modeling**.  It is not
LLVM-type-field sensitivity: the model deliberately works with opaque pointers and
derives identity from PAG address flow, GEP offsets, access extents, and allocation
roots ([design rationale](DESIGN_lite.md#c-steensgaard-demoted-to-base-solver)).

The abbreviation “FSA” elsewhere in this codebase can also mean the function-signature
compatibility filter ([`fsa_compatible`](crates/pangs-pir/src/lib.rs#L986)); that is a
separate indirect-call target filter, not this field-sensitive memory analysis.

## Common representation and boundary

The PIR/PAG preserves a `Gep` byte offset and, when a sequential index is dynamic, a
normalized affine lane `residue + k * modulus`
([PIR statement](crates/pangs-pir/src/lib.rs#L612),
[`GepLane`](crates/pangs-pir/src/lib.rs#L739),
[PAG edge](crates/pangs-pag/src/lib.rs#L934)).  Loads and stores also retain access
extents, and `memcpy` retains a constant byte extent when known.  This permits overlap
rather than simple offset equality.

Both solvers independently certify an address as `(allocation root, FieldLocation)`.
The proof starts at an `AddrOf`, propagates through GEP, and permits an assignment join
only when all non-null alternatives name the same root.  Differing offsets become that
root’s unknown-offset location; loads and other producers end the proof
([`exact_allocation_addresses`](crates/pangs-solve/src/lib.rs#L1276)).  Thus field
precision applies only to a proven allocation root.  Without that proof, analysis
falls back to the carrier/pointee model (Steensgaard) or ordinary GEP constraints
(Andersen), preserving soundness rather than guessing a field.

`FieldLocation` has `Exact`, `Lane`, and `Unknown` variants
([definition and construction](crates/pangs-solve/src/lib.rs#L1130),
[composition and aliasing](crates/pangs-solve/src/lib.rs#L1232)).  `FieldRegion` adds
an optional byte width; it joins only regions that may overlap.  Exact intervals,
exact-vs-lane, and lane-vs-lane overlap are handled explicitly; unknown location or
unknown width conservatively overlaps everything for that allocation
([overlap implementation](crates/pangs-solve/src/lib.rs#L1151)).  This is why a
dynamic array index can retain a known struct-member lane, while an arbitrary unknown
byte offset collapses only the fields of the same allocation.

## Steensgaard: field-aware base/fallback solution

Steensgaard remains a unification-based base solver, but it is no longer wholly
field-insensitive.  For a certified GEP destination it creates/uses a synthetic
location class for the allocation-relative address rather than unifying the derived
pointer with its base ([GEP rule](crates/pangs-solve/src/lib.rs#L1915)).  Certified
loads, stores, copies, and certain pointer copies resolve through the corresponding
region class ([edge rules](crates/pangs-solve/src/lib.rs#L1837),
[`storage_class_for_address`](crates/pangs-solve/src/lib.rs#L3100)).  This preserves
separate pointer *carriers* while making them designate the same precise field when
appropriate; the one-hop carrier/location invariant is asserted in debug builds
([invariant](crates/pangs-solve/src/lib.rs#L3033)).

`field_class` lazily materializes a synthetic location per `(root, region)`, propagates
global ownership/escape envelope information, and unifies only overlapping regions of
that root ([implementation](crates/pangs-solve/src/lib.rs#L3117)).  Consequently:

- Constant-offset fields of one allocation stay separate when their byte regions do not overlap.
- Affine lanes only meet compatible offsets/lanes; different residues remain separate.
- An unknown GEP/extent joins all materialized fields of **that allocation**, not fields of
  unrelated allocations.
- Bounded `memcpy` joins only overlapping source/destination regions; unbounded copy is
  conservative.

Field classes also participate in the conservative boundary facts: a certified escaped
allocation root propagates escape to its known fields and, through content flow, to
their contents ([field escape closure](crates/pangs-solve/src/lib.rs#L2954)).  Global
field classes retain their owning-global membership.  This matters because Steensgaard
is the complete answer wherever Andersen is not admitted.

The behavior is directly regression-tested for carrier separation, unknown-GEP
contamination, bounded-copy isolation, lane compatibility, and byte overlap
([tests](crates/pangs-solve/src/lib.rs#L3678),
[unknown/bounded-copy tests](crates/pangs-solve/src/lib.rs#L3831)).

## Andersen: field-sensitive inclusion refinement

Andersen is the partition-scoped inclusion refinement over the Steensgaard envelope;
it may narrow points-to-derived answers only in admitted regions, while the base answer
remains the oversize/uninteresting fallback
([solver contract](crates/pangs-solve/src/andersen.rs#L1)).  It shares the independent
address certification above and uses it in two places.

First, the admission graph has synthetic allocation-relative region vertices.  Certified
loads/stores/memcpy use those vertices, and certified GEPs connect their destination
carrier to the precise region.  Region vertices are unioned only for overlapping byte
regions of the same allocation ([region construction](crates/pangs-solve/src/andersen.rs#L1175),
[scope construction](crates/pangs-solve/src/andersen.rs#L1353)).  This prevents an
imprecise Steensgaard class from forcing unrelated allocations or disjoint fields into
one Andersen admission partition.  Synthetic global fields also make their partitions
interesting, as specified in the design.

Second, the actual inclusion solve materializes a field cell for each object/location.
A certified GEP directly points its destination at the certified root-relative field;
otherwise the ordinary GEP rule computes fields for every base pointee
([constraint construction](crates/pangs-solve/src/andersen.rs#L2825),
[GEP propagation](crates/pangs-solve/src/andersen.rs#L6730)).  `field_of` canonicalizes
nested GEPs to finite root-relative locations and creates a per-object unknown-offset
summary when necessary.  That summary has bidirectional copy edges only with aliasing
fields of the same root, so dynamic-index stores are visible to constant-field loads
without globally merging all future fields ([`field_of`](crates/pangs-solve/src/andersen.rs#L5903)).

Whole-object accesses are the intentional precision boundary.  Direct loads/stores and
bulk copies may need to exchange facts with field cells; `note_direct_access` bridges
the object and its unknown-field summary under the configured policy
([bridge implementation](crates/pangs-solve/src/andersen.rs#L5968)).  `memcpy` is
currently a contents-copy relation between endpoint objects rather than a byte-sliced
field copy.  Its incremental/summary implementation records endpoint pairs and invokes
the whole-object bridge, so it is sound but can merge field payloads
([copy implementation](crates/pangs-solve/src/andersen.rs#L5701),
[propagation](crates/pangs-solve/src/andersen.rs#L6705)).  The design’s phrase
“lazy `(object, byte_off)` field materialization” is therefore accurate for GEP and
certified memory access, but should not be read as full byte-precise `memcpy` modeling.

Regression coverage shows both solvers distinguish struct callback/data fields and
preserve affine array-member lanes; it also checks field-sensitive external/pointee
results and the whole-object bridge
([field tests](crates/pangs-solve/src/andersen.rs#L7418),
[bridge/copy tests](crates/pangs-solve/src/andersen.rs#L7632)).

## Optional extension: receiver-relative payload cells

When `PANGS_ANDERSEN_RECEIVER_PAYLOADS` is enabled, Andersen adds a narrow,
allocation-sensitive container summary: payload cells are keyed by receiver allocation
root and `FieldLocation`, so different receivers and constant-offset members remain
distinct.  The implementation infers only the documented receiver/store/return pattern
and feeds the resulting cells into both partition admission and the inclusion solve
([feature/design](DESIGN_lite.md#receiver-allocation-relative-payload-summaries-experimental),
[inference entry point](crates/pangs-solve/src/andersen.rs#L875),
[admission integration](crates/pangs-solve/src/andersen.rs#L1448)).  It is explicitly
an opt-in, bounded object-sensitive enhancement—not the general field-sensitivity
mechanism described above.

## Bottom line

Field sensitivity is implemented and exercised in **both** production solvers.  Its
unit of precision is a proven allocation-relative byte region, supporting exact offsets,
affine GEP lanes, and overlap-aware accesses.  It degrades conservatively at unknown
roots, unknown offsets/extents, whole-object operations, and unadmitted Andersen
partitions.  The main remaining intentional coarse point is bulk memory copying (and
whole-object bridging), not ordinary constant/lane GEP field handling.
