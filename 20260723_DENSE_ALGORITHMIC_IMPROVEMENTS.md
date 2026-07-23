The current solver has several algorithmic inefficiencies that make dense cycles especially painful. Dynamic fallback is useful
  protection, but it is not the only—or necessarily the best—answer.

  The most promising alternatives, roughly in implementation order, are:

  1. Delta-based propagation

  Currently, when a node is processed, complete points-to sets are propagated again along its outgoing copy edges at crates/pangs-solve/
  src/andersen.rs:2077. In a cycle, the same old facts are revisited many times.

  Instead, each node can maintain:

  points_to       all known objects
  pending_delta   objects not yet propagated

  A worklist step propagates only pending_delta, then clears it. Adding a fact already present does nothing.

  Dynamic constraints need corresponding incremental treatment:

  - New pointee of a load base: instantiate loads only for that new object.
  - New pointee of a store base: instantiate stores only for that new object.
  - New pointee of a GEP base: create only the newly implied field.
  - New source/destination pointee for memcpy: join the new element against the opposite existing set.

  For memcpy, this changes repeated full products into an incremental join:

  new destination × all existing sources
  new source      × all existing destinations

  Every necessary object pair is still processed, so this preserves exact Andersen semantics. It cannot avoid an intrinsically huge final
  relation, but it avoids recomputing the same pair every time one endpoint grows. This is the clearest first optimization for YAPET.

  2. Copy-SCC collapsing or wave propagation

  Mutually reachable nodes in the copy graph have equal points-to sets. The solver can compute strongly connected components and represent
  each copy SCC with one shared points-to set.

  A wave-propagation solver typically:

  1. Saturates current copy propagation.
  2. Collapses newly discovered copy SCCs.
  3. Processes loads/stores/GEPs that create new copy edges.
  4. Repeats in waves.

  This turns a cycle of hundreds of nodes repeatedly copying the same large set into one component operating on one set.

  Collapsing a true mutual-inclusion SCC is exact: if pts(a) ⊆ pts(b) and pts(b) ⊆ pts(a), the two sets are necessarily equal. The
  complication is that loads, stores, memcpy, and indirect calls create copy edges dynamically, so SCC maintenance must either be
  incremental or periodically recomputed.

  This likely has high payoff for YAPET’s feedback-heavy partition.

  3. Hybrid sparse/dense bitsets

  The solver currently uses hash sets for points-to sets and copy successors. Hash sets work well while sets are small, but YAPET quickly
  reaches hundreds or thousands of pointees per node.

  A hybrid representation could use:

  - Small vectors or sparse bitsets for small sets.
  - Dense bitsets once density crosses a threshold.
  - Word-wise OR and AND-NOT to compute propagation deltas.

  Then propagation becomes roughly:

  delta = source_bits & ~destination_bits
  destination_bits |= source_bits

  rather than thousands of individual hash lookups and insertions.

  Dynamic field cells complicate indexing slightly, but cells already receive compact integer IDs, so growable bitsets are practical.
  External-provenance sets should receive the same treatment; prior profiling showed significant time in their hash-set propagation too.

  This improves constant factors substantially, but delta propagation should come first because bitsets alone would still rescan full sets
  unnecessarily.

  4. Incremental memcpy joins

  This can be implemented independently of general delta propagation.

  At present, whenever either memcpy endpoint is dequeued, the solver reconstructs both complete points-to vectors and traverses their
  full Cartesian product at crates/pangs-solve/src/andersen.rs:2051. For YAPET, the same half-million-pair product is revisited as the
  endpoints grow.

  Each memcpy constraint could instead track:

  seen_destinations
  seen_sources

  Then process only:

  (destinations - seen_destinations) × sources
  destinations × (sources - seen_sources)

  with care not to duplicate the new/new quadrant.

  This is exact and narrowly targets the most visible YAPET hotspot. It may be a good contained first patch before converting the entire
  solver to deltas.

  5. Pointer-layout-aware memcpy

  A more semantic refinement is to stop treating every byte copy as copying pointer payload.

  YAPET’s motivating operation is:

  memcpy(bs->pos, s, l);

  Both sides are character buffers. Copying those bytes should not create pointer-flow edges between all objects reachable through bs->pos
  and s.

  A sound model could retain:

  - The copied byte range, when statically known.
  - The LLVM pointee or aggregate layout.
  - Which byte ranges may contain pointer fields.
  - Whether the source or destination is provably pointer-free storage.

  Then:

  - A copy wholly within pointer-free storage adds no pointer constraint.
  - A fixed aggregate copy transfers only overlapping pointer-bearing fields.
  - Unknown type, unknown layout, or ambiguous range retains today’s conservative behavior.

  This attacks the cause rather than merely accelerating saturation. It would probably eliminate the pathological append_build_string
  expansion entirely. The implementation scope is larger because LLVM’s opaque-pointer representation means useful layout information must
  be preserved during lowering rather than reconstructed later.

  6. Monotone on-the-fly call-graph construction

  The current refinement begins with a broad Steensgaard target map—670 target edges for YAPET—and solves with all those argument/return
  bindings. It then discards the solve and starts over when Andersen narrows the call graph.

  An alternative is a conventional on-the-fly Andersen call graph:

  - Start from directly known callees and points-to seeds.
  - As function objects reach an indirect callee operand, add that callee’s bindings.
  - Never remove a binding; the call graph grows monotonically toward the joint least fixed point.

  This can avoid injecting hundreds of speculative Steensgaard callees into the first solve. It also avoids rebuilding all points-to state
  from scratch between call-graph rounds.

  This is potentially a major YAPET improvement because it has 102 indirect-call sites in the problematic partition. Soundness requires
  treating truly unknown external calls conservatively from the beginning, but internally resolved function targets can be discovered
  monotonically.

  7. Constraint-graph preprocessing

  Classic Andersen implementations often apply offline reductions before solving:

  - Merge copy-equivalent variables.
  - Eliminate redundant constraints.
  - Collapse cycles visible before dynamic solving.
  - Use pointer-equivalence or location-equivalence analysis.
  - Remove nodes irrelevant to any queried result.

  These techniques reduce both graph size and eventual relation size. They are exact when based on proven equivalence; more aggressive
  variants may trade precision for speed.

  The existing Steensgaard result provides useful preprocessing information, but using entire Steensgaard partitions only as an admission
  decision leaves much of that structure unused.

  8. Sparse evaluation over dependency SCCs

  Instead of solving every admitted Steensgaard partition as one flat worklist, construct a dependency graph between constraint SCCs:

  address seeds → copy SCCs → dereference constraints → downstream SCCs

  Process the condensation graph in topological waves and revisit only SCCs affected by newly created dynamic edges.

  This confines churn to the cyclic kernel rather than repeatedly revisiting the entire 2,835-node partition. It is more involved than
  ordinary copy-SCC collapsing but is a better architectural match for large partitions with a relatively small dense core.

  9. BDD-backed relation representation

  Binary decision diagrams have historically been effective for very large, highly regular points-to relations. Instead of storing each
  (value, object) pair explicitly, they symbolically represent the relation.

  They can make dense Cartesian relations compact, but:

  - Performance is sensitive to variable ordering.
  - Dynamic fields and provenance annotations add complexity.
  - Integration and debugging costs are high.
  - Modern hybrid bitsets are often simpler and sufficiently fast at this scale.

  I would treat BDDs as a later option, not the first response to YAPET.

  10. Selective unification inside dense regions

  A hybrid solver could retain Andersen precision for most of the partition but use Steensgaard-style unification for a dense internal
  SCC, external-memory region, or memcpy-connected subgraph.

  This is sound as an overapproximation but loses precision locally. It is preferable to falling back the entire partition because
  unrelated globals and callsites can retain Andersen precision.

  The difficult part is defining a stable boundary: flows crossing into the unified region must receive the unified summary, while flows
  outside continue through inclusion constraints.

  Recommended sequence

  I would pursue:

  1. Incremental memcpy joins.
  2. General delta propagation.
  3. Hybrid sparse/dense bitsets for points-to and provenance sets.
  4. Copy-SCC/wave propagation.
  5. Monotone on-the-fly indirect-call discovery.
  6. Pointer-layout-aware memcpy modeling.

  The first three directly address the observed repeated work without changing analysis results. SCC processing then tackles the cycle
  structure. On-the-fly call resolution prevents Steensgaard’s broad initial target set from creating the dense state in the first place.
  Layout-aware memcpy offers the greatest precision improvement, but requires more lowering and representation work.

  A dynamic per-partition guard would still be valuable as a safety net even after these improvements, because exact Andersen analysis has
  unavoidable worst cases. However, YAPET’s present behavior appears to contain enough repeated work that it should be possible to improve
  it by orders of magnitude before resorting to fallback.

