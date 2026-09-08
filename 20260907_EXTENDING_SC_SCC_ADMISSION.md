# Extending Source-Closed SCC Admission Beyond Indirect Calls

*Design sketch and measurement note, 2026-09-07.*

## 0. Status and recommendation

PANGS-lite already has a bounded source-closed (SC) SCC admission path for indirect-call
operands stranded in an oversize Andersen prepartition.  The implementation condenses the
directed prepartition-flow graph, closes a candidate call operand over predecessor SCCs, and
admits the union of closures that fits the ordinary partition budget.  The enclosing weak
component remains an oversize Steensgaard fallback.

This note proposes generalizing that mechanism to **explicit client query seeds**, initially
targeted node labels and then selected global/ModRef queries.  The intended result is not a second
solver or a demand-driven tier.  It is a more selective admission policy for the existing
exhaustive Andersen solver:

> Admit the complete producer closure required by a client row, solve that closure to a fixed
> point, overwrite only rows covered by admitted closures, and retain the complete Steensgaard
> row everywhere else.

The proposal is motivated by YAPET's surviving megapartition.  Its weak component has roughly
2.7k vertices, but its directed condensation has 2,485 SCCs and a largest SCC of only 78 vertices.
The current icall policy admits a 190-node predecessor-closed slice under the normal budget.  This
is strong evidence that weak connectivity, rather than one irreducible inclusion cycle, creates
the admission cliff.

The recommendation is nevertheless staged:

1. Refactor and instrument the existing icall-only path without changing answers.
2. Add label-targeted SC admission and prove per-row fallback behavior.
3. Add global/client seeds only after defining their complete projection requirements.
4. Evaluate on the full oversize-fallback population against both normal admission and a forced
   solve.

Do not remove GEP, load, or store dependencies to split a component.  The partition-cut profile
is a connectivity diagnostic, not a license to omit inclusion constraints.  Do not combine this
work with PWC lanes or asymmetric field overlap; YAPET measurements below show that both change
solver economics substantially and neither dissolves the admission component.

## 1. Existing mechanism

The independent Andersen prepartition graph has two simultaneous views:

- a union-find over weak connectivity, used for ordinary all-or-fallback admission; and
- `prepartition_flow_edges`, a directed producer-to-consumer graph used for SC slicing.

Certified memory accesses use allocation-relative synthetic region vertices.  The principal
directions are:

| PAG operation | prepartition flow |
|---|---|
| `AddrOf` | object/region → pointer value |
| `Assign` | source value → destination value |
| `Load` | storage region → loaded value, with the address-carrier dependency retained |
| `Store` | stored value → storage region, with the address-carrier dependency retained |
| `Gep` | root-relative region → derived address carrier |
| `Memcpy` | source region/carriers → destination region |

Indirect-call argument/parameter and return/result bindings from the complete Steensgaard target
envelope are inserted before condensation.  Receiver-payload support edges are likewise inserted
before admission when that experiment is enabled.  This is important: the directed graph must
already contain every producer relation that a later joint call-graph/points-to round may
activate.

For an oversize weak component, `directional_icall_slice` currently:

1. selects indirect-call operand vertices as seeds;
2. computes SCCs of the component's directed flow graph;
3. builds the condensation DAG and its predecessor relation;
4. computes the complete predecessor closure for each seed SCC;
5. sorts candidates deterministically by priority, closure size, and seed id;
6. greedily unions closures while
   `nodes * (nodes + attributed_edges) <= partition_budget`; and
7. marks base PAG nodes in selected SCCs as `in_scope`.

The inclusion solver then runs one joint fixed point over all in-scope regions.  On successful
completion, refined callsite and node rows overwrite the corresponding Steensgaard rows.  Nodes
outside scope retain the base result.  If the Andersen run exhausts a step/resume limit, no
partial ascending result is published: all non-exact rows remain byte-for-byte Steensgaard.

The implementation is in `crates/pangs-solve/src/andersen.rs`, principally
`directional_icall_slice`, `build_scope`, `build_base_solve`, and `finish_andersen_controlled`.
The architectural contract is in `DESIGN_lite.md` §2 D′.

## 2. Why predecessor closure is the sound cut

Let the directed prepartition graph be `G = (V, E)`, with an edge `u → v` when facts produced at
`u` may contribute to `v`.  Let `C(G)` be its SCC condensation DAG.  For a query seed `q`, define:

```text
SC(q) = union of every SCC in Pred*(SCC(q))
```

where `Pred*` includes the seed SCC itself.

Every edge entering `SC(q)` therefore originates inside `SC(q)`.  Solving the induced producer
closure cannot omit a producer needed by `q`.  Edges may leave the closure; their consumers are
not claimed as refined unless they are independently covered by another admitted closure.  Those
consumers retain Steensgaard.

Three qualifications are essential.

### 2.1 Direction must describe semantic production

Source closure is useful only if `prepartition_flow_edges` is a conservative producer graph for
every constraint form.  A missing producer edge turns a small closure into an unsound
under-approximation.  Each new PAG/summary constraint must therefore add both its weak-admission
relationship and its directed producer relationships, with focused tests for load addresses,
store addresses, whole-object copies, exact/lane/unknown fields, indirect bindings, external
seeds, and late call activation.

### 2.2 A closure covers a row, not necessarily an aggregate client object

A value-node points-to row can be covered by the predecessor closure of that value.  An
object-granular global points-to row is different: the export unions the root object's contents
with every materialized field.  It may be overwritten only when the closure covers the root and
all field regions that the projection can read.  Otherwise the global keeps its complete
Steensgaard row even if one field happened to be refined.

Likewise, a disposition certificate may depend on a set of access rows, callgraph reachability,
violation exposure, and global escape facts.  SC admission may sharpen its points-to-derived
inputs, but it does not independently certify the final disposition.  The existing certificate
passes continue to fail closed on incomplete access sets.

### 2.3 Ω inside a closure remains Ω

An external or integer-forged producer does not make a closed slice unsound; the corresponding
external-region fact must be seeded and propagated inside the slice.  It often makes the slice
unprofitable because the answer remains top.  Admission policy may decline such candidates for
economics, but it must not silently omit the Ω producer and call the result complete.

## 3. Proposed API and data model

Refactor the current special case into a reusable closure selector.

```rust
enum RefinementConsumer {
    IndirectCall { callsite: usize },
    NodeLabel { label: String },
    GlobalProjection { global: NodeId },
    ModRefAddress { owner: usize, statement: usize },
    AuditValue { finding: usize },
}

struct RefinementSeed {
    vertex: usize,
    consumer: RefinementConsumer,
    priority: u8,
    stable_key: String,
}

struct ClosureCandidate {
    seed: RefinementSeed,
    components: /* compact SCC set */,
    nodes: u64,
    edges: u64,
    omega_kinds: BTreeMap<String, usize>,
}

struct AdmissionCoverage {
    admitted_vertices: HashSet<usize>,
    covered_consumers: BTreeSet<RefinementConsumerId>,
    rejected_consumers: Vec<AdmissionRejection>,
}
```

The public analysis API should distinguish two concepts that are currently easy to conflate:

- **base materialization labels** request retained Steensgaard points-to rows needed as fallback;
- **refinement seeds** request an attempt to admit the label's Andersen producer closure.

`solve_andersen_with_overrides_and_target_points_to` already carries label information for
registry handling.  The first extension can add a separate `refinement_labels` set rather than
changing the meaning of existing targeted labels.  This preserves callers that request a base
row but do not authorize additional solve work.  Before solving Steensgaard, materialize the
union of the base labels and every resolved refinement label: requesting refinement must also
request its fallback.  An unresolved label is reported as a missing-label rejection; it has no
PAG row to materialize and must never be interpreted as a certified empty points-to set.

M1's `NodeLabel` consumer denotes the **direct value points-to projection**.  Its output bundle
contains both the named allocation set in `node_points_to[label]` and the corresponding
`RefinedNodeResolution` properties, including external status and provenance.  The existing
`RefinedNodeResolution` alone cannot supply this projection: it contains summary properties and
global candidates, but no named function/allocation set.  Admission coverage must identify the
projection being replaced, not merely the label that seeded it.

## 4. Seed families and staging

### 4.1 M0: behavior-preserving refactor

Replace `directional_icall_slice(ap)` with a general helper such as:

```text
source_closed_selection(ap, seeds, budget) -> AdmissionCoverage
```

Cache one condensation per oversize weak component.  Feed it only the existing icall seeds.
Require identical callgraph, ModRef, globals, disposition records, solver metrics other than new
telemetry, and deterministic profile output.

### 4.2 M1: explicit node-label seeds

Permit a caller to nominate value-like PAG node labels.  Resolve labels before admission and add
their SCC predecessor closures as candidates.  After successful completion of the joint solve,
a covered direct projection receives its Andersen allocation set in `node_points_to[label]`
and its matching node properties as one bundle.  A rejected or uncovered projection retains the
complete materialized Steensgaard bundle.  Solver exhaustion restores every such bundle together;
do not combine a narrowed external bit with a stale allocation set.  An empty named allocation
set does not itself certify an empty value: retain external/unknown alternatives and the
independently justified empty-witness semantics.

Registry resolution reads `node_points_to` for direct operands, but reads
`node_pointee_points_to` and `node_pointee_external` for registrations through memory.  The
predecessor closure of a pointer value does not necessarily cover the contents of its pointees.
M1 therefore refines only direct registry operands (`pointee = false`).  Registrations through
memory retain their complete baseline registry inputs until a separate projection requirement
covers every possible pointee, relevant field, content producer, and external alternative,
including late-materialized fields.  Publishing that projection must replace its allocation
and external-provenance rows together; admitting the address label alone is insufficient.

Good first consumers are already explicit and bounded:

- direct spawn/signal registry target operands;
- values attached to deferred pointer/integer or aggregate-flow audits; and
- diagnostic `PANGS_ANDERSEN_EXPLAIN_NODE` labels.

This phase tests generalized selection and merge semantics without inventing a broad heuristic
over all memory operands.

### 4.3 M2: global projection seeds

For each client-relevant mutable global, construct a projection requirement containing:

- its root object vertex;
- every fixed-PAG synthetic field region owned by the global;
- address/value nodes whose rows are directly consumed by the global access inventory; and
- any registry/callgraph rows required to interpret those accesses.

The candidate closure is the union of the predecessor closures of those required vertices.
Mark `GlobalProjection(g)` covered only if the entire requirement fits.  A partial selection may
still refine independently covered value rows, but must not overwrite `node_points_to[g]` or mark
the global access set complete.

Do not seed every global blindly into one union.  Compute candidates independently, rank them,
then charge only their marginal SCC/edge cost as closures are combined.

### 4.4 M3: selective ModRef address seeds

Seeding every load/store address recreates the full weak component.  Select only rows with a
plausible client payoff from the Steensgaard baseline, for example:

- an address row names more than one client-relevant global;
- an address row is external or violation-tainted and blocks a certificate;
- a row participates in an unhandled global's decisive access-set blocker; or
- the caller's exported ModRef row differs from a cheap direct/PAG attribution.

This is a policy heuristic, not a soundness premise.  Any unselected or rejected address row keeps
Steensgaard.  Report the selection reason so measured benefit can be attributed to policy rather
than to the closure algorithm.

## 5. Candidate selection and budgeting

Keep the current quadratic proxy initially so this work changes only scope selection.  For every
candidate record both total closure cost and marginal cost relative to already selected SCCs.

Recommended priority order:

1. exact production requirements needed to preserve existing icall behavior;
2. explicit caller-requested labels;
3. blockers for currently unhandled globals;
4. other global projections;
5. diagnostic or broad ModRef candidates.

Within one priority, sort by marginal cost and then a stable semantic key.  Numeric node ids may
break ties but must not be the only ordering key.  The selected union must satisfy the budget
after every addition; individually cheap candidates can have an expensive union.

Initially keep one budget per oversize weak component, matching current behavior.  A later global
budget across components is possible, but it adds a corpus-dependent scheduling policy and should
not be mixed into the first correctness evaluation.

Record Ω content separately from structural cost:

```text
closure_omega={int_to_ptr:1,unknown_operand_escape:6,...}
```

Possible policies are `allow`, `deprioritize`, or `reject-forged`.  `allow` is the semantic
baseline because Ω is propagated normally.  `deprioritize` may improve cost/benefit.  A rejection
must retain the Steensgaard row and be reported as policy fallback.

## 6. Solver and merge behavior

The first implementation should continue to solve the union of all admitted closures in one
joint Andersen fixed point.  This preserves current call-target activation, parameter/return
bindings, field materialization, and resume behavior.  Solving closures independently would need
an additional composition proof and is out of scope.

The merge rules are:

- an admitted callsite may replace its Steensgaard call row only after the joint solve completes;
- an admitted value node may replace its Steensgaard node summary; a covered M1 direct
  projection additionally replaces its materialized allocation set and corresponding node
  properties together, as specified in §4.2;
- a registration through memory retains its baseline input bundle unless that separate content
  projection is covered; direct-value coverage cannot authorize its replacement;
- a global object row may be replaced only when its `GlobalProjection` requirement is covered;
- global escape and baseline unknown-caller facts remain Steensgaard except where an existing
  independent certificate explicitly permits narrowing;
- rejected/unselected rows retain Steensgaard and carry fallback provenance; and
- any solver exhaustion discards all non-exact Andersen output, as today.

The union of predecessor-closed SCC sets is itself predecessor-closed, so all admitted value rows
are safe to emit.  Nevertheless, make coverage explicit rather than inferring it later from
`in_scope`: aggregate consumers have stronger requirements than membership of one base node.

Constraints with one in-scope endpoint and one out-of-scope successor may remain in the internal
solve, as in the existing implementation.  They can propagate refined facts outward, but those
out-of-scope rows are not exported as refinements.  There must be no edge from an out-of-scope
producer into an admitted row; assert this over the final selected set in debug/test builds.

## 7. Telemetry

Add machine-readable records per oversize weak component and per consumer candidate:

```text
weak_root, weak_nodes, weak_edges, weak_cost
scc_count, largest_scc, condensation_edges
consumer_kind, consumer_key, seed_vertex, seed_scc
closure_sccs, closure_nodes, closure_edges, closure_cost
marginal_sccs, marginal_nodes, marginal_edges, marginal_cost
omega_seed_counts
selected, rejection_reason, priority
```

Module-level counters should include:

```text
sc_components_considered
sc_candidates_by_kind
sc_candidates_selected_by_kind
sc_candidates_rejected_budget
sc_candidates_rejected_policy
sc_union_nodes / sc_union_edges
sc_covered_node_rows / sc_covered_global_projections
```

For benefit, compare each selected run with both normal Steensgaard-backed admission and the
forced-partition oracle:

- callgraph target/unknown changes;
- ModRef rows added and removed;
- global facts, violation classifications, and access-set completeness;
- disposition changes and certificate states;
- propagation steps and pair counts;
- wall time and peak RSS; and
- the fraction of the full-force semantic delta recovered by SC admission.

Do not summarize guard counts as disjoint global populations.  Use the disposition measurement
rules in `HOWTO_MEASURE_DISPOSITION_COVERAGE.md`.

## 8. Supporting YAPET data

### 8.1 Input and measurement identity

```text
input:  /home/brk/pangs-corpus/_out_bc/exe-yapteaparprfotci-O0-g.bc
SHA-256: ff215d14cf964f3ce0e071c4c6541d8fdffaf1cc1342209c42faec1f3c381013
mode: executable
stage: andersen
normal partition budget: 200000
```

The paired 2026-09-07 measurements used release binary SHA-256
`0bbc2d9cf85c43522b6148fc68717ef022ae6501814cefeb7425722fe461e936`.  The checkout uses
Jujutsu without `.git`, so emitted manifests record `pangs_git: unknown`; the binary hash is the
reproducibility anchor.  The working copy advanced during later drafting, so do not attribute
these numbers to a later binary without rerunning them.

### 8.2 Conservative normal admission

The surviving oversize component in the paired binary was:

| property | value |
|---|---:|
| weak root (run-local id) | 3630 |
| nodes | 2,695 |
| edges | 3,184 |
| quadratic proxy | 15,843,905 |
| indirect-call seeds | 66 |
| function objects | 10 |
| global objects | 6 |
| external classes | 1,789 |
| escaped classes | 28 |
| integer-forged | yes |

Root ids are not stable identities.  A 2026-09-05 binary called the analogous component root
3628 and measured 2,671 nodes/3,167 edges.  Use structure and symbol samples, not the numeric
root, to join runs.

The directed view of the paired component was:

```text
SCCs                         2,485
largest SCC                     78 nodes
icall candidates                66
selected icall seeds            57
selected union                 188 SCCs
selected union                 190 nodes
selected edges                 235
selected quadratic cost     80,750
budget                      200,000
```

Thus the current SC mechanism admits work for 57 callsites while the full weak component remains
a fallback.  All 66 callsites nevertheless retain unknown-callee in conservative mode.  The
component's Ω provenance, not merely its size, prevents those slices from producing finite
answers.

### 8.3 Structural cut diagnostics

On the 2,671-node profile, the largest residual node components were:

| diagnostic cut | largest residual components |
|---|---|
| none | 2,468, 10, 10, 9, ... |
| without loads | 643, 601, 151, 87, ... |
| without stores | 1,209, 1,101, 47, ... |
| without loads and stores | 507, 267, 180, 76, ... |
| without unknown GEP | 2,468, 10, 10, 9, ... |
| without constant GEP | 421, 96, 95, 94, ... |
| without memcpy/memset | 2,244, 157, 48, ... |

The component contained 1,194 constant-GEP, 451 load, 203 store, and 19 memcpy edges.  No offset
collision, function/data cohabitation, or aggregate-copy-bridge diagnostic was emitted for this
root, and the largest reported memory hub had only seven stores.  The evidence supports a
distributed weak-connectivity problem.  It does **not** identify a removable constant-GEP or
load/store edge.

### 8.4 Forced and isolated-root cost

On the 2026-09-05 release binary, a full `u64::MAX` solve and an isolated forced solve of the
megapartition produced identical callgraph, ModRef, globals, and disposition outputs.  The
isolated root used 93,936 of the full forced run's 99,359 propagation steps (94.54%).  Normal
admission used 2,518 steps.  Full forced wall time was 0.88 s versus 0.23 s normal, with peak RSS
59,516 versus 56,768 KiB.

Forced conservative Andersen narrowed exported ModRef rows from 1,406 to 1,008 but left all 66
icalls unknown and left disposition coverage unchanged at 11/13 handled.  This is the relevant
cost/benefit ceiling for a conservative-policy SC extension on that binary: it may recover useful
ModRef or violation attribution, but full-component refinement did not improve headline
disposition or callgraph coverage.

### 8.5 Integer-tag control

The only `IntToPtr` Ω seed is source line `clp.c:1205`:

```c
parse_int(clp, arg, 0, (void *)(uintptr_t)(sl->val_long ? 2 : 0))
```

`parse_int` converts `user_data` back to `uintptr_t` and inspects its low bits; it does not use it
as an address.  Under the explicit `--integer-pointer-policy assume-tags` supported-program
contract, the component is no longer forged and fits the sparse promotion caps (4,096 nodes and
4,096 edges).  It is therefore admitted at the ordinary 200,000 budget.

Same-binary results were:

| metric | conservative | `assume-tags` |
|---|---:|---:|
| oversize fallbacks | 1 | 0 |
| wall time | 0.54 s | 1.59 s |
| peak RSS | 56,932 KiB | 60,032 KiB |
| Andersen steps | 1,685 | 66,830 |
| unknown icalls | 66 | 12 |
| internal unique pointer-ModRef rows | 9,191 | 8,334 |
| final dispositions | atomic 7, localize 4, unhandled 2 | atomic 7, localize 5, unhandled 1 |

`yapteaparprfotci.c::options` moves from unhandled to localize.  This is not an argument for making
`assume-tags` the default.  It is a control demonstrating that semantic Ω provenance is the
dominant callgraph/disposition blocker after admission.  A future site-local cross-call opaque-tag
certificate could recover this case under a narrower contract, but it is separate from SC SCC
admission.

### 8.6 Field experiments are not substitutes for SC admission

With `assume-tags` held fixed so the whole component was admitted, the existing opt-ins produced:

| configuration | wall | steps | GEP pairs | copy-fact pairs | internal ModRef rows | disposition |
|---|---:|---:|---:|---:|---:|---|
| neither | 1.59 s | 66,830 | 4.52M | 31.8M | 8,334 | 7 atomic / 5 localize / 1 unhandled |
| PWC lanes | 2.55 s | 100,366 | 5.47M | 36.4M | 8,334 | unchanged |
| asymmetric overlap | 3.85 s | 246,065 | 2.40M | 259.9M | 7,969 | unchanged |
| both | 4.90 s | 419,627 | 2.60M | 234.0M | 7,969 | unchanged |

PWC lanes halve missing-exact collapses but expand the represented lane domain and increase work
without client benefit on YAPET.  Asymmetric overlap narrows ModRef by another 4.4% but creates a
large persistent overlap-read/copy workload.  Neither changes prepartition weak connectivity.
They should remain separate ablations during SC admission evaluation.

The compact ablation artifacts were retained under
`/tmp/pangs-yap-bridge-ablation-20260907.z9rn55`; the paired conservative run under
`/tmp/pangs-yap-conservative-paired-20260907.X8DRGD`; and the tag run under
`/tmp/pangs-yap-assume-tags-20260907.YJkFAa`.  `/tmp` paths are not durable project artifacts, so
the tables above are the retained measurement record.

### 8.7 Reproduction commands

The paired normal/tag runs used this command shape, changing only the integer-pointer policy:

```bash
PANGS_ANDERSEN_PROFILE=1 \
PANGS_PARTITION_PROFILE=1 \
PANGS_PARTITION_PROFILE_TOP=3 \
/usr/bin/time -f 'elapsed_seconds=%e\npeak_rss_kib=%M' \
  target/release/pangs analyze \
  /home/brk/pangs-corpus/_out_bc/exe-yapteaparprfotci-O0-g.bc \
  --stage andersen \
  --build-mode executable \
  --partition-budget 200000 \
  --integer-pointer-policy conservative \
  --dispose \
  --repo-root /home/brk/tmp/yapteaparprfotci \
  --no-overrides \
  --out OUT \
  --validate
```

For the tag control, replace `conservative` with `assume-tags`.  The field ablation held that tag
policy fixed and set the following pairs independently:

```text
baseline: PANGS_PAG_PWC_LANES=0 PANGS_ANDERSEN_ASYMMETRIC_FIELD_OVERLAP=0
PWC:      PANGS_PAG_PWC_LANES=1 PANGS_ANDERSEN_ASYMMETRIC_FIELD_OVERLAP=0
overlap:  PANGS_PAG_PWC_LANES=0 PANGS_ANDERSEN_ASYMMETRIC_FIELD_OVERLAP=1
both:     PANGS_PAG_PWC_LANES=1 PANGS_ANDERSEN_ASYMMETRIC_FIELD_OVERLAP=1
```

Scrub all other `PANGS_ANDERSEN_*`, `PANGS_PARTITION_*`, and `PANGS_PAG_*` experiment variables
for a fresh reproduction.  Use a new output directory for every arm and record the release binary
hash before and after the sequence; root numbers alone are not comparable across binaries.

## 9. Tests and invariants

### 9.1 Graph and selection tests

- A seed SCC includes every transitive predecessor and no unrelated successor.
- The union of overlapping closures charges shared SCCs/edges once.
- Candidate selection is deterministic under permuted PAG insertion order.
- A candidate individually below budget may be rejected when its marginal union exceeds budget.
- Exact/lane/unknown field-region vertices map back to the correct base nodes.
- An incoming edge from outside the selected set triggers a debug assertion/test failure.
- Ω seeds in a selected closure are present in the solve; policy rejection keeps fallback.

### 9.2 Constraint-family fixtures

- assign and GEP producer chains;
- load with separately produced address and storage contents;
- store with separately produced address and stored value;
- an unknown-offset load overlapping separately initialized exact fields;
- bounded and whole-object memcpy;
- a late indirect target whose parameter/return bindings were preinstalled from the envelope;
- an admitted callback result whose producing indirect-call operand exceeds the budget;
- receiver payload support components when enabled; and
- an outgoing-only tail that remains Steensgaard, extending the current directional-admission
  fixture.

The executable regressions `sc_admission_overlapping_fields.pir.json` and
`sc_admission_indirect_return.pir.json` live in `fixtures/synthetic/m1_4b/`.  Their solver tests
compare budget 200 with forced admission and independently require `{f0, f1}` and
`{other, target}`, respectively.  Each includes an independent target so a missing producer
leaves a nonempty answer and cannot be hidden by empty-result fallback.  Run both with
`cargo test -p pangs-solve sc_admission_preserves_ -- --nocapture`.

### 9.3 Client merge fixtures

- selected node label narrows while an adjacent unselected label stays byte-identical to Steens;
- rejected label retains its base points-to row and fallback provenance;
- a refinement-only label has its Steensgaard fallback materialized before admission;
- a missing label is rejected explicitly, never emitted as an empty resolution;
- a direct registry operand narrows its named target set and external status together;
- a registration through memory retains its complete baseline inputs when only the address
  value's closure is covered;
- partially covered global fields do not overwrite the global object projection;
- fully covered global projection may narrow and agrees with the same projection of the forced
  solve, in addition to passing the global subset ledger;
- deferred audit remains module-wide/base when one required value is uncovered;
- two client consumers sharing a closure both become covered;
- solver exhaustion publishes no partial SC result; and
- exact B1/B2 callsite overrides retain their precedence.

### 9.4 End-to-end validation

- `cargo test --workspace --all-targets`;
- conservative→Steens→Andersen differential checks with SC off/on;
- schema validation for all exported artifacts;
- per-site call targets and covered ModRef/global projections satisfy both sides of the
  same-input refinement ledger: `forced(q) ⊑ SC(q) ⊑ Steensgaard(q)`, where `⊑` means no more
  possible behavior and unknown/top is a lattice value rather than an empty target set;
- fully covered raw points-to projections equal the forced-solve projections under identical
  solver semantics; compare the named allocations and external alternatives, not just counts;
- uncovered projections retain their complete baseline rows;
- full disposition global records compared off/on, not only distribution counts; and
- dynamic icall traces where available.

The forced arm must complete, cover all producers of the compared projection, and use the same
bitcode, semantic knobs, exact overrides, and projection definition as the SC arm.  An exhausted
forced solve is inconclusive, not an oracle.  Compare raw projections separately from certificate
or policy decisions whose eligibility may depend on broader coverage.

The Steensgaard subset check is only an upper-bound check: dropping a real target also satisfies
it.  The forced-to-SC direction detects missing producers, and focused fixtures must additionally
assert their known required targets so a defect shared by both solves cannot make the test pass.
Likewise, an incoming-edge assertion over `prepartition_flow_edges` checks closure in that graph;
it cannot detect semantic dependencies omitted from the graph itself.  Keep these independent
checks alongside the graph assertions.

## 10. Evaluation plan

Use three arms on identical bitcode bytes and a fixed release binary:

1. normal weak-component admission;
2. normal budget plus extended SC admission; and
3. forced admission of the relevant weak component.

Hold build mode, integer-pointer policy, registry configuration, overrides, PWC lanes, asymmetric
overlap, receiver payloads, and closed-producer/consumer settings fixed.  Run the tag-policy arm
separately; do not mix it into the conservative baseline.

Start with YAPET because it supplies a cheap, well-characterized positive structural case and an
important semantic negative control.  Then run every current oversize-fallback artifact.  A small
closure on YAPET is not evidence that Vim, SQLite, tmux, or library-mode components have the same
condensation shape.

For each consumer family report:

```text
selected / rejected candidates
closure and marginal cost distributions
normal → SC semantic delta
normal → forced semantic delta
fraction of forced delta recovered
SC / forced propagation work, wall time, and RSS
fallback and exhaustion counts
```

An extension is useful only when it recovers client-visible forced-solve deltas at materially less
cost.  Selecting many slices with no row change is not success.  Conversely, unchanged disposition
does not erase a demonstrated ModRef or violation-attribution gain; report each client separately.

## 11. Rejected shortcuts and alternatives

### Drop constant-GEP or load/store edges

Rejected.  These are semantic producer dependencies.  The deletion cuts explain weak
connectivity but would make the admitted solve incomplete.

### Raise the global partition budget

Available as a measurement oracle, not a general policy.  Prior corpus profiling found forced
slowdowns from roughly 1.1× to more than 70× among completed modules, with many 30–90 second
timeouts.  It also spends work on client-irrelevant regions.

### Promote PWC lanes to split the partition

Rejected as a premise.  PWC lanes change finite field representation inside the PAG/solver; they
do not remove the GEP dependency in the admission graph.  YAPET is a measured negative case.

### Use asymmetric field overlap to split the partition

Rejected as a premise.  The experiment changes how overlapping fields are read after admission,
while `build_scope` remains unchanged.  On YAPET it improves ModRef precision but is substantially
more expensive.

### Treat every `inttoptr` as a tag

Rejected.  The explicit `assume-tags` policy is suitable only when its supported-program contract
is accepted and recorded.  Generic conservative analysis must preserve the Ω seed unless a local
proof establishes non-address use.

### Per-query independent Andersen solves

Deferred.  It duplicates shared closure work and complicates joint callgraph activation and
fallback composition.  One solve over the union of admitted predecessor closures is the smallest
extension of the current architecture.

## 12. Open questions

1. Which value labels are the minimal complete input set for each disposition access inventory?
2. Should a closure containing a forged/external source be allowed, deprioritized, or skipped by
   default after the structural M0/M1 implementation?
3. Is the current quadratic proxy still predictive for small SCC unions, or should actual-work
   profiles motivate a second bounded sparse exception?
4. Should priorities maximize number of covered consumers, estimated disposition payoff, or
   forced-oracle row delta?  The last is valid for calibration but unavailable in production.
5. Can global projection completeness be expressed solely in fixed-PAG region vertices, including
   fields materialized only after late call activation?
6. Does unioning many individually source-closed candidates recreate a megapartition often enough
   to require per-client quotas?
7. Should SC coverage and fallback provenance be exported in `metrics.json`, the disposition
   manifest, or both?

## 13. Concrete implementation sequence

1. Extract and unit-test a reusable condensation/closure selector; keep only icall seeds.
2. Add structured telemetry and a census mode that emits candidate closure sizes without solving.
3. Add explicit label seeds and per-consumer coverage markers.
4. Assert producer closure over every selected union in debug builds.
5. Add per-row merge tests and exhaustion fallback tests.
6. Profile YAPET normal/SC/forced with conservative integer policy and all unrelated experiments
   off.
7. Add global projection seeds, beginning with one explicitly requested global rather than all
   mutable globals.
8. Extend the admission profiler to calculate client-row deltas per seed/closure.
9. Run the full oversize-fallback population under the disposition measurement runbook.
10. Only then decide whether SC admission should remain opt-in, become a bounded default, or be
    restricted to explicit client requests.

The core design criterion is simple: **source closure is a completeness certificate for a chosen
row, not a reason to claim the enclosing weak component was solved.**  Keeping that distinction
explicit preserves PANGS-lite's fail-closed posture while exploiting the fine directed structure
already present inside its largest weak components.
