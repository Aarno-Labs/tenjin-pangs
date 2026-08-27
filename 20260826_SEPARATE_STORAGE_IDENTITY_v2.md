# Restore One-Hop Steensgaard Storage Contents

Date: 2026-08-26

## Status

Proposal for a replacement experiment. This document supersedes the representation and rollout
plan in `20260826_SEPARATE_STORAGE_IDENTITY.md`; it does not describe the current working-copy
implementation.

The experiment starts from the pre-implementation base, after the existing positive-null and
fail-closed empty-ModRef changes. Before the experiment, the field-owner coherence repair and the
two applicable v1 remediation fixes are landed as independently attributable prerequisite
revisions (§10.1). The legacy Steensgaard solver remains the production answer and continues to
feed Andersen for the duration of the experiment. The new solver runs beside it and emits a
separately named experimental answer.

## 1. Thesis

The defect is real, but the first repair introduced an unnecessary graph level.

Let:

```text
V(x) = the Steensgaard node for pointer-capable value x
S(a) = the storage location designated by address a
P(n) = the location to which the pointer value contained in n may point
```

The defective rules are:

```text
x = *a:  V(x) ≡ S(a)
*b = x:  S(b) ≡ V(x)
```

Their composition equates the source and destination containers:

```text
x = *a; *b = x

V(x) ≡ S(a)
S(b) ≡ V(x)
─────────────
S(a) ≡ S(b)
```

The correct one-hop Steensgaard rules are:

```text
x = *a:  P(V(x)) ≡ P(S(a))
*b = x:  P(S(b)) ≡ P(V(x))
```

Composing them equates only the pointer targets stored in the two containers:

```text
P(S(a)) ≡ P(S(b))
```

It does not equate `S(a)` and `S(b)`. That is sufficient to stop allocation tags, fields,
function objects, escape state, and callsite frontiers from moving between containers merely
because a pointer was copied through memory.

This is the storage-shape interpretation used by
[Steensgaard's original formulation](https://www.microsoft.com/en-us/research/publication/points-to-analysis-in-almost-linear-time/).
A graph node describes a location and its possible contents; its pointer/location component is a
direct edge to another location node. The value-type product attached to a node is not a separately
unioned storage-shape node. The v1 `Identity -> contents Carrier -> target Identity` chain reified
that product and added an unnecessary hop.

The v2 experiment therefore uses one storage-node arena with phantom-typed IDs and a one-hop
storage graph:

```text
points_to(Carrier)  -> Identity
points_to(Identity) -> Identity
```

There is no carrier/identity alternation and no intermediate contents carrier. `Carrier` and
`Identity` are compile-time views of the same node representation, not successive graph levels.

## 2. Defect witness

The motivating SQLite path remains:

```c
pOut->z = (char *)sqlite3JournalModename(eNew);
```

The loaded value comes from `sqlite3JournalModename.azModeName[eMode]`. Under the defective Load,
the value node is equated with the `azModeName` storage location. The following Store then equates
that class with the unresolved destination storage class, which already contains
`sqlite3RegisterDateTimeFunctions.aDateTimeFuncs` and hundreds of other allocation tags.

Under v2:

```text
load:   P(V(loaded_name)) ≡ P(S(azModeName[eMode]))
store:  P(S(pOut->z))     ≡ P(V(loaded_name))
```

The string targets may flow into `pOut->z`; the `azModeName` allocation identity does not. This is
the same precision result sought by v1 without an intermediate carrier or alternating hop count.

## 3. Abstract representation

### 3.1 One arena, phantom-typed IDs

Use one union-find arena for the one textbook node kind. Phantom-typed IDs make the two PAG roles
visible at the API without duplicating the node vocabulary:

```rust
struct Carrier;
struct Identity;

#[repr(transparent)]
struct LocId<K> {
    raw: u32,
    _kind: PhantomData<K>,
}

type CarrierId = LocId<Carrier>;
type IdentityId = LocId<Identity>;

struct LocationData {
    parent: u32,
    size: u32,
    points_to: Option<IdentityId>,
    may_be_null: bool,
    provenance: u8,
}

struct IdentityFacts {
    global_objs: Set<GlobalId>,
    fn_objs: Set<FunctionId>,

    // Facts about this identity/target set, never about a Carrier.
    external: bool,
    universal: bool,
    escaped: bool,
    universal_sources: SourceSet,
    escape_sources: SourceSet,

    icall_sites: Set<CallsiteId>,
    processed_icall_sites: Set<CallsiteId>,
    processed_fn_objs: Set<FunctionId>,
    processed_external_icall_sites: Set<CallsiteId>,
}

struct Classes {
    locations: Vec<LocationData>,
    identity_facts: IdentitySideTable,
}
```

Exact set representations and integer widths are illustrative. `IdentitySideTable` may be a
parallel slot vector or another compact mapping, but its public internal API accepts only
`IdentityId`. The shared `LocationData::points_to` and `may_be_null` fields have one meaning:
the pointer value contained in this node may point to that Identity and may be null. For a Carrier
the contained value is an SSA/PAG value; for an Identity it is the contents of that storage
location.

This removes the duplicated `target`/`points_to` and `may_be_null`/`contents_may_be_null`
vocabulary while preserving the type-level fact boundary. There is one backing union-find, one
link operation, and one null field.

### 3.2 Required PAG target invariant

Every points-to target is an allocation/location Identity. No points-to edge may target a
`Value`, `Param`, or `Return` Carrier. This is already the post-mem2reg shape assumed by the
solver, but v2 hard-codes it in `LocationData::points_to: Option<IdentityId>` and therefore makes
it an explicit PAG contract.

PAG validation must assert:

- ordinary `AddrOf` is Object -> value-like;
- the modeled external-readonly contents initializer is the sole shape-checked Object -> Object
  `AddrOf` exception;
- Assign, Load, Store, GEP, and Memcpy endpoints retain their existing value-like constraints;
- every base points-to target producer names an Object; and
- every synthetic exact/field target is allocated as an Identity.

PAG base-node IDs map statically:

- `Value`, `Param`, and `Return` nodes become `CarrierId` views;
- `Object` nodes become `IdentityId` views; and
- allocation-relative synthetic fields are created as `IdentityId`.

`node_class` remains one `Vec<u32>` indexed by PAG node. Its phantom discriminant is recovered from
the validated node kind, so there is no runtime role enum or per-node tag. The legacy snapshot
remains unchanged because it is still produced by the legacy solver; the v2 snapshot is
experimental and typed.

### 3.3 Why external and universal are Identity facts

`external` and `universal` describe a target set. They therefore live in the Identity-only side
table.

```text
x may point to external memory
    = identity_facts(points_to(carrier(x))).external
```

Load and Store join Identity targets, so these facts transfer through the ordinary Identity join.
An external call result materializes `points_to_of(result)` and sets `external` on that Identity.
An integer-forged pointer similarly sets `universal` on its target Identity.

Do not put either fact in `LocationData`. Parking a target-set fact on a Carrier recreates the v1
need for:

- `ext_or_target_ext` and parallel role-aware disjunctions;
- private raw fact vectors enforced only by accessor discipline; and
- `propagate_equal_target_carrier_facts`, including its special decision to copy external and
  universal state but not escape state.

With the fact on the target Identity, all three mechanisms disappear.

Keep an implicit external/Ω bit per Identity. Do not create one explicit Ω Identity and union
every external-pointing target with it: that would turn all external pointers into one
Steensgaard mega-class.

`escaped` is also Identity-only: it says that the address represented by that Identity is
reachable across an external or unknown boundary. A Carrier is not an allocation identity.

### 3.4 Globals and functions are Identity-only facts

Only `IdentityFacts` can contain `global_objs` or `fn_objs`. Consequently:

- a `join<Carrier>` cannot move allocation tags;
- allocation and function tags cannot be placed on a Carrier through the typed API; and
- a Carrier/Identity union is unrepresentable because both arguments to `join<K>` have the same
  phantom kind.

These replace v1 invariants 1--3. Do not port `ClassRole`, the role vector, or
`assert_role_invariants`.

### 3.5 Typed joins and links

Expose the uniform operations:

```rust
fn join<K: LocationKind>(LocId<K>, LocId<K>, Provenance) -> LocId<K>;
fn points_to_of<K: LocationKind>(LocId<K>) -> IdentityId;
fn peek_points_to<K: LocationKind>(LocId<K>) -> Option<IdentityId>;
```

`join<K>` merges `may_be_null` and provenance. If both nodes have `points_to` links, it recursively
calls `join<Identity>` on those targets; if only one has a link, it attaches that Identity to the
joined root. `join<Identity>` additionally merges the Identity-only side facts through a sealed
`LocationKind` hook; `join<Carrier>` has no access to those facts.

No operation accepts an untyped `usize`, and no `LocId<Carrier>` can be stored in a `points_to`
field.

## 4. One-step eager materialization

V2 deliberately uses eager materialization when processing a constraint:

```text
points_to_of(Carrier)   creates at most one Identity
points_to_of(Identity)  creates at most one Identity
```

A newly created Identity starts with `points_to: None`. Creating it does not recursively create
the location to which its own contents might point. Materialization is therefore depth one and
terminates:

```text
Carrier --points_to_of--> new Identity(points_to = None)
Identity --points_to_of--> new Identity(points_to = None)
```

Making either link recursively non-optional would manufacture an infinite storage chain and is
forbidden.

For each corrected Load or Store, v2 materializes both target identities needed by that concrete
constraint and joins them immediately. There is no unresolved equality between two absent target
slots and therefore no pending-target list.

This is a correctness simplification, not merely a coding convenience. V1's most dangerous
invariant was that a fact could arrive before a target link and then be stranded when the link was
materialized later. That required owner re-enqueueing plus explicit propagation across pending
carrier pairs. V2 deletes the pending pairs entirely.

One-step eager construction is not presumed cheap. The
[SQLite v1 measurements](ju_out/separate_storage_identity_sqlite_20260826/SUMMARY.md) were:

```text
pre-v1 baseline pointee classes:       58,471
eager alternating prototype:           83,106  (exceeded the RSS gate)
pending-list alternating implementation: 63,432
```

The eager alternating delta was 24,635 classes. V2 removes one of the three eager links requested
by that representation. A first-order two-thirds projection is therefore approximately 74,900
classes: about 28% above the pre-v1 baseline and 18% above the pending implementation. This is a
planning estimate, not an acceptance result; allocation sharing and the different one-hop union
shape may move it in either direction. The SQLite gate measures the actual count and RSS (§12.5).

Lazy `points_to_of` still has one local order obligation: if an Identity already has
external/universal/escape state when its `points_to` target is first created, the constructor must
initialize the child with the conservative inherited state. Conversely, setting one of those
facts after a link exists propagates it through that link using the normal worklist. This is one
constructor/setter invariant, not a graph of deferred equalities.

The first performance lever has already been applied: v2 omits the intermediate contents Carrier.
If the measured v2 eager result still exceeds the focused class-count or RSS budget, enter the
fallback ladder immediately rather than running the full corpus. Do not reintroduce an
intermediate carrier as a performance mechanism. Pending lists remain the last fallback because
they restore the late-materialization hazards this design is intended to remove.

## 5. Transfer rules

The v2 implementation is a complete Steensgaard solver. "Small experiment" refers to the semantic
delta and the absence of migration optimizations, not to an allowlist of supported PAG operations.

### 5.1 Changed rules

| Operation | V2 rule | Notes |
|---|---|---|
| `x = *a` | `join<Identity>(P(V(x)), P(S(a)))` | Do not join `V(x)` with `S(a)`. |
| `*b = x` | `join<Identity>(P(S(b)), P(V(x)))` | Do not join `S(b)` with `V(x)`. |
| `memcpy(d,s)` pointer contents | `join<Identity>(P(S(d)), P(S(s)))` | The pre-v1 code already had this one-hop shape. |
| Load null flow | `contents-null(S(a)) -> null(V(x))` | Heterogeneous directed fact edge. |
| Store null flow | `null(V(x)) -> contents-null(S(b))` | A null Store still produces a Mod row. |
| Memcpy null flow | `contents-null(S(s)) -> contents-null(S(d))` | Storage-to-storage, as in the pre-v1 solver. |

Here `P(V(x))` is `points_to_of(carrier(x))`, while `P(S(a))` is
`points_to_of(storage_identity(a))`. The same API expresses both one-hop edges.

Use a typed null-flow endpoint rather than manufacturing a carrier solely for storage contents:

```rust
enum NullEndpoint {
    Carrier(CarrierId),
    Identity(IdentityId),
}

struct NullFlow {
    src: NullEndpoint,
    dst: NullEndpoint,
}
```

Both variants read or set `LocationData::may_be_null`; the enum preserves the phantom kind across
the dynamically stored directed edge.

### 5.2 Ported unchanged

The following behavior remains present and retains its existing semantics, filters, and
provenance. It is ported to typed IDs rather than omitted:

| Rule family | V2 typed form |
|---|---|
| `AddrOf(o,p)` | `join<Identity>(points_to_of(p), identity(o))` |
| `Assign(s,d)` | `join<Carrier>(carrier(s), carrier(d))` when pointer-capable |
| ExactAssign fixed-address shortcut | `join<Identity>(points_to_of(d), exact_field_identity)` |
| Exact and unknown-root GEP | Join the destination target with the certified field identity or source target, respectively. |
| Actual/formal binding | `join<Carrier>(actual, formal)` with existing pointer-capable and by-value rules. |
| Return/result binding | `join<Carrier>(return, result)` with existing null handling. |
| Direct-call binding | Port complete argument/result behavior and external summary handling. |
| Indirect-call registration/binding | Register callsites on target identities; retain FSA filtering and joint callgraph fixed point. |
| `field_class` | Create/lookup allocation-relative `IdentityId`; retain overlap unions. |
| `storage_class_for_address` | Return an exact field/root identity when certified, otherwise `points_to_of(address_carrier)`. |
| Boundary seeding | Port exported/imported symbols, ptr/int, varargs, inline assembly, unknown callers/results, and external calls without weakening pointer-capable classification. |
| Function/global object registration | Seed tags only in the Identity side table. |
| Canonical null | Positive carrier null fact, no target identity, and no dropped PAG use. |

The ExactAssign branch is explicitly listed because it bypasses ordinary Carrier/Carrier Assign
unification and is easy to lose during a typed port.

The modeled external-readonly table initializer is also retained. When its destination is an
object slot rather than a value node, it initializes `points_to_of(slot_identity)` directly with
the table identity. It does not require `Identity -> Carrier -> Identity` routing. The PAG
validation exception and regression that admit this shape are prerequisite work in §10.1.

Every field Identity inherits its allocation owner's final global tags and its
external/universal/escape envelope. Inheritance occurs at creation and when the owner later
acquires a boundary fact; the solve-end prerequisite check in §10.1 closes and asserts both
envelopes before result materialization.

### 5.3 Boundary fact placement

Representative seeds become:

```text
external call result r:  external(points_to_of(V(r))) = true
inttoptr result r:        universal(points_to_of(V(r))) = true
external call argument a: escaped(points_to_of(V(a))) = true
exported object o:        escaped(I(o)) = true
unknown returned pointer: external(points_to_of(V(result))) = true
```

Null actuals are excluded only from binding/target creation. They remain pointer-capable for
boundary classification, so vararg, inline-assembly, and external-boundary Ω seeds are not
suppressed.

Escape/external closure follows existing conservative intent. If an identity is externally
reachable and already has a `points_to` edge, its target inherits the necessary external/escape
envelope. If the edge is created later, `points_to_of` performs the same inheritance at creation.
No client reads a carrier-local external bit because no such bit exists.

## 6. Result interpretation

### 6.1 Pointer values

For a value-like node `v`:

```text
let target = peek_points_to(carrier(v))

points_to(v) = target.map(tags).unwrap_or(empty)
external(v)  = target.map(external).unwrap_or(false)
universal(v) = target.map(universal).unwrap_or(false)
escaped(v)   = target.map(escaped).unwrap_or(false)
```

Queries never call the materializing `points_to_of`; they use `peek_points_to` and cannot mutate a
solved graph. There are no `_or_target_` accessors. Every positive fact is read from the target
Identity uniformly.

Absent -> `external == false` means only that the solver materialized no Identity carrying a
positive external fact. It is not a proof that the runtime value cannot be external or that the
producer set is complete. Every modeled external/universal producer eagerly materializes a target,
so a pointer-producing PAG edge with an absent target is classified as
`ProducerPresentTargetAbsent` and fails the experiment (§11.4). Downstream ModRef and icall policy
still treats an uncertified empty answer as unknown.

### 6.2 Storage locations

For an object or synthetic field identity `i`:

```text
let target = peek_points_to(i)

pointer targets stored in i = target.map(tags).unwrap_or(empty)
stored pointer is external  = target.map(external).unwrap_or(false)
stored pointer may be null   = location(i).may_be_null
```

A query through one additional pointer dereference follows `points_to` once more. Object queries
do not require the v1 identity-to-contents-carrier hop.

### 6.3 Empty is not a semantic proof

`points_to: None` is a lazy graph state, not proof of null, bottom, uninitialized storage,
producer completeness, or no global access. It does prove the narrower implementation fact that
no modeled constraint or boundary seed requested a target for that node. The producer audit decides
whether that is expected (`NoProducer` or `ProvenNullOnly`) or a solver omission
(`ProducerPresentTargetAbsent`). Positive null and the fixed-PAG non-global certificate remain the
only relevant positive semantic facts.

The existing fail-closed empty ModRef rule remains unchanged:

```text
empty named-global set + fixed-PAG LocalAlloca certificate => no global row
empty named-global set + every other state                  => Unknown Mod/Ref
```

Apply this policy after recording the raw v2 answer and its empty/Ω provenance instrumentation
(§11.4), so the safety fallback cannot hide a solver regression.

## 7. Invariants

The v2 solver must maintain:

1. `join<K>` accepts two IDs with the same phantom kind; Carrier/Identity union is unrepresentable.
2. Global and function tags exist only in the Identity side table.
3. External, universal, and escaped facts exist only in the Identity side table.
4. Every `LocationData::points_to` link names an Identity; no Carrier is ever a points-to target.
5. Creating an optional link creates exactly one Identity and does not recursively
   materialize that Identity's `points_to` link.
6. Load joins `P(V(dst))` with `P(S(src))`, never the value Carrier with the storage Identity.
7. Store joins `P(S(dst))` with `P(V(src))`, never the storage Identity with the value Carrier.
8. Memcpy joins storage `points_to` identities and transfers the uniform node null fact from the
   source Identity to the destination Identity.
9. A newly materialized `points_to` target of an Identity inherits an already-present conservative
   external/escape envelope from its owner.
10. Canonical null has a positive carrier null fact and no target Identity.
11. Null, scalar, unsupported, or empty pointer payloads never delete the PAG access or its
    ModRef evidence.
12. No general client treats an absent link as a finite empty proof.
13. Existing field identities contain their final owner tag and external/universal/escape
    envelopes before either solver materializes results; this is established by prerequisite A1,
    not by the v2 semantic delta.

Items 1--3 are enforced by the typed API and Identity-only side table; item 4 is enforced by the
link type plus the explicit PAG validation contract. Do not add a runtime
`assert_role_invariants` pass to restate them. Focus runtime assertions on link canonicalization,
union closure, tag containment, and result-oracle comparisons.

## 8. Experimental dual-solver architecture

### 8.1 Why both Steensgaard solvers run

Andersen is not independent of the current Steensgaard snapshot. It uses Steensgaard external,
universal, and escape facts to seed interesting partitions, profile them, and select special
universal-store handling. Feeding it the v2 fact layout without an adapter would silently change
admission and answers, then invalidate its use as an oracle.

During the experiment:

```text
PAG
 ├─ legacy Steensgaard ──> unchanged Andersen ──> independent complete-component oracle
 └─ v2 Steensgaard ─────────────────────────────> experimental answer
```

The legacy solver remains unchanged apart from the independently audited A1--A3 prerequisite
stack. Its snapshot continues to feed Andersen. Do not port Andersen's direct class reads,
prepartitioning, profiling, or external-field behavior to v2 during this experiment.

The v2 solver independently ports the complete Steensgaard call-binding fixed point and produces
its own callgraph, ModRef candidates, escape facts, and metrics. Complete Andersen components are
compared against v2 but do not depend on it.

This arrangement deliberately does **not** solve the Andersen external-field problem found during
v1 remediation. Legacy Andersen collapses fields of escaped external objects; FreeType showed that
a forged/universal value stored in one field can then make Andersen strictly coarser than corrected
Steensgaard. Splitting those fields made FreeType containment pass, but the narrowest tested repair
drove Placebo past 329 seconds and 12,283,916 KiB RSS before termination, versus a 67.22-second
clean baseline.

V2 answers a narrower experimental question: is the one-hop Steensgaard fallback itself correct,
usefully more precise, and affordable? It must not be broadened to Ω merely to contain a known
coarser legacy-Andersen external-field summary. Andersen containment is hard only on the eligible
components defined in §12.1; known external-field-contaminated components go to a separate
incompatibility ledger. A production cutover remains blocked until a separate design either fixes
the Andersen external-field model within the Placebo budget or supplies another independent
admission/oracle argument. V2 does not defer that work while claiming to have solved it.

This intentionally pays two fallback-solver runs. Report:

- legacy Steensgaard wall/RSS;
- v2 Steensgaard wall/RSS in isolation;
- unchanged Andersen wall/RSS;
- combined experimental process wall/RSS; and
- projected production cost with the legacy solver removed.

The dual run is experiment scaffolding. It is removed only after v2 passes its applicable
independent gates and the separate Andersen compatibility blocker is resolved; it is not part of
the proposed production architecture.

### 8.2 Output separation

The default artifacts remain the legacy production artifacts. V2 writes separately named
experimental outputs and never overwrites goldens or manifests by default.

The experiment records three views:

1. raw v2 local facts before empty fallback and high-fanout presentation collapse;
2. v2 final facts after the existing pre-v2 fail-closed empty-ModRef policy and summary closure;
   and
3. the unchanged legacy-plus-Andersen production result.

This separation distinguishes a solver precision change from a safety-policy change.

### 8.3 Stage-matched comparisons

Every directional gate isolates the solver under test:

| Question | Baseline | Candidate | Use |
|---|---|---|---|
| What did v2 Steensgaard change? | field-coherent legacy `--stage steens` | v2 `--stage steens` | hard row, escape, disposition, and cost gates |
| Does an independently complete refinement fit inside v2? | unchanged Andersen on legacy snapshot | v2 `--stage steens` | eligible static oracle plus incompatibility ledger |
| What would users see before a cutover? | legacy Steensgaard + Andersen | v2 experimental answer | descriptive impact only; not a directional safety gate |

Never compare v2-Steensgaard-only against legacy-Steensgaard-plus-Andersen for a
`never_written`, ModRef-removal, or escape-direction gate. Andersen removes spurious rows, so that
comparison is biased toward v2 appearing conservatively written and can mask a genuine v2
false-negative. The existing `--stage steens` output is the required baseline for SQLite and the
corpus.

## 9. Consumer audit

The v2 representation is not fed to Andersen during the experiment, but its own result clients
must use the one-hop interpretation consistently.

Audit and test:

- value and object `materialize_points_to` queries;
- local ModRef address attribution;
- indirect-call operands and function tags;
- external, universal, and escape reporting;
- global escape and address-exposure reporting;
- fields by allocation root;
- stationarity, runtime writers, `never_written`, and disposition inputs;
- summary closure and high-fanout presentation fallback;
- violation exposure and unknown-caller propagation; and
- the differential ledger.

Do not port v1's role-aware hop-count accessors. Introduce typed helpers whose names state whether
the input is a Carrier or storage Identity.

## 10. Sequencing

### 10.1 Prerequisite revisions and baseline

Start from the pre-v1 implementation base, but do not discard independently valid remediation
findings. Land the prerequisites as separately attributable `jj` revisions before adding v2.

**Revision A1: field-owner coherence.** Fix the existing creation-order bug in which `field_class`
copies `root_class.global_objs` only when the field is created and misses global tags added to the
root by a later union. Extend the same owner relation to boundary facts:

- global and function owner tags;
- external and universal state plus provenance; and
- escape state plus provenance.

A simple implementation is:

1. record the owner `NodeId` for every synthetic field;
2. at field creation, copy the owner's current tag and boundary envelope;
3. after each owner later acquires external/universal/escape state, propagate the delta to all
   existing fields and enqueue them for ordinary closure;
4. after the solve reaches a fixed point, canonicalize every field and owner root, backfill the
   final tag envelope, and drain any remaining boundary-fact propagation; and
5. assert tag and boundary containment before materializing results.

Adding only global/function tags after union completion needs no additional union fixed point;
boundary facts do, because they may propagate through existing `points_to` links. Multiple owners
of a merged field contribute the union of their final envelopes.

Add regressions that create a field before its owner later acquires (a) another global tag and (b)
external/universal/escape facts. Verify final ModRef membership and boundary closure. Land A1 alone
and audit every row, escape, and disposition change before proceeding.

**Revision A2: modeled external-readonly initializer contract.** Preserve the v1 PAG validation
fix that admits the shape-checked ExternalReadonly Object -> ExternalReadonly Object `AddrOf` used
for libc table contents, plus its regression. The legacy one-hop solver already interprets the
destination object's outgoing edge as its contents target; v2 does the same. No v1
Identity-to-Carrier routing is retained.

**Revision A3: effective fail-closed Andersen comparison.** Preserve the v1 `andersen.rs` assertion
alignment that compares refined ModRef against Steensgaard's effective emission envelope:
an uncertified empty address is Ω even when its pre-emission class bit is false. This makes the
eligible comparison in §12.1 well-posed without changing Andersen's actual answer.

The following v1 remediation code is deliberately not carried into the prerequisite baseline:

- pending-pair external/universal hand propagation, because v2 has no pending pairs and legacy has
  not changed;
- role-aware `_or_target_` accessors, because v2 facts live only on target Identities and Andersen
  still consumes the legacy snapshot; and
- the experimental Andersen external-field split, because it is the unresolved Placebo blocker
  described in §8.1.

Freeze new legacy `--stage steens` and full-pipeline baselines only after A1--A3 pass independently.
All v2 directional comparisons use those baselines.

### 10.2 Revision B: discriminating fixtures and instrumentation

Before implementing v2, add:

- the precision fixture in §11.1;
- the FN-direction fixture in §11.2;
- empty/Ω-reason instrumentation in §11.4;
- raw per-global Mod/Ref witness output used by the disposition gate; and
- separate timers/counters for the legacy solver, v2 solver, and Andersen.

The tests should initially demonstrate that the precision fixture fails under the defective rules
and that the positive FN fixture passes.

### 10.3 Revision C: v2 typed solver

Implement the phantom-typed one-arena solver, Identity-only fact side table, one-step eager links,
complete ported rule set, changed Load/Store equations, null flow, result materialization, and
experimental output. Keep the legacy solver and Andersen path untouched after A1--A3.

Do not add pending lists, copy-on-write provenance representations, an external-field Andersen
model, or production schema changes in this revision.

### 10.4 Revision D: focused evaluation

Run unit fixtures, SQLite at 64 and 256, FreeType, Placebo, and Curl. Fix semantic defects in v2;
do not change Andersen to make an oracle failure disappear.

Only after the FreeType compatibility diagnostic and Placebo v2-cost gate complete should the
experiment run the complete corpus and dynamic oracle.

### 10.5 Revision E: production decision

If all gates pass, propose a separate cutover revision that:

- makes v2 the production Steensgaard answer;
- supplies an explicit adapter or independently justified prepartition input for Andersen;
- reruns Andersen admission validation rather than assuming it is unchanged;
- removes the legacy Steensgaard experiment path; and
- regenerates artifacts only after review of every disposition transition.

The experiment itself does not authorize this cutover.

## 11. Regression and diagnostic fixtures

### 11.1 Precision-direction fixture

Use two independent pointer tables and two destination containers:

```c
static char a0[] = "a";
static char b0[] = "b";
static char *NamesA[] = { a0 };
static char *NamesB[] = { b0 };

struct Cell { char *z; };
static struct Cell CellsA[2];
static struct Cell CellsB[2];

void route_name(int which, int i, int j) {
    char *p = which ? NamesA[j] : NamesB[j];
    if (which)
        CellsA[i].z = p;
    else
        CellsB[i].z = p;
}
```

Assert positive and negative facts:

- Ref rows for `NamesA` and `NamesB` exist;
- Mod rows for `CellsA` and `CellsB` exist;
- the loaded payload may target `a0`/`b0`;
- neither source table identity appears in either destination storage candidate set; and
- the independent source and destination container identities are not unioned.

### 11.2 FN-direction fixture

Add a fixture in which two containers legitimately acquire the same stored target and a later
load must recover it:

```c
static int payload;
static int *left;
static int *right;

int *round_trip(int choose) {
    int *p = &payload;
    left = p;
    right = p;
    return choose ? left : right;
}
```

The containers `left` and `right` remain distinct storage identities, but their outgoing
`points_to` identities must be unified because both contain the same pointer target. Assert:

- both Mod rows are present;
- both later Ref rows are present;
- `payload` is present in the result of both loads;
- no Ω fallback is used to mask an absent finite target; and
- the shared contents target is the result of the required identity join.

This catches a rule that avoids overmerging by failing to propagate real stored targets. Andersen
containment alone cannot cover components that Andersen did not admit.

### 11.3 Boundary and recursion matrix

Cover:

- global, alloca, exact-field, affine-lane, and unknown-root Load/Store round trips;
- pointer-to-pointer chains of depth at least three;
- self-referential and mutually recursive storage graphs;
- Memcpy target and null transfer;
- null stores retaining Mod evidence;
- canonical null isolation;
- function-pointer tables and indirect-call binding;
- actual/formal and return/result propagation;
- external result, external argument, vararg, inline assembly, ptrtoint, and inttoptr seeds;
- modeled external-readonly table initialization;
- escaped identity facts both before and after `points_to` materialization; and
- exact-address Assign and field overlap.

### 11.4 Empty and Ω provenance instrumentation

Every raw empty pointer answer records why it is empty before the existing fail-closed emission
policy converts it to Ω. At minimum, distinguish:

```text
NoProducer
    The frozen PAG producer table contains no pointer-producing edge or seed for the value/cell.

ProducerPresentTargetAbsent
    At least one pointer-producing edge or seed exists, but the corresponding v2 target link was
    never materialized. Under one-step eager constraint processing this is presumptively a solver
    defect and is a hard diagnostic unless the producers are proven-null-only.

ProvenNullOnly
    Every complete producer is the canonical null value.

FiniteNonGlobalCertified
    The independent fixed-PAG LocalAlloca certificate proves no global row is required.

ModeledUnknown
    A boundary or unsupported producer deliberately supplies Ω/external rather than a finite tag.

MaterializedNoNamedTarget
    The target identity exists but contains no named global/function tag and has no positive
    completeness certificate.
```

In addition, every final Ω ModRef record and every `unknown_global` taint witness gets a primary
origin and full provenance set. The primary origin taxonomy distinguishes at least:

```text
FailClosedEmpty(<raw-empty reason>)

ExternalSeed {
    kind: ExternalCallResult | ExternalArgumentReachability | ExportedObject |
          UnknownCallerOrReturn | ExternalReadonly | OtherBoundary
}

UniversalSeed {
    kind: IntToPtr | InlineAssembly | Vararg | AssumptionViolation | OtherBoundary
}

ExternalPropagation {
    via: Assign | Load | Store | Memcpy | Gep | CallBinding | ReturnBinding |
         FieldOwnerInheritance | EscapeClosure
}

UniversalPropagation {
    via: Assign | Load | Store | Memcpy | Gep | CallBinding | ReturnBinding |
         FieldOwnerInheritance | EscapeClosure
}

PresentationCollapse
```

For propagated facts, retain a bounded witness path to the originating seed and the first edge that
moved the fact onto the queried target. Distinguish finite-scope external from module-wide
universal Ω and record the exact transition that promoted the scope.

Record producer edge IDs/kinds, seed kinds, target-link state, fixed-root state, and final policy
decision. Report counts per module and examples for every category. A bare empty, external, or Ω
count is insufficient; it would repeat the v1 audit's inability to explain the dominant precision
loss without a separate forensic run.

## 12. Validation gates

### 12.0 Measured precision risk and numeric Ω budgets

The [v1 corpus audit](ju_out/separate_storage_identity_corpus_20260826/REPORT.md) already measured
the likely dominant v2 risk on zstd, Curl, and SQLite:

```text
unknown ModRef records:          10,456 -> 80,829   (7.73x)
named ModRef records:                         -19.7%
module-wide unknown records:      5,479 -> 60,845   (11.1x)
unknown_global taint witnesses:   7,045 -> 55,675   (7.90x)
```

The reason split was not an empty-answer story:

```text
fail-closed empty fallback:       +897  (1.3% of the increase)
Steens external/universal:      +69,476 (98.7% of the increase)
```

Curl also lost the context rewrite site
`Curl_uint_hash_clear@uint-hash.c:89:7#0`. Moving external/universal bits from a Carrier to its
target Identity simplifies transfer but does not inherently narrow that propagation; v2 may
reproduce this coverage collapse.

Apply the following hard, stage-matched budgets to the field-coherent legacy-Steens versus v2-Steens
comparison. These thresholds are fixed before running v2 and may not be relaxed after observing
the candidate:

- across the zstd/Curl/SQLite focused set, module-wide Ω records and distinct logical effects may
  grow by at most 25% in aggregate;
- `unknown_global` taint witnesses may grow by at most 25% in aggregate;
- no focused or corpus module may grow either metric by more than 50%;
- aggregate named local ModRef records may fall by at most 10%, and no module may fall by more than
  20%, without an audited proof that the removed rows were spurious and dynamic containment for
  the affected accesses;
- no previously selected context rewrite site may disappear without an audited independent
  blocker; and
- after excluding only positively justified open-boundary Ω, the module-wide Ω rate over eligible
  pointer ModRef logical effects may increase by at most five percentage points.

When a per-module baseline count is zero, any positive candidate count is treated as an infinite
ratio and must be individually justified; it is not omitted from the ratio gate.

The adjusted denominator is:

```text
all pointer ModRef logical effects
    minus effects independently proven open by an exported hook, explicit external contract,
         assumption violation, or other positive boundary certificate
```

An Ω record does not leave the numerator merely because its provenance ultimately contains an
external/universal seed. The queried access itself must have the positive open-boundary
certificate; otherwise broad propagation is exactly the precision behavior being measured.

Report raw and justified-adjusted ratios. Failing any budget rejects the experiment or requires a
new narrowing design; soundness alone does not make a 7.7x Ω increase acceptable for the client.

### 12.1 Independent Andersen containment

For every **eligible complete** Andersen component, compare the unchanged Andersen answer with the
v2 answer before high-fanout collapse:

```text
Andersen unfiltered named-global candidates subset-of v2 unfiltered candidates
Andersen Ω => v2 Ω
```

Eligibility requires that the Andersen answer did not become external/universal through the
legacy field-insensitive external-object summary and that both answers use the same address and
FSA filters. This keeps Andersen representation-independent with respect to the v2 storage graph
without pretending that its known external-field collapse is a precision oracle.

Compare local access facts before summary closure and emitted rows after closure. Apply identical
global-address-exposure predicates if filtered sets are compared. For indirect calls, compare
either pre-FSA envelopes on both sides or post-FSA targets after the same signature filter.

On eligible failure report the statement/callsite, access kind, missing object/function, Andersen
component status, v2 identity roots, and provenance from both solvers. Do not weaken the assertion
or modify Andersen admission as part of v2.

Every ineligible complete component goes to a separate ledger with the external base, field
location, forged/universal seed, and the exact Andersen collapse witness. FreeType's known case is
expected in this ledger. It is not a v2 pass, not a v2 containment failure, and not permission to
make v2 more conservative. The ledger is a production-cutover blocker owned by the separate
Andersen external-field work item described in §8.1.

### 12.2 Hard disposition-direction gate

Compare field-coherent legacy `--stage steens` with v2 `--stage steens`. In that stage-matched
comparison, no global may:

- newly acquire `never_written`; or
- lose `omega_escaped_address`.

Both changes move toward the `immutable` guard:

```text
immutable iff never_written && !omega_escaped_address
```

Either transition requires an audit record identifying every removed Mod or escape witness and an
independent proof that it was spurious. Run the gate on raw per-global witnesses before
disposition aggregation and again on final manifest facts. Regenerating a golden is not an
explanation.

Do not use the legacy Steensgaard-plus-Andersen production answer as this baseline. Andersen's
removal of spurious Mod rows can otherwise mask a v2-caused `never_written` gain. The full-pipeline
comparison is reported separately as user-impact context only.

Also report the opposite transitions. They are conservative coverage losses rather than the
silent-corruption direction, but large increases in writes or escaped addresses still require a
precision budget.

### 12.3 Dynamic global-access oracle

Extend the existing trace checker to record concrete global loads, stores, and memory-intrinsic
endpoints. Every observed access must be present in the v2 finite row or covered by v2 Ω. Run the
precision and FN fixtures plus corpus executables that exercise global pointer tables.

### 12.4 Indirect-call gates

Run `pangs icall-census` for legacy and v2 answers, split into:

- finite target sites;
- Ω-marked sites;
- empty operand/target sites; and
- FSA-filtered sites.

An empty indirect-call target remains unknown. Check every eligible complete Andersen target
against v2 with aligned FSA filtering and ledger the external-field-ineligible cases separately.
Audit every newly empty operand. Losing the Curl rewrite site named in §12.0 or any other previously
selected context rewrite site fails the no-shrink gate unless an independent blocker is recorded.

### 12.5 SQLite acceptance run

Run `lib-sqlite-O1` in library mode at ModRef fanout limits 64 and 256. Compare against the
field-coherent legacy `--stage steens` baseline for every directional row, escape, and disposition
gate. Report the legacy full pipeline separately for user-impact context:

- whether `aDateTimeFuncs` and `azModeName` co-occur in any finite or collapsed set;
- the identities and outgoing targets at the motivating edge;
- local named, raw-empty, Ω, and collapsed rows;
- closure named, Ω, and collapsed rows;
- distinct fanout-set hashes and sizes;
- raw empty reasons from §11.4;
- Mod/Ref keys moving finite-to-finite, finite-to-Ω, Ω-to-finite, and absent transitions;
- callgraph and icall-census changes;
- per-global write and escape transitions;
- legacy, v2, Andersen, and combined wall/RSS; and
- total Location and Identity-target creation counts, joins, worklist activity, and maximum class
  sizes.

The focused eager-materialization budget is:

```text
v2 created Identity targets <= 75,000
v2 isolated RSS             <= 1.15 * field-coherent legacy-stage-Steens RSS
```

The class ceiling is the rounded 74,900 projection from §4, not a claim that the projection will
hold. Exceeding either bound enters §13 before broader evaluation. Also report v2 class count
against the measured 58,471 pre-v1 and 63,432 pending-v1 reference points.

Success requires the motivating container identities to separate. It does not require every
formerly collapsed row to become finite: missing producer information may correctly remain Ω.
However, `ProducerPresentTargetAbsent` must be zero or fully explained; fail-closed emission may
not silently absorb it. This allowance does not waive §12.0: external/universal propagation,
module-wide Ω, named-row loss, and `unknown_global` taint must remain within their numeric budgets.

### 12.6 FreeType compatibility diagnostic and Placebo v2-cost gate

Run FreeType and Placebo before the full corpus, but do not imply that v2 exercises or resolves the
v1 Andersen external-field repair.

For FreeType:

- run unchanged legacy Steensgaard -> unchanged legacy Andersen, without the experimental
  external-field split;
- run v2 independently;
- enforce hard containment on eligible components;
- place the known external-field/universal incompatibility in the §12.1 ledger; and
- reject any new containment failure outside that known-ineligible class.

For Placebo:

- measure v2's own isolated solver wall time, RSS, class creation, Ω growth, and taint growth;
- verify that the unchanged legacy Andersen configuration retains its baseline behavior; and
- do not enable the v1 external-field split whose unfinished run exceeded 329 seconds and
  12,283,916 KiB.

Reject the v2 experiment if v2 alone exceeds 2x the field-coherent legacy-stage-Steens wall time or
RSS on either module. Combined dual-run time is reported separately and is not the projected
production cost.

Passing this section means only that v2 does not reproduce Placebo's cost explosion in its own
solver and introduces no new eligible oracle failure. It does not clear the Andersen
external-field production-cutover blocker.

### 12.7 Full corpus

After the focused gates pass, run every canonical corpus module. Report per module and geomean:

- raw and final ModRef categories;
- unknown-global taint and provenance;
- icall categories and call-edge changes;
- eligible complete Andersen containment coverage and external-field incompatibility ledger size;
- field/global envelope differences;
- stage-matched legacy-Steens -> v2-Steens stationarity and disposition transitions, plus a
  separately labeled full-pipeline impact comparison;
- legacy/v2/Andersen/combined wall and RSS; and
- arena sizes and union/worklist metrics.

Verify the construction invariant that one changed memory constraint requests no more than two
previously absent Identity targets. Report the observed creation count normalized by changed
Load/Store/Memcpy constraints; this is instrumentation, not the arena-growth budget.

Performance and precision budgets for v2 alone:

- no more than 15% geomean wall-time or RSS regression;
- no unexplained module above 2x;
- no unexplained Identity-count growth above 50% geomean or 2x on one module; and
- no unbounded growth in provenance or callsite sets;
- all module-wide Ω, named-row, `unknown_global`, and adjusted-denominator limits in §12.0; and
- no context rewrite-set shrink without an independent blocker.

The dual-solver experiment is expected to cost more than these limits in total. Judge the proposed
production cost using the separately measured v2 run, not by pretending the experimental oracle is
free.

## 13. Fallback ladder

Use this order if v2 misses its performance budget:

1. Verify that no intermediate contents Carrier was accidentally recreated and that materialized
   Identity nodes are interned/canonicalized correctly.
2. Remove accidental result/provenance duplication and optimize set storage without changing
   equations.
3. Identify which Load/Store/Memcpy edges create two previously absent targets and measure their
   empty/Ω provenance categories.
4. Only then consider Steensgaard conditional joins/pending target equalities for two absent
   targets.

The earlier typed sketch's first fallback was to collapse
`Identity.contents: CarrierId` into a direct optional Identity target. V2 generalizes that
collapsed representation into the single `LocationData::points_to` field from the start. There is
therefore no intermediate carrier left to remove later.

If pending equalities are eventually required, they must carry only identity-target equality.
External/universal/escape facts remain on Identity and must never be hand-copied between carriers.
Reintroducing pending state also reopens late-materialization proof obligations and requires a
separate design review; it is not an implementation detail.

## 14. Acceptance and rejection

Accept v2 for a production-cutover proposal only if:

- the two-table fixture removes container co-occurrence while the FN fixture retains every required
  target and row;
- every eligible complete Andersen answer is contained with aligned filters;
- the Andersen external-field incompatibility ledger is resolved by a separately accepted design
  that passes the Placebo budget;
- dynamic observed global accesses are contained;
- no unaudited global acquires `never_written` or loses `omega_escaped_address`;
- empty reasons show no unexplained producer-present/unmaterialized-target cases;
- module-wide Ω, named rows, `unknown_global` taint, and justified-adjusted coverage satisfy every
  numeric budget in §12.0;
- no context rewrite site is lost without an independent blocker;
- the motivating SQLite merge is removed with useful fanout reduction;
- FreeType's eligible checks and Placebo's v2 correctness/performance gate pass; and
- the full corpus meets the precision and cost budgets.

Reject or redesign v2 if:

- soundness requires equating a storage Identity with an SSA Carrier;
- a real pointer round trip requires an intermediate contents Carrier;
- the one-hop representation cannot preserve external, universal, null, or escape closure without
  a carrier-local target-set fact;
- eligible complete Andersen or dynamic observations fall outside v2;
- external/universal propagation exceeds the module-wide Ω or `unknown_global` budgets;
- fail-closed empty answers make total or justified-adjusted Ω exceed §12.0, or contain an
  unexplained producer-present/unmaterialized-target case;
- the Andersen external-field incompatibility cannot be resolved without the measured Placebo
  blowup or an equally unacceptable cost;
- disposition moves in the corruption direction without independent proof; or
- arena growth or runtime exceeds the corpus budgets after representational optimizations.

If rejected, preserve the core diagnostic: direct `V(x) ≡ S(a)` and `S(b) ≡ V(x)` Load/Store
unions are container-merging rules. Any replacement must equate outgoing pointer targets instead,
even if it chooses a different representation for those targets.
