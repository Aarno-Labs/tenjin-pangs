# Restore the Standard Steensgaard Load/Store Rules

Date: 2026-08-26

## Status

Proposal for review. Not implemented.

The current fallback already has the alternating structure needed by the standard Steensgaard
formulation. The defect is narrower than a new abstract-domain design: pointer `Load` and `Store`
dereference that structure at the wrong level and thereby equate storage identity with pointer
contents.

The proposed solver change is therefore limited to the pointer `Load` and `Store` equations. A
small set of consumers must become role-aware, and validation must treat empty ModRef answers as a
soundness boundary rather than as an automatic proof of no global access.

## 1. The defect

Let:

```text
V(x) = the class for pointer-capable value x
T(v) = the pointee/target component of carrier v
S(a) = the storage identity designated by address a
C(i) = the contents carrier of storage identity i
```

The current pointer rules in `crates/pangs-solve/src/lib.rs` are effectively:

```text
x = *a:  V(x)  ≡ S(a)
*b = x:  S(b)  ≡ V(x)
```

Composing them gives:

```text
x = *a;  *b = x;

V(x) ≡ S(a)
S(b) ≡ V(x)
─────────────
S(a) ≡ S(b)
```

Every copy of a pointer through memory can therefore unify the source and destination containers.
For example:

```c
p = list->next;
other->head = p;
```

can make `list->next` and `other->head` the same abstract storage location. The union carries not
only pointer targets, but every allocation tag, function tag, `ext`/`universal`/`esc` bit, field
class, callsite frontier, and provenance fact accumulated by either side.

This is larger than the initially observed symptom that allocation tags leak onto loaded values.
It is a general container-to-container merge channel and is likely a major source of Steensgaard
mega-classes throughout the corpus.

### 1.1 SQLite witness

The concrete SQLite witness is:

```c
pOut->z = (char *)sqlite3JournalModename(eNew);
```

in `sqlite3VdbeExec` at `sqlite3.c:103710` (PAG edge 147177). The loaded value comes from
`sqlite3JournalModename.azModeName[eMode]`. Immediately before the store, the source class carries
the `azModeName` allocation tag while the unresolved destination storage class already carries
`sqlite3RegisterDateTimeFunctions.aDateTimeFuncs` and hundreds of other allocation tags. The
current Store joins them.

Positive canonical-null modeling removed a different bridge but cannot affect this non-null
load/store path. Directional Andersen admission was also evaluated and rejected: the relevant
predecessor closure contained 22,392 nodes, exceeded the budget by four orders of magnitude,
changed no SQLite rows, and raised wall time from roughly 33 seconds to 179 seconds. The evidence
is in `ju_out/modref_directional_sqlite_20260826/SUMMARY.md`.

SQLite is a useful witness and acceptance workload, but it is not the definition or full extent of
the defect.

## 2. This restores textbook Steensgaard

The standard Steensgaard rule for `x = *y` unifies the pointee components of the value type and
the storage-contents type. It does not unify the value carrier with the storage identity. In the
notation above:

```text
x = *a:  T(V(x))    ≡ T(C(S(a)))
*b = x:  T(C(S(b))) ≡ T(V(x))
```

The two statements may make the pointer targets stored in `S(a)` and `S(b)` equivalent, which is
the intended unification abstraction. They do not imply `S(a) ≡ S(b)`.

This framing matters:

- the complexity and soundness argument are the standard almost-linear Steensgaard argument;
- the existing `pointee` field already represents both alternating links needed by the rule; and
- review can focus on two incorrect transfer rules and their consumers rather than on a new
  two-domain solver.

The surrounding implementation corroborates the diagnosis:

- `AddrOf` joins `pointee(value)` with an object identity;
- `Assign` joins value carriers and recursively joins their pointees;
- `GEP` joins target identities; and
- `Memcpy` already joins `pointee(dst_storage)` with `pointee(src_storage)`, contents to contents.

Those rule families already have the correct alternating shape. Pointer `Load` and `Store` are the
exceptions.

## 3. Scope

### 3.1 Required semantic change

Only pointer `Load` and pointer `Store` change in the Steensgaard solver, together with directed
nullability flow for those operations. `AddrOf`, `Assign`, call binding, `GEP`, `Memcpy`, field
overlap, boundary seeding, and indirect-call binding retain their existing equations.

The implementation keeps:

- one union-find backing vector;
- the existing `ClassData::pointee` link;
- the current worklist and recursive pointee-union closure;
- the existing allocation-relative field classes; and
- the current `SteensClasses` snapshot shape, extended only as needed to expose role information.

It does not require separate carrier and identity union-finds, a wholesale result-schema
replacement, a five-phase solver cutover, or two permanently running fallback solvers.

### 3.2 Non-goals

- Making the SQLite `pOut` address allocation-exact.
- Solving unknown-root GEP precision.
- Adding context sensitivity, heap cloning, or typed-heap specialization.
- Removing any Ω seed or weakening pointer-capable boundary classification.
- Changing the canonical-null, undef, poison, integer-forged-pointer, or address-zero contracts.
- Claiming to fix dispatch-table sites whose operand has no function pointees at all.

The last item is important. This change narrows the over-merge half of indirect-call imprecision.
It is orthogonal to the empty-set half and may expose more empty answers that coarse merging used to
hide.

## 4. Alternating roles in the existing union-find

No new abstract domain is necessary. Each union-find class has one of two roles:

```text
Carrier --pointee--> Identity --pointee--> Carrier --pointee--> Identity ...
```

- PAG `Value`, `Param`, and `Return` nodes begin as `Carrier`.
- PAG `Object` nodes begin as `Identity`.
- allocation-relative synthetic field classes are `Identity`.
- `pointee_of(Carrier)` creates or returns an `Identity` target.
- `pointee_of(Identity)` creates or returns a `Carrier` for storage contents.

This is structural, not inferred from LLVM types. PAG validation already enforces `AddrOf` as
object-to-value and `Assign`, `Load`, `Store`, `GEP`, and `Memcpy` as value-to-value, so base-node
roles are known before solving.

Add a compact role tag for synthetic classes and role-checked wrappers:

```rust
enum ClassRole {
    Carrier,
    Identity,
}

fn join_carriers(...)
fn join_identities(...)
fn target_of(carrier: usize) -> usize       // Identity
fn contents_of(identity: usize) -> usize    // Carrier
```

Both wrappers may call the existing `join`; they assert that both roots have the expected role.
When same-role roots are joined, their pointees necessarily have the opposite role, so the
existing recursive pointee join remains valid.

The critical lazy-materialization behavior must remain unchanged: when `pointee_of` creates a
pointee, it enqueues the owner root. An identity may become escaped or external before its contents
carrier exists, and a contents carrier may acquire those facts before its target identity exists.
Re-enqueueing the owner is what lets `process_class` propagate the already-present facts through a
newly materialized link.

## 5. Transfer rules

### 5.1 Load

Replace:

```text
join(V(dst), S(address))
```

with:

```text
join_identities(T(V(dst)), T(C(S(address))))
```

On the existing non-null pointer path, in terms of the current vector:

```rust
let dst_carrier = class_of(edge.dst);
let storage_identity = storage_class_for_address(edge.src, width, true);
let contents_carrier = contents_of(storage_identity);
let dst_target = target_of(dst_carrier);
let contents_target = target_of(contents_carrier);
join_identities(dst_target, contents_target, provenance);
```

The Ref row is still attributed from `S(address)`. The loaded value receives the targets held in
the storage contents, not the storage allocation's own tags.

### 5.2 Store

Replace:

```text
join(S(address), V(src))
```

with:

```text
join_identities(T(C(S(address))), T(V(src)))
```

On the existing non-null pointer path, in terms of the current vector:

```rust
let src_carrier = class_of(edge.src);
let storage_identity = storage_class_for_address(edge.dst, width, true);
let contents_carrier = contents_of(storage_identity);
let src_target = target_of(src_carrier);
let contents_target = target_of(contents_carrier);
join_identities(contents_target, src_target, provenance);
```

The Mod row is still attributed from `S(address)`. The source pointer target becomes a possible
target of the destination contents; neither carrier is joined to the destination identity.

### 5.3 Positive nullability

Nullability remains a positive carrier fact. It is not represented by an absent target and it does
not join the canonical-null class into another class.

Generalize `null_copy_edges` into directed carrier-to-carrier null-flow edges:

```text
Load:    C(S(src)) -> V(dst)
Store:   V(src)    -> C(S(dst))
Memcpy:  C(S(src)) -> C(S(dst))
```

This fixes the existing Memcpy mismatch: `null_copy_edges` currently records
`(src_storage, dst_storage)`, which are identity classes, even though `may_be_null` belongs to the
contents carriers under the alternating interpretation.

A proven-null Store sets nullability on `C(S(dst))` and retains the Mod row. A proven-null Load or
invalid null address retains its current fail-closed behavior and access evidence. GEP from null
remains outside the canonical-null contract. Undef and poison remain distinct from null.

The solver must not create a non-null target identity solely to encode a proven-null value. When a
carrier is positively proven null and has no target, transfer the null fact without materializing a
target for that path.

### 5.4 Unchanged rules

```text
AddrOf(o, p):  T(V(p)) ≡ I(o)
Assign(s, d):  V(s) ≡ V(d)
ExactAssign(d, root, field): T(V(d)) ≡ I(root, field)
GEP(b, d):     T(V(b)) ≡ T(V(d))       // subject to existing exact-field handling
Memcpy(d, s):  C(S(d)) ≡ C(S(s))
actual/formal: V(actual) ≡ V(formal)
return/result: V(return) ≡ V(result)
```

`ExactAssign` is the existing fixed-PAG shortcut for an Assign destination whose complete
allocation-relative address is known. It deliberately bypasses Carrier/Carrier union and joins the
destination target to the certified field identity. The role-checked implementation must cover
this branch explicitly; describing Assign solely as `V(s) ≡ V(d)` is incomplete.

Exact-address and field-overlap certificates otherwise remain unchanged. Unknown-root GEP stays
field-insensitive, but a later Store now merges through the selected identity's contents instead
of merging the selected identity itself.

## 6. Escape, external, and Ω facts

Keep the current `ext`, `universal`, and `esc` bits on `ClassData`; do not introduce a second
external-identity representation in this change.

`process_class` already propagates `ext`/`esc` from a class to its pointee. With alternating roles,
that closure is:

```text
Identity -> contents Carrier -> target Identity
Carrier  -> target Identity  -> contents Carrier -> ...
```

This is the required escape-through-storage closure. Existing exported/global seeds, external
calls, varargs, inline assembly, pointer/integer boundaries, and indirect-call cross products do
not need new transfer equations. That statement applies only to producers: the interpretation of
the resulting bits changes for every consumer because a value carrier need not inherit the bits on
its target identity.

Two details are mandatory:

1. `pointee_of` must continue to enqueue the owner on lazy materialization, even when the owner was
   processed earlier.
2. Result queries and internal clients must use one role-aware interpretation of existing bits. A
   value is external, universal, or escaped if the fact is present on its carrier or on its target
   identity after worklist closure. No parallel explicit-external-identity model is added.
3. The raw `ext`, `universal`, and `esc` vectors in `SteensClasses` become private. Public internal
   clients use role-aware accessors such as `ext_or_target_ext(node)`,
   `universal_or_target_universal(node)`, `esc_or_target_esc(node)`, and an explicitly identity-only
   accessor for object roots. It must be impossible to combine `class_of(value_node)` with a raw
   bit-vector index.

Regression tests must cover both late-materialization orders:

- mark an identity escaped, then create its contents and contents target; and
- mark a contents carrier external, then create its target.

In each case the new target must receive the conservative fact after the worklist drains.

## 7. Enumerated consumer audit

The solver equations change in only two places, but consumers of the alternating `pointee` link
must distinguish value nodes from object nodes.

### 7.1 `materialize_points_to`

The current comment explicitly gives `pointee` two meanings: targets for value nodes and contents
for object nodes. After restoring the standard rules, object contents carriers no longer carry
allocation tags, so object queries need an additional hop.

For a value-like node `v`:

```text
node_points_to(v)         = tags(T(V(v)))
node_pointee_points_to(v) = tags(T(C(T(V(v)))))
```

For an object node `o`:

```text
node_points_to(o)         = tags(T(C(I(o))))
node_pointee_points_to(o) = tags(T(C(T(C(I(o))))))
```

The second object expression is needed only where the existing targeted registry query asks what
is reachable through the pointer stored in the object. Field enumeration must apply the same
role-aware hop count to each storage identity.

### 7.2 Node resolution and indirect calls

`pointee_globals` and indirect-call function targets for value/parameter/return nodes remain tags
on `T(V(node))`. Their target traversal is unchanged. Their `external` and `universal` summaries
must include conservative facts on that target identity, not only bits on the carrier root.

An indirect-call operand with no finite function target remains unknown. This proposal does not
turn an empty target into a resolved no-callee result.

### 7.3 `SteensClasses` and Andersen prepartition

Retain the existing snapshot vectors. Add enough role information for synthetic roots, or provide
role-aware accessors over the snapshot, so the prepartition can distinguish:

```text
value target:     T(V(node))
storage contents: C(I(storage))
contents target:  T(C(I(storage)))
```

The Andersen solver itself already separates points-to sets from allocation identities. Its
equations do not change. Its Steens fallback and prepartition adapter do change.

In particular, Andersen currently seeds interesting partitions by evaluating raw
`classes.ext[class_of(node)] || classes.esc[class_of(node)]` for every PAG node. For a value loaded
from external or escaped storage, the corrected representation may place that fact on
`T(V(node))`, not on `V(node)`. The admission seed must call a role-aware
`escape_envelope(node)`/`ext_or_target_ext(node)` accessor or the interesting set silently shrinks.
The two partition-profile reads must use the same semantic accessor so diagnostics describe the
answer actually used for admission. The escaped-function-parameter seed operates on a function
object identity and must use the identity-only accessor.

Make the raw bit vectors private rather than relying on a one-time audit. Then all future direct
class reads fail at compile time unless the caller chooses carrier, target, or identity semantics
explicitly.

### 7.4 Nullability and absence

The corrected Load/Store rules eagerly request `T(V(dst))`, `C(S(address))`, and
`T(C(S(address)))`. As a result, `pointee.is_none()` becomes primarily a lazy-allocation state; it
is not evidence of bottom, unknown, uninitialized memory, or null.

Enumerate and replace its semantic uses:

- `NodeResolution::proven_null` must come from the positive PAG/fixed-root null fact, not from
  `may_be_null && pointee.is_none()`.
- Empty indirect-call and ModRef answers retain their explicit unknown rules.
- The canonical-null solve-end tripwire may continue to require no materialized pointee, because
  that is a structural isolation assertion about the canonical-null class, not a general query
  convention.
- `pointee_of` may continue to test absence solely to decide whether to allocate the alternating
  component.

No other semantic consumer may branch on `pointee.is_none()`. Add one regression where a nullable
carrier retains `may_be_null` alongside an eagerly materialized non-null target, and another where
canonical null reports `proven_null` from its positive source fact while the solve-end isolation
tripwire still rejects target contamination.

### 7.5 Storage and disposition clients

ModRef attribution, `fields_by_root`, stationarity, never-written detection, runtime-writer
accounting, global-address exposure, and violation exposure continue to use storage identity roots.
They must never infer a write to an identity merely because that identity is a target stored in
some other identity's contents.

Every such client must be audited, but it does not require a new result representation.

### 7.6 Field-tag coherence

`field_class` currently copies `root_class.global_objs` only when a synthetic field is created. If
the root class acquires another global tag through a later union, an older field retains the stale
snapshot. Coarse memory merging can mask that omission; narrowing Load/Store makes the missing-tag
FN visible.

Before clients run, require:

```text
for every (root_node, field_class) in fields_by_root:
    global_objs(class(root_node)) ⊆ global_objs(class(field_class))
```

Satisfy it either by propagating global-tag deltas to existing fields during root union or by a
solve-end backfill before result materialization. New fields still copy the current final owner
envelope. Add a regression that creates a field, later joins another global tag into its root
class, and verifies that the field's ModRef candidate envelope contains the late tag. Do not leave
field precision dependent on creation order.

## 8. Empty versus unknown ModRef

Before the 2026-08-26 empty-ModRef change, the API emitted no row when `pointee_globals` was empty
and `external == false`. Indirect calls already rejected the analogous interpretation and used an
unknown callee instead. Restoring the standard Load/Store rules will make empty sets more common,
so ModRef must also distinguish a positive no-global proof from analysis silence.

The implemented rule for indirect pointer accesses is:

```text
empty named-global set + fixed-PAG LocalAlloca certificate => no global row
empty named-global set + every other state                  => Unknown Mod/Ref
```

### 8.1 Why the union-find cannot certify the general case

The pre-change `ClassData` records `global_objs` and `fn_objs`, but it does not record membership
for every alloca, heap object, or other non-global allocation. Therefore:

```text
class.global_objs.is_empty()
```

cannot distinguish these two states:

```text
the address points only to non-global allocations
the address points nowhere because one or more producers were not modeled
```

Adding only a `contains_non_global_object` bit is still insufficient. For example, joining
`&local_alloca` with a producerless value would produce a class that contains a non-global object,
contains no global object, and nevertheless has an incomplete address answer. That was the defect
in the rejected allocation-presence prototype: allocation presence is not producer completeness.

A general class-derived certificate would need both complete non-global membership and an explicit
incompleteness fact propagated through every producer and transfer, including Assign, Load, GEP,
call binding, memory contents, aggregate copies, and external/unsupported boundaries. That is a
closed-producer analysis, not a fact available from the current Steensgaard class representation.

Andersen has the same issue at its result boundary. A nonempty Andersen set containing only known
non-global objects does not prove that an unmodeled producer could not have supplied another
object. The implementation therefore does not derive this certificate from either solver's
points-to set.

### 8.2 Implemented positive certificate

`NodeResolution::finite_non_global_only` is derived solely from the independent fixed-PAG
allocation-root proof:

```text
allocation_storage_roots(address) == StorageRootState::Root(LocalAlloca)
```

That analysis constructs the complete value-producer table before solving and accepts only its
small address-preserving grammar. It proves that every admitted producer resolves to the same
local alloca; unknown producers, loads, mixed roots, and unsupported transfers fail the proof.
The API validates the certified root against the PAG object kind and clears
`finite_non_global_only` if storage-root validation fails. Andersen preserves this fixed-PAG fact;
it does not replace it with a set-membership inference.

This is deliberately narrower than the semantic ideal of "a complete finite set containing only
non-global allocations." In the current implementation, multi-alloca sets, function objects,
external-readonly objects, heap-derived addresses, mixed local/producerless values, and all other
uncertified empty answers fail closed to Ω even when some known targets are non-global. A future
broader certificate must supply an independently audited completeness proof before it may suppress
those rows.

### 8.3 Emission behavior

The rule applies uniformly to indirect loads, stores, both `memcpy` endpoints, and `memset`
destinations:

- a producerless, mixed, or incompletely modeled address emits an Ω Mod/Ref row;
- only a fixed-PAG single-local-alloca address may suppress an otherwise empty global row;
- a canonical-null or invalid address retains its PAG access evidence and emits Ω rather than
  becoming analysis silence;
- the certificate does not change pointer-capable boundary classification or any solver transfer
  equation; and
- high-fanout collapse remains a presentation fallback after empty-versus-unknown classification.

This prevents a missing initializer or transfer from silently becoming:

```text
dropped Mod row -> never-written -> immutable
```

which is the silent relational failure identified by `DISPOSITION.md` and the FN-corruption class
identified by the design.

The corrected `lib-sqlite-O1` evaluation added 515 local Ω rows at both fanout limits, comprising
365 Ref and 150 Mod rows, and removed no existing local row. A broader rejected
allocation-presence certificate added only 421; the additional 94 rows are cases where some
non-global allocation evidence existed but producer completeness did not.

## 9. Required invariants

The implementation is complete only when the following hold:

1. **Role-matched unions:** every union is Carrier/Carrier or Identity/Identity.
2. **Alternation:** every materialized `pointee` link crosses roles.
3. **Metadata confinement:** object/global/function tags occur only on Identity roots.
4. **Load routing:** pointer Load joins `T(V(dst))` with `T(C(S(src)))`, never `V(dst)` with
   `S(src)`.
5. **Store routing:** pointer Store joins `T(C(S(dst)))` with `T(V(src))`, never `S(dst)` with
   `V(src)`.
6. **Exact-Assign routing:** the fixed-address Assign shortcut joins `T(V(dst))` to the certified
   field Identity and passes an Identity/Identity role assertion.
7. **Memcpy routing:** pointer contents and null flow are both contents-to-contents.
8. **Materialization wakeup:** creating a pointee re-enqueues an already processed owner so
   `ext`/`universal`/`esc` closure cannot be lost.
9. **No absence semantics:** `pointee.is_none()` is used only for lazy allocation and the
   canonical-null structural tripwire, never as a general semantic proof.
10. **Canonical-null isolation:** canonical null has positive nullability and no pointee,
   `ext`, `universal`, or `esc` fact.
11. **Role-aware fact access:** raw Steens `ext`, `universal`, and `esc` vectors are private; value
    consumers include the target identity and object consumers choose identity semantics.
12. **Field-tag coherence:** every existing field identity contains the final global-owner envelope
    of its root class before results are materialized.
13. **Access retention:** null, scalar, unsupported, or empty pointer payloads never erase the PAG
   access or its ModRef evidence.
14. **Empty safety:** no indirect call or indirect ModRef access treats analysis silence as a
    finite no-target proof.
15. **Static envelope:** at each complete refined access, Andersen's unfiltered ModRef candidates
    are a subset of the new Steensgaard unfiltered candidates, including Ω state; filtered and FSA
    comparisons use identical predicates on both sides.

Role and alternation assertions should run at solve completion in production builds during the
experimental period. PAG base-node roles require no dynamic inference because validation already
establishes their edge kinds.

## 10. Implementation plan

### Step 0: freeze baselines and add discriminating tests

- Retain the fixed-root empty-ModRef SQLite 64/256 artifacts as the comparison baseline.
- Add the two-table/two-destination fixture in §11 before changing output.
- Add late-pointee-materialization escape tests.
- Record baseline `pangs icall-census`, split into finite, Ω-marked, and empty-operand sites.

### Step 1: enforce roles and restore Load/Store

- Add `ClassRole` for base and synthetic classes.
- Add role-checked `target_of`, `contents_of`, `join_carriers`, and `join_identities` helpers over
  the existing backing vector.
- Change only the pointer Load and Store blocks to the equations in §5.
- Route the exact-address Assign shortcut through the Identity/Identity helper.
- Move Memcpy null-flow endpoints from storage identities to contents carriers and add directed
  Load/Store null flow.
- Preserve `pointee_of`'s materialization-triggered `enqueue(root)`.

An experimental whole-answer switch may isolate the output change, but the implementation is one
solver with two corrected edge blocks, not a second complete fallback solver.

### Step 2: audit the enumerated consumers and enable validation

- Make `materialize_points_to` role-aware with the hop counts in §7.1.
- Privatize the raw Steens fact vectors and convert Andersen admission/profiling and result clients
  to the role-aware accessors in §7.3.
- Replace semantic `pointee.is_none()` tests and make positive null the only source of
  `proven_null` as required by §7.4.
- Backfill or incrementally propagate late root global tags to existing field identities.
- Audit node external/universal summaries, ModRef, stationarity, and disposition consumers listed
  in §7.
- Implement the explicit empty-versus-unknown ModRef rule in §8.
- Enable filter-aligned hard Andersen containment before high-fanout collapse.
- Run the synthetic, differential, corpus, trace, and SQLite gates in §12.

Remove the experimental switch only after the validation and performance criteria pass. Do not
retain an old escape envelope or old solver in the production answer; correctness is established
by the independent oracles below.

## 11. Regression matrix

### 11.1 Discriminating identity/content fixture

A one-table/one-store fixture is vacuous because there is nothing independent to merge. Use two
tables, a merged payload carrier, and two instances of the same destination field shape:

```c
static char a0[] = "a";
static char b0[] = "b";
static char *NamesA[] = { a0 };
static char *NamesB[] = { b0 };

struct Cell { int flags; char *z; };
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

The branch legitimately merges the payload targets `a0` and `b0` in `p`. It must not merge the
container identities `NamesA`, `NamesB`, `CellsA.z`, and `CellsB.z`.

Assert all of the following:

- neither `NamesA` nor `NamesB` occurs in the address candidate set for either destination store;
- `&NamesA` and `&NamesB` do not alias either `CellsA[i].z` or `CellsB[i].z` storage;
- the two source-table allocation tags do not co-occur in either destination's storage candidate
  set;
- Ref rows for `NamesA` and `NamesB` are present;
- Mod rows for `CellsA` and `CellsB` are present;
- the corresponding cross-container Mod/Ref rows are absent; and
- loading the destination field may produce `a0`/`b0` payload targets without producing either
  source-table allocation tag.

These are positive row-presence assertions as well as precision assertions.

### 11.2 Rule and boundary fixtures

- Pointer Store/Load round-trips through global, alloca, exact field, lane field, and unknown-root
  storage.
- A carrier that may target `A` or `B` updates both through a store and a later load retains both.
- `Memcpy` transfers targets and nullability contents-to-contents without joining endpoint
  identities.
- Null stores retain Mod rows and nullable contents without a null pointee.
- A nullable carrier retains `may_be_null` alongside an eagerly materialized target; canonical
  `proven_null` is derived from its positive source fact and never inferred from an absent pointee.
- Null addresses, undef/poison, partial pointer bytes, and unknown memcpy endpoints fail closed.
- Function-pointer globals load their function targets without loading the table allocation tag.
- Actual/formal, return/result, exported, external, vararg, inline-assembly, and ptr/int fixtures
  retain their current Ω and unknown-caller behavior.
- A value whose loaded target identity is external/escaped remains in Andersen's interesting
  partition set even when its carrier root lacks the raw bit.
- The exact-address Assign shortcut passes the Identity/Identity role tripwire.
- A field created before its root receives a late global tag observes that tag in the final ModRef
  candidate envelope.
- An oversize Andersen component receives the complete corrected Steensgaard fallback.
- Object-node `node_points_to` and `node_pointee_points_to` exercise their distinct extra hops.

## 12. Validation and evaluation

### 12.1 Independent static oracle

`new ⊆ old` is useful only as a precision diagnostic. It cannot establish soundness because both an
intended removal and a dropped real effect appear as a subset.

During the experimental period, make `Andersen ⊆ new Steensgaard` a hard assertion at ModRef-row
granularity wherever the Andersen component is complete. The primary comparison uses the
unfiltered allocation envelope:

```text
for each address site and Access kind, before high-fanout collapse:
    U(Andersen named-global candidates) ⊆ U(new Steensgaard named-global candidates)
    Andersen Ω                          => new Steensgaard Ω

where U(result) = result.pointee_globals_unfiltered when that envelope is present,
                  otherwise result.pointee_globals
```

Steensgaard applies the per-global address-exposure filter before exporting
`pointee_globals`, while Andersen overwrites the filtered and unfiltered fields separately.
Comparing Andersen's unfiltered set with Steensgaard's filtered set would produce false failures.
If the filtered export is compared as a second gate, apply the identical
`global_address_exposed` predicate to both unfiltered sets first.

Perform the comparison on local access facts before summary closure, and repeat it on emitted rows
after closure. Report the node label, statement/callsite key, access kind, missing global, component
status, and both provenance envelopes on failure. Do not downgrade failures to diagnostics or
regenerate them into goldens.

The same alignment rule applies to indirect calls. Steensgaard applies FSA during
`consider_indirect_pair`; therefore compare pre-FSA envelopes on both sides or post-FSA targets
after applying the same signature predicate to both. No `Andersen ⊆ Steensgaard` claim is valid
across different filters.

SQLite already demonstrates why this is a useful independent oracle: its complete Andersen
answers have a maximum finite global fanout of 75 in the case where the fallback answer becomes a
high-fanout unknown. The two solvers reach their answers through different representations.

The old-Steens relation may still be recorded:

```text
new Steensgaard targets ⊆ old Steensgaard targets
```

but it is never a soundness oracle.

### 12.2 Dynamic oracle

Extend the existing LLVM callsite instrumentation and `check-traces` workflow to global accesses.
For instrumented loads, stores, and memory intrinsics, record the stable statement identity,
access kind, and the concrete global allocation whose address range contains the runtime address.
The check requires containment:

```text
every observed global access is present in the static finite row or covered by static Ω
```

Equality is neither required nor expected. Stack/heap accesses that do not resolve to a registered
global range are outside this particular check, not evidence of a static no-access proof.

Run the dynamic check on the discriminating fixture and executable corpus programs that exercise
global pointer tables. It complements, rather than replaces, the representation-independent
Andersen assertion.

### 12.3 Indirect-call census

Run `pangs icall-census` before and after as a first-class gate. Report per module:

- finite target sites;
- Ω-marked sites;
- empty operand/target sites; and
- FSA-filtered sites.

Every empty indirect-call answer must remain unknown. Any increase in the empty category must be
explained as newly visible missing producer information, not advertised as resolved dispatch. This
proposal must not be described as fixing the dispatch-table defect unless a separate producer fix
does so.

### 12.4 SQLite acceptance run

Re-run `/home/brk/pangs-corpus/_out_bc/lib-sqlite-O1.bc` in Andersen/library mode at fanout limits
64 and 256. Compare with the implemented fixed-root empty-ModRef baseline in
`ju_out/modref_empty_unknown_fixedroot_sqlite_20260826`:

| limit | collapsed | unknown | local rows | transitive rows | analysis wall | process wall | max RSS |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 64 | 2,743 | 5,533 | 146,536 | 4,776,887 | 33.61 s | 38.21 s | 1,239,040 KiB |
| 256 | 0 | 3,548 | 161,773 | 3,088,300 | 33.56 s | 38.57 s | 1,245,780 KiB |

Measure:

- whether `aDateTimeFuncs` and `azModeName` still co-occur in a finite or collapsed set;
- the target/storage classes at PAG edge 147177;
- distinct fanout-set sizes and hashes;
- collapsed rows made finite, unknown rows, and local/transitive row counts;
- empty-address answers split into positive non-global certificates versus Ω fallback;
- join attempts/successes, maximum class size, worklist activity, and the exact
  `steens_pointee_classes_created` count and delta;
- created pointee classes normalized by pointer Load/Store edges, split by `T(V)`, `C(S)`, and
  `T(C(S))` materialization where practical;
- Andersen admission, steps, fallback counts, and hard-oracle coverage;
- `icall-census` categories;
- stationarity and disposition transitions; and
- analysis/process wall time and peak RSS.

The expected local result is that loading `azModeName[eMode]` propagates string targets while the
`azModeName` identity remains attached to the load address. Success is not merely deletion of one
name: all removed Mod/Ref candidates must be explained by the restored rule, and the independent
oracles must retain every real access.

### 12.5 Wider corpus and performance gates

Run the standard corpus, disposition, manifest, differential, and trace gates. Report named and Ω
call changes, empty icalls, local/transitive ModRef changes, stationarity/disposition transitions,
partition changes, wall time, and RSS per module.

Suggested performance bounds:

- no more than 15% geomean wall-time or RSS regression;
- no unexplained single-module regression above 2×;
- SQLite wall time and RSS no more than 15% above the fixed-root empty-ModRef baseline;
- no more than two additional pointee classes per pointer Load/Store on average, no edge causing
  more than the three structurally possible new links, no more than 50% geomean growth in
  `steens_pointee_classes_created`, and no unexplained single-module growth above 2×; and
- a measurable reduction in high-fanout fallback events/rows or a demonstrated split of the
  motivating pair with neutral downstream row counts.

Hard relational gate:

- no global may transition from `never_written == false` to `never_written == true`, or newly
  become `immutable` as a consequence, without an audit record identifying every removed Mod
  witness and independently proving it spurious. Any unexplained transition fails the experiment;
  it is not accepted by regenerating stationarity or disposition goldens.

This is the silent-corruption direction in the disposition matrix and the direction narrower
storage identities can expose. The gate runs on per-global raw Mod witnesses before disposition
aggregation as well as on the final disposition diff.

If eager class growth exceeds the budget, use the standard Steensgaard pending-list refinement:
retain unresolved load/store component constraints on pending lists and discharge them when the
required alternating link materializes. Do not recover memory by restoring direct
carrier/identity joins.

## 13. Risks and mitigations

### Empty answers exposed by precision

Coarse identity/content unions can hide missing initializers or producers. The explicit ModRef
empty rule, hard Andersen containment, icall empty-as-unknown rule, and dynamic containment check
make those gaps fail closed rather than silently proving immutability.

### Late escape propagation

The easiest silent failure is losing `ext`/`esc` when a pointee is materialized after its owner was
processed. Preserve `pointee_of`'s enqueue side effect and test both alternating late-materialization
orders. Make all result and Andersen-admission reads role-aware; successful propagation to a target
does not help a client that still reads only the value carrier. Do not retain the old merged escape
envelope as a substitute.

### Eager alternating materialization

Each corrected pointer Load/Store can request a value target, storage contents, and contents
target. Sharing should make the average increment smaller, but eager construction can still add
roughly one or two classes per memory edge and can destroy any semantic convention based on an
absent pointee. Track `steens_pointee_classes_created` against the explicit §12.5 budget and derive
null/unknown/bottom only from positive facts. If the budget fails, use Steensgaard pending lists to
delay component construction until a constraint can discharge; absence itself never becomes an
answer.

### Role mistakes in synthetic fields

Field classes are storage identities. Whole-object and overlapping field unions remain
Identity/Identity; their contents are joined recursively. Solve-end alternation assertions and the
field regression matrix catch accidental field/content unions. The same solve-end pass must
backfill or reject stale global-owner tags on fields created before a late root union.

### Null-flow mismatch

Nullability belongs to carriers. Load, Store, and Memcpy null-flow endpoints must use contents
carriers where appropriate. Canonical-null isolation and null-store Mod-row tests remain mandatory.

### Mischaracterizing dispatch improvements

Narrower mega-classes may reduce overmerged function targets, but they do not repair producerless
dispatch-table operands. The before/after `icall-census` split prevents the two mechanisms from
being conflated.

### Golden and manifest churn

Improved fallback precision can change call edges, ModRef exports, `pointee_globals`, stationarity,
audit relevance, and dispositions. Regenerate artifacts only after the static and dynamic
containment gates pass and every disposition improvement has been audited.

## 14. Rejection criteria

Reject or redesign the proposal if any of the following remains after reasonable implementation
debugging:

- a soundness counterexample requires joining storage identity directly with stored contents;
- the corrected Steensgaard answer is not a conservative envelope for complete Andersen results;
- complete initialization cannot populate contents without unavailable type metadata;
- escape correctness cannot be maintained through alternating `pointee` closure and lazy-owner
  re-enqueue;
- empty ModRef answers cannot be distinguished from positive non-global proofs without an
  unacceptable conservative fallback;
- any global newly acquires `never_written` or an immutable disposition without the audited
  witness required by §12.5;
- SQLite retains the motivating merge with no meaningful fanout reduction while paying material
  runtime or memory cost; or
- standard-corpus performance exceeds the gates in §12.5 without offsetting, audited precision.

If rejected, retain the diagnostic lesson: larger Andersen budgets and null handling do not repair
this non-null memory-copy channel. The next alternative should target unknown-root field summaries
or another bounded fallback representation, not a SQLite-specific exception.
