# Steensgaard one-hop GEP: a field address must not survive uncertified pointer arithmetic

## 0. Summary

The base tier mixes two different address vocabularies on the same pointer chain and loses a
real write when it does.

Field-sensitive classes are used when the PAG independently certifies an allocation-relative
address.  Field-insensitive unification is used when it does not.  Each is sound on its own.
They are not sound together: a pointer whose target class is *one specific field* of an
allocation can be handed to an **uncertified** GEP, and the current rule gives the result the
**same** field class instead of the field the offset actually selects.  The derived pointer then
designates the wrong cell, and a store through it reaches nothing.

The result is an unsound answer, not merely an imprecise one.  A global that is written at run
time is reported as never written, and the disposition cascade selects `immutable` for it.

The fix is local, to one match arm.  When an uncertified GEP has a non-zero or unknown delta and
its base's target is a field class of a known allocation, resolve the result against that same
allocation instead of reusing the base's field: shift the field exactly when the base names one
unambiguous region, and fall back to that allocation's unknown-offset summary when it does not.

This document is a proposal.  It is not implemented.

## 1. The defect

### 1.1 A fixture that shows it

`fixtures/synthetic/disposition/republished_aggregate_write.ll`, already in the tree as the
regression cover for the downstream symptom:

```llvm
@flag  = internal global i32 0
@table = internal global i32** null

define void @publish(i32** %o) {
  store i32** %o, i32*** @table          ; the aggregate's base goes into a global
  ret void }

define void @write_through() {
  %t = load i32**, i32*** @table         ; read the base back
  %e = getelementptr i32*, i32** %t, i32 1   ; base + 1 lane
  %p = load i32*, i32** %e
  store i32 1, i32* %p                   ; a real write to @flag
  ret void }

define i32 @main() {
  %opts = alloca [3 x i32*]
  %slot = getelementptr [3 x i32*], [3 x i32*]* %opts, i64 0, i64 1
  store i32* @flag, i32** %slot          ; &flag goes to lane 1
  %base = getelementptr [3 x i32*], [3 x i32*]* %opts, i64 0, i64 0
  call void @publish(i32** %base)
  call void @write_through()
  %v = load i32, i32* @flag
  ret i32 %v }
```

The store in `write_through` writes `@flag`.  The base tier does not see it.

Only the offset matters.  The same fixture with the pointer at lane 0 is handled correctly, and
neither bitcasts nor dynamic indices change the outcome.  Measured on the two variants:

```text
lane 0 : the final store resolves to pointee root 28 = flag's object root -> written
lane 1 : the final store resolves to pointee root 24, flag's root is 28   -> not written
```

### 1.2 Where the two vocabularies meet

In `crates/pangs-solve/src/lib.rs`, `EdgeKind::Gep` has two arms:

```rust
if let Some(address) = self.exact_addresses[edge.dst.0 as usize] {
    // certified: the result designates one allocation-relative field
    let dst_p = self.pointee_of(dst);
    let storage = self.field_class(address.root, FieldRegion::address(address.location));
    self.join(dst_p, storage, PROV_DIRECT_ADDRESS);
} else {
    // uncertified: the result designates whatever the base designates
    let src = self.class_of(edge.src);
    self.unify_pointees(dst, src, PROV_DIRECT_ADDRESS);
    self.add_content_edge(src, dst);
}
```

`exact_allocation_addresses` is deliberately weak, and says so in its own comment: address-of
seeds a root, GEP preserves it, a matching Assign join keeps it, and **a load stops the proof**.
That weakness is fine by itself.  The problem is what the `else` arm does with a base whose
target class came from the *certified* arm.

### 1.3 The trace

Follow the fixture through the solver.

In `main`:

- `%slot` is a certified GEP.  Its target becomes `field_class(%opts, address(Exact(8)))` —
  call it **F8**.
- `store i32* @flag, i32** %slot` resolves its destination through the certificate to
  `field_class(%opts, access(Exact(8), 8))`, which overlaps F8 and joins with it.  The content of
  that cell becomes `@flag`'s object class.  This is all correct: lane 1 of `%opts` holds a
  pointer to `@flag`.
- `%base` is a certified GEP at offset 0.  Its target becomes
  `field_class(%opts, address(Exact(0)))` — call it **F0**.  F0 and F8 do not overlap, so they
  stay separate.  Also correct.
- `%o` inherits `%base`'s certificate across the call, and `store i32** %o, i32*** @table` puts
  F0 in `@table`'s content.

In `write_through`:

- `%t = load ... @table` gives `%t` the target F0.  Still correct: `%t` points at lane 0.
- `%e = getelementptr %t, 1`.  `%t`'s producer is a load, so `%t` has no certificate, so neither
  does `%e`.  The `else` arm fires: `unify_pointees(%e, %t)` gives `%e` the target **F0**.

  **This is the defect.**  `%e` is `%t + 8` and must designate lane 1.  It is instead pinned to
  lane 0.
- `%p = load ... %e` therefore reads F0's content.  Nothing was ever stored at lane 0, so `%p`
  gets a fresh empty target class.
- `store i32 1, i32* %p` writes that fresh class.  `@flag`'s object class is never touched, and
  `runtime_written` for `@flag` stays false.

### 1.4 Why it is unsound rather than imprecise

`unify_pointees(dst, src)` on a GEP is the textbook Steensgaard rule, and it is sound **when the
base's target is a summary of the whole allocation**.  Under that reading, "the same cell" means
"somewhere in the same object", and adding an offset keeps you inside it.

The certified arm broke that reading.  It made target classes mean "exactly this byte region of
this allocation".  Under *that* reading, keeping the same class after adding an offset is a claim
that `base + 8` and `base` are the same cell, which is false.  The rule did not fail closed to a
wider class; it stayed on a narrower one that excludes the right answer.

So the two arms are individually sound and jointly unsound.  Nothing detects the transition
between them, because there is no record on a class of which vocabulary produced it.

## 2. Why this is worth fixing

### 2.1 It produces a wrong answer, not a conservative one

In `exe-lemon-O0` the affected global is `showPrecedenceConflict_xjtr_0`.  Lemon registers it in
its command-line option table:

```c
{OPT_FLAG, "p", (char*)&showPrecedenceConflict_xjtr_0, "Show conflicts resolved by precedence rules"},
```

`OptInit` publishes the table through the global `op_xjtr_0`, and `handleflags` writes through it:

```c
}else if( op_xjtr_0[j].type==OPT_FLAG ){
  *((int*)op_xjtr_0[j].arg) = v;
```

This is the fixture's shape exactly.  `lemon -p` writes this global.  The base tier reports it as
never written, and `--stage steens --dispose` selects `immutable` for it.  Converting it to a
Rust immutable static would be wrong.

### 2.2 The surface is known and small

The reconciliation landed on 2026-09-06 makes the *Andersen* tier fail closed on the pointer
ModRef row, so production answers are already safe.  It cannot help the base tier, because the
base tier produces no row at all to fail closed on.  The `written_globals` rule added to
`pangs differential` at the same time reports the residue directly.  Over the 53-module sample:

| module | globals the base tier loses |
|---|---|
| `exe-tree-O0` | 15 |
| `exe-OMP__tree-O0` | 15 |
| `exe-lemon-O0` | 1 |
| `exe-lemon-nostatic-O0` | 1 |

32 globals in 4 modules, and these are the **only** differential violations anywhere in the
sample.  Every other cross-tier check passes on all 53 modules.  So this is a narrow, named
defect with a ready acceptance test, not an open-ended search.

### 2.3 It also costs precision downstream

Because the base tier misses the write, the Andersen tier has to fail closed on an aliased ModRef
row instead of a certified one.  On the corpus that moved 35 globals off `immutable` — 30 to
`mutex`, 4 to `localize`, and one vim global to `unhandled`.  Some of those are true writes and
should have moved.  Others are probably false alias rows that a correct base tier would let us
argue about on better evidence.  Fixing the base tier is what makes that distinction available.

## 3. Proposed fix

### 3.1 The idea

A class produced by the certified arm means "this byte region of this allocation".  Record that
meaning on the class, and honour it in the uncertified arm.

When an uncertified GEP's base has such a target, do not reuse it.  Resolve the result against
the **same allocation** at the **shifted** region, and widen only when the shift cannot be
determined.

### 3.2 Record the meaning on the class

`field_class(root, region)` is the only place these classes are made.  Give `ClassData` one new
field:

```rust
/// Allocation-relative regions this class stands for, as `(root, region)` pairs.  Empty for
/// ordinary carrier and summary classes.  Unions on join, like the other side tables.
field_regions: BTreeSet<(NodeId, FieldRegion)>,
```

`field_class` inserts its own pair.  `join` unions the sets, exactly as it already does for
`global_objs` and `escape_sources`.  A class with an empty set is an ordinary summary and keeps
today's behaviour everywhere.

This is bookkeeping the solver almost has already: `field_classes` maps `(root, region)` to a
class, and `fields_by_root` maps a root to its classes.  What is missing is the reverse direction
from a class back to its regions, which is what the GEP arm needs.

### 3.3 Change the uncertified GEP arm

```rust
} else {
    let src = self.class_of(edge.src);
    let src_p = self.pointee_of(src);
    let delta = FieldLocation::from_gep(byte_off, lane);
    let src_p_root = self.find(src_p);
    let regions = self.classes[src_p_root].field_regions.clone();

    if regions.is_empty() || delta == FieldLocation::Exact(0) {
        // Ordinary summary target, or no movement: today's rule is correct.
        self.unify_pointees(dst, src, PROV_DIRECT_ADDRESS);
    } else {
        // The base designates specific fields.  The result designates the shifted ones.
        let dst_p = self.pointee_of(dst);
        for (root, region) in regions {
            let shifted = match region.location.add(delta) {
                FieldLocation::Unknown => FieldRegion::access(FieldLocation::Unknown, None),
                location => FieldRegion::address(location),
            };
            let target = self.field_class(root, shifted);
            self.join(dst_p, target, PROV_DIRECT_ADDRESS);
        }
    }
    self.add_content_edge(src, dst);
}
```

Three cases fall out of this, and each is the right answer:

1. **Base is an ordinary summary.**  Unchanged.  This is the overwhelming majority of GEPs.
2. **Base names one region and the delta is exact.**  `Exact(L).add(Exact(d))` is `Exact(L + d)`,
   so the result designates exactly the right field.  **No precision is lost at all.**  This is
   the fixture, and Lemon's option table: F0 plus 8 bytes gives F8, `%p` reads the pointer to
   `@flag`, and the write lands.
3. **Base names several regions, or the delta is a lane or unknown.**  `FieldLocation::add`
   already handles lane arithmetic and degrades to `Unknown`.  An `Unknown` region overlaps every
   region of its allocation in `FieldRegion::may_overlap`, so `field_class` joins it to all of
   them.  The result is "somewhere in that allocation" — a widening, which is what soundness
   requires when the offset cannot be pinned down.

Case 3's widening primitive is not new.  `DESIGN_lite.md` §C' already specifies it: *"A genuinely
unstructured dynamic byte offset gets one summary joined only to the materialized fields of that
same allocation."*  The fix extends that existing rule to the case where the *base*, rather than
the offset, is what stops the proof.

### 3.4 Keep the content edge

`add_content_edge(src, dst)` stays in both branches.  It carries external and null facts along the
value transfer and is independent of which cell the result designates.  Removing it would drop
escape facts.

### 3.5 Cost

The extra work is one set lookup per GEP edge, plus, in the field case, one `field_class` call per
region the base names.  `field_class` is memoised.  Case 1 is unchanged and is the common path.

The precision effect should be neutral-to-positive:

- Case 2 **gains** precision.  Today the result is pinned to the wrong field; after the change it
  names the right one.
- Case 3 **loses** precision against today, but today's answer in that case is unsound, so the
  comparison is not meaningful.  Against a correct baseline it is the minimum widening.

The one real risk is that case 3 fires more often than expected and collapses whole allocations
into one class, enlarging partitions.  §6 says how to measure that.

## 4. What does not change

- Certified GEPs.  The certified arm is already root-relative and correct.
- `exact_allocation_addresses`.  It stays deliberately weak, and a load still stops the proof.
  This proposal does **not** try to carry address certificates through memory; see §5.
- The store and load equations.  `storage_class_for_address` already prefers a certificate and
  otherwise takes the base's target.  Once the target is right, both are right.
- Andersen.  It builds its own constraint graph and already resolves the fixture correctly.
- The `written` reconciliation added on 2026-09-06.  It stays.  It is a fail-closed rule about
  ModRef rows and remains correct whether or not the base tier improves; the tripwire
  `modref_write_without_written_fact` stays as its regression guard.

## 5. Alternatives considered

**Carry the address certificate through loads.**  Let `exact_allocation_addresses` propagate
through a load when the loaded cell has a single certified content.  This would also fix the
fixture, and would fix it more precisely.  It is rejected here: it turns an intentionally weak
syntactic proof into a fixpoint over memory, which is what the real solver is for, and its
soundness argument is much harder — a cell with one *observed* certified content may still hold
something else.  §C' calls this proof "deliberately weaker than points-to analysis" on purpose.

**Never use field classes as pointer targets.**  Make the certified arm join to the allocation
summary instead of a field.  This is sound and trivially removes the mismatch, but it throws away
the field sensitivity the base tier was given on purpose, and would widen every certified GEP in
the corpus.

**Widen at offset 0 too.**  Simpler to state, but `gep +0` is very common — it is how bitcasts and
first-member access are lowered — and unifying there is exactly correct.  Widening it would cost
real precision for no soundness gain.

**Detect the mismatch and fail closed on the whole function.**  Sound, and much blunter than
necessary.  The shifted-field answer is available and cheap.

## 6. Tests and acceptance

### 6.1 Unit fixtures

Add to the existing solver suite, at both Steensgaard and Andersen stages:

- **The shift is exact.**  `republished_aggregate_write.ll` at `--stage steens`: `@flag` is
  written.  Today it is not.  Extend the existing
  `a_pointer_modref_write_is_visible_in_the_written_fact` test back to `Stage::Steens`, which is
  currently excluded with a comment pointing at this document.
- **The shift is exact and lands on an empty field.**  Store `&g` at lane 1, read through
  `base + 2`: no write to `g`.  This checks that the fix does not simply widen everything.
- **The shift is a lane.**  An array of structs indexed dynamically, with a known member offset:
  the result must alias the matching lane and not the whole allocation.
- **The shift is unknown.**  An unstructured dynamic byte offset: the result aliases every
  materialized field of that allocation, and only that allocation.
- **The base names several regions.**  Two certified GEPs joined into one class, then an
  uncertified shift: widen to the allocation summary.
- **Offset 0 stays exact.**  `gep +0` off a field target keeps the field.
- **Ordinary summary base is untouched.**  A GEP off a pointer with no field target behaves
  exactly as before.
- **Negative offsets.**  `base - 8` from lane 1 reaches lane 0.
- **Cross-allocation join.**  A class joined across two roots widens within each root and does not
  connect them.

### 6.2 Acceptance

```text
pangs differential over the 53-module sample: zero written_globals violations
exe-lemon-O0 --stage steens: showPrecedenceConflict_xjtr_0 is written, not immutable
modref_write_without_written_fact: still 0 on every module
cargo test --workspace --all-targets: green
```

The `written_globals` count going to zero is the primary acceptance signal.  It is already
measured, currently 32 in 4 modules, and it should go to 0 without any other differential check
starting to fire.

### 6.3 What to measure for regressions

Because case 3 widens, watch the base tier's own size and the answers that depend on it:

- `steens_pointee_classes_created`, `steens_join_successes`, `steens_content_edges`;
- `partition_count`, `partition_max_size`, `oversize_fallbacks`;
- `pointer_modref_rows_unique` and the named Mod/Ref split;
- the full disposition histogram, before and after, across all 59 modules;
- `analysis_wall_us` and peak RSS on the four heavy modules.

The expected shape is: `written_globals` violations to zero, a small rise in Steensgaard join
counts, and disposition movement confined to globals the differential already names.  A large
rise in `partition_max_size` or in `oversize_fallbacks` would mean case 3 is firing far more than
expected, and would justify keeping a per-root cap on how many distinct regions trigger the
widening.

### 6.4 Stopping rule

Stop when `written_globals` is zero across the corpus and no other differential check fires.  Do
**not** extend the work into carrying certificates through memory (§5) to chase the remaining
imprecision; that is a separate decision with its own payoff argument.

## 7. Risks

- **The widening is larger than expected.**  Mitigated by §6.3.  If it bites, the fallback is to
  cap the region count per root and widen only above the cap.
- **`field_regions` grows on heavily joined classes.**  The set is bounded by the number of
  distinct `(root, region)` pairs, which is already bounded by `field_classes`.  Memory should be
  flat, but it is worth watching on vim and openssl, which dominate the corpus footprint.
- **The carrier/location invariant.**  Debug builds assert that a class holds carriers or
  locations, never both.  `field_regions` belongs only on location classes; the new field should
  be asserted empty on any class with `has_carrier`.
- **Order sensitivity.**  `field_class` joins overlapping regions when a region is first
  materialized.  Adding new `field_class` calls from the GEP arm changes when regions are
  materialized, which can change join order.  The result should be order-independent because
  joins are monotone, but the existing differential and golden tests are the check for that.
