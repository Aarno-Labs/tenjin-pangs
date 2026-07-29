The right approach is to add an explicit immutable-storage-closure certificate rather than weakening Ω or declaring compound literals constant globally.

For chibicc, the intended certificate would prove:

```text
owner:   type.c::ty_ushort
storage: .compoundliteral.7
result:  owner pointer and backing object receive no runtime writes
```

This should eliminate all thirteen `ty_*` globals, taking experimental chibicc from 15 unhandled globals to the expected 2: `scope` and `tmpfiles`.

### 1. Recognize the initializer shape

Start with named pointer globals whose initializer resolves exactly to a private static allocation:

```c
Type *ty_ushort = &(Type){TY_SHORT, 2, 2, true};
```

The PIR-level conditions would be:

- the owner is a named pointer global;
- its initializer has one exact allocation root, optionally plus a constant interior offset;
- that allocation has private/internal linkage or is an unnamed compiler-generated object;
- the allocation has static lifetime;
- the initializer is complete and contains no forged or external pointer alternative.

The existing `storage_members` relationship already associates `ty_ushort` with `.compoundliteral.7`; this supplies most of the ownership information.

An interior pointer should be accepted only when the entire materialized object can be associated with the owner, or when the certificate explicitly covers the containing allocation and offset.

### 2. Define a physical storage closure

The closure should contain storage that must move or change disposition together:

```text
closure(ty_ushort) = {
    global cell ty_ushort,
    backing allocation .compoundliteral.7
}
```

It should not blindly follow every pointer stored inside the `Type` object. For example, if a field pointed to some shared mutable object, that target would not automatically become part of `ty_ushort`’s physical closure.

Closure edges should be limited to ownership relationships such as:

- named global → its private anonymous initializer;
- anonymous aggregate → nested anonymous initializer storage;
- compiler-generated backing object → subordinate backing arrays where ownership is unique.

Shared named objects remain separate disposition candidates. A closure may depend on their immutability, but does not own them.

### 3. Separate real writes from escape-derived writes

The current `written` fact conflates two kinds of evidence:

```text
definite runtime write
possible write because the address reached Ω
```

For `ty_ushort`, the witness is the second kind:

```text
derived:external-pointee
```

That is useful conservatism for general alias analysis, but it is too coarse to decide immutability.

Internally, write evidence should be classified:

```rust
enum WriteEvidence {
    Initializer,
    DefiniteStore,
    MemcpyDestination,
    MemsetDestination,
    ModeledExternalWrite,
    UnknownStoreMayAlias,
    EscapeMayWrite,
}
```

The ordinary `written` and Ω facts can remain unchanged. The new certificate separately asks whether every non-initializer write possibility has been discharged.

This avoids weakening results for other clients.

### 4. Use write completeness, not access completeness

`ty_ushort` currently has an incomplete access set because of the unresolved read:

```c
*rel->label
```

That read causes module-wide access, but it cannot mutate `ty_ushort`. An immutable certificate only needs a complete account of possible writes.

The audit should therefore distinguish:

```text
unknown read  -> irrelevant to immutability
unknown write -> blocks immutability
unknown mod/ref call:
    Ref only  -> acceptable
    Mod       -> blocks
    ModRef    -> blocks
```

This is an important structural improvement. Requiring the entire accessor set to be finite would leave the `ty_*` family dependent on the unrelated `Relocation.label` precision problem.

The write audit must cover:

- direct stores;
- stores through aliases;
- `memcpy` and `memmove` destinations;
- `memset` destinations;
- modeled external-call modification;
- vararg outputs such as `%n`;
- inline assembly memory effects;
- unknown stores whose destination may alias the closure.

Loads and readonly external uses do not block the certificate.

### 5. Audit the owner and backing storage separately

The certificate must prove both:

```text
ty_ushort is never reassigned
.compoundliteral.7 is never modified after initialization
```

These are different questions. For example:

```c
Type *p = &(Type){...};
p = another_type;       // owner write
```

and:

```c
Type *p = &(Type){...};
p->size = 8;            // backing-object write
```

must both reject immutability.

Stores should be checked against every byte range in the physical closure. Unknown-width aggregate writes fail closed.

### 6. Handle exported linkage by build mode

External linkage alone should not automatically mean “external code mutates the object” in a closed executable analysis. But accepting it needs an explicit policy.

A reasonable initial rule is:

- **Application/executable mode:** an externally linked owner is acceptable when the linked bitcode is treated as the complete application and no concrete external escape exposes the pointer.
- **Library mode:** an exported writable pointer global remains open unless an explicit ABI contract says external clients are readonly.
- **Explicit export lists:** treat listed symbols like library exports even in another build mode.
- **Interposition/dynamic lookup mode:** reject the certificate if the build claims to preserve ELF interposition, `dlsym` access, or an otherwise open symbol namespace.

For chibicc, merely having external linkage in the source should not count as a concrete runtime escape under the whole-executable assumption. Actual flows remain relevant:

```c
external_function(ty_ushort);  // requires readonly/nocapture modeling
return ty_ushort;              // open if caller set is open
opaque_global = ty_ushort;     // open storage exposure
```

This policy should be visible in the certificate, for example:

```json
{
  "scope": "linked-executable",
  "export_policy": "closed-application-symbol"
}
```

### 7. Perform a forward exposure audit

The backing object’s address begins in the owner initializer. Audit its consumers similarly to the closed-consumer function-address certificate:

Safe consumers:

- internal loads of the owner;
- field reads;
- comparisons;
- propagation among modeled internal values;
- calls with proven readonly arguments;
- returning through a closed internal call graph.

Open consumers:

- external arguments without readonly summaries;
- stores into exported or opaque memory;
- returns from externally callable functions;
- pointer-to-integer operations if address preservation matters to transformation;
- unsupported pointer arithmetic;
- admission boundaries that omit a consumer.

There should be one special accepted terminal:

```text
private backing object address stored in its certified application-mode owner
```

That is the initializer pattern being recognized. Other exported storage remains open.

### 8. Make the certificate independent of Ω

The result should not remove the object’s Ω bit from the base points-to solution. Instead, disposition gets a stronger client-specific fact:

```rust
ImmutableStorageClosure {
    owner: GlobalId,
    members: Vec<StorageId>,
    initialization_complete: bool,
    runtime_write_complete: bool,
    exposure_closed: bool,
    scope: CertificateScope,
}
```

Then the immutable cascade guard becomes conceptually:

```text
ordinary path:
    !written && !omega_escaped_address

or certified path:
    immutable_storage_closure.complete
```

This lets alias analysis continue saying “the externally visible pointer may escape” while disposition says “within the supported application model, no consumer can mutate this storage.”

### 9. Fail closed on ambiguous ownership

The first implementation should reject:

- multiple named writable owners of the same anonymous object;
- owner initialization with multiple possible pointees;
- dynamic or unknown initializer offsets;
- backing objects also reachable through an unmodelled exported path;
- runtime owner reassignment;
- any store that may overlap the backing object;
- unknown external calls receiving the pointer;
- incomplete initialization;
- forged pointer flow into the closure.

Multiple readonly aliases could be admitted later, but unique ownership is a useful initial restriction and matches the chibicc pattern.

### 10. Suggested implementation sequence

1. **Candidate discovery**

   Identify named globals with exact private anonymous initializer roots using the existing `storage_members` inventory.

2. **Write-evidence separation**

   Preserve definite store/memory-operation evidence separately from escape-derived possible writes.

3. **Closure-local write audit**

   Check owner and backing allocations for runtime writes. Do not require read-access completeness.

4. **Application-mode export rule**

   Stop treating linkage exposure by itself as a write in closed executable mode. Preserve actual external flows as blockers.

5. **Disposition integration**

   Add the certificate as an alternative immutable guard and emit its scope and witnesses in the manifest.

6. **Nested closures and dependency SCCs**

   Generalize from one owner/one object to nested anonymous initializers after the basic pattern is validated.

### 11. Regression tests

Positive cases:

```c
struct S *p = &(struct S){1, 2};
int read(void) { return p->x; }
```

```c
struct Outer *p = &(struct Outer){
    .nested = &(struct Inner){1}
};
```

Negative cases:

```c
p = q;                 // owner reassigned
p->x = 3;              // backing storage modified
opaque(p);             // unmodelled external exposure
saved = p;             // exported opaque storage
memset(p, 0, sizeof *p);
```

Policy tests should show:

- accepted in closed executable mode;
- rejected in library mode;
- rejected when explicitly exported;
- accepted through a modeled readonly external call;
- rejected through a possibly writing call;
- unaffected by unrelated unknown reads such as `*rel->label`.

The most important design choice is to make this a disposition-specific proof of write immutability, not a global assertion that the backing object never escapes. That gives the desired result without making the underlying alias analysis less conservative.
  ### What I agree with

  My earlier discussion of *rel->label was misplaced. That is a read in codegen; the relevant incomplete-write witnesses are the stores
  through label in eval2, eval_rval, and new_str_token. Full admission resolves those stores to local candidate sets, so they should not
  influence the immutable-closure design.

  I also agree that:

  - the regression suite should include the full-admission chibicc configuration;
  - changing the repository-wide default budget needs the calibration work described in notes/andersen_admission_calibration_2026-07-
    27.md;

  - an owner-cell refinement in allocation_isolation is preferable to broad Andersen reconstruction of every GlobalResolution;
  - the owner/member distinction must be consumed before fold_storage_member combines their facts (crates/pangs-clients/src/lib.rs:635);
  - ¬omega_escaped_address must remain part of immutable’s soundness contract;
  - a raw old facts || new certificate cascade guard would be the wrong shape.

  If immutable becomes backed by a dedicated pass, it should indeed be:

  immutable iff immutable_eligibility certificate present

  with the existing never-written ∧ ¬omega-escaped-address requirements internal to that pass.

  ### The remaining qualification

  At full admission, the four module-wide writes disappear, but ty_ushort still has:

  written: true
  witness: compute_vla_size at parse.c:827

  The corresponding refined ModRef row says:

  compute_vla_size modifies .compoundliteral.7
  via aliased

  The source is:

  if (ty->kind != TY_VLA)
      return node;

  ty->vla_size = new_lvar("", ty_ulong);

  at /home/brk/pangs-corpus/chibicc/parse.c:813.

  ty_ushort can legitimately reach compute_vla_size as the base type of a VLA, but its initializer fixes kind = TY_SHORT, so that
  invocation returns before the store. Flow-insensitive Andersen sees the Type * receiver reach the function and the field store, but
  cannot use the discriminator guard to exclude the builtin object.

  Therefore, the statement that “the only remaining issue is one pointee-derived escape bit” is not quite borne out by the supplied full-
  budget manifest. There are two residual raw facts:

  omega_escaped_address:
      derived:external-pointee

  written:
      compute_vla_size:827

  The second is no longer module-wide, but it is still a false positive.

  ### Why the owner-cell change may not be sufficient alone

  The proposed owner-cell terminal addresses a real limitation at crates/pangs-solve/src/lib.rs:684: any store of a derived allocation
  address currently invalidates both address and write isolation. The exact initializer store:

  &.compoundliteral.7 -> ty_ushort

  should be recognized as publication into the literal’s unique owner, not arbitrary memory escape.

  That should eliminate the pointee-derived escape. But the current GlobalResolution.never_written is computed independently from
  Steensgaard stored_classes:

  let never_written =
      !escape_external
      && storage_roots.iter().all(|root| !stored_classes.contains(root));

  at crates/pangs-solve/src/lib.rs:1745.

  Moreover, allocation_isolation.write currently only clears runtime_written; it does not recompute never_written (crates/pangs-solve/src/
  lib.rs:1762). So accepting the owner initializer store does not obviously remove the compute_vla_size contribution to written.

  It is worth prototyping the owner terminal first because it is small and may interact with fact folding more favorably than this static
  inspection suggests. But “all thirteen become immutable” should be an experimental question, not an assumption.

  ### Revised implementation sequence

  1. Add the full-admission regression row.

     I would preserve three distinguishable measurements:

     chibicc-vanilla             default knobs, 200k
     chibicc-experimental        experimental knobs, 200k
     chibicc-full-admission      experimental knobs, 200m

     That avoids conflating receiver/consumer features with admission budget. If only two rows are desired, label the experimental row
     clearly as full-admission.

  2. Implement the owner-cell initializer terminal.

     Accept a store of a private synthetic object’s address when:
      - it is part of global initialization;
      - the destination is the unique named owner;
      - the owner/member relation was established transitively and uniquely;
      - no second owner exists;
      - all other escape sources remain audited normally.

     This should refine the literal’s address_escape/external-pointee result at the fact source.

  3. Rerun at full admission.

     Check separately:

     omega_escaped_address
     written
     access_set_complete
     final disposition

     Do not infer success merely from the escape bit disappearing.

  4. If compute_vla_size remains, add a narrow guarded-store proof.

     The minimal proof would recognize:

     object discriminator is invariant TY_SHORT
     store is dominated by requirement discriminator == TY_VLA
     therefore store cannot target this allocation

     This is a small instance of the tagged-object refinement we deliberately postponed. It need not implement the full callback-bearing
     tagged-union design: equality against an invariant constant discriminator is enough for this family.

  5. Settle one immutable fact source.

     Two valid shapes remain:
      - refine never_written and omega_escaped_address themselves, preserving immutable’s existing raw guard; or
      - introduce immutable_eligibility and make immutable certificate-backed.

     The first is smaller if owner isolation plus guarded-store exclusion are reusable objective facts. The second is cleaner if the proof
     depends on closure materialization and application-specific transformation requirements.

  I would currently favor refining the two objective facts at their source. It preserves DISPOSITION.md:55 unchanged and avoids adding a
  strategy-specific pass unless the marker/materialization proof genuinely needs more information.

  So my bottom line is: use full admission as the experimental baseline, prototype the owner-cell terminal first, but expect a second
  small discriminator-sensitive store refinement may be necessary. Broader Andersen-to-GlobalResolution feedback remains unnecessary for
  now.

