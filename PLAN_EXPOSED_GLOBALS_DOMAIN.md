# ExposedGlobals unknown-pointer domain prototype

Date: 2026-07-17

Status: evaluated; implementation discarded because the measured impact was not
compelling.  The prototype was commit `38cf9f68` before abandonment.

## 1. Problem

PANGS currently represents every pointer with a non-local/unknown origin using one
Ω bit.  Mod/ref emission therefore treats an Ω access with no named global pointees
as module-wide.  This conflates three materially different cases:

1. storage that cannot be a mutable global in this module (for example the process's
   `argv` storage, caller stack, or foreign heap);
2. storage returned or supplied by unanalyzed code, which may be foreign storage or a
   module global that the unanalyzed code can already reach; and
3. a truly arbitrary address, such as an integer-derived pointer.

The first two cases need not invalidate access completeness for every private,
unescaped mutable global.

## 2. Domain

Carry this monotone domain beside the existing points-to facts:

```text
None < ForeignOnly < ExposedGlobals < Universal
```

- `None`: no unknown external-memory target.
- `ForeignOnly`: may designate heap, stack, process, or immutable external storage,
  but no mutable global defined by the analyzed module.
- `ExposedGlobals`: may additionally designate globals in the run's exposure
  surface: `is_exported_global || address_escaped`.
- `Universal`: may designate any module global.

Named global pointees coexist with the domain.  The candidate set for one access is
the union of its named globals and the globals admitted by its domain.

The domain joins by maximum.  Assign, load, store, GEP, memcpy, Steensgaard union,
and Andersen Ω-source propagation must preserve that join.  Any unclassified Ω
source is `Universal`, never `ForeignOnly`.

## 3. Initial source classification

This prototype uses deliberately small, reviewable classifications:

| source | domain | reason |
|---|---|---|
| executable `main` parameters after `argc` | `ForeignOnly` | ABI-owned argument/environment storage cannot name a module-defined mutable global |
| result of an unanalyzed external call | `ExposedGlobals` | external code can return foreign storage, an exported global, or a global whose address previously escaped |
| parameter of an address-escaped function | `ExposedGlobals` | an unknown caller has the same exposure surface |
| unknown pointer value written by external/vararg code | `ExposedGlobals` | the external producer has the same exposure surface |
| `inttoptr` or a missing/unclassified Ω provenance | `Universal` | integer addresses defeat name/escape reasoning |

Precise allocator and readonly-libc models remain ordinary named/object points-to
facts and do not need an unknown domain.  `realloc` and other functions without an
explicit summary are not newly classified as fresh heap.

## 4. Soundness boundary

`ExposedGlobals` assumes the existing whole-linked-module boundary used by PANGS:
unanalyzed code cannot manufacture the address of a private, unescaped global except
through integer-address operations, which are `Universal`.  The candidate exposure
set uses the analysis-level exported bit, including build mode and exports config,
not raw LLVM external linkage.

The address-escaped half of the set is computed by the escape analysis before
mod/ref rows are emitted.  The solver must not be seeded with all exposed globals;
the compact domain is expanded only at API emission.  This avoids increasing
points-to partition density.

`ForeignOnly` permits a finite empty mutable-global candidate set.  This is an
explicit proof, not an interpretation of an empty legacy `pointee_globals` vector.
`Universal` remains `GlobalCandidateSet::ModuleWide`.

## 5. Prototype implementation

1. Add the domain to `NodeResolution` and the Steensgaard class snapshot while
   retaining the existing `external` boolean for compatibility.
2. Propagate source domains through Steensgaard joins and Andersen Ω provenance.
3. Build `exported || address_escaped` IDs after solver escape post-processing.
4. Emit unknown mod/ref rows as:
   - `ForeignOnly`: `Finite(named)` (including finite empty);
   - `ExposedGlobals`: `Finite(named ∪ exposed)`;
   - `Universal`: `ModuleWide`.
5. Use the same candidates for `AccessSite` expansion and memset handling.

The ordinary JSON surface need not expose the internal enum in this prototype; the
existing Ω detail provenance remains available for audit.

## 6. Evaluation

Compare the prototype with commit `86dc8b67` by global key on the non-Vim, non-PHP
sibling corpus.  Record:

- mutable definition globals and disposition counts;
- access-incomplete totals split by module-wide and external-escape;
- unknown-row counts by domain and candidate fanout where practical;
- newly access-complete and newly atomic-certified globals;
- runtime and peak RSS for representative large inputs.

Every module-wide-to-finite change must be attributable to `ForeignOnly` or to the
explicit exported-or-escaped set.  Keep the commit only if the recovered coverage is
meaningful relative to complexity and no targeted soundness test regresses.

## 7. 2026-07-17 evaluation

The implementation carried the lattice through both solvers, expanded
`ExposedGlobals` to `exported || address_escaped` during mod/ref emission, and added
targeted tests for finite-empty `main` argument storage and Universal `inttoptr`.
The full workspace test suite passed.  One existing fixture exposed a real issue in
the old representation: a Steensgaard class containing both `@Table` and an
integer-derived pointer had been exported as finite merely because its named pointee
list was non-empty.  Under the prototype it correctly remained module-wide.

The 34 non-Vim, non-PHP sibling modules other than OpenSSL all completed.  Relative
to the 2026-07-17 baseline for the same modules:

| metric | baseline | prototype | delta |
|---|---:|---:|---:|
| mutable definition globals | 1,461 | 1,461 | 0 |
| immutable | 178 | 178 | 0 |
| atomic | 14 | 10 | -4 |
| unhandled | 1,269 | 1,273 | +4 |
| access complete | 30 | 32 | +2 |
| module-wide witness | 1,352 | 1,344 | -8 |
| external-escape witness | 79 | 85 | +6 |

The only five finite-empty unknown rows occurred in
`exe-b2-hashmap_tree-O0.bc`, which has no mutable definition globals.  They therefore
recovered no disposition coverage.  The ten surviving atomic certificates were the
five JPEGoptim globals at O0 and O1.  The four YAPET O0-g certificates were lost
because an `inttoptr`-tainted, oversize Steensgaard fallback class joined the named
global candidates and correctly raised the class to `Universal`.  Weakening that
join to regain the certificates would violate the domain's soundness rule.

The 34 runs took 80.54 seconds in aggregate and peaked at 1.56 GB RSS (SQLite O1).
The OpenSSL prototype run was killed by signal 9 after 208.72 seconds at 33.24 GB RSS,
before producing a manifest.  Its preserved baseline had likewise required roughly
33 GB RSS, so this failure gives no useful coverage comparison.

Conclusion: the compact domain is feasible, but this corpus does not justify landing
it in its current form.  A two-global net access-completeness gain, no new policy
decision, and four lost static atomic certificates are not compelling.  The prototype
commit was discarded; this design remains a record for a future implementation with
a more precise fallback than whole-class Steensgaard domain joins.
