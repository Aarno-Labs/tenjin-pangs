# D4 YAPET mutex-selection audit

Date: 2026-07-18

## `cats`

`cats` is a mutable, externally linked `cat_t *` declared at
`yapteaparprfotci.c:58`. The retained O0-g ledger reports 26 access sites in two
accessor functions:

- `addcat` grows the allocation with `realloc` and initializes the new element;
- `cat` reads and mutates elements while lazily loading GIF streams.

The atomic pass rejects it because the pointee aggregate is not a word-sized scalar.
The D4 whole-accessor-function recipe is meaningful: a per-global mutex around
`addcat` and `cat` serializes both pointer replacement and element access. Neither
accessor reaches either accessor in the known final call graph, so the original D4
reentrancy check certifies it. Unknown/external callees still need the fail-closed
hardening described below before the certificate is sound.

## `options`

`options` is a 13-element, statically initialized `Clp_Option` table declared at
`yapteaparprfotci.c:76`. It is passed to `Clp_NewParser` from `main`, but the retained
ledger contains zero LLVM load/store access sites for the global itself. Its current
facts nevertheless classify it as written, reject atomic handling because it is a
2,496-bit aggregate, and vacuously certify mutex handling with an empty accessor set.

That certificate follows the current D4 inputs but is not materializable: there is no
accessor at which to acquire the proposed lock. Semantically, `options` should be an
immutable table. The false mutex selection is an upstream precision issue in aggregate
initializer/reference modeling, not evidence that a runtime lock is appropriate.
Until that modeling is fixed, D4 source materialization must explicitly block a
certificate with no runtime accessor sites.

## Hardening implications

1. Reachability must fail closed when a path from an accessor reaches an unknown
   callee, since that call can re-enter an accessor while the whole-function lock is
   held.
2. A mutex certificate needs declaration metadata and a source-materialization status,
   parallel to the atomic certificate.
3. Source materialization must be blocked when the declaration is unmapped or the
   accessor set is empty. The latter keeps `options` visible as a static eligibility
   result without claiming that the v1 lock recipe can actually be emitted.
