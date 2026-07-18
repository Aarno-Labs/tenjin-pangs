# Per-Global Atomic Remeasurement and Certificate Audit

Date: 2026-07-17

## Scope and method

This rerun measures the disposition corpus after removing co-write candidates,
coupling-edge discharge, hard-group atomic vetoes, and the proposed co-update runtime
audit. It includes every non-Vim, non-PHP sibling currently present in
`/home/brk/pangs-corpus/_out_bc`: 41 modules (21 executables and 20 libraries).

Each module used the release CLI, Andersen, export validation, no overrides, and
`/home/brk/pangs-corpus` as the repository root:

```bash
target/release/pangs analyze INPUT.bc \
  --stage andersen \
  --build-mode executable-or-library \
  --dispose \
  --repo-root /home/brk/pangs-corpus \
  --no-overrides \
  --out OUTPUT \
  --validate
```

All 41 runs completed and validated. OpenSSL was isolated: it took 308.03 seconds and
peaked at 33,004,452 KiB RSS. The other notable peaks were lib-placebo at 3.62 GiB,
lib-sqlite-O1 at 1.44 GiB, and lib-freetype at 1.13 GiB. Retained manifests and audits
are under `/tmp/pangs-disposition-perglobal-20260717`.

## Coverage result

The inventory contains 2,040 mutable definition globals:

- 204 `immutable`;
- 14 `atomic`;
- 1,822 `unhandled`;
- 30 with complete access sets;
- no hard-grouped globals in these corpus manifests.

The atomic certificate set is unchanged from the prior 14-certificate baseline. No
global became newly certified and no prior certificate was lost:

- JPEGoptim O0 and O1: `average_count`, `compress_err_count`,
  `decompress_err_count`, `verbose_mode`, and `worker_count` (five per build);
- YAPET O0-g: `cat.catcolorspace`, `cats_capacity`, `ncats`, and `report_error`.

The simplification therefore removes analysis time, manifest volume, false-negative
risk, and an unneeded production audit obligation without changing current corpus
coverage. The six siblings added since the earlier 35-module measurement contribute
no atomic certificates.

The other 16 access-complete globals fail locally: 13 fail scalar shape, two
JPEGoptim O1 integers (`quality` and `target_size`) have two unmapped access sites
each, and `workers` also carries violation taint in addition to its non-scalar shape.

## Audit of all 14 certificates

The absence of a certificate delta makes the newly-certified audit vacuous, so all 14
surviving certificates were audited instead.

### Checks that passed

- Every certificate has `access_set_complete=true`, `violation_taint=false`, and
  `omega_escaped_address=false`.
- Twelve globals are aligned 32-bit integers; the two `average_count` variants are
  aligned 64-bit signed integers. In every case `align_bits == size_bits` and the width
  is in the target atomic-width set.
- The two signal-accessed certificates are the O0/O1 `verbose_mode` variants. Both
  require and record target-guaranteed lock-free 32-bit atomic support.
- Twelve definitions have external linkage and correctly mark linked-module cross-TU
  rewriting as required. `cat.catcolorspace` and `report_error` have internal linkage.
- The recipes contain 113 entries: 89 loads, four stores, and 20 paired
  `rmw-source-expression` entries. Counting each RMW pair as two IR accesses gives 133
  underlying loads/stores. Direct inspection of the three input modules found exactly
  the same 133 references, per global, with no missing or extra recipe access.
- All 113 recipe entries have a source site, file, function, and statement index (or
  statement-index pair).
- LLVM disassembly contains no volatile access to any certified global and no use of a
  certified global's address outside its definition and direct loads/stores. The
  audited RMW source expressions are increments or decrements.

### Materialization-contract gaps

These do not invalidate the present static eligibility result, but the certificate is
not yet sufficient as a self-contained production materialization recipe:

1. `rmw-source-expression` records the paired statement indices but not the operator
   or operand. A materializer must currently re-parse the source site to distinguish
   increment from decrement and choose the exact atomic operation.
2. The declaration recipe does not carry the initializer. A materializer must recover
   it independently when constructing the atomic definition.
3. Nine certificates have `declaration.file=null`: all five JPEGoptim O0 certificates
   and all four YAPET certificates. Their access sites are mapped, but locating the C
   declaration requires the pipeline's symbol-uniquification/source-recovery contract
   rather than this manifest alone. Only the five JPEGoptim O1 declarations are fully
   source-mapped.
4. Volatile is counted by LLVM lowering metrics but is not retained on `AccessSite` and
   is therefore not an explicit D3 guard. The audited globals are non-volatile, but D3
   should carry and reject volatile access before this property can be trusted without
   a disassembly audit.
5. External-linkage certificates state `cross_tu.scope=linked-module`. Production use
   must continue to enforce the run's exported-bit/whole-linked-module assumption so
   an unrewritten external consumer cannot access the retyped object.

The next highest-value atomic work is to close items 1, 2, and 4 in the certificate
contract, then decide whether source-less declarations are intentionally materialized
through symbol recovery or remain analysis-only certificates.

### Roadmap follow-up

The subsequent D3 hardening carries volatile provenance through `AccessSite` and
rejects it, closing item 4. It also replaces proximity-based `rmw-source-expression`
pairing with proven scalar data flow. Current recipes name `fetch_add`, `fetch_sub`,
`fetch_and`, `fetch_or`, or `fetch_xor`, include the exact IR operand, and identify the
load, operation, and store statement indices. The same 14 corpus certificates survive;
their 20 updates classify exactly, including JPEGoptim's `worker_count--` as
`fetch_add` with operand `-1` in the optimized IR.

Declaration recipes now also retain the typed LLVM initializer, alignment, scalar
class, and signedness. All 14 certificates have complete representation data: their
initializers are `i32 0` or `i64 0`. This closes item 2 without changing ordinary
analysis JSON. A separate `source_materialization` result preserves the distinction
between static eligibility and immediate source rewriteability: five certificates are
`source-mapped`, while nine remain `blocked` with
`declaration-source-unmapped`. Thus item 3 is explicit rather than silently delegated
to the materializer. Item 5 remains a production pipeline invariant.

## Hardened-certificate remeasurement (2026-07-18)

The non-Vim/non-PHP directory grew during the rerun from 41 to 42 modules with the
addition of `lib-ksba-O0-g.bc`. Forty-one current runs completed and validated.
OpenSSL was again the resource outlier and was killed at 219.61 seconds after reaching
37,901,612 KiB RSS. Its prior validated manifest has no atomic certificates (24
immutable and 202 unhandled globals), so it is unaffected by these D3-only recipe and
guard changes and can be used to close the coverage inventory.

Across the resulting 42-module inventory there are 2,049 mutable definition globals:

- 204 `immutable`;
- 14 `atomic`;
- 1,831 `unhandled`.

The added KSBA O0 module contributes nine unhandled globals. Removing it gives the
same 41-module totals as the previous measurement: 2,040 globals, 204 immutable, 14
atomic, and 1,822 unhandled. The atomic set is unchanged. All 14 have a non-null
initializer and complete representation data; five are source-mapped and nine are
explicitly blocked on declaration source recovery.

The run also found and fixed a robustness regression introduced by scalar-op
lowering: curl O0 contains an integer constant wider than 64 bits. Asking LLVM for its
signed 64-bit value aborts. Pang now prints wide constants without narrowing and only
uses LLVM's 64-bit integer accessors for constants of at most 64 bits. A dedicated
`i128` regression test and the successful curl O0 rerun cover the fix.

### JPEGoptim O1 source mapping audit

The two otherwise eligible integers `quality` and `target_size` still each have two
unmapped O1 access sites. These are not ordinary missing-location cases suitable for
nearest-neighbor recovery:

- the three C assignments involved in clamping `quality` are folded into one LLVM
  store whose debug location has line zero;
- the two branch-specific `target_size` assignments are folded through a phi into one
  line-zero store;
- one `quality` load and one `target_size` load have no instruction location after
  condition folding, although their downstream combined predicates retain a location.

The O0 PIR confirms the lost multiplicity: it contains five separate `quality`
accesses for the clamp and two separate `target_size` writes. Assigning a nearby O1
location to either fused store would therefore emit an incomplete, falsely one-to-one
source recipe. No heuristic recovery was added. Safely certifying these globals needs
multi-site source provenance retained through optimization or an AST-level
identifier-rewrite contract.
