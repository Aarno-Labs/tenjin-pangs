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
