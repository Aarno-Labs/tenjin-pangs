# M3.2 MHS notes

Date: 2026-06-16

M3.2 adds a byte-offset memory-history stack (MHS) mode to the callee query kernel:

```bash
pangs query callees <module.bc|module.pir.json> --mode field-sensitive
```

`field-sensitive` is now the default query mode. `field-insensitive` remains available for
M3.1/M3.2 comparison.

## Semantics implemented

- `Store` pushes a fresh zero-offset memory frame and enters backward alias search.
- `Gep{off}` adjusts the active frame by signed byte offset.
- `Gep{unknown}` saturates the active frame to top.
- `Load` may close a memory frame only when the active frame is zero or top.
- Query sinks are collected only in forward phase with an empty MHS.

## Synthetic coverage

Focused tests cover:

- struct function-pointer fields: M3.1 field-insensitive returns `{f0,f1}`; M3.2 MHS
  returns `{f0}` for the loaded field.
- two-level memory remains reachable under MHS.
- unknown GEP offsets saturate to top and remain soundly permissive.
- unknown offsets on the load side also saturate to top and remain soundly permissive.
- container_of-style negative-offset arithmetic reaches the matching field.
- zero-offset GEPs used as casts preserve exact field matches.
- mismatched concrete field offsets do not match under MHS, while M3.1 still reaches the
  same target field-insensitively.
- nested memory levels keep independent MHS frames while preserving concrete field
  offsets across an extra pointer indirection.
- synthetic-suite ledger: M3.1 and M3.2 answers both stay inside the Steensgaard
  envelope.

## Corpus smoke

On `exe-jpegoptim-O1.bc`:

| mode | callsites with candidates | max visited states | histogram `>1000` |
|---|---:|---:|---:|
| field-insensitive | 5 | 256 | 0 |
| field-sensitive | 0 | 115 | 0 |

This is a kernel smoke, not an end-to-end precision claim. The field-sensitive query is
stricter and may remove field-insensitive false positives, but it is not yet wired through
the M3.3 call-graph fixpoint or dynamic validation.
