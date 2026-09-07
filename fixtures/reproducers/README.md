# Known-defect reproducers

These fixtures intentionally reproduce unresolved failures and are not part of the
all-green `fixtures/synthetic` differential sweep. Their characterization tests must
be updated when the defects are fixed; placement here does not waive a soundness gate.

- `republished_aggregate_callback.pir.json`: expected differential exit 3; Steensgaard
  misses an unknown callback after an aggregate escapes through a republished address.
  See `20260907_CALLBACK_ESCAPE_REPRODUCTION.md` at the repository root for controls,
  mechanism, and the reproduction command.
- `republished_aggregate_callback.ll`: typed LLVM-14 counterpart; reproduces the same
  differential violation without hand-authored PIR pointer annotations.
