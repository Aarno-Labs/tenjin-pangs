# Known-defect reproducers

These fixtures intentionally reproduce unresolved failures and are not part of the
all-green `fixtures/synthetic` differential sweep. Their characterization tests must
be updated when the defects are fixed; placement here does not waive a soundness gate.

The repaired `republished_aggregate_callback.pir.json` and LLVM counterpart now live
in `fixtures/synthetic/m1_4`, where the PIR participates in the all-green differential
sweep. See `20260907_CALLBACK_ESCAPE_REPRODUCTION.md` for the original failure.
