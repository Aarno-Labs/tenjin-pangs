# Known-defect reproducers

These fixtures intentionally reproduce unresolved failures and are not part of the
all-green `fixtures/synthetic` differential sweep. Their characterization tests must
be updated when the defects are fixed; placement here does not waive a soundness gate.

The repaired `internal_aggregate_callback_admission` and
`null_callback_empty_refinement` fixtures now live in `fixtures/synthetic/m1_4`,
with LLVM and PIR variants. They cover missing initializer admission and finite
base fallback for an uncertified empty callback result. Their PIR variants are
included in the all-green differential sweep. See
`20260907_VIM_CALLBACK_ADMISSION_INVESTIGATION.md` for the historical diagnosis and
`20260907_CALLBACK_ADMISSION_FIX_EVALUATION.md` for the repair.

The repaired `republished_aggregate_callback.pir.json` and LLVM counterpart now live
in `fixtures/synthetic/m1_4`, where the PIR participates in the all-green differential
sweep. See `20260907_CALLBACK_ESCAPE_REPRODUCTION.md` for the original failure.
