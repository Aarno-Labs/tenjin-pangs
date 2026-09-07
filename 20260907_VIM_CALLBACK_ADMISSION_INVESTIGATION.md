# Vim callback mismatches: admission and empty-result handling

Follow-up: these two defects are repaired in
`20260907_CALLBACK_ADMISSION_FIX_EVALUATION.md`. Both reproducers have moved from
`fixtures/reproducers` to `fixtures/synthetic/m1_4`, with PIR counterparts. The
failure observations below describe the pre-fix implementation.

2026-09-07. Investigation only; no production solver change. This supersedes the
earlier inference that Vim's 26 unknown additions necessarily came from external
provenance missing in Steensgaard.

## Findings

All 26 sites have a finite, one-target Steensgaard answer and **zero Andersen
function targets, with no external region in the operand points-to set**. The
unknown bit is introduced by `unknown_callee |= targets.is_empty()` at the end of
`Refiner::emit_indirect_calls`, not by `operand_unknown`.

There are two distinguishable groups:

| Sites | Count | Evidence |
| --- | ---: | --- |
| `json_decode`, `json_decode_item`, `json_decode_string` | 17 | The `channel_fill` initializer component is excluded; admitting it recovers one known target at every site. |
| `xdl_call_hunk_func`, `xdl_emit_diffrec`, `xdl_emit_hunk_hdr` | 3 | The `xdiff_out_indices` / `xdiff_out_unified` initializer components are excluded; admitting them recovers the known targets. |
| `json_find_end` | 2 | No reference to the function exists in the linked LLVM module other than its definition. Its callback address has an empty points-to set in executable mode. |
| `json_decode_all` | 4 | Its two direct callers pass local readers whose `js_fill` fields are explicitly initialized to null. The callback address reaches those two allocations, not the channel reader. |

The last six remain empty after admitting the three missing initializer components.
The source/points-to evidence is consistent with legitimate precision removing
Steensgaard's spurious `channel_fill` target, followed by the empty-to-unknown
fallback. This is not a new general proof of unreachable/null callsites: no
production empty-result certificate was implemented or validated here.

## Confirmed admission defect

`build_scope` gives certified accesses separate allocation-relative region
vertices. A GEP/load through a helper parameter lacks that fixed exact-address
certificate and instead joins the parameter/carrier component. These components
are not connected by a dependency from the possible field's initializer to its
consumer. The callback load makes its own component interesting, but the local
field initializer's component has no global, escape, or indirect-call seed and
is left uninteresting.

`build_base_solve` skips an edge when both original PAG endpoints are out of scope.
Consequently it can materialize the field address from an included base-pointer
GEP while omitting both the function-address seed and the store into that field.
It nevertheless treats the admitted callback result as a complete refinement.
This defect occurs even in a tiny program with no oversize component; increasing
the partition budget does not address the missing interestingness/dependency.

Concrete unmodified Vim trace:

- `diff_file_internal::emit_cb` and `xdl_emit_diffrec::ecb` are admitted.
- Writer `diff_file_internal::out_line` is excluded, reader
  `xdl_emit_diffrec::out_line` is admitted, and both point to the same field cell
  (415169 in the recorded unmodified run).
- `sym:function:@xdiff_out_unified` is excluded and has no Andersen points-to seed.
- `channel_parse_json::js_fill2` and `sym:function:@channel_fill` are excluded.
- `diff_file_internal::hunk_func`, the `xdiff_out_indices` store address, is excluded.

The callback operands sometimes contain unrelated data allocations from
conservative content overlap, but no external region and no function. Those data
allocations are not evidence of an external escape.

## Causal controls

`fixtures/reproducers/internal_aggregate_callback_admission.ll` contains only:
allocate a local aggregate, store `@cb` at byte 16, pass the aggregate address to an
internal helper, load byte 16, and invoke it. Differential exits 3 at
`invoke@!noloc#0`; Steensgaard returns `cb`, Andersen returns empty then unknown.
The diagnostic confirms the helper's load is admitted while the writer and `@cb`
seed are excluded.

With PWC enabled, this fails with asymmetric overlap both off and on. It also fails
with both experiments disabled. Two controls pass with overlap off/on:

1. Perform the callback load in the allocating function, preserving the fixed
   root-relative address proof.
2. Add an unused internal global initialized to `@cb`. This seeds the writer's
   component as interesting without adding an external boundary.

On a **temporary copy** of Vim's LLVM IR, adding three such internal globals for
`channel_fill`, `xdiff_out_indices`, and `xdiff_out_unified` makes their initializer
components admitted. The census keeps 2,099 sites and changes exactly 20 unknown
bits from true to false, each with one target. Total Andersen unknowns fall from
232 to 212. The remaining six original sites are:

```
json_find_end@!noloc#1
json_find_end@!noloc#3
json_decode_all@!noloc#1
json_decode_all@!noloc#3
json_decode_all@!noloc#8
json_decode_all@!noloc#10
```

This input perturbation is a diagnostic control, **not a fix or a clean Vim
differential result**. No full three-tier differential or client-output comparison
was run on the perturbed Vim module.

`fixtures/reproducers/null_callback_empty_refinement.ll` independently reproduces
the second mechanism. A shared internal parameter makes Steensgaard merge two
allocations: one has `cb`, the other has null. Only the null allocation reaches a
guarded callback. Andersen correctly has no callable target; its final policy
still promotes empty to unknown and triggers the differential. An internal global
anchor admits the callback producer, excluding the first fixture's failure cause.

## Suggested repair direction

Repair admission's producer closure for indirect/uncertified memory accesses:
include supporting field initializer dependencies for every conservative possible
allocation/region, including interprocedural address flow. Apply the same closure
to ordinary admission and source-closed SCC slices. Bound expansion and retain the
Steensgaard answer whenever the complete producer support cannot be admitted.
Do not merely mark all function addresses interesting: that would fix these
examples without establishing closure for arbitrary stored pointer producers.

Separately, make empty refinement explicitly fail back to the existing base answer
when there is no trustworthy empty witness, instead of replacing a finite base
answer with top. A proven-null/unreachable answer could eventually retain a
certified empty state, but silence alone must not clear unknown. Merely changing
the empty-result fallback would mask the missing-initializer reproducer; it would
not repair admission completeness or partial, nonempty under-approximations.

## Reproduction and artifacts

Artifacts: `/tmp/pangs-vim-unknown-trace.nxyS5L/`.
Original input: `/home/brk/pangs-corpus/_out_bc/exe-vim-9.2-O1.bc`, SHA-256
`d29a9471def3dad7f747b65f74ebfcdf2154212f8407d7a1193574ad6dcd448a`.
All Vim runs use executable mode, PWC=1, overlap=1, default admission and certificates.

- `census.jsonl`, `explain.log`: existing node-explanation hook on the unchanged
  release implementation.
- `diagnostic.log`, `diagnostic2.log`: temporary observational instrumentation
  reporting empty-call external bits, base target identities, node admission and
  points-to cells. Field locations print `None` after query-state compaction has
  released the location table; cell identities and field-to-root mappings remain.
- `pangs-diagnostic`: frozen diagnostic binary, SHA-256
  `b6d3127caebd2855f83122223d567f9641389250283673819dfcdc83a7edda01`.
- `vim.ll`, `vim-anchored.ll`, `anchored.log`, `anchored-census.jsonl`: original
  disassembly and three-global admission control.
- `fixture-diagnostic.log`, `null-control.log`, and temporary LLVM controls.

All temporary solver instrumentation was removed and the release executable
rebuilt. Only this report, a follow-up note, and known-defect LLVM fixtures/README
are retained. No solver fix or experimental default promotion is included.
