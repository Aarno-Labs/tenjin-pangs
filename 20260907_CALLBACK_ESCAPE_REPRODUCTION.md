# Semantic callback reproduction

2026-09-07. A small semantic fixture reproduces the same **direction** of unknown-call
mismatch as the Vim investigation. It identifies a concrete escape-closure defect;
it does not yet prove that this explains every one of Vim's 26 sites. No propagation
fix is included in this change.

## Results

The solver test `semantic_callback_boundaries_characterize_republished_escape_gap`
constructs independent PIR programs. Each initializes a callback at byte offset 8;
the payload case uses byte offset 0 for the unrelated external pointer. All cases
retain the known `cb` target. The table reports the additional unknown-callee bit.

| Semantic case | Steensgaard | Andersen | Required interpretation |
|---|---|---|---|
| Pass aggregate address directly to foreign code, then load callback | true | true | Foreign code may overwrite the callback. |
| Store/load aggregate address through a separate slot, pass loaded address to foreign code, read original member | **false** | true | Same aggregate escapes; Steensgaard is missing unknown. |
| Same publication, then GEP +8 and load through the published address | **false** | true | The shifted-load reproducer has the same defect. |
| Store an externally returned pointer only in field 0; read callback in field 8 | false | false | External field-0 payload must not imply sibling mutation. Field-0 load is explicitly external. |
| Merge an external pointer and a local allocation address, then read through an independent known-local address | false | false | The allocation-location UF class carries `ext`, but this read still names the initialized local field. |
| Shift the merged possibly-external pointer by +8, load callback | true | true | The load may address external storage. |

The tests use ordinary PIR calls, stores, loads, assigns (a pointer selection), and
GEPs. They never inject `set_ext`, `set_esc`, joins, or synthetic solver metadata.
Pointer value-kind annotations preserve the pointer semantics of ABI `integer`
values. Read-only internal assertions confirm that the identity cases really have
an external allocation-location class, and distinguish owner escape from field escape.

## Confirmed mechanism in the reproducer

`apply_external_call` first calls `escape_exact_address_fields_with_source`, then
marks the argument's pointee escaped. For the direct address, the exact-address
certificate identifies the allocation and `escape_allocation_fields` records the
root-wide escape envelope, covering current and future fields.

After publication through memory, `exact_addresses[published]` is absent, even
though the solved pointee still identifies the same allocation. The fallback marks
the allocation's Exact(0) location escaped, but does not populate
`field_escape_sources_by_root` or mark the separate field-8 location escaped.
The test verifies all three observations: owner `esc=true`, field-8 `esc=false`,
and missing root-wide escape registration. Andersen's boundary traversal does
reach the field and retains unknown.

This is a missing **escape envelope**, not evidence for copying every field's
external payload to its siblings. A future fix should recover allocation roots from
the solved boundary pointee alternatives, including late bindings, and propagate the
allocation escape envelope without conflating carriers, storage, and field contents.

## Standalone reproduction

`fixtures/reproducers/republished_aggregate_callback.pir.json` contains just the
published-address, shifted-load case. Run:

```bash
LD_LIBRARY_PATH=/home/brk/tenjin/_local/xj-llvm-14/lib \
target/release/pangs differential \
  fixtures/reproducers/republished_aggregate_callback.pir.json --build-mode executable
```

Expected current exit code: **3**, with
`icall_unknown: andersen has main@!noloc#1 absent from steens`.
This reproduces with asymmetric overlap off and on, including with static PWC enabled.
The fixture is intentionally outside the all-green synthetic corpus. The two new
characterization tests assert the current defect explicitly; when repaired, change
them to require the sound unknown result rather than preserving the faulty behavior.

The adjacent `republished_aggregate_callback.ll` is a typed LLVM-14 counterpart with
a `{ i8*, void ()* }` aggregate. Substituting that filename in the command above also
reproduces the same unknown-call violation (exit 3), independently validating the PIR
pointer annotations and layout. `cargo test --workspace --all-targets` passes,
including 141 solver tests; this includes the known-defect characterization, not a
claim that the standalone differential now passes.
