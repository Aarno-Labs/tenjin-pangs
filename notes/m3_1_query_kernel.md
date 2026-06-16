# M3.1 query-kernel notes

Date: 2026-06-16

M3.1 adds the first field-insensitive demand-driven callee query kernel:

```bash
pangs query callees <module.bc|module.pir.json> --build-mode <library|executable>
```

The command emits JSON with:

- `by_callsite`: indirect callsite key -> candidate target function names
- `queries`: one source-function traversal record per function object
- `visit_histogram`: coarse visited-state buckets
- `max_visited_states`: largest per-query traversal

## Synthetic coverage

Focused unit tests cover:

- direct assignment to an indirect-call operand
- store/load through memory
- two-level memory aliasing
- independent global function-pointer slots
- the expected field-insensitive over-approximation before M3.2 MHS lands
- a synthetic-suite ledger check that every M3.1 target stays inside the Steensgaard
  envelope

## Corpus smoke

Command:

```bash
LLVM_SYS_140_PREFIX=/home/brk/tenjin/_local/xj-llvm-14 \
LD_LIBRARY_PATH=/home/brk/tenjin/_local/xj-llvm-14/lib \
cargo run -q -p pangs-cli -- query callees \
  /home/brk/pangs-corpus/_out_bc/exe-jpegoptim-O1.bc \
  --build-mode executable
```

Summary:

| metric | value |
|---|---:|
| function-source queries | 129 |
| callsites with M3.1 candidates | 5 |
| visited-state min | 1 |
| visited-state p50 | 1 |
| visited-state max | 256 |
| histogram `<=10` | 117 |
| histogram `<=100` | 5 |
| histogram `<=1000` | 7 |
| histogram `>1000` | 0 |

The smoke run is deliberately not a precision claim. The current kernel has no MHS and
therefore reports field-insensitive target sets. M3.2 is expected to narrow cases like
struct field dispatch tables.
