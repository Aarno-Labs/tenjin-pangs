# M2.7 validation notes

Date: 2026-06-16

Command shape:

```bash
LLVM_SYS_140_PREFIX=/home/brk/tenjin/_local/xj-llvm-14 \
LD_LIBRARY_PATH=/home/brk/tenjin/_local/xj-llvm-14/lib \
timeout 300s target/release/pangs m2-ablation <module.bc> \
  --stage andersen --build-mode <executable|library>
```

Artifacts live under `ju_out/m2_7/`.

## Completed ablations

| Module | Build mode | Wall time | call_edges delta | icalls_simple | Notes |
|---|---:|---:|---:|---:|---|
| `exe-jpegoptim-O1.bc` | executable | 0.83s | none | 0 | no B1/B2 precision delta |
| `exe-jpegoptim-O0.bc` | executable | 2.18s | none | 0 | no B1/B2 precision delta |
| `exe-curl-O1.bc` | executable | 29.64s | none | 0 | no B1/B2 precision delta |
| `exe-chibicc-O1.bc` | executable | 90.08s | none | 0 | no B1/B2 precision delta |
| `exe-jq-O1.bc` | executable | 97.01s | none | 0 | default Andersen path completes with 17 oversize fallbacks |
| `exe-gifsicle-O1.bc` | executable | 118.32s | none | 0 | `icalls_andersen=4`, but no B1/B2-added sites |
| `lib-parson-O0.bc` | library | 0.22s | none | 0 | no B1/B2 precision delta |
| `lib-parson-O1.bc` | library | 0.09s | none | 0 | no B1/B2 precision delta |

## Timeouts

| Module | Build mode | Timeout | Notes |
|---|---:|---:|---|
| `exe-lua-O1.bc` | executable | 300.72s | no JSON emitted |
| `exe-chibicc-O0.bc` | executable | 240.26s | no JSON emitted |

## Interpretation

The completed real-corpus sweep did not expose a measurable B1/B2 precision win:
`call_edges` were identical across all ablation variants and `icalls_simple=0` in every
completed run. This does not contradict the M2 semantics; the synthetic fixtures cover
the intended exact-resolution cases. It means this corpus snapshot mostly lacks the
initializer/simple-flow dispatch-table shapes that B1/B2 are designed to exploit, or the
surviving shapes do not feed indirect call operands in the current PIR.

Spot checks:

- `lib-parson-O1.bc` has function-reference initializer stores for allocator hook globals
  (`@parson_free = @free`, `@parson_malloc = @malloc`), but they do not feed observed
  indirect callsites in the ablation.
- `exe-gifsicle-O1.bc` has a few function-reference initializer stores, including
  compare/diversity switch tables, but B1/B2 did not resolve additional callsites beyond
  the existing Andersen tier.

M2.7 is therefore frozen on synthetic semantic coverage plus this documented corpus
observation, with the lua/chibicc-O0 timeouts left as performance follow-up candidates
rather than M2 blockers.
