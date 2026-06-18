# `pangs cc2json` — port of the cclyzer++ `cc2json` client

`pangs cc2json <module.bc> --json-out <file>` reproduces the JSON summary that the
`cclyzer.tenjin` standalone `cc2json` client emitted (`src/cc2json.cpp` + `datalog/`). It
consumes bitcode and writes the six-section summary the goldens in `ju_cc2json/*.cc2json.json`
contain.

```
pangs cc2json <module> --json-out out.json
               [--stage andersen|steens|conservative]   (default: andersen)
               [--entrypoints library|executable]        (default: library)
               [--internalize-globals]                    (default: off)
```

The goldens were produced by cclyzer's **unification** points-to with
`--context-sensitivity=insensitive --entrypoints=library` and **no** `--internalize-globals`
(see `ju_cc2json/before/run-big-baseline.sh`). pangs' `--stage steens` is the closest analog;
`--stage andersen` (the default) is more precise and will narrow some sets further.

## Where the logic lives

| section | source in pangs | cc2json/datalog origin |
|---|---|---|
| `mutated_globals` | `Analysis::modrefs()` rows with `access:mod` | escape-analysis.dl `mutated_global` (store-target half) |
| `escaped_globals` | PIR-based dataflow over function-body stores/returns | escape-analysis.dl `escaped_global` |
| `call_graph_components` | bipartite union-find over `Analysis::call_edges()` | callgraph/connected-components.dl |
| `unique_filenames` | `UniqueFilenameMapper` over PIR `Loc` dir/filename | `UniqueFilenameMapper` (cc2json.cpp) |
| `mutable_global_tissue` | direct modrefs + reverse call-graph closure | mutable-global-tissue.dl |
| `global_initializer_references` | PIR `Global::init_refs` | constant-init.dl |

Implementation: `crates/pangs-clients/src/cc2json.rs`. Two small, additive PIR-frontend changes
support it (neither touches the pointer-analysis core):

* `Global::init_refs` — the global-value names referenced by a global's constant initializer,
  recursing only through struct/array elements (matching cclyzer's `constant_in_initializer`,
  which does **not** descend into GEP/bitcast `ConstantExpr` operands).
* `Loc::dir` / `Loc::filename` — the raw DWARF directory and filename, preserved separately so
  the `(directory, filename)` split is exact even when the filename itself contains `/`
  (`Loc::file` stays the joined display path used by witnesses).

## Fidelity

`lib-small-g-O0` (the library showcase) is reproduced **byte-for-byte** under `--stage steens`
(regression test: `cc2json::tests::lib_small_matches_golden_byte_for_byte`). `exe-b2-hashmap_tree-O0`
matches **every section's contents** (only component array *order* differs). For all executables,
`unique_filenames`, `global_initializer_references`, `mutable_global_tissue` (hashmap, sbase), and
empty `escaped_globals` match. The remaining divergences, with cause:

* **`mutated_globals`.** Both cclyzer sources are reproduced: the store-target rule (`access:mod`
  modrefs) and the non-readonly-argument rule. The latter resolves a global whose address is
  passed to a call argument — including inline constant-expr `getelementptr`/`bitcast` arguments
  (e.g. hashmap's `__func__.*` passed to a printf) — and honors a ported libc readonly table,
  which includes `__assert_fail` (so the `__PRETTY_FUNCTION__.*` arrays it receives are not
  flagged). hashmap's 14 `__func__.*` now match exactly. It resolves only *directly*-denoted
  globals (not values flowing through loads/memory), so sbase/OMP still differ by a few entries
  (e.g. sbase's `stdout`, an external FILE\* declaration) where cclyzer's full points-to differs.
* **`escaped_globals` (over/under on executables).** Reproduced via a PIR dataflow escape
  (global value stored into / returned alongside an externally-visible global, to a fixpoint),
  which is exact on lib-small (`transform_apply`). cclyzer's full result depends on its
  context-sensitive points-to and reachability: it does **not** escape function pointers
  reassigned at runtime through externally-visible fnptr globals in executables (e.g. OMP's
  `basesort = versort` in `main`), which our syntactic rule does; and it escapes some returned
  static buffers (OMP's `pathconcat.buf_xjtr_2`) our rule misses. These are inherent to the
  different solver.
* **`call_graph_components` ordering.** Contents match (as sets) far more often than order does.
  We order components by their smallest call-site key, which reproduces cclyzer's
  representative-based order exactly on lib-small but not always on the larger modules (cclyzer
  orders by instruction/function refmode strings pangs does not reproduce). A handful of
  components also differ in content on sbase/OMP because pangs' call graph resolves a few
  edges differently.

These are exactly the "differs for good reasons (different/sometimes-more-precise analysis)"
cases — acceptable per the project decision, documented here and inline in `cc2json.rs`.
