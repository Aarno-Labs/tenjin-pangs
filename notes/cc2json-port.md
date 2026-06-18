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
matches **every section's contents** (only component array *order* differs). `exe-sbase_cal-O0`
matches `mutated_globals`, `escaped_globals`, `mutable_global_tissue`, `unique_filenames`, and
`global_initializer_references` (only some components/order differ). `unique_filenames` and
`global_initializer_references` match on all four. Remaining divergences, with cause:

* **`mutated_globals`.** Both cclyzer sources are reproduced: the store-target rule (`access:mod`
  modrefs) and the non-readonly-argument rule. The latter resolves a global whose address is
  passed to a call argument — including inline constant-expr `getelementptr`/`bitcast` arguments
  (hashmap's `__func__.*` passed to a printf) — and honors a ported libc readonly table including
  `__assert_fail` (so `__PRETTY_FUNCTION__.*` is not flagged). Results are restricted to globals
  *defined* in the module (cclyzer only allocates those), which drops field-insensitive aliased
  false-positives that land on external declarations (sbase's `stdout`). OMP still differs by a
  handful: pangs' field-insensitive Steensgaard produces spurious aliased writes onto defined
  aggregates that cclyzer's field-sensitive points-to avoids.
* **`escaped_globals`.** Computed over real allocation-level points-to
  (`solve_steensgaard_with_points_to`): an allocation pointed to by an externally-visible global
  escapes (transitively), plus a syntactic return-escape. A **collapse guard** ignores pointee
  sets that contain a string constant — the hallmark of pangs' field-insensitive merging of an
  aggregate's fields (e.g. OMP's `struct sorts {char*; fnptr;}`), which would otherwise escape a
  ~40-element blob. lib-small/hashmap/sbase match exactly. OMP still over-reports a few function
  pointers reachable through a clean fnptr global (`getfulltree`) that cclyzer, for reasons not
  derivable from the published rules, does not escape, and misses one returned static buffer.
* **`call_graph_components`.** Contents match (as sets) far more often than order does. We order
  by smallest call-site key — exact on lib-small, not always on larger modules (cclyzer orders by
  instruction/function refmode strings pangs does not emit). A few components also differ in
  content on sbase/OMP because pangs' call graph resolves some edges differently (reachability).

These are exactly the "differs for good reasons (different/sometimes-more-precise analysis)"
cases — acceptable per the project decision, documented here and inline in `cc2json.rs`.
