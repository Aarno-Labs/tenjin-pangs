# Design: resolve cc2json points-to-precision divergences via real points-to

## Problem

Three `cc2json` sections diverge from the goldens on the larger executables, all rooted in
pangs not driving mutation/escape from allocation-level points-to (it used syntactic PIR
resolution):

* `mutated_globals` — sbase over-reports `stdout`. The non-readonly-arg rule resolves the
  *address-of* a global syntactically, but cclyzer mutates the argument's *pointee*. `stdout`
  passed to `fprintf` is a loaded `FILE*`; its pointee is the FILE object, not the `stdout`
  global.
* `escaped_globals` — OMP over-escapes functions reassigned to externally-visible fnptr globals
  at runtime and misses returned static buffers. The PIR-syntactic escape doesn't match
  cclyzer's points-to-based `escaped_alloc`.
* `call_graph_components` — content gaps on sbase/OMP come from call-graph **reachability**
  differences (a separate axis), plus ordering (cclyzer refmode strings pangs doesn't emit).

## Key facts about the existing solver

pangs' Steensgaard solver (`crates/pangs-solve/src/lib.rs`) already maintains, per union-find
class (`ClassData`): `global_objs` and `fn_objs` (the allocation members) and a `pointee` class.
So for any PAG node, `points_to(node) = global_objs ∪ fn_objs` of `find(pointee(class_of(node)))`.
The current `SolveResult.nodes[label].pointee_globals` is insufficient — it lists globals only
(no functions, e.g. misses `transform_apply`) and only for value/param/return nodes (no
object→pointee edges, i.e. no `ptr_points_to`). cclyzer ran unification, so escape is computed
from a steens solve regardless of the call-graph `--stage`.

## Plan

1. **Augment `pangs-solve` (additive, gated, cheap).** New `solve_steensgaard_with_points_to`
   materializes `node_points_to: BTreeMap<String, BTreeSet<String>>` over *all* nodes (value/
   param/return and object), memoized per class root — O(#nodes). The default `solve_steensgaard`
   / `solve_andersen` are unchanged, so the `analyze` pipeline runtime is unaffected; only the
   `cc2json` client pays for it.
2. **`cc2json` reimplements the rules over points-to.**
   * mutated-via-arg: `operand_points_to(arg) ∩ globals` minus readonly positions.
   * escaped: port `escape-analysis.dl` (pointee-of-externally-accessible global; returned by an
     escaped function; stored to escaped/heap memory; passed to an escaping arg; transitive +
     subregion) over `node_points_to` + linkage (`Global::exported`).
3. **Components** addressed separately (reachability), after escape.

## Runtime

No change to `analyze`. The `cc2json` path adds one points-to materialization
(O(#nodes + #globals + #functions)) plus a small allocation-level fixpoint. Negligible.

## Validation gate

Before committing to the full escape port, dump pangs points-to for the divergent allocations
(`stdout`, `transform_apply`, `versort`/`basesort`, `pathconcat.buf_xjtr_2`) and confirm it
supplies the facts the rules need. The OMP fnptr-escape case may remain divergent if cclyzer's
unification points-to genuinely differs; measure and document.

## Outcome (implemented)

* Added `solve_steensgaard_with_points_to` + `SolveResult::node_points_to` (gated; the `analyze`
  pipeline is unchanged). Unit-tested in `pangs-solve`.
* **Key finding:** pangs' Steensgaard is **field-insensitive**, so it over-merges aggregates into
  giant classes (one OMP class held ~40 unrelated globals+functions; sbase's `stdout` merged into
  a flush function's FILE\* class). cclyzer is field-sensitive (subobjects), so it stays precise.
  This — not missing logic — is the root cause of the remaining divergences. Closing it fully
  needs field-sensitive points-to, a large change with disproportionate runtime cost (out of
  scope per the constraint).
* **What the available augmentation did resolve, soundly/cheaply:**
  * `mutated_globals`: restrict to globals *defined* in the module (cclyzer allocates only those)
    — drops field-insensitive aliased false-positives on external declarations. Fixes sbase
    `stdout` exactly; lib-small/hashmap unchanged.
  * `escaped_globals`: recompute over `node_points_to` (allocation-level points-to) with a
    collapse guard that ignores pointee sets containing a string constant (the signature of
    field-insensitive aggregate merging). lib-small/hashmap/sbase now match exactly; OMP's escape
    over-report shrank from ~40 (raw points-to) / 7 (syntactic) to 5.
* **Not resolvable here:** OMP's remaining escape over-report (clean fnptr global `getfulltree`'s
  pointees, which cclyzer does not escape for reasons not derivable from the published datalog)
  and the component reachability/order differences. Both would need either field-sensitivity or a
  precise model of cclyzer's exact escape/reachability conditioning.
