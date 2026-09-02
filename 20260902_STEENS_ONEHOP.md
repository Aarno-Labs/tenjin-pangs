# One-Hop Steensgaard Load/Store: Design and Implementation Plan

Date: 2026-09-02
Status: proposal. Supersedes `20260826_SEPARATE_STORAGE_IDENTITY_v3.md` and the v1/v2 experiments
recorded under `ju_out/separate_storage_identity_*`.

## 0. Summary

The production Steensgaard solver (`crates/pangs-solve/src/lib.rs`, `Solver::apply_edge_rules`)
implements Load and Store as container unifications:

```text
x = *a:  V(x) ≡ S(a)
*b = x:  S(b) ≡ V(x)
```

Their composition through any value that is loaded and then stored equates the two containers,
`S(a) ≡ S(b)`, which moves allocation tags, allocation-relative fields, function objects, escape
state, and callsite frontiers between containers that merely exchanged a pointer. The textbook
rules equate only the stored pointer targets:

```text
x = *a:  P(V(x)) ≡ P(S(a))
*b = x:  P(S(b)) ≡ P(V(x))
```

This document specifies how to make that change **inside the existing solver**, with no second
solver, no typed arena, no Andersen adapter, and no new result machinery. The whole change is
three parts:

1. Two match arms in `apply_edge_rules` (Load, Store) switch from `join` to a new
   `unify_pointees` primitive; GEP and Memcpy already have the one-hop shape and only adopt the
   same primitive.
2. A directed **content-fact edge** list replaces what the container unification was silently
   carrying: the flow of the `ext`, `universal`, and `has_empty_witness` facts from a storage class
   into a loaded value, from a stored value into its storage, across a `memcpy`, and across a
   GEP. This generalizes the `empty_witness_copy_edges` side relation that Memcpy already uses.
3. One debug invariant: after the change, no union-find class ever contains both a value-like
   node and a location (object node or synthetic pointee/field class). Every location-level
   fact then stays on locations by construction.

Estimated size: about 200 lines net in `lib.rs` plus tests. Nothing outside `pangs-solve`
changes in the first two revisions.

### What the three prior attempts established

- **The equations are right and the precision exists.** v1 removed the motivating SQLite
  co-occurrence of `aDateTimeFuncs` and `azModeName` (2,740 envelopes to zero), passed the
  precision and FN fixtures, and ran 34% faster than legacy on the three large modules
  (`ju_out/separate_storage_identity_corpus_20260826/REPORT.md`).
- **The Ω explosion was the fact *read*, not the equations.** v2 read `external`/`universal`
  from the *target identity* (`external(x) = external(P(V(x)))`). Ablation A, which read them
  at the carrier instead, took SQLite's unknown rows from 45,876 to 2,092 with zero named-row
  change (`ju_out/v2_factroot_field_boundary_ablations_20260827/REPORT.md`). A Steensgaard
  location class is a coarse union; any fact attached to it is inherited by every pointer that
  may reach any member. The mega-class behind SQLite's 35,976 Ω nodes held 1,192 globals and one
  `getenv` result.
- **The same read has since entered the legacy solver.** Revision `vowqvntwtlpw`
  (2026-08-31, "Steens boundary propagation fix") made `Solver::finish` read `ext`/`universal`
  from the carrier *or its pointee*. Measured today on the current binary (§7.2 baseline),
  `lib-sqlite-O1 --stage steens` emits 45,182 module-wide unknown ModRef rows, against 3,548
  unknown rows in the 2026-08-26 legacy reference; a scratch build with only that read reverted
  emits 2,740 (§7.2). The one-hop change is not the cause of that
  regression and is not, by itself, the cure; §4.4 makes the read a first-class part of this
  design because the carrier-level read becomes provably sound once content edges exist.
- **The cost blowups were experiment scaffolding.** v2's finish-time timeouts were the
  field-owner "logical membership" expansion (4.18 billion escape-source clones) that the typed
  design introduced; the v1 phantom-type role assertions crashed 7 of 18 corpus modules. This
  design reuses the legacy data structures unchanged, so neither hazard exists.

## 1. The change, rule by rule

`V(x)` is the class of the PAG value node `x`. `S(a)` is `storage_class_for_address(a)`: the
certified allocation-relative field class when the fixed PAG proves one, otherwise
`pointee_of(V(a))`. `P(c)` is `pointee_of(c)`.

| PAG edge | Today | After | Content edge |
|---|---|---|---|
| `Load` `x = *a` | `join(V(x), S(a))` | `unify_pointees(V(x), S(a))` | `S(a) → V(x)` |
| `Store` `*b = x` | `join(S(b), V(x))` | `unify_pointees(S(b), V(x))` | `V(x) → S(b)` |
| `Gep` unknown root | `join(P(V(d)), P(V(s)))` | `unify_pointees(V(d), V(s))` (same meaning) | `V(s) → V(d)` |
| `Gep` exact root | `join(P(V(d)), field)` | unchanged | none (certified address) |
| `Memcpy` | `join(P(S(d)), P(S(s)))` + empty-witness edge | `unify_pointees(S(d), S(s))` | `S(s) → S(d)` |
| `Assign` | `join(V(d), V(s))` | unchanged | none (join carries facts) |
| `Assign` exact shortcut | `join(P(V(d)), storage)` | unchanged | none (certified address) |
| `AddrOf` | `join(P(V(p)), obj)` | unchanged | none |
| call/return bindings | `join` of carriers | unchanged | none |
| proven-empty operands | universal / witness special cases | unchanged | none |

`Assign` deliberately keeps its carrier join. For SSA values, `V(d) ≡ V(s)` is stronger than the
textbook `P(V(d)) ≡ P(V(s))` only by merging two carriers that hold nothing but content facts,
and that merge is exactly the content-fact transfer an Assign needs. Changing it would buy no
precision and would cost another content edge per Assign.

## 2. What a class means after the change

Every `ClassData` field is either a fact about the **contents** of the cells in the class or a
fact about the cells **as locations**:

| Field | Kind | Meaning |
|---|---|---|
| `pointee` | content | `P(c)`: where the pointer held in the cells may point |
| `ext` | content | the held pointer may be an external pointer |
| `universal`, `universal_sources` | content | the held pointer may be integer-forged |
| `has_empty_witness` | content | the held pointer may be null |
| `provenance` | content (diagnostic) | how the contents were merged |
| `esc`, `escape_sources` | location | the cells are reachable by external code |
| `global_objs`, `fn_objs` | location | named objects among the cells |
| `icall_sites`, `processed_*` | location | callsite frontier over function objects in the cells |

Legacy Load/Store unified a value carrier with a storage location, so a value class could carry
location facts (a loaded value's class "contained" globals and function objects, and inherited
`esc`). After the change no rule joins a carrier with a location, so:

> **One-hop invariant.** A class root contains value-like nodes (`Value`, `Param`, `Return`) or
> locations (`Object` nodes, synthetic pointee classes, synthetic field classes), never both.
> Consequently `esc`, `global_objs`, `fn_objs`, and `icall_sites` are only ever non-trivial on
> location classes.

The invariant is what v3 wanted from phantom-typed IDs. It needs no types: it is a consequence of
the rule table, checked once per solve in debug builds (§3.5).

### 2.1 What the container unification was silently providing

Removing `V(x) ≡ S(a)` must replace each thing it carried. The checklist:

| Carried by legacy `V ≡ S` | Replacement |
|---|---|
| `P(V(x)) ≡ P(S(a))` | `unify_pointees` (the intended rule) |
| `ext`, `universal`, `has_empty_witness` transfer between value and storage | content edges (§3.2) |
| escaped storage makes its loaded value external (`external = ext ‖ esc` read on the value's class) | a content edge transfers `ext(src) ‖ esc(src)` into `ext(dst)` |
| location facts leaking into carriers and across containers | intentionally dropped: this is the precision gain |
| `provenance` mask merging | `unify_pointees` ORs it into the shared pointee class |

## 3. Solver changes

### 3.1 `unify_pointees`

```rust
/// Equate the pointer targets held in `a` and `b` without equating `a` and `b`.
fn unify_pointees(&mut self, a: usize, b: usize, provenance: u8) -> usize {
    let a = self.find(a);
    let b = self.find(b);
    if a == b {
        return self.pointee_of(a);
    }
    match (self.classes[a].pointee, self.classes[b].pointee) {
        (Some(pa), Some(pb)) => self.join(pa, pb, provenance),
        (Some(p), None) => { self.classes[b].pointee = Some(p); self.enqueue(b); self.find(p) }
        (None, Some(p)) => { self.classes[a].pointee = Some(p); self.enqueue(a); self.find(p) }
        (None, None) => {
            // Share one new class between both slots instead of creating two and joining them.
            let p = self.pointee_of(a);
            self.classes[b].pointee = Some(p);
            self.enqueue(b);
            p
        }
    }
}
```

The `(None, None)` sharing is the "immediate target sharing" that took v2 from 82,236 to 60,699
pointee classes; it is free here. Enqueuing the class that acquired a pointee link is what makes
the existing push-down rule (`process_class`: `(ext ‖ esc)(c) ⇒ ext(P(c)) ∧ esc(P(c))`) fire for
a link created after the fact was set. That is the entire "late materialization" obligation that
v3 §4 discusses; `pointee_of` already enqueues for the same reason.

### 3.2 Content edges

```rust
struct ClassData {
    ...
    /// Classes whose contents include this class's contents. Stored as raw class ids and
    /// resolved through `find` when used, like `empty_witness_copy_edges` today.
    content_succ: Vec<usize>,
}

fn add_content_edge(&mut self, src: usize, dst: usize) {
    let src = self.find(src);
    self.classes[src].content_succ.push(dst);
    self.enqueue(src);
}
```

`join` appends the absorbed class's `content_succ` to the survivor's (same pattern as
`icall_sites`). `process_class`, after its existing push-down block, pushes content facts along
the edges:

```rust
let carries_ext = ext || esc;          // esc: external code may have written these cells
if carries_ext || universal || self.classes[root].has_empty_witness {
    let succs = self.classes[root].content_succ.clone();
    for succ in succs {
        let dst = self.find(succ);
        if dst == root { continue; }
        if carries_ext { self.set_ext(dst); }
        if universal { self.set_universal_ext_with_sources(dst, &universal_sources); }
        if self.classes[root].has_empty_witness { self.set_empty_witness(dst); }
    }
}
```

`set_empty_witness` gains an `enqueue` on change, so witness propagation converges inside the
worklist. `empty_witness_copy_edges` and `propagate_empty_witnesses` are deleted; Memcpy's
witness flow is now one of the content edges.

Direction matters. A load transfers facts from storage to value, a store from value to storage;
making the relation symmetric would push a container's external contents back into every value
stored into it. The directed form is exactly what the legacy merge already implied for the
soundness-relevant direction and nothing more.

Cost control: `process_class` scans `content_succ` every time the class is re-enqueued. The
first cut accepts that; if profiling shows repeated scans on the largest location classes, add a
`pushed: (ext, universal_sources.len(), empty, succ_len)` record and push only the delta. Do
not add that until the counter `steens_content_pushes` says it matters.

### 3.3 Edge rules

```rust
EdgeKind::Load => {
    if !self.node_may_carry_pointer(edge.dst) { continue; }
    let dst = self.class_of(edge.dst);
    if self.node_is_proven_empty(edge.src) { /* unchanged: universal, continue */ }
    let storage = self.storage_class_for_address(edge.src, width, true);
    self.unify_pointees(storage, dst, PROV_MEMORY_MERGING | PROV_SCALAR_OR_UNKNOWN_PAYLOAD);
    self.add_content_edge(storage, dst);
}
EdgeKind::Store => {
    if self.node_is_proven_empty(edge.dst) { continue; }
    let storage = self.storage_class_for_address(edge.dst, width, true);
    if !self.node_may_carry_pointer(edge.src) { continue; }
    if self.node_is_proven_empty(edge.src) { self.set_empty_witness(storage); continue; }
    let src = self.class_of(edge.src);
    self.unify_pointees(storage, src, PROV_MEMORY_MERGING | PROV_SCALAR_OR_UNKNOWN_PAYLOAD);
    self.add_content_edge(src, storage);
}
EdgeKind::Gep { .. } => {
    /* proven-empty base and exact-address branches unchanged */
    let src = self.class_of(edge.src);
    self.unify_pointees(dst, src, PROV_DIRECT_ADDRESS);
    self.add_content_edge(src, dst);
}
EdgeKind::Memcpy { bytes } => {
    /* proven-empty branches unchanged */
    self.unify_pointees(dst_storage, src_storage, PROV_MEMORY_MERGING | PROV_SCALAR_OR_UNKNOWN_PAYLOAD);
    self.add_content_edge(src_storage, dst_storage);
}
```

The GEP content edge is new behavior with a specific purpose: it is what lets the value read in
§4.4 stop consulting the pointee. Today a GEP of an external pointer is external only because
the pointee read recovers it.

### 3.4 Everything that does not change

`AddrOf`, `Assign` (both branches), `register_indirect_calls`, `apply_seeds`,
`seed_main_entry_params`, `process_class`'s push-down and escaped-function blocks,
`consider_indirect_pair`, `bind_indirect_call`, `apply_external_call`, `apply_vararg_call`,
`field_class`, `exact_storage_class`, `storage_class_for_address`, `escape_allocation_fields`,
`join` (apart from merging `content_succ`), `export_classes`, the whole of `finish` in revision
R1, `materialize_points_to`, `allocation_isolation`, `global_address_exposure`,
`violation_exposure`, and `SteensClasses`. The PAG is untouched, so node labels are stable
across baseline and candidate artifacts (§7.2 depends on this).

### 3.5 Debug invariant

Add `has_carrier: bool` and `has_location: bool` to `ClassData`, set at construction (value-like
nodes; object nodes and every synthetic class created by `pointee_of`/`field_class`), OR-merged
in `join`. `join` debug-asserts that it never merges a carrier-bearing class with a
location-bearing class, and `run` asserts at the end that no carrier class has `esc`, non-empty
`global_objs`, or non-empty `fn_objs`. This is the check that would have caught the v1
`target_of requires a Carrier, got Identity` crashes at their source; it costs nothing in release.

### 3.6 Cost model

Per pointer-carrying Load the solver now creates at most one class it did not create before
(`P(V(x))`), shared when the storage side is also absent. v1 and v2 measured the resulting
growth on SQLite at 8.5% and 3.8% respectively over 58,471 baseline pointee classes. Joins fall
(v1: 112,706 to 99,148) because storage classes stop absorbing carriers, and the candidate-pair
work in `process_class` falls with them. Worklist pops rise (v1: 74,399 to 98,078). The v1
stage-Steens wall time on SQLite fell from 38.6 s to 24.7 s. The content-edge scan is linear in
loads + stores + memcpys + GEPs per enqueue of the source class.

The finish-time blowups that sank v2 came from data structures this design does not add.
`storage_roots_by_global`, `global_storage_roots_index`, and the escape-source materialization
are the legacy code paths, operating on strictly smaller classes.

## 4. External, universal, null, and escape facts

### 4.1 Seeds stay where they are

Every seed in `apply_seeds`, `seed_main_entry_params`, `apply_external_call`,
`apply_vararg_call`, and `process_class` already places content facts on carriers and location
facts on pointees:

| Seed | Placed on | Kind |
|---|---|---|
| `IntToPtr` result | `V(r)`: `universal`+`ext` | content |
| `UnknownResultExternal`, external call result, `main` argv/envp, escaped-function params | `V(r)`: `ext` | content |
| external/vararg call argument, `PtrToInt`, `UnknownOperandEscape`, escaped-function return | `P(V(a))`: `esc` | location |
| `ExportedSymbol`/`ImportedSymbol` | object class: `esc` (+ field escape for exports) | location |

v3 §5.3 proposed moving the content seeds onto target identities. That is the change that caused
the v2 explosion and it is explicitly **not** made here.

### 4.2 Push-down and escape closure stay as they are

`(ext ‖ esc)(c) ⇒ ext(P(c)) ∧ esc(P(c))` in `process_class` is a location-level rule: the memory a
possibly-external pointer designates is external memory, and everything reachable from an
escaped cell is escaped. It is unchanged, as are `escape_allocation_fields`, the exported-table
field escape of revision `qwwlllrspmyk`, and the owner/field coherence assertion. Consequently:

- `unknown_callee = ext(P(V(operand))) ‖ targets.is_empty()` is unchanged in form. It becomes
  narrower only when a container stops inheriting `ext`/`esc` from an unrelated container.
- `unknown_callers` (`esc` on a function object's class) and `GlobalResolution.escape_external`
  (`esc` on any class holding the global or its fields) are read from location classes exactly
  as before.
- The jpegoptim cases from revision `opwlnqwsrosl` (`&nofix_mode` stored into `long_options[]`
  that is passed to `getopt_long`) still escape: the external call marks `S(long_options)` and
  its field classes `esc`, and push-down marks `P(field) ∋ nofix_mode` escaped. No carrier is
  involved in that chain.

### 4.3 Every value transfer carries content facts

The carrier-level content facts are sound only if every operation that moves a pointer value
between two cells either joins the carriers or has a content edge:

| Transfer | Mechanism |
|---|---|
| Assign, direct-call bindings (already Assign edges), indirect-call bindings | carrier `join` |
| Assign exact-address shortcut, GEP with exact root | destination is a certified allocation address; cannot be external or forged |
| Load, Store, Memcpy, GEP from an unknown root | content edge |
| seeds | set directly |
| load through a proven-empty address, GEP of a proven-empty base | fail closed to universal (unchanged) |

### 4.4 The node read: carrier-only

`Solver::finish` computes per value node:

```rust
let external  = ext(root) || esc(root) || ext(pointee);      // since 2026-08-31
let universal = universal(root) || universal(pointee);
```

The `pointee` terms were added because two transfers had no carrier-level mechanism: GEP joined
only pointees, and Memcpy joined only contents. Reading the pointee is a sound patch for both
but it reads a *location-class* fact as if it were a value fact, which is the v2 mistake in
another place: `*b = getenv(...)` makes `b` "external" because `ext(S(b))`, and every pointer
whose target class ever absorbed a forged pointer becomes universal.

With the content edges of §3.3, GEP and Memcpy transfer facts at the carrier level, so the read
can return to:

```rust
let external  = ext(root);          // esc(root) is always false on a carrier (§3.5)
let universal = universal(root);
```

The soundness argument is §4.3: an external or forged pointer reaches `x` only along value
transfers, and every transfer now propagates the fact. `reaches_function_pointer` keeps its
existing `ext(pointee)` term, which is a legitimate location read (may the pointed-to cells hold
external function addresses?). `proven_empty`, `pointee_globals`, and the object-side reads in
`materialize_points_to` are unchanged.

This read change is a separate revision (R2 in §8) so that its effect is attributable. It is
expected to move SQLite's stage-Steens module-wide unknown rows from about 45k back toward the
pre-08-31 level; the scratch measurement in §7.2 bounds that expectation.

## 5. Interaction with the Andersen solver

Andersen (`andersen.rs`) consumes Steensgaard through `SteensClasses` and the base
`SolveResult`. Each dependency, and what the change does to it:

| Consumer | Reads | Effect of one-hop |
|---|---|---|
| interesting-partition seeding (`build_scope`) | `ext[class] ‖ esc[class]` per node's class | fewer value classes are `esc` (never) or `ext` (only via content flow); fewer partitions are admitted for escape reasons. Coverage-only: an un-admitted partition keeps its Steensgaard rows. |
| `seed_escaped_function_params` | `esc` on function-object classes | location-level, unchanged |
| prepartition on-the-fly bindings | `base.indirect_calls[*].targets` | narrower sound envelopes: smaller weak components, more admissions, fewer activated targets |
| target discovery envelope | same | same |
| `unknown_callers` for closed consumers, `unknown_callee` merge | `base.unknown_callers`, `steens.unknown_callee` | narrower when a container stops inheriting escape; the closed-consumer certificate has less to clear |
| fallback rows for out-of-scope nodes | `base.nodes` | more precise rows survive into the final result |
| `global_storage`, `global_address_exposed`, `violation_exposure`, `storage_roots`, `exact_addresses` | independent proofs | unchanged |
| admission and partition profiles | `ext_classes`, `esc_classes` counts | diagnostic meaning shifts (fewer ext/esc carriers); note in the metrics docs |

Three points deserve care.

**Envelope narrowing is monotone.** Andersen discovers targets within the Steensgaard envelope
and asserts `Andersen ⊆ Steens` per site in debug builds (`debug_assert_narrows`). The one-hop
envelope is a subset of the legacy envelope for every site, and Andersen's discovery is bounded
by whichever envelope it is given, so the tripwire cannot newly fire from narrowing alone. Exact
B1/B2 overrides are checked against their own envelopes separately and are unaffected.

**Andersen may now be visibly coarser than Steensgaard at some nodes.** Andersen models the
contents of an escaped object field-insensitively (`seed_unknown_store_through` writes an
external region through the whole carrier), so a forged pointer stored into one field can make
Andersen's per-node `external_universal` true where one-hop Steensgaard's is false. The v1 corpus
audit saw this as aborts on `exe-sbase_cal-O0`, `exe-jpegoptim-O*`, and `lib-freetype-O1`
(`FT_Get_Kerning::clazz`); those release assertions no longer exist in the tree, and the
per-node external facts are not covered by `debug_assert_narrows`. Andersen's answer replaces
Steensgaard's for in-scope nodes, so the shipped result at such a node is the coarser but still
sound one. Policy for this work:

- do not change Andersen's external-field model (the narrow repair measured on Placebo ran past
  329 s and 12 GiB);
- add a counter, `andersen_coarser_than_steens_nodes`, incremented in `emit_node_resolutions`
  when Andersen's `external` or `external_universal` is true and the base row's is false, with
  the first few labels printed under `PANGS_ANDERSEN_EXPLAIN_NODE`;
- report the counter per module in the evaluation (§7.5). A production follow-up may take the
  meet of the two sound answers per node; that is a separate decision.

**Escape facts are taken verbatim from Steensgaard, so their narrowing reaches clients
directly.** `unknown_callers`, `GlobalResolution.escape_external`, and `address_escape` do not
pass through Andersen. §6 covers the audit obligation this creates.

Receiver payload summaries, bounded origins, closed-producer certificates, memcpy summaries, and
the exhaustion fallback consume nothing that changes here.

## 6. Consequences for clients and disposition

The change is a refinement: every relation in the one-hop solution is a subset of the legacy
relation (fewer unions at every level, directed instead of symmetric fact flow, identical seeds
and identical push-down). Every observable fact can therefore move in one direction only, and
each direction has a client reading:

| Fact | Moves | Client reading | Obligation |
|---|---|---|---|
| ModRef named rows | fewer (containers stop sharing tags) | precision | budget only |
| ModRef unknown rows via `external` | fewer (R2) or unchanged (R1) | precision | budget only |
| ModRef rows that become *empty* | more: a narrower class exposes a missing producer, and the fail-closed policy emits Ω (`notes/about_missing_producers.md`) | coverage | budget; v1 measured +897 rows, 1.3% of its Ω growth |
| `never_written` | may become true | `immutable` guard: corruption direction if wrong | audit every transition |
| `omega_escaped_address` / `escape_external` | may become false | `immutable` guard: corruption direction | audit every transition |
| `unknown_callers` | may lose functions | localization blocker: corruption direction | audit every transition |
| finite icall target sets | may shrink; `unknown_callee` may clear | call-graph clients: corruption direction if a real callee is lost | audit every removed target; dynamic traces where available |
| `access_set_complete` | may become true | `atomic`/`mutex` certificates | audit |
| phase-stationarity / `initval_stable` | may certify | `once-lock` | audit (v1: 13 SQLite `const` tables became `initval_stable`; all were legitimate) |

"Audit" means: for each transition in the corruption direction, name the legacy witness that
disappeared and show that it was produced by a container merge that the one-hop rules no longer
make, or stop. The v1 SQLite run produced one such item that was never resolved:
`sqlite3Config` moved from `escape=external` to `escape=module`. It is the first entry on the
audit list.

Disposition policy, the manifest schema, the cascade, overrides, and markers are untouched;
they consume facts that become more precise.

## 7. Evaluation

### 7.1 Parallel solvers versus snapshot comparison

Two approaches were considered.

*Parallel old and new solvers in one binary* (the v2 shape). Advantages: one PAG in one process,
so per-node comparisons need no label matching and no build provenance. Disadvantages, all
measured in v2: the second solver needs its own `SteensClasses` adapter or cannot feed Andersen,
so the experimental answer never exercises the production pipeline; the dual run doubles solver
cost and pollutes timing; the scaffolding (stage enum, output separation, adapter) was a large
share of the v2 diff and was thrown away.

*Snapshot and compare across revisions.* Advantages: the candidate is the production pipeline,
Andersen included; artifacts are deterministic JSONL keyed by stable labels because the PAG is
unchanged; `jj` makes the baseline binary a one-line checkout; the triage tooling already exists
(`ju_out/legacy_absent_v2_unknown_20260827/join_modref.py`,
`ju_out/v2_identity_transition_audit_20260827/summarize_transitions.py`,
`analyze_target_reach.py`). Disadvantage: per-node side-by-side needs the two `nodes` maps
joined by label, which is a script.

**Decision: snapshot and compare.** The v2 evidence is that the parallel scaffolding cost more
than the semantics. The one property the parallel approach offered, same-PAG alignment, is
retained by freezing `pangs-pag` across the comparison (§3.4).

No environment knob toggles the old rules. The revision split in §8 provides attribution.

### 7.2 Baseline snapshot

Baseline revision: `stnrlplv` (`c3986d23`, the parent of the working copy; the working copy
differs only in a Markdown file). Build it into a separate target directory, record the binary
SHA-256, and keep it for the whole R1 to R3 series. Current measurements with that code, release
build, `PANGS_POINTER_MODREF_HIGH_FANOUT_LIMIT=256`, `--stage steens`:

| module | mode | wall | max RSS | named rows | unknown rows | pointee classes | joins | pops | max partition |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `exe-tmux-O0` | executable | 3.24 s | 366 MB | 119,010 | 12,272 (12,050 finite-collapsed, 222 finite) | 28,797 | 56,675 / 71,900 | 45,295 | 16,359 |
| `lib-sqlite-O1` | library | 11.89 s | 1.22 GB | 184,743 | 45,464 (45,182 module-wide, 282 finite) | 58,484 | 112,617 / 229,929 | 74,473 | 36,770 |

Scratch check of the read hypothesis (§0, §4.4): the same source with the two `pointee` terms
removed from the `finish` read, everything else identical:

| module | wall | named rows | unknown rows | other artifacts |
|---|---:|---:|---:|---|
| `exe-tmux-O0` | 2.99 s | 119,010 (unchanged) | 706 (601 finite-collapsed, 105 finite) | `functions`, `callgraph` identical; `globals` and `stationarity`: `tty_default_raw_keys` (a `const` table) and `key_bindings_init.defaults` become `initval_stable`/stationary; 34 other stationarity records differ in witness or reason text only |
| `lib-sqlite-O1` | 10.84 s | 158,283 (from 184,743) | 2,989 (2,740 module-wide, 146 finite-collapsed, 103 finite) | `globals`, `functions`, `callgraph` identical; `stationarity`: witness/reason text only, no verdict change |

The pointee-level read accounts for the whole difference between today's 45,182 module-wide rows
and the 2026-08-26 level: removing it alone returns SQLite to 2,740 module-wide rows and tmux from
12,050 collapsed rows to 601. No `never_written`, `escape`, or `unknown_callers` fact and no call-
graph edge moved on either module; the two tmux stationarity gains are precision-direction
transitions of the same shape as v1's thirteen SQLite `const` tables and would go through the §6
audit like any other. The named-row drop on SQLite is the companion rows that a universal access
emits for every global (`push_all_targets` in the ModRef assembly), not a lost finite fact. This
scratch variant is *not* sound on its own, because GEP and Memcpy still lack a carrier-level
transfer; §4.4 is the sound version of the same read, and these numbers are its expected effect.
The scratch binary and its outputs are in the session scratchpad only; the source tree and the
release binary were restored to the baseline hash `08cd90a8…ffe0`.

### 7.3 Protocol

1. Corpus: the 56 `.bc` inputs under `~/pangs-corpus/_out_bc`, build mode from the `exe-`/`lib-`
   prefix. Focused set, run first and after every revision: `lib-parson-O0` (smallest v1
   crasher), `exe-sbase_cal-O0` and `lib-freetype-O1` (Andersen-coarser cases),
   `exe-jpegoptim-O1` (escape soundness fixtures of 2026-08-31), `exe-tmux-O0`,
   `exe-chibicc-O1`, `lib-zstd-O1-g`, `lib-curl-O1`, `lib-sqlite-O1`, `lib-placebo-O1-g` (cost).
2. Two stages per module: `--stage steens` and `--stage andersen --dispose --validate`. Every
   gate is **stage-matched** (Steens against Steens, full pipeline against full pipeline) and
   **knob-matched** (same fanout limit, same experimental Andersen flags, both off). Comparing
   candidate Steens against baseline Andersen, or across the fanout limit, was the confounder
   that made several v2 tables unreadable.
3. Artifacts compared: `modref.jsonl` (key `(func, access, witness, address_node)`; named rows
   also by `global.name`), `globals.jsonl`, `functions.jsonl`, `callgraph.jsonl`,
   `stationarity.jsonl`, `components.json`, `manifest.json`, `metrics.json`, plus `pangs
   icall-census` and `pangs differential` outputs.
4. A debug build of the candidate runs the focused set once per revision, so that
   `debug_assert_narrows`, the field/owner coherence assertion, canonical-null isolation, and
   the new one-hop invariant all execute on real modules.
5. `pangs check-traces` runs on every executable module that has an instrumented test run
   available (chibicc, jq, lua at minimum): no dynamically observed callee may be absent from
   the candidate envelope.
6. Timing: three sequential runs per focused module on a quiet machine; report medians, wall
   and RSS, for Steens-only and for the full pipeline.

### 7.4 Gates

**Hard, audited, no numeric budget.** Each corruption-direction transition from §6 is listed
with its legacy witness and a one-line justification. One unexplained transition stops the
series. Transitions that are explained by a legacy container merge are recorded and accepted.

**Soundness tripwires.** Zero failures in: debug-build focused set; `pangs differential` on
every module that completes; `check-traces`; the unit fixtures of §8 R0; the full
`cargo test --workspace`.

**Numeric budgets** (candidate versus baseline, stage-matched, aggregate over the focused set
unless stated):

- R1: module-wide unknown ModRef rows within ±5%; finite-scope unknown rows may grow by at most
  the count of newly empty answers, which is reported separately.
- R2: module-wide unknown rows must fall on `lib-sqlite-O1`; no module may grow module-wide
  unknown rows by more than 5%.
- Named local ModRef rows: any decrease is expected; a per-module drop above 30% is reported
  with the top ten affected functions so that container-merge false positives can be spot-checked
  against source.
- Disposition: no `unhandled` count may rise on any module; handled coverage (566/1,795 on the
  2026-08-28 corpus) may not fall.
- Cost, Steens stage: geomean wall and RSS within +15%, no module above 2x. Pointee classes
  within +20% per module. Full pipeline: geomean within +10%, since narrower envelopes should
  make Andersen cheaper.
- Andersen: `oversize_fallbacks` may not rise; `andersen_coarser_than_steens_nodes` is reported,
  not gated.

### 7.5 Report

Per revision, one Markdown report under `ju_out/steens_onehop_<date>/` with: binary hashes and
revision ids for both sides; the per-module row/transition tables; the audited transition list;
the tripwire results; timing; and the Andersen coarser-node counter. The final entry goes into
`EXPERIMENT_HISTORY.md`, and `DESIGN_lite.md` §2 C′ gains one paragraph stating the one-hop
rules and the carrier/location invariant.

## 8. Implementation plan

Each revision is one `jj` change with a green `cargo test --workspace`, formatted, and its own
focused-set report. Later revisions are not started until the earlier one's hard gate is clean.

### R0: fixtures and baseline (no solver change)

- Unit tests in `pangs-solve` (the v3 §11 fixtures, kept small):
  - *precision*: two independent pointer tables `NamesA`/`NamesB` routed into two containers
    `CellsA`/`CellsB`; assert that neither source table's class is unified with either
    destination and that the loaded payload still targets `a0`/`b0`;
  - *FN round trip*: `left = p; right = p; return choose ? left : right` with `p = &payload`;
    assert both loads recover `payload` with no Ω and that `P(S(left)) ≡ P(S(right))`;
  - *content-fact flow*: external result stored then loaded is external; forged pointer stored
    then loaded is universal; null stored then loaded has the empty witness; escaped storage
    makes a loaded value external; GEP of an external pointer is external; memcpy transfers all
    three facts; and none of these flow *backwards* into an unrelated value stored into the same
    container;
  - *location facts stay put*: a loaded value's class has no `global_objs`, `fn_objs`, or `esc`;
    an indirect call through a loaded function pointer still binds its targets.
  Under the legacy rules the precision and location-facts tests fail; mark them `#[ignore]`
  until R1 with a comment, or land them in R1. The rest must pass on both.
- Build the baseline binary from `stnrlplv` into a separate target directory; run the focused
  set at both stages; store under `ju_out/steens_onehop_<date>/baseline/`.
- Write the join/transition scripts once, adapted from the existing `ju_out` tools, into
  `scripts/steens_onehop_compare.py`.

Estimate: 150 lines of tests, one script.

### R1: one-hop rules and content edges, reads unchanged

- §3.1 `unify_pointees`; §3.2 `content_succ`, `add_content_edge`, `join` merge,
  `process_class` push, `set_empty_witness` enqueue, removal of `empty_witness_copy_edges`
  and `propagate_empty_witnesses`; §3.3 edge rules; §3.5 invariant and counters
  (`steens_content_edges`, `steens_content_pushes`, `steens_unify_pointees_shared`).
- `finish` unchanged, including the `pointee` read terms.
- Un-ignore the R0 tests. Update any existing test whose expectation encoded container merging
  (candidates: `store_through_unknown_pointer_escapes_stored_targets`,
  `external_output_pointer_load_is_unknown_in_steens_envelope`,
  `trusted_free_does_not_escape_a_freed_containers_pointer_payload`) only after confirming the
  new expectation is the textbook answer; record each such change in the R1 report.
- Gates: §7.4 with the R1 budgets. Expected shape, from v1: named rows down, module-wide
  unknown flat (dominated by the pointee read), Steens wall time down, a small number of audited
  escape/stationarity transitions on SQLite and curl.
- Stop rule: any unexplained corruption-direction transition, any tripwire failure, or Steens
  cost above 2x on any focused module.

Estimate: 150 to 200 lines net in `lib.rs`.

### R2: carrier-only value read

- §4.4: drop the two `pointee` terms in `finish`; keep `reaches_function_pointer`'s pointee
  term; drop the `esc(root)` term or leave it as a documented no-op.
- Regression test: the R0 GEP and memcpy content-fact fixtures are exactly the cases the pointee
  read was added for (`external_pointer_boundary_survives_gep_in_steens_envelope`,
  `universal_pointer_boundary_survives_gep_in_steens_envelope`); they must still pass.
- Gates: §7.4 with the R2 budgets. Expected: SQLite module-wide unknown rows fall by an order of
  magnitude; `unknown_global` taint witnesses and ModRef-driven `access_set_complete` improve;
  no named-row change (the read does not touch pointee sets).
- Stop rule: any module where module-wide unknown rows *rise*, which would mean a value transfer
  without a content edge; find the transfer, add the edge, re-run.

Estimate: under 20 lines.

### R3: Andersen ledger and documentation

- §5 counter `andersen_coarser_than_steens_nodes` in `emit_node_resolutions`, exported in
  `metrics.json` and `schemas/metrics.schema.json`.
- Full-corpus run of the final candidate at both stages; `EXPERIMENT_HISTORY.md` entry;
  `DESIGN_lite.md` §2 C′ paragraph; retire `20260826_SEPARATE_STORAGE_IDENTITY_v3.md` with a
  one-line pointer to this document and the report.
- No solver change.

### Deferred, deliberately

- Taking the per-node meet of Andersen and Steensgaard external facts (§5).
- Any Andersen external-field repair.
- Pending-equality or lazy-materialization schemes for pointee classes: the `(None, None)`
  sharing in `unify_pointees` is the only class-count optimization; §7.4's +20% budget decides
  whether more is needed, and v2's measured 3.8% says it will not be.
- A `PANGS_STEENS_LEGACY_LOAD_STORE` attribution knob. R1/R2 already separate the two effects.

## 9. Risks and fallbacks

| Risk | Signal | Response |
|---|---|---|
| A value transfer without carrier join or content edge | R2 module-wide unknown rows rise somewhere; a content-fact unit fixture fails | add the edge; the §4.3 table is the checklist |
| A legacy escape/unknown-caller fact was load-bearing and disappears | R1 audit finds a transition with no container-merge explanation | stop; the one-hop rule is textbook-sound, so this would be a bug elsewhere (seed placement, push-down) and is fixed there, not by re-merging containers |
| Missing producers surface as Ω | finite-scope unknown rows grow beyond the newly-empty count | expected and bounded (v1: +897); the fail-closed policy is correct; feed the empties to the producer-completeness work, not to this change |
| Andersen coarser than Steensgaard at more nodes | the R3 counter | reported; production meet is a separate decision |
| Content-edge rescans dominate on the largest location class | `steens_content_pushes` ≫ `steens_content_edges` | add the pushed-delta record in §3.2 |
| Class growth beyond budget | `steens_pointee_classes_created` | verify `(None, None)` sharing fires (`steens_unify_pointees_shared`); nothing further is planned |

## 10. Open questions

1. Whether to keep `esc` in the carrier read as a no-op for one revision (belt and braces) or
   remove it in R2 together with the invariant that guarantees it. RESOLUTION: remove, since the
   invariant is asserted.
2. Whether the Andersen interesting-partition seed should switch from `ext ‖ esc` on the node's
   class to `ext` on the class or `esc` on its pointee; today's predicate was written for the
   merged representation. Coverage-only; measure `oversize_fallbacks` and the number of
   interesting partitions in R1 before deciding.
