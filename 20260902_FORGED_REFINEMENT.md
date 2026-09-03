# Forged-Pointer Refinement: Bounding Universal Mod/Ref by Address Exposure

Date: 2026-09-02
Status: implemented and evaluated. Production results are in
`ju_out/forged_refinement_20260902/REPORT.md`. Follows `20260902_STEENS_ONEHOP.md` and the two measurement reports under
`ju_out/steens_onehop_20260902/` and `ju_out/universal_closure_20260902/`.

Implementation note: R1b retains one non-serialized `external_escaped_union` boolean. Removing
every selector, as the original text proposed, cannot preserve the R1 distinction between forged
external rows (which union escaped globals) and plain external rows (whose union is deferred).
Exact source sets and all universal diagnostics were removed as planned.

## 0. Summary

An integer-forged pointer (`inttoptr` result) carries the `universal` marker. Today that marker has
three scope effects, all of which say "any global in the module":

1. `Solver::finish` skips the address-exposure filter on the node's pointee class, so the row
   carries the raw class envelope (1,192 globals on `lib-sqlite-O1`).
2. `finite_or_module_wide` maps the row to `GlobalCandidateSet::ModuleWide`, and
   `push_all_targets` sets every global's bit at the access site.
3. `audit_global_flow` returns `AuditGlobalFlow::ModuleWide`, so violation relevance and audit
   attribution poison every global.

This document replaces all three with one rule:

> A forged-pointer access may touch the address-exposed globals of its pointee class, plus every
> global whose address is externally escaped, plus external memory.

The row stays an unknown row (`via: unknown`, `omega:steens_external`) and becomes
`GlobalCandidateSet::Finite`. Once scope no longer depends on it, the `universal` marker has no
consumer that `ext` does not already cover: every setter sets `ext` in the same statement, and
Andersen's admission gates read the `IntToPtr` seeds directly. A second revision therefore removes
the marker, its source-set propagation, and the diagnostics built on it. The `IntToPtr` seed kind,
the violation finding, the `PtrToInt` validation, and Andersen's provenance-separated
`ForgedPointer` region remain; the region simply stops being "universal".

Measured ceiling on SQLite (`ju_out/universal_closure_20260902/sqlite_universal_ceiling.tsv`):
43,113 module-wide rows become finite rows over 53 globals, unknown-row identities are unchanged,
and disposition gains three `atomic` certificates and 22 complete access sets. The explicit
escaped-global union adds at most 16 constant globals to that set on SQLite. Corpus-wide,
288,548 module-wide rows in 17 modules are in scope.

Estimated size: under 150 lines net for the scope change across `pangs-solve` and `pangs-api`,
then a net deletion of several hundred lines for the marker removal, plus tests and two paragraphs
in `DESIGN_lite.md`.

## 1. Evidence

From `ju_out/universal_closure_20260902/REPORT.md`:

- Every one of the 288,548 module-wide rows in the 59-module corpus carries at least one exact
  `inttoptr` source. Forty-two modules have none. Module-wide scope is a cliff, not a tax: Lua
  reaches 7,445 rows from 2 seeds, Freetype 16,362 from 3, gifsicle O1 has 1 seed and 4 rows.
- On SQLite, 43,112 of 43,113 rows carry all 13 seeds at once. Leave-one-out ablation moves one
  row. The `universal` bit is an OR over a connected closure, so no per-idiom policy can clear it.
- Demoting all 13 seeds to ordinary external flow leaves the unknown-row set byte-identical apart
  from detail fields and turns every module-wide row into the same 53-global finite row. The
  Andersen admission structure is unchanged: the 91,618-node component stays oversize, so the
  forged-partition admission gates were never what kept SQLite out of Andersen.
- The 53-global set is the address-exposure filter applied to the class. Address-escaped globals
  outside the class number 16 on SQLite, all constant.

From the client-consumption check (recorded in the same report's discussion): an external row
with `GlobalCandidateSet::Finite` affects exactly its candidate ids. Escaped globals in other
classes are not implicitly unioned anywhere (`crates/pangs-api/src/lib.rs:899`,
`crates/pangs-api/src/lib.rs:5623`, regression test at `crates/pangs-clients/src/lib.rs:5966`).
The only per-global safety net is `access_set_complete`, which fails for any global whose own
`address_escaped` bit is set (`crates/pangs-clients/src/lib.rs:194`).

## 2. The contract

### 2.1 What `universal` means today

`DESIGN_lite.md` §3: "Integer-forged pointers retain a separate universal marker and therefore
never narrow module-wide mod/ref" and "Universal external rows bypass the filter." §2 F:
"Universal or assumption-tainted flow remains module-wide." The intent was that an integer can
equal any address, so a forged pointer can designate any allocation.

### 2.2 What the document already commits to

The same section adopts a provenance contract for integers:

- `ptrtoint` validation is use-sensitive and fails closed; every non-exempt `ptrtoint` seeds `esc`
  on its pointee class with a named source (`apply_seeds`, `crates/pangs-solve/src/lib.rs:1955`).
- The address-exposure proof treats `ptrtoint`, memcpy and memset operands, stores as a value,
  calls, returns, initializer capture, export, and unknown operations as exposing every root they
  can carry. A global is unexposed only when every producer and use of its address is a direct
  access operand, a same-root GEP or assignment, or the argument of a recognized `free`.
- `allocation_isolation` treats `PtrToInt` seeds as boundaries and separately closes over
  reachability from `IntToPtr` seeds (`crates/pangs-solve/src/lib.rs:561` onward).
- "Numeric layout leakage, address hashing, and other integer-only observations are outside the
  supported clients." The paired-subtraction shape is accepted with a named theoretical hole.

Under that contract, an integer that becomes a valid pointer to module global `g` was derived from
an address of `g` that was integerized inside the module or handed to external code. The first
case makes `g`'s class `esc` with a `PtrToInt` source, which the isolation proof does not clear.
The second case is `escape_external`. Both cases expose `g`. Therefore:

```text
targets(forged p) ⊆ exposed(class(P(p))) ∪ { g | escape_external(g) } ∪ Ω_external
```

The only thing the old "any global" scope covered beyond this is a program that computes a module
address from layout knowledge without ever converting one. The document already places such
programs outside the supported set.

### 2.3 What does not change, and what waits for R1b

- All Ω seeds, the `IntToPtr` violation finding, and the `PtrToInt` validation are untouched.
- In R1 the `universal` flag, `universal_sources`, the push-down `universal(c) ⇒ universal(P(c))`,
  and the content-edge transfer are untouched. After R1 they feed diagnostics only; R1b removes
  them (§4.6).
- `reaches_function_pointer` and `proven_empty` keep their `universal` terms through R1. Both are
  redundant with the `ext` terms beside them, because `set_universal_ext_with_sources` always
  sets `ext`, and a forged pointer that is called, dereferenced, or passed out acquires a pointee
  that push-down marks `ext`. R1b deletes the terms.
- `ViolationExposure::ModuleWide` (opaque inline assembly) keeps its filter bypass. That is a
  different contract: assembly with embedded symbol references really can name any global.
- The Andersen admission gates on `forged_partitions` (`andersen.rs:1649`) are not changed in this
  work. They are computed from the `IntToPtr` seeds, not from the marker, so R1b does not touch
  them either. The ceiling showed they have no effect on SQLite's structure; changing them is a
  separate decision with its own cost measurement.

### 2.4 Why an explicit union, not the external-row convention

External rows already rely on the convention "named candidates plus Ω, where Ω membership is read
per global from `address_escaped`." Demoting forged rows to that convention would be exactly as
sound as external rows are today. But the check in §1 showed that only `access_set_complete`
consults the per-global bit; registry, read/write, violation relevance, and access-site effects do
not. Rather than make forged rows inherit a question this work did not open, the row unions the
escaped set explicitly. The cost is 16 constant globals on SQLite. Whether external rows should do
the same is an open question recorded in §8, not a prerequisite.

The union uses `escape_external`, not `address_escaped`. `address_escape` excludes a global's own
export source; an exported global in library mode is reachable by any external pointer and must be
in the set.

## 3. Row semantics after the change

| Row property | Today (forged) | After |
|---|---|---|
| `global.unknown` | `omega_load` etc. | unchanged |
| `via` | `unknown` | unchanged |
| `detail` `omega:` | `steens_external` (+ provenance) | unchanged, plus `escaped_union=N` |
| `detail` `universal_sources=` | present | unchanged in R1; removed in R1b |
| `candidate_scope` | `module-wide` | `finite` or `finite-collapsed` |
| `pointee_globals` sample | unfiltered class members | filtered class ∪ escaped |
| `pointee_global_count` | unfiltered count | filtered ∪ escaped count |
| `prefilter_pointee_count`, `address_filtered_count` | absent | present when filtering removed members |
| `AccessSite` bits | all globals | filtered ∪ escaped |
| `AuditGlobalFlow` | `ModuleWide` | `Finite(filtered ∪ escaped)` |
| `pointee_provenance` `universal_origin` | present | unchanged in R1; removed in R1b |
| `NodeResolution.external_universal` | true | unchanged in R1; field removed in R1b |

The union set is one bitset per module, computed once. It is the same for every forged row, so
`pointee_global_bits` caching by class key still works with the union folded in at the cache
boundary.

## 4. Implementation guide

### 4.1 `pangs-solve`: `Solver::finish`

At `crates/pangs-solve/src/lib.rs:2269`:

```rust
if matches!(self.violation_exposure, ViolationExposure::ModuleWide)
    || summary.universal
{
    return (unfiltered, SharedStringList::default());
}
```

Drop the `|| summary.universal` arm. Forged nodes then go through the exposure filter like every
other node, and `pointee_globals_unfiltered` carries the envelope for differential checks as it
does for external rows. Nothing else in `finish` changes in R1: `external_universal` is still
exported on `NodeResolution`, `universal_sources` is still collected, and `pointee_provenance`
still labels `UniversalOrigin`. All three go in R1b.

The escaped-global union is not done here. The solver's `GlobalResolution` map is produced by the
same `finish`, but the union belongs at the row-assembly boundary where the bitset already exists.

### 4.2 `pangs-api`: candidate scope

Build the union bitset once where the per-global escape state is already materialized, in the
caller of `push_pointer_modrefs_from_pag` (`crates/pangs-api/src/lib.rs:1736`, immediately after
the loop that sets `global.escape` from `solved.globals`):

```rust
let escaped_external_bits: Rc<[u64]> = global_target_bits(
    global_lookup.len(),
    globals.iter().filter(|g| g.escape == EscapeStatus::External).map(|g| &g.key),
);
let escaped_external_ids: Rc<[GlobalId]> = /* same set as ids */;
```

Pass both into `push_pointer_modrefs_from_pag` and `push_pointer_memset_modrefs_from_pir`.

Then, at each of the four read sites:

| Site | Today | After |
|---|---|---|
| `build_modref_node_summary_data` (`:5267`) | `pointee_global_ids/bits` from `resolution.pointee_globals` | when `resolution.external_universal`, OR `escaped_external_bits` into `pointee_global_bits` and merge `escaped_external_ids` into `pointee_global_ids`; record `escaped_union_count` |
| local access sites (`:5633`) | `if summary.external_universal { push_all_targets } else { push_target_bits }` | always `push_target_bits` |
| memset access sites (`:5877`) | same shape | same change |
| `finite_or_module_wide` (`:6858`, called at `:5722` and `:5984`) | `ModuleWide` when `external_universal` | delete the function; callers construct `Finite` directly |
| `audit_global_flow` (`:2487`) | `return ModuleWide` when `external_universal` | fall through and extend `globals` with the union set |

`GlobalCandidateSet::ModuleWide` remains in the type. It is still produced for
`ViolationExposure::ModuleWide` rows and is the `Default`. Every client `match` arm stays as it is.

Detail string: `modref_detail_with_external_suffix_and_pointee_count` reports the unioned count;
`append_address_filter_counts` now fires for forged rows because `unfiltered_pointee_global_count`
differs from the filtered count. Add `escaped_union=N` after the filter counts so a reader can
reconstruct the class-only count.

### 4.3 `pangs-solve`: Andersen node emission

At `crates/pangs-solve/src/andersen.rs:4194`:

```rust
let global_indices = if external_universal || violation_module_wide {
    global_indices_unfiltered.clone()
} else { /* filter by address_exposed */ };
```

Drop `external_universal ||`. Andersen's `external_universal` stays true for nodes whose points-to
set contains a `ForgedPointer` region, so the `universal_sources` export and the
`andersen_coarser_than_steens_nodes` counter keep working. The escaped union is applied in
`pangs-api` for Andersen rows exactly as for Steensgaard rows, because both flow through the same
`NodeResolution` map.

`debug_assert_narrows` compares Andersen's per-node global list against Steensgaard's. Both sides
are now filtered, so the assertion keeps its meaning.

### 4.4 Tests

Existing tests whose expectations encode the bypass:

- `universal_or_violation_tainted_enumeration_keeps_unexposed_globals`
  (`crates/pangs-solve/src/lib.rs:4292`). Split: the violation-tainted half keeps `["closed",
  "exposed"]`; the universal half now expects `["exposed"]` filtered and `["closed", "exposed"]`
  unfiltered, with provenance still `UniversalOrigin`.
- `forged_indirect_operand_retains_unknown_fallback_provenance` (`andersen.rs:7266`) and the
  `val:main:%forged` assertions near `andersen.rs:7532`. These test `external_universal` and
  fallback provenance, which do not change. Confirm they pass unmodified; if one asserts a
  `ModuleWide` candidate set, that assertion moves to the new expectation.
- `modref_summary_counts_module_wide_rows_by_universal_source`
  (`crates/pangs-cli/tests/pipeline.rs:1520`). Its fixture will produce zero module-wide rows.
  Keep the summary's `universal_sources` histogram over all unknown rows instead of module-wide
  rows only, and update the expected counts.
- The `pangs-api` and `pangs-clients` fixtures added with the `universal_sources` export (load,
  store, memcpy meet, memset, transitive closure). Their `candidate_scope` expectations change
  from `module-wide` to `finite`.

New fixtures in `pangs-api/tests/analysis.rs`:

- *forged row is exposure-filtered*: an `inttoptr` result stored through a slot whose class also
  holds an unexposed global `closed` and an exposed global `open`; the load's unknown row names
  `open` only and its `address_filtered_count` is 1.
- *forged row unions escaped globals*: same module plus a global `leaked` whose address is passed
  to an external call and never enters the forged class; the row names `open` and `leaked`, with
  `escaped_union=1`.
- *forged row in library mode includes exported globals*: exported `table` is in the union even
  when its only in-module uses are direct accesses.
- *violation exposure still bypasses*: opaque inline assembly in the same module returns the row
  to `module-wide`.
- *access sites match rows*: `Analysis::affected_globals` for the forged row equals the union set,
  and `access_set_complete` for a global outside the union is unaffected by the row.

### 4.5 R1b: removing the marker

Everything below is a deletion or a rename. No output other than the named diagnostic fields may
change, which is the R1b gate (§5).

`pangs-solve`, `lib.rs`:

| Item | Action |
|---|---|
| `ClassData.universal`, `ClassData.universal_sources`, `ClassData.content_pushed_universal_sources` | delete |
| `set_universal_ext_with_source`, `set_universal_ext_with_sources` | replace every call with `set_ext`; the `IntToPtr` seed arm in `apply_seeds` becomes an ordinary `ext` seed |
| `join` merge of `universal` and the source-set swap | delete |
| `process_class`: the `if universal { set_universal… } else { set_ext }` branch and the `universal` arm of the content push | collapse to `set_ext`; the frontier keeps `content_pushed_ext` and `content_pushed_empty` only |
| `finish`: `universal` in the cached summary, `!universal` in `proven_empty` and `pointee_is_empty`, `|| universal` in `reaches_function_pointer`, the `(mask, external, universal)` provenance key, `universal_sources` on `NodeResolution` | delete; the provenance key becomes `(mask, external)` |
| `PointeeProvenance::UniversalOrigin` and `pointee_provenance_labels`'s `universal` parameter | delete |
| `SteensClasses.universal` and its fill in `export_classes` | delete; no production code reads it (the only reader is a canonical-null test assertion) |
| `NodeResolution.external_universal` | delete |
| canonical-null assertion `!universal` | delete the conjunct |
| `ProvenanceId` interning | keep; `escape_sources` still uses it |

`pangs-solve`, `andersen.rs`:

| Item | Action |
|---|---|
| `ExternalRegion::is_universal`, `Solve::is_universal_external` | delete |
| `ExternalRegion::ForgedPointer(id)` | keep as a distinct region; it still prevents forged and external-return values from aliasing merely by both being Ω |
| `external_universal` and `universal_sources` on the node result, the `omega:inttoptr:` source reconstruction near `:4275`, and the `external_universal` half of `andersen_coarser_than_steens_nodes` | delete; the counter keeps its `external` half |
| `global_indices` filter (`:4194`) | already reduced to `violation_module_wide` in R1 |
| `PANGS_ANDERSEN_EXPLAIN_NODE` output | drop the `external_universal=` field |

`pangs-api`:

| Item | Action |
|---|---|
| `ModRefNodeSummaryData.external_universal`, `.universal_sources`, `append_universal_sources` | delete |
| `NodeResolution` serialization of `external_universal` and `universal_sources` | delete; `NodeResolution` is not written to any artifact file, so no schema changes |
| `audit_global_flow` | the `external_universal` arm was already removed in R1 |
| `external_policy_census.rs`: `ForgedPointerSeedRow`, `forged_pointer_groups`, the `feasibly_certifiable` and `bounded_constant_candidate` counts, and the `omega:inttoptr` case in `stable_principal_source` | delete the forged-group machinery; keep the census itself. Its question (which seeds make rows module-wide) has no instances after R1 |
| `pangs-clients`: `module_wide_leave_one_out`, `module_wide_remove_all_counterfactual`, `feasible_forged_groups_counterfactual`, `bounded_constant_groups_counterfactual` | delete; they were the scaffolding for the 2026-09-02 ceiling measurement, and the measurement is recorded |
| `pangs modref-summary` | keep the unknown and module-wide counts; drop the per-source histogram |
| `schemas/` | no change; no schema mentions `universal`, and `modref.schema.json`'s `detail` is free text |

Tests: the fixtures added with the `universal_sources` export (`modref_summary_counts_module_wide_rows_by_universal_source`, the load/store, memcpy-meet, memset, and transitive-closure fixtures) are deleted with the feature. `forged_indirect_operand_retains_unknown_fallback_provenance` and the `val:main:%forged` assertions keep their `external` and fallback checks and lose the `external_universal` ones. `universal_pointer_boundary_survives_gep_in_steens_envelope` becomes a second external-boundary GEP fixture whose seed is an `inttoptr`, asserting `external` and the finite candidate set. The R0 fixtures of §4.4 are unaffected.

What R1b must not remove: the `IntToPtr` and `PtrToInt` seed kinds and their PAG lowering, the `fnptr_inttoptr` violation finding and every other conversion finding, the `ptrtoint` use-sensitive validation, the reserved non-address integer contract, and the provenance-only integer origin recovery for the storage-root certificate. Those are the contract of §2.2; the marker was only one of its consumers.

### 4.6 Documentation

`DESIGN_lite.md`:

- §2 F, "Universal or assumption-tainted flow remains module-wide" becomes "Assumption-tainted
  flow remains module-wide. Integer-forged flow is bounded by address exposure plus the
  externally escaped globals (§3)."
- §3, replace "Integer-forged pointers retain a separate universal marker and therefore never
  narrow module-wide mod/ref" with a paragraph stating the contract of §2.2 above, and replace
  "Universal external rows bypass the filter" with "Only module-wide violation exposure bypasses
  the filter; forged rows are filtered and then unioned with every externally escaped global."
- §2 C', the push-down paragraph added on 2026-09-02, drops "universal" from the list of pushed
  facts once R1b lands.
- §3, the Ω-region paragraph: "integer-forged pointers have distinct identities" stays;
  "retain a separate universal marker" goes.
- §2 F, "Rows distinguish direct, aliased, finite-unknown, and universal-unknown provenance"
  loses its last item.

`EXPERIMENT_HISTORY.md` gets the final entry (§7). `schemas/modref.schema.json` needs no change:
`candidate_scope` keeps its three values and `detail` is free text.

## 5. Revisions

### R0: fixtures and baseline

- Land the §4.4 fixtures marked `#[ignore]` with a comment naming this document, except the
  violation-exposure fixture, which passes today.
- Baseline binary: the current tip after the `universal_sources` export (corpus SHA
  `ad990866…93ef`). Run the ten-module focused set from the one-hop protocol at both stages,
  plus `exe-vim-9.2-O1`, `lib-openssl-4.1.0-O1`, `exe-lua-O1`, and `lib-cairo-O1-g`, which carry
  the largest module-wide populations after SQLite. Store under
  `ju_out/forged_refinement_<date>/baseline/`.
- Extend `scripts/steens_onehop_compare.py` with a candidate-set comparison: per module, the
  distribution of finite candidate-set sizes for rows that were module-wide in the baseline.

### R1: the change

§4.1 through §4.4 in one revision. The solver and Andersen read changes, the API union, and the
test updates are one semantic change and should not be attributed separately.

Gates, stage-matched and knob-matched as in the one-hop protocol:

- **Hard.** Unknown-row identities (`func`, `access`, `witness`, `address_node`) are unchanged on
  every module. Named rows are unchanged. `unknown_callee`, call-graph edges, `never_written`,
  `escape`, and `unknown_callers` are unchanged. Any movement means the change leaked outside
  candidate scope.
- **Hard, audited.** Every `access_set_complete` transition and every disposition gain is listed
  with its source-level justification: the global's writers are all direct or all in the
  candidate set. On SQLite this is 22 globals and 3 certificates.
- **Budget.** Module-wide rows must reach zero on every module without opaque assembly. The
  largest finite candidate set produced from a formerly module-wide row is reported per module;
  Vim and OpenSSL have no ceiling measurement yet and decide whether the union is small enough to
  be useful there.
- **Cost.** No measurable change expected. The union is one bitset OR per forged row. Report the
  Steens-stage wall time as a sanity check only.
- **Tripwires.** `cargo test --workspace`, debug-build focused set, `pangs differential` on every
  completing module.

### R1b: remove the marker

§4.5 in one revision, after the R1 report is accepted. Doing it separately keeps `universal_sources`
available during the R1 audit and gives the removal a gate of its own:

- **Hard.** Every artifact (`modref.jsonl`, `globals.jsonl`, `functions.jsonl`,
  `callgraph.jsonl`, `stationarity.jsonl`, `components.json`, `manifest.json`) is byte-identical
  to R1 on the full focused set at both stages after deleting exactly three things from the
  comparison: the `universal_sources=` and `provenance=…universal_origin` detail tokens and the
  `external_universal` field. Nothing else may differ. A difference means a read of `universal`
  had semantics R1 did not account for, and the revision stops until it is named.
- **Cost.** Steens-stage solve time should fall slightly, since `process_class` stops cloning a
  `BTreeSet` per pop and `join` stops merging two. Report it; do not gate on it.
- **Tripwires.** As R1.

### R2: corpus and documentation

Full 59-module sweep at both stages, `pangs modref-summary` per module, the §4.6 documentation
edits, the `EXPERIMENT_HISTORY.md` entry, and the retirement note in
`ju_out/universal_closure_20260902/REPORT.md` pointing at the production result.

### Deferred, deliberately

- Applying the escaped-global union to plain external rows (§8.1).
- Changing the Andersen `forged_partitions` admission gates.
- Any per-idiom treatment of `inttoptr` sites, which the leave-one-out result rules out as a
  strategy.
- Library-mode opaque-handle contracts, which address the external half of the residual and are a
  separate design decision.

## 6. Expected impact on SQLite

All figures from `sqlite_universal_ceiling.tsv` and the R2 one-hop artifacts, adjusted for the
explicit union. The ceiling run demoted seeds inside the solver and also disabled the forged
admission exception; R1 does neither, so the Andersen step count is not expected to reproduce.

| Metric | Baseline | Expected after R1 | Basis |
|---|---:|---:|---|
| Steens unknown rows | 43,886 | 43,886 | identities unchanged in ceiling |
| Steens module-wide rows | 43,113 | 0 | ceiling |
| rows over the shared candidate set | 0 | 43,112 | ceiling |
| shared candidate set size | 1,192 (envelope) | 53 to 69 | 53 filtered, plus at most 16 escaped globals outside the class; exact count depends on `escape_external` membership, which was not probed |
| `tmp360` isolated row | module-wide | finite, escaped globals only | ceiling gave empty; union adds the escaped set |
| Andersen module-wide rows | 43,107 | 0 | ceiling |
| Andersen oversize fallback | 1 (91,618 nodes) | 1 (91,618 nodes) | admission gates unchanged |
| named rows | 125,594 | 125,594 | scope-only change |
| `unhandled` | 40 | 37 | ceiling; the 16 extra candidates are constant |
| `atomic` | 0 | 3 | `randomnessPid`, `sqlite3TreeTrace`, `sqlite3WhereTrace` |
| `access_set_complete` | 0 | 22 | ceiling |
| `thread_visible` | 40 | 30 | ceiling |
| `violation_tainted` | 27 | 22 | ceiling, via `audit_global_flow` |
| `omega_escaped_address` | 16 | 16 | escape facts untouched |

Two things the ceiling could not show and R1 must:

- The three atomics and 22 complete access sets are corruption-direction transitions. Each needs
  its writer inventory checked against source before the change is accepted. `sqlite3TreeTrace`
  and `sqlite3WhereTrace` are debug trace masks written through `sqlite3_test_control`;
  `randomnessPid` is written in `sqlite3_randomness`. The check is whether any writer reaches them
  through a pointer whose row is now finite and excludes them.
- The `violation_tainted` drop from 27 to 22 comes from `audit_global_flow` no longer returning
  `ModuleWide`. Those five globals need the same treatment: which violation's candidate set no
  longer names them, and why that is right.

R1b changes none of these numbers. Its only visible effect on SQLite is the disappearance of the
`universal_sources=` token from 43,113 row details and of `universal_origin` from their provenance
labels.

Corpus-wide, 17 modules lose their module-wide rows. The ones to watch are Vim O1 (57,600 rows,
14 seeds) and OpenSSL O1 (46,748 rows, 4 seeds), where the filtered class and the escaped set
have not been measured and may be large enough that the finite row is no more useful to clients
than the module-wide one was. That would not be a soundness problem; it would mean the gain there
is limited to `audit_global_flow` and disposition.

## 7. Report

One Markdown report under `ju_out/forged_refinement_<date>/` with: binary hashes for both sides;
the per-module module-wide-to-finite table with candidate-set sizes; the audited transition list
for every `access_set_complete`, disposition, and `violation_tainted` change; the tripwire
results; and the Vim and OpenSSL candidate-set sizes. Its summary goes into
`EXPERIMENT_HISTORY.md` under the one-hop entry.

## 8. Open questions

1. **External rows.** They rely on the per-global `address_escaped` net rather than naming escaped
   globals. After R1, forged rows will be strictly more explicit than external rows, which is
   backwards from the reader's point of view. Either external rows adopt the same union, and the
   two row kinds collapse into one, or the row contract is written down as it is: named candidates plus an Ω whose members are found only
   through per-global escape bits, with a list of which certificates must consult them. Decide
   after R1, with the corpus union sizes in hand.
2. **Andersen forged gates.** `ANDERSEN_PROVENANCE_PROMOTION_*` and the closed-producer promotion
   both refuse forged partitions. The ceiling shows they do not bind on SQLite. Whether they bind
   anywhere is a cheap corpus count from the admission profiles, and should be taken before
   anyone spends time on them.
3. **Seed attribution after R1b.** If a future investigation needs to know which `inttoptr`
   sites reach a row, the answer is a debug-build reachability pass from the seed set over the
   fixed PAG and the solved classes, not a fact carried through every join. Record that here so
   nobody reinstates the source sets by reflex.
4. **`tmp360`.** The one isolated row (`sqlite3GenerateConstraintChecks`, `IndexIterator` union)
   becomes an empty-or-escaped finite row. Under the fail-closed policy for empty answers it may
   surface as a missing-producer Ω. Confirm which it is in R1 and record it.
