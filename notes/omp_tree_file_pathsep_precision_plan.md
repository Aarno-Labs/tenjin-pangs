# OMP tree `file_pathsep` Precision Plan

This plan records the next implementation work for making
`pangs cc2json` stop reporting `file_pathsep` as a concrete mutated global for:

```text
/home/brk/pangs-corpus/_out_bc/exe-OMP__tree-O0.bc
```

The source cache used during investigation was:

```text
/tmp/tenjin_pytest_repo_cache/https:__github.com_brk_Old-Man-Programmer__tree.git_3f3077dbd87fc89396c8dc74fcf7920ec8b0c7d5
```

## Current Diagnosis

In the C source, `file_pathsep` is defined as:

```c
char *file_comment = "#", *file_pathsep = "/";
```

The observed uses are reads of the global cell, uses of the `char *` value, or reads of
the pointed-to separator bytes. No runtime assignment to the `file_pathsep` global cell
was found.

`cc2json` lists it because `mutated_globals` is derived from `Access::Mod` modref rows,
and the analysis currently emits many aliased mod rows such as:

```json
{"func":"split","global":{"name":"file_pathsep"},"access":"mod","via":"aliased","witness":"split@!noloc#0"}
```

These rows are not caused by the static initializer. PIR lowers global initializers as
`global_ref access=mod` and synthetic stores, including `@file_pathsep = ...`, but the
cc2json renderer intentionally restricts initializer writes out of `mutated_globals`.

They are also not caused by the cc2json syntactic call-argument rule for `strchr` or
`strrchr`: those callees are already in `known_readonly_arg`. The deeper PAG/solver
external-call model is still conservative for external calls, but the concrete
`file_pathsep` rows seen here come from broad pointer-modref expansion over imprecise
address-node pointee sets.

Important current metrics from the default Andersen executable run:

```text
oversize_fallbacks=3
oversize_fallback_max_size=5012
pointer_modref_max_fact_fanout=318
globals_with_complete_initval=0
stationary_globals=0
```

With `--partition-budget 10000000`, `file_pathsep` still appears and one large fallback
remains:

```text
oversize_fallbacks=1
oversize_fallback_max_size=5012
pointer_modref_max_fact_fanout=318
```

So raising the default partition budget is not enough by itself.

## Goal

Make `file_pathsep` absent from `cc2json`'s `mutated_globals` because the analysis no
longer emits false concrete `Access::Mod` rows for it.

Secondary goal: reduce broad concrete pointer-modref spray for the OMP oversized
partition without hiding real concrete writers.

Non-goal: prove all globals in OMP stationary in one pass. This plan is about removing a
specific, well-understood false concrete mutation while improving the general precision
path that created it.

## Phase 1: Add Diagnostics Before Semantics Changes

Add an opt-in diagnostic that explains why the remaining large partition and high-fanout
modref emitters exist.

Minimum useful output:

```text
partition root / size
edge-family counts: assign, load, store, addr_of, gep_const, gep_unknown, memcpy, memset
top address nodes by pointer-modref fanout
top load/store hub classes
sample witnesses for each top hub
contains globals/functions/icall sites
ext/esc bits and omega sources where available
```

Add graph-cut experiments for the largest partition:

```text
without_load
without_store
without_load_store
without_unknown_gep
without_const_gep
without_memcpy_memset
without_external_boundary
without_indirect_bindings
```

These graph cuts are diagnostics only. They should not become analysis modes. Their job
is to identify which edge families keep the oversized component connected.

Suggested entry point:

```text
pangs analyze ... --stage andersen --build-mode executable
```

with environment flags, consistent with the existing pointer-modref profile style:

```text
PANGS_PARTITION_PROFILE=1
PANGS_PARTITION_PROFILE_TOP=20
```

Acceptance for Phase 1:

- A run on `exe-OMP__tree-O0.bc` identifies the address nodes or classes that cause
  concrete `file_pathsep` mod rows.
- The diagnostic distinguishes local stack-slot stores from true global writes.
- The output is small enough to paste into a note or issue.

## Phase 2: Local Stack Promotion / Non-Escaping Alloca Filtering

Implement a cheap local pass before pointer-modref expansion, or a filter inside
pointer-modref expansion, for allocas that are provably function-local.

Candidate rule:

```text
An alloca is local-promotable if every use is through local load/store/gep/bitcast-style
address-preserving operations, it is not returned, not stored into nonlocal memory, not
passed to an external or indirect call, and not reachable from a global initializer.
```

For local-promotable allocas:

- Do not emit global modref rows for stores whose address resolves only to those local
  stack cells.
- Keep any intra-function value-flow needed for call target or return precision.
- Be conservative when a local pointer may alias nonlocal memory.

This is likely the highest ROI for OMP because many false rows are from ordinary stack
slot traffic. Examples include local stores in `split`, where a store to a local variable
is expanded against an imprecise pointee set containing unrelated globals, including
`file_pathsep`.

Acceptance for Phase 2:

- The number of `via:"aliased"` concrete `mod` rows for `file_pathsep` drops
  substantially or to zero.
- No existing synthetic tests regress.
- Add at least one focused fixture:

```c
char *g = "/";
void f(void) {
  char *local = g;
  local = "x";
}
```

The local assignment must not be reported as a mutation of `g`.

## Phase 3: Dynamic GEP Summary Cells

Improve dynamic GEP handling so it does not collapse unrelated memory into one broad
component.

Target behavior:

- Constant offsets keep the existing precise field behavior.
- Dynamic index over a known array-like base maps to a per-base array-summary cell.
- Truly unknown pointer arithmetic keeps the current conservative fallback.

The key distinction is between:

```text
base + dynamic_index_within_known_object
```

and:

```text
unknown pointer arithmetic where the base object is itself unknown or escaped
```

Acceptance for Phase 3:

- OMP's max pointer-modref fanout decreases.
- The largest/fallback partition either splits or has fewer concrete global pointees.
- Existing `m3_2` unknown-offset tests are updated only if the semantics change is
  intentional and documented.

## Phase 4: High-Fanout Modref Reporting Guard

Add a reporting guard for imprecise pointer-modref expansion:

```text
if address-node pointee global fanout > limit:
  emit one unknown omega_store/omega_load row with pointee count/detail
else:
  emit concrete rows
```

This does not prove `file_pathsep` is non-mutated, so it should not be the first or only
fix. It is still useful because naming 318 globals as concrete mutations from one
imprecise address node is misleading.

There is already code for high-fanout fallback in pointer-modref emission. Audit why it
does not trigger in the current OMP run by default, then decide whether the default limit,
phase coverage, or local-row batching needs adjustment.

Acceptance for Phase 4:

- High-fanout sites no longer spray hundreds of concrete global names.
- Unknown rows preserve enough detail for auditing:

```text
source phase
address node label
fanout
occurrence count
sample pointee globals, optionally
```

## Phase 5: Scalar Pointer InitVal / Stationarity

Teach InitVal/stationarity to model scalar pointer global initializers such as:

```text
file_pathsep -> .str.7.419
```

Current stationarity output for `file_pathsep` is:

```json
{"global":"file_pathsep","complete_initval":false,"stationary":false,
 "reason":"incomplete_initval",
 "initval_diagnostics":[{"reason":"no_modeled_pointer_initializer","witness":null}]}
```

Once scalar pointer initializers are modeled, a global like `file_pathsep` can be
certified stationary if all runtime writers are absent or initializer-only.

Acceptance for Phase 5:

- `file_pathsep` has `complete_initval:true` if its initializer is otherwise modeled.
- If Phase 2/3 removes the false runtime writers, stationarity marks it stationary.
- Add a scalar pointer global fixture and a pointer table fixture to avoid conflating
  scalar pointers with aggregate dispatch tables.

## Validation Commands

Baseline reproduction:

```text
cargo run -q -p pangs-cli -- cc2json \
  /home/brk/pangs-corpus/_out_bc/exe-OMP__tree-O0.bc \
  --json-out /tmp/omp_tree.cc2json.json \
  --entrypoints executable
```

Check `file_pathsep`:

```text
python3 - <<'PY'
import json
d = json.load(open('/tmp/omp_tree.cc2json.json'))
print('file_pathsep' in d['mutated_globals'])
print(len(d['mutated_globals']))
PY
```

Export analysis for evidence:

```text
cargo run -q -p pangs-cli -- analyze \
  /home/brk/pangs-corpus/_out_bc/exe-OMP__tree-O0.bc \
  --out /tmp/omp_tree_analysis \
  --stage andersen \
  --build-mode executable
```

Inspect `file_pathsep` rows:

```text
jq -r 'select(.global.name? == "file_pathsep")' \
  /tmp/omp_tree_analysis/modref.jsonl
```

Metrics to watch:

```text
jq '{oversize_fallbacks, oversize_fallback_max_size,
     pointer_modref_max_fact_fanout,
     pointer_modref_rows_unique,
     globals_with_complete_initval,
     stationary_globals}' \
  /tmp/omp_tree_analysis/metrics.json
```

## Final Success Criteria

- `file_pathsep` is absent from `mutated_globals` for the OMP executable run.
- `modref.jsonl` has no concrete `access:"mod"` row for `file_pathsep`.
- If unknown mod rows remain due to genuinely imprecise memory, they are rendered as
  unknown rows rather than concrete `file_pathsep` mutation claims.
- Existing golden and synthetic tests pass.
- New regression fixtures cover:
  - scalar pointer global initialized to a string literal;
  - local stack pointer assignment that must not mutate the source global;
  - external readonly string search (`strchr`/`strrchr`) not causing mutation;
  - a true global pointer-cell write that must still be reported.

## Implemented Outcome

Implemented in this worktree:

- Added `PANGS_POINTER_MODREF_PROFILE_GLOBAL=<global>` as an opt-in pointer-modref
  diagnostic. It prints the top emitters whose pointee set contains the requested global,
  including the address node, fanout, occurrence count, and a small pointee sample.
- Added a PAG pointer-modref reporting filter for precise storage addresses:
  - direct alloca storage accesses are local stack traffic and are not expanded to globals;
  - bare direct global symbols stay suppressed in pointer expansion, relying on `GlobalRef`
    lowering for direct rows;
  - constant GEPs derived from global storage emit the base global instead of expanding the
    pointee contents.
- Lowered the default `PANGS_POINTER_MODREF_HIGH_FANOUT_LIMIT` from `4096` to `16`.
  Impractically broad address-node pointee sets now produce unknown `omega_load` /
  `omega_store` rows instead of many concrete global rows.
- Applied the same high-fanout fallback to the PIR `memset` modref path.
- Added regression fixtures:
  - `fixtures/synthetic/m1_6/precise_storage_modref.pir.json`
  - `fixtures/synthetic/m1_6/high_fanout_modref.pir.json`
- Implemented per-base unknown-offset summary cells in the Andersen solver. Dynamic GEPs now
  route through a summary cell for the base instead of root-wide field collapse. This preserves
  the existing conservative aliasing between dynamic and materialized constant fields, and
  profiles now report `unknown_fields` rather than legacy collapse counts.
- Taught InitVal to treat scalar pointer initializers to data globals as complete
  non-dispatch values. This covers OMP-style lowering where a scalar pointer global stores a
  temp `gep` of a string constant.
- Added regression fixtures:
  - `fixtures/synthetic/m2_4/initval_scalar_pointer_global.pir.json`
  - `fixtures/synthetic/m2_4/initval_scalar_pointer_global_runtime_write.pir.json`
- Added a cc2json regression proving `strchr` and `strrchr` arguments are readonly for
  `mutated_globals`, while a non-readonly call argument is still reported.

Final OMP validation:

```text
cargo run -q -p pangs-cli -- analyze \
  /home/brk/pangs-corpus/_out_bc/exe-OMP__tree-O0.bc \
  --out /tmp/omp_tree_final_verify \
  --stage andersen \
  --build-mode executable

rg '"name":"file_pathsep".*"access":"mod"|"access":"mod".*"name":"file_pathsep"' \
  /tmp/omp_tree_final_verify/modref.jsonl
# no output

cargo run -q -p pangs-cli -- cc2json \
  /home/brk/pangs-corpus/_out_bc/exe-OMP__tree-O0.bc \
  --json-out /tmp/omp_tree_final_verify.cc2json.json \
  --entrypoints executable

jq '.mutated_globals | index("file_pathsep"), length' \
  /tmp/omp_tree_final_verify.cc2json.json
# null
# 48

jq -r 'select(.global == "file_pathsep") | {global, complete_initval, stationary, reason}' \
  /tmp/omp_tree_final_verify/stationarity.jsonl
# {"global":"file_pathsep","complete_initval":true,"stationary":false,
#  "reason":"unknown_runtime_writer"}
```

Final OMP metrics snapshot:

```json
{
  "globals_with_complete_initval": 32,
  "stationary_globals": 0,
  "mutable_globals_total": 86,
  "pointer_modref_high_fanout_fallbacks": 890,
  "pointer_modref_high_fanout_fallback_rows": 24920,
  "pointer_modref_rows_attempted": 7008,
  "pointer_modref_rows_unique": 6689,
  "pointer_modref_pag_rows_attempted": 1407,
  "pointer_modref_pag_rows_unique": 1088,
  "pointer_modref_max_fact_fanout": 622,
  "pointer_modref_pag_max_fact_fanout": 130,
  "oversize_fallbacks": 3,
  "oversize_fallback_max_size": 5012
}
```

Verification:

```text
cargo test -q
# passed
```

Remaining follow-ups from the original plan:

- Phase 3 dynamic GEP summary cells are implemented in Andersen, but the OMP validation did
  not show the intended metric improvement. The remaining broad rows are dominated by
  fallback/imprecise partitions, so this change does not split the oversized OMP component by
  itself.
- `file_pathsep` now has `complete_initval:true`, but it is not certified stationary because
  remaining high-fanout unknown runtime writers conservatively block stationarity. Phase 3 is
  still useful locally, but another partition/fallback precision pass is needed to reduce or
  eliminate those unknown rows in this program.
- The external-call solver model remains conservative; `strchr` and `strrchr` are still only
  known-readonly in the cc2json syntactic call-argument rule, not in the core PAG boundary
  model. The cc2json behavior is now regression-tested.
