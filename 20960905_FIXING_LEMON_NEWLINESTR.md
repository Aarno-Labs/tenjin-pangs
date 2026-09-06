# Fixing Lemon `newlinestr`: recover localization before chasing immutability

## 0. Status and outcome

**Resolved by Work item A on 2026-09-06.**  The shared varargs work was enough on its own.
No new object-sensitive solver, no field-aware content flow, and no content proof were needed.

The target is `translate_code.newlinestr_xjtr_0` in `exe-lemon-O0`:

```c
if( rp->code==0 ){
  static char newlinestr[2] = { '\n', '\0' };
  rp->code = newlinestr;
  ...
}
```

The prediction in this plan was correct.  `newlinestr` was blocked only by
`access_set_complete`, and that block came from a single Ω source: the `va_list` argument of
`lemon_sprintf`.  Once `va_start`, `va_end` and `va_copy` became explicit local operations
instead of opaque intrinsics, the source disappeared, the access set closed, and the existing
localization plan succeeded unchanged.

`newlinestr` is now `localize`, with localization verdict `ok` and zero blockers.  That meets
the acceptance stated in §3.  The other Lemon array, `tplt_open.templatename_xjtr_0`, did
better: it is now `immutable`.  Measurements are in §3.1.

The varargs work landed in revisions `vulo` ("Improve handling of varargs") and `kovx`
("Model `llvm.va_copy` instead of leaving it an opaque intrinsic").  Its plan document,
`20260905_EXT_VARARGS_CONTRACT.md`, was deleted once the work was done; references to it below
mean those two revisions.

Per the stopping rule in §7, work stops here.  Work items B, C and D are **not** to be
implemented for this target.  They stay in this document as a record of what was considered
and why it turned out to be unnecessary.

The filename intentionally follows the requested `20960905_...` spelling.

## 1. Measured baseline (superseded, see §3.1)

The validated 2026-09-05 Andersen run used:

```text
/home/brk/pangs-corpus/_out_bc/exe-lemon-O0.bc
--stage andersen --build-mode executable --dispose --no-overrides
default conservative integer-pointer policy
```

Facts as of 2026-09-05.  §3.1 has the current ones:

```text
chosen                     unhandled
written                    true
  representative witness  Action_add:1730
omega_escaped_address      true
  selected source          UnknownOperandEscape at lemon_sprintf's va_list
access_set_complete         false
violation_taint             true (fnptr_varargs_internal_unmodeled)
phase_stationarity          access-set-complete, never-quiescent, violation-taint
localization                ctx0001, blocked only by access-set-complete
atomic access sites         1,147
```

The named ModRef surface is 121 rows across 75 functions: 47 Mod and 74 Ref, all aliased.
Steensgaard has 137 rows across 88 functions (58 Mod and 79 Ref), so Andersen removes only a
small part of the contamination.  The Andersen solve itself is complete: 6,966 partitions,
maximum partition size 140, zero oversize fallbacks, one round.  Raising the partition budget
cannot fix this case.

`PANGS_ANDERSEN_RECEIVER_PAYLOADS=1` produces exactly the same final distribution and the same
facts for both Lemon arrays.  The prototype recognizes receiver-style setter/getter families
called on multiple exact roots; Lemon's direct `rp->code` store/load pattern is not that shape.

The relevant PAG path starts precisely:

```text
obj:global:translate_code.newlinestr_xjtr_0
  --AddrOf--> sym:global:@translate_code.newlinestr_xjtr_0
  --Gep(0)--> %translate_code::tmp1
  --Store-->  %translate_code::code

%translate_code::code = Gep(%translate_code::rp, 56)
```

Thus the initial modeling is correct: the array address is stored in the `code` field of a
`struct rule`.  Precision is lost later, when pointer contents are transported from that field
through the rule graph and conservative address classes/boundaries.

## 2. Why “prove immutable” is the wrong first target

The representative `Action_add` writes are false aliases: an action-object field cannot modify
the two-byte global array.  Better field/payload precision should remove those rows.

However, even perfect field points-to precision leaves a harder source-level ambiguity.  Later
in `translate_code`, `cp` ranges over `rp->code`; for identifier-looking spans the function
temporarily executes:

```c
saved = *xp;
*xp = 0;
...
*xp = saved;
```

For the concrete `newlinestr` value, the loop sees `\n` and the alphabetic branch is never
taken.  A flow-insensitive pointer analysis sees `rp->code == &newlinestr[0]` and a store through
a derivative of `rp->code`, so treating a residual write as possible is sound.  Proving it
unreachable requires path and byte-content reasoning.  Proving that the value is restored is
not enough for an immutable Rust static: temporary mutation would still be illegal.

Localization does not need a never-written proof.  It needs a complete inventory of every place
where the address/value may be used so those uses can be rewritten.  The current localization
graph already reports no blocker other than completeness.  Therefore the desired near-term
outcome is `localize`, not necessarily `immutable`.

## 3. Work item A: take the shared varargs fix first (done)

*Done.  The plan below is kept as written; the result is in §3.1.*

Implement `20260905_EXT_VARARGS_CONTRACT.md` and rerun Lemon before changing field logic.  Record:

- all `newlinestr` external/Ω sources, not only the selected witness;
- `omega_escaped_address`, `access_set_complete`, and violation relevance;
- named Mod/Ref row and function counts;
- the localization component and blocker list; and
- the final disposition.

The `fnptr_varargs_internal_unmodeled` finding blocks immutable/once-lock/atomic/mutex but is
already an allowed localization-only violation kind.  Once the same callsites are proved by the
shared vararg summary, the finding should disappear anyway.  If `access_set_complete` becomes
true, expect `localize`; stop there unless immutable precision is independently valuable.

Acceptance for this work item, **met**:

```text
newlinestr localization verdict = ok
chosen disposition             = localize (or an earlier independently certified strategy)
```

Do not require its aliased ModRef set to become tiny.  A large but finite, complete rewrite set
is acceptable for localization, and the manifest already says the resulting context component
has no other blocker.

### 3.1 Measured outcome (2026-09-06)

The §1 command was run twice: once with the sources of `ptrw`, the revision just before the
varargs work, and once with the current sources.  For `newlinestr`:

| | before | after |
|---|---|---|
| chosen disposition | `unhandled` | **`localize`** |
| `written` | true | true |
| `omega_escaped_address` | true | **false** |
| selected Ω source | `UnknownOperandEscape` at `lemon_sprintf`'s `%arraydecay1` | none |
| `access_set_complete` | false | **true** |
| `violation_taint` | true (`fnptr_varargs_internal_unmodeled`) | **false** |
| localization | `ctx0001`, blocked, 1 blocker | **`ctx0001`, ok, 0 blockers** |
| named ModRef rows | 121 (47 Mod / 74 Ref) over 75 functions | 108 (34 Mod / 74 Ref) over 75 functions |
| atomic access sites | 1,147 | 1,112 |

`tplt_open.templatename_xjtr_0` carried the same selected witness and moved further.  Its named
surface fell to 2 Ref rows over 2 functions with no Mod row at all, so `written` became false
and the cascade selected `immutable` at the first strategy.

Across the whole module, three of 29 keyed globals changed disposition and all three improved:

- `translate_code.newlinestr_xjtr_0`: `unhandled` → `localize`
- `tplt_open.templatename_xjtr_0`: `unhandled` → `immutable`
- `emsg_xjtr_0`: `localize` → `immutable`

Nothing regressed.  Module counters:

| | before | after |
|---|---|---|
| `unhandled` globals | 2 | **0** |
| audit findings | 39 | **0** |
| modeled `llvm.va_start` / `llvm.va_end` | 0 / 0 | 2 / 2 |
| `unknown` statements | 4 | **0** |
| unique pointer ModRef rows | 5,284 | 5,049 |
| analysis wall time | 0.78 s | 0.56 s |
| partitions / max size / oversize / rounds | 6,966 / 140 / 0 / 1 | 7,033 / 140 / 0 / 1 |

The solve was already complete before the change and is still complete after it, which confirms
§1: the partition budget was never the problem.  The gain came entirely from removing four
`unknown` statements — the two `va_start` and two `va_end` calls — that had been escaping their
operands.

The 34 surviving Mod rows are still the false `Action_add` alias family described in §2, and
`written` is still true.  That no longer matters.  Localization does not need a never-written
proof.  It needs a complete inventory of the accesses, and the inventory is now complete.  This
is the outcome §2 argued for.

`cargo test --workspace --all-targets` is green.

## 4. Work item B: explain the first remaining open terminal (not needed)

*Work item A made the access set complete, so this was never started.  Kept as a design record.*

If Work item A does not make the access set complete, add a narrow diagnostic to the existing
allocation-isolation/address-flow proof rather than inferring the cause from row counts.

Suggested interface:

```text
PANGS_EXPLAIN_ALLOCATION=translate_code.newlinestr_xjtr_0
```

For the selected global, retain one predecessor per address-flow state and print JSONL records
for:

- every store of the global address as a value: destination carrier, certified allocation root,
  `FieldLocation`, and access width;
- every store-to-load content transfer used by the proof: why the two memory addresses may
  alias, their roots/regions, and whether the relation came from exact overlap, unknown offset,
  whole-object access, memcpy, or class fallback;
- the first terminal that rejects address isolation: external call and contract status,
  return to an unknown caller, unknown operation, vararg boundary, `ptrtoint`, container escape,
  or resource limit;
- every store through a derivative of the global address, reported separately from address
  escape; and
- whether every node/edge on the path was inside a complete Andersen partition.

This can remain an environment-gated diagnostic and should not add long-lived data to every
`SolveResult`.  The explanation must identify a concrete path from `&newlinestr` to the terminal;
the current `pointee_provenance` labels (`memory_merging`, `call_return_merging`, and so on) are
useful summaries but are not enough to choose a fix.

### 4.1 Corpus census

Use the same machinery in a bounded `stored-global-address` census.  Emit one row for each
defined global whose address is stored into memory, with:

- global and source store;
- destination root/field exactness and number of compatible loads;
- Steensgaard versus Andersen address-escape result;
- whether Andersen was complete for the entire candidate flow;
- first open terminal category and path length;
- number of named Mod/Ref rows/functions at both tiers;
- `access_set_complete`, localization's non-completeness blockers, and disposition; and
- whether the receiver-payload experiment changed the result.

This census answers whether the refinement is a reusable corpus feature or a Lemon-only corner.
It should be a small standalone/reporting path, not a revival of the removed general
`external-policy-census` or a permanent parallel analysis API.

## 5. Work item C: field-aware content flow in allocation isolation (not needed)

*Not started: §7 requires an explanation diagnostic and a corpus census before this is justified,
and Work item A removed the reason to run either.  Kept as a design record.*

The current independent `allocation_isolation` proof follows pointer values stored in module
memory to loads through conservative alias-equivalent address components.  That is sound but can
transport `&newlinestr` from `rule.code` into unrelated payloads after an address class widens.

Refine only the store-to-load matching relation.  Reuse the existing
`exact_allocation_addresses`, `FieldLocation`, `FieldRegion`, access-width, and
`FieldRegion::may_overlap` machinery:

1. For each pointer-bearing Store, describe its destination as
   `(possible allocation roots, FieldRegion)` when this is completely known.
2. Do the same for each pointer-bearing Load source.
3. Flow the stored pointer value to the load result only when the root sets intersect and the
   regions may overlap.
4. If either root set is incomplete, the address has an unknown offset/extent, a whole-object
   operation may overlap it, or the relevant Andersen partition is absent/incomplete, use the
   current component-wide relation unchanged.
5. A containing object passed to an uncontracted external call remains an open terminal for all
   captured pointer fields.  Field precision must not hide container escape.
6. Keep address escape and write isolation separate.  A store *through* a derived global address
   invalidates the write proof but does not by itself publish the address.

The safest implementation order is to improve the Steensgaard-side independent proof first,
because final global escape facts are currently retained from the base result even when Andersen
refines node points-to and ModRef rows.  If Steensgaard cannot prove the memory channel, an
optional second implementation may use complete Andersen points-to sets as a dedicated
allocation-address certificate:

- seed `&g` and traverse only modeled transfers;
- use refined store/load overlap for admitted nodes;
- require every reachable transfer and terminal to be in scope and the entire solve to be
  complete;
- reject on any fallback/unadmitted node; and
- use the result only to narrow that global's `address_escape`/completeness fact, not to erase
  unrelated Ω behavior.

That second path changes the current rule that global escape facts remain Steensgaard-owned and
therefore needs a `DESIGN_lite.md` update and an explicit refinement-order assertion.

### 5.1 Tests

- `&g` stored in exact field 8, loaded from field 8, passed to a modeled read-only sink:
  address closed and complete;
- same store, load from disjoint exact field 16: no value flow;
- load through Unknown offset overlapping field 8: value flows;
- unknown root, unknown width, whole-object memcpy, or overlapping byte range: fall back and
  preserve flow;
- containing object passed externally: `g` remains escaped;
- loaded pointer passed to an uncontracted external call, returned to an unknown caller, stored
  in externally reachable memory, converted with `ptrtoint`, or invoked: reject;
- store through the loaded pointer: address may remain closed, but write isolation fails;
- sibling object at the same allocation site: do not claim per-instance separation without a
  certified receiver/allocation context;
- forced Andersen exhaustion or excluded partition: no refined certificate;
- Lemon-shaped fixture with a global string stored in `object.code` and unrelated stores to
  `action.*`: the unrelated stores no longer become writes to the string.

Run these tests at Steensgaard and Andersen stages and assert that every failure mode returns to
the current conservative answer.

## 6. Optional work item D: immutable-content proof (dropped)

*Dropped.  §7 says not to implement this merely to turn a sound `localize` into `immutable` for
one two-byte array, and that is now exactly what it would be.*

Only pursue this if there is measured value in selecting `immutable` instead of `localize`.
Field-aware points-to alone cannot prove Lemon's guarded temporary stores unreachable.

A sufficient proof would need bounded symbolic execution over the exact global byte initializer:

- the only candidate base is the fixed two-byte array;
- all pointer arithmetic remains within its known bounds;
- branch conditions controlling every store are evaluated over those bytes;
- loops have a finite, proved bound; and
- no external/unknown mutation can change the bytes before the check.

For `newlinestr`, this can show that `ISALPHA('\n')` is false and the store branch is unreachable.
The analysis is specialized, target/libc-sensitive, and substantially more complex than the
single disposition it improves.  Do not replace it with “the store restores the byte,” a
source-name allowlist, or an assumption that initialized character arrays are immutable.

An explicit accepted-risk override could force localization, but it is not an analysis fix and
should not be used to validate this proposal.

## 7. Evaluation and stopping rules

The stopping rule was: *stop after Work item A if `newlinestr` becomes localizable.*  It did,
so only the first two variants were ever evaluated.

| Variant | Purpose | Status |
|---|---|---|
| baseline | current default | measured, §3.1 |
| varargs | revisions `vulo` and `kovx` | measured, §3.1 — **rule fired here** |
| varargs + field-flow | Work item C, only if still needed | not needed, not run |
| optional immutable proof | only after a separate payoff decision | dropped |

### 7.1 Required record

Both target globals, all retained items from the original list, are in §3.1.  The remaining
required checks were run on 2026-09-06:

- **Corpus transitions.**  The varargs work was swept over 55 corpus modules while it was being
  built.  Corpus-wide `unhandled` fell from 7,121 to 6,985, so Lemon's two globals are part of a
  136-global improvement rather than a one-module special case.  Lemon itself is not a heavy
  module: 0.56 s wall, negligible RSS.
- **Schema validation.**  `--validate` passes at all three stages.
- **Differential ledger.**  `pangs differential` was run on Lemon before and after the varargs
  work.  Both runs print byte-identical output, so the change introduced no new ledger
  complaint.  The complaints that are present are pre-existing and are described in §7.2.
- **Tests.**  `cargo test --workspace --all-targets` is green.
- **Source check.**  `newlinestr` is now handled through a closed access set built from named
  accesses only; the Ω source that used to open it, `lemon_sprintf`'s `va_list`, is gone because
  `va_start` and `va_end` are now modeled locally instead of being `unknown` statements.

### 7.2 Two pre-existing findings, unchanged by this work

Both were investigated on 2026-09-06.  Neither is caused by the varargs work: `pangs
differential` prints byte-identical output before and after it.  Neither changes the §3.1
result.

#### 7.2.1 The `in_rewritable_components` drop is a defect in the metric, not in Andersen

`differential` reports `in_rewritable_components` falling from 6 at Steensgaard to 1 at
Andersen and calls it a monotonicity break.  Andersen is right and the check is wrong.

The component structure is **identical** at both tiers: 42 components, same members, same
frozen flags.  Nothing merges.  The whole difference is one function.  `Symbol_Nth` is a
one-function component with no taint, and its body is:

```c
struct symbol *Symbol_Nth(int n){
  if( x2a_xjtr_0 && n>0 && n<=x2a_xjtr_0->count ){
    data = x2a_xjtr_0->tbl[n-1].data;
  }
  ...
}
```

At Steensgaard the load `x2a_xjtr_0->tbl[n-1].data` carries five extra `aliased ref` rows, for
`append_str.empty`, `basis`, `current`, `templatename` and `newlinestr`.  They are false:
`Symbol_Nth` reads one hash table and nothing else.  Andersen separates the classes and leaves
the single true row, a direct ref of `x2a_xjtr_0`.  That is a precision win.

It reads as a loss because of how the metric is defined.  `in_rewritable_components` counts a
global as rewritable if **any** non-frozen component names it, and never checks whether a frozen
component also names it.  All six of these globals are also in `c0001`, the frozen 120-function
component.  Under the strict reading — named by a clean component and by no frozen one — the
count is **0 at both tiers**, so there is no drop at all.

Measured over 53 corpus modules:

| | Steensgaard | Andersen |
|---|---|---|
| loose count (current metric) | 102 | 92 |
| strict count (clean and never frozen) | **55** | **55** |

The current metric is inflated by roughly a factor of two, and the strict count is identical at
both tiers.  Only four modules move at all under the loose metric, and one of them moves *up*:
`exe-yapteaparprfotci-O1-g` goes 5 → 6 loose and 0 → 1 strict.  So the quantity is not monotone
in either direction, and the assertion cannot be repaired by flipping its sense.

The reasoning error is stated in the check's own comment in `crates/pangs-api/src/differential.rs`:

> steens → andersen share the pointer-aware mod/ref machinery; Andersen only refines pts, so it
> can never *reveal* new aliased taint — coverage must be monotone here.

The premise is true and the conclusion does not follow.  `rewritable_globals` is not a taint
set.  It is the set of globals **named by** a clean component, and it is built from ModRef rows.
Andersen refining points-to *removes* rows, and removing a false row removes a global from a
clean component.  The check confuses "taint never grows" with "coverage never shrinks".

Suggested fix, in two parts:

1. Define the metric as *named by a non-frozen component and by no frozen component*.  A global
   that a frozen component also names is not rewritable, and counting it hides that.
2. Drop the `rewritable_globals` subset assertion and the `in_rewritable_components` comparison.
   Neither direction is a theorem.  If a cross-tier invariant is wanted here, the candidate to
   test is the taint side — no global should become *newly* frozen at Andersen — which is what
   the comment actually argues for.

#### 7.2.2 A real write is missed, and the global is dispositioned `immutable`

This one is a soundness bug, found while checking the component sets above.  It is not specific
to Lemon's varargs and it is not new.

Lemon registers its `-p` flag in `main`'s local option table:

```c
{OPT_FLAG, "p", (char*)&showPrecedenceConflict_xjtr_0,
                "Show conflicts resolved by precedence rules"},
```

`OptInit(argv, options, stderr)` publishes that table as `op_xjtr_0 = o`, and `handleflags`
writes through it:

```c
}else if( op_xjtr_0[j].type==OPT_FLAG ){
  *((int*)op_xjtr_0[j].arg) = v;
```

So `lemon -p` writes `showPrecedenceConflict_xjtr_0`, and line 3982 reads it back.  The write is
real and reachable.

Andersen sees it.  `modref.jsonl` carries the row:

```text
handleflags_xjtr_0  showPrecedenceConflict_xjtr_0  mod  aliased  ...:2726:31#0
```

The disposition does not.  All three stages report `written = false` and choose `immutable`.
Converting this global to a Rust immutable static would be wrong.

The cause is that the two facts come from different machinery and only one of them is consulted.
In `crates/pangs-clients/src/lib.rs`:

```rust
let written = info.runtime_written || info.escape == pangs_api::EscapeStatus::External;
```

ModRef rows are never read.  They are used only to *label* a write once `written` is already
true.  `runtime_written` comes from the solver's class-level `runtime_stored_classes` evidence,
which misses this store, while `push_pointer_modrefs_from_pag` — a later, separate pass over the
PAG — catches it.  Nothing reconciles the two.

The allocation-isolation override a few lines above is **not** the cause.  Instrumenting

```rust
if locally_defined && isolation.write.contains(&global.key) { runtime_written = false; }
```

shows it firing for `tplt_open.templatename_xjtr_0`, `append_str.empty_xjtr_0` and
`emsg_xjtr_0`, but never for `showPrecedenceConflict_xjtr_0`.  The class evidence was already
false.  (The same instrumentation shows that `templatename`'s new `immutable` result in §3.1
rests on that isolation proof, not on an absence of evidence — the class evidence for it says
written.)

A minimal fixture of the same shape — a global's address into a stack aggregate, the aggregate
passed to a function that publishes it in a global pointer, a third function storing through a
pointer loaded back out — is handled **correctly**, reaching `written = true` and `localize`.
So the trigger is narrower than the general pattern.  Lemon's version adds a struct field, a
round trip through `char*`, a dynamic index, and sibling entries holding function addresses and
null.  Isolating which of those loses the write is the first step of any fix.

Population at risk, over the same 53 modules and 1,917 keyed globals: **34 globals in 6 modules
have a `mod` ModRef row while `written` is false, and all 34 are dispositioned `immutable`.**

| module | globals affected |
|---|---|
| `exe-tree-O0` | 15 |
| `exe-OMP__tree-O0` | 15 |
| `exe-curl-O0` | 1 |
| `exe-apg_bore-O0` | 1 |
| `exe-lemon-O0` | 1 |
| `exe-lemon-nostatic-O0` | 1 |

Only the Lemon global is confirmed against source.  The 30 in the two `tree` builds are witnessed
from `html_outtro` and `print_version`, which look like printf-family over-approximation, so they
may well be false rows with a correct `written = false`; their source tree is a deleted pytest
temporary directory, so this could not be checked.  Treat 34 as the population to triage, not as
34 proven bugs — but note that the disagreement is currently invisible, because no check
compares a `mod` row against the `written` fact.

Suggested first step: add exactly that check, as a debug assertion or a differential rule — a
named `mod` ModRef row for a locally defined global must imply `written`.  It costs nothing, it
would have caught this, and it decides the `tree` cases immediately by pointing at whichever side
is wrong.
