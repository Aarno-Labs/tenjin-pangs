# Fixing Lemon `newlinestr`: recover localization before chasing immutability

## 0. Status and recommendation

Proposal, not implemented.  The target is
`translate_code.newlinestr_xjtr_0` in `exe-lemon-O0`:

```c
if( rp->code==0 ){
  static char newlinestr[2] = { '\n', '\0' };
  rp->code = newlinestr;
  ...
}
```

The best first step is **not** a new object-sensitive solver.  Implement and measure
`20260905_EXT_VARARGS_CONTRACT.md` first.  `newlinestr` has the same selected
`lemon_sprintf`/`llvm.va_start` escape witness as `templatename`, and localization is currently
blocked only by `access_set_complete`.  If the shared varargs fix makes the access set complete,
the existing localization plan already succeeds (`ctx0001`, no non-completeness blockers) and
the disposition problem is solved.

If it remains incomplete, add a targeted explanation census and refine allocation-address flow
with field-aware store/load matching.  Do not attempt path-sensitive string reasoning unless the
goal changes from “handle this global soundly” to “prove it immutable”.

The filename intentionally follows the requested `20960905_...` spelling.

## 1. Measured baseline

The validated 2026-09-05 Andersen run used:

```text
/home/brk/pangs-corpus/_out_bc/exe-lemon-O0.bc
--stage andersen --build-mode executable --dispose --no-overrides
default conservative integer-pointer policy
```

Current facts:

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

## 3. Work item A: take the shared varargs fix first

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

Acceptance for this work item:

```text
newlinestr localization verdict = ok
chosen disposition             = localize (or an earlier independently certified strategy)
```

Do not require its aliased ModRef set to become tiny.  A large but finite, complete rewrite set
is acceptable for localization, and the manifest already says the resulting context component
has no other blocker.

## 4. Work item B: explain the first remaining open terminal

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

## 5. Work item C: field-aware content flow in allocation isolation

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

## 6. Optional work item D: immutable-content proof (defer)

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

Evaluate cumulatively:

| Variant | Purpose |
|---|---|
| baseline | current default |
| varargs | all work from `20260905_EXT_VARARGS_CONTRACT.md` |
| varargs + field-flow | Work item C, only if still needed |
| optional immutable proof | only after a separate payoff decision |

For Lemon, report both target globals so shared effects are visible.  For `newlinestr`, retain:

- Ω/external source set;
- escape and completeness facts;
- named and unknown Mod/Ref rows, functions, and Mod/Ref split;
- first false/remaining write witnesses;
- violation relevance;
- localization component/blockers; and
- final disposition.

For the whole corpus, report precision and disposition transitions plus runtime/RSS and the
standard solver counters.  Source-check every newly handled global reachable from an accepted
internal-vararg summary or a newly closed allocation path.  Run `cargo test --workspace
--all-targets`, validation, and the conservative → Steensgaard → Andersen differential ledger.

Stop after Work item A if `newlinestr` becomes localizable.  Proceed to Work item C only when the
explanation diagnostic identifies a field/content-flow false edge and the corpus census shows a
reusable population.  Do not implement Work item D merely to turn a sound `localize` result into
`immutable` for one two-byte array.
