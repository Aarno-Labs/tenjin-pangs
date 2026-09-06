# Imprecision Examples

## Chibicc builtin `Type` objects

Chibicc defines thirteen builtin types as named pointers to private compound
literals:

```c
Type *ty_ushort = &(Type){TY_SHORT, 2, 2, true};
```

The backing literal is uniquely owned and never mutated on a feasible path, but
Steensgaard treats the initializer store of its address into `ty_ushort` as an
arbitrary address escape. The synthetic backing object's
`derived:external-pointee` fact is folded into its named owner, making
`omega_escaped_address` and `written` true.

A separate generic update is guarded by the object's discriminator:

```c
static Node *compute_vla_size(Type *ty, Token *tok) {
  if (ty->kind != TY_VLA)
    return node;
  ty->vla_size = new_lvar("", ty_ulong);
}
```

Builtin types can reach this function as VLA base types, but their constant
non-`TY_VLA` kind makes the store infeasible for them. Flow-insensitive analysis
does not retain that correlation and reports the store as modifying every
builtin `Type` literal.

At the ordinary chibicc budget, one oversize fallback additionally turns four
local stores through output parameters in `eval2`, `eval_rval`, and
`new_str_token` into module-wide writes. Full admission removes those four
unknown writes, but not the pointee-derived escape or the guarded-store false
positive.

Consequently all thirteen `ty_*` globals remain `unhandled` in the experimental
disposition run, producing 15 unhandled globals instead of the expected 2
(`scope` and `tmpfiles`). The likely remedies are an owning-initializer terminal
in allocation isolation and, if still required, a narrow invariant-discriminator
proof for guarded stores.

## curl `no_protos`

curl initializes the pointer holder `built_in_protos` with `&no_protos`, then
later overwrites the holder in `get_libcurl_info`; `no_protos` itself is never
written. Allocation isolation represents the initializer capture with a flow
edge from `&no_protos` to the address of `built_in_protos`. Reverse write-blocker
propagation then follows that edge and incorrectly attributes the later holder
overwrite to `no_protos`.

The proof must distinguish a container's address from its contents: overwriting
`built_in_protos` mutates the holder, while only a store through a value loaded
from it could mutate `no_protos`. This false `written` fact prevents the correct
`immutable` disposition.

## fribidi `caprtl_to_unicode`

  This is the lazy CapRTL lookup-table pointer:

```
  static FriBidiChar *caprtl_to_unicode = NULL;

  if (!caprtl_to_unicode)
      init_cap_rtl();
```

  Its classification is mostly a real consequence of the lazy-initialization pattern:

  - It is written when `init_cap_rtl()` assigns the result of malloc at fribidi-char-sets-cap-rtl.c:86, so it is not immutable.

  - PANGS does not consider pointer-valued storage an atomic word-sized scalar, even though the pointer happens to be 64 bits.
  - Mutex certification fails with reentrant-access-path: an accessor first reads the pointer in the null check and then calls
    `init_cap_rtl()`, which writes the same pointer. A mechanical lock around the initial access would remain held across that call and
    attempt to reacquire itself.

  - Localization is blocked by unknown callers of the exported `fribidi_charset_to_unicode` and `fribidi_unicode_to_charset` dispatchers.
    Those functions invoke the CapRTL implementation through the `char_sets` function-pointer table. Threading a context to the static
    pointer would therefore have to cross public library entry points and indirect callback dispatch.

  Conceptually this is an excellent once-initialization candidate—the source already implements an unsynchronized hand-written once
  pattern—but the current once-lock proof only operates on an executable’s main-rooted entry spine. A library-aware once certificate would
  likely be the most natural disposition.

## fribidi `sentinel`

```
  static FriBidiRun sentinel = { ..., FRIBIDI_TYPE_SENTINEL, ... };

  if (!ppp)
      return &sentinel;
```

  PANGS reports a possible write through `ppp_next` at:

```
  if (next_type == FRIBIDI_TYPE_NSM)
      RL_TYPE(ppp_next) = FRIBIDI_TYPE_AN;
```

Because `get_adjacent_run()` can return `&sentinel`, the
  path-insensitive points-to analysis includes the sentinel at that indirect store.
In the actual source, the sentinel’s type is
  `FRIBIDI_TYPE_SENTINEL`, so the `next_type == FRIBIDI_TYPE_NSM` guard prevents that write.
Proving this requires a relational/path-sensitive
  value argument that ModRef currently lacks.



## gifsicle `Clp_ValType::func`

CLP dispatches an option-value parser through a function pointer held in a
heap array of structs, written by `Clp_AddType` and read back at a dynamic
index:

```c
  cli->valtype[vtpos].func = parser;          /* clp.c, Clp_AddType */

  Clp_ValType *atr = &cli->valtype[vtpos];    /* clp.c, Clp_Next */
  if (atr->func(clp, clp->vstr, complain, atr->user_data) <= 0)
```

The true target set is five functions: `parse_string`, `parse_int`,
`parse_bool`, `parse_double` and `parse_string_list`. PANGS reports 25 and marks
the callee unknown. It does so at 203 of gifsicle's 207 indirect callsites.

The merge starts in a header. `gif.h` has `#define Gif_Free free`, so
`gfi->free_image_data = Gif_Free` takes the address of `free` and stores it in a
struct field. Steensgaard then holds `free` in the same class as every other
address-taken function, including the five parsers. The signature envelope does
not separate them either: `fsa_compatible` deliberately admits a callee with
fewer parameters and a void return, so `free`, declared `void(void *)`, is a
legal candidate at this four-argument site.

Two mechanisms then keep the site unknown, and neither is about Andersen's
precision.

First, a base-tier verdict decides the reported answer. When Steensgaard reports
`unknown_callee`, Andersen puts the site in `eager_sites`, activates the whole
Steensgaard envelope, and marks the answer a fallback. The reported target set is
that activated envelope, and Andersen's own points-to can only add to it. So the
answer stays the envelope however precise the refinement becomes.

Second, until the external target's own contract was consulted, activating the
external `free` applied the generic client boundary to every argument of the
site. One of those arguments is `clp`, so the parser object escaped, everything
reachable from it read back as external memory, `atr->func` read back external,
and the callee stayed unknown — a self-sustaining loop whose only Ω source was
the callsite itself. A direct `free(p)` never did this: the PAG consults the
contract table and raises no boundary at all.

Admission is not the remaining lever, and this was measured rather than assumed.
gifsicle's indirect-call operands sit in one partition of 9,353 nodes, which
exceeds the budget, so only a 3,488-node directional slice of it is refined.
Admitting the whole partition costs 4m50s against 0.8s and leaves the reported
target set at 26, unchanged. At full admission the operand is external again,
now through the boundaries of *other* indirect callsites: the contamination is a
whole-program fixed point over indirect calls, not a property of one site.

The cost is concentrated. All 73 of gifsicle's written-but-unescaped globals sit
in one localization component with about 133 blockers, every sampled one
`unknown-callee-taint` at `Clp_Next`. Localization is the only disposition left
open to them — the write rules out `immutable`, their aggregate shape rules out
`atomic`, and an accessor that can re-enter an accessor rules out `mutex` — so
the unresolved callee is what holds all 73 at `unhandled`.

Separating them needs base-tier class precision: a field-sensitive account of
which functions reach `Clp_ValType::func`, distinct from the class that holds
`free`. Nothing downstream of that verdict can recover it.
