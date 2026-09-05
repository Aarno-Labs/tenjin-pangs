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


