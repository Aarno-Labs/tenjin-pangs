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
