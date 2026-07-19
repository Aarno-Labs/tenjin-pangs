# D4 hardening remeasurement

Date: 2026-07-18

## Scope and method

The unknown-callee and source-materialization hardening was remeasured on the three
modules that produced all eight original D4 certificates: JPEGoptim O0/O1 and YAPET
O0-g. They were freshly analyzed with the release CLI, Andersen, executable/application
mode, validation, and no overrides. Artifacts are under
`/tmp/pangs-d4-hardening-20260718`.

The guard can only remove certificates, so rerunning the other corpus modules (which
previously certified none) cannot change the certificate inventory. The corpus-wide
distribution below combines these fresh results with the unchanged modules from the
original remeasurement.

## Certificate result

Six of the original eight certificates survive:

| module | global | final disposition | source materialization |
|---|---|---|---|
| JPEGoptim O0 | `last_error` | immutable | blocked: declaration source unmapped |
| JPEGoptim O1 | `last_error` | immutable | blocked: no runtime accessor sites |
| YAPET O0-g | `Clp_CurOptionName.buf` | immutable | blocked: declaration source unmapped |
| YAPET O0-g | `cats_capacity` | atomic | blocked: declaration source unmapped |
| YAPET O0-g | `options` | mutex | blocked: declaration source unmapped |
| YAPET O0-g | `report_error` | atomic | blocked: declaration source unmapped |

`cat.catcolorspace` and `cats` are no longer certified. Both have the deterministic
unknown-callee path:

```text
cat -> Gif_DeleteStream -> omega_fnptr
```

The final edge is the deletion-hook call at `giffunc.c:510`,
`(*hook->func)(GIF_T_STREAM, gfs, hook->callback_data)`. This is a genuine callback
surface, not a missing model for an ordinary external declaration. A callback may
re-enter `cat` or another accessor while `cat` holds the proposed whole-function lock,
so the fail-closed result is justified.

## Coverage consequence

Only `cats` changes final disposition: it moves from `mutex` back to `unhandled`.
`cat.catcolorspace` remains atomic. The hardened corpus-wide distribution across the
same 2,049 mutable globals is therefore:

| disposition | before D4 | initial D4 | hardened D4 |
|---|---:|---:|---:|
| immutable | 204 | 204 | 204 |
| atomic | 14 | 14 | 14 |
| mutex | 0 | 2 | 1 |
| unhandled | 1,831 | 1,829 | 1,830 |

The remaining mutex disposition is YAPET `options`, whose zero runtime accessor set
already showed that locking is not the appropriate source transformation. Its static
certificate is retained as an independent analysis fact, but source materialization is
blocked (the declaration is unmapped; even with a recovered declaration, the empty
accessor set would leave the v1 recipe without an insertion site).

The practical hardened takeaway is thus: D4 has six sound static certificates, but no
currently useful, source-ready mutex transformation in this corpus. Its main value at
this point is the explicit evidence boundary and the precision signal for future
statement-level lock scope, rather than immediate disposition coverage.
