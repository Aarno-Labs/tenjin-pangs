# D4 Mutex Eligibility Remeasurement

Date: 2026-07-18

## Scope and method

D4 was measured on every non-Vim, non-PHP sibling in
`/home/brk/pangs-corpus/_out_bc`. Forty-one modules were freshly analyzed with the
release CLI, Andersen, export validation, no overrides, and the executable/library
mode implied by the filename. The retained artifacts are under
`/tmp/pangs-d4-remeasurement-20260718`.

OpenSSL was not rerun: its most recent attempt exceeded the host memory limit after
roughly 38 GiB RSS. Its prior validated manifest has 226 mutable globals and
`access_set_complete=false` for all 226, which is sufficient to derive that D4 would
certify none and would leave its 24 immutable / 202 unhandled distribution unchanged.
The combined 42-module totals below include that derived zero contribution.

## Result

Across 2,049 mutable definition globals, D4 certifies eight:

- JPEGoptim O0/O1: `last_error` (two certificates, both already `immutable`);
- YAPET O0-g: `Clp_CurOptionName.buf` (already `immutable`), `cat.catcolorspace`,
  `cats`, `cats_capacity`, `options`, and `report_error`.

The default cascade therefore gains two final mutex dispositions:

| disposition | before D4 | after D4 |
|---|---:|---:|
| immutable | 204 | 204 |
| atomic | 14 | 14 |
| mutex | 0 | 2 |
| unhandled | 1,831 | 1,829 |

The two new handled globals are YAPET's `cats` and `options`. `cats` has accessors
`addcat` and `cat`; neither can reach an accessor in the final call graph. `options`
has no runtime accessor site in the retained ledger: its may-write fact is attributable
to global initialization/synthesized module code, so its reentrancy check is vacuous.

The other six certificates lose to stronger earlier dispositions: three immutable and
three atomic. This is expected because eligibility slots are independent facts and the
cascade chooses the strongest applicable representation.

## Failure shape and precision takeaway

The 41 fresh modules contain 19 `reentrant-access-path` failures after the coarse gates.
They are concentrated in JPEGoptim (18) and YAPET `ncats` (one). Typical witnesses are
`main -> wait_for_worker`, `main -> parse_arguments`, `optimize -> write_markers`, and
`main -> addcat`: both endpoints access the same global.

These are sound failures for D4's pinned v1 recipe, which holds the would-be lock for
the whole accessor function. They also identify the obvious future precision lever:
access-site lock scopes could accept cases where the caller's access does not span the
call. That refinement would require statement/control-flow lock placement and a new
reentrancy model, not merely relaxing the current reachability test.

The overall payoff is modest but real: two formerly unhandled globals become governed,
the certificates carry deterministic path witnesses, and the results expose exactly
where finer lock-scope analysis could matter. No production C/Rust mutex materializer
is included in this milestone.
