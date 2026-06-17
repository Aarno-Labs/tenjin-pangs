# M5.0 Gate Census

Generated from PANGS export directories.

Interpretation:

- `known_runtime_writer` is the strongest M5a candidate bucket: a flow-sensitive
  summary pass could potentially separate init-time writes from post-publish writes.
- `incomplete_initval` may include B1 poisoning, but it first needs source audit;
  M5a should not be green-lit from this count alone.
- `unknown_runtime_writer` and `exported_global` are not M5a wins without earlier
  boundary/modeling improvements.

## Summary

| row | mutable | rewritable | frozen | known runtime writer | incomplete initval | unknown runtime writer | exported | stationary | M5a gate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `exe-chibicc-O1` | 133 | 0 | 133 | 0 | 133 | 0 | 0 | 0 | audit_incomplete_initval |
| `exe-curl-O1` | 80 | 16 | 64 | 0 | 80 | 0 | 0 | 0 | audit_incomplete_initval |
| `exe-gifsicle-O1` | 93 | 1 | 92 | 0 | 93 | 0 | 0 | 0 | audit_incomplete_initval |
| `exe-jpegoptim-O1` | 48 | 0 | 48 | 0 | 48 | 0 | 0 | 0 | audit_incomplete_initval |
| `exe-jq-O1` | 14 | 5 | 9 | 0 | 14 | 0 | 0 | 0 | audit_incomplete_initval |
| `exe-lua-O1` | 5 | 0 | 5 | 0 | 5 | 0 | 0 | 0 | audit_incomplete_initval |
| `exe-tmux-O1` | 107 | 0 | 107 | 0 | 107 | 0 | 0 | 0 | audit_incomplete_initval |
| `lib-parson-O1` | 5 | 0 | 5 | 0 | 5 | 0 | 0 | 0 | audit_incomplete_initval |
| **total** | 485 | 22 | 463 | 0 | 485 | 0 | 0 | 0 | audit_incomplete_initval |

## Gate Decision

M5a is not green-lit from this corpus snapshot. There are no mutable globals whose
stationarity verdict is blocked by a known `runtime_writer`, so the flow-sensitive
summary machinery in `PLAN-M5.md` would not currently target a measured population.

The dominant earlier blocker is `incomplete_initval`: every mutable global in this
census falls into that bucket. Use the Initval Diagnostics section below to distinguish
ordinary globals with no modeled pointer initializer from explicit B1 poison cases.

M5b is not green-lit by this census alone; it still requires a client that consumes
thread-confinement facts.

## Frozen-Component Taints

### exe-chibicc-O1

- `fnptr_varargs_internal_unmodeled`: 91
- `unknown_global`: 65
- `fnptr_ptrtoint`: 14
- `fnptr_varargs_external`: 9
- `unknown_caller`: 2
- `unknown_callee`: 1
- `memset_fnptr_aggregate`: 1
- `fnptr_inttoptr`: 1

### exe-curl-O1

- `fnptr_varargs_internal_unmodeled`: 91
- `unknown_global`: 86
- `fnptr_varargs_external`: 35
- `fnptr_ptrtoint`: 14
- `unknown_caller`: 1
- `unknown_callee`: 1
- `inline_asm`: 1

### exe-gifsicle-O1

- `unknown_callee`: 203
- `unknown_global`: 125
- `fnptr_varargs_internal_unmodeled`: 30
- `fnptr_varargs_external`: 22
- `fnptr_ptrtoint`: 19
- `unknown_caller`: 9
- `memcpy_fnptr_aggregate`: 2
- `fnptr_varargs_indirect`: 2
- `memset_fnptr_aggregate`: 1

### exe-jpegoptim-O1

- `fnptr_varargs_internal_unmodeled`: 29
- `fnptr_varargs_external`: 24
- `unknown_global`: 17
- `unknown_callee`: 14
- `unknown_caller`: 1
- `setjmp_longjmp`: 1
- `fnptr_ptrtoint`: 1

### exe-jq-O1

- `unknown_global`: 217
- `fnptr_varargs_internal_unmodeled`: 95
- `fnptr_ptrtoint`: 37
- `fnptr_varargs_external`: 20
- `unknown_callee`: 8
- `unknown_caller`: 1

### exe-lua-O1

- `unknown_global`: 319
- `fnptr_varargs_internal_unmodeled`: 87
- `unknown_callee`: 64
- `fnptr_ptrtoint`: 48
- `fnptr_varargs_external`: 22
- `fnptr_inttoptr`: 2
- `unknown_caller`: 1

### exe-tmux-O1

- `unknown_global`: 564
- `fnptr_varargs_internal_unmodeled`: 70
- `unknown_callee`: 49
- `fnptr_ptrtoint`: 37
- `fnptr_varargs_external`: 31
- `memset_fnptr_aggregate`: 4
- `unknown_caller`: 1

### lib-parson-O1

- `unknown_callee`: 133
- `unknown_global`: 41
- `fnptr_ptrtoint`: 6
- `unknown_caller`: 4

## Initval Diagnostics

### exe-chibicc-O1

- `no_modeled_pointer_initializer`: 133

### exe-curl-O1

- `no_modeled_pointer_initializer`: 80

### exe-gifsicle-O1

- `no_modeled_pointer_initializer`: 93

### exe-jpegoptim-O1

- `no_modeled_pointer_initializer`: 48

### exe-jq-O1

- `no_modeled_pointer_initializer`: 14

### exe-lua-O1

- `no_modeled_pointer_initializer`: 5

### exe-tmux-O1

- `no_modeled_pointer_initializer`: 107

### lib-parson-O1

- `no_modeled_pointer_initializer`: 5

## Top Runtime Writers

### exe-chibicc-O1

- none

### exe-curl-O1

- none

### exe-gifsicle-O1

- none

### exe-jpegoptim-O1

- none

### exe-jq-O1

- none

### exe-lua-O1

- none

### exe-tmux-O1

- none

### lib-parson-O1

- none

