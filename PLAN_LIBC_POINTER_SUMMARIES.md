# Libc Pointer-Summary Plan

## Purpose

PANGS treats an unmodeled external call as an Ω boundary: pointer arguments may be
written through and a pointer result may point anywhere.  That default is required
for sound incomplete-program analysis.  It is unnecessarily imprecise for a small
set of pure libc search routines whose result is known to be derived from an input
pointer.

The motivating case is `report_error` in `exe-yapteaparprfotci-O0-g.bc`.
`catdir` computes `end = strchr(dir, '\0')`, then reads through `end[-1]` and
`end[-2]`.  Without a return-alias summary, those reads are `omega_load` rows with
module-wide candidates, making every global's `access_set_complete` false.

This is an analysis-model change, not a disposition-policy exception.  D3 continues
to require `access_set_complete`; the summary seeks to make that fact accurately
reflect the pointer provenance available in the program.

## Fixed rules

- External calls remain Ω by default.
- A summary is exact-name and signature-shape specific.  Similar-looking names do
  not match by substring.
- A return-alias summary adds only the stated pointer-flow edge and suppresses the
  ordinary external-call Ω effect for that call.  It must therefore apply only to a
  function whose documented behavior has no hidden pointer writes or fresh/unknown
  pointer result.
- An unavailable result or missing required pointer argument falls back to the
  ordinary Ω boundary.
- The model is target-independent and has no C-to-Rust materialization behavior.

## Initial scope: pure search return aliases

The first implementation models these external functions as `return aliases arg0`:

| Function | Argument behavior | Result behavior |
|---|---|---|
| `strchr` | reads arg0 | pointer within arg0 or null |
| `strrchr` | reads arg0 | pointer within arg0 or null |
| `strstr` | reads arg0/arg1 | pointer within arg0 or null |
| `strpbrk` | reads arg0/arg1 | pointer within arg0 or null |
| `memchr` | reads arg0 | pointer within arg0 or null |

The pointer analysis is may-analysis: the null alternative needs no separate object;
the alias edge safely represents the non-null case.

## Explicitly deferred summaries

- Copy/fill routines (`memcpy`, `memmove`, `strcpy`, `memset`) have distinct memory
  effects and need destination-return plus read/write transfer rules.
- Allocation routines need fresh-object or reallocation semantics.
- `strtok`, `basename`, and `dirname` have stateful or mutating behavior.
- Conversion APIs such as `strtol` need an out-parameter relation for `endptr`.
- APIs returning external storage (`getenv`, `readdir`, `strerror`) must not be
  represented as aliases of an input pointer.

Each deferred family requires its own proposal and fixtures; this plan does not
create a general libc database.

## Verification

1. Unit fixtures prove each listed function creates the arg0-to-result pointer flow.
2. An unlisted function with the same pointer signature remains an Ω external result.
3. The synthetic/corpus result for `catdir` no longer emits an `omega_load` merely
   because of `strchr`'s result; any remaining Ω reflects the provenance of `dir`.
4. Full workspace tests pass. Corpus measurements report the change in module-wide
   access rows.

## Initial result

Implemented 2026-07-17 for the five pure search functions listed above.  On
`exe-yapteaparprfotci-O0-g.bc`, the four `catdir` loads through the `strchr` result
at lines 142 and 144 changed from module-wide `omega_load` rows to finite aliased
global rows.  `report_error` remains access-incomplete, but its decisive witness now
correctly identifies a separate unknown access in `check_ps2write` at line 418.
