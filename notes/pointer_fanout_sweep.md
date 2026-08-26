# Pointer Mod/Ref high-fanout sweep (2026-08-25)

Scope: current release source, Andersen stage, 53-module historical completed set from
`~/pangs-corpus/_out_bc`, with build mode selected from the `exe-`/`lib-` prefix.
`exe-vim-9.2-O1`, `exe-vim-9.2-g-O1`, and `lib-openssl-4.1.0-O1` are excluded to keep the
comparison on the same historical completed set. OpenSSL again exceeded the 2,400-second
timeout and reached 28.1 GiB RSS.

Counts are over local `Analysis::modrefs()` rows. A collapsed row is an unknown row whose
detail begins `high_fanout_pointer_modref:`. Wall time is the sum of the in-process
`analysis_wall_us` metric; the four configurations were interleaved with rotated per-module
order.

| limit | collapsed rows remaining | baseline collapses recovered | all unknown rows | local rows | row growth vs 16 | summed analysis wall | pointer-ModRef phase |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 16 | 233,178 | 0 | 265,899 | 324,895 | baseline | 327.97 s | 3.20 s |
| 64 | 120,824 | 112,354 (48.2%) | 154,009 | 687,696 | +362,801 (+111.7%) | 316.67 s | 3.41 s |
| 256 | 0 | 233,178 (100%) | 36,027 | 1,933,469 | +1,608,574 (+495.1%) | 314.42 s | 4.21 s |
| 1024 | 0 | 233,178 (100%) | 36,027 | 1,933,469 | +1,608,574 (+495.1%) | 300.26 s | 4.13 s |

The fresh control does not reproduce the prompt's 35,608 / 47,112 baseline under this raw-row
definition and corpus configuration. Mutation-only raw rows are 72,656 / 83,209 at limit 16.
The threshold conclusions are therefore stated against the fresh control, not by silently
combining it with the supplied baseline.

At 256 and 1024 every per-module count above is identical. Runtime variation is dominated by
the unchanged solver; the isolated pointer-ModRef phase rises by about one second corpus-wide at
256, while total analysis wall time shows no measurable regression in these single interleaved
runs.
