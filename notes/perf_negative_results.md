# Performance Negative Results

This note records optimization experiments that were measured and abandoned. Check here
before re-implementing an apparently obvious performance idea.

## Memcpy Pointer Mod/Ref Local Prefilter

Date: 2026-06-17

Status: abandoned.

Experiment:

- Generalized the local pointer mod/ref row flusher so it could account rows under either
  `PagPointer` or `MemsetMemcpy`.
- Added a function-scoped local accumulator for `MemsetMemcpy` rows emitted from PAG
  `edge:memcpy_*` pointer accesses.
- Preserved raw attempted/duplicate metrics with
  `note_named_empty_prefiltered_duplicates`, while trying to avoid repeated
  `ModRefBuilder::push_named_empty` and fanout hash work for duplicate memcpy-derived
  named rows.
- Left direct PIR `memset` emission unchanged.

Reason it looked plausible:

- After compacting external pointer mod/ref diagnostics, a fresh Vim profile still showed
  `ModRefBuilder::push_named_empty` and fanout accounting in the remaining
  `pointer_modref_us` cost.
- Vim metrics showed `MemsetMemcpy` was duplicate-heavy:
  `pointer_modref_mem_rows_attempted=3904108`,
  `pointer_modref_mem_rows_duplicate=1604901`.

Measured result:

- Fresh pre-experiment Vim profile:
  `analysis_wall_us=18746933`, `pointer_modref_us=11929525`.
- After the experiment:
  - lua: `analysis_wall_us=225771`, `pointer_modref_us=94968`
  - tmux: `analysis_wall_us=2022563`, `pointer_modref_us=1441286`
  - Vim: `analysis_wall_us=21029926`, `pointer_modref_us=13557665`

Conclusion:

- The win was too small and noisy for the extra phase-specific accumulator complexity.
- tmux improved modestly, lua was unchanged, and Vim did not improve relative to the best
  fresh pre-experiment profile.
- Do not reimplement this exact local `MemsetMemcpy` accumulator unless a new profile
  shows a substantially different shape or the builder/fanout accounting changes enough
  to alter the tradeoff.

Better next directions:

- Re-profile first; do not infer from phase duplicate counts alone.
- Prefer optimizations that reduce the dominant `Vec::from_iter` / string lookup path or
  simplify `ModRefBuilder` fanout accounting globally.
- If revisiting memcpy rows, require an A/B measurement on at least lua, tmux, and Vim
  before keeping the change.
