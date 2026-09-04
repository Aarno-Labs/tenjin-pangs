# DEA — "Fast and Precise Handling of Positive Weight Cycles for Field-sensitive Pointer Analysis" (Lei, Sui — SAS 2019)

## What it is
A field-sensitive Andersen (Pearce/PKH field-index model, LLVM IR, SVF) in which a *positive
weight cycle* (PWC: a copy/GEP cycle whose GEP weights sum > 0, e.g. `p = p + 1` in a loop)
would derive `o.f_i, o.f_{i+s}, o.f_{i+2s}, ...` until PKH's per-object max-field bound. DEA
replaces that chain by one *stride-based field representation* σ = ⟨o, i, S⟩ = {o.f_j | j = i +
Σ k_n s_n}, with S the weights of the PWCs containing the GEP edge. Same points-to results as
PKH; 7.1× faster (11 programs, 0.3–2.2 MLoC); 86.6% fewer PWC-derived fields.

## Key ideas
1. **Derivation equivalence.** Fields derived along one PWC are always pointed to by the same
   variables, so they can share one representative without precision loss.
2. **Stride representation + subsumption ([E-FIELD]).** A GEP inside a PWC derives ⟨o, i+w, S∪S'⟩;
   a new σ is dropped when some σ' ∈ pts already covers it (σ ⊑ σ'). Two iterations per PWC.
3. **Asymmetric load/store ([E-LOAD]/[E-STORE], Fig. 8).** A store through σ writes only σ; a load
   through σ unions every σ' overlapping σ. Avoids the spurious sibling-merge that a symmetric
   treatment introduces.
4. Cycle/weight detection is redone each wave-propagation round (Nuutila SCC), so cycles that
   appear through load/store-added copy edges are covered too.

## How PANGS already relates (measured 2026-09-04)
- PANGS's `FieldLocation::Lane { modulus, residue }` **is** ⟨o, i, S⟩ with S collapsed to
  gcd(S) (sound superset, both signs), and `Lane.add(Exact)` is already a fixpoint under
  congruent GEPs. Lanes are only ever *produced* from dynamic GEP indices by LLVM lowering, never
  from cycles. `p + 1` on a pointer lowers to a constant byte offset, so pointer walks are PWCs.
- Andersen terminates a PWC by walking the **global** constant-offset vocabulary
  (`known_locations`, 125 offsets in lua, 518 tmux, 499 sqlite, 2 505 vim) and then collapsing to
  the root's `Unknown` summary, which aliases *all* fields of that root. That is the PKH cost
  structure with the vocabulary in place of max-fields, and a precision loss DEA does not have
  for modulus > 1.
- The fixed-PAG exact-address proof (`exact_allocation_addresses`) cannot resolve any cycle, so
  a walked pointer never gets a root-relative location in Steensgaard either.

Static PWC census over the fixed PAG (SCCs over Assign ∪ Gep edges; script in the session
scratchpad, ~80 lines of Python over `pangs dump-pag`):

| module | GEP edges | static PWCs | PWC GEP edges | gcd = 1 | single-root |
|---|---:|---:|---:|---:|---:|
| exe-lua-O1 | 9 017 | 49 | 1.4% | 28 | 0 |
| exe-chibicc-O1 | 5 106 | 9 | 0.8% | 9 | 0 |
| exe-gifsicle-O1 | 6 056 | 74 | 1.3% | 48 | 0 |
| exe-jq-O1 | 9 913 | 296 | 3.7% | 95 | 0 |
| exe-tmux-O1 | 22 206 | 89 | 0.7% | 63 | 0 |
| lib-sqlite-O1 | 52 346 | 952 | 2.0% | 738 | 0 |
| exe-vim-9.2-O1 | 124 432 | 915 | 1.6% | 744 | 0 |

Every PWC's root set was poisoned by a load, a parameter, or a producerless value (call
result); none walks a provable allocation root. Most are byte walks (gcd 1: string scanning);
the rest are struct-array walks (moduli 8/12/16/24/32/56/72).

Solver-side cost, temporary counters in `Solve::field_of` (chained = GEP applied to a field
cell whose combined offset is in the vocabulary; collapse = falls off the vocabulary into
`Unknown`), `PANGS_ANDERSEN_PROFILE=1`, default knobs, executable mode:

| module | gep pairs | chained | collapses | all pair work | GEP share |
|---|---:|---:|---:|---:|---:|
| exe-tmux-O1 | 451 | 10 | 0 | 33 k | 1% |
| lib-sqlite-O1 | 98 559 | 94 374 | 1 056 | 240 k | 41% |
| exe-vim-9.2-O1 | 131 148 | 71 909 | 20 123 | 426 k | 31% |

So DEA's target phenomenon is real here at sqlite/vim scale: 96% (sqlite) and 55% (vim) of
GEP pair work is chain derivation, and vim collapses to field-insensitive `Unknown` 20 k times.
It is invisible on tmux because the admitted solve barely contains GEP constraints.

## Relevance to our design
- **Take: stride inference on PWCs → Lane.** Cheapest form is static and needs no solver
  change: run the SCC census on the fixed PAG in `build_base_solve` (and in Steensgaard), and
  give every GEP edge inside a static PWC `lane = Lane { gcd(cycle weights), byte_off }` instead
  of `byte_off`, i.e. treat `p++` in a loop exactly like the dynamic index the lowering already
  models. Conservative by construction (lane ⊇ exact). Expected effect: chain length L → 1 cell,
  and for modulus > 1 a lane instead of `Unknown`. Re-measure `chained`/`collapses`; if a large
  residue remains it comes from *dynamic* PWCs (cycles through load/store copies) and needs
  DEA's per-round detection, which fits naturally into `collapse_copy_sccs` (extend the
  adjacency with GEP edges, gcd of weights per SCC).
- **Consider afterwards: asymmetric load/store over overlapping cells.** `field_of` installs
  bidirectional copy edges between a Lane/Unknown summary and every overlapping cell, and the
  whole-object bridge does the same for base ↔ summary. A store to `o.f8` therefore reaches
  `o.f16` via the summary — exactly the spurious target of DEA's Fig. 8. Replacing that with
  "store writes its cell; load unions overlapping cells" is sound and strictly more precise;
  payoff unmeasured, and it touches the solve loop, so do it after the lane rewrite.
- **Not applicable / already covered:** field-index modeling and max-field bounds (we use byte
  offsets and a finite vocabulary); wave propagation (we have semi-naive joins + SCC collapse);
  the SVF implementation.
- **Not yet motivated:** extending the exact-address proof with SCC strides. It would let a
  `for (e = tbl; ...; e++)` walk over a global table keep per-field precision in Steensgaard,
  but the census found zero single-root PWCs in eight modules (tables are indexed, not walked,
  at O1). Keep in mind if a target program shows that shape.
- Expectations: not the paper's 7×. GEP pair work is 30–40% of pair work on sqlite/vim and
  copy pairs dominate, so the ceiling is roughly a third of solve time there and nothing on
  small admitted solves; the precision gain is confined to modulus > 1 walks.
