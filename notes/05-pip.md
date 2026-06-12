# PIP — "Making Andersen's Points-to Analysis Sound and Practical for Incomplete C Programs" (Krogstie, Bahmann, Själander, Reissmann — IEEE 2026)

## What it is
Andersen-style field-insensitive, context-insensitive points-to that is **sound for incomplete C programs** (per-file / library analysis, no summaries needed), with an efficient *implicit* representation of external memory. Implemented in the jlm research compiler (RVSDG IR built from LLVM IR). Per-file solver runtime ~1.1 ms.

## Key ideas
1. **Escape tracking for incompleteness:** track which memory locations escape the module (exported symbols, passed to external fns, returned from escaped fns, pointed-to by escaped objects — transitively) and which pointers have unknown origin (returns of external fns, params of escaped fns, loads from externally accessible memory). Unknown-origin pointers may target only *externally accessible* locations — never non-escaped module-local memory. Big precision win vs Andersen's single "Unknown" blob.
2. **Ω node:** single constraint variable representing all external memory. Constraints: Ω ⊇ {Ω}, Ω ⊇ *Ω, *Ω ⊇ Ω, Call(Ω,...), Func(Ω,...). Escaped object x: Ω ⊇ {x}; unknown-origin pointer p: p ⊇ Ω.
3. **Implicit pointee representation (IP):** explicit Ω is a hotspot (Cartesian product of unknown pointers × escaped locations). Replace with two 1-bit flags per variable: `p ⊒ Ω` ("p points to everything external") and `Ω ⊒ {x}` ("x escaped"), plus 6 new constraint types/inference rules (TransΩ propagates the flag along edges instead of copying sets). Sol(p) = explicit set ∪ (all escaped if flagged). 15× speedup over best explicit-pointee configuration (incl. an oracle picking the fastest per file).
4. **PIP (Prefer Implicit Pointees):** online solver technique avoiding "doubled-up" pointees (x both explicit in Sol(p) and implied via flags). Back-propagation of flags; clear Sol(p) when p ⊒ Ω ∧ Ω ⊒ p; skip adding edges that are subsumed. Additional 1.9× (14× alone vs no-PIP baseline); makes other classic solver optimizations (OVS, LCD, HCD, DP, cycle detection variants) superfluous in their setting.
5. **Pointer provenance / PNVI-ae-udi compliance:** ptr→int cast: mark all pointees exposed (Ω ⊇ p); int→ptr cast: p ⊇ Ω. Pointer smuggling through incompatible-type loads/stores handled by Ω ⊇ *p / *p ⊇ Ω on scalar loads/stores. Sound integer handling without polluting analysis with provenance-carrying ints.
6. Cycle elimination is no substitute for IP (51% of pointers end up ⊒ Ω; only some are in Ω-cycles).

## Evaluation
- 3,659 C files from SPEC CPU2017 + emacs/gdb/ghostscript/sendmail, analyzed per-file (compilation model). Mean solver time 1.1 ms/file; precision client: 40% fewer MayAlias vs BasicAA alone.

## Relevance to our design
- **Modular soundness story**: for C→Rust conversion you must handle libraries/incomplete programs honestly. The escaped/external dichotomy with implicit Ω-flags is exactly the right (and cheap) model — and "escape status" is literally one of the user's analysis outputs! PIP shows escape can be computed *inside* the points-to fixpoint at bit-flag cost.
- The two 1-bit flags (points-to-external / escaped) are a compact universal lattice element; in a parallel solver they're monotone bits → race-free to set (idempotent OR), great for lock-free parallelism.
- Per-translation-unit (or per-SCC-of-call-graph) modular analysis with Ω at module boundaries gives an embarrassingly parallel *bottom-up* phase, optionally refined at link time.
- Caveats: field-insensitive & context-insensitive as presented; precision relies on client. But the Ω construction is orthogonal — can be grafted onto a field-sensitive inclusion analysis.
- Worth noting: provenance-aware int↔ptr handling fixes the exact ptrtoint/inttoptr soundness gap KallGraph reported.
