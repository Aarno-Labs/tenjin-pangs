# Cai dissertation — "Making Call Graph Construction More Practical for Program Analysis in the Real World" (Yuandao Cai, HKUST, Sept 2023)

Chapters 2–3 are KELP and CORAL verbatim (see notes 03 & 04). New material relevant to us: Chapter 4 (Canary). Chapters 5–6 (Peahen deadlock detection via context reduction; Lockpick lock-misuse detection) reuse the same meta-strategy: build a cheap context-insensitive structure first, then lazy context-sensitive refinement of only the suspicious parts.

## Chapter 4: Canary (PLDI'21 work) — interference-aware value-flow analysis
Relevant to us not for concurrency bugs but for **how it builds a whole-program value-flow graph (VFG) cheaply, without a prior exhaustive pointer analysis**:
- Partial SSA, LLVM convention: top-level vars V (SSA, direct def-use free) vs address-taken objects O (via loads/stores).
- **Bottom-up, thread-modular/compositional construction:** process functions in reverse topological order of (thread) call graph; per function an intra-procedural flow- (and path-) sensitive points-to dataflow (IN_ℓ/OUT_ℓ for address-taken vars; global PG_top for SSA vars) resolves local store→load (indirect) def-use edges. Each function summarized by a **procedural transfer function Trans(F)** describing points-to side effects on formal-in/formal-out params; call sites apply summaries. Strong updates when Pts(x) is a singleton (Algorithm 1, line 16-17).
- Guards: edges annotated with the *conditions* (branch + alias conditions) under which the value flows — path-sensitivity recorded lazily, not solved eagerly; SMT only at query time on the constraints of a candidate source-sink path.
- **Escape analysis interleaved with interference-edge discovery** (Algorithm 2): EspObj initialized with objects passed to forks; grows via stores into escaped objects; Pted(o) = vars reachable from o in the VFG; new inter-thread store→load edges added between accesses of escaped objects in different threads; iterate to fixed point (cyclic dependence: new edges → more escape → more edges). Piggybacks pointer analysis onto interference resolution — no exhaustive prior whole-program Andersen.
- Load-store order constraints (Φ_ls) + partial-order constraints (Φ_po, fork/join semantics) checked by SMT at the end; constraints on different source-sink paths independent → **parallelizable**.
- Results: VFG built 70×–500× faster (and less memory) than SABER/FSAM (SVF); path-sensitive checking of MySQL (~3 MLoC) in ~2.5 h.

## Chapter 7 future directions
Domain-tailored analyses (incl. Rust/Go), combining with dynamic/AI techniques, LLM synergy. Nothing technical we need.

## Relevance to our design
- **Compositional bottom-up function summaries + intra-procedural flow-sensitive solving** is the algorithmic-efficiency counterpoint to whole-program Andersen: most C functions are small; their pointer effects compress into small transfer functions; the global phase only stitches summaries. This is also naturally parallel (functions at the same call-graph level are independent — KallGraph-style thread pool applies).
- The **escape-set fixpoint** (EspObj/Pted) is literally an escape analysis of the kind the user needs (theirs: escape across module/thread boundaries; ours: escape for Rust ownership reasoning) and shows how to compute it *during* VFG construction at low cost.
- Guarded/lazy constraint recording (don't solve eagerly; attach conditions, decide at query time) is a useful pattern for mutability queries that need path qualification ("written only under init flag").
