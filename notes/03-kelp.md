# KELP — "Unleashing the Power of Type-Based Call Graph Construction by Using Regional Pointer Information" (Cai, Jin, Zhang — USENIX Security 2024)

## What it is
Staged indirect-call resolution: a cheap, *regional* (non-whole-program) def-use analysis resolves "simple" function pointers exactly; the rest fall back to type analysis (MLTA), made more precise because confined functions are removed from the candidate pool. Pre-processing step orthogonal to any type analysis. HKUST group (same first author as the dissertation: Yuandao Cai).

## Key concepts
- **Simple function pointer** (Def 1): never referenced by other pointers (address not taken into another pointer) and doesn't derive its value by dereferencing other pointers. Simple icall = icall through a simple fn ptr.
- **Confined function** (Def 2): address-taken function only invocable via simple icalls (all its address-taken sites appear only in def-use chains of simple fn ptrs).
- **Empirical findings (Linux v5.15):** 34.5% of icalls are simple; 23.9% of address-taken functions are confined; 76.3% of address-taken functions are address-taken exactly once.

## Stage I: regional def-use tracking (field-, flow-, context-sensitive)
- Works on mem2reg'd LLVM IR (SSA, direct value flows). DUG: direct value-flow edges (SSA def-use, free) + indirect value-flow edges (store→load through object, expensive — avoided).
- Backward rules: FUNC-SITE (p=&func → target found), COPY, PHI, FIELD (p=&q→fld, tracks FLD(q,fld) for field sensitivity), CALL/RET with CFL parenthesis matching for context sensitivity. **LOAD ⇒ classify as complex, abort tracking** (value via dereference = not simple).
- Forward phase: ensure the fn ptr's value isn't propagated into memory via other pointers (no escape into complex region). If it stores into objects read elsewhere → complex.
- Globals: flow-insensitive — collect all values ever written to the simple global var.
- Safe fallback: unknown control flow (dlopen, asm, incomplete code), uncollectable chains → leave to type analysis. No additional false negatives vs type analysis.

## Stage II: precise type analysis for complex icalls
- CandiFunc = all address-taken funcs − ConFunc (confined). Type matching (FSA or MLTA) against this reduced candidate pool.
- Confined funcs identified via DefUseReachingSites collected in stage I (all of func's address-taken sites are def-use-reachable in simple icall chains).

## Results
- 20 programs ≥100 KLoC incl. Linux (26M LoC), Firefox (8M). Avg callee-size reduction vs MLTA: 54.2%, at +8.5% time (6.3s avg). Linux CG in ~11 min single pipeline; million-line programs ≤4 min each.
- Downstream: thread-sharing analysis −25.3% spurious shared statements; SABER value-flow bugs −17.1% false positives; directed fuzzing (BEACON) −51.9% time.
- Ablation: stage I alone +32.7% precision over MLTA; stage II alone +23.2%; combined 54.2%.
- FN analysis: Intel PT-based tracing + AFL++ fuzzing — no new FNs beyond type analysis (after fixing primitive-type equalization in MLTA).
- Contrast with CORAL (concurrent work, same group): CORAL's "stationary fn pointers" are complex (can be referenced by other ptrs); CORAL is refinement-based, higher cost, for precision-tolerant scenarios (daily builds); KELP is for fast CI-style scenarios.

## Relevance to our design
- **Cheap-first staging**: classify pointers by difficulty; resolve the easy majority with SSA def-use chains (almost free), reserve expensive machinery for the hard residue. This is a general architectural principle — applies to mutability/escape too, not just icalls.
- The "confined" subtraction idea: results of the cheap stage *shrink the candidate space* of the expensive/imprecise stage — stages are synergistic, not just parallel.
- mem2reg/SSA preprocessing materializes most def-use edges for free (top-level variables) — same trick SVF/partial-SSA uses; our design should exploit direct value flow maximally before touching memory.
- Caveat: KELP itself doesn't compute points-to for data pointers; it's icall-only. But the simple/complex dichotomy extends naturally.
