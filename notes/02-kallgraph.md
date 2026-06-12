# KallGraph — "Redefining Indirect Call Analysis with KallGraph" (Li, Sridharan, Qian — IEEE S&P 2025)

## What it is
Sound(er), precise, **fully parallelizable** indirect-call analysis for huge C programs (Linux kernel 24M LoC). Built on **Unias** (USENIX Sec '23 hybrid alias analysis), itself built on SVF's PAG. Demand-driven CFL-reachability points-to with type-based shortcuts. Open source: github.com/seclab-ucr/KallGraph.

## Background landscape (their §2–3)
- Exhaustive points-to (Andersen via SVF) times out / takes days on Linux; Steensgaard imprecise (ECs collapse).
- Type-based: FSA (signature match) — scalable, imprecise. MLTA (multi-layer type analysis): refines via struct-layer contexts; successors TyPM, KELP, TFA, SMLTA.
- **They show MLTA & successors are both unsound and imprecise** by design: ① fallback-to-FSA when struct layers missing intra-procedurally (imprecise); ② no fallback on confinement side (unsound — missed targets); ③ type-level cast handling conservative (type escape on void*, cast at type level not object level); ④ inclusion-only cast propagation unsound; ⑤ impl flaws (BitCastOperator, Phi/Select "must" logic).

## Core design
- **Per-address-taken-function demand-driven query**: for each address-taken function, run CFL-reachability from its address node through PAG (Store/Load/Assign/Gep edges) to find which icall sites it can reach. This is "individualized" — each query independent → **embarrassingly parallel** (80 threads).
- Grammar (their final rules):
  - F → (Assign | Gep_{t,o} | ~Gep_{t,o} | Store I-Alias Load)*
  - ~F → (~Assign | Gep | ~Gep | ~Load I-Alias ~Store)*
  - I-Alias → ~F I-Alias F | ~Load I-Alias Load | ε | Shortcut_f | Shortcut_{c-t,o} I-Alias Gep_{t,o}
- **Type-based shortcuts (from Unias):** instead of traversing long Store…Load chains through struct fields, insert Shortcut_f edges that match Gep field offsets type-wise — skipping large graph portions, soundly (formally reasoned), unlike MLTA's ad-hoc shortcuts.
- **Individualized/object-level CastMap** (not type-level): record cast relationships per *object* (cast instruction operands), so `struct C→A` cast only aliases the specific instance. "Look-ahead" on-demand points-to per cast filters trivial local casts out of the CastMap (e.g., memcpy void* roundtrips) → minimal CastMap (§5.5).
- **Gep handling redesign (§5.3):** don't require Gep edges to be paired; treat Gep as Assign-with-offset, maintain cumulative-offset stack (MHS), check offset==0 at Load/~Store points. Handles unpaired GEPs, (X+Y, −Z) arithmetic. Uses **byte offsets** (not field indices) for consistency across struct types; accurate byte offset model fixed SVF's flattened-index inconsistencies (a->b[i]->c vs a->b+b[j]->c). Strictly array-insensitive (note: opposite of cclyzer!).
- **Bootstrapping without prior call graph (§5.4):** prior demand-driven analyses needed an MLTA-seeded call graph (unsound). KallGraph starts from empty call graph and iterates to fixed point; optimized via dependency tracking — DepiCalls[func] = icalls that func's query reached (as call arg/ret); only re-analyze funcs whose dependent icalls gained new targets. Fixed point in ~4 iterations.
- History-aware: CFL state (MHS stack) remembered across shortcut traversal.

## Implementation/scalability facts
- 2.1K SLOC on top of Unias/SVF (LLVM 14, SVF-2.5). PAG construction is the memory hog (up to ~250GB for allyesconfig kernels); after construction, PAG accessed **read-only**, <30MB per thread → near-linear parallel scaling on 80 threads.
- allyesconfig Linux-6.5: 270 CPU-hours but 3h49m wall-clock on 80 threads. defconfig kernels: ~8 min wall.
- Precision: prunes 75–90% of icall targets vs MLTA; avg targets per icall e.g. 17.5 vs 137.5 (Linux-6.5a). Soundness: 0 FNs found by 7-day fuzzing trace + manual verification (vs 100+ FN icalls for MLTA/TyPM/SMLTA).
- Ablation: optimized fixed-point algorithm → 29–66% CPU reduction; minimal CastMap → 3.3–7.3% more.
- Their key architectural claim: exhaustive analyses have hard-to-parallelize preprocessing/lookup-map phases with interleaved reads/writes; demand-driven queries over a read-only graph parallelize trivially.
- Known gaps: ptrtoint/inttoptr not modeled (SVF PAG tracks pointers not integers) — caused their only 2 FNs; field precision via byte offsets but **no array sensitivity**; flow- and context-insensitive (multi-entry nature of kernels).

## Relevance to our design
- The architecture to steal: **build a PAG-like read-only graph once; answer queries demand-driven in parallel** (per address-taken function, or per icall, or per mutability/escape query).
- On-the-fly call graph via their optimized fixed-point + dependency re-analysis is directly applicable.
- Object-level minimal CastMap is the sound replacement for cclyzer-style type filtering at casts.
- Tension to resolve: KallGraph is array-insensitive & uses byte offsets; cclyzer's array sensitivity matters for vtables (C++) and for precise per-element mutability. Byte-offset field sensitivity is the robust common denominator for C.
- For our use case (whole-program mutability/escape for *all* pointers, not just icalls), pure demand-driven may approach exhaustive cost — but queries are still parallel and can be batched/cached (they note caching traversed regions + graph preprocessing like cycle elimination as future work).
