# CORAL — "A Cocktail Approach to Practical Call Graph Construction" (Cai & Zhang — OOPSLA 2023)

## What it is
Progressive multi-precision ("cocktail") CG construction for C: Stage Zero pre-analysis captures *initial values* of function-pointer objects; then Steensgaard (Stage I) → Andersen (Stage II) → demand-driven flow/context-sensitive (Stage III, SUPA-style), each stage settling the icalls it can prove precise and passing the rest on. First to characterize **stationary function pointers**.

## Empirical study (5,355 icalls in Tmux, Curl, Redis, Git, FFmpeg)
- Finding I: 23% of icalls via global vars; **97% of those globals stationary** → flow-insensitive suffices.
- Finding II: 74% of icalls through struct fields; **61% of all icalls via *stationary* fields** (initialized, possibly multiple writes during init, then never re-assigned; initial values often externally selected). For these, no precision beyond "the set of initial values" is achievable even by flow/context-sensitive analysis.
- Finding III: 76% of icalls through function parameters → context-sensitivity genuinely needed for some.
- Definitions: stationary fn ptr = unchanged for reading after initialization (à la Unkel & Lam stationary fields for Java); initialization phase ends when the object's reference is stored into other objects.

## Architecture
- **Stage Zero (pre-analysis):** flow- & context-sensitive *def-use* tracking of each newly created object during its initialization phase only (before its reference escapes into other objects). Field-sensitive (FLD rule); CALL/RET with push/pop contexts. Produces InitVal(o.fld) = set of functions initially assigned. Cost: ~1.5 min per 718 KLoC (4.2% of total). Sparse — ignores statements irrelevant to the object.
- **Result-oriented & lazy precision check:** after each flow-insensitive stage, an icall κ: v=v0(...), v0:=*p is "already precise" iff every object o the analysis says p points to satisfies pts(v0) = InitVal(o) or |pts(v0)|=1. No need to identify which pointers are stationary a priori. (Key trick! Detecting "stationaryness" directly à la Unkel–Lam needs expensive flow analysis; comparing against InitVal is cheap.)
- **Stage I: Steensgaard** (near-linear). Resolves I₁ = 55.6% of icalls.
- **Stage II: Andersen, bootstrapped** — NOT whole-program: uses Kahlon-style bootstrapping; runs Andersen only on Steensgaard partitions related to unresolved icall fn ptrs (~1/3 of program statements). Resolves I₂ = 25.2%.
- **Stage III: demand-driven flow- & context-sensitive (SUPA-style)** on the remaining 19.2%, reusing Andersen results from stage II to build sparse def-use chains.
- Soundness: corner case — non-stationary ptr whose non-initial values coincide with initial values may be misjudged precise (rare). Empty InitVal (dlopen etc.) → forwarded to Stage III; no new FNs.

## Results
- 20 C programs (avg 718 KLoC, max MariaDB 1.8M, Wine 4M, FFmpeg 2.7M... 26M total incl Linux? no — Linux not included; FFmpeg 1213 KLoC analyzed ~1h). CORAL: avg 35.4 min / 13.9 GB; SUPA & Andersen OOM (128GB) on 12 and 11 of 20 programs respectively. SPA (Steensgaard) is 9.3× faster than CORAL but CORAL prunes 50% of SPA's false targets and 24.2% of Andersen's.
- Precision ≈ SUPA (where SUPA runs), at a fraction of cost; CG is context-sensitive for I₃ calls.
- Downstream: Pinpoint UAF +57.4% bugs found, −75.6% false warnings vs SPA; thin slicing −44.6% statements; AFLGo fuzzing −35.7% time. 12 confirmed new bugs.
- FN analysis: Intel PT tracing + 2 weeks AFLGo fuzzing — no FNs found (after fixing 7 impl bugs).
- Ablation: removing Steensgaard → OOM ×12 (Andersen had to absorb 55% of icalls); removing Andersen → OOM ×12 (25% of icalls hit stage III).
- Arrays: constant-index elements as distinct abstract objects when statically determinable (cclyzer-style); unknown index → monolithic. Function-signature compatibility check used to prune during pointer analysis.

## Relevance to our design
- **The tiered-precision pipeline with a result-oriented "precision certificate"** (compare against InitVal) is the central organizing idea: cheap analyses settle most queries *with proof*, expensive analyses only touch the residue. Directly generalizes beyond icalls — e.g., mutability/escape facts could have analogous certificates (e.g., "object never written after init" is literally the stationary concept = immutability!).
- **Stationarity ≈ immutability**: CORAL's stationary-field notion is essentially "field is immutable after construction" — *exactly* what a C→Rust converter needs to decide `&T` vs `&mut T` / `Cell`. The Stage-Zero init-phase def-use tracking is a cheap immutability pre-analysis.
- Bootstrapping (Kahlon 2008): use Steensgaard partitions to scope Andersen runs — algorithmic scalability lever independent of parallelism; partitions are also natural parallel work units!
- CORAL is sequential in implementation; stages are pipeline-parallel-unfriendly but partition-parallel-friendly. Combine with KallGraph-style parallelism.
