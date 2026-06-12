# M1 Implementation Plan

*Companion to `DESIGN.md` §10 M1: frozen PAG, Steensgaard + Ω flags, assumption-violation
audit, and a correct end-to-end feed for the globals-localization client.*

## 0. The headline answers

**When do we have a running analysis?** End of step **M1.2** — roughly two weeks in. It
is conservative to the point of being weak (FSA icalls, syntactic global access, blanket
unknown-taint), but it is *end-to-end and sound*: it emits the bipartite caller/callee
graph, components, taint verdicts, and a coverage number for the client. Every step after
M1.2 is a precision/coverage upgrade to a tool that already runs; nothing after M1.2 is
load-bearing for correctness.

**How big is the gap from "parses IR with debug metadata" to "M1 done"?** Moderate, and
front-loaded in an unglamorous place: the IR *lowering* step (M1.1) is where the long tail
lives — not parsing, but normalizing LLVM's warts (constant-expression GEPs/casts inside
global initializers, aggregate first-class ops, varargs, weird intrinsics). The analysis
algorithms themselves (M1.4's Steensgaard is ~300 lines; the Ω bits are two booleans and
five rules) are small by comparison. Total estimate: **24–43 working days** of focused
single-developer effort, with the first demo at ~day 8–10 and the riskiest 30% in M1.1
and M1.3. §2 pins down the observable contract (API surface, export schemas, CLI, golden
tests) — an implementation matching §2 on the fixtures is correct by definition, so an
implementor should read §2 before the algorithm steps. There is no ingestion shortcut in
M1: cclyzer++'s FactGenerator is advisory context only, not an expected buildable
fallback. If native LLVM lowering stalls badly enough that a fallback seems necessary,
stop and ask for a plan decision rather than switching routes.

```
M1.0 synthetic harness ──▶ M1.1 IR→PIR lowering ──▶ M1.2 conservative end-to-end ★ RUNNING
                                                        │
                                  M1.3 PAG ◀────────────┘
                                    │
                          M1.4 Steensgaard + Ω ──▶ M1.5 violation audit ──▶ M1.6 ptr-aware mod/ref
                                                                                  │
                                          M1.7 perf pass ◀───────────────────────┘
                                                │
                                          M1.8 validation & freeze
```

## 1. Standing decisions (made once, here)

- **LLVM version: 14** Fixtures and later
  full-scale corpora must be built with the same clang the reader links against — newer
  readers accept older bitcode but not vice versa, so pin everything to 14 now and record
  the pin in the harness. There is a wrapper script to run clang version 14 in
  `./clang-14.sh`; the libraries are in `/home/brk/tenjin/_local/xj-llvm-14/lib`.
- **Ingestion route (Option A, default): `llvm-ir`**
  All FFI is confined to one crate that lowers LLVM IR into **PIR**, our owned, simple,
  analysis-facing IR. Everything downstream is safe Rust against PIR, and an LLVM upgrade
  later touches one crate.
- **No ingestion fallback in M1.** `cclyzerpp/FactGenerator` may be read for modeling
  ideas and test-case inspiration, but it is advisory only: do not assume it builds, do
  not make it part of CI, and do not switch to TSV ingestion. If native LLVM lowering
  hits a blocker that appears to require a fallback route, stop and check back with the
  project owner.
- **Full-scale corpus build recipe, deferred beyond initial synthetic stages:** per-TU
  `./clang-14.sh -O0 -g -emit-llvm -Xclang -disable-O0-optnone`, whole-program linked with
  `llvm-link`. The
  `-disable-O0-optnone` flag is load-bearing: plain `-O0` stamps `optnone` on every
  function, which would block the `mem2reg` we run ourselves (`opt -passes=mem2reg`) on
  the linked module. Nothing else from the optimizer is applied (DESIGN §8: analyze
  near-`-O0` IR). **M1 implementation scope:** the first implementation stages use only
  checked-in synthetic C/`.ll` fixtures of our own design. Full-scale programs (Vim, PHP,
  coreutils, etc.) are deferred until after the synthetic M1 pipeline is established; at
  that point we add scripts/recipes and generated artifacts remain out of git.
- **Repo layout:** Cargo workspace at repo root:
  `crates/pangs-api` (typed public analysis surface), `crates/pangs-pir` (FFI +
  lowering), `crates/pangs-pag`, `crates/pangs-solve`, `crates/pangs-clients`,
  `crates/pangs-cli` (single `pangs` binary, subcommand per artifact),
  `crates/pangs-testutil`. All IDs are `u32` newtypes; all cross-entity references are
  indices into frozen arenas.
- **Implementation staging:** land M1 in reviewable increments. The first target is the
  M1.2 conservative end-to-end pipeline over synthetic fixtures; later stages add PAG,
  Steensgaard/Ω, audit, mod/ref, and validation without restructuring the earlier CLI,
  API, schema, or golden-test surfaces.
- **Every step ends with a runnable `pangs` subcommand and a committed metrics snapshot**
  (JSON under `metrics/`) so precision/coverage regressions are diffs, not vibes.

## 2. Output contract & observable behavior

This section is normative: it defines what a correct M1 implementation *observably does*.
The algorithm sections say how; an implementation that matches this section's contracts
on the fixture corpus is acceptable regardless of internal choices.

### 2.1 Two-layer design: typed in-memory API is primary, serialization is a projection

- **Primary surface: the `pangs-api` crate.** All analysis results live in frozen,
  index-addressed structures behind a typed API. Unit and integration tests are written
  against *this*, not against serialized bytes (fast, refactor-safe, no parsing in
  tests). Sketch of the M1 surface:

  ```rust
  pub struct Analysis { /* frozen after run() */ }
  impl Analysis {
      pub fn run(module: &Pir, opts: &Opts) -> Result<Analysis, AnalysisError>;
      // entity tables (iterable, index-addressed, interned stable keys)
      pub fn functions(&self) -> &Table<FuncId, FuncInfo>;
      pub fn globals(&self) -> &Table<GlobalId, GlobalInfo>;
      pub fn callsites(&self) -> &Table<CallsiteId, CallsiteInfo>;
      // results
      pub fn callees(&self, cs: CallsiteId) -> CalleeSet<'_>;   // funcs + unknown flag w/ reason
      pub fn callers(&self, f: FuncId) -> CallerSet<'_>;
      pub fn modref(&self, f: FuncId) -> impl Iterator<Item = (GlobalId, Access, Via)>;
      pub fn component_of(&self, f: FuncId) -> ComponentId;
      pub fn component(&self, c: ComponentId) -> &ComponentInfo; // members, frozen?, taint reasons
      pub fn escape(&self, g: GlobalId) -> EscapeStatus;
      pub fn audit_findings(&self) -> &[Finding];
      pub fn lookup_func(&self, key: &str) -> Option<FuncId>;   // and similar resolvers
  }
  ```

- **Secondary surface: a versioned export directory.** `pangs analyze` serializes the
  same results for the refactoring client, debugging, differential testing, and golden
  tests. **The contract is the logical schema + determinism + stable keys — not the
  encoding.** Encodings are swappable behind serde; we start with JSON Lines because the
  team already lives in JSON (cclyzer++ tooling, `jq` debuggability, line-oriented
  diffs), and we keep the exits open rather than locking in: if artifacts get large or a
  consumer needs speed, the known upgrade paths are `postcard`/`bincode` for the
  *non-contractual* PAG cache, SQLite or Parquet for analytics-shaped consumers. None of
  these change the logical schema, so adopting them later is mechanical. (Decision rule:
  revisit encoding only when a measured pain exists — file size >~1 GB, client parse
  time material, or a join-heavy consumer appears.)

### 2.2 Stable keys (the part that makes outputs diffable and clients possible)

Internal `u32` IDs are run-local and never serialized. Every exported record uses string
keys, deterministic for a fixed input module:

| Entity | Key | Notes |
|---|---|---|
| function | LLVM symbol name in the *linked* module | unique by construction (llvm-link suffixes colliding statics `foo`, `foo.1`); source coords carried alongside, not part of the key |
| global | LLVM global name in linked module | same |
| call site | `<funcKey>@<file>:<line>:<col>#<ord>` | `ord` disambiguates multiple calls per location (macro expansions); ord assigned in instruction order |
| abstract object | `stack:<funcKey>@<file>:<line>:<col>#<ord>` / `heap:<funcKey>@…` / `global:<name>` | M1's object kinds |
| component | `c<NNNN>` ordered by smallest member key | stable given membership |

**Missing-location fallback (normative).** Keys must never depend on debug info being
present. When an instruction has no `DebugLoc` (compiler-generated code, macro artifacts,
sanitizer/builtin expansions), the location segment of its key falls back to the
instruction's **deterministic ordinal**: `<funcKey>@!noloc#<k>`, where `k` is the
instruction's index among that function's no-location instructions of the same entity
kind, in module instruction order. The record additionally carries `"loc": null` plus a
`"synthetic": true` flag so the client can render it honestly. Same rule for object keys
(`stack:<funcKey>@!noloc#<k>` etc.). Functions/globals lacking `DISubprogram`/
`DIGlobalVariable` keep their (always-present) symbol-name keys with `"file": null`.

Caveat to document in the manifest: keys are stable across runs *on the same input
module*; across source edits, llvm-link's suffixing may renumber colliding statics and
ordinals may shift (acceptable — no incrementality requirement).

### 2.3 Export directory layout and record schemas

`pangs analyze <module.bc> -o <outdir>` writes (JSONL = one record per line, records
sorted by primary key, object keys in fixed order, no floats, no timestamps outside the
manifest — so byte-identical reruns are a *requirement*, not a nicety):

- `manifest.json` — `{schema_version, pangs_git, llvm_version, input_path, input_sha256,
  opts, files: [{name, records, sha256}], wall_ms}`. The only file allowed to differ
  between identical reruns (`wall_ms`); golden tests exclude it.
- `functions.jsonl` —
  `{"key":"do_cmdline","file":"src/ex_docmd.c","line":871,"external":false,
  "exported":false,"address_taken":true,"vararg":false,"sig":"i32(ptr,ptr,i32)"}`
- `globals.jsonl` —
  `{"key":"p_secure","file":"src/option.c","line":312,"is_const":false,
  "never_written":false,"escape":"module","mutable":true}`
- `callgraph.jsonl` — one record per edge:
  `{"caller":"call_func","callsite":"call_func@src/userfunc.c:3471:9#0",
  "callee":{"func":"f_abs"},"kind":"indirect","tier":"fsa"}` …
  `"callee":{"unknown":"omega_fnptr"}` for unknown-callee edges;
  unknown-caller facts live on functions:
  `{"caller":{"unknown":"address_escapes_to_external"},"callee":{"func":"sig_winch"},…}`.
  `tier ∈ {direct, fsa, steens}` in M1 (M2+ appends `simple`, `steens_cert`, …; consumers
  must treat the set as open).
- `modref.jsonl` — the `global` field is a tagged union, mirroring `callee` in
  `callgraph.jsonl`:
  `{"func":"do_set","global":{"name":"p_secure"},"access":"mod","via":"aliased",
  "witness":"do_set@src/option.c:5120:5#0"}` for concrete globals
  (`via ∈ {direct, aliased}`), and
  `{"func":"do_set","global":{"unknown":"omega_store"},"access":"mod","via":"unknown",
  "witness":"do_set@src/option.c:5134:5#1"}` when the access is through an
  Ω-flagged pointer or an opaque boundary (reason is an open enum:
  `omega_store, omega_load, external_callee, asm, …`). Invariant:
  `global.unknown ⟺ via == "unknown"`, so consumers may filter on either.
  `access ∈ {ref, mod}` in both forms. Unknown-global records are how per-function
  "touches memory we can't name" reaches the client — the client must treat any
  component containing such a `mod` (and, conservatively, `ref`) as tainted, and the
  same witnesses appear in `components.json` taint reasons. Transitive closure is *not*
  exported (clients recompute over the call graph; exporting it would bloat and bake in
  one closure semantics).
- `components.json` —
  `{"components":[{"id":"c0001","frozen":true,
  "taint":[{"kind":"unknown_callee","witness":"call_func@…#0"}],
  "members":["call_func","do_cmdline",…],
  "mutable_globals":["p_secure",…]}],
  "coverage":{"mutable_globals_total":412,"in_rewritable_components":97}}`
- `audit.jsonl` (M1.5) —
  `{"kind":"fnptr_inttoptr","file":"src/eval.c","line":2210,
  "affected":["global:fnptr_table"],"effect":"omega_taint"}`;
  `kind` is an open enum mirroring the detector list.
- `metrics.json` — counts and the coverage headline; the file `metrics/` snapshots are
  copies of this.

JSON Schema documents for each stream are checked into `schemas/` and are the normative
artifact; `pangs analyze --validate` re-reads its own output against them (cheap, catches
drift). `schema_version` bumps on any non-additive change; within M1 changes must be
additive.

### 2.4 CLI contract

```
pangs analyze <module.bc> -o <dir> [--stage conservative|steens] [--validate]
              [--build-mode library|executable]   # default: library (see below)
              [--exports <file>]                  # overrides the exported-symbol set
pangs stats   <module.bc>                      # entity counts to stdout (JSON)
pangs dump-pir|dump-pag <module.bc> [--func K] # debugging projections, *not* schema-stable
pangs check-pag <module.bc>                    # integrity validator; exit 3 on violation
pangs report  <dir>                            # human-readable summary from an export dir
```
Exit codes: 0 success; 2 input/usage error; 3 internal invariant failure (assertion,
schema self-validation failure). Logs to stderr; stdout is reserved for requested data.
`--stage` selects the M1.2-conservative vs M1.4+ pipeline so the conservative path stays
runnable (and golden-tested) forever as the regression floor.

**Build mode** (the DESIGN §11.3 executable-vs-library question, surfaced as a knob in
both `Opts` and the CLI; recorded in the manifest):
- `library`: every symbol with external linkage is externally callable (unknown-caller)
  and externally readable/writable (Ω-seeded). This is the **default** because it is a
  sound over-approximation of *every* link scenario — wrong only in the direction of
  over-tainting. `--exports <file>` (one symbol per line, version-script subset) narrows
  the exported set for libraries with visibility control.
- `executable`: external linkage does not by itself make a symbol externally reachable;
  entry points are `main`, `llvm.global_ctors`/`llvm.global_dtors`, and anything in
  `llvm.used`. Unknown-caller then arises only via genuine Ω escape (function address
  passed to external code — callbacks, signal handlers, pthreads), which the analysis
  derives itself. **The corpus programs (Vim, PHP binary) should be analyzed with
  `--build-mode executable`**; the harness passes it explicitly.
- Mode mismatch is the one silently-unsound knob in the system (analyzing a real library
  as `executable` drops legitimate unknown-callers), so `analyze` logs the mode at
  startup, the manifest records it, and `report` prints it in the header.

### 2.5 Golden tests (how "observable behavior" is enforced)

`tests/golden/<fixture>/` holds a small synthetic C or `.ll` input, build recipe, and the
expected export dir (manifest excluded). CI runs `pangs analyze` and byte-diffs. A
`PANGS_BLESS=1` env regenerates expectations; blessing is a reviewed diff in version
control — this is where a reviewer literally sees "this change added/removed these call
edges / flipped this component to frozen". Initial schemas and goldens are provisional:
create and bless them during implementation so drift is visible, then do a client-owner
schema review before treating them as frozen contracts. Every step M1.2–M1.6 must land
with golden fixtures exercising its observable additions, and determinism (two runs,
byte-identical) is itself a CI assertion over the synthetic fixture set. Full-scale
program determinism is added later with the full-scale corpus scripts.

## 3. Steps

### M1.0 — Synthetic fixture harness (1–2 days)
Build scripts (checked in, pinned) producing `.bc` **with debug info** for synthetic C
and hand-written `.ll` fixtures of our own design. Initial M1 work intentionally avoids
existing codebases; the goal is to make behavior explicit and reviewable before carrying
the pipeline to full-scale programs. Full-scale corpus scripts for GNU/coreutils-style
programs, Vim, and PHP are deferred until after the synthetic M1 pipeline is established,
and generated `.bc` artifacts stay out of git.

Also: `pangs stats <module.bc>` placeholder wired through CI (`cargo test` + a smoke
script), plus the **observable-behavior scaffolding from §2**: `schemas/` directory,
golden-test harness with `PANGS_BLESS` workflow, and the determinism CI check (run twice,
byte-diff) over the synthetic fixture set. **Acceptance:** representative synthetic
fixtures build to `.bc`, `llvm-dis` round-trips them, sizes/function counts recorded in
`metrics/corpus.json`; one trivial golden fixture passes end to end through the harness.

### M1.1 — IR → PIR lowering (3–6 days; the long tail lives here)
PIR design: a flat, owned, pre-digested instruction set — only what analysis needs:
`Alloca`, `Load`, `Store`, `Gep{base, byte_off: Option<u64>}`, `CastPtr`, `PtrToInt`,
`IntToPtr`, `Phi/Select` (as multi-source `Assign`), `CallDirect`, `CallIndirect`
(fn-ptr operand + args), `Return`, `GlobalDef{init}`, `FuncDecl{signature, is_vararg,
is_external}`, `AsmBlob`, `Memcpy`-family, `UnknownIntrinsic`. Notes:
- **Byte offsets resolved at lowering time** via DataLayout (`LLVMOffsetOfElement`/
  `LLVMABISizeOfType`); non-constant GEP indices lower to `byte_off: None`.
- **Constant-expression normalization:** ConstantExpr GEP/bitcast/ptrtoint appearing in
  operands and (especially) global initializers are flattened into PIR pseudo-statements
  in a synthetic `@__global_init` context. This is the single most underestimated task in
  any LLVM analysis; budget for it explicitly and use `cclyzerpp/FactGenerator` and its
  test suite only as advisory sources for synthetic fixture ideas.
- **Debug metadata captured where the client needs it:** `DIGlobalVariable` → global name/
  file/line; `llvm.dbg.declare`/`#dbg_declare` → alloca↔source-variable map; per-
  instruction `DebugLoc`. (The refactoring is source-to-source; every PIR entity that can
  surface in client output must carry source coordinates from day one — retrofitting this
  is miserable.)
- Lowering is per-function and trivially parallel (rayon) from the start, not as an
  optimization but because it forces the frozen-arena discipline early.

**Lowering policy table (normative).** Every LLVM construct gets exactly one of three
verdicts, and `pangs stats` reports per-construct counts for all three so coverage gaps
are visible, not silent:
- **Model** — lower to PIR with real semantics;
- **Taint** — lower to an `Unknown` op that Ω-taints its pointer operands and results
  (the sound "we refuse to understand this" bucket; M1.5's audit detectors largely read
  from it);
- **Skip** — provably irrelevant to points-to/call-graph/mod-ref facts; dropped but
  counted.

| Construct | Verdict | Notes |
|---|---|---|
| missing `DebugLoc` | n/a | affects keys only, never semantics — §2.2 fallback rule |
| opaque pointers (LLVM 15+ default) | Model | PIR never reads pointee types; all type/offset info comes from instructions that carry it: `alloca`'s type, GEP's *source element type*, load/store value types, DataLayout |
| `phi`, `select`, `freeze`, `addrspacecast`, ptr `bitcast` | Model | all become (multi-source) `Assign` |
| `getelementptr` (incl. ConstantExpr form) | Model | byte offset when indices constant, else ⊤ |
| `extractvalue`/`insertvalue`, first-class aggregates (incl. struct returns) | Model | aggregate SSA value = tuple; constant indices by construction → per-field `Assign` |
| `byval` argument | Model | fresh stack object at the call site + copy-in (Memcpy semantics) |
| `sret` argument | Model | it's just a pointer arg to a caller alloca; nothing special |
| atomic load/store, `atomicrmw` (incl. `xchg` of ptr), `cmpxchg` | Model | as plain load/store pairs; ordering is irrelevant to may-alias; `cmpxchg` result via the aggregate path |
| `volatile` load/store | Model | as plain load/store |
| `invoke`/`callbr` | Model | as call; `landingpad` results → Taint |
| tail/`musttail` calls | Model | ordinary calls |
| `alias` (`@a = alias`) | Model | resolve to aliasee as `Assign`/direct call; *interposable* (weak) aliases additionally count as exported under `--build-mode library` |
| `ifunc` | Taint | resolver picks the target at load time; unknown-callee edge. Rare outside libc; revisit only if it shows up in stats |
| `blockaddress` + `indirectbr` | Skip | computed-goto labels are not functions and `indirectbr` is intraprocedural CFG only — no pointer/CG/modref effect. **PHP's VM uses computed goto; this Skip is why that's fine** |
| `llvm.memcpy/memmove/memset` | Model | the PIR `Memcpy` family: whole-object load+store between pointee objects (`memset` non-zero patterns → Taint the dst contents) |
| `llvm.dbg.*` | Skip | consumed for the variable map first |
| `llvm.lifetime/assume/expect/annotation/prefetch` | Skip | no data flow |
| `llvm.va_*`, vararg accesses | Taint | per DESIGN §8 |
| any other intrinsic | **default rule:** Taint if any pointer operand/result, else Skip | whitelist grows by stats-driven review, never ad hoc in code review |
| inline asm | Taint | + M1.5 audit finding |
| `ptrtoint`/`inttoptr` | Model | PIP's Ω wiring (already in PIR set) |
| vectors of pointers (`<N x ptr>`) | Taint | essentially absent in `-O0` C; counted to verify |
| `undef`/`poison` operands | Skip | contribute no targets |
| thread-local globals | Model | ordinary global object (revisit in M5b) |
| `llvm.used`/`llvm.global_ctors`/`dtors` | Model | consumed by the §2.4 build-mode entry-point logic |

The table is exhaustive-by-default: the two `default` rows (intrinsics, plus "anything
unrecognized → Taint if pointer-typed anywhere, else Skip+counted") guarantee no
construct is silently mishandled, and the stats counters make every fallback visible on
real inputs. Acceptance for the synthetic-only M1.1 pass includes: Taint+Skip counts on
the synthetic fixture suite reviewed and each high-frequency entry either promoted to
Model or justified in a comment in the policy table. Vim/PHP review is deferred until
the full-scale corpus scripts are introduced.

**Runnable:** `pangs dump-pir`, `pangs stats` (entity counts, % instructions lowered vs
`UnknownIntrinsic`, varargs/asm inventory). **Acceptance:** the synthetic fixture suite
lowers without panic; counts cross-check against `llvm-nm`/`opt -passes=print<...>` spot
checks where applicable; ≥20 hand-written `.ll` fixtures round-trip with golden PIR
dumps. **Fallback rule:** if ConstantExpr/intrinsic handling is still spewing
`Unknown`s after sustained native-lowering work, stop and ask for a plan decision; do not
switch ingestion to FactGenerator TSV.

### M1.2 — Conservative end-to-end pipeline ★ first running analysis (3–5 days)
Pure PIR consumers, no points-to yet — built against the `pangs-api` surface and export
schemas of §2 (this step implements most of both):
1. **Direct call graph** (trivial from `CallDirect`).
2. **Address-taken function set** (any use of a function other than direct callee).
3. **FSA icall edges** — normative compatibility spec. FSA is the M1 soundness
   envelope: every later tier only *intersects* it, so a too-wide rule costs transient
   precision while a too-narrow rule is a silent false negative (= corrupted rewrite).
   Every rule below is therefore biased wide, and the known-risky width choices cite the
   measured failure they prevent.

   Compatibility is defined on **lowered LLVM signatures** (the `call` instruction's
   function type vs. each address-taken function's definition type). This choice does the
   struct-by-value ABI work for us: clang has already lowered aggregates identically on
   both sides (`sret` hidden return pointers, `byval` stack copies, small-struct
   register splitting), so source-level ABI questions become positional comparisons of
   lowered params. Note that with LLVM 18's opaque pointers there are **no function
   bitcasts left in the IR** — a source-level fn-ptr cast is invisible, the call simply
   carries whatever function type the source cast claimed. That is *why* matching must be
   class-based rather than exact-type: the callee's real signature and the call site's
   claimed signature legitimately differ in deployed C.

   `compatible(site, F)` holds iff all of:

   | Dimension | Rule | Rationale / risk note |
   |---|---|---|
   | calling convention | must be equal | cc mismatch is a guaranteed miscompile, and at `-O0` everything is `ccc`; count any non-`ccc` sighting in stats (its appearance means our assumption broke) |
   | parameter classes | positionwise over the first `min(n_site, m_callee)` params, each pair in the same **register class** (below) | |
   | arity, callee vararg | `m_fixed ≤ n_site` | vararg targets match longer call sites by construction |
   | arity, otherwise | **`m_callee ≤ n_site`** (callee may ignore trailing args); `m_callee > n_site` ⇒ incompatible | callbacks declared with fewer params than the registration type are a common, ABI-harmless C idiom (caller-cleanup); the reverse (callee reads args never passed) reads garbage and real code doesn't rely on it — this asymmetry is a **documented audited assumption**, surfaced in stats (`m < n` match counts) |
   | K&R / no-prototype | mostly dissolves at IR level (calls through `T (*)()` carry their actual lowered args); any residue is covered by the arity rules | note in code where this was considered |
   | return | same register class, or **either side `void`** | ignoring a return, and calling a value-returning function through a `void`-returning type, are both ABI-harmless register-level facts; aggregate returns don't hit this rule at all (they lowered to `sret` params) |

   **Register classes** (SysV x86-64; the table is the target-specific point of the
   design — AArch64 needs its own column if we ever target it):
   - `INTEGER`: all `iN` (N ≤ 64) **and `ptr`**, mutually compatible. Folding all integer
     widths and pointers into one class is deliberately wide: KELP's false-negative
     analysis traced its only dynamic misses to implicit primitive casts (`long` vs
     `char *`), and KallGraph's 32-vs-64-bit syscall-table example is the same failure
     shape. Width punning through fn-ptr casts is real C.
   - `SSE`: `float`, `double`. Not compatible with `INTEGER` (different argument
     registers — a mismatch here genuinely crashes, and C code does not pun across it).
   - `X87`: `x86_fp80` alone. `FP128`/`i128` likewise their own classes.
   - **Attribute-qualified params are their own classes**: `byval(T)` matches only
     `byval` of the same size (a `byval` stack copy vs. a plain pointer is an ABI
     difference hiding behind the same `ptr` type); same for `sret(T)`. This is where
     "compare lowered signatures" needs the attributes, not just the types.

   Required golden fixtures for this spec, one per row above: vararg target; ignored
   return + void-through-int call; `long`/`ptr` arg punning; fewer-param callback;
   `byval` size mismatch (must NOT match); `float`-vs-`int` (must NOT match);
   `x86_fp80`. The dynamic-trace harness (M1.8) is the empirical check that the envelope
   was wide enough — any observed (callsite, target) pair outside FSA is a spec bug to
   fix *in this table*, not in code.

   Every icall also gets an edge to *unknown-callee* in this step
   (blanket-conservative until M1.4 replaces it with Ω-derived reasoning).
4. **Unknown-caller marking**: every address-taken function whose address reaches any
   external call's arguments *syntactically*, every external/exported function — for now,
   conservatively: *all* address-taken functions.
5. **Syntactic global mod/ref** per function + transitive closure over (1)+(3).
6. **Client emission**: the §2.3 export directory — functions, globals, call-graph edges
   with provenance tiers, mod/ref, components with taint witnesses, and the headline
   **coverage metric** (% of mutable globals in rewritable components — expected to be
   near zero at this step; that's fine, the point is the pipeline and the metric).

**Acceptance:** runs on the synthetic fixture suite end to end; export validates against
`schemas/` (`--validate` green); provisional golden fixtures for each record stream;
`metrics/` snapshot committed. §2.3 schemas are reviewed with the client's owner before
the provisional goldens become frozen contracts. From here on, every step must move the
coverage number or shrink components on at least one fixture — visibly, in golden diffs.

### M1.3 — PAG construction (4–8 days)
Frozen graph per DESIGN §4A, *minus* the tier-B refinements (typed heap clones and lazy
field subobjects are M2 — record the inputs they'll need, don't build them):
- Nodes: PIR values, abstract objects (one per alloca/global/function/heap-site).
- Edges: `Assign`, `Store`, `Load`, `Gep{byte_off}` (offsets recorded now, *used* in
  M2+/tier-E; M1's Steensgaard treats objects monolithically).
- **Ω seeding** (PIP): imported symbols, exported symbols *per the §2.4 build-mode knob*,
  external call boundaries, ptrtoint/inttoptr wiring, vararg sinks.
- **CastMap recording** (object-level cast pairs, KallGraph-minimal filtering deferred).
- A `pangs check-pag` integrity validator (no dangling IDs, edge-kind invariants, every
  Store/Load reachable from a function).

**Acceptance:** PAG builds for the synthetic fixture suite; node/edge counts in metrics;
edge-level golden fixtures cover alloc sites, assign/load/store edges, GEPs, calls, and
Ω seeds. cclyzer++/FactGenerator may inform fixture design, but is not a buildable
oracle or CI dependency in M1.

### M1.4 — Sequential Steensgaard + Ω bits (3–5 days)

**State.** Union-find (path-halving) over *all* PAG nodes — value nodes and object nodes
share one universe. Each class representative carries:
- `pointee: Option<Class>` — the single class this class's members may point to
  (Steensgaard's invariant: at most one pointee class; created lazily by
  `pointee_of(c)`, which allocates a fresh empty class on first demand);
- two monotone bits: `EXT` ("members may *point to* external or escaped memory" — PIP's
  `p ⊒ Ω`) and `ESC` ("object members are reachable by external code" — PIP's
  `Ω ⊒ {x}`);
- pending vectors for the call machinery: `icall_sites: Vec<CallsiteId>`,
  `fn_objs: Vec<FuncId>`.

`join(a, b)`: union the classes; OR the bits; concatenate the pending vectors; if both
sides had a pointee class, recursively `join` the pointees (this cascade is why a
worklist is needed); then re-run the *trigger rules* below for any bit/membership that
changed. Termination: joins strictly decrease class count; bits only turn on; pair
applications are memoized — near-linear overall.

**Edge rules** (each PAG edge processed once; cascades via join):

| PAG edge | Rule |
|---|---|
| `p = &o` (alloca/global/function address) | `join(pointee_of(p), class(o))` |
| `p = q` (assign/cast/phi/select/freeze) | `join(class(p), class(q))` |
| `p = *q` (load) | `join(class(p), pointee_of(q))` |
| `*p = q` (store) | `join(pointee_of(p), class(q))` |
| `p = q + off` (Gep, M1 field-insensitive) | `join(pointee_of(p), pointee_of(q))` — p points *into* the same (monolithic) objects q points to; deliberately finer than treating Gep as `p = q`, which would also merge the two pointers' value classes |
| `memcpy(dst, src)` | `join(pointee_of(pointee_of(dst)), pointee_of(pointee_of(src)))` — contents of the pointed-to objects unify (field-insensitive contents-copy) |
| `x = ptrtoint p` | `ESC(pointee_of(p))` — p's targets are now address-exposed (PIP's provenance rule); the int x carries no further tracking |
| `p = inttoptr x` | `EXT(class(p))` — unknown-origin pointer |
| `Unknown`/Taint op (from the M1.1 policy table), inline asm | every pointer operand a: `ESC(pointee_of(a))`; every pointer result r: `EXT(class(r))` |

**Calls.** Each function f's object node `o_f` carries attached `param_i(f)` and
`ret(f)` value nodes (its body's PAG uses them).
- *Direct call* `r = call f(a_1..a_n)`: `join(class(a_i), class(param_i(f)))` for
  i ≤ min(n, arity(f)) — the FSA arity rules (M1.2) decide admissibility, vararg tail
  args of external printf-likes get no binding (their object effects are covered by the
  external-call rule if f is external) — and `join(class(r), class(ret(f)))`.
- *Indirect call* `r = call p(a..)`: register the site in
  `pointee_of(p).icall_sites`. Whenever a class's `icall_sites × fn_objs` product gains
  new pairs (initial registration, or a join brought new function objects), apply, for
  each **FSA-compatible** pair, exactly the direct-call bindings above; memoize applied
  (site, func) pairs. Whenever such a class has or gains `EXT`, additionally apply the
  *external-call rule* to its sites (the unknown-callee case).
- *External call* `r = call ext(a_1..a_n)` (declared-only callee, or the unknown-callee
  case above): for every pointer-typed a_i (incl. vararg actuals):
  `ESC(pointee_of(a_i))`; and `EXT(class(r))` if r is pointer-typed.

**Signature filtering without false negatives.** The FSA filter is applied in exactly
two places: (a) selecting which (site, func) pairs get param/ret bindings, and
(b) computing the *reported* target sets. It is **never** applied to block a `join` —
joins are demanded by assignments that actually execute, and refusing one would be
unsound. The reason (a) is safe: a runtime call whose target is FSA-incompatible with
the site is excluded by the FSA-envelope contract (M1.2's table is the soundness
boundary, checked dynamically in M1.8); given that envelope, an unbound incompatible
class member is a Steensgaard imprecision artifact, and *not* binding it is precisely
what prevents the classic whole-class signature collapse. Operational consequence,
recorded as a build rule: **any widening of the FSA table invalidates and re-runs
M1.4** (new pairs may need bindings).

**Ω seeds** (build-mode-aware, §2.4):
- exported global/function g (per `--build-mode`/`--exports`): `ESC(class(o_g))`;
- imported (declared-only) global: its storage is external — `ESC(class(o_g))`;
- entry-point formals in `executable` mode (`main`'s argv): `EXT` on the param,
  `ESC` on its pointee chain via the flood rule below.

**Bit propagation (the unification form of PIP's Fig. 7).** One flood rule, applied as
a trigger whenever a bit is first set or a pointee link appears/merges:

> if `EXT(c)` or `ESC(c)`, then set *both* `EXT` and `ESC` on `pointee_of(c)` (creating
> it if c has any pointee link; do not create one otherwise).

Justification per bit-direction: contents loaded from escaped memory may have been
overwritten by external code with unknown pointers (`ESC(c) ⇒ EXT(pointee)`); objects
reachable from escaped memory are reachable by external code (`ESC(c) ⇒ ESC(pointee)`);
loads through unknown-origin pointers yield unknown-origin values
(`EXT(c) ⇒ EXT(pointee)`); and values stored through unknown-origin pointers land in
externally accessible memory, so their targets escape — which we over-approximate as
`EXT(c) ⇒ ESC(pointee)`. That last clause is *coarser than PIP* (PIP's invariant lets it
avoid marking everything an unknown pointer can reach as escaped; class pollution makes
the fine version awkward under unification). The coarseness errs toward more
escape/taint — the sound direction for the client — and tiers D/E carry the precise Ω
rules for whatever this over-freezes. The escaped-function consequence falls out
automatically: when `ESC` lands on a class containing function objects, those functions
become unknown-callers, and a trigger applies `EXT(class(param_i))` and
`ESC(pointee_of(ret))` for each such f (external code may call f with arbitrary
arguments and read its returns — PIP's `CalledByΩ`).

**Outputs wired into the M1.2 pipeline**, replacing blanket conservatism:
icall targets := FSA ∩ {address-taken functions in `pointee_of(p)`} (∪ unknown-callee
iff that class has `EXT`); unknown-caller := functions whose object class has `ESC`
(this now *includes* the exported set via seeding, so the M1.2 special case retires);
`never-written` mutability for globals whose cell class receives no store and lacks
`ESC`.

**Acceptance:** one fixture per edge rule and per Ω seed/trigger above (the store-through-
unknown and escaped-function-object cases especially — they're the ones a wrong flood
rule silently drops); strictly ⊆ FSA targets per icall, zero new unknowns vs M1.2 (only
removals); coverage metric moves on at least one synthetic fixture. Sequential is
deliberate: at ≤1 MLoC this is likely seconds, and M1.7 will prove or disprove the need
to parallelize it with a profile once full-scale inputs are introduced.

### M1.5 — Assumption-violation audit (2–3 days)
Detectors over PIR (each is a local pattern match): inline asm; ptrtoint/inttoptr whose
class reaches function pointers; memcpy/memset over aggregates containing fn-ptr fields;
fn ptrs passed to varargs; `dlopen`/`dlsym`; `setjmp`/`longjmp`. Each detection emits a
structured finding (kind, source location, affected PAG nodes) **and** sets Ω-taint on
the involved classes, so the component containing it freezes automatically (DESIGN §7's
audited soundiness). **Acceptance:** `pangs audit` report on the synthetic fixture suite;
findings count in metrics; a written one-page "per-component soundness statement"
deriving what guarantee survives, reviewed against the detector list.

### M1.6 — Pointer-aware global mod/ref (2–4 days)
Upgrade M1.2's syntactic mod/ref: a store/load through pointer `p` mods/refs global `g`
iff `pointee_of(find(p))` contains `g`'s object; if `find(p)` has the `EXT` bit, emit an
**unknown-global record** (`"global":{"unknown":"omega_store"|"omega_load"}, "via":
"unknown"` per §2.3) — one per witnessing instruction, not per hypothetical global.
Recompute transitive closure; client output now distinguishes `direct|aliased|unknown`
access provenance, and component taint reasons cite the unknown-record witnesses.
**Acceptance:** mod/ref ⊇ syntactic on every function (regression check); coverage delta
recorded; spot-audit aliased-access findings by hand on synthetic fixtures designed to
exercise indirect global access.

### M1.7 — Performance pass (3–5 days)
Profile-first, initially on the largest synthetic stress fixture. Expectations are PAG
build and client closures dominate, with Steensgaard a rounding error at this scale.
Parallelize what the profile indicts (PAG build is already sharded from M1.1; closures
via rayon; concurrent union-find **only if measurements demand it** — DESIGN §5 keeps it
in reserve for bigger inputs). The PHP-scale budget is deferred until full-scale corpus
scripts are introduced. **Acceptance:** flamegraph + before/after wall times in metrics;
no output diffs vs M1.6 (bit-for-bit).

### M1.8 — Validation & baseline freeze (3–5 days)
- **Internal differential checks** over synthetic fixtures: compare conservative,
  Steensgaard, and later solver stages for the required subset/monotonicity relations;
  triage diffs into {bug, intended precision difference}. cclyzer++ remains advisory
  only, not a required oracle.
- **Dynamic icall spot-validation:** tiny LLVM pass (or PIR-driven source instrumentation)
  logging `(callsite, target)` at indirect calls; run the synthetic executable fixtures;
  assert every observed pair is in our edge set. This is the cheap version of the
  KallGraph/KELP/CORAL trace methodology and the right standard of evidence for a
  transformation feed. Full-scale test-suite validation is deferred until the full-scale
  corpus scripts exist.
- Freeze the M1 metrics dashboard (coverage, components, unknowns, violations, wall time)
  as the baseline M2's certificates must beat.

## 4. Effort & risk summary

| Step | Est. days | Risk | Mitigation |
|---|---|---|---|
| M1.0 | 1–2 | fixture gaps | synthetic fixture checklist; full-scale corpus deferred |
| M1.1 | 3–6 | ConstantExpr/intrinsic long tail | fixture-driven; stop-and-check-back if native lowering stalls |
| M1.2 | 3–5 | schema churn after blessing | provisional goldens first; client-owner review before freezing (§2.5) |
| M1.3 | 4–8 | IR-modeling correctness | edge-level goldens; FactGenerator advisory only |
| M1.4 | 3–5 | Steensgaard fn-ptr collapse | signature filtering; measured vs FSA |
| M1.5 | 2–3 | low | detector list reviewed vs DESIGN §8 |
| M1.6 | 2–4 | low | regression: ⊇ syntactic |
| M1.7 | 3–5 | premature parallelism | profile-first rule |
| M1.8 | 3–5 | schedule pressure to skip | dynamic check is a client-trust gate |
| **Σ** | **24–43** | | |

Sequencing freedom: M1.5 and M1.6 are independent of each other; M1.3 can start while
M1.2's client schema is being reviewed. The only hard chain is 1.0 → 1.1 → {1.2, 1.3} →
1.4 → rest.
