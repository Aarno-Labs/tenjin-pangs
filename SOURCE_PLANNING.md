# Source-aware localization contract (version 1)

`pangs analyze module.bc --dispose --repo-root ROOT --source-compdb COMMANDS ...`
augments the analysis-owned localization candidates before disposition. The
database must describe the exact preprocessed, static-uniquified translation
units used to build the module, with effective compiler/target/ABI flags.
Different commands for the same file, ambiguous global/function names, parse
failures, and incompatible cross-TU declarations fail explicitly.

`pangs-source` links Clang 14's C++ APIs in-process because parameter-list
`TypeLoc`s and semantic aggregate initializers are needed. Build with
`LLVM_SYS_140_PREFIX` pointing at an LLVM/Clang 14 installation containing
headers and `libclang-cpp`. ASTs are released after each TU; only owned facts
are retained. A private VFS honors each command's working directory. The
driver's cc1 job preserves `.i` input mode (ClangTool 14 itself rejects these
jobs). This is not a separate extractor executable or interchange service.

The existing manifest schema remains 8; the independent required **source
plan version is 1**. IR-only schema-8 manifests remain readable but do not
satisfy Tenjin's localization contract. `context_rewrite.source` records source
hashes and normalized paths, compilation commands and their hash, expanded
cc1 options, compiler version, linked-module hash, construction recipe, and
extraction/closure measurements. Each field carries `source_edits` and reason
edges. The selected projection carries the deduplicated, conflict-checked edit
union. Edits have byte ranges, expected original text, replacement, and kind.

Runtime written/escape/points-to/call-graph facts are unchanged. Source writes
and address uses are recorded under `facts.source_representation`; absence
from the manifest is never an immutability proof. Source-only functions can
enter a recipe, but source-only globals are not silently added as disposition
subjects. Safety gates are rechecked for newly reached functions.

Supported source constraints include direct calls, global references,
indirect calls through fields/variables/arrays, initializers, assignments,
conditional producers, direct argument/parameter flow, and pointer comparison
constraints. All producers of a changed slot receive the same signature.
Single-level callback typedefs are cloned per affected use; equal signatures
and shared typedef names do not themselves create value flow. Declaration
occurrences and shared fields are checked across TUs. `main` retains its ABI.

Version 1 deliberately blocks, with scoped witnesses, unsupported callable
returns/nested higher-order values, typedef alias chains, pointer-to-pointer
callable storage, union callable storage, aggregate copies, opaque/cast or
variadic transfers, external callbacks/producers/storage, external-inline
boundaries, assembly operands, lifecycle entries, context
name collisions, static initializer dependencies, and owned synthetic storage
requiring a relocation recipe. It emits no identity-changing adapters.
Some checks conservatively reject safe programs; these are coverage limits,
not accepted-risk proofs. New forms need an extraction rule and executable
recipe with regressions before removing their blockers.

`pangs validate-source --source-compdb COMMANDS [--removed-global NAME ...]`
checks rewritten C and cross-TU function/global/record consistency without
running the solver or repairing source. `pangs reproject MANIFEST --failures
FAILURES --out OUTPUT` accepts a JSON map of global keys to witnesses, applies
only demotions, preserves analysis and cascade history, respects joint
once-lock/mutex groups, and reprojects the surviving recipes without rerunning
the cascade. Concrete markers/validation from a previous attempt are invalidated.

Tenjin supplies the effective database from its bitcode builder, verifies the
source contract and anchors, applies signature edits on a private copy, and
performs its existing context-storage materialization. It validates C with
both provided compilers and calls `validate-source` before publication. Stale
inputs or unexplained C errors abort without publishing partial edits. Known
materializer limitations (including joined global declarations) demote only
their dependent fields and restart from the unchanged snapshot through
`reproject`; failed edits are never reused. The
existing downstream Rust compilation gates still apply. Representation
demotions use `reproject` and retain the semantic analysis evidence.

For development across the two repositories, set `XJ_PANGS_EXE` in Tenjin to
the newly built `pangs` binary; otherwise its provisioned release is used.
Cross-repository tests in `tests/test_pangs_source.py` use this override.

The libtommath regression snapshot has 163 translation units and 5,882 source
calls. Source planning currently rejects its localization candidates that
reach the retained `pthread_create`/`CreateThread` callback paths, even when
LLVM eliminates those paths. Supporting these cases requires a separately
justified recipe; successful analysis does not imply localization coverage.
An end-to-end run with `XJ_EXTRA_PREPARATION_PASSES=0` (skipping the lengthy
preprocessor-refolding pass) compiles the translated Rust and matches the C
test program's exit status and summary. Its final zero-unsafe-functions
assertion still fails: 247 unsafe functions remain. This is a coverage limit,
not a passing result for the full slow test; that assertion is unchanged.
