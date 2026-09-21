# Source obligations and localization contract (version 3)

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
plan version is 3**. IR-only schema-8 manifests remain readable but do not
satisfy Tenjin's localization contract. `context_rewrite.source` records
normalized source paths, compilation commands, expanded cc1 options, compiler
version, construction recipe, and extraction/closure measurements. Each field
carries `source_edits` and reason edges. The selected projection carries the
deduplicated, conflict-checked edit union. Conditional `source_wrappers` recipes
are included only for functions that none of the selected fields needs to change.
Edits have byte ranges, replacement,
and kind. Tenjin controls source
changes and the order of analysis and rewriting; neither side checks for
changes to the analyzed inputs or stores source hashes or original edit text.

Runtime written/escape/points-to/call-graph facts are unchanged. Concrete source
observations are recorded under `facts.source_obligations`: assignments,
increments/decrements, reads, pointer reads, address-taking, array decay and
unevaluated operands, each with a source location and containing function.
Unknown uses are explicit. The old `requires_mutable_storage` conclusion is
not emitted. Absence from the manifest is never an immutability proof. Source-only functions can
enter a recipe, but source-only globals are not silently added as disposition
subjects. Safety gates are rechecked for newly reached functions.

LLVM constant definitions are disposition subjects too, including function-scope
statics. Their source obligations and emitter capabilities are checked before
selecting `immutable`; C `const` alone does not imply an immutable Rust static.

Source obligations follow C2Rust's per-TU declaration dependency closure with
`--preserve-unused-functions` disabled. Roots are externally visible function
and variable definitions (including the compiler's inline visibility rules)
and declarations marked `used`. Dependencies include source references in
constant-false branches, initializers, types and cleanup attributes. This is
not LLVM reachability. Discarded declaration bodies do not contribute effects
or callback-flow blockers. The manifest records the retention policy, retained
function definitions and discarded declarations; Tenjin checks the policy.

Retention also follows the AST that C2Rust actually exports, not every child
visited by Clang's default visitor. `_Generic` retains only its selected
expression. `typeof` operands, constant array bounds, enum values, bitfield
widths, alignment operands and type-compatibility predicates contribute their
exported type/value rather than references in the folded-away syntax. Ordinary
`sizeof` expression dependencies and variable-length array bounds remain
distinct from these folded forms.

Logical C2Rust pruning does not by itself require source edits. PANGS preserves
discarded declarations and folded expressions unless a selected localization
would invalidate something they name. Dependency edges then pull in the needed
`prune-declaration` and `prune-expression` edits transitively. This keeps, for
example, an unrelated constant array bound in its original form while still
removing a discarded function and a folded `sizeof` expression that names it.
For `_Generic`, pruning preserves the selected expression's offsets for nested
signature and call edits. Unprintable or callable `typeof` rewrites and
declaration groups that cannot be pruned independently block only plans that
reach them; the consumer never guesses a repair.

## Emitter profile and disposition

Source-enabled analysis currently targets the fixed `tenjin-c2rust-default-v1`
profile, recorded in both source metadata and per-global obligations. This is
the actual Tenjin C2Rust configuration without `--preserve-unused-functions`,
not an arbitrary Clang frontend's notion of liveness. No separate PANGS
preservation flag or generalized capability negotiation is needed. Tenjin
rejects a mismatched profile. Custom user type/mutability guidance remains an
explicit override outside the default-representation guarantee.

The profile is tied to these emitter implementations and tested by translating
the same fixtures through C2Rust:

| Emitter behavior | Planning constraint |
| --- | --- |
| `TypedAstContext::prune_unwanted_items(false)` | Declaration-dependency retention, not LLVM reachability |
| `static_decl_rust_mutability` / `type_contains_unguided_raw_pointer` | Default immutable static must not contain object raw pointers; function pointers are allowed |
| `static_initializer_is_uncompilable` | Initializer forms moved to runtime assignments cannot use immutable storage |
| `static_storage_root` / `convert_address_of_common` | Read-only address-taking and array decay support const-address lowering |
| Tenjin context materializer | Joined variable declarations, unprunable groups and unsupported context recipes are blocked before selection |
| Tenjin recipe consumers | Immutable, native atomic and localize are implemented; OnceLock/Mutex materialization is not |

PANGS records initializer syntax features (for example unsigned arithmetic,
pointer-to-integer casts and bitfield initializers) separately from runtime
facts. Disposition checks the proposed strategy against the profile. A retained
direct assignment rejects immutable storage even when LLVM proves
`written=false`; a discarded writer adds no obligation. Address-taking alone
does not reject immutable storage. Pointer-containing palette arrays reject
the *default immutable representation*, not semantic immutability. Each failed
guard has a source witness, and the ordinary cascade considers its remaining
strategies, including localization. LLVM evidence and certificates are preserved.

Declaration bindings include C2Rust's function scope (`function:local_static`).
Tenjin forwards the exact binding for a finalized immutable selection, without
rediscovering declarations or stripping the function name.

Supported source constraints include direct calls, global references,
indirect calls through fields/variables/arrays, initializers, assignments,
conditional producers, direct argument/parameter flow, and pointer comparison
constraints. A changed slot receives context-taking function values. Functions
that need localized storage change signature, as do the callers that must pass
them context. Other producers use `_xjw` wrappers that ignore the context and
forward the original arguments and return value. Their original declarations,
definitions, direct callers and unrelated callback slots remain unchanged.

Function-value occurrences are distinct graph nodes: changing a function reaches
all its occurrences, but changing an occurrence does not require changing that
function. This source closure replaces the IR-only recipe's all-target signature
closure; LLVM's runtime facts, access/lifetime gates and unknown-entry checks
remain intact. An external producer can be adapted when those gates permit it;
an unresolved runtime callback escape still blocks localization.

Each original function has one adapter identity. Externally linked functions
get one external wrapper definition for the entire program and declarations in
the participating TUs; private functions get private wrappers. Comparisons join
the relevant slots and occurrences, so comparisons use the same adapter rather
than comparing an adapter to its original. Opaque/cast escapes, weak/alias symbols,
`returns_twice` functions (which cannot safely return through a forwarding frame),
unsupported wrapper signatures and generated-name collisions are rejected.
The wrapper's declaration types must already be visible at its insertion point.
The selected projection omits an adapter if another selected field already
requires its original function to take context. PANGS composes and validates
the final edit list. Tenjin checks its supported operations, paths, ranges and
overlaps, then applies the supplied edits without interpreting wrapper recipes
or independently choosing adapters.

Single-level callback typedefs are cloned per affected use; equal signatures
and shared typedef names do not themselves create value flow. Declarations of
externally linked functions and shared fields are checked across TUs. Private
function copies, including static inline functions from headers, may have
different signatures in different TUs. `main` retains its ABI.

Version 3 deliberately blocks, with scoped witnesses, unsupported callable
returns/nested higher-order values, typedef alias chains, pointer-to-pointer
callable storage, union callable storage, aggregate copies, opaque/cast or
variadic transfers, external callback consumers/storage, external-inline
boundaries, assembly operands, lifecycle entries, context
name collisions, static initializer dependencies, and owned synthetic storage
requiring a relocation recipe.
The automatic context-in-main recipe also leaves storage in place when its
initializer refers to a private function in another TU. Changing the callback
type is still supported; moving its storage would require a separate recipe
that initializes it in the owning TU without changing function identity.
Some checks conservatively reject safe programs; these are coverage limits,
not accepted-risk proofs. New forms need an extraction rule and executable
recipe with regressions before removing their blockers.

## Corresponding declarations across translation units

Preprocessing a shared header produces a separate copy of its declarations in
each translation unit. Independently written declarations can describe the
same external object or compatible types too. Such declarations must remain
compatible after rewriting, even when their source text differs: macro
expansion, typedefs, `int` versus `signed int`, parameter names and whitespace
can all change the spelling without changing the required interface.

Correspondence is not textual equality, a shared filename, or a matching name
alone. Independent private declarations need not change together merely
because they look alike. Conversely, different names can refer to objects
whose declarations share one type. For example, suppose two TUs each contain:

```c
extern struct { int x; } g1, g3;
extern struct { int x; } g2;
```

Within either TU, `g1` and `g3` share a type; `g2` has a distinct type despite
its identical layout. Across TUs, declarations of the same external object
must remain compatible. A correspondence model must account for both these
relationships, including their transitive consequences. Matching only type
contents, only variable names, or only sets of variable names is insufficient.
This example describes the identity problem, not a promise that every
anonymous-type form is supported by the current planner.

There is no inherently authoritative copy from which to copy all changes.
Different TUs or localization candidates can impose different requirements
on corresponding declarations. Planning must combine compatible requirements
and reject conflicts; choosing one modified definition and overwriting the
others can discard required transformations.

PANGS separates the semantic operation from its concrete source edit. For
example, adding a context parameter to a callback field requires finding that
field's parameter list in each corresponding declaration. The
[extractor](crates/pangs-source/src/extract.cpp) groups supported declarations
by identity and uses each declaration's Clang `TypeLoc` to generate its own
edit. Byte offsets and replacement text need not be equal across TUs. A
typedef use may need a cloned context-taking typedef where another occurrence
has an explicit function-pointer declarator. Neither a byte-identical
definition nor a formatting pass is a prerequisite, and offsets relative to
one definition must not be reused in another.

Clang supplies syntax and type information, not a complete correspondence
algorithm for this transformation. The current identities use Clang USRs,
function/parameter identities and record field positions. The
[source planner](crates/pangs-source/src/lib.rs) checks canonical signatures
and record layouts/field types, collects the edits required by each candidate,
and supplies them for final composition. These mechanisms support the modeled
cases; unsupported forms need explicit handling rather than inference from
similar spelling. Post-edit validation checks consistency but does not invent
missing edits.

Consistent source edits do not by themselves reconstruct shared headers.
Corresponding declarations can require compatible changes with different final
spellings. Tenjin separately decides whether those changes can be consolidated
into a header and preserves them if an include remains expanded; see its
`docs/passes/refold_and_revert.md`. Refolding convenience must not determine
which declarations PANGS changes or force independent declarations to agree.

## Validation and materialization

`pangs validate-source --source-compdb COMMANDS [--removed-global NAME ...]`
checks rewritten C and cross-TU consistency of external functions, globals and
records without running the solver or repairing source. The older
`pangs reproject` command remains available for explicit artifact demotion, but it is not part of the
Tenjin pipeline and is not a substitute for disposition's feasibility guards.

Tenjin supplies the effective database from its bitcode builder, checks the
plan's supported operations and internal consistency, applies signature edits
on a private copy, and performs its existing context-storage materialization.
It makes initializer function declarations visible in `main` and places the
required complete type definitions before each generated context-header include.
Late definitions are moved rather than duplicated.
It validates C with both provided compilers and calls `validate-source` before publication.
Unexplained C errors abort without publishing partial edits.
Materialization gets one private attempt. Any unexpected failure reports a
source-plan contract violation, preserves the original source and manifest,
and does not demote, retry or run policy. Known limitations belong in the
planner. The existing downstream Rust compilation gates still apply.

For development across the two repositories, set `XJ_PANGS_EXE` in Tenjin to
the newly built `pangs` binary; otherwise its provisioned release is used.
Cross-repository tests in `tests/test_pangs_source.py` use this override.

The original source-plan-v1 libtommath survey snapshot had 163 translation units and 5,882 source
calls. That survey rejected its localization candidates that
reach the retained `pthread_create`/`CreateThread` callback paths, even when
LLVM eliminates those paths. Supporting these cases requires a separately
justified recipe; successful analysis does not imply localization coverage.
An end-to-end run with `XJ_EXTRA_PREPARATION_PASSES=0` (skipping the lengthy
preprocessor-refolding pass) compiles the translated Rust and matches the C
test program's exit status and summary. Its final zero-unsafe-functions
assertion failed: 247 unsafe functions remained. Those are historical baseline
measurements; the retention-aware corpus comparison is recorded in Tenjin's
survey report. The unsafe-count assertion is not relaxed by this contract.
