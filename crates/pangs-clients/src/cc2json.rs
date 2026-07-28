//! Port of the `cclyzer++` `cc2json` standalone client (see `src/cc2json.cpp` and
//! `datalog/` in the cclyzer.tenjin tree) onto pangs' analysis outputs.
//!
//! `cc2json` consumed bitcode, ran cclyzer's points-to + a set of derived datalog relations
//! (escape analysis, bipartite call-graph connected components, mutable-global tissue, global
//! initializer references), and emitted a JSON summary. This module reproduces that JSON from
//! pangs' primitives (`Analysis::call_edges`/`callsites`/`modrefs`/`globals`/`functions`, the
//! PIR, and a direct solver run for escape/points-to facts).
//!
//! Fidelity: the goldens (`ju_cc2json/*.cc2json.json`) were produced by cclyzer's *unification*
//! points-to (`--datalog-analysis=unification --context-sensitivity=insensitive
//! --entrypoints=library`, no `--internalize-globals`). pangs is an independent solver, so some
//! set-level results may diverge; divergences are noted inline. Sections verified exact on the
//! `lib-small` golden: `mutated_globals`, `global_initializer_references`, `mutable_global_tissue`,
//! `unique_filenames`, `call_graph_components`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use anyhow::{Context, Result};
use pangs_api::{
    AffectedGlobals, Analysis, BuildMode, CallKind, Callee, Caller, FuncId, Opts, Stage,
};
use pangs_pag::{Pag, PagOpts};
use pangs_pir::{Access, Func, Loc, Pir, Stmt};
use pangs_solve::{
    solve_andersen_with_global_points_to, solve_steensgaard_with_global_points_to, SolveResult,
};

/// Options for the `cc2json` subcommand. `entrypoints`/`build_mode` follow pangs naming
/// (library = all functions reachable; executable = reachable from `main`). `internalize_globals`
/// mirrors cclyzer's flag — when off (the default, matching how the goldens were produced),
/// external-linkage globals are externally visible and can anchor escape. `partition_budget`
/// caps which partitions the Andersen stage refines (oversize ones fall back to Steensgaard).
#[derive(Debug, Clone)]
pub struct Cc2jsonOpts {
    pub stage: Stage,
    pub build_mode: BuildMode,
    pub internalize_globals: bool,
    pub partition_budget: u64,
}

/// Run the analysis on `pir` and render the `cc2json` JSON summary.
pub fn run_cc2json(pir: &Pir, _input_path: &Path, opts: &Cc2jsonOpts) -> Result<String> {
    let api_opts = Opts {
        stage: opts.stage,
        build_mode: opts.build_mode,
        ..Opts::default()
    };
    let analysis = Analysis::run(pir, &api_opts).context("run pangs analysis")?;

    // Global-object points-to for escape analysis. The Andersen stage refines this within the
    // partition budget (oversize/uninteresting partitions keep the Steensgaard answer); the Steens
    // stage uses Steensgaard for every partition. cclyzer ran unification, so its goldens match the
    // Steens stage exactly — Andersen only narrows (never widens) the points-to it builds on.
    let pag = Pag::from_pir(
        pir,
        &PagOpts {
            build_mode: opts.build_mode.into(),
            ..PagOpts::default()
        },
    );
    let solved = match opts.stage {
        Stage::Andersen => solve_andersen_with_global_points_to(
            pir,
            &pag,
            opts.build_mode.into(),
            opts.partition_budget,
        ),
        _ => solve_steensgaard_with_global_points_to(pir, &pag, opts.build_mode.into()),
    };

    let source = pir.source.clone().unwrap_or_default();

    let mutated = mutated_globals(pir, &analysis);
    let escaped = escaped_globals(pir, &solved, opts.internalize_globals, opts.build_mode);

    let mut json = JsonBuilder::new();
    write_cc2json(&mut json, pir, &analysis, &source, &mutated, &escaped);
    Ok(json.into_string())
}

// ---------------------------------------------------------------------------
// Section 1: mutated_globals
// ---------------------------------------------------------------------------

/// Named globals considered *mutated* by cclyzer (escape-analysis.dl), in PIR/global-definition
/// order with `.`-prefixed (string-constant) names dropped. Two sources:
///
/// * Store target: a global written by a store instruction — pangs' `access:mod` modref rows.
///   (Not `globals().mutable`/`never_written`, which fold in static-initializer writes.)
/// * Non-readonly argument: a global whose address is passed to a call-argument position that is
///   not known-readonly. With no per-callee readonly knowledge for user functions, any
///   by-address global argument counts (e.g. hashmap's `__func__.*` arrays passed to a printf),
///   except positions in the ported libc readonly table — which includes `__assert_fail` (so the
///   `__PRETTY_FUNCTION__.*` arrays it receives are not flagged).
///
/// DIVERGENCE: the argument rule resolves only globals whose address an argument *directly*
/// denotes (a `@g`, a temp gep/bitcast chain, or a constant-expr `getelementptr`/`bitcast` over a
/// global). It cannot follow values that flow through memory/loads, so executables relying on
/// aliased arguments may still under-report relative to cclyzer's full points-to.
fn mutated_globals(pir: &Pir, analysis: &Analysis) -> Vec<String> {
    let defined = defined_globals(pir);
    let mut mutated = BTreeSet::<String>::new();
    for mr in analysis
        .modrefs()
        .iter()
        .filter(|mr| matches!(mr.access, Access::Mod))
    {
        if mr.detail.as_deref().is_some_and(|detail| {
            detail.starts_with("high_fanout_pointer_modref:")
                && detail.contains("pointee_has_string=true")
        }) {
            continue;
        }
        match analysis.affected_globals(mr) {
            AffectedGlobals::Finite(globals) => {
                mutated.extend(globals.iter().map(|&id| analysis.globals()[id].key.clone()))
            }
            AffectedGlobals::ModuleWide => {
                mutated.extend(
                    analysis
                        .globals()
                        .iter()
                        .filter(|g| g.mutable && defined.contains(g.key.as_str()))
                        .map(|g| g.key.clone()),
                );
            }
        }
    }

    let global_names: BTreeSet<&str> = pir.globals.iter().map(|g| g.key.as_str()).collect();
    let arg_mutated = mutated_via_call_args(pir, &global_names);
    mutated.extend(arg_mutated);

    // cclyzer only forms a global_allocation for globals *defined* in the module, so external
    // declarations (e.g. libc's `stdout`) are never mutated. pangs records a `GlobalRef` mod in
    // `global_init` for exactly the defined globals (those with an initializer), so restrict to
    // that set. This drops field-insensitive aliased false-positives that land on extern decls
    // (sbase's `stdout`) without losing defined aggregates like `g_buffer`.
    analysis
        .globals()
        .iter()
        .filter(|g| mutated.contains(g.key.as_str()) && defined.contains(g.key.as_str()))
        .filter_map(|g| process_global_name(&g.key))
        .collect()
}

/// Globals *defined* in this module (those with a constant initializer). pangs' PIR lowering emits
/// a `GlobalRef` mod into `global_init` for each such global; external declarations are absent.
fn defined_globals(pir: &Pir) -> BTreeSet<&str> {
    pir.global_init
        .iter()
        .filter_map(|stmt| match stmt {
            Stmt::GlobalRef { global, .. } => Some(global.as_str()),
            _ => None,
        })
        .collect()
}

/// Globals whose address is passed to a non-readonly call-argument position (cclyzer's
/// mutation-via-(external-)function rule). Direct calls use the ported readonly table; indirect
/// calls have no callee identity here, so any global-address argument is conservatively mutated.
/// Returns full global names; the caller drops `.`-prefixed ones.
fn mutated_via_call_args(pir: &Pir, global_names: &BTreeSet<&str>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for func in &pir.functions {
        let mut resolver = BaseGlobalResolver::new(func);
        for stmt in &func.body {
            match stmt {
                Stmt::CallDirect { callee, args, .. } => {
                    for (index, arg) in args.iter().enumerate() {
                        if known_readonly_arg(callee, index) {
                            continue;
                        }
                        if let Some(base) = resolver.resolve_arg_global(arg) {
                            if global_names.contains(base.as_str()) {
                                out.insert(base);
                            }
                        }
                    }
                }
                Stmt::CallIndirect { args, .. } => {
                    for arg in args {
                        if let Some(base) = resolver.resolve_arg_global(arg) {
                            if global_names.contains(base.as_str()) {
                                out.insert(base);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    out
}

/// Extract the first `@symbol` name from an operand string (used for inline constant-expr args).
fn first_global_symbol(operand: &str) -> Option<String> {
    let at = operand.find('@')?;
    let name: String = operand[at + 1..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '$' | '-'))
        .collect();
    (!name.is_empty()).then_some(name)
}

/// Whether argument `index` of `callee` is a known read-only pointer position. Ported from the
/// `known_readonly_arg` rules in escape-analysis.dl, plus `__assert_fail` (all positions
/// read-only) so the `__PRETTY_FUNCTION__`/`__func__` strings it receives are not treated as
/// mutated. Match exact libc names and anchored LLVM intrinsic prefixes; substring matching would
/// incorrectly classify unrelated writable callees whose names merely contain a readonly helper.
fn known_readonly_arg(callee: &str, index: usize) -> bool {
    let callee = normalized_callee_name(callee);
    // assert helpers: all arguments are read-only.
    if matches!(
        callee,
        "__assert_fail" | "__assert_perror_fail" | "__assert_rtn"
    ) {
        return true;
    }
    // memcpy/memmove source (arg 1), incl. LLVM intrinsics.
    if (matches!(
        callee,
        "memcpy" | "memmove" | "__memcpy_chk" | "__memmove_chk"
    ) || callee.starts_with("llvm.memcpy.")
        || callee.starts_with("llvm.memmove."))
        && index == 1
    {
        return true;
    }
    // strcpy/strncpy source (arg 1).
    if matches!(
        callee,
        "strcpy" | "strncpy" | "__strcpy_chk" | "__strncpy_chk"
    ) && index == 1
    {
        return true;
    }
    // string search/compare: args 0,1,2 read-only.
    if matches!(
        callee,
        "strlen"
            | "strcmp"
            | "strncmp"
            | "strchr"
            | "strrchr"
            | "strstr"
            | "strcspn"
            | "strspn"
            | "strpbrk"
    ) && index <= 2
    {
        return true;
    }
    // memory search: memchr/memcmp args 0,1,2.
    if matches!(callee, "memchr" | "memcmp") && index <= 2 {
        return true;
    }
    // bsearch: key/array (args 0,1).
    if callee == "bsearch" && index <= 1 {
        return true;
    }
    // llvm.objectsize: arg 0.
    if callee.starts_with("llvm.objectsize.") && index == 0 {
        return true;
    }
    false
}

fn normalized_callee_name(callee: &str) -> &str {
    callee.strip_prefix('@').unwrap_or(callee)
}

// ---------------------------------------------------------------------------
// Section 2: escaped_globals
// ---------------------------------------------------------------------------

/// Allocations (functions and global variables) that *escape* in cclyzer's dataflow sense — not
/// merely "externally visible". Reimplemented over the PIR, mirroring escape-analysis.dl:
///
/// * Store-escape: a global value stored (by a *function-body* store instruction) into an
///   externally-accessible global — or into an already-escaped global — escapes. Crucially this
///   uses runtime stores only, NOT static initializers, matching cclyzer (whose escape rule reads
///   the store-derived `ptr_points_to`, not `constant_ptr_points_to`). So `transform_apply`
///   escapes via `transform_init`'s `g_transform_fn = transform_apply`, while a function merely
///   named in a static initializer (e.g. OMP's `basesort = alnumsort`) does NOT.
/// * Return-escape: a directly returned global value escapes (covers OMP's
///   `stat2info.info_xjtr_0`). Inline constant-expression returns are not escape roots by
///   themselves, but an inline returned global escapes when a caller passes that returned value
///   into another internal function call (covers OMP's `pathconcat.buf_xjtr_2` flowing into
///   `new_ignorefile` while keeping formatting-only uses like `prot()`/`do_date()` local).
///
/// Closed to a fixpoint (an escaped global becomes escaped memory). Operands are resolved
/// syntactically through gep/bitcast/select chains (not through loads).
///
/// DIVERGENCE: escape that flows only through *aliased* (memory-indirect) stores or through
/// escaping external-call arguments is not modeled — pangs may under-report there relative to
/// cclyzer's points-to-based analysis. Names are `.`-filtered, ordered global-then-function.
fn escaped_globals(
    pir: &Pir,
    solved: &SolveResult,
    internalize_globals: bool,
    build_mode: BuildMode,
) -> Vec<String> {
    let global_names: BTreeSet<&str> = pir.globals.iter().map(|g| g.key.as_str()).collect();
    let func_names: BTreeSet<&str> = pir.functions.iter().map(|f| f.key.as_str()).collect();
    let internal_func_names: BTreeSet<&str> = pir
        .functions
        .iter()
        .filter(|f| !f.external)
        .map(|f| f.key.as_str())
        .collect();
    let is_known = |n: &str| global_names.contains(n) || func_names.contains(n);
    let defined = defined_globals(pir);

    // Externally-accessible base globals (external-linkage, defined here). With internalize, none.
    let externally_visible: Vec<&str> =
        if internalize_globals || build_mode == BuildMode::Executable {
            Vec::new()
        } else {
            pir.globals
                .iter()
                .filter(|g| g.exported && defined.contains(g.key.as_str()))
                .map(|g| g.key.as_str())
                .collect()
        };

    let mut escaped: BTreeSet<String> = BTreeSet::new();

    // escape-analysis.dl rule 1 + transitive (rule 5): an allocation pointed to by externally-
    // accessible memory escapes, and the pointees of an escaped allocation escape in turn. This
    // is `ptr_points_to(alloc, mem)` read off the solver's allocation-level points-to for the
    // memory object node `obj:global:<mem>`. Using real points-to (rather than syntactic stores)
    // avoids escaping function pointers that field-insensitive over-merging never resolves onto
    // a global object (e.g. OMP's runtime-reassigned `basesort`), matching cclyzer far better.
    let mut worklist: Vec<String> = externally_visible.iter().map(|s| s.to_string()).collect();
    let mut visited_mem: BTreeSet<String> = BTreeSet::new();
    while let Some(mem) = worklist.pop() {
        if !visited_mem.insert(mem.clone()) {
            continue;
        }
        if let Some(pointees) = solved.node_points_to.get(&format!("obj:global:{mem}")) {
            // Collapse guard: pangs' field-insensitive unification can merge an aggregate's fields
            // into one giant class (e.g. OMP's `struct sorts {char*; fnptr;}` table), so a single
            // global object appears to point at dozens of unrelated allocations. A precise
            // function-pointer / data-pointer global never points to a string constant, so a
            // pointee set containing a `.`-prefixed name signals such a collapse — skip it rather
            // than escape the whole blob. cclyzer's field-sensitive points-to keeps these apart.
            if pointees.iter().any(|p| p.starts_with('.')) {
                continue;
            }
            for pointee in pointees {
                if is_known(pointee) && escaped.insert(pointee.clone()) {
                    worklist.push(pointee.clone());
                }
            }
        }
    }

    // Return-escape: match cclyzer's cc2json relation, which includes direct returned globals but
    // does not turn every inline constant-expression return into an escape root. This keeps
    // formatting helpers like OMP's prot()/do_date() local while retaining direct returns such as
    // stat2info().
    for func in &pir.functions {
        let mut resolver = BaseGlobalResolver::new(func);
        for stmt in &func.body {
            if let Stmt::Return {
                value: Some(value), ..
            } = stmt
            {
                if let Some(base) = resolver.resolve_base_global(value) {
                    if is_known(&base) {
                        escaped.insert(base);
                    }
                }
            }
        }
    }
    escaped.extend(inline_returned_globals_passed_to_internal_calls(
        pir,
        &global_names,
        &func_names,
        &internal_func_names,
    ));

    // Keep escaped *functions* and escaped *defined* data globals (cclyzer allocates only defined
    // globals). Render in global- then function-definition order, dropping `.`-prefixed names.
    let mut out = Vec::new();
    for g in &pir.globals {
        if escaped.contains(&g.key) && defined.contains(g.key.as_str()) {
            if let Some(name) = process_global_name(&g.key) {
                out.push(name);
            }
        }
    }
    for f in &pir.functions {
        if escaped.contains(&f.key) {
            if let Some(name) = process_global_name(&f.key) {
                out.push(name);
            }
        }
    }
    out
}

fn inline_returned_globals_passed_to_internal_calls(
    pir: &Pir,
    global_names: &BTreeSet<&str>,
    func_names: &BTreeSet<&str>,
    internal_func_names: &BTreeSet<&str>,
) -> BTreeSet<String> {
    let returned_globals = returned_globals_by_func(pir, global_names, func_names);
    let mut escaped = BTreeSet::new();

    for func in &pir.functions {
        let mut value_globals: HashMap<&str, BTreeSet<String>> = HashMap::new();
        for stmt in &func.body {
            match stmt {
                Stmt::CallDirect {
                    callee, args, dest, ..
                } => {
                    if internal_func_names.contains(callee.as_str()) {
                        for arg in args {
                            if let Some(globals) = value_globals.get(arg.as_str()) {
                                escaped.extend(globals.iter().cloned());
                            }
                        }
                    }
                    if let Some(dest) = dest {
                        if let Some(globals) = returned_globals.get(callee.as_str()) {
                            value_globals.insert(dest.as_str(), globals.clone());
                        }
                    }
                }
                Stmt::Gep { dest, base, .. } => {
                    if let Some(globals) = value_globals.get(base.as_str()).cloned() {
                        value_globals.insert(dest.as_str(), globals);
                    }
                }
                Stmt::Assign { dest, sources, .. } => {
                    let mut globals = BTreeSet::new();
                    for source in sources {
                        if let Some(source_globals) = value_globals.get(source.as_str()) {
                            globals.extend(source_globals.iter().cloned());
                        }
                    }
                    if !globals.is_empty() {
                        value_globals.insert(dest.as_str(), globals);
                    }
                }
                _ => {}
            }
        }
    }

    escaped
}

fn returned_globals_by_func(
    pir: &Pir,
    global_names: &BTreeSet<&str>,
    func_names: &BTreeSet<&str>,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut returned_globals = BTreeMap::new();
    for func in &pir.functions {
        let mut resolver = BaseGlobalResolver::new(func);
        let mut globals = BTreeSet::new();
        for stmt in &func.body {
            if let Stmt::Return {
                value: Some(value), ..
            } = stmt
            {
                if let Some(base) = resolver.resolve_arg_global(value) {
                    if global_names.contains(base.as_str()) || func_names.contains(base.as_str()) {
                        globals.insert(base);
                    }
                }
            }
        }
        if !globals.is_empty() {
            returned_globals.insert(func.key.clone(), globals);
        }
    }
    returned_globals
}

struct BaseGlobalResolver<'a> {
    defs: HashMap<&'a str, usize>,
    entries: Vec<BaseDef<'a>>,
    can_reach_global: Vec<bool>,
    memo: Vec<Option<Option<&'a str>>>,
    visiting: Vec<bool>,
}

enum BaseDef<'a> {
    Gep(SourceRef<'a>),
    Assign(Vec<SourceRef<'a>>),
    Other,
}

#[derive(Clone, Copy)]
enum SourceRef<'a> {
    Global(&'a str),
    Def(usize),
    Other,
}

enum BaseGlobalResolution<'a> {
    Found(&'a str),
    NotFound,
    Cycle,
}

impl<'a> BaseGlobalResolver<'a> {
    fn new(func: &'a Func) -> Self {
        let mut defs = HashMap::new();
        for stmt in &func.body {
            let Some(dest) = stmt_dest(stmt) else {
                continue;
            };
            if !defs.contains_key(dest) {
                let id = defs.len();
                defs.insert(dest, id);
            }
        }

        let mut entries = Vec::with_capacity(defs.len());
        entries.resize_with(defs.len(), || None);
        for stmt in &func.body {
            let Some(dest) = stmt_dest(stmt) else {
                continue;
            };
            let id = defs[dest];
            if entries[id].is_some() {
                continue;
            }
            entries[id] = Some(match stmt {
                Stmt::Gep { base, .. } => BaseDef::Gep(source_ref(&defs, base)),
                Stmt::Assign { sources, .. } => {
                    BaseDef::Assign(sources.iter().map(|s| source_ref(&defs, s)).collect())
                }
                _ => BaseDef::Other,
            });
        }
        let entries = entries
            .into_iter()
            .map(|entry| entry.unwrap_or(BaseDef::Other))
            .collect::<Vec<_>>();
        let can_reach_global = compute_can_reach_global(&entries);
        Self {
            memo: vec![None; entries.len()],
            visiting: vec![false; entries.len()],
            defs,
            entries,
            can_reach_global,
        }
    }

    /// Resolve a call argument to the global whose address it denotes: a temp gep/bitcast chain or
    /// a literal `@g`, else the first global symbol inside a constant-expr operand string such as
    /// `i8* getelementptr inbounds (... @g, ...)` / `i8* bitcast (... @g ...)`.
    fn resolve_arg_global(&mut self, operand: &'a str) -> Option<String> {
        self.resolve_base_global(operand)
            .or_else(|| first_global_symbol(operand))
    }

    /// Resolve an operand to the base global value it refers to, tracing only address-preserving
    /// chains: a literal `@name`, or a temp defined by a gep/bitcast/select (`Assign`) over a base
    /// that resolves. Never traces through a `Load` (that would be a dereference, not the address).
    fn resolve_base_global(&mut self, operand: &'a str) -> Option<String> {
        let mut touched = Vec::new();
        match self.resolve_operand(operand, &mut touched) {
            BaseGlobalResolution::Found(name) => Some(name.to_string()),
            BaseGlobalResolution::NotFound | BaseGlobalResolution::Cycle => {
                for id in touched {
                    if self.memo[id].is_none() {
                        self.memo[id] = Some(None);
                    }
                }
                None
            }
        }
    }

    fn resolve_operand(
        &mut self,
        operand: &'a str,
        touched: &mut Vec<usize>,
    ) -> BaseGlobalResolution<'a> {
        if matches!(operand, "null" | "undef" | "poison") {
            return BaseGlobalResolution::NotFound;
        }
        self.resolve_source(source_ref(&self.defs, operand), touched)
    }

    fn resolve_source(
        &mut self,
        source: SourceRef<'a>,
        touched: &mut Vec<usize>,
    ) -> BaseGlobalResolution<'a> {
        match source {
            SourceRef::Global(name) => BaseGlobalResolution::Found(name),
            SourceRef::Def(id) if self.can_reach_global[id] => self.resolve_def(id, touched),
            SourceRef::Def(_) | SourceRef::Other => BaseGlobalResolution::NotFound,
        }
    }

    fn resolve_def(&mut self, id: usize, touched: &mut Vec<usize>) -> BaseGlobalResolution<'a> {
        if let Some(cached) = self.memo[id] {
            return match cached {
                Some(name) => BaseGlobalResolution::Found(name),
                None => BaseGlobalResolution::NotFound,
            };
        }
        if self.visiting[id] {
            return BaseGlobalResolution::Cycle;
        }
        self.visiting[id] = true;
        touched.push(id);

        let resolved = if let Some(base) = match &self.entries[id] {
            BaseDef::Gep(base) => Some(*base),
            _ => None,
        } {
            self.resolve_source(base, touched)
        } else if let Some(len) = match &self.entries[id] {
            BaseDef::Assign(sources) => Some(sources.len()),
            _ => None,
        } {
            let mut saw_cycle = false;
            let mut found = None;
            for index in 0..len {
                let source = match &self.entries[id] {
                    BaseDef::Assign(sources) => sources[index],
                    _ => unreachable!("base-global resolver entry changed during recursion"),
                };
                match self.resolve_source(source, touched) {
                    BaseGlobalResolution::Found(name) => {
                        found = Some(name);
                        break;
                    }
                    BaseGlobalResolution::NotFound => {}
                    BaseGlobalResolution::Cycle => saw_cycle = true,
                }
            }
            match found {
                Some(name) => BaseGlobalResolution::Found(name),
                None if saw_cycle => BaseGlobalResolution::Cycle,
                None => BaseGlobalResolution::NotFound,
            }
        } else {
            BaseGlobalResolution::NotFound
        };

        self.visiting[id] = false;
        match &resolved {
            BaseGlobalResolution::Found(name) => {
                self.memo[id] = Some(Some(*name));
            }
            BaseGlobalResolution::NotFound => {
                self.memo[id] = Some(None);
            }
            BaseGlobalResolution::Cycle => {}
        }
        resolved
    }
}

fn compute_can_reach_global(entries: &[BaseDef<'_>]) -> Vec<bool> {
    let mut can_reach = vec![false; entries.len()];
    loop {
        let mut changed = false;
        for (id, entry) in entries.iter().enumerate() {
            if can_reach[id] {
                continue;
            }
            let reaches = match entry {
                BaseDef::Gep(base) => source_can_reach_global(&can_reach, *base),
                BaseDef::Assign(sources) => sources
                    .iter()
                    .any(|source| source_can_reach_global(&can_reach, *source)),
                BaseDef::Other => false,
            };
            if reaches {
                can_reach[id] = true;
                changed = true;
            }
        }
        if !changed {
            return can_reach;
        }
    }
}

fn source_can_reach_global(can_reach: &[bool], source: SourceRef<'_>) -> bool {
    match source {
        SourceRef::Global(_) => true,
        SourceRef::Def(id) => can_reach[id],
        SourceRef::Other => false,
    }
}

fn stmt_dest(stmt: &Stmt) -> Option<&str> {
    match stmt {
        Stmt::Alloca { dest, .. }
        | Stmt::Assign { dest, .. }
        | Stmt::Load { dest, .. }
        | Stmt::Gep { dest, .. }
        | Stmt::PtrToInt { dest, .. }
        | Stmt::IntToPtr { dest, .. } => Some(dest.as_str()),
        _ => None,
    }
}

fn source_ref<'a>(defs: &HashMap<&'a str, usize>, operand: &'a str) -> SourceRef<'a> {
    if let Some(name) = operand.strip_prefix('@') {
        SourceRef::Global(name)
    } else if let Some(&id) = defs.get(operand) {
        SourceRef::Def(id)
    } else {
        SourceRef::Other
    }
}

// ---------------------------------------------------------------------------
// Sections 3 & 4: call_graph_components + unique_filenames
// ---------------------------------------------------------------------------

/// One node in the bipartite call graph: a call site (rendered later) or a callee target string.
struct ComponentData {
    /// Call-site node keys (pangs callsite keys), sorted.
    call_sites: BTreeSet<String>,
    /// Callee target strings (`"<source>:name"`), sorted; never includes `"UNKNOWN"`.
    call_targets: BTreeSet<String>,
    /// False if the component has an UNKNOWN target or any external/escaped callee.
    all_mutable: bool,
}

/// Build the bipartite (call-site ↔ callee) connected components from pangs call edges, mirroring
/// callgraph/connected-components.dl. Direct calls to *external* functions keep their real name
/// (e.g. `printf`) as a target — unresolved indirect targets become `"UNKNOWN"`.
fn call_graph_components(
    pir: &Pir,
    analysis: &Analysis,
    source: &str,
    escaped: &BTreeSet<String>,
    site_render: &BTreeMap<String, SiteKind>,
) -> Vec<ComponentData> {
    // Direct-callee name per callsite key (call edges don't carry the external callee's name, so
    // recover it from the PIR body in callsite order — callsites are built in the same order).
    let direct_callee = direct_callee_names(pir, analysis);

    // Bipartite edges: (site key, callee node string). callee node is "<source>:name" or "UNKNOWN".
    let mut edges: Vec<(String, String)> = Vec::new();
    let mut site_has_unknown: BTreeSet<String> = BTreeSet::new();
    for edge in analysis.call_edges() {
        let Some(cs) = edge.callsite else { continue };
        let key = analysis.callsites()[cs].key.clone();
        let callee_node = match (&edge.callee, edge.kind) {
            (Callee::Func(id), _) => format!("<{source}>:{}", analysis.functions()[*id].key),
            (Callee::Unknown(_), CallKind::Direct) => {
                // External direct callee: use the syntactic callee name.
                match direct_callee.get(&key) {
                    Some(name) => format!("<{source}>:{name}"),
                    None => continue,
                }
            }
            (Callee::Unknown(_), CallKind::Indirect) => {
                site_has_unknown.insert(key.clone());
                "UNKNOWN".to_string()
            }
        };
        edges.push((key, callee_node));
    }

    // Union-find over all nodes (site keys + callee strings, including "UNKNOWN").
    let mut uf = UnionFind::new();
    for (site, callee) in &edges {
        uf.union(site, callee);
    }

    // Group nodes by representative.
    let mut comps: BTreeMap<String, ComponentData> = BTreeMap::new();
    let mut unknown_reprs: BTreeSet<String> = BTreeSet::new();
    for (site, callee) in &edges {
        let repr = uf.find(site);
        let entry = comps.entry(repr.clone()).or_insert_with(|| ComponentData {
            call_sites: BTreeSet::new(),
            call_targets: BTreeSet::new(),
            all_mutable: true,
        });
        // A site node is one that we know how to render (i.e. an actual call site).
        if site_render.contains_key(site) {
            entry.call_sites.insert(site.clone());
        }
        if callee == "UNKNOWN" {
            unknown_reprs.insert(repr);
        } else {
            entry.call_targets.insert(callee.clone());
        }
    }

    // external_funcs: full target strings "<source>:name" for functions without a definition.
    let external_funcs: BTreeSet<String> = analysis
        .functions()
        .iter()
        .filter(|f| f.external)
        .map(|f| format!("<{source}>:{}", f.key))
        .collect();

    for (repr, comp) in comps.iter_mut() {
        if unknown_reprs.contains(repr) {
            comp.all_mutable = false;
            continue;
        }
        for target in &comp.call_targets {
            if external_funcs.contains(target) {
                comp.all_mutable = false;
                break;
            }
            let func_name = target.rsplit(':').next().unwrap_or(target);
            if escaped.contains(func_name) {
                comp.all_mutable = false;
                break;
            }
        }
    }

    // Order components by their smallest call-site key. cclyzer orders by the component's
    // representative (smallest CGNode = call-site instruction refmode); ordering by the smallest
    // call-site key reproduces that order, since site keys sort by caller name then location.
    let mut out: Vec<ComponentData> = comps.into_values().collect();
    out.sort_by(|a, b| a.call_sites.iter().next().cmp(&b.call_sites.iter().next()));
    out
}

/// How a call site renders in the JSON: a debug-location object, or a bare function name string
/// (cclyzer's `llvm_call_site_to_string` else-branch for instructions without a debug location).
#[derive(Clone)]
enum SiteKind {
    Loc {
        line: u32,
        col: u32,
        func: String,
        dir: String,
        file: String,
    },
    Bare(String),
}

/// Build the renderable site descriptor for every call site. Locations come from the PIR `Loc`
/// (which preserves the raw DWARF directory/filename) so the `(directory, filename)` split — and
/// thus the `uf` short name — matches cclyzer exactly even when the filename contains `/`.
fn site_renders(pir: &Pir, analysis: &Analysis) -> BTreeMap<String, SiteKind> {
    let pir_locs = callsite_pir_locs(pir, analysis);
    let mut out = BTreeMap::new();
    for cs in analysis.callsites().iter() {
        let func = analysis.functions()[cs.caller].key.clone();
        let kind = match (&cs.loc, pir_locs.get(cs.key.as_str())) {
            (Some(loc), pir_loc) => {
                // Prefer the raw DWARF (dir, filename); fall back to splitting the joined path.
                let (dir, file) =
                    match pir_loc.and_then(|l| l.dir.as_ref().zip(l.filename.as_ref())) {
                        Some((dir, filename)) => (dir.clone(), filename.clone()),
                        None => split_dir_file(&loc.file),
                    };
                SiteKind::Loc {
                    line: loc.line,
                    col: loc.col,
                    func: func.clone(),
                    dir,
                    file,
                }
            }
            (None, _) => SiteKind::Bare(func.clone()),
        };
        out.insert(cs.key.clone(), kind);
    }
    out
}

/// Map each callsite key to its PIR `Loc`. pangs builds callsites in body order, so a function's
/// k-th call statement is its k-th callsite.
fn callsite_pir_locs<'a>(pir: &'a Pir, analysis: &Analysis) -> BTreeMap<String, &'a Loc> {
    let mut by_caller: BTreeMap<FuncId, Vec<&pangs_api::CallsiteInfo>> = BTreeMap::new();
    for cs in analysis.callsites().iter() {
        by_caller.entry(cs.caller).or_default().push(cs);
    }
    let mut out = BTreeMap::new();
    for (idx, func) in pir.functions.iter().enumerate() {
        let Some(callsites) = by_caller.get(&FuncId(idx as u32)) else {
            continue;
        };
        let mut k = 0usize;
        for stmt in &func.body {
            let loc = match stmt {
                Stmt::CallDirect { loc, .. } | Stmt::CallIndirect { loc, .. } => {
                    let entry = (callsites.get(k), loc.as_ref());
                    k += 1;
                    entry
                }
                _ => continue,
            };
            if let (Some(cs), Some(loc)) = loc {
                out.insert(cs.key.clone(), loc);
            }
        }
    }
    out
}

/// Map each callsite key to the syntactic callee name of its direct call (if any). pangs builds
/// callsites in body order, so the k-th call statement of a function is its k-th callsite.
fn direct_callee_names(pir: &Pir, analysis: &Analysis) -> BTreeMap<String, String> {
    // callsites grouped by caller, preserving global (body) order.
    let mut by_caller: BTreeMap<FuncId, Vec<&pangs_api::CallsiteInfo>> = BTreeMap::new();
    for cs in analysis.callsites().iter() {
        by_caller.entry(cs.caller).or_default().push(cs);
    }
    let mut out = BTreeMap::new();
    for (idx, func) in pir.functions.iter().enumerate() {
        let fid = FuncId(idx as u32);
        let Some(callsites) = by_caller.get(&fid) else {
            continue;
        };
        let mut k = 0usize;
        for stmt in &func.body {
            match stmt {
                Stmt::CallDirect { callee, .. } => {
                    if let Some(cs) = callsites.get(k) {
                        out.insert(cs.key.clone(), callee.clone());
                    }
                    k += 1;
                }
                Stmt::CallIndirect { .. } => {
                    k += 1;
                }
                _ => {}
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Section 5: mutable_global_tissue
// ---------------------------------------------------------------------------

/// `(directly_accesses, tissue)`, mirroring points-to/mutable-global-tissue.dl.
/// `directly_accesses` = functions that *directly* reference (address-of, via a constant) a
/// mutated-or-escaped global that is neither a function nor a string constant. `tissue` =
/// `directly_accesses` plus transitive callers. Both in function-definition order.
fn mutable_global_tissue(
    pir: &Pir,
    analysis: &Analysis,
    mutated: &BTreeSet<String>,
    escaped: &BTreeSet<String>,
) -> (Vec<String>, Vec<String>) {
    // mutated_or_escaped over *data globals* only (functions and `.str*` excluded).
    let global_keys: BTreeSet<&str> = analysis.globals().iter().map(|g| g.key.as_str()).collect();
    let interesting: BTreeSet<&str> = mutated
        .iter()
        .chain(escaped.iter())
        .map(String::as_str)
        .filter(|name| global_keys.contains(name))
        .filter(|name| !is_string_constant(name))
        .collect();

    // directly_accesses: functions that reference an interesting global via *any* constant in
    // their body (cclyzer's `constant_in_func` + `constant_points_to`). A reference is a `@g`
    // symbol appearing in any operand — loads/stores/geps/calls, including inline constant-expr
    // call arguments (e.g. `__func__.*` passed to a printf) — or a direct `GlobalRef` target. The
    // defining statement of any temp is itself scanned, so we need not chase temps here.
    let mut direct: BTreeSet<FuncId> = BTreeSet::new();
    for (idx, func) in pir.functions.iter().enumerate() {
        if func_references_interesting(func, &interesting) {
            direct.insert(FuncId(idx as u32));
        }
    }

    // tissue: reverse-reachability closure over the call graph (caller of a tissue member joins).
    let mut tissue = direct.clone();
    let mut changed = true;
    while changed {
        changed = false;
        for edge in analysis.call_edges() {
            let (Caller::Func(caller), Callee::Func(callee)) = (&edge.caller, &edge.callee) else {
                continue;
            };
            if tissue.contains(callee) && tissue.insert(*caller) {
                changed = true;
            }
        }
    }

    let order = |set: &BTreeSet<FuncId>| -> Vec<String> {
        (0..pir.functions.len())
            .map(|i| FuncId(i as u32))
            .filter(|id| set.contains(id))
            .map(|id| analysis.functions()[id].key.clone())
            .collect()
    };
    (order(&direct), order(&tissue))
}

/// Whether `func`'s body references any `interesting` global through a constant — a `@g` symbol in
/// any operand string, or a `GlobalRef` target.
fn func_references_interesting(func: &Func, interesting: &BTreeSet<&str>) -> bool {
    let hits =
        |operand: &str| all_global_symbols(operand).any(|g| interesting.contains(g.as_str()));
    for stmt in &func.body {
        let found = match stmt {
            Stmt::GlobalRef { global, .. } => interesting.contains(global.as_str()),
            Stmt::Store { address, value, .. } => hits(address) || hits(value),
            Stmt::Load { address, .. } => hits(address),
            Stmt::Gep { base, .. } => hits(base),
            Stmt::Assign { sources, .. } => sources.iter().any(|s| hits(s)),
            Stmt::PtrToInt { source, .. } | Stmt::IntToPtr { source, .. } => hits(source),
            Stmt::Memcpy { dst, src, .. } => hits(dst) || hits(src),
            Stmt::Memset { dst, .. } => hits(dst),
            Stmt::Return { value: Some(v), .. } => hits(v),
            Stmt::CallDirect { args, .. } => args.iter().any(|a| hits(a)),
            Stmt::CallIndirect { operand, args, .. } => {
                hits(operand) || args.iter().any(|a| hits(a))
            }
            _ => false,
        };
        if found {
            return true;
        }
    }
    false
}

/// Every `@symbol` name appearing in an operand string (direct refs and inline constant-exprs).
fn all_global_symbols(operand: &str) -> impl Iterator<Item = String> + '_ {
    operand.match_indices('@').filter_map(|(at, _)| {
        let name: String = operand[at + 1..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '$' | '-'))
            .collect();
        (!name.is_empty()).then_some(name)
    })
}

// ---------------------------------------------------------------------------
// Section 6: global_initializer_references (from PIR `init_refs`, computed at lowering)
// ---------------------------------------------------------------------------

/// `global -> [referenced names]`, `.`-filtered, dropping globals with no surviving references.
/// Built from PIR `Global::init_refs` (cclyzer's constant-init.dl). Map is keyed/sorted by global
/// name (BTreeMap), reference lists preserve initializer order.
fn global_initializer_references(pir: &Pir) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    for g in &pir.globals {
        let refs: Vec<String> = g
            .init_refs
            .iter()
            .filter(|r| !r.starts_with('.'))
            .cloned()
            .collect();
        if !refs.is_empty() {
            out.insert(g.key.clone(), refs);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// JSON assembly (hand-rolled to mirror cc2json.cpp's writer formatting)
// ---------------------------------------------------------------------------

fn write_cc2json(
    json: &mut JsonBuilder,
    pir: &Pir,
    analysis: &Analysis,
    source: &str,
    mutated: &[String],
    escaped: &[String],
) {
    let site_render = site_renders(pir, analysis);
    let escaped_set: BTreeSet<String> = escaped.iter().cloned().collect();
    let mutated_set: BTreeSet<String> = mutated.iter().cloned().collect();
    let components = call_graph_components(pir, analysis, source, &escaped_set, &site_render);
    let (directly_accesses, tissue) =
        mutable_global_tissue(pir, analysis, &mutated_set, &escaped_set);
    let init_refs = global_initializer_references(pir);

    let mut ufm = UniqueFilenameMapper::default();

    json.raw("{\n");

    // mutated_globals
    json.raw("  \"mutated_globals\": [\n");
    json.string_array_body(mutated, "    ");
    json.raw("\n  ],\n");

    // escaped_globals
    json.raw("  \"escaped_globals\": [\n");
    json.string_array_body(escaped, "    ");
    json.raw("\n  ],\n");

    // call_graph_components
    json.raw("  \"call_graph_components\": [\n");
    let mut first = true;
    for comp in &components {
        if !first {
            json.raw(",\n");
        }
        first = false;
        json.raw("    {\n");
        json.raw("      \"call_sites\": [\n");
        let mut first_site = true;
        for site in &comp.call_sites {
            if !first_site {
                json.raw(",\n");
            }
            first_site = false;
            json.raw("        ");
            json.raw(&render_site(&site_render[site], &mut ufm));
        }
        json.raw("\n      ],\n");
        json.raw("      \"call_targets\": [\n");
        let mut first_target = true;
        for target in &comp.call_targets {
            if !first_target {
                json.raw(",\n");
            }
            first_target = false;
            json.raw("        \"");
            json.raw(&json_escape(target));
            json.raw("\"");
        }
        json.raw("\n      ],\n");
        json.raw(&format!(
            "      \"all_mutable\": {}\n",
            if comp.all_mutable { "true" } else { "false" }
        ));
        json.raw("    }");
    }
    json.raw("\n  ],\n");

    // unique_filenames (populated by the render_site calls above)
    json.raw("  \"unique_filenames\": {\n");
    let mut first_uf = true;
    for (short, (dir, file)) in &ufm.short_to_full {
        if !first_uf {
            json.raw(",\n");
        }
        first_uf = false;
        json.raw("  \"");
        json.raw(&json_escape(short));
        json.raw("\": {\"directory\": \"");
        json.raw(&json_escape(dir));
        json.raw("\", \"filename\": \"");
        json.raw(&json_escape(file));
        json.raw("\"}");
    }
    json.raw("\n  },\n");

    // mutable_global_tissue
    json.raw("  \"mutable_global_tissue\": {\n");
    json.raw("    \"directly_accesses\": [\n");
    json.string_array_body(&directly_accesses, "      ");
    json.raw("\n    ],\n");
    json.raw("    \"tissue\": [\n");
    json.string_array_body(&tissue, "      ");
    json.raw("\n    ]\n");
    json.raw("  },\n\n");

    // global_initializer_references
    json.raw("  \"global_initializer_references\": {\n");
    let mut first_ref = true;
    for (var, refs) in &init_refs {
        if !first_ref {
            json.raw(",\n");
        }
        first_ref = false;
        json.raw("    \"");
        json.raw(&json_escape(var));
        json.raw("\": [\n");
        let mut first_r = true;
        for r in refs {
            if !first_r {
                json.raw(",\n");
            }
            first_r = false;
            json.raw("      \"");
            json.raw(&json_escape(r));
            json.raw("\"");
        }
        json.raw("\n    ]");
    }
    json.raw("\n  }\n");

    json.raw("}\n");
}

fn render_site(site: &SiteKind, ufm: &mut UniqueFilenameMapper) -> String {
    match site {
        SiteKind::Loc {
            line,
            col,
            func,
            dir,
            file,
        } => {
            let uf = ufm.get_short(dir, file);
            format!(
                "{{ \"line\": {line}, \"col\": {col}, \"p\": \"{}\", \"uf\": \"{}\" }}",
                func,
                json_escape(&uf)
            )
        }
        SiteKind::Bare(name) => format!("\"{}\"", json_escape(name)),
    }
}

// ---------------------------------------------------------------------------
// Helpers ported from cc2json.cpp
// ---------------------------------------------------------------------------

/// Strip the `*global_alloc@` prefix (pangs names lack it, but harmless) and drop names starting
/// with `.` (string constants). Mirrors `process_global_name`.
fn process_global_name(name: &str) -> Option<String> {
    let stripped = name.strip_prefix("*global_alloc@").unwrap_or(name);
    if stripped.starts_with('.') {
        return None;
    }
    Some(stripped.to_string())
}

fn is_string_constant(name: &str) -> bool {
    name.contains(".str")
}

/// Split a (possibly joined) `dir/file` path into `(directory, filename)`. pangs collapses the
/// DWARF directory/filename boundary into one string, so we split at the last `/`.
///
/// DIVERGENCE: when the DWARF *filename* itself contains a `/` (e.g. OMP/sbase use
/// `c_11_run.../foo.nolines.i`), this split misplaces the boundary versus cclyzer, which keeps
/// the two DWARF fields separate.
fn split_dir_file(path: &str) -> (String, String) {
    match path.rfind('/') {
        Some(idx) => (path[..idx].to_string(), path[idx + 1..].to_string()),
        None => (String::new(), path.to_string()),
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Port of `UniqueFilenameMapper`: assign each `(dir, file)` a short name (the filename, with a
/// `!N` suffix on collisions). `short_to_full` is a BTreeMap so iteration is sorted by short name.
#[derive(Default)]
struct UniqueFilenameMapper {
    short_to_full: BTreeMap<String, (String, String)>,
    full_to_short: BTreeMap<(String, String), String>,
}

impl UniqueFilenameMapper {
    fn get_short(&mut self, dir: &str, file: &str) -> String {
        let key = (dir.to_string(), file.to_string());
        if let Some(short) = self.full_to_short.get(&key) {
            return short.clone();
        }
        let mut candidate = file.to_string();
        let mut suffix = 1;
        loop {
            match self.short_to_full.get(&candidate) {
                None => {
                    self.short_to_full.insert(candidate.clone(), key.clone());
                    self.full_to_short.insert(key, candidate.clone());
                    return candidate;
                }
                Some(existing) if *existing == key => return candidate,
                Some(_) => {
                    candidate = format!("{file}!{suffix}");
                    suffix += 1;
                }
            }
        }
    }
}

/// Minimal string-based union-find over node-name strings.
#[derive(Default)]
struct UnionFind {
    parent: BTreeMap<String, String>,
}

impl UnionFind {
    fn new() -> Self {
        Self::default()
    }

    fn find(&mut self, x: &str) -> String {
        let mut node = x.to_string();
        loop {
            let parent = self
                .parent
                .entry(node.clone())
                .or_insert_with(|| node.clone())
                .clone();
            if parent == node {
                return node;
            }
            // Path halving.
            let grandparent = self
                .parent
                .entry(parent.clone())
                .or_insert_with(|| parent.clone())
                .clone();
            self.parent.insert(node.clone(), grandparent.clone());
            node = parent;
        }
    }

    fn union(&mut self, a: &str, b: &str) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra == rb {
            return;
        }
        // Keep the lexicographically smaller root as the representative (matches the datalog's
        // "lexicographically smallest node" component representative).
        let (keep, drop) = if ra <= rb { (ra, rb) } else { (rb, ra) };
        self.parent.insert(drop, keep);
    }
}

/// A tiny append-only JSON string builder.
struct JsonBuilder {
    buf: String,
}

impl JsonBuilder {
    fn new() -> Self {
        Self { buf: String::new() }
    }

    fn raw(&mut self, s: &str) {
        self.buf.push_str(s);
    }

    /// Write the body of a string array (no surrounding brackets), one `indent`ed quoted string
    /// per element, comma+newline separated. Empty input writes nothing.
    fn string_array_body(&mut self, items: &[String], indent: &str) {
        let mut first = true;
        for item in items {
            if !first {
                self.buf.push_str(",\n");
            }
            first = false;
            self.buf.push_str(indent);
            self.buf.push('"');
            self.buf.push_str(&json_escape(item));
            self.buf.push('"');
        }
    }

    fn into_string(self) -> String {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pangs_pir::{AbiClass, Global, Param, Signature};
    use std::path::PathBuf;

    fn workspace_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn test_func(body: Vec<Stmt>) -> Func {
        Func {
            key: "f".to_string(),
            sig: Signature {
                ret: AbiClass::Void,
                params: Vec::new(),
                vararg: false,
                cc: "ccc".to_string(),
            },
            param_names: Vec::new(),
            file: None,
            line: None,
            external: false,
            exported: false,
            address_taken: false,
            body,
        }
    }

    fn void_sig() -> Signature {
        Signature {
            ret: AbiClass::Void,
            params: Vec::new(),
            vararg: false,
            cc: "ccc".to_string(),
        }
    }

    fn test_global(key: &str) -> Global {
        Global {
            key: key.to_string(),
            file: None,
            line: None,
            is_const: false,
            mutable: true,
            init_refs: Vec::new(),
            exported: false,
            ..Global::default()
        }
    }

    fn cc2json_test_opts() -> Cc2jsonOpts {
        Cc2jsonOpts {
            stage: Stage::Steens,
            build_mode: BuildMode::Executable,
            internalize_globals: false,
            partition_budget: 100_000,
        }
    }

    #[test]
    fn base_global_resolver_memoizes_branching_assigns_and_breaks_cycles() {
        let func = test_func(vec![
            Stmt::Assign {
                dest: "%a".to_string(),
                sources: vec!["%b".to_string(), "%c".to_string()],
                loc: None,
            },
            Stmt::Assign {
                dest: "%b".to_string(),
                sources: vec!["%a".to_string()],
                loc: None,
            },
            Stmt::Gep {
                dest: "%c".to_string(),
                base: "@G".to_string(),
                byte_off: Some(8),
                lane: None,
                loc: None,
            },
        ]);

        let mut resolver = BaseGlobalResolver::new(&func);
        assert_eq!(resolver.resolve_base_global("%a"), Some("G".to_string()));
        assert_eq!(resolver.resolve_base_global("%b"), Some("G".to_string()));
        assert_eq!(
            resolver.resolve_arg_global("i8* bitcast (@H to i8*)"),
            Some("H".to_string())
        );
    }

    #[test]
    fn base_global_resolver_caches_unresolved_cycles() {
        let func = test_func(vec![
            Stmt::Assign {
                dest: "%a".to_string(),
                sources: vec!["%b".to_string()],
                loc: None,
            },
            Stmt::Assign {
                dest: "%b".to_string(),
                sources: vec!["%a".to_string()],
                loc: None,
            },
        ]);

        let mut resolver = BaseGlobalResolver::new(&func);
        assert!(!resolver.can_reach_global[resolver.defs["%a"]]);
        assert!(!resolver.can_reach_global[resolver.defs["%b"]]);
        assert_eq!(resolver.resolve_base_global("%a"), None);
        assert_eq!(resolver.resolve_base_global("%b"), None);
    }

    #[test]
    fn cc2json_inline_constexpr_return_alone_does_not_escape() {
        let pir = Pir {
            module: "returned_inline_constexpr".to_string(),
            source: None,
            lowering: Default::default(),
            target: None,
            functions: vec![Func {
                key: "main".to_string(),
                sig: Signature {
                    ret: AbiClass::Integer,
                    params: Vec::new(),
                    vararg: false,
                    cc: "ccc".to_string(),
                },
                param_names: Vec::new(),
                file: None,
                line: None,
                external: false,
                exported: true,
                address_taken: false,
                body: vec![Stmt::Return {
                    value: Some(
                        "i8* getelementptr inbounds ([8 x i8], [8 x i8]* @ReturnedBuf, i64 0, i64 0)"
                            .to_string(),
                    ),
                    loc: None,
                }],
            }],
            globals: vec![test_global("ReturnedBuf")],
            global_init: vec![Stmt::GlobalRef {
                global: "ReturnedBuf".to_string(),
                access: Access::Mod,
                volatile: false,
                loc: None,
            }],
        };

        let rendered = run_cc2json(
            &pir,
            Path::new("returned_inline_constexpr.pir.json"),
            &cc2json_test_opts(),
        )
        .unwrap();
        let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(json["escaped_globals"], serde_json::json!([]), "{rendered}");
    }

    #[test]
    fn cc2json_inline_constexpr_return_passed_to_internal_call_escapes() {
        let ptr_sig = Signature {
            ret: AbiClass::Integer,
            params: Vec::new(),
            vararg: false,
            cc: "ccc".to_string(),
        };
        let pir = Pir {
            module: "returned_inline_constexpr_internal_use".to_string(),
            source: None,
            lowering: Default::default(),
            target: None,
            functions: vec![
                Func {
                    key: "producer".to_string(),
                    sig: ptr_sig.clone(),
                    param_names: Vec::new(),
                    file: None,
                    line: None,
                    external: false,
                    exported: false,
                    address_taken: false,
                    body: vec![Stmt::Return {
                        value: Some(
                            "i8* getelementptr inbounds ([8 x i8], [8 x i8]* @ReturnedBuf, i64 0, i64 0)"
                                .to_string(),
                        ),
                        loc: None,
                    }],
                },
                Func {
                    key: "sink".to_string(),
                    sig: void_sig(),
                    param_names: vec!["%sink::p".to_string()],
                    file: None,
                    line: None,
                    external: false,
                    exported: false,
                    address_taken: false,
                    body: Vec::new(),
                },
                Func {
                    key: "main".to_string(),
                    sig: void_sig(),
                    param_names: Vec::new(),
                    file: None,
                    line: None,
                    external: false,
                    exported: true,
                    address_taken: false,
                    body: vec![
                        Stmt::CallDirect {
                            callee: "producer".to_string(),
                            sig: ptr_sig,
                            args: Vec::new(),
                            dest: Some("%p".to_string()),
                            loc: None,
                        },
                        Stmt::CallDirect {
                            callee: "sink".to_string(),
                            sig: void_sig(),
                            args: vec!["%p".to_string()],
                            dest: None,
                            loc: None,
                        },
                    ],
                },
            ],
            globals: vec![test_global("ReturnedBuf")],
            global_init: vec![Stmt::GlobalRef {
                global: "ReturnedBuf".to_string(),
                access: Access::Mod,
                volatile: false,
                loc: None,
            }],
        };

        let rendered = run_cc2json(
            &pir,
            Path::new("returned_inline_constexpr_internal_use.pir.json"),
            &cc2json_test_opts(),
        )
        .unwrap();
        let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(
            json["escaped_globals"],
            serde_json::json!(["ReturnedBuf"]),
            "{rendered}"
        );
    }

    #[test]
    fn cc2json_inline_constexpr_return_passed_to_external_call_does_not_escape() {
        let ptr_sig = Signature {
            ret: AbiClass::Integer,
            params: Vec::new(),
            vararg: false,
            cc: "ccc".to_string(),
        };
        let format_sig = Signature {
            ret: AbiClass::Integer,
            params: vec![Param::Integer, Param::Integer],
            vararg: true,
            cc: "ccc".to_string(),
        };
        let pir = Pir {
            module: "returned_inline_constexpr_external_use".to_string(),
            source: None,
            lowering: Default::default(),
            target: None,
            functions: vec![
                Func {
                    key: "producer".to_string(),
                    sig: ptr_sig.clone(),
                    param_names: Vec::new(),
                    file: None,
                    line: None,
                    external: false,
                    exported: false,
                    address_taken: false,
                    body: vec![Stmt::Return {
                        value: Some(
                            "i8* getelementptr inbounds ([8 x i8], [8 x i8]* @ReturnedBuf, i64 0, i64 0)"
                                .to_string(),
                        ),
                        loc: None,
                    }],
                },
                Func {
                    key: "fprintf".to_string(),
                    sig: format_sig.clone(),
                    param_names: Vec::new(),
                    file: None,
                    line: None,
                    external: true,
                    exported: true,
                    address_taken: false,
                    body: Vec::new(),
                },
                Func {
                    key: "main".to_string(),
                    sig: void_sig(),
                    param_names: Vec::new(),
                    file: None,
                    line: None,
                    external: false,
                    exported: true,
                    address_taken: false,
                    body: vec![
                        Stmt::CallDirect {
                            callee: "producer".to_string(),
                            sig: ptr_sig,
                            args: Vec::new(),
                            dest: Some("%p".to_string()),
                            loc: None,
                        },
                        Stmt::CallDirect {
                            callee: "fprintf".to_string(),
                            sig: format_sig,
                            args: vec![
                                "%stream".to_string(),
                                "@Fmt".to_string(),
                                "%p".to_string(),
                            ],
                            dest: Some("%written".to_string()),
                            loc: None,
                        },
                    ],
                },
            ],
            globals: vec![test_global("ReturnedBuf"), test_global("Fmt")],
            global_init: vec![
                Stmt::GlobalRef {
                    global: "ReturnedBuf".to_string(),
                    access: Access::Mod,
                    volatile: false,
                    loc: None,
                },
                Stmt::GlobalRef {
                    global: "Fmt".to_string(),
                    access: Access::Ref,
                    volatile: false,
                    loc: None,
                },
            ],
        };

        let rendered = run_cc2json(
            &pir,
            Path::new("returned_inline_constexpr_external_use.pir.json"),
            &cc2json_test_opts(),
        )
        .unwrap();
        let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(json["escaped_globals"], serde_json::json!([]), "{rendered}");
    }

    #[test]
    fn cc2json_direct_returned_global_escapes() {
        let pir = Pir {
            module: "direct_returned_global".to_string(),
            source: None,
            lowering: Default::default(),
            target: None,
            functions: vec![Func {
                key: "main".to_string(),
                sig: Signature {
                    ret: AbiClass::Integer,
                    params: Vec::new(),
                    vararg: false,
                    cc: "ccc".to_string(),
                },
                param_names: Vec::new(),
                file: None,
                line: None,
                external: false,
                exported: true,
                address_taken: false,
                body: vec![Stmt::Return {
                    value: Some("@ReturnedBuf".to_string()),
                    loc: None,
                }],
            }],
            globals: vec![test_global("ReturnedBuf")],
            global_init: vec![Stmt::GlobalRef {
                global: "ReturnedBuf".to_string(),
                access: Access::Mod,
                volatile: false,
                loc: None,
            }],
        };

        let rendered = run_cc2json(
            &pir,
            Path::new("direct_returned_global.pir.json"),
            &cc2json_test_opts(),
        )
        .unwrap();
        let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(
            json["escaped_globals"],
            serde_json::json!(["ReturnedBuf"]),
            "{rendered}"
        );
    }

    #[test]
    fn cc2json_strchr_and_strrchr_args_are_readonly_for_mutated_globals() {
        let pir = Pir {
            module: "readonly_search".to_string(),
            source: None,
            lowering: Default::default(),
            target: None,
            functions: vec![Func {
                key: "main".to_string(),
                sig: void_sig(),
                param_names: Vec::new(),
                file: None,
                line: None,
                external: false,
                exported: true,
                address_taken: false,
                body: vec![
                    Stmt::CallDirect {
                        callee: "strchr".to_string(),
                        sig: void_sig(),
                        args: vec!["@ReadonlyA".to_string(), "47".to_string()],
                        dest: None,
                        loc: None,
                    },
                    Stmt::CallDirect {
                        callee: "strrchr".to_string(),
                        sig: void_sig(),
                        args: vec!["@ReadonlyB".to_string(), "47".to_string()],
                        dest: None,
                        loc: None,
                    },
                    Stmt::CallDirect {
                        callee: "may_write".to_string(),
                        sig: void_sig(),
                        args: vec!["@Mutated".to_string()],
                        dest: None,
                        loc: None,
                    },
                    Stmt::CallDirect {
                        callee: "not_strchr_but_writes".to_string(),
                        sig: void_sig(),
                        args: vec!["@SubstringMutated".to_string()],
                        dest: None,
                        loc: None,
                    },
                ],
            }],
            globals: vec![
                test_global("ReadonlyA"),
                test_global("ReadonlyB"),
                test_global("Mutated"),
                test_global("SubstringMutated"),
            ],
            global_init: vec![
                Stmt::GlobalRef {
                    global: "ReadonlyA".to_string(),
                    access: Access::Mod,
                    volatile: false,
                    loc: None,
                },
                Stmt::GlobalRef {
                    global: "ReadonlyB".to_string(),
                    access: Access::Mod,
                    volatile: false,
                    loc: None,
                },
                Stmt::GlobalRef {
                    global: "Mutated".to_string(),
                    access: Access::Mod,
                    volatile: false,
                    loc: None,
                },
                Stmt::GlobalRef {
                    global: "SubstringMutated".to_string(),
                    access: Access::Mod,
                    volatile: false,
                    loc: None,
                },
            ],
        };

        let rendered = run_cc2json(
            &pir,
            Path::new("readonly_search.pir.json"),
            &cc2json_test_opts(),
        )
        .unwrap();
        let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(
            json["mutated_globals"],
            serde_json::json!(["Mutated", "SubstringMutated"]),
            "{rendered}"
        );
    }

    #[test]
    fn cc2json_indirect_call_args_are_conservatively_mutated_globals() {
        let pir = Pir {
            module: "indirect_global_arg".to_string(),
            source: None,
            lowering: Default::default(),
            target: None,
            functions: vec![Func {
                key: "main".to_string(),
                sig: void_sig(),
                param_names: Vec::new(),
                file: None,
                line: None,
                external: false,
                exported: true,
                address_taken: false,
                body: vec![Stmt::CallIndirect {
                    operand: "%fp".to_string(),
                    sig: void_sig(),
                    args: vec![
                        "@IndirectMutated".to_string(),
                        "i8* bitcast (@IndirectExprMutated to i8*)".to_string(),
                    ],
                    dest: None,
                    loc: None,
                }],
            }],
            globals: vec![
                test_global("IndirectMutated"),
                test_global("IndirectExprMutated"),
            ],
            global_init: vec![
                Stmt::GlobalRef {
                    global: "IndirectMutated".to_string(),
                    access: Access::Mod,
                    volatile: false,
                    loc: None,
                },
                Stmt::GlobalRef {
                    global: "IndirectExprMutated".to_string(),
                    access: Access::Mod,
                    volatile: false,
                    loc: None,
                },
            ],
        };

        let rendered = run_cc2json(
            &pir,
            Path::new("indirect_global_arg.pir.json"),
            &cc2json_test_opts(),
        )
        .unwrap();
        let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(
            json["mutated_globals"],
            serde_json::json!(["IndirectMutated", "IndirectExprMutated"]),
            "{rendered}"
        );
    }

    #[test]
    fn cc2json_high_fanout_unknown_store_uses_retained_target_set() {
        let fixture = workspace_root().join("fixtures/synthetic/m1_6/high_fanout_modref.pir.json");
        let pir = Pir::from_path(&fixture).unwrap();

        let rendered = run_cc2json(&pir, &fixture, &cc2json_test_opts()).unwrap();
        let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        let expected = (0..=16)
            .map(|idx| format!("@G{idx:02}"))
            .collect::<Vec<_>>();
        assert_eq!(
            json["mutated_globals"],
            serde_json::json!(expected),
            "{rendered}"
        );
    }

    #[test]
    fn cc2json_high_fanout_with_string_pointee_is_not_mutation_evidence() {
        let mut body = vec![Stmt::Alloca {
            dest: "%slot".to_string(),
            ty: "i8*".to_string(),
            loc: None,
        }];
        for idx in 0..=16 {
            body.push(Stmt::Store {
                address: "%slot".to_string(),
                value: format!("@G{idx:02}"),
                access_bytes: None,
                loc: None,
            });
        }
        body.push(Stmt::Store {
            address: "%slot".to_string(),
            value: "@.str.collapse".to_string(),
            access_bytes: None,
            loc: None,
        });
        body.push(Stmt::Load {
            dest: "%p".to_string(),
            address: "%slot".to_string(),
            access_bytes: None,
            loc: None,
        });
        body.push(Stmt::Store {
            address: "%p".to_string(),
            value: "%x".to_string(),
            access_bytes: None,
            loc: None,
        });

        let mut globals = (0..=16)
            .map(|idx| test_global(&format!("@G{idx:02}")))
            .collect::<Vec<_>>();
        globals.push(Global {
            key: "@.str.collapse".to_string(),
            file: None,
            line: None,
            is_const: true,
            mutable: false,
            init_refs: Vec::new(),
            exported: false,
            ..Global::default()
        });
        let global_init = (0..=16)
            .map(|idx| Stmt::GlobalRef {
                global: format!("@G{idx:02}"),
                access: Access::Mod,
                volatile: false,
                loc: None,
            })
            .collect();
        let pir = Pir {
            module: "high_fanout_string_collapse".to_string(),
            source: None,
            lowering: Default::default(),
            target: None,
            functions: vec![Func {
                key: "main".to_string(),
                sig: void_sig(),
                param_names: Vec::new(),
                file: None,
                line: None,
                external: false,
                exported: true,
                address_taken: false,
                body,
            }],
            globals,
            global_init,
        };

        let rendered = run_cc2json(
            &pir,
            Path::new("high_fanout_string_collapse.pir.json"),
            &cc2json_test_opts(),
        )
        .unwrap();
        let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(json["mutated_globals"], serde_json::json!([]), "{rendered}");
    }

    #[test]
    fn executable_cc2json_does_not_escape_functions_via_exported_global_roots() {
        let pir = Pir {
            module: "executable_exported_fp_root".to_string(),
            source: None,
            lowering: Default::default(),
            target: None,
            functions: vec![
                Func {
                    key: "main".to_string(),
                    sig: void_sig(),
                    param_names: Vec::new(),
                    file: None,
                    line: None,
                    external: false,
                    exported: true,
                    address_taken: false,
                    body: vec![Stmt::Store {
                        address: "@Dispatch".to_string(),
                        value: "@Target".to_string(),
                        access_bytes: None,
                        loc: None,
                    }],
                },
                Func {
                    key: "Target".to_string(),
                    sig: void_sig(),
                    param_names: Vec::new(),
                    file: None,
                    line: None,
                    external: false,
                    exported: false,
                    address_taken: true,
                    body: Vec::new(),
                },
            ],
            globals: vec![Global {
                key: "Dispatch".to_string(),
                file: None,
                line: None,
                is_const: false,
                mutable: true,
                init_refs: Vec::new(),
                exported: true,
                ..Global::default()
            }],
            global_init: vec![Stmt::GlobalRef {
                global: "Dispatch".to_string(),
                access: Access::Mod,
                volatile: false,
                loc: None,
            }],
        };

        let rendered = run_cc2json(
            &pir,
            Path::new("executable_exported_fp_root.pir.json"),
            &cc2json_test_opts(),
        )
        .unwrap();
        let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(json["escaped_globals"], serde_json::json!([]), "{rendered}");
    }

    /// The `lib-small` library golden was produced by cclyzer's unification analysis; pangs'
    /// `steens` stage reproduces it byte-for-byte through the full cc2json renderer.
    #[test]
    fn lib_small_matches_golden_byte_for_byte() {
        let root = workspace_root();
        let bc = root.join("ju_cc2json/lib-small-g-O0.bc");
        if !bc.exists() {
            // Golden inputs are not always vendored; skip rather than fail in that case.
            return;
        }
        let pir = Pir::from_path(&bc).unwrap();
        let opts = Cc2jsonOpts {
            stage: Stage::Steens,
            build_mode: BuildMode::Library,
            internalize_globals: false,
            partition_budget: 100_000,
        };
        let got = run_cc2json(&pir, &bc, &opts).unwrap();
        let golden =
            std::fs::read_to_string(root.join("ju_cc2json/lib-small-g-O0.cc2json.json")).unwrap();
        assert_eq!(got, golden, "cc2json output diverged from lib-small golden");
    }

    /// The Andersen stage runs over the same module without panicking and produces a parseable
    /// summary. Andersen only *narrows* the points-to the escape fixpoint builds on, so its
    /// `escaped_globals` must be a subset of the Steens stage's — never a superset (a widening
    /// would be a soundness regression in the narrowing ledger).
    #[test]
    fn lib_small_andersen_escaped_globals_subset_of_steens() {
        let root = workspace_root();
        let bc = root.join("ju_cc2json/lib-small-g-O0.bc");
        if !bc.exists() {
            return;
        }
        let pir = Pir::from_path(&bc).unwrap();
        let base = Cc2jsonOpts {
            stage: Stage::Steens,
            build_mode: BuildMode::Library,
            internalize_globals: false,
            partition_budget: 100_000,
        };
        let andersen = Cc2jsonOpts {
            stage: Stage::Andersen,
            ..base.clone()
        };

        let escaped = |opts: &Cc2jsonOpts| -> Vec<String> {
            let pag = Pag::from_pir(
                &pir,
                &PagOpts {
                    build_mode: opts.build_mode.into(),
                    ..PagOpts::default()
                },
            );
            let solved = match opts.stage {
                Stage::Andersen => pangs_solve::solve_andersen_with_global_points_to(
                    &pir,
                    &pag,
                    opts.build_mode.into(),
                    opts.partition_budget,
                ),
                _ => pangs_solve::solve_steensgaard_with_global_points_to(
                    &pir,
                    &pag,
                    opts.build_mode.into(),
                ),
            };
            escaped_globals(&pir, &solved, opts.internalize_globals, opts.build_mode)
        };

        let steens_escaped: BTreeSet<String> = escaped(&base).into_iter().collect();
        for g in escaped(&andersen) {
            assert!(
                steens_escaped.contains(&g),
                "andersen escaped global {g:?} not in steens envelope (ledger break)"
            );
        }

        // And the full renderer runs end-to-end under the Andersen stage.
        assert!(run_cc2json(&pir, &bc, &andersen).is_ok());
    }

    #[test]
    fn json_escape_handles_control_and_quotes() {
        assert_eq!(json_escape("a\"b\\c\n"), "a\\\"b\\\\c\\n");
        assert_eq!(json_escape("\u{1}"), "\\u0001");
    }

    #[test]
    fn unique_filename_mapper_disambiguates_collisions() {
        let mut ufm = UniqueFilenameMapper::default();
        assert_eq!(ufm.get_short("/a", "f.c"), "f.c");
        assert_eq!(ufm.get_short("/a", "f.c"), "f.c"); // same pair → same short name
        assert_eq!(ufm.get_short("/b", "f.c"), "f.c!1"); // collision → suffixed
    }
}
