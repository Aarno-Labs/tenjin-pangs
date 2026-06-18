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

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result};
use pangs_api::{
    Analysis, BuildMode, Callee, Caller, CallKind, FuncId, GlobalTarget, Opts, Stage,
};
use pangs_pir::{Access, Func, Loc, Pir, Stmt};
use pangs_pag::{Pag, PagOpts};
use pangs_solve::{solve_steensgaard_with_points_to, SolveResult};

/// Options for the `cc2json` subcommand. `entrypoints`/`build_mode` follow pangs naming
/// (library = all functions reachable; executable = reachable from `main`). `internalize_globals`
/// mirrors cclyzer's flag — when off (the default, matching how the goldens were produced),
/// external-linkage globals are externally visible and can anchor escape.
#[derive(Debug, Clone)]
pub struct Cc2jsonOpts {
    pub stage: Stage,
    pub build_mode: BuildMode,
    pub internalize_globals: bool,
}

/// Run the analysis on `pir` and render the `cc2json` JSON summary.
pub fn run_cc2json(pir: &Pir, _input_path: &Path, opts: &Cc2jsonOpts) -> Result<String> {
    let api_opts = Opts {
        stage: opts.stage,
        build_mode: opts.build_mode,
        ..Opts::default()
    };
    let analysis = Analysis::run(pir, &api_opts).context("run pangs analysis")?;

    // Allocation-level points-to (cclyzer ran unification, so escape/mutation use a steens solve
    // regardless of the call-graph stage).
    let pag = Pag::from_pir(
        pir,
        &PagOpts {
            build_mode: opts.build_mode.into(),
            ..PagOpts::default()
        },
    );
    let solved = solve_steensgaard_with_points_to(pir, &pag, opts.build_mode.into());

    let source = pir.source.clone().unwrap_or_default();

    let mutated = mutated_globals(pir, &analysis);
    let escaped = escaped_globals(pir, &solved, opts.internalize_globals);

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
    let mut mutated: BTreeSet<&str> = analysis
        .modrefs()
        .iter()
        .filter(|mr| matches!(mr.access, Access::Mod))
        .filter_map(|mr| match &mr.global {
            GlobalTarget::Name(id) => Some(analysis.globals()[*id].key.as_str()),
            GlobalTarget::Unknown(_) => None,
        })
        .collect();

    let global_names: BTreeSet<&str> = pir.globals.iter().map(|g| g.key.as_str()).collect();
    let arg_mutated = mutated_via_call_args(pir, &global_names);
    mutated.extend(arg_mutated.iter().map(String::as_str));

    // cclyzer only forms a global_allocation for globals *defined* in the module, so external
    // declarations (e.g. libc's `stdout`) are never mutated. pangs records a `GlobalRef` mod in
    // `global_init` for exactly the defined globals (those with an initializer), so restrict to
    // that set. This drops field-insensitive aliased false-positives that land on extern decls
    // (sbase's `stdout`) without losing defined aggregates like `g_buffer`.
    let defined = defined_globals(pir);
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
/// mutation-via-(external-)function rule). Only direct calls are scanned. Returns full global
/// names; the caller drops `.`-prefixed ones.
fn mutated_via_call_args(pir: &Pir, global_names: &BTreeSet<&str>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for func in &pir.functions {
        let map = operand_def_map(func);
        for stmt in &func.body {
            let Stmt::CallDirect { callee, args, .. } = stmt else {
                continue;
            };
            for (index, arg) in args.iter().enumerate() {
                if known_readonly_arg(callee, index) {
                    continue;
                }
                if let Some(base) = resolve_arg_global(&map, arg) {
                    if global_names.contains(base.as_str()) {
                        out.insert(base);
                    }
                }
            }
        }
    }
    out
}

/// Resolve a call argument to the global whose address it denotes: a temp gep/bitcast chain or a
/// literal `@g` (`resolve_base_global`), else the first global symbol inside a constant-expr
/// operand string such as `i8* getelementptr inbounds (... @g, ...)` / `i8* bitcast (... @g ...)`.
fn resolve_arg_global(map: &BTreeMap<&str, &Stmt>, operand: &str) -> Option<String> {
    if let Some(base) = resolve_base_global(map, operand) {
        return Some(base);
    }
    first_global_symbol(operand)
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
/// `known_readonly_arg` rules in escape-analysis.dl (substring matches on the callee name), plus
/// `__assert_fail` (all positions read-only) so the `__PRETTY_FUNCTION__`/`__func__` strings it
/// receives are not treated as mutated.
fn known_readonly_arg(callee: &str, index: usize) -> bool {
    let c = |needle: &str| callee.contains(needle);
    // assert helpers: all arguments are read-only.
    if c("__assert_fail") || c("__assert_perror_fail") || c("__assert_rtn") {
        return true;
    }
    // memcpy/memmove source (arg 1), incl. LLVM intrinsics.
    if (c("memcpy") || c("memmove") || c("llvm.memcpy.p0") || c("llvm.memmove.p0")) && index == 1 {
        return true;
    }
    // strcpy/strncpy source (arg 1).
    if (c("strcpy") || c("strncpy")) && index == 1 {
        return true;
    }
    // string search/compare: args 0,1,2 read-only.
    if (c("strlen")
        || c("strcmp")
        || c("strncmp")
        || c("strchr")
        || c("strrchr")
        || c("strstr")
        || c("strcspn")
        || c("strspn")
        || c("strpbrk"))
        && index <= 2
    {
        return true;
    }
    // memory search: memchr/memcmp args 0,1,2.
    if (c("memchr") || c("memcmp")) && index <= 2 {
        return true;
    }
    // bsearch: key/array (args 0,1).
    if c("bsearch") && index <= 1 {
        return true;
    }
    // llvm.objectsize: arg 0.
    if c("llvm.objectsize.") && index == 0 {
        return true;
    }
    false
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
/// * Return-escape: a pointer to a global value returned from a (reachable) function escapes
///   (covers returned `static` buffers like OMP's `stat2info.info_xjtr_0`).
///
/// Closed to a fixpoint (an escaped global becomes escaped memory). Operands are resolved
/// syntactically through gep/bitcast/select chains (not through loads).
///
/// DIVERGENCE: escape that flows only through *aliased* (memory-indirect) stores or through
/// escaping external-call arguments is not modeled — pangs may under-report there relative to
/// cclyzer's points-to-based analysis. Names are `.`-filtered, ordered global-then-function.
fn escaped_globals(pir: &Pir, solved: &SolveResult, internalize_globals: bool) -> Vec<String> {
    let global_names: BTreeSet<&str> = pir.globals.iter().map(|g| g.key.as_str()).collect();
    let func_names: BTreeSet<&str> = pir.functions.iter().map(|f| f.key.as_str()).collect();
    let is_known = |n: &str| global_names.contains(n) || func_names.contains(n);
    let defined = defined_globals(pir);

    // Externally-accessible base globals (external-linkage, defined here). With internalize, none.
    let externally_visible: Vec<&str> = if internalize_globals {
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

    // Return-escape: a pointer to a global value returned from a function escapes (covers returned
    // `static` buffers). Resolved syntactically through gep/bitcast chains.
    let func_maps: Vec<BTreeMap<&str, &Stmt>> =
        pir.functions.iter().map(operand_def_map).collect();
    for (func, map) in pir.functions.iter().zip(&func_maps) {
        for stmt in &func.body {
            if let Stmt::Return {
                value: Some(value), ..
            } = stmt
            {
                if let Some(base) = resolve_base_global(map, value) {
                    if is_known(&base) {
                        escaped.insert(base);
                    }
                }
            }
        }
    }

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

/// Map each SSA result name in a function body to its defining statement.
fn operand_def_map(func: &Func) -> BTreeMap<&str, &Stmt> {
    let mut map = BTreeMap::new();
    for stmt in &func.body {
        let dest = match stmt {
            Stmt::Alloca { dest, .. }
            | Stmt::Assign { dest, .. }
            | Stmt::Load { dest, .. }
            | Stmt::Gep { dest, .. }
            | Stmt::PtrToInt { dest, .. }
            | Stmt::IntToPtr { dest, .. } => Some(dest.as_str()),
            _ => None,
        };
        if let Some(dest) = dest {
            map.entry(dest).or_insert(stmt);
        }
    }
    map
}

/// Resolve an operand to the base global value it refers to, tracing only address-preserving
/// chains: a literal `@name`, or a temp defined by a gep/bitcast/select (`Assign`) over a base
/// that resolves. Never traces through a `Load` (that would be a dereference, not the address).
fn resolve_base_global(map: &BTreeMap<&str, &Stmt>, operand: &str) -> Option<String> {
    fn go(map: &BTreeMap<&str, &Stmt>, operand: &str, depth: usize) -> Option<String> {
        if depth > 64 {
            return None;
        }
        if let Some(name) = operand.strip_prefix('@') {
            return Some(name.to_string());
        }
        match map.get(operand)? {
            Stmt::Gep { base, .. } => go(map, base, depth + 1),
            Stmt::Assign { sources, .. } => {
                sources.iter().find_map(|s| go(map, s, depth + 1))
            }
            _ => None,
        }
    }
    go(map, operand, 0)
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
                let (dir, file) = match pir_loc.and_then(|l| l.dir.as_ref().zip(l.filename.as_ref()))
                {
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
    let hits = |operand: &str| all_global_symbols(operand).any(|g| interesting.contains(g.as_str()));
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
            Stmt::CallIndirect { operand, args, .. } => hits(operand) || args.iter().any(|a| hits(a)),
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
    use std::path::PathBuf;

    fn workspace_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
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
        };
        let got = run_cc2json(&pir, &bc, &opts).unwrap();
        let golden =
            std::fs::read_to_string(root.join("ju_cc2json/lib-small-g-O0.cc2json.json")).unwrap();
        assert_eq!(got, golden, "cc2json output diverged from lib-small golden");
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
