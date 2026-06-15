use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Instant;

use pangs_pag::{BuildMode as PagBuildMode, Edge, EdgeKind, Owner, Pag, PagOpts};
use pangs_pir::{fsa_compatible, Access, LoweringStats, Pir, Stmt};
use pangs_solve::{
    debug_assert_narrows, solve_andersen_with_overrides, solve_steensgaard, NodeResolution,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod differential;
mod initval;
mod simple;
pub use differential::{run_differential, DifferentialReport};
use initval::resolve_initval_icalls;
use simple::{resolve_simple_icalls, SimpleIcallQuery, SimpleIcallResolution};

#[derive(Debug, Error)]
pub enum AnalysisError {
    #[error("duplicate function key {0}")]
    DuplicateFunction(String),
    #[error("duplicate global key {0}")]
    DuplicateGlobal(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FuncId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GlobalId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CallsiteId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ComponentId(pub u32);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Opts {
    pub stage: Stage,
    pub build_mode: BuildMode,
    pub exports: BTreeSet<String>,
    pub partition_budget: u64,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            stage: Stage::Conservative,
            build_mode: BuildMode::Library,
            exports: BTreeSet::new(),
            partition_budget: 1_000_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Conservative,
    Steens,
    Andersen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildMode {
    Library,
    Executable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuncInfo {
    pub key: String,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub external: bool,
    pub exported: bool,
    pub address_taken: bool,
    pub vararg: bool,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalInfo {
    pub key: String,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub is_const: bool,
    pub mutable: bool,
    pub never_written: bool,
    pub escape: EscapeStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscapeStatus {
    Module,
    External,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallsiteInfo {
    pub key: String,
    pub caller: FuncId,
    pub kind: CallKind,
    pub loc: Option<LocInfo>,
    pub synthetic: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallKind {
    Direct,
    Indirect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocInfo {
    pub file: String,
    pub line: u32,
    pub col: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallEdge {
    pub caller: Caller,
    pub callsite: Option<CallsiteId>,
    pub callee: Callee,
    pub kind: CallKind,
    pub tier: Tier,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Caller {
    Func(FuncId),
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Callee {
    Func(FuncId),
    Unknown(String),
}

/// Provenance of a resolved call edge. Tiers are ordered by *exactness*: a later phase may
/// only narrow an earlier one (`Simple ⊆ Andersen ⊆ Steens ⊆ Fsa`); `Direct` is a
/// syntactic call. `Simple` is the M2 lite provenance (`DESIGN_lite.md` §2F) for icalls
/// resolved exactly by a B1/B2 def-use walk — it bypasses the FSA envelope entirely. It is
/// declared now (M2.0) and populated by M2.2/M2.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Direct,
    Fsa,
    Steens,
    Andersen,
    Simple,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModRef {
    pub func: FuncId,
    pub global: GlobalTarget,
    pub access: Access,
    pub via: Via,
    pub witness: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GlobalTarget {
    Name(GlobalId),
    Unknown(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Via {
    Direct,
    Aliased,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentInfo {
    pub id: String,
    pub frozen: bool,
    pub taint: Vec<Taint>,
    pub members: Vec<FuncId>,
    pub mutable_globals: Vec<GlobalId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Taint {
    pub kind: String,
    pub witness: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub kind: String,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub affected: Vec<String>,
    pub effect: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metrics {
    pub functions: usize,
    pub globals: usize,
    pub callsites: usize,
    pub call_edges: usize,
    pub audit_findings: usize,
    pub mutable_globals_total: usize,
    pub in_rewritable_components: usize,
    pub partition_count: usize,
    pub partition_p50_size: usize,
    pub partition_p95_size: usize,
    pub partition_max_size: usize,
    pub oversize_fallbacks: usize,
    pub rounds: usize,
    /// Flat per-provenance icall attribution (M2.0, `DESIGN_lite.md` §2F). Counts indirect
    /// callsites whose resolved edges carry each tier; the ablation signal M2.7 reads.
    /// `icalls_unknown` counts sites with an Ω/unknown-callee edge. No certificate cascade.
    pub icalls_simple: usize,
    pub icalls_andersen: usize,
    pub icalls_steens: usize,
    pub icalls_fsa: usize,
    pub icalls_unknown: usize,
    pub confined_functions: usize,
    pub globals_with_complete_initval: usize,
    pub stationary_globals: usize,
    pub analysis_wall_us: u64,
    pub pag_build_us: u64,
    pub solve_us: u64,
    pub transitive_modref_us: u64,
    pub components_us: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lowering: Option<LoweringStats>,
}

#[derive(Debug)]
enum DeferredAudit {
    PtrToInt {
        caller: FuncId,
        owner: String,
        operand: String,
        loc: Option<pangs_pir::Loc>,
    },
    IntToPtr {
        caller: FuncId,
        owner: String,
        result: String,
        loc: Option<pangs_pir::Loc>,
    },
    VarargFnPtr {
        caller: FuncId,
        owner: String,
        values: Vec<String>,
        loc: Option<pangs_pir::Loc>,
        witness: String,
    },
}

#[derive(Debug, Default)]
struct AggregateFnPtrState {
    flagged: BTreeSet<String>,
}

impl AggregateFnPtrState {
    fn note(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Alloca { dest, ty, .. } => {
                if is_fnptr_aggregate_type(ty) {
                    self.flagged.insert(dest.clone());
                }
            }
            Stmt::Assign { dest, sources, .. } => {
                if sources.iter().any(|source| self.flagged.contains(source)) {
                    self.flagged.insert(dest.clone());
                }
            }
            Stmt::Gep { dest, base, .. } => {
                if self.flagged.contains(base) {
                    self.flagged.insert(dest.clone());
                }
            }
            _ => {}
        }
    }

    fn contains(&self, value: &str) -> bool {
        self.flagged.contains(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Table<I, T> {
    rows: Vec<T>,
    #[serde(skip)]
    _id: std::marker::PhantomData<I>,
}

impl<I, T> Table<I, T> {
    fn new(rows: Vec<T>) -> Self {
        Self {
            rows,
            _id: std::marker::PhantomData,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.rows.iter()
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

impl<T> std::ops::Index<FuncId> for Table<FuncId, T> {
    type Output = T;

    fn index(&self, id: FuncId) -> &Self::Output {
        &self.rows[id.0 as usize]
    }
}

impl<T> std::ops::Index<GlobalId> for Table<GlobalId, T> {
    type Output = T;

    fn index(&self, id: GlobalId) -> &Self::Output {
        &self.rows[id.0 as usize]
    }
}

impl<T> std::ops::Index<CallsiteId> for Table<CallsiteId, T> {
    type Output = T;

    fn index(&self, id: CallsiteId) -> &Self::Output {
        &self.rows[id.0 as usize]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Analysis {
    functions: Table<FuncId, FuncInfo>,
    globals: Table<GlobalId, GlobalInfo>,
    callsites: Table<CallsiteId, CallsiteInfo>,
    call_edges: Vec<CallEdge>,
    modrefs: Vec<ModRef>,
    #[serde(skip)]
    transitive_modrefs: Vec<Vec<ModRef>>,
    components: Vec<ComponentInfo>,
    findings: Vec<Finding>,
    metrics: Metrics,
    #[serde(skip)]
    func_lookup: HashMap<String, FuncId>,
    #[serde(skip)]
    global_lookup: HashMap<String, GlobalId>,
}

impl Analysis {
    pub fn run(module: &Pir, opts: &Opts) -> Result<Self, AnalysisError> {
        let analysis_started = Instant::now();
        let mut func_lookup = HashMap::new();
        let mut functions = Vec::new();
        for (idx, func) in module.functions.iter().enumerate() {
            if func_lookup
                .insert(func.key.clone(), FuncId(idx as u32))
                .is_some()
            {
                return Err(AnalysisError::DuplicateFunction(func.key.clone()));
            }
            functions.push(FuncInfo {
                key: func.key.clone(),
                file: func.file.clone(),
                line: func.line,
                external: func.external,
                exported: is_exported_func(func.exported, &func.key, opts),
                address_taken: func.address_taken,
                vararg: func.vararg(),
                sig: signature_text(&func.sig),
            });
        }

        let mut global_lookup = HashMap::new();
        let mut globals = Vec::new();
        for (idx, global) in module.globals.iter().enumerate() {
            if global_lookup
                .insert(global.key.clone(), GlobalId(idx as u32))
                .is_some()
            {
                return Err(AnalysisError::DuplicateGlobal(global.key.clone()));
            }
            let exported = is_exported_global(global.exported, &global.key, opts);
            globals.push(GlobalInfo {
                key: global.key.clone(),
                file: global.file.clone(),
                line: global.line,
                is_const: global.is_const,
                mutable: global.mutable && !global.is_const,
                never_written: true,
                escape: if exported {
                    EscapeStatus::External
                } else {
                    EscapeStatus::Module
                },
            });
        }

        let mut callsites = Vec::new();
        let mut call_edges = Vec::new();
        let mut modrefs = Vec::new();
        let mut findings = Vec::new();
        let mut audit_taints = BTreeMap::<FuncId, Vec<Taint>>::new();
        let mut deferred_audits = Vec::<DeferredAudit>::new();
        let mut indirect_callsites = Vec::new();
        let mut simple_icall_queries = Vec::new();
        let mut solver_metrics = None;
        let mut pag_build_us = 0;
        let mut solve_us = 0;
        let address_taken: Vec<_> = module
            .functions
            .iter()
            .enumerate()
            .filter(|(_, f)| f.address_taken)
            .map(|(idx, f)| (FuncId(idx as u32), f))
            .collect();

        let mut noloc_ord: BTreeMap<(String, String), u32> = BTreeMap::new();
        for (func_idx, func) in module.functions.iter().enumerate() {
            let caller = FuncId(func_idx as u32);
            let mut aggregate_fnptrs = AggregateFnPtrState::default();
            for (stmt_idx, stmt) in func.body.iter().enumerate() {
                match stmt {
                    Stmt::Alloca { .. } | Stmt::Assign { .. } | Stmt::Gep { .. } => {
                        aggregate_fnptrs.note(stmt);
                    }
                    Stmt::CallDirect { callee, loc, .. } => {
                        let cs = push_callsite(
                            &mut callsites,
                            &mut noloc_ord,
                            caller,
                            &func.key,
                            CallKind::Direct,
                            loc,
                        );
                        let callsite_key = callsites[cs.0 as usize].key.clone();
                        detect_direct_call_audits(
                            &mut findings,
                            &mut audit_taints,
                            module,
                            caller,
                            callee,
                            stmt,
                            loc,
                            &callsite_key,
                        );
                        if let Stmt::CallDirect { sig, .. } = stmt {
                            record_vararg_deferred_audit(
                                &mut deferred_audits,
                                caller,
                                &func.key,
                                stmt,
                                sig,
                                loc,
                                &callsite_key,
                            );
                        }
                        if let Some(&callee_id) = func_lookup.get(callee) {
                            call_edges.push(CallEdge {
                                caller: Caller::Func(caller),
                                callsite: Some(cs),
                                callee: Callee::Func(callee_id),
                                kind: CallKind::Direct,
                                tier: Tier::Direct,
                            });
                        } else {
                            call_edges.push(CallEdge {
                                caller: Caller::Func(caller),
                                callsite: Some(cs),
                                callee: Callee::Unknown("external_callee".to_string()),
                                kind: CallKind::Direct,
                                tier: Tier::Direct,
                            });
                        }
                    }
                    Stmt::CallIndirect {
                        operand, sig, loc, ..
                    } => {
                        let cs = push_callsite(
                            &mut callsites,
                            &mut noloc_ord,
                            caller,
                            &func.key,
                            CallKind::Indirect,
                            loc,
                        );
                        let callsite_key = callsites[cs.0 as usize].key.clone();
                        detect_indirect_call_audits(
                            &mut findings,
                            &mut audit_taints,
                            module,
                            caller,
                            stmt,
                            sig,
                            loc,
                            &callsite_key,
                        );
                        record_vararg_deferred_audit(
                            &mut deferred_audits,
                            caller,
                            &func.key,
                            stmt,
                            sig,
                            loc,
                            &callsite_key,
                        );
                        indirect_callsites.push((cs, caller, sig.clone()));
                        simple_icall_queries.push(SimpleIcallQuery {
                            callsite: cs,
                            callsite_key,
                            func_index: func_idx,
                            stmt_index: stmt_idx,
                            operand: operand.clone(),
                            sig: sig.clone(),
                        });
                    }
                    Stmt::Unknown {
                        reason,
                        operands,
                        results,
                        loc,
                        ..
                    } if reason.starts_with("inline_asm") => {
                        let witness = witness_key(&func.key, loc, &mut noloc_ord, "audit");
                        push_audit_finding(
                            &mut findings,
                            &mut audit_taints,
                            caller,
                            "inline_asm",
                            loc,
                            audit_affected_values(func.key.as_str(), operands, results),
                            witness,
                        );
                    }
                    Stmt::Memcpy { dst, src, loc, .. } => {
                        detect_memory_aggregate_audits(
                            &mut findings,
                            &mut audit_taints,
                            &mut noloc_ord,
                            caller,
                            &func.key,
                            "memcpy_fnptr_aggregate",
                            loc,
                            [dst.as_str(), src.as_str()]
                                .into_iter()
                                .filter(|value| aggregate_fnptrs.contains(value))
                                .map(ToOwned::to_owned)
                                .collect(),
                        );
                    }
                    Stmt::Memset { dst, loc, .. } => {
                        detect_memory_aggregate_audits(
                            &mut findings,
                            &mut audit_taints,
                            &mut noloc_ord,
                            caller,
                            &func.key,
                            "memset_fnptr_aggregate",
                            loc,
                            if aggregate_fnptrs.contains(dst) {
                                vec![dst.clone()]
                            } else {
                                Vec::new()
                            },
                        );
                    }
                    Stmt::PtrToInt { source, loc, .. } => {
                        deferred_audits.push(DeferredAudit::PtrToInt {
                            caller,
                            owner: func.key.clone(),
                            operand: source.clone(),
                            loc: loc.clone(),
                        });
                    }
                    Stmt::IntToPtr { dest, loc, .. } => {
                        deferred_audits.push(DeferredAudit::IntToPtr {
                            caller,
                            owner: func.key.clone(),
                            result: dest.clone(),
                            loc: loc.clone(),
                        });
                    }
                    Stmt::GlobalRef {
                        global,
                        access,
                        loc,
                    } => {
                        if let Some(&gid) = global_lookup.get(global) {
                            if matches!(access, Access::Mod) {
                                globals[gid.0 as usize].never_written = false;
                            }
                            modrefs.push(ModRef {
                                func: caller,
                                global: GlobalTarget::Name(gid),
                                access: *access,
                                via: Via::Direct,
                                witness: witness_key(&func.key, loc, &mut noloc_ord, "global"),
                            });
                        }
                    }
                    _ => {}
                }
            }
        }
        for stmt in &module.global_init {
            if let Stmt::GlobalRef {
                global,
                access: Access::Mod,
                ..
            } = stmt
            {
                if let Some(&gid) = global_lookup.get(global) {
                    globals[gid.0 as usize].never_written = false;
                }
            }
        }
        let simple_report = resolve_simple_icalls(module, &simple_icall_queries);
        let initval_report = resolve_initval_icalls(module, &simple_icall_queries);
        let mut exact_icalls = simple_report.resolutions.clone();
        for (callsite, resolution) in &initval_report.resolutions {
            exact_icalls
                .entry(*callsite)
                .or_insert_with(|| resolution.clone());
        }
        let simple_icalls = &exact_icalls;
        let confined_functions = &simple_report.confined_functions;
        let simple_queries: BTreeMap<CallsiteId, &SimpleIcallQuery> = simple_icall_queries
            .iter()
            .map(|query| (query.callsite, query))
            .collect();
        let simple_exact_targets: BTreeMap<String, Vec<String>> = simple_icalls
            .iter()
            .filter_map(|(callsite, resolution)| {
                simple_queries
                    .get(callsite)
                    .map(|query| (query.callsite_key.clone(), resolution.targets.clone()))
            })
            .collect();

        match opts.stage {
            Stage::Conservative => {
                for (cs, caller, sig) in &indirect_callsites {
                    for (target_id, target) in &address_taken {
                        if fsa_compatible(sig, &target.sig) {
                            call_edges.push(CallEdge {
                                caller: Caller::Func(*caller),
                                callsite: Some(*cs),
                                callee: Callee::Func(*target_id),
                                kind: CallKind::Indirect,
                                tier: Tier::Fsa,
                            });
                        }
                    }
                    call_edges.push(CallEdge {
                        caller: Caller::Func(*caller),
                        callsite: Some(*cs),
                        callee: Callee::Unknown("omega_fnptr".to_string()),
                        kind: CallKind::Indirect,
                        tier: Tier::Fsa,
                    });
                }
                for (idx, func) in module.functions.iter().enumerate() {
                    if functions[idx].address_taken || functions[idx].exported || func.external {
                        call_edges.push(CallEdge {
                            caller: Caller::Unknown("address_escapes_to_external".to_string()),
                            callsite: None,
                            callee: Callee::Func(FuncId(idx as u32)),
                            kind: CallKind::Direct,
                            tier: Tier::Fsa,
                        });
                    }
                }
            }
            Stage::Steens | Stage::Andersen => {
                let pag_started = Instant::now();
                let pag = Pag::from_pir(
                    module,
                    &PagOpts {
                        build_mode: opts.build_mode.into(),
                        exports: opts.exports.clone(),
                    },
                );
                pag_build_us = pag_started.elapsed().as_micros() as u64;
                let solve_started = Instant::now();
                let solved = match opts.stage {
                    Stage::Andersen => solve_andersen_with_overrides(
                        module,
                        &pag,
                        opts.build_mode.into(),
                        opts.partition_budget,
                        &simple_exact_targets,
                        confined_functions,
                    ),
                    _ => solve_steensgaard(module, &pag, opts.build_mode.into()),
                };
                solve_us = solve_started.elapsed().as_micros() as u64;
                solver_metrics = Some(solved.metrics.clone());
                emit_deferred_steens_audits(
                    &mut findings,
                    &mut audit_taints,
                    module,
                    &solved.nodes,
                    deferred_audits,
                );
                let callsite_by_key: HashMap<_, _> = callsites
                    .iter()
                    .enumerate()
                    .map(|(idx, callsite)| (callsite.key.clone(), CallsiteId(idx as u32)))
                    .collect();
                let mut simple_emitted = BTreeSet::new();

                for solved_site in &solved.indirect_calls {
                    // Every solver-resolved indirect callsite MUST map back to a callsite
                    // in this export's table — they are built from the same module body in
                    // the same order. A miss means the callsite-key schemes have drifted
                    // apart again (as they once did: per-function vs per-loc ordinals),
                    // which silently drops this site's resolved targets — a soundness false
                    // negative. Make that loud in debug; never widen silently in release.
                    let Some(&cs) = callsite_by_key.get(&solved_site.callsite_key) else {
                        debug_assert!(
                            false,
                            "solved indirect callsite {} (targets={:?}, unknown_callee={}) \
                             has no matching callsite key in the export table — \
                             callsite-key scheme drift, see ju_steens_overmerge_bug.md",
                            solved_site.callsite_key,
                            solved_site.targets,
                            solved_site.unknown_callee,
                        );
                        continue;
                    };
                    let caller = callsites[cs.0 as usize].caller;
                    if let Some(simple) = simple_icalls.get(&cs) {
                        if let Some(query) = simple_queries.get(&cs) {
                            emit_simple_call_edges(
                                &mut call_edges,
                                module,
                                &func_lookup,
                                &address_taken,
                                caller,
                                cs,
                                query,
                                simple,
                            );
                            simple_emitted.insert(cs);
                            continue;
                        }
                    }
                    // Oversize/uninteresting partitions keep the Steensgaard answer even
                    // under `--stage andersen`, so they are tagged `steens`.
                    let site_tier = match opts.stage {
                        Stage::Steens => Tier::Steens,
                        Stage::Andersen if solved_site.fallback => Tier::Steens,
                        Stage::Andersen => Tier::Andersen,
                        Stage::Conservative => unreachable!(),
                    };
                    for target in &solved_site.targets {
                        if confined_functions.contains(target) {
                            continue;
                        }
                        if let Some(&callee_id) = func_lookup.get(target) {
                            call_edges.push(CallEdge {
                                caller: Caller::Func(caller),
                                callsite: Some(cs),
                                callee: Callee::Func(callee_id),
                                kind: CallKind::Indirect,
                                tier: site_tier,
                            });
                        }
                    }
                    if solved_site.unknown_callee {
                        call_edges.push(CallEdge {
                            caller: Caller::Func(caller),
                            callsite: Some(cs),
                            callee: Callee::Unknown("omega_fnptr".to_string()),
                            kind: CallKind::Indirect,
                            tier: site_tier,
                        });
                    }
                }
                for (cs, simple) in simple_icalls {
                    if simple_emitted.contains(cs) {
                        continue;
                    }
                    if let Some(query) = simple_queries.get(cs) {
                        emit_simple_call_edges(
                            &mut call_edges,
                            module,
                            &func_lookup,
                            &address_taken,
                            callsites[cs.0 as usize].caller,
                            *cs,
                            query,
                            simple,
                        );
                    }
                }

                for target in &solved.unknown_callers {
                    if let Some(&callee_id) = func_lookup.get(target) {
                        call_edges.push(CallEdge {
                            caller: Caller::Unknown("address_escapes_to_external".to_string()),
                            callsite: None,
                            callee: Callee::Func(callee_id),
                            kind: CallKind::Direct,
                            tier: match opts.stage {
                                Stage::Steens => Tier::Steens,
                                Stage::Andersen => Tier::Andersen,
                                Stage::Conservative => unreachable!(),
                            },
                        });
                    }
                }

                for global in &mut globals {
                    if let Some(state) = solved.globals.get(&global.key) {
                        global.escape = if state.escape_external {
                            EscapeStatus::External
                        } else {
                            EscapeStatus::Module
                        };
                        global.never_written = state.never_written;
                    }
                }

                push_pointer_modrefs_from_pag(
                    &mut modrefs,
                    &func_lookup,
                    &global_lookup,
                    &pag,
                    &solved.nodes,
                    &mut noloc_ord,
                );
                push_pointer_memset_modrefs_from_pir(
                    &mut modrefs,
                    module,
                    &func_lookup,
                    &global_lookup,
                    &solved.nodes,
                    &mut noloc_ord,
                );
            }
        }

        call_edges.sort_by_key(|edge| edge_sort_key(edge, &functions, &callsites));
        call_edges.dedup_by_key(|edge| edge_sort_key(edge, &functions, &callsites));
        modrefs.sort_by_key(|mr| modref_sort_key(mr, &functions, &globals));
        modrefs.dedup_by_key(|mr| modref_sort_key(mr, &functions, &globals));

        let transitive_started = Instant::now();
        let transitive_modrefs = compute_transitive_modrefs(
            functions.len(),
            &functions,
            &globals,
            &call_edges,
            &modrefs,
        );
        let transitive_modref_us = transitive_started.elapsed().as_micros() as u64;
        findings.sort_by_key(|finding| {
            (
                finding.kind.clone(),
                finding.file.clone(),
                finding.line.unwrap_or(0),
                finding.affected.join("|"),
            )
        });
        findings.dedup_by_key(|finding| {
            (
                finding.kind.clone(),
                finding.file.clone(),
                finding.line.unwrap_or(0),
                finding.affected.join("|"),
            )
        });

        let components_started = Instant::now();
        let components = compute_components(
            &functions,
            &globals,
            &callsites,
            &call_edges,
            &modrefs,
            &audit_taints,
        );
        let components_us = components_started.elapsed().as_micros() as u64;
        let mutable_globals_total = globals.iter().filter(|g| g.mutable).count();
        let in_rewritable_components = components
            .iter()
            .filter(|c| !c.frozen)
            .flat_map(|c| c.mutable_globals.iter())
            .collect::<BTreeSet<_>>()
            .len();

        // M2.0 flat per-provenance icall attribution: one verdict per indirect callsite
        // (all of a site's edges share its `tier`), plus a count of sites carrying an
        // Ω/unknown-callee edge. This is bookkeeping, not a certificate cascade.
        let mut site_tier: BTreeMap<CallsiteId, Tier> = BTreeMap::new();
        let mut site_unknown: BTreeSet<CallsiteId> = BTreeSet::new();
        for edge in &call_edges {
            if edge.kind != CallKind::Indirect {
                continue;
            }
            let Some(cs) = edge.callsite else { continue };
            site_tier.insert(cs, edge.tier);
            if matches!(edge.callee, Callee::Unknown(_)) {
                site_unknown.insert(cs);
            }
        }
        let mut icalls_simple = 0;
        let mut icalls_andersen = 0;
        let mut icalls_steens = 0;
        let mut icalls_fsa = 0;
        for tier in site_tier.values() {
            match tier {
                Tier::Simple => icalls_simple += 1,
                Tier::Andersen => icalls_andersen += 1,
                Tier::Steens => icalls_steens += 1,
                Tier::Fsa => icalls_fsa += 1,
                Tier::Direct => {}
            }
        }
        let icalls_unknown = site_unknown.len();

        let metrics = Metrics {
            functions: functions.len(),
            globals: globals.len(),
            callsites: callsites.len(),
            call_edges: call_edges.len(),
            icalls_simple,
            icalls_andersen,
            icalls_steens,
            icalls_fsa,
            icalls_unknown,
            confined_functions: confined_functions.len(),
            globals_with_complete_initval: initval_report.complete_globals.len(),
            stationary_globals: initval_report.stationary_globals.len(),
            audit_findings: findings.len(),
            mutable_globals_total,
            in_rewritable_components,
            partition_count: 0,
            partition_p50_size: 0,
            partition_p95_size: 0,
            partition_max_size: 0,
            oversize_fallbacks: 0,
            rounds: 0,
            analysis_wall_us: 0,
            pag_build_us,
            solve_us,
            transitive_modref_us,
            components_us,
            lowering: (!module.lowering.is_empty()).then(|| module.lowering.clone()),
        };

        let metrics = if let Some(solved) = solver_metrics {
            Metrics {
                partition_count: solved.partition_count,
                partition_p50_size: solved.partition_p50_size,
                partition_p95_size: solved.partition_p95_size,
                partition_max_size: solved.partition_max_size,
                oversize_fallbacks: solved.oversize_fallbacks,
                rounds: solved.rounds,
                ..metrics
            }
        } else {
            metrics
        };
        let metrics = Metrics {
            analysis_wall_us: analysis_started.elapsed().as_micros() as u64,
            ..metrics
        };

        Ok(Self {
            functions: Table::new(functions),
            globals: Table::new(globals),
            callsites: Table::new(callsites),
            call_edges,
            modrefs,
            transitive_modrefs,
            components,
            findings,
            metrics,
            func_lookup,
            global_lookup,
        })
    }

    pub fn functions(&self) -> &Table<FuncId, FuncInfo> {
        &self.functions
    }

    pub fn globals(&self) -> &Table<GlobalId, GlobalInfo> {
        &self.globals
    }

    pub fn callsites(&self) -> &Table<CallsiteId, CallsiteInfo> {
        &self.callsites
    }

    pub fn call_edges(&self) -> &[CallEdge] {
        &self.call_edges
    }

    pub fn modrefs(&self) -> &[ModRef] {
        &self.modrefs
    }

    pub fn components(&self) -> &[ComponentInfo] {
        &self.components
    }

    pub fn component(&self, id: ComponentId) -> &ComponentInfo {
        &self.components[id.0 as usize]
    }

    pub fn escape(&self, id: GlobalId) -> EscapeStatus {
        self.globals[id].escape
    }

    pub fn audit_findings(&self) -> &[Finding] {
        &self.findings
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    pub fn lookup_func(&self, key: &str) -> Option<FuncId> {
        self.func_lookup.get(key).copied()
    }

    pub fn lookup_global(&self, key: &str) -> Option<GlobalId> {
        self.global_lookup.get(key).copied()
    }

    pub fn callees(&self, cs: CallsiteId) -> impl Iterator<Item = &Callee> {
        self.call_edges
            .iter()
            .filter(move |edge| edge.callsite == Some(cs))
            .map(|edge| &edge.callee)
    }

    pub fn callers(&self, func: FuncId) -> impl Iterator<Item = &Caller> {
        self.call_edges
            .iter()
            .filter(move |edge| edge.callee == Callee::Func(func))
            .map(|edge| &edge.caller)
    }

    pub fn modref(&self, func: FuncId) -> impl Iterator<Item = &ModRef> {
        self.transitive_modrefs[func.0 as usize].iter()
    }

    pub fn component_of(&self, func: FuncId) -> ComponentId {
        for (idx, component) in self.components.iter().enumerate() {
            if component.members.contains(&func) {
                return ComponentId(idx as u32);
            }
        }
        ComponentId(0)
    }
}

fn emit_deferred_steens_audits(
    findings: &mut Vec<Finding>,
    audit_taints: &mut BTreeMap<FuncId, Vec<Taint>>,
    module: &Pir,
    node_summaries: &BTreeMap<String, NodeResolution>,
    deferred: Vec<DeferredAudit>,
) {
    for item in deferred {
        match item {
            DeferredAudit::PtrToInt {
                caller,
                owner,
                operand,
                loc,
            } => {
                let label = pag_value_label(module, &owner, &operand);
                if node_summaries
                    .get(&label)
                    .map(|node| node.reaches_function_pointer)
                    .unwrap_or(false)
                {
                    push_audit_finding(
                        findings,
                        audit_taints,
                        caller,
                        "fnptr_ptrtoint",
                        &loc,
                        vec![format!("value:{operand}")],
                        Some(audit_witness(&owner, &loc)),
                    );
                }
            }
            DeferredAudit::IntToPtr {
                caller,
                owner,
                result,
                loc,
            } => {
                let label = pag_value_label(module, &owner, &result);
                if node_summaries
                    .get(&label)
                    .map(|node| node.reaches_function_pointer)
                    .unwrap_or(false)
                {
                    push_audit_finding(
                        findings,
                        audit_taints,
                        caller,
                        "fnptr_inttoptr",
                        &loc,
                        vec![format!("value:{result}")],
                        Some(audit_witness(&owner, &loc)),
                    );
                }
            }
            DeferredAudit::VarargFnPtr {
                caller,
                owner,
                values,
                loc,
                witness,
            } => {
                let affected = values
                    .into_iter()
                    .filter(|value| {
                        let label = pag_value_label(module, &owner, value);
                        node_summaries
                            .get(&label)
                            .map(|node| node.reaches_function_pointer)
                            .unwrap_or(false)
                    })
                    .map(|value| format!("value:{value}"))
                    .collect::<Vec<_>>();
                if !affected.is_empty() {
                    push_audit_finding(
                        findings,
                        audit_taints,
                        caller,
                        "fnptr_varargs",
                        &loc,
                        affected,
                        Some(witness),
                    );
                }
            }
        }
    }
}

fn pag_value_label(module: &Pir, owner: &str, value: &str) -> String {
    if module.globals.iter().any(|global| global.key == value) {
        format!("sym:global:{value}")
    } else if module.functions.iter().any(|func| func.key == value) {
        format!("sym:function:{value}")
    } else {
        format!("val:{owner}:{value}")
    }
}

fn audit_witness(owner: &str, loc: &Option<pangs_pir::Loc>) -> String {
    match loc {
        Some(loc) => format!("{owner}@{}:{}:{}#0", loc.file, loc.line, loc.col),
        None => format!("{owner}@!noloc#0"),
    }
}

fn emit_simple_call_edges(
    call_edges: &mut Vec<CallEdge>,
    module: &Pir,
    func_lookup: &HashMap<String, FuncId>,
    address_taken: &[(FuncId, &pangs_pir::Func)],
    caller: FuncId,
    callsite: CallsiteId,
    query: &SimpleIcallQuery,
    simple: &SimpleIcallResolution,
) {
    let mut fsa_envelope = address_taken
        .iter()
        .filter(|(_, func)| fsa_compatible(&query.sig, &func.sig))
        .map(|(_, func)| func.key.clone())
        .collect::<Vec<_>>();
    fsa_envelope.sort();
    fsa_envelope.dedup();
    debug_assert_narrows(
        &query.callsite_key,
        "simple",
        &simple.targets,
        "fsa",
        &fsa_envelope,
    );
    debug_assert!(
        !simple.sites.is_empty(),
        "simple resolver produced targets without reaching sites for {}",
        query.callsite_key
    );

    for target in &simple.targets {
        let Some(&callee_id) = func_lookup.get(target) else {
            debug_assert!(
                false,
                "simple resolver returned non-module target {target:?} for {}",
                query.callsite_key
            );
            continue;
        };
        let Some(func) = module.functions.iter().find(|func| func.key == *target) else {
            continue;
        };
        if !fsa_compatible(&query.sig, &func.sig) {
            continue;
        }
        call_edges.push(CallEdge {
            caller: Caller::Func(caller),
            callsite: Some(callsite),
            callee: Callee::Func(callee_id),
            kind: CallKind::Indirect,
            tier: Tier::Simple,
        });
    }
}

impl From<BuildMode> for PagBuildMode {
    fn from(value: BuildMode) -> Self {
        match value {
            BuildMode::Library => PagBuildMode::Library,
            BuildMode::Executable => PagBuildMode::Executable,
        }
    }
}

fn is_exported_func(marked: bool, key: &str, opts: &Opts) -> bool {
    opts.exports.contains(key)
        || (opts.build_mode == BuildMode::Library && marked)
        || (opts.build_mode == BuildMode::Executable && key == "main")
}

fn is_exported_global(marked: bool, key: &str, opts: &Opts) -> bool {
    opts.exports.contains(key) || (opts.build_mode == BuildMode::Library && marked)
}

fn signature_text(sig: &pangs_pir::Signature) -> String {
    format!("{:?}({:?})", sig.ret, sig.params)
}

fn push_callsite(
    callsites: &mut Vec<CallsiteInfo>,
    noloc_ord: &mut BTreeMap<(String, String), u32>,
    caller_id: FuncId,
    caller: &str,
    kind: CallKind,
    loc: &Option<pangs_pir::Loc>,
) -> CallsiteId {
    let id = CallsiteId(callsites.len() as u32);
    // The callsite-key ordinal MUST match pag's `add_callsite` scheme: a single
    // per-caller counter incremented for every call in body order, regardless of whether
    // the call has a source location. Keying the ordinal per-distinct-loc (as this used
    // to) silently diverges from pag whenever a function has ≥2 calls at different lines —
    // the solver emits `…:9:5#1` while this table held `…:9:5#0`, so the export-time
    // `callsite_by_key` lookup misses and that icall's resolved targets are dropped
    // (a soundness false negative). See ju_steens_overmerge_bug.md.
    let ord = next_noloc(noloc_ord, caller, "call");
    let (key, loc_info, synthetic) = if let Some(loc) = loc {
        (
            format!("{}@{}:{}:{}#{}", caller, loc.file, loc.line, loc.col, ord),
            Some(LocInfo {
                file: loc.file.clone(),
                line: loc.line,
                col: loc.col,
            }),
            false,
        )
    } else {
        (format!("{}@!noloc#{}", caller, ord), None, true)
    };
    callsites.push(CallsiteInfo {
        key,
        caller: caller_id,
        kind,
        loc: loc_info,
        synthetic,
    });
    id
}

fn witness_key(
    func: &str,
    loc: &Option<pangs_pir::Loc>,
    noloc_ord: &mut BTreeMap<(String, String), u32>,
    kind: &str,
) -> Option<String> {
    Some(if let Some(loc) = loc {
        format!("{}@{}:{}:{}#0", func, loc.file, loc.line, loc.col)
    } else {
        format!("{}@!noloc#{}", func, next_noloc(noloc_ord, func, kind))
    })
}

fn next_noloc(noloc_ord: &mut BTreeMap<(String, String), u32>, func: &str, kind: &str) -> u32 {
    let entry = noloc_ord
        .entry((func.to_string(), kind.to_string()))
        .or_default();
    let value = *entry;
    *entry += 1;
    value
}

fn edge_sort_key(
    edge: &CallEdge,
    funcs: &[FuncInfo],
    callsites: &[CallsiteInfo],
) -> (String, String, String, String) {
    (
        caller_key(&edge.caller, funcs),
        edge.callsite
            .map(|id| callsites[id.0 as usize].key.clone())
            .unwrap_or_default(),
        callee_key(&edge.callee, funcs),
        format!("{:?}{:?}", edge.kind, edge.tier),
    )
}

fn detect_direct_call_audits(
    findings: &mut Vec<Finding>,
    audit_taints: &mut BTreeMap<FuncId, Vec<Taint>>,
    module: &Pir,
    caller: FuncId,
    callee: &str,
    stmt: &Stmt,
    loc: &Option<pangs_pir::Loc>,
    callsite_key: &str,
) {
    if let Some(kind) = direct_boundary_kind(callee) {
        push_audit_finding(
            findings,
            audit_taints,
            caller,
            kind,
            loc,
            vec![format!("callsite:{callsite_key}")],
            Some(callsite_key.to_string()),
        );
    }
    if let Stmt::CallDirect { sig, args, .. } = stmt {
        detect_vararg_fnptr_audit(
            findings,
            audit_taints,
            module,
            caller,
            sig,
            args,
            loc,
            callsite_key,
        );
    }
}

fn detect_indirect_call_audits(
    findings: &mut Vec<Finding>,
    audit_taints: &mut BTreeMap<FuncId, Vec<Taint>>,
    module: &Pir,
    caller: FuncId,
    stmt: &Stmt,
    sig: &pangs_pir::Signature,
    loc: &Option<pangs_pir::Loc>,
    callsite_key: &str,
) {
    if let Stmt::CallIndirect { args, .. } = stmt {
        detect_vararg_fnptr_audit(
            findings,
            audit_taints,
            module,
            caller,
            sig,
            args,
            loc,
            callsite_key,
        );
    }
}

fn detect_vararg_fnptr_audit(
    findings: &mut Vec<Finding>,
    audit_taints: &mut BTreeMap<FuncId, Vec<Taint>>,
    module: &Pir,
    caller: FuncId,
    sig: &pangs_pir::Signature,
    args: &[String],
    loc: &Option<pangs_pir::Loc>,
    callsite_key: &str,
) {
    if !sig.vararg {
        return;
    }
    let fixed = sig.params.len();
    let mut affected = args
        .iter()
        .skip(fixed)
        .filter(|arg| module.functions.iter().any(|func| func.key == **arg))
        .map(|arg| format!("function:{arg}"))
        .collect::<Vec<_>>();
    affected.sort();
    affected.dedup();
    if affected.is_empty() {
        return;
    }
    push_audit_finding(
        findings,
        audit_taints,
        caller,
        "fnptr_varargs",
        loc,
        affected,
        Some(callsite_key.to_string()),
    );
}

fn detect_memory_aggregate_audits(
    findings: &mut Vec<Finding>,
    audit_taints: &mut BTreeMap<FuncId, Vec<Taint>>,
    noloc_ord: &mut BTreeMap<(String, String), u32>,
    caller: FuncId,
    owner: &str,
    kind: &str,
    loc: &Option<pangs_pir::Loc>,
    values: Vec<String>,
) {
    if values.is_empty() {
        return;
    }
    let mut affected = values
        .into_iter()
        .map(|value| format!("value:{value}"))
        .collect::<Vec<_>>();
    affected.sort();
    affected.dedup();
    let witness = witness_key(owner, loc, noloc_ord, "audit");
    push_audit_finding(findings, audit_taints, caller, kind, loc, affected, witness);
}

fn record_vararg_deferred_audit(
    deferred: &mut Vec<DeferredAudit>,
    caller: FuncId,
    owner: &str,
    stmt: &Stmt,
    sig: &pangs_pir::Signature,
    loc: &Option<pangs_pir::Loc>,
    callsite_key: &str,
) {
    if !sig.vararg {
        return;
    }
    let args = match stmt {
        Stmt::CallDirect { args, .. } | Stmt::CallIndirect { args, .. } => args,
        _ => return,
    };
    let values = args
        .iter()
        .skip(sig.params.len())
        .cloned()
        .collect::<Vec<_>>();
    if values.is_empty() {
        return;
    }
    deferred.push(DeferredAudit::VarargFnPtr {
        caller,
        owner: owner.to_string(),
        values,
        loc: loc.clone(),
        witness: callsite_key.to_string(),
    });
}

fn direct_boundary_kind(callee: &str) -> Option<&'static str> {
    match callee {
        "dlopen" | "dlsym" => Some("dlopen_dlsym"),
        "setjmp" | "longjmp" => Some("setjmp_longjmp"),
        _ => None,
    }
}

fn audit_affected_values(func: &str, operands: &[String], results: &[String]) -> Vec<String> {
    let mut affected = operands
        .iter()
        .map(|operand| format!("value:{operand}"))
        .chain(results.iter().map(|result| format!("value:{result}")))
        .collect::<Vec<_>>();
    if affected.is_empty() {
        affected.push(format!("function:{func}"));
    }
    affected.sort();
    affected.dedup();
    affected
}

fn is_fnptr_aggregate_type(ty: &str) -> bool {
    let aggregate = ty.contains('{') || ty.contains('[');
    aggregate && ty.contains(")*")
}

fn push_audit_finding(
    findings: &mut Vec<Finding>,
    audit_taints: &mut BTreeMap<FuncId, Vec<Taint>>,
    caller: FuncId,
    kind: &str,
    loc: &Option<pangs_pir::Loc>,
    affected: Vec<String>,
    witness: Option<String>,
) {
    findings.push(Finding {
        kind: kind.to_string(),
        file: loc.as_ref().map(|loc| loc.file.clone()),
        line: loc.as_ref().map(|loc| loc.line),
        affected,
        effect: "omega_taint".to_string(),
    });
    audit_taints.entry(caller).or_default().push(Taint {
        kind: kind.to_string(),
        witness,
    });
}

fn modref_sort_key(
    mr: &ModRef,
    funcs: &[FuncInfo],
    globals: &[GlobalInfo],
) -> (String, String, String, String, String) {
    (
        funcs[mr.func.0 as usize].key.clone(),
        match mr.global {
            GlobalTarget::Name(id) => globals[id.0 as usize].key.clone(),
            GlobalTarget::Unknown(ref reason) => reason.clone(),
        },
        format!("{:?}", mr.access),
        format!("{:?}", mr.via),
        mr.witness.clone().unwrap_or_default(),
    )
}

fn push_pointer_modrefs_from_pag(
    modrefs: &mut Vec<ModRef>,
    func_lookup: &HashMap<String, FuncId>,
    global_lookup: &HashMap<String, GlobalId>,
    pag: &Pag,
    nodes: &BTreeMap<String, NodeResolution>,
    noloc_ord: &mut BTreeMap<(String, String), u32>,
) {
    for edge in &pag.edges {
        let Some((owner, func, accesses)) = edge_accesses(edge, func_lookup) else {
            continue;
        };
        let witness = witness_key(&owner, &edge.loc, noloc_ord, "global");
        for (access, address_node, unknown_reason, suppress_direct_symbol) in accesses {
            let Some(node) = pag.nodes.get(address_node.0 as usize) else {
                continue;
            };
            let Some(resolution) = nodes.get(&node.label) else {
                continue;
            };

            for global_key in &resolution.pointee_globals {
                if suppress_direct_symbol && node.label == format!("sym:global:{global_key}") {
                    continue;
                }
                let Some(&gid) = global_lookup.get(global_key) else {
                    continue;
                };
                modrefs.push(ModRef {
                    func,
                    global: GlobalTarget::Name(gid),
                    access,
                    via: Via::Aliased,
                    witness: witness.clone(),
                });
            }

            if resolution.external {
                modrefs.push(ModRef {
                    func,
                    global: GlobalTarget::Unknown(unknown_reason.to_string()),
                    access,
                    via: Via::Unknown,
                    witness: witness.clone(),
                });
            }
        }
    }
}

fn push_pointer_memset_modrefs_from_pir(
    modrefs: &mut Vec<ModRef>,
    module: &Pir,
    func_lookup: &HashMap<String, FuncId>,
    global_lookup: &HashMap<String, GlobalId>,
    nodes: &BTreeMap<String, NodeResolution>,
    noloc_ord: &mut BTreeMap<(String, String), u32>,
) {
    for func in &module.functions {
        let Some(&func_id) = func_lookup.get(&func.key) else {
            continue;
        };
        for stmt in &func.body {
            let Stmt::Memset { dst, loc, .. } = stmt else {
                continue;
            };
            if let Some(&gid) = global_lookup.get(dst) {
                modrefs.push(ModRef {
                    func: func_id,
                    global: GlobalTarget::Name(gid),
                    access: Access::Mod,
                    via: Via::Aliased,
                    witness: witness_key(&func.key, loc, noloc_ord, "global"),
                });
                continue;
            }
            let label = pag_value_label(module, &func.key, dst);
            let Some(resolution) = nodes.get(&label) else {
                continue;
            };
            let witness = witness_key(&func.key, loc, noloc_ord, "global");
            for global_key in &resolution.pointee_globals {
                let Some(&gid) = global_lookup.get(global_key) else {
                    continue;
                };
                modrefs.push(ModRef {
                    func: func_id,
                    global: GlobalTarget::Name(gid),
                    access: Access::Mod,
                    via: Via::Aliased,
                    witness: witness.clone(),
                });
            }
            if resolution.external {
                modrefs.push(ModRef {
                    func: func_id,
                    global: GlobalTarget::Unknown("omega_store".to_string()),
                    access: Access::Mod,
                    via: Via::Unknown,
                    witness,
                });
            }
        }
    }
}

fn edge_accesses(
    edge: &Edge,
    func_lookup: &HashMap<String, FuncId>,
) -> Option<(
    String,
    FuncId,
    Vec<(Access, pangs_pag::NodeId, &'static str, bool)>,
)> {
    let Owner::Function(owner) = &edge.owner else {
        return None;
    };
    let &func = func_lookup.get(owner)?;
    match edge.kind {
        EdgeKind::Load => Some((
            owner.clone(),
            func,
            vec![(Access::Ref, edge.src, "omega_load", true)],
        )),
        EdgeKind::Store => Some((
            owner.clone(),
            func,
            vec![(Access::Mod, edge.dst, "omega_store", true)],
        )),
        EdgeKind::Memcpy { .. } => Some((
            owner.clone(),
            func,
            vec![
                (Access::Ref, edge.src, "omega_load", false),
                (Access::Mod, edge.dst, "omega_store", false),
            ],
        )),
        _ => None,
    }
}

fn caller_key(caller: &Caller, funcs: &[FuncInfo]) -> String {
    match caller {
        Caller::Func(id) => funcs[id.0 as usize].key.clone(),
        Caller::Unknown(reason) => format!("unknown:{reason}"),
    }
}

fn callee_key(callee: &Callee, funcs: &[FuncInfo]) -> String {
    match callee {
        Callee::Func(id) => funcs[id.0 as usize].key.clone(),
        Callee::Unknown(reason) => format!("unknown:{reason}"),
    }
}

fn compute_components(
    funcs: &[FuncInfo],
    globals: &[GlobalInfo],
    callsites: &[CallsiteInfo],
    edges: &[CallEdge],
    modrefs: &[ModRef],
    audit_taints: &BTreeMap<FuncId, Vec<Taint>>,
) -> Vec<ComponentInfo> {
    let mut parent: Vec<usize> = (0..funcs.len()).collect();
    for edge in edges {
        if let (Caller::Func(a), Callee::Func(b)) = (&edge.caller, &edge.callee) {
            union(&mut parent, a.0 as usize, b.0 as usize);
        }
    }

    let mut by_root: BTreeMap<usize, Vec<FuncId>> = BTreeMap::new();
    for idx in 0..funcs.len() {
        let root = find(&mut parent, idx);
        by_root.entry(root).or_default().push(FuncId(idx as u32));
    }

    let mut components: Vec<_> = by_root
        .into_values()
        .map(|mut members| {
            members.sort_by_key(|id| funcs[id.0 as usize].key.clone());
            members
        })
        .collect();
    components.sort_by_key(|members| funcs[members[0].0 as usize].key.clone());

    let mut modrefs_by_func = vec![Vec::<&ModRef>::new(); funcs.len()];
    for mr in modrefs {
        modrefs_by_func[mr.func.0 as usize].push(mr);
    }
    let mut unknown_callee_witnesses = vec![Vec::<Option<String>>::new(); funcs.len()];
    let mut unknown_caller = vec![false; funcs.len()];
    for edge in edges {
        if matches!(edge.callee, Callee::Unknown(_)) {
            if let Caller::Func(fid) = edge.caller {
                unknown_callee_witnesses[fid.0 as usize]
                    .push(edge.callsite.map(|id| callsites[id.0 as usize].key.clone()));
            }
        }
        if matches!(edge.caller, Caller::Unknown(_)) {
            if let Callee::Func(fid) = edge.callee {
                unknown_caller[fid.0 as usize] = true;
            }
        }
    }

    components
        .into_iter()
        .enumerate()
        .map(|(idx, members)| {
            let mut mutable_globals = BTreeSet::new();
            let mut taint = Vec::new();
            for member in &members {
                for mr in &modrefs_by_func[member.0 as usize] {
                    if let GlobalTarget::Name(gid) = mr.global {
                        if globals[gid.0 as usize].mutable {
                            mutable_globals.insert(gid);
                        }
                    }
                    if matches!(mr.global, GlobalTarget::Unknown(_)) {
                        taint.push(Taint {
                            kind: "unknown_global".to_string(),
                            witness: mr.witness.clone(),
                        });
                    }
                }
                for witness in &unknown_callee_witnesses[member.0 as usize] {
                    taint.push(Taint {
                        kind: "unknown_callee".to_string(),
                        witness: witness.clone(),
                    });
                }
                if unknown_caller[member.0 as usize] {
                    taint.push(Taint {
                        kind: "unknown_caller".to_string(),
                        witness: None,
                    });
                }
                if let Some(member_taints) = audit_taints.get(member) {
                    taint.extend(member_taints.iter().cloned());
                }
            }
            taint.sort_by_key(|t| (t.kind.clone(), t.witness.clone()));
            taint.dedup_by_key(|t| (t.kind.clone(), t.witness.clone()));
            ComponentInfo {
                id: format!("c{:04}", idx + 1),
                frozen: !taint.is_empty(),
                taint,
                members,
                mutable_globals: mutable_globals.into_iter().collect(),
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ModRefPayload {
    global: GlobalTarget,
    access: Access,
    via: Via,
    witness: Option<String>,
}

impl PartialOrd for ModRefPayload {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ModRefPayload {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.global.cmp(&other.global) {
            Ordering::Equal => {}
            order => return order,
        }
        match access_rank(self.access).cmp(&access_rank(other.access)) {
            Ordering::Equal => {}
            order => return order,
        }
        match via_rank(self.via).cmp(&via_rank(other.via)) {
            Ordering::Equal => {}
            order => return order,
        }
        self.witness.cmp(&other.witness)
    }
}

fn access_rank(access: Access) -> u8 {
    match access {
        Access::Ref => 0,
        Access::Mod => 1,
    }
}

fn via_rank(via: Via) -> u8 {
    match via {
        Via::Direct => 0,
        Via::Aliased => 1,
        Via::Unknown => 2,
    }
}

fn compute_transitive_modrefs(
    func_count: usize,
    funcs: &[FuncInfo],
    globals: &[GlobalInfo],
    edges: &[CallEdge],
    local_modrefs: &[ModRef],
) -> Vec<Vec<ModRef>> {
    let mut callees_by_func = vec![Vec::<usize>::new(); func_count];
    for edge in edges {
        if let (Caller::Func(caller), Callee::Func(callee)) = (&edge.caller, &edge.callee) {
            callees_by_func[caller.0 as usize].push(callee.0 as usize);
        }
    }
    for callees in &mut callees_by_func {
        callees.sort_unstable();
        callees.dedup();
    }

    let (scc_members, scc_of_func) = strongly_connected_components(&callees_by_func);
    let mut payload_ids = BTreeMap::<ModRefPayload, usize>::new();
    let mut payloads = Vec::<ModRefPayload>::new();
    let mut local_by_scc = vec![Vec::<usize>::new(); scc_members.len()];
    for mr in local_modrefs {
        let payload = ModRefPayload {
            global: mr.global.clone(),
            access: mr.access,
            via: mr.via,
            witness: mr.witness.clone(),
        };
        let id = if let Some(&id) = payload_ids.get(&payload) {
            id
        } else {
            let id = payloads.len();
            payload_ids.insert(payload.clone(), id);
            payloads.push(payload);
            id
        };
        local_by_scc[scc_of_func[mr.func.0 as usize]].push(id);
    }
    for rows in &mut local_by_scc {
        rows.sort_unstable();
        rows.dedup();
    }

    let mut scc_succs = vec![Vec::<usize>::new(); scc_members.len()];
    for (func, callees) in callees_by_func.iter().enumerate() {
        let from = scc_of_func[func];
        for &callee in callees {
            let to = scc_of_func[callee];
            if from != to {
                scc_succs[from].push(to);
            }
        }
    }
    for succs in &mut scc_succs {
        succs.sort_unstable();
        succs.dedup();
    }

    let mut memo = vec![None::<Vec<usize>>; scc_members.len()];
    for scc in 0..scc_members.len() {
        collect_scc_payload_ids(scc, &local_by_scc, &scc_succs, &mut memo);
    }

    let mut transitive = Vec::with_capacity(func_count);
    for root_idx in 0..func_count {
        let root = FuncId(root_idx as u32);
        let mut rows = memo[scc_of_func[root_idx]]
            .as_ref()
            .unwrap()
            .iter()
            .map(|&payload_id| {
                let payload = &payloads[payload_id];
                ModRef {
                    func: root,
                    global: payload.global.clone(),
                    access: payload.access,
                    via: payload.via,
                    witness: payload.witness.clone(),
                }
            })
            .collect::<Vec<_>>();
        rows.sort_by_key(|mr| modref_sort_key(mr, funcs, globals));
        transitive.push(rows);
    }
    transitive
}

fn collect_scc_payload_ids(
    scc: usize,
    local_by_scc: &[Vec<usize>],
    scc_succs: &[Vec<usize>],
    memo: &mut [Option<Vec<usize>>],
) -> Vec<usize> {
    if let Some(existing) = &memo[scc] {
        return existing.clone();
    }
    let mut rows = local_by_scc[scc].clone();
    for &succ in &scc_succs[scc] {
        let succ_rows = collect_scc_payload_ids(succ, local_by_scc, scc_succs, memo);
        rows = merge_sorted_unique(rows, succ_rows);
    }
    rows.dedup();
    memo[scc] = Some(rows.clone());
    rows
}

fn merge_sorted_unique(left: Vec<usize>, right: Vec<usize>) -> Vec<usize> {
    let mut merged = Vec::with_capacity(left.len() + right.len());
    let mut i = 0;
    let mut j = 0;
    while i < left.len() && j < right.len() {
        match left[i].cmp(&right[j]) {
            Ordering::Less => {
                merged.push(left[i]);
                i += 1;
            }
            Ordering::Greater => {
                merged.push(right[j]);
                j += 1;
            }
            Ordering::Equal => {
                merged.push(left[i]);
                i += 1;
                j += 1;
            }
        }
    }
    merged.extend_from_slice(&left[i..]);
    merged.extend_from_slice(&right[j..]);
    merged
}

fn strongly_connected_components(edges: &[Vec<usize>]) -> (Vec<Vec<usize>>, Vec<usize>) {
    struct Tarjan<'a> {
        edges: &'a [Vec<usize>],
        index: usize,
        indices: Vec<Option<usize>>,
        lowlink: Vec<usize>,
        stack: Vec<usize>,
        on_stack: Vec<bool>,
        members: Vec<Vec<usize>>,
        scc_of: Vec<usize>,
    }

    impl<'a> Tarjan<'a> {
        fn new(edges: &'a [Vec<usize>]) -> Self {
            Self {
                edges,
                index: 0,
                indices: vec![None; edges.len()],
                lowlink: vec![0; edges.len()],
                stack: Vec::new(),
                on_stack: vec![false; edges.len()],
                members: Vec::new(),
                scc_of: vec![0; edges.len()],
            }
        }

        fn visit(&mut self, node: usize) {
            self.indices[node] = Some(self.index);
            self.lowlink[node] = self.index;
            self.index += 1;
            self.stack.push(node);
            self.on_stack[node] = true;

            for &succ in &self.edges[node] {
                if self.indices[succ].is_none() {
                    self.visit(succ);
                    self.lowlink[node] = self.lowlink[node].min(self.lowlink[succ]);
                } else if self.on_stack[succ] {
                    self.lowlink[node] = self.lowlink[node].min(self.indices[succ].unwrap());
                }
            }

            if self.lowlink[node] == self.indices[node].unwrap() {
                let mut component = Vec::new();
                while let Some(top) = self.stack.pop() {
                    self.on_stack[top] = false;
                    self.scc_of[top] = self.members.len();
                    component.push(top);
                    if top == node {
                        break;
                    }
                }
                component.sort_unstable();
                self.members.push(component);
            }
        }
    }

    let mut tarjan = Tarjan::new(edges);
    for node in 0..edges.len() {
        if tarjan.indices[node].is_none() {
            tarjan.visit(node);
        }
    }
    (tarjan.members, tarjan.scc_of)
}

fn union(parent: &mut [usize], a: usize, b: usize) {
    let ra = find(parent, a);
    let rb = find(parent, b);
    if ra != rb {
        parent[rb] = ra;
    }
}

fn find(parent: &mut [usize], x: usize) -> usize {
    if parent[x] != x {
        parent[x] = find(parent, parent[x]);
    }
    parent[x]
}
