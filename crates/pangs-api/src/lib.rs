use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Instant;

use pangs_pag::{BuildMode as PagBuildMode, Edge, EdgeKind, Owner, Pag, PagOpts};
use pangs_pir::{fsa_compatible, Access, LoweringStats, Pir, Stmt};
use pangs_solve::{
    debug_assert_narrows, solve_andersen_with_overrides, solve_steensgaard, IndirectCallResolution,
    NodeResolution,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod differential;
mod initval;
mod simple;
pub use differential::{run_differential, DifferentialReport};
use initval::resolve_initval_icalls;
use simple::{
    resolve_simple_icalls, SimpleIcallQuery, SimpleIcallResolution, DEFAULT_CONTEXT_DEPTH,
};

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
    pub enable_b1_initval: bool,
    pub enable_b2_simple: bool,
    pub enable_b3_confined: bool,
    pub b2_context_depth: usize,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            stage: Stage::Conservative,
            build_mode: BuildMode::Library,
            exports: BTreeSet::new(),
            partition_budget: 1_000,
            enable_b1_initval: true,
            enable_b2_simple: true,
            enable_b3_confined: true,
            b2_context_depth: DEFAULT_CONTEXT_DEPTH,
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
    pub stationary: bool,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_node: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pointee_globals: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StationarityVerdict {
    pub global: GlobalId,
    pub complete_initval: bool,
    pub stationary: bool,
    pub reason: StationarityReason,
    pub runtime_writers: Vec<StationarityWriter>,
    pub initval_diagnostics: Vec<InitValDiagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StationarityReason {
    Stationary,
    ConservativeStage,
    IncompleteInitval,
    ExportedGlobal,
    RuntimeWriter,
    UnknownRuntimeWriter,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StationarityWriter {
    pub func: Option<FuncId>,
    pub global: GlobalTarget,
    pub access: Access,
    pub via: Via,
    pub witness: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitValDiagnostic {
    pub reason: String,
    pub witness: Option<String>,
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
    pub oversize_fallback_max_size: usize,
    pub rounds: usize,
    #[serde(default)]
    pub steens_worklist_pops: u64,
    #[serde(default)]
    pub steens_process_class_calls: u64,
    #[serde(default)]
    pub steens_candidate_pairs: u64,
    #[serde(default)]
    pub steens_seen_pairs_new: u64,
    #[serde(default)]
    pub steens_seen_pairs_duplicate: u64,
    #[serde(default)]
    pub steens_fsa_compatible_pairs: u64,
    #[serde(default)]
    pub steens_fsa_rejected_pairs: u64,
    #[serde(default)]
    pub steens_indirect_bindings: u64,
    #[serde(default)]
    pub steens_external_call_requests: u64,
    #[serde(default)]
    pub steens_external_call_applications: u64,
    #[serde(default)]
    pub steens_escaped_function_applications: u64,
    #[serde(default)]
    pub steens_join_attempts: u64,
    #[serde(default)]
    pub steens_join_successes: u64,
    #[serde(default)]
    pub steens_pointee_classes_created: u64,
    #[serde(default)]
    pub steens_max_class_icall_sites: usize,
    #[serde(default)]
    pub steens_max_class_fn_objs: usize,
    #[serde(default)]
    pub steens_max_class_candidate_pairs: u64,
    #[serde(default)]
    pub pointer_modref_rows_attempted: u64,
    #[serde(default)]
    pub pointer_modref_rows_unique: u64,
    #[serde(default)]
    pub pointer_modref_rows_duplicate: u64,
    #[serde(default)]
    pub pointer_modref_pag_rows_attempted: u64,
    #[serde(default)]
    pub pointer_modref_pag_rows_unique: u64,
    #[serde(default)]
    pub pointer_modref_pag_rows_duplicate: u64,
    #[serde(default)]
    pub pointer_modref_mem_rows_attempted: u64,
    #[serde(default)]
    pub pointer_modref_mem_rows_unique: u64,
    #[serde(default)]
    pub pointer_modref_mem_rows_duplicate: u64,
    #[serde(default)]
    pub pointer_modref_closure_rows_attempted: u64,
    #[serde(default)]
    pub pointer_modref_closure_rows_unique: u64,
    #[serde(default)]
    pub pointer_modref_closure_rows_duplicate: u64,
    #[serde(default)]
    pub pointer_modref_max_fact_fanout: u64,
    #[serde(default)]
    pub pointer_modref_pag_max_fact_fanout: u64,
    #[serde(default)]
    pub pointer_modref_mem_max_fact_fanout: u64,
    #[serde(default)]
    pub pointer_modref_closure_max_fact_fanout: u64,
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
    pub setup_scan_us: u64,
    pub preanalysis_us: u64,
    pub pag_build_us: u64,
    pub solve_us: u64,
    pub solver_postprocess_us: u64,
    pub pointer_modref_us: u64,
    pub callgraph_dedup_us: u64,
    pub modref_dedup_us: u64,
    pub stationarity_us: u64,
    pub initval_reapply_us: u64,
    pub transitive_modref_us: u64,
    pub findings_dedup_us: u64,
    pub components_us: u64,
    pub metrics_bookkeeping_us: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lowering: Option<LoweringStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct M2AblationReport {
    pub variants: Vec<M2AblationVariant>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct M2AblationVariant {
    pub mode: M2AblationMode,
    pub icalls_simple: usize,
    pub icalls_andersen: usize,
    pub icalls_steens: usize,
    pub icalls_fsa: usize,
    pub icalls_unknown: usize,
    pub confined_functions: usize,
    pub globals_with_complete_initval: usize,
    pub stationary_globals: usize,
    pub oversize_fallbacks: usize,
    pub oversize_fallback_max_size: usize,
    pub mutable_globals_total: usize,
    pub in_rewritable_components: usize,
    pub call_edges: usize,
    pub analysis_wall_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M2AblationMode {
    M1Baseline,
    B2Only,
    B1Only,
    Both,
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
        kind: String,
        detail: Option<String>,
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
    stationarity: Vec<StationarityVerdict>,
    #[serde(skip)]
    transitive_modrefs: TransitiveModRefs,
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
        let setup_scan_started = Instant::now();
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
                stationary: false,
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
        let mut modrefs = ModRefBuilder::new();
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
                            if let Some(kind) = direct_vararg_audit_kind(module, callee) {
                                record_vararg_deferred_audit(
                                    &mut deferred_audits,
                                    caller,
                                    &func.key,
                                    kind,
                                    Some(format!("callee:{callee}")),
                                    stmt,
                                    sig,
                                    loc,
                                    &callsite_key,
                                );
                            }
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
                        if opts.stage == Stage::Conservative {
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
                        }
                        record_vararg_deferred_audit(
                            &mut deferred_audits,
                            caller,
                            &func.key,
                            "fnptr_varargs_indirect",
                            Some("callee:<indirect>".to_string()),
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
                                detail: None,
                                address_node: None,
                                pointee_globals: Vec::new(),
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
        let setup_scan_us = setup_scan_started.elapsed().as_micros() as u64;
        let preanalysis_started = Instant::now();
        let mut simple_report = if opts.enable_b2_simple {
            resolve_simple_icalls(module, &simple_icall_queries, opts.b2_context_depth)
        } else {
            Default::default()
        };
        if !opts.enable_b3_confined {
            simple_report.confined_functions.clear();
        }
        let initval_report = if opts.enable_b1_initval {
            resolve_initval_icalls(module, &simple_icall_queries, &BTreeSet::new())
        } else {
            Default::default()
        };
        let simple_icalls = &simple_report.resolutions;
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
        let preanalysis_us = preanalysis_started.elapsed().as_micros() as u64;

        let mut solver_postprocess_us = 0;
        let mut pointer_modref_us = 0;
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
                let indirect_vararg_keys = indirect_callsites
                    .iter()
                    .filter_map(|(cs, _, sig)| {
                        sig.vararg.then(|| callsites[cs.0 as usize].key.clone())
                    })
                    .collect::<BTreeSet<_>>();
                let mut pag = Pag::from_pir(
                    module,
                    &PagOpts {
                        build_mode: opts.build_mode.into(),
                        exports: opts.exports.clone(),
                        ..PagOpts::default()
                    },
                );
                pag_build_us = pag_started.elapsed().as_micros() as u64;
                let solve_started = Instant::now();
                let mut solved = match opts.stage {
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
                let safe_indirect_varargs =
                    safe_indirect_vararg_callsites(module, &indirect_vararg_keys, &solved);
                if !safe_indirect_varargs.is_empty() {
                    let pag_started = Instant::now();
                    pag = Pag::from_pir(
                        module,
                        &PagOpts {
                            build_mode: opts.build_mode.into(),
                            exports: opts.exports.clone(),
                            safe_indirect_vararg_callsites: safe_indirect_varargs.clone(),
                        },
                    );
                    pag_build_us += pag_started.elapsed().as_micros() as u64;
                    let solve_started = Instant::now();
                    solved = match opts.stage {
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
                    solve_us += solve_started.elapsed().as_micros() as u64;
                }
                let safe_indirect_varargs =
                    safe_indirect_vararg_callsites(module, &indirect_vararg_keys, &solved);
                solver_metrics = Some(solved.metrics.clone());
                let solver_postprocess_started = Instant::now();
                emit_deferred_steens_audits(
                    &mut findings,
                    &mut audit_taints,
                    module,
                    &solved.nodes,
                    deferred_audits,
                    &safe_indirect_varargs,
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
                solver_postprocess_us = solver_postprocess_started.elapsed().as_micros() as u64;

                let pointer_modref_started = Instant::now();
                modrefs.print_profile("local-start");
                push_pointer_modrefs_from_pag(
                    &mut modrefs,
                    &func_lookup,
                    &global_lookup,
                    &pag,
                    &solved.nodes,
                    &mut noloc_ord,
                );
                modrefs.print_profile("after-pag");
                push_pointer_memset_modrefs_from_pir(
                    &mut modrefs,
                    module,
                    &func_lookup,
                    &global_lookup,
                    &solved.nodes,
                    &mut noloc_ord,
                );
                modrefs.print_profile("after-mem");
                pointer_modref_us = pointer_modref_started.elapsed().as_micros() as u64;
            }
        }

        let callgraph_dedup_started = Instant::now();
        call_edges.sort_by_key(|edge| edge_sort_key(edge, &functions, &callsites));
        call_edges.dedup_by_key(|edge| edge_sort_key(edge, &functions, &callsites));
        let callgraph_dedup_us = callgraph_dedup_started.elapsed().as_micros() as u64;
        let modref_dedup_started = Instant::now();
        let mut pointer_modref_metrics = modrefs.metrics();
        let modrefs = modrefs.into_vec();
        let modref_dedup_us = modref_dedup_started.elapsed().as_micros() as u64;

        let stationarity_started = Instant::now();
        let (stationary_globals, stationarity) = if opts.stage == Stage::Conservative {
            conservative_stationarity_verdicts(module, &global_lookup)
        } else {
            stationarity_verdicts_from_modrefs(
                module,
                &globals,
                &initval_report.complete_globals,
                &initval_report.diagnostics,
                &global_lookup,
                &modrefs,
            )
        };
        let stationarity_us = stationarity_started.elapsed().as_micros() as u64;
        let initval_reapply_started = Instant::now();
        let initval_report = if opts.enable_b1_initval {
            resolve_initval_icalls(module, &simple_icall_queries, &stationary_globals)
        } else {
            Default::default()
        };
        for global in &mut globals {
            global.stationary = initval_report.stationary_globals.contains(&global.key);
        }
        apply_initval_exact_call_edges(
            &mut call_edges,
            module,
            &func_lookup,
            &address_taken,
            &callsites,
            &simple_queries,
            simple_icalls,
            &initval_report.resolutions,
        );
        let initval_reapply_us = initval_reapply_started.elapsed().as_micros() as u64;

        let transitive_started = Instant::now();
        let (transitive_modrefs, closure_modref_metrics) = compute_transitive_modrefs(
            functions.len(),
            &functions,
            &globals,
            &call_edges,
            &modrefs,
        );
        let transitive_modref_us = transitive_started.elapsed().as_micros() as u64;
        pointer_modref_metrics.merge_closure(closure_modref_metrics);
        let findings_dedup_started = Instant::now();
        findings.sort_by_key(|finding| {
            (
                finding.kind.clone(),
                finding.file.clone(),
                finding.line.unwrap_or(0),
                finding.affected.join("|"),
                finding.detail.clone(),
            )
        });
        findings.dedup_by_key(|finding| {
            (
                finding.kind.clone(),
                finding.file.clone(),
                finding.line.unwrap_or(0),
                finding.affected.join("|"),
                finding.detail.clone(),
            )
        });
        let findings_dedup_us = findings_dedup_started.elapsed().as_micros() as u64;

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
        let mutable_globals_total = globals
            .iter()
            .filter(|g| g.mutable && !g.stationary)
            .count();
        let in_rewritable_components = components
            .iter()
            .filter(|c| !c.frozen)
            .flat_map(|c| c.mutable_globals.iter())
            .collect::<BTreeSet<_>>()
            .len();

        let metrics_bookkeeping_started = Instant::now();
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
            oversize_fallback_max_size: 0,
            rounds: 0,
            steens_worklist_pops: 0,
            steens_process_class_calls: 0,
            steens_candidate_pairs: 0,
            steens_seen_pairs_new: 0,
            steens_seen_pairs_duplicate: 0,
            steens_fsa_compatible_pairs: 0,
            steens_fsa_rejected_pairs: 0,
            steens_indirect_bindings: 0,
            steens_external_call_requests: 0,
            steens_external_call_applications: 0,
            steens_escaped_function_applications: 0,
            steens_join_attempts: 0,
            steens_join_successes: 0,
            steens_pointee_classes_created: 0,
            steens_max_class_icall_sites: 0,
            steens_max_class_fn_objs: 0,
            steens_max_class_candidate_pairs: 0,
            pointer_modref_rows_attempted: pointer_modref_metrics.attempted(),
            pointer_modref_rows_unique: pointer_modref_metrics.unique(),
            pointer_modref_rows_duplicate: pointer_modref_metrics.duplicate(),
            pointer_modref_pag_rows_attempted: pointer_modref_metrics.pag.attempted,
            pointer_modref_pag_rows_unique: pointer_modref_metrics.pag.unique,
            pointer_modref_pag_rows_duplicate: pointer_modref_metrics.pag.duplicate,
            pointer_modref_mem_rows_attempted: pointer_modref_metrics.mem.attempted,
            pointer_modref_mem_rows_unique: pointer_modref_metrics.mem.unique,
            pointer_modref_mem_rows_duplicate: pointer_modref_metrics.mem.duplicate,
            pointer_modref_closure_rows_attempted: pointer_modref_metrics.closure.attempted,
            pointer_modref_closure_rows_unique: pointer_modref_metrics.closure.unique,
            pointer_modref_closure_rows_duplicate: pointer_modref_metrics.closure.duplicate,
            pointer_modref_max_fact_fanout: pointer_modref_metrics.pointer_modref_max_fact_fanout,
            pointer_modref_pag_max_fact_fanout: pointer_modref_metrics.pag.max_fact_fanout,
            pointer_modref_mem_max_fact_fanout: pointer_modref_metrics.mem.max_fact_fanout,
            pointer_modref_closure_max_fact_fanout: pointer_modref_metrics.closure.max_fact_fanout,
            analysis_wall_us: 0,
            setup_scan_us,
            preanalysis_us,
            pag_build_us,
            solve_us,
            solver_postprocess_us,
            pointer_modref_us,
            callgraph_dedup_us,
            modref_dedup_us,
            stationarity_us,
            initval_reapply_us,
            transitive_modref_us,
            findings_dedup_us,
            components_us,
            metrics_bookkeeping_us: 0,
            lowering: (!module.lowering.is_empty()).then(|| module.lowering.clone()),
        };
        let metrics_bookkeeping_us = metrics_bookkeeping_started.elapsed().as_micros() as u64;

        let metrics = if let Some(solved) = solver_metrics {
            Metrics {
                partition_count: solved.partition_count,
                partition_p50_size: solved.partition_p50_size,
                partition_p95_size: solved.partition_p95_size,
                partition_max_size: solved.partition_max_size,
                oversize_fallbacks: solved.oversize_fallbacks,
                oversize_fallback_max_size: solved.oversize_fallback_max_size,
                rounds: solved.rounds,
                steens_worklist_pops: solved.steens_worklist_pops,
                steens_process_class_calls: solved.steens_process_class_calls,
                steens_candidate_pairs: solved.steens_candidate_pairs,
                steens_seen_pairs_new: solved.steens_seen_pairs_new,
                steens_seen_pairs_duplicate: solved.steens_seen_pairs_duplicate,
                steens_fsa_compatible_pairs: solved.steens_fsa_compatible_pairs,
                steens_fsa_rejected_pairs: solved.steens_fsa_rejected_pairs,
                steens_indirect_bindings: solved.steens_indirect_bindings,
                steens_external_call_requests: solved.steens_external_call_requests,
                steens_external_call_applications: solved.steens_external_call_applications,
                steens_escaped_function_applications: solved.steens_escaped_function_applications,
                steens_join_attempts: solved.steens_join_attempts,
                steens_join_successes: solved.steens_join_successes,
                steens_pointee_classes_created: solved.steens_pointee_classes_created,
                steens_max_class_icall_sites: solved.steens_max_class_icall_sites,
                steens_max_class_fn_objs: solved.steens_max_class_fn_objs,
                steens_max_class_candidate_pairs: solved.steens_max_class_candidate_pairs,
                ..metrics
            }
        } else {
            metrics
        };
        let metrics = Metrics {
            analysis_wall_us: analysis_started.elapsed().as_micros() as u64,
            metrics_bookkeeping_us,
            ..metrics
        };

        Ok(Self {
            functions: Table::new(functions),
            globals: Table::new(globals),
            callsites: Table::new(callsites),
            call_edges,
            modrefs,
            stationarity,
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

    pub fn stationarity_verdicts(&self) -> &[StationarityVerdict] {
        &self.stationarity
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

    pub fn modref(&self, func: FuncId) -> impl Iterator<Item = ModRef> + '_ {
        self.transitive_modrefs.iter(func)
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

pub fn run_m2_ablation(module: &Pir, base: &Opts) -> Result<M2AblationReport, AnalysisError> {
    let variants = [
        (M2AblationMode::M1Baseline, false, false, false),
        (M2AblationMode::B2Only, false, true, true),
        (M2AblationMode::B1Only, true, false, false),
        (M2AblationMode::Both, true, true, true),
    ];
    let mut rows = Vec::new();
    for (mode, enable_b1_initval, enable_b2_simple, enable_b3_confined) in variants {
        let opts = Opts {
            enable_b1_initval,
            enable_b2_simple,
            enable_b3_confined,
            ..base.clone()
        };
        let analysis = Analysis::run(module, &opts)?;
        rows.push(M2AblationVariant::from_metrics(mode, analysis.metrics()));
    }
    Ok(M2AblationReport { variants: rows })
}

impl M2AblationVariant {
    fn from_metrics(mode: M2AblationMode, metrics: &Metrics) -> Self {
        Self {
            mode,
            icalls_simple: metrics.icalls_simple,
            icalls_andersen: metrics.icalls_andersen,
            icalls_steens: metrics.icalls_steens,
            icalls_fsa: metrics.icalls_fsa,
            icalls_unknown: metrics.icalls_unknown,
            confined_functions: metrics.confined_functions,
            globals_with_complete_initval: metrics.globals_with_complete_initval,
            stationary_globals: metrics.stationary_globals,
            oversize_fallbacks: metrics.oversize_fallbacks,
            oversize_fallback_max_size: metrics.oversize_fallback_max_size,
            mutable_globals_total: metrics.mutable_globals_total,
            in_rewritable_components: metrics.in_rewritable_components,
            call_edges: metrics.call_edges,
            analysis_wall_us: metrics.analysis_wall_us,
        }
    }
}

fn emit_deferred_steens_audits(
    findings: &mut Vec<Finding>,
    audit_taints: &mut BTreeMap<FuncId, Vec<Taint>>,
    module: &Pir,
    node_summaries: &BTreeMap<String, NodeResolution>,
    deferred: Vec<DeferredAudit>,
    safe_indirect_varargs: &BTreeSet<String>,
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
                kind,
                detail,
                values,
                loc,
                witness,
            } => {
                if kind == "fnptr_varargs_indirect" && safe_indirect_varargs.contains(&witness) {
                    continue;
                }
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
                    push_audit_finding_with_detail(
                        findings,
                        audit_taints,
                        caller,
                        &kind,
                        &loc,
                        affected,
                        Some(witness),
                        detail,
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

fn conservative_stationarity_verdicts(
    module: &Pir,
    global_lookup: &HashMap<String, GlobalId>,
) -> (BTreeSet<String>, Vec<StationarityVerdict>) {
    let verdicts = module
        .globals
        .iter()
        .filter_map(|global| {
            global_lookup
                .get(&global.key)
                .copied()
                .map(|gid| StationarityVerdict {
                    global: gid,
                    complete_initval: false,
                    stationary: false,
                    reason: StationarityReason::ConservativeStage,
                    runtime_writers: Vec::new(),
                    initval_diagnostics: Vec::new(),
                })
        })
        .collect();
    (BTreeSet::new(), verdicts)
}

fn stationarity_verdicts_from_modrefs(
    module: &Pir,
    globals: &[GlobalInfo],
    complete_globals: &BTreeSet<String>,
    initval_diagnostics: &BTreeMap<String, Vec<InitValDiagnostic>>,
    global_lookup: &HashMap<String, GlobalId>,
    modrefs: &[ModRef],
) -> (BTreeSet<String>, Vec<StationarityVerdict>) {
    let mut runtime_writers = BTreeMap::<String, Vec<StationarityWriter>>::new();
    let mut unknown_writers = Vec::<StationarityWriter>::new();
    for mr in modrefs {
        if mr.access != Access::Mod {
            continue;
        }
        match &mr.global {
            GlobalTarget::Name(gid) => {
                let Some(global) = module.globals.get(gid.0 as usize) else {
                    continue;
                };
                runtime_writers
                    .entry(global.key.clone())
                    .or_default()
                    .push(stationarity_writer_from_modref(mr));
            }
            GlobalTarget::Unknown(_) => unknown_writers.push(stationarity_writer_from_modref(mr)),
        }
    }
    for writers in runtime_writers.values_mut() {
        writers.sort_by(stationarity_writer_cmp);
        writers.dedup_by(|left, right| stationarity_writer_cmp(left, right) == Ordering::Equal);
    }
    unknown_writers.sort_by(stationarity_writer_cmp);
    unknown_writers.dedup_by(|left, right| stationarity_writer_cmp(left, right) == Ordering::Equal);

    let mut stationary_globals = BTreeSet::new();
    let mut verdicts = Vec::new();
    for global in &module.globals {
        let Some(&gid) = global_lookup.get(&global.key) else {
            continue;
        };
        let global_info = &globals[gid.0 as usize];
        let complete_initval = complete_globals.contains(&global.key);
        let mut initval_diagnostics = if complete_initval || !global_info.mutable {
            Vec::new()
        } else {
            initval_diagnostics
                .get(&global.key)
                .cloned()
                .filter(|diagnostics| !diagnostics.is_empty())
                .unwrap_or_else(|| {
                    vec![InitValDiagnostic {
                        reason: "no_modeled_pointer_initializer".to_string(),
                        witness: None,
                    }]
                })
        };
        initval_diagnostics.sort_by(initval_diagnostic_cmp);
        initval_diagnostics
            .dedup_by(|left, right| initval_diagnostic_cmp(left, right) == Ordering::Equal);
        let absence_only_initval = initval_is_absence_only(&initval_diagnostics);
        let mut writers = Vec::new();
        let reason = if !complete_initval
            && !(absence_only_initval
                && global_info.escape == EscapeStatus::Module
                && unknown_writers.is_empty()
                && !runtime_writers.contains_key(&global.key))
        {
            StationarityReason::IncompleteInitval
        } else if !unknown_writers.is_empty() {
            writers.extend(unknown_writers.iter().cloned());
            StationarityReason::UnknownRuntimeWriter
        } else if global_info.escape == EscapeStatus::External {
            StationarityReason::ExportedGlobal
        } else if let Some(known_writers) = runtime_writers.get(&global.key) {
            writers.extend(known_writers.iter().cloned());
            StationarityReason::RuntimeWriter
        } else {
            stationary_globals.insert(global.key.clone());
            StationarityReason::Stationary
        };
        verdicts.push(StationarityVerdict {
            global: gid,
            complete_initval,
            stationary: reason == StationarityReason::Stationary,
            reason,
            runtime_writers: writers,
            initval_diagnostics,
        });
    }
    verdicts.sort_by(|left, right| {
        module.globals[left.global.0 as usize]
            .key
            .cmp(&module.globals[right.global.0 as usize].key)
    });
    (stationary_globals, verdicts)
}

fn stationarity_writer_from_modref(mr: &ModRef) -> StationarityWriter {
    StationarityWriter {
        func: Some(mr.func),
        global: mr.global.clone(),
        access: mr.access,
        via: mr.via,
        witness: mr.witness.clone(),
    }
}

fn stationarity_writer_cmp(left: &StationarityWriter, right: &StationarityWriter) -> Ordering {
    left.func
        .map(|id| id.0)
        .cmp(&right.func.map(|id| id.0))
        .then_with(|| left.global.cmp(&right.global))
        .then_with(|| access_rank(left.access).cmp(&access_rank(right.access)))
        .then_with(|| via_rank(left.via).cmp(&via_rank(right.via)))
        .then_with(|| option_str(&left.witness).cmp(option_str(&right.witness)))
}

fn initval_diagnostic_cmp(left: &InitValDiagnostic, right: &InitValDiagnostic) -> Ordering {
    left.reason
        .cmp(&right.reason)
        .then_with(|| option_str(&left.witness).cmp(option_str(&right.witness)))
}

fn initval_is_absence_only(diagnostics: &[InitValDiagnostic]) -> bool {
    !diagnostics.is_empty()
        && diagnostics
            .iter()
            .all(|diagnostic| diagnostic.reason == "no_modeled_pointer_initializer")
}

fn apply_initval_exact_call_edges(
    call_edges: &mut Vec<CallEdge>,
    module: &Pir,
    func_lookup: &HashMap<String, FuncId>,
    address_taken: &[(FuncId, &pangs_pir::Func)],
    callsites: &[CallsiteInfo],
    simple_queries: &BTreeMap<CallsiteId, &SimpleIcallQuery>,
    b2_resolutions: &BTreeMap<CallsiteId, SimpleIcallResolution>,
    initval_resolutions: &BTreeMap<CallsiteId, SimpleIcallResolution>,
) {
    for (cs, resolution) in initval_resolutions {
        if b2_resolutions.contains_key(cs) {
            continue;
        }
        let Some(query) = simple_queries.get(cs) else {
            continue;
        };
        let Some(callsite) = callsites.get(cs.0 as usize) else {
            continue;
        };
        call_edges.retain(|edge| !(edge.kind == CallKind::Indirect && edge.callsite == Some(*cs)));
        emit_simple_call_edges(
            call_edges,
            module,
            func_lookup,
            address_taken,
            callsite.caller,
            *cs,
            query,
            resolution,
        );
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
            direct_vararg_audit_kind(module, callee),
            Some(format!("callee:{callee}")),
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
            Some("fnptr_varargs_indirect"),
            Some("callee:<indirect>".to_string()),
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
    kind: Option<&str>,
    detail: Option<String>,
    sig: &pangs_pir::Signature,
    args: &[String],
    loc: &Option<pangs_pir::Loc>,
    callsite_key: &str,
) {
    if !sig.vararg {
        return;
    }
    let Some(kind) = kind else {
        return;
    };
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
    push_audit_finding_with_detail(
        findings,
        audit_taints,
        caller,
        kind,
        loc,
        affected,
        Some(callsite_key.to_string()),
        detail,
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
    kind: &str,
    detail: Option<String>,
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
        kind: kind.to_string(),
        detail,
        values,
        loc: loc.clone(),
        witness: callsite_key.to_string(),
    });
}

fn direct_vararg_audit_kind(module: &Pir, callee: &str) -> Option<&'static str> {
    if is_known_benign_vararg_callee(callee) {
        return None;
    }
    match module.functions.iter().find(|func| func.key == callee) {
        Some(func) if !func.external && !func.body.iter().any(stmt_consumes_varargs) => None,
        Some(func) if !func.external => Some("fnptr_varargs_internal_unmodeled"),
        _ => Some("fnptr_varargs_external"),
    }
}

fn safe_indirect_vararg_callsites(
    module: &Pir,
    indirect_vararg_keys: &BTreeSet<String>,
    solved: &pangs_solve::SolveResult,
) -> BTreeSet<String> {
    solved
        .indirect_calls
        .iter()
        .filter(|site| indirect_vararg_site_is_safe(module, indirect_vararg_keys, site))
        .map(|site| site.callsite_key.clone())
        .collect()
}

fn indirect_vararg_site_is_safe(
    module: &Pir,
    indirect_vararg_keys: &BTreeSet<String>,
    site: &IndirectCallResolution,
) -> bool {
    if !indirect_vararg_keys.contains(&site.callsite_key)
        || site.unknown_callee
        || site.targets.is_empty()
    {
        return false;
    }
    site.targets.iter().all(|target| {
        module
            .functions
            .iter()
            .find(|func| func.key == *target)
            .map(|func| {
                func.sig.vararg
                    && !func.external
                    && direct_vararg_audit_kind(module, target).is_none()
            })
            .unwrap_or(false)
    })
}

fn is_known_benign_vararg_callee(callee: &str) -> bool {
    matches!(
        callee,
        // tmux formatting/logging wrappers inspected for M4.3.
        "log_debug"
            | "cmdq_error"
            | "cmdq_print"
            | "fatalx"
            | "xasprintf"
            | "xsnprintf"
            | "format_add"
            | "cfg_add_cause"
            // curl formatting/message wrappers inspected for M4.3.
            | "warnf"
            | "errorf"
            | "notef"
            | "helpf"
            | "easysrc_addf"
            | "curl_mprintf"
            | "curl_mfprintf"
            | "curl_msnprintf"
            | "curl_maprintf"
            | "curlx_dyn_addf"
    )
}

fn stmt_consumes_varargs(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Unknown { op, reason, .. } => {
            reason == "va_arg" || reason == "varargs_intrinsic" || op.starts_with("llvm.va_")
        }
        _ => false,
    }
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
    push_audit_finding_with_detail(
        findings,
        audit_taints,
        caller,
        kind,
        loc,
        affected,
        witness,
        None,
    );
}

fn push_audit_finding_with_detail(
    findings: &mut Vec<Finding>,
    audit_taints: &mut BTreeMap<FuncId, Vec<Taint>>,
    caller: FuncId,
    kind: &str,
    loc: &Option<pangs_pir::Loc>,
    affected: Vec<String>,
    witness: Option<String>,
    detail: Option<String>,
) {
    findings.push(Finding {
        kind: kind.to_string(),
        file: loc.as_ref().map(|loc| loc.file.clone()),
        line: loc.as_ref().map(|loc| loc.line),
        affected,
        effect: "omega_taint".to_string(),
        detail,
    });
    audit_taints.entry(caller).or_default().push(Taint {
        kind: kind.to_string(),
        witness,
    });
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ModRefFactHashKey {
    func: u32,
    global_kind: u8,
    global_value: u32,
    access_rank: u8,
    via_rank: u8,
    detail: u32,
    address_node: u32,
    pointee_globals: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CompactModRefFactKey {
    func: u32,
    global: u32,
    access_rank: u8,
    via_rank: u8,
}

fn compact_modref_key(row: &ModRef) -> Option<CompactModRefFactKey> {
    if row.detail.is_some() || row.address_node.is_some() || !row.pointee_globals.is_empty() {
        return None;
    }
    let GlobalTarget::Name(global) = row.global else {
        return None;
    };
    Some(CompactModRefFactKey {
        func: row.func.0,
        global: global.0,
        access_rank: access_rank(row.access),
        via_rank: via_rank(row.via),
    })
}

#[derive(Debug, Default)]
struct ModRefFactInterners {
    strings: HashMap<String, u32>,
    pointee_globals: HashMap<Vec<String>, u32>,
}

impl ModRefFactInterners {
    fn key_for(&mut self, mr: &ModRef) -> ModRefFactHashKey {
        let (global_kind, global_value) = match &mr.global {
            GlobalTarget::Name(id) => (0, id.0),
            GlobalTarget::Unknown(reason) => (1, self.intern_str(reason)),
        };
        ModRefFactHashKey {
            func: mr.func.0,
            global_kind,
            global_value,
            access_rank: access_rank(mr.access),
            via_rank: via_rank(mr.via),
            detail: self.intern_option_str(&mr.detail),
            address_node: self.intern_option_str(&mr.address_node),
            pointee_globals: self.intern_pointee_globals(&mr.pointee_globals),
        }
    }

    fn intern_option_str(&mut self, value: &Option<String>) -> u32 {
        value.as_deref().map_or(0, |value| self.intern_str(value))
    }

    fn intern_str(&mut self, value: &str) -> u32 {
        if let Some(&id) = self.strings.get(value) {
            return id;
        }
        let id = self.strings.len() as u32 + 1;
        self.strings.insert(value.to_owned(), id);
        id
    }

    fn intern_pointee_globals(&mut self, values: &[String]) -> u32 {
        if values.is_empty() {
            return 0;
        }
        if let Some(&id) = self.pointee_globals.get(values) {
            return id;
        }
        let id = self.pointee_globals.len() as u32 + 1;
        self.pointee_globals.insert(values.to_vec(), id);
        id
    }
}

#[derive(Debug, Default)]
struct ModRefBuilder {
    rows: Vec<ModRef>,
    interners: ModRefFactInterners,
    compact_by_fact: HashMap<CompactModRefFactKey, usize>,
    by_fact: HashMap<ModRefFactHashKey, usize>,
    metrics: ModRefEmissionMetrics,
    fanout_by_fact: HashMap<ModRefFanoutKey, u64>,
    fanout_by_phase: HashMap<(ModRefSourcePhase, ModRefFanoutKey), u64>,
    profile: PointerModRefProfile,
}

impl ModRefBuilder {
    fn new() -> Self {
        Self {
            profile: PointerModRefProfile::from_env(),
            ..Self::default()
        }
    }

    fn push(&mut self, row: ModRef) {
        self.push_with_phase(row, None);
    }

    fn push_with_phase(&mut self, mut row: ModRef, phase: Option<ModRefSourcePhase>) {
        self.note_modref_attempt(&row, phase);
        if let Some(key) = compact_modref_key(&row) {
            if let Some(&idx) = self.compact_by_fact.get(&key) {
                let existing = &mut self.rows[idx];
                existing.witness =
                    preferred_modref_witness(existing.witness.take(), row.witness.take());
                self.note_modref_result(phase, false);
                return;
            }
            self.compact_by_fact.insert(key, self.rows.len());
            self.rows.push(row);
            self.note_modref_result(phase, true);
            return;
        }

        let key = self.interners.key_for(&row);
        if let Some(&idx) = self.by_fact.get(&key) {
            let existing = &mut self.rows[idx];
            existing.witness =
                preferred_modref_witness(existing.witness.take(), row.witness.take());
            self.note_modref_result(phase, false);
            return;
        }
        self.by_fact.insert(key, self.rows.len());
        self.rows.push(row);
        self.note_modref_result(phase, true);
    }

    fn push_named_empty(
        &mut self,
        func: FuncId,
        global: GlobalId,
        access: Access,
        via: Via,
        witness: Option<&str>,
        phase: Option<ModRefSourcePhase>,
    ) {
        let fanout_key = ModRefFanoutKey {
            func,
            global: GlobalTarget::Name(global),
            access_rank: access_rank(access),
            via_rank: via_rank(via),
        };
        self.note_modref_fanout(fanout_key, phase);
        let key = CompactModRefFactKey {
            func: func.0,
            global: global.0,
            access_rank: access_rank(access),
            via_rank: via_rank(via),
        };
        if let Some(&idx) = self.compact_by_fact.get(&key) {
            prefer_modref_witness_ref(&mut self.rows[idx].witness, witness);
            self.note_modref_result(phase, false);
            return;
        }
        self.compact_by_fact.insert(key, self.rows.len());
        self.rows.push(ModRef {
            func,
            global: GlobalTarget::Name(global),
            access,
            via,
            witness: witness.map(str::to_owned),
            detail: None,
            address_node: None,
            pointee_globals: Vec::new(),
        });
        self.note_modref_result(phase, true);
    }

    fn metrics(&self) -> ModRefEmissionMetrics {
        self.metrics.clone()
    }

    fn note_modref_attempt(&mut self, row: &ModRef, phase: Option<ModRefSourcePhase>) {
        let fanout_key = ModRefFanoutKey {
            func: row.func,
            global: row.global.clone(),
            access_rank: access_rank(row.access),
            via_rank: via_rank(row.via),
        };
        self.note_modref_fanout(fanout_key, phase);
    }

    fn note_modref_fanout(
        &mut self,
        fanout_key: ModRefFanoutKey,
        phase: Option<ModRefSourcePhase>,
    ) {
        self.note_modref_fanout_count(fanout_key, phase, 1);
    }

    fn note_modref_fanout_count(
        &mut self,
        fanout_key: ModRefFanoutKey,
        phase: Option<ModRefSourcePhase>,
        delta: u64,
    ) {
        if delta == 0 {
            return;
        }
        let count = self.fanout_by_fact.entry(fanout_key.clone()).or_default();
        *count += delta;
        self.metrics.pointer_modref_max_fact_fanout =
            self.metrics.pointer_modref_max_fact_fanout.max(*count);
        let Some(phase) = phase else {
            return;
        };
        self.metrics.phase_mut(phase).attempted += delta;
        let phase_count = self.fanout_by_phase.entry((phase, fanout_key)).or_default();
        *phase_count += delta;
        let phase_metrics = self.metrics.phase_mut(phase);
        phase_metrics.max_fact_fanout = phase_metrics.max_fact_fanout.max(*phase_count);
    }

    fn note_modref_result(&mut self, phase: Option<ModRefSourcePhase>, unique: bool) {
        let Some(phase) = phase else {
            return;
        };
        let phase_metrics = self.metrics.phase_mut(phase);
        if unique {
            phase_metrics.unique += 1;
        } else {
            phase_metrics.duplicate += 1;
        }
        self.maybe_print_profile("progress");
    }

    fn note_named_empty_prefiltered_duplicates(
        &mut self,
        func: FuncId,
        global: GlobalId,
        access: Access,
        via: Via,
        phase: ModRefSourcePhase,
        duplicate_count: u64,
    ) {
        if duplicate_count == 0 {
            return;
        }
        let fanout_key = ModRefFanoutKey {
            func,
            global: GlobalTarget::Name(global),
            access_rank: access_rank(access),
            via_rank: via_rank(via),
        };
        self.note_modref_fanout_count(fanout_key, Some(phase), duplicate_count);
        self.metrics.phase_mut(phase).duplicate += duplicate_count;
        self.maybe_print_profile("progress");
    }

    fn maybe_print_profile(&mut self, label: &str) {
        self.profile
            .maybe_print_local(label, &self.metrics, self.rows.len());
    }

    fn print_profile(&self, label: &str) {
        self.profile
            .print_local(label, &self.metrics, self.rows.len());
    }

    fn into_vec(self) -> Vec<ModRef> {
        self.rows
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ModRefSourcePhase {
    PagPointer,
    MemsetMemcpy,
}

#[derive(Debug, Clone, Default)]
struct ModRefPhaseMetrics {
    attempted: u64,
    unique: u64,
    duplicate: u64,
    max_fact_fanout: u64,
}

#[derive(Debug, Clone, Default)]
struct ModRefEmissionMetrics {
    pag: ModRefPhaseMetrics,
    mem: ModRefPhaseMetrics,
    closure: ModRefPhaseMetrics,
    pointer_modref_max_fact_fanout: u64,
}

impl ModRefEmissionMetrics {
    fn phase_mut(&mut self, phase: ModRefSourcePhase) -> &mut ModRefPhaseMetrics {
        match phase {
            ModRefSourcePhase::PagPointer => &mut self.pag,
            ModRefSourcePhase::MemsetMemcpy => &mut self.mem,
        }
    }

    fn merge_closure(&mut self, closure: ModRefPhaseMetrics) {
        self.closure = closure;
        self.pointer_modref_max_fact_fanout = self
            .pointer_modref_max_fact_fanout
            .max(self.closure.max_fact_fanout);
    }

    fn attempted(&self) -> u64 {
        self.pag.attempted + self.mem.attempted + self.closure.attempted
    }

    fn unique(&self) -> u64 {
        self.pag.unique + self.mem.unique + self.closure.unique
    }

    fn duplicate(&self) -> u64 {
        self.pag.duplicate + self.mem.duplicate + self.closure.duplicate
    }
}

#[derive(Debug)]
struct PointerModRefProfile {
    enabled: bool,
    started: Instant,
    interval_attempted: u64,
    next_attempted: u64,
}

impl Default for PointerModRefProfile {
    fn default() -> Self {
        Self {
            enabled: false,
            started: Instant::now(),
            interval_attempted: pointer_modref_profile_interval_attempts(),
            next_attempted: pointer_modref_profile_interval_attempts(),
        }
    }
}

impl PointerModRefProfile {
    fn from_env() -> Self {
        let interval_attempted = pointer_modref_profile_interval_attempts();
        Self {
            enabled: pointer_modref_profile_enabled(),
            started: Instant::now(),
            interval_attempted,
            next_attempted: interval_attempted,
        }
    }

    fn maybe_print_local(
        &mut self,
        label: &str,
        metrics: &ModRefEmissionMetrics,
        local_rows: usize,
    ) {
        if !self.enabled || metrics.attempted() < self.next_attempted {
            return;
        }
        self.print_local(label, metrics, local_rows);
        while self.next_attempted <= metrics.attempted() {
            self.next_attempted += self.interval_attempted;
        }
    }

    fn print_local(&self, label: &str, metrics: &ModRefEmissionMetrics, local_rows: usize) {
        if !self.enabled {
            return;
        }
        eprintln!(
            "pangs pointer modref profile {label}: elapsed_ms={} local_rows={} \
             attempted={} unique={} duplicate={} \
             pag={}/{}/{} mem={}/{}/{} closure={}/{}/{} \
             max_fanout={} pag_max_fanout={} mem_max_fanout={} closure_max_fanout={}",
            self.started.elapsed().as_millis(),
            local_rows,
            metrics.attempted(),
            metrics.unique(),
            metrics.duplicate(),
            metrics.pag.attempted,
            metrics.pag.unique,
            metrics.pag.duplicate,
            metrics.mem.attempted,
            metrics.mem.unique,
            metrics.mem.duplicate,
            metrics.closure.attempted,
            metrics.closure.unique,
            metrics.closure.duplicate,
            metrics.pointer_modref_max_fact_fanout,
            metrics.pag.max_fact_fanout,
            metrics.mem.max_fact_fanout,
            metrics.closure.max_fact_fanout,
        );
    }

    fn maybe_print_closure(
        &mut self,
        label: &str,
        metrics: &ModRefPhaseMetrics,
        funcs_done: usize,
        payloads: usize,
    ) {
        if !self.enabled || metrics.attempted < self.next_attempted {
            return;
        }
        self.print_closure(label, metrics, funcs_done, payloads);
        while self.next_attempted <= metrics.attempted {
            self.next_attempted += self.interval_attempted;
        }
    }

    fn print_closure(
        &self,
        label: &str,
        metrics: &ModRefPhaseMetrics,
        funcs_done: usize,
        payloads: usize,
    ) {
        if !self.enabled {
            return;
        }
        eprintln!(
            "pangs pointer modref profile {label}: elapsed_ms={} funcs_done={} payloads={} \
             attempted={} unique={} duplicate={} max_fanout={}",
            self.started.elapsed().as_millis(),
            funcs_done,
            payloads,
            metrics.attempted,
            metrics.unique,
            metrics.duplicate,
            metrics.max_fact_fanout,
        );
    }
}

fn pointer_modref_profile_enabled() -> bool {
    std::env::var_os("PANGS_POINTER_MODREF_PROFILE").is_some()
}

fn pointer_modref_profile_interval_attempts() -> u64 {
    std::env::var("PANGS_POINTER_MODREF_PROFILE_INTERVAL")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|&value| value > 0)
        .unwrap_or(10_000_000)
}

fn pointer_modref_profile_top_emitters() -> usize {
    std::env::var("PANGS_POINTER_MODREF_PROFILE_TOP")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(20)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ModRefFanoutKey {
    func: FuncId,
    global: GlobalTarget,
    access_rank: u8,
    via_rank: u8,
}

fn modref_payload_cmp(
    left: &ModRefPayload,
    right: &ModRefPayload,
    globals: &[GlobalInfo],
) -> Ordering {
    global_target_label(&left.global, globals)
        .cmp(global_target_label(&right.global, globals))
        .then_with(|| access_rank(left.access).cmp(&access_rank(right.access)))
        .then_with(|| via_rank(left.via).cmp(&via_rank(right.via)))
        .then_with(|| option_str(&left.witness).cmp(option_str(&right.witness)))
        .then_with(|| option_str(&left.detail).cmp(option_str(&right.detail)))
        .then_with(|| option_str(&left.address_node).cmp(option_str(&right.address_node)))
        .then_with(|| left.pointee_globals.cmp(&right.pointee_globals))
}

fn global_target_label<'a>(target: &'a GlobalTarget, globals: &'a [GlobalInfo]) -> &'a str {
    match target {
        GlobalTarget::Name(id) => &globals[id.0 as usize].key,
        GlobalTarget::Unknown(reason) => reason,
    }
}

fn option_str(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("")
}

struct PointerAccess {
    access: Access,
    address_node: pangs_pag::NodeId,
    unknown_reason: &'static str,
    detail: &'static str,
    suppress_direct_symbol: bool,
}

#[derive(Debug, Clone)]
struct ModRefNodeSummary<'a> {
    label: &'a str,
    external: bool,
    pointee_global_ids: Vec<GlobalId>,
    diagnostic_pointee_globals: &'a [String],
    external_source_suffix: Option<String>,
    direct_symbol_global: Option<GlobalId>,
}

struct LocalPointerModRefRow {
    witness: Option<String>,
    count: u64,
}

struct LocalPointerModRefRows {
    rows: Vec<Option<LocalPointerModRefRow>>,
    touched: Vec<usize>,
}

impl LocalPointerModRefRows {
    fn new(global_count: usize) -> Self {
        let row_count = global_count.saturating_mul(2);
        Self {
            rows: (0..row_count).map(|_| None).collect(),
            touched: Vec::new(),
        }
    }

    fn push(&mut self, global: GlobalId, access: Access, witness: Option<&str>, count: u64) {
        if count == 0 {
            return;
        }
        let idx = global.0 as usize * 2 + access_rank(access) as usize;
        let Some(slot) = self.rows.get_mut(idx) else {
            return;
        };
        match slot {
            Some(row) => {
                row.count += count;
                prefer_modref_witness_ref(&mut row.witness, witness);
            }
            None => {
                *slot = Some(LocalPointerModRefRow {
                    witness: witness.map(str::to_owned),
                    count,
                });
                self.touched.push(idx);
            }
        }
    }

    fn drain_touched(&mut self) -> impl Iterator<Item = (usize, LocalPointerModRefRow)> + '_ {
        self.touched
            .drain(..)
            .filter_map(|idx| self.rows[idx].take().map(|row| (idx, row)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct LocalPointerAccessKey {
    func: u32,
    address_node: u32,
    access_rank: u8,
    suppress_direct_symbol: bool,
}

struct LocalPointerAccessRow {
    witness: Option<String>,
    count: u64,
}

#[derive(Debug, Clone)]
struct PointerAccessEmitterEntry {
    expanded_rows: u64,
    occurrences: u64,
    fanout: usize,
    func: FuncId,
    node_label: String,
    access_rank: u8,
    suppress_direct_symbol: bool,
}

#[derive(Debug)]
struct PointerAccessEmitterProfile {
    enabled: bool,
    limit: usize,
    started: Instant,
    observed_rows: u64,
    interval_rows: u64,
    next_rows: u64,
    entries: Vec<PointerAccessEmitterEntry>,
}

impl PointerAccessEmitterProfile {
    fn from_env() -> Self {
        let limit = pointer_modref_profile_top_emitters();
        let interval_rows = pointer_modref_profile_interval_attempts();
        Self {
            enabled: pointer_modref_profile_enabled() && limit > 0,
            limit,
            started: Instant::now(),
            observed_rows: 0,
            interval_rows,
            next_rows: interval_rows,
            entries: Vec::new(),
        }
    }

    fn observe(
        &mut self,
        key: LocalPointerAccessKey,
        summary: &ModRefNodeSummary<'_>,
        fanout: usize,
        occurrences: u64,
    ) {
        if !self.enabled || fanout == 0 || occurrences == 0 {
            return;
        }
        let expanded_rows = occurrences.saturating_mul(fanout as u64);
        self.observed_rows = self.observed_rows.saturating_add(expanded_rows);
        if self.should_keep(expanded_rows) {
            self.entries.push(PointerAccessEmitterEntry {
                expanded_rows,
                occurrences,
                fanout,
                func: FuncId(key.func),
                node_label: summary.label.to_string(),
                access_rank: key.access_rank,
                suppress_direct_symbol: key.suppress_direct_symbol,
            });
            self.entries.sort_by(|left, right| {
                right
                    .expanded_rows
                    .cmp(&left.expanded_rows)
                    .then_with(|| right.occurrences.cmp(&left.occurrences))
                    .then_with(|| right.fanout.cmp(&left.fanout))
                    .then_with(|| left.func.cmp(&right.func))
                    .then_with(|| left.node_label.cmp(&right.node_label))
            });
            self.entries.truncate(self.limit);
        }
        if self.observed_rows >= self.next_rows {
            self.print("top-emitters-progress");
            while self.next_rows <= self.observed_rows {
                self.next_rows += self.interval_rows;
            }
        }
    }

    fn should_keep(&self, expanded_rows: u64) -> bool {
        self.entries.len() < self.limit
            || self
                .entries
                .last()
                .is_some_and(|entry| expanded_rows > entry.expanded_rows)
    }

    fn print(&self, label: &str) {
        if !self.enabled {
            return;
        }
        eprintln!(
            "pangs pointer modref profile {label}: elapsed_ms={} observed_expanded_rows={} entries={}",
            self.started.elapsed().as_millis(),
            self.observed_rows,
            self.entries.len(),
        );
        for (idx, entry) in self.entries.iter().enumerate() {
            eprintln!(
                "pangs pointer modref profile {label} #{}: expanded_rows={} occurrences={} \
                 fanout={} func={} access_rank={} suppress_direct_symbol={} node={}",
                idx + 1,
                entry.expanded_rows,
                entry.occurrences,
                entry.fanout,
                entry.func.0,
                entry.access_rank,
                entry.suppress_direct_symbol,
                entry.node_label,
            );
        }
    }
}

fn push_local_pointer_modref_row(
    local_rows: &mut LocalPointerModRefRows,
    global: GlobalId,
    access: Access,
    witness: Option<&str>,
    count: u64,
) {
    local_rows.push(global, access, witness, count);
}

fn flush_local_pointer_access_rows(
    local_rows: &mut LocalPointerModRefRows,
    local_accesses: &mut HashMap<LocalPointerAccessKey, LocalPointerAccessRow>,
    node_summaries: &[Option<ModRefNodeSummary<'_>>],
    access_profile: &mut PointerAccessEmitterProfile,
) {
    for (key, row) in local_accesses.drain() {
        let Some(Some(summary)) = node_summaries.get(key.address_node as usize) else {
            continue;
        };
        let access = match key.access_rank {
            0 => Access::Ref,
            _ => Access::Mod,
        };
        let fanout = summary
            .pointee_global_ids
            .iter()
            .filter(|&&gid| {
                !(key.suppress_direct_symbol && summary.direct_symbol_global == Some(gid))
            })
            .count();
        access_profile.observe(key, summary, fanout, row.count);
        for &gid in &summary.pointee_global_ids {
            if key.suppress_direct_symbol && summary.direct_symbol_global == Some(gid) {
                continue;
            }
            push_local_pointer_modref_row(
                local_rows,
                gid,
                access,
                row.witness.as_deref(),
                row.count,
            );
        }
    }
}

fn flush_local_pointer_modref_rows(
    modrefs: &mut ModRefBuilder,
    func: Option<FuncId>,
    local_rows: &mut LocalPointerModRefRows,
) {
    let Some(func) = func else {
        return;
    };
    for (idx, row) in local_rows.drain_touched() {
        let global = GlobalId((idx / 2) as u32);
        let access = match idx % 2 {
            0 => Access::Ref,
            _ => Access::Mod,
        };
        let via = Via::Aliased;
        modrefs.push_named_empty(
            func,
            global,
            access,
            via,
            row.witness.as_deref(),
            Some(ModRefSourcePhase::PagPointer),
        );
        modrefs.note_named_empty_prefiltered_duplicates(
            func,
            global,
            access,
            via,
            ModRefSourcePhase::PagPointer,
            row.count.saturating_sub(1),
        );
    }
}

fn build_modref_node_summary<'a>(
    label: &'a str,
    resolution: &'a NodeResolution,
    global_lookup: &HashMap<String, GlobalId>,
) -> ModRefNodeSummary<'a> {
    let pointee_global_ids = resolution
        .pointee_globals
        .iter()
        .filter_map(|global_key| global_lookup.get(global_key).copied())
        .collect();
    let direct_symbol_global = label
        .strip_prefix("sym:global:")
        .and_then(|global_key| global_lookup.get(global_key).copied());
    ModRefNodeSummary {
        label,
        external: resolution.external,
        pointee_global_ids,
        diagnostic_pointee_globals: resolution.pointee_globals.as_ref(),
        external_source_suffix: resolution
            .external
            .then(|| modref_external_source_suffix(&resolution.external_sources))
            .flatten(),
        direct_symbol_global,
    }
}

fn push_pointer_modrefs_from_pag(
    modrefs: &mut ModRefBuilder,
    func_lookup: &HashMap<String, FuncId>,
    global_lookup: &HashMap<String, GlobalId>,
    pag: &Pag,
    nodes: &BTreeMap<String, NodeResolution>,
    noloc_ord: &mut BTreeMap<(String, String), u32>,
) {
    let mut node_summaries = Vec::new();
    node_summaries.resize_with(pag.nodes.len(), || None);
    let mut missing_nodes = vec![false; pag.nodes.len()];
    let mut local_accesses = HashMap::<LocalPointerAccessKey, LocalPointerAccessRow>::new();
    let mut local_rows = LocalPointerModRefRows::new(global_lookup.len());
    let mut access_profile = PointerAccessEmitterProfile::from_env();
    let mut active_func = None;
    for edge in &pag.edges {
        let Some((owner, func, accesses)) = edge_accesses(edge, func_lookup) else {
            continue;
        };
        if active_func != Some(func) {
            flush_local_pointer_access_rows(
                &mut local_rows,
                &mut local_accesses,
                &node_summaries,
                &mut access_profile,
            );
            flush_local_pointer_modref_rows(modrefs, active_func, &mut local_rows);
            active_func = Some(func);
        }
        let witness = witness_key(&owner, &edge.loc, noloc_ord, "global");
        for pointer_access in accesses {
            let node_idx = pointer_access.address_node.0 as usize;
            if missing_nodes.get(node_idx).copied().unwrap_or(true) {
                continue;
            }
            if node_summaries[node_idx].is_none() {
                let Some(node) = pag.nodes.get(node_idx) else {
                    continue;
                };
                let Some(resolution) = nodes.get(&node.label) else {
                    missing_nodes[node_idx] = true;
                    continue;
                };
                node_summaries[node_idx] = Some(build_modref_node_summary(
                    &node.label,
                    resolution,
                    global_lookup,
                ));
            }
            let summary = node_summaries[node_idx].as_ref().unwrap();
            let phase = if pointer_access.detail.starts_with("edge:memcpy") {
                ModRefSourcePhase::MemsetMemcpy
            } else {
                ModRefSourcePhase::PagPointer
            };
            if phase != ModRefSourcePhase::PagPointer {
                flush_local_pointer_access_rows(
                    &mut local_rows,
                    &mut local_accesses,
                    &node_summaries,
                    &mut access_profile,
                );
                flush_local_pointer_modref_rows(modrefs, active_func, &mut local_rows);
            }

            if phase == ModRefSourcePhase::PagPointer {
                let key = LocalPointerAccessKey {
                    func: func.0,
                    address_node: pointer_access.address_node.0,
                    access_rank: access_rank(pointer_access.access),
                    suppress_direct_symbol: pointer_access.suppress_direct_symbol,
                };
                local_accesses
                    .entry(key)
                    .and_modify(|row| {
                        row.count += 1;
                        prefer_modref_witness_ref(&mut row.witness, witness.as_deref());
                    })
                    .or_insert_with(|| LocalPointerAccessRow {
                        witness: witness.clone(),
                        count: 1,
                    });
            } else {
                for &gid in &summary.pointee_global_ids {
                    if pointer_access.suppress_direct_symbol
                        && summary.direct_symbol_global == Some(gid)
                    {
                        continue;
                    }
                    modrefs.push_named_empty(
                        func,
                        gid,
                        pointer_access.access,
                        Via::Aliased,
                        witness.as_deref(),
                        Some(phase),
                    );
                }
            }

            if summary.external {
                modrefs.push_with_phase(
                    ModRef {
                        func,
                        global: GlobalTarget::Unknown(pointer_access.unknown_reason.to_string()),
                        access: pointer_access.access,
                        via: Via::Unknown,
                        witness: witness.clone(),
                        detail: Some(modref_detail_with_external_suffix(
                            pointer_access.detail,
                            summary.external_source_suffix.as_deref(),
                        )),
                        address_node: Some(summary.label.to_string()),
                        pointee_globals: summary.diagnostic_pointee_globals.to_vec(),
                    },
                    Some(phase),
                );
            }
        }
    }
    flush_local_pointer_access_rows(
        &mut local_rows,
        &mut local_accesses,
        &node_summaries,
        &mut access_profile,
    );
    access_profile.print("top-emitters-done");
    flush_local_pointer_modref_rows(modrefs, active_func, &mut local_rows);
}

fn push_pointer_memset_modrefs_from_pir(
    modrefs: &mut ModRefBuilder,
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
                let witness = witness_key(&func.key, loc, noloc_ord, "global");
                modrefs.push_named_empty(
                    func_id,
                    gid,
                    Access::Mod,
                    Via::Aliased,
                    witness.as_deref(),
                    Some(ModRefSourcePhase::MemsetMemcpy),
                );
                continue;
            }
            let label = pag_value_label(module, &func.key, dst);
            let Some(resolution) = nodes.get(&label) else {
                continue;
            };
            let witness = witness_key(&func.key, loc, noloc_ord, "global");
            for global_key in resolution.pointee_globals.iter() {
                let Some(&gid) = global_lookup.get(global_key) else {
                    continue;
                };
                modrefs.push_named_empty(
                    func_id,
                    gid,
                    Access::Mod,
                    Via::Aliased,
                    witness.as_deref(),
                    Some(ModRefSourcePhase::MemsetMemcpy),
                );
            }
            if resolution.external {
                modrefs.push_with_phase(
                    ModRef {
                        func: func_id,
                        global: GlobalTarget::Unknown("omega_store".to_string()),
                        access: Access::Mod,
                        via: Via::Unknown,
                        witness,
                        detail: Some(modref_detail_with_external_sources(
                            "stmt:memset_dst",
                            &resolution.external_sources,
                        )),
                        address_node: Some(label.clone()),
                        pointee_globals: resolution.pointee_globals.to_vec(),
                    },
                    Some(ModRefSourcePhase::MemsetMemcpy),
                );
            }
        }
    }
}

fn modref_external_source_suffix(sources: &[String]) -> Option<String> {
    if sources.is_empty() {
        return None;
    }
    let mut sources = sources.to_vec();
    sources.sort();
    sources.dedup();
    Some(sources.join("+"))
}

fn modref_detail_with_external_suffix(base: &str, suffix: Option<&str>) -> String {
    match suffix {
        Some(suffix) => format!("{base}|{suffix}"),
        None => base.to_string(),
    }
}

fn modref_detail_with_external_sources(base: &str, sources: &[String]) -> String {
    modref_detail_with_external_suffix(base, modref_external_source_suffix(sources).as_deref())
}

fn edge_accesses(
    edge: &Edge,
    func_lookup: &HashMap<String, FuncId>,
) -> Option<(String, FuncId, Vec<PointerAccess>)> {
    let Owner::Function(owner) = &edge.owner else {
        return None;
    };
    let &func = func_lookup.get(owner)?;
    match edge.kind {
        EdgeKind::Load => Some((
            owner.clone(),
            func,
            vec![PointerAccess {
                access: Access::Ref,
                address_node: edge.src,
                unknown_reason: "omega_load",
                detail: "edge:load",
                suppress_direct_symbol: true,
            }],
        )),
        EdgeKind::Store => Some((
            owner.clone(),
            func,
            vec![PointerAccess {
                access: Access::Mod,
                address_node: edge.dst,
                unknown_reason: "omega_store",
                detail: "edge:store",
                suppress_direct_symbol: true,
            }],
        )),
        EdgeKind::Memcpy { .. } => Some((
            owner.clone(),
            func,
            vec![
                PointerAccess {
                    access: Access::Ref,
                    address_node: edge.src,
                    unknown_reason: "omega_load",
                    detail: "edge:memcpy_src",
                    suppress_direct_symbol: false,
                },
                PointerAccess {
                    access: Access::Mod,
                    address_node: edge.dst,
                    unknown_reason: "omega_store",
                    detail: "edge:memcpy_dst",
                    suppress_direct_symbol: false,
                },
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
                        let global = &globals[gid.0 as usize];
                        if global.mutable && !global.stationary {
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
    detail: Option<String>,
    address_node: Option<String>,
    pointee_globals: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct TransitiveModRefs {
    payloads: Vec<ModRefPayload>,
    by_func: Vec<Vec<usize>>,
}

impl TransitiveModRefs {
    fn iter(&self, func: FuncId) -> impl Iterator<Item = ModRef> + '_ {
        let root = func;
        self.by_func[func.0 as usize]
            .iter()
            .map(move |&payload_id| {
                let payload = &self.payloads[payload_id];
                ModRef {
                    func: root,
                    global: payload.global.clone(),
                    access: payload.access,
                    via: payload.via,
                    witness: payload.witness.clone(),
                    detail: payload.detail.clone(),
                    address_node: payload.address_node.clone(),
                    pointee_globals: payload.pointee_globals.clone(),
                }
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ModRefFactKey {
    global: GlobalTarget,
    access_rank: u8,
    via_rank: u8,
    detail: Option<String>,
    address_node: Option<String>,
    pointee_globals: Vec<String>,
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
        match self.witness.cmp(&other.witness) {
            Ordering::Equal => {}
            order => return order,
        }
        match self.detail.cmp(&other.detail) {
            Ordering::Equal => {}
            order => return order,
        }
        match self.address_node.cmp(&other.address_node) {
            Ordering::Equal => {}
            order => return order,
        }
        self.pointee_globals.cmp(&other.pointee_globals)
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

fn preferred_modref_witness(existing: Option<String>, candidate: Option<String>) -> Option<String> {
    match (existing, candidate) {
        (None, witness @ Some(_)) => witness,
        (witness @ Some(_), None) => witness,
        (Some(left), Some(right)) => Some(left.min(right)),
        (None, None) => None,
    }
}

fn prefer_modref_witness_ref(existing: &mut Option<String>, candidate: Option<&str>) {
    let Some(candidate) = candidate else {
        return;
    };
    match existing {
        Some(current) if current.as_str() <= candidate => {}
        _ => *existing = Some(candidate.to_owned()),
    }
}

fn compute_transitive_modrefs(
    func_count: usize,
    _funcs: &[FuncInfo],
    globals: &[GlobalInfo],
    edges: &[CallEdge],
    local_modrefs: &[ModRef],
) -> (TransitiveModRefs, ModRefPhaseMetrics) {
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
    let mut payload_ids = BTreeMap::<ModRefFactKey, usize>::new();
    let mut payloads = Vec::<ModRefPayload>::new();
    let mut local_by_scc = vec![Vec::<usize>::new(); scc_members.len()];
    for mr in local_modrefs {
        let payload = ModRefPayload {
            global: mr.global.clone(),
            access: mr.access,
            via: mr.via,
            witness: mr.witness.clone(),
            detail: mr.detail.clone(),
            address_node: mr.address_node.clone(),
            pointee_globals: mr.pointee_globals.clone(),
        };
        let key = ModRefFactKey {
            global: mr.global.clone(),
            access_rank: access_rank(mr.access),
            via_rank: via_rank(mr.via),
            detail: mr.detail.clone(),
            address_node: mr.address_node.clone(),
            pointee_globals: mr.pointee_globals.clone(),
        };
        let id = if let Some(&id) = payload_ids.get(&key) {
            let existing = &mut payloads[id];
            existing.witness = preferred_modref_witness(existing.witness.take(), payload.witness);
            id
        } else {
            let id = payloads.len();
            payload_ids.insert(key, id);
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
    let mut metrics = ModRefPhaseMetrics::default();
    let mut fanout_by_fact = HashMap::<ModRefFanoutKey, u64>::new();
    let mut profile = PointerModRefProfile::from_env();
    profile.print_closure("closure-start", &metrics, 0, payloads.len());
    for root_idx in 0..func_count {
        let mut rows = memo[scc_of_func[root_idx]].as_ref().unwrap().clone();
        rows.sort_by(|&left, &right| {
            modref_payload_cmp(&payloads[left], &payloads[right], globals)
        });
        metrics.attempted += rows.len() as u64;
        metrics.unique += rows.len() as u64;
        for &payload_id in &rows {
            let payload = &payloads[payload_id];
            let key = ModRefFanoutKey {
                func: FuncId(root_idx as u32),
                global: payload.global.clone(),
                access_rank: access_rank(payload.access),
                via_rank: via_rank(payload.via),
            };
            let count = fanout_by_fact.entry(key).or_default();
            *count += 1;
            metrics.max_fact_fanout = metrics.max_fact_fanout.max(*count);
        }
        transitive.push(rows);
        profile.maybe_print_closure("closure-progress", &metrics, root_idx + 1, payloads.len());
    }
    profile.print_closure("closure-done", &metrics, func_count, payloads.len());
    (
        TransitiveModRefs {
            payloads,
            by_func: transitive,
        },
        metrics,
    )
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
