use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ops::Deref;
use std::rc::Rc;
use std::time::Instant;

use pangs_pag::{BuildMode as PagBuildMode, Edge, EdgeKind, Owner, Pag, PagOpts};
use pangs_pir::{
    fsa_compatible, Access, LoweringStats, Pir, ScalarOp, ScalarTypeClass, Stmt, SymbolLinkage,
};
use pangs_solve::{
    debug_assert_narrows, solve_andersen_with_overrides,
    solve_andersen_with_overrides_and_target_points_to, solve_steensgaard,
    solve_steensgaard_with_target_points_to, IndirectCallResolution, NodeResolution,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disposition_registries: Vec<RegistryApi>,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            stage: Stage::Conservative,
            build_mode: BuildMode::Library,
            exports: BTreeSet::new(),
            partition_budget: 100_000,
            enable_b1_initval: true,
            enable_b2_simple: true,
            enable_b3_confined: true,
            b2_context_depth: DEFAULT_CONTEXT_DEPTH,
            disposition_registries: Vec::new(),
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
    #[serde(skip)]
    pub address_escaped: bool,
    #[serde(skip)]
    pub escape_witness: Option<String>,
    /// Every non-own-export source by which the function object reaches external code. Kept
    /// in-process for phase-stationarity pseudo-read placement; the ordinary analysis JSON
    /// continues to expose neither this nor the preferred `escape_witness`.
    #[serde(skip)]
    pub escape_sources: Vec<String>,
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
    pub address_escaped: bool,
    pub escape_witness: Option<String>,
    pub exported: bool,
    pub is_definition: bool,
    pub linkage: SymbolLinkage,
    pub type_spelling: Option<String>,
    pub size_bits: Option<u64>,
    pub align_bits: Option<u64>,
    pub path_error: Option<String>,
    pub scalar_class: Option<ScalarTypeClass>,
    pub signed: Option<bool>,
    /// Retained for in-process disposition recipes; not part of ordinary analysis JSON.
    #[serde(skip)]
    pub initializer_ir: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
    #[serde(skip)]
    pub global_candidates: GlobalCandidateSet,
}

/// Complete in-process target scope for an unknown mod/ref row. Export abbreviation must never
/// alter this value: a large but bounded target set remains `Finite`, while `ModuleWide` is
/// reserved for accesses whose targets cannot be soundly enumerated.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum GlobalCandidateSet {
    Finite(Rc<[GlobalId]>),
    ModuleWide,
}

impl Default for GlobalCandidateSet {
    fn default() -> Self {
        Self::ModuleWide
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AffectedGlobals<'a> {
    Finite(&'a [GlobalId]),
    ModuleWide,
}

/// Unaggregated local memory-access provenance retained for refactoring clients. Unlike
/// `ModRef`, this records every analyzed site and is never serialized in ordinary analysis
/// output. Unknown pointer targets are expanded over the client-visible global universe.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AccessSite {
    pub func: FuncId,
    pub global: GlobalId,
    pub access: Access,
    pub via: Via,
    pub volatile: bool,
    pub atomic_rmw: Option<AtomicRmwAccess>,
    pub loc: Option<LocInfo>,
    pub statement_index: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AtomicRmwAccess {
    pub op: ScalarOp,
    pub operand: String,
    pub reference_statement_index: u32,
    pub operation_statement_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GlobalTarget {
    Name(GlobalId),
    Unknown(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
    #[serde(skip)]
    pub function: Option<FuncId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryKind {
    Spawn,
    Signal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryApi {
    pub name: String,
    pub kind: RegistryKind,
    pub entry: RegistryEntryOperand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RegistryEntryOperand {
    Arg { arg: usize },
    PointeeOfArg { pointee_of_arg: usize },
}

#[derive(Debug, Clone)]
pub struct RegistryEntryResolution {
    pub kind: RegistryKind,
    pub targets: Vec<FuncId>,
    pub unresolved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StationarityVerdict {
    pub global: GlobalId,
    pub complete_initval: bool,
    pub stationary: bool,
    pub reason: StationarityReason,
    pub runtime_writers: StationarityWriters,
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

#[derive(Debug, Clone, Default)]
pub struct StationarityWriters(Rc<[StationarityWriter]>);

impl StationarityWriters {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, StationarityWriter> {
        self.0.iter()
    }
}

impl From<Vec<StationarityWriter>> for StationarityWriters {
    fn from(writers: Vec<StationarityWriter>) -> Self {
        Self(Rc::from(writers))
    }
}

impl Deref for StationarityWriters {
    type Target = [StationarityWriter];

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl Serialize for StationarityWriters {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.as_ref().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for StationarityWriters {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<StationarityWriter>::deserialize(deserializer).map(Self::from)
    }
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
    #[serde(default)]
    pub pointer_modref_high_fanout_fallbacks: u64,
    #[serde(default)]
    pub pointer_modref_high_fanout_fallback_rows: u64,
    #[serde(default)]
    pub pointer_modref_closure_high_fanout_fallbacks: u64,
    #[serde(default)]
    pub pointer_modref_closure_high_fanout_fallback_rows: u64,
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
    #[serde(skip)]
    callees_by_callsite: Vec<Vec<Callee>>,
    #[serde(skip)]
    callers_by_function: Vec<Vec<Caller>>,
    modrefs: Vec<ModRef>,
    #[serde(skip)]
    direct_writes_by_function: Vec<Vec<GlobalId>>,
    #[serde(skip)]
    directly_written_globals: Vec<GlobalId>,
    #[serde(skip)]
    access_sites: Vec<AccessSite>,
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
    #[serde(skip)]
    registry_entries: BTreeMap<CallsiteId, RegistryEntryResolution>,
    #[serde(skip)]
    registry_apis: Vec<RegistryApi>,
}

impl Analysis {
    /// Returns the complete semantic target scope of a mod/ref row. Clients must use this rather
    /// than interpreting an abbreviated `pointee_globals` export.
    pub fn affected_globals<'a>(&'a self, row: &'a ModRef) -> AffectedGlobals<'a> {
        match &row.global {
            GlobalTarget::Name(global) => AffectedGlobals::Finite(std::slice::from_ref(global)),
            GlobalTarget::Unknown(_) => match &row.global_candidates {
                GlobalCandidateSet::Finite(globals) => AffectedGlobals::Finite(globals),
                GlobalCandidateSet::ModuleWide => AffectedGlobals::ModuleWide,
            },
        }
    }

    pub fn run(module: &Pir, opts: &Opts) -> Result<Self, AnalysisError> {
        Self::run_internal(module, opts, false)
    }

    pub fn run_with_disposition(module: &Pir, opts: &Opts) -> Result<Self, AnalysisError> {
        Self::run_internal(module, opts, true)
    }

    fn run_internal(
        module: &Pir,
        opts: &Opts,
        disposition_facts: bool,
    ) -> Result<Self, AnalysisError> {
        let analysis_started = Instant::now();
        let registry_apis = if disposition_facts {
            effective_registry_apis(&opts.disposition_registries)
        } else {
            Vec::new()
        };
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
                address_escaped: false,
                escape_witness: None,
                escape_sources: Vec::new(),
                vararg: func.vararg(),
                sig: signature_text(&func.sig),
            });
        }

        let mut global_lookup = HashMap::new();
        let mut globals = Vec::new();
        let mut external_storage_globals = BTreeSet::new();
        for global in &module.globals {
            if is_ignored_client_global(&global.key) {
                continue;
            }
            let gid = GlobalId(globals.len() as u32);
            if global_lookup.insert(global.key.clone(), gid).is_some() {
                return Err(AnalysisError::DuplicateGlobal(global.key.clone()));
            }
            let exported = is_exported_global(global.exported, &global.key, opts);
            if exported {
                external_storage_globals.insert(global.key.clone());
            }
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
                address_escaped: false,
                escape_witness: None,
                exported,
                is_definition: global.is_definition,
                linkage: global.linkage,
                type_spelling: global.type_spelling.clone(),
                size_bits: global.size_bits,
                align_bits: global.align_bits,
                path_error: global.path_error.clone(),
                scalar_class: global.scalar_class,
                signed: global.signed,
                initializer_ir: global.initializer_ir.clone(),
            });
        }

        let mut callsites = Vec::new();
        let mut call_edges = Vec::new();
        let mut modrefs = ModRefBuilder::new();
        let mut access_sites = Vec::new();
        let mut findings = Vec::new();
        let mut audit_taints = BTreeMap::<FuncId, Vec<Taint>>::new();
        let mut deferred_audits = Vec::<DeferredAudit>::new();
        let mut indirect_callsites = Vec::new();
        let mut simple_icall_queries = Vec::new();
        let mut solver_metrics = None;
        let mut registry_entries = BTreeMap::new();
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
                        volatile,
                        loc,
                    } => {
                        if let Some(&gid) = global_lookup.get(global) {
                            access_sites.push(AccessSite {
                                func: caller,
                                global: gid,
                                access: *access,
                                via: Via::Direct,
                                volatile: *volatile,
                                atomic_rmw: (*access == Access::Mod)
                                    .then(|| direct_atomic_rmw(&func.body, stmt_idx, global))
                                    .flatten(),
                                loc: loc.as_ref().map(loc_info),
                                statement_index: Some(stmt_idx as u32),
                            });
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
                                global_candidates: GlobalCandidateSet::Finite(Rc::from([])),
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
                    if functions[idx].address_taken && !func.external {
                        functions[idx].address_escaped = true;
                        functions[idx].escape_witness = Some("conservative-address-taken".into());
                        functions[idx].escape_sources = vec!["conservative-address-taken".into()];
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
                let mut registry_labels = if disposition_facts {
                    registry_target_labels(&pag, None, &registry_apis)
                } else {
                    BTreeSet::new()
                };
                let solve_started = Instant::now();
                let mut solved = match opts.stage {
                    Stage::Andersen if !registry_labels.is_empty() => {
                        solve_andersen_with_overrides_and_target_points_to(
                            module,
                            &pag,
                            opts.build_mode.into(),
                            opts.partition_budget,
                            &simple_exact_targets,
                            confined_functions,
                            &registry_labels,
                        )
                    }
                    Stage::Andersen => solve_andersen_with_overrides(
                        module,
                        &pag,
                        opts.build_mode.into(),
                        opts.partition_budget,
                        &simple_exact_targets,
                        confined_functions,
                    ),
                    _ if !registry_labels.is_empty() => solve_steensgaard_with_target_points_to(
                        module,
                        &pag,
                        opts.build_mode.into(),
                        &registry_labels,
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
                    registry_labels = if disposition_facts {
                        registry_target_labels(&pag, None, &registry_apis)
                    } else {
                        BTreeSet::new()
                    };
                    let solve_started = Instant::now();
                    solved = match opts.stage {
                        Stage::Andersen if !registry_labels.is_empty() => {
                            solve_andersen_with_overrides_and_target_points_to(
                                module,
                                &pag,
                                opts.build_mode.into(),
                                opts.partition_budget,
                                &simple_exact_targets,
                                confined_functions,
                                &registry_labels,
                            )
                        }
                        Stage::Andersen => solve_andersen_with_overrides(
                            module,
                            &pag,
                            opts.build_mode.into(),
                            opts.partition_budget,
                            &simple_exact_targets,
                            confined_functions,
                        ),
                        _ if !registry_labels.is_empty() => {
                            solve_steensgaard_with_target_points_to(
                                module,
                                &pag,
                                opts.build_mode.into(),
                                &registry_labels,
                            )
                        }
                        _ => solve_steensgaard(module, &pag, opts.build_mode.into()),
                    };
                    solve_us += solve_started.elapsed().as_micros() as u64;
                }
                if disposition_facts {
                    // Direct calls identify their designated operands before solving. An
                    // indirect call can only be recognized as a registry call from the final
                    // call graph, so perform one bounded narrow re-solve when that discovers
                    // additional operand labels. No all-node points-to export is involved.
                    let expanded_labels =
                        registry_target_labels(&pag, Some(&solved), &registry_apis);
                    if expanded_labels != registry_labels {
                        registry_labels = expanded_labels;
                        let solve_started = Instant::now();
                        solved = match opts.stage {
                            Stage::Andersen => solve_andersen_with_overrides_and_target_points_to(
                                module,
                                &pag,
                                opts.build_mode.into(),
                                opts.partition_budget,
                                &simple_exact_targets,
                                confined_functions,
                                &registry_labels,
                            ),
                            _ => solve_steensgaard_with_target_points_to(
                                module,
                                &pag,
                                opts.build_mode.into(),
                                &registry_labels,
                            ),
                        };
                        solve_us += solve_started.elapsed().as_micros() as u64;
                    }
                }
                let safe_indirect_varargs =
                    safe_indirect_vararg_callsites(module, &indirect_vararg_keys, &solved);
                if disposition_facts {
                    registry_entries = resolve_registry_entries(
                        &pag,
                        &solved,
                        &func_lookup,
                        &registry_apis,
                        &registry_labels,
                    );
                }
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

                for function in &mut functions {
                    if let Some(state) = solved.function_escapes.get(&function.key) {
                        function.address_escaped = state.address_escape;
                        let own_export = format!("exported-symbol:obj:function:{}", function.key);
                        function.escape_witness = state
                            .escape_sources
                            .iter()
                            .find(|source| *source != &own_export)
                            .cloned();
                        function.escape_sources = state
                            .escape_sources
                            .iter()
                            .filter(|source| *source != &own_export)
                            .cloned()
                            .collect();
                    }
                }

                for global in &mut globals {
                    if let Some(state) = solved.globals.get(&global.key) {
                        global.escape = if state.escape_external {
                            EscapeStatus::External
                        } else {
                            EscapeStatus::Module
                        };
                        global.address_escaped = state.address_escape;
                        let own_export = format!("exported-symbol:obj:global:{}", global.key);
                        global.escape_witness = state
                            .escape_sources
                            .iter()
                            .find(|source| *source != &own_export)
                            .cloned();
                        global.never_written = state.never_written;
                    }
                }
                mark_external_storage_globals(
                    &mut external_storage_globals,
                    module,
                    &global_lookup,
                    &solved.nodes,
                );
                solver_postprocess_us = solver_postprocess_started.elapsed().as_micros() as u64;

                let pointer_modref_started = Instant::now();
                modrefs.print_profile("local-start");
                push_pointer_modrefs_from_pag(
                    &mut modrefs,
                    &mut access_sites,
                    &func_lookup,
                    &global_lookup,
                    &pag,
                    &solved.nodes,
                    &mut noloc_ord,
                );
                modrefs.print_profile("after-pag");
                push_pointer_memcpy_constexpr_modrefs_from_pir(
                    &mut modrefs,
                    &mut access_sites,
                    module,
                    &func_lookup,
                    &global_lookup,
                    &mut noloc_ord,
                );
                push_pointer_memset_modrefs_from_pir(
                    &mut modrefs,
                    &mut access_sites,
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
        call_edges.sort_by(|left, right| call_edge_cmp(left, right, &functions, &callsites));
        call_edges
            .dedup_by(|left, right| call_edge_cmp(left, right, &functions, &callsites).is_eq());
        let callgraph_dedup_us = callgraph_dedup_started.elapsed().as_micros() as u64;
        let modref_dedup_started = Instant::now();
        let mut pointer_modref_metrics = modrefs.metrics();
        let modrefs = modrefs.into_vec();
        access_sites.sort_by(|left, right| {
            (
                left.func,
                left.global,
                left.statement_index,
                &left.loc,
                left.access,
                left.via,
            )
                .cmp(&(
                    right.func,
                    right.global,
                    right.statement_index,
                    &right.loc,
                    right.access,
                    right.via,
                ))
        });
        let indexed_locations = access_sites
            .iter()
            .filter(|site| site.statement_index.is_some())
            .map(|site| {
                (
                    site.func,
                    site.global,
                    site.access,
                    site.via,
                    site.loc.clone(),
                )
            })
            .collect::<BTreeSet<_>>();
        access_sites.retain(|site| {
            site.statement_index.is_some()
                || !indexed_locations.contains(&(
                    site.func,
                    site.global,
                    site.access,
                    site.via,
                    site.loc.clone(),
                ))
        });
        access_sites.dedup();
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
                &external_storage_globals,
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
            pointer_modref_high_fanout_fallbacks: pointer_modref_metrics.high_fanout_fallbacks,
            pointer_modref_high_fanout_fallback_rows: pointer_modref_metrics
                .high_fanout_fallback_rows,
            pointer_modref_closure_high_fanout_fallbacks: pointer_modref_metrics
                .closure_high_fanout_fallbacks,
            pointer_modref_closure_high_fanout_fallback_rows: pointer_modref_metrics
                .closure_high_fanout_fallback_rows,
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

        let mut callees_by_callsite = vec![Vec::new(); callsites.len()];
        let mut callers_by_function = vec![Vec::new(); functions.len()];
        for edge in &call_edges {
            if let Some(callsite) = edge.callsite {
                callees_by_callsite[callsite.0 as usize].push(edge.callee.clone());
            }
            if let Callee::Func(callee) = edge.callee {
                callers_by_function[callee.0 as usize].push(edge.caller.clone());
            }
        }
        let mut direct_writes_by_function = vec![Vec::new(); functions.len()];
        let mut directly_written = vec![false; globals.len()];
        for row in &modrefs {
            if row.access == Access::Mod && row.via == Via::Direct {
                let GlobalTarget::Name(global) = row.global else {
                    continue;
                };
                direct_writes_by_function[row.func.0 as usize].push(global);
                directly_written[global.0 as usize] = true;
            }
        }
        for writes in &mut direct_writes_by_function {
            writes.sort_unstable();
            writes.dedup();
        }
        let directly_written_globals = directly_written
            .into_iter()
            .enumerate()
            .filter_map(|(index, written)| written.then_some(GlobalId(index as u32)))
            .collect();

        Ok(Self {
            functions: Table::new(functions),
            globals: Table::new(globals),
            callsites: Table::new(callsites),
            call_edges,
            callees_by_callsite,
            callers_by_function,
            modrefs,
            direct_writes_by_function,
            directly_written_globals,
            access_sites,
            stationarity,
            transitive_modrefs,
            components,
            findings,
            metrics,
            func_lookup,
            global_lookup,
            registry_entries,
            registry_apis,
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

    pub fn direct_writes(&self, function: FuncId) -> &[GlobalId] {
        &self.direct_writes_by_function[function.0 as usize]
    }

    pub fn directly_written_globals(&self) -> &[GlobalId] {
        &self.directly_written_globals
    }

    pub fn access_sites(&self) -> &[AccessSite] {
        &self.access_sites
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

    pub fn registry_entry(&self, callsite: CallsiteId) -> Option<&RegistryEntryResolution> {
        self.registry_entries.get(&callsite)
    }

    /// Effective spawn/signal registry definitions for this analysis run (built-ins with
    /// configured replacements/extensions applied). Policy clients use this single registry
    /// source rather than duplicating names or operand conventions.
    pub fn registry_apis(&self) -> &[RegistryApi] {
        &self.registry_apis
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
        self.callees_by_callsite
            .get(cs.0 as usize)
            .into_iter()
            .flatten()
    }

    pub fn callers(&self, func: FuncId) -> impl Iterator<Item = &Caller> {
        self.callers_by_function
            .get(func.0 as usize)
            .into_iter()
            .flatten()
    }

    pub fn modref(&self, func: FuncId) -> impl Iterator<Item = ModRef> + '_ {
        self.transitive_modrefs.iter(func)
    }

    /// Borrowed transitive access summaries for clients that only need target scope and access
    /// kind.  This avoids cloning full mod/ref provenance (including strings and candidate sets)
    /// merely to inspect a registry callback's global effects.
    pub fn transitive_accesses(
        &self,
        func: FuncId,
    ) -> impl Iterator<Item = (Access, AffectedGlobals<'_>)> + '_ {
        self.transitive_modrefs.iter_payloads(func).map(|payload| {
            let affected = match &payload.global {
                GlobalTarget::Name(global) => AffectedGlobals::Finite(std::slice::from_ref(global)),
                GlobalTarget::Unknown(_) => match &payload.global_candidates {
                    GlobalCandidateSet::Finite(globals) => AffectedGlobals::Finite(globals),
                    GlobalCandidateSet::ModuleWide => AffectedGlobals::ModuleWide,
                },
            };
            (payload.access, affected)
        })
    }

    pub fn modref_count(&self, func: FuncId) -> usize {
        self.transitive_modrefs.row_count(func)
    }

    pub fn transitive_modref_count(&self) -> usize {
        self.transitive_modrefs.total_row_count()
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
                    runtime_writers: StationarityWriters::default(),
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
    external_storage_globals: &BTreeSet<String>,
    modrefs: &[ModRef],
) -> (BTreeSet<String>, Vec<StationarityVerdict>) {
    let mut unknown_writers = Vec::<StationarityWriter>::new();
    for mr in modrefs {
        if is_module_unknown_stationarity_writer(mr) {
            unknown_writers.push(stationarity_writer_from_modref(mr));
        }
    }
    unknown_writers.sort_by(stationarity_writer_cmp);
    unknown_writers.dedup_by(|left, right| stationarity_writer_cmp(left, right) == Ordering::Equal);
    let unknown_writers = StationarityWriters::from(unknown_writers);
    let (runtime_writers, target_unknown_writers) = if unknown_writers.is_empty() {
        collect_targeted_stationarity_writers(modrefs, globals, global_lookup)
    } else {
        (BTreeMap::new(), BTreeMap::new())
    };

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
        let mut writers = StationarityWriters::default();
        let reason = if !complete_initval
            && !(absence_only_initval
                && !external_storage_globals.contains(&global.key)
                && unknown_writers.is_empty()
                && !runtime_writers.contains_key(&global.key))
        {
            StationarityReason::IncompleteInitval
        } else if !unknown_writers.is_empty() {
            writers = unknown_writers.clone();
            StationarityReason::UnknownRuntimeWriter
        } else if let Some(known_unknown_writers) = target_unknown_writers.get(&global.key) {
            writers = known_unknown_writers.clone();
            StationarityReason::UnknownRuntimeWriter
        } else if external_storage_globals.contains(&global.key) {
            StationarityReason::ExportedGlobal
        } else if let Some(known_writers) = runtime_writers.get(&global.key) {
            writers = known_writers.clone();
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

fn collect_targeted_stationarity_writers(
    modrefs: &[ModRef],
    globals: &[GlobalInfo],
    _global_lookup: &HashMap<String, GlobalId>,
) -> (
    BTreeMap<String, StationarityWriters>,
    BTreeMap<String, StationarityWriters>,
) {
    let mut runtime_writers = BTreeMap::<String, Vec<StationarityWriter>>::new();
    let mut target_unknown_writer_groups =
        BTreeMap::<Vec<GlobalId>, Vec<StationarityWriter>>::new();
    for mr in modrefs {
        if mr.access != Access::Mod {
            continue;
        }
        match &mr.global {
            GlobalTarget::Name(gid) => {
                runtime_writers
                    .entry(globals[gid.0 as usize].key.clone())
                    .or_default()
                    .push(stationarity_writer_from_modref(mr));
            }
            GlobalTarget::Unknown(_) if matches!(&mr.global_candidates, GlobalCandidateSet::Finite(ids) if !ids.is_empty()) =>
            {
                let GlobalCandidateSet::Finite(ids) = &mr.global_candidates else {
                    unreachable!()
                };
                let targets = stationarity_target_key_from_ids(ids, globals);
                if !targets.is_empty() {
                    target_unknown_writer_groups
                        .entry(targets)
                        .or_default()
                        .push(stationarity_writer_from_modref(mr));
                }
            }
            GlobalTarget::Unknown(_) => {}
        }
    }
    for writers in runtime_writers.values_mut() {
        writers.sort_by(stationarity_writer_cmp);
        writers.dedup_by(|left, right| stationarity_writer_cmp(left, right) == Ordering::Equal);
    }
    for writers in target_unknown_writer_groups.values_mut() {
        writers.sort_by(stationarity_writer_cmp);
        writers.dedup_by(|left, right| stationarity_writer_cmp(left, right) == Ordering::Equal);
    }
    let mut target_unknown_groups_by_global = BTreeMap::<GlobalId, Vec<StationarityWriters>>::new();
    for (targets, writers) in target_unknown_writer_groups {
        let writers = StationarityWriters::from(writers);
        for gid in targets {
            target_unknown_groups_by_global
                .entry(gid)
                .or_default()
                .push(writers.clone());
        }
    }
    let target_unknown_writers: BTreeMap<String, StationarityWriters> =
        target_unknown_groups_by_global
            .into_iter()
            .filter_map(|(gid, groups)| {
                globals.get(gid.0 as usize).map(|global| {
                    let writers = merge_stationarity_writer_groups(groups);
                    (global.key.clone(), writers)
                })
            })
            .collect();
    (
        runtime_writers
            .into_iter()
            .map(|(global, writers)| (global, StationarityWriters::from(writers)))
            .collect(),
        target_unknown_writers
            .into_iter()
            .map(|(global, writers)| (global, StationarityWriters::from(writers)))
            .collect(),
    )
}

fn stationarity_target_key_from_ids(ids: &[GlobalId], globals: &[GlobalInfo]) -> Vec<GlobalId> {
    let mut targets = ids
        .iter()
        .copied()
        .filter(|gid| globals.get(gid.0 as usize).is_some())
        .collect::<Vec<_>>();
    targets.sort();
    targets.dedup();
    targets
}

fn merge_stationarity_writer_groups(groups: Vec<StationarityWriters>) -> StationarityWriters {
    if groups.len() == 1 {
        return groups.into_iter().next().unwrap();
    }
    let mut writers = groups
        .iter()
        .flat_map(|group| group.iter().cloned())
        .collect::<Vec<_>>();
    writers.sort_by(stationarity_writer_cmp);
    writers.dedup_by(|left, right| stationarity_writer_cmp(left, right) == Ordering::Equal);
    StationarityWriters::from(writers)
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

fn is_module_unknown_stationarity_writer(mr: &ModRef) -> bool {
    if mr.access != Access::Mod || !matches!(mr.global, GlobalTarget::Unknown(_)) {
        return false;
    }
    matches!(mr.global_candidates, GlobalCandidateSet::ModuleWide)
        && unknown_modref_may_touch_module_global(mr)
}

fn unknown_modref_may_touch_module_global(mr: &ModRef) -> bool {
    match &mr.global_candidates {
        GlobalCandidateSet::Finite(globals) => return !globals.is_empty(),
        GlobalCandidateSet::ModuleWide => {}
    }
    let Some(detail) = mr.detail.as_deref() else {
        return true;
    };
    if detail.starts_with("high_fanout_pointer_modref:") {
        return true;
    }
    if detail.contains("omega:inttoptr") || detail.contains("omega:ptrtoint_escape") {
        return true;
    }
    if let Some(count) = detail_pointee_count(detail) {
        return count > 0;
    }
    false
}

fn detail_pointee_count(detail: &str) -> Option<usize> {
    let suffix = detail.rsplit('|').find_map(|part| {
        part.strip_prefix("pointee_count=")
            .and_then(|value| value.parse::<usize>().ok())
    });
    suffix
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

fn mark_external_storage_globals(
    external_storage_globals: &mut BTreeSet<String>,
    module: &Pir,
    global_lookup: &HashMap<String, GlobalId>,
    nodes: &BTreeMap<String, NodeResolution>,
) {
    for global in &module.globals {
        if !global_lookup.contains_key(&global.key) {
            continue;
        }
        if global_symbol_labels(&global.key)
            .iter()
            .any(|label| nodes.get(label).is_some_and(|node| node.external))
        {
            external_storage_globals.insert(global.key.clone());
        }
    }
}

fn global_symbol_labels(key: &str) -> Vec<String> {
    let mut labels = vec![format!("sym:global:{key}")];
    if !key.starts_with('@') {
        labels.push(format!("sym:global:@{key}"));
    }
    labels
}

fn is_ignored_client_global(key: &str) -> bool {
    let key = key.strip_prefix('@').unwrap_or(key);
    key.starts_with(".str") || key.starts_with("__PRETTY_FUNCTION__") || key.starts_with("__const")
}

fn signature_text(sig: &pangs_pir::Signature) -> String {
    format!("{:?}({:?})", sig.ret, sig.params)
}

fn direct_atomic_rmw(body: &[Stmt], mod_ref_index: usize, global: &str) -> Option<AtomicRmwAccess> {
    let store_index = mod_ref_index.checked_sub(1)?;
    let Stmt::Store {
        address,
        value,
        loc: store_loc,
    } = &body[store_index]
    else {
        return None;
    };
    if !same_global_address(address, global) {
        return None;
    }
    let operation_index = store_index.checked_sub(1)?;
    let Stmt::ScalarOp {
        dest,
        op,
        lhs,
        rhs,
        loc: operation_loc,
    } = &body[operation_index]
    else {
        return None;
    };
    if dest != value || operation_loc != store_loc {
        return None;
    }

    let (loaded, operand) = match op {
        ScalarOp::Sub => (lhs, rhs),
        ScalarOp::Add | ScalarOp::And | ScalarOp::Or | ScalarOp::Xor => {
            if scalar_value_is_direct_global_load(body, operation_index, lhs, global, store_loc) {
                (lhs, rhs)
            } else {
                (rhs, lhs)
            }
        }
    };
    let reference_index =
        direct_global_load_reference(body, operation_index, loaded, global, store_loc)?;
    Some(AtomicRmwAccess {
        op: *op,
        operand: operand.clone(),
        reference_statement_index: reference_index as u32,
        operation_statement_index: operation_index as u32,
    })
}

fn scalar_value_is_direct_global_load(
    body: &[Stmt],
    before: usize,
    value: &str,
    global: &str,
    loc: &Option<pangs_pir::Loc>,
) -> bool {
    direct_global_load_reference(body, before, value, global, loc).is_some()
}

fn direct_global_load_reference(
    body: &[Stmt],
    before: usize,
    value: &str,
    global: &str,
    loc: &Option<pangs_pir::Loc>,
) -> Option<usize> {
    let load_index = (0..before).rev().find(|&index| {
        matches!(
            &body[index],
            Stmt::Load { dest, address, loc: load_loc }
                if dest == value && same_global_address(address, global) && load_loc == loc
        )
    })?;
    let reference_index = (load_index + 1..before).find(|&index| {
        matches!(
            &body[index],
            Stmt::GlobalRef {
                global: reference_global,
                access: Access::Ref,
                loc: reference_loc,
                ..
            } if reference_global == global && reference_loc == loc
        )
    })?;
    Some(reference_index)
}

fn same_global_address(address: &str, global: &str) -> bool {
    address.strip_prefix('@').unwrap_or(address) == global.strip_prefix('@').unwrap_or(global)
}

fn loc_info(loc: &pangs_pir::Loc) -> LocInfo {
    LocInfo {
        file: loc.file.clone(),
        line: loc.line,
        col: loc.col,
    }
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

fn call_edge_cmp(
    left: &CallEdge,
    right: &CallEdge,
    funcs: &[FuncInfo],
    callsites: &[CallsiteInfo],
) -> Ordering {
    caller_label_cmp(&left.caller, &right.caller, funcs)
        .then_with(|| callsite_label_cmp(left.callsite, right.callsite, callsites))
        .then_with(|| callee_label_cmp(&left.callee, &right.callee, funcs))
        .then_with(|| call_kind_label(left.kind).cmp(call_kind_label(right.kind)))
        .then_with(|| tier_label(left.tier).cmp(tier_label(right.tier)))
}

fn caller_label_cmp(left: &Caller, right: &Caller, funcs: &[FuncInfo]) -> Ordering {
    match (left, right) {
        (Caller::Func(left), Caller::Func(right)) => {
            funcs[left.0 as usize].key.cmp(&funcs[right.0 as usize].key)
        }
        (Caller::Unknown(left), Caller::Unknown(right)) => left.cmp(right),
        (Caller::Func(left), Caller::Unknown(right)) => {
            str_cmp_chunks(&[funcs[left.0 as usize].key.as_str()], &["unknown:", right])
        }
        (Caller::Unknown(left), Caller::Func(right)) => {
            str_cmp_chunks(&["unknown:", left], &[funcs[right.0 as usize].key.as_str()])
        }
    }
}

fn callee_label_cmp(left: &Callee, right: &Callee, funcs: &[FuncInfo]) -> Ordering {
    match (left, right) {
        (Callee::Func(left), Callee::Func(right)) => {
            funcs[left.0 as usize].key.cmp(&funcs[right.0 as usize].key)
        }
        (Callee::Unknown(left), Callee::Unknown(right)) => left.cmp(right),
        (Callee::Func(left), Callee::Unknown(right)) => {
            str_cmp_chunks(&[funcs[left.0 as usize].key.as_str()], &["unknown:", right])
        }
        (Callee::Unknown(left), Callee::Func(right)) => {
            str_cmp_chunks(&["unknown:", left], &[funcs[right.0 as usize].key.as_str()])
        }
    }
}

fn callsite_label_cmp(
    left: Option<CallsiteId>,
    right: Option<CallsiteId>,
    callsites: &[CallsiteInfo],
) -> Ordering {
    let left = left
        .map(|id| callsites[id.0 as usize].key.as_str())
        .unwrap_or_default();
    let right = right
        .map(|id| callsites[id.0 as usize].key.as_str())
        .unwrap_or_default();
    left.cmp(right)
}

fn call_kind_label(kind: CallKind) -> &'static str {
    match kind {
        CallKind::Direct => "Direct",
        CallKind::Indirect => "Indirect",
    }
}

fn tier_label(tier: Tier) -> &'static str {
    match tier {
        Tier::Direct => "Direct",
        Tier::Fsa => "Fsa",
        Tier::Steens => "Steens",
        Tier::Andersen => "Andersen",
        Tier::Simple => "Simple",
    }
}

fn str_cmp_chunks(left: &[&str], right: &[&str]) -> Ordering {
    // Allocation-free equivalent of `left.concat().cmp(&right.concat())`.
    let mut left_chunks = left.iter();
    let mut right_chunks = right.iter();
    let mut left_bytes = left_chunks.next().map(|chunk| chunk.as_bytes());
    let mut right_bytes = right_chunks.next().map(|chunk| chunk.as_bytes());
    let mut left_index = 0;
    let mut right_index = 0;

    loop {
        match (left_bytes, right_bytes) {
            (Some(left), Some(right)) => {
                let left_remaining = &left[left_index..];
                let right_remaining = &right[right_index..];
                let shared_len = left_remaining.len().min(right_remaining.len());
                let cmp = left_remaining[..shared_len].cmp(&right_remaining[..shared_len]);
                if !cmp.is_eq() {
                    return cmp;
                }
                left_index += shared_len;
                right_index += shared_len;
                if left_index == left.len() {
                    left_bytes = left_chunks.next().map(|chunk| chunk.as_bytes());
                    left_index = 0;
                }
                if right_index == right.len() {
                    right_bytes = right_chunks.next().map(|chunk| chunk.as_bytes());
                    right_index = 0;
                }
            }
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (None, None) => return Ordering::Equal,
        }
    }
}

#[cfg(test)]
mod callgraph_sort_tests {
    use super::*;

    #[test]
    fn call_edge_cmp_matches_allocated_sort_key_order() {
        let funcs = vec![
            FuncInfo {
                key: "alpha".to_string(),
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                address_escaped: false,
                escape_witness: None,
                escape_sources: Vec::new(),
                vararg: false,
                sig: "void()".to_string(),
            },
            FuncInfo {
                key: "unknown:zeta".to_string(),
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                address_escaped: false,
                escape_witness: None,
                escape_sources: Vec::new(),
                vararg: false,
                sig: "void()".to_string(),
            },
        ];
        let callsites = vec![
            CallsiteInfo {
                key: "alpha@!noloc#0".to_string(),
                caller: FuncId(0),
                kind: CallKind::Direct,
                loc: None,
                synthetic: true,
            },
            CallsiteInfo {
                key: "alpha@!noloc#1".to_string(),
                caller: FuncId(0),
                kind: CallKind::Indirect,
                loc: None,
                synthetic: true,
            },
        ];
        let edges = vec![
            CallEdge {
                caller: Caller::Func(FuncId(0)),
                callsite: Some(CallsiteId(1)),
                callee: Callee::Unknown("omega_fnptr".to_string()),
                kind: CallKind::Indirect,
                tier: Tier::Steens,
            },
            CallEdge {
                caller: Caller::Unknown("address_escapes_to_external".to_string()),
                callsite: None,
                callee: Callee::Func(FuncId(1)),
                kind: CallKind::Direct,
                tier: Tier::Fsa,
            },
            CallEdge {
                caller: Caller::Func(FuncId(1)),
                callsite: Some(CallsiteId(0)),
                callee: Callee::Func(FuncId(0)),
                kind: CallKind::Direct,
                tier: Tier::Direct,
            },
            CallEdge {
                caller: Caller::Func(FuncId(0)),
                callsite: Some(CallsiteId(0)),
                callee: Callee::Func(FuncId(1)),
                kind: CallKind::Direct,
                tier: Tier::Direct,
            },
        ];

        let mut allocated_key_order = edges.clone();
        allocated_key_order.sort_by_key(|edge| {
            (
                match &edge.caller {
                    Caller::Func(id) => funcs[id.0 as usize].key.clone(),
                    Caller::Unknown(reason) => format!("unknown:{reason}"),
                },
                edge.callsite
                    .map(|id| callsites[id.0 as usize].key.clone())
                    .unwrap_or_default(),
                match &edge.callee {
                    Callee::Func(id) => funcs[id.0 as usize].key.clone(),
                    Callee::Unknown(reason) => format!("unknown:{reason}"),
                },
                format!("{:?}{:?}", edge.kind, edge.tier),
            )
        });

        let mut borrowed_cmp_order = edges;
        borrowed_cmp_order.sort_by(|left, right| call_edge_cmp(left, right, &funcs, &callsites));

        assert_eq!(
            allocated_key_order
                .iter()
                .map(|edge| format!("{edge:?}"))
                .collect::<Vec<_>>(),
            borrowed_cmp_order
                .iter()
                .map(|edge| format!("{edge:?}"))
                .collect::<Vec<_>>()
        );
    }
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
        function: Some(caller),
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

#[derive(Debug, Clone, Copy, Default)]
struct CompactModRefFanoutCounts {
    total: u64,
    pag: u64,
    mem: u64,
}

impl CompactModRefFanoutCounts {
    fn phase_mut(&mut self, phase: ModRefSourcePhase) -> &mut u64 {
        match phase {
            ModRefSourcePhase::PagPointer => &mut self.pag,
            ModRefSourcePhase::MemsetMemcpy => &mut self.mem,
        }
    }
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
    compact_fanout_by_fact: HashMap<CompactModRefFactKey, CompactModRefFanoutCounts>,
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
                merge_global_candidates(&mut existing.global_candidates, row.global_candidates);
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
            merge_global_candidates(&mut existing.global_candidates, row.global_candidates);
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
        let key = CompactModRefFactKey {
            func: func.0,
            global: global.0,
            access_rank: access_rank(access),
            via_rank: via_rank(via),
        };
        self.note_compact_modref_fanout(key, phase);
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
            global_candidates: GlobalCandidateSet::Finite(Rc::from([])),
        });
        self.note_modref_result(phase, true);
    }

    fn metrics(&self) -> ModRefEmissionMetrics {
        self.metrics.clone()
    }

    fn note_modref_attempt(&mut self, row: &ModRef, phase: Option<ModRefSourcePhase>) {
        if let Some(key) = compact_modref_key(row) {
            self.note_compact_modref_fanout(key, phase);
            return;
        }
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

    fn note_compact_modref_fanout(
        &mut self,
        fanout_key: CompactModRefFactKey,
        phase: Option<ModRefSourcePhase>,
    ) {
        self.note_compact_modref_fanout_count(fanout_key, phase, 1);
    }

    fn note_compact_modref_fanout_count(
        &mut self,
        fanout_key: CompactModRefFactKey,
        phase: Option<ModRefSourcePhase>,
        delta: u64,
    ) {
        if delta == 0 {
            return;
        }
        let counts = self.compact_fanout_by_fact.entry(fanout_key).or_default();
        counts.total += delta;
        self.metrics.pointer_modref_max_fact_fanout = self
            .metrics
            .pointer_modref_max_fact_fanout
            .max(counts.total);
        let Some(phase) = phase else {
            return;
        };
        self.metrics.phase_mut(phase).attempted += delta;
        let phase_count = counts.phase_mut(phase);
        *phase_count += delta;
        let phase_metrics = self.metrics.phase_mut(phase);
        phase_metrics.max_fact_fanout = phase_metrics.max_fact_fanout.max(*phase_count);
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
        let fanout_key = CompactModRefFactKey {
            func: func.0,
            global: global.0,
            access_rank: access_rank(access),
            via_rank: via_rank(via),
        };
        self.note_compact_modref_fanout_count(fanout_key, Some(phase), duplicate_count);
        self.metrics.phase_mut(phase).duplicate += duplicate_count;
        self.maybe_print_profile("progress");
    }

    fn note_high_fanout_fallback(&mut self, collapsed_rows: u64) {
        self.metrics.high_fanout_fallbacks += 1;
        self.metrics.high_fanout_fallback_rows = self
            .metrics
            .high_fanout_fallback_rows
            .saturating_add(collapsed_rows);
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
    high_fanout_fallbacks: u64,
    high_fanout_fallback_rows: u64,
}

#[derive(Debug, Clone, Default)]
struct ModRefEmissionMetrics {
    pag: ModRefPhaseMetrics,
    mem: ModRefPhaseMetrics,
    closure: ModRefPhaseMetrics,
    pointer_modref_max_fact_fanout: u64,
    high_fanout_fallbacks: u64,
    high_fanout_fallback_rows: u64,
    closure_high_fanout_fallbacks: u64,
    closure_high_fanout_fallback_rows: u64,
}

impl ModRefEmissionMetrics {
    fn phase_mut(&mut self, phase: ModRefSourcePhase) -> &mut ModRefPhaseMetrics {
        match phase {
            ModRefSourcePhase::PagPointer => &mut self.pag,
            ModRefSourcePhase::MemsetMemcpy => &mut self.mem,
        }
    }

    fn merge_closure(&mut self, closure: ModRefPhaseMetrics) {
        self.closure_high_fanout_fallbacks = closure.high_fanout_fallbacks;
        self.closure_high_fanout_fallback_rows = closure.high_fanout_fallback_rows;
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

    fn print_closure_finalization(
        &self,
        label: &str,
        sccs: usize,
        payloads: usize,
        total_rows: usize,
        max_rows: usize,
    ) {
        if !self.enabled {
            return;
        }
        eprintln!(
            "pangs pointer modref profile {label}: elapsed_ms={} sccs={} payloads={} \
             total_rows={} max_rows={}",
            self.started.elapsed().as_millis(),
            sccs,
            payloads,
            total_rows,
            max_rows,
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

fn pointer_modref_profile_global() -> Option<String> {
    std::env::var("PANGS_POINTER_MODREF_PROFILE_GLOBAL")
        .ok()
        .filter(|value| !value.is_empty())
}

fn pointer_modref_high_fanout_limit() -> usize {
    std::env::var("PANGS_POINTER_MODREF_HIGH_FANOUT_LIMIT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(16)
}

fn transitive_modref_high_fanout_limit() -> usize {
    std::env::var("PANGS_TRANSITIVE_MODREF_HIGH_FANOUT_LIMIT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(16_384)
}

fn effective_registry_apis(extensions: &[RegistryApi]) -> Vec<RegistryApi> {
    let mut entries = vec![
        RegistryApi {
            name: "pthread_create".into(),
            kind: RegistryKind::Spawn,
            entry: RegistryEntryOperand::Arg { arg: 2 },
        },
        RegistryApi {
            name: "thrd_create".into(),
            kind: RegistryKind::Spawn,
            entry: RegistryEntryOperand::Arg { arg: 1 },
        },
        RegistryApi {
            name: "signal".into(),
            kind: RegistryKind::Signal,
            entry: RegistryEntryOperand::Arg { arg: 1 },
        },
        RegistryApi {
            name: "sigaction".into(),
            kind: RegistryKind::Signal,
            entry: RegistryEntryOperand::PointeeOfArg { pointee_of_arg: 1 },
        },
    ];
    for extension in extensions {
        if let Some(existing) = entries
            .iter_mut()
            .find(|entry| entry.name == extension.name)
        {
            *existing = extension.clone();
        } else {
            entries.push(extension.clone());
        }
    }
    entries
}

fn registry_spec(name: &str, registries: &[RegistryApi]) -> Option<(RegistryKind, usize, bool)> {
    let name = name.strip_prefix('@').unwrap_or(name);
    let entry = registries.iter().find(|entry| entry.name == name)?;
    Some(match entry.entry {
        RegistryEntryOperand::Arg { arg } => (entry.kind, arg, false),
        RegistryEntryOperand::PointeeOfArg { pointee_of_arg } => (entry.kind, pointee_of_arg, true),
    })
}

fn registry_target_labels(
    pag: &Pag,
    solved: Option<&pangs_solve::SolveResult>,
    registries: &[RegistryApi],
) -> BTreeSet<String> {
    let mut labels = BTreeSet::new();
    for callsite in &pag.callsites {
        let mut specs = callsite
            .callee
            .as_deref()
            .and_then(|name| registry_spec(name, registries))
            .into_iter()
            .collect::<Vec<_>>();
        if let Some(resolution) = solved.and_then(|solved| {
            solved
                .indirect_calls
                .iter()
                .find(|resolution| resolution.callsite_key == callsite.key)
        }) {
            for target in &resolution.targets {
                if let Some(spec) = registry_spec(target, registries) {
                    if !specs.contains(&spec) {
                        specs.push(spec);
                    }
                }
            }
        }
        for (_, index, _) in specs {
            if let Some(node) = callsite.args.get(index) {
                labels.insert(pag.nodes[node.0 as usize].label.clone());
            }
        }
    }
    labels
}

fn resolve_registry_entries(
    pag: &Pag,
    solved: &pangs_solve::SolveResult,
    func_lookup: &HashMap<String, FuncId>,
    registries: &[RegistryApi],
    targeted_labels: &BTreeSet<String>,
) -> BTreeMap<CallsiteId, RegistryEntryResolution> {
    let mut entries = BTreeMap::new();
    for (index, callsite) in pag.callsites.iter().enumerate() {
        let mut specs = callsite
            .callee
            .as_deref()
            .and_then(|name| registry_spec(name, registries))
            .into_iter()
            .collect::<Vec<_>>();
        if let Some(resolution) = solved
            .indirect_calls
            .iter()
            .find(|resolution| resolution.callsite_key == callsite.key)
        {
            for target in &resolution.targets {
                if let Some(spec) = registry_spec(target, registries) {
                    if !specs.contains(&spec) {
                        specs.push(spec);
                    }
                }
            }
        }
        for (kind, arg_index, pointee) in specs {
            let node = callsite.args.get(arg_index);
            let label = node.map(|node| pag.nodes[node.0 as usize].label.as_str());
            let allocations = label.and_then(|label| {
                if pointee {
                    solved.node_pointee_points_to.get(label)
                } else {
                    solved.node_points_to.get(label)
                }
            });
            let mut targets = allocations
                .into_iter()
                .flatten()
                .filter_map(|name| func_lookup.get(name).copied())
                .collect::<Vec<_>>();
            targets.sort();
            targets.dedup();
            let external = label.is_some_and(|label| {
                if pointee {
                    pointee_operand_external(solved, label, &callsite.key)
                } else {
                    solved.nodes.get(label).is_some_and(|node| node.external)
                }
            });
            let targeted = label.is_some_and(|label| targeted_labels.contains(label));
            entries.insert(
                CallsiteId(index as u32),
                RegistryEntryResolution {
                    kind,
                    targets,
                    unresolved: external || !targeted,
                },
            );
        }
    }
    entries
}

fn pointee_operand_external(
    solved: &pangs_solve::SolveResult,
    label: &str,
    callsite_key: &str,
) -> bool {
    let own_boundary = format!("external-call:{callsite_key}");
    solved
        .node_pointee_external
        .get(label)
        .is_some_and(|sources| sources.iter().any(|source| source != &own_boundary))
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ModRefFanoutKey {
    func: FuncId,
    global: GlobalTarget,
    access_rank: u8,
    via_rank: u8,
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
struct ModRefNodeSummaryData {
    external: bool,
    pointee_global_ids: Rc<[GlobalId]>,
    pointee_global_sample: Rc<[String]>,
    pointee_global_count: usize,
    pointee_has_string: bool,
    external_source_suffix: Option<String>,
    direct_symbol_global: Option<GlobalId>,
}

#[derive(Debug, Clone)]
struct ModRefNodeSummary<'a> {
    label: &'a str,
    data: Rc<ModRefNodeSummaryData>,
}

impl std::ops::Deref for ModRefNodeSummary<'_> {
    type Target = ModRefNodeSummaryData;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
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

struct LocalPointerAccessRows {
    rows: Vec<Option<LocalPointerAccessRow>>,
    touched: Vec<usize>,
}

impl LocalPointerAccessRows {
    fn new(node_count: usize) -> Self {
        let row_count = node_count.saturating_mul(4);
        Self {
            rows: (0..row_count).map(|_| None).collect(),
            touched: Vec::new(),
        }
    }

    fn push(
        &mut self,
        address_node: pangs_pag::NodeId,
        access: Access,
        suppress_direct_symbol: bool,
        witness: Option<&str>,
    ) {
        let idx = address_node.0 as usize * 4
            + access_rank(access) as usize * 2
            + usize::from(suppress_direct_symbol);
        let Some(slot) = self.rows.get_mut(idx) else {
            return;
        };
        match slot {
            Some(row) => {
                row.count += 1;
                prefer_modref_witness_ref(&mut row.witness, witness);
            }
            None => {
                *slot = Some(LocalPointerAccessRow {
                    witness: witness.map(str::to_owned),
                    count: 1,
                });
                self.touched.push(idx);
            }
        }
    }

    fn drain_touched(&mut self) -> impl Iterator<Item = (usize, LocalPointerAccessRow)> + '_ {
        self.touched
            .drain(..)
            .filter_map(|idx| self.rows[idx].take().map(|row| (idx, row)))
    }
}

#[derive(Debug, Clone)]
struct PointerAccessEmitterEntry {
    expanded_rows: u64,
    occurrences: u64,
    fanout: usize,
    func: FuncId,
    node_label: String,
    pointee_global_count: usize,
    pointee_global_sample: Rc<[String]>,
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
    target_global: Option<String>,
    target_global_id: Option<GlobalId>,
    target_entries: Vec<PointerAccessEmitterEntry>,
}

impl PointerAccessEmitterProfile {
    fn from_env(global_lookup: &HashMap<String, GlobalId>) -> Self {
        let limit = pointer_modref_profile_top_emitters();
        let interval_rows = pointer_modref_profile_interval_attempts();
        let target_global = pointer_modref_profile_global();
        let target_global_id = target_global
            .as_deref()
            .and_then(|global| global_lookup.get(global).copied());
        Self {
            enabled: pointer_modref_profile_enabled() && limit > 0,
            limit,
            started: Instant::now(),
            observed_rows: 0,
            interval_rows,
            next_rows: interval_rows,
            entries: Vec::new(),
            target_global,
            target_global_id,
            target_entries: Vec::new(),
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
        let entry = PointerAccessEmitterEntry {
            expanded_rows,
            occurrences,
            fanout,
            func: FuncId(key.func),
            node_label: summary.label.to_string(),
            pointee_global_count: summary.pointee_global_count,
            pointee_global_sample: Rc::clone(&summary.pointee_global_sample),
            access_rank: key.access_rank,
            suppress_direct_symbol: key.suppress_direct_symbol,
        };
        if self.should_keep(&self.entries, expanded_rows) {
            self.entries.push(entry.clone());
            Self::sort_and_truncate(&mut self.entries, self.limit);
        }
        if self
            .target_global_id
            .is_some_and(|target| summary.pointee_global_ids.contains(&target))
            && self.should_keep(&self.target_entries, expanded_rows)
        {
            self.target_entries.push(entry);
            Self::sort_and_truncate(&mut self.target_entries, self.limit);
        }
        if self.observed_rows >= self.next_rows {
            self.print("top-emitters-progress");
            while self.next_rows <= self.observed_rows {
                self.next_rows += self.interval_rows;
            }
        }
    }

    fn sort_and_truncate(entries: &mut Vec<PointerAccessEmitterEntry>, limit: usize) {
        entries.sort_by(|left, right| {
            right
                .expanded_rows
                .cmp(&left.expanded_rows)
                .then_with(|| right.occurrences.cmp(&left.occurrences))
                .then_with(|| right.fanout.cmp(&left.fanout))
                .then_with(|| left.func.cmp(&right.func))
                .then_with(|| left.node_label.cmp(&right.node_label))
        });
        entries.truncate(limit);
    }

    fn should_keep(&self, entries: &[PointerAccessEmitterEntry], expanded_rows: u64) -> bool {
        entries.len() < self.limit
            || entries
                .last()
                .is_some_and(|entry| expanded_rows > entry.expanded_rows)
    }

    fn print_entry(prefix: &str, idx: usize, entry: &PointerAccessEmitterEntry) {
        eprintln!(
            "{prefix} #{}: expanded_rows={} occurrences={} fanout={} \
             pointee_global_count={} func={} access_rank={} suppress_direct_symbol={} \
             node={} pointee_sample={}",
            idx + 1,
            entry.expanded_rows,
            entry.occurrences,
            entry.fanout,
            entry.pointee_global_count,
            entry.func.0,
            entry.access_rank,
            entry.suppress_direct_symbol,
            entry.node_label,
            entry.pointee_global_sample.join(","),
        );
    }

    fn print_entries(&self, label: &str, entries: &[PointerAccessEmitterEntry]) {
        let prefix = format!("pangs pointer modref profile {label}");
        for (idx, entry) in entries.iter().enumerate() {
            Self::print_entry(&prefix, idx, entry);
        }
    }

    fn print_target_entries(&self, label: &str) {
        let Some(target) = self.target_global.as_deref() else {
            return;
        };
        eprintln!(
            "pangs pointer modref profile {label}: target_global={target} target_entries={}",
            self.target_entries.len(),
        );
        self.print_entries(&format!("{label} target-global"), &self.target_entries);
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
        self.print_entries(label, &self.entries);
        self.print_target_entries(label);
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
    modrefs: &mut ModRefBuilder,
    func: Option<FuncId>,
    local_rows: &mut LocalPointerModRefRows,
    local_accesses: &mut LocalPointerAccessRows,
    node_summaries: &[Option<ModRefNodeSummary<'_>>],
    access_profile: &mut PointerAccessEmitterProfile,
    high_fanout_limit: usize,
) {
    let Some(func) = func else {
        return;
    };
    for (idx, row) in local_accesses.drain_touched() {
        let address_node = (idx / 4) as u32;
        let key = LocalPointerAccessKey {
            func: func.0,
            address_node,
            access_rank: ((idx % 4) / 2) as u8,
            suppress_direct_symbol: idx % 2 == 1,
        };
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
        if high_fanout_limit > 0 && fanout > high_fanout_limit {
            push_high_fanout_pointer_modref_fallback(
                modrefs,
                func,
                access,
                row.witness,
                summary,
                modref_stationarity_pointees(summary, key.suppress_direct_symbol),
                fanout,
                row.count,
                ModRefSourcePhase::PagPointer,
                "pag_pointer",
            );
            continue;
        }
        for &gid in summary.pointee_global_ids.iter() {
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

fn push_high_fanout_pointer_modref_fallback(
    modrefs: &mut ModRefBuilder,
    func: FuncId,
    access: Access,
    witness: Option<String>,
    summary: &ModRefNodeSummary<'_>,
    global_candidates: Rc<[GlobalId]>,
    fanout: usize,
    occurrences: u64,
    phase: ModRefSourcePhase,
    source: &str,
) {
    let collapsed_rows = occurrences.saturating_mul(fanout as u64);
    modrefs.note_high_fanout_fallback(collapsed_rows);
    let reason = match access {
        Access::Ref => "omega_load",
        Access::Mod => "omega_store",
    };
    let mut detail = format!(
        "high_fanout_pointer_modref:source={source}:node={}:fanout={}:occurrences={occurrences}",
        summary.label, fanout
    );
    if summary.pointee_has_string {
        detail.push_str(":pointee_has_string=true");
    }
    modrefs.push_with_phase(
        ModRef {
            func,
            global: GlobalTarget::Unknown(reason.to_string()),
            access,
            via: Via::Unknown,
            witness,
            detail: Some(detail),
            address_node: Some(summary.label.to_string()),
            pointee_globals: Vec::new(),
            global_candidates: GlobalCandidateSet::Finite(global_candidates),
        },
        Some(phase),
    );
}

fn modref_stationarity_pointees(
    summary: &ModRefNodeSummary<'_>,
    suppress_direct_symbol: bool,
) -> Rc<[GlobalId]> {
    if !suppress_direct_symbol || summary.direct_symbol_global.is_none() {
        return Rc::clone(&summary.pointee_global_ids);
    }
    Rc::from(
        summary
            .pointee_global_ids
            .iter()
            .copied()
            .filter(|&gid| summary.direct_symbol_global != Some(gid))
            .collect::<Vec<_>>(),
    )
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

fn build_modref_node_summary_data(
    label: &str,
    resolution: &NodeResolution,
    global_lookup: &HashMap<String, GlobalId>,
    pointee_global_id_cache: &mut HashMap<(usize, usize), Rc<[GlobalId]>>,
) -> ModRefNodeSummaryData {
    let pointee_global_ids =
        if let Some(ids) = pointee_global_id_cache.get(&resolution.pointee_globals.cache_key()) {
            Rc::clone(ids)
        } else {
            let ids = Rc::<[GlobalId]>::from(
                resolution
                    .pointee_globals
                    .iter()
                    .filter_map(|global_key| global_lookup.get(global_key).copied())
                    .collect::<Vec<_>>(),
            );
            pointee_global_id_cache.insert(resolution.pointee_globals.cache_key(), Rc::clone(&ids));
            ids
        };
    let direct_symbol_global = label
        .strip_prefix("sym:global:")
        .and_then(|global_key| global_lookup.get(global_key).copied());
    let pointee_global_sample = Rc::<[String]>::from(
        resolution
            .pointee_globals
            .iter()
            .take(16)
            .cloned()
            .collect::<Vec<_>>(),
    );
    let pointee_has_string = resolution
        .pointee_globals
        .iter()
        .any(|global_key| looks_like_string_global_key(global_key));
    ModRefNodeSummaryData {
        external: resolution.external,
        pointee_global_ids,
        pointee_global_sample,
        pointee_global_count: resolution.pointee_globals.len(),
        pointee_has_string,
        external_source_suffix: resolution
            .external
            .then(|| modref_external_source_suffix(&resolution.external_sources))
            .flatten(),
        direct_symbol_global,
    }
}

fn global_key_by_id(global_lookup: &HashMap<String, GlobalId>) -> Vec<String> {
    let mut keys = vec![String::new(); global_lookup.len()];
    for (key, &gid) in global_lookup {
        if let Some(slot) = keys.get_mut(gid.0 as usize) {
            *slot = key.clone();
        }
    }
    keys
}

fn global_keys_for_ids(ids: &[GlobalId], global_key_by_id: &[String]) -> Vec<String> {
    ids.iter()
        .filter_map(|gid| global_key_by_id.get(gid.0 as usize))
        .filter(|key| !key.is_empty())
        .cloned()
        .collect()
}

fn global_ids_for_keys<'a>(
    keys: impl Iterator<Item = &'a String>,
    global_lookup: &HashMap<String, GlobalId>,
) -> Rc<[GlobalId]> {
    Rc::from(
        keys.filter_map(|key| global_lookup.get(key).copied())
            .collect::<Vec<_>>(),
    )
}

fn push_pointer_modrefs_from_pag(
    modrefs: &mut ModRefBuilder,
    access_sites: &mut Vec<AccessSite>,
    func_lookup: &HashMap<String, FuncId>,
    global_lookup: &HashMap<String, GlobalId>,
    pag: &Pag,
    nodes: &BTreeMap<String, NodeResolution>,
    noloc_ord: &mut BTreeMap<(String, String), u32>,
) {
    let mut node_summaries = Vec::new();
    node_summaries.resize_with(pag.nodes.len(), || None);
    let mut summary_data_by_label = HashMap::new();
    let mut pointee_global_id_cache = HashMap::new();
    let mut missing_nodes = vec![false; pag.nodes.len()];
    let mut local_accesses = LocalPointerAccessRows::new(pag.nodes.len());
    let mut local_rows = LocalPointerModRefRows::new(global_lookup.len());
    let mut access_profile = PointerAccessEmitterProfile::from_env(global_lookup);
    let high_fanout_limit = pointer_modref_high_fanout_limit();
    let precise_storage_addresses = precise_storage_addresses(pag, global_lookup);
    let global_key_by_id = global_key_by_id(global_lookup);
    let mut active_func = None;
    for edge in &pag.edges {
        let Some((owner, func, accesses)) = edge_accesses(edge, func_lookup) else {
            continue;
        };
        if active_func != Some(func) {
            flush_local_pointer_access_rows(
                modrefs,
                active_func,
                &mut local_rows,
                &mut local_accesses,
                &node_summaries,
                &mut access_profile,
                high_fanout_limit,
            );
            flush_local_pointer_modref_rows(modrefs, active_func, &mut local_rows);
            active_func = Some(func);
        }
        let witness = witness_key(&owner, &edge.loc, noloc_ord, "global");
        let site_loc = edge.loc.as_ref().map(loc_info);
        for pointer_access in accesses {
            let node_idx = pointer_access.address_node.0 as usize;
            if missing_nodes.get(node_idx).copied().unwrap_or(true) {
                continue;
            }
            if node_summaries[node_idx].is_none() {
                let Some(node) = pag.nodes.get(node_idx) else {
                    continue;
                };
                let data = if let Some(data) = summary_data_by_label.get(node.label.as_str()) {
                    Rc::clone(data)
                } else {
                    let Some(resolution) = nodes.get(&node.label) else {
                        missing_nodes[node_idx] = true;
                        continue;
                    };
                    let data = Rc::new(build_modref_node_summary_data(
                        &node.label,
                        resolution,
                        global_lookup,
                        &mut pointee_global_id_cache,
                    ));
                    summary_data_by_label.insert(node.label.as_str(), Rc::clone(&data));
                    data
                };
                node_summaries[node_idx] = Some(ModRefNodeSummary {
                    label: &node.label,
                    data,
                });
            }
            let summary = node_summaries[node_idx].as_ref().unwrap();
            let phase = if pointer_access.detail.starts_with("edge:memcpy") {
                ModRefSourcePhase::MemsetMemcpy
            } else {
                ModRefSourcePhase::PagPointer
            };
            if phase == ModRefSourcePhase::PagPointer {
                if precise_storage_addresses
                    .local_allocas
                    .contains(&pointer_access.address_node)
                {
                    continue;
                }
                if precise_storage_addresses
                    .direct_global_symbols
                    .contains(&pointer_access.address_node)
                {
                    continue;
                }
                if let Some(&gid) = precise_storage_addresses
                    .global_bases
                    .get(&pointer_access.address_node)
                {
                    access_sites.push(AccessSite {
                        func,
                        global: gid,
                        access: pointer_access.access,
                        via: Via::Aliased,
                        volatile: false,
                        atomic_rmw: None,
                        loc: site_loc.clone(),
                        statement_index: None,
                    });
                    push_local_pointer_modref_row(
                        &mut local_rows,
                        gid,
                        pointer_access.access,
                        witness.as_deref(),
                        1,
                    );
                    continue;
                }
            }
            if phase != ModRefSourcePhase::PagPointer {
                flush_local_pointer_access_rows(
                    modrefs,
                    active_func,
                    &mut local_rows,
                    &mut local_accesses,
                    &node_summaries,
                    &mut access_profile,
                    high_fanout_limit,
                );
                flush_local_pointer_modref_rows(modrefs, active_func, &mut local_rows);
            }

            let mut site_globals = summary
                .pointee_global_ids
                .iter()
                .copied()
                .filter(|gid| {
                    !(pointer_access.suppress_direct_symbol
                        && summary.direct_symbol_global == Some(*gid))
                })
                .collect::<Vec<_>>();
            if summary.external && site_globals.is_empty() {
                site_globals.extend((0..global_lookup.len()).map(|index| GlobalId(index as u32)));
            }
            for gid in site_globals {
                access_sites.push(AccessSite {
                    func,
                    global: gid,
                    access: pointer_access.access,
                    via: if summary.external {
                        Via::Unknown
                    } else {
                        Via::Aliased
                    },
                    volatile: false,
                    atomic_rmw: None,
                    loc: site_loc.clone(),
                    statement_index: None,
                });
            }

            if phase == ModRefSourcePhase::PagPointer {
                local_accesses.push(
                    pointer_access.address_node,
                    pointer_access.access,
                    pointer_access.suppress_direct_symbol,
                    witness.as_deref(),
                );
            } else {
                let fanout = summary
                    .pointee_global_ids
                    .iter()
                    .filter(|&&gid| {
                        !(pointer_access.suppress_direct_symbol
                            && summary.direct_symbol_global == Some(gid))
                    })
                    .count();
                if high_fanout_limit > 0 && fanout > high_fanout_limit {
                    push_high_fanout_pointer_modref_fallback(
                        modrefs,
                        func,
                        pointer_access.access,
                        witness.clone(),
                        summary,
                        modref_stationarity_pointees(
                            summary,
                            pointer_access.suppress_direct_symbol,
                        ),
                        fanout,
                        1,
                        phase,
                        pointer_access.detail,
                    );
                    continue;
                }
                for &gid in summary.pointee_global_ids.iter() {
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
                        detail: Some(modref_detail_with_external_suffix_and_pointee_count(
                            pointer_access.detail,
                            summary.external_source_suffix.as_deref(),
                            summary.pointee_global_count,
                        )),
                        address_node: Some(summary.label.to_string()),
                        pointee_globals: global_keys_for_ids(
                            &summary.pointee_global_ids,
                            &global_key_by_id,
                        ),
                        global_candidates: finite_or_module_wide(Rc::clone(
                            &summary.pointee_global_ids,
                        )),
                    },
                    Some(phase),
                );
            }
        }
    }
    flush_local_pointer_access_rows(
        modrefs,
        active_func,
        &mut local_rows,
        &mut local_accesses,
        &node_summaries,
        &mut access_profile,
        high_fanout_limit,
    );
    access_profile.print("top-emitters-done");
    flush_local_pointer_modref_rows(modrefs, active_func, &mut local_rows);
}

fn push_pointer_memcpy_constexpr_modrefs_from_pir(
    modrefs: &mut ModRefBuilder,
    access_sites: &mut Vec<AccessSite>,
    module: &Pir,
    func_lookup: &HashMap<String, FuncId>,
    global_lookup: &HashMap<String, GlobalId>,
    noloc_ord: &mut BTreeMap<(String, String), u32>,
) {
    for func in &module.functions {
        let Some(&func_id) = func_lookup.get(&func.key) else {
            continue;
        };
        for (statement_index, stmt) in func.body.iter().enumerate() {
            let Stmt::Memcpy { dst, src, loc, .. } = stmt else {
                continue;
            };
            for (operand, access) in [(src, Access::Ref), (dst, Access::Mod)] {
                if global_lookup.contains_key(operand) {
                    continue;
                }
                let Some(gid) = label_known_global(operand, global_lookup) else {
                    continue;
                };
                let witness = witness_key(&func.key, loc, noloc_ord, "global");
                access_sites.push(AccessSite {
                    func: func_id,
                    global: gid,
                    access,
                    via: Via::Aliased,
                    volatile: false,
                    atomic_rmw: None,
                    loc: loc.as_ref().map(loc_info),
                    statement_index: Some(statement_index as u32),
                });
                modrefs.push_named_empty(
                    func_id,
                    gid,
                    access,
                    Via::Aliased,
                    witness.as_deref(),
                    Some(ModRefSourcePhase::MemsetMemcpy),
                );
            }
        }
    }
}

fn push_pointer_memset_modrefs_from_pir(
    modrefs: &mut ModRefBuilder,
    access_sites: &mut Vec<AccessSite>,
    module: &Pir,
    func_lookup: &HashMap<String, FuncId>,
    global_lookup: &HashMap<String, GlobalId>,
    nodes: &BTreeMap<String, NodeResolution>,
    noloc_ord: &mut BTreeMap<(String, String), u32>,
) {
    let high_fanout_limit = pointer_modref_high_fanout_limit();
    for func in &module.functions {
        let Some(&func_id) = func_lookup.get(&func.key) else {
            continue;
        };
        for (statement_index, stmt) in func.body.iter().enumerate() {
            let Stmt::Memset { dst, loc, .. } = stmt else {
                continue;
            };
            if let Some(&gid) = global_lookup.get(dst) {
                let witness = witness_key(&func.key, loc, noloc_ord, "global");
                access_sites.push(AccessSite {
                    func: func_id,
                    global: gid,
                    access: Access::Mod,
                    via: Via::Aliased,
                    volatile: false,
                    atomic_rmw: None,
                    loc: loc.as_ref().map(loc_info),
                    statement_index: Some(statement_index as u32),
                });
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
            if let Some(gid) = label_known_global(dst, global_lookup) {
                let witness = witness_key(&func.key, loc, noloc_ord, "global");
                access_sites.push(AccessSite {
                    func: func_id,
                    global: gid,
                    access: Access::Mod,
                    via: Via::Aliased,
                    volatile: false,
                    atomic_rmw: None,
                    loc: loc.as_ref().map(loc_info),
                    statement_index: Some(statement_index as u32),
                });
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
            let mut site_globals = resolution
                .pointee_globals
                .iter()
                .filter_map(|key| global_lookup.get(key).copied())
                .collect::<Vec<_>>();
            if resolution.external && site_globals.is_empty() {
                site_globals.extend((0..global_lookup.len()).map(|index| GlobalId(index as u32)));
            }
            for gid in site_globals {
                access_sites.push(AccessSite {
                    func: func_id,
                    global: gid,
                    access: Access::Mod,
                    via: if resolution.external {
                        Via::Unknown
                    } else {
                        Via::Aliased
                    },
                    volatile: false,
                    atomic_rmw: None,
                    loc: loc.as_ref().map(loc_info),
                    statement_index: Some(statement_index as u32),
                });
            }
            let fanout = resolution
                .pointee_globals
                .iter()
                .filter(|global_key| global_lookup.contains_key(*global_key))
                .count();
            if high_fanout_limit > 0 && fanout > high_fanout_limit {
                modrefs.note_high_fanout_fallback(fanout as u64);
                let mut detail = format!(
                    "high_fanout_pointer_modref:source=stmt:memset_dst:node={label}:fanout={fanout}:occurrences=1"
                );
                if resolution
                    .pointee_globals
                    .iter()
                    .any(|global_key| looks_like_string_global_key(global_key))
                {
                    detail.push_str(":pointee_has_string=true");
                }
                modrefs.push_with_phase(
                    ModRef {
                        func: func_id,
                        global: GlobalTarget::Unknown("omega_store".to_string()),
                        access: Access::Mod,
                        via: Via::Unknown,
                        witness,
                        detail: Some(detail),
                        address_node: Some(label),
                        pointee_globals: Vec::new(),
                        global_candidates: GlobalCandidateSet::Finite(global_ids_for_keys(
                            resolution.pointee_globals.iter(),
                            global_lookup,
                        )),
                    },
                    Some(ModRefSourcePhase::MemsetMemcpy),
                );
                continue;
            }
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
                        global_candidates: finite_or_module_wide(global_ids_for_keys(
                            resolution.pointee_globals.iter(),
                            global_lookup,
                        )),
                    },
                    Some(ModRefSourcePhase::MemsetMemcpy),
                );
            }
        }
    }
}

fn looks_like_string_global_key(global_key: &str) -> bool {
    global_key.starts_with('.') || global_key.starts_with("@.")
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

fn modref_detail_with_external_suffix_and_pointee_count(
    base: &str,
    suffix: Option<&str>,
    pointee_count: usize,
) -> String {
    match suffix {
        Some(suffix) => format!("{base}|{suffix}|pointee_count={pointee_count}"),
        None => base.to_string(),
    }
}

fn modref_detail_with_external_sources(base: &str, sources: &[String]) -> String {
    modref_detail_with_external_suffix(base, modref_external_source_suffix(sources).as_deref())
}

struct PreciseStorageAddresses {
    local_allocas: BTreeSet<pangs_pag::NodeId>,
    direct_global_symbols: BTreeSet<pangs_pag::NodeId>,
    global_bases: BTreeMap<pangs_pag::NodeId, GlobalId>,
}

fn precise_storage_addresses(
    pag: &Pag,
    global_lookup: &HashMap<String, GlobalId>,
) -> PreciseStorageAddresses {
    let mut local_allocas = BTreeSet::new();
    let mut direct_global_symbols = BTreeSet::new();
    let mut global_bases = BTreeMap::new();
    for node in &pag.nodes {
        if let Some(global) = node
            .label
            .strip_prefix("sym:global:")
            .and_then(|global_key| global_lookup.get(global_key).copied())
        {
            direct_global_symbols.insert(node.id);
            global_bases.insert(node.id, global);
        } else if let Some(global) = label_known_global(&node.label, global_lookup) {
            global_bases.insert(node.id, global);
        }
    }
    for edge in &pag.edges {
        if !matches!(edge.kind, EdgeKind::AddrOf) {
            continue;
        }
        let Some(src) = pag.nodes.get(edge.src.0 as usize) else {
            continue;
        };
        match &src.kind {
            pangs_pag::NodeKind::Object {
                object: pangs_pag::ObjectKind::Alloca,
                ..
            } => {
                local_allocas.insert(edge.dst);
            }
            pangs_pag::NodeKind::Object {
                object: pangs_pag::ObjectKind::Global,
                key,
                ..
            } => {
                if let Some(&global) = global_lookup.get(key) {
                    direct_global_symbols.insert(edge.dst);
                    global_bases.insert(edge.dst, global);
                }
            }
            _ => {}
        }
    }
    let mut changed = true;
    while changed {
        changed = false;
        for edge in &pag.edges {
            let Some(&global) = global_bases.get(&edge.src) else {
                continue;
            };
            if !matches!(edge.kind, EdgeKind::Gep { byte_off: Some(_) }) {
                continue;
            }
            changed |= global_bases.insert(edge.dst, global).is_none();
        }
    }
    PreciseStorageAddresses {
        local_allocas,
        direct_global_symbols,
        global_bases,
    }
}

fn label_known_global(label: &str, global_lookup: &HashMap<String, GlobalId>) -> Option<GlobalId> {
    for token in label.split('@').skip(1) {
        let symbol: String = token
            .chars()
            .take_while(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '$'))
            .collect();
        if !symbol.is_empty() {
            if let Some(&global) = global_lookup.get(&symbol) {
                return Some(global);
            }
            let sigiled = format!("@{symbol}");
            if let Some(&global) = global_lookup.get(&sigiled) {
                return Some(global);
            }
        }
    }
    None
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
    global_candidates: GlobalCandidateSet,
}

#[derive(Debug, Clone, Default)]
struct TransitiveModRefs {
    payloads: Vec<ModRefPayload>,
    row_sets: Vec<Vec<usize>>,
    row_set_by_func: Vec<usize>,
}

impl TransitiveModRefs {
    fn row_count(&self, func: FuncId) -> usize {
        let row_set = self.row_set_by_func[func.0 as usize];
        self.row_sets[row_set].len()
    }

    fn total_row_count(&self) -> usize {
        self.row_set_by_func
            .iter()
            .map(|&row_set| self.row_sets[row_set].len())
            .sum()
    }

    fn iter(&self, func: FuncId) -> impl Iterator<Item = ModRef> + '_ {
        let root = func;
        let row_set = self.row_set_by_func[func.0 as usize];
        self.row_sets[row_set].iter().map(move |&payload_id| {
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
                global_candidates: payload.global_candidates.clone(),
            }
        })
    }

    fn iter_payloads(&self, func: FuncId) -> impl Iterator<Item = &ModRefPayload> + '_ {
        let row_set = self.row_set_by_func[func.0 as usize];
        self.row_sets[row_set]
            .iter()
            .map(|&payload_id| &self.payloads[payload_id])
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
    global_candidates: GlobalCandidateSet,
}

fn modref_payload_key(payload: &ModRefPayload) -> ModRefFactKey {
    ModRefFactKey {
        global: payload.global.clone(),
        access_rank: access_rank(payload.access),
        via_rank: via_rank(payload.via),
        detail: payload.detail.clone(),
        address_node: payload.address_node.clone(),
        pointee_globals: payload.pointee_globals.clone(),
        global_candidates: payload.global_candidates.clone(),
    }
}

fn intern_modref_payload(
    payload_ids: &mut BTreeMap<ModRefFactKey, usize>,
    payloads: &mut Vec<ModRefPayload>,
    payload: ModRefPayload,
) -> usize {
    let key = modref_payload_key(&payload);
    if let Some(&id) = payload_ids.get(&key) {
        let existing = &mut payloads[id];
        existing.witness = preferred_modref_witness(existing.witness.take(), payload.witness);
        id
    } else {
        let id = payloads.len();
        payload_ids.insert(key, id);
        payloads.push(payload);
        id
    }
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
        self.pointee_globals
            .cmp(&other.pointee_globals)
            .then_with(|| self.global_candidates.cmp(&other.global_candidates))
    }
}

fn merge_global_candidates(existing: &mut GlobalCandidateSet, incoming: GlobalCandidateSet) {
    let GlobalCandidateSet::Finite(incoming) = incoming else {
        *existing = GlobalCandidateSet::ModuleWide;
        return;
    };
    let GlobalCandidateSet::Finite(current) = existing else {
        return;
    };
    if current.as_ref() == incoming.as_ref() {
        return;
    }
    let mut merged = current.iter().copied().collect::<Vec<_>>();
    merged.extend(incoming.iter().copied());
    merged.sort();
    merged.dedup();
    *existing = GlobalCandidateSet::Finite(Rc::from(merged));
}

fn finite_or_module_wide(globals: Rc<[GlobalId]>) -> GlobalCandidateSet {
    if globals.is_empty() {
        GlobalCandidateSet::ModuleWide
    } else {
        GlobalCandidateSet::Finite(globals)
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
    _globals: &[GlobalInfo],
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
            global_candidates: mr.global_candidates.clone(),
        };
        let id = intern_modref_payload(&mut payload_ids, &mut payloads, payload);
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

    let mut metrics = ModRefPhaseMetrics::default();
    let high_fanout_limit = transitive_modref_high_fanout_limit();
    let mut memo = vec![None; scc_members.len()];
    let mut profile = PointerModRefProfile::from_env();
    profile.print_closure_finalization(
        "closure-collect-start",
        scc_members.len(),
        payloads.len(),
        0,
        0,
    );
    for scc in 0..scc_members.len() {
        collect_scc_payload_ids(
            scc,
            &local_by_scc,
            &scc_succs,
            &mut memo,
            &mut payload_ids,
            &mut payloads,
            &mut metrics,
            high_fanout_limit,
        );
    }
    let (total_closure_rows, max_closure_rows) = scc_row_count_summary(&memo);
    profile.print_closure_finalization(
        "closure-collect-done",
        scc_members.len(),
        payloads.len(),
        total_closure_rows,
        max_closure_rows,
    );
    profile.print_closure_finalization(
        "closure-rank-start",
        scc_members.len(),
        payloads.len(),
        total_closure_rows,
        max_closure_rows,
    );
    let (payload_fanout_ranks, fanout_rank_count) = modref_payload_fanout_ranks(&payloads);
    profile.print_closure_finalization(
        "closure-rank-done",
        scc_members.len(),
        payloads.len(),
        total_closure_rows,
        max_closure_rows,
    );

    let mut row_sets = Vec::with_capacity(scc_members.len());
    let mut max_fanout_by_scc = Vec::with_capacity(scc_members.len());
    let mut fanout_counts = vec![0u32; fanout_rank_count];
    let mut touched_fanout_ranks = Vec::new();
    profile.print_closure_finalization(
        "closure-fanout-start",
        scc_members.len(),
        payloads.len(),
        total_closure_rows,
        max_closure_rows,
    );
    for scc in 0..scc_members.len() {
        let rows = memo[scc].take().unwrap_or_default().rows;
        max_fanout_by_scc.push(max_modref_payload_fanout_by_rank(
            &rows,
            &payload_fanout_ranks,
            &mut fanout_counts,
            &mut touched_fanout_ranks,
        ));
        row_sets.push(rows);
    }
    profile.print_closure_finalization(
        "closure-fanout-done",
        scc_members.len(),
        payloads.len(),
        total_closure_rows,
        max_closure_rows,
    );

    let mut row_set_by_func = Vec::with_capacity(func_count);
    profile.print_closure("closure-start", &metrics, 0, payloads.len());
    for root_idx in 0..func_count {
        let scc = scc_of_func[root_idx];
        let rows = &row_sets[scc];
        metrics.attempted += rows.len() as u64;
        metrics.unique += rows.len() as u64;
        metrics.max_fact_fanout = metrics.max_fact_fanout.max(max_fanout_by_scc[scc]);
        row_set_by_func.push(scc);
        profile.maybe_print_closure("closure-progress", &metrics, root_idx + 1, payloads.len());
    }
    profile.print_closure("closure-done", &metrics, func_count, payloads.len());
    (
        TransitiveModRefs {
            payloads,
            row_sets,
            row_set_by_func,
        },
        metrics,
    )
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ModRefPayloadFanoutKey {
    global: GlobalTarget,
    access_rank: u8,
    via_rank: u8,
}

fn modref_payload_fanout_ranks(payloads: &[ModRefPayload]) -> (Vec<usize>, usize) {
    let mut ranks = Vec::with_capacity(payloads.len());
    let mut by_key = BTreeMap::<ModRefPayloadFanoutKey, usize>::new();
    for payload in payloads {
        let next_rank = by_key.len();
        let rank = *by_key
            .entry(ModRefPayloadFanoutKey {
                global: payload.global.clone(),
                access_rank: access_rank(payload.access),
                via_rank: via_rank(payload.via),
            })
            .or_insert(next_rank);
        ranks.push(rank);
    }
    (ranks, by_key.len())
}

fn scc_row_count_summary(memo: &[Option<SccPayloadIds>]) -> (usize, usize) {
    let mut total_rows = 0usize;
    let mut max_rows = 0usize;
    for rows in memo.iter().filter_map(|rows| rows.as_ref()) {
        total_rows = total_rows.saturating_add(rows.rows.len());
        max_rows = max_rows.max(rows.rows.len());
    }
    (total_rows, max_rows)
}

fn max_modref_payload_fanout_by_rank(
    rows: &[usize],
    payload_fanout_ranks: &[usize],
    counts: &mut [u32],
    touched: &mut Vec<usize>,
) -> u64 {
    let mut max = 0;
    for &payload_id in rows {
        let rank = payload_fanout_ranks[payload_id];
        let count = &mut counts[rank];
        if *count == 0 {
            touched.push(rank);
        }
        *count += 1;
        max = max.max(*count as u64);
    }
    for rank in touched.drain(..) {
        counts[rank] = 0;
    }
    max
}

#[derive(Debug, Clone, Default)]
struct SccPayloadIds {
    rows: Vec<usize>,
    approximate: bool,
}

fn collapse_high_fanout_transitive_rows(
    rows: &mut Vec<usize>,
    payload_ids: &mut BTreeMap<ModRefFactKey, usize>,
    payloads: &mut Vec<ModRefPayload>,
    metrics: &mut ModRefPhaseMetrics,
    high_fanout_limit: usize,
) -> bool {
    if high_fanout_limit == 0 || rows.len() <= high_fanout_limit {
        return false;
    }

    let precise_rows = rows.len() as u64;
    let detail = Some(format!(
        "high_fanout_transitive_modref:limit={high_fanout_limit}"
    ));
    compact_transitive_rows(rows, payload_ids, payloads, detail);
    metrics.high_fanout_fallbacks += 1;
    metrics.high_fanout_fallback_rows = metrics
        .high_fanout_fallback_rows
        .saturating_add(precise_rows);
    true
}

fn compact_transitive_rows(
    rows: &mut Vec<usize>,
    payload_ids: &mut BTreeMap<ModRefFactKey, usize>,
    payloads: &mut Vec<ModRefPayload>,
    detail: Option<String>,
) {
    let has_ref = rows
        .iter()
        .any(|&payload_id| payloads[payload_id].access == Access::Ref);
    let has_mod = rows
        .iter()
        .any(|&payload_id| payloads[payload_id].access == Access::Mod);
    let ref_candidates = has_ref.then(|| transitive_candidate_union(rows, payloads, Access::Ref));
    let mod_candidates = has_mod.then(|| transitive_candidate_union(rows, payloads, Access::Mod));
    let mut fallback_rows = Vec::with_capacity(2);
    if has_ref {
        fallback_rows.push(intern_modref_payload(
            payload_ids,
            payloads,
            high_fanout_transitive_payload(Access::Ref, detail.clone(), ref_candidates.unwrap()),
        ));
    }
    if has_mod {
        fallback_rows.push(intern_modref_payload(
            payload_ids,
            payloads,
            high_fanout_transitive_payload(Access::Mod, detail, mod_candidates.unwrap()),
        ));
    }
    fallback_rows.sort_unstable();
    fallback_rows.dedup();
    *rows = fallback_rows;
}

fn transitive_candidate_union(
    rows: &[usize],
    payloads: &[ModRefPayload],
    access: Access,
) -> GlobalCandidateSet {
    let mut globals = Vec::new();
    for payload in rows
        .iter()
        .map(|&id| &payloads[id])
        .filter(|payload| payload.access == access)
    {
        match (&payload.global, &payload.global_candidates) {
            (GlobalTarget::Name(global), _) => globals.push(*global),
            (GlobalTarget::Unknown(_), GlobalCandidateSet::Finite(candidates)) => {
                globals.extend(candidates.iter().copied());
            }
            (GlobalTarget::Unknown(_), GlobalCandidateSet::ModuleWide) => {
                return GlobalCandidateSet::ModuleWide;
            }
        }
    }
    globals.sort();
    globals.dedup();
    GlobalCandidateSet::Finite(Rc::from(globals))
}

fn high_fanout_transitive_payload(
    access: Access,
    detail: Option<String>,
    global_candidates: GlobalCandidateSet,
) -> ModRefPayload {
    let reason = match access {
        Access::Ref => "omega_load",
        Access::Mod => "omega_store",
    };
    ModRefPayload {
        global: GlobalTarget::Unknown(reason.to_string()),
        access,
        via: Via::Unknown,
        witness: None,
        detail,
        address_node: None,
        pointee_globals: Vec::new(),
        global_candidates,
    }
}

fn collect_scc_payload_ids(
    scc: usize,
    local_by_scc: &[Vec<usize>],
    scc_succs: &[Vec<usize>],
    memo: &mut [Option<SccPayloadIds>],
    payload_ids: &mut BTreeMap<ModRefFactKey, usize>,
    payloads: &mut Vec<ModRefPayload>,
    metrics: &mut ModRefPhaseMetrics,
    high_fanout_limit: usize,
) -> SccPayloadIds {
    if let Some(existing) = &memo[scc] {
        return existing.clone();
    }
    let mut rows = local_by_scc[scc].clone();
    let mut approximate = collapse_high_fanout_transitive_rows(
        &mut rows,
        payload_ids,
        payloads,
        metrics,
        high_fanout_limit,
    );
    for &succ in &scc_succs[scc] {
        let succ_rows = collect_scc_payload_ids(
            succ,
            local_by_scc,
            scc_succs,
            memo,
            payload_ids,
            payloads,
            metrics,
            high_fanout_limit,
        );
        rows = merge_sorted_unique(rows, succ_rows.rows);
        approximate |= succ_rows.approximate;
        approximate |= collapse_high_fanout_transitive_rows(
            &mut rows,
            payload_ids,
            payloads,
            metrics,
            high_fanout_limit,
        );
        if approximate {
            compact_transitive_rows(
                &mut rows,
                payload_ids,
                payloads,
                Some("high_fanout_transitive_modref:propagated".to_string()),
            );
        }
    }
    rows.dedup();
    let result = SccPayloadIds { rows, approximate };
    memo[scc] = Some(result.clone());
    result
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

#[cfg(test)]
mod registry_tests {
    use std::collections::BTreeSet;

    use pangs_solve::SolveResult;

    use super::pointee_operand_external;

    #[test]
    fn pointee_registry_ignores_only_its_own_boundary_uncertainty() {
        let label = "val:install:%action";
        let site = "install@file.c:10:3#0";
        let mut solved = SolveResult::default();
        solved.node_pointee_external.insert(
            label.into(),
            BTreeSet::from([format!("external-call:{site}")]),
        );
        assert!(!pointee_operand_external(&solved, label, site));

        solved
            .node_pointee_external
            .get_mut(label)
            .unwrap()
            .insert("external-call:earlier@file.c:9:3#0".into());
        assert!(pointee_operand_external(&solved, label, site));
    }
}
