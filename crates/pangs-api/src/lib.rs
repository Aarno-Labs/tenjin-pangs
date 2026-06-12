use std::collections::{BTreeMap, BTreeSet, HashMap};

use pangs_pir::{fsa_compatible, Access, Pir, Stmt};
use serde::{Deserialize, Serialize};
use thiserror::Error;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Direct,
    Fsa,
    Steens,
    Andersen,
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
    pub mutable_globals_total: usize,
    pub in_rewritable_components: usize,
    pub partition_count: usize,
    pub partition_p50_size: usize,
    pub partition_p95_size: usize,
    pub partition_max_size: usize,
    pub oversize_fallbacks: usize,
    pub rounds: usize,
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
        let address_taken: Vec<_> = module
            .functions
            .iter()
            .enumerate()
            .filter(|(_, f)| f.address_taken && !f.external)
            .map(|(idx, f)| (FuncId(idx as u32), f))
            .collect();

        let mut noloc_ord: BTreeMap<(String, String), u32> = BTreeMap::new();
        for (func_idx, func) in module.functions.iter().enumerate() {
            let caller = FuncId(func_idx as u32);
            for stmt in &func.body {
                match stmt {
                    Stmt::CallDirect { callee, loc, .. } => {
                        let cs = push_callsite(
                            &mut callsites,
                            &mut noloc_ord,
                            caller,
                            &func.key,
                            CallKind::Direct,
                            loc,
                        );
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
                    Stmt::CallIndirect { sig, loc, .. } => {
                        let cs = push_callsite(
                            &mut callsites,
                            &mut noloc_ord,
                            caller,
                            &func.key,
                            CallKind::Indirect,
                            loc,
                        );
                        for (target_id, target) in &address_taken {
                            if fsa_compatible(sig, &target.sig) {
                                call_edges.push(CallEdge {
                                    caller: Caller::Func(caller),
                                    callsite: Some(cs),
                                    callee: Callee::Func(*target_id),
                                    kind: CallKind::Indirect,
                                    tier: match opts.stage {
                                        Stage::Andersen => Tier::Andersen,
                                        Stage::Steens => Tier::Steens,
                                        Stage::Conservative => Tier::Fsa,
                                    },
                                });
                            }
                        }
                        call_edges.push(CallEdge {
                            caller: Caller::Func(caller),
                            callsite: Some(cs),
                            callee: Callee::Unknown("omega_fnptr".to_string()),
                            kind: CallKind::Indirect,
                            tier: Tier::Fsa,
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
                }
            }
        }

        for (idx, func) in module.functions.iter().enumerate() {
            if functions[idx].exported || (opts.build_mode == BuildMode::Library && !func.external)
            {
                call_edges.push(CallEdge {
                    caller: Caller::Unknown("address_escapes_to_external".to_string()),
                    callsite: None,
                    callee: Callee::Func(FuncId(idx as u32)),
                    kind: CallKind::Direct,
                    tier: Tier::Fsa,
                });
            }
        }

        call_edges.sort_by_key(|edge| edge_sort_key(edge, &functions, &callsites));
        call_edges.dedup_by_key(|edge| edge_sort_key(edge, &functions, &callsites));
        modrefs.sort_by_key(|mr| modref_sort_key(mr, &functions, &globals));
        modrefs.dedup_by_key(|mr| modref_sort_key(mr, &functions, &globals));

        let components = compute_components(&functions, &globals, &call_edges, &modrefs);
        let mutable_globals_total = globals.iter().filter(|g| g.mutable).count();
        let in_rewritable_components = components
            .iter()
            .filter(|c| !c.frozen)
            .flat_map(|c| c.mutable_globals.iter())
            .collect::<BTreeSet<_>>()
            .len();

        let metrics = Metrics {
            functions: functions.len(),
            globals: globals.len(),
            callsites: callsites.len(),
            call_edges: call_edges.len(),
            mutable_globals_total,
            in_rewritable_components,
            partition_count: 0,
            partition_p50_size: 0,
            partition_p95_size: 0,
            partition_max_size: 0,
            oversize_fallbacks: 0,
            rounds: match opts.stage {
                Stage::Andersen => 1,
                _ => 0,
            },
        };

        Ok(Self {
            functions: Table::new(functions),
            globals: Table::new(globals),
            callsites: Table::new(callsites),
            call_edges,
            modrefs,
            components,
            findings: Vec::new(),
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
        self.modrefs.iter().filter(move |mr| mr.func == func)
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
    let (key, loc_info, synthetic) = if let Some(loc) = loc {
        let ord = next_noloc(
            noloc_ord,
            caller,
            &format!("call@{}:{}:{}", loc.file, loc.line, loc.col),
        );
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
        let ord = next_noloc(noloc_ord, caller, "call");
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

fn modref_sort_key(
    mr: &ModRef,
    funcs: &[FuncInfo],
    globals: &[GlobalInfo],
) -> (String, String, String, String) {
    (
        funcs[mr.func.0 as usize].key.clone(),
        match mr.global {
            GlobalTarget::Name(id) => globals[id.0 as usize].key.clone(),
            GlobalTarget::Unknown(ref reason) => reason.clone(),
        },
        format!("{:?}", mr.access),
        mr.witness.clone().unwrap_or_default(),
    )
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
    edges: &[CallEdge],
    modrefs: &[ModRef],
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

    components
        .into_iter()
        .enumerate()
        .map(|(idx, members)| {
            let member_set: BTreeSet<_> = members.iter().copied().collect();
            let mut mutable_globals = BTreeSet::new();
            for mr in modrefs {
                if member_set.contains(&mr.func) {
                    if let GlobalTarget::Name(gid) = mr.global {
                        if globals[gid.0 as usize].mutable {
                            mutable_globals.insert(gid);
                        }
                    }
                }
            }
            let mut taint = Vec::new();
            for edge in edges {
                if matches!(edge.callee, Callee::Unknown(_)) {
                    if let Caller::Func(fid) = edge.caller {
                        if member_set.contains(&fid) {
                            taint.push(Taint {
                                kind: "unknown_callee".to_string(),
                                witness: None,
                            });
                        }
                    }
                }
                if matches!(edge.caller, Caller::Unknown(_)) {
                    if let Callee::Func(fid) = edge.callee {
                        if member_set.contains(&fid) {
                            taint.push(Taint {
                                kind: "unknown_caller".to_string(),
                                witness: None,
                            });
                        }
                    }
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
