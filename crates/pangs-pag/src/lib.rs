use std::collections::{BTreeMap, BTreeSet};

use pangs_pir::{Loc, Pir, Signature, Stmt};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PagOpts {
    pub build_mode: BuildMode,
    #[serde(default)]
    pub exports: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildMode {
    #[default]
    Library,
    Executable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pag {
    pub module: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub metrics: PagMetrics,
    #[serde(default)]
    pub nodes: Vec<Node>,
    #[serde(default)]
    pub edges: Vec<Edge>,
    #[serde(default)]
    pub callsites: Vec<Callsite>,
    #[serde(default)]
    pub omega_seeds: Vec<OmegaSeed>,
}

impl Pag {
    pub fn from_pir(pir: &Pir, opts: &PagOpts) -> Self {
        Builder::new(pir, opts).build()
    }

    pub fn metrics(&self) -> &PagMetrics {
        &self.metrics
    }

    pub fn for_function(&self, func: &str) -> Self {
        let mut keep_nodes = BTreeSet::new();
        let mut keep_callsites = BTreeSet::new();

        for node in &self.nodes {
            match &node.kind {
                NodeKind::Value {
                    scope: Scope::Function(owner),
                } if owner == func => {
                    keep_nodes.insert(node.id);
                }
                NodeKind::Object {
                    object: ObjectKind::Alloca,
                    owner: Some(owner),
                    ..
                } if owner == func => {
                    keep_nodes.insert(node.id);
                }
                NodeKind::Object {
                    object: ObjectKind::Function,
                    key,
                    ..
                } if key == func => {
                    keep_nodes.insert(node.id);
                }
                NodeKind::Param { func: owner, .. } if owner == func => {
                    keep_nodes.insert(node.id);
                }
                NodeKind::Return { func: owner } if owner == func => {
                    keep_nodes.insert(node.id);
                }
                _ => {}
            }
        }

        for callsite in &self.callsites {
            if callsite.caller == func {
                keep_callsites.insert(callsite.id);
                if let Some(operand) = callsite.operand {
                    keep_nodes.insert(operand);
                }
                for arg in &callsite.args {
                    keep_nodes.insert(*arg);
                }
                if let Some(result) = callsite.result {
                    keep_nodes.insert(result);
                }
            }
        }

        let edges: Vec<_> = self
            .edges
            .iter()
            .filter(|edge| matches!(&edge.owner, Owner::Function(owner) if owner == func))
            .cloned()
            .collect();
        for edge in &edges {
            keep_nodes.insert(edge.src);
            keep_nodes.insert(edge.dst);
        }

        let nodes: Vec<_> = self
            .nodes
            .iter()
            .filter(|node| keep_nodes.contains(&node.id))
            .cloned()
            .collect();

        let callsites: Vec<_> = self
            .callsites
            .iter()
            .filter(|callsite| keep_callsites.contains(&callsite.id))
            .cloned()
            .collect();

        let omega_seeds: Vec<_> = self
            .omega_seeds
            .iter()
            .filter(|seed| match seed.target {
                SeedTarget::Node(id) => keep_nodes.contains(&id),
                SeedTarget::Callsite(id) => keep_callsites.contains(&id),
            })
            .cloned()
            .collect();

        let node_map: BTreeMap<_, _> = nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (node.id, NodeId(index as u32)))
            .collect();
        let callsite_map: BTreeMap<_, _> = callsites
            .iter()
            .enumerate()
            .map(|(index, callsite)| (callsite.id, CallsiteId(index as u32)))
            .collect();

        let nodes = nodes
            .into_iter()
            .enumerate()
            .map(|(index, mut node)| {
                node.id = NodeId(index as u32);
                node
            })
            .collect::<Vec<_>>();
        let edges = edges
            .into_iter()
            .enumerate()
            .map(|(index, mut edge)| {
                edge.id = EdgeId(index as u32);
                edge.src = node_map[&edge.src];
                edge.dst = node_map[&edge.dst];
                edge
            })
            .collect::<Vec<_>>();
        let callsites = callsites
            .into_iter()
            .enumerate()
            .map(|(index, mut callsite)| {
                callsite.id = CallsiteId(index as u32);
                callsite.operand = callsite.operand.map(|id| node_map[&id]);
                callsite.args = callsite.args.into_iter().map(|id| node_map[&id]).collect();
                callsite.result = callsite.result.map(|id| node_map[&id]);
                callsite
            })
            .collect::<Vec<_>>();
        let omega_seeds = omega_seeds
            .into_iter()
            .map(|mut seed| {
                seed.target = match seed.target {
                    SeedTarget::Node(id) => SeedTarget::Node(node_map[&id]),
                    SeedTarget::Callsite(id) => SeedTarget::Callsite(callsite_map[&id]),
                };
                seed
            })
            .collect::<Vec<_>>();

        Self {
            module: self.module.clone(),
            source: self.source.clone(),
            metrics: PagMetrics::compute(&nodes, &edges, &callsites, &omega_seeds),
            nodes,
            edges,
            callsites,
            omega_seeds,
        }
    }

    pub fn validate(&self) -> Result<(), Vec<ValidationIssue>> {
        let mut issues = Vec::new();
        let expected_metrics =
            PagMetrics::compute(&self.nodes, &self.edges, &self.callsites, &self.omega_seeds);

        if self.metrics.nodes != expected_metrics.nodes
            || self.metrics.edges != expected_metrics.edges
            || self.metrics.callsites != expected_metrics.callsites
            || self.metrics.omega_seeds != expected_metrics.omega_seeds
            || self.metrics.value_nodes != expected_metrics.value_nodes
            || self.metrics.object_nodes != expected_metrics.object_nodes
            || self.metrics.param_nodes != expected_metrics.param_nodes
            || self.metrics.return_nodes != expected_metrics.return_nodes
            || self.metrics.addr_of_edges != expected_metrics.addr_of_edges
            || self.metrics.assign_edges != expected_metrics.assign_edges
            || self.metrics.load_edges != expected_metrics.load_edges
            || self.metrics.store_edges != expected_metrics.store_edges
            || self.metrics.gep_edges != expected_metrics.gep_edges
            || self.metrics.memcpy_edges != expected_metrics.memcpy_edges
            || self.metrics.direct_calls != expected_metrics.direct_calls
            || self.metrics.indirect_calls != expected_metrics.indirect_calls
        {
            issues.push(ValidationIssue::MetricsMismatch);
        }

        for (index, node) in self.nodes.iter().enumerate() {
            if node.id.0 as usize != index {
                issues.push(ValidationIssue::NodeIdMismatch {
                    expected: index as u32,
                    actual: node.id.0,
                    label: node.label.clone(),
                });
            }
        }

        for (index, edge) in self.edges.iter().enumerate() {
            if edge.id.0 as usize != index {
                issues.push(ValidationIssue::EdgeIdMismatch {
                    expected: index as u32,
                    actual: edge.id.0,
                });
            }
            let Some(src) = self.nodes.get(edge.src.0 as usize) else {
                issues.push(ValidationIssue::DanglingEdgeEndpoint {
                    edge: edge.id,
                    which: "src",
                    node: edge.src,
                });
                continue;
            };
            let Some(dst) = self.nodes.get(edge.dst.0 as usize) else {
                issues.push(ValidationIssue::DanglingEdgeEndpoint {
                    edge: edge.id,
                    which: "dst",
                    node: edge.dst,
                });
                continue;
            };

            match edge.kind {
                EdgeKind::AddrOf => {
                    if !matches!(src.kind, NodeKind::Object { .. })
                        || !matches!(
                            dst.kind,
                            NodeKind::Value { .. }
                                | NodeKind::Param { .. }
                                | NodeKind::Return { .. }
                        )
                    {
                        issues.push(ValidationIssue::EdgeKindInvariant {
                            edge: edge.id,
                            kind: "addr_of",
                            detail: format!(
                                "expected object -> value, saw {:?} -> {:?}",
                                src.kind, dst.kind
                            ),
                        });
                    }
                }
                EdgeKind::Assign | EdgeKind::Load | EdgeKind::Store | EdgeKind::Memcpy { .. } => {
                    if !src.kind.is_value_like() || !dst.kind.is_value_like() {
                        issues.push(ValidationIssue::EdgeKindInvariant {
                            edge: edge.id,
                            kind: edge.kind.name(),
                            detail: format!(
                                "expected value -> value, saw {:?} -> {:?}",
                                src.kind, dst.kind
                            ),
                        });
                    }
                }
                EdgeKind::Gep { .. } => {
                    if !src.kind.is_value_like() || !dst.kind.is_value_like() {
                        issues.push(ValidationIssue::EdgeKindInvariant {
                            edge: edge.id,
                            kind: "gep",
                            detail: format!(
                                "expected value -> value, saw {:?} -> {:?}",
                                src.kind, dst.kind
                            ),
                        });
                    }
                }
            }

            if matches!(edge.kind, EdgeKind::Load | EdgeKind::Store)
                && matches!(edge.owner, Owner::Module)
            {
                issues.push(ValidationIssue::LoadStoreNeedsOwner {
                    edge: edge.id,
                    kind: edge.kind.name(),
                });
            }
        }

        for (index, callsite) in self.callsites.iter().enumerate() {
            if callsite.id.0 as usize != index {
                issues.push(ValidationIssue::CallsiteIdMismatch {
                    expected: index as u32,
                    actual: callsite.id.0,
                });
            }
            if let Some(operand) = callsite.operand {
                match self.nodes.get(operand.0 as usize) {
                    Some(node) if node.kind.is_value_like() => {}
                    Some(node) => issues.push(ValidationIssue::CallsiteOperandInvariant {
                        callsite: callsite.id,
                        detail: format!("expected value-like operand, saw {:?}", node.kind),
                    }),
                    None => issues.push(ValidationIssue::DanglingCallsiteOperand {
                        callsite: callsite.id,
                        node: operand,
                    }),
                }
            }
            for arg in &callsite.args {
                match self.nodes.get(arg.0 as usize) {
                    Some(node) if node.kind.is_value_like() => {}
                    Some(node) => issues.push(ValidationIssue::CallsiteOperandInvariant {
                        callsite: callsite.id,
                        detail: format!("expected value-like arg, saw {:?}", node.kind),
                    }),
                    None => issues.push(ValidationIssue::DanglingCallsiteOperand {
                        callsite: callsite.id,
                        node: *arg,
                    }),
                }
            }
            if let Some(result) = callsite.result {
                match self.nodes.get(result.0 as usize) {
                    Some(node) if node.kind.is_value_like() => {}
                    Some(node) => issues.push(ValidationIssue::CallsiteOperandInvariant {
                        callsite: callsite.id,
                        detail: format!("expected value-like result, saw {:?}", node.kind),
                    }),
                    None => issues.push(ValidationIssue::DanglingCallsiteOperand {
                        callsite: callsite.id,
                        node: result,
                    }),
                }
            }
        }

        for seed in &self.omega_seeds {
            match seed.target {
                SeedTarget::Node(id) => {
                    if self.nodes.get(id.0 as usize).is_none() {
                        issues.push(ValidationIssue::DanglingSeedTarget {
                            kind: seed.kind.name().to_string(),
                            target: format!("node {}", id.0),
                        });
                    }
                }
                SeedTarget::Callsite(id) => {
                    if self.callsites.get(id.0 as usize).is_none() {
                        issues.push(ValidationIssue::DanglingSeedTarget {
                            kind: seed.kind.name().to_string(),
                            target: format!("callsite {}", id.0),
                        });
                    }
                }
            }
        }

        if issues.is_empty() {
            Ok(())
        } else {
            Err(issues)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EdgeId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CallsiteId(pub u32);

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PagMetrics {
    pub nodes: usize,
    pub value_nodes: usize,
    pub object_nodes: usize,
    pub param_nodes: usize,
    pub return_nodes: usize,
    pub edges: usize,
    pub addr_of_edges: usize,
    pub assign_edges: usize,
    pub load_edges: usize,
    pub store_edges: usize,
    pub gep_edges: usize,
    pub memcpy_edges: usize,
    pub callsites: usize,
    pub direct_calls: usize,
    pub indirect_calls: usize,
    pub omega_seeds: usize,
}

impl PagMetrics {
    fn compute(
        nodes: &[Node],
        edges: &[Edge],
        callsites: &[Callsite],
        omega_seeds: &[OmegaSeed],
    ) -> Self {
        let mut metrics = Self {
            nodes: nodes.len(),
            edges: edges.len(),
            callsites: callsites.len(),
            omega_seeds: omega_seeds.len(),
            ..Self::default()
        };

        for node in nodes {
            match node.kind {
                NodeKind::Value { .. } => metrics.value_nodes += 1,
                NodeKind::Object { .. } => metrics.object_nodes += 1,
                NodeKind::Param { .. } => metrics.param_nodes += 1,
                NodeKind::Return { .. } => metrics.return_nodes += 1,
            }
        }

        for edge in edges {
            match edge.kind {
                EdgeKind::AddrOf => metrics.addr_of_edges += 1,
                EdgeKind::Assign => metrics.assign_edges += 1,
                EdgeKind::Load => metrics.load_edges += 1,
                EdgeKind::Store => metrics.store_edges += 1,
                EdgeKind::Gep { .. } => metrics.gep_edges += 1,
                EdgeKind::Memcpy { .. } => metrics.memcpy_edges += 1,
            }
        }

        for callsite in callsites {
            match callsite.kind {
                CallKind::Direct => metrics.direct_calls += 1,
                CallKind::Indirect => metrics.indirect_calls += 1,
            }
        }

        metrics
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeId,
    pub label: String,
    pub kind: NodeKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NodeKind {
    Value {
        scope: Scope,
    },
    Object {
        object: ObjectKind,
        key: String,
        #[serde(default)]
        owner: Option<String>,
    },
    Param {
        func: String,
        index: u32,
    },
    Return {
        func: String,
    },
}

impl NodeKind {
    fn is_value_like(&self) -> bool {
        matches!(
            self,
            NodeKind::Value { .. } | NodeKind::Param { .. } | NodeKind::Return { .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", content = "func", rename_all = "snake_case")]
pub enum Scope {
    Module,
    GlobalInit,
    Function(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    Alloca,
    Global,
    Function,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub id: EdgeId,
    pub kind: EdgeKind,
    pub src: NodeId,
    pub dst: NodeId,
    pub owner: Owner,
    #[serde(default)]
    pub loc: Option<Loc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EdgeKind {
    AddrOf,
    Assign,
    Load,
    Store,
    Gep { byte_off: Option<i64> },
    Memcpy { bytes: Option<u64> },
}

impl EdgeKind {
    fn name(&self) -> &'static str {
        match self {
            EdgeKind::AddrOf => "addr_of",
            EdgeKind::Assign => "assign",
            EdgeKind::Load => "load",
            EdgeKind::Store => "store",
            EdgeKind::Gep { .. } => "gep",
            EdgeKind::Memcpy { .. } => "memcpy",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", content = "func", rename_all = "snake_case")]
pub enum Owner {
    Module,
    GlobalInit,
    Function(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Callsite {
    pub id: CallsiteId,
    pub key: String,
    pub caller: String,
    pub kind: CallKind,
    #[serde(default)]
    pub callee: Option<String>,
    #[serde(default)]
    pub operand: Option<NodeId>,
    #[serde(default)]
    pub args: Vec<NodeId>,
    #[serde(default)]
    pub result: Option<NodeId>,
    pub sig: Signature,
    #[serde(default)]
    pub external_boundary: bool,
    #[serde(default)]
    pub loc: Option<Loc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallKind {
    Direct,
    Indirect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OmegaSeed {
    pub kind: OmegaSeedKind,
    pub target: SeedTarget,
    #[serde(default)]
    pub owner: Option<Owner>,
    #[serde(default)]
    pub loc: Option<Loc>,
    #[serde(default)]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OmegaSeedKind {
    ExportedSymbol,
    ImportedSymbol,
    ExternalCallBoundary,
    VarargCallBoundary,
    PtrToInt,
    IntToPtr,
    UnknownOperandEscape,
    UnknownResultExternal,
}

impl OmegaSeedKind {
    fn name(&self) -> &'static str {
        match self {
            OmegaSeedKind::ExportedSymbol => "exported_symbol",
            OmegaSeedKind::ImportedSymbol => "imported_symbol",
            OmegaSeedKind::ExternalCallBoundary => "external_call_boundary",
            OmegaSeedKind::VarargCallBoundary => "vararg_call_boundary",
            OmegaSeedKind::PtrToInt => "ptr_to_int",
            OmegaSeedKind::IntToPtr => "int_to_ptr",
            OmegaSeedKind::UnknownOperandEscape => "unknown_operand_escape",
            OmegaSeedKind::UnknownResultExternal => "unknown_result_external",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "target", content = "id", rename_all = "snake_case")]
pub enum SeedTarget {
    Node(NodeId),
    Callsite(CallsiteId),
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ValidationIssue {
    #[error("node id mismatch for {label}: expected {expected}, got {actual}")]
    NodeIdMismatch {
        expected: u32,
        actual: u32,
        label: String,
    },
    #[error("edge id mismatch: expected {expected}, got {actual}")]
    EdgeIdMismatch { expected: u32, actual: u32 },
    #[error("callsite id mismatch: expected {expected}, got {actual}")]
    CallsiteIdMismatch { expected: u32, actual: u32 },
    #[error("edge {edge:?} has dangling {which} endpoint {node:?}")]
    DanglingEdgeEndpoint {
        edge: EdgeId,
        which: &'static str,
        node: NodeId,
    },
    #[error("callsite {callsite:?} has dangling operand {node:?}")]
    DanglingCallsiteOperand { callsite: CallsiteId, node: NodeId },
    #[error("seed {kind} targets missing {target}")]
    DanglingSeedTarget { kind: String, target: String },
    #[error("edge {edge:?} violates {kind} invariant: {detail}")]
    EdgeKindInvariant {
        edge: EdgeId,
        kind: &'static str,
        detail: String,
    },
    #[error("load/store edge {edge:?} ({kind}) must be owned by a function or global_init")]
    LoadStoreNeedsOwner { edge: EdgeId, kind: &'static str },
    #[error("callsite {callsite:?} has invalid operand: {detail}")]
    CallsiteOperandInvariant {
        callsite: CallsiteId,
        detail: String,
    },
    #[error("pag metrics do not match the graph contents")]
    MetricsMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum NodeKey {
    GlobalObject(usize),
    FunctionObject(usize),
    AllocaObject(usize, usize),
    Param(usize, usize),
    Return(usize),
    SymbolValue(SymbolKind, usize),
    FunctionValue(usize, String),
    GlobalInitValue(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SymbolKind {
    Global,
    Function,
}

struct Builder<'a> {
    pir: &'a Pir,
    opts: &'a PagOpts,
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    callsites: Vec<Callsite>,
    omega_seeds: Vec<OmegaSeed>,
    node_ids: BTreeMap<NodeKey, NodeId>,
    symbol_addr_edges: BTreeSet<(ObjectKind, usize, SymbolKind, usize)>,
    globals: BTreeMap<String, usize>,
    functions: BTreeMap<String, usize>,
    callsite_ordinals: BTreeMap<usize, u32>,
}

impl<'a> Builder<'a> {
    fn new(pir: &'a Pir, opts: &'a PagOpts) -> Self {
        let globals = pir
            .globals
            .iter()
            .enumerate()
            .map(|(index, global)| (global.key.clone(), index))
            .collect();
        let functions = pir
            .functions
            .iter()
            .enumerate()
            .map(|(index, func)| (func.key.clone(), index))
            .collect();
        Self {
            pir,
            opts,
            nodes: Vec::new(),
            edges: Vec::new(),
            callsites: Vec::new(),
            omega_seeds: Vec::new(),
            node_ids: BTreeMap::new(),
            symbol_addr_edges: BTreeSet::new(),
            globals,
            functions,
            callsite_ordinals: BTreeMap::new(),
        }
    }

    fn build(mut self) -> Pag {
        for (index, global) in self.pir.globals.iter().enumerate() {
            let node = self.add_node(
                NodeKey::GlobalObject(index),
                format!("obj:global:{}", global.key),
                NodeKind::Object {
                    object: ObjectKind::Global,
                    key: global.key.clone(),
                    owner: None,
                },
            );
            if is_exported_global(global.exported, &global.key, self.opts) {
                self.add_seed(
                    OmegaSeedKind::ExportedSymbol,
                    SeedTarget::Node(node),
                    None,
                    None,
                    Some(global.key.clone()),
                );
            }
        }

        for (index, func) in self.pir.functions.iter().enumerate() {
            let object = self.add_node(
                NodeKey::FunctionObject(index),
                format!("obj:function:{}", func.key),
                NodeKind::Object {
                    object: ObjectKind::Function,
                    key: func.key.clone(),
                    owner: None,
                },
            );
            if is_exported_func(func.exported, &func.key, self.opts) {
                self.add_seed(
                    OmegaSeedKind::ExportedSymbol,
                    SeedTarget::Node(object),
                    None,
                    None,
                    Some(func.key.clone()),
                );
            }
            if func.external {
                self.add_seed(
                    OmegaSeedKind::ImportedSymbol,
                    SeedTarget::Node(object),
                    None,
                    None,
                    Some(func.key.clone()),
                );
            }
            for param_index in 0..func.sig.params.len() {
                let param = self.add_node(
                    NodeKey::Param(index, param_index),
                    format!("param:{}:{}", func.key, param_index),
                    NodeKind::Param {
                        func: func.key.clone(),
                        index: param_index as u32,
                    },
                );
                if let Some(name) = func.param_names.get(param_index) {
                    let value = self.value_node(index, Scope::Function(func.key.clone()), name);
                    self.add_edge(
                        EdgeKind::Assign,
                        param,
                        value,
                        Owner::Function(func.key.clone()),
                        None,
                    );
                }
            }
            self.add_node(
                NodeKey::Return(index),
                format!("ret:{}", func.key),
                NodeKind::Return {
                    func: func.key.clone(),
                },
            );
        }

        for (func_index, func) in self.pir.functions.iter().enumerate() {
            for (stmt_index, stmt) in func.body.iter().enumerate() {
                self.lower_stmt(
                    Owner::Function(func.key.clone()),
                    func_index,
                    stmt_index,
                    stmt,
                );
            }
        }

        for (stmt_index, stmt) in self.pir.global_init.iter().enumerate() {
            self.lower_stmt(Owner::GlobalInit, usize::MAX, stmt_index, stmt);
        }

        let metrics =
            PagMetrics::compute(&self.nodes, &self.edges, &self.callsites, &self.omega_seeds);

        Pag {
            module: self.pir.module.clone(),
            source: self.pir.source.clone(),
            metrics,
            nodes: self.nodes,
            edges: self.edges,
            callsites: self.callsites,
            omega_seeds: self.omega_seeds,
        }
    }

    fn lower_stmt(&mut self, owner: Owner, func_index: usize, stmt_index: usize, stmt: &Stmt) {
        match stmt {
            Stmt::Alloca { dest, loc, .. } => {
                let value = self.value_node(func_index, owner_scope(&owner), dest);
                let object = self.add_node(
                    NodeKey::AllocaObject(func_index, stmt_index),
                    format!("obj:alloca:{}:{}", owner_name(&owner), dest),
                    NodeKind::Object {
                        object: ObjectKind::Alloca,
                        key: dest.clone(),
                        owner: Some(owner_name(&owner).to_string()),
                    },
                );
                self.add_edge(EdgeKind::AddrOf, object, value, owner, loc.clone());
            }
            Stmt::Assign { dest, sources, loc } => {
                let dst = self.value_node(func_index, owner_scope(&owner), dest);
                for source in sources {
                    let src = self.operand_node(func_index, owner_scope(&owner), source);
                    self.add_edge(EdgeKind::Assign, src, dst, owner.clone(), loc.clone());
                }
            }
            Stmt::Load { dest, address, loc } => {
                let src = self.operand_node(func_index, owner_scope(&owner), address);
                let dst = self.value_node(func_index, owner_scope(&owner), dest);
                self.add_edge(EdgeKind::Load, src, dst, owner, loc.clone());
            }
            Stmt::Store {
                address,
                value,
                loc,
            } => {
                let src = self.operand_node(func_index, owner_scope(&owner), value);
                let dst = self.operand_node(func_index, owner_scope(&owner), address);
                self.add_edge(EdgeKind::Store, src, dst, owner, loc.clone());
            }
            Stmt::Gep {
                dest,
                base,
                byte_off,
                loc,
            } => {
                let src = self.operand_node(func_index, owner_scope(&owner), base);
                let dst = self.value_node(func_index, owner_scope(&owner), dest);
                self.add_edge(
                    EdgeKind::Gep {
                        byte_off: *byte_off,
                    },
                    src,
                    dst,
                    owner,
                    loc.clone(),
                );
            }
            Stmt::PtrToInt { dest, source, loc } => {
                let src = self.operand_node(func_index, owner_scope(&owner), source);
                self.value_node(func_index, owner_scope(&owner), dest);
                self.add_seed(
                    OmegaSeedKind::PtrToInt,
                    SeedTarget::Node(src),
                    Some(owner),
                    loc.clone(),
                    Some(source.clone()),
                );
            }
            Stmt::IntToPtr { dest, source, loc } => {
                self.operand_node(func_index, owner_scope(&owner), source);
                let dst = self.value_node(func_index, owner_scope(&owner), dest);
                self.add_seed(
                    OmegaSeedKind::IntToPtr,
                    SeedTarget::Node(dst),
                    Some(owner),
                    loc.clone(),
                    Some(dest.clone()),
                );
            }
            Stmt::Memcpy {
                dst,
                src,
                bytes,
                loc,
            } => {
                let src = self.operand_node(func_index, owner_scope(&owner), src);
                let dst = self.operand_node(func_index, owner_scope(&owner), dst);
                self.add_edge(
                    EdgeKind::Memcpy { bytes: *bytes },
                    src,
                    dst,
                    owner,
                    loc.clone(),
                );
            }
            Stmt::Memset { .. } => {}
            Stmt::Unknown {
                operands,
                results,
                loc,
                reason,
                ..
            } => {
                for operand in operands {
                    let node = self.operand_node(func_index, owner_scope(&owner), operand);
                    self.add_seed(
                        OmegaSeedKind::UnknownOperandEscape,
                        SeedTarget::Node(node),
                        Some(owner.clone()),
                        loc.clone(),
                        Some(reason.clone()),
                    );
                }
                for result in results {
                    let node = self.value_node(func_index, owner_scope(&owner), result);
                    self.add_seed(
                        OmegaSeedKind::UnknownResultExternal,
                        SeedTarget::Node(node),
                        Some(owner.clone()),
                        loc.clone(),
                        Some(reason.clone()),
                    );
                }
            }
            Stmt::Return { value, loc } => {
                if let Some(value) = value {
                    let src = self.operand_node(func_index, owner_scope(&owner), value);
                    if let Some(dst) = self.return_node(func_index) {
                        self.add_edge(EdgeKind::Assign, src, dst, owner, loc.clone());
                    }
                }
            }
            Stmt::CallDirect {
                callee,
                sig,
                args,
                dest,
                loc,
            } => {
                let arg_nodes: Vec<_> = args
                    .iter()
                    .map(|arg| self.operand_node(func_index, owner_scope(&owner), arg))
                    .collect();
                let result = dest
                    .as_ref()
                    .map(|dest| self.value_node(func_index, owner_scope(&owner), dest));
                let external_boundary = self
                    .functions
                    .get(callee)
                    .and_then(|index| self.pir.functions.get(*index))
                    .map(|func| func.external)
                    .unwrap_or(true);
                let callsite = self.add_callsite(
                    func_index,
                    CallKind::Direct,
                    Some(callee.clone()),
                    None,
                    arg_nodes.clone(),
                    result,
                    sig.clone(),
                    external_boundary,
                    loc.clone(),
                );
                if let Some(callee_index) = self.functions.get(callee).copied() {
                    if let Some(callee_func) = self.pir.functions.get(callee_index) {
                        if !callee_func.external {
                            for (arg, param_index) in arg_nodes
                                .iter()
                                .copied()
                                .zip(0..callee_func.sig.params.len())
                            {
                                if let Some(param) = self
                                    .node_ids
                                    .get(&NodeKey::Param(callee_index, param_index))
                                {
                                    self.add_edge(
                                        EdgeKind::Assign,
                                        arg,
                                        *param,
                                        owner.clone(),
                                        loc.clone(),
                                    );
                                }
                            }
                            if let Some(result) = result {
                                if let Some(ret) = self.return_node(callee_index) {
                                    self.add_edge(
                                        EdgeKind::Assign,
                                        ret,
                                        result,
                                        owner.clone(),
                                        loc.clone(),
                                    );
                                }
                            }
                        }
                    }
                }
                if external_boundary {
                    self.add_seed(
                        OmegaSeedKind::ExternalCallBoundary,
                        SeedTarget::Callsite(callsite),
                        Some(owner.clone()),
                        loc.clone(),
                        Some(callee.clone()),
                    );
                }
                if sig.vararg && self.direct_vararg_call_requires_boundary(callee) {
                    self.add_seed(
                        OmegaSeedKind::VarargCallBoundary,
                        SeedTarget::Callsite(callsite),
                        Some(owner),
                        loc.clone(),
                        Some(callee.clone()),
                    );
                }
            }
            Stmt::CallIndirect {
                operand,
                sig,
                args,
                dest,
                loc,
            } => {
                let node = self.operand_node(func_index, owner_scope(&owner), operand);
                let arg_nodes: Vec<_> = args
                    .iter()
                    .map(|arg| self.operand_node(func_index, owner_scope(&owner), arg))
                    .collect();
                let result = dest
                    .as_ref()
                    .map(|dest| self.value_node(func_index, owner_scope(&owner), dest));
                let callsite = self.add_callsite(
                    func_index,
                    CallKind::Indirect,
                    None,
                    Some(node),
                    arg_nodes,
                    result,
                    sig.clone(),
                    false,
                    loc.clone(),
                );
                if sig.vararg {
                    self.add_seed(
                        OmegaSeedKind::VarargCallBoundary,
                        SeedTarget::Callsite(callsite),
                        Some(owner),
                        loc.clone(),
                        Some(operand.clone()),
                    );
                }
            }
            Stmt::GlobalRef { .. } => {}
        }
    }

    fn add_node(&mut self, key: NodeKey, label: String, kind: NodeKind) -> NodeId {
        if let Some(id) = self.node_ids.get(&key) {
            return *id;
        }
        let id = NodeId(self.nodes.len() as u32);
        self.nodes.push(Node { id, label, kind });
        self.node_ids.insert(key, id);
        id
    }

    fn direct_vararg_call_requires_boundary(&self, callee: &str) -> bool {
        if is_known_benign_vararg_callee(callee) {
            return false;
        }
        let Some(func) = self
            .functions
            .get(callee)
            .and_then(|index| self.pir.functions.get(*index))
        else {
            return true;
        };
        func.external || func.body.iter().any(stmt_consumes_varargs)
    }

    fn add_edge(
        &mut self,
        kind: EdgeKind,
        src: NodeId,
        dst: NodeId,
        owner: Owner,
        loc: Option<Loc>,
    ) -> EdgeId {
        let id = EdgeId(self.edges.len() as u32);
        self.edges.push(Edge {
            id,
            kind,
            src,
            dst,
            owner,
            loc,
        });
        id
    }

    fn add_callsite(
        &mut self,
        func_index: usize,
        kind: CallKind,
        callee: Option<String>,
        operand: Option<NodeId>,
        args: Vec<NodeId>,
        result: Option<NodeId>,
        sig: Signature,
        external_boundary: bool,
        loc: Option<Loc>,
    ) -> CallsiteId {
        let ordinal = self.callsite_ordinals.entry(func_index).or_default();
        let caller = self
            .pir
            .functions
            .get(func_index)
            .map(|func| func.key.clone())
            .unwrap_or_else(|| "global_init".to_string());
        let key = format!("{}@{}#{}", caller, loc_key(loc.as_ref()), *ordinal);
        *ordinal += 1;
        let id = CallsiteId(self.callsites.len() as u32);
        self.callsites.push(Callsite {
            id,
            key,
            caller,
            kind,
            callee,
            operand,
            args,
            result,
            sig,
            external_boundary,
            loc,
        });
        id
    }

    fn add_seed(
        &mut self,
        kind: OmegaSeedKind,
        target: SeedTarget,
        owner: Option<Owner>,
        loc: Option<Loc>,
        detail: Option<String>,
    ) {
        self.omega_seeds.push(OmegaSeed {
            kind,
            target,
            owner,
            loc,
            detail,
        });
    }

    fn value_node(&mut self, func_index: usize, scope: Scope, key: &str) -> NodeId {
        match scope {
            Scope::Function(_) => self.add_node(
                NodeKey::FunctionValue(func_index, key.to_string()),
                format!("val:{}:{}", owner_label(&scope), key),
                NodeKind::Value { scope },
            ),
            Scope::GlobalInit => self.add_node(
                NodeKey::GlobalInitValue(key.to_string()),
                format!("val:global_init:{}", key),
                NodeKind::Value { scope },
            ),
            Scope::Module => unreachable!("module-scoped values are symbols"),
        }
    }

    fn operand_node(&mut self, func_index: usize, scope: Scope, operand: &str) -> NodeId {
        // Symbol operands lowered from LLVM carry an `@` sigil (`@hello`) while object keys
        // are the bare symbol (`hello`); hand-written fixtures may use either form. Try the
        // operand verbatim first, then with a leading `@` stripped, so both resolve.
        let symbol = self.resolve_symbol(operand);
        if let Some(index) = self.globals.get(symbol).copied() {
            let value = self.add_node(
                NodeKey::SymbolValue(SymbolKind::Global, index),
                format!("sym:global:{}", operand),
                NodeKind::Value {
                    scope: Scope::Module,
                },
            );
            self.ensure_symbol_addr_of(ObjectKind::Global, index, SymbolKind::Global, index, value);
            return value;
        }
        if let Some(index) = self.functions.get(symbol).copied() {
            let value = self.add_node(
                NodeKey::SymbolValue(SymbolKind::Function, index),
                format!("sym:function:{}", operand),
                NodeKind::Value {
                    scope: Scope::Module,
                },
            );
            self.ensure_symbol_addr_of(
                ObjectKind::Function,
                index,
                SymbolKind::Function,
                index,
                value,
            );
            return value;
        }
        self.value_node(func_index, scope, operand)
    }

    /// Resolve a symbol operand to its object-map key: the operand verbatim if a global or
    /// function already uses it as a key, else with a leading `@` stripped.
    fn resolve_symbol<'b>(&self, operand: &'b str) -> &'b str {
        if self.globals.contains_key(operand) || self.functions.contains_key(operand) {
            return operand;
        }
        operand.strip_prefix('@').unwrap_or(operand)
    }

    fn ensure_symbol_addr_of(
        &mut self,
        object_kind: ObjectKind,
        object_index: usize,
        symbol_kind: SymbolKind,
        symbol_index: usize,
        value: NodeId,
    ) {
        if !self
            .symbol_addr_edges
            .insert((object_kind, object_index, symbol_kind, symbol_index))
        {
            return;
        }
        let object = match object_kind {
            ObjectKind::Global => self.node_ids[&NodeKey::GlobalObject(object_index)],
            ObjectKind::Function => self.node_ids[&NodeKey::FunctionObject(object_index)],
            ObjectKind::Alloca => unreachable!("symbols do not name alloca objects"),
        };
        self.add_edge(EdgeKind::AddrOf, object, value, Owner::Module, None);
    }

    fn return_node(&self, func_index: usize) -> Option<NodeId> {
        self.node_ids.get(&NodeKey::Return(func_index)).copied()
    }
}

fn owner_scope(owner: &Owner) -> Scope {
    match owner {
        Owner::Module => Scope::Module,
        Owner::GlobalInit => Scope::GlobalInit,
        Owner::Function(func) => Scope::Function(func.clone()),
    }
}

fn owner_name(owner: &Owner) -> &str {
    match owner {
        Owner::Module => "module",
        Owner::GlobalInit => "global_init",
        Owner::Function(func) => func,
    }
}

fn owner_label(scope: &Scope) -> &str {
    match scope {
        Scope::Module => "module",
        Scope::GlobalInit => "global_init",
        Scope::Function(func) => func,
    }
}

fn loc_key(loc: Option<&Loc>) -> String {
    match loc {
        Some(loc) => format!("{}:{}:{}", loc.file, loc.line, loc.col),
        None => "!noloc".to_string(),
    }
}

fn stmt_consumes_varargs(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Unknown { op, reason, .. } => {
            reason == "va_arg" || reason == "varargs_intrinsic" || op.starts_with("llvm.va_")
        }
        _ => false,
    }
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

fn is_exported_func(marked: bool, key: &str, opts: &PagOpts) -> bool {
    opts.exports.contains(key)
        || (opts.build_mode == BuildMode::Library && marked)
        || (opts.build_mode == BuildMode::Executable && key == "main")
}

fn is_exported_global(marked: bool, key: &str, opts: &PagOpts) -> bool {
    opts.exports.contains(key) || (opts.build_mode == BuildMode::Library && marked)
}
