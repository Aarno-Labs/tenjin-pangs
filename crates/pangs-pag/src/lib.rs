use std::collections::{BTreeMap, BTreeSet};

use pangs_pir::{external_return_alias_arg, Loc, Pir, Signature, Stmt, VarArgPosition};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PagOpts {
    pub build_mode: BuildMode,
    #[serde(default)]
    pub exports: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub safe_indirect_vararg_callsites: BTreeSet<String>,
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
    ExternalReadonly,
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
    HeapObject(usize, usize),
    ExternalReadonlyObject(String),
    Param(usize, usize),
    Return(usize),
    SymbolValue(SymbolKind, usize),
    FunctionValue(usize, String),
    ExternalNonPointerWrite(usize, usize),
    GlobalInitValue(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenPrintfEffect {
    NoClientWrite,
    WritesArg { index: usize },
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
    positional_vararg_functions: BTreeSet<String>,
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
        let positional_vararg_functions = positionally_modeled_vararg_functions(pir, opts);
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
            positional_vararg_functions,
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
            Stmt::PtrToInt {
                dest,
                source,
                comparison_only,
                loc,
            } => {
                let src = self.operand_node(func_index, owner_scope(&owner), source);
                self.value_node(func_index, owner_scope(&owner), dest);
                if !comparison_only {
                    self.add_seed(
                        OmegaSeedKind::PtrToInt,
                        SeedTarget::Node(src),
                        Some(owner),
                        loc.clone(),
                        Some(source.clone()),
                    );
                }
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
            Stmt::VarArg { dest, .. } => {
                // Direct callsites add the proven actual-to-result edges. Keeping node creation
                // here also makes a malformed/unbound model fail closed as an empty value.
                self.value_node(func_index, owner_scope(&owner), dest);
            }
            Stmt::Memcpy {
                dst,
                src,
                bytes,
                loc,
                ..
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
            Stmt::Memset { dst, loc, .. } => {
                // Model the write even though the fill byte is not a pointer.  The synthetic
                // source prevents the pointer solver from interpreting the scalar operand,
                // while the Store edge lets allocation-specific write proofs see the effect.
                let destination = self.operand_node(func_index, owner_scope(&owner), dst);
                let source = self.add_node(
                    NodeKey::ExternalNonPointerWrite(func_index, stmt_index),
                    format!(
                        "val:{}:@memset-nonpointer-write:{stmt_index}",
                        owner_name(&owner)
                    ),
                    NodeKind::Value {
                        scope: owner_scope(&owner),
                    },
                );
                self.add_edge(EdgeKind::Store, source, destination, owner, loc.clone());
            }
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
                let fresh_allocation = is_fresh_allocator(callee) && result.is_some();
                let is_external = self
                    .functions
                    .get(callee)
                    .and_then(|index| self.pir.functions.get(*index))
                    .map(|func| func.external)
                    .unwrap_or(true);
                let return_alias = is_external
                    .then(|| external_return_alias_arg(callee))
                    .flatten()
                    .and_then(|arg_index| {
                        result
                            .zip(arg_nodes.get(arg_index).copied())
                            .map(|(result, arg)| (arg, result))
                    });
                let external_readonly_result = is_external
                    .then(|| external_readonly_result_model(callee))
                    .flatten()
                    .zip(result);
                let pure_constant_external = is_external && external_constant_result_model(callee);
                let printf_effect = is_external
                    .then(|| proven_printf_effect(self.pir, callee, args))
                    .flatten();
                let external_boundary = !fresh_allocation
                    && return_alias.is_none()
                    && external_readonly_result.is_none()
                    && !pure_constant_external
                    && printf_effect.is_none()
                    && self
                        .functions
                        .get(callee)
                        .and_then(|index| self.pir.functions.get(*index))
                        .map(|func| func.external)
                        .unwrap_or(true);
                if let Some((arg, result)) = return_alias {
                    self.add_edge(EdgeKind::Assign, arg, result, owner.clone(), loc.clone());
                }
                if let Some((model, result)) = external_readonly_result {
                    let slot = self.external_readonly_object(&format!("{model}:slot"));
                    let table = self.external_readonly_object(&format!("{model}:table"));
                    self.add_edge(EdgeKind::AddrOf, slot, result, owner.clone(), loc.clone());
                    self.add_edge(EdgeKind::AddrOf, table, slot, owner.clone(), loc.clone());
                }
                if let Some(result) = result.filter(|_| fresh_allocation) {
                    let object = self.add_node(
                        NodeKey::HeapObject(func_index, stmt_index),
                        format!("obj:heap:{}:{stmt_index}", owner_name(&owner)),
                        NodeKind::Object {
                            object: ObjectKind::Alloca,
                            key: format!("{callee}@{stmt_index}"),
                            owner: Some(owner_name(&owner).to_string()),
                        },
                    );
                    self.add_edge(EdgeKind::AddrOf, object, result, owner.clone(), loc.clone());
                }
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
                if let Some(ProvenPrintfEffect::WritesArg { index }) = printf_effect {
                    if let Some(&destination) = arg_nodes.get(index) {
                        let source = self.add_node(
                            NodeKey::ExternalNonPointerWrite(func_index, stmt_index),
                            format!(
                                "val:{}:@external-nonpointer-write:{stmt_index}",
                                owner_name(&owner)
                            ),
                            NodeKind::Value {
                                scope: owner_scope(&owner),
                            },
                        );
                        self.add_edge(
                            EdgeKind::Store,
                            source,
                            destination,
                            owner.clone(),
                            loc.clone(),
                        );
                    }
                }
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
                            if self.positional_vararg_functions.contains(callee) {
                                for access in callee_func.body.iter().filter_map(|stmt| {
                                    let Stmt::VarArg { dest, position, .. } = stmt else {
                                        return None;
                                    };
                                    Some((dest, *position))
                                }) {
                                    let destination = self.value_node(
                                        callee_index,
                                        Scope::Function(callee.clone()),
                                        access.0,
                                    );
                                    let fixed = callee_func.sig.params.len();
                                    let actuals: &[NodeId] = match access.1 {
                                        VarArgPosition::Exact { index } => arg_nodes
                                            .get(fixed + index as usize)
                                            .map(std::slice::from_ref)
                                            .unwrap_or(&[]),
                                        VarArgPosition::From { index } => {
                                            arg_nodes.get(fixed + index as usize..).unwrap_or(&[])
                                        }
                                    };
                                    for &actual in actuals {
                                        self.add_edge(
                                            EdgeKind::Assign,
                                            actual,
                                            destination,
                                            owner.clone(),
                                            loc.clone(),
                                        );
                                    }
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
                if sig.vararg && self.direct_vararg_call_requires_boundary(callee, args) {
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
                if sig.vararg && self.indirect_vararg_call_requires_boundary(callsite) {
                    self.add_seed(
                        OmegaSeedKind::VarargCallBoundary,
                        SeedTarget::Callsite(callsite),
                        Some(owner),
                        loc.clone(),
                        Some(operand.clone()),
                    );
                }
            }
            Stmt::GlobalRef { .. } | Stmt::ScalarOp { .. } => {}
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

    fn direct_vararg_call_requires_boundary(&self, callee: &str, args: &[String]) -> bool {
        if direct_vararg_call_is_benign(self.pir, callee, args) {
            return false;
        }
        let Some(func) = self
            .functions
            .get(callee)
            .and_then(|index| self.pir.functions.get(*index))
        else {
            return true;
        };
        func.external
            || (!self.positional_vararg_functions.contains(callee)
                && func.body.iter().any(stmt_consumes_varargs))
    }

    fn indirect_vararg_call_requires_boundary(&self, callsite: CallsiteId) -> bool {
        let key = &self.callsites[callsite.0 as usize].key;
        !self.opts.safe_indirect_vararg_callsites.contains(key)
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

    #[allow(clippy::too_many_arguments)]
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
                format!("val:global_init:{key}"),
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
        let global_index = self.globals.get(symbol).copied().or_else(|| {
            llvm_pointer_cast_global_operand(operand).and_then(|global| {
                self.globals
                    .get(global.as_str())
                    .or_else(|| self.globals.get(&format!("@{global}")))
                    .copied()
            })
        });
        if let Some(index) = global_index {
            let value = self.add_node(
                NodeKey::SymbolValue(SymbolKind::Global, index),
                format!("sym:global:{operand}"),
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
                format!("sym:function:{operand}"),
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
            ObjectKind::Alloca | ObjectKind::ExternalReadonly => {
                unreachable!("symbols do not name synthetic storage objects")
            }
        };
        self.add_edge(EdgeKind::AddrOf, object, value, Owner::Module, None);
    }

    fn return_node(&self, func_index: usize) -> Option<NodeId> {
        self.node_ids.get(&NodeKey::Return(func_index)).copied()
    }

    fn external_readonly_object(&mut self, key: &str) -> NodeId {
        self.add_node(
            NodeKey::ExternalReadonlyObject(key.into()),
            format!("obj:external-readonly:{key}"),
            NodeKind::Object {
                object: ObjectKind::ExternalReadonly,
                key: key.into(),
                owner: None,
            },
        )
    }
}

fn is_fresh_allocator(callee: &str) -> bool {
    matches!(
        callee.strip_prefix('@').unwrap_or(callee),
        "malloc" | "calloc" | "aligned_alloc"
    )
}

/// Exact-name external functions whose pointer result leads only to stable external readonly
/// storage. The returned slot and its table are represented as non-client objects, so reads of
/// libc classification data cannot become module-global accesses.
fn external_readonly_result_model(callee: &str) -> Option<&'static str> {
    matches!(callee.strip_prefix('@').unwrap_or(callee), "__ctype_b_loc").then_some("glibc-ctype-b")
}

/// Glibc's `__ctype_get_*` accessors return process-invariant scalar values.  They do not
/// observe or modify client storage, so treating them as an external boundary would introduce
/// spurious module-wide effects into disposition analysis.
fn external_constant_result_model(callee: &str) -> bool {
    callee
        .strip_prefix('@')
        .unwrap_or(callee)
        .starts_with("__ctype_get_")
}

fn printf_format_arg(callee: &str) -> Option<usize> {
    match callee.strip_prefix('@').unwrap_or(callee) {
        "printf" => Some(0),
        "fprintf" | "sprintf" | "dprintf" => Some(1),
        "snprintf" => Some(2),
        _ => None,
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
        Stmt::VarArg { .. } => true,
        Stmt::Unknown { op, reason, .. } => {
            reason == "va_arg" || reason == "varargs_intrinsic" || op.starts_with("llvm.va_")
        }
        _ => false,
    }
}

/// Functions whose visible `va_arg` operations can be bound to direct callsite actuals without
/// an opaque ABI boundary. The proof is deliberately whole-function and build-mode-sensitive:
/// address-taken functions and library-visible definitions may have callers absent from the PIR.
pub fn positionally_modeled_vararg_functions(pir: &Pir, opts: &PagOpts) -> BTreeSet<String> {
    pir.functions
        .iter()
        .filter(|func| {
            if func.external
                || !func.sig.vararg
                || func.address_taken
                || is_exported_func(func.exported, &func.key, opts)
            {
                return false;
            }
            let accesses = func
                .body
                .iter()
                .filter_map(|stmt| match stmt {
                    Stmt::VarArg { position, .. } => Some(*position),
                    _ => None,
                })
                .collect::<Vec<_>>();
            if accesses.is_empty()
                || func.body.iter().any(|stmt| {
                    matches!(stmt, Stmt::Unknown { op, reason, .. }
                        if reason == "va_arg"
                            || reason == "varargs_intrinsic"
                            || op.starts_with("llvm.va_"))
                })
            {
                return false;
            }
            let fixed = func.sig.params.len();
            let calls = pir
                .functions
                .iter()
                .flat_map(|caller| caller.body.iter())
                .filter_map(|stmt| match stmt {
                    Stmt::CallDirect { callee, args, .. } if callee == &func.key => {
                        Some(args.len())
                    }
                    _ => None,
                });
            let mut saw_call = false;
            for actual_count in calls {
                saw_call = true;
                if accesses.iter().any(|position| {
                    let index = match position {
                        VarArgPosition::Exact { index } | VarArgPosition::From { index } => *index,
                    } as usize;
                    actual_count <= fixed + index
                }) {
                    return false;
                }
            }
            saw_call
        })
        .map(|func| func.key.clone())
        .collect()
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

/// Whether this direct variadic call has a proved pointer-safe ABI boundary. Project-specific
/// wrappers retain their inspected whole-function contracts. Standard printf-family calls are
/// accepted only when the exact format operand resolves to a constant LLVM byte string and its
/// parsed conversion sequence contains no `%n`; every unsupported or dynamic shape fails closed.
pub fn direct_vararg_call_is_benign(pir: &Pir, callee: &str, args: &[String]) -> bool {
    if is_known_benign_vararg_callee(callee) {
        return true;
    }
    proven_printf_effect(pir, callee, args).is_some()
}

pub fn proven_printf_effect(
    pir: &Pir,
    callee: &str,
    args: &[String],
) -> Option<ProvenPrintfEffect> {
    let format_index = printf_format_arg(callee)?;
    let safe = args
        .get(format_index)
        .and_then(|operand| constant_format_bytes(pir, operand))
        .is_some_and(|format| format_is_proven_percent_n_free(&format));
    if !safe {
        return None;
    }
    match callee.strip_prefix('@').unwrap_or(callee) {
        "printf" | "fprintf" | "dprintf" => Some(ProvenPrintfEffect::NoClientWrite),
        "sprintf" | "snprintf" => Some(ProvenPrintfEffect::WritesArg { index: 0 }),
        _ => None,
    }
}

fn constant_format_bytes(pir: &Pir, operand: &str) -> Option<Vec<u8>> {
    let key = llvm_global_operand_key(operand)?;
    let global = pir
        .globals
        .iter()
        .find(|global| global.key == key || global.key.strip_prefix('@') == Some(key.as_str()))?;
    if !global.is_const {
        return None;
    }
    decode_llvm_c_string(global.initializer_ir.as_deref()?)
}

fn llvm_global_operand_key(operand: &str) -> Option<String> {
    let at = operand.find('@')?;
    let tail = &operand[at + 1..];
    if tail.starts_with('"') {
        return None;
    }
    let len = tail
        .bytes()
        .take_while(|byte| {
            byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'.' | b'$' | b'-')
        })
        .count();
    (len > 0).then(|| tail[..len].to_string())
}

/// Extract the allocation named by an exact LLVM constant pointer cast.  This is deliberately
/// narrower than `llvm_global_operand_key`: a GEP or expression mentioning multiple globals is
/// not an exact root address and must retain its own value node.
fn llvm_pointer_cast_global_operand(operand: &str) -> Option<String> {
    if !(operand.contains(" bitcast (") || operand.contains(" addrspacecast ("))
        || operand.contains("getelementptr")
    {
        return None;
    }
    let key = llvm_global_operand_key(operand)?;
    let first_at = operand.find('@')?;
    if operand[first_at + 1..].contains('@') {
        return None;
    }
    Some(key)
}

fn decode_llvm_c_string(initializer: &str) -> Option<Vec<u8>> {
    let start = initializer.find("c\"")? + 2;
    let encoded = initializer.get(start..initializer.len().checked_sub(1)?)?;
    let mut bytes = Vec::with_capacity(encoded.len());
    let raw = encoded.as_bytes();
    let mut index = 0usize;
    while index < raw.len() {
        if raw[index] == b'\\' {
            if raw.get(index + 1) == Some(&b'\\') {
                bytes.push(b'\\');
                index += 2;
                continue;
            }
            let hi = *raw.get(index + 1)?;
            let lo = *raw.get(index + 2)?;
            bytes.push(hex_nibble(hi)? << 4 | hex_nibble(lo)?);
            index += 3;
        } else {
            bytes.push(raw[index]);
            index += 1;
        }
    }
    if let Some(nul) = bytes.iter().position(|byte| *byte == 0) {
        bytes.truncate(nul);
    }
    Some(bytes)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn format_is_proven_percent_n_free(format: &[u8]) -> bool {
    let mut index = 0usize;
    while index < format.len() {
        if format[index] != b'%' {
            index += 1;
            continue;
        }
        index += 1;
        if format.get(index) == Some(&b'%') {
            index += 1;
            continue;
        }

        // Optional positional argument, flags, width, precision, and length modifiers.
        let positional_start = index;
        while format.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        if format.get(index) != Some(&b'$') {
            index = positional_start;
        } else {
            index += 1;
        }
        while format
            .get(index)
            .is_some_and(|byte| b"#0- +'I".contains(byte))
        {
            index += 1;
        }
        if format.get(index) == Some(&b'*') {
            index += 1;
            while format.get(index).is_some_and(u8::is_ascii_digit) {
                index += 1;
            }
            if format.get(index) == Some(&b'$') {
                index += 1;
            }
        } else {
            while format.get(index).is_some_and(u8::is_ascii_digit) {
                index += 1;
            }
        }
        if format.get(index) == Some(&b'.') {
            index += 1;
            if format.get(index) == Some(&b'*') {
                index += 1;
                while format.get(index).is_some_and(u8::is_ascii_digit) {
                    index += 1;
                }
                if format.get(index) == Some(&b'$') {
                    index += 1;
                }
            } else {
                while format.get(index).is_some_and(u8::is_ascii_digit) {
                    index += 1;
                }
            }
        }
        while format
            .get(index)
            .is_some_and(|byte| b"hljztLq".contains(byte))
        {
            index += 1;
        }
        if format.get(index) == Some(&b'n') {
            return false;
        }
        let Some(conversion) = format.get(index) else {
            return false;
        };
        if !b"diouxXfFeEgGaAcspmCS%".contains(conversion) {
            return false;
        }
        index += 1;
    }
    true
}

fn is_exported_func(marked: bool, key: &str, opts: &PagOpts) -> bool {
    opts.exports.contains(key)
        || (opts.build_mode == BuildMode::Library && marked)
        || (opts.build_mode == BuildMode::Executable && key == "main")
}

fn is_exported_global(marked: bool, key: &str, opts: &PagOpts) -> bool {
    opts.exports.contains(key) || (opts.build_mode == BuildMode::Library && marked)
}

#[cfg(test)]
mod tests {
    use super::{
        direct_vararg_call_is_benign, EdgeKind, NodeKind, ObjectKind, OmegaSeedKind, Pag, PagOpts,
        SeedTarget,
    };
    use pangs_pir::{Global, Pir};

    #[test]
    fn printf_format_proof_decodes_literals_and_fails_closed() {
        let format = |key: &str, initializer: &str, is_const: bool| Global {
            key: key.to_string(),
            is_const,
            mutable: !is_const,
            initializer_ir: Some(initializer.to_string()),
            ..Global::default()
        };
        let pir = Pir {
            module: "printf-formats".to_string(),
            source: None,
            lowering: Default::default(),
            target: None,
            functions: vec![],
            globals: vec![
                format("safe", "[16 x i8] c\"%2$.*3$s %%n\\00\"", true),
                format("escaped_backslash", "[6 x i8] c\"\\\\%03o\\00\"", true),
                format("percent_n", "[5 x i8] c\"%hhn\\00\"", true),
                format("encoded", "[3 x i8] c\"\\25n\\00\"", true),
                format("invalid_escape", "[3 x i8] c\"\\xz\\00\"", true),
                format("unknown", "[4 x i8] c\"%wn\\00\"", true),
                format("mutable", "[3 x i8] c\"%s\\00\"", false),
            ],
            global_init: vec![],
        };
        let fprintf_args = |format: &str| {
            vec![
                "stream".to_string(),
                format.to_string(),
                "value".to_string(),
            ]
        };

        assert!(direct_vararg_call_is_benign(
            &pir,
            "fprintf",
            &fprintf_args("i8* getelementptr ([16 x i8], [16 x i8]* @safe, i64 0, i64 0)")
        ));
        assert!(direct_vararg_call_is_benign(
            &pir,
            "fprintf",
            &fprintf_args("@escaped_backslash")
        ));
        assert!(!direct_vararg_call_is_benign(
            &pir,
            "fprintf",
            &fprintf_args("@percent_n")
        ));
        assert!(!direct_vararg_call_is_benign(
            &pir,
            "fprintf",
            &fprintf_args("@encoded")
        ));
        assert!(!direct_vararg_call_is_benign(
            &pir,
            "fprintf",
            &fprintf_args("@invalid_escape")
        ));
        assert!(!direct_vararg_call_is_benign(
            &pir,
            "fprintf",
            &fprintf_args("@unknown")
        ));
        assert!(!direct_vararg_call_is_benign(
            &pir,
            "fprintf",
            &fprintf_args("@mutable")
        ));
        assert!(!direct_vararg_call_is_benign(
            &pir,
            "fprintf",
            &fprintf_args("dynamic_format")
        ));
    }

    #[test]
    fn modeled_externals_do_not_create_omega_boundaries() {
        let pir: Pir = serde_json::from_str(
            r#"{
                "module":"libc-summary",
                "globals":[
                    {"key":"@fmt_safe","is_const":true,"mutable":false,"initializer_ir":"[3 x i8] c\"%s\\00\""},
                    {"key":"@fmt_percent_n","is_const":true,"mutable":false,"initializer_ir":"[3 x i8] c\"%n\\00\""}
                ],
                "functions":[
                    {"key":"main","exported":true,"sig":{"ret":{"class":"void"},"params":[]},"body":[
                        {"kind":"call_direct","callee":"strchr","sig":{"ret":{"class":"integer"},"params":[{"class":"integer"},{"class":"integer"}]},"args":["input","zero"],"dest":"found"},
                        {"kind":"call_direct","callee":"__ctype_b_loc","sig":{"ret":{"class":"integer"},"params":[]},"dest":"ctype"},
                        {"kind":"call_direct","callee":"__ctype_get_mb_cur_max","sig":{"ret":{"class":"integer"},"params":[]},"dest":"mb_cur_max"},
                        {"kind":"call_direct","callee":"fprintf","sig":{"ret":{"class":"integer"},"params":[{"class":"integer"},{"class":"integer"}],"vararg":true},"args":["stream","@fmt_safe","input"],"dest":"printed"},
                        {"kind":"call_direct","callee":"fprintf","sig":{"ret":{"class":"integer"},"params":[{"class":"integer"},{"class":"integer"}],"vararg":true},"args":["stream","@fmt_percent_n","output"],"dest":"counted"},
                        {"kind":"call_direct","callee":"fprintf","sig":{"ret":{"class":"integer"},"params":[{"class":"integer"},{"class":"integer"}],"vararg":true},"args":["stream","dynamic_format","input"],"dest":"dynamic"},
                        {"kind":"call_direct","callee":"sprintf","sig":{"ret":{"class":"integer"},"params":[{"class":"integer"},{"class":"integer"}],"vararg":true},"args":["output","@fmt_safe","input"],"dest":"formatted"},
                        {"kind":"call_direct","callee":"unmodeled_search","sig":{"ret":{"class":"integer"},"params":[{"class":"integer"}]},"args":["input"],"dest":"unknown"}
                    ]},
                    {"key":"strchr","external":true,"sig":{"ret":{"class":"integer"},"params":[{"class":"integer"},{"class":"integer"}]},"body":[]},
                    {"key":"__ctype_b_loc","external":true,"sig":{"ret":{"class":"integer"},"params":[]},"body":[]},
                    {"key":"__ctype_get_mb_cur_max","external":true,"sig":{"ret":{"class":"integer"},"params":[]},"body":[]},
                    {"key":"fprintf","external":true,"sig":{"ret":{"class":"integer"},"params":[{"class":"integer"},{"class":"integer"}],"vararg":true},"body":[]},
                    {"key":"sprintf","external":true,"sig":{"ret":{"class":"integer"},"params":[{"class":"integer"},{"class":"integer"}],"vararg":true},"body":[]},
                    {"key":"unmodeled_search","external":true,"sig":{"ret":{"class":"integer"},"params":[{"class":"integer"}]},"body":[]}
                ]
            }"#,
        )
        .unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        let strchr = pag
            .callsites
            .iter()
            .find(|callsite| callsite.callee.as_deref() == Some("strchr"))
            .unwrap();
        assert!(!strchr.external_boundary);
        assert!(pag.edges.iter().any(|edge| {
            edge.kind == EdgeKind::Assign
                && edge.src == strchr.args[0]
                && Some(edge.dst) == strchr.result
        }));
        assert!(!pag.omega_seeds.iter().any(|seed| {
            seed.kind == OmegaSeedKind::ExternalCallBoundary
                && seed.target == SeedTarget::Callsite(strchr.id)
        }));

        let ctype = pag
            .callsites
            .iter()
            .find(|callsite| callsite.callee.as_deref() == Some("__ctype_b_loc"))
            .unwrap();
        assert!(!ctype.external_boundary);
        assert!(!pag.omega_seeds.iter().any(|seed| {
            seed.kind == OmegaSeedKind::ExternalCallBoundary
                && seed.target == SeedTarget::Callsite(ctype.id)
        }));
        let slot = pag
            .nodes
            .iter()
            .find(|node| {
                matches!(
                    &node.kind,
                    NodeKind::Object {
                        object: ObjectKind::ExternalReadonly,
                        key,
                        ..
                    } if key == "glibc-ctype-b:slot"
                )
            })
            .unwrap();
        assert!(pag.edges.iter().any(|edge| {
            edge.kind == EdgeKind::AddrOf && edge.src == slot.id && Some(edge.dst) == ctype.result
        }));

        let ctype_get = pag
            .callsites
            .iter()
            .find(|callsite| callsite.callee.as_deref() == Some("__ctype_get_mb_cur_max"))
            .unwrap();
        assert!(!ctype_get.external_boundary);
        assert!(!pag.omega_seeds.iter().any(|seed| {
            seed.kind == OmegaSeedKind::ExternalCallBoundary
                && seed.target == SeedTarget::Callsite(ctype_get.id)
        }));

        let fprintf_calls = pag
            .callsites
            .iter()
            .filter(|callsite| callsite.callee.as_deref() == Some("fprintf"))
            .collect::<Vec<_>>();
        assert_eq!(fprintf_calls.len(), 3);
        let fprintf = fprintf_calls[0];
        assert!(!fprintf.external_boundary);
        assert!(!pag.omega_seeds.iter().any(|seed| {
            matches!(
                seed.kind,
                OmegaSeedKind::ExternalCallBoundary | OmegaSeedKind::VarargCallBoundary
            ) && seed.target == SeedTarget::Callsite(fprintf.id)
        }));
        assert!(!pag
            .edges
            .iter()
            .any(|edge| { edge.kind == EdgeKind::Store && edge.dst == fprintf.args[0] }));
        assert_eq!(
            pag.omega_seeds
                .iter()
                .filter(|seed| {
                    seed.kind == OmegaSeedKind::VarargCallBoundary
                        && fprintf_calls
                            .iter()
                            .any(|callsite| seed.target == SeedTarget::Callsite(callsite.id))
                })
                .count(),
            2,
            "%n and dynamic formats must fail closed"
        );
        for callsite in &fprintf_calls[1..] {
            assert!(callsite.external_boundary);
            assert!(pag.omega_seeds.iter().any(|seed| {
                seed.kind == OmegaSeedKind::ExternalCallBoundary
                    && seed.target == SeedTarget::Callsite(callsite.id)
            }));
        }

        let sprintf = pag
            .callsites
            .iter()
            .find(|callsite| callsite.callee.as_deref() == Some("sprintf"))
            .unwrap();
        assert!(!sprintf.external_boundary);
        assert!(!pag.omega_seeds.iter().any(|seed| {
            seed.kind == OmegaSeedKind::ExternalCallBoundary
                && seed.target == SeedTarget::Callsite(sprintf.id)
        }));
        assert!(!pag.omega_seeds.iter().any(|seed| {
            seed.kind == OmegaSeedKind::VarargCallBoundary
                && seed.target == SeedTarget::Callsite(sprintf.id)
        }));
        assert!(pag
            .edges
            .iter()
            .any(|edge| edge.kind == EdgeKind::Store && edge.dst == sprintf.args[0]));

        let unmodeled = pag
            .callsites
            .iter()
            .find(|callsite| callsite.callee.as_deref() == Some("unmodeled_search"))
            .unwrap();
        assert!(unmodeled.external_boundary);
        assert!(pag.omega_seeds.iter().any(|seed| {
            seed.kind == OmegaSeedKind::ExternalCallBoundary
                && seed.target == SeedTarget::Callsite(unmodeled.id)
        }));
    }

    #[test]
    fn comparison_only_ptrtoint_does_not_seed_omega() {
        let pir: Pir = serde_json::from_str(
            r#"{
                "module":"ptrtoint-uses",
                "globals":[{"key":"g","mutable":true}],
                "functions":[{"key":"main","sig":{"ret":{"class":"void"},"params":[]},"body":[
                    {"kind":"ptr_to_int","dest":"closed","source":"g","comparison_only":true},
                    {"kind":"ptr_to_int","dest":"escaping","source":"g"}
                ]}]
            }"#,
        )
        .unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        let ptrtoint_seeds = pag
            .omega_seeds
            .iter()
            .filter(|seed| seed.kind == OmegaSeedKind::PtrToInt)
            .collect::<Vec<_>>();
        assert_eq!(ptrtoint_seeds.len(), 1);
        let SeedTarget::Node(node) = ptrtoint_seeds[0].target else {
            panic!("ptrtoint seed must target the source node")
        };
        assert_eq!(pag.nodes[node.0 as usize].label, "sym:global:g");
    }
}
