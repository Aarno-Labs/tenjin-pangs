use std::collections::{BTreeMap, BTreeSet};

use pangs_pir::{
    external_call_contract, ExternalArgEffect, ExternalCallContract, ExternalCaptureContract,
    ExternalContractPolicy, ExternalResultContract, GepLane, Loc, Pir, Signature, Stmt, ValueKind,
    VarArgPosition,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod knobs;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PagOpts {
    pub build_mode: BuildMode,
    /// How to model integer/pointer conversions that do not already satisfy one of the
    /// supported safe-use proofs below.
    #[serde(default)]
    pub integer_pointer_policy: IntegerPointerPolicy,
    #[serde(default)]
    pub exports: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub safe_indirect_vararg_callsites: BTreeSet<String>,
}

/// Policy for otherwise fail-closed LLVM integer/pointer operations.
///
/// `AssumeTags` is an explicit supported-program contract. Otherwise-unhandled `ptrtoint`
/// remains conservative. An `inttoptr` with a recovered pointer origin or a function-local
/// address-sensitive use also remains conservative; other conversions are treated as non-address
/// tags. In particular, the reconstructed pointer has a positive empty witness rather than merely
/// being left without an Ω seed. Memory, call, and return crossings are counted audit boundaries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegerPointerPolicy {
    #[default]
    Conservative,
    AssumeTags,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildMode {
    Library,
    Executable,
}

impl Default for BuildMode {
    fn default() -> Self {
        knobs::DEFAULT_BUILD_MODE
    }
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
    /// Proven pointer origins of integer-derived pointer values. These records are consumed only
    /// by allocation-root analyses; ordinary points-to solvers continue to see the corresponding
    /// `IntToPtr` as an Ω source unless the stricter lossless-round-trip proof also succeeds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pointer_integer_origins: Vec<PointerIntegerOrigin>,
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

        let pointer_integer_origins: Vec<_> = self
            .pointer_integer_origins
            .iter()
            .filter(|origin| matches!(&origin.owner, Owner::Function(owner) if owner == func))
            .cloned()
            .collect();
        for origin in &pointer_integer_origins {
            keep_nodes.insert(origin.destination);
            keep_nodes.extend(origin.sources.iter().copied());
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
        let pointer_integer_origins = pointer_integer_origins
            .into_iter()
            .map(|origin| PointerIntegerOrigin {
                destination: node_map[&origin.destination],
                sources: origin
                    .sources
                    .into_iter()
                    .map(|source| node_map[&source])
                    .collect(),
                complete: origin.complete,
                owner: origin.owner,
            })
            .collect();

        Self {
            module: self.module.clone(),
            source: self.source.clone(),
            metrics: PagMetrics::compute(&nodes, &edges, &callsites, &omega_seeds),
            nodes,
            edges,
            callsites,
            omega_seeds,
            pointer_integer_origins,
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

        for origin in &self.pointer_integer_origins {
            if self.nodes.get(origin.destination.0 as usize).is_none() {
                issues.push(ValidationIssue::DanglingPointerIntegerOrigin {
                    which: "destination",
                    node: origin.destination,
                });
            }
            for source in &origin.sources {
                if self.nodes.get(source.0 as usize).is_none() {
                    issues.push(ValidationIssue::DanglingPointerIntegerOrigin {
                        which: "source",
                        node: *source,
                    });
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

/// A pointer value reconstructed from an integer expression, together with every compatible
/// `ptrtoint` source found in that expression. `complete` means the whole integer producer graph
/// was made only from those sources, integer constants, assignments, and supported scalar ops.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointerIntegerOrigin {
    pub destination: NodeId,
    #[serde(default)]
    pub sources: Vec<NodeId>,
    #[serde(default)]
    pub complete: bool,
    pub owner: Owner,
}

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
    /// `inttoptr` values certified empty by the explicit `assume-tags` contract after all
    /// conservative vetoes have run.
    #[serde(default)]
    pub assumed_integer_pointer_tags: usize,
    /// Relaxed values stored into memory. These are audit-only because this first refinement
    /// deliberately does not follow the value through memory.
    #[serde(default)]
    pub assumed_tag_crosses_memory: usize,
    /// Relaxed values passed as call arguments. These are audit-only because this first
    /// refinement deliberately does not follow the value through callees.
    #[serde(default)]
    pub assumed_tag_crosses_call: usize,
    /// Relaxed values returned from their defining function.
    #[serde(default)]
    pub assumed_tag_returned: usize,
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
    /// Semantic pointer-payload kind, independent of ABI register class.  Older PAG fixtures
    /// deserialize as `Unknown` and therefore retain the conservative behavior.
    #[serde(default)]
    pub value_kind: ValueKind,
    /// True only for the canonical pointer-null operand emitted by PIR lowering.  This is kept
    /// explicit so allocation-root proofs never infer nullness from a user-controlled label.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub canonical_pointer_null: bool,
    /// Positive evidence that this value denotes no allocation or function object. Canonical
    /// null and target-contract reserved addresses seed this fact.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub has_empty_witness: bool,
}

pub fn is_canonical_pointer_null(node: &Node) -> bool {
    node.canonical_pointer_null
}

pub fn has_empty_witness(node: &Node) -> bool {
    node.has_empty_witness
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StorageRoot {
    Global {
        object_node: NodeId,
        pir_global_index: usize,
        canonical_key: String,
    },
    LocalAlloca {
        object_node: NodeId,
    },
}

impl StorageRoot {
    pub fn object_node(&self) -> NodeId {
        match self {
            Self::Global { object_node, .. } | Self::LocalAlloca { object_node } => *object_node,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "state", content = "root", rename_all = "snake_case")]
pub enum StorageRootState {
    #[default]
    Unknown,
    ProvenEmpty,
    Root(StorageRoot),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorageRoots {
    pub states: Vec<StorageRootState>,
    pub global_objects: BTreeMap<NodeId, usize>,
    /// Globals whose AddrOf value did not satisfy the sole-producer invariant.
    pub force_exposed_globals: BTreeSet<usize>,
    /// False when PIR/PAG global identity is missing or ambiguous.  Consumers must disable
    /// exposure filtering rather than attempting a heuristic recovery.
    pub global_identity_valid: bool,
}

fn canonical_global_key(key: &str) -> &str {
    key.strip_prefix('@').unwrap_or(key)
}

fn same_semantic_scope(lhs: &NodeKind, rhs: &NodeKind) -> bool {
    fn scope(kind: &NodeKind) -> (&str, Option<&str>) {
        match kind {
            NodeKind::Value {
                scope: Scope::Function(func),
            }
            | NodeKind::Param { func, .. }
            | NodeKind::Return { func } => ("function", Some(func)),
            NodeKind::Value {
                scope: Scope::Module,
            } => ("module", None),
            NodeKind::Value {
                scope: Scope::GlobalInit,
            } => ("global_init", None),
            NodeKind::Object {
                owner: Some(owner), ..
            } => ("function", Some(owner)),
            NodeKind::Object { owner: None, .. } => ("module", None),
        }
    }
    scope(lhs) == scope(rhs)
}

/// Prove allocation roots using the deliberately small address-preserving grammar shared by
/// solver filtering and API ModRef attribution.
pub fn allocation_storage_roots(pir: &Pir, pag: &Pag) -> StorageRoots {
    let mut by_key = BTreeMap::<String, Vec<usize>>::new();
    for (index, global) in pir.globals.iter().enumerate() {
        by_key
            .entry(canonical_global_key(&global.key).to_string())
            .or_default()
            .push(index);
    }
    let mut object_roots = BTreeMap::<NodeId, StorageRoot>::new();
    let mut global_objects = BTreeMap::new();
    let mut global_identity_valid = by_key.values().all(|indices| indices.len() == 1);
    for node in &pag.nodes {
        let NodeKind::Object { object, key, .. } = &node.kind else {
            continue;
        };
        match object {
            ObjectKind::Global => match by_key.get(canonical_global_key(key)).map(Vec::as_slice) {
                Some([index]) => {
                    global_objects.insert(node.id, *index);
                    object_roots.insert(
                        node.id,
                        StorageRoot::Global {
                            object_node: node.id,
                            pir_global_index: *index,
                            canonical_key: canonical_global_key(&pir.globals[*index].key)
                                .to_string(),
                        },
                    );
                }
                _ => global_identity_valid = false,
            },
            ObjectKind::Alloca => {
                object_roots.insert(
                    node.id,
                    StorageRoot::LocalAlloca {
                        object_node: node.id,
                    },
                );
            }
            ObjectKind::Function | ObjectKind::ExternalReadonly => {}
        }
    }

    // Construct the complete value-producer table before seeding AddrOf destinations.  Store
    // destinations and memcpy operands are consumers, not producers.
    let mut producers = vec![Vec::<&Edge>::new(); pag.nodes.len()];
    for edge in &pag.edges {
        if matches!(
            edge.kind,
            EdgeKind::AddrOf | EdgeKind::Assign | EdgeKind::Load | EdgeKind::Gep { .. }
        ) {
            if let Some(incoming) = producers.get_mut(edge.dst.0 as usize) {
                incoming.push(edge);
            }
        }
    }

    let mut states = pag
        .nodes
        .iter()
        .map(|node| {
            if has_empty_witness(node) {
                StorageRootState::ProvenEmpty
            } else {
                StorageRootState::Unknown
            }
        })
        .collect::<Vec<_>>();
    let mut force_exposed_globals = BTreeSet::new();
    for (destination, incoming) in producers.iter().enumerate() {
        let addr_of = incoming
            .iter()
            .filter(|edge| edge.kind == EdgeKind::AddrOf)
            .collect::<Vec<_>>();
        if addr_of.is_empty() {
            continue;
        }
        if incoming.len() == 1 {
            if let Some(root) = object_roots.get(&addr_of[0].src) {
                states[destination] = StorageRootState::Root(root.clone());
            }
        } else {
            for edge in addr_of {
                if let Some(StorageRoot::Global {
                    pir_global_index, ..
                }) = object_roots.get(&edge.src)
                {
                    force_exposed_globals.insert(*pir_global_index);
                }
            }
            states[destination] = StorageRootState::Unknown;
        }
    }

    loop {
        let mut changed = false;
        for (destination, incoming) in producers.iter().enumerate() {
            if !matches!(states[destination], StorageRootState::Unknown) || incoming.is_empty() {
                continue;
            }
            let candidate = match incoming[0].kind {
                EdgeKind::Gep { .. } if incoming.len() == 1 => {
                    match &states[incoming[0].src.0 as usize] {
                        StorageRootState::Root(root) => StorageRootState::Root(root.clone()),
                        // Pointer arithmetic does not preserve a certified empty value.
                        StorageRootState::ProvenEmpty => continue,
                        StorageRootState::Unknown => continue,
                    }
                }
                EdgeKind::Assign
                    if incoming.iter().all(|edge| {
                        edge.kind == EdgeKind::Assign
                            && same_semantic_scope(
                                &pag.nodes[edge.src.0 as usize].kind,
                                &pag.nodes[edge.dst.0 as usize].kind,
                            )
                    }) =>
                {
                    let mut common: Option<&StorageRoot> = None;
                    let mut has_unknown = false;
                    let mut mixed = false;
                    for edge in incoming {
                        match &states[edge.src.0 as usize] {
                            StorageRootState::Unknown => has_unknown = true,
                            StorageRootState::ProvenEmpty => {}
                            StorageRootState::Root(root) => match common {
                                None => common = Some(root),
                                Some(first) if first == root => {}
                                Some(_) => mixed = true,
                            },
                        }
                    }
                    if has_unknown || mixed {
                        continue;
                    }
                    common
                        .cloned()
                        .map(StorageRootState::Root)
                        .unwrap_or(StorageRootState::ProvenEmpty)
                }
                _ => continue,
            };
            states[destination] = candidate;
            changed = true;
        }
        for origin in &pag.pointer_integer_origins {
            let destination = origin.destination.0 as usize;
            if !origin.complete
                || !matches!(states[destination], StorageRootState::Unknown)
                || origin.sources.is_empty()
            {
                continue;
            }
            let mut common: Option<&StorageRoot> = None;
            let mut unknown = false;
            let mut mixed = false;
            for source in &origin.sources {
                match &states[source.0 as usize] {
                    StorageRootState::Unknown => unknown = true,
                    StorageRootState::ProvenEmpty => {}
                    StorageRootState::Root(root) => match common {
                        None => common = Some(root),
                        Some(first) if first == root => {}
                        Some(_) => mixed = true,
                    },
                }
            }
            if unknown || mixed {
                continue;
            }
            states[destination] = common
                .cloned()
                .map(StorageRootState::Root)
                .unwrap_or(StorageRootState::ProvenEmpty);
            changed = true;
        }
        if !changed {
            break;
        }
    }
    StorageRoots {
        states,
        global_objects,
        force_exposed_globals,
        global_identity_valid,
    }
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
    /// Operation-specific memory width. Kept on the edge so solvers do not need to recover a
    /// pointee type from an LLVM pointer (which is impossible with opaque pointers).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_bytes: Option<u64>,
    /// Distinguishes a genuinely unknown-width operation (for example dynamic memset) from a
    /// legacy hand-written load/store that predates `access_bytes`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub access_extent_unknown: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub volatile: bool,
    /// The memory effect is a summary of a non-capturing external call, rather than a source
    /// load/store expression. Consumers must retain the effect for ModRef while treating its
    /// address use as indirect for source-materialization purposes.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub modeled_external_write: bool,
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
    Gep {
        byte_off: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lane: Option<GepLane>,
    },
    Memcpy {
        bytes: Option<u64>,
    },
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
    #[error("pointer-integer origin has dangling {which} node {node:?}")]
    DanglingPointerIntegerOrigin { which: &'static str, node: NodeId },
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
    ByvalObject(usize, usize, usize),
    HeapObject(usize, usize),
    ExternalReadonlyObject(String),
    Param(usize, usize),
    Return(usize),
    SymbolValue(SymbolKind, usize),
    FunctionValue(usize, String),
    ExternalNonPointerWrite(usize, usize),
    ExternalPointerWrite(usize, usize),
    ExternalStateAddress(String),
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

/// Recognize only the literal SSA round trip represented by
/// `p -> ptrtoint -> inttoptr -> q`. All uses of the integer result must be compatible
/// `inttoptr` operations; a store, arithmetic operation, call, return, or unknown use keeps the
/// original fail-closed seeds. Address-space equality is intentionally stricter than attempting
/// to infer target-specific equivalence between distinct spaces.
fn collect_lossless_pointer_round_trips(
    pir: &Pir,
    scope: usize,
    body: &[Stmt],
    safe_ptrtoint: &mut BTreeSet<(usize, usize)>,
    safe_inttoptr: &mut BTreeMap<(usize, usize), String>,
) {
    let Some(target) = pir.target.as_ref() else {
        return;
    };
    let non_integral = target
        .data_layout
        .split('-')
        .find_map(|part| part.strip_prefix("ni:"))
        .into_iter()
        .flat_map(|spaces| spaces.split(':'))
        .filter_map(|space| space.parse::<u32>().ok())
        .collect::<BTreeSet<_>>();

    let mut definitions = BTreeMap::new();
    let mut multiply_defined = BTreeSet::new();
    let mut uses_by_operand: BTreeMap<&str, Vec<(usize, &Stmt)>> = BTreeMap::new();
    for (index, stmt) in body.iter().enumerate() {
        if let Some(dest) = stmt_destination(stmt) {
            if definitions.insert(dest, index).is_some() {
                multiply_defined.insert(dest);
            }
        }
        for operand in stmt_input_operands(stmt) {
            uses_by_operand
                .entry(operand)
                .or_default()
                .push((index, stmt));
        }
    }

    for (ptr_index, ptr_stmt) in body.iter().enumerate() {
        let Stmt::PtrToInt {
            dest: integer,
            source: pointer,
            integer_bits: Some(integer_bits),
            pointer_bits: Some(source_pointer_bits),
            pointer_address_space: Some(source_space),
            ..
        } = ptr_stmt
        else {
            continue;
        };
        if integer_bits != source_pointer_bits || non_integral.contains(source_space) {
            continue;
        }

        let Some(uses) = uses_by_operand.get(integer.as_str()) else {
            continue;
        };
        if multiply_defined.contains(integer.as_str()) {
            continue;
        }

        let mut round_trips = Vec::new();
        let all_lossless = uses.iter().all(|(int_index, stmt)| {
            let Stmt::IntToPtr {
                source,
                integer_bits: Some(destination_integer_bits),
                pointer_bits: Some(destination_pointer_bits),
                pointer_address_space: Some(destination_space),
                ..
            } = stmt
            else {
                return false;
            };
            let compatible = source == integer
                && *int_index > ptr_index
                && definitions.get(source.as_str()) == Some(&ptr_index)
                && destination_integer_bits == integer_bits
                && destination_pointer_bits == integer_bits
                && destination_space == source_space
                && !non_integral.contains(destination_space);
            if compatible {
                round_trips.push(*int_index);
            }
            compatible
        });
        if all_lossless {
            safe_ptrtoint.insert((scope, ptr_index));
            for int_index in round_trips {
                safe_inttoptr.insert((scope, int_index), pointer.clone());
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
struct IntegerOriginProof {
    sources: BTreeSet<String>,
    complete: bool,
}

#[derive(Debug, Clone, Copy, Default)]
struct IntToPtrUseSummary {
    address_sensitive: bool,
    crosses_memory: bool,
    crosses_call: bool,
    returned: bool,
}

#[derive(Debug, Clone, Copy, Default)]
struct AssumedTagCounts {
    values: usize,
    crosses_memory: usize,
    crosses_call: usize,
    returned: usize,
}

/// Classify uses reachable from each `inttoptr` result through function-local SSA copies.
///
/// This intentionally stops at memory, call, and return boundaries. Those uses are recorded for
/// auditing but do not veto `assume-tags`; following them precisely is the substantially more
/// expensive refinement that this policy is intended to avoid. Direct address uses do veto the
/// assumption: loads, stores, GEPs, memory intrinsics, indirect calls, and inline assembly can all
/// interpret the reconstructed value as an address immediately.
fn collect_inttoptr_local_uses(
    scope: usize,
    body: &[Stmt],
    summaries: &mut BTreeMap<(usize, usize), IntToPtrUseSummary>,
) {
    let mut uses = BTreeMap::<&str, Vec<&Stmt>>::new();
    for stmt in body {
        for operand in stmt_input_operands(stmt) {
            uses.entry(operand).or_default().push(stmt);
        }
    }

    for (index, stmt) in body.iter().enumerate() {
        let Stmt::IntToPtr { dest, .. } = stmt else {
            continue;
        };
        let mut summary = IntToPtrUseSummary::default();
        let mut pending = vec![dest.as_str()];
        let mut visited = BTreeSet::new();
        while let Some(value) = pending.pop() {
            if !visited.insert(value) {
                continue;
            }
            for user in uses.get(value).into_iter().flatten() {
                match user {
                    Stmt::Assign { dest, .. } => pending.push(dest),
                    Stmt::Load { address, .. } if address == value => {
                        summary.address_sensitive = true;
                    }
                    Stmt::Store {
                        address,
                        value: stored,
                        ..
                    } => {
                        if address == value {
                            summary.address_sensitive = true;
                        }
                        if stored == value {
                            summary.crosses_memory = true;
                        }
                    }
                    Stmt::Gep { base, .. } if base == value => {
                        summary.address_sensitive = true;
                    }
                    Stmt::Memcpy { dst, src, .. } if dst == value || src == value => {
                        summary.address_sensitive = true;
                    }
                    Stmt::Memset { dst, .. } if dst == value => {
                        summary.address_sensitive = true;
                    }
                    Stmt::CallDirect { args, .. } if args.iter().any(|arg| arg == value) => {
                        summary.crosses_call = true;
                    }
                    Stmt::CallIndirect { operand, args, .. } => {
                        if operand == value {
                            summary.address_sensitive = true;
                        }
                        if args.iter().any(|arg| arg == value) {
                            summary.crosses_call = true;
                        }
                    }
                    Stmt::Unknown {
                        operands, reason, ..
                    } if reason.starts_with("inline_asm")
                        && operands.iter().any(|operand| operand == value) =>
                    {
                        summary.address_sensitive = true;
                    }
                    Stmt::Return {
                        value: Some(returned),
                        ..
                    } if returned == value => {
                        summary.returned = true;
                    }
                    _ => {}
                }
            }
        }
        summaries.insert((scope, index), summary);
    }
}

fn is_integer_literal(value: &str) -> bool {
    let token = value.split_whitespace().last().unwrap_or(value);
    if matches!(token, "true" | "false") {
        return true;
    }
    let digits = token.strip_prefix(['-', '+']).unwrap_or(token);
    if let Some(hex) = digits.strip_prefix("0x") {
        return !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit());
    }
    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
}

const RESERVED_LOW_ADDRESS_LIMIT: u128 = 4096;

fn parse_unsigned_integer_literal(token: &str) -> Option<u128> {
    let token = token.strip_prefix('+').unwrap_or(token);
    if let Some(hex) = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
        (!hex.is_empty())
            .then(|| u128::from_str_radix(hex, 16).ok())
            .flatten()
    } else {
        token.parse().ok()
    }
}

/// Recognize the conventional-architecture addresses reserved by the supported-program
/// contract. The integer and pointer representations must already have the same width in the
/// default integral address space; missing target facts fail closed.
fn is_reserved_non_address_inttoptr(
    pir: &Pir,
    source: &str,
    integer_bits: Option<u32>,
    pointer_bits: Option<u32>,
    pointer_address_space: Option<u32>,
) -> bool {
    let (Some(integer_bits), Some(pointer_bits), Some(0)) =
        (integer_bits, pointer_bits, pointer_address_space)
    else {
        return false;
    };
    if integer_bits != pointer_bits || integer_bits == 0 || integer_bits > 128 {
        return false;
    }
    let Some(target) = pir.target.as_ref() else {
        return false;
    };
    let default_space_is_non_integral = target
        .data_layout
        .split('-')
        .find_map(|part| part.strip_prefix("ni:"))
        .into_iter()
        .flat_map(|spaces| spaces.split(':'))
        .any(|space| space == "0");
    if default_space_is_non_integral {
        return false;
    }

    let token = source.split_whitespace().last().unwrap_or(source);
    if let Some(magnitude) = token.strip_prefix('-') {
        return parse_unsigned_integer_literal(magnitude)
            .is_some_and(|magnitude| magnitude < RESERVED_LOW_ADDRESS_LIMIT);
    }
    let Some(value) = parse_unsigned_integer_literal(token) else {
        return false;
    };
    let all_ones = if integer_bits == 128 {
        u128::MAX
    } else {
        (1u128 << integer_bits) - 1
    };
    let is_small_negative_bit_pattern =
        value <= all_ones && all_ones - value < RESERVED_LOW_ADDRESS_LIMIT - 1;
    value < RESERVED_LOW_ADDRESS_LIMIT || is_small_negative_bit_pattern
}

/// Recover pointer provenance through the integer side of an `inttoptr`. Unlike the lossless
/// round-trip proof above, scalar arithmetic does not become an ordinary pointer assignment: it
/// only records allocation origins for the positive origin analyses. Unknown leaves make the
/// record incomplete without discarding compatible pointer origins already found.
fn collect_pointer_integer_origins(
    pir: &Pir,
    scope: usize,
    body: &[Stmt],
    origins: &mut BTreeMap<(usize, usize), IntegerOriginProof>,
) {
    let Some(target) = pir.target.as_ref() else {
        return;
    };
    let non_integral = target
        .data_layout
        .split('-')
        .find_map(|part| part.strip_prefix("ni:"))
        .into_iter()
        .flat_map(|spaces| spaces.split(':'))
        .filter_map(|space| space.parse::<u32>().ok())
        .collect::<BTreeSet<_>>();
    let mut definitions = BTreeMap::<&str, usize>::new();
    let mut multiply_defined = BTreeSet::new();
    for (index, stmt) in body.iter().enumerate() {
        if let Some(destination) = stmt_destination(stmt) {
            if definitions.insert(destination, index).is_some() {
                multiply_defined.insert(destination);
            }
        }
    }

    fn trace(
        value: &str,
        before: usize,
        integer_bits: u32,
        address_space: u32,
        non_integral: &BTreeSet<u32>,
        body: &[Stmt],
        definitions: &BTreeMap<&str, usize>,
        multiply_defined: &BTreeSet<&str>,
        visiting: &mut BTreeSet<usize>,
    ) -> IntegerOriginProof {
        let Some(&definition) = definitions.get(value) else {
            return IntegerOriginProof {
                sources: BTreeSet::new(),
                complete: is_integer_literal(value),
            };
        };
        if definition >= before || multiply_defined.contains(value) || !visiting.insert(definition)
        {
            return IntegerOriginProof::default();
        }

        let mut merge = |operands: &[&str]| {
            let mut result = IntegerOriginProof {
                sources: BTreeSet::new(),
                complete: true,
            };
            for operand in operands {
                let source = trace(
                    operand,
                    definition,
                    integer_bits,
                    address_space,
                    non_integral,
                    body,
                    definitions,
                    multiply_defined,
                    visiting,
                );
                result.sources.extend(source.sources);
                result.complete &= source.complete;
            }
            result
        };

        let result = match &body[definition] {
            Stmt::PtrToInt {
                source,
                integer_bits: Some(source_integer_bits),
                pointer_bits: Some(source_pointer_bits),
                pointer_address_space: Some(source_address_space),
                ..
            } if *source_integer_bits == integer_bits
                && source_integer_bits == source_pointer_bits
                && *source_address_space == address_space
                && !non_integral.contains(source_address_space) =>
            {
                IntegerOriginProof {
                    sources: BTreeSet::from([source.clone()]),
                    complete: true,
                }
            }
            Stmt::Assign { sources, .. } if !sources.is_empty() => {
                merge(&sources.iter().map(String::as_str).collect::<Vec<_>>())
            }
            Stmt::ScalarOp { lhs, rhs, .. } => merge(&[lhs, rhs]),
            _ => IntegerOriginProof::default(),
        };
        visiting.remove(&definition);
        result
    }

    for (index, stmt) in body.iter().enumerate() {
        let Stmt::IntToPtr {
            source,
            integer_bits: Some(integer_bits),
            pointer_bits: Some(pointer_bits),
            pointer_address_space: Some(address_space),
            ..
        } = stmt
        else {
            continue;
        };
        if integer_bits != pointer_bits || non_integral.contains(address_space) {
            continue;
        }
        let proof = trace(
            source,
            index,
            *integer_bits,
            *address_space,
            &non_integral,
            body,
            &definitions,
            &multiply_defined,
            &mut BTreeSet::new(),
        );
        if !proof.sources.is_empty() {
            origins.insert((scope, index), proof);
        }
    }
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
    vararg_call_proof: VarargCallProof<'a>,
    callsite_ordinals: BTreeMap<usize, u32>,
    /// Statement-indexed proofs. The value on an `inttoptr` row is the original pointer
    /// operand whose representation survived the integer detour unchanged.
    lossless_inttoptr: BTreeMap<(usize, usize), String>,
    lossless_ptrtoint: BTreeSet<(usize, usize)>,
    pointer_integer_origin_proofs: BTreeMap<(usize, usize), IntegerOriginProof>,
    pointer_integer_origins: Vec<PointerIntegerOrigin>,
    inttoptr_use_summaries: BTreeMap<(usize, usize), IntToPtrUseSummary>,
    assumed_tag_counts: AssumedTagCounts,
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
        let mut lossless_inttoptr = BTreeMap::new();
        let mut lossless_ptrtoint = BTreeSet::new();
        let mut pointer_integer_origin_proofs = BTreeMap::new();
        let mut inttoptr_use_summaries = BTreeMap::new();
        for (func_index, func) in pir.functions.iter().enumerate() {
            collect_lossless_pointer_round_trips(
                pir,
                func_index,
                &func.body,
                &mut lossless_ptrtoint,
                &mut lossless_inttoptr,
            );
            collect_pointer_integer_origins(
                pir,
                func_index,
                &func.body,
                &mut pointer_integer_origin_proofs,
            );
            collect_inttoptr_local_uses(func_index, &func.body, &mut inttoptr_use_summaries);
        }
        collect_lossless_pointer_round_trips(
            pir,
            usize::MAX,
            &pir.global_init,
            &mut lossless_ptrtoint,
            &mut lossless_inttoptr,
        );
        collect_pointer_integer_origins(
            pir,
            usize::MAX,
            &pir.global_init,
            &mut pointer_integer_origin_proofs,
        );
        collect_inttoptr_local_uses(usize::MAX, &pir.global_init, &mut inttoptr_use_summaries);
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
            vararg_call_proof: VarargCallProof::new(pir),
            callsite_ordinals: BTreeMap::new(),
            lossless_inttoptr,
            lossless_ptrtoint,
            pointer_integer_origin_proofs,
            pointer_integer_origins: Vec::new(),
            inttoptr_use_summaries,
            assumed_tag_counts: AssumedTagCounts::default(),
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

        let mut metrics =
            PagMetrics::compute(&self.nodes, &self.edges, &self.callsites, &self.omega_seeds);
        metrics.assumed_integer_pointer_tags = self.assumed_tag_counts.values;
        metrics.assumed_tag_crosses_memory = self.assumed_tag_counts.crosses_memory;
        metrics.assumed_tag_crosses_call = self.assumed_tag_counts.crosses_call;
        metrics.assumed_tag_returned = self.assumed_tag_counts.returned;

        Pag {
            module: self.pir.module.clone(),
            source: self.pir.source.clone(),
            metrics,
            nodes: self.nodes,
            edges: self.edges,
            callsites: self.callsites,
            omega_seeds: self.omega_seeds,
            pointer_integer_origins: self.pointer_integer_origins,
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
            Stmt::Load {
                dest,
                address,
                volatile,
                access_bytes,
                loc,
            } => {
                let src = self.operand_node(func_index, owner_scope(&owner), address);
                let dst = self.value_node(func_index, owner_scope(&owner), dest);
                self.add_memory_edge(
                    EdgeKind::Load,
                    src,
                    dst,
                    owner,
                    *access_bytes,
                    false,
                    *volatile,
                    loc.clone(),
                );
            }
            Stmt::Store {
                address,
                value,
                volatile,
                access_bytes,
                loc,
            } => {
                let src = self.operand_node(func_index, owner_scope(&owner), value);
                let dst = self.operand_node(func_index, owner_scope(&owner), address);
                self.add_memory_edge(
                    EdgeKind::Store,
                    src,
                    dst,
                    owner,
                    *access_bytes,
                    false,
                    *volatile,
                    loc.clone(),
                );
            }
            Stmt::Gep {
                dest,
                base,
                byte_off,
                lane,
                loc,
            } => {
                let src = self.operand_node(func_index, owner_scope(&owner), base);
                let dst = self.value_node(func_index, owner_scope(&owner), dest);
                self.add_edge(
                    EdgeKind::Gep {
                        byte_off: *byte_off,
                        lane: *lane,
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
                ..
            } => {
                let src = self.operand_node(func_index, owner_scope(&owner), source);
                self.value_node(func_index, owner_scope(&owner), dest);
                if !comparison_only && !self.lossless_ptrtoint.contains(&(func_index, stmt_index)) {
                    self.add_seed(
                        OmegaSeedKind::PtrToInt,
                        SeedTarget::Node(src),
                        Some(owner),
                        loc.clone(),
                        Some(source.clone()),
                    );
                }
            }
            Stmt::IntToPtr {
                dest,
                source,
                integer_bits,
                pointer_bits,
                pointer_address_space,
                loc,
                ..
            } => {
                self.operand_node(func_index, owner_scope(&owner), source);
                let dst = self.value_node(func_index, owner_scope(&owner), dest);
                if let Some(original) = self
                    .lossless_inttoptr
                    .get(&(func_index, stmt_index))
                    .cloned()
                {
                    let src = self.operand_node(func_index, owner_scope(&owner), &original);
                    self.add_edge(EdgeKind::Assign, src, dst, owner, loc.clone());
                } else if is_reserved_non_address_inttoptr(
                    self.pir,
                    source,
                    *integer_bits,
                    *pointer_bits,
                    *pointer_address_space,
                ) {
                    self.nodes[dst.0 as usize].has_empty_witness = true;
                } else {
                    let proof = self
                        .pointer_integer_origin_proofs
                        .get(&(func_index, stmt_index))
                        .cloned();
                    let use_summary = self
                        .inttoptr_use_summaries
                        .get(&(func_index, stmt_index))
                        .copied()
                        .unwrap_or_default();
                    let assume_tag = self.opts.integer_pointer_policy
                        == IntegerPointerPolicy::AssumeTags
                        && proof.is_none()
                        && !use_summary.address_sensitive;
                    if assume_tag {
                        // This is intentionally stronger than omitting the Ω seed. The explicit
                        // tag contract proves that this value cannot name an allocation or
                        // function object, so consumers can distinguish it from an unmodelled
                        // pointer. Nonlocal uses remain an explicit, counted assumption boundary.
                        self.nodes[dst.0 as usize].has_empty_witness = true;
                        self.assumed_tag_counts.values += 1;
                        self.assumed_tag_counts.crosses_memory +=
                            usize::from(use_summary.crosses_memory);
                        self.assumed_tag_counts.crosses_call +=
                            usize::from(use_summary.crosses_call);
                        self.assumed_tag_counts.returned += usize::from(use_summary.returned);
                    } else {
                        if let Some(proof) = proof {
                            let sources = proof
                                .sources
                                .iter()
                                .map(|source| {
                                    self.operand_node(func_index, owner_scope(&owner), source)
                                })
                                .collect();
                            self.pointer_integer_origins.push(PointerIntegerOrigin {
                                destination: dst,
                                sources,
                                complete: proof.complete,
                                owner: owner.clone(),
                            });
                        }
                        self.add_seed(
                            OmegaSeedKind::IntToPtr,
                            SeedTarget::Node(dst),
                            Some(owner),
                            loc.clone(),
                            Some(dest.clone()),
                        );
                    }
                }
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
            Stmt::Memset {
                dst, bytes, loc, ..
            } => {
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
                self.add_memory_edge(
                    EdgeKind::Store,
                    source,
                    destination,
                    owner,
                    *bytes,
                    bytes.is_none(),
                    false,
                    loc.clone(),
                );
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
                    if !reason.starts_with("inline_asm")
                        || self.nodes[node.0 as usize].value_kind.may_carry_pointer()
                    {
                        self.add_seed(
                            OmegaSeedKind::UnknownOperandEscape,
                            SeedTarget::Node(node),
                            Some(owner.clone()),
                            loc.clone(),
                            Some(reason.clone()),
                        );
                    }
                }
                for result in results {
                    let node = self.value_node(func_index, owner_scope(&owner), result);
                    if !reason.starts_with("inline_asm")
                        || self.nodes[node.0 as usize].value_kind.may_carry_pointer()
                    {
                        self.add_seed(
                            OmegaSeedKind::UnknownResultExternal,
                            SeedTarget::Node(node),
                            Some(owner.clone()),
                            loc.clone(),
                            Some(reason.clone()),
                        );
                    }
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
                let is_external = direct_callee_is_external(self.pir, callee);
                let contract =
                    proven_external_call_contract(self.pir, callee, sig, args, dest.is_some());
                let external_boundary = is_external && contract.is_none();

                if let Some(contract) = contract {
                    if let Some(result) = result {
                        match contract.result {
                            ExternalResultContract::AliasArg(index)
                            | ExternalResultContract::AliasArgOrFresh(index) => {
                                if let Some(&arg) = arg_nodes.get(index) {
                                    self.add_edge(
                                        EdgeKind::Assign,
                                        arg,
                                        result,
                                        owner.clone(),
                                        loc.clone(),
                                    );
                                }
                            }
                            ExternalResultContract::ExternalObject => {
                                let object = self.external_readonly_object(&format!(
                                    "external-contract:{callee}"
                                ));
                                self.add_edge(
                                    EdgeKind::AddrOf,
                                    object,
                                    result,
                                    owner.clone(),
                                    loc.clone(),
                                );
                            }
                            ExternalResultContract::CtypeTable => {
                                let slot = self.external_readonly_object("glibc-ctype-b:slot");
                                let table = self.external_readonly_object("glibc-ctype-b:table");
                                self.add_edge(
                                    EdgeKind::AddrOf,
                                    slot,
                                    result,
                                    owner.clone(),
                                    loc.clone(),
                                );
                                self.add_edge(
                                    EdgeKind::AddrOf,
                                    table,
                                    slot,
                                    owner.clone(),
                                    loc.clone(),
                                );
                            }
                            ExternalResultContract::Void
                            | ExternalResultContract::Scalar
                            | ExternalResultContract::Fresh
                            | ExternalResultContract::RetainedState => {}
                        }
                    }
                    if result.is_some()
                        && matches!(
                            contract.result,
                            ExternalResultContract::Fresh
                                | ExternalResultContract::AliasArgOrFresh(_)
                        )
                    {
                        let object = self.add_node(
                            NodeKey::HeapObject(func_index, stmt_index),
                            format!("obj:heap:{}:{stmt_index}", owner_name(&owner)),
                            NodeKind::Object {
                                object: ObjectKind::Alloca,
                                key: format!("{callee}@{stmt_index}"),
                                owner: Some(owner_name(&owner).to_string()),
                            },
                        );
                        self.add_edge(
                            EdgeKind::AddrOf,
                            object,
                            result.expect("checked above"),
                            owner.clone(),
                            loc.clone(),
                        );
                    }

                    if let Some(copy) = contract.copy {
                        if let (Some(&dst), Some(&src)) =
                            (arg_nodes.get(copy.destination), arg_nodes.get(copy.source))
                        {
                            let bytes = args
                                .get(copy.byte_count)
                                .and_then(|value| {
                                    parse_unsigned_integer_literal(
                                        value.split_whitespace().last().unwrap_or(value),
                                    )
                                })
                                .and_then(|value| u64::try_from(value).ok());
                            if bytes != Some(0) {
                                self.add_edge(
                                    EdgeKind::Memcpy { bytes },
                                    src,
                                    dst,
                                    owner.clone(),
                                    loc.clone(),
                                );
                            }
                        }
                    }
                    if let Some((source, destination)) = contract.pointer_store {
                        if let (Some(&source), Some(&destination)) =
                            (arg_nodes.get(source), arg_nodes.get(destination))
                        {
                            let edge = self.add_memory_edge(
                                EdgeKind::Store,
                                source,
                                destination,
                                owner.clone(),
                                None,
                                true,
                                false,
                                loc.clone(),
                            );
                            self.edges[edge.0 as usize].modeled_external_write = true;
                        }
                    }
                    if let ExternalCaptureContract::RetainedArgument(index) = contract.capture {
                        let state = self.external_state_address(callee);
                        if let Some(&argument) = arg_nodes.get(index) {
                            let edge = self.add_memory_edge(
                                EdgeKind::Store,
                                argument,
                                state,
                                owner.clone(),
                                None,
                                true,
                                false,
                                loc.clone(),
                            );
                            self.edges[edge.0 as usize].modeled_external_write = true;
                        }
                        if let Some(result) = result {
                            self.add_memory_edge(
                                EdgeKind::Load,
                                state,
                                result,
                                owner.clone(),
                                None,
                                true,
                                false,
                                loc.clone(),
                            );
                        }
                    }

                    let mut effects = contract.effects.to_vec();
                    match contract.policy {
                        ExternalContractPolicy::Printf => {
                            let safe_format =
                                proven_printf_effect(self.pir, callee, args).is_some();
                            effects.extend((contract.fixed_params..arg_nodes.len()).map(|index| {
                                if safe_format {
                                    ExternalArgEffect::Read(index)
                                } else {
                                    ExternalArgEffect::ReadWrite(index)
                                }
                            }));
                        }
                        ExternalContractPolicy::Scanf => effects.extend(
                            (contract.fixed_params..arg_nodes.len()).map(ExternalArgEffect::Write),
                        ),
                        ExternalContractPolicy::Plain
                        | ExternalContractPolicy::NoVariadicActuals => {}
                    }
                    if !effects.is_empty() {
                        let read_sink = self.add_node(
                            NodeKey::ExternalNonPointerWrite(func_index, stmt_index),
                            format!(
                                "val:{}:@external-contract-effect:{stmt_index}",
                                owner_name(&owner)
                            ),
                            NodeKind::Value {
                                scope: owner_scope(&owner),
                            },
                        );
                        // `%p` makes a scanf-family output pointer-bearing. Without parsing the
                        // format, every variadic destination must admit that possibility.
                        let pointer_write = (contract.policy == ExternalContractPolicy::Scanf)
                            .then(|| {
                                let value = self.add_node(
                                    NodeKey::ExternalPointerWrite(func_index, stmt_index),
                                    format!(
                                        "val:{}:@external-contract-pointer-write:{stmt_index}",
                                        owner_name(&owner)
                                    ),
                                    NodeKind::Value {
                                        scope: owner_scope(&owner),
                                    },
                                );
                                self.add_seed(
                                    OmegaSeedKind::UnknownResultExternal,
                                    SeedTarget::Node(value),
                                    Some(owner.clone()),
                                    loc.clone(),
                                    Some(format!("external-contract:{callee}:pointer-write")),
                                );
                                value
                            });
                        for effect in effects {
                            let (index, read, write) = match effect {
                                ExternalArgEffect::Read(index) => (index, true, false),
                                ExternalArgEffect::Write(index) => (index, false, true),
                                ExternalArgEffect::ReadWrite(index) => (index, true, true),
                            };
                            let Some(&argument) = arg_nodes.get(index) else {
                                continue;
                            };
                            if !self.nodes[argument.0 as usize]
                                .value_kind
                                .may_carry_pointer()
                            {
                                continue;
                            }
                            if read {
                                self.add_memory_edge(
                                    EdgeKind::Load,
                                    argument,
                                    read_sink,
                                    owner.clone(),
                                    None,
                                    true,
                                    false,
                                    loc.clone(),
                                );
                            }
                            if write {
                                let value = pointer_write.unwrap_or(read_sink);
                                let edge = self.add_memory_edge(
                                    EdgeKind::Store,
                                    value,
                                    argument,
                                    owner.clone(),
                                    None,
                                    true,
                                    false,
                                    loc.clone(),
                                );
                                self.edges[edge.0 as usize].modeled_external_write = true;
                            }
                        }
                    }
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
                if let Some(callee_index) = self.functions.get(callee).copied() {
                    if let Some(callee_func) = self.pir.functions.get(callee_index) {
                        if !callee_func.external {
                            for (arg, param_index) in arg_nodes
                                .iter()
                                .copied()
                                .zip(0..callee_func.sig.params.len())
                            {
                                let Some(param) = self
                                    .node_ids
                                    .get(&NodeKey::Param(callee_index, param_index))
                                    .copied()
                                else {
                                    continue;
                                };
                                if let Some(pangs_pir::Param::Byval { size }) =
                                    callee_func.sig.params.get(param_index)
                                {
                                    // A `byval` parameter points at a fresh callee copy rather
                                    // than aliasing the caller's aggregate address. Copy memory
                                    // payload into an explicit object so pointer-bearing fields
                                    // still flow without equating the two addresses.
                                    let object = self.add_node(
                                        NodeKey::ByvalObject(func_index, stmt_index, param_index),
                                        format!(
                                            "obj:byval:{}:{stmt_index}:{param_index}",
                                            owner_name(&owner)
                                        ),
                                        NodeKind::Object {
                                            object: ObjectKind::Alloca,
                                            key: format!("byval@{stmt_index}:{param_index}"),
                                            owner: Some(owner_name(&owner).to_string()),
                                        },
                                    );
                                    self.add_edge(
                                        EdgeKind::AddrOf,
                                        object,
                                        param,
                                        owner.clone(),
                                        loc.clone(),
                                    );
                                    self.add_edge(
                                        EdgeKind::Memcpy { bytes: Some(*size) },
                                        arg,
                                        param,
                                        owner.clone(),
                                        loc.clone(),
                                    );
                                } else {
                                    self.add_edge(
                                        EdgeKind::Assign,
                                        arg,
                                        param,
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
                if sig.vararg && self.direct_vararg_call_requires_boundary(callee, sig, args) {
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
        let value_kind = self.value_kind(&key, &kind);
        let canonical_pointer_null = matches!(
            &key,
            NodeKey::FunctionValue(_, value) | NodeKey::GlobalInitValue(value)
                if value == "null" && value_kind == ValueKind::Pointer
        );
        self.nodes.push(Node {
            id,
            label,
            kind,
            value_kind,
            canonical_pointer_null,
            has_empty_witness: canonical_pointer_null,
        });
        self.node_ids.insert(key, id);
        id
    }

    fn value_kind(&self, key: &NodeKey, _kind: &NodeKind) -> ValueKind {
        match key {
            NodeKey::SymbolValue(..) => ValueKind::Pointer,
            NodeKey::FunctionValue(_, value) | NodeKey::GlobalInitValue(value) => self
                .pir
                .lowering
                .semantic_value_kinds
                .get(value)
                .copied()
                .unwrap_or(ValueKind::Unknown),
            NodeKey::ExternalNonPointerWrite(..) => ValueKind::NonPointer,
            NodeKey::ExternalPointerWrite(..) => ValueKind::Pointer,
            NodeKey::ExternalStateAddress(_) => ValueKind::Pointer,
            NodeKey::Param(func_index, param_index) => self
                .pir
                .functions
                .get(*func_index)
                .and_then(|func| func.param_names.get(*param_index))
                .and_then(|name| self.pir.lowering.semantic_value_kinds.get(name))
                .copied()
                .unwrap_or(ValueKind::Unknown),
            NodeKey::Return(_) | NodeKey::GlobalObject(_) | NodeKey::FunctionObject(_) => {
                ValueKind::Unknown
            }
            NodeKey::AllocaObject(..)
            | NodeKey::ByvalObject(..)
            | NodeKey::HeapObject(..)
            | NodeKey::ExternalReadonlyObject(_) => ValueKind::Unknown,
        }
    }

    fn direct_vararg_call_requires_boundary(
        &mut self,
        callee: &str,
        sig: &Signature,
        args: &[String],
    ) -> bool {
        let external = self
            .functions
            .get(callee)
            .and_then(|index| self.pir.functions.get(*index))
            .map(|func| func.external)
            .unwrap_or(true);
        if external && proven_external_call_contract(self.pir, callee, sig, args, false).is_some() {
            return false;
        }
        if self.vararg_call_proof.is_benign(callee, args) {
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
            access_bytes: None,
            access_extent_unknown: false,
            volatile: false,
            modeled_external_write: false,
            loc,
        });
        id
    }

    fn add_memory_edge(
        &mut self,
        kind: EdgeKind,
        src: NodeId,
        dst: NodeId,
        owner: Owner,
        access_bytes: Option<u64>,
        access_extent_unknown: bool,
        volatile: bool,
        loc: Option<Loc>,
    ) -> EdgeId {
        let id = self.add_edge(kind, src, dst, owner, loc);
        self.edges[id.0 as usize].access_bytes = access_bytes;
        self.edges[id.0 as usize].access_extent_unknown = access_extent_unknown;
        self.edges[id.0 as usize].volatile = volatile;
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

    fn external_state_address(&mut self, key: &str) -> NodeId {
        let node_key = NodeKey::ExternalStateAddress(key.into());
        if let Some(&node) = self.node_ids.get(&node_key) {
            return node;
        }
        let object = self.external_readonly_object(&format!("external-state:{key}"));
        let address = self.add_node(
            node_key,
            format!("val:external-state:{key}"),
            NodeKind::Value {
                scope: Scope::Module,
            },
        );
        self.add_edge(EdgeKind::AddrOf, object, address, Owner::Module, None);
        address
    }
}

/// Whether a direct callee is outside the analyzed module. Missing declarations retain the
/// existing external-call fallback.
pub fn direct_callee_is_external(pir: &Pir, callee: &str) -> bool {
    pir.functions
        .iter()
        .find(|function| function.key == callee)
        .map(|function| function.external)
        .unwrap_or(true)
}

/// Recognize the standard `free(void *)` contract at a direct callsite. PIR classifies LLVM
/// pointers in the integer ABI class, so exact name plus this complete call shape is the strongest
/// check available without restoring source-level types. Replacement implementations present in
/// the analyzed module are deliberately excluded.
pub fn trusted_free_call(
    pir: &Pir,
    callee: &str,
    sig: &Signature,
    arg_count: usize,
    has_result: bool,
) -> bool {
    let declared = pir
        .functions
        .iter()
        .find(|function| function.key == callee)
        .is_some_and(|function| function.external && function.sig == *sig);
    declared
        && callee.strip_prefix('@').unwrap_or(callee) == "free"
        && external_call_contract(callee)
            .is_some_and(|contract| contract.matches_signature(sig, arg_count, has_result))
}

/// Validate a shared external-call contract against the exact declaration and this callsite.
/// This is the sole admission path used by PAG construction and disposition certificate
/// assembly. A missing declaration, a module-local replacement, an ABI mismatch, or a dynamic
/// printf formats remain complete by conservatively treating pointer variadic actuals as possible
/// `%n` destinations; the format proof is used only to sharpen those effects.
pub fn proven_external_call_contract(
    pir: &Pir,
    callee: &str,
    sig: &Signature,
    args: &[String],
    has_result: bool,
) -> Option<ExternalCallContract> {
    let declaration = pir
        .functions
        .iter()
        .find(|function| function.key == callee)?;
    if !declaration.external || declaration.sig != *sig {
        return None;
    }
    let contract = external_call_contract(callee)?;
    if !contract.matches_signature(sig, args.len(), has_result) {
        return None;
    }
    if contract.policy == ExternalContractPolicy::NoVariadicActuals
        && args.len() != contract.fixed_params
    {
        return None;
    }
    Some(contract)
}

fn printf_format_arg(callee: &str) -> Option<usize> {
    match callee.strip_prefix('@').unwrap_or(callee) {
        "printf" => Some(0),
        "fprintf" | "sprintf" | "dprintf" => Some(1),
        "snprintf" => Some(2),
        _ => None,
    }
}

/// Standard scanf-family conversion arguments are caller-owned output pointers which are used
/// only for the duration of the call. The coarse model deliberately does not parse the format:
/// every pointer-valued variadic actual may be written, which over-approximates suppressed,
/// conditional, and unused conversions without turning a non-capturing libc contract into an
/// address escape. `v*scanf` entry points are excluded because their destinations are hidden in a
/// `va_list` rather than present as positional callsite actuals.
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
/// accepted only when every constant LLVM byte string selected by the format operand contains no
/// `%n`; every unsupported or genuinely dynamic shape fails closed.
pub fn direct_vararg_call_is_benign(pir: &Pir, callee: &str, args: &[String]) -> bool {
    VarargCallProof::new(pir).is_benign(callee, args)
}

/// Reusable proof context for direct variadic calls in one PIR module.  The structural contracts
/// of internal `va_list` forwarders are properties of callees, rather than callsites, so clients
/// which inspect a whole module should retain one context instead of launching the proof anew for
/// every call.
pub struct VarargCallProof<'a> {
    pir: &'a Pir,
    functions: BTreeMap<&'a str, &'a pangs_pir::Func>,
    fixed_forwarders: BTreeMap<String, FixedForwarderState>,
    variadic_forwarders: BTreeMap<String, Option<usize>>,
    #[cfg(test)]
    fixed_summary_computations: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FixedVfprintfForwarder {
    format_param: usize,
    va_list_param: usize,
}

#[derive(Clone, Copy, Debug)]
enum FixedForwarderState {
    InProgress,
    Done(Option<FixedVfprintfForwarder>),
}

#[derive(Clone, Copy, Debug)]
enum FixedForwarderLookup {
    Contract(FixedVfprintfForwarder),
    NoContract,
    Cycle,
}

#[derive(Clone, Debug)]
struct VaForwardSink {
    stmt_index: usize,
    format_value: String,
    va_list_value: String,
    va_list_arg: usize,
}

/// Recognize a closed `printf`-style wrapper whose variadic tail is consumed only by one proved
/// forwarding chain ending in `vfprintf`. The returned index identifies the wrapper's fixed format
/// parameter. Helpers in the chain receive the format and `va_list` through fixed parameters and
/// must themselves have a closed, single-forward structural contract.
impl<'a> VarargCallProof<'a> {
    pub fn new(pir: &'a Pir) -> Self {
        Self {
            pir,
            functions: pir
                .functions
                .iter()
                .map(|func| (func.key.as_str(), func))
                .collect(),
            fixed_forwarders: BTreeMap::new(),
            variadic_forwarders: BTreeMap::new(),
            #[cfg(test)]
            fixed_summary_computations: 0,
        }
    }

    pub fn is_benign(&mut self, callee: &str, args: &[String]) -> bool {
        if is_known_benign_vararg_callee(callee) {
            return true;
        }
        proven_printf_effect(self.pir, callee, args).is_some()
            || self
                .internal_vfprintf_forwarder_format_index(callee)
                .and_then(|index| args.get(index))
                .is_some_and(|operand| constant_formats_are_percent_n_free(self.pir, operand))
    }

    fn internal_vfprintf_forwarder_format_index(&mut self, callee: &str) -> Option<usize> {
        if let Some(summary) = self.variadic_forwarders.get(callee) {
            return *summary;
        }
        let summary = self.compute_vfprintf_forwarder_format_index(callee);
        self.variadic_forwarders.insert(callee.to_string(), summary);
        summary
    }

    fn compute_vfprintf_forwarder_format_index(&mut self, callee: &str) -> Option<usize> {
        let func = *self.functions.get(callee)?;
        if func.external || !func.sig.vararg || func.param_names.len() != func.sig.params.len() {
            return None;
        }

        let starts = func
            .body
            .iter()
            .filter_map(|stmt| vararg_intrinsic_operand(stmt, "llvm.va_start"))
            .collect::<Vec<_>>();
        let ends = func
            .body
            .iter()
            .filter_map(|stmt| vararg_intrinsic_operand(stmt, "llvm.va_end"))
            .collect::<Vec<_>>();
        if starts.is_empty() {
            return None;
        }

        let mut start_roots = starts
            .iter()
            .map(|value| unique_local_alloca_root(func, value))
            .collect::<Option<Vec<_>>>()?;
        let mut end_roots = ends
            .iter()
            .map(|value| unique_local_alloca_root(func, value))
            .collect::<Option<Vec<_>>>()?;
        start_roots.sort_unstable();
        start_roots.dedup();
        end_roots.sort_unstable();
        end_roots.dedup();
        if end_roots.iter().any(|root| !start_roots.contains(root)) {
            return None;
        }
        let va_list_roots = start_roots.iter().copied().collect::<BTreeSet<_>>();
        let va_list_values = local_pointer_derivatives(func, &va_list_roots);
        let start_values = starts.into_iter().collect::<BTreeSet<_>>();
        let end_values = ends.into_iter().collect::<BTreeSet<_>>();

        let sinks = func
            .body
            .iter()
            .enumerate()
            .filter_map(|(stmt_index, stmt)| {
                let Stmt::CallDirect { args, .. } = stmt else {
                    return None;
                };
                // Most direct calls in a wrapper cannot carry its local `va_list`.  Establish that
                // cheap local fact before asking for the callee's compositional summary.
                if !args.iter().any(|arg| va_list_values.contains(arg.as_str())) {
                    return None;
                }
                let (format_arg, va_list_arg) = match self.forwarding_call_arg_indexes(stmt) {
                    FixedForwarderLookup::Contract(contract) => {
                        (contract.format_param, contract.va_list_param)
                    }
                    FixedForwarderLookup::NoContract | FixedForwarderLookup::Cycle => return None,
                };
                va_list_values
                    .contains(args[va_list_arg].as_str())
                    .then(|| VaForwardSink {
                        stmt_index,
                        format_value: args[format_arg].clone(),
                        va_list_value: args[va_list_arg].clone(),
                        va_list_arg,
                    })
            })
            .collect::<Vec<_>>();
        if sinks.len() != 1 {
            return None;
        }
        let sink = &sinks[0];
        let forward_root = unique_local_alloca_root(func, &sink.va_list_value)?;
        if !start_roots.contains(&forward_root)
            || !va_list_uses_are_confined(func, &va_list_values, sink, &start_values, &end_values)
        {
            return None;
        }

        let indexes = func
            .param_names
            .iter()
            .enumerate()
            .filter_map(|(index, param)| {
                value_is_unchanged_copy(func, param, &sink.format_value).then_some(index)
            })
            .collect::<Vec<_>>();
        (indexes.len() == 1).then(|| indexes[0])
    }

    fn forwarding_call_arg_indexes(&mut self, stmt: &Stmt) -> FixedForwarderLookup {
        let Stmt::CallDirect { callee, args, .. } = stmt else {
            return FixedForwarderLookup::NoContract;
        };
        if callee.strip_prefix('@').unwrap_or(callee) == "vfprintf" {
            return if args.len() == 3 {
                FixedForwarderLookup::Contract(FixedVfprintfForwarder {
                    format_param: 1,
                    va_list_param: 2,
                })
            } else {
                FixedForwarderLookup::NoContract
            };
        }
        match self.internal_fixed_vfprintf_forwarder(callee) {
            FixedForwarderLookup::Contract(contract)
                if contract.format_param < args.len() && contract.va_list_param < args.len() =>
            {
                FixedForwarderLookup::Contract(contract)
            }
            FixedForwarderLookup::Cycle => FixedForwarderLookup::Cycle,
            FixedForwarderLookup::Contract(_) | FixedForwarderLookup::NoContract => {
                FixedForwarderLookup::NoContract
            }
        }
    }

    fn internal_fixed_vfprintf_forwarder(&mut self, callee: &str) -> FixedForwarderLookup {
        match self.fixed_forwarders.get(callee).copied() {
            Some(FixedForwarderState::Done(Some(contract))) => {
                return FixedForwarderLookup::Contract(contract);
            }
            Some(FixedForwarderState::Done(None)) => return FixedForwarderLookup::NoContract,
            Some(FixedForwarderState::InProgress) => return FixedForwarderLookup::Cycle,
            None => {}
        }
        self.fixed_forwarders
            .insert(callee.to_string(), FixedForwarderState::InProgress);
        #[cfg(test)]
        {
            self.fixed_summary_computations += 1;
        }

        let computed = self.compute_fixed_vfprintf_forwarder(callee);
        let contract = match computed {
            FixedForwarderLookup::Contract(contract) => Some(contract),
            FixedForwarderLookup::NoContract | FixedForwarderLookup::Cycle => None,
        };
        self.fixed_forwarders
            .insert(callee.to_string(), FixedForwarderState::Done(contract));
        computed
    }

    fn compute_fixed_vfprintf_forwarder(&mut self, callee: &str) -> FixedForwarderLookup {
        let Some(func) = self.functions.get(callee).copied() else {
            return FixedForwarderLookup::NoContract;
        };
        if func.external || func.sig.vararg || func.param_names.len() != func.sig.params.len() {
            return FixedForwarderLookup::NoContract;
        }

        let pointer_derivatives = func
            .param_names
            .iter()
            .map(|param| unchanged_pointer_derivatives(func, param))
            .collect::<Vec<_>>();
        let mut contracts = Vec::new();
        for (stmt_index, stmt) in func.body.iter().enumerate() {
            let Stmt::CallDirect { args, .. } = stmt else {
                continue;
            };
            if !call_could_forward_distinct_params(func, args, &pointer_derivatives) {
                continue;
            }
            let contract = match self.forwarding_call_arg_indexes(stmt) {
                FixedForwarderLookup::Contract(contract) => contract,
                // A potentially relevant recursive cycle is rejected as a whole.  In
                // particular, do not cache a summary inferred by ignoring the back edge: that
                // would make mutually recursive wrappers depend on traversal order.
                FixedForwarderLookup::Cycle => return FixedForwarderLookup::Cycle,
                FixedForwarderLookup::NoContract => continue,
            };
            let format_arg = contract.format_param;
            let va_list_arg = contract.va_list_param;
            let format_value = &args[format_arg];
            let va_list_value = &args[va_list_arg];
            let format_params = func
                .param_names
                .iter()
                .enumerate()
                .filter_map(|(index, param)| {
                    value_is_unchanged_copy(func, param, format_value).then_some(index)
                })
                .collect::<Vec<_>>();
            let va_list_params = func
                .param_names
                .iter()
                .enumerate()
                .filter_map(|(index, param)| {
                    let derived = unchanged_pointer_derivatives(func, param);
                    let sink = VaForwardSink {
                        stmt_index,
                        format_value: format_value.clone(),
                        va_list_value: va_list_value.clone(),
                        va_list_arg,
                    };
                    (derived.contains(va_list_value.as_str())
                        && va_list_uses_are_confined(
                            func,
                            &derived,
                            &sink,
                            &BTreeSet::new(),
                            &BTreeSet::new(),
                        ))
                    .then_some(index)
                })
                .collect::<Vec<_>>();
            if format_params.len() == 1
                && va_list_params.len() == 1
                && format_params[0] != va_list_params[0]
            {
                contracts.push(FixedVfprintfForwarder {
                    format_param: format_params[0],
                    va_list_param: va_list_params[0],
                });
            }
        }
        if contracts.len() == 1 {
            FixedForwarderLookup::Contract(contracts[0])
        } else {
            FixedForwarderLookup::NoContract
        }
    }
}

fn call_could_forward_distinct_params(
    func: &pangs_pir::Func,
    args: &[String],
    pointer_derivatives: &[BTreeSet<&str>],
) -> bool {
    args.iter().enumerate().any(|(format_arg, format_value)| {
        let format_params = func
            .param_names
            .iter()
            .enumerate()
            .filter(|(_, param)| value_is_unchanged_copy(func, param, format_value));
        format_params.into_iter().any(|(format_param, _)| {
            args.iter().enumerate().any(|(va_list_arg, va_list_value)| {
                va_list_arg != format_arg
                    && pointer_derivatives
                        .iter()
                        .enumerate()
                        .any(|(va_list_param, derived)| {
                            va_list_param != format_param
                                && derived.contains(va_list_value.as_str())
                        })
            })
        })
    })
}

fn vararg_intrinsic_operand<'a>(stmt: &'a Stmt, expected: &str) -> Option<&'a str> {
    match stmt {
        Stmt::Unknown {
            op,
            operands,
            results,
            reason,
            ..
        } if op == expected
            && reason == "varargs_intrinsic"
            && operands.len() == 1
            && results.is_empty() =>
        {
            Some(operands[0].as_str())
        }
        _ => None,
    }
}

fn local_alloca_roots<'a>(func: &'a pangs_pir::Func, value: &str) -> Option<BTreeSet<&'a str>> {
    fn visit<'a>(
        func: &'a pangs_pir::Func,
        value: &str,
        visiting: &mut BTreeSet<String>,
        roots: &mut BTreeSet<&'a str>,
    ) -> Option<()> {
        if !visiting.insert(value.to_string()) {
            return None;
        }
        let stmt = func
            .body
            .iter()
            .find(|stmt| stmt_destination(stmt) == Some(value))?;
        match stmt {
            Stmt::Alloca { dest, .. } => {
                roots.insert(dest);
            }
            Stmt::Assign { sources, .. } if !sources.is_empty() => {
                for source in sources {
                    visit(func, source, visiting, roots)?;
                }
            }
            Stmt::Gep { base, .. } => visit(func, base, visiting, roots)?,
            _ => return None,
        }
        visiting.remove(value);
        Some(())
    }

    let mut roots = BTreeSet::new();
    visit(func, value, &mut BTreeSet::new(), &mut roots)?;
    Some(roots)
}

fn unique_local_alloca_root<'a>(func: &'a pangs_pir::Func, value: &str) -> Option<&'a str> {
    let roots = local_alloca_roots(func, value)?;
    (roots.len() == 1).then(|| *roots.first().expect("one root was checked"))
}

fn local_pointer_derivatives<'a>(
    func: &'a pangs_pir::Func,
    roots: &BTreeSet<&'a str>,
) -> BTreeSet<&'a str> {
    let mut derived = roots.clone();
    loop {
        let old_len = derived.len();
        for stmt in &func.body {
            match stmt {
                Stmt::Assign { dest, sources, .. }
                    if sources
                        .iter()
                        .any(|source| derived.contains(source.as_str())) =>
                {
                    derived.insert(dest);
                }
                Stmt::Gep { dest, base, .. } if derived.contains(base.as_str()) => {
                    derived.insert(dest);
                }
                _ => {}
            }
        }
        if derived.len() == old_len {
            return derived;
        }
    }
}

fn value_is_unchanged_copy(func: &pangs_pir::Func, source: &str, target: &str) -> bool {
    let mut values = BTreeSet::from([source]);
    let mut slots = BTreeSet::<&str>::new();
    loop {
        let old_values = values.len();
        let old_slots = slots.len();
        for stmt in &func.body {
            match stmt {
                Stmt::Assign { dest, sources, .. }
                    if !sources.is_empty()
                        && sources.iter().all(|value| values.contains(value.as_str())) =>
                {
                    values.insert(dest);
                }
                Stmt::Load { dest, address, .. }
                    if exact_local_alloca_root(func, address)
                        .is_some_and(|root| slots.contains(root)) =>
                {
                    values.insert(dest);
                }
                _ => {}
            }
        }
        let candidates = func.body.iter().filter_map(|stmt| match stmt {
            Stmt::Store { address, value, .. } if values.contains(value.as_str()) => {
                exact_local_alloca_root(func, address)
            }
            _ => None,
        });
        for root in candidates {
            let stores = func.body.iter().filter_map(|stmt| match stmt {
                Stmt::Store { address, value, .. }
                    if exact_local_alloca_root(func, address) == Some(root) =>
                {
                    Some(value.as_str())
                }
                _ => None,
            });
            if stores.clone().count() > 0
                && stores.clone().all(|value| values.contains(value))
                && local_slot_uses_are_confined(func, root)
            {
                slots.insert(root);
            }
        }
        if values.len() == old_values && slots.len() == old_slots {
            break;
        }
    }
    values.contains(target)
}

fn unchanged_pointer_derivatives<'a>(
    func: &'a pangs_pir::Func,
    root: &'a str,
) -> BTreeSet<&'a str> {
    let mut derived = BTreeSet::from([root]);
    loop {
        let old_len = derived.len();
        for stmt in &func.body {
            match stmt {
                Stmt::Assign { dest, sources, .. }
                    if !sources.is_empty()
                        && sources
                            .iter()
                            .all(|source| derived.contains(source.as_str())) =>
                {
                    derived.insert(dest);
                }
                Stmt::Gep { dest, base, .. } if derived.contains(base.as_str()) => {
                    derived.insert(dest);
                }
                _ => {}
            }
        }
        if derived.len() == old_len {
            return derived;
        }
    }
}

fn exact_local_alloca_root<'a>(func: &'a pangs_pir::Func, value: &str) -> Option<&'a str> {
    fn visit<'a>(
        func: &'a pangs_pir::Func,
        value: &str,
        visiting: &mut BTreeSet<String>,
    ) -> Option<&'a str> {
        if !visiting.insert(value.to_string()) {
            return None;
        }
        let stmt = func
            .body
            .iter()
            .find(|stmt| stmt_destination(stmt) == Some(value))?;
        let root = match stmt {
            Stmt::Alloca { dest, .. } => Some(dest.as_str()),
            Stmt::Assign { sources, .. } if !sources.is_empty() => {
                let roots = sources
                    .iter()
                    .map(|source| visit(func, source, visiting))
                    .collect::<Option<BTreeSet<_>>>()?;
                (roots.len() == 1).then(|| *roots.first().expect("one root was checked"))
            }
            Stmt::Gep {
                base,
                byte_off: Some(0),
                ..
            } => visit(func, base, visiting),
            _ => None,
        };
        visiting.remove(value);
        root
    }
    visit(func, value, &mut BTreeSet::new())
}

fn local_slot_uses_are_confined<'a>(func: &'a pangs_pir::Func, root: &'a str) -> bool {
    let derived = local_pointer_derivatives(func, &BTreeSet::from([root]));
    func.body.iter().all(|stmt| match stmt {
        Stmt::Assign { .. } => true,
        Stmt::Gep {
            base,
            byte_off: Some(0),
            ..
        } => !derived.contains(base.as_str()) || exact_local_alloca_root(func, base) == Some(root),
        Stmt::Load { address, .. } => {
            !derived.contains(address.as_str())
                || exact_local_alloca_root(func, address) == Some(root)
        }
        Stmt::Store { address, value, .. } => {
            !derived.contains(value.as_str())
                && (!derived.contains(address.as_str())
                    || exact_local_alloca_root(func, address) == Some(root))
        }
        _ => !stmt_input_operands(stmt)
            .iter()
            .any(|operand| derived.contains(*operand)),
    })
}

fn stmt_destination(stmt: &Stmt) -> Option<&str> {
    match stmt {
        Stmt::Alloca { dest, .. }
        | Stmt::Assign { dest, .. }
        | Stmt::ScalarOp { dest, .. }
        | Stmt::Load { dest, .. }
        | Stmt::Gep { dest, .. }
        | Stmt::PtrToInt { dest, .. }
        | Stmt::IntToPtr { dest, .. }
        | Stmt::VarArg { dest, .. } => Some(dest),
        Stmt::CallDirect { dest, .. } | Stmt::CallIndirect { dest, .. } => dest.as_deref(),
        _ => None,
    }
}

fn stmt_input_operands(stmt: &Stmt) -> Vec<&str> {
    match stmt {
        Stmt::Alloca { .. } | Stmt::GlobalRef { .. } => Vec::new(),
        Stmt::Assign { sources, .. } => sources.iter().map(String::as_str).collect(),
        Stmt::ScalarOp { lhs, rhs, .. } => vec![lhs, rhs],
        Stmt::Load { address, .. } => vec![address],
        Stmt::Store { address, value, .. } => vec![address, value],
        Stmt::Gep { base, .. } => vec![base],
        Stmt::PtrToInt { source, .. } | Stmt::IntToPtr { source, .. } => vec![source],
        Stmt::VarArg { .. } => Vec::new(),
        Stmt::Memcpy { dst, src, .. } => vec![dst, src],
        Stmt::Memset { dst, value, .. } => vec![dst, value],
        Stmt::Unknown { operands, .. } => operands.iter().map(String::as_str).collect(),
        Stmt::Return { value, .. } => value.iter().map(String::as_str).collect(),
        Stmt::CallDirect { args, .. } => args.iter().map(String::as_str).collect(),
        Stmt::CallIndirect { operand, args, .. } => std::iter::once(operand.as_str())
            .chain(args.iter().map(String::as_str))
            .collect(),
    }
}

fn va_list_uses_are_confined(
    func: &pangs_pir::Func,
    derived: &BTreeSet<&str>,
    sink: &VaForwardSink,
    starts: &BTreeSet<&str>,
    ends: &BTreeSet<&str>,
) -> bool {
    func.body.iter().enumerate().all(|(stmt_index, stmt)| {
        let used = stmt_input_operands(stmt)
            .into_iter()
            .filter(|operand| derived.contains(*operand))
            .collect::<Vec<_>>();
        if used.is_empty() {
            return true;
        }
        match stmt {
            Stmt::Assign { dest, sources, .. } => {
                derived.contains(dest.as_str())
                    && !sources.is_empty()
                    && sources
                        .iter()
                        .all(|source| derived.contains(source.as_str()))
            }
            Stmt::Gep { dest, base, .. } => {
                used.len() == 1 && used[0] == base && derived.contains(dest.as_str())
            }
            Stmt::Unknown { op, operands, .. }
                if matches!(op.as_str(), "llvm.va_start" | "llvm.va_end") =>
            {
                operands.len() == 1
                    && used.len() == 1
                    && ((op == "llvm.va_start" && starts.contains(used[0]))
                        || (op == "llvm.va_end" && ends.contains(used[0])))
            }
            Stmt::CallDirect { args, .. } if stmt_index == sink.stmt_index => {
                args.get(sink.va_list_arg)
                    .is_some_and(|arg| arg == &sink.va_list_value)
                    && used.len() == 1
                    && used[0] == sink.va_list_value
            }
            _ => false,
        }
    })
}

pub fn proven_printf_effect(
    pir: &Pir,
    callee: &str,
    args: &[String],
) -> Option<ProvenPrintfEffect> {
    let format_index = printf_format_arg(callee)?;
    let safe = args
        .get(format_index)
        .is_some_and(|operand| constant_formats_are_percent_n_free(pir, operand));
    if !safe {
        return None;
    }
    match callee.strip_prefix('@').unwrap_or(callee) {
        "printf" | "fprintf" | "dprintf" => Some(ProvenPrintfEffect::NoClientWrite),
        "sprintf" | "snprintf" => Some(ProvenPrintfEffect::WritesArg { index: 0 }),
        _ => None,
    }
}

const MAX_CONSTANT_FORMAT_ALTERNATIVES: usize = 32;

fn constant_formats_are_percent_n_free(pir: &Pir, operand: &str) -> bool {
    constant_format_bytes(pir, operand).is_some_and(|formats| {
        !formats.is_empty()
            && formats
                .iter()
                .all(|format| format_is_proven_percent_n_free(format))
    })
}

/// Resolve a pointer-valued format operand through the PIR's representation of pointer SSA
/// copies, `select`, and `phi`. LLVM lowering deliberately represents all three as `Assign`;
/// requiring every source to resolve keeps the proof independent of pointee types and rejects
/// cycles, memory loads, and genuinely dynamic alternatives.
fn constant_format_bytes(pir: &Pir, operand: &str) -> Option<BTreeSet<Vec<u8>>> {
    fn visit(
        pir: &Pir,
        operand: &str,
        visiting: &mut BTreeSet<String>,
        formats: &mut BTreeSet<Vec<u8>>,
    ) -> Option<()> {
        if let Some(format) = direct_constant_format_bytes(pir, operand) {
            formats.insert(format);
            return (formats.len() <= MAX_CONSTANT_FORMAT_ALTERNATIVES).then_some(());
        }
        if !visiting.insert(operand.to_string()) {
            return None;
        }
        let mut definitions = pir
            .functions
            .iter()
            .flat_map(|func| func.body.iter())
            .filter(|stmt| stmt_destination(stmt) == Some(operand));
        let definition = definitions.next()?;
        if definitions.next().is_some() {
            return None;
        }
        let Stmt::Assign { sources, .. } = definition else {
            return None;
        };
        if sources.is_empty() {
            return None;
        }
        for source in sources {
            visit(pir, source, visiting, formats)?;
        }
        visiting.remove(operand);
        Some(())
    }

    let mut formats = BTreeSet::new();
    visit(pir, operand, &mut BTreeSet::new(), &mut formats)?;
    Some(formats)
}

fn direct_constant_format_bytes(pir: &Pir, operand: &str) -> Option<Vec<u8>> {
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
        allocation_storage_roots, direct_vararg_call_is_benign, proven_external_call_contract,
        trusted_free_call, CallKind, Edge, EdgeId, EdgeKind, IntegerPointerPolicy, NodeKind,
        ObjectKind, OmegaSeedKind, Owner, Pag, PagOpts, PointerIntegerOrigin, SeedTarget,
        StorageRoot, StorageRootState, VarargCallProof,
    };
    use pangs_pir::{ExternalArgEffect, Global, Pir, Stmt, ValueKind};
    use std::collections::BTreeSet;

    #[test]
    fn printf_format_proof_decodes_literals_and_fails_closed() {
        let format = |key: &str, initializer: &str, is_const: bool| Global {
            key: key.to_string(),
            is_const,
            mutable: !is_const,
            initializer_ir: Some(initializer.to_string()),
            ..Global::default()
        };
        let mut pir = Pir {
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
        pir.functions = serde_json::from_str(
            r#"[{
                "key":"caller",
                "sig":{"ret":{"class":"void"},"params":[]},
                "body":[
                    {"kind":"assign","dest":"%caller::safe_join","sources":["@safe","@escaped_backslash"]},
                    {"kind":"assign","dest":"%caller::safe_copy","sources":["%caller::safe_join"]},
                    {"kind":"assign","dest":"%caller::mixed_join","sources":["@safe","@percent_n"]},
                    {"kind":"assign","dest":"%caller::dynamic_join","sources":["@safe","%caller::unknown"]},
                    {"kind":"assign","dest":"%caller::cycle","sources":["@safe","%caller::cycle"]}
                ]
            }]"#,
        )
        .unwrap();
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
        assert!(direct_vararg_call_is_benign(
            &pir,
            "fprintf",
            &fprintf_args("%caller::safe_join")
        ));
        assert!(direct_vararg_call_is_benign(
            &pir,
            "fprintf",
            &fprintf_args("%caller::safe_copy")
        ));
        assert!(!direct_vararg_call_is_benign(
            &pir,
            "fprintf",
            &fprintf_args("%caller::mixed_join")
        ));
        assert!(!direct_vararg_call_is_benign(
            &pir,
            "fprintf",
            &fprintf_args("%caller::dynamic_join")
        ));
        assert!(!direct_vararg_call_is_benign(
            &pir,
            "fprintf",
            &fprintf_args("%caller::cycle")
        ));
    }

    #[test]
    fn internal_vfprintf_forwarder_requires_constant_safe_format_and_closed_va_list() {
        let pir: Pir = serde_json::from_str(
            r#"{
                "module":"printf-wrapper",
                "globals":[
                    {"key":"safe","is_const":true,"mutable":false,"initializer_ir":"[3 x i8] c\"%d\\00\""},
                    {"key":"percent_n","is_const":true,"mutable":false,"initializer_ir":"[3 x i8] c\"%n\\00\""}
                ],
                "functions":[
                    {
                        "key":"report",
                        "sig":{"ret":{"class":"void"},"params":[{"class":"integer"}],"vararg":true},
                        "param_names":["%fmt"],
                        "body":[
                            {"kind":"alloca","dest":"%fmt.addr","ty":"i8*"},
                            {"kind":"alloca","dest":"%ap","ty":"va_list"},
                            {"kind":"alloca","dest":"%unused-ap","ty":"va_list"},
                            {"kind":"store","address":"%fmt.addr","value":"%fmt"},
                            {"kind":"load","dest":"%fmt.load","address":"%fmt.addr"},
                            {"kind":"gep","dest":"%unused.start","base":"%unused-ap","byte_off":0},
                            {"kind":"unknown","op":"llvm.va_start","operands":["%unused.start"],"reason":"varargs_intrinsic"},
                            {"kind":"gep","dest":"%unused.end","base":"%unused-ap","byte_off":0},
                            {"kind":"unknown","op":"llvm.va_end","operands":["%unused.end"],"reason":"varargs_intrinsic"},
                            {"kind":"gep","dest":"%ap.start","base":"%ap","byte_off":0},
                            {"kind":"unknown","op":"llvm.va_start","operands":["%ap.start"],"reason":"varargs_intrinsic"},
                            {"kind":"gep","dest":"%ap.forward","base":"%ap","byte_off":0},
                            {"kind":"call_direct","callee":"vfprintf","sig":{"ret":{"class":"integer"},"params":[{"class":"integer"},{"class":"integer"},{"class":"integer"}]},"args":["%stream","%fmt.load","%ap.forward"]},
                            {"kind":"gep","dest":"%ap.end","base":"%ap","byte_off":0},
                            {"kind":"unknown","op":"llvm.va_end","operands":["%ap.end"],"reason":"varargs_intrinsic"}
                        ]
                    },
                    {
                        "key":"report_chained",
                        "sig":{"ret":{"class":"void"},"params":[{"class":"integer"}],"vararg":true},
                        "param_names":["%chain.fmt"],
                        "body":[
                            {"kind":"alloca","dest":"%chain.ap","ty":"va_list"},
                            {"kind":"gep","dest":"%chain.ap.start","base":"%chain.ap","byte_off":0},
                            {"kind":"unknown","op":"llvm.va_start","operands":["%chain.ap.start"],"reason":"varargs_intrinsic"},
                            {"kind":"gep","dest":"%chain.ap.forward","base":"%chain.ap","byte_off":0},
                            {"kind":"call_direct","callee":"forward_report","sig":{"ret":{"class":"void"},"params":[{"class":"integer"},{"class":"integer"},{"class":"integer"}]},"args":["%where","%chain.fmt","%chain.ap.forward"]}
                        ]
                    },
                    {
                        "key":"forward_report",
                        "sig":{"ret":{"class":"void"},"params":[{"class":"integer"},{"class":"integer"},{"class":"integer"}]},
                        "param_names":["%forward.stream","%forward.fmt","%forward.ap"],
                        "body":[
                            {"kind":"call_direct","callee":"final_report","sig":{"ret":{"class":"void"},"params":[{"class":"integer"},{"class":"integer"},{"class":"integer"}]},"args":["%forward.stream","%forward.fmt","%forward.ap"]}
                        ]
                    },
                    {
                        "key":"final_report",
                        "sig":{"ret":{"class":"void"},"params":[{"class":"integer"},{"class":"integer"},{"class":"integer"}]},
                        "param_names":["%final.stream","%final.fmt","%final.ap"],
                        "body":[
                            {"kind":"call_direct","callee":"vfprintf","sig":{"ret":{"class":"integer"},"params":[{"class":"integer"},{"class":"integer"},{"class":"integer"}]},"args":["%final.stream","%final.fmt","%final.ap"]}
                        ]
                    }
                ]
            }"#,
        )
        .unwrap();

        assert!(direct_vararg_call_is_benign(
            &pir,
            "report",
            &["@safe".to_string(), "%value".to_string()]
        ));
        assert!(!direct_vararg_call_is_benign(
            &pir,
            "report",
            &["@percent_n".to_string(), "%value".to_string()]
        ));
        assert!(!direct_vararg_call_is_benign(
            &pir,
            "report",
            &["%dynamic".to_string(), "%value".to_string()]
        ));
        assert!(direct_vararg_call_is_benign(
            &pir,
            "report_chained",
            &["@safe".to_string(), "%value".to_string()]
        ));
        assert!(!direct_vararg_call_is_benign(
            &pir,
            "report_chained",
            &["@percent_n".to_string(), "%value".to_string()]
        ));

        let mut escaped = pir.clone();
        escaped.functions[0].body.push(pangs_pir::Stmt::CallDirect {
            callee: "consume_list".to_string(),
            sig: pangs_pir::Signature {
                ret: pangs_pir::AbiClass::Void,
                params: vec![pangs_pir::Param::Integer],
                vararg: false,
                cc: "ccc".to_string(),
            },
            args: vec!["%ap.forward".to_string()],
            dest: None,
            loc: None,
        });
        assert!(!direct_vararg_call_is_benign(
            &escaped,
            "report",
            &["@safe".to_string(), "%value".to_string()]
        ));

        let mut escaped_helper = pir.clone();
        escaped_helper.functions[2]
            .body
            .push(pangs_pir::Stmt::CallDirect {
                callee: "consume_list".to_string(),
                sig: pangs_pir::Signature {
                    ret: pangs_pir::AbiClass::Void,
                    params: vec![pangs_pir::Param::Integer],
                    vararg: false,
                    cc: "ccc".to_string(),
                },
                args: vec!["%forward.ap".to_string()],
                dest: None,
                loc: None,
            });
        assert!(!direct_vararg_call_is_benign(
            &escaped_helper,
            "report_chained",
            &["@safe".to_string(), "%value".to_string()]
        ));
    }

    #[test]
    fn repeated_nested_forwarders_reuse_callee_summaries() {
        let pir: Pir = serde_json::from_str(
            r#"{
                "module":"repeated-forwarders",
                "globals":[
                    {"key":"safe","is_const":true,"mutable":false,"initializer_ir":"[3 x i8] c\"%d\\00\""}
                ],
                "functions":[
                    {
                        "key":"report",
                        "sig":{"ret":{"class":"void"},"params":[{"class":"integer"}],"vararg":true},
                        "param_names":["%fmt"],
                        "body":[
                            {"kind":"alloca","dest":"%ap","ty":"va_list"},
                            {"kind":"unknown","op":"llvm.va_start","operands":["%ap"],"reason":"varargs_intrinsic"},
                            {"kind":"call_direct","callee":"forward","sig":{"ret":{"class":"void"},"params":[{"class":"integer"},{"class":"integer"}]},"args":["%fmt","%ap"]},
                            {"kind":"unknown","op":"llvm.va_end","operands":["%ap"],"reason":"varargs_intrinsic"}
                        ]
                    },
                    {
                        "key":"forward",
                        "sig":{"ret":{"class":"void"},"params":[{"class":"integer"},{"class":"integer"}]},
                        "param_names":["%fmt","%ap"],
                        "body":[
                            {"kind":"call_direct","callee":"final","sig":{"ret":{"class":"void"},"params":[{"class":"integer"},{"class":"integer"}]},"args":["%fmt","%ap"]}
                        ]
                    },
                    {
                        "key":"final",
                        "sig":{"ret":{"class":"void"},"params":[{"class":"integer"},{"class":"integer"}]},
                        "param_names":["%fmt","%ap"],
                        "body":[
                            {"kind":"call_direct","callee":"vfprintf","sig":{"ret":{"class":"integer"},"params":[{"class":"integer"},{"class":"integer"},{"class":"integer"}]},"args":["%stream","%fmt","%ap"]}
                        ]
                    }
                ]
            }"#,
        )
        .unwrap();

        let mut proof = VarargCallProof::new(&pir);
        for _ in 0..50 {
            assert!(proof.is_benign("report", &["@safe".to_string()]));
        }
        assert_eq!(proof.fixed_summary_computations, 2);
        assert_eq!(proof.variadic_forwarders.len(), 1);
    }

    #[test]
    fn relevant_recursive_forwarder_cycles_fail_closed_but_irrelevant_calls_are_filtered() {
        let make_pir = |helper_body: &str, extra_functions: &str| {
            serde_json::from_str::<Pir>(&format!(
                r#"{{
                    "module":"recursive-forwarders",
                    "globals":[
                        {{"key":"safe","is_const":true,"mutable":false,"initializer_ir":"[3 x i8] c\"%d\\00\""}}
                    ],
                    "functions":[
                        {{
                            "key":"report",
                            "sig":{{"ret":{{"class":"void"}},"params":[{{"class":"integer"}}],"vararg":true}},
                            "param_names":["%fmt"],
                            "body":[
                                {{"kind":"alloca","dest":"%ap","ty":"va_list"}},
                                {{"kind":"unknown","op":"llvm.va_start","operands":["%ap"],"reason":"varargs_intrinsic"}},
                                {{"kind":"call_direct","callee":"helper","sig":{{"ret":{{"class":"void"}},"params":[{{"class":"integer"}},{{"class":"integer"}}]}},"args":["%fmt","%ap"]}},
                                {{"kind":"unknown","op":"llvm.va_end","operands":["%ap"],"reason":"varargs_intrinsic"}}
                            ]
                        }},
                        {{
                            "key":"helper",
                            "sig":{{"ret":{{"class":"void"}},"params":[{{"class":"integer"}},{{"class":"integer"}}]}},
                            "param_names":["%fmt","%ap"],
                            "body":[{helper_body}]
                        }}
                        {extra_functions}
                    ]
                }}"#
            ))
            .unwrap()
        };
        let direct_sink = r#"{"kind":"call_direct","callee":"vfprintf","sig":{"ret":{"class":"integer"},"params":[{"class":"integer"},{"class":"integer"},{"class":"integer"}]},"args":["%stream","%fmt","%ap"]}"#;
        let self_call = r#"{"kind":"call_direct","callee":"helper","sig":{"ret":{"class":"void"},"params":[{"class":"integer"},{"class":"integer"}]},"args":["%fmt","%ap"]}"#;

        // A naive in-progress=false lookup can ignore this back edge and accept the remaining
        // terminal.  The complete summary rejects the relevant recursive use instead.
        let self_recursive = make_pir(&format!("{direct_sink},{self_call}"), "");
        assert!(!VarargCallProof::new(&self_recursive).is_benign("report", &["@safe".to_string()]));

        let mutual_call = r#"{"kind":"call_direct","callee":"mutual","sig":{"ret":{"class":"void"},"params":[{"class":"integer"},{"class":"integer"}]},"args":["%fmt","%ap"]}"#;
        let mutual_function = format!(
            r#",{{
                "key":"mutual",
                "sig":{{"ret":{{"class":"void"}},"params":[{{"class":"integer"}},{{"class":"integer"}}]}},
                "param_names":["%fmt","%ap"],
                "body":[{direct_sink},{self_call}]
            }}"#
        );
        let mutually_recursive = make_pir(mutual_call, &mutual_function);
        assert!(
            !VarargCallProof::new(&mutually_recursive).is_benign("report", &["@safe".to_string()])
        );

        let irrelevant_call = r#"{"kind":"call_direct","callee":"helper","sig":{"ret":{"class":"void"},"params":[{"class":"integer"},{"class":"integer"}]},"args":["@constant-a","@constant-b"]}"#;
        let irrelevant_recursion = make_pir(&format!("{irrelevant_call},{direct_sink}"), "");
        assert!(
            VarargCallProof::new(&irrelevant_recursion).is_benign("report", &["@safe".to_string()])
        );
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
            0,
            "%n-capable formats are represented by conservative read/write effects"
        );
        for callsite in &fprintf_calls[1..] {
            assert!(!callsite.external_boundary);
            assert!(!pag.omega_seeds.iter().any(|seed| {
                matches!(
                    seed.kind,
                    OmegaSeedKind::ExternalCallBoundary | OmegaSeedKind::VarargCallBoundary
                ) && seed.target == SeedTarget::Callsite(callsite.id)
            }));
            assert!(pag.edges.iter().any(|edge| {
                edge.kind == EdgeKind::Store
                    && callsite.args[2..]
                        .iter()
                        .any(|argument| *argument == edge.dst)
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
    fn trusted_free_requires_an_external_standard_call_with_exactly_one_argument() {
        let pir: Pir = serde_json::from_str(
            r#"{
                "module":"free-summary",
                "functions":[
                    {"key":"main","sig":{"ret":{"class":"void"},"params":[]},"body":[
                        {"kind":"call_direct","callee":"free","sig":{"ret":{"class":"void"},"params":[{"class":"integer"}]},"args":["one"]},
                        {"kind":"call_direct","callee":"free","sig":{"ret":{"class":"void"},"params":[{"class":"integer"}]},"args":["one","two"]},
                        {"kind":"call_direct","callee":"free","sig":{"ret":{"class":"integer"},"params":[{"class":"integer"}]},"args":["one"],"dest":"result"}
                    ]},
                    {"key":"free","external":true,"sig":{"ret":{"class":"void"},"params":[{"class":"integer"}]},"body":[]}
                ]
            }"#,
        )
        .unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        let free_calls = pag
            .callsites
            .iter()
            .filter(|callsite| callsite.callee.as_deref() == Some("free"))
            .collect::<Vec<_>>();
        assert_eq!(free_calls.len(), 3);
        assert!(!free_calls[0].external_boundary);
        assert!(free_calls[1].external_boundary);
        assert!(free_calls[2].external_boundary);
        assert!(!pag.omega_seeds.iter().any(|seed| {
            seed.kind == OmegaSeedKind::ExternalCallBoundary
                && seed.target == SeedTarget::Callsite(free_calls[0].id)
        }));
        for callsite in &free_calls[1..] {
            assert!(pag.omega_seeds.iter().any(|seed| {
                seed.kind == OmegaSeedKind::ExternalCallBoundary
                    && seed.target == SeedTarget::Callsite(callsite.id)
            }));
        }

        let mut replacement = pir.clone();
        replacement.functions[1].external = false;
        let call = &free_calls[0];
        assert!(!trusted_free_call(
            &replacement,
            "free",
            &call.sig,
            call.args.len(),
            call.result.is_some()
        ));

        let mut unresolved = pir.clone();
        unresolved.functions.pop();
        let unresolved_pag = Pag::from_pir(&unresolved, &PagOpts::default());
        let unresolved_free = unresolved_pag
            .callsites
            .iter()
            .find(|callsite| callsite.callee.as_deref() == Some("free"))
            .unwrap();
        assert!(unresolved_free.external_boundary);
        assert!(unresolved_pag.omega_seeds.iter().any(|seed| {
            seed.kind == OmegaSeedKind::ExternalCallBoundary
                && seed.target == SeedTarget::Callsite(unresolved_free.id)
        }));
    }

    #[test]
    fn complete_output_contract_records_write_and_rejects_untrusted_shapes() {
        let pir: Pir = serde_json::from_str(
            r#"{
                "module":"external-output-contract",
                "globals":[{"key":"@out","mutable":true}],
                "functions":[
                    {"key":"main","sig":{"ret":{"class":"void"},"params":[]},"body":[
                        {"kind":"call_direct","callee":"gethostname","sig":{"ret":{"class":"integer"},"params":[{"class":"integer"},{"class":"integer"}]},"args":["@out","64"],"dest":"status"},
                        {"kind":"call_indirect","operand":"fp","sig":{"ret":{"class":"integer"},"params":[{"class":"integer"},{"class":"integer"}]},"args":["@out","64"],"dest":"indirect_status"}
                    ]},
                    {"key":"gethostname","external":true,"sig":{"ret":{"class":"integer"},"params":[{"class":"integer"},{"class":"integer"}]},"body":[]}
                ]
            }"#,
        )
        .unwrap();
        let direct = match &pir.functions[0].body[0] {
            Stmt::CallDirect {
                callee,
                sig,
                args,
                dest,
                ..
            } => proven_external_call_contract(&pir, callee, sig, args, dest.is_some()).unwrap(),
            _ => unreachable!(),
        };
        assert_eq!(direct.effects, &[ExternalArgEffect::Write(0)]);

        let pag = Pag::from_pir(&pir, &PagOpts::default());
        let callsite = &pag.callsites[0];
        assert!(!callsite.external_boundary);
        assert!(pag.edges.iter().any(|edge| {
            edge.kind == EdgeKind::Store
                && edge.dst == callsite.args[0]
                && edge.modeled_external_write
        }));
        assert!(!pag.omega_seeds.iter().any(|seed| {
            seed.kind == OmegaSeedKind::ExternalCallBoundary
                && seed.target == SeedTarget::Callsite(callsite.id)
        }));
        assert_eq!(pag.callsites[1].kind, CallKind::Indirect);

        let mut replacement = pir.clone();
        replacement.functions[1].external = false;
        let Stmt::CallDirect {
            callee,
            sig,
            args,
            dest,
            ..
        } = &replacement.functions[0].body[0]
        else {
            unreachable!()
        };
        assert!(
            proven_external_call_contract(&replacement, callee, sig, args, dest.is_some())
                .is_none()
        );

        let mut wrong_signature = pir.clone();
        let Stmt::CallDirect { sig, .. } = &mut wrong_signature.functions[0].body[0] else {
            unreachable!()
        };
        sig.ret = pangs_pir::AbiClass::Void;
        let Stmt::CallDirect {
            callee,
            sig,
            args,
            dest,
            ..
        } = &wrong_signature.functions[0].body[0]
        else {
            unreachable!()
        };
        assert!(
            proven_external_call_contract(&wrong_signature, callee, sig, args, dest.is_some())
                .is_none()
        );
    }

    #[test]
    fn realloc_contract_keeps_old_abstract_allocation_and_a_fresh_alternative() {
        let pir: Pir = serde_json::from_str(
            r#"{
                "module":"realloc-contract",
                "functions":[
                    {"key":"main","sig":{"ret":{"class":"void"},"params":[]},"body":[
                        {"kind":"call_direct","callee":"realloc","sig":{"ret":{"class":"integer"},"params":[{"class":"integer"},{"class":"integer"}]},"args":["%old","64"],"dest":"%new"}
                    ]},
                    {"key":"realloc","external":true,"sig":{"ret":{"class":"integer"},"params":[{"class":"integer"},{"class":"integer"}]},"body":[]}
                ]
            }"#,
        )
        .unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        let callsite = &pag.callsites[0];
        let result = callsite.result.unwrap();

        assert!(!callsite.external_boundary);
        assert!(pag.edges.iter().any(|edge| {
            edge.kind == EdgeKind::Assign && edge.src == callsite.args[0] && edge.dst == result
        }));
        assert!(pag.edges.iter().any(|edge| {
            edge.kind == EdgeKind::AddrOf
                && edge.dst == result
                && matches!(pag.nodes[edge.src.0 as usize].kind, NodeKind::Object { .. })
        }));
    }

    #[test]
    fn strdup_contract_reads_source_and_returns_fresh_storage() {
        let pir: Pir = serde_json::from_str(
            r#"{
                "module":"strdup-contract",
                "globals":[{"key":"@source","mutable":true}],
                "functions":[
                    {"key":"main","sig":{"ret":{"class":"void"},"params":[]},"body":[
                        {"kind":"call_direct","callee":"strdup","sig":{"ret":{"class":"integer"},"params":[{"class":"integer"}]},"args":["@source"],"dest":"%copy"}
                    ]},
                    {"key":"strdup","external":true,"sig":{"ret":{"class":"integer"},"params":[{"class":"integer"}]},"body":[]}
                ]
            }"#,
        )
        .unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        let callsite = &pag.callsites[0];
        let result = callsite.result.unwrap();

        assert!(!callsite.external_boundary);
        assert!(pag
            .edges
            .iter()
            .any(|edge| edge.kind == EdgeKind::Load && edge.src == callsite.args[0]));
        assert!(pag.edges.iter().any(|edge| {
            edge.kind == EdgeKind::AddrOf
                && edge.dst == result
                && matches!(
                    &pag.nodes[edge.src.0 as usize].kind,
                    NodeKind::Object {
                        object: ObjectKind::Alloca,
                        key,
                        ..
                    } if key == "strdup@0"
                )
        }));
        assert!(!pag.omega_seeds.iter().any(|seed| {
            seed.kind == OmegaSeedKind::ExternalCallBoundary
                && seed.target == SeedTarget::Callsite(callsite.id)
        }));
    }

    #[test]
    fn external_copy_contract_preserves_constant_extent_and_zero_is_a_noop() {
        let pir: Pir = serde_json::from_str(
            r#"{
                "module":"external-copy-contract",
                "functions":[
                    {"key":"main","sig":{"ret":{"class":"void"},"params":[]},"body":[
                        {"kind":"call_direct","callee":"memcpy","sig":{"ret":{"class":"integer"},"params":[{"class":"integer"},{"class":"integer"},{"class":"integer"}]},"args":["%dst","%src","i64 16"],"dest":"%r0"},
                        {"kind":"call_direct","callee":"memcpy","sig":{"ret":{"class":"integer"},"params":[{"class":"integer"},{"class":"integer"},{"class":"integer"}]},"args":["%dst","%src","%n"],"dest":"%r1"},
                        {"kind":"call_direct","callee":"memcpy","sig":{"ret":{"class":"integer"},"params":[{"class":"integer"},{"class":"integer"},{"class":"integer"}]},"args":["%dst","%src","0"],"dest":"%r2"}
                    ]},
                    {"key":"memcpy","external":true,"sig":{"ret":{"class":"integer"},"params":[{"class":"integer"},{"class":"integer"},{"class":"integer"}]},"body":[]}
                ]
            }"#,
        )
        .unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        let copies = pag
            .edges
            .iter()
            .filter_map(|edge| match edge.kind {
                EdgeKind::Memcpy { bytes } => Some(bytes),
                _ => None,
            })
            .collect::<Vec<_>>();

        assert_eq!(copies, vec![Some(16), None]);
        assert!(pag
            .callsites
            .iter()
            .all(|callsite| !callsite.external_boundary));
    }

    #[test]
    fn scanf_family_models_pointer_outputs_as_non_capturing_external_values() {
        let pir: Pir = serde_json::from_str(
            r#"{
                "module":"scanf-summary",
                "globals":[
                    {"key":"@out_a","initializer_ir":"i8 0"},
                    {"key":"@out_b","initializer_ir":"i32 0"}
                ],
                "functions":[
                    {"key":"main","exported":true,"sig":{"ret":{"class":"void"},"params":[]},"body":[
                        {"kind":"call_direct","callee":"sscanf","sig":{"ret":{"class":"integer"},"params":[{"class":"integer"},{"class":"integer"}],"vararg":true},"args":["%input","%dynamic_format","@out_a"]},
                        {"kind":"call_direct","callee":"__isoc99_scanf","sig":{"ret":{"class":"integer"},"params":[{"class":"integer"}],"vararg":true},"args":["%dynamic_format","@out_b"]}
                    ]},
                    {"key":"sscanf","external":true,"sig":{"ret":{"class":"integer"},"params":[{"class":"integer"},{"class":"integer"}],"vararg":true},"body":[]},
                    {"key":"__isoc99_scanf","external":true,"sig":{"ret":{"class":"integer"},"params":[{"class":"integer"}],"vararg":true},"body":[]}
                ]
            }"#,
        )
        .unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());

        assert_eq!(pag.callsites.len(), 2);
        for callsite in &pag.callsites {
            assert!(!callsite.external_boundary);
            assert!(!pag.omega_seeds.iter().any(|seed| {
                matches!(
                    seed.kind,
                    OmegaSeedKind::ExternalCallBoundary | OmegaSeedKind::VarargCallBoundary
                ) && seed.target == SeedTarget::Callsite(callsite.id)
            }));
            let destination = *callsite.args.last().unwrap();
            let write = pag.edges.iter().find(|edge| {
                edge.kind == EdgeKind::Store
                    && edge.dst == destination
                    && edge.modeled_external_write
                    && edge.access_extent_unknown
            });
            let write = write.expect("scanf destination write");
            assert_eq!(
                pag.nodes[write.src.0 as usize].value_kind,
                ValueKind::Pointer
            );
            assert!(pag.omega_seeds.iter().any(|seed| {
                seed.kind == OmegaSeedKind::UnknownResultExternal
                    && seed.target == SeedTarget::Node(write.src)
            }));
        }
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

    #[test]
    fn assume_tags_keeps_ptrtoint_and_pointer_origin_vetoes_but_relaxes_unknown_tags() {
        let pir: Pir = serde_json::from_str(
            r#"{
                "module":"assume-tags",
                "target":{"triple":"x86_64","data_layout":"e-p:64:64","supported_atomic_widths":[8,16,32,64]},
                "globals":[{"key":"g","mutable":true}],
                "functions":[{"key":"main","sig":{"ret":{"class":"void"},"params":[]},"body":[
                    {"kind":"ptr_to_int","dest":"bits","source":"g","integer_bits":64,"pointer_bits":64,"pointer_address_space":0},
                    {"kind":"scalar_op","dest":"tagged","op":"xor","lhs":"bits","rhs":"1"},
                    {"kind":"int_to_ptr","dest":"reconstructed","source":"tagged","integer_bits":64,"pointer_bits":64,"pointer_address_space":0},
                    {"kind":"int_to_ptr","dest":"tag","source":"unknown_integer","integer_bits":64,"pointer_bits":64,"pointer_address_space":0}
                ]}]
            }"#,
        )
        .unwrap();

        let conservative = Pag::from_pir(&pir, &PagOpts::default());
        assert!(conservative
            .omega_seeds
            .iter()
            .any(|seed| seed.kind == OmegaSeedKind::PtrToInt));
        assert!(conservative
            .omega_seeds
            .iter()
            .any(|seed| seed.kind == OmegaSeedKind::IntToPtr));

        let assumed = Pag::from_pir(
            &pir,
            &PagOpts {
                integer_pointer_policy: IntegerPointerPolicy::AssumeTags,
                ..PagOpts::default()
            },
        );
        assert!(assumed
            .omega_seeds
            .iter()
            .any(|seed| seed.kind == OmegaSeedKind::PtrToInt));
        let reconstructed = assumed
            .nodes
            .iter()
            .find(|node| node.label == "val:main:reconstructed")
            .expect("reconstructed destination node");
        assert!(assumed.omega_seeds.iter().any(|seed| {
            seed.kind == OmegaSeedKind::IntToPtr
                && seed.target == SeedTarget::Node(reconstructed.id)
        }));
        assert_eq!(assumed.pointer_integer_origins.len(), 1);
        let tag = assumed
            .nodes
            .iter()
            .find(|node| node.label == "val:main:tag")
            .expect("tag destination node");
        assert!(tag.has_empty_witness);
        assert_eq!(assumed.metrics.assumed_integer_pointer_tags, 1);
        assert_eq!(
            allocation_storage_roots(&pir, &assumed).states[tag.id.0 as usize],
            StorageRootState::ProvenEmpty
        );
    }

    #[test]
    fn assume_tags_vetoes_local_address_use_and_audits_nonlocal_boundaries() {
        let pir: Pir = serde_json::from_str(
            r#"{
                "module":"assume-tags-uses",
                "target":{"triple":"x86_64","data_layout":"e-p:64:64","supported_atomic_widths":[8,16,32,64]},
                "functions":[
                    {"key":"main","sig":{"ret":{"class":"integer"},"params":[]},"body":[
                        {"kind":"int_to_ptr","dest":"address","source":"address_bits","integer_bits":64,"pointer_bits":64,"pointer_address_space":0},
                        {"kind":"assign","dest":"address_copy","sources":["address"]},
                        {"kind":"load","dest":"loaded","address":"address_copy"},
                        {"kind":"int_to_ptr","dest":"callee","source":"callee_bits","integer_bits":64,"pointer_bits":64,"pointer_address_space":0},
                        {"kind":"call_indirect","operand":"callee","sig":{"ret":{"class":"void"},"params":[]},"args":[]},
                        {"kind":"int_to_ptr","dest":"asm_address","source":"asm_bits","integer_bits":64,"pointer_bits":64,"pointer_address_space":0},
                        {"kind":"unknown","op":"call","operands":["asm_address"],"reason":"inline_asm"},
                        {"kind":"int_to_ptr","dest":"stored","source":"stored_tag","integer_bits":64,"pointer_bits":64,"pointer_address_space":0},
                        {"kind":"store","address":"slot","value":"stored"},
                        {"kind":"int_to_ptr","dest":"called","source":"called_tag","integer_bits":64,"pointer_bits":64,"pointer_address_space":0},
                        {"kind":"call_direct","callee":"sink","sig":{"ret":{"class":"void"},"params":[{"class":"integer"}]},"args":["called"]},
                        {"kind":"int_to_ptr","dest":"returned","source":"returned_tag","integer_bits":64,"pointer_bits":64,"pointer_address_space":0},
                        {"kind":"return","value":"returned"}
                    ]},
                    {"key":"sink","sig":{"ret":{"class":"void"},"params":[{"class":"integer"}]},"body":[]}
                ]
            }"#,
        )
        .unwrap();
        let pag = Pag::from_pir(
            &pir,
            &PagOpts {
                integer_pointer_policy: IntegerPointerPolicy::AssumeTags,
                ..PagOpts::default()
            },
        );
        let node = |dest: &str| {
            pag.nodes
                .iter()
                .find(|node| node.label == format!("val:main:{dest}"))
                .unwrap_or_else(|| panic!("missing {dest}"))
        };

        for dest in ["address", "callee", "asm_address"] {
            let address = node(dest);
            assert!(!address.has_empty_witness, "{dest}");
            assert!(
                pag.omega_seeds.iter().any(|seed| {
                    seed.kind == OmegaSeedKind::IntToPtr
                        && seed.target == SeedTarget::Node(address.id)
                }),
                "{dest}"
            );
        }
        for dest in ["stored", "called", "returned"] {
            assert!(node(dest).has_empty_witness, "{dest}");
        }
        assert_eq!(pag.metrics.assumed_integer_pointer_tags, 3);
        assert_eq!(pag.metrics.assumed_tag_crosses_memory, 1);
        assert_eq!(pag.metrics.assumed_tag_crosses_call, 1);
        assert_eq!(pag.metrics.assumed_tag_returned, 1);
    }

    #[test]
    fn lossless_integral_pointer_round_trip_is_an_assignment_not_omega() {
        let pir: Pir = serde_json::from_str(
            r#"{
                "module":"pointer-round-trip",
                "target":{"triple":"x86_64","data_layout":"e-p:64:64","supported_atomic_widths":[8,16,32,64]},
                "globals":[{"key":"g","mutable":true}],
                "functions":[{"key":"main","sig":{"ret":{"class":"void"},"params":[]},"body":[
                    {"kind":"assign","dest":"p","sources":["g"]},
                    {"kind":"ptr_to_int","dest":"i","source":"p","integer_bits":64,"pointer_bits":64,"pointer_address_space":0},
                    {"kind":"int_to_ptr","dest":"q","source":"i","integer_bits":64,"pointer_bits":64,"pointer_address_space":0}
                ]}]
            }"#,
        )
        .unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());

        assert!(!pag
            .omega_seeds
            .iter()
            .any(|seed| matches!(seed.kind, OmegaSeedKind::PtrToInt | OmegaSeedKind::IntToPtr)));
        let p = pag
            .nodes
            .iter()
            .find(|node| node.label == "val:main:p")
            .unwrap()
            .id;
        let q = pag
            .nodes
            .iter()
            .find(|node| node.label == "val:main:q")
            .unwrap()
            .id;
        assert!(pag
            .edges
            .iter()
            .any(|edge| { edge.kind == EdgeKind::Assign && edge.src == p && edge.dst == q }));
    }

    #[test]
    fn reserved_inttoptr_literals_are_certified_empty_without_omega() {
        let pir: Pir = serde_json::from_str(
            r#"{
                "module":"reserved-addresses",
                "target":{"triple":"x86_64","data_layout":"e-p:64:64-p1:64:64","supported_atomic_widths":[8,16,32,64]},
                "functions":[{"key":"main","sig":{"ret":{"class":"void"},"params":[]},"body":[
                    {"kind":"int_to_ptr","dest":"minus-one","source":"-1","integer_bits":64,"pointer_bits":64,"pointer_address_space":0},
                    {"kind":"int_to_ptr","dest":"zero","source":"0","integer_bits":64,"pointer_bits":64,"pointer_address_space":0},
                    {"kind":"int_to_ptr","dest":"eight","source":"8","integer_bits":64,"pointer_bits":64,"pointer_address_space":0},
                    {"kind":"int_to_ptr","dest":"last-low","source":"4095","integer_bits":64,"pointer_bits":64,"pointer_address_space":0},
                    {"kind":"int_to_ptr","dest":"unsigned-all-ones","source":"18446744073709551615","integer_bits":64,"pointer_bits":64,"pointer_address_space":0},
                    {"kind":"int_to_ptr","dest":"first-high","source":"4096","integer_bits":64,"pointer_bits":64,"pointer_address_space":0},
                    {"kind":"int_to_ptr","dest":"minus-two","source":"-2","integer_bits":64,"pointer_bits":64,"pointer_address_space":0},
                    {"kind":"int_to_ptr","dest":"last-low-negative","source":"-4095","integer_bits":64,"pointer_bits":64,"pointer_address_space":0},
                    {"kind":"int_to_ptr","dest":"first-high-negative","source":"-4096","integer_bits":64,"pointer_bits":64,"pointer_address_space":0},
                    {"kind":"int_to_ptr","dest":"unsigned-minus-two","source":"18446744073709551614","integer_bits":64,"pointer_bits":64,"pointer_address_space":0},
                    {"kind":"int_to_ptr","dest":"unsigned-last-low-negative","source":"18446744073709547521","integer_bits":64,"pointer_bits":64,"pointer_address_space":0},
                    {"kind":"int_to_ptr","dest":"unsigned-first-high-negative","source":"18446744073709547520","integer_bits":64,"pointer_bits":64,"pointer_address_space":0},
                    {"kind":"int_to_ptr","dest":"width-mismatch","source":"8","integer_bits":32,"pointer_bits":64,"pointer_address_space":0},
                    {"kind":"int_to_ptr","dest":"other-space","source":"8","integer_bits":64,"pointer_bits":64,"pointer_address_space":1}
                ]}]
            }"#,
        )
        .unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        let roots = allocation_storage_roots(&pir, &pag);
        let node = |dest: &str| {
            pag.nodes
                .iter()
                .find(|node| node.label == format!("val:main:{dest}"))
                .unwrap_or_else(|| panic!("missing {dest}"))
        };

        for dest in [
            "minus-one",
            "zero",
            "eight",
            "last-low",
            "unsigned-all-ones",
            "minus-two",
            "last-low-negative",
            "unsigned-minus-two",
            "unsigned-last-low-negative",
        ] {
            let node = node(dest);
            assert!(node.has_empty_witness, "{dest}");
            assert_eq!(
                roots.states[node.id.0 as usize],
                StorageRootState::ProvenEmpty,
                "{dest}"
            );
            assert!(!pag.omega_seeds.iter().any(|seed| {
                seed.kind == OmegaSeedKind::IntToPtr && seed.target == SeedTarget::Node(node.id)
            }));
        }
        for dest in [
            "first-high",
            "first-high-negative",
            "unsigned-first-high-negative",
            "width-mismatch",
            "other-space",
        ] {
            let node = node(dest);
            assert!(!node.has_empty_witness, "{dest}");
            assert!(pag.omega_seeds.iter().any(|seed| {
                seed.kind == OmegaSeedKind::IntToPtr && seed.target == SeedTarget::Node(node.id)
            }));
        }

        for (name, target) in [
            ("missing-target", "null"),
            (
                "non-integral-default",
                r#"{"triple":"test","data_layout":"e-p:64:64-ni:0","supported_atomic_widths":[]}"#,
            ),
        ] {
            let json = format!(
                r#"{{
                    "module":"{name}",
                    "target":{target},
                    "functions":[{{"key":"main","sig":{{"ret":{{"class":"void"}},"params":[]}},"body":[
                        {{"kind":"int_to_ptr","dest":"sentinel","source":"-1","integer_bits":64,"pointer_bits":64,"pointer_address_space":0}}
                    ]}}]
                }}"#
            );
            let pir: Pir = serde_json::from_str(&json).unwrap();
            let pag = Pag::from_pir(&pir, &PagOpts::default());
            assert!(
                pag.omega_seeds
                    .iter()
                    .any(|seed| seed.kind == OmegaSeedKind::IntToPtr),
                "{name}"
            );
        }
    }

    #[test]
    fn integer_transforms_preserve_allocation_origin_without_becoming_assignments() {
        let pir: Pir = serde_json::from_str(
            r#"{
                "module":"pointer-tag",
                "target":{"triple":"x86_64","data_layout":"e-p:64:64","supported_atomic_widths":[8,16,32,64]},
                "globals":[{"key":"g","mutable":true}],
                "functions":[{"key":"main","sig":{"ret":{"class":"void"},"params":[]},"body":[
                    {"kind":"ptr_to_int","dest":"bits","source":"g","integer_bits":64,"pointer_bits":64,"pointer_address_space":0},
                    {"kind":"scalar_op","dest":"tagged","op":"xor","lhs":"bits","rhs":"1"},
                    {"kind":"int_to_ptr","dest":"q","source":"tagged","integer_bits":64,"pointer_bits":64,"pointer_address_space":0}
                ]}]
            }"#,
        )
        .unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        let node = |label: &str| {
            pag.nodes
                .iter()
                .find(|node| node.label == label)
                .unwrap_or_else(|| panic!("missing PAG node {label}"))
                .id
        };
        let source = node("sym:global:g");
        let destination = node("val:main:q");

        assert_eq!(
            pag.pointer_integer_origins,
            [PointerIntegerOrigin {
                destination,
                sources: vec![source],
                complete: true,
                owner: Owner::Function("main".into()),
            }]
        );
        assert!(pag
            .omega_seeds
            .iter()
            .any(|seed| seed.kind == OmegaSeedKind::PtrToInt));
        assert!(pag
            .omega_seeds
            .iter()
            .any(|seed| seed.kind == OmegaSeedKind::IntToPtr));
        assert!(!pag.edges.iter().any(|edge| {
            edge.kind == EdgeKind::Assign && edge.src == source && edge.dst == destination
        }));

        assert!(matches!(
            &allocation_storage_roots(&pir, &pag).states[destination.0 as usize],
            StorageRootState::Root(StorageRoot::Global { canonical_key, .. }) if canonical_key == "g"
        ));
    }

    #[test]
    fn pointer_round_trip_proof_fails_closed_on_unsafe_variants() {
        for (name, data_layout, ptr_bits, destination_space, extra) in [
            ("width", "e-p:64:64", 32, 0, ""),
            ("address-space", "e-p:64:64-p1:64:64", 64, 1, ""),
            ("non-integral", "e-p:64:64-ni:0", 64, 0, ""),
            (
                "integer-storage",
                "e-p:64:64",
                64,
                0,
                r#",{"kind":"store","address":"slot","value":"i"}"#,
            ),
            (
                "integer-arithmetic",
                "e-p:64:64",
                64,
                0,
                r#",{"kind":"scalar_op","dest":"changed","op":"add","lhs":"i","rhs":"1"}"#,
            ),
        ] {
            let json = format!(
                r#"{{
                    "module":"{name}",
                    "target":{{"triple":"test","data_layout":"{data_layout}","supported_atomic_widths":[]}},
                    "functions":[{{"key":"main","sig":{{"ret":{{"class":"void"}},"params":[]}},"body":[
                        {{"kind":"ptr_to_int","dest":"i","source":"p","integer_bits":64,"pointer_bits":64,"pointer_address_space":0}},
                        {{"kind":"int_to_ptr","dest":"q","source":"i","integer_bits":64,"pointer_bits":{ptr_bits},"pointer_address_space":{destination_space}}}{extra}
                    ]}}]
                }}"#
            );
            let pir: Pir = serde_json::from_str(&json).unwrap();
            let pag = Pag::from_pir(&pir, &PagOpts::default());
            assert!(
                pag.omega_seeds
                    .iter()
                    .any(|seed| seed.kind == OmegaSeedKind::PtrToInt),
                "{name}"
            );
            assert!(
                pag.omega_seeds
                    .iter()
                    .any(|seed| seed.kind == OmegaSeedKind::IntToPtr),
                "{name}"
            );
        }
    }

    #[test]
    fn storage_roots_preserve_gep_and_same_root_or_canonical_null_join() {
        let mut pir: Pir = serde_json::from_str(
            r#"{
                "module":"storage-roots",
                "globals":[{"key":"g","mutable":true}],
                "functions":[{"key":"f","sig":{"ret":{"class":"void"},"params":[]},"body":[
                    {"kind":"gep","dest":"elt","base":"@g"},
                    {"kind":"assign","dest":"maybe","sources":["elt","null"]},
                    {"kind":"assign","dest":"both-null","sources":["null","null"]},
                    {"kind":"gep","dest":"bad-null-gep","base":"null","byte_off":8}
                ]}]
            }"#,
        )
        .unwrap();
        pir.lowering
            .semantic_value_kinds
            .insert("null".into(), ValueKind::Pointer);
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        let roots = allocation_storage_roots(&pir, &pag);
        let state = |label: &str| {
            let id = pag
                .nodes
                .iter()
                .find(|node| node.label == label)
                .unwrap()
                .id;
            &roots.states[id.0 as usize]
        };
        assert!(matches!(
            state("val:f:elt"),
            StorageRootState::Root(StorageRoot::Global { .. })
        ));
        assert_eq!(state("val:f:maybe"), state("val:f:elt"));
        assert_eq!(state("val:f:null"), &StorageRootState::ProvenEmpty);
        assert_eq!(state("val:f:both-null"), &StorageRootState::ProvenEmpty);
        assert_eq!(state("val:f:bad-null-gep"), &StorageRootState::Unknown);
    }

    #[test]
    fn storage_roots_fail_closed_when_addr_of_has_an_additional_producer() {
        let pir: Pir = serde_json::from_str(
            r#"{"module":"multi-producer","globals":[{"key":"g","mutable":true}],
                "functions":[{"key":"f","sig":{"ret":{"class":"void"},"params":[]},"body":[]}]}"#,
        )
        .unwrap();
        let mut pag = Pag::from_pir(&pir, &PagOpts::default());
        let symbol = pag
            .nodes
            .iter()
            .find(|node| node.label == "sym:global:g")
            .map(|node| node.id)
            .unwrap_or_else(|| {
                // Force creation of the otherwise-unused symbol through a temporary build.
                let mut with_use = pir.clone();
                with_use.functions[0].body.push(Stmt::Load {
                    dest: "x".into(),
                    address: "g".into(),
                    volatile: false,
                    access_bytes: None,
                    loc: None,
                });
                pag = Pag::from_pir(&with_use, &PagOpts::default());
                pag.nodes
                    .iter()
                    .find(|node| node.label == "sym:global:g")
                    .unwrap()
                    .id
            });
        let unknown = pag
            .nodes
            .iter()
            .find(|node| node.label == "val:f:x")
            .map(|node| node.id)
            .unwrap();
        let object = pag
            .nodes
            .iter()
            .find(|node| node.label == "obj:global:g")
            .unwrap()
            .id;
        for (name, kind, src) in [
            ("assign", EdgeKind::Assign, unknown),
            ("load", EdgeKind::Load, unknown),
            ("duplicate-addr-of", EdgeKind::AddrOf, object),
        ] {
            let mut malformed = pag.clone();
            malformed.edges.push(Edge {
                id: EdgeId(malformed.edges.len() as u32),
                kind,
                src,
                dst: symbol,
                owner: Owner::Function("f".into()),
                access_bytes: None,
                access_extent_unknown: false,
                volatile: false,
                modeled_external_write: false,
                loc: None,
            });
            let roots = allocation_storage_roots(&pir, &malformed);
            assert_eq!(
                roots.states[symbol.0 as usize],
                StorageRootState::Unknown,
                "{name}"
            );
            assert_eq!(roots.force_exposed_globals, BTreeSet::from([0]), "{name}");
        }
    }
}
