use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use pangs_pag::{
    CallKind, CallsiteId, EdgeKind, NodeId, NodeKind, ObjectKind, OmegaSeedKind, Pag, SeedTarget,
};
use pangs_pir::{fsa_compatible, Signature};

const QUERY_STATE_BUDGET: usize = 25_000;

/// M3.1 field-insensitive CFL query kernel for callees.
///
/// This first cut intentionally has no byte-offset memory-history stack and no call-graph
/// fixpoint. It answers one source-function query at a time: "which indirect-call operands
/// can this function object's address reach through value flow and Store/Load alias
/// expansion?" GEPs and memcpy are treated as assignment-like edges.
pub fn query_callees_field_insensitive(pag: &Pag, function: &str) -> CflCalleeQuery {
    let graph = QueryGraph::new(pag);
    graph.query_function(function)
}

/// M3.2 byte-offset-sensitive callee query kernel.
///
/// This adds the memory-history stack (MHS) from the M3 plan: Store pushes a fresh
/// zero-offset memory level, GEP adjusts the active level, and Load may close a memory
/// level only when the active offset is zero (or ⊤, which is soundly imprecise).
pub fn query_callees_field_sensitive(pag: &Pag, function: &str) -> CflCalleeQuery {
    let graph = QueryGraph::new(pag);
    graph.query_function_mhs(function)
}

/// Run one M3.1 query per function object and invert the source-oriented answers into
/// callsite -> target function names.
pub fn query_all_callees_field_insensitive(pag: &Pag) -> BTreeMap<String, BTreeSet<String>> {
    query_all_callees_field_insensitive_report(pag).by_callsite
}

/// Run all M3.1 callee queries and retain per-query traversal metrics.
pub fn query_all_callees_field_insensitive_report(pag: &Pag) -> CflCalleeReport {
    query_all_callees_field_insensitive_report_inner(pag, None)
}

/// Run all M3.1 callee queries with ABI/FSA-compatible sink filtering.
pub fn query_all_callees_field_insensitive_report_with_signatures(
    pag: &Pag,
    signatures: &BTreeMap<String, Signature>,
) -> CflCalleeReport {
    query_all_callees_field_insensitive_report_inner(pag, Some(signatures))
}

fn query_all_callees_field_insensitive_report_inner(
    pag: &Pag,
    signatures: Option<&BTreeMap<String, Signature>>,
) -> CflCalleeReport {
    let graph = QueryGraph::with_signatures(pag, signatures);
    let mut by_callsite: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut queries = Vec::new();
    for key in callee_query_function_keys(pag) {
        let answer = graph.query_function(key);
        for callsite in &answer.callsites {
            by_callsite
                .entry(callsite.clone())
                .or_default()
                .insert(key.to_string());
        }
        queries.push(answer);
    }
    CflCalleeReport {
        by_callsite,
        queries,
    }
}

/// Run one M3.2 MHS query per function object and invert the source-oriented answers into
/// callsite -> target function names.
pub fn query_all_callees_field_sensitive(pag: &Pag) -> BTreeMap<String, BTreeSet<String>> {
    query_all_callees_field_sensitive_report(pag).by_callsite
}

/// Run all M3.2 MHS callee queries and retain per-query traversal metrics.
pub fn query_all_callees_field_sensitive_report(pag: &Pag) -> CflCalleeReport {
    query_all_callees_field_sensitive_report_inner(pag, None)
}

/// Run all M3.2 MHS callee queries with ABI/FSA-compatible sink filtering.
pub fn query_all_callees_field_sensitive_report_with_signatures(
    pag: &Pag,
    signatures: &BTreeMap<String, Signature>,
) -> CflCalleeReport {
    query_all_callees_field_sensitive_report_inner(pag, Some(signatures))
}

fn query_all_callees_field_sensitive_report_inner(
    pag: &Pag,
    signatures: Option<&BTreeMap<String, Signature>>,
) -> CflCalleeReport {
    let graph = QueryGraph::with_signatures(pag, signatures);
    let mut by_callsite: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut queries = Vec::new();
    for key in callee_query_function_keys(pag) {
        let answer = graph.query_function_mhs(key);
        for callsite in &answer.callsites {
            by_callsite
                .entry(callsite.clone())
                .or_default()
                .insert(key.to_string());
        }
        queries.push(answer);
    }
    CflCalleeReport {
        by_callsite,
        queries,
    }
}

/// Run M3.3 dependency-tracked MHS callee queries to an interprocedural fixpoint.
///
/// Round 0 uses only the frozen PAG. When a round discovers that an indirect callsite may
/// target an internal function, the next round's query graph includes synthetic
/// Assign-shaped call bindings for that target: actual args flow to callee params, and
/// callee returns flow to the call result. Queries that touched the unresolved call's
/// arguments or the discovered callee's return node are scheduled for the next round.
pub fn query_all_callees_field_sensitive_fixpoint_report(pag: &Pag) -> CflFixpointReport {
    query_all_callees_field_sensitive_fixpoint_report_inner(pag, None)
}

/// Run M3.3 dependency-tracked MHS callee queries with ABI/FSA-compatible sink filtering.
pub fn query_all_callees_field_sensitive_fixpoint_report_with_signatures(
    pag: &Pag,
    signatures: &BTreeMap<String, Signature>,
) -> CflFixpointReport {
    query_all_callees_field_sensitive_fixpoint_report_inner(pag, Some(signatures))
}

fn query_all_callees_field_sensitive_fixpoint_report_inner(
    pag: &Pag,
    signatures: Option<&BTreeMap<String, Signature>>,
) -> CflFixpointReport {
    let function_keys = callee_query_function_keys(pag)
        .into_iter()
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let mut pending: BTreeSet<String> = function_keys.iter().cloned().collect();
    let mut targets_by_site: BTreeMap<CallsiteId, BTreeSet<String>> = BTreeMap::new();
    let mut latest_queries: BTreeMap<String, CflCalleeQuery> = BTreeMap::new();
    let mut deps_by_callsite: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut deps_by_return_func: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut rounds = Vec::new();

    for round_index in 0..32 {
        if pending.is_empty() {
            break;
        }

        let graph = QueryGraph::with_indirect_call_targets_and_signatures(
            pag,
            &targets_by_site,
            signatures,
        );
        let current = std::mem::take(&mut pending);
        let mut newly_discovered = Vec::new();
        let mut new_targets = 0;
        let mut new_interproc_edges = 0;
        let mut dependency_records = 0;

        for function in &current {
            let answer = graph.query_function_mhs(function);
            dependency_records += answer.dependencies.len() + answer.return_dependencies.len();
            for dep in &answer.dependencies {
                deps_by_callsite
                    .entry(dep.clone())
                    .or_default()
                    .insert(function.clone());
            }
            for dep in &answer.return_dependencies {
                deps_by_return_func
                    .entry(dep.clone())
                    .or_default()
                    .insert(function.clone());
            }

            for callsite in &answer.callsites {
                let Some(&site_id) = graph.callsite_ids.get(callsite.as_str()) else {
                    continue;
                };
                let inserted = targets_by_site
                    .entry(site_id)
                    .or_default()
                    .insert(function.clone());
                if inserted {
                    new_targets += 1;
                    new_interproc_edges += graph.binding_edge_count(site_id, function);
                    newly_discovered.push((callsite.clone(), function.clone()));
                }
            }

            latest_queries.insert(function.clone(), answer);
        }

        let mut next_pending = BTreeSet::new();
        for (callsite, target) in &newly_discovered {
            if let Some(dependents) = deps_by_callsite.get(callsite) {
                next_pending.extend(dependents.iter().cloned());
            }
            if let Some(dependents) = deps_by_return_func.get(target) {
                next_pending.extend(dependents.iter().cloned());
            }
        }

        rounds.push(CflFixpointRound {
            round: round_index,
            queries_run: current.len(),
            new_targets,
            new_interproc_edges,
            dependency_records,
        });

        if new_targets == 0 {
            break;
        }
        pending = next_pending;
    }

    let by_callsite = targets_by_site
        .iter()
        .filter_map(|(site_id, targets)| {
            let callsite = pag.callsites.get(site_id.0 as usize)?;
            Some((callsite.key.clone(), targets.clone()))
        })
        .collect();
    let queries = function_keys
        .into_iter()
        .filter_map(|function| latest_queries.remove(&function))
        .collect();

    CflFixpointReport {
        by_callsite,
        queries,
        rounds,
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CflCalleeQuery {
    pub function: String,
    pub source: Option<NodeId>,
    pub callsites: BTreeSet<String>,
    pub dependencies: BTreeSet<String>,
    pub return_dependencies: BTreeSet<String>,
    pub metrics: CflQueryMetrics,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CflQueryMetrics {
    pub visited_states: usize,
    pub max_worklist: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CflCalleeReport {
    pub by_callsite: BTreeMap<String, BTreeSet<String>>,
    pub queries: Vec<CflCalleeQuery>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CflFixpointReport {
    pub by_callsite: BTreeMap<String, BTreeSet<String>>,
    pub queries: Vec<CflCalleeQuery>,
    pub rounds: Vec<CflFixpointRound>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CflCalleeFallbackReport {
    pub by_callsite: BTreeMap<String, BTreeSet<String>>,
    pub fallback_by_callsite: BTreeMap<String, BTreeSet<String>>,
    pub fallback_callsites: BTreeSet<String>,
    pub truncated_functions: BTreeSet<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CflFixpointRound {
    pub round: usize,
    pub queries_run: usize,
    pub new_targets: usize,
    pub new_interproc_edges: usize,
    pub dependency_records: usize,
}

impl CflCalleeReport {
    pub fn visit_histogram(&self) -> CflVisitHistogram {
        visit_histogram(&self.queries)
    }

    pub fn max_visited_states(&self) -> usize {
        max_visited_states(&self.queries)
    }

    pub fn truncated_queries(&self) -> usize {
        truncated_queries(&self.queries)
    }
}

impl CflFixpointReport {
    pub fn visit_histogram(&self) -> CflVisitHistogram {
        visit_histogram(&self.queries)
    }

    pub fn max_visited_states(&self) -> usize {
        max_visited_states(&self.queries)
    }

    pub fn truncated_queries(&self) -> usize {
        truncated_queries(&self.queries)
    }

    pub fn truncated_functions(&self) -> BTreeSet<String> {
        truncated_functions(&self.queries)
    }

    pub fn fallback_for_truncated_queries(
        &self,
        envelope_by_callsite: &BTreeMap<String, BTreeSet<String>>,
    ) -> CflCalleeFallbackReport {
        fallback_for_truncated_queries(&self.by_callsite, &self.queries, envelope_by_callsite)
    }
}

impl CflCalleeFallbackReport {
    pub fn fallback_callsite_count(&self) -> usize {
        self.fallback_callsites.len()
    }

    pub fn fallback_target_count(&self) -> usize {
        self.fallback_by_callsite.values().map(BTreeSet::len).sum()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CflVisitHistogram {
    pub le_10: usize,
    pub le_100: usize,
    pub le_1000: usize,
    pub gt_1000: usize,
}

pub fn fallback_for_truncated_queries(
    by_callsite: &BTreeMap<String, BTreeSet<String>>,
    queries: &[CflCalleeQuery],
    envelope_by_callsite: &BTreeMap<String, BTreeSet<String>>,
) -> CflCalleeFallbackReport {
    let truncated_functions = truncated_functions(queries);
    let fallback_callsites = truncated_queries_touched_callsites(queries);
    let mut merged = by_callsite.clone();
    let mut fallback_by_callsite = BTreeMap::new();

    for callsite in &fallback_callsites {
        let Some(envelope_targets) = envelope_by_callsite.get(callsite) else {
            continue;
        };
        merged.insert(callsite.clone(), envelope_targets.clone());
        fallback_by_callsite.insert(callsite.clone(), envelope_targets.clone());
    }

    CflCalleeFallbackReport {
        by_callsite: merged,
        fallback_by_callsite,
        fallback_callsites,
        truncated_functions,
    }
}

struct QueryGraph<'a> {
    pag: &'a Pag,
    edges: Vec<QueryEdge>,
    forward: Vec<Vec<usize>>,
    reverse: Vec<Vec<usize>>,
    function_objects: HashMap<&'a str, NodeId>,
    external_functions: HashSet<&'a str>,
    params: HashMap<&'a str, BTreeMap<u32, NodeId>>,
    returns: HashMap<&'a str, NodeId>,
    callsite_ids: HashMap<&'a str, CallsiteId>,
    indirect_operands: HashMap<NodeId, Vec<CallsiteId>>,
    indirect_call_dependencies: HashMap<NodeId, Vec<CallsiteId>>,
    return_dependencies: HashMap<NodeId, &'a str>,
    function_signatures: Option<&'a BTreeMap<String, Signature>>,
}

impl<'a> QueryGraph<'a> {
    fn new(pag: &'a Pag) -> Self {
        Self::with_indirect_call_targets(pag, &BTreeMap::new())
    }

    fn with_signatures(
        pag: &'a Pag,
        function_signatures: Option<&'a BTreeMap<String, Signature>>,
    ) -> Self {
        Self::with_indirect_call_targets_and_signatures(pag, &BTreeMap::new(), function_signatures)
    }

    fn with_indirect_call_targets(
        pag: &'a Pag,
        indirect_targets: &BTreeMap<CallsiteId, BTreeSet<String>>,
    ) -> Self {
        Self::with_indirect_call_targets_and_signatures(pag, indirect_targets, None)
    }

    fn with_indirect_call_targets_and_signatures(
        pag: &'a Pag,
        indirect_targets: &BTreeMap<CallsiteId, BTreeSet<String>>,
        function_signatures: Option<&'a BTreeMap<String, Signature>>,
    ) -> Self {
        let mut edges = pag
            .edges
            .iter()
            .map(|edge| QueryEdge {
                kind: edge.kind,
                src: edge.src,
                dst: edge.dst,
            })
            .collect::<Vec<_>>();

        let external_functions = external_function_keys(pag);
        let params = param_nodes(pag);
        let returns = return_nodes(pag);
        append_indirect_call_binding_edges(
            pag,
            indirect_targets,
            &external_functions,
            &params,
            &returns,
            function_signatures,
            &mut edges,
        );

        let mut forward = vec![Vec::new(); pag.nodes.len()];
        let mut reverse = vec![Vec::new(); pag.nodes.len()];
        for (index, edge) in edges.iter().enumerate() {
            forward[edge.src.0 as usize].push(index);
            reverse[edge.dst.0 as usize].push(index);
        }

        let function_objects = pag
            .nodes
            .iter()
            .filter_map(|node| match &node.kind {
                NodeKind::Object {
                    object: ObjectKind::Function,
                    key,
                    ..
                } => Some((key.as_str(), node.id)),
                _ => None,
            })
            .collect();

        let callsite_ids = pag
            .callsites
            .iter()
            .map(|callsite| (callsite.key.as_str(), callsite.id))
            .collect();

        let mut indirect_operands: HashMap<NodeId, Vec<CallsiteId>> = HashMap::new();
        let mut indirect_call_dependencies: HashMap<NodeId, Vec<CallsiteId>> = HashMap::new();
        for callsite in &pag.callsites {
            if callsite.kind == CallKind::Indirect {
                if let Some(operand) = callsite.operand {
                    indirect_operands
                        .entry(operand)
                        .or_default()
                        .push(callsite.id);
                }
                for node in callsite.args.iter().chain(callsite.result.iter()) {
                    indirect_call_dependencies
                        .entry(*node)
                        .or_default()
                        .push(callsite.id);
                }
            }
        }

        let return_dependencies = pag
            .nodes
            .iter()
            .filter_map(|node| match &node.kind {
                NodeKind::Return { func } => Some((node.id, func.as_str())),
                _ => None,
            })
            .collect();

        Self {
            pag,
            edges,
            forward,
            reverse,
            function_objects,
            external_functions,
            params,
            returns,
            callsite_ids,
            indirect_operands,
            indirect_call_dependencies,
            return_dependencies,
            function_signatures,
        }
    }

    fn query_function(&self, function: &str) -> CflCalleeQuery {
        let Some(&source) = self.function_objects.get(function) else {
            return CflCalleeQuery {
                function: function.to_string(),
                ..CflCalleeQuery::default()
            };
        };

        let mut out = CflCalleeQuery {
            function: function.to_string(),
            source: Some(source),
            ..CflCalleeQuery::default()
        };
        let mut visited = HashSet::new();
        let mut worklist = VecDeque::from([(source, Phase::Forward)]);

        while let Some((node, phase)) = worklist.pop_back() {
            if !visited.insert((node, phase)) {
                continue;
            }
            out.metrics.visited_states = visited.len();
            out.metrics.max_worklist = out.metrics.max_worklist.max(worklist.len() + 1);
            if visited.len() >= QUERY_STATE_BUDGET || worklist.len() >= QUERY_STATE_BUDGET {
                out.metrics.truncated = true;
                break;
            }
            self.record_dependencies(node, &mut out);

            if phase == Phase::Forward {
                if let Some(sites) = self.indirect_operands.get(&node) {
                    for site in sites {
                        self.record_callsite_sink(function, *site, &mut out);
                    }
                }
            }

            match phase {
                Phase::Forward => self.step_forward(node, &mut worklist),
                Phase::Backward => self.step_backward(node, &mut worklist),
            }
        }

        out
    }

    fn query_function_mhs(&self, function: &str) -> CflCalleeQuery {
        let Some(&source) = self.function_objects.get(function) else {
            return CflCalleeQuery {
                function: function.to_string(),
                ..CflCalleeQuery::default()
            };
        };

        let mut out = CflCalleeQuery {
            function: function.to_string(),
            source: Some(source),
            ..CflCalleeQuery::default()
        };
        let mut visited = HashSet::new();
        let mut worklist = VecDeque::from([MhsState {
            node: source,
            phase: Phase::Forward,
            stack: Vec::new(),
        }]);

        while let Some(state) = worklist.pop_back() {
            if !visited.insert(state.visit_key()) {
                continue;
            }
            out.metrics.visited_states = visited.len();
            out.metrics.max_worklist = out.metrics.max_worklist.max(worklist.len() + 1);
            if visited.len() >= QUERY_STATE_BUDGET || worklist.len() >= QUERY_STATE_BUDGET {
                out.metrics.truncated = true;
                break;
            }
            self.record_dependencies(state.node, &mut out);

            if state.phase == Phase::Forward && state.stack.is_empty() {
                if let Some(sites) = self.indirect_operands.get(&state.node) {
                    for site in sites {
                        self.record_callsite_sink(function, *site, &mut out);
                    }
                }
            }

            match state.phase {
                Phase::Forward => self.step_forward_mhs(state, &mut worklist),
                Phase::Backward => self.step_backward_mhs(state, &mut worklist),
            }
        }

        out
    }

    fn step_forward(&self, node: NodeId, worklist: &mut VecDeque<(NodeId, Phase)>) {
        for &edge_index in &self.forward[node.0 as usize] {
            let edge = &self.edges[edge_index];
            match edge.kind {
                EdgeKind::AddrOf
                | EdgeKind::Assign
                | EdgeKind::Load
                | EdgeKind::Gep { .. }
                | EdgeKind::Memcpy { .. } => {
                    worklist.push_back((edge.dst, Phase::Forward));
                }
                EdgeKind::Store => {
                    worklist.push_back((edge.dst, Phase::Backward));
                }
            }
        }
    }

    fn step_backward(&self, node: NodeId, worklist: &mut VecDeque<(NodeId, Phase)>) {
        // I-Alias may choose this node as the midpoint, then continue forward.
        worklist.push_back((node, Phase::Forward));

        for &edge_index in &self.reverse[node.0 as usize] {
            let edge = &self.edges[edge_index];
            if backward_edge(edge) {
                worklist.push_back((edge.src, Phase::Backward));
            }
        }
    }

    fn step_forward_mhs(&self, state: MhsState, worklist: &mut VecDeque<MhsState>) {
        for &edge_index in &self.forward[state.node.0 as usize] {
            let edge = &self.edges[edge_index];
            match edge.kind {
                EdgeKind::AddrOf | EdgeKind::Assign | EdgeKind::Memcpy { .. } => {
                    worklist.push_back(state.clone().next(edge.dst, Phase::Forward));
                }
                EdgeKind::Gep { byte_off } => {
                    worklist.push_back(state.clone().adjust(
                        edge.dst,
                        Phase::Forward,
                        byte_off,
                        -1,
                    ));
                }
                EdgeKind::Store => {
                    worklist.push_back(state.clone().push(edge.dst, Phase::Backward));
                }
                EdgeKind::Load => {
                    if let Some(next) = state.clone().pop_if_zero(edge.dst, Phase::Forward) {
                        worklist.push_back(next);
                    }
                }
            }
        }
    }

    fn step_backward_mhs(&self, state: MhsState, worklist: &mut VecDeque<MhsState>) {
        // I-Alias may choose this node as the midpoint, then continue forward.
        worklist.push_back(state.clone().next(state.node, Phase::Forward));

        for &edge_index in &self.reverse[state.node.0 as usize] {
            let edge = &self.edges[edge_index];
            match edge.kind {
                EdgeKind::AddrOf | EdgeKind::Assign | EdgeKind::Memcpy { .. } => {
                    worklist.push_back(state.clone().next(edge.src, Phase::Backward));
                }
                EdgeKind::Gep { byte_off } => {
                    worklist.push_back(state.clone().adjust(
                        edge.src,
                        Phase::Backward,
                        byte_off,
                        1,
                    ));
                }
                EdgeKind::Load => {
                    worklist.push_back(state.clone().push(edge.src, Phase::Backward));
                }
                EdgeKind::Store => {
                    if let Some(next) = state.clone().pop_if_zero(edge.src, Phase::Backward) {
                        worklist.push_back(next);
                    }
                }
            }
        }
    }

    fn record_dependencies(&self, node: NodeId, out: &mut CflCalleeQuery) {
        if let Some(sites) = self.indirect_call_dependencies.get(&node) {
            for site in sites {
                out.dependencies
                    .insert(self.pag.callsites[site.0 as usize].key.clone());
            }
        }
        if let Some(func) = self.return_dependencies.get(&node) {
            out.return_dependencies.insert((*func).to_string());
        }
    }

    fn record_callsite_sink(
        &self,
        function: &str,
        callsite_id: CallsiteId,
        out: &mut CflCalleeQuery,
    ) {
        if !self.compatible_target(function, callsite_id) {
            return;
        }
        out.callsites
            .insert(self.pag.callsites[callsite_id.0 as usize].key.clone());
    }

    fn compatible_target(&self, function: &str, callsite: CallsiteId) -> bool {
        let Some(function_signatures) = self.function_signatures else {
            return true;
        };
        let Some(function_sig) = function_signatures.get(function) else {
            return true;
        };
        let Some(callsite) = self.pag.callsites.get(callsite.0 as usize) else {
            return true;
        };
        fsa_compatible(&callsite.sig, function_sig)
    }

    fn binding_edge_count(&self, callsite: CallsiteId, target: &str) -> usize {
        if self.external_functions.contains(target) {
            return 0;
        }
        if !self.compatible_target(target, callsite) {
            return 0;
        }
        let Some(callsite) = self.pag.callsites.get(callsite.0 as usize) else {
            return 0;
        };
        let arg_edges = self
            .params
            .get(target)
            .map(|params| callsite.args.len().min(params.len()))
            .unwrap_or(0);
        let ret_edges = usize::from(callsite.result.is_some() && self.returns.contains_key(target));
        arg_edges + ret_edges
    }
}

#[derive(Debug, Clone, Copy)]
struct QueryEdge {
    kind: EdgeKind,
    src: NodeId,
    dst: NodeId,
}

fn backward_edge(edge: &QueryEdge) -> bool {
    matches!(
        edge.kind,
        EdgeKind::AddrOf
            | EdgeKind::Assign
            | EdgeKind::Load
            | EdgeKind::Store
            | EdgeKind::Gep { .. }
            | EdgeKind::Memcpy { .. }
    )
}

fn function_object_keys(pag: &Pag) -> Vec<String> {
    pag.nodes
        .iter()
        .filter_map(|node| match &node.kind {
            NodeKind::Object {
                object: ObjectKind::Function,
                key,
                ..
            } => Some(key.clone()),
            _ => None,
        })
        .collect()
}

fn callee_query_function_keys(pag: &Pag) -> Vec<&str> {
    let address_materialized = pag
        .edges
        .iter()
        .filter_map(|edge| {
            if edge.kind != EdgeKind::AddrOf {
                return None;
            }
            let node = pag.nodes.get(edge.src.0 as usize)?;
            match &node.kind {
                NodeKind::Object {
                    object: ObjectKind::Function,
                    key,
                    ..
                } => Some(key.as_str()),
                _ => None,
            }
        })
        .collect::<BTreeSet<_>>();

    function_object_keys(pag)
        .into_iter()
        .filter_map(|key| address_materialized.get(key.as_str()).copied())
        .collect()
}

fn external_function_keys(pag: &Pag) -> HashSet<&str> {
    pag.omega_seeds
        .iter()
        .filter_map(|seed| {
            if seed.kind != OmegaSeedKind::ImportedSymbol {
                return None;
            }
            let SeedTarget::Node(node) = seed.target else {
                return None;
            };
            match &pag.nodes.get(node.0 as usize)?.kind {
                NodeKind::Object {
                    object: ObjectKind::Function,
                    key,
                    ..
                } => Some(key.as_str()),
                _ => None,
            }
        })
        .collect()
}

fn param_nodes(pag: &Pag) -> HashMap<&str, BTreeMap<u32, NodeId>> {
    let mut params: HashMap<&str, BTreeMap<u32, NodeId>> = HashMap::new();
    for node in &pag.nodes {
        if let NodeKind::Param { func, index } = &node.kind {
            params
                .entry(func.as_str())
                .or_default()
                .insert(*index, node.id);
        }
    }
    params
}

fn return_nodes(pag: &Pag) -> HashMap<&str, NodeId> {
    pag.nodes
        .iter()
        .filter_map(|node| match &node.kind {
            NodeKind::Return { func } => Some((func.as_str(), node.id)),
            _ => None,
        })
        .collect()
}

fn append_indirect_call_binding_edges(
    pag: &Pag,
    indirect_targets: &BTreeMap<CallsiteId, BTreeSet<String>>,
    external_functions: &HashSet<&str>,
    params: &HashMap<&str, BTreeMap<u32, NodeId>>,
    returns: &HashMap<&str, NodeId>,
    function_signatures: Option<&BTreeMap<String, Signature>>,
    edges: &mut Vec<QueryEdge>,
) {
    for (site_id, targets) in indirect_targets {
        let Some(callsite) = pag.callsites.get(site_id.0 as usize) else {
            continue;
        };
        if callsite.kind != CallKind::Indirect {
            continue;
        }
        for target in targets {
            if external_functions.contains(target.as_str()) {
                continue;
            }
            if !compatible_target(function_signatures, callsite, target) {
                continue;
            }
            if let Some(target_params) = params.get(target.as_str()) {
                for (arg, param) in callsite.args.iter().zip(target_params.values()) {
                    edges.push(QueryEdge {
                        kind: EdgeKind::Assign,
                        src: *arg,
                        dst: *param,
                    });
                }
            }
            if let (Some(result), Some(ret)) = (callsite.result, returns.get(target.as_str())) {
                edges.push(QueryEdge {
                    kind: EdgeKind::Assign,
                    src: *ret,
                    dst: result,
                });
            }
        }
    }
}

fn compatible_target(
    function_signatures: Option<&BTreeMap<String, Signature>>,
    callsite: &pangs_pag::Callsite,
    target: &str,
) -> bool {
    let Some(function_signatures) = function_signatures else {
        return true;
    };
    let Some(function_sig) = function_signatures.get(target) else {
        return true;
    };
    fsa_compatible(&callsite.sig, function_sig)
}

fn visit_histogram(queries: &[CflCalleeQuery]) -> CflVisitHistogram {
    let mut histogram = CflVisitHistogram::default();
    for query in queries {
        match query.metrics.visited_states {
            0..=10 => histogram.le_10 += 1,
            11..=100 => histogram.le_100 += 1,
            101..=1_000 => histogram.le_1000 += 1,
            _ => histogram.gt_1000 += 1,
        }
    }
    histogram
}

fn max_visited_states(queries: &[CflCalleeQuery]) -> usize {
    queries
        .iter()
        .map(|query| query.metrics.visited_states)
        .max()
        .unwrap_or(0)
}

fn truncated_queries(queries: &[CflCalleeQuery]) -> usize {
    queries
        .iter()
        .filter(|query| query.metrics.truncated)
        .count()
}

fn truncated_functions(queries: &[CflCalleeQuery]) -> BTreeSet<String> {
    queries
        .iter()
        .filter(|query| query.metrics.truncated)
        .map(|query| query.function.clone())
        .collect()
}

fn truncated_queries_touched_callsites(queries: &[CflCalleeQuery]) -> BTreeSet<String> {
    queries
        .iter()
        .filter(|query| query.metrics.truncated)
        .flat_map(|query| {
            query
                .callsites
                .iter()
                .chain(query.dependencies.iter())
                .cloned()
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Phase {
    Forward,
    Backward,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MhsState {
    node: NodeId,
    phase: Phase,
    stack: Vec<Offset>,
}

impl MhsState {
    fn visit_key(&self) -> MhsVisitState {
        MhsVisitState {
            node: self.node,
            phase: self.phase,
            top: self.stack.last().copied(),
        }
    }

    fn next(mut self, node: NodeId, phase: Phase) -> Self {
        self.node = node;
        self.phase = phase;
        self
    }

    fn push(mut self, node: NodeId, phase: Phase) -> Self {
        self.node = node;
        self.phase = phase;
        self.stack.push(Offset::Known(0));
        self
    }

    fn pop_if_zero(mut self, node: NodeId, phase: Phase) -> Option<Self> {
        match self.stack.last() {
            None => Some(self.next(node, phase)),
            Some(Offset::Known(0) | Offset::Top) => {
                self.stack.pop();
                Some(self.next(node, phase))
            }
            Some(Offset::Known(_)) => None,
        }
    }

    fn adjust(mut self, node: NodeId, phase: Phase, byte_off: Option<i64>, sign: i64) -> Self {
        self.node = node;
        self.phase = phase;
        let Some(top) = self.stack.last_mut() else {
            return self;
        };
        match (top, byte_off) {
            (slot @ Offset::Known(_), None) => *slot = Offset::Top,
            (Offset::Known(value), Some(off)) => {
                *value = value.saturating_add(sign.saturating_mul(off));
            }
            (Offset::Top, _) => {}
        }
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct MhsVisitState {
    node: NodeId,
    phase: Phase,
    top: Option<Offset>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Offset {
    Known(i64),
    Top,
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;

    use pangs_pag::{BuildMode, Pag, PagOpts};
    use pangs_pir::{Pir, Signature};

    use crate::solve_steensgaard;

    use super::{
        fallback_for_truncated_queries, query_all_callees_field_insensitive,
        query_all_callees_field_insensitive_report,
        query_all_callees_field_insensitive_report_with_signatures,
        query_all_callees_field_sensitive, query_all_callees_field_sensitive_fixpoint_report,
        query_all_callees_field_sensitive_fixpoint_report_with_signatures,
        query_all_callees_field_sensitive_report,
        query_all_callees_field_sensitive_report_with_signatures, query_callees_field_insensitive,
        query_callees_field_sensitive, CflCalleeQuery, CflQueryMetrics,
    };

    fn load(root: &str, name: &str) -> Pag {
        load_pir_pag(root, name).1
    }

    fn load_pir_pag(root: &str, name: &str) -> (Pir, Pag) {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/synthetic")
            .join(root)
            .join(name);
        let pir = Pir::from_path(path).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        (pir, pag)
    }

    fn steens_targets_by_callsite(pir: &Pir, pag: &Pag) -> BTreeMap<String, BTreeSet<String>> {
        solve_steensgaard(pir, pag, BuildMode::Library)
            .indirect_calls
            .into_iter()
            .map(|resolution| {
                (
                    resolution.callsite_key,
                    resolution.targets.into_iter().collect::<BTreeSet<_>>(),
                )
            })
            .collect()
    }

    fn function_signatures(pir: &Pir) -> BTreeMap<String, Signature> {
        pir.functions
            .iter()
            .map(|func| (func.key.clone(), func.sig.clone()))
            .collect()
    }

    #[test]
    fn m3_1_reaches_direct_assignment_icall_operand() {
        let pag = load("m2_2", "simple_local_assign.pir.json");

        let cb = query_callees_field_insensitive(&pag, "cb");
        assert_eq!(
            cb.callsites,
            ["driver@!noloc#0".to_string()].into_iter().collect()
        );
        assert!(cb.metrics.visited_states >= 3, "{:?}", cb.metrics);

        let other = query_callees_field_insensitive(&pag, "other");
        assert!(other.callsites.is_empty(), "{other:?}");
    }

    #[test]
    fn m3_1_reaches_store_load_icall_operand() {
        let pag = load("m1_4b", "local_fnptr_indirection.pir.json");

        let answer = query_callees_field_insensitive(&pag, "f");
        assert_eq!(
            answer.callsites,
            ["caller@!noloc#0".to_string()].into_iter().collect()
        );

        let mhs = query_callees_field_sensitive(&pag, "f");
        assert_eq!(mhs.callsites, answer.callsites);
    }

    #[test]
    fn m3_1_keeps_independent_global_function_pointer_sites_separate() {
        let pag = load("m1_4b", "two_global_fnptrs.pir.json");

        let by_callsite = query_all_callees_field_insensitive(&pag);
        assert_eq!(
            by_callsite["caller@fixtures/synthetic/m1_4b/two_global_fnptrs.c:7:5#0"],
            ["alpha".to_string()].into_iter().collect()
        );
        assert_eq!(
            by_callsite["caller@fixtures/synthetic/m1_4b/two_global_fnptrs.c:9:5#1"],
            ["beta".to_string()].into_iter().collect()
        );
    }

    #[test]
    fn m3_1_reaches_through_two_levels_of_memory() {
        let pag = load("m3_1", "two_level_memory.pir.json");

        let report = query_all_callees_field_insensitive_report(&pag);
        assert_eq!(
            report.by_callsite["driver@!noloc#0"],
            ["target".to_string()].into_iter().collect()
        );
        assert!(!report.by_callsite["driver@!noloc#0"].contains("other"));
        assert_eq!(report.queries.len(), 1);
        assert!(report.max_visited_states() >= 6);
        let histogram = report.visit_histogram();
        assert_eq!(
            histogram.le_10 + histogram.le_100 + histogram.le_1000 + histogram.gt_1000,
            report.queries.len()
        );
    }

    #[test]
    fn m3_1_is_field_insensitive_until_mhs_lands() {
        let pag = load("m1_4b", "field_sensitive_fnptr.pir.json");

        let by_callsite = query_all_callees_field_insensitive(&pag);
        assert_eq!(
            by_callsite["setup@!noloc#0"],
            ["f0".to_string(), "f1".to_string()].into_iter().collect()
        );
    }

    #[test]
    fn m3_2_mhs_distinguishes_struct_function_pointer_fields() {
        let pag = load("m1_4b", "field_sensitive_fnptr.pir.json");

        let by_callsite = query_all_callees_field_sensitive(&pag);
        assert_eq!(
            by_callsite["setup@!noloc#0"],
            ["f0".to_string()].into_iter().collect()
        );
    }

    #[test]
    fn m3_2_mhs_preserves_two_level_memory_aliasing() {
        let pag = load("m3_1", "two_level_memory.pir.json");

        let report = query_all_callees_field_sensitive_report(&pag);
        assert_eq!(
            report.by_callsite["driver@!noloc#0"],
            ["target".to_string()].into_iter().collect()
        );
        assert!(!report.by_callsite["driver@!noloc#0"].contains("other"));
        assert_eq!(report.queries.len(), 1);
        assert!(report.max_visited_states() >= 6);
    }

    #[test]
    fn m3_2_unknown_gep_offset_saturates_to_top() {
        let pag = load("m3_2", "unknown_offset_saturates.pir.json");

        let by_callsite = query_all_callees_field_sensitive(&pag);
        assert_eq!(
            by_callsite["driver@!noloc#0"],
            ["target".to_string()].into_iter().collect()
        );
    }

    #[test]
    fn m3_2_handles_container_of_style_negative_offsets() {
        let pag = load("m3_2", "negative_offset_container.pir.json");

        let by_callsite = query_all_callees_field_sensitive(&pag);
        assert_eq!(
            by_callsite["driver@!noloc#0"],
            ["target".to_string()].into_iter().collect()
        );
    }

    #[test]
    fn m3_2_zero_offset_gep_cast_preserves_match() {
        let pag = load("m3_2", "zero_offset_cast.pir.json");

        let by_callsite = query_all_callees_field_sensitive(&pag);
        assert_eq!(
            by_callsite["driver@!noloc#0"],
            ["target".to_string()].into_iter().collect()
        );
    }

    #[test]
    fn m3_2_mismatched_offsets_do_not_match() {
        let pag = load("m3_2", "mismatched_offsets_do_not_match.pir.json");

        let insensitive = query_all_callees_field_insensitive(&pag);
        assert_eq!(
            insensitive["driver@!noloc#0"],
            ["target".to_string()].into_iter().collect()
        );

        let sensitive = query_all_callees_field_sensitive(&pag);
        assert!(!sensitive.contains_key("driver@!noloc#0"));
    }

    #[test]
    fn m3_2_unknown_load_offset_saturates_to_top() {
        let pag = load("m3_2", "unknown_offset_load_saturates.pir.json");

        let by_callsite = query_all_callees_field_sensitive(&pag);
        assert_eq!(
            by_callsite["driver@!noloc#0"],
            ["target".to_string()].into_iter().collect()
        );
    }

    #[test]
    fn m3_2_nested_field_memory_keeps_stack_frames_separate() {
        let pag = load("m3_2", "nested_field_memory.pir.json");

        let by_callsite = query_all_callees_field_sensitive(&pag);
        assert_eq!(
            by_callsite["driver@!noloc#0"],
            ["target".to_string()].into_iter().collect()
        );
    }

    #[test]
    fn m3_3_fixpoint_discovers_argument_dependent_icall() {
        let pag = load("m3_3", "indirect_arg_fixpoint.pir.json");

        let round0 = query_all_callees_field_sensitive(&pag);
        assert_eq!(
            round0["driver@!noloc#0"],
            ["invoke".to_string()].into_iter().collect()
        );
        assert!(!round0.contains_key("invoke@!noloc#0"));

        let report = query_all_callees_field_sensitive_fixpoint_report(&pag);
        assert_eq!(
            report.by_callsite["driver@!noloc#0"],
            ["invoke".to_string()].into_iter().collect()
        );
        assert_eq!(
            report.by_callsite["invoke@!noloc#0"],
            ["target".to_string()].into_iter().collect()
        );
        assert_eq!(report.rounds.len(), 2, "{:?}", report.rounds);
        assert_eq!(report.rounds[0].new_targets, 1);
        assert_eq!(report.rounds[1].new_targets, 1);
        assert!(report.rounds[0].dependency_records > 0);
    }

    #[test]
    fn m3_3_fixpoint_discovers_return_dependent_icall() {
        let pag = load("m3_3", "indirect_return_fixpoint.pir.json");

        let round0 = query_all_callees_field_sensitive(&pag);
        assert_eq!(
            round0["driver@!noloc#0"],
            ["choose".to_string()].into_iter().collect()
        );
        assert!(!round0.contains_key("driver@!noloc#1"));

        let report = query_all_callees_field_sensitive_fixpoint_report(&pag);
        assert_eq!(
            report.by_callsite["driver@!noloc#0"],
            ["choose".to_string()].into_iter().collect()
        );
        assert_eq!(
            report.by_callsite["driver@!noloc#1"],
            ["target".to_string()].into_iter().collect()
        );
        assert_eq!(report.rounds.len(), 2, "{:?}", report.rounds);
        assert_eq!(report.rounds[0].new_targets, 1);
        assert_eq!(report.rounds[1].new_targets, 1);
        assert!(report.rounds[0].dependency_records > 0);
    }

    #[test]
    fn m3_3_signature_filter_rejects_incompatible_callee_sink() {
        let (pir, pag) = load_pir_pag("m3_3", "incompatible_signature_filter.pir.json");

        let raw = query_all_callees_field_sensitive(&pag);
        assert_eq!(
            raw["driver@!noloc#0"],
            ["bad".to_string()].into_iter().collect()
        );

        let signatures = function_signatures(&pir);
        let filtered = query_all_callees_field_sensitive_report_with_signatures(&pag, &signatures);
        assert!(!filtered.by_callsite.contains_key("driver@!noloc#0"));

        let fixpoint =
            query_all_callees_field_sensitive_fixpoint_report_with_signatures(&pag, &signatures);
        assert!(!fixpoint.by_callsite.contains_key("driver@!noloc#0"));
        assert_eq!(fixpoint.rounds.len(), 1);
        assert_eq!(fixpoint.rounds[0].new_targets, 0);
    }

    #[test]
    fn m3_3_untruncated_fallback_preserves_narrowing() {
        let by_callsite = BTreeMap::from([(
            "driver@!noloc#0".to_string(),
            ["precise".to_string(), "outside_envelope".to_string()]
                .into_iter()
                .collect(),
        )]);
        let envelope = BTreeMap::from([(
            "driver@!noloc#0".to_string(),
            ["precise".to_string(), "coarse".to_string()]
                .into_iter()
                .collect(),
        )]);
        let queries = vec![CflCalleeQuery {
            function: "precise".to_string(),
            callsites: ["driver@!noloc#0".to_string()].into_iter().collect(),
            metrics: CflQueryMetrics {
                visited_states: 12,
                ..CflQueryMetrics::default()
            },
            ..CflCalleeQuery::default()
        }];

        let fallback = fallback_for_truncated_queries(&by_callsite, &queries, &envelope);
        assert_eq!(fallback.by_callsite, by_callsite);
        assert!(fallback.fallback_by_callsite.is_empty());
        assert!(fallback.fallback_callsites.is_empty());
        assert!(fallback.truncated_functions.is_empty());
    }

    #[test]
    fn m3_3_truncated_touched_sites_fall_back_to_envelope() {
        let by_callsite = BTreeMap::from([(
            "driver@!noloc#0".to_string(),
            ["precise".to_string()].into_iter().collect(),
        )]);
        let envelope = BTreeMap::from([
            (
                "driver@!noloc#0".to_string(),
                ["precise".to_string(), "missed".to_string()]
                    .into_iter()
                    .collect(),
            ),
            (
                "invoke@!noloc#0".to_string(),
                ["nested".to_string()].into_iter().collect(),
            ),
            (
                "untouched@!noloc#0".to_string(),
                ["ignored".to_string()].into_iter().collect(),
            ),
        ]);
        let queries = vec![
            CflCalleeQuery {
                function: "precise".to_string(),
                callsites: ["driver@!noloc#0".to_string()].into_iter().collect(),
                dependencies: ["invoke@!noloc#0".to_string()].into_iter().collect(),
                metrics: CflQueryMetrics {
                    visited_states: 25_000,
                    truncated: true,
                    ..CflQueryMetrics::default()
                },
                ..CflCalleeQuery::default()
            },
            CflCalleeQuery {
                function: "ignored".to_string(),
                callsites: ["untouched@!noloc#0".to_string()].into_iter().collect(),
                ..CflCalleeQuery::default()
            },
        ];

        let fallback = fallback_for_truncated_queries(&by_callsite, &queries, &envelope);
        assert_eq!(
            fallback.by_callsite["driver@!noloc#0"],
            ["precise".to_string(), "missed".to_string()]
                .into_iter()
                .collect()
        );
        assert_eq!(
            fallback.by_callsite["invoke@!noloc#0"],
            ["nested".to_string()].into_iter().collect()
        );
        assert!(!fallback.by_callsite.contains_key("untouched@!noloc#0"));
        assert_eq!(fallback.fallback_callsite_count(), 2);
        assert_eq!(fallback.fallback_target_count(), 3);
        assert_eq!(
            fallback.truncated_functions,
            ["precise".to_string()].into_iter().collect()
        );
    }

    #[test]
    fn m3_1_answers_stay_inside_steensgaard_envelope_on_synthetic_suite() {
        let roots = [
            "m1_4", "m1_4b", "m1_5", "m2_2", "m2_3", "m2_4", "m3_1", "m3_2", "m3_3",
        ];
        let mut checked = 0;
        let mut sites_with_m3_answers = 0;
        let mut max_visited = 0;

        for root in roots {
            let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/synthetic")
                .join(root);
            if !dir.exists() {
                continue;
            }
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                    continue;
                }
                let pir = Pir::from_path(&path).unwrap();
                let pag = Pag::from_pir(&pir, &PagOpts::default());
                let steens = steens_targets_by_callsite(&pir, &pag);
                let signatures = function_signatures(&pir);
                let report =
                    query_all_callees_field_insensitive_report_with_signatures(&pag, &signatures);
                let mhs_report =
                    query_all_callees_field_sensitive_report_with_signatures(&pag, &signatures);
                let fixpoint_report =
                    query_all_callees_field_sensitive_fixpoint_report_with_signatures(
                        &pag,
                        &signatures,
                    );
                max_visited = max_visited.max(report.max_visited_states());

                for (callsite, targets) in &report.by_callsite {
                    let Some(envelope) = steens.get(callsite) else {
                        panic!(
                            "{}: M3.1 found {callsite}, absent from Steensgaard",
                            path.display()
                        );
                    };
                    for target in targets {
                        assert!(
                            envelope.contains(target),
                            "{}: M3.1 target {target} for {callsite} is outside Steensgaard envelope {envelope:?}",
                            path.display()
                        );
                    }
                    if !targets.is_empty() {
                        sites_with_m3_answers += 1;
                    }
                }
                for (callsite, targets) in &mhs_report.by_callsite {
                    let Some(envelope) = steens.get(callsite) else {
                        panic!(
                            "{}: M3.2 found {callsite}, absent from Steensgaard",
                            path.display()
                        );
                    };
                    for target in targets {
                        assert!(
                            envelope.contains(target),
                            "{}: M3.2 target {target} for {callsite} is outside Steensgaard envelope {envelope:?}",
                            path.display()
                        );
                    }
                }
                for (callsite, targets) in &fixpoint_report.by_callsite {
                    let Some(envelope) = steens.get(callsite) else {
                        panic!(
                            "{}: M3.3 found {callsite}, absent from Steensgaard",
                            path.display()
                        );
                    };
                    for target in targets {
                        assert!(
                            envelope.contains(target),
                            "{}: M3.3 target {target} for {callsite} is outside Steensgaard envelope {envelope:?}",
                            path.display()
                        );
                    }
                }
                checked += 1;
            }
        }

        assert!(checked >= 25, "checked only {checked} fixtures");
        assert!(
            sites_with_m3_answers >= 6,
            "expected several non-empty M3.1 answers, got {sites_with_m3_answers}"
        );
        assert!(max_visited > 0);
    }
}
