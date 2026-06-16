use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use pangs_pag::{CallKind, CallsiteId, Edge, EdgeKind, NodeId, NodeKind, ObjectKind, Pag};

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

/// Run one M3.1 query per function object and invert the source-oriented answers into
/// callsite -> target function names.
pub fn query_all_callees_field_insensitive(pag: &Pag) -> BTreeMap<String, BTreeSet<String>> {
    let graph = QueryGraph::new(pag);
    let mut by_callsite: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for node in &pag.nodes {
        let NodeKind::Object {
            object: ObjectKind::Function,
            key,
            ..
        } = &node.kind
        else {
            continue;
        };
        let answer = graph.query_function(key);
        for callsite in answer.callsites {
            by_callsite.entry(callsite).or_default().insert(key.clone());
        }
    }
    by_callsite
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CflCalleeQuery {
    pub function: String,
    pub source: Option<NodeId>,
    pub callsites: BTreeSet<String>,
    pub metrics: CflQueryMetrics,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CflQueryMetrics {
    pub visited_states: usize,
    pub max_worklist: usize,
}

struct QueryGraph<'a> {
    pag: &'a Pag,
    forward: Vec<Vec<usize>>,
    reverse: Vec<Vec<usize>>,
    function_objects: HashMap<&'a str, NodeId>,
    indirect_operands: HashMap<NodeId, Vec<CallsiteId>>,
}

impl<'a> QueryGraph<'a> {
    fn new(pag: &'a Pag) -> Self {
        let mut forward = vec![Vec::new(); pag.nodes.len()];
        let mut reverse = vec![Vec::new(); pag.nodes.len()];
        for (index, edge) in pag.edges.iter().enumerate() {
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

        let mut indirect_operands: HashMap<NodeId, Vec<CallsiteId>> = HashMap::new();
        for callsite in &pag.callsites {
            if callsite.kind == CallKind::Indirect {
                if let Some(operand) = callsite.operand {
                    indirect_operands
                        .entry(operand)
                        .or_default()
                        .push(callsite.id);
                }
            }
        }

        Self {
            pag,
            forward,
            reverse,
            function_objects,
            indirect_operands,
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

            if phase == Phase::Forward {
                if let Some(sites) = self.indirect_operands.get(&node) {
                    for site in sites {
                        out.callsites
                            .insert(self.pag.callsites[site.0 as usize].key.clone());
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

    fn step_forward(&self, node: NodeId, worklist: &mut VecDeque<(NodeId, Phase)>) {
        for &edge_index in &self.forward[node.0 as usize] {
            let edge = &self.pag.edges[edge_index];
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
            let edge = &self.pag.edges[edge_index];
            if backward_edge(edge) {
                worklist.push_back((edge.src, Phase::Backward));
            }
        }
    }
}

fn backward_edge(edge: &Edge) -> bool {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Phase {
    Forward,
    Backward,
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use pangs_pag::{Pag, PagOpts};
    use pangs_pir::Pir;

    use super::{query_all_callees_field_insensitive, query_callees_field_insensitive};

    fn load(root: &str, name: &str) -> Pag {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/synthetic")
            .join(root)
            .join(name);
        let pir = Pir::from_path(path).unwrap();
        Pag::from_pir(&pir, &PagOpts::default())
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

        let by_callsite = query_all_callees_field_insensitive(&pag);
        assert_eq!(
            by_callsite["driver@!noloc#0"],
            ["target".to_string()].into_iter().collect()
        );
        assert!(!by_callsite["driver@!noloc#0"].contains("other"));
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
}
