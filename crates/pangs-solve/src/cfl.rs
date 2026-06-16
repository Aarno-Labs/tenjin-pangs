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
    query_all_callees_field_insensitive_report(pag).by_callsite
}

/// Run all M3.1 callee queries and retain per-query traversal metrics.
pub fn query_all_callees_field_insensitive_report(pag: &Pag) -> CflCalleeReport {
    let graph = QueryGraph::new(pag);
    let mut by_callsite: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut queries = Vec::new();
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
        for callsite in &answer.callsites {
            by_callsite
                .entry(callsite.clone())
                .or_default()
                .insert(key.clone());
        }
        queries.push(answer);
    }
    CflCalleeReport {
        by_callsite,
        queries,
    }
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CflCalleeReport {
    pub by_callsite: BTreeMap<String, BTreeSet<String>>,
    pub queries: Vec<CflCalleeQuery>,
}

impl CflCalleeReport {
    pub fn visit_histogram(&self) -> CflVisitHistogram {
        let mut histogram = CflVisitHistogram::default();
        for query in &self.queries {
            match query.metrics.visited_states {
                0..=10 => histogram.le_10 += 1,
                11..=100 => histogram.le_100 += 1,
                101..=1_000 => histogram.le_1000 += 1,
                _ => histogram.gt_1000 += 1,
            }
        }
        histogram
    }

    pub fn max_visited_states(&self) -> usize {
        self.queries
            .iter()
            .map(|query| query.metrics.visited_states)
            .max()
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CflVisitHistogram {
    pub le_10: usize,
    pub le_100: usize,
    pub le_1000: usize,
    pub gt_1000: usize,
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
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;

    use pangs_pag::{BuildMode, Pag, PagOpts};
    use pangs_pir::Pir;

    use crate::solve_steensgaard;

    use super::{
        query_all_callees_field_insensitive, query_all_callees_field_insensitive_report,
        query_callees_field_insensitive,
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

        let report = query_all_callees_field_insensitive_report(&pag);
        assert_eq!(
            report.by_callsite["driver@!noloc#0"],
            ["target".to_string()].into_iter().collect()
        );
        assert!(!report.by_callsite["driver@!noloc#0"].contains("other"));
        assert_eq!(report.queries.len(), 3);
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
    fn m3_1_answers_stay_inside_steensgaard_envelope_on_synthetic_suite() {
        let roots = ["m1_4", "m1_4b", "m1_5", "m2_2", "m2_3", "m2_4", "m3_1"];
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
                let report = query_all_callees_field_insensitive_report(&pag);
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
