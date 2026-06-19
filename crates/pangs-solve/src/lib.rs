use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::ops::Deref;
use std::sync::Arc;
use std::time::Instant;

use pangs_pag::{
    BuildMode, CallKind, NodeId, NodeKind, ObjectKind, OmegaSeedKind, Pag, SeedTarget,
};
use pangs_pir::{fsa_compatible, Pir, Signature};
use serde::{Deserialize, Serialize};

mod andersen;
mod cfl;
pub use andersen::{solve_andersen, solve_andersen_with_overrides};

// Experimental tier-E prototype APIs. These are intentionally kept out of the
// PANGS-lite `analyze` path; use them only through diagnostic/query surfaces or a
// future explicit graduation back to the full tier-E design.
pub use cfl::{
    fallback_for_truncated_queries, query_all_callees_field_insensitive,
    query_all_callees_field_insensitive_report,
    query_all_callees_field_insensitive_report_with_signatures, query_all_callees_field_sensitive,
    query_all_callees_field_sensitive_fixpoint_report,
    query_all_callees_field_sensitive_fixpoint_report_with_signatures,
    query_all_callees_field_sensitive_report,
    query_all_callees_field_sensitive_report_with_signatures, query_callees_field_insensitive,
    query_callees_field_sensitive, CflCalleeFallbackReport, CflCalleeQuery, CflCalleeReport,
    CflFixpointReport, CflFixpointRound, CflQueryMetrics, CflVisitHistogram,
};

/// M2.0 subset-narrowing tripwire (`PLAN-M2_lite_delta.md` §1 M2.0). A more-exact
/// provenance may only *narrow* an answer; if `refined` is not a subset of `envelope`, a
/// tier produced a target the coarser tier did not — a soundness regression. This is the
/// cheapest such tripwire we buy: it costs a set membership per resolved site and fires in
/// debug builds. Reused by every narrowing source (Andersen∩FSA now; B1/B2 overrides in
/// M2.2/M2.4). In release it is a no-op (we never widen silently — the coarser answer is
/// already sound).
#[track_caller]
pub fn debug_assert_narrows(
    site: &str,
    refined_tier: &str,
    refined: &[String],
    envelope_tier: &str,
    envelope: &[String],
) {
    if cfg!(debug_assertions) {
        let env: HashSet<&str> = envelope.iter().map(|s| s.as_str()).collect();
        for t in refined {
            assert!(
                env.contains(t.as_str()),
                "subset-narrowing violation at {site}: {refined_tier} target {t:?} \
                 is not in the {envelope_tier} envelope {envelope:?} (a more-exact tier \
                 widened the answer — soundness regression)",
            );
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SolveMetrics {
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
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SolveResult {
    #[serde(default)]
    pub indirect_calls: Vec<IndirectCallResolution>,
    #[serde(default)]
    pub unknown_callers: BTreeSet<String>,
    #[serde(default)]
    pub globals: BTreeMap<String, GlobalResolution>,
    #[serde(default)]
    pub nodes: BTreeMap<String, NodeResolution>,
    /// Allocation-level points-to: PAG node label → the named allocations (global and function
    /// keys) the node's class points to. Populated only by `solve_steensgaard_with_points_to`
    /// (the cc2json client); empty otherwise. This is cclyzer's `operand_points_to` /
    /// `var_points_to` over named allocations, and — for object nodes — `ptr_points_to`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub node_points_to: BTreeMap<String, BTreeSet<String>>,
    #[serde(default)]
    pub metrics: SolveMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndirectCallResolution {
    pub callsite_key: String,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub unknown_callee: bool,
    /// When true, this site's targets were *not* refined by Andersen (the owning
    /// partition was uninteresting or exceeded the oversize budget) and carry the
    /// Steensgaard answer; the API tags such edges `tier: steens` even under
    /// `--stage andersen`.
    #[serde(default)]
    pub fallback: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlobalResolution {
    pub escape_external: bool,
    pub never_written: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeResolution {
    pub reaches_function_pointer: bool,
    #[serde(default)]
    pub external: bool,
    #[serde(default)]
    pub pointee_globals: SharedStringList,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external_sources: Vec<String>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct SharedStringList(Arc<[String]>);

impl SharedStringList {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Stable identity for process-local caches while this shared list is alive.
    pub fn cache_key(&self) -> (usize, usize) {
        (self.0.as_ptr() as usize, self.0.len())
    }

    pub fn to_vec(&self) -> Vec<String> {
        self.0.to_vec()
    }
}

impl Deref for SharedStringList {
    type Target = [String];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[String]> for SharedStringList {
    fn as_ref(&self) -> &[String] {
        &self.0
    }
}

impl From<Vec<String>> for SharedStringList {
    fn from(values: Vec<String>) -> Self {
        Self(values.into())
    }
}

impl From<SharedStringList> for Vec<String> {
    fn from(values: SharedStringList) -> Self {
        values.0.to_vec()
    }
}

impl PartialEq<Vec<String>> for SharedStringList {
    fn eq(&self, other: &Vec<String>) -> bool {
        self.0.as_ref() == other.as_slice()
    }
}

impl Serialize for SharedStringList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.as_ref().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SharedStringList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Vec::<String>::deserialize(deserializer).map(Self::from)
    }
}

pub fn solve_steensgaard(pir: &Pir, pag: &Pag, build_mode: BuildMode) -> SolveResult {
    let mut solver = Solver::new(pir, pag, build_mode);
    solver.run();
    solver.finish()
}

/// Like [`solve_steensgaard`] but also materializes `SolveResult::node_points_to` for every PAG
/// node. Diagnostic clients can use this for full allocation-level points-to; the normal pipeline
/// uses `solve_steensgaard` and pays nothing for this.
pub fn solve_steensgaard_with_points_to(
    pir: &Pir,
    pag: &Pag,
    build_mode: BuildMode,
) -> SolveResult {
    let mut solver = Solver::new(pir, pag, build_mode);
    solver.points_to_materialization = PointsToMaterialization::AllNodes;
    solver.run();
    solver.finish()
}

/// Like [`solve_steensgaard_with_points_to`] but only materializes object-node points-to for
/// globals. This is enough for cc2json's escape fixpoint (`ptr_points_to` from global memory
/// objects) without building allocation-level points-to sets for every SSA/PAG node.
pub fn solve_steensgaard_with_global_points_to(
    pir: &Pir,
    pag: &Pag,
    build_mode: BuildMode,
) -> SolveResult {
    let mut solver = Solver::new(pir, pag, build_mode);
    solver.points_to_materialization = PointsToMaterialization::GlobalObjects;
    solver.run();
    solver.finish()
}

/// Run Steensgaard and also export the final union-find class structure, which the
/// Andersen pass (`andersen::solve_andersen`) consumes as Kahlon partitions plus the
/// round-0 escape/pointee facts. The two are produced from one solve so the partition
/// scoping and the round-0 call graph stay consistent.
pub fn solve_steensgaard_with_classes(
    pir: &Pir,
    pag: &Pag,
    build_mode: BuildMode,
) -> (SolveResult, SteensClasses) {
    let mut solver = Solver::new(pir, pag, build_mode);
    solver.run();
    let classes = solver.export_classes();
    let result = solver.finish();
    (result, classes)
}

/// Snapshot of the Steensgaard union-find after solving: for every PAG node, its class
/// root, and for every class root, its pointee class and Ω bits. Class roots are indices
/// into a universe that includes synthetic pointee classes beyond `pag.nodes.len()`.
#[derive(Debug, Clone, Default)]
pub struct SteensClasses {
    /// `node_class[node_id] = class root` for the `pag.nodes.len()` base nodes.
    pub node_class: Vec<usize>,
    /// `pointee[root] = Some(pointee root)` when the class points somewhere.
    pub pointee: Vec<Option<usize>>,
    /// `ext[root]` — class members may point to external/escaped memory (PIP `p ⊒ Ω`).
    pub ext: Vec<bool>,
    /// `esc[root]` — class members are reachable by external code (PIP `Ω ⊒ {x}`).
    pub esc: Vec<bool>,
}

impl SteensClasses {
    /// Class root of a PAG node.
    pub fn class_of(&self, node: NodeId) -> usize {
        self.node_class[node.0 as usize]
    }
}

#[derive(Debug, Clone)]
struct FunctionMeta {
    sig: Signature,
    address_taken: bool,
    external: bool,
    param_nodes: Vec<NodeId>,
    ret_node: Option<NodeId>,
}

#[derive(Debug, Clone, Default)]
struct ClassData {
    parent: usize,
    size: usize,
    node_count: usize,
    pointee: Option<usize>,
    ext: bool,
    esc: bool,
    icall_sites: HashSet<usize>,
    fn_objs: HashSet<usize>,
    processed_icall_sites: HashSet<usize>,
    processed_fn_objs: HashSet<usize>,
    processed_external_icall_sites: HashSet<usize>,
    global_objs: HashSet<usize>,
}

#[derive(Clone)]
struct CachedRootNodeSummary {
    reaches_function_pointer: bool,
    external: bool,
    pointee: Option<usize>,
}

struct Solver<'a> {
    pir: &'a Pir,
    pag: &'a Pag,
    build_mode: BuildMode,
    classes: Vec<ClassData>,
    function_meta: Vec<FunctionMeta>,
    function_name_to_index: HashMap<String, usize>,
    function_keys: Vec<String>,
    function_object_nodes: Vec<Option<NodeId>>,
    global_keys: Vec<String>,
    global_object_nodes: Vec<Option<NodeId>>,
    callsites_by_index: Vec<&'a pangs_pag::Callsite>,
    worklist: VecDeque<usize>,
    queued: Vec<bool>,
    seen_pairs: SeenPairBits,
    external_applied: HashSet<usize>,
    escaped_fn_applied: HashSet<usize>,
    metrics: SolveMetrics,
    profile: bool,
    profile_started: Instant,
    profile_interval_candidate_pairs: u64,
    next_profile_candidate_pairs: u64,
    /// Controls optional `SolveResult::node_points_to` materialization. Off for the normal
    /// `analyze` pipeline so it pays nothing.
    points_to_materialization: PointsToMaterialization,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PointsToMaterialization {
    None,
    AllNodes,
    GlobalObjects,
}

#[derive(Debug, Clone)]
struct SeenPairBits {
    words_per_site: usize,
    sites: Vec<Vec<u64>>,
}

impl SeenPairBits {
    fn new(site_count: usize, func_count: usize) -> Self {
        Self {
            words_per_site: func_count.div_ceil(64),
            sites: vec![Vec::new(); site_count],
        }
    }

    fn insert(&mut self, site_index: usize, func_index: usize) -> bool {
        let word = func_index / 64;
        let bit = 1u64 << (func_index % 64);
        let Some(site_words) = self.sites.get_mut(site_index) else {
            debug_assert!(false, "invalid callsite index {site_index}");
            return false;
        };
        if site_words.is_empty() {
            site_words.resize(self.words_per_site, 0);
        }
        let Some(slot) = site_words.get_mut(word) else {
            debug_assert!(false, "invalid function index {func_index}");
            return false;
        };
        if *slot & bit != 0 {
            return false;
        }
        *slot |= bit;
        true
    }
}

impl<'a> Solver<'a> {
    fn new(pir: &'a Pir, pag: &'a Pag, build_mode: BuildMode) -> Self {
        let function_keys = pir
            .functions
            .iter()
            .map(|func| func.key.clone())
            .collect::<Vec<_>>();
        let function_name_to_index = function_keys
            .iter()
            .enumerate()
            .map(|(idx, key)| (key.clone(), idx))
            .collect::<HashMap<_, _>>();
        let mut function_meta = pir
            .functions
            .iter()
            .map(|func| FunctionMeta {
                sig: func.sig.clone(),
                address_taken: func.address_taken,
                external: func.external,
                param_nodes: Vec::new(),
                ret_node: None,
            })
            .collect::<Vec<_>>();
        let mut function_object_nodes = vec![None; function_keys.len()];

        let global_keys = pir
            .globals
            .iter()
            .map(|global| global.key.clone())
            .collect::<Vec<_>>();
        let global_name_to_index = global_keys
            .iter()
            .enumerate()
            .map(|(idx, key)| (key.clone(), idx))
            .collect::<HashMap<_, _>>();
        let mut global_object_nodes = vec![None; global_keys.len()];

        let mut classes = Vec::with_capacity(pag.nodes.len());
        for (index, node) in pag.nodes.iter().enumerate() {
            let mut data = ClassData {
                parent: index,
                size: 1,
                node_count: 1,
                ..ClassData::default()
            };
            match &node.kind {
                NodeKind::Object { object, key, .. } => match object {
                    pangs_pag::ObjectKind::Function => {
                        if let Some(&func_index) = function_name_to_index.get(key) {
                            data.fn_objs.insert(func_index);
                            function_object_nodes[func_index] = Some(node.id);
                        }
                    }
                    pangs_pag::ObjectKind::Global => {
                        if let Some(&global_index) = global_name_to_index.get(key) {
                            data.global_objs.insert(global_index);
                            global_object_nodes[global_index] = Some(node.id);
                        }
                    }
                    pangs_pag::ObjectKind::Alloca => {}
                },
                NodeKind::Param { func, index } => {
                    if let Some(&func_index) = function_name_to_index.get(func) {
                        let meta = &mut function_meta[func_index];
                        if meta.param_nodes.len() <= *index as usize {
                            meta.param_nodes
                                .resize(*index as usize + 1, NodeId(u32::MAX));
                        }
                        meta.param_nodes[*index as usize] = node.id;
                    }
                }
                NodeKind::Return { func } => {
                    if let Some(&func_index) = function_name_to_index.get(func) {
                        function_meta[func_index].ret_node = Some(node.id);
                    }
                }
                NodeKind::Value { .. } => {}
            }
            classes.push(data);
        }

        let function_count = function_keys.len();
        let callsites_by_index = pag.callsites.iter().collect();
        let queued = vec![false; classes.len()];

        Self {
            pir,
            pag,
            build_mode,
            classes,
            function_meta,
            function_name_to_index,
            function_keys,
            function_object_nodes,
            global_keys,
            global_object_nodes,
            callsites_by_index,
            worklist: VecDeque::new(),
            queued,
            seen_pairs: SeenPairBits::new(pag.callsites.len(), function_count),
            external_applied: HashSet::new(),
            escaped_fn_applied: HashSet::new(),
            metrics: SolveMetrics::default(),
            profile: steens_profile_enabled(),
            profile_started: Instant::now(),
            profile_interval_candidate_pairs: steens_profile_interval_candidate_pairs(),
            next_profile_candidate_pairs: steens_profile_interval_candidate_pairs(),
            points_to_materialization: PointsToMaterialization::None,
        }
    }

    fn run(&mut self) {
        self.apply_edge_rules();
        self.register_indirect_calls();
        self.apply_seeds();
        self.seed_main_entry_params();

        while let Some(class) = self.worklist.pop_front() {
            self.metrics.steens_worklist_pops += 1;
            self.queued[class] = false;
            let root = self.find(class);
            self.process_class(root);
        }
        self.print_steens_profile("done");
    }

    /// Snapshot the solved union-find for the Andersen pass. Must be called after
    /// `run()` and before `finish()` (which consumes `self`).
    fn export_classes(&mut self) -> SteensClasses {
        let n_nodes = self.pag.nodes.len();
        let total = self.classes.len();
        let mut node_class = vec![0usize; n_nodes];
        for i in 0..n_nodes {
            node_class[i] = self.find(i);
        }
        let mut pointee = vec![None; total];
        let mut ext = vec![false; total];
        let mut esc = vec![false; total];
        for i in 0..total {
            let root = self.find(i);
            if root == i {
                pointee[i] = self.classes[i].pointee.map(|p| self.find(p));
                ext[i] = self.classes[i].ext;
                esc[i] = self.classes[i].esc;
            }
        }
        SteensClasses {
            node_class,
            pointee,
            ext,
            esc,
        }
    }

    fn apply_edge_rules(&mut self) {
        for edge in &self.pag.edges {
            match edge.kind {
                pangs_pag::EdgeKind::AddrOf => {
                    let ptr = self.class_of(edge.dst);
                    let obj = self.class_of(edge.src);
                    let pointee = self.pointee_of(ptr);
                    self.join(pointee, obj);
                }
                pangs_pag::EdgeKind::Assign => {
                    let src = self.class_of(edge.src);
                    let dst = self.class_of(edge.dst);
                    self.join(src, dst);
                }
                pangs_pag::EdgeKind::Load => {
                    let dst = self.class_of(edge.dst);
                    let src = self.class_of(edge.src);
                    let pointee = self.pointee_of(src);
                    self.join(dst, pointee);
                }
                pangs_pag::EdgeKind::Store => {
                    let src = self.class_of(edge.src);
                    let dst = self.class_of(edge.dst);
                    let pointee = self.pointee_of(dst);
                    self.join(pointee, src);
                }
                pangs_pag::EdgeKind::Gep { .. } => {
                    let dst = self.class_of(edge.dst);
                    let src = self.class_of(edge.src);
                    let dst_p = self.pointee_of(dst);
                    let src_p = self.pointee_of(src);
                    self.join(dst_p, src_p);
                }
                pangs_pag::EdgeKind::Memcpy { .. } => {
                    let dst = self.class_of(edge.dst);
                    let src = self.class_of(edge.src);
                    let dst_p = self.pointee_of(dst);
                    let src_p = self.pointee_of(src);
                    let dst_pp = self.pointee_of(dst_p);
                    let src_pp = self.pointee_of(src_p);
                    self.join(dst_pp, src_pp);
                }
            }
        }
    }

    fn register_indirect_calls(&mut self) {
        for (site_index, callsite) in self.pag.callsites.iter().enumerate() {
            if callsite.kind != CallKind::Indirect {
                continue;
            }
            let Some(operand) = callsite.operand else {
                continue;
            };
            let operand = self.class_of(operand);
            let cls = self.pointee_of(operand);
            let root = self.find(cls);
            self.classes[root].icall_sites.insert(site_index);
            self.enqueue(root);
        }
    }

    fn apply_seeds(&mut self) {
        for seed in &self.pag.omega_seeds {
            match (seed.kind, seed.target) {
                (OmegaSeedKind::ExportedSymbol, SeedTarget::Node(id))
                | (OmegaSeedKind::ImportedSymbol, SeedTarget::Node(id)) => {
                    let class = self.class_of(id);
                    self.set_esc(class);
                }
                (OmegaSeedKind::PtrToInt, SeedTarget::Node(id))
                | (OmegaSeedKind::UnknownOperandEscape, SeedTarget::Node(id)) => {
                    let class = self.class_of(id);
                    let pointee = self.pointee_of(class);
                    self.set_esc(pointee);
                }
                (OmegaSeedKind::IntToPtr, SeedTarget::Node(id))
                | (OmegaSeedKind::UnknownResultExternal, SeedTarget::Node(id)) => {
                    let class = self.class_of(id);
                    self.set_ext(class);
                }
                (OmegaSeedKind::ExternalCallBoundary, SeedTarget::Callsite(id)) => {
                    self.apply_external_call(id.0 as usize);
                }
                (OmegaSeedKind::VarargCallBoundary, SeedTarget::Callsite(id)) => {
                    self.apply_vararg_call(id.0 as usize);
                }
                _ => {}
            }
        }
    }

    fn seed_main_entry_params(&mut self) {
        if self.build_mode != BuildMode::Executable {
            return;
        }
        let Some(&main_index) = self.function_name_to_index.get("main") else {
            return;
        };
        let params = self.function_meta[main_index].param_nodes.clone();
        for param in params.iter().skip(1).copied() {
            if param.0 != u32::MAX {
                let class = self.class_of(param);
                self.set_ext(class);
            }
        }
    }

    fn finish(mut self) -> SolveResult {
        let mut indirect_calls = Vec::new();
        for callsite in &self.pag.callsites {
            if callsite.kind != CallKind::Indirect {
                continue;
            }
            let Some(operand) = callsite.operand else {
                continue;
            };
            let operand = self.class_of(operand);
            let pointee = self.pointee_of(operand);
            let root = self.find(pointee);
            let mut targets = self.classes[root]
                .fn_objs
                .iter()
                .filter_map(|&func_index| {
                    let meta = &self.function_meta[func_index];
                    if !meta.address_taken {
                        return None;
                    }
                    if !fsa_compatible(&callsite.sig, &meta.sig) {
                        return None;
                    }
                    Some(self.function_keys[func_index].clone())
                })
                .collect::<Vec<_>>();
            targets.sort();
            indirect_calls.push(IndirectCallResolution {
                callsite_key: callsite.key.clone(),
                targets,
                unknown_callee: self.classes[root].ext,
                fallback: false,
            });
        }

        let mut unknown_callers = BTreeSet::new();
        for func_index in 0..self.function_meta.len() {
            let Some(class) = self.function_object_class(func_index) else {
                continue;
            };
            let root = self.find(class);
            if self.classes[root].esc {
                unknown_callers.insert(self.function_keys[func_index].clone());
            }
        }

        let mut stored_classes = BTreeSet::new();
        for edge in &self.pag.edges {
            if !matches!(edge.kind, pangs_pag::EdgeKind::Store) {
                continue;
            }
            let dst = self.class_of(edge.dst);
            let pointee = self.pointee_of(dst);
            stored_classes.insert(self.find(pointee));
        }

        let mut globals = BTreeMap::new();
        for (global_index, global) in self.pir.globals.iter().enumerate() {
            let Some(class) = self.global_object_class(global_index) else {
                continue;
            };
            let root = self.find(class);
            let escape_external = self.classes[root].esc;
            let never_written = !escape_external && !stored_classes.contains(&root);
            globals.insert(
                global.key.clone(),
                GlobalResolution {
                    escape_external,
                    never_written,
                },
            );
        }

        let mut pointee_globals_by_root: Vec<Option<SharedStringList>> =
            vec![None; self.classes.len()];
        let mut reaches_function_pointer_by_root: Vec<Option<bool>> =
            vec![None; self.classes.len()];
        let mut node_summary_by_root: Vec<Option<CachedRootNodeSummary>> =
            vec![None; self.classes.len()];
        let mut nodes = BTreeMap::new();
        for node in &self.pag.nodes {
            if !matches!(
                node.kind,
                NodeKind::Value { .. } | NodeKind::Param { .. } | NodeKind::Return { .. }
            ) {
                continue;
            }
            let root = self.class_of(node.id);
            let summary = if let Some(cached) = &node_summary_by_root[root] {
                cached.clone()
            } else {
                let external = self.classes[root].ext;
                let pointee = self.classes[root].pointee.map(|p| self.find(p));
                let reaches_function_pointer = pointee
                    .map(|pointee| {
                        if let Some(reaches) = reaches_function_pointer_by_root[pointee] {
                            reaches
                        } else {
                            let reaches = !self.classes[pointee].fn_objs.is_empty()
                                || self.classes[pointee].ext
                                || !self.classes[pointee].icall_sites.is_empty();
                            reaches_function_pointer_by_root[pointee] = Some(reaches);
                            reaches
                        }
                    })
                    .unwrap_or(false);
                let cached = CachedRootNodeSummary {
                    reaches_function_pointer,
                    external,
                    pointee,
                };
                node_summary_by_root[root] = Some(cached.clone());
                cached
            };
            let pointee_globals = summary
                .pointee
                .map(|pointee| {
                    if let Some(globals) = &pointee_globals_by_root[pointee] {
                        globals.clone()
                    } else {
                        let mut globals = self.classes[pointee]
                            .global_objs
                            .iter()
                            .map(|&global_index| self.global_keys[global_index].clone())
                            .collect::<Vec<_>>();
                        globals.sort();
                        let globals = SharedStringList::from(globals);
                        pointee_globals_by_root[pointee] = Some(globals.clone());
                        globals
                    }
                })
                .unwrap_or_default();
            nodes.insert(
                node.label.clone(),
                NodeResolution {
                    reaches_function_pointer: summary.reaches_function_pointer,
                    external: summary.external,
                    pointee_globals,
                    external_sources: if summary.external {
                        vec!["omega:steens_external".to_string()]
                    } else {
                        Vec::new()
                    },
                },
            );
        }

        let mut sizes = Vec::new();
        for index in 0..self.classes.len() {
            let root = self.find(index);
            if root == index && self.classes[index].node_count > 0 {
                sizes.push(self.classes[index].node_count);
            }
        }
        sizes.sort_unstable();
        self.metrics.partition_count = sizes.len();
        self.metrics.partition_p50_size = percentile(&sizes, 50);
        self.metrics.partition_p95_size = percentile(&sizes, 95);
        self.metrics.partition_max_size = sizes.last().copied().unwrap_or(0);
        self.metrics.oversize_fallbacks = 0;
        self.metrics.oversize_fallback_max_size = 0;
        self.metrics.rounds = 1;
        let metrics = self.metrics.clone();

        let node_points_to = match self.points_to_materialization {
            PointsToMaterialization::None => BTreeMap::new(),
            mode => self.materialize_points_to(mode),
        };

        SolveResult {
            indirect_calls,
            unknown_callers,
            globals,
            nodes,
            node_points_to,
            metrics,
        }
    }

    /// For every PAG node, the named allocations (global + function keys) its class points to —
    /// `global_objs ∪ fn_objs` of `find(pointee(class_of(node)))`. Object nodes thus expose
    /// `ptr_points_to` (what a memory cell holds); value/param/return nodes expose
    /// `operand_points_to`. Memoized per pointee-class root, so this is O(#nodes).
    fn materialize_points_to(
        &mut self,
        mode: PointsToMaterialization,
    ) -> BTreeMap<String, BTreeSet<String>> {
        let mut by_pointee_root: Vec<Option<BTreeSet<String>>> = vec![None; self.classes.len()];
        let mut out = BTreeMap::new();
        for node in &self.pag.nodes {
            if mode == PointsToMaterialization::GlobalObjects
                && !matches!(
                    node.kind,
                    NodeKind::Object {
                        object: ObjectKind::Global,
                        ..
                    }
                )
            {
                continue;
            }
            let root = self.find(node.id.0 as usize);
            let Some(pointee) = self.classes[root].pointee else {
                continue;
            };
            let pointee = self.find(pointee);
            let allocs = if let Some(cached) = &by_pointee_root[pointee] {
                cached.clone()
            } else {
                let mut allocs = BTreeSet::new();
                for &g in &self.classes[pointee].global_objs {
                    allocs.insert(self.global_keys[g].clone());
                }
                for &f in &self.classes[pointee].fn_objs {
                    allocs.insert(self.function_keys[f].clone());
                }
                by_pointee_root[pointee] = Some(allocs.clone());
                allocs
            };
            if !allocs.is_empty() {
                out.insert(node.label.clone(), allocs);
            }
        }
        out
    }

    fn process_class(&mut self, class: usize) {
        self.metrics.steens_process_class_calls += 1;
        let root = self.find(class);
        let ext = self.classes[root].ext;
        let esc = self.classes[root].esc;

        if ext || esc {
            if let Some(pointee) = self.classes[root].pointee {
                self.set_ext(pointee);
                self.set_esc(pointee);
            }
        }

        if esc {
            let escaped = self.classes[root]
                .fn_objs
                .iter()
                .copied()
                .collect::<Vec<_>>();
            for func_index in escaped {
                if !self.escaped_fn_applied.insert(func_index) {
                    continue;
                }
                self.metrics.steens_escaped_function_applications += 1;
                let meta = &self.function_meta[func_index];
                let params = meta.param_nodes.clone();
                let ret_node = meta.ret_node;
                for param in params {
                    if param.0 != u32::MAX {
                        let class = self.class_of(param);
                        self.set_ext(class);
                    }
                }
                if let Some(ret) = ret_node {
                    let class = self.class_of(ret);
                    let pointee = self.pointee_of(class);
                    self.set_esc(pointee);
                }
            }
        }

        let site_count = self.classes[root].icall_sites.len();
        let func_count = self.classes[root].fn_objs.len();
        let class_candidate_pairs = site_count as u64 * func_count as u64;
        if class_candidate_pairs > self.metrics.steens_max_class_candidate_pairs {
            self.metrics.steens_max_class_candidate_pairs = class_candidate_pairs;
            self.metrics.steens_max_class_icall_sites = site_count;
            self.metrics.steens_max_class_fn_objs = func_count;
        }

        if ext && self.classes[root].processed_external_icall_sites.len() < site_count {
            let external_site_ids = self.classes[root]
                .icall_sites
                .iter()
                .copied()
                .filter(|site| {
                    !self.classes[root]
                        .processed_external_icall_sites
                        .contains(site)
                })
                .collect::<Vec<_>>();
            self.classes[root]
                .processed_external_icall_sites
                .extend(external_site_ids.iter().copied());
            for site_index in external_site_ids {
                self.apply_external_call(site_index);
            }
        }

        if site_count == 0
            || func_count == 0
            || (self.classes[root].processed_icall_sites.len() == site_count
                && self.classes[root].processed_fn_objs.len() == func_count)
        {
            return;
        }

        let site_ids = self.classes[root]
            .icall_sites
            .iter()
            .copied()
            .collect::<Vec<_>>();
        let funcs = self.classes[root]
            .fn_objs
            .iter()
            .copied()
            .collect::<Vec<_>>();
        let processed_site_ids = site_ids
            .iter()
            .copied()
            .filter(|site| self.classes[root].processed_icall_sites.contains(site))
            .collect::<Vec<_>>();
        let new_site_ids = site_ids
            .iter()
            .copied()
            .filter(|site| !self.classes[root].processed_icall_sites.contains(site))
            .collect::<Vec<_>>();
        let new_funcs = funcs
            .iter()
            .copied()
            .filter(|func| !self.classes[root].processed_fn_objs.contains(func))
            .collect::<Vec<_>>();

        let mut bindings = Vec::new();
        for &site_index in &new_site_ids {
            for &func_index in &funcs {
                self.consider_indirect_pair(site_index, func_index, &mut bindings);
            }
        }
        for &site_index in &processed_site_ids {
            for &func_index in &new_funcs {
                self.consider_indirect_pair(site_index, func_index, &mut bindings);
            }
        }

        self.classes[root]
            .processed_icall_sites
            .extend(new_site_ids);
        self.classes[root].processed_fn_objs.extend(new_funcs);

        for (site_index, func_index) in bindings {
            self.bind_indirect_call(site_index, func_index);
        }
    }

    fn consider_indirect_pair(
        &mut self,
        site_index: usize,
        func_index: usize,
        bindings: &mut Vec<(usize, usize)>,
    ) {
        self.metrics.steens_candidate_pairs += 1;
        self.maybe_print_steens_profile();
        if !self.seen_pairs.insert(site_index, func_index) {
            self.metrics.steens_seen_pairs_duplicate += 1;
            return;
        }
        self.metrics.steens_seen_pairs_new += 1;
        let callsite = self.callsites_by_index[site_index];
        let meta = &self.function_meta[func_index];
        if !fsa_compatible(&callsite.sig, &meta.sig) {
            self.metrics.steens_fsa_rejected_pairs += 1;
            return;
        }
        self.metrics.steens_fsa_compatible_pairs += 1;
        bindings.push((site_index, func_index));
    }

    fn bind_indirect_call(&mut self, site_index: usize, func_index: usize) {
        self.metrics.steens_indirect_bindings += 1;
        let callsite = self.callsites_by_index[site_index];
        let (external, param_nodes, ret_node) = {
            let meta = &self.function_meta[func_index];
            (meta.external, meta.param_nodes.clone(), meta.ret_node)
        };
        if external {
            self.apply_external_call(site_index);
        }
        for (arg, param) in callsite.args.iter().zip(param_nodes.iter()) {
            if param.0 == u32::MAX {
                continue;
            }
            let arg = self.class_of(*arg);
            let param = self.class_of(*param);
            self.join(arg, param);
        }
        if let (Some(result), Some(ret)) = (callsite.result, ret_node) {
            let result = self.class_of(result);
            let ret = self.class_of(ret);
            self.join(result, ret);
        }
    }

    fn apply_external_call(&mut self, site_index: usize) {
        self.metrics.steens_external_call_requests += 1;
        if !self.external_applied.insert(site_index) {
            return;
        }
        self.metrics.steens_external_call_applications += 1;
        let callsite = self.callsites_by_index[site_index];
        for arg in &callsite.args {
            let arg = self.class_of(*arg);
            let pointee = self.pointee_of(arg);
            self.set_esc(pointee);
        }
        if let Some(result) = callsite.result {
            let result = self.class_of(result);
            self.set_ext(result);
        }
    }

    fn apply_vararg_call(&mut self, site_index: usize) {
        let callsite = self.callsites_by_index[site_index];
        let fixed = callsite.sig.params.len();
        let extra_args = callsite
            .args
            .iter()
            .skip(fixed)
            .copied()
            .collect::<Vec<_>>();
        for arg in extra_args {
            let class = self.class_of(arg);
            let root = self.find(class);
            let Some(pointee) = self.classes[root].pointee else {
                continue;
            };
            self.set_esc(pointee);
        }
    }

    fn function_object_class(&mut self, func_index: usize) -> Option<usize> {
        let id = self
            .function_object_nodes
            .get(func_index)
            .and_then(|id| *id)?;
        Some(self.class_of(id))
    }

    fn global_object_class(&mut self, global_index: usize) -> Option<usize> {
        let id = self
            .global_object_nodes
            .get(global_index)
            .and_then(|id| *id)?;
        Some(self.class_of(id))
    }

    fn class_of(&mut self, node: NodeId) -> usize {
        self.find(node.0 as usize)
    }

    fn pointee_of(&mut self, class: usize) -> usize {
        let root = self.find(class);
        if let Some(pointee) = self.classes[root].pointee {
            return self.find(pointee);
        }
        let id = self.classes.len();
        self.metrics.steens_pointee_classes_created += 1;
        self.classes.push(ClassData {
            parent: id,
            size: 1,
            ..ClassData::default()
        });
        self.queued.push(false);
        self.classes[root].pointee = Some(id);
        self.enqueue(root);
        id
    }

    fn set_ext(&mut self, class: usize) {
        let root = self.find(class);
        if !self.classes[root].ext {
            self.classes[root].ext = true;
            self.enqueue(root);
        }
    }

    fn set_esc(&mut self, class: usize) {
        let root = self.find(class);
        if !self.classes[root].esc {
            self.classes[root].esc = true;
            self.enqueue(root);
        }
    }

    fn join(&mut self, left: usize, right: usize) -> usize {
        self.metrics.steens_join_attempts += 1;
        let mut a = self.find(left);
        let mut b = self.find(right);
        if a == b {
            return a;
        }
        self.metrics.steens_join_successes += 1;
        if self.classes[a].size < self.classes[b].size {
            std::mem::swap(&mut a, &mut b);
        }

        self.classes[b].parent = a;
        self.classes[a].size += self.classes[b].size;
        self.classes[a].node_count += self.classes[b].node_count;
        self.classes[a].ext |= self.classes[b].ext;
        self.classes[a].esc |= self.classes[b].esc;

        let other_sites = std::mem::take(&mut self.classes[b].icall_sites);
        self.classes[a].icall_sites.extend(other_sites);
        let other_fns = std::mem::take(&mut self.classes[b].fn_objs);
        self.classes[a].fn_objs.extend(other_fns);
        let other_globals = std::mem::take(&mut self.classes[b].global_objs);
        self.classes[a].global_objs.extend(other_globals);
        let other_external_sites =
            std::mem::take(&mut self.classes[b].processed_external_icall_sites);
        self.classes[a]
            .processed_external_icall_sites
            .extend(other_external_sites);
        let a_processed_pairs =
            self.classes[a].processed_icall_sites.len() * self.classes[a].processed_fn_objs.len();
        let b_processed_pairs =
            self.classes[b].processed_icall_sites.len() * self.classes[b].processed_fn_objs.len();
        // The processed frontier represents one already-visited site/function rectangle.
        // Unioning both roots' frontiers would incorrectly mark the cross product between
        // independently processed classes as done, so keep only the larger rectangle.
        if b_processed_pairs > a_processed_pairs {
            let processed_sites = std::mem::take(&mut self.classes[b].processed_icall_sites);
            let processed_fns = std::mem::take(&mut self.classes[b].processed_fn_objs);
            self.classes[a].processed_icall_sites = processed_sites;
            self.classes[a].processed_fn_objs = processed_fns;
        } else {
            self.classes[b].processed_icall_sites.clear();
            self.classes[b].processed_fn_objs.clear();
        }

        let pointee = match (self.classes[a].pointee, self.classes[b].pointee) {
            (Some(pa), Some(pb)) => Some(self.join(pa, pb)),
            (Some(pa), None) => Some(self.find(pa)),
            (None, Some(pb)) => Some(self.find(pb)),
            (None, None) => None,
        };
        self.classes[a].pointee = pointee;
        self.classes[b].pointee = None;
        self.enqueue(a);
        a
    }

    fn enqueue(&mut self, class: usize) {
        if self.queued[class] {
            return;
        }
        self.queued[class] = true;
        self.worklist.push_back(class);
    }

    fn maybe_print_steens_profile(&mut self) {
        if !self.profile || self.metrics.steens_candidate_pairs < self.next_profile_candidate_pairs
        {
            return;
        }
        self.print_steens_profile("progress");
        while self.next_profile_candidate_pairs <= self.metrics.steens_candidate_pairs {
            self.next_profile_candidate_pairs += self.profile_interval_candidate_pairs;
        }
    }

    fn print_steens_profile(&self, label: &str) {
        if !self.profile {
            return;
        }
        eprintln!(
            "pangs steens profile {label}: elapsed_ms={} worklist_pops={} process_class_calls={} \
             candidate_pairs={} seen_new={} seen_duplicate={} fsa_compatible={} \
             fsa_rejected={} bindings={} joins={}/{} pointee_classes_created={} \
             max_class_sites={} max_class_fns={} max_class_candidate_pairs={} worklist_len={}",
            self.profile_started.elapsed().as_millis(),
            self.metrics.steens_worklist_pops,
            self.metrics.steens_process_class_calls,
            self.metrics.steens_candidate_pairs,
            self.metrics.steens_seen_pairs_new,
            self.metrics.steens_seen_pairs_duplicate,
            self.metrics.steens_fsa_compatible_pairs,
            self.metrics.steens_fsa_rejected_pairs,
            self.metrics.steens_indirect_bindings,
            self.metrics.steens_join_successes,
            self.metrics.steens_join_attempts,
            self.metrics.steens_pointee_classes_created,
            self.metrics.steens_max_class_icall_sites,
            self.metrics.steens_max_class_fn_objs,
            self.metrics.steens_max_class_candidate_pairs,
            self.worklist.len(),
        );
    }

    fn find(&mut self, class: usize) -> usize {
        let parent = self.classes[class].parent;
        if parent == class {
            return class;
        }
        let root = self.find(parent);
        self.classes[class].parent = root;
        root
    }
}

fn steens_profile_enabled() -> bool {
    std::env::var_os("PANGS_STEENS_PROFILE").is_some()
}

fn steens_profile_interval_candidate_pairs() -> u64 {
    std::env::var("PANGS_STEENS_PROFILE_INTERVAL")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|&value| value > 0)
        .unwrap_or(10_000_000)
}

fn percentile(sorted: &[usize], pct: usize) -> usize {
    if sorted.is_empty() {
        return 0;
    }
    let index = ((sorted.len() - 1) * pct) / 100;
    sorted[index]
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use pangs_pag::{CallKind, Callsite, CallsiteId, Node, NodeId, NodeKind, Pag, PagOpts, Scope};
    use pangs_pir::{AbiClass, Func};

    use super::*;

    fn fixture(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/synthetic/m1_4")
            .join(name)
    }

    #[test]
    fn narrowing_tripwire_is_silent_when_refined_is_a_subset() {
        // M2.0: a more-exact tier narrowing within the envelope must not fire.
        debug_assert_narrows(
            "site",
            "andersen",
            &["f".into()],
            "steens",
            &["f".into(), "g".into()],
        );
        debug_assert_narrows("site", "simple", &[], "steens", &["f".into()]);
    }

    #[test]
    #[should_panic(expected = "subset-narrowing violation")]
    fn narrowing_tripwire_fires_when_refined_adds_a_target() {
        // M2.0: a "more-exact" tier that introduces a target the envelope lacks is a
        // soundness regression — the tripwire must catch it.
        debug_assert_narrows("site", "simple", &["g".into()], "steens", &["f".into()]);
    }

    fn fixture_m1_5(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/synthetic/m1_5")
            .join(name)
    }

    fn void_sig() -> Signature {
        Signature {
            ret: AbiClass::Void,
            params: Vec::new(),
            vararg: false,
            cc: "ccc".to_string(),
        }
    }

    fn frontier_test_func(key: &str) -> Func {
        Func {
            key: key.to_string(),
            sig: void_sig(),
            param_names: Vec::new(),
            file: None,
            line: None,
            external: false,
            exported: false,
            address_taken: true,
            body: Vec::new(),
        }
    }

    fn frontier_test_callsite(index: usize) -> Callsite {
        Callsite {
            id: CallsiteId(index as u32),
            key: format!("caller@frontier#{index}"),
            caller: "caller".to_string(),
            kind: CallKind::Indirect,
            callee: None,
            operand: None,
            args: Vec::new(),
            result: None,
            sig: void_sig(),
            external_boundary: false,
            loc: None,
        }
    }

    #[test]
    fn steens_frontier_processes_cross_pairs_after_joining_processed_classes() {
        let pir = Pir {
            module: "frontier_merge".to_string(),
            source: None,
            lowering: Default::default(),
            functions: vec![frontier_test_func("f0"), frontier_test_func("f1")],
            globals: Vec::new(),
            global_init: Vec::new(),
        };
        let pag = Pag {
            module: pir.module.clone(),
            source: None,
            metrics: Default::default(),
            nodes: vec![
                Node {
                    id: NodeId(0),
                    label: "%left".to_string(),
                    kind: NodeKind::Value {
                        scope: Scope::Module,
                    },
                },
                Node {
                    id: NodeId(1),
                    label: "%right".to_string(),
                    kind: NodeKind::Value {
                        scope: Scope::Module,
                    },
                },
            ],
            edges: Vec::new(),
            callsites: vec![frontier_test_callsite(0), frontier_test_callsite(1)],
            omega_seeds: Vec::new(),
        };
        let mut solver = Solver::new(&pir, &pag, BuildMode::Library);
        solver.classes[0].icall_sites.insert(0);
        solver.classes[0].fn_objs.insert(0);
        solver.process_class(0);
        solver.classes[1].icall_sites.insert(1);
        solver.classes[1].fn_objs.insert(1);
        solver.process_class(1);

        assert_eq!(solver.metrics.steens_candidate_pairs, 2);
        assert_eq!(solver.metrics.steens_seen_pairs_new, 2);
        assert_eq!(solver.metrics.steens_indirect_bindings, 2);

        let root = solver.join(0, 1);
        solver.process_class(root);

        assert_eq!(solver.metrics.steens_seen_pairs_new, 4);
        assert_eq!(solver.metrics.steens_indirect_bindings, 4);
        assert_eq!(solver.metrics.steens_seen_pairs_duplicate, 1);
        assert_eq!(solver.metrics.steens_candidate_pairs, 5);

        let root = solver.find(root);
        solver.process_class(root);
        assert_eq!(solver.metrics.steens_candidate_pairs, 5);
        assert_eq!(solver.metrics.steens_seen_pairs_duplicate, 1);
    }

    #[test]
    fn steens_external_frontier_processes_only_new_sites_after_join() {
        let pir = Pir {
            module: "external_frontier_merge".to_string(),
            source: None,
            lowering: Default::default(),
            functions: Vec::new(),
            globals: Vec::new(),
            global_init: Vec::new(),
        };
        let pag = Pag {
            module: pir.module.clone(),
            source: None,
            metrics: Default::default(),
            nodes: vec![
                Node {
                    id: NodeId(0),
                    label: "%left".to_string(),
                    kind: NodeKind::Value {
                        scope: Scope::Module,
                    },
                },
                Node {
                    id: NodeId(1),
                    label: "%right".to_string(),
                    kind: NodeKind::Value {
                        scope: Scope::Module,
                    },
                },
            ],
            edges: Vec::new(),
            callsites: vec![frontier_test_callsite(0), frontier_test_callsite(1)],
            omega_seeds: Vec::new(),
        };
        let mut solver = Solver::new(&pir, &pag, BuildMode::Library);
        solver.classes[0].ext = true;
        solver.classes[0].icall_sites.insert(0);
        solver.process_class(0);
        solver.process_class(0);

        assert_eq!(solver.metrics.steens_external_call_requests, 1);
        assert_eq!(solver.metrics.steens_external_call_applications, 1);

        solver.classes[1].icall_sites.insert(1);
        let root = solver.join(0, 1);
        solver.process_class(root);
        solver.process_class(root);

        assert_eq!(solver.metrics.steens_external_call_requests, 2);
        assert_eq!(solver.metrics.steens_external_call_applications, 2);
    }

    #[test]
    fn steens_narrows_indirect_targets_and_tracks_escape() {
        let pir = Pir::from_path(fixture("steens_escape_icall.pir.json")).unwrap();
        let pag = Pag::from_pir(
            &pir,
            &PagOpts {
                build_mode: BuildMode::Library,
                ..PagOpts::default()
            },
        );

        let result = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert_eq!(result.indirect_calls.len(), 1);
        assert_eq!(result.indirect_calls[0].callsite_key, "setup@!noloc#0");
        assert_eq!(result.indirect_calls[0].targets, vec!["cb".to_string()]);
        assert!(result.indirect_calls[0].unknown_callee);
        assert!(result.unknown_callers.contains("cb"));
        assert!(!result.unknown_callers.contains("other"));
        assert!(result.globals["@CB"].escape_external);
        assert!(!result.globals["@CB"].never_written);
        assert!(!result.globals["@Local"].escape_external);
        assert!(result.globals["@Local"].never_written);
        assert!(result.metrics.partition_count > 0);
    }

    #[test]
    fn ptrtoint_marks_the_pointee_class_escaped() {
        let pir = Pir::from_path(fixture("ptrtoint_escape.pir.json")).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());

        let result = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert!(result.indirect_calls.is_empty());
        assert!(result.unknown_callers.is_empty());
        assert!(result.globals["@G"].escape_external);
        assert!(!result.globals["@G"].never_written);
    }

    #[test]
    fn points_to_accessor_is_gated_and_lists_known_allocations() {
        let pir = Pir::from_path(fixture("steens_escape_icall.pir.json")).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());

        // Off by default: the `analyze` pipeline pays nothing for points-to materialization.
        assert!(solve_steensgaard(&pir, &pag, BuildMode::Library)
            .node_points_to
            .is_empty());

        // On demand it materializes allocation-level points-to, and every listed allocation is a
        // real global/function key. The icall operand points to the `cb` callback.
        let with_pt = solve_steensgaard_with_points_to(&pir, &pag, BuildMode::Library);
        assert!(!with_pt.node_points_to.is_empty());
        let known: BTreeSet<&str> = pir
            .globals
            .iter()
            .map(|g| g.key.as_str())
            .chain(pir.functions.iter().map(|f| f.key.as_str()))
            .collect();
        for allocs in with_pt.node_points_to.values() {
            for alloc in allocs {
                assert!(known.contains(alloc.as_str()), "unknown alloc {alloc}");
            }
        }
        assert!(with_pt
            .node_points_to
            .values()
            .any(|allocs| allocs.contains("cb")));

        let with_global_pt =
            solve_steensgaard_with_global_points_to(&pir, &pag, BuildMode::Library);
        assert!(!with_global_pt.node_points_to.is_empty());
        assert!(with_global_pt
            .node_points_to
            .keys()
            .all(|key| key.starts_with("obj:global:")));
        assert!(with_global_pt.node_points_to.len() <= with_pt.node_points_to.len());
    }

    #[test]
    fn inttoptr_keeps_only_unknown_indirect_call_targets() {
        let pir = Pir::from_path(fixture("inttoptr_unknown_call.pir.json")).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());

        let result = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert_eq!(result.indirect_calls.len(), 1);
        assert_eq!(result.indirect_calls[0].callsite_key, "driver@!noloc#0");
        assert!(result.indirect_calls[0].targets.is_empty());
        assert!(result.indirect_calls[0].unknown_callee);
        assert!(!result.unknown_callers.contains("cb"));
        assert!(!result.globals["@G"].escape_external);
        assert!(result.globals["@G"].never_written);
    }

    #[test]
    fn external_call_marks_pointer_argument_targets_escaped() {
        let pir = Pir::from_path(fixture("external_call_arg_escape.pir.json")).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());

        let result = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert!(result.indirect_calls.is_empty());
        assert!(result.unknown_callers.contains("ext_decl"));
        assert!(result.globals["@Esc"].escape_external);
        assert!(!result.globals["@Esc"].never_written);
        assert!(!result.globals["@Local"].escape_external);
        assert!(result.globals["@Local"].never_written);
    }

    #[test]
    fn unknown_operand_and_result_seed_escape_and_unknown_call() {
        let pir = Pir::from_path(fixture("unknown_op_escape.pir.json")).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());

        let result = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert_eq!(result.indirect_calls.len(), 1);
        assert_eq!(result.indirect_calls[0].callsite_key, "driver@!noloc#0");
        assert!(result.indirect_calls[0].targets.is_empty());
        assert!(result.indirect_calls[0].unknown_callee);
        assert!(result.globals["@Esc"].escape_external);
        assert!(!result.globals["@Esc"].never_written);
        assert!(!result.globals["@Local"].escape_external);
        assert!(result.globals["@Local"].never_written);
    }

    #[test]
    fn escaped_function_return_marks_return_pointee_escaped() {
        let pir = Pir::from_path(fixture("escaped_fn_return_escape.pir.json")).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());

        let result = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert!(result.unknown_callers.contains("cb"));
        assert!(result.globals["@CB"].escape_external);
        assert!(!result.globals["@CB"].never_written);
        assert!(result.globals["@Ret"].escape_external);
        assert!(!result.globals["@Ret"].never_written);
        assert!(!result.globals["@Local"].escape_external);
        assert!(result.globals["@Local"].never_written);
    }

    #[test]
    fn store_through_unknown_pointer_escapes_stored_targets() {
        let pir = Pir::from_path(fixture("store_through_unknown_escape.pir.json")).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());

        let result = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert!(result.indirect_calls.is_empty());
        assert!(result.unknown_callers.is_empty());
        assert!(result.globals["@Esc"].escape_external);
        assert!(!result.globals["@Esc"].never_written);
        assert!(!result.globals["@Local"].escape_external);
        assert!(result.globals["@Local"].never_written);
    }

    #[test]
    fn escaped_function_parameter_binding_marks_param_value_unknown_origin() {
        let pir = Pir::from_path(fixture("escaped_fn_param_escape.pir.json")).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());

        let result = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert!(result.unknown_callers.contains("cb"));
        assert!(result.globals["@CB"].escape_external);
        assert!(!result.globals["@CB"].never_written);
        assert!(result.globals["@Esc"].escape_external);
        assert!(!result.globals["@Esc"].never_written);
        assert!(!result.globals["@Local"].escape_external);
        assert!(result.globals["@Local"].never_written);
    }

    #[test]
    fn vararg_boundary_escapes_function_pointer_actuals() {
        let pir = Pir::from_path(fixture_m1_5("vararg_fnptr_flow.pir.json")).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());

        let result = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert!(result.unknown_callers.contains("cb"));
    }
}
