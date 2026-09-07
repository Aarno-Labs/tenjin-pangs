use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::ops::Deref;
use std::sync::Arc;
use std::time::Instant;

use pangs_pag::{
    allocation_storage_roots, trusted_free_call, BuildMode, CallKind, NodeId, NodeKind, ObjectKind,
    OmegaSeedKind, Pag, SeedTarget, StorageRoot, StorageRootState, StorageRoots,
};
use pangs_pir::{fsa_compatible, Pir, Signature};
use serde::{Deserialize, Serialize};

mod andersen;
mod cfl;
mod knobs;
pub use andersen::{
    andersen_admission_census, solve_andersen, solve_andersen_with_global_points_to,
    solve_andersen_with_overrides, solve_andersen_with_overrides_and_target_points_to,
    AdmissionStructureProfile,
};

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
    /// Whether the partition-scoped Andersen tier reached its joint points-to/call-graph
    /// fixed point. A false value means every non-exact Andersen output was discarded and
    /// the result retains its complete Steensgaard fallback.
    #[serde(default = "default_true")]
    pub andersen_complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub andersen_exhaustion_reason: Option<String>,
    #[serde(default)]
    pub andersen_steps: usize,
    #[serde(default)]
    pub andersen_resume_rounds: usize,
    #[serde(default)]
    pub andersen_activated_targets: usize,
    #[serde(default)]
    pub andersen_known_unbound_targets: usize,
    #[serde(default)]
    pub andersen_coarser_than_steens_nodes: usize,
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
    pub steens_content_edges: u64,
    #[serde(default)]
    pub steens_content_pushes: u64,
    #[serde(default)]
    pub steens_unify_pointees_shared: u64,
    #[serde(default)]
    pub steens_max_class_icall_sites: usize,
    #[serde(default)]
    pub steens_max_class_fn_objs: usize,
    #[serde(default)]
    pub steens_max_class_candidate_pairs: u64,
    #[serde(default)]
    pub steens_gep_replay_transfers: u64,
    #[serde(default)]
    pub steens_gep_region_shifts: u64,
    #[serde(default)]
    pub steens_gep_missing_exact_widenings: u64,
    #[serde(default)]
    pub steens_gep_lane_cap_widenings: u64,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SolveResult {
    /// In-memory soundness certificate shared with API ModRef construction.  It is deliberately
    /// not serialized: loading an old solve cannot authorize derived-address filtering.
    #[serde(skip)]
    pub storage_roots: StorageRoots,
    #[serde(default)]
    pub indirect_calls: Vec<IndirectCallResolution>,
    #[serde(default)]
    pub unknown_callers: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub function_escapes: BTreeMap<String, FunctionResolution>,
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
    /// Named allocations reachable by loading from memory designated by a targeted node:
    /// node -> pointee memory -> stored pointer target. This is populated only for the same
    /// narrow label set as `node_points_to`, for registry operands such as `sigaction`'s
    /// `struct sigaction *` argument.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub node_pointee_points_to: BTreeMap<String, BTreeSet<String>>,
    /// Targeted nodes whose reachable pointee memory may contain an external/unknown pointer,
    /// with the boundary sources that caused that uncertainty. A registry consumer can exclude
    /// its own call boundary: passing a local input struct to `sigaction` makes the struct escape
    /// at that call, but does not make its entry-time handler value unknown.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub node_pointee_external: BTreeMap<String, BTreeSet<String>>,
    #[serde(default)]
    pub metrics: SolveMetrics,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionResolution {
    pub address_escape: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub escape_sources: Vec<String>,
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
    /// Diagnostic only: how many address-taken function objects the pointer solution placed
    /// in this operand's pointee set, before the FSA signature filter ran. `targets` remains
    /// the authoritative post-filter answer; nothing reads either counter for soundness.
    #[serde(default)]
    pub prefsa_targets: usize,
    /// Diagnostic only: how many of `prefsa_targets` the FSA signature envelope rejected —
    /// the per-site count of callees the pointer solution proposed and only the type
    /// envelope excluded (Clash's `escape_number` in `~/tmp/clash`).
    #[serde(default)]
    pub fsa_rejected_targets: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlobalResolution {
    pub escape_external: bool,
    #[serde(default)]
    pub address_escape: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub escape_sources: Vec<String>,
    pub never_written: bool,
    /// Whether a store edge owned by runtime function code may reach this object.
    /// Static-initializer stores are deliberately excluded.
    #[serde(default)]
    pub runtime_written: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeResolution {
    pub reaches_function_pointer: bool,
    /// A positive witness says that the value may denote no allocation or function object. It is
    /// kept independently of the points-to set so an empty set is never overloaded as either a
    /// certified empty value or analysis silence.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub has_empty_witness: bool,
    /// The value is proven empty: it has an empty witness, no allocation pointee, and carries no
    /// external provenance.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub proven_empty: bool,
    #[serde(default)]
    pub external: bool,
    /// Internal scope selector for external rows that explicitly include every externally
    /// escaped global. This is not provenance and is not serialized by any artifact.
    #[serde(skip)]
    pub external_escaped_union: bool,
    #[serde(default)]
    pub pointee_globals: SharedStringList,
    /// The pre-filter solver enumeration, emitted only when address-exposure
    /// filtering removed at least one candidate.  Differential checks can reconstruct the
    /// envelope as this list when non-empty, or `pointee_globals` otherwise.
    #[serde(default, skip_serializing_if = "SharedStringList::is_empty")]
    pub pointee_globals_unfiltered: SharedStringList,
    /// Diagnostic provenance accumulated by the solver class that produced the post-filter
    /// pointee set. These labels explain which precision-losing mechanisms participated; they
    /// are not certificates and never affect solving or eligibility.
    #[serde(default, skip_serializing_if = "SharedProvenanceList::is_empty")]
    pub pointee_provenance: SharedProvenanceList,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external_sources: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PointeeProvenance {
    DirectAddressFlow,
    ScalarOrUnknownPayload,
    ByValueAggregateBinding,
    MemoryMerging,
    CallReturnMerging,
    FiniteExternalRegion,
}

impl PointeeProvenance {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DirectAddressFlow => "direct_address_flow",
            Self::ScalarOrUnknownPayload => "scalar_or_unknown_payload",
            Self::ByValueAggregateBinding => "by_value_aggregate_binding",
            Self::MemoryMerging => "memory_merging",
            Self::CallReturnMerging => "call_return_merging",
            Self::FiniteExternalRegion => "finite_external_region",
        }
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct SharedProvenanceList(Arc<[PointeeProvenance]>);

impl SharedProvenanceList {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Deref for SharedProvenanceList {
    type Target = [PointeeProvenance];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<PointeeProvenance>> for SharedProvenanceList {
    fn from(values: Vec<PointeeProvenance>) -> Self {
        Self(values.into())
    }
}

impl PartialEq<Vec<PointeeProvenance>> for SharedProvenanceList {
    fn eq(&self, other: &Vec<PointeeProvenance>) -> bool {
        self.0.as_ref() == other.as_slice()
    }
}

impl Serialize for SharedProvenanceList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.as_ref().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SharedProvenanceList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Vec::<PointeeProvenance>::deserialize(deserializer).map(Self::from)
    }
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

/// Like [`solve_steensgaard`] but materializes allocation-level points-to only for the
/// requested PAG node labels. This is intended for narrow analysis consumers such as
/// spawn/signal registry operands; it does not turn the normal solve into an all-node export.
pub fn solve_steensgaard_with_target_points_to(
    pir: &Pir,
    pag: &Pag,
    build_mode: BuildMode,
    labels: &BTreeSet<String>,
) -> SolveResult {
    let mut solver = Solver::new(pir, pag, build_mode);
    solver.points_to_materialization = PointsToMaterialization::Targeted;
    solver.points_to_labels = labels.clone();
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
    solve_steensgaard_classes_materialized(pir, pag, build_mode, PointsToMaterialization::None)
}

/// Like [`solve_steensgaard_with_classes`] but also materializes `SolveResult::node_points_to`
/// per `materialization`. The Andersen pass uses this to seed a Steensgaard global-object
/// points-to fallback (`solve_andersen_with_global_points_to`) for partitions it does not refine.
pub(crate) fn solve_steensgaard_classes_materialized(
    pir: &Pir,
    pag: &Pag,
    build_mode: BuildMode,
    materialization: PointsToMaterialization,
) -> (SolveResult, SteensClasses) {
    let mut solver = Solver::new(pir, pag, build_mode);
    solver.points_to_materialization = materialization;
    solver.run();
    let classes = solver.export_classes();
    let result = solver.finish();
    (result, classes)
}

pub(crate) fn solve_steensgaard_classes_targeted(
    pir: &Pir,
    pag: &Pag,
    build_mode: BuildMode,
    labels: &BTreeSet<String>,
) -> (SolveResult, SteensClasses) {
    let mut solver = Solver::new(pir, pag, build_mode);
    solver.points_to_materialization = PointsToMaterialization::Targeted;
    solver.points_to_labels = labels.clone();
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
    /// `ext[root]` — the class identity may denote external memory (PIP `p ⊒ Ω`).
    /// Externally reachable local storage remains represented separately by `esc`.
    pub ext: Vec<bool>,
    /// `esc[root]` — class members are reachable by external code (PIP `Ω ⊒ {x}`).
    pub esc: Vec<bool>,
    /// The class contains a global allocation or one of its allocation-relative fields.
    /// Field-aware partitioning uses this to keep synthetic global-field partitions interesting.
    pub global_storage: Vec<bool>,
    /// One bit per PIR global. False proves that the global symbol is used only as the
    /// address operand of direct memory accesses.
    pub global_address_exposed: Vec<bool>,
    /// Storage reachable by assumption violations. Modeled inline assembly names its exact
    /// pointer-capable operand/result nodes; only opaque assembly defeats exposure filtering
    /// module-wide.
    pub violation_exposure: ViolationExposure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViolationExposure {
    Finite(BTreeSet<NodeId>),
    ModuleWide,
}

impl Default for ViolationExposure {
    fn default() -> Self {
        Self::Finite(BTreeSet::new())
    }
}

impl SteensClasses {
    /// Class root of a PAG node.
    pub fn class_of(&self, node: NodeId) -> usize {
        self.node_class[node.0 as usize]
    }
}

#[derive(Debug, Default)]
struct AllocationIsolation {
    address: BTreeSet<String>,
    write: BTreeSet<String>,
}

/// Prove, independently of Steensgaard class identity, whether selected global allocations have
/// isolated addresses and, separately, whether they are never written after initialization.
///
/// This deliberately tracks only the address of an allocation, not values stored in it.  The
/// supported flow operations are exhaustive for the PAG: address-of, assign, GEP (including
/// unknown offsets), pointer-bearing stores matched to loads through alias-equivalent addresses,
/// direct-call bindings already present as Assign edges, and solved internal indirect-call
/// bindings added below. If a containing address reaches an unknown boundary, so does every
/// pointer stored in it. Any unmodeled/external use still rejects the proof. A store *through* the
/// derived address invalidates write isolation but does not by itself make the address escape.
/// Consequently each successful result can safely narrow its corresponding union-induced
/// class-level fact without narrowing pointer behavior.
fn allocation_isolation(
    pir: &Pir,
    pag: &Pag,
    indirect_calls: &[IndirectCallResolution],
    unknown_callers: &BTreeSet<String>,
) -> AllocationIsolation {
    let mut flow = vec![Vec::<NodeId>::new(); pag.nodes.len()];
    for edge in &pag.edges {
        let pointer_flow = match edge.kind {
            pangs_pag::EdgeKind::AddrOf | pangs_pag::EdgeKind::Gep { .. } => true,
            pangs_pag::EdgeKind::Assign => {
                pag.nodes[edge.src.0 as usize]
                    .value_kind
                    .may_carry_pointer()
                    && pag.nodes[edge.dst.0 as usize]
                        .value_kind
                        .may_carry_pointer()
            }
            pangs_pag::EdgeKind::Load
            | pangs_pag::EdgeKind::Store
            | pangs_pag::EdgeKind::Memcpy { .. } => false,
        };
        if pointer_flow {
            flow[edge.src.0 as usize].push(edge.dst);
        }
    }

    // Follow pointer values through module memory without confusing a container's address with
    // its contents. Assign/GEP-connected address carriers form conservative alias components;
    // each pointer store flows to every pointer load from the same component. The additional
    // source -> destination-address edge makes an escaped container reject every captured value.
    let mut address_aliases = vec![Vec::<NodeId>::new(); pag.nodes.len()];
    for edge in &pag.edges {
        if matches!(
            edge.kind,
            pangs_pag::EdgeKind::Assign | pangs_pag::EdgeKind::Gep { .. }
        ) && pag.nodes[edge.src.0 as usize]
            .value_kind
            .may_carry_pointer()
            && pag.nodes[edge.dst.0 as usize]
                .value_kind
                .may_carry_pointer()
        {
            address_aliases[edge.src.0 as usize].push(edge.dst);
            address_aliases[edge.dst.0 as usize].push(edge.src);
        }
    }
    let mut address_component = vec![usize::MAX; pag.nodes.len()];
    let mut next_component = 0_usize;
    for start in 0..pag.nodes.len() {
        if address_component[start] != usize::MAX {
            continue;
        }
        address_component[start] = next_component;
        let mut queue = VecDeque::from([NodeId(start as u32)]);
        while let Some(node) = queue.pop_front() {
            for &next in &address_aliases[node.0 as usize] {
                if address_component[next.0 as usize] == usize::MAX {
                    address_component[next.0 as usize] = next_component;
                    queue.push_back(next);
                }
            }
        }
        next_component += 1;
    }
    let mut pointer_loads = vec![Vec::<NodeId>::new(); next_component];
    for edge in &pag.edges {
        if edge.kind == pangs_pag::EdgeKind::Load
            && pag.nodes[edge.dst.0 as usize]
                .value_kind
                .may_carry_pointer()
        {
            pointer_loads[address_component[edge.src.0 as usize]].push(edge.dst);
        }
    }
    for edge in &pag.edges {
        if edge.kind != pangs_pag::EdgeKind::Store
            || !pag.nodes[edge.src.0 as usize]
                .value_kind
                .may_carry_pointer()
        {
            continue;
        }
        flow[edge.src.0 as usize].push(edge.dst);
        flow[edge.src.0 as usize].extend(
            pointer_loads[address_component[edge.dst.0 as usize]]
                .iter()
                .copied(),
        );
    }

    let mut params: HashMap<(String, u32), NodeId> = HashMap::new();
    let mut returns: HashMap<String, NodeId> = HashMap::new();
    let mut global_objects: HashMap<String, NodeId> = HashMap::new();
    let mut unknown_parameter_seeds = Vec::new();
    for node in &pag.nodes {
        match &node.kind {
            NodeKind::Param { func, index } => {
                params.insert((func.clone(), *index), node.id);
            }
            NodeKind::Return { func } => {
                returns.insert(func.clone(), node.id);
            }
            NodeKind::Object {
                object: ObjectKind::Global,
                key,
                ..
            } => {
                global_objects.insert(key.clone(), node.id);
            }
            _ => {}
        }
    }

    let functions: HashMap<&str, &pangs_pir::Func> = pir
        .functions
        .iter()
        .map(|func| (func.key.as_str(), func))
        .collect();
    let resolutions: HashMap<&str, &IndirectCallResolution> = indirect_calls
        .iter()
        .map(|resolution| (resolution.callsite_key.as_str(), resolution))
        .collect();
    let mut unsafe_indirect_sites = BTreeSet::new();
    for callsite in &pag.callsites {
        if callsite.kind != CallKind::Indirect {
            continue;
        }
        let Some(resolution) = resolutions.get(callsite.key.as_str()) else {
            unsafe_indirect_sites.insert(callsite.id);
            continue;
        };
        let mut unsafe_site = resolution.unknown_callee || resolution.targets.is_empty();
        for target in &resolution.targets {
            let Some(function) = functions.get(target.as_str()) else {
                unsafe_site = true;
                continue;
            };
            if function.external {
                unsafe_site = true;
                continue;
            }
            for (index, &arg) in callsite.args.iter().enumerate() {
                if let Some(&param) = params.get(&(target.clone(), index as u32)) {
                    if pag.nodes[arg.0 as usize].value_kind.may_carry_pointer()
                        && pag.nodes[param.0 as usize].value_kind.may_carry_pointer()
                    {
                        flow[arg.0 as usize].push(param);
                    }
                }
            }
            if let (Some(&ret), Some(result)) = (returns.get(target), callsite.result) {
                if pag.nodes[ret.0 as usize].value_kind.may_carry_pointer()
                    && pag.nodes[result.0 as usize].value_kind.may_carry_pointer()
                {
                    flow[ret.0 as usize].push(result);
                }
            }
        }
        if unsafe_site {
            unsafe_indirect_sites.insert(callsite.id);
        }
    }

    let reachable = |adjacency: &[Vec<NodeId>], seeds: &[NodeId]| {
        let mut reached = vec![false; pag.nodes.len()];
        let mut queue = VecDeque::new();
        for &seed in seeds {
            if !reached[seed.0 as usize] {
                reached[seed.0 as usize] = true;
                queue.push_back(seed);
            }
        }
        while let Some(node) = queue.pop_front() {
            for &next in &adjacency[node.0 as usize] {
                if !reached[next.0 as usize] {
                    reached[next.0 as usize] = true;
                    queue.push_back(next);
                }
            }
        }
        reached
    };

    // Keep forged-pointer provenance separate from allocation-address provenance.  A forged
    // pointer defeats the certificate for a particular allocation only when the two
    // address-preserving closures meet.  In particular, `flow` deliberately contains no Load
    // edge: loading a pointer stored in a global follows the global's contents, not an address
    // derived from the global's storage.
    let forged_seeds = pag
        .omega_seeds
        .iter()
        .filter_map(|seed| {
            (seed.kind == OmegaSeedKind::IntToPtr)
                .then_some(seed.target)
                .and_then(|target| match target {
                    SeedTarget::Node(node) => Some(node),
                    SeedTarget::Callsite(_) => None,
                })
        })
        .collect::<Vec<_>>();
    let forged = reachable(&flow, &forged_seeds);

    let runtime_direct_writes = pir
        .functions
        .iter()
        .flat_map(|func| &func.body)
        .filter_map(|stmt| match stmt {
            pangs_pir::Stmt::GlobalRef {
                global,
                access: pangs_pir::Access::Mod,
                ..
            } => Some(global.as_str()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();

    // A global's forward closure reaches a blocker exactly when its object is in the blocker's
    // reverse closure. Build the two blocker sets once, then answer every global with two bit
    // lookups instead of traversing and rescanning the PAG once per global.
    let mut address_blockers = vec![false; pag.nodes.len()];
    let mut write_blockers = vec![false; pag.nodes.len()];
    for (index, &reached) in forged.iter().enumerate() {
        if reached {
            address_blockers[index] = true;
        }
    }

    for edge in &pag.edges {
        match edge.kind {
            pangs_pag::EdgeKind::Store => {
                // Writing through the derived address is a runtime mutation. Storing the
                // derived address as a value is followed by the conservative pointer-content
                // flow above, so it is no longer an immediate address-isolation failure.
                if matches!(edge.owner, pangs_pag::Owner::Function(_)) {
                    write_blockers[edge.dst.0 as usize] = true;
                }
            }
            pangs_pag::EdgeKind::Memcpy { .. }
                if matches!(edge.owner, pangs_pag::Owner::Function(_)) =>
            {
                write_blockers[edge.dst.0 as usize] = true;
            }
            _ => {}
        }
    }

    for seed in &pag.omega_seeds {
        match seed.target {
            SeedTarget::Node(node)
                if matches!(
                    seed.kind,
                    OmegaSeedKind::ExportedSymbol
                        | OmegaSeedKind::PtrToInt
                        | OmegaSeedKind::UnknownOperandEscape
                        | OmegaSeedKind::UnknownResultExternal
                ) =>
            {
                address_blockers[node.0 as usize] = true;
            }
            SeedTarget::Callsite(id) => {
                let Some(callsite) = pag.callsites.get(id.0 as usize) else {
                    // Preserve the existing fail-closed behavior: a malformed callsite seed
                    // prevents every allocation-isolation certificate.
                    return AllocationIsolation::default();
                };
                for &node in callsite.args.iter().chain(callsite.operand.iter()) {
                    address_blockers[node.0 as usize] = true;
                }
            }
            _ => {}
        }
    }

    for callsite in &pag.callsites {
        if callsite.external_boundary || unsafe_indirect_sites.contains(&callsite.id) {
            for &node in callsite.args.iter().chain(callsite.operand.iter()) {
                address_blockers[node.0 as usize] = true;
            }
        }
    }

    for node in &pag.nodes {
        if matches!(&node.kind, NodeKind::Return { func } if unknown_callers.contains(func)) {
            address_blockers[node.id.0 as usize] = true;
        }
        if matches!(&node.kind, NodeKind::Param { func, .. } if unknown_callers.contains(func)) {
            address_blockers[node.id.0 as usize] = true;
            unknown_parameter_seeds.push(node.id);
        }
    }

    // The named SSA value for a parameter is an Assign successor of its Param node. Mark the
    // conservative forward closure of externally supplied parameters so a store through `%p`
    // is recognized as writing into externally controlled storage.
    for (blocked, reached) in address_blockers
        .iter_mut()
        .zip(reachable(&flow, &unknown_parameter_seeds))
    {
        *blocked |= reached;
    }

    // Export seeds name object nodes while stores and calls use the corresponding address value.
    // Mark that one AddrOf carrier without closing through Assign/phi: closing forward there
    // would conflate an escaped alternative with every other phi input and defeat the allocation
    // provenance proof this routine exists to preserve.
    for edge in &pag.edges {
        if edge.kind == pangs_pag::EdgeKind::AddrOf && address_blockers[edge.src.0 as usize] {
            address_blockers[edge.dst.0 as usize] = true;
        }
    }

    for (write_blocked, &address_blocked) in write_blockers.iter_mut().zip(&address_blockers) {
        *write_blocked |= address_blocked;
    }

    let mut reverse_flow = vec![Vec::<NodeId>::new(); pag.nodes.len()];
    for (src, destinations) in flow.iter().enumerate() {
        for &dst in destinations {
            reverse_flow[dst.0 as usize].push(pag.nodes[src].id);
        }
    }
    let blocker_seeds = |blockers: &[bool]| {
        blockers
            .iter()
            .enumerate()
            .filter_map(|(index, &blocked)| blocked.then_some(pag.nodes[index].id))
            .collect::<Vec<_>>()
    };
    let reaches_address_blocker = reachable(&reverse_flow, &blocker_seeds(&address_blockers));
    let reaches_write_blocker = reachable(&reverse_flow, &blocker_seeds(&write_blockers));

    let mut isolated = AllocationIsolation::default();
    for global in &pir.globals {
        let Some(&object) = global_objects.get(&global.key) else {
            continue;
        };
        if !reaches_address_blocker[object.0 as usize] {
            isolated.address.insert(global.key.clone());
            if !reaches_write_blocker[object.0 as usize]
                && !runtime_direct_writes.contains(global.key.as_str())
            {
                isolated.write.insert(global.key.clone());
            }
        }
    }
    isolated
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
    has_empty_witness: bool,
    ext: bool,
    external_escaped_union: bool,
    esc: bool,
    /// A real escape boundary (or its reachable storage), distinct from the synthetic
    /// escape bit used when pushing an external pointer identity through its pointee.
    allocation_escape: bool,
    escape_sources: BTreeSet<ProvenanceId>,
    icall_sites: HashSet<usize>,
    fn_objs: HashSet<usize>,
    processed_icall_sites: HashSet<usize>,
    processed_fn_objs: HashSet<usize>,
    processed_external_icall_sites: HashSet<usize>,
    global_objs: HashSet<usize>,
    provenance: u8,
    /// Classes whose contents include this class's contents. Targets are raw class ids and are
    /// resolved through `find` when the edge fires, just like the other union-find side tables.
    content_succ: Vec<usize>,
    /// Content propagation frontier. Facts are monotone, so unchanged facts need visit only
    /// successors appended since the previous push. A class join resets this compact frontier.
    content_pushed_succ_len: usize,
    content_pushed_ext: bool,
    content_pushed_external_escaped_union: bool,
    content_pushed_empty: bool,
    /// Debug-only semantic roles. A solved class may contain carriers or locations, never both.
    has_carrier: bool,
    has_location: bool,
    /// True when this location class has an ordinary, whole-object alternative.  A class made
    /// solely from allocation-relative cells may be shifted by an uncertified GEP; once it joins
    /// a summary location it must retain that summary alternative instead.
    has_summary_region: bool,
    /// Roots represented by ordinary summary alternatives. A nonzero GEP must connect each to
    /// its own Unknown cell so later materialized fields are not missed.
    summary_roots: BTreeSet<NodeId>,
    /// Reverse identity for allocation-relative cells.  This deliberately survives UF joins:
    /// a cross-root join is a real alias and therefore carries alternatives for every root.
    field_regions: BTreeSet<(NodeId, FieldRegion)>,
    /// Uncertified GEPs are one-hop constraints on this location.  Keeping them here, rather
    /// than applying them once while reading the PAG, replays them after late bindings and UF
    /// joins enlarge the target class.
    gep_succ: Vec<GepTransfer>,
    gep_processed_succ_len: usize,
    gep_processed_region_len: usize,
    gep_processed_summary: bool,
    /// Region inventory already covered by allocation-wide escape. A UF join can only
    /// grow the surviving inventory, so a changed length replays newly discovered roots.
    escape_processed_regions: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct GepTransfer {
    dst: usize,
    delta: FieldLocation,
}

/// Compact identity for a diagnostic provenance string. Provenance flows through the same hot
/// union/find worklist as points-to state, but its text is only needed while materializing the
/// final result. Keeping IDs in classes avoids repeatedly cloning source strings during joins and
/// propagation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct ProvenanceId(u32);

#[derive(Debug, Default)]
struct ProvenanceInterner {
    ids: HashMap<Arc<str>, ProvenanceId>,
    values: Vec<Arc<str>>,
}

impl ProvenanceInterner {
    fn intern(&mut self, source: String) -> ProvenanceId {
        if let Some(&id) = self.ids.get(source.as_str()) {
            return id;
        }
        let value: Arc<str> = source.into();
        let id = ProvenanceId(
            self.values
                .len()
                .try_into()
                .expect("too many provenance sources"),
        );
        self.values.push(value.clone());
        self.ids.insert(value, id);
        id
    }

    fn get(&self, id: ProvenanceId) -> &str {
        &self.values[id.0 as usize]
    }

    fn first_lexicographic<'b>(
        &self,
        sources: impl IntoIterator<Item = &'b ProvenanceId>,
    ) -> Option<ProvenanceId> {
        sources
            .into_iter()
            .copied()
            .min_by(|left, right| self.get(*left).cmp(self.get(*right)))
    }

    fn strings<'b>(&self, sources: impl IntoIterator<Item = &'b ProvenanceId>) -> Vec<String> {
        let mut values = sources
            .into_iter()
            .map(|&id| self.get(id).to_owned())
            .collect::<Vec<_>>();
        values.sort();
        values.dedup();
        values
    }

    fn string_set<'b>(
        &self,
        sources: impl IntoIterator<Item = &'b ProvenanceId>,
    ) -> BTreeSet<String> {
        sources
            .into_iter()
            .map(|&id| self.get(id).to_owned())
            .collect()
    }
}

fn global_storage_roots_index(classes: &[ClassData], global_count: usize) -> Vec<Vec<usize>> {
    let mut roots_by_global = vec![Vec::new(); global_count];
    for (candidate, class) in classes.iter().enumerate() {
        if class.parent != candidate {
            continue;
        }
        for &global_index in &class.global_objs {
            if let Some(roots) = roots_by_global.get_mut(global_index) {
                roots.push(candidate);
            } else {
                debug_assert!(
                    false,
                    "class {candidate} names absent global index {global_index}"
                );
            }
        }
    }
    roots_by_global
}

const PROV_DIRECT_ADDRESS: u8 = 1 << 0;
const PROV_SCALAR_OR_UNKNOWN_PAYLOAD: u8 = 1 << 1;
const PROV_BY_VALUE_AGGREGATE: u8 = 1 << 2;
const PROV_MEMORY_MERGING: u8 = 1 << 3;
const PROV_CALL_RETURN: u8 = 1 << 4;

fn meta_param_is_by_value(sig: &Signature, index: usize) -> bool {
    sig.params
        .get(index)
        .is_some_and(|param| matches!(param, pangs_pir::Param::Byval { .. }))
}

fn pointee_provenance_labels(mask: u8, external: bool) -> Vec<PointeeProvenance> {
    let mut labels = Vec::new();
    for (bit, label) in [
        (PROV_DIRECT_ADDRESS, PointeeProvenance::DirectAddressFlow),
        (
            PROV_SCALAR_OR_UNKNOWN_PAYLOAD,
            PointeeProvenance::ScalarOrUnknownPayload,
        ),
        (
            PROV_BY_VALUE_AGGREGATE,
            PointeeProvenance::ByValueAggregateBinding,
        ),
        (PROV_MEMORY_MERGING, PointeeProvenance::MemoryMerging),
        (PROV_CALL_RETURN, PointeeProvenance::CallReturnMerging),
    ] {
        if mask & bit != 0 {
            labels.push(label);
        }
    }
    if external {
        labels.push(PointeeProvenance::FiniteExternalRegion);
    }
    labels.sort();
    labels.dedup();
    labels
}

#[derive(Clone)]
struct CachedRootNodeSummary {
    reaches_function_pointer: bool,
    has_empty_witness: bool,
    proven_empty: bool,
    external: bool,
    external_escaped_union: bool,
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
    global_object_index_by_node: Vec<Option<usize>>,
    storage_roots: StorageRoots,
    global_address_exposed: Vec<bool>,
    violation_exposure: ViolationExposure,
    exact_addresses: Vec<Option<ExactAddress>>,
    /// Finite, fixed exact vocabulary derived from the PAG certificate.  One-hop arithmetic may
    /// reuse only these exact cells; a new arbitrary exact offset becomes the root summary.
    exact_field_locations: HashMap<NodeId, BTreeSet<FieldLocation>>,
    /// Direct constant GEP deltas are also a finite exact vocabulary for every allocation.
    direct_gep_exact_offsets: BTreeSet<i64>,
    /// Lazily admitted derived lanes.  The fixed PAG vocabulary is finite; this cap prevents a
    /// cyclic or late-bound one-hop replay from manufacturing an unbounded second vocabulary.
    derived_lanes_by_root: HashMap<NodeId, BTreeSet<FieldLocation>>,
    field_classes: HashMap<(NodeId, FieldRegion), usize>,
    fields_by_root: HashMap<NodeId, Vec<usize>>,
    /// Direct per-allocation inventory keeps replay proportional to fields of this allocation,
    /// not to every synthetic field in the module.
    field_inventory: HashMap<NodeId, Vec<(FieldRegion, usize)>>,
    /// Allocation-specific escape sources for certified fields. Retain this precision when
    /// legacy unification merges the allocation's owner class with unrelated objects.
    field_escape_sources_by_root: HashMap<NodeId, BTreeSet<ProvenanceId>>,
    provenance: ProvenanceInterner,
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
    points_to_labels: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PointsToMaterialization {
    None,
    AllNodes,
    GlobalObjects,
    Targeted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExactAddress {
    root: NodeId,
    location: FieldLocation,
    via_gep: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum FieldLocation {
    Exact(i64),
    Lane(pangs_pir::GepLane),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct FieldRegion {
    location: FieldLocation,
    /// `Some(0)` denotes an address identity, while `None` is an access of unknown extent.
    width: Option<u64>,
}

impl FieldRegion {
    fn address(location: FieldLocation) -> Self {
        Self {
            location,
            width: Some(0),
        }
    }

    fn access(location: FieldLocation, width: Option<u64>) -> Self {
        Self { location, width }
    }

    fn may_overlap(self, other: Self) -> bool {
        if matches!(self.location, FieldLocation::Unknown)
            || matches!(other.location, FieldLocation::Unknown)
        {
            return true;
        }
        let (Some(lhs_width), Some(rhs_width)) = (self.width, other.width) else {
            return true;
        };
        // Address identities occupy one byte for overlap purposes. This connects a GEP's
        // storage identity to a wider load/store/memcpy covering that address, while two
        // distinct zero-width legacy accesses remain separate.
        let lhs_width = lhs_width.max(1);
        let rhs_width = rhs_width.max(1);

        match (self.location, other.location) {
            (FieldLocation::Exact(lhs), FieldLocation::Exact(rhs)) => {
                let lhs = i128::from(lhs);
                let rhs = i128::from(rhs);
                lhs < rhs + i128::from(rhs_width) && rhs < lhs + i128::from(lhs_width)
            }
            (FieldLocation::Exact(exact), FieldLocation::Lane(lane)) => {
                lane_overlaps_exact(lane, rhs_width, exact, lhs_width)
            }
            (FieldLocation::Lane(lane), FieldLocation::Exact(exact)) => {
                lane_overlaps_exact(lane, lhs_width, exact, rhs_width)
            }
            (FieldLocation::Lane(lhs), FieldLocation::Lane(rhs)) => {
                let modulus = gcd_u64(lhs.modulus, rhs.modulus);
                let residue_delta = i128::from(lhs.residue) - i128::from(rhs.residue);
                congruence_in_range(
                    residue_delta,
                    modulus,
                    -(i128::from(lhs_width) - 1),
                    i128::from(rhs_width) - 1,
                )
            }
            (FieldLocation::Unknown, _) | (_, FieldLocation::Unknown) => true,
        }
    }
}

fn lane_overlaps_exact(
    lane: pangs_pir::GepLane,
    lane_width: u64,
    exact: i64,
    exact_width: u64,
) -> bool {
    congruence_in_range(
        i128::from(lane.residue) - i128::from(exact),
        lane.modulus,
        -(i128::from(lane_width) - 1),
        i128::from(exact_width) - 1,
    )
}

fn congruence_in_range(residue: i128, modulus: u64, min: i128, max: i128) -> bool {
    if min > max {
        return false;
    }
    let modulus = i128::from(modulus);
    let normalized = residue.rem_euclid(modulus);
    let first = min + (normalized - min).rem_euclid(modulus);
    first <= max
}

impl FieldLocation {
    fn from_gep(byte_off: Option<i64>, lane: Option<pangs_pir::GepLane>) -> Self {
        byte_off
            .map(Self::Exact)
            .or_else(|| {
                lane.and_then(|lane| pangs_pir::GepLane::new(lane.modulus, lane.residue))
                    .map(Self::Lane)
            })
            .unwrap_or(Self::Unknown)
    }

    fn add(self, delta: Self) -> Self {
        match (self, delta) {
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::Exact(lhs), Self::Exact(rhs)) => lhs
                .checked_add(rhs)
                .map(Self::Exact)
                .unwrap_or(Self::Unknown),
            (Self::Lane(lane), Self::Exact(off)) | (Self::Exact(off), Self::Lane(lane)) => {
                lane.shifted(off).map(Self::Lane).unwrap_or(Self::Unknown)
            }
            (Self::Lane(lhs), Self::Lane(rhs)) => {
                lhs.combined(rhs).map(Self::Lane).unwrap_or(Self::Unknown)
            }
        }
    }

    fn may_alias(self, other: Self) -> bool {
        match (self, other) {
            (Self::Unknown, _) | (_, Self::Unknown) => true,
            (Self::Exact(lhs), Self::Exact(rhs)) => lhs == rhs,
            (Self::Exact(exact), Self::Lane(lane)) | (Self::Lane(lane), Self::Exact(exact)) => {
                let modulus = i64::try_from(lane.modulus).expect("normalized GEP lane modulus");
                exact.rem_euclid(modulus) == lane.residue
            }
            (Self::Lane(lhs), Self::Lane(rhs)) => {
                let modulus = gcd_u64(lhs.modulus, rhs.modulus);
                let modulus = i64::try_from(modulus).expect("normalized GEP lane modulus");
                lhs.residue.rem_euclid(modulus) == rhs.residue.rem_euclid(modulus)
            }
        }
    }
}

fn gcd_u64(mut lhs: u64, mut rhs: u64) -> u64 {
    while rhs != 0 {
        (lhs, rhs) = (rhs, lhs % rhs);
    }
    lhs
}

/// Independently derive allocation-relative addresses from the fixed PAG. This is deliberately
/// weaker than points-to analysis: address-of seeds a root, GEP preserves it, and an Assign join
/// is retained only when every incoming alternative names the same root. A differing offset
/// becomes the root's unknown-offset summary; loads and all other producers stop the proof.
fn exact_allocation_addresses(
    pag: &Pag,
    storage_roots: &StorageRoots,
) -> Vec<Option<ExactAddress>> {
    let mut addresses = vec![None; pag.nodes.len()];
    let mut producers = BTreeMap::<NodeId, Vec<&pangs_pag::Edge>>::new();
    for edge in &pag.edges {
        if matches!(
            edge.kind,
            pangs_pag::EdgeKind::AddrOf
                | pangs_pag::EdgeKind::Assign
                | pangs_pag::EdgeKind::Load
                | pangs_pag::EdgeKind::Gep { .. }
        ) {
            producers.entry(edge.dst).or_default().push(edge);
        }
    }
    for (&destination, incoming) in &producers {
        if incoming.len() != 1 || incoming[0].kind != pangs_pag::EdgeKind::AddrOf {
            continue;
        }
        if let Some(StorageRootState::Root(root)) = storage_roots.states.get(destination.0 as usize)
        {
            addresses[destination.0 as usize] = Some(ExactAddress {
                root: root.object_node(),
                location: FieldLocation::Exact(0),
                via_gep: false,
            });
        }
    }

    let mut changed = true;
    while changed {
        changed = false;
        for (&dst, incoming) in &producers {
            if addresses[dst.0 as usize].is_some() || incoming.is_empty() {
                continue;
            }
            let Some(StorageRootState::Root(certified_root)) =
                storage_roots.states.get(dst.0 as usize)
            else {
                continue;
            };
            let candidate = match incoming[0].kind {
                pangs_pag::EdgeKind::Gep { byte_off, lane } if incoming.len() == 1 => {
                    addresses[incoming[0].src.0 as usize].map(|base| ExactAddress {
                        root: base.root,
                        location: base.location.add(FieldLocation::from_gep(byte_off, lane)),
                        via_gep: true,
                    })
                }
                pangs_pag::EdgeKind::Assign
                    if incoming
                        .iter()
                        .all(|edge| edge.kind == pangs_pag::EdgeKind::Assign) =>
                {
                    let alternatives = incoming.iter().try_fold(Vec::new(), |mut out, edge| {
                        match storage_roots.states.get(edge.src.0 as usize) {
                            Some(StorageRootState::ProvenEmpty) => {}
                            Some(StorageRootState::Root(_)) => {
                                out.push(addresses[edge.src.0 as usize]?);
                            }
                            _ => return None,
                        }
                        Some(out)
                    });
                    alternatives.and_then(|alternatives| {
                        let first = *alternatives.first()?;
                        alternatives
                            .iter()
                            .all(|address| address.root == first.root)
                            .then(|| {
                                let same_location = alternatives
                                    .iter()
                                    .all(|address| address.location == first.location);
                                let same_derivation = alternatives
                                    .iter()
                                    .all(|address| address.via_gep == first.via_gep);
                                ExactAddress {
                                    root: first.root,
                                    location: (same_location && same_derivation)
                                        .then_some(first.location)
                                        .unwrap_or(FieldLocation::Unknown),
                                    via_gep: same_location && same_derivation && first.via_gep,
                                }
                            })
                    })
                }
                _ => None,
            };
            if let Some(address) =
                candidate.filter(|address| address.root == certified_root.object_node())
            {
                addresses[dst.0 as usize] = Some(address);
                changed = true;
            }
        }
    }
    addresses
}

#[derive(Default)]
struct MaterializedPointsTo {
    direct: BTreeMap<String, BTreeSet<String>>,
    through_memory: BTreeMap<String, BTreeSet<String>>,
    through_memory_external: BTreeMap<String, BTreeSet<String>>,
}

/// Compute the negative-proof bit used when enumerating finite pointee classes. A global is
/// unexposed only when the storage-root certificate accounts for every producer and every use is
/// a safe terminal: a direct load/store address or the sole argument of recognized standard
/// `free`. Everything else fails closed, including memcpy/memset, cross-scope propagation,
/// storage as a value, other calls/returns, ptr-to-int, unknown operations (including inline
/// assembly), initializer capture, and export.
fn global_address_exposure(pir: &Pir, pag: &Pag, roots: &StorageRoots) -> Vec<bool> {
    fn global_index(roots: &StorageRoots, node: NodeId) -> Option<usize> {
        match roots.states.get(node.0 as usize)? {
            StorageRootState::Root(StorageRoot::Global {
                pir_global_index, ..
            }) => Some(*pir_global_index),
            _ => None,
        }
    }
    fn semantic_scope(kind: &NodeKind) -> (&str, Option<&str>) {
        match kind {
            NodeKind::Value {
                scope: pangs_pag::Scope::Function(func),
            }
            | NodeKind::Param { func, .. }
            | NodeKind::Return { func } => ("function", Some(func)),
            NodeKind::Value {
                scope: pangs_pag::Scope::Module,
            } => ("module", None),
            NodeKind::Value {
                scope: pangs_pag::Scope::GlobalInit,
            } => ("global_init", None),
            NodeKind::Object {
                owner: Some(owner), ..
            } => ("function", Some(owner)),
            NodeKind::Object { owner: None, .. } => ("module", None),
        }
    }
    fn expose(exposed: &mut [bool], roots: &StorageRoots, node: NodeId) {
        if let Some(index) = global_index(roots, node) {
            exposed[index] = true;
        }
    }

    let global_by_key = pir
        .globals
        .iter()
        .enumerate()
        .flat_map(|(index, global)| {
            let bare = global.key.strip_prefix('@').unwrap_or(&global.key);
            [(global.key.as_str(), index), (bare, index)]
        })
        .collect::<HashMap<_, _>>();
    let object_global = &roots.global_objects;
    let mut exposed = if roots.global_identity_valid {
        vec![false; pir.globals.len()]
    } else {
        vec![true; pir.globals.len()]
    };
    for &index in &roots.force_exposed_globals {
        if let Some(bit) = exposed.get_mut(index) {
            *bit = true;
        }
    }
    for edge in &pag.edges {
        use pangs_pag::EdgeKind;
        match edge.kind {
            EdgeKind::AddrOf => {}
            EdgeKind::Gep { .. } => {
                let same =
                    roots.states.get(edge.src.0 as usize) == roots.states.get(edge.dst.0 as usize);
                if !same {
                    expose(&mut exposed, roots, edge.src);
                }
            }
            EdgeKind::Assign => {
                let source = roots.states.get(edge.src.0 as usize);
                let destination = roots.states.get(edge.dst.0 as usize);
                let same_root = source == destination
                    || matches!(source, Some(StorageRootState::ProvenEmpty))
                        && matches!(
                            destination,
                            Some(StorageRootState::ProvenEmpty | StorageRootState::Root(_))
                        );
                let same_scope = semantic_scope(&pag.nodes[edge.src.0 as usize].kind)
                    == semantic_scope(&pag.nodes[edge.dst.0 as usize].kind);
                if !same_root || !same_scope {
                    expose(&mut exposed, roots, edge.src);
                    expose(&mut exposed, roots, edge.dst);
                }
            }
            EdgeKind::Load => {
                // src is the admitted address operand; a rooted destination would mean a
                // malformed additional producer and is never admitted.
                expose(&mut exposed, roots, edge.dst);
            }
            EdgeKind::Store => {
                // dst is the admitted address operand; storing an address value exposes it.
                expose(&mut exposed, roots, edge.src);
            }
            EdgeKind::Memcpy { .. } => {
                expose(&mut exposed, roots, edge.src);
                expose(&mut exposed, roots, edge.dst);
            }
        }
    }
    for callsite in &pag.callsites {
        let trusted_free = callsite.kind == CallKind::Direct
            && callsite.callee.as_deref().is_some_and(|callee| {
                trusted_free_call(
                    pir,
                    callee,
                    &callsite.sig,
                    callsite.args.len(),
                    callsite.result.is_some(),
                )
            });
        if trusted_free {
            continue;
        }
        for node in callsite.operand.iter().chain(&callsite.args) {
            expose(&mut exposed, roots, *node);
        }
    }
    for seed in &pag.omega_seeds {
        let SeedTarget::Node(node) = seed.target else {
            continue;
        };
        expose(&mut exposed, roots, node);
        if let Some(&pir_global_index) = object_global.get(&node) {
            exposed[pir_global_index] = true;
        }
    }
    for node in &pag.nodes {
        if matches!(node.kind, NodeKind::Return { .. }) {
            expose(&mut exposed, roots, node.id);
        }
    }
    for initializer in &pir.globals {
        for referenced in &initializer.init_refs {
            if let Some(&index) = global_by_key
                .get(referenced.as_str())
                .or_else(|| global_by_key.get(referenced.strip_prefix('@').unwrap_or(referenced)))
            {
                exposed[index] = true;
            }
        }
    }
    // Memset lowers to an ordinary synthetic Store, so distinguish it at PIR level. Index its
    // exact function/global-init value labels and canonical global spellings first, then scan
    // the PAG nodes once instead of once per memset.
    let function_memsets = pir.functions.iter().flat_map(|function| {
        function.body.iter().filter_map(|stmt| match stmt {
            pangs_pir::Stmt::Memset { dst, .. } => Some((function.key.as_str(), dst.as_str())),
            _ => None,
        })
    });
    let global_init_memsets = pir.global_init.iter().filter_map(|stmt| match stmt {
        pangs_pir::Stmt::Memset { dst, .. } => Some(("global_init", dst.as_str())),
        _ => None,
    });
    let mut memset_value_labels = HashSet::new();
    let mut memset_global_names = HashSet::new();
    for (owner, dst) in function_memsets.chain(global_init_memsets) {
        let bare = dst.strip_prefix('@').unwrap_or(dst);
        if let Some(&index) = global_by_key.get(dst).or_else(|| global_by_key.get(bare)) {
            exposed[index] = true;
        }
        memset_value_labels.insert(format!("val:{owner}:{dst}"));
        memset_global_names.insert(bare);
    }

    if !memset_value_labels.is_empty() {
        for node in &pag.nodes {
            let is_memset_global = node
                .label
                .strip_prefix("sym:global:")
                .map(|key| key.strip_prefix('@').unwrap_or(key))
                .is_some_and(|key| memset_global_names.contains(key));
            if memset_value_labels.contains(node.label.as_str()) || is_memset_global {
                expose(&mut exposed, roots, node.id);
            }
        }
    }
    exposed
}

fn violation_exposure(pir: &Pir, pag: &Pag) -> ViolationExposure {
    // A statement with no modeled value boundary, or one whose lowerer found an embedded symbol,
    // can touch storage absent from the PAG. Everything else is bounded by the Ω seeds emitted
    // for its pointer-capable operands/results.
    let inline_asm = pir
        .functions
        .iter()
        .flat_map(|func| &func.body)
        .chain(&pir.global_init)
        .filter_map(|stmt| match stmt {
            pangs_pir::Stmt::Unknown {
                operands,
                results,
                reason,
                ..
            } if reason.starts_with("inline_asm") => Some((operands, results, reason)),
            _ => None,
        })
        .collect::<Vec<_>>();

    if inline_asm.iter().any(|(operands, results, reason)| {
        (operands.is_empty() && results.is_empty()) || reason.contains("symbol_reference")
    }) {
        return ViolationExposure::ModuleWide;
    }

    let nodes = pag
        .omega_seeds
        .iter()
        .filter(|seed| {
            seed.detail
                .as_deref()
                .is_some_and(|detail| detail.starts_with("inline_asm"))
        })
        .filter_map(|seed| match seed.target {
            SeedTarget::Node(node) => Some(node),
            SeedTarget::Callsite(_) => None,
        })
        .collect();
    ViolationExposure::Finite(nodes)
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
        let storage_roots = allocation_storage_roots(pir, pag);
        let global_address_exposed = global_address_exposure(pir, pag, &storage_roots);
        let violation_exposure = violation_exposure(pir, pag);

        let mut classes = Vec::with_capacity(pag.nodes.len());
        for (index, node) in pag.nodes.iter().enumerate() {
            let mut data = ClassData {
                parent: index,
                size: 1,
                node_count: 1,
                has_empty_witness: matches!(
                    storage_roots.states.get(index),
                    Some(StorageRootState::ProvenEmpty)
                ),
                ..ClassData::default()
            };
            match &node.kind {
                NodeKind::Object { object, key, .. } => {
                    data.has_location = true;
                    // Function addresses retain the historical summary treatment: nonzero
                    // function-pointer arithmetic is unsupported, and synthetic fields do not
                    // carry function-object identity. Ordinary data allocations are registered
                    // below as their concrete root-relative Exact(0) location instead.
                    if matches!(object, pangs_pag::ObjectKind::Function) {
                        data.has_summary_region = true;
                        data.summary_roots.insert(node.id);
                    }
                    match object {
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
                        pangs_pag::ObjectKind::Alloca | pangs_pag::ObjectKind::ExternalReadonly => {
                        }
                    }
                }
                NodeKind::Param { func, index } => {
                    data.has_carrier = true;
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
                    data.has_carrier = true;
                    if let Some(&func_index) = function_name_to_index.get(func) {
                        function_meta[func_index].ret_node = Some(node.id);
                    }
                }
                NodeKind::Value { .. } => data.has_carrier = true,
            }
            classes.push(data);
        }

        let function_count = function_keys.len();
        let callsites_by_index = pag.callsites.iter().collect();
        let queued = vec![false; classes.len()];
        let exact_addresses = exact_allocation_addresses(pag, &storage_roots);
        let mut exact_field_locations = HashMap::<NodeId, BTreeSet<FieldLocation>>::new();
        for address in exact_addresses.iter().flatten() {
            exact_field_locations
                .entry(address.root)
                .or_default()
                .insert(address.location);
        }
        let direct_gep_exact_offsets = pag
            .edges
            .iter()
            .filter_map(|edge| match edge.kind {
                pangs_pag::EdgeKind::Gep {
                    byte_off: Some(offset),
                    ..
                } => Some(offset),
                _ => None,
            })
            .collect();
        let mut field_classes = HashMap::new();
        let mut fields_by_root = HashMap::<NodeId, Vec<usize>>::new();
        let mut field_inventory = HashMap::<NodeId, Vec<(FieldRegion, usize)>>::new();
        for node in &pag.nodes {
            let NodeKind::Object { object, .. } = &node.kind else {
                continue;
            };
            if matches!(object, pangs_pag::ObjectKind::Function) {
                continue;
            }
            let region = FieldRegion::address(FieldLocation::Exact(0));
            exact_field_locations
                .entry(node.id)
                .or_default()
                .insert(FieldLocation::Exact(0));
            classes[node.id.0 as usize]
                .field_regions
                .insert((node.id, region));
            field_classes.insert((node.id, region), node.id.0 as usize);
            fields_by_root
                .entry(node.id)
                .or_default()
                .push(node.id.0 as usize);
            field_inventory
                .entry(node.id)
                .or_default()
                .push((region, node.id.0 as usize));
        }
        let mut global_object_index_by_node = vec![None; pag.nodes.len()];
        for (global_index, node) in global_object_nodes.iter().copied().enumerate() {
            if let Some(node) = node {
                global_object_index_by_node[node.0 as usize] = Some(global_index);
            }
        }

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
            global_object_index_by_node,
            storage_roots,
            global_address_exposed,
            violation_exposure,
            exact_addresses,
            exact_field_locations,
            direct_gep_exact_offsets,
            derived_lanes_by_root: HashMap::new(),
            field_classes,
            fields_by_root,
            field_inventory,
            field_escape_sources_by_root: HashMap::new(),
            provenance: ProvenanceInterner::default(),
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
            points_to_labels: BTreeSet::new(),
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
        self.assert_field_root_coherence();
        self.assert_canonical_null_isolated();
        self.assert_one_hop_invariant();
        self.print_steens_profile("done");
    }

    /// Snapshot the solved union-find for the Andersen pass. Must be called after
    /// `run()` and before `finish()` (which consumes `self`).
    fn export_classes(&mut self) -> SteensClasses {
        let n_nodes = self.pag.nodes.len();
        let total = self.classes.len();
        let mut node_class = vec![0usize; n_nodes];
        for (i, class) in node_class.iter_mut().enumerate() {
            *class = self.find(i);
        }
        let mut pointee = vec![None; total];
        let mut ext = vec![false; total];
        let mut esc = vec![false; total];
        let mut global_storage = vec![false; total];
        for i in 0..total {
            let root = self.find(i);
            if root == i {
                pointee[i] = self.classes[i].pointee.map(|p| self.find(p));
                ext[i] = self.classes[i].ext;
                esc[i] = self.classes[i].esc;
                global_storage[i] = !self.classes[i].global_objs.is_empty();
            }
        }
        SteensClasses {
            node_class,
            pointee,
            ext,
            esc,
            global_storage,
            global_address_exposed: self.global_address_exposed.clone(),
            violation_exposure: self.violation_exposure.clone(),
        }
    }

    fn apply_edge_rules(&mut self) {
        for edge in &self.pag.edges {
            match edge.kind {
                pangs_pag::EdgeKind::AddrOf => {
                    let ptr = self.class_of(edge.dst);
                    let obj = self.class_of(edge.src);
                    let pointee = self.pointee_of(ptr);
                    self.join(pointee, obj, PROV_DIRECT_ADDRESS);
                }
                pangs_pag::EdgeKind::Assign => {
                    if !self.pointer_transfer(edge.src, edge.dst) {
                        continue;
                    }
                    let dst = self.class_of(edge.dst);
                    if self.node_is_proven_empty(edge.src) {
                        self.set_empty_witness(dst);
                        continue;
                    }
                    if let Some(storage) = self.exact_storage_class(edge.dst, Some(0), true) {
                        // A complete fixed-PAG certificate proves every producer of `dst`
                        // names this one allocation-relative location. Preserve that fact
                        // directly instead of recursively unifying the pointer carriers,
                        // which would needlessly merge their storage classes.
                        let dst_p = self.pointee_of(dst);
                        self.join(dst_p, storage, self.assign_provenance(edge.src, edge.dst));
                    } else {
                        let src = self.class_of(edge.src);
                        self.join(src, dst, self.assign_provenance(edge.src, edge.dst));
                    }
                }
                pangs_pag::EdgeKind::Load => {
                    if !self.node_may_carry_pointer(edge.dst) {
                        continue;
                    }
                    let dst = self.class_of(edge.dst);
                    if self.node_is_proven_empty(edge.src) {
                        self.set_external_escaped_union(dst);
                        continue;
                    }
                    // Missing widths occur only in legacy/hand-written PIR. Preserve its
                    // historical same-offset semantics; LLVM lowering always emits a width.
                    let width =
                        (!edge.access_extent_unknown).then_some(edge.access_bytes.unwrap_or(0));
                    let storage = self.storage_class_for_address(edge.src, width, true);
                    self.unify_pointees(
                        storage,
                        dst,
                        PROV_MEMORY_MERGING | PROV_SCALAR_OR_UNKNOWN_PAYLOAD,
                    );
                    self.add_content_edge(storage, dst);
                }
                pangs_pag::EdgeKind::Store => {
                    if self.node_is_proven_empty(edge.dst) {
                        // Preserve the PAG store for ModRef and completeness audits, but an
                        // certified empty address has no allocation storage class to unify.
                        continue;
                    }
                    // Scalar stores have no points-to payload. ModRef and runtime-written
                    // accounting consume the PAG edge directly, so avoid materializing a storage
                    // class which this solver arm would immediately discard.
                    if !self.node_may_carry_pointer(edge.src) {
                        continue;
                    }
                    let width =
                        (!edge.access_extent_unknown).then_some(edge.access_bytes.unwrap_or(0));
                    let storage = self.storage_class_for_address(edge.dst, width, true);
                    if self.node_is_proven_empty(edge.src) {
                        self.set_empty_witness(storage);
                        continue;
                    }
                    let src = self.class_of(edge.src);
                    self.unify_pointees(
                        storage,
                        src,
                        PROV_MEMORY_MERGING | PROV_SCALAR_OR_UNKNOWN_PAYLOAD,
                    );
                    self.add_content_edge(src, storage);
                }
                pangs_pag::EdgeKind::Gep { byte_off, lane } => {
                    let dst = self.class_of(edge.dst);
                    if self.node_is_proven_empty(edge.src) {
                        // Pointer arithmetic on an empty address is outside the contract. Keep the
                        // empty class isolated and fail closed on the derived value.
                        self.set_external_escaped_union(dst);
                        continue;
                    }
                    if let Some(address) = self.exact_addresses[edge.dst.0 as usize] {
                        let dst_p = self.pointee_of(dst);
                        let storage =
                            self.field_class(address.root, FieldRegion::address(address.location));
                        self.join(dst_p, storage, PROV_DIRECT_ADDRESS);
                    } else {
                        let src = self.class_of(edge.src);
                        self.add_gep_transfer(src, dst, FieldLocation::from_gep(byte_off, lane));
                        self.add_content_edge(src, dst);
                    }
                }
                pangs_pag::EdgeKind::Memcpy { bytes } => {
                    if self.node_is_proven_empty(edge.dst) {
                        // The destination has no modeled storage. Keep the edge in the PAG so
                        // clients still observe the invalid write.
                        continue;
                    }
                    let dst_storage = self.storage_class_for_address(edge.dst, bytes, false);
                    if self.node_is_proven_empty(edge.src) {
                        // Reading bytes from an empty address is unsupported. Preserve the access
                        // edge and conservatively make the destination contents external.
                        self.set_external_escaped_union(dst_storage);
                        continue;
                    }
                    let src_storage = self.storage_class_for_address(edge.src, bytes, false);
                    self.unify_pointees(
                        dst_storage,
                        src_storage,
                        PROV_MEMORY_MERGING | PROV_SCALAR_OR_UNKNOWN_PAYLOAD,
                    );
                    self.add_content_edge(src_storage, dst_storage);
                }
            }
        }
    }

    fn assign_provenance(&self, src: NodeId, dst: NodeId) -> u8 {
        let mut provenance = PROV_DIRECT_ADDRESS;
        for node in [src, dst] {
            match &self.pag.nodes[node.0 as usize].kind {
                NodeKind::Param { func, index } => {
                    provenance |= PROV_CALL_RETURN;
                    if self
                        .function_name_to_index
                        .get(func)
                        .is_some_and(|&func_index| {
                            meta_param_is_by_value(
                                &self.function_meta[func_index].sig,
                                *index as usize,
                            )
                        })
                    {
                        provenance |= PROV_BY_VALUE_AGGREGATE;
                    }
                }
                NodeKind::Return { .. } => provenance |= PROV_CALL_RETURN,
                _ => {}
            }
        }
        provenance
    }

    fn register_indirect_calls(&mut self) {
        for (site_index, callsite) in self.pag.callsites.iter().enumerate() {
            if callsite.kind != CallKind::Indirect {
                continue;
            }
            let Some(operand) = callsite.operand else {
                continue;
            };
            if self.node_is_proven_empty(operand) {
                continue;
            }
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
                    let label = &self.pag.nodes[id.0 as usize].label;
                    let source = if seed.kind == OmegaSeedKind::ExportedSymbol {
                        format!("exported-symbol:{label}")
                    } else {
                        format!("imported-symbol:{label}")
                    };
                    self.set_esc_with_source(class, source.clone());
                    if seed.kind == OmegaSeedKind::ExportedSymbol {
                        self.escape_allocation_fields_with_source(id, source.clone());
                    }
                }
                (OmegaSeedKind::PtrToInt, SeedTarget::Node(id))
                | (OmegaSeedKind::UnknownOperandEscape, SeedTarget::Node(id)) => {
                    let class = self.class_of(id);
                    self.add_class_provenance(class, PROV_SCALAR_OR_UNKNOWN_PAYLOAD);
                    if self.node_is_proven_empty(id) {
                        // Retain the boundary/violation seed in the PAG, but null points to no
                        // allocation whose address could escape through it.
                        continue;
                    }
                    let pointee = self.pointee_of(class);
                    let source = format!("{:?}:{}", seed.kind, self.pag.nodes[id.0 as usize].label);
                    self.escape_exact_address_fields_with_source(id, source.clone());
                    self.add_class_provenance(pointee, PROV_SCALAR_OR_UNKNOWN_PAYLOAD);
                    self.set_esc_with_source(pointee, source);
                }
                (OmegaSeedKind::IntToPtr, SeedTarget::Node(id)) => {
                    let class = self.class_of(id);
                    self.add_class_provenance(class, PROV_SCALAR_OR_UNKNOWN_PAYLOAD);
                    self.set_external_escaped_union(class);
                }
                (OmegaSeedKind::UnknownResultExternal, SeedTarget::Node(id)) => {
                    let class = self.class_of(id);
                    self.add_class_provenance(class, PROV_SCALAR_OR_UNKNOWN_PAYLOAD);
                    self.set_ext(class);
                }
                (OmegaSeedKind::ExternalCallBoundary, SeedTarget::Callsite(id)) => {
                    self.apply_external_call(id.0 as usize);
                }
                (OmegaSeedKind::VarargCallBoundary, SeedTarget::Callsite(id)) => {
                    self.apply_vararg_call(id.0 as usize);
                }
                (OmegaSeedKind::VarargListPayload, SeedTarget::Node(id)) => {
                    // `va_start` does not publish the list's address, so nothing escapes here.
                    // What it writes into the list is the caller's variadic tail, so the list's
                    // contents are external: a pointer read out of it designates unknown memory
                    // rather than nothing. The content push-down carries that through the
                    // multi-level extraction the ABI actually uses.
                    let class = self.class_of(id);
                    self.add_class_provenance(class, PROV_SCALAR_OR_UNKNOWN_PAYLOAD);
                    let pointee = self.pointee_of(class);
                    self.add_class_provenance(pointee, PROV_SCALAR_OR_UNKNOWN_PAYLOAD);
                    self.set_ext(pointee);
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

    fn add_class_provenance(&mut self, class: usize, provenance: u8) {
        let root = self.find(class);
        self.classes[root].provenance |= provenance;
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
            if self.node_is_proven_empty(operand) {
                indirect_calls.push(IndirectCallResolution {
                    callsite_key: callsite.key.clone(),
                    targets: Vec::new(),
                    unknown_callee: true,
                    fallback: false,
                    prefsa_targets: 0,
                    fsa_rejected_targets: 0,
                });
                continue;
            }
            let operand = self.class_of(operand);
            let pointee = self.pointee_of(operand);
            let root = self.find(pointee);
            let mut prefsa_targets = 0usize;
            let mut fsa_rejected_targets = 0usize;
            for &func_index in &self.classes[root].fn_objs {
                let meta = &self.function_meta[func_index];
                if !meta.address_taken {
                    continue;
                }
                prefsa_targets += 1;
                if !fsa_compatible(&callsite.sig, &meta.sig) {
                    fsa_rejected_targets += 1;
                }
            }
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
            // An empty finite answer is not conservative.  It commonly indicates that an
            // address producer was not represented in the PAG; represent that loss as top so
            // clients never mistake analysis silence for a proof that the call has no target.
            let unknown_callee = self.classes[root].ext || targets.is_empty();
            indirect_calls.push(IndirectCallResolution {
                callsite_key: callsite.key.clone(),
                targets,
                unknown_callee,
                fallback: false,
                prefsa_targets,
                fsa_rejected_targets,
            });
        }

        let mut unknown_callers = BTreeSet::new();
        let mut function_escapes = BTreeMap::new();
        for func_index in 0..self.function_meta.len() {
            let Some(class) = self.function_object_class(func_index) else {
                continue;
            };
            let root = self.find(class);
            if self.classes[root].esc {
                unknown_callers.insert(self.function_keys[func_index].clone());
            }
            let escape_sources = self
                .provenance
                .strings(self.classes[root].escape_sources.iter());
            let own_export = format!(
                "exported-symbol:obj:function:{}",
                self.function_keys[func_index]
            );
            function_escapes.insert(
                self.function_keys[func_index].clone(),
                FunctionResolution {
                    address_escape: escape_sources.iter().any(|source| source != &own_export),
                    escape_sources,
                },
            );
        }

        let mut stored_classes = BTreeSet::new();
        let mut runtime_stored_classes = BTreeSet::new();
        for edge in &self.pag.edges {
            if !matches!(
                edge.kind,
                pangs_pag::EdgeKind::Store | pangs_pag::EdgeKind::Memcpy { .. }
            ) {
                continue;
            }
            if self.node_is_proven_empty(edge.dst) {
                continue;
            }
            let dst = self.class_of(edge.dst);
            let pointee = self.pointee_of(dst);
            let root = self.find(pointee);
            stored_classes.insert(root);
            if matches!(edge.owner, pangs_pag::Owner::Function(_)) {
                runtime_stored_classes.insert(root);
            }
        }

        let isolation = allocation_isolation(self.pir, self.pag, &indirect_calls, &unknown_callers);
        let storage_roots_by_global =
            global_storage_roots_index(&self.classes, self.pir.globals.len());

        let mut globals = BTreeMap::new();
        for (global_index, global) in self.pir.globals.iter().enumerate() {
            let Some(class) = self.global_object_class(global_index) else {
                continue;
            };
            let object_root = self.find(class);
            let storage_roots = &storage_roots_by_global[global_index];
            debug_assert!(storage_roots.contains(&object_root));
            let mut escape_external = storage_roots
                .iter()
                .any(|&storage| self.classes[storage].esc);
            let mut escape_sources = self.provenance.strings(
                storage_roots
                    .iter()
                    .flat_map(|&storage| self.classes[storage].escape_sources.iter()),
            );
            let own_export = format!("exported-symbol:obj:global:{}", global.key);
            let mut address_escape = escape_sources.iter().any(|source| source != &own_export);
            // Imported declarations are storage owned by another module: absence of a local
            // store is not a proof that they are immutable, and allocation-isolation over this
            // module cannot discharge their external address/write boundary.
            let locally_defined = global.is_definition;
            let never_written = locally_defined
                && !escape_external
                && storage_roots
                    .iter()
                    .all(|storage| !stored_classes.contains(storage));
            let mut runtime_written = storage_roots
                .iter()
                .any(|storage| runtime_stored_classes.contains(storage));
            if locally_defined && isolation.address.contains(&global.key) {
                // Steensgaard may merge a dynamically-indexed aggregate with an unrelated,
                // externally exposed pointer class.  A completed allocation-provenance proof
                // is strictly narrower: every flow of this object's own address was followed
                // and no external boundary was reached. Runtime writes through that address do
                // not make the address escape and are retained independently below.
                escape_external = false;
                address_escape = false;
                escape_sources.clear();
            }
            if locally_defined && isolation.write.contains(&global.key) {
                runtime_written = false;
            }
            globals.insert(
                global.key.clone(),
                GlobalResolution {
                    escape_external,
                    address_escape,
                    escape_sources,
                    never_written,
                    runtime_written,
                },
            );
        }

        let mut unfiltered_pointee_globals_by_root: Vec<Option<SharedStringList>> =
            vec![None; self.classes.len()];
        let mut exposed_pointee_globals_by_root: Vec<Option<SharedStringList>> =
            vec![None; self.classes.len()];
        let mut reaches_function_pointer_by_root: Vec<Option<bool>> =
            vec![None; self.classes.len()];
        let mut pointee_provenance_by_key = HashMap::<(u8, bool), SharedProvenanceList>::new();
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
                let pointee = self.classes[root].pointee.map(|p| self.find(p));
                // Every value transfer now either joins carriers or has a directed content edge,
                // so content boundary facts are complete on the carrier. Reading the location
                // class here would reintroduce container contamination (for example, treating a
                // pointer stored in external memory as itself external).
                let external = self.classes[root].ext;
                let external_escaped_union = self.classes[root].external_escaped_union;
                let has_empty_witness = self.classes[root].has_empty_witness;
                let pointee_is_empty = pointee.is_none_or(|pointee| {
                    self.classes[pointee].node_count == 0
                        && !self.classes[pointee].ext
                        && !self.classes[pointee].esc
                        && self.classes[pointee].fn_objs.is_empty()
                        && self.classes[pointee].global_objs.is_empty()
                });
                let proven_empty = has_empty_witness
                    && pointee_is_empty
                    && !external
                    && self.classes[root].fn_objs.is_empty()
                    && self.classes[root].global_objs.is_empty();
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
                    has_empty_witness,
                    proven_empty,
                    external,
                    external_escaped_union,
                    pointee,
                };
                node_summary_by_root[root] = Some(cached.clone());
                cached
            };
            let (pointee_globals, pointee_globals_unfiltered) = summary
                .pointee
                .map(|pointee| {
                    let unfiltered =
                        if let Some(globals) = &unfiltered_pointee_globals_by_root[pointee] {
                            globals.clone()
                        } else {
                            let mut globals = self.classes[pointee]
                                .global_objs
                                .iter()
                                .map(|&global_index| self.global_keys[global_index].clone())
                                .collect::<Vec<_>>();
                            globals.sort();
                            let globals = SharedStringList::from(globals);
                            unfiltered_pointee_globals_by_root[pointee] = Some(globals.clone());
                            globals
                        };
                    if matches!(self.violation_exposure, ViolationExposure::ModuleWide) {
                        return (unfiltered, SharedStringList::default());
                    }
                    let filtered = if let Some(globals) = &exposed_pointee_globals_by_root[pointee]
                    {
                        globals.clone()
                    } else {
                        let mut globals = self.classes[pointee]
                            .global_objs
                            .iter()
                            .filter(|&&global_index| self.global_address_exposed[global_index])
                            .map(|&global_index| self.global_keys[global_index].clone())
                            .collect::<Vec<_>>();
                        globals.sort();
                        let globals = SharedStringList::from(globals);
                        exposed_pointee_globals_by_root[pointee] = Some(globals.clone());
                        globals
                    };
                    debug_assert_narrows(
                        &node.label,
                        "address-exposed",
                        &filtered,
                        "steens-class",
                        &unfiltered,
                    );
                    let envelope = if filtered != unfiltered {
                        unfiltered
                    } else {
                        SharedStringList::default()
                    };
                    (filtered, envelope)
                })
                .unwrap_or_default();
            let pointee_provenance = if pointee_globals.is_empty() {
                SharedProvenanceList::default()
            } else {
                let pointee_mask = summary
                    .pointee
                    .map(|pointee| self.classes[pointee].provenance)
                    .unwrap_or(0);
                let key = (
                    self.classes[root].provenance | pointee_mask,
                    summary.external,
                );
                pointee_provenance_by_key
                    .entry(key)
                    .or_insert_with(|| {
                        SharedProvenanceList::from(pointee_provenance_labels(key.0, key.1))
                    })
                    .clone()
            };
            nodes.insert(
                node.label.clone(),
                NodeResolution {
                    reaches_function_pointer: summary.reaches_function_pointer,
                    has_empty_witness: summary.has_empty_witness,
                    proven_empty: summary.proven_empty,
                    external: summary.external,
                    external_escaped_union: summary.external_escaped_union,
                    pointee_globals,
                    pointee_globals_unfiltered,
                    pointee_provenance,
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
        self.assert_canonical_null_isolated();
        let metrics = self.metrics.clone();

        let materialized = match self.points_to_materialization {
            PointsToMaterialization::None => MaterializedPointsTo::default(),
            mode => self.materialize_points_to(mode),
        };

        SolveResult {
            storage_roots: self.storage_roots,
            indirect_calls,
            unknown_callers,
            function_escapes,
            globals,
            nodes,
            node_points_to: materialized.direct,
            node_pointee_points_to: materialized.through_memory,
            node_pointee_external: materialized.through_memory_external,
            metrics,
        }
    }

    /// For every PAG node, the named allocations (global + function keys) its class points to —
    /// `global_objs ∪ fn_objs` of `find(pointee(class_of(node)))`. Object nodes thus expose
    /// `ptr_points_to` (what a memory cell holds); value/param/return nodes expose
    /// `operand_points_to`. Memoized per pointee-class root, so this is O(#nodes).
    fn materialize_points_to(&mut self, mode: PointsToMaterialization) -> MaterializedPointsTo {
        let mut by_pointee_root: Vec<Option<BTreeSet<String>>> = vec![None; self.classes.len()];
        let mut out = BTreeMap::new();
        let mut pointee_out = BTreeMap::new();
        let mut pointee_external = BTreeMap::new();
        let field_roots = self
            .fields_by_root
            .iter()
            .map(|(&root, fields)| (root, fields.clone()))
            .collect::<Vec<_>>();
        let mut storage_by_object = HashMap::<usize, BTreeSet<usize>>::new();
        for (object, fields) in field_roots {
            let object_class = self.class_of(object);
            storage_by_object
                .entry(object_class)
                .or_default()
                .insert(object_class);
            for field in fields {
                let field = self.find(field);
                storage_by_object
                    .entry(object_class)
                    .or_default()
                    .insert(field);
            }
        }
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
            if mode == PointsToMaterialization::Targeted
                && !self.points_to_labels.contains(&node.label)
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

            // A field-insensitive load through the designated pointer. The first pointee is
            // the reachable memory object/class; its pointee is what that memory may store.
            // This is registry-only targeted output: the existing diagnostic/global accessors
            // retain their original output shape and cost.
            if mode == PointsToMaterialization::Targeted {
                if self.classes[pointee].ext {
                    pointee_external
                        .entry(node.label.clone())
                        .or_insert_with(BTreeSet::new)
                        .insert("omega:reachable-memory".to_string());
                }
                if self.classes[pointee].esc {
                    let sources = if self.classes[pointee].escape_sources.is_empty() {
                        BTreeSet::from(["derived:external-pointee".to_string()])
                    } else {
                        self.provenance
                            .string_set(self.classes[pointee].escape_sources.iter())
                    };
                    pointee_external
                        .entry(node.label.clone())
                        .or_insert_with(BTreeSet::new)
                        .extend(sources);
                }
            }
            if mode == PointsToMaterialization::Targeted {
                let storage_classes = storage_by_object
                    .get(&pointee)
                    .cloned()
                    .unwrap_or_else(|| BTreeSet::from([pointee]));
                let mut content_roots = BTreeSet::new();
                for storage in storage_classes {
                    if let Some(contents) = self.classes[storage].pointee {
                        content_roots.insert(self.find(contents));
                    }
                }
                let mut contents_allocs = BTreeSet::new();
                for contents in content_roots {
                    if self.classes[contents].ext {
                        let sources = if self.classes[contents].escape_sources.is_empty() {
                            BTreeSet::from(["omega:reachable-contents".to_string()])
                        } else {
                            self.provenance
                                .string_set(self.classes[contents].escape_sources.iter())
                        };
                        pointee_external
                            .entry(node.label.clone())
                            .or_insert_with(BTreeSet::new)
                            .extend(sources);
                    }
                    for &g in &self.classes[contents].global_objs {
                        contents_allocs.insert(self.global_keys[g].clone());
                    }
                    for &f in &self.classes[contents].fn_objs {
                        contents_allocs.insert(self.function_keys[f].clone());
                    }
                }
                if !contents_allocs.is_empty() {
                    pointee_out.insert(node.label.clone(), contents_allocs);
                }
            }
        }
        MaterializedPointsTo {
            direct: out,
            through_memory: pointee_out,
            through_memory_external: pointee_external,
        }
    }

    fn process_class(&mut self, class: usize) {
        self.metrics.steens_process_class_calls += 1;
        let mut root = self.find(class);
        self.replay_gep_transfers(root);
        // Replaying can join this location with a destination target.  All remaining one-hop
        // processing must observe the canonical post-replay class.
        root = self.find(root);
        let ext = self.classes[root].ext;
        let external_escaped_union = self.classes[root].external_escaped_union;
        let esc = self.classes[root].esc;
        let escape_sources = self.classes[root].escape_sources.clone();

        // Escape belongs to the allocation, including addresses discovered through memory
        // after the fixed exact-address proof. Revisit after late UF/address growth, but
        // do not turn a field's external pointer payload into sibling external contents.
        let allocation_escape = self.classes[root].allocation_escape;
        if allocation_escape
            && self.classes[root].escape_processed_regions != self.classes[root].field_regions.len()
        {
            self.classes[root].escape_processed_regions = self.classes[root].field_regions.len();
            let owners = self.classes[root]
                .field_regions
                .iter()
                .map(|(owner, _)| *owner)
                .collect::<BTreeSet<_>>();
            for owner in owners {
                // The first root-wide witness already covers every current/future field.
                // Re-unioning a large class's provenance into every covered root can dwarf
                // the solve, even though no new escape fact would be generated.
                if !self.field_escape_sources_by_root.contains_key(&owner) {
                    self.escape_allocation_fields(owner, &escape_sources);
                }
            }
        }

        if ext || esc {
            if let Some(pointee) = self.classes[root].pointee {
                if external_escaped_union {
                    self.set_external_escaped_union(pointee);
                } else {
                    self.set_ext(pointee);
                }
                if escape_sources.is_empty() {
                    let pointee = self.find(pointee);
                    if !self.classes[pointee].esc {
                        let source = self.provenance.intern("derived:external-pointee".into());
                        self.set_esc_sources_kind(
                            pointee,
                            &BTreeSet::from([source]),
                            allocation_escape,
                        );
                    }
                } else {
                    self.set_esc_sources_kind(pointee, &escape_sources, allocation_escape);
                }
            }
        }

        // Load/store/memcpy/unknown-GEP move pointer contents without equating their carrier and
        // location classes. Propagate exactly the content facts that the old container merge
        // carried implicitly, in the direction of the value transfer.
        let has_empty_witness = self.classes[root].has_empty_witness;
        if ext || esc || external_escaped_union || has_empty_witness {
            let facts_changed = (ext || esc) && !self.classes[root].content_pushed_ext
                || external_escaped_union
                    && !self.classes[root].content_pushed_external_escaped_union
                || has_empty_witness && !self.classes[root].content_pushed_empty;
            let successor_count = self.classes[root].content_succ.len();
            let first_successor = if facts_changed {
                0
            } else {
                self.classes[root]
                    .content_pushed_succ_len
                    .min(successor_count)
            };
            let successors = self.classes[root].content_succ[first_successor..].to_vec();
            for successor in successors {
                let dst = self.find(successor);
                if dst == root {
                    continue;
                }
                self.metrics.steens_content_pushes += 1;
                if ext || esc {
                    self.set_ext(dst);
                }
                if external_escaped_union {
                    self.set_external_escaped_union(dst);
                }
                if has_empty_witness {
                    self.set_empty_witness(dst);
                }
            }
            self.classes[root].content_pushed_succ_len = successor_count;
            self.classes[root].content_pushed_ext |= ext || esc;
            self.classes[root].content_pushed_external_escaped_union |= external_escaped_union;
            self.classes[root].content_pushed_empty |= has_empty_witness;
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
                    if self.node_is_proven_empty(ret) {
                        continue;
                    }
                    self.escape_exact_address_fields(ret, &escape_sources);
                    let class = self.class_of(ret);
                    let pointee = self.pointee_of(class);
                    self.set_esc_sources(pointee, &escape_sources);
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
        for (index, (arg, param)) in callsite.args.iter().zip(param_nodes.iter()).enumerate() {
            if param.0 == u32::MAX {
                continue;
            }
            if !self.pointer_transfer(*arg, *param) {
                continue;
            }
            let param = self.class_of(*param);
            if self.node_is_proven_empty(*arg) {
                self.set_empty_witness(param);
                continue;
            }
            let arg = self.class_of(*arg);
            let mut provenance = PROV_CALL_RETURN;
            if meta_param_is_by_value(&self.function_meta[func_index].sig, index) {
                provenance |= PROV_BY_VALUE_AGGREGATE;
            }
            self.join(arg, param, provenance);
        }
        if let (Some(result), Some(ret)) = (callsite.result, ret_node) {
            if !self.pointer_transfer(ret, result) {
                return;
            }
            let result = self.class_of(result);
            if self.node_is_proven_empty(ret) {
                self.set_empty_witness(result);
                return;
            }
            let ret = self.class_of(ret);
            self.join(result, ret, PROV_CALL_RETURN);
        }
    }

    fn apply_external_call(&mut self, site_index: usize) {
        self.metrics.steens_external_call_requests += 1;
        if !self.external_applied.insert(site_index) {
            return;
        }
        self.metrics.steens_external_call_applications += 1;
        let callsite = self.callsites_by_index[site_index];
        let source = format!("external-call:{}", callsite.key);
        for &arg_node in &callsite.args {
            if self.node_is_proven_empty(arg_node) {
                continue;
            }
            self.escape_exact_address_fields_with_source(arg_node, source.clone());
            let arg = self.class_of(arg_node);
            let pointee = self.pointee_of(arg);
            self.set_esc_with_source(pointee, source.clone());
        }
        if let Some(result) = callsite.result {
            let result = self.class_of(result);
            self.set_ext(result);
        }
    }

    fn apply_vararg_call(&mut self, site_index: usize) {
        let callsite = self.callsites_by_index[site_index];
        let source = format!("vararg-call:{}", callsite.key);
        let fixed = callsite.sig.params.len();
        let extra_args = callsite
            .args
            .iter()
            .skip(fixed)
            .copied()
            .collect::<Vec<_>>();
        for arg in extra_args {
            self.escape_exact_address_fields_with_source(arg, source.clone());
            let class = self.class_of(arg);
            let root = self.find(class);
            let Some(pointee) = self.classes[root].pointee else {
                continue;
            };
            self.set_esc_with_source(pointee, source.clone());
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

    fn node_may_carry_pointer(&self, node: NodeId) -> bool {
        self.pag.nodes[node.0 as usize]
            .value_kind
            .may_carry_pointer()
    }

    fn node_is_proven_empty(&self, node: NodeId) -> bool {
        matches!(
            self.storage_roots.states.get(node.0 as usize),
            Some(StorageRootState::ProvenEmpty)
        )
    }

    fn pointer_transfer(&self, src: NodeId, dst: NodeId) -> bool {
        self.node_may_carry_pointer(src) && self.node_may_carry_pointer(dst)
    }

    fn set_empty_witness(&mut self, class: usize) {
        let root = self.find(class);
        if !self.classes[root].has_empty_witness {
            self.classes[root].has_empty_witness = true;
            self.enqueue(root);
        }
    }

    /// Equate the pointer targets held in `a` and `b` without equating the cells themselves.
    fn unify_pointees(&mut self, a: usize, b: usize, provenance: u8) -> usize {
        let a = self.find(a);
        let b = self.find(b);
        if a == b {
            let pointee = self.pointee_of(a);
            self.add_class_provenance(pointee, provenance);
            return pointee;
        }
        match (self.classes[a].pointee, self.classes[b].pointee) {
            (Some(pa), Some(pb)) => self.join(pa, pb, provenance),
            (Some(p), None) => {
                let p = self.find(p);
                self.classes[b].pointee = Some(p);
                self.add_class_provenance(p, provenance);
                self.enqueue(b);
                p
            }
            (None, Some(p)) => {
                let p = self.find(p);
                self.classes[a].pointee = Some(p);
                self.add_class_provenance(p, provenance);
                self.enqueue(a);
                p
            }
            (None, None) => {
                let p = self.pointee_of(a);
                self.classes[b].pointee = Some(p);
                self.add_class_provenance(p, provenance);
                self.enqueue(b);
                self.metrics.steens_unify_pointees_shared += 1;
                p
            }
        }
    }

    fn add_content_edge(&mut self, src: usize, dst: usize) {
        let src = self.find(src);
        self.classes[src].content_succ.push(dst);
        self.metrics.steens_content_edges += 1;
        self.enqueue(src);
    }

    fn escape_allocation_fields(&mut self, root: NodeId, sources: &BTreeSet<ProvenanceId>) {
        let sources_by_root = self.field_escape_sources_by_root.entry(root).or_default();
        let already_escaped = !sources_by_root.is_empty();
        sources_by_root.extend(sources.iter().cloned());
        if already_escaped {
            return;
        }
        let source = self
            .provenance
            .first_lexicographic(sources.iter())
            .unwrap_or_else(|| {
                self.provenance
                    .intern("derived:allocation-field-escape".into())
            });
        let fields = self.fields_by_root.get(&root).cloned().unwrap_or_default();
        for field in fields {
            self.set_esc_with_id(field, source);
        }
    }

    fn escape_allocation_fields_with_source(&mut self, root: NodeId, source: String) {
        let source = self.provenance.intern(source);
        self.escape_allocation_fields(root, &BTreeSet::from([source]));
    }

    fn escape_exact_address_fields(&mut self, address: NodeId, sources: &BTreeSet<ProvenanceId>) {
        if let Some(address) = self.exact_addresses[address.0 as usize] {
            self.escape_allocation_fields(address.root, sources);
        }
    }

    fn escape_exact_address_fields_with_source(&mut self, address: NodeId, source: String) {
        let source = self.provenance.intern(source);
        self.escape_exact_address_fields(address, &BTreeSet::from([source]));
    }

    fn assert_field_root_coherence(&mut self) {
        let edges = self
            .fields_by_root
            .iter()
            .flat_map(|(&owner, fields)| fields.iter().copied().map(move |field| (owner, field)))
            .collect::<Vec<_>>();
        for (owner_node, field) in edges {
            let owner = self.class_of(owner_node);
            let field = self.find(field);
            let expected_global = self.global_object_index_by_node[owner_node.0 as usize];
            let expected_escape = self.field_escape_sources_by_root.contains_key(&owner_node);
            assert!(
                expected_global
                    .is_none_or(|global| self.classes[field].global_objs.contains(&global))
                    && (!expected_escape
                        || (self.classes[field].esc && self.classes[field].allocation_escape)),
                "allocation-relative field class {field} lost root envelope from class {owner}"
            );
        }
    }

    fn assert_canonical_null_isolated(&mut self) {
        let canonical_nulls = self
            .pag
            .nodes
            .iter()
            .filter(|node| node.canonical_pointer_null)
            .map(|node| (node.id, node.label.clone()))
            .collect::<Vec<_>>();
        for (node, label) in canonical_nulls {
            let root = self.class_of(node);
            assert!(
                self.classes[root].has_empty_witness,
                "{label} lost its null fact"
            );
            assert!(
                self.classes[root].pointee.is_none()
                    && !self.classes[root].ext
                    && !self.classes[root].esc,
                "canonical-null class was contaminated: {label}"
            );
        }
    }

    fn assert_one_hop_invariant(&mut self) {
        #[cfg(debug_assertions)]
        for class in 0..self.classes.len() {
            let root = self.find(class);
            if root != class {
                continue;
            }
            debug_assert!(
                !(self.classes[root].has_carrier && self.classes[root].has_location),
                "Steensgaard class {root} mixes value carriers with storage locations"
            );
            if self.classes[root].has_carrier {
                debug_assert!(
                    !self.classes[root].esc
                        && self.classes[root].global_objs.is_empty()
                        && self.classes[root].fn_objs.is_empty(),
                    "Steensgaard carrier class {root} contains location-only facts"
                );
            }
        }
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
            has_location: true,
            ..ClassData::default()
        });
        self.queued.push(false);
        self.classes[root].pointee = Some(id);
        self.enqueue(root);
        id
    }

    fn add_gep_transfer(&mut self, src: usize, dst: usize, delta: FieldLocation) {
        let target = self.pointee_of(src);
        let target = self.find(target);
        self.classes[target]
            .gep_succ
            .push(GepTransfer { dst, delta });
        self.enqueue(target);
    }

    /// Replay one-hop arithmetic whenever its source target changes.  A field-only target may
    /// translate each recorded allocation-relative alternative.  A summary alternative wins
    /// conservatively: translating only the fields would drop the ordinary alternative.
    fn replay_gep_transfers(&mut self, class: usize) {
        let root = self.find(class);
        let transfer_len = self.classes[root].gep_succ.len();
        if transfer_len == 0 {
            return;
        }
        let summary = self.classes[root].has_summary_region;
        let region_len = self.classes[root].field_regions.len();
        if self.classes[root].gep_processed_succ_len == transfer_len
            && self.classes[root].gep_processed_region_len == region_len
            && self.classes[root].gep_processed_summary == summary
        {
            return;
        }
        self.classes[root].gep_processed_succ_len = transfer_len;
        self.classes[root].gep_processed_region_len = region_len;
        self.classes[root].gep_processed_summary = summary;
        let transfers = self.classes[root].gep_succ.clone();
        let regions = self.classes[root].field_regions.clone();
        let regions_empty = regions.is_empty();
        if summary {
            let destinations = transfers
                .iter()
                .map(|transfer| transfer.dst)
                .collect::<HashSet<_>>();
            for dst in destinations {
                let dst_p = self.pointee_of(dst);
                self.join(dst_p, root, PROV_DIRECT_ADDRESS);
            }
            if transfers
                .iter()
                .any(|transfer| transfer.delta != FieldLocation::Exact(0))
            {
                let canonical_root = self.find(root);
                let mut roots = self.classes[canonical_root].summary_roots.clone();
                roots.extend(regions.iter().map(|(allocation, _)| *allocation));
                for allocation in roots {
                    let unknown =
                        self.field_class(allocation, FieldRegion::address(FieldLocation::Unknown));
                    self.join(canonical_root, unknown, PROV_DIRECT_ADDRESS);
                }
            }
            self.metrics.steens_gep_replay_transfers += transfers.len() as u64;
            return;
        }
        let transfers = transfers.into_iter().collect::<HashSet<_>>();
        // Unknown subsumes every exact/lane alternative of its own allocation.  Retain other
        // roots independently: a cross-root join is real aliasing, not permission to discard
        // their precise alternatives.
        let mut regions_by_root = BTreeMap::<NodeId, Vec<FieldRegion>>::new();
        for (allocation, region) in regions {
            let entry = regions_by_root.entry(allocation).or_default();
            if matches!(region.location, FieldLocation::Unknown) {
                entry.clear();
                entry.push(region);
            } else if !entry
                .iter()
                .any(|existing| matches!(existing.location, FieldLocation::Unknown))
            {
                entry.push(region);
            }
        }
        if !regions_by_root.is_empty()
            && regions_by_root.values().all(|regions| {
                regions.len() == 1 && matches!(regions[0].location, FieldLocation::Unknown)
            })
        {
            for dst in transfers
                .iter()
                .map(|transfer| transfer.dst)
                .collect::<HashSet<_>>()
            {
                let dst_p = self.pointee_of(dst);
                self.join(dst_p, root, PROV_DIRECT_ADDRESS);
            }
            self.metrics.steens_gep_replay_transfers += transfers.len() as u64;
            return;
        }
        for transfer in transfers {
            self.metrics.steens_gep_replay_transfers += 1;
            let dst_p = self.pointee_of(transfer.dst);
            if transfer.delta == FieldLocation::Exact(0) {
                self.join(dst_p, root, PROV_DIRECT_ADDRESS);
                continue;
            }
            // An unbound synthetic pointee is neither a summary nor a field alternative yet.
            // Deferring it is essential: equating `p + d` with that placeholder before its late
            // F0 binding arrives irreversibly aliases F0 and the shifted result.
            if regions_empty {
                continue;
            }
            // `p = p + exact_nonzero` requires every repeated exact shift.  In our finite exact
            // vocabulary that closure necessarily reaches this allocation's Unknown cell; jump
            // there directly instead of walking every named offset.  Do not apply this to lanes:
            // their congruence class is a meaningful bounded invariant.
            let exact_self_cycle = matches!(transfer.delta, FieldLocation::Exact(offset) if offset != 0)
                && self.find(dst_p) == self.find(root);
            for (allocation, regions) in &regions_by_root {
                for region in regions {
                    self.metrics.steens_gep_region_shifts += 1;
                    let target = if exact_self_cycle
                        && matches!(region.location, FieldLocation::Exact(_))
                    {
                        self.field_class(
                            *allocation,
                            FieldRegion::access(FieldLocation::Unknown, region.width),
                        )
                    } else {
                        let shifted =
                            FieldRegion::access(region.location.add(transfer.delta), region.width);
                        self.shifted_field_class(*allocation, shifted)
                    };
                    self.join(dst_p, target, PROV_DIRECT_ADDRESS);
                }
            }
        }
    }

    /// Select a bounded root-relative target for replayed pointer arithmetic.  Exact locations
    /// may only reuse the fixed certificate vocabulary.  Lanes are admitted lazily but capped;
    /// every failure routes to this allocation's own unknown cell.
    fn shifted_field_class(&mut self, allocation: NodeId, region: FieldRegion) -> usize {
        let precise = match region.location {
            FieldLocation::Exact(offset) => {
                self.exact_field_locations
                    .get(&allocation)
                    .is_some_and(|locations| locations.contains(&region.location))
                    || self.direct_gep_exact_offsets.contains(&offset)
            }
            FieldLocation::Lane(_) => {
                let fixed = self
                    .exact_field_locations
                    .get(&allocation)
                    .is_some_and(|locations| locations.contains(&region.location));
                fixed || self.admit_derived_lane(allocation, region.location)
            }
            FieldLocation::Unknown => false,
        };
        if !precise {
            match region.location {
                FieldLocation::Exact(_) => self.metrics.steens_gep_missing_exact_widenings += 1,
                FieldLocation::Lane(_) => self.metrics.steens_gep_lane_cap_widenings += 1,
                FieldLocation::Unknown => {}
            }
        }
        let region = precise
            .then_some(region)
            .unwrap_or(FieldRegion::access(FieldLocation::Unknown, region.width));
        self.field_class(allocation, region)
    }

    fn admit_derived_lane(&mut self, allocation: NodeId, location: FieldLocation) -> bool {
        let lanes = self.derived_lanes_by_root.entry(allocation).or_default();
        if lanes.contains(&location) {
            return true;
        }
        if lanes.len() >= knobs::STEENS_ONE_HOP_DERIVED_LANE_CAP {
            return false;
        }
        lanes.insert(location);
        true
    }

    /// Return the independently certified allocation-relative storage cell for `address`,
    /// using the same per-allocation field identities as certified GEPs.
    fn exact_storage_class(
        &mut self,
        address: NodeId,
        width: Option<u64>,
        direct_root_at_zero: bool,
    ) -> Option<usize> {
        let address = self.exact_addresses[address.0 as usize]?;
        Some(match address.location {
            FieldLocation::Exact(0) if !address.via_gep && direct_root_at_zero => {
                let root = self.class_of(address.root);
                if width != Some(0) {
                    let region = self
                        .field_class(address.root, FieldRegion::access(address.location, width));
                    self.join(root, region, PROV_DIRECT_ADDRESS)
                } else {
                    root
                }
            }
            location => self.field_class(address.root, FieldRegion::access(location, width)),
        })
    }

    /// Resolve a memory address to its storage class, preferring an allocation-relative
    /// certificate over the (potentially much broader) Steensgaard carrier class.
    fn storage_class_for_address(
        &mut self,
        address: NodeId,
        width: Option<u64>,
        direct_root_at_zero: bool,
    ) -> usize {
        if let Some(storage) = self.exact_storage_class(address, width, direct_root_at_zero) {
            storage
        } else {
            let class = self.class_of(address);
            self.pointee_of(class)
        }
    }

    /// Allocation-relative byte-region identity used by both the fallback answer and Kahlon
    /// partitioning. Exact, affine-lane, and memcpy accesses join only when their byte intervals
    /// can overlap; an unknown location or extent naturally aliases every region of the object.
    fn field_class(&mut self, root: NodeId, region: FieldRegion) -> usize {
        if let Some(&class) = self.field_classes.get(&(root, region)) {
            return self.find(class);
        }

        let id = self.classes.len();
        let mut data = ClassData {
            parent: id,
            size: 1,
            has_location: true,
            ..ClassData::default()
        };
        data.field_regions.insert((root, region));
        if let Some(global_index) = self.global_object_index_by_node[root.0 as usize] {
            data.global_objs.insert(global_index);
        }
        if let Some(sources) = self.field_escape_sources_by_root.get(&root) {
            data.esc = true;
            data.allocation_escape = true;
            data.escape_sources.insert(
                self.provenance
                    .first_lexicographic(sources.iter())
                    .expect("escaped field root has a provenance source"),
            );
        }
        self.classes.push(data);
        self.queued.push(false);
        self.field_classes.insert((root, region), id);

        self.fields_by_root.entry(root).or_default().push(id);
        self.field_inventory
            .entry(root)
            .or_default()
            .push((region, id));
        let aliasing = self
            .field_inventory
            .get(&root)
            .into_iter()
            .flatten()
            .filter_map(|&(candidate_region, class)| {
                (candidate_region != region && region.may_overlap(candidate_region))
                    .then_some(class)
            })
            .collect::<Vec<_>>();
        let mut class = id;
        for alias in aliasing {
            class = self.join(class, alias, PROV_DIRECT_ADDRESS);
        }
        class
    }

    fn set_ext(&mut self, class: usize) {
        let root = self.find(class);
        if !self.classes[root].ext {
            self.classes[root].ext = true;
            self.enqueue(root);
        }
    }

    fn set_external_escaped_union(&mut self, class: usize) {
        let root = self.find(class);
        if !self.classes[root].ext || !self.classes[root].external_escaped_union {
            self.classes[root].ext = true;
            self.classes[root].external_escaped_union = true;
            self.enqueue(root);
        }
    }

    fn set_esc_with_source(&mut self, class: usize, source: String) {
        let source = self.provenance.intern(source);
        self.set_esc_with_id(class, source);
    }

    fn set_esc_with_id(&mut self, class: usize, source: ProvenanceId) {
        let root = self.find(class);
        let changed = self.classes[root].escape_sources.insert(source);
        if !self.classes[root].esc || !self.classes[root].allocation_escape || changed {
            self.classes[root].esc = true;
            self.classes[root].allocation_escape = true;
            self.enqueue(root);
        }
    }

    fn set_esc_sources(&mut self, class: usize, sources: &BTreeSet<ProvenanceId>) {
        self.set_esc_sources_kind(class, sources, true);
    }

    fn set_esc_sources_kind(
        &mut self,
        class: usize,
        sources: &BTreeSet<ProvenanceId>,
        allocation_escape: bool,
    ) {
        let root = self.find(class);
        let old_len = self.classes[root].escape_sources.len();
        self.classes[root]
            .escape_sources
            .extend(sources.iter().cloned());
        if !self.classes[root].esc
            || self.classes[root].escape_sources.len() != old_len
            || (allocation_escape && !self.classes[root].allocation_escape)
        {
            self.classes[root].esc = true;
            self.classes[root].allocation_escape |= allocation_escape;
            self.enqueue(root);
        }
    }

    fn join(&mut self, left: usize, right: usize, provenance: u8) -> usize {
        self.metrics.steens_join_attempts += 1;
        let mut a = self.find(left);
        let mut b = self.find(right);
        if a == b {
            debug_assert!(!(self.classes[a].has_carrier && self.classes[a].has_location));
            self.classes[a].provenance |= provenance;
            return a;
        }
        debug_assert!(
            !(self.classes[a].has_carrier && self.classes[b].has_location)
                && !(self.classes[a].has_location && self.classes[b].has_carrier),
            "attempted to merge Steensgaard carrier class {a} with location class {b}"
        );
        self.metrics.steens_join_successes += 1;
        if self.classes[a].size < self.classes[b].size {
            std::mem::swap(&mut a, &mut b);
        }
        // GEP replay depends only on address alternatives/subscriptions, not on content, Ω, or
        // callsite facts. Do not invalidate its frontier for an otherwise unrelated UF join.
        let gep_structure_grew = (self.classes[b].has_summary_region
            && (!self.classes[a].has_summary_region
                || self.classes[b]
                    .summary_roots
                    .iter()
                    .any(|root| !self.classes[a].summary_roots.contains(root))))
            || self.classes[b]
                .field_regions
                .iter()
                .any(|region| !self.classes[a].field_regions.contains(region))
            || self.classes[b]
                .gep_succ
                .iter()
                .any(|transfer| !self.classes[a].gep_succ.contains(transfer));

        self.classes[b].parent = a;
        self.classes[a].size += self.classes[b].size;
        self.classes[a].node_count += self.classes[b].node_count;
        self.classes[a].has_carrier |= self.classes[b].has_carrier;
        self.classes[a].has_location |= self.classes[b].has_location;
        self.classes[a].has_summary_region |= self.classes[b].has_summary_region;
        self.classes[a].has_empty_witness |= self.classes[b].has_empty_witness;
        self.classes[a].ext |= self.classes[b].ext;
        self.classes[a].external_escaped_union |= self.classes[b].external_escaped_union;
        self.classes[a].esc |= self.classes[b].esc;
        self.classes[a].allocation_escape |= self.classes[b].allocation_escape;
        self.classes[a].provenance |= self.classes[b].provenance | provenance;
        let mut other_escape_sources = std::mem::take(&mut self.classes[b].escape_sources);
        if self.classes[a].escape_sources.len() < other_escape_sources.len() {
            std::mem::swap(
                &mut self.classes[a].escape_sources,
                &mut other_escape_sources,
            );
        }
        self.classes[a].escape_sources.extend(other_escape_sources);

        let other_sites = std::mem::take(&mut self.classes[b].icall_sites);
        self.classes[a].icall_sites.extend(other_sites);
        let other_fns = std::mem::take(&mut self.classes[b].fn_objs);
        self.classes[a].fn_objs.extend(other_fns);
        let other_globals = std::mem::take(&mut self.classes[b].global_objs);
        self.classes[a].global_objs.extend(other_globals);
        let other_field_regions = std::mem::take(&mut self.classes[b].field_regions);
        self.classes[a].field_regions.extend(other_field_regions);
        let other_summary_roots = std::mem::take(&mut self.classes[b].summary_roots);
        self.classes[a].summary_roots.extend(other_summary_roots);
        let other_gep_succ = std::mem::take(&mut self.classes[b].gep_succ);
        self.classes[a].gep_succ.extend(other_gep_succ);
        let other_content_succ = std::mem::take(&mut self.classes[b].content_succ);
        self.classes[a].content_succ.extend(other_content_succ);
        // The merged fact set must be offered to both roots' successor lists. Most joins happen
        // before propagation starts, so resetting is both simple and cheap; subsequent unchanged
        // enqueues use the frontier above.
        self.classes[a].content_pushed_succ_len = 0;
        self.classes[a].content_pushed_ext = false;
        self.classes[a].content_pushed_external_escaped_union = false;
        self.classes[a].content_pushed_empty = false;
        if gep_structure_grew {
            self.classes[a].gep_processed_succ_len = 0;
            self.classes[a].gep_processed_region_len = 0;
            self.classes[a].gep_processed_summary = false;
        }
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
            (Some(pa), Some(pb)) => Some(self.join(pa, pb, provenance)),
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
             max_class_sites={} max_class_fns={} max_class_candidate_pairs={} gep_replays={} \
             gep_shifts={} gep_missing_exact={} gep_lane_cap={} worklist_len={}",
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
            self.metrics.steens_gep_replay_transfers,
            self.metrics.steens_gep_region_shifts,
            self.metrics.steens_gep_missing_exact_widenings,
            self.metrics.steens_gep_lane_cap_widenings,
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
    std::env::var_os(knobs::ENV_STEENS_PROFILE).is_some()
}

fn steens_profile_interval_candidate_pairs() -> u64 {
    std::env::var(knobs::ENV_STEENS_PROFILE_INTERVAL)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|&value| value > 0)
        .unwrap_or(knobs::STEENS_PROFILE_INTERVAL_CANDIDATE_PAIRS)
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
    use pangs_pir::{AbiClass, Func, Global, Stmt, ValueKind};

    use super::*;

    fn fixture(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/synthetic/m1_4")
            .join(name)
    }

    #[test]
    fn global_storage_root_index_inverts_only_root_class_payloads() {
        let mut classes = vec![ClassData::default(); 5];
        for (index, class) in classes.iter_mut().enumerate() {
            class.parent = index;
        }
        classes[0].global_objs.extend([0, 2]);
        classes[2].global_objs.insert(1);
        classes[3].parent = 2;
        classes[3].global_objs.insert(2);
        classes[4].global_objs.extend([0, 1]);

        assert_eq!(
            global_storage_roots_index(&classes, 3),
            vec![vec![0, 4], vec![2, 4], vec![0]]
        );
    }

    #[test]
    fn proven_scalar_memory_payload_does_not_join_pointer_fields() {
        let mut lowering = pangs_pir::LoweringStats::default();
        lowering.semantic_value_kinds.extend([
            ("%f::scalar.addr".into(), ValueKind::Pointer),
            ("%f::pointer.addr".into(), ValueKind::Pointer),
            ("%f::scalar".into(), ValueKind::NonPointer),
            ("%f::pointer".into(), ValueKind::Pointer),
            ("7".into(), ValueKind::NonPointer),
        ]);
        let pir = Pir {
            module: "semantic-payload".into(),
            source: None,
            lowering,
            target: None,
            functions: vec![Func {
                key: "f".into(),
                sig: void_sig(),
                param_names: Vec::new(),
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                body: vec![
                    Stmt::Gep {
                        dest: "%f::scalar.addr".into(),
                        base: "@aggregate".into(),
                        byte_off: Some(0),
                        lane: None,
                        loc: None,
                    },
                    Stmt::Store {
                        address: "%f::scalar.addr".into(),
                        value: "7".into(),
                        volatile: false,
                        access_bytes: Some(8),
                        loc: None,
                    },
                    Stmt::Gep {
                        dest: "%f::pointer.addr".into(),
                        base: "@aggregate".into(),
                        byte_off: Some(8),
                        lane: None,
                        loc: None,
                    },
                    Stmt::Store {
                        address: "%f::pointer.addr".into(),
                        value: "@target".into(),
                        volatile: false,
                        access_bytes: Some(8),
                        loc: None,
                    },
                    Stmt::Load {
                        dest: "%f::scalar".into(),
                        address: "%f::scalar.addr".into(),
                        volatile: false,
                        access_bytes: Some(8),
                        loc: None,
                    },
                    Stmt::Load {
                        dest: "%f::pointer".into(),
                        address: "%f::pointer.addr".into(),
                        volatile: false,
                        access_bytes: Some(8),
                        loc: None,
                    },
                ],
            }],
            globals: vec![
                Global {
                    key: "aggregate".into(),
                    ..Global::default()
                },
                Global {
                    key: "target".into(),
                    ..Global::default()
                },
            ],
            global_init: Vec::new(),
        };
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        assert!(pag.edges.iter().any(|edge| {
            edge.kind == pangs_pag::EdgeKind::Store
                && pag.nodes[edge.src.0 as usize].label.ends_with(":7")
        }));

        for solved in [
            solve_steensgaard(&pir, &pag, BuildMode::Executable),
            solve_andersen(&pir, &pag, BuildMode::Executable, u64::MAX),
        ] {
            let scalar = solved.nodes.get("val:f:%f::scalar");
            assert!(
                scalar.is_none_or(|node| node.pointee_globals.is_empty()),
                "proven scalar load acquired a pointer target"
            );
            let pointer = solved.nodes.get("val:f:%f::pointer").unwrap();
            assert!(pointer.pointee_globals.iter().any(|key| key == "target"));
        }
    }

    #[test]
    fn positive_null_fact_does_not_bridge_unrelated_allocations() {
        let mut pir: Pir = serde_json::from_str(
            r#"{
                "module":"positive-null",
                "globals":[{"key":"Cell"},{"key":"A"},{"key":"B"}],
                "functions":[{"key":"f","sig":{"ret":{"class":"void"},"params":[]},"body":[
                    {"kind":"store","address":"@Cell","value":"@A","access_bytes":8},
                    {"kind":"store","address":"@Cell","value":"null","access_bytes":8},
                    {"kind":"load","dest":"loaded","address":"@Cell","access_bytes":8},
                    {"kind":"assign","dest":"maybe-b","sources":["@B","null"]}
                ]}]
            }"#,
        )
        .unwrap();
        pir.lowering.semantic_value_kinds.extend([
            ("null".into(), ValueKind::Pointer),
            ("loaded".into(), ValueKind::Pointer),
            ("maybe-b".into(), ValueKind::Pointer),
        ]);
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        assert!(pag.edges.iter().any(|edge| {
            edge.kind == pangs_pag::EdgeKind::Store
                && pag.nodes[edge.src.0 as usize].canonical_pointer_null
        }));

        let solved = solve_steensgaard_with_points_to(&pir, &pag, BuildMode::Executable);
        let null = &solved.nodes["val:f:null"];
        assert!(null.has_empty_witness);
        assert!(null.proven_empty);
        assert!(!null.external);
        assert_eq!(
            solved.node_points_to["val:f:loaded"],
            BTreeSet::from(["A".to_string()])
        );
        assert_eq!(
            solved.node_points_to["val:f:maybe-b"],
            BTreeSet::from(["B".to_string()])
        );
        assert!(solved.nodes["val:f:loaded"].has_empty_witness);
        assert!(!solved.nodes["val:f:loaded"].proven_empty);
        assert!(solved.nodes["val:f:maybe-b"].has_empty_witness);
        assert!(!solved.nodes["val:f:maybe-b"].proven_empty);

        let (_, classes) = solve_steensgaard_with_classes(&pir, &pag, BuildMode::Executable);
        let null_node = pag
            .nodes
            .iter()
            .find(|node| node.canonical_pointer_null)
            .unwrap();
        let null_class = classes.class_of(null_node.id);
        assert!(classes.pointee[null_class].is_none());
        assert!(!classes.ext[null_class]);
        assert!(!classes.esc[null_class]);
    }

    #[test]
    fn reserved_inttoptr_empty_witness_survives_copy_and_memory() {
        let mut pir: Pir = serde_json::from_str(
            r#"{
                "module":"reserved-empty-flow",
                "target":{"triple":"x86_64","data_layout":"e-p:64:64","supported_atomic_widths":[8,16,32,64]},
                "functions":[{"key":"f","sig":{"ret":{"class":"void"},"params":[]},"body":[
                    {"kind":"alloca","dest":"slot","ty":"ptr"},
                    {"kind":"int_to_ptr","dest":"sentinel","source":"8","integer_bits":64,"pointer_bits":64,"pointer_address_space":0},
                    {"kind":"assign","dest":"copied","sources":["sentinel"]},
                    {"kind":"store","address":"slot","value":"copied","access_bytes":8},
                    {"kind":"load","dest":"loaded","address":"slot","access_bytes":8}
                ]}]
            }"#,
        )
        .unwrap();
        pir.lowering.semantic_value_kinds.extend([
            ("slot".into(), ValueKind::Pointer),
            ("sentinel".into(), ValueKind::Pointer),
            ("copied".into(), ValueKind::Pointer),
            ("loaded".into(), ValueKind::Pointer),
        ]);
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        assert!(!pag
            .omega_seeds
            .iter()
            .any(|seed| seed.kind == OmegaSeedKind::IntToPtr));

        let solved = solve_steensgaard_with_points_to(&pir, &pag, BuildMode::Executable);
        for label in ["val:f:sentinel", "val:f:copied", "val:f:loaded"] {
            let resolution = &solved.nodes[label];
            assert!(resolution.has_empty_witness, "{label}");
            assert!(resolution.proven_empty, "{label}");
            assert!(
                solved
                    .node_points_to
                    .get(label)
                    .is_none_or(BTreeSet::is_empty),
                "{label}"
            );
        }
    }

    #[test]
    fn fields_keep_exact_tags_and_root_specific_boundary_closure() {
        let pir = Pir {
            module: "field-owner-coherence".into(),
            source: None,
            lowering: Default::default(),
            target: None,
            functions: Vec::new(),
            globals: vec![
                Global {
                    key: "A".into(),
                    ..Global::default()
                },
                Global {
                    key: "B".into(),
                    ..Global::default()
                },
            ],
            global_init: Vec::new(),
        };
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        let object = |key: &str| {
            pag.nodes
                .iter()
                .find(|node| node.label == format!("obj:global:{key}"))
                .unwrap()
                .id
        };
        let mut solver = Solver::new(&pir, &pag, BuildMode::Library);
        let field = solver.field_class(object("A"), FieldRegion::address(FieldLocation::Exact(8)));
        let contents = solver.pointee_of(field);
        let a = solver.class_of(object("A"));
        let b = solver.class_of(object("B"));
        let owner = solver.join(a, b, PROV_DIRECT_ADDRESS);
        solver.set_ext(owner);
        solver.set_esc_with_source(owner, "test:owner-escape".into());
        solver.escape_allocation_fields_with_source(
            object("A"),
            "test:exact-field-escape".to_string(),
        );
        solver.escape_allocation_fields_with_source(
            object("A"),
            "test:later-root-witness".to_string(),
        );

        while let Some(class) = solver.worklist.pop_front() {
            solver.queued[class] = false;
            let root = solver.find(class);
            solver.process_class(root);
        }
        solver.assert_field_root_coherence();

        let field = solver.find(field);
        assert_eq!(solver.classes[field].global_objs.len(), 1);
        assert!(solver.classes[field].global_objs.contains(&0));
        assert!(solver.classes[field].fn_objs.is_empty());
        assert!(!solver.classes[field].ext);
        assert!(solver.classes[field].esc);
        assert!(solver.classes[field]
            .escape_sources
            .iter()
            .any(|&source| solver.provenance.get(source) == "test:exact-field-escape"));
        assert!(!solver.classes[field]
            .escape_sources
            .iter()
            .any(|&source| solver.provenance.get(source) == "test:later-root-witness"));
        assert!(solver.field_escape_sources_by_root[&object("A")]
            .iter()
            .any(|&source| solver.provenance.get(source) == "test:later-root-witness"));
        let contents = solver.find(contents);
        assert!(solver.classes[contents].ext);
        assert!(solver.classes[contents].esc);
    }

    #[test]
    fn allocation_escape_replays_late_roots_and_fields_without_cross_root_leakage() {
        let pir: Pir = serde_json::from_str(
            r#"{
            "module":"late-allocation-escape",
            "globals":[{"key":"A"},{"key":"B"},{"key":"C"}],"functions":[]
        }"#,
        )
        .unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        let object = |key: &str| {
            pag.nodes
                .iter()
                .find(|node| node.label == format!("obj:global:{key}"))
                .unwrap()
                .id
        };
        let mut solver = Solver::new(&pir, &pag, BuildMode::Executable);
        let a8 = solver.field_class(object("A"), FieldRegion::address(FieldLocation::Exact(8)));
        let b8 = solver.field_class(object("B"), FieldRegion::address(FieldLocation::Exact(8)));
        let c8 = solver.field_class(object("C"), FieldRegion::address(FieldLocation::Exact(8)));
        // A boundary arrives before its target has any allocation identity.
        let unbound = solver.pointee_of(a8);
        solver.set_esc_with_source(unbound, "test:late-boundary".into());
        let drain = |solver: &mut Solver<'_>| {
            while let Some(class) = solver.worklist.pop_front() {
                solver.queued[class] = false;
                solver.process_class(class);
            }
        };
        drain(&mut solver);
        let a = solver.class_of(object("A"));
        let escaped = solver.join(unbound, a, PROV_MEMORY_MERGING);
        drain(&mut solver);
        let field = solver.find(a8);
        assert!(solver.classes[field].esc);
        let b = solver.class_of(object("B"));
        solver.join(escaped, b, PROV_MEMORY_MERGING);
        drain(&mut solver);
        let field = solver.find(b8);
        assert!(
            solver.classes[field].esc,
            "a second late allocation root must replay escape"
        );
        let late = solver.field_class(object("B"), FieldRegion::address(FieldLocation::Exact(16)));
        let contents = solver.pointee_of(late);
        drain(&mut solver);
        let late = solver.find(late);
        let contents = solver.find(contents);
        assert!(solver.classes[late].esc);
        assert!(
            !solver.classes[late].ext,
            "escape is not an external field payload"
        );
        assert!(
            solver.classes[contents].ext,
            "late loads from escaped fields must remain unknown"
        );
        let unrelated = solver.find(c8);
        assert!(!solver.classes[unrelated].esc);
        assert!(!solver.classes[unrelated].ext);
        assert!(!solver
            .field_escape_sources_by_root
            .contains_key(&object("C")));
    }

    #[test]
    fn affine_gep_lanes_alias_only_matching_residue_classes() {
        let fn_lane = FieldLocation::Lane(pangs_pir::GepLane::new(24, 8).unwrap());
        let used_lane = FieldLocation::Lane(pangs_pir::GepLane::new(24, 16).unwrap());
        let wider_fn_lane = FieldLocation::Lane(pangs_pir::GepLane::new(48, 32).unwrap());

        assert!(fn_lane.may_alias(FieldLocation::Exact(8)));
        assert!(fn_lane.may_alias(FieldLocation::Exact(32)));
        assert!(fn_lane.may_alias(wider_fn_lane));
        assert!(!fn_lane.may_alias(FieldLocation::Exact(0)));
        assert!(!fn_lane.may_alias(used_lane));
        assert_eq!(
            fn_lane.add(FieldLocation::Exact(8)),
            FieldLocation::Lane(pangs_pir::GepLane::new(24, 16).unwrap())
        );
        assert_eq!(
            FieldLocation::from_gep(
                None,
                Some(pangs_pir::GepLane {
                    modulus: 0,
                    residue: 8,
                }),
            ),
            FieldLocation::Unknown
        );
    }

    #[test]
    fn typed_regions_use_byte_overlap_for_exact_and_affine_accesses() {
        let exact = |offset, width| FieldRegion::access(FieldLocation::Exact(offset), Some(width));
        let lane = |modulus, residue, width| {
            FieldRegion::access(
                FieldLocation::Lane(pangs_pir::GepLane::new(modulus, residue).unwrap()),
                Some(width),
            )
        };

        assert!(exact(8, 8).may_overlap(exact(12, 8)));
        assert!(!exact(8, 8).may_overlap(exact(16, 8)));
        assert!(lane(24, 8, 8).may_overlap(exact(12, 8)));
        assert!(!lane(24, 8, 8).may_overlap(lane(24, 16, 8)));
        assert!(lane(24, 8, 9).may_overlap(lane(24, 16, 8)));
        assert!(FieldRegion::access(FieldLocation::Unknown, Some(1)).may_overlap(exact(4096, 1)));
        assert!(FieldRegion::access(FieldLocation::Exact(0), None).may_overlap(exact(4096, 1)));
    }

    #[test]
    fn allocation_relative_copy_preserves_distinct_pointer_carriers() {
        let mut lowering = pangs_pir::LoweringStats::default();
        lowering.semantic_value_kinds.extend([
            ("%f::field".into(), ValueKind::Pointer),
            ("%f::copy".into(), ValueKind::Pointer),
        ]);
        let pir = Pir {
            module: "allocation-relative-copy".into(),
            source: None,
            lowering,
            target: None,
            functions: vec![Func {
                key: "f".into(),
                sig: void_sig(),
                param_names: Vec::new(),
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                body: vec![
                    Stmt::Gep {
                        dest: "%f::field".into(),
                        base: "@aggregate".into(),
                        byte_off: Some(8),
                        lane: None,
                        loc: None,
                    },
                    Stmt::Assign {
                        dest: "%f::copy".into(),
                        sources: vec!["%f::field".into()],
                        loc: None,
                    },
                ],
            }],
            globals: vec![Global {
                key: "aggregate".into(),
                ..Global::default()
            }],
            global_init: Vec::new(),
        };
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        let node = |suffix: &str| {
            pag.nodes
                .iter()
                .find(|node| node.label.ends_with(suffix))
                .unwrap()
                .id
        };
        let field = node(":%f::field");
        let copy = node(":%f::copy");

        let (_, classes) = solve_steensgaard_with_classes(&pir, &pag, BuildMode::Executable);
        let field_class = classes.class_of(field);
        let copy_class = classes.class_of(copy);
        assert_ne!(
            field_class, copy_class,
            "a certified pointer copy need not merge its carrier classes"
        );
        assert_eq!(
            classes.pointee[field_class], classes.pointee[copy_class],
            "both carriers must still designate the same allocation-relative field"
        );
    }

    fn field_contamination_fixture(extra: Vec<Stmt>, globals: Vec<Global>) -> (Pir, Pag) {
        let mut lowering = pangs_pir::LoweringStats::default();
        lowering
            .semantic_value_kinds
            .insert("%f::field".into(), ValueKind::Pointer);
        let mut body = vec![Stmt::Gep {
            dest: "%f::field".into(),
            base: "@aggregate".into(),
            byte_off: Some(8),
            lane: None,
            loc: None,
        }];
        body.extend(extra);
        let pir = Pir {
            module: "field-contamination".into(),
            source: None,
            lowering,
            target: None,
            functions: vec![Func {
                key: "f".into(),
                sig: void_sig(),
                param_names: Vec::new(),
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                body,
            }],
            globals,
            global_init: Vec::new(),
        };
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        (pir, pag)
    }

    fn class_for_label(classes: &SteensClasses, pag: &Pag, label: &str) -> usize {
        let node = pag.nodes.iter().find(|node| node.label == label).unwrap();
        classes.class_of(node.id)
    }

    #[test]
    fn constant_only_object_retains_distinct_field_storage() {
        let (pir, pag) = field_contamination_fixture(
            vec![Stmt::Assign {
                dest: "%f::result".into(),
                sources: vec!["%f::field".into()],
                loc: None,
            }],
            vec![Global {
                key: "aggregate".into(),
                ..Global::default()
            }],
        );
        let (_, classes) = solve_steensgaard_with_classes(&pir, &pag, BuildMode::Executable);
        let object = class_for_label(&classes, &pag, "obj:global:aggregate");
        let address = class_for_label(&classes, &pag, "val:f:%f::field");
        assert_ne!(classes.pointee[address], Some(object));
    }

    #[test]
    fn unknown_gep_overlaps_every_field_of_its_allocation() {
        let (pir, pag) = field_contamination_fixture(
            vec![Stmt::Gep {
                dest: "%f::dynamic".into(),
                base: "@aggregate".into(),
                byte_off: None,
                lane: None,
                loc: None,
            }],
            vec![Global {
                key: "aggregate".into(),
                ..Global::default()
            }],
        );
        let (_, classes) = solve_steensgaard_with_classes(&pir, &pag, BuildMode::Executable);
        let field = class_for_label(&classes, &pag, "val:f:%f::field");
        let dynamic = class_for_label(&classes, &pag, "val:f:%f::dynamic");
        assert_eq!(classes.pointee[field], classes.pointee[dynamic]);
    }

    #[test]
    fn one_hop_gep_replays_after_late_field_binding_without_aliasing_base() {
        let (pir, pag) = field_contamination_fixture(
            vec![Stmt::Assign {
                dest: "%f::result".into(),
                sources: vec!["%f::field".into()],
                loc: None,
            }],
            vec![Global {
                key: "aggregate".into(),
                ..Global::default()
            }],
        );
        let carrier = pag
            .nodes
            .iter()
            .find(|node| node.label == "val:f:%f::field")
            .unwrap()
            .id;
        let allocation = pag
            .nodes
            .iter()
            .find(|node| node.label == "obj:global:aggregate")
            .unwrap()
            .id;
        let result = pag
            .nodes
            .iter()
            .find(|node| node.label == "val:f:%f::result")
            .unwrap()
            .id;
        let mut solver = Solver::new(&pir, &pag, BuildMode::Executable);
        let carrier_class = solver.class_of(carrier);
        let result_class = solver.class_of(result);
        let derived = solver.pointee_of(carrier_class);
        solver.add_gep_transfer(carrier_class, result_class, FieldLocation::Exact(8));
        // This is the reordered schedule: the one-hop GEP sees an unbound placeholder first.
        while let Some(class) = solver.worklist.pop_front() {
            solver.queued[class] = false;
            solver.process_class(class);
        }
        let result_target = solver.pointee_of(result_class);
        assert_ne!(solver.find(derived), solver.find(result_target));
        let f0 = solver.field_class(allocation, FieldRegion::address(FieldLocation::Exact(0)));
        let f8 = solver.field_class(allocation, FieldRegion::address(FieldLocation::Exact(8)));
        solver.join(derived, f0, PROV_DIRECT_ADDRESS);
        while let Some(class) = solver.worklist.pop_front() {
            solver.queued[class] = false;
            solver.process_class(class);
        }
        let result_target = solver.pointee_of(result_class);
        let target = solver.find(result_target);
        assert_eq!(target, solver.find(f8));
        assert_ne!(target, solver.find(f0));
        // A second field arriving after the first successful replay must be translated too.
        let source_f8 =
            solver.field_class(allocation, FieldRegion::address(FieldLocation::Exact(8)));
        solver
            .exact_field_locations
            .entry(allocation)
            .or_default()
            .insert(FieldLocation::Exact(16));
        let f16 = solver.field_class(allocation, FieldRegion::address(FieldLocation::Exact(16)));
        solver.join(derived, source_f8, PROV_DIRECT_ADDRESS);
        while let Some(class) = solver.worklist.pop_front() {
            solver.queued[class] = false;
            solver.process_class(class);
        }
        assert_eq!(solver.find(result_target), solver.find(f16));
        solver.assert_one_hop_invariant();
    }

    #[test]
    fn one_hop_gep_from_ordinary_root_connects_late_field_and_excludes_other_root() {
        let (pir, pag) = field_contamination_fixture(
            vec![Stmt::Assign {
                dest: "%f::result".into(),
                sources: vec!["%f::field".into()],
                loc: None,
            }],
            vec![
                Global {
                    key: "aggregate".into(),
                    ..Global::default()
                },
                Global {
                    key: "other".into(),
                    ..Global::default()
                },
            ],
        );
        let id = |label: &str| {
            pag.nodes
                .iter()
                .find(|node| node.label == label)
                .unwrap()
                .id
        };
        let carrier = id("val:f:%f::field");
        let result = id("val:f:%f::result");
        let aggregate = id("obj:global:aggregate");
        let other = id("obj:global:other");
        let mut solver = Solver::new(&pir, &pag, BuildMode::Executable);
        let carrier_class = solver.class_of(carrier);
        let result_class = solver.class_of(result);
        let source = solver.pointee_of(carrier_class);
        let f8 = solver.field_class(aggregate, FieldRegion::address(FieldLocation::Exact(8)));
        let other_f8 = solver.field_class(other, FieldRegion::address(FieldLocation::Exact(8)));
        let aggregate_class = solver.class_of(aggregate);
        solver.join(source, aggregate_class, PROV_DIRECT_ADDRESS);
        solver.add_gep_transfer(carrier_class, result_class, FieldLocation::Exact(8));
        while let Some(class) = solver.worklist.pop_front() {
            solver.queued[class] = false;
            solver.process_class(class);
        }
        let result_target = solver.pointee_of(result_class);
        assert_eq!(solver.find(result_target), solver.find(f8));
        assert_ne!(solver.find(result_target), solver.find(other_f8));
    }

    #[test]
    fn one_hop_zero_gep_over_summary_does_not_materialize_unknown() {
        let (pir, pag) = field_contamination_fixture(
            vec![Stmt::Assign {
                dest: "%f::result".into(),
                sources: vec!["%f::field".into()],
                loc: None,
            }],
            vec![Global {
                key: "aggregate".into(),
                ..Global::default()
            }],
        );
        let id = |label: &str| {
            pag.nodes
                .iter()
                .find(|node| node.label == label)
                .unwrap()
                .id
        };
        let carrier = id("val:f:%f::field");
        let result = id("val:f:%f::result");
        let aggregate = id("obj:global:aggregate");
        let mut solver = Solver::new(&pir, &pag, BuildMode::Executable);
        let carrier_class = solver.class_of(carrier);
        let result_class = solver.class_of(result);
        let source = solver.pointee_of(carrier_class);
        let aggregate_class = solver.class_of(aggregate);
        solver.join(source, aggregate_class, PROV_DIRECT_ADDRESS);
        solver.add_gep_transfer(carrier_class, result_class, FieldLocation::Exact(0));
        while let Some(class) = solver.worklist.pop_front() {
            solver.queued[class] = false;
            solver.process_class(class);
        }
        assert!(!solver
            .field_classes
            .contains_key(&(aggregate, FieldRegion::address(FieldLocation::Unknown))));
    }

    #[test]
    fn one_hop_gep_self_cycle_stays_in_finite_field_domain() {
        let (pir, pag) = field_contamination_fixture(
            Vec::new(),
            vec![Global {
                key: "aggregate".into(),
                ..Global::default()
            }],
        );
        let carrier = pag
            .nodes
            .iter()
            .find(|node| node.label == "val:f:%f::field")
            .unwrap()
            .id;
        let aggregate = pag
            .nodes
            .iter()
            .find(|node| node.label == "obj:global:aggregate")
            .unwrap()
            .id;
        let mut solver = Solver::new(&pir, &pag, BuildMode::Executable);
        let carrier_class = solver.class_of(carrier);
        let source = solver.pointee_of(carrier_class);
        let f0 = solver.field_class(aggregate, FieldRegion::address(FieldLocation::Exact(0)));
        solver.join(source, f0, PROV_DIRECT_ADDRESS);
        // A cyclic p = p + 8 may widen, but cannot manufacture a chain of new exact cells.
        solver.add_gep_transfer(carrier_class, carrier_class, FieldLocation::Exact(8));
        while let Some(class) = solver.worklist.pop_front() {
            solver.queued[class] = false;
            solver.process_class(class);
        }
        assert!(
            solver.field_classes.len() <= 3,
            "{:#?}",
            solver.field_classes
        );
        assert!(solver
            .field_classes
            .contains_key(&(aggregate, FieldRegion::address(FieldLocation::Unknown))));
        solver.assert_one_hop_invariant();
    }

    #[test]
    fn one_hop_gep_mixed_summary_widens_each_field_root() {
        let (pir, pag) = field_contamination_fixture(
            vec![Stmt::Assign {
                dest: "%f::result".into(),
                sources: vec!["%f::field".into()],
                loc: None,
            }],
            vec![
                Global {
                    key: "aggregate".into(),
                    ..Global::default()
                },
                Global {
                    key: "summary".into(),
                    ..Global::default()
                },
            ],
        );
        let id = |label: &str| {
            pag.nodes
                .iter()
                .find(|node| node.label == label)
                .unwrap()
                .id
        };
        let carrier = id("val:f:%f::field");
        let result = id("val:f:%f::result");
        let allocation = id("obj:global:aggregate");
        let summary = id("obj:global:summary");
        let mut solver = Solver::new(&pir, &pag, BuildMode::Executable);
        let carrier_class = solver.class_of(carrier);
        let result_class = solver.class_of(result);
        let summary_class = solver.class_of(summary);
        // Model an actual unstructured alternative, rather than treating a normal allocation
        // base (now Exact(0)) as a summary.
        solver.classes[summary_class].has_summary_region = true;
        solver.classes[summary_class].summary_roots.insert(summary);
        let source = solver.pointee_of(carrier_class);
        let f0 = solver.field_class(allocation, FieldRegion::address(FieldLocation::Exact(0)));
        let f8 = solver.field_class(allocation, FieldRegion::address(FieldLocation::Exact(8)));
        solver.join(source, f0, PROV_DIRECT_ADDRESS);
        solver.join(source, summary_class, PROV_DIRECT_ADDRESS);
        solver.add_gep_transfer(carrier_class, result_class, FieldLocation::Exact(8));
        while let Some(class) = solver.worklist.pop_front() {
            solver.queued[class] = false;
            solver.process_class(class);
        }
        // Do not materialize the expected summary here: doing so would itself join F8
        // and could hide a replay that failed to widen the mixed source.
        let unknown =
            solver.field_classes[&(allocation, FieldRegion::address(FieldLocation::Unknown))];
        let result_target = solver.pointee_of(result_class);
        let target = solver.find(result_target);
        assert_eq!(target, solver.find(unknown));
        assert_eq!(target, solver.find(summary_class));
        assert_eq!(target, solver.find(f8));
        solver.assert_one_hop_invariant();
    }

    #[test]
    fn one_hop_shift_uses_fixed_exact_vocabulary_or_root_unknown() {
        let (pir, pag) = field_contamination_fixture(
            Vec::new(),
            vec![Global {
                key: "aggregate".into(),
                ..Global::default()
            }],
        );
        let allocation = pag
            .nodes
            .iter()
            .find(|node| node.label == "obj:global:aggregate")
            .unwrap()
            .id;
        let mut solver = Solver::new(&pir, &pag, BuildMode::Executable);
        let unknown = solver.field_class(allocation, FieldRegion::address(FieldLocation::Unknown));
        let shifted = solver.shifted_field_class(
            allocation,
            FieldRegion::address(FieldLocation::Exact(1_234_567)),
        );
        assert_eq!(solver.find(shifted), solver.find(unknown));
        solver.direct_gep_exact_offsets.insert(-8);
        let negative = solver.shifted_field_class(
            allocation,
            FieldRegion::access(FieldLocation::Exact(-8), Some(8)),
        );
        let negative_region = FieldRegion::access(FieldLocation::Exact(-8), Some(8));
        let expected_negative = solver.field_class(allocation, negative_region);
        assert_eq!(solver.find(negative), solver.find(expected_negative));
        let lane = FieldLocation::Lane(pangs_pir::GepLane::new(24, 8).unwrap());
        assert!(solver.admit_derived_lane(allocation, lane));
        for residue in 0..knobs::STEENS_ONE_HOP_DERIVED_LANE_CAP {
            let lane = FieldLocation::Lane(pangs_pir::GepLane::new(512, residue as i64).unwrap());
            let _ = solver.admit_derived_lane(allocation, lane);
        }
        let overflow = FieldLocation::Lane(pangs_pir::GepLane::new(1024, 777).unwrap());
        assert!(!solver.admit_derived_lane(allocation, overflow));
    }

    #[test]
    fn one_hop_replayed_negative_and_lane_shifts_keep_disjoint_targets() {
        for (source_location, delta, expected_location, sibling_location) in [
            (
                FieldLocation::Exact(8),
                FieldLocation::Exact(-8),
                FieldLocation::Exact(0),
                FieldLocation::Exact(16),
            ),
            (
                FieldLocation::Lane(pangs_pir::GepLane::new(24, 8).unwrap()),
                FieldLocation::Exact(8),
                FieldLocation::Lane(pangs_pir::GepLane::new(24, 16).unwrap()),
                FieldLocation::Lane(pangs_pir::GepLane::new(24, 0).unwrap()),
            ),
        ] {
            let (pir, pag) = field_contamination_fixture(
                vec![Stmt::Assign {
                    dest: "%f::result".into(),
                    sources: vec!["%f::field".into()],
                    loc: None,
                }],
                vec![Global {
                    key: "aggregate".into(),
                    ..Global::default()
                }],
            );
            let id = |label: &str| {
                pag.nodes
                    .iter()
                    .find(|node| node.label == label)
                    .unwrap()
                    .id
            };
            let allocation = id("obj:global:aggregate");
            let mut solver = Solver::new(&pir, &pag, BuildMode::Executable);
            let src = solver.class_of(id("val:f:%f::field"));
            let dst = solver.class_of(id("val:f:%f::result"));
            let source = solver.field_class(allocation, FieldRegion::address(source_location));
            let expected = solver.field_class(allocation, FieldRegion::address(expected_location));
            let sibling = solver.field_class(allocation, FieldRegion::address(sibling_location));
            let source_target = solver.pointee_of(src);
            solver.join(source_target, source, PROV_DIRECT_ADDRESS);
            solver.add_gep_transfer(src, dst, delta);
            while let Some(class) = solver.worklist.pop_front() {
                solver.queued[class] = false;
                solver.process_class(class);
            }
            let target = solver.pointee_of(dst);
            assert_eq!(solver.find(target), solver.find(expected));
            assert_ne!(solver.find(target), solver.find(sibling));
            assert_ne!(solver.find(target), solver.find(source));
            solver.assert_one_hop_invariant();
        }
    }

    #[test]
    fn one_hop_lane_overflow_reaches_a_late_field_payload() {
        let (pir, pag) = field_contamination_fixture(
            Vec::new(),
            vec![
                Global {
                    key: "aggregate".into(),
                    ..Global::default()
                },
                Global {
                    key: "payload".into(),
                    ..Global::default()
                },
            ],
        );
        let id = |label: &str| {
            pag.nodes
                .iter()
                .find(|node| node.label == label)
                .unwrap()
                .id
        };
        let allocation = id("obj:global:aggregate");
        let mut solver = Solver::new(&pir, &pag, BuildMode::Executable);
        for residue in 0..knobs::STEENS_ONE_HOP_DERIVED_LANE_CAP {
            assert!(solver.admit_derived_lane(
                allocation,
                FieldLocation::Lane(pangs_pir::GepLane::new(512, residue as i64).unwrap()),
            ));
        }
        let rejected = solver.shifted_field_class(
            allocation,
            FieldRegion::address(FieldLocation::Lane(
                pangs_pir::GepLane::new(1024, 777).unwrap(),
            )),
        );
        assert_eq!(solver.metrics.steens_gep_lane_cap_widenings, 1);
        let result_payload = solver.pointee_of(rejected);
        let late = solver.field_class(allocation, FieldRegion::address(FieldLocation::Exact(8)));
        let late_payload = solver.pointee_of(late);
        let payload = solver.class_of(id("obj:global:payload"));
        solver.join(late_payload, payload, PROV_MEMORY_MERGING);
        assert_eq!(solver.find(result_payload), solver.find(payload));
        assert_eq!(
            solver.derived_lanes_by_root[&allocation].len(),
            knobs::STEENS_ONE_HOP_DERIVED_LANE_CAP
        );
        solver.assert_one_hop_invariant();
    }

    #[test]
    fn one_hop_memory_roundtrip_preserves_base_zero_and_unknown_arithmetic() {
        for (unknown_first, offset, reaches_payload) in
            [(false, 8, true), (false, 16, false), (true, 16, true)]
        {
            let mut body = vec![
                serde_json::json!({"kind":"gep", "dest":"slot", "base":"@aggregate", "byte_off":8}),
                serde_json::json!({"kind":"store", "address":"slot", "value":"@payload", "access_bytes":8}),
                // Publish the actual allocation base, without a certified zero-offset GEP.
                serde_json::json!({"kind":"store", "address":"@table", "value":"@aggregate", "access_bytes":8}),
                serde_json::json!({"kind":"load", "dest":"loaded", "address":"@table", "access_bytes":8}),
            ];
            if unknown_first {
                body.push(serde_json::json!({"kind":"gep", "dest":"dynamic", "base":"loaded", "byte_off":null}));
            }
            body.push(serde_json::json!({"kind":"gep", "dest":"shifted", "base":if unknown_first {"dynamic"} else {"loaded"}, "byte_off":offset}));
            body.push(serde_json::json!({"kind":"load", "dest":"result", "address":"shifted", "access_bytes":8}));
            let mut pir: Pir = serde_json::from_value(serde_json::json!({
                "module":"one-hop-root-zero",
                "globals":[{"key":"@aggregate"},{"key":"@payload"},{"key":"@table"}],
                "functions":[{"key":"f", "sig":{"ret":{"class":"void"}, "params":[]}, "body":body}],
            }))
            .unwrap();
            for value in ["slot", "loaded", "dynamic", "shifted", "result"] {
                pir.lowering
                    .semantic_value_kinds
                    .insert(value.into(), ValueKind::Pointer);
            }
            let pag = Pag::from_pir(&pir, &PagOpts::default());
            let solved = solve_steensgaard(&pir, &pag, BuildMode::Executable);
            assert_eq!(
                solved.nodes["val:f:result"]
                    .pointee_globals_unfiltered
                    .iter()
                    .chain(solved.nodes["val:f:result"].pointee_globals.iter())
                    .any(|name| name == "@payload"),
                reaches_payload,
                "unknown_first={unknown_first} offset={offset}: {:?}",
                solved.nodes["val:f:result"],
            );
        }
    }

    #[test]
    fn bounded_memcpy_does_not_contaminate_nonoverlapping_fields() {
        let (pir, pag) = field_contamination_fixture(
            vec![
                Stmt::Gep {
                    dest: "%f::outside".into(),
                    base: "@aggregate".into(),
                    byte_off: Some(24),
                    lane: None,
                    loc: None,
                },
                Stmt::Memcpy {
                    dst: "@aggregate".into(),
                    src: "@source".into(),
                    bytes: Some(16),
                    proven_fnptr_init: false,
                    loc: None,
                },
            ],
            vec![
                Global {
                    key: "aggregate".into(),
                    ..Global::default()
                },
                Global {
                    key: "source".into(),
                    ..Global::default()
                },
            ],
        );
        let (_, classes) = solve_steensgaard_with_classes(&pir, &pag, BuildMode::Executable);
        let copied = class_for_label(&classes, &pag, "val:f:%f::field");
        let outside = class_for_label(&classes, &pag, "val:f:%f::outside");
        assert_ne!(classes.pointee[copied], classes.pointee[outside]);
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

    fn address_exposure_filter_fixture(tainted: bool) -> NodeResolution {
        let pir = Pir {
            module: "address_exposure".into(),
            source: None,
            lowering: Default::default(),
            target: None,
            functions: Vec::new(),
            globals: vec![
                Global {
                    key: "closed".into(),
                    ..Global::default()
                },
                Global {
                    key: "exposed".into(),
                    ..Global::default()
                },
            ],
            global_init: tainted
                .then(|| pangs_pir::Stmt::Unknown {
                    op: "call".into(),
                    operands: Vec::new(),
                    results: Vec::new(),
                    reason: "inline_asm".into(),
                    loc: None,
                })
                .into_iter()
                .collect(),
        };
        let nodes = vec![
            Node {
                id: NodeId(0),
                label: "obj:global:closed".into(),
                kind: NodeKind::Object {
                    object: ObjectKind::Global,
                    key: "closed".into(),
                    owner: None,
                },
                value_kind: Default::default(),
                canonical_pointer_null: false,
                has_empty_witness: false,
            },
            Node {
                id: NodeId(1),
                label: "obj:global:exposed".into(),
                kind: NodeKind::Object {
                    object: ObjectKind::Global,
                    key: "exposed".into(),
                    owner: None,
                },
                value_kind: Default::default(),
                canonical_pointer_null: false,
                has_empty_witness: false,
            },
            Node {
                id: NodeId(2),
                label: "sym:global:@closed".into(),
                kind: NodeKind::Value {
                    scope: Scope::Module,
                },
                value_kind: Default::default(),
                canonical_pointer_null: false,
                has_empty_witness: false,
            },
            Node {
                id: NodeId(3),
                label: "sym:global:@exposed".into(),
                kind: NodeKind::Value {
                    scope: Scope::Module,
                },
                value_kind: Default::default(),
                canonical_pointer_null: false,
                has_empty_witness: false,
            },
            Node {
                id: NodeId(4),
                label: "val:query".into(),
                kind: NodeKind::Value {
                    scope: Scope::Module,
                },
                value_kind: Default::default(),
                canonical_pointer_null: false,
                has_empty_witness: false,
            },
            Node {
                id: NodeId(5),
                label: "val:gep".into(),
                kind: NodeKind::Value {
                    scope: Scope::Module,
                },
                value_kind: Default::default(),
                canonical_pointer_null: false,
                has_empty_witness: false,
            },
        ];
        let edges = vec![
            pangs_pag::Edge {
                id: pangs_pag::EdgeId(0),
                kind: pangs_pag::EdgeKind::AddrOf,
                src: NodeId(0),
                dst: NodeId(2),
                owner: pangs_pag::Owner::Module,
                access_bytes: None,
                access_extent_unknown: false,
                volatile: false,
                modeled_external_write: false,
                loc: None,
            },
            pangs_pag::Edge {
                id: pangs_pag::EdgeId(1),
                kind: pangs_pag::EdgeKind::AddrOf,
                src: NodeId(1),
                dst: NodeId(3),
                owner: pangs_pag::Owner::Module,
                access_bytes: None,
                access_extent_unknown: false,
                volatile: false,
                modeled_external_write: false,
                loc: None,
            },
            pangs_pag::Edge {
                id: pangs_pag::EdgeId(2),
                kind: pangs_pag::EdgeKind::Gep {
                    byte_off: Some(0),
                    lane: None,
                },
                src: NodeId(3),
                dst: NodeId(5),
                owner: pangs_pag::Owner::Module,
                access_bytes: None,
                access_extent_unknown: false,
                volatile: false,
                modeled_external_write: false,
                loc: None,
            },
        ];
        let pag = Pag {
            module: pir.module.clone(),
            source: None,
            metrics: Default::default(),
            nodes,
            edges,
            callsites: Vec::new(),
            omega_seeds: vec![pangs_pag::OmegaSeed {
                kind: OmegaSeedKind::PtrToInt,
                target: SeedTarget::Node(NodeId(5)),
                owner: None,
                loc: None,
                detail: None,
            }],
            pointer_integer_origins: Vec::new(),
            pwc_lanes_enabled: false,
        };
        let mut solver = Solver::new(&pir, &pag, BuildMode::Executable);
        let pointee = solver.join(0, 1, 0);
        solver.classes[4].pointee = Some(pointee);
        solver.finish().nodes.remove("val:query").unwrap()
    }

    #[test]
    fn finite_class_enumeration_drops_globals_without_address_exposure() {
        let resolution = address_exposure_filter_fixture(false);
        assert_eq!(&*resolution.pointee_globals, &["exposed".to_string()]);
        assert_eq!(
            &*resolution.pointee_globals_unfiltered,
            &["closed".to_string(), "exposed".to_string()]
        );
    }

    #[test]
    fn derived_addresses_are_closed_only_for_local_load_store_uses() {
        let pir: Pir = serde_json::from_str(
            r#"{
              "module":"derived-exposure",
              "globals":[
                {"key":"safe","mutable":true}, {"key":"called","mutable":true},
                {"key":"returned","mutable":true}, {"key":"copied","mutable":true},
                {"key":"filled","mutable":true}
              ],
              "functions":[
                {"key":"helper","sig":{"ret":{"class":"void"},"params":[{"class":"integer"}]},"body":[]},
                {"key":"f","sig":{"ret":{"class":"integer"},"params":[]},"body":[
                  {"kind":"gep","dest":"safe.elt","base":"safe"},
                  {"kind":"load","dest":"x","address":"safe.elt"},
                  {"kind":"store","address":"safe.elt","value":"x"},
                  {"kind":"gep","dest":"called.elt","base":"called"},
                  {"kind":"call_direct","callee":"helper","sig":{"ret":{"class":"void"},"params":[{"class":"integer"}]},"args":["called.elt"]},
                  {"kind":"gep","dest":"copied.elt","base":"copied"},
                  {"kind":"memcpy","dst":"safe.elt","src":"copied.elt","bytes":8},
                  {"kind":"gep","dest":"filled.elt","base":"filled"},
                  {"kind":"memset","dst":"filled.elt","value":"0","bytes":8},
                  {"kind":"gep","dest":"returned.elt","base":"returned"},
                  {"kind":"return","value":"returned.elt"}
                ]}
              ]
            }"#,
        )
        .unwrap();
        let pag = Pag::from_pir(&pir, &pangs_pag::PagOpts::default());
        let roots = allocation_storage_roots(&pir, &pag);
        assert_eq!(
            global_address_exposure(&pir, &pag, &roots),
            vec![true, true, true, true, true],
            "memcpy exposes both operands; calls, returns, and memset are boundaries"
        );

        let mut safe_only = pir.clone();
        safe_only.globals.truncate(1);
        safe_only.functions.truncate(1);
        safe_only.functions.push(pangs_pir::Func {
            key: "safe_f".into(),
            body: vec![
                pangs_pir::Stmt::Gep {
                    dest: "elt".into(),
                    base: "safe".into(),
                    byte_off: None,
                    lane: None,
                    loc: None,
                },
                pangs_pir::Stmt::Load {
                    dest: "x".into(),
                    address: "elt".into(),
                    volatile: false,
                    access_bytes: None,
                    loc: None,
                },
                pangs_pir::Stmt::Store {
                    address: "elt".into(),
                    value: "x".into(),
                    volatile: false,
                    access_bytes: None,
                    loc: None,
                },
            ],
            ..frontier_test_func("safe_f")
        });
        let pag = Pag::from_pir(&safe_only, &pangs_pag::PagOpts::default());
        let roots = allocation_storage_roots(&safe_only, &pag);
        assert_eq!(
            global_address_exposure(&safe_only, &pag, &roots),
            vec![false]
        );
    }

    #[test]
    fn memset_exposure_indexes_direct_and_global_init_destinations() {
        let pir: Pir = serde_json::from_str(
            r#"{
              "module":"memset-exposure-index",
              "globals":[
                {"key":"direct","mutable":true},
                {"key":"init_derived","mutable":true},
                {"key":"untouched","mutable":true}
              ],
              "functions":[
                {"key":"f","sig":{"ret":{"class":"void"},"params":[]},"body":[
                  {"kind":"memset","dst":"@direct","value":"0","bytes":8}
                ]}
              ],
              "global_init":[
                {"kind":"gep","dest":"init.elt","base":"@init_derived"},
                {"kind":"memset","dst":"init.elt","value":"0","bytes":8}
              ]
            }"#,
        )
        .unwrap();
        let pag = Pag::from_pir(&pir, &pangs_pag::PagOpts::default());
        let roots = allocation_storage_roots(&pir, &pag);

        assert_eq!(
            global_address_exposure(&pir, &pag, &roots),
            vec![true, true, false]
        );
    }

    #[test]
    fn unused_exported_global_is_exposed_from_its_object_seed() {
        let pir = Pir {
            module: "export".into(),
            source: None,
            lowering: Default::default(),
            target: None,
            functions: Vec::new(),
            globals: vec![Global {
                key: "unused".into(),
                exported: true,
                ..Global::default()
            }],
            global_init: Vec::new(),
        };
        let pag = Pag::from_pir(
            &pir,
            &pangs_pag::PagOpts {
                build_mode: BuildMode::Library,
                ..Default::default()
            },
        );
        let roots = allocation_storage_roots(&pir, &pag);
        assert_eq!(global_address_exposure(&pir, &pag, &roots), vec![true]);
    }

    #[test]
    fn null_alternative_join_is_safe_but_unknown_alternative_exposes() {
        let make = |unknown: bool| {
            let sources = if unknown {
                r#"["elt","mystery"]"#
            } else {
                r#"["elt","null"]"#
            };
            let mut pir: Pir = serde_json::from_str(&format!(
                r#"{{"module":"join","globals":[{{"key":"g","mutable":true}}],
                    "functions":[{{"key":"f","sig":{{"ret":{{"class":"void"}},"params":[]}},"body":[
                      {{"kind":"gep","dest":"elt","base":"g"}},
                      {{"kind":"assign","dest":"maybe","sources":{sources}}},
                      {{"kind":"load","dest":"x","address":"maybe"}},
                      {{"kind":"store","address":"maybe","value":"x"}}
                    ]}}]}}"#
            ))
            .unwrap();
            pir.lowering
                .semantic_value_kinds
                .insert("null".into(), pangs_pir::ValueKind::Pointer);
            let pag = Pag::from_pir(&pir, &pangs_pag::PagOpts::default());
            let roots = allocation_storage_roots(&pir, &pag);
            global_address_exposure(&pir, &pag, &roots)
        };
        assert_eq!(make(false), vec![false]);
        assert_eq!(make(true), vec![true]);
    }

    #[test]
    fn mixed_global_root_join_exposes_every_known_alternative() {
        let pir: Pir = serde_json::from_str(
            r#"{"module":"mixed-join","globals":[{"key":"g"},{"key":"h"}],
                "functions":[{"key":"f","sig":{"ret":{"class":"void"},"params":[]},"body":[
                  {"kind":"gep","dest":"g.elt","base":"g"},
                  {"kind":"gep","dest":"h.elt","base":"h"},
                  {"kind":"assign","dest":"mixed","sources":["g.elt","h.elt"]},
                  {"kind":"load","dest":"x","address":"mixed"}
                ]}]}"#,
        )
        .unwrap();
        let pag = Pag::from_pir(&pir, &pangs_pag::PagOpts::default());
        let roots = allocation_storage_roots(&pir, &pag);
        assert_eq!(
            global_address_exposure(&pir, &pag, &roots),
            vec![true, true]
        );
    }

    #[test]
    fn violation_taint_still_bypasses_address_exposure_filtering() {
        let violation_tainted = address_exposure_filter_fixture(true);
        assert_eq!(
            &*violation_tainted.pointee_globals,
            &["closed".to_string(), "exposed".to_string()]
        );
        assert!(violation_tainted.pointee_globals_unfiltered.is_empty());
    }

    #[test]
    fn inline_asm_violation_exposure_is_operand_local_unless_opaque() {
        let mut modeled = frontier_test_func("asm_user");
        modeled.body = vec![pangs_pir::Stmt::Unknown {
            op: "call".into(),
            operands: vec!["@bits".into(), "%scalar".into()],
            results: Vec::new(),
            reason: "inline_asm".into(),
            loc: None,
        }];
        let mut pir = Pir {
            module: "modeled_inline_asm".into(),
            source: None,
            lowering: Default::default(),
            target: None,
            functions: vec![modeled],
            globals: vec![
                Global {
                    key: "bits".into(),
                    ..Global::default()
                },
                Global {
                    key: "transfersl".into(),
                    ..Global::default()
                },
            ],
            global_init: Vec::new(),
        };
        pir.lowering
            .semantic_value_kinds
            .insert("%scalar".into(), pangs_pir::ValueKind::NonPointer);
        let pag = Pag::from_pir(&pir, &pangs_pag::PagOpts::default());

        let ViolationExposure::Finite(nodes) = violation_exposure(&pir, &pag) else {
            panic!("modeled inline assembly must have finite exposure");
        };
        assert_eq!(nodes.len(), 1);
        assert_eq!(
            pag.nodes[nodes.iter().next().unwrap().0 as usize].label,
            "sym:global:@bits"
        );
        let roots = allocation_storage_roots(&pir, &pag);
        assert_eq!(
            global_address_exposure(&pir, &pag, &roots),
            vec![true, false]
        );
        assert!(pag.omega_seeds.iter().all(|seed| {
            !matches!(seed.target, SeedTarget::Node(node) if pag.nodes[node.0 as usize].label == "val:asm_user:%scalar")
        }));

        if let pangs_pir::Stmt::Unknown { operands, .. } = &mut pir.functions[0].body[0] {
            operands.clear();
        }
        assert_eq!(
            violation_exposure(&pir, &Pag::from_pir(&pir, &pangs_pag::PagOpts::default())),
            ViolationExposure::ModuleWide
        );

        if let pangs_pir::Stmt::Unknown {
            operands, reason, ..
        } = &mut pir.functions[0].body[0]
        {
            operands.push("@bits".into());
            *reason = "inline_asm_symbol_reference".into();
        }
        assert_eq!(
            violation_exposure(&pir, &Pag::from_pir(&pir, &pangs_pag::PagOpts::default())),
            ViolationExposure::ModuleWide
        );
    }

    #[test]
    fn pointee_provenance_labels_cover_every_diagnostic_category() {
        assert_eq!(
            pointee_provenance_labels(
                PROV_DIRECT_ADDRESS
                    | PROV_SCALAR_OR_UNKNOWN_PAYLOAD
                    | PROV_BY_VALUE_AGGREGATE
                    | PROV_MEMORY_MERGING
                    | PROV_CALL_RETURN,
                true,
            ),
            vec![
                PointeeProvenance::DirectAddressFlow,
                PointeeProvenance::ScalarOrUnknownPayload,
                PointeeProvenance::ByValueAggregateBinding,
                PointeeProvenance::MemoryMerging,
                PointeeProvenance::CallReturnMerging,
                PointeeProvenance::FiniteExternalRegion,
            ]
        );
    }

    #[test]
    fn steens_frontier_processes_cross_pairs_after_joining_processed_classes() {
        let pir = Pir {
            module: "frontier_merge".to_string(),
            source: None,
            lowering: Default::default(),
            target: None,
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
                    value_kind: Default::default(),
                    canonical_pointer_null: false,
                    has_empty_witness: false,
                },
                Node {
                    id: NodeId(1),
                    label: "%right".to_string(),
                    kind: NodeKind::Value {
                        scope: Scope::Module,
                    },
                    value_kind: Default::default(),
                    canonical_pointer_null: false,
                    has_empty_witness: false,
                },
            ],
            edges: Vec::new(),
            callsites: vec![frontier_test_callsite(0), frontier_test_callsite(1)],
            omega_seeds: Vec::new(),
            pointer_integer_origins: Vec::new(),
            pwc_lanes_enabled: false,
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

        let root = solver.join(0, 1, 0);
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
            target: None,
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
                    value_kind: Default::default(),
                    canonical_pointer_null: false,
                    has_empty_witness: false,
                },
                Node {
                    id: NodeId(1),
                    label: "%right".to_string(),
                    kind: NodeKind::Value {
                        scope: Scope::Module,
                    },
                    value_kind: Default::default(),
                    canonical_pointer_null: false,
                    has_empty_witness: false,
                },
            ],
            edges: Vec::new(),
            callsites: vec![frontier_test_callsite(0), frontier_test_callsite(1)],
            omega_seeds: Vec::new(),
            pointer_integer_origins: Vec::new(),
            pwc_lanes_enabled: false,
        };
        let mut solver = Solver::new(&pir, &pag, BuildMode::Library);
        solver.classes[0].ext = true;
        solver.classes[0].icall_sites.insert(0);
        solver.process_class(0);
        solver.process_class(0);

        assert_eq!(solver.metrics.steens_external_call_requests, 1);
        assert_eq!(solver.metrics.steens_external_call_applications, 1);

        solver.classes[1].icall_sites.insert(1);
        let root = solver.join(0, 1, 0);
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
    fn ptrtoint_escapes_data_pointee_without_making_address_a_function_pointer() {
        let pir = Pir::from_path(fixture("ptrtoint_escape.pir.json")).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());

        let result = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert!(result.indirect_calls.is_empty());
        assert!(result.unknown_callers.is_empty());
        assert!(result.globals["@G"].escape_external);
        assert!(!result.globals["@G"].never_written);
        let pointer = &result.nodes["val:driver:%p"];
        assert!(!pointer.external);
        assert!(!pointer.reaches_function_pointer);
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

        let target_label = with_pt
            .node_points_to
            .iter()
            .find(|(_, allocs)| allocs.contains("cb"))
            .map(|(label, _)| label.clone())
            .unwrap();
        let targeted = solve_steensgaard_with_target_points_to(
            &pir,
            &pag,
            BuildMode::Library,
            &BTreeSet::from([target_label.clone()]),
        );
        assert_eq!(targeted.node_points_to.len(), 1);
        assert_eq!(
            targeted.node_points_to[&target_label],
            with_pt.node_points_to[&target_label]
        );
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
    fn producerless_indirect_call_is_unknown_not_silent() {
        let pir: Pir = serde_json::from_str(
            r#"{
                "module":"producerless-icall",
                "functions":[
                    {"key":"cb","address_taken":true,"sig":{"ret":{"class":"void"},"params":[]},"body":[]},
                    {"key":"driver","sig":{"ret":{"class":"void"},"params":[]},"body":[
                        {"kind":"call_indirect","operand":"%driver::missing","sig":{"ret":{"class":"void"},"params":[]},"args":[]}
                    ]}
                ]
            }"#,
        )
        .unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());

        for result in [
            solve_steensgaard(&pir, &pag, BuildMode::Executable),
            solve_andersen(&pir, &pag, BuildMode::Executable, u64::MAX),
        ] {
            assert_eq!(result.indirect_calls.len(), 1);
            assert!(result.indirect_calls[0].targets.is_empty());
            assert!(result.indirect_calls[0].unknown_callee);
        }
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
    fn external_output_pointer_load_is_unknown_in_steens_envelope() {
        let mut pir: Pir = serde_json::from_str(
            r#"{
                "module":"external-output-pointer",
                "functions":[
                    {"key":"ext","external":true,
                     "sig":{"ret":{"class":"void"},"params":[{"class":"integer"}]},
                     "body":[]},
                    {"key":"f","sig":{"ret":{"class":"void"},"params":[]},"body":[
                        {"kind":"alloca","dest":"slot","ty":"ptr"},
                        {"kind":"call_direct","callee":"ext",
                         "sig":{"ret":{"class":"void"},"params":[{"class":"integer"}]},
                         "args":["slot"]},
                        {"kind":"load","dest":"loaded","address":"slot","access_bytes":8},
                        {"kind":"load","dest":"byte","address":"loaded","access_bytes":1}
                    ]}
                ]
            }"#,
        )
        .unwrap();
        pir.lowering.semantic_value_kinds.extend([
            ("slot".into(), ValueKind::Pointer),
            ("loaded".into(), ValueKind::Pointer),
        ]);
        let pag = Pag::from_pir(&pir, &PagOpts::default());

        for solved in [
            solve_steensgaard(&pir, &pag, BuildMode::Executable),
            solve_andersen(&pir, &pag, BuildMode::Executable, u64::MAX),
        ] {
            let loaded = &solved.nodes["val:f:loaded"];
            assert!(loaded.external);
            assert!(loaded.reaches_function_pointer);
        }
    }

    #[test]
    fn trusted_free_does_not_escape_a_freed_containers_pointer_payload() {
        let pir: Pir = serde_json::from_str(
            r#"{
                "module":"free-summary",
                "globals":[
                    {"key":"@payload","mutable":true},
                    {"key":"@freed_address","mutable":true},
                    {"key":"@malformed","mutable":true}
                ],
                "functions":[
                    {"key":"main","sig":{"ret":{"class":"void"},"params":[]},"body":[
                        {"kind":"call_direct","callee":"malloc","sig":{"ret":{"class":"integer"},"params":[{"class":"integer"}]},"args":["24"],"dest":"container"},
                        {"kind":"store","address":"container","value":"@payload"},
                        {"kind":"call_direct","callee":"free","sig":{"ret":{"class":"void"},"params":[{"class":"integer"}]},"args":["container"]},
                        {"kind":"gep","dest":"freed.elt","base":"@freed_address","byte_off":0},
                        {"kind":"call_direct","callee":"free","sig":{"ret":{"class":"void"},"params":[{"class":"integer"}]},"args":["freed.elt"]},
                        {"kind":"gep","dest":"malformed.elt","base":"@malformed","byte_off":0},
                        {"kind":"call_direct","callee":"free","sig":{"ret":{"class":"void"},"params":[{"class":"integer"}]},"args":["malformed.elt","extra"]}
                    ]},
                    {"key":"malloc","external":true,"sig":{"ret":{"class":"integer"},"params":[{"class":"integer"}]},"body":[]},
                    {"key":"free","external":true,"sig":{"ret":{"class":"void"},"params":[{"class":"integer"}]},"body":[]}
                ]
            }"#,
        )
        .unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        let roots = allocation_storage_roots(&pir, &pag);
        assert_eq!(
            global_address_exposure(&pir, &pag, &roots),
            vec![true, false, true],
            "trusted free is a safe terminal; a shape mismatch remains exposing"
        );

        for solved in [
            solve_steensgaard(&pir, &pag, BuildMode::Executable),
            solve_andersen(&pir, &pag, BuildMode::Executable, u64::MAX),
        ] {
            assert!(
                !solved.globals["@payload"].escape_external,
                "freeing the container must not recursively escape its pointer payload"
            );
        }
    }

    #[test]
    fn modeled_scanf_output_is_written_without_external_escape() {
        let pir: Pir = serde_json::from_str(
            r#"{
                "module":"scanf-summary",
                "globals":[{"key":"@out","initializer_ir":"i8 0"}],
                "functions":[
                    {"key":"main","exported":true,"sig":{"ret":{"class":"void"},"params":[]},"body":[
                        {"kind":"call_direct","callee":"sscanf","sig":{"ret":{"class":"integer"},"params":[{"class":"integer"},{"class":"integer"}],"vararg":true},"args":["%input","%dynamic_format","@out"]}
                    ]},
                    {"key":"sscanf","external":true,"sig":{"ret":{"class":"integer"},"params":[{"class":"integer"},{"class":"integer"}],"vararg":true},"body":[]}
                ]
            }"#,
        )
        .unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());

        let steens = solve_steensgaard(&pir, &pag, BuildMode::Executable);
        assert!(!steens.globals["@out"].escape_external);
        assert!(!steens.globals["@out"].never_written);

        let andersen = solve_andersen(&pir, &pag, BuildMode::Executable, u64::MAX);
        assert!(!andersen.globals["@out"].escape_external);
        assert!(!andersen.globals["@out"].never_written);
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

    #[test]
    fn semantic_callback_boundaries_preserve_republished_escape() {
        use serde_json::json;
        // Foreign code may overwrite field 8 in both direct and republished cases.
        // External payloads and externally addressed storage remain distinct controls.
        // No solver state is injected.
        for case in [
            "escaped",
            "escaped-published",
            "escaped-published-shifted",
            "payload",
            "identity",
            "identity-shifted",
            "identity-escaped",
        ] {
            let mut body = vec![
                json!({"kind":"gep","dest":"zero","base":"@aggregate","byte_off":0}),
                json!({"kind":"gep","dest":"member","base":"@aggregate","byte_off":8}),
                json!({"kind":"store","address":"member","value":"cb","access_bytes":8}),
            ];
            if case.starts_with("escaped") {
                if case.starts_with("escaped-published") {
                    body.push(json!({"kind":"store","address":"@slot","value":"@aggregate","access_bytes":8}));
                    body.push(json!({"kind":"load","dest":"published","address":"@slot","access_bytes":8}));
                }
                body.push(json!({"kind":"call_direct","callee":"foreign_use",
                    "sig":{"ret":{"class":"void"},"params":[{"class":"integer"}]},"args":[if case.starts_with("escaped-published") { "published" } else { "@aggregate" }]}));
                if case == "escaped-published-shifted" {
                    body.push(
                        json!({"kind":"gep","dest":"shifted","base":"published","byte_off":8}),
                    );
                }
            } else {
                body.push(json!({"kind":"call_direct","callee":"foreign_ptr",
                    "sig":{"ret":{"class":"integer"},"params":[]},"args":[],"dest":"foreign"}));
                if case == "payload" {
                    body.push(
                        json!({"kind":"store","address":"zero","value":"foreign","access_bytes":8}),
                    );
                    body.push(json!({"kind":"load","dest":"payload_read","address":"zero","access_bytes":8}));
                } else {
                    body.push(json!({"kind":"assign","dest":"mixed","sources":["zero","foreign"]}));
                    // Distinct address carrier for the same allocation, not a copy of mixed.
                    body.push(
                        json!({"kind":"gep","dest":"independent","base":"@aggregate","byte_off":0}),
                    );
                    body.push(json!({"kind":"gep","dest":"shifted","base":if case == "identity-shifted" { "mixed" } else { "independent" },"byte_off":8}));
                    if case == "identity-escaped" {
                        body.push(json!({"kind":"call_direct","callee":"foreign_use",
                            "sig":{"ret":{"class":"void"},"params":[{"class":"integer"}]},"args":["mixed"]}));
                    }
                }
            }
            body.extend([
                json!({"kind":"load","dest":"callback","address":if case.starts_with("identity") || case == "escaped-published-shifted" { "shifted" } else { "member" },"access_bytes":8}),
                json!({"kind":"call_indirect","operand":"callback","sig":{"ret":{"class":"void"},"params":[]},"args":[]}),
            ]);
            let mut pir: Pir = serde_json::from_value(json!({
                "module":case,"globals":[{"key":"@aggregate"},{"key":"@slot"}],
                "functions":[
                    {"key":"cb","address_taken":true,"sig":{"ret":{"class":"void"},"params":[]},"body":[]},
                    {"key":"foreign_use","external":true,"sig":{"ret":{"class":"void"},"params":[{"class":"integer"}]},"body":[]},
                    {"key":"foreign_ptr","external":true,"sig":{"ret":{"class":"integer"},"params":[]},"body":[]},
                    {"key":"main","sig":{"ret":{"class":"void"},"params":[]},"body":body}
                ]
            })).unwrap();
            for name in [
                "zero",
                "member",
                "foreign",
                "mixed",
                "independent",
                "shifted",
                "callback",
                "published",
                "payload_read",
            ] {
                pir.lowering
                    .semantic_value_kinds
                    .insert(name.into(), ValueKind::Pointer);
            }
            let pag = Pag::from_pir(&pir, &PagOpts::default());
            let mut solver = Solver::new(&pir, &pag, BuildMode::Executable);
            solver.run();
            if case.starts_with("identity") {
                let owner = pag
                    .nodes
                    .iter()
                    .find(|node| node.label == "obj:global:@aggregate")
                    .unwrap()
                    .id;
                let owner = solver.class_of(owner);
                assert!(
                    solver.classes[owner].ext,
                    "{case}: the allocation-location class must actually carry external identity"
                );
            }
            if case.starts_with("escaped") {
                let node = |label: &str| {
                    pag.nodes
                        .iter()
                        .find(|node| node.label == label)
                        .unwrap()
                        .id
                };
                let owner = node("obj:global:@aggregate");
                let owner_class = solver.class_of(owner);
                let member = solver.class_of(node("val:main:member"));
                let field = solver.classes[member].pointee.unwrap();
                let field = solver.find(field);
                assert!(
                    solver.classes[owner_class].esc,
                    "{case}: allocation itself must escape"
                );
                let direct = case == "escaped";
                assert!(
                    solver.classes[field].esc,
                    "{case}: escaped allocation must cover field 8"
                );
                assert!(solver.field_escape_sources_by_root.contains_key(&owner));
                if !direct {
                    assert!(
                        solver.exact_addresses[node("val:main:published").0 as usize].is_none()
                    );
                }
            }
            for (tier, solved) in [
                ("steens", solver.finish()),
                (
                    "andersen",
                    solve_andersen(&pir, &pag, BuildMode::Executable, u64::MAX),
                ),
            ] {
                assert_eq!(solved.indirect_calls.len(), 1);
                let call = &solved.indirect_calls[0];
                assert_eq!(
                    call.targets,
                    ["cb"],
                    "{case} {tier}: known callback must remain reachable"
                );
                let unknown = case.starts_with("escaped")
                    || case == "identity-shifted"
                    || case == "identity-escaped";
                assert_eq!(call.unknown_callee, unknown, "{case} {tier}");
                if case == "payload" {
                    assert!(solved.nodes["val:main:payload_read"].external);
                    assert!(!solved.nodes["val:main:callback"].external);
                }
            }
        }
    }

    #[test]
    fn republished_aggregate_callback_fixture_keeps_unknown() {
        let pir = Pir::from_path(fixture("republished_aggregate_callback.pir.json")).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        let steens = solve_steensgaard(&pir, &pag, BuildMode::Executable);
        let andersen = solve_andersen(&pir, &pag, BuildMode::Executable, u64::MAX);
        assert_eq!(steens.indirect_calls.len(), 1);
        assert_eq!(andersen.indirect_calls.len(), 1);
        assert_eq!(steens.indirect_calls[0].targets, ["cb"]);
        assert_eq!(andersen.indirect_calls[0].targets, ["cb"]);
        assert!(steens.indirect_calls[0].unknown_callee);
        assert!(andersen.indirect_calls[0].unknown_callee);
    }

    #[test]
    fn external_pointer_boundary_survives_gep_in_steens_envelope() {
        let mut pir: Pir = serde_json::from_str(
            r#"{
                "module":"external-gep",
                "functions":[
                  {"key":"external_ptr","sig":{"ret":{"class":"integer"},"params":[]},
                   "external":true,"body":[]},
                  {"key":"f","sig":{"ret":{"class":"void"},"params":[]},"body":[
                    {"kind":"call_direct","callee":"external_ptr",
                     "sig":{"ret":{"class":"integer"},"params":[]},"args":[],"dest":"ret"},
                    {"kind":"gep","dest":"derived","base":"ret","byte_off":0},
                    {"kind":"load","dest":"byte","address":"derived","access_bytes":1}
                  ]}
                ]
            }"#,
        )
        .unwrap();
        pir.lowering.semantic_value_kinds.extend([
            ("ret".into(), ValueKind::Pointer),
            ("derived".into(), ValueKind::Pointer),
        ]);
        let pag = Pag::from_pir(&pir, &PagOpts::default());

        let solved = solve_steensgaard(&pir, &pag, BuildMode::Executable);
        assert!(solved.nodes["val:f:derived"].external);
    }

    #[test]
    fn forged_pointer_boundary_survives_gep_as_external_flow() {
        let mut pir: Pir = serde_json::from_str(
            r#"{
                "module":"forged-gep",
                "functions":[{
                  "key":"f","sig":{"ret":{"class":"void"},"params":[]},"body":[
                    {"kind":"int_to_ptr","dest":"forged","source":"bits"},
                    {"kind":"gep","dest":"derived","base":"forged","byte_off":0},
                    {"kind":"load","dest":"byte","address":"derived","access_bytes":1}
                  ]
                }]
            }"#,
        )
        .unwrap();
        pir.lowering.semantic_value_kinds.extend([
            ("forged".into(), ValueKind::Pointer),
            ("derived".into(), ValueKind::Pointer),
        ]);
        let pag = Pag::from_pir(&pir, &PagOpts::default());

        let solved = solve_steensgaard(&pir, &pag, BuildMode::Executable);
        let derived = &solved.nodes["val:f:derived"];
        assert!(derived.external);
    }

    #[test]
    fn one_hop_memory_keeps_carriers_separate_from_locations() {
        let mut pir: Pir = serde_json::from_str(
            r#"{
              "module":"one-hop-memory",
              "globals":[{"key":"CellA"},{"key":"CellB"},{"key":"A"},{"key":"B"}],
              "functions":[{"key":"f","sig":{"ret":{"class":"void"},"params":[]},"body":[
                {"kind":"store","address":"@CellA","value":"@A","access_bytes":8},
                {"kind":"store","address":"@CellB","value":"@B","access_bytes":8},
                {"kind":"load","dest":"loaded_a","address":"@CellA","access_bytes":8},
                {"kind":"load","dest":"loaded_b","address":"@CellB","access_bytes":8}
              ]}]
            }"#,
        )
        .unwrap();
        pir.lowering.semantic_value_kinds.extend([
            ("loaded_a".into(), ValueKind::Pointer),
            ("loaded_b".into(), ValueKind::Pointer),
        ]);
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        let node = |label: &str| {
            pag.nodes
                .iter()
                .find(|node| node.label == label)
                .unwrap()
                .id
        };
        let mut solver = Solver::new(&pir, &pag, BuildMode::Executable);
        solver.points_to_materialization = PointsToMaterialization::AllNodes;
        solver.run();

        for (cell, loaded) in [
            ("obj:global:CellA", "val:f:loaded_a"),
            ("obj:global:CellB", "val:f:loaded_b"),
        ] {
            let cell = solver.class_of(node(cell));
            let loaded = solver.class_of(node(loaded));
            assert_ne!(cell, loaded);
            assert!(solver.classes[cell].has_location);
            assert!(!solver.classes[cell].has_carrier);
            assert!(solver.classes[loaded].has_carrier);
            assert!(!solver.classes[loaded].has_location);
            assert!(solver.classes[loaded].global_objs.is_empty());
            assert!(solver.classes[loaded].fn_objs.is_empty());
            assert!(!solver.classes[loaded].esc);
        }

        let solved = solver.finish();
        assert_eq!(
            solved.node_points_to["val:f:loaded_a"],
            BTreeSet::from(["A".to_string()])
        );
        assert_eq!(
            solved.node_points_to["val:f:loaded_b"],
            BTreeSet::from(["B".to_string()])
        );
        assert!(solved.metrics.steens_content_edges >= 4);
    }

    #[test]
    fn content_edges_propagate_facts_only_forward() {
        let pir = Pir {
            module: "content-edge-direction".into(),
            source: None,
            lowering: Default::default(),
            target: None,
            functions: Vec::new(),
            globals: Vec::new(),
            global_init: Vec::new(),
        };
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        let mut solver = Solver::new(&pir, &pag, BuildMode::Library);
        let new_location = ClassData::default;
        let source = solver.classes.len();
        let mut source_data = new_location();
        source_data.parent = source;
        source_data.size = 1;
        source_data.has_location = true;
        solver.classes.push(source_data);
        solver.queued.push(false);
        let destination = solver.classes.len();
        let mut destination_data = new_location();
        destination_data.parent = destination;
        destination_data.size = 1;
        destination_data.has_location = true;
        solver.classes.push(destination_data);
        solver.queued.push(false);
        let unrelated = solver.classes.len();
        let mut unrelated_data = new_location();
        unrelated_data.parent = unrelated;
        unrelated_data.size = 1;
        unrelated_data.has_location = true;
        solver.classes.push(unrelated_data);
        solver.queued.push(false);
        solver.add_content_edge(source, destination);
        solver.add_content_edge(unrelated, destination);
        solver.set_ext(source);
        solver.set_empty_witness(source);
        while let Some(class) = solver.worklist.pop_front() {
            solver.queued[class] = false;
            let root = solver.find(class);
            solver.process_class(root);
        }
        let source = solver.find(source);
        let destination = solver.find(destination);
        let unrelated = solver.find(unrelated);
        assert!(solver.classes[destination].ext);
        assert!(solver.classes[destination].has_empty_witness);
        assert!(!solver.classes[unrelated].ext);
        assert!(!solver.classes[unrelated].has_empty_witness);
        assert!(solver.classes[source].ext);
    }

    #[test]
    fn imported_global_is_never_certified_as_isolated_or_never_written() {
        let pir = Pir {
            module: "imported-global".into(),
            source: None,
            lowering: Default::default(),
            target: None,
            functions: Vec::new(),
            globals: vec![Global {
                key: "external_slot".into(),
                exported: true,
                is_definition: false,
                mutable: true,
                ..Global::default()
            }],
            global_init: Vec::new(),
        };
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        let solved = solve_steensgaard(&pir, &pag, BuildMode::Executable);
        let global = &solved.globals["external_slot"];
        assert!(global.escape_external);
        assert!(!global.never_written);
    }
}
