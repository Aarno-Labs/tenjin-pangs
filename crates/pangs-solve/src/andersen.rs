//! Partition-scoped, field-sensitive inclusion (Andersen) solver — the lite design's one
//! real solver (`DESIGN_lite.md` §2 D', `PLAN-M1_lite_delta.md` §M1.4b).
//!
//! It runs *on top of* Steensgaard: `solve_steensgaard_with_classes` provides sound target
//! envelopes, fallback answers, and authoritative global escape facts. Andersen then
//! refines the **points-to sets** within interesting, within-budget partitions, which
//! sharpens per-node points-to-derived outputs — indirect-call concrete targets,
//! `reaches_function_pointer`, `external`, and `pointee_globals` (mod/ref) — while global
//! escape and unknown-caller verdicts stay exactly as Steensgaard computed them.
//!
//! Soundness rests on three facts:
//! * Steensgaard unification is a sound over-approximation of Andersen, so refined targets
//!   are always ⊆ the Steensgaard targets (the narrowing ledger, asserted in tests).
//! * Admission partitions are weak components of the inclusion constraints. Certified memory
//!   accesses pass through allocation-relative byte-region vertices; unresolved accesses retain
//!   their address carrier. Sound indirect-call envelopes contribute their possible bindings.
//! * Anything reachable only through Ω stays Ω (absorbing), and the global escape/unknown
//!   outputs that drive component freezing are taken verbatim from Steensgaard.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use pangs_pag::{
    BuildMode, CallKind, EdgeKind, NodeId, NodeKind, ObjectKind, OmegaSeedKind, Pag, SeedTarget,
};
use pangs_pir::Pir;

use crate::knobs;
use crate::{
    debug_assert_narrows, exact_allocation_addresses, ExactAddress, FieldLocation, FieldRegion,
    IndirectCallResolution, SolveResult, SteensClasses,
};

/// Return the cheap, Steensgaard-derived structural census used to calibrate
/// Andersen partition admission. This stops before the inclusion solve and
/// does not construct any API client rows.
pub fn andersen_admission_census(
    pir: &Pir,
    pag: &Pag,
    build_mode: BuildMode,
) -> Vec<AdmissionStructureProfile> {
    let labels = BTreeSet::new();
    let (base, classes) = crate::solve_steensgaard_classes_targeted(pir, pag, build_mode, &labels);
    let exact_targets = BTreeMap::new();
    let confined_targets = BTreeSet::new();
    let refiner = Refiner::new(
        pir,
        pag,
        &classes,
        &base,
        build_mode,
        0,
        &exact_targets,
        &confined_targets,
        true,
    );
    refiner.admission_structures
}

/// Solve Andersen as a refinement of Steensgaard and fold the refined facts back into a
/// `SolveResult` that is otherwise identical to the Steensgaard answer.
pub fn solve_andersen(
    pir: &Pir,
    pag: &Pag,
    build_mode: BuildMode,
    partition_budget: u64,
) -> SolveResult {
    solve_andersen_with_overrides(
        pir,
        pag,
        build_mode,
        partition_budget,
        &BTreeMap::new(),
        &BTreeSet::new(),
    )
}

/// Solve Andersen with exact per-callsite target overrides and globally confined targets.
///
/// Exact overrides represent higher-precedence callsites already proven by a def-use
/// walker. They remain active even when their target is globally confined, so the fixed
/// call graph still binds params/returns for the real exact call. Confined targets are
/// removed only from non-exact candidate sites.
pub fn solve_andersen_with_overrides(
    pir: &Pir,
    pag: &Pag,
    build_mode: BuildMode,
    partition_budget: u64,
    exact_targets: &BTreeMap<String, Vec<String>>,
    confined_targets: &BTreeSet<String>,
) -> SolveResult {
    let (base, classes) = crate::solve_steensgaard_with_classes(pir, pag, build_mode);
    finish_andersen(
        pir,
        pag,
        &classes,
        base,
        build_mode,
        partition_budget,
        exact_targets,
        confined_targets,
        false,
    )
}

/// Andersen refinement with Steensgaard allocation-level points-to retained only for the
/// requested PAG node labels. The targeted rows are a sound fallback for partitions Andersen
/// does not currently materialize as standalone operand sets.
pub fn solve_andersen_with_overrides_and_target_points_to(
    pir: &Pir,
    pag: &Pag,
    build_mode: BuildMode,
    partition_budget: u64,
    exact_targets: &BTreeMap<String, Vec<String>>,
    confined_targets: &BTreeSet<String>,
    labels: &BTreeSet<String>,
) -> SolveResult {
    let (base, classes) = crate::solve_steensgaard_classes_targeted(pir, pag, build_mode, labels);
    finish_andersen(
        pir,
        pag,
        &classes,
        base,
        build_mode,
        partition_budget,
        exact_targets,
        confined_targets,
        false,
    )
}

/// Solve Andersen and materialize allocation-level points-to for *global memory objects*
/// (`SolveResult::node_points_to`, keyed `obj:global:<name>`), refining the partitions below the
/// budget and falling back to the Steensgaard global points-to for the rest. This is the cc2json
/// escape client's solve: it sharpens which allocations a global's memory reaches (so escape need
/// not over-approximate every within-budget partition) while keeping the Steensgaard answer for
/// uninteresting/oversize partitions.
pub fn solve_andersen_with_global_points_to(
    pir: &Pir,
    pag: &Pag,
    build_mode: BuildMode,
    partition_budget: u64,
) -> SolveResult {
    // Seed `base.node_points_to` with the Steensgaard global-object points-to; the refiner then
    // overwrites the in-scope globals it sharpens, leaving the rest as the Steensgaard fallback.
    let (base, classes) = crate::solve_steensgaard_classes_materialized(
        pir,
        pag,
        build_mode,
        crate::PointsToMaterialization::GlobalObjects,
    );
    finish_andersen(
        pir,
        pag,
        &classes,
        base,
        build_mode,
        partition_budget,
        &BTreeMap::new(),
        &BTreeSet::new(),
        true,
    )
}

/// Run the refiner over `base`/`classes` and fold the refined facts back into `base`. When
/// `materialize_global_points_to` is set, also overwrite `base.node_points_to` for the global
/// objects whose partitions were refined.
#[allow(clippy::too_many_arguments)]
fn finish_andersen(
    pir: &Pir,
    pag: &Pag,
    classes: &SteensClasses,
    base: SolveResult,
    build_mode: BuildMode,
    partition_budget: u64,
    exact_targets: &BTreeMap<String, Vec<String>>,
    confined_targets: &BTreeSet<String>,
    materialize_global_points_to: bool,
) -> SolveResult {
    finish_andersen_controlled(
        pir,
        pag,
        classes,
        base,
        build_mode,
        partition_budget,
        exact_targets,
        confined_targets,
        materialize_global_points_to,
        AndersenControls::from_environment(),
    )
}

#[derive(Clone, Default)]
struct AndersenControls {
    max_steps: Option<usize>,
    max_resumes: Option<usize>,
    inject_exhaustion: Option<String>,
    disable_eager_unknown: bool,
    subtractive_differential: bool,
}

impl AndersenControls {
    fn from_environment() -> Self {
        Self {
            max_steps: andersen_max_steps(),
            max_resumes: Some(andersen_max_resumes()),
            inject_exhaustion: std::env::var(knobs::ENV_ANDERSEN_INJECT_EXHAUSTION).ok(),
            disable_eager_unknown: std::env::var_os(knobs::ENV_ANDERSEN_DISABLE_EAGER_UNKNOWN)
                .is_some(),
            subtractive_differential: std::env::var_os(
                knobs::ENV_ANDERSEN_DIFFERENTIAL_SUBTRACTIVE,
            )
            .is_some(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn finish_andersen_controlled(
    pir: &Pir,
    pag: &Pag,
    classes: &SteensClasses,
    mut base: SolveResult,
    build_mode: BuildMode,
    partition_budget: u64,
    exact_targets: &BTreeMap<String, Vec<String>>,
    confined_targets: &BTreeSet<String>,
    materialize_global_points_to: bool,
    controls: AndersenControls,
) -> SolveResult {
    let mut refiner = Refiner::new(
        pir,
        pag,
        classes,
        &base,
        build_mode,
        partition_budget,
        exact_targets,
        confined_targets,
        admission_profile_enabled(),
    );
    refiner.materialize_global_points_to = materialize_global_points_to;
    let outcome = refiner.run(controls);

    match outcome {
        RefinerOutcome::Complete(refined) => {
            // Override only complete refined facts; keep global escape/unknown-caller facts
            // from Steensgaard. Unrefined/oversize node partitions retain their base rows.
            base.indirect_calls = refined.indirect_calls;
            patch_exact_overrides(pir, &mut base.indirect_calls, exact_targets);
            for resolution in refined.nodes {
                if let Some(node) = base.nodes.get_mut(&resolution.label) {
                    node.reaches_function_pointer = resolution.reaches_function_pointer;
                    node.external = resolution.external;
                    node.external_universal = resolution.external_universal;
                    node.pointee_globals = resolution.pointee_globals.into();
                    node.pointee_globals_unfiltered = resolution.pointee_globals_unfiltered.into();
                    if node.pointee_globals.is_empty() {
                        node.pointee_provenance = Default::default();
                    }
                    node.external_sources = resolution.external_sources;
                }
            }
            for (label, allocs) in refined.global_points_to {
                base.node_points_to.insert(label, allocs);
            }
            base.metrics.rounds = refined.resume_rounds;
            base.metrics.andersen_complete = true;
            base.metrics.andersen_steps = refined.steps;
            base.metrics.andersen_resume_rounds = refined.resume_rounds;
            base.metrics.andersen_activated_targets = refined.activated_targets;
            base.metrics.andersen_known_unbound_targets = 0;
            base.metrics.oversize_fallbacks = refined.oversize_fallbacks;
            base.metrics.oversize_fallback_max_size = refined.oversize_fallback_max_size;
        }
        RefinerOutcome::Exhausted(exhausted) => {
            // The ascending solve is incomplete. Preserve only independently proven exact
            // callsite answers; every other output family remains byte-for-byte Steensgaard.
            patch_exact_overrides(pir, &mut base.indirect_calls, exact_targets);
            for row in &mut base.indirect_calls {
                if !exact_targets.contains_key(&row.callsite_key) {
                    row.fallback = true;
                }
            }
            base.metrics.andersen_complete = false;
            base.metrics.andersen_exhaustion_reason = Some(exhausted.reason.clone());
            base.metrics.andersen_steps = exhausted.steps;
            base.metrics.andersen_resume_rounds = exhausted.resume_rounds;
            base.metrics.andersen_activated_targets = exhausted.activated_targets;
            base.metrics.andersen_known_unbound_targets = exhausted.known_unbound_targets;
            base.metrics.rounds = exhausted.resume_rounds;
            base.metrics.oversize_fallbacks = exhausted.oversize_fallbacks;
            base.metrics.oversize_fallback_max_size = exhausted.oversize_fallback_max_size;
            eprintln!(
                "pangs andersen exhausted: reason={} steps={} resume_rounds={} worklist={} queued={} pending_copy_seeds={} pending_pts_deltas={} known_unbound_targets={} activated_targets={} scc_passes={} scc_nodes_collapsed={} scc_copy_edges_removed={} memcpy_pairs_processed={} copy_fact_pairs_processed={}",
                exhausted.reason,
                exhausted.steps,
                exhausted.resume_rounds,
                exhausted.worklist,
                exhausted.queued,
                exhausted.pending_copy_seeds,
                exhausted.pending_pts_deltas,
                exhausted.known_unbound_targets,
                exhausted.activated_targets,
                exhausted.scc_passes,
                exhausted.scc_nodes_collapsed,
                exhausted.scc_copy_edges_removed,
                exhausted.memcpy_pairs_processed,
                exhausted.copy_fact_pairs_processed,
            );
        }
    }
    base
}

enum RefinerOutcome {
    Complete(RefinerOutput),
    Exhausted(ExhaustionDiagnostic),
}

struct RefinerOutput {
    indirect_calls: Vec<IndirectCallResolution>,
    nodes: Vec<RefinedNodeResolution>,
    /// Refined global-object points-to (`obj:global:<name>` label → named allocations), only
    /// populated when `Refiner::materialize_global_points_to` is set.
    global_points_to: Vec<(String, BTreeSet<String>)>,
    resume_rounds: usize,
    steps: usize,
    activated_targets: usize,
    oversize_fallbacks: usize,
    oversize_fallback_max_size: usize,
}

struct ExhaustionDiagnostic {
    reason: String,
    steps: usize,
    resume_rounds: usize,
    worklist: usize,
    queued: usize,
    pending_copy_seeds: usize,
    pending_pts_deltas: usize,
    known_unbound_targets: usize,
    activated_targets: usize,
    scc_passes: usize,
    scc_nodes_collapsed: usize,
    scc_copy_edges_removed: usize,
    memcpy_pairs_processed: usize,
    copy_fact_pairs_processed: usize,
    oversize_fallbacks: usize,
    oversize_fallback_max_size: usize,
}

fn patch_exact_overrides(
    pir: &Pir,
    rows: &mut [IndirectCallResolution],
    exact_targets: &BTreeMap<String, Vec<String>>,
) {
    let functions: HashSet<&str> = pir.functions.iter().map(|f| f.key.as_str()).collect();
    for row in rows {
        let Some(targets) = exact_targets.get(&row.callsite_key) else {
            continue;
        };
        let mut targets = targets
            .iter()
            .filter(|target| functions.contains(target.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        targets.sort();
        targets.dedup();
        debug_assert_narrows(&row.callsite_key, "exact", &targets, "steens", &row.targets);
        row.targets = targets;
        row.fallback = false;
    }
}

struct RefinedNodeResolution {
    label: String,
    reaches_function_pointer: bool,
    external: bool,
    external_universal: bool,
    pointee_globals: Vec<String>,
    pointee_globals_unfiltered: Vec<String>,
    external_sources: Vec<String>,
}

#[derive(Default)]
struct TargetDiscovery {
    targets: Vec<(usize, usize)>,
    eager_sites: Vec<usize>,
}

#[derive(Debug, Default)]
struct ScopeProfile {
    in_scope_nodes: usize,
    in_scope_edges: usize,
    in_scope_loads: usize,
    in_scope_stores: usize,
    in_scope_geps: usize,
    in_scope_memcpys: usize,
}

#[derive(Debug, Default)]
struct PartitionProfile {
    root: usize,
    nodes: usize,
    values: usize,
    allocas: usize,
    globals: Vec<String>,
    functions: Vec<String>,
    icalls: usize,
    ext_classes: usize,
    esc_classes: usize,
    edge_counts: BTreeMap<&'static str, usize>,
    omega_seed_counts: BTreeMap<&'static str, usize>,
}

#[derive(Debug, serde::Serialize)]
pub struct AdmissionStructureProfile {
    pub kind: &'static str,
    pub root: usize,
    pub nodes: u64,
    pub edges: u64,
    pub quadratic_proxy: u64,
    pub forged: bool,
    pub values: usize,
    pub allocas: usize,
    pub globals: usize,
    pub functions: usize,
    pub icalls: usize,
    pub ext_classes: usize,
    pub esc_classes: usize,
    pub edge_counts: BTreeMap<&'static str, usize>,
    pub omega_seed_counts: BTreeMap<&'static str, usize>,
}

#[derive(Debug, serde::Serialize)]
struct AdmissionWorkProfile {
    kind: &'static str,
    root: usize,
    actual_work: usize,
    worklist_pops: usize,
    points_to_facts_inserted: usize,
    copy_edges_inserted: usize,
    copy_fact_pairs_processed: usize,
    load_pairs_processed: usize,
    store_pairs_processed: usize,
    gep_pairs_processed: usize,
    memcpy_pairs_processed: usize,
    field_cells_allocated: usize,
    scc_nodes_scanned: usize,
    scc_edges_scanned: usize,
    scc_passes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PartitionCut {
    None,
    WithoutLoad,
    WithoutStore,
    WithoutLoadStore,
    WithoutUnknownGep,
    WithoutConstGep,
    WithoutMemcpyMemset,
}

impl PartitionCut {
    fn label(self) -> &'static str {
        match self {
            PartitionCut::None => "all_edges",
            PartitionCut::WithoutLoad => "without_load",
            PartitionCut::WithoutStore => "without_store",
            PartitionCut::WithoutLoadStore => "without_load_store",
            PartitionCut::WithoutUnknownGep => "without_unknown_gep",
            PartitionCut::WithoutConstGep => "without_const_gep",
            PartitionCut::WithoutMemcpyMemset => "without_memcpy_memset",
        }
    }

    fn removes(self, family: &str) -> bool {
        match self {
            PartitionCut::None => false,
            PartitionCut::WithoutLoad => family == "load",
            PartitionCut::WithoutStore => family == "store",
            PartitionCut::WithoutLoadStore => family == "load" || family == "store",
            PartitionCut::WithoutUnknownGep => family == "gep_unknown",
            PartitionCut::WithoutConstGep => family == "gep_const",
            PartitionCut::WithoutMemcpyMemset => family == "memcpy",
        }
    }
}

/// One abstract object that can appear in a points-to set: a PAG object node, a lazily
/// materialized field of one, or a provenance-specific external-memory region.
type Cell = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ExternalRegion {
    EntryArguments,
    GenericStorage,
    ClientBoundary(u32),
    ExternalReturn(u32),
    UnknownReturn(u32),
    EscapedFunctionParam(u32),
    ForgedPointer(u32),
}

impl ExternalRegion {
    fn is_universal(self) -> bool {
        matches!(self, Self::ForgedPointer(_))
    }

    fn may_contain_function_pointer(self) -> bool {
        !matches!(self, Self::EntryArguments)
    }

    fn label(self) -> String {
        match self {
            Self::EntryArguments => "entry_arguments".to_string(),
            Self::GenericStorage => "generic_external_storage".to_string(),
            Self::ClientBoundary(id) => format!("client_boundary:{id}"),
            Self::ExternalReturn(id) => format!("external_return:{id}"),
            Self::UnknownReturn(id) => format!("unknown_return:{id}"),
            Self::EscapedFunctionParam(id) => format!("escaped_function_param:{id}"),
            Self::ForgedPointer(id) => format!("forged_pointer:{id}"),
        }
    }
}

struct Refiner<'a> {
    pir: &'a Pir,
    pag: &'a Pag,
    classes: &'a SteensClasses,
    base: &'a SolveResult,
    build_mode: BuildMode,
    budget: u64,
    exact_targets: &'a BTreeMap<String, Vec<String>>,
    confined_targets: &'a BTreeSet<String>,

    n_base: usize,
    // PIR/PAG cross-reference tables.
    func_index: HashMap<String, usize>,
    /// PAG object node id for each address-taken function (membership target of `&f`).
    fn_cell_to_index: HashMap<Cell, usize>,
    /// PAG object/field cell -> owning global index (a field of a global still touches it).
    global_of_cell: HashMap<Cell, usize>,
    /// (func_index, param ordinal) -> PAG param node id.
    param_nodes: HashMap<(usize, usize), NodeId>,
    /// func_index -> PAG return node id.
    ret_nodes: HashMap<usize, NodeId>,
    /// Independently certified allocation-relative addresses used to cut GEP dependencies at
    /// field-aware partition boundaries.
    exact_addresses: Vec<Option<ExactAddress>>,

    /// Union-find for the independent prepartition constraint graph. PAG nodes occupy
    /// `[0, n_base)`; allocation-relative memory regions are synthetic vertices above it.
    ap_parent: Vec<usize>,
    /// Region identity for synthetic prepartition vertices.
    prepartition_regions: Vec<Option<(NodeId, FieldRegion)>>,
    /// Constraint endpoints used by diagnostics, parallel to `pag.edges`.
    prepartition_edge_vertices: Vec<Option<(usize, usize)>>,
    /// Whether a base node sits in an interesting, within-budget partition.
    in_scope: Vec<bool>,
    oversize_fallbacks: usize,
    oversize_fallback_max_size: usize,
    /// Diagnostic-only root selection used by the admission profiler. A selected
    /// interesting partition is forcibly admitted in isolation.
    admission_profile_root: Option<usize>,
    collect_admission_structures: bool,
    admission_structures: Vec<AdmissionStructureProfile>,
    /// When set, `run` also emits refined points-to for in-scope global memory objects.
    materialize_global_points_to: bool,
}

impl<'a> Refiner<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        pir: &'a Pir,
        pag: &'a Pag,
        classes: &'a SteensClasses,
        base: &'a SolveResult,
        build_mode: BuildMode,
        budget: u64,
        exact_targets: &'a BTreeMap<String, Vec<String>>,
        confined_targets: &'a BTreeSet<String>,
        collect_admission_structures: bool,
    ) -> Self {
        let n_base = pag.nodes.len();
        let func_index: HashMap<String, usize> = pir
            .functions
            .iter()
            .enumerate()
            .map(|(idx, f)| (f.key.clone(), idx))
            .collect();
        let global_index: HashMap<String, usize> = pir
            .globals
            .iter()
            .enumerate()
            .map(|(idx, g)| (g.key.clone(), idx))
            .collect();

        let mut fn_cell_to_index = HashMap::new();
        let mut global_of_cell = HashMap::new();
        let mut param_nodes = HashMap::new();
        let mut ret_nodes = HashMap::new();
        for node in &pag.nodes {
            match &node.kind {
                NodeKind::Object {
                    object: ObjectKind::Function,
                    key,
                    ..
                } => {
                    if let Some(&idx) = func_index.get(key) {
                        fn_cell_to_index.insert(node.id.0, idx);
                    }
                }
                NodeKind::Object {
                    object: ObjectKind::Global,
                    key,
                    ..
                } => {
                    if let Some(&idx) = global_index.get(key) {
                        global_of_cell.insert(node.id.0, idx);
                    }
                }
                NodeKind::Param { func, index } => {
                    if let Some(&idx) = func_index.get(func) {
                        param_nodes.insert((idx, *index as usize), node.id);
                    }
                }
                NodeKind::Return { func } => {
                    if let Some(&idx) = func_index.get(func) {
                        ret_nodes.insert(idx, node.id);
                    }
                }
                _ => {}
            }
        }

        let mut refiner = Self {
            pir,
            pag,
            classes,
            base,
            build_mode,
            budget,
            exact_targets,
            confined_targets,
            n_base,
            func_index,
            fn_cell_to_index,
            global_of_cell,
            param_nodes,
            ret_nodes,
            exact_addresses: exact_allocation_addresses(pag),
            ap_parent: Vec::new(),
            prepartition_regions: Vec::new(),
            prepartition_edge_vertices: Vec::new(),
            in_scope: vec![false; n_base],
            oversize_fallbacks: 0,
            oversize_fallback_max_size: 0,
            admission_profile_root: admission_profile_root(),
            collect_admission_structures,
            admission_structures: Vec::new(),
            materialize_global_points_to: false,
        };
        refiner.build_scope();
        refiner
    }

    fn node_may_carry_pointer(&self, node: NodeId) -> bool {
        self.pag.nodes[node.0 as usize]
            .value_kind
            .may_carry_pointer()
    }

    fn pointer_transfer(&self, src: NodeId, dst: NodeId) -> bool {
        self.node_may_carry_pointer(src) && self.node_may_carry_pointer(dst)
    }

    // ----- partition extraction + interesting-set + oversize guard ----------------------

    fn ap_find(&mut self, mut x: usize) -> usize {
        while self.ap_parent[x] != x {
            self.ap_parent[x] = self.ap_parent[self.ap_parent[x]];
            x = self.ap_parent[x];
        }
        x
    }

    fn ap_union(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.ap_find(a), self.ap_find(b));
        if ra != rb {
            self.ap_parent[rb] = ra;
        }
    }

    fn partition_of_node(&self, node: NodeId) -> usize {
        ap_find_const(&self.ap_parent, node.0 as usize)
    }

    fn prepartition_region_vertex(
        &mut self,
        regions: &mut HashMap<(NodeId, FieldRegion), usize>,
        root: NodeId,
        region: FieldRegion,
    ) -> usize {
        if let Some(&vertex) = regions.get(&(root, region)) {
            return vertex;
        }
        let vertex = self.ap_parent.len();
        self.ap_parent.push(vertex);
        self.prepartition_regions.push(Some((root, region)));
        regions.insert((root, region), vertex);

        // Region identities are allocation-relative. Join only regions of this allocation
        // whose byte extents may overlap; unrelated allocations and disjoint fields remain
        // distinct even if Steensgaard put their pointer carriers in one class.
        let aliases = regions
            .iter()
            .filter_map(|(&(candidate_root, candidate_region), &candidate)| {
                (candidate != vertex
                    && candidate_root == root
                    && region.may_overlap(candidate_region))
                .then_some(candidate)
            })
            .collect::<Vec<_>>();
        for alias in aliases {
            self.ap_union(vertex, alias);
        }
        vertex
    }

    fn prepartition_storage_vertex(
        &mut self,
        regions: &mut HashMap<(NodeId, FieldRegion), usize>,
        address_node: NodeId,
        width: Option<u64>,
        direct_root_at_zero: bool,
    ) -> Option<usize> {
        let address = self.exact_addresses[address_node.0 as usize]?;
        if address.location == FieldLocation::Exact(0) && !address.via_gep && direct_root_at_zero {
            return Some(address.root.0 as usize);
        }
        Some(self.prepartition_region_vertex(
            regions,
            address.root,
            FieldRegion::access(address.location, width),
        ))
    }

    /// Build weak components of the actual inclusion constraints, using independent
    /// allocation-relative region vertices for certified memory accesses. This graph is
    /// intentionally not derived from final Steensgaard equivalence classes: those classes
    /// remain the sound fallback and target envelope, but no longer dictate admission size.
    fn build_scope(&mut self) {
        self.ap_parent = (0..self.n_base).collect();
        self.prepartition_regions = vec![None; self.n_base];
        self.prepartition_edge_vertices = vec![None; self.pag.edges.len()];
        let mut regions = HashMap::new();

        for (edge_index, edge) in self.pag.edges.iter().enumerate() {
            let src = edge.src.0 as usize;
            let dst = edge.dst.0 as usize;
            let endpoints = match edge.kind {
                EdgeKind::AddrOf => Some((dst, src)),
                EdgeKind::Assign if self.pointer_transfer(edge.src, edge.dst) => Some((src, dst)),
                EdgeKind::Assign => None,
                EdgeKind::Load if self.node_may_carry_pointer(edge.dst) => {
                    let width =
                        (!edge.access_extent_unknown).then_some(edge.access_bytes.unwrap_or(0));
                    let storage = self
                        .prepartition_storage_vertex(&mut regions, edge.src, width, true)
                        .unwrap_or(src);
                    Some((storage, dst))
                }
                EdgeKind::Load => None,
                EdgeKind::Store if self.node_may_carry_pointer(edge.src) => {
                    let width =
                        (!edge.access_extent_unknown).then_some(edge.access_bytes.unwrap_or(0));
                    let storage = self
                        .prepartition_storage_vertex(&mut regions, edge.dst, width, true)
                        .unwrap_or(dst);
                    Some((storage, src))
                }
                EdgeKind::Store => None,
                EdgeKind::Gep { .. } => {
                    let region = self
                        .prepartition_storage_vertex(&mut regions, edge.dst, Some(0), false)
                        .unwrap_or(src);
                    // The destination pointer is the carrier for this precise location in
                    // Andersen; connecting it to the region keeps its producer and consumers
                    // in the same component without connecting the allocation's other fields.
                    Some((dst, region))
                }
                EdgeKind::Memcpy { bytes } => {
                    let dst_storage = self
                        .prepartition_storage_vertex(&mut regions, edge.dst, bytes, false)
                        .unwrap_or(dst);
                    let src_storage = self
                        .prepartition_storage_vertex(&mut regions, edge.src, bytes, false)
                        .unwrap_or(src);
                    Some((dst_storage, src_storage))
                }
            };
            if let Some((left, right)) = endpoints {
                self.ap_union(left, right);
            }
            self.prepartition_edge_vertices[edge_index] = endpoints;
        }

        // On-the-fly indirect-call bindings are constraints too. Add every binding admitted
        // by the sound Steensgaard target envelope (plus independently exact overrides) so
        // an argument's address-producing constraints cannot be stranded outside the
        // callee parameter's component.
        let base_targets = self
            .base
            .indirect_calls
            .iter()
            .map(|row| (row.callsite_key.as_str(), row.targets.as_slice()))
            .collect::<HashMap<_, _>>();
        for callsite in &self.pag.callsites {
            if callsite.kind != CallKind::Indirect {
                continue;
            }
            let mut targets = base_targets
                .get(callsite.key.as_str())
                .into_iter()
                .flat_map(|targets| targets.iter().map(String::as_str))
                .chain(
                    self.exact_targets
                        .get(&callsite.key)
                        .into_iter()
                        .flat_map(|targets| targets.iter().map(String::as_str)),
                )
                .filter_map(|target| self.func_index.get(target).copied())
                .collect::<Vec<_>>();
            targets.sort_unstable();
            targets.dedup();
            for function in targets {
                for (index, &argument) in callsite.args.iter().enumerate() {
                    if let Some(&parameter) = self.param_nodes.get(&(function, index)) {
                        if self.pointer_transfer(argument, parameter) {
                            self.ap_union(argument.0 as usize, parameter.0 as usize);
                        }
                    }
                }
                if let (Some(result), Some(&ret)) = (callsite.result, self.ret_nodes.get(&function))
                {
                    if self.pointer_transfer(ret, result) {
                        self.ap_union(ret.0 as usize, result.0 as usize);
                    }
                }
            }
        }

        // Seed interesting Andersen partitions.
        let mut interesting: HashSet<usize> = HashSet::new();
        for callsite in &self.pag.callsites {
            if callsite.kind == CallKind::Indirect {
                if let Some(op) = callsite.operand {
                    let ap = self.ap_find(op.0 as usize);
                    interesting.insert(ap);
                }
            }
        }
        for node in &self.pag.nodes {
            let class = self.classes.class_of(node.id);
            let ap = self.ap_find(node.id.0 as usize);
            let escape = self.classes.ext[class] || self.classes.esc[class];
            let is_global = matches!(
                node.kind,
                NodeKind::Object {
                    object: ObjectKind::Global,
                    ..
                }
            );
            if escape || is_global {
                interesting.insert(ap);
            }
        }
        for vertex in self.n_base..self.prepartition_regions.len() {
            if let Some((root, _)) = self.prepartition_regions[vertex] {
                if matches!(
                    self.pag.nodes[root.0 as usize].kind,
                    NodeKind::Object {
                        object: ObjectKind::Global,
                        ..
                    }
                ) {
                    interesting.insert(self.ap_find(vertex));
                }
            }
        }

        // Per-partition oversize estimate: nodes × (nodes + edges touching the partition),
        // a proxy for "constraints × pts bits" (`PLAN-M1_lite_delta.md` §M1.4b).
        let mut nodes_in: HashMap<usize, u64> = HashMap::new();
        for node in &self.pag.nodes {
            let ap = self.ap_find(node.id.0 as usize);
            *nodes_in.entry(ap).or_insert(0) += 1;
        }
        for vertex in self.n_base..self.prepartition_regions.len() {
            let ap = self.ap_find(vertex);
            *nodes_in.entry(ap).or_insert(0) += 1;
        }
        let mut edges_in: HashMap<usize, u64> = HashMap::new();
        for (edge_index, _) in self.pag.edges.iter().enumerate() {
            if let Some((left, _)) = self.prepartition_edge_vertices[edge_index] {
                let ap = self.ap_find(left);
                *edges_in.entry(ap).or_insert(0) += 1;
            }
        }

        let mut oversize: HashSet<usize> = HashSet::new();
        let forged_partitions = self
            .pag
            .omega_seeds
            .iter()
            .filter(|seed| seed.kind == OmegaSeedKind::IntToPtr)
            .filter_map(|seed| self.omega_seed_partition(seed))
            .collect::<HashSet<_>>();
        for &ap in &interesting {
            let n = nodes_in.get(&ap).copied().unwrap_or(0);
            let e = edges_in.get(&ap).copied().unwrap_or(0);
            let cost = n.saturating_mul(n.saturating_add(e));
            let provenance_promoted = self.budget
                >= knobs::ANDERSEN_PROVENANCE_PROMOTION_MIN_BUDGET
                && n <= knobs::ANDERSEN_PROVENANCE_PROMOTION_MAX_NODES
                && e <= knobs::ANDERSEN_PROVENANCE_PROMOTION_MAX_EDGES
                && !forged_partitions.contains(&ap);
            if cost > self.budget && !provenance_promoted {
                oversize.insert(ap);
            }
        }
        if self.collect_admission_structures && self.admission_profile_root.is_none() {
            self.admission_structures = self.collect_admission_structure_profiles(
                &interesting,
                &forged_partitions,
                &nodes_in,
                &edges_in,
            );
            if admission_profile_enabled() {
                for record in &self.admission_structures {
                    eprintln!(
                        "pangs andersen admission profile: {}",
                        serde_json::to_string(record)
                            .expect("serialize admission structure profile")
                    );
                }
            }
        }
        if let Some(selected) = self.admission_profile_root {
            assert!(
                interesting.contains(&selected),
                "{}={} is not an interesting partition root",
                knobs::ENV_ANDERSEN_ADMISSION_PROFILE_ROOT,
                selected
            );
            oversize = interesting
                .iter()
                .copied()
                .filter(|&partition| partition != selected)
                .collect();
        }
        self.oversize_fallbacks = oversize.len();
        self.oversize_fallback_max_size = oversize
            .iter()
            .filter_map(|ap| nodes_in.get(ap).copied())
            .max()
            .unwrap_or(0) as usize;

        if partition_profile_enabled() {
            self.print_partition_profile(&interesting, &oversize, &nodes_in, &edges_in);
        }

        for i in 0..self.n_base {
            let ap = self.ap_find(i);
            self.in_scope[i] = interesting.contains(&ap) && !oversize.contains(&ap);
        }
    }

    fn collect_admission_structure_profiles(
        &self,
        interesting: &HashSet<usize>,
        forged_partitions: &HashSet<usize>,
        nodes_in: &HashMap<usize, u64>,
        edges_in: &HashMap<usize, u64>,
    ) -> Vec<AdmissionStructureProfile> {
        let mut profiles = self.collect_partition_profiles();
        profiles.retain(|root, _| interesting.contains(root));
        let mut roots = profiles.keys().copied().collect::<Vec<_>>();
        roots.sort_unstable();
        roots
            .into_iter()
            .map(|root| {
                let profile = &profiles[&root];
                let nodes = nodes_in.get(&root).copied().unwrap_or(0);
                let edges = edges_in.get(&root).copied().unwrap_or(0);
                AdmissionStructureProfile {
                    kind: "structure",
                    root,
                    nodes,
                    edges,
                    quadratic_proxy: nodes.saturating_mul(nodes.saturating_add(edges)),
                    forged: forged_partitions.contains(&root),
                    values: profile.values,
                    allocas: profile.allocas,
                    globals: profile.globals.len(),
                    functions: profile.functions.len(),
                    icalls: profile.icalls,
                    ext_classes: profile.ext_classes,
                    esc_classes: profile.esc_classes,
                    edge_counts: profile.edge_counts.clone(),
                    omega_seed_counts: profile.omega_seed_counts.clone(),
                }
            })
            .collect()
    }

    fn collect_partition_profiles(&self) -> HashMap<usize, PartitionProfile> {
        let mut profiles: HashMap<usize, PartitionProfile> = HashMap::new();
        for node in &self.pag.nodes {
            let class = self.classes.class_of(node.id);
            let root = self.partition_of_node(node.id);
            let profile = profiles.entry(root).or_insert_with(|| PartitionProfile {
                root,
                ..PartitionProfile::default()
            });
            profile.nodes += 1;
            if self.classes.ext.get(class).copied().unwrap_or(false) {
                profile.ext_classes += 1;
            }
            if self.classes.esc.get(class).copied().unwrap_or(false) {
                profile.esc_classes += 1;
            }
            match &node.kind {
                NodeKind::Value { .. } | NodeKind::Param { .. } | NodeKind::Return { .. } => {
                    profile.values += 1;
                }
                NodeKind::Object { object, key, .. } => match object {
                    ObjectKind::Alloca => profile.allocas += 1,
                    ObjectKind::Global => profile.globals.push(key.clone()),
                    ObjectKind::Function => profile.functions.push(key.clone()),
                    ObjectKind::ExternalReadonly => {}
                },
            }
        }
        for callsite in &self.pag.callsites {
            if callsite.kind != CallKind::Indirect {
                continue;
            }
            let Some(operand) = callsite.operand else {
                continue;
            };
            let root = self.partition_of_node(operand);
            profiles
                .entry(root)
                .or_insert_with(|| PartitionProfile {
                    root,
                    ..PartitionProfile::default()
                })
                .icalls += 1;
        }
        for (edge_index, edge) in self.pag.edges.iter().enumerate() {
            let Some((vertex, _)) = self.prepartition_edge_vertices[edge_index] else {
                continue;
            };
            let root = ap_find_const(&self.ap_parent, vertex);
            *profiles
                .entry(root)
                .or_insert_with(|| PartitionProfile {
                    root,
                    ..PartitionProfile::default()
                })
                .edge_counts
                .entry(edge_family(edge.kind))
                .or_insert(0) += 1;
        }
        for seed in &self.pag.omega_seeds {
            let Some(root) = self.omega_seed_partition(seed) else {
                continue;
            };
            *profiles
                .entry(root)
                .or_insert_with(|| PartitionProfile {
                    root,
                    ..PartitionProfile::default()
                })
                .omega_seed_counts
                .entry(omega_seed_kind_label(seed.kind))
                .or_insert(0) += 1;
        }
        for profile in profiles.values_mut() {
            profile.globals.sort();
            profile.globals.dedup();
            profile.functions.sort();
            profile.functions.dedup();
        }
        profiles
    }

    fn print_partition_profile(
        &self,
        interesting: &HashSet<usize>,
        oversize: &HashSet<usize>,
        nodes_in: &HashMap<usize, u64>,
        edges_in: &HashMap<usize, u64>,
    ) {
        let top = partition_profile_top();
        let mut profiles: HashMap<usize, PartitionProfile> = HashMap::new();
        for node in &self.pag.nodes {
            let class = self.classes.class_of(node.id);
            let ap = self.partition_of_node(node.id);
            let profile = profiles.entry(ap).or_insert_with(|| PartitionProfile {
                root: ap,
                ..PartitionProfile::default()
            });
            profile.nodes += 1;
            if self.classes.ext.get(class).copied().unwrap_or(false) {
                profile.ext_classes += 1;
            }
            if self.classes.esc.get(class).copied().unwrap_or(false) {
                profile.esc_classes += 1;
            }
            match &node.kind {
                NodeKind::Value { .. } | NodeKind::Param { .. } | NodeKind::Return { .. } => {
                    profile.values += 1;
                }
                NodeKind::Object { object, key, .. } => match object {
                    ObjectKind::Alloca => profile.allocas += 1,
                    ObjectKind::Global => profile.globals.push(key.clone()),
                    ObjectKind::Function => profile.functions.push(key.clone()),
                    ObjectKind::ExternalReadonly => {}
                },
            }
        }
        for callsite in &self.pag.callsites {
            if callsite.kind != CallKind::Indirect {
                continue;
            }
            let Some(operand) = callsite.operand else {
                continue;
            };
            let ap = self.partition_of_node(operand);
            profiles
                .entry(ap)
                .or_insert_with(|| PartitionProfile {
                    root: ap,
                    ..PartitionProfile::default()
                })
                .icalls += 1;
        }
        for (edge_index, edge) in self.pag.edges.iter().enumerate() {
            let Some((vertex, _)) = self.prepartition_edge_vertices[edge_index] else {
                continue;
            };
            let ap = ap_find_const(&self.ap_parent, vertex);
            *profiles
                .entry(ap)
                .or_insert_with(|| PartitionProfile {
                    root: ap,
                    ..PartitionProfile::default()
                })
                .edge_counts
                .entry(edge_family(edge.kind))
                .or_insert(0) += 1;
        }
        for seed in &self.pag.omega_seeds {
            let Some(ap) = self.omega_seed_partition(seed) else {
                continue;
            };
            *profiles
                .entry(ap)
                .or_insert_with(|| PartitionProfile {
                    root: ap,
                    ..PartitionProfile::default()
                })
                .omega_seed_counts
                .entry(omega_seed_kind_label(seed.kind))
                .or_insert(0) += 1;
        }

        let mut interesting_profiles: Vec<_> = profiles
            .values_mut()
            .filter(|profile| interesting.contains(&profile.root))
            .collect();
        for profile in &mut interesting_profiles {
            profile.globals.sort();
            profile.globals.dedup();
            profile.functions.sort();
            profile.functions.dedup();
        }
        interesting_profiles.sort_by(|left, right| {
            nodes_in
                .get(&right.root)
                .copied()
                .unwrap_or(right.nodes as u64)
                .cmp(
                    &nodes_in
                        .get(&left.root)
                        .copied()
                        .unwrap_or(left.nodes as u64),
                )
                .then_with(|| left.root.cmp(&right.root))
        });

        eprintln!(
            "pangs partition profile: interesting={} oversize={} top={}",
            interesting.len(),
            oversize.len(),
            top
        );
        for profile in interesting_profiles.into_iter().take(top) {
            let n = nodes_in
                .get(&profile.root)
                .copied()
                .unwrap_or(profile.nodes as u64);
            let e = edges_in.get(&profile.root).copied().unwrap_or(0);
            let cost = n.saturating_mul(n.saturating_add(e));
            eprintln!(
                "pangs partition profile: root={} nodes={} edges={} cost={} oversize={} values={} allocas={} globals={} functions={} icalls={} ext_classes={} esc_classes={}",
                profile.root,
                n,
                e,
                cost,
                oversize.contains(&profile.root),
                profile.values,
                profile.allocas,
                profile.globals.len(),
                profile.functions.len(),
                profile.icalls,
                profile.ext_classes,
                profile.esc_classes
            );
            eprintln!(
                "pangs partition profile: root={} edge_counts={}",
                profile.root,
                format_counts(&profile.edge_counts)
            );
            if !profile.omega_seed_counts.is_empty() {
                eprintln!(
                    "pangs partition profile: root={} omega_seeds={}",
                    profile.root,
                    format_counts(&profile.omega_seed_counts)
                );
            }
            eprintln!(
                "pangs partition profile: root={} global_sample={:?} function_sample={:?}",
                profile.root,
                sample_strings(
                    &profile.globals,
                    knobs::PARTITION_PROFILE_SYMBOL_SAMPLE_LIMIT
                ),
                sample_strings(
                    &profile.functions,
                    knobs::PARTITION_PROFILE_SYMBOL_SAMPLE_LIMIT
                )
            );
            let hubs = self.partition_hubs(profile.root, knobs::PARTITION_PROFILE_HUB_LIMIT);
            if !hubs.is_empty() {
                eprintln!(
                    "pangs partition profile: root={} top_load_store_hubs={}",
                    profile.root,
                    hubs.join("; ")
                );
            }
            let offset_collisions = self
                .partition_offset_collisions(profile.root, knobs::PARTITION_PROFILE_DETAIL_LIMIT);
            if !offset_collisions.is_empty() {
                eprintln!(
                    "pangs partition profile: root={} offset_collisions={}",
                    profile.root,
                    offset_collisions.join("; ")
                );
            }
            let mixed_classes = self.partition_function_data_cohabitation(
                profile.root,
                knobs::PARTITION_PROFILE_DETAIL_LIMIT,
            );
            if !mixed_classes.is_empty() {
                eprintln!(
                    "pangs partition profile: root={} function_data_cohabitation={}",
                    profile.root,
                    mixed_classes.join("; ")
                );
            }
            let copy_bridges = self.partition_aggregate_copy_bridges(
                profile.root,
                knobs::PARTITION_PROFILE_DETAIL_LIMIT,
            );
            if !copy_bridges.is_empty() {
                eprintln!(
                    "pangs partition profile: root={} aggregate_copy_bridges={}",
                    profile.root,
                    copy_bridges.join("; ")
                );
            }
            let cuts = [
                PartitionCut::None,
                PartitionCut::WithoutLoad,
                PartitionCut::WithoutStore,
                PartitionCut::WithoutLoadStore,
                PartitionCut::WithoutUnknownGep,
                PartitionCut::WithoutConstGep,
                PartitionCut::WithoutMemcpyMemset,
            ];
            for cut in cuts {
                eprintln!(
                    "pangs partition profile: root={} cut={} largest_node_components={:?}",
                    profile.root,
                    cut.label(),
                    self.partition_cut_components(
                        profile.root,
                        cut,
                        knobs::PARTITION_PROFILE_DETAIL_LIMIT
                    )
                );
            }
            eprintln!(
                "pangs partition profile: root={} cut=without_external_boundary largest_node_components=n/a(no explicit partition edge)",
                profile.root
            );
            eprintln!(
                "pangs partition profile: root={} cut=without_indirect_bindings largest_node_components=n/a(no explicit partition edge)",
                profile.root
            );
        }
    }

    fn omega_seed_partition(&self, seed: &pangs_pag::OmegaSeed) -> Option<usize> {
        match seed.target {
            SeedTarget::Node(node) => Some(self.partition_of_node(node)),
            SeedTarget::Callsite(callsite) => self
                .pag
                .callsites
                .get(callsite.0 as usize)
                .and_then(|callsite| callsite.operand)
                .map(|node| self.partition_of_node(node)),
        }
    }

    fn diagnostic_join_edge(&self, edge_index: usize) -> Option<(usize, usize, &'static str)> {
        let edge = &self.pag.edges[edge_index];
        let (left, right) = self.prepartition_edge_vertices[edge_index]?;
        let family = match edge.kind {
            EdgeKind::AddrOf => "addr_of",
            EdgeKind::Assign => "assign",
            EdgeKind::Load => "load",
            EdgeKind::Store => "store",
            EdgeKind::Gep { byte_off, lane } => {
                if byte_off.is_some() || lane.is_some() {
                    "gep_const"
                } else {
                    "gep_unknown"
                }
            }
            EdgeKind::Memcpy { .. } => "memcpy",
        };
        Some((left, right, family))
    }

    fn partition_hubs(&self, ap: usize, limit: usize) -> Vec<String> {
        let mut counts: HashMap<usize, (usize, usize)> = HashMap::new();
        let mut witnesses: HashMap<usize, Vec<String>> = HashMap::new();
        for (edge_index, edge) in self.pag.edges.iter().enumerate() {
            let Some((left, right, family)) = self.diagnostic_join_edge(edge_index) else {
                continue;
            };
            if ap_find_const(&self.ap_parent, left) != ap
                || ap_find_const(&self.ap_parent, right) != ap
            {
                continue;
            }
            match family {
                "load" => {
                    counts.entry(right).or_default().0 += 1;
                    push_limited_witness(&mut witnesses, right, edge_witness("load", edge), 3);
                }
                "store" => {
                    counts.entry(left).or_default().1 += 1;
                    push_limited_witness(&mut witnesses, left, edge_witness("store", edge), 3);
                }
                _ => {}
            }
        }
        let mut hubs: Vec<_> = counts
            .into_iter()
            .filter(|(_, (loads, stores))| *loads > 0 || *stores > 0)
            .collect();
        hubs.sort_by(
            |(left_root, (left_loads, left_stores)), (right_root, (right_loads, right_stores))| {
                right_loads
                    .saturating_add(*right_stores)
                    .cmp(&left_loads.saturating_add(*left_stores))
                    .then_with(|| left_root.cmp(right_root))
            },
        );
        hubs.into_iter()
            .take(limit)
            .map(|(root, (loads, stores))| {
                format!(
                    "class={} loads={} stores={} labels={:?} witnesses={:?}",
                    root,
                    loads,
                    stores,
                    self.class_label_sample(
                        root,
                        knobs::PARTITION_PROFILE_CLASS_LABEL_SAMPLE_LIMIT,
                    ),
                    witnesses.remove(&root).unwrap_or_default()
                )
            })
            .collect()
    }

    /// Report final Steensgaard object classes into which multiple source-level GEP
    /// offsets were folded. This does not claim that the GEPs alone caused the complete
    /// class merge; it records the exact field distinctions a field-sensitive fallback
    /// could have retained.
    fn partition_offset_collisions(&self, ap: usize, limit: usize) -> Vec<String> {
        #[derive(Default)]
        struct Collision {
            offsets: BTreeSet<FieldLocation>,
            edges: usize,
            witnesses: Vec<String>,
        }

        let mut by_class = HashMap::<usize, Collision>::new();
        for (edge_index, edge) in self.pag.edges.iter().enumerate() {
            let EdgeKind::Gep { byte_off, lane } = edge.kind else {
                continue;
            };
            let Some((left, right, _)) = self.diagnostic_join_edge(edge_index) else {
                continue;
            };
            if ap_find_const(&self.ap_parent, left) != ap
                || ap_find_const(&self.ap_parent, right) != ap
            {
                continue;
            }
            let class = left;
            let collision = by_class.entry(class).or_default();
            let location = FieldLocation::from_gep(byte_off, lane);
            collision.offsets.insert(location);
            collision.edges += 1;
            if collision.witnesses.len() < knobs::PARTITION_PROFILE_COLLISION_WITNESS_LIMIT {
                collision
                    .witnesses
                    .push(format!("off={location:?}:{}", edge_witness("gep", edge)));
            }
        }

        let mut collisions = by_class
            .into_iter()
            .filter(|(_, collision)| collision.offsets.len() > 1)
            .collect::<Vec<_>>();
        collisions.sort_by(|(left_class, left), (right_class, right)| {
            right
                .offsets
                .len()
                .cmp(&left.offsets.len())
                .then_with(|| right.edges.cmp(&left.edges))
                .then_with(|| left_class.cmp(right_class))
        });
        collisions
            .into_iter()
            .take(limit)
            .map(|(class, collision)| {
                let offset_count = collision.offsets.len();
                let offsets = collision
                    .offsets
                    .iter()
                    .take(knobs::PARTITION_PROFILE_COLLISION_OFFSET_SAMPLE_LIMIT)
                    .map(|offset| format!("{offset:?}"))
                    .collect::<Vec<_>>();
                format!(
                    "class={} offset_count={} offset_sample={:?} edges={} labels={:?} witnesses={:?}",
                    class,
                    offset_count,
                    offsets,
                    collision.edges,
                    self.class_label_sample(
                        class,
                        knobs::PARTITION_PROFILE_CLASS_LABEL_SAMPLE_LIMIT,
                    ),
                    collision.witnesses
                )
            })
            .collect()
    }

    /// Report Steensgaard classes that simultaneously contain function allocations and
    /// data allocations. These are the concrete mixed-domain classes that pointer lanes
    /// are intended to split.
    fn partition_function_data_cohabitation(&self, ap: usize, limit: usize) -> Vec<String> {
        #[derive(Default)]
        struct Occupants {
            functions: Vec<String>,
            data: Vec<String>,
        }

        let mut by_class = HashMap::<usize, Occupants>::new();
        for node in &self.pag.nodes {
            let NodeKind::Object { object, key, .. } = &node.kind else {
                continue;
            };
            let class = node.id.0 as usize;
            if self.partition_of_node(node.id) != ap {
                continue;
            }
            let occupants = by_class.entry(class).or_default();
            match object {
                ObjectKind::Function => occupants.functions.push(key.clone()),
                ObjectKind::Alloca | ObjectKind::Global | ObjectKind::ExternalReadonly => {
                    occupants.data.push(key.clone());
                }
            }
        }
        let mut mixed = by_class
            .into_iter()
            .filter(|(_, occupants)| !occupants.functions.is_empty() && !occupants.data.is_empty())
            .collect::<Vec<_>>();
        for (_, occupants) in &mut mixed {
            occupants.functions.sort();
            occupants.functions.dedup();
            occupants.data.sort();
            occupants.data.dedup();
        }
        mixed.sort_by(|(left_class, left), (right_class, right)| {
            right
                .functions
                .len()
                .saturating_mul(right.data.len())
                .cmp(&left.functions.len().saturating_mul(left.data.len()))
                .then_with(|| left_class.cmp(right_class))
        });
        mixed
            .into_iter()
            .take(limit)
            .map(|(class, occupants)| {
                format!(
                    "class={} functions={} data={} function_sample={:?} data_sample={:?}",
                    class,
                    occupants.functions.len(),
                    occupants.data.len(),
                    sample_strings(
                        &occupants.functions,
                        knobs::PARTITION_PROFILE_OCCUPANT_SAMPLE_LIMIT
                    ),
                    sample_strings(
                        &occupants.data,
                        knobs::PARTITION_PROFILE_OCCUPANT_SAMPLE_LIMIT
                    )
                )
            })
            .collect()
    }

    /// Report aggregate-copy constraints whose field-insensitive content join lands in a
    /// function/data mixed class. They are potential layout-erasing bridges, not causal
    /// proofs: another constraint may already have merged the same content class.
    fn partition_aggregate_copy_bridges(&self, ap: usize, limit: usize) -> Vec<String> {
        let mut object_kinds = HashMap::<usize, (bool, bool)>::new();
        for node in &self.pag.nodes {
            let NodeKind::Object { object, .. } = &node.kind else {
                continue;
            };
            let entry = object_kinds.entry(node.id.0 as usize).or_default();
            match object {
                ObjectKind::Function => entry.0 = true,
                ObjectKind::Alloca | ObjectKind::Global | ObjectKind::ExternalReadonly => {
                    entry.1 = true;
                }
            }
        }

        self.pag
            .edges
            .iter()
            .enumerate()
            .filter_map(|(edge_index, edge)| {
                let EdgeKind::Memcpy { bytes } = edge.kind else {
                    return None;
                };
                let (left, right, _) = self.diagnostic_join_edge(edge_index)?;
                if ap_find_const(&self.ap_parent, left) != ap
                    || ap_find_const(&self.ap_parent, right) != ap
                {
                    return None;
                }
                let left_kinds = object_kinds.get(&left).copied().unwrap_or_default();
                let right_kinds = object_kinds.get(&right).copied().unwrap_or_default();
                let mixed = (left_kinds.0 || right_kinds.0) && (left_kinds.1 || right_kinds.1);
                mixed.then(|| {
                    format!(
                        "content_classes={}->{} bytes={} src={} dst={} witness={}",
                        right,
                        left,
                        bytes
                            .map(|bytes| bytes.to_string())
                            .unwrap_or_else(|| "unknown".to_string()),
                        self.pag.nodes[edge.src.0 as usize].label,
                        self.pag.nodes[edge.dst.0 as usize].label,
                        edge_witness("memcpy", edge)
                    )
                })
            })
            .take(limit)
            .collect()
    }

    fn partition_cut_components(&self, ap: usize, cut: PartitionCut, limit: usize) -> Vec<usize> {
        let mut nodes = BTreeSet::<u32>::new();
        for node in &self.pag.nodes {
            if self.partition_of_node(node.id) == ap {
                nodes.insert(node.id.0);
            }
        }
        let mut adjacency: HashMap<u32, Vec<u32>> = HashMap::new();
        for edge in &self.pag.edges {
            let family = edge_family(edge.kind);
            if cut.removes(family) {
                continue;
            }
            let src_ap = self.partition_of_node(edge.src);
            let dst_ap = self.partition_of_node(edge.dst);
            if src_ap == ap && dst_ap == ap {
                nodes.insert(edge.src.0);
                nodes.insert(edge.dst.0);
                adjacency.entry(edge.src.0).or_default().push(edge.dst.0);
                adjacency.entry(edge.dst.0).or_default().push(edge.src.0);
            }
        }
        let mut seen = HashSet::new();
        let mut sizes = Vec::new();
        for &start in &nodes {
            if !seen.insert(start) {
                continue;
            }
            let mut stack = vec![start];
            let mut size = 0usize;
            while let Some(node) = stack.pop() {
                size += 1;
                if let Some(neighbors) = adjacency.get(&node) {
                    for &next in neighbors {
                        if seen.insert(next) {
                            stack.push(next);
                        }
                    }
                }
            }
            sizes.push(size);
        }
        sizes.sort_by(|left, right| right.cmp(left));
        sizes.truncate(limit);
        sizes
    }

    fn class_label_sample(&self, vertex: usize, _limit: usize) -> Vec<String> {
        if vertex < self.n_base {
            return vec![self.pag.nodes[vertex].label.clone()];
        }
        self.prepartition_regions
            .get(vertex)
            .and_then(|region| *region)
            .map(|(root, region)| {
                vec![format!(
                    "region:{}:{:?}",
                    self.pag.nodes[root.0 as usize].label, region
                )]
            })
            .unwrap_or_else(|| vec![format!("synthetic:{vertex}")])
    }

    // ----- monotone on-the-fly call-graph refinement -----------------------------------

    fn run(mut self, controls: AndersenControls) -> RefinerOutcome {
        // Indirect callsites we will refine (in-scope), with their PAG indices.
        let in_scope_sites: Vec<usize> = (0..self.pag.callsites.len())
            .filter(|&i| {
                let cs = &self.pag.callsites[i];
                cs.kind == CallKind::Indirect
                    && cs
                        .operand
                        .map(|op| self.in_scope[op.0 as usize])
                        .unwrap_or(false)
            })
            .collect();
        if andersen_profile_enabled() {
            let scope = self.scope_profile();
            eprintln!(
                "pangs andersen profile: scope nodes={} edges={} loads={} stores={} geps={} memcpys={} in_scope_icalls={} oversize_fallbacks={} oversize_fallback_max_size={}",
                scope.in_scope_nodes,
                scope.in_scope_edges,
                scope.in_scope_loads,
                scope.in_scope_stores,
                scope.in_scope_geps,
                scope.in_scope_memcpys,
                in_scope_sites.len(),
                self.oversize_fallbacks,
                self.oversize_fallback_max_size
            );
        }

        // Store each non-exact site's sound target envelope. Exact sites are pinned
        // independently and never participate in discovery.
        let steens_by_key: HashMap<&str, &IndirectCallResolution> = self
            .base
            .indirect_calls
            .iter()
            .map(|r| (r.callsite_key.as_str(), r))
            .collect();
        let mut envelopes: HashMap<usize, Vec<usize>> = HashMap::new();
        let mut exact_map: HashMap<usize, Vec<usize>> = HashMap::new();
        let mut eager_sites = HashSet::new();
        for &site in &in_scope_sites {
            let key = self.pag.callsites[site].key.as_str();
            if let Some(funcs) = self.exact_target_indices(key) {
                exact_map.insert(site, funcs);
            } else {
                let envelope = steens_by_key
                    .get(key)
                    .map(|r| self.non_confined_target_indices(&r.targets))
                    .unwrap_or_default();
                envelopes.insert(site, envelope);
                // A Steensgaard unknown-callee verdict means named address flow is not a
                // complete account of possible internal callbacks. Activate the envelope
                // eagerly and retain fallback provenance for this site.
                if !controls.disable_eager_unknown
                    && steens_by_key.get(key).is_some_and(|row| row.unknown_callee)
                {
                    eager_sites.insert(site);
                }
            }
        }

        let mut solve = self.build_base_solve();
        let mut activated: HashMap<usize, BTreeSet<usize>> = HashMap::new();
        let mut external_summaries = HashSet::new();
        let mut initial = exact_map
            .iter()
            .flat_map(|(&site, funcs)| funcs.iter().map(move |&func| (site, func)))
            .collect::<Vec<_>>();
        for &site in &eager_sites {
            if let Some(functions) = envelopes.get(&site) {
                initial.extend(functions.iter().map(|&function| (site, function)));
            }
        }
        initial.sort_unstable();
        initial.dedup();
        for (site, func) in initial {
            self.activate_target(
                &mut solve,
                &mut activated,
                &mut external_summaries,
                site,
                func,
            );
        }

        let max_steps = controls.max_steps;
        let max_resumes = controls
            .max_resumes
            .unwrap_or(knobs::ANDERSEN_MAX_RESUME_ROUNDS);
        let injection = controls.inject_exhaustion;
        let mut resume_rounds = 0usize;
        let mut known_unbound = Vec::new();
        loop {
            resume_rounds += 1;
            if injection.as_deref() == Some("propagation") {
                return RefinerOutcome::Exhausted(self.exhaustion(
                    &solve,
                    "injected_during_propagation",
                    resume_rounds,
                    known_unbound.len(),
                    activated.values().map(BTreeSet::len).sum(),
                ));
            }
            if !solve.run_with_limit(max_steps) {
                return RefinerOutcome::Exhausted(self.exhaustion(
                    &solve,
                    "propagation_step_budget",
                    resume_rounds,
                    known_unbound.len(),
                    activated.values().map(BTreeSet::len).sum(),
                ));
            }

            let discovery =
                self.discover_targets(&in_scope_sites, &envelopes, &exact_map, &activated, &solve);
            known_unbound = discovery.targets;
            if !controls.disable_eager_unknown {
                for site in discovery.eager_sites {
                    if eager_sites.insert(site) {
                        known_unbound.extend(
                            envelopes
                                .get(&site)
                                .into_iter()
                                .flat_map(|funcs| funcs.iter().map(|&func| (site, func))),
                        );
                    }
                }
            }
            known_unbound.sort_unstable();
            known_unbound.dedup();
            known_unbound.retain(|(site, func)| {
                !activated
                    .get(site)
                    .is_some_and(|targets| targets.contains(func))
            });

            if known_unbound.is_empty() {
                break;
            }
            if injection.as_deref() == Some("discovery") {
                return RefinerOutcome::Exhausted(self.exhaustion(
                    &solve,
                    "injected_after_discovery",
                    resume_rounds,
                    known_unbound.len(),
                    activated.values().map(BTreeSet::len).sum(),
                ));
            }
            if resume_rounds >= max_resumes {
                return RefinerOutcome::Exhausted(self.exhaustion(
                    &solve,
                    "resume_round_cap",
                    resume_rounds,
                    known_unbound.len(),
                    activated.values().map(BTreeSet::len).sum(),
                ));
            }
            if andersen_profile_enabled() {
                eprintln!(
                    "pangs andersen profile: resume {resume_rounds} discovered {} new call bindings",
                    known_unbound.len()
                );
            }
            for &(site, func) in &known_unbound {
                self.activate_target(
                    &mut solve,
                    &mut activated,
                    &mut external_summaries,
                    site,
                    func,
                );
            }
            if injection.as_deref() == Some("activation") {
                return RefinerOutcome::Exhausted(self.exhaustion(
                    &solve,
                    "injected_after_activation",
                    resume_rounds,
                    0,
                    activated.values().map(BTreeSet::len).sum(),
                ));
            }
        }

        if controls.subtractive_differential {
            assert!(
                controls.disable_eager_unknown,
                "subtractive differential requires pure-LFP mode (set {})",
                knobs::ENV_ANDERSEN_DISABLE_EAGER_UNKNOWN
            );
            let oracle = self.subtractive_oracle(&in_scope_sites, &envelopes, &exact_map);
            for &site in &in_scope_sites {
                let additive = activated.get(&site).cloned().unwrap_or_default();
                let descending = oracle.get(&site).cloned().unwrap_or_default();
                assert!(
                    additive.is_subset(&descending),
                    "monotone OTF target set is not a subset of subtractive oracle at {}: \
                     additive={additive:?} subtractive={descending:?}",
                    self.pag.callsites[site].key
                );
                if exact_map.contains_key(&site) {
                    assert_eq!(
                        additive, descending,
                        "exact target changed across Andersen constructions"
                    );
                }
            }
        }

        let activated_targets = activated.values().map(BTreeSet::len).sum();
        if andersen_profile_enabled() {
            eprintln!(
                "pangs andersen profile: joint solve done steps={} resume_rounds={} activated_targets={} eager_sites={} pts_entries={} pts_facts={} copy_sources={} copy_edges={} fields={} unknown_fields={} memcpy_pairs_processed={} copy_fact_pairs_processed={} load_pairs_processed={} store_pairs_processed={} gep_pairs_processed={} scc_passes={} scc_nodes_collapsed={} scc_copy_edges_removed={}",
                solve.steps,
                resume_rounds,
                activated_targets,
                eager_sites.len(),
                solve.pts.len(),
                solve.pts_facts(),
                solve.copy_sources(),
                solve.copy_edges(),
                solve.fields.len(),
                solve.unknown_fields.len(),
                solve.memcpy_pairs_processed,
                solve.copy_fact_pairs_processed,
                solve.load_pairs_processed,
                solve.store_pairs_processed,
                solve.gep_pairs_processed,
                solve.scc_passes,
                solve.scc_nodes_collapsed,
                solve.scc_copy_edges_removed,
            );
        }
        let indirect_calls =
            self.emit_indirect_calls(&in_scope_sites, &activated, &eager_sites, &solve);
        let nodes = self.emit_node_resolutions(&solve);
        let global_points_to = if self.materialize_global_points_to {
            self.emit_global_points_to(&solve)
        } else {
            Vec::new()
        };
        if let Some(root) = self.admission_profile_root {
            let actual_work = solve
                .steps
                .saturating_add(solve.points_to_facts_inserted)
                .saturating_add(solve.copy_edges_inserted)
                .saturating_add(solve.copy_fact_pairs_processed)
                .saturating_add(solve.load_pairs_processed)
                .saturating_add(solve.store_pairs_processed)
                .saturating_add(solve.gep_pairs_processed)
                .saturating_add(solve.memcpy_pairs_processed)
                .saturating_add(solve.field_cells_allocated)
                .saturating_add(solve.scc_nodes_scanned)
                .saturating_add(solve.scc_edges_scanned);
            let record = AdmissionWorkProfile {
                kind: "work",
                root,
                actual_work,
                worklist_pops: solve.steps,
                points_to_facts_inserted: solve.points_to_facts_inserted,
                copy_edges_inserted: solve.copy_edges_inserted,
                copy_fact_pairs_processed: solve.copy_fact_pairs_processed,
                load_pairs_processed: solve.load_pairs_processed,
                store_pairs_processed: solve.store_pairs_processed,
                gep_pairs_processed: solve.gep_pairs_processed,
                memcpy_pairs_processed: solve.memcpy_pairs_processed,
                field_cells_allocated: solve.field_cells_allocated,
                scc_nodes_scanned: solve.scc_nodes_scanned,
                scc_edges_scanned: solve.scc_edges_scanned,
                scc_passes: solve.scc_passes,
            };
            eprintln!(
                "pangs andersen admission profile: {}",
                serde_json::to_string(&record).expect("serialize admission work profile")
            );
        }
        RefinerOutcome::Complete(RefinerOutput {
            indirect_calls,
            nodes,
            global_points_to,
            resume_rounds,
            steps: solve.steps,
            activated_targets,
            oversize_fallbacks: self.oversize_fallbacks,
            oversize_fallback_max_size: self.oversize_fallback_max_size,
        })
    }

    fn exhaustion(
        &self,
        solve: &Solve,
        reason: &str,
        resume_rounds: usize,
        known_unbound_targets: usize,
        activated_targets: usize,
    ) -> ExhaustionDiagnostic {
        ExhaustionDiagnostic {
            reason: reason.to_string(),
            steps: solve.steps,
            resume_rounds,
            worklist: solve.worklist.len(),
            queued: solve.queued.len(),
            pending_copy_seeds: solve.pending_succ.values().map(HashSet::len).sum(),
            pending_pts_deltas: solve.pending_pts.values().map(Vec::len).sum(),
            known_unbound_targets,
            activated_targets,
            scc_passes: solve.scc_passes,
            scc_nodes_collapsed: solve.scc_nodes_collapsed,
            scc_copy_edges_removed: solve.scc_copy_edges_removed,
            memcpy_pairs_processed: solve.memcpy_pairs_processed,
            copy_fact_pairs_processed: solve.copy_fact_pairs_processed,
            oversize_fallbacks: self.oversize_fallbacks,
            oversize_fallback_max_size: self.oversize_fallback_max_size,
        }
    }

    // ----- the persistent inclusion solve -----------------------------------------------

    fn build_base_solve(&mut self) -> Solve {
        let profile = andersen_profile_enabled();
        let mut solve = Solve::new(self.n_base, profile);
        solve.known_locations.extend(
            self.exact_addresses
                .iter()
                .flatten()
                .map(|address| address.location),
        );

        // Base constraints from PAG edges (in-scope only; partitions are self-contained).
        for edge in &self.pag.edges {
            if !self.in_scope[edge.dst.0 as usize] && !self.in_scope[edge.src.0 as usize] {
                continue;
            }
            match edge.kind {
                EdgeKind::AddrOf => solve.add_pts(edge.dst.0, edge.src.0),
                EdgeKind::Assign => {
                    if self.pointer_transfer(edge.src, edge.dst) {
                        solve.add_copy(edge.src.0, edge.dst.0);
                    }
                }
                EdgeKind::Load => {
                    if self.node_may_carry_pointer(edge.dst) {
                        solve.add_load(edge.src.0, edge.dst.0);
                    }
                }
                EdgeKind::Store => {
                    if self.node_may_carry_pointer(edge.src) {
                        solve.add_store(edge.dst.0, edge.src.0, None);
                    }
                }
                EdgeKind::Gep { byte_off, lane } => {
                    let location = FieldLocation::from_gep(byte_off, lane);
                    solve.known_locations.insert(location);
                    if let Some(address) = self.exact_addresses[edge.dst.0 as usize] {
                        let field = solve.field_of(address.root.0, address.location);
                        solve.add_pts(edge.dst.0, field);
                    } else {
                        solve.add_gep(edge.src.0, location, edge.dst.0);
                    }
                }
                EdgeKind::Memcpy { .. } => solve.add_memcpy(edge.dst.0, edge.src.0),
            }
        }

        self.apply_boundary_omega_seeds(&mut solve);

        if profile {
            eprintln!(
                "pangs andersen profile: solve start target_sites=0 target_edges=0 pts_entries={} pts_facts={} copy_sources={} copy_edges={} loads={} stores={} geps={} memcpys={} copy_scc_enabled={} copy_scc_min_edges={}",
                solve.pts.len(),
                solve.pts_facts(),
                solve.copy_sources(),
                solve.copy_edges(),
                solve.loads.values().map(Vec::len).sum::<usize>()
                    + solve.pending_loads.values().map(Vec::len).sum::<usize>(),
                solve.stores.values().map(Vec::len).sum::<usize>()
                    + solve.pending_stores.values().map(Vec::len).sum::<usize>(),
                solve.geps.values().map(Vec::len).sum::<usize>()
                    + solve.pending_geps.values().map(Vec::len).sum::<usize>(),
                solve.memcpys.len(),
                solve.scc_enabled,
                solve.scc_min_edges
            );
        }
        solve
    }

    fn activate_target(
        &self,
        solve: &mut Solve,
        activated: &mut HashMap<usize, BTreeSet<usize>>,
        external_summaries: &mut HashSet<usize>,
        site: usize,
        function: usize,
    ) {
        if !activated.entry(site).or_default().insert(function) {
            return;
        }
        let callsite = &self.pag.callsites[site];
        if self.pir.functions[function].external && external_summaries.insert(site) {
            self.apply_external_call_effects(solve, callsite);
        }
        for (index, &argument) in callsite.args.iter().enumerate() {
            if let Some(&parameter) = self.param_nodes.get(&(function, index)) {
                if self.pointer_transfer(argument, parameter) {
                    solve.add_copy(argument.0, parameter.0);
                }
            }
        }
        if let (Some(result), Some(&ret)) = (callsite.result, self.ret_nodes.get(&function)) {
            if self.pointer_transfer(ret, result) {
                solve.add_copy(ret.0, result.0);
            }
        }
    }

    /// Temporary migration oracle: solve the old descending target construction to
    /// convergence. It is enabled only by an explicit diagnostic switch and intentionally
    /// shares base construction and target activation with the additive path so differences
    /// isolate fixed-point direction rather than constraint generation.
    fn subtractive_oracle(
        &mut self,
        sites: &[usize],
        envelopes: &HashMap<usize, Vec<usize>>,
        exact: &HashMap<usize, Vec<usize>>,
    ) -> HashMap<usize, BTreeSet<usize>> {
        let mut targets = sites
            .iter()
            .map(|&site| {
                let functions = exact
                    .get(&site)
                    .or_else(|| envelopes.get(&site))
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                (site, functions)
            })
            .collect::<HashMap<_, BTreeSet<_>>>();
        let max_rounds = targets.values().map(BTreeSet::len).sum::<usize>() + 1;

        for _ in 0..max_rounds {
            let mut solve = self.build_base_solve();
            let mut installed = HashMap::new();
            let mut summaries = HashSet::new();
            for (&site, functions) in &targets {
                for &function in functions {
                    self.activate_target(
                        &mut solve,
                        &mut installed,
                        &mut summaries,
                        site,
                        function,
                    );
                }
            }
            solve.run();

            let mut next = HashMap::new();
            for &site in sites {
                if let Some(functions) = exact.get(&site) {
                    next.insert(site, functions.iter().copied().collect());
                    continue;
                }
                let envelope = envelopes
                    .get(&site)
                    .map(|functions| functions.iter().copied().collect::<HashSet<_>>())
                    .unwrap_or_default();
                let functions = self.pag.callsites[site]
                    .operand
                    .and_then(|operand| solve.points_to(operand.0))
                    .into_iter()
                    .flat_map(|points_to| points_to.iter())
                    .filter_map(|cell| {
                        let root = solve.field_base.get(cell).copied().unwrap_or(*cell);
                        self.fn_cell_to_index.get(&root).copied()
                    })
                    .filter(|function| envelope.contains(function))
                    .collect::<BTreeSet<_>>();
                next.insert(site, functions);
            }
            for (&site, functions) in &next {
                debug_assert!(
                    functions.is_subset(&targets[&site]),
                    "subtractive Andersen oracle grew a target set"
                );
            }
            if next == targets {
                return next;
            }
            targets = next;
        }
        panic!("subtractive Andersen differential oracle failed to converge")
    }

    fn discover_targets(
        &self,
        sites: &[usize],
        envelopes: &HashMap<usize, Vec<usize>>,
        exact: &HashMap<usize, Vec<usize>>,
        activated: &HashMap<usize, BTreeSet<usize>>,
        solve: &Solve,
    ) -> TargetDiscovery {
        let mut discovery = TargetDiscovery::default();
        for &site in sites {
            if exact.contains_key(&site) {
                continue;
            }
            let Some(operand) = self.pag.callsites[site].operand else {
                continue;
            };
            let Some(points_to) = solve.points_to(operand.0) else {
                continue;
            };
            let envelope = envelopes
                .get(&site)
                .map(|targets| targets.iter().copied().collect::<HashSet<_>>())
                .unwrap_or_default();
            for &cell in points_to {
                if solve
                    .external_region(cell)
                    .is_some_and(ExternalRegion::may_contain_function_pointer)
                {
                    discovery.eager_sites.push(site);
                }
                let root = solve.field_base.get(&cell).copied().unwrap_or(cell);
                if let Some(&function) = self.fn_cell_to_index.get(&root) {
                    if envelope.contains(&function)
                        && !activated
                            .get(&site)
                            .is_some_and(|targets| targets.contains(&function))
                    {
                        discovery.targets.push((site, function));
                    }
                }
            }
        }
        discovery.targets.sort_unstable();
        discovery.targets.dedup();
        discovery.eager_sites.sort_unstable();
        discovery.eager_sites.dedup();
        discovery
    }

    fn apply_boundary_omega_seeds(&self, solve: &mut Solve) {
        for seed in &self.pag.omega_seeds {
            match (seed.kind, seed.target) {
                (OmegaSeedKind::IntToPtr, SeedTarget::Node(id)) => self.seed_points_to_region(
                    solve,
                    id,
                    ExternalRegion::ForgedPointer(id.0),
                    omega_seed_source(seed.kind),
                ),
                (OmegaSeedKind::UnknownResultExternal, SeedTarget::Node(id)) => self
                    .seed_points_to_region(
                        solve,
                        id,
                        ExternalRegion::UnknownReturn(id.0),
                        omega_seed_source(seed.kind),
                    ),
                (
                    OmegaSeedKind::PtrToInt | OmegaSeedKind::UnknownOperandEscape,
                    SeedTarget::Node(id),
                ) => self.seed_unknown_store_through(
                    solve,
                    id,
                    ExternalRegion::GenericStorage,
                    omega_seed_source(seed.kind),
                ),
                (
                    OmegaSeedKind::ExportedSymbol | OmegaSeedKind::ImportedSymbol,
                    SeedTarget::Node(id),
                ) => {
                    if matches!(
                        self.pag.nodes.get(id.0 as usize).map(|node| &node.kind),
                        Some(NodeKind::Object {
                            object: ObjectKind::Global,
                            ..
                        })
                    ) {
                        self.seed_points_to_region(
                            solve,
                            id,
                            ExternalRegion::GenericStorage,
                            omega_seed_source(seed.kind),
                        );
                    }
                }
                (OmegaSeedKind::ExternalCallBoundary, SeedTarget::Callsite(id)) => {
                    if let Some(callsite) = self.pag.callsites.get(id.0 as usize) {
                        self.apply_external_call_effects(solve, callsite);
                    }
                }
                (OmegaSeedKind::VarargCallBoundary, SeedTarget::Callsite(id)) => {
                    if let Some(callsite) = self.pag.callsites.get(id.0 as usize) {
                        self.apply_vararg_call_effects(solve, callsite);
                    }
                }
                _ => {}
            }
        }
        self.seed_escaped_function_params(solve);
        self.seed_main_entry_params(solve);
    }

    fn apply_external_call_effects(&self, solve: &mut Solve, callsite: &pangs_pag::Callsite) {
        let detailed = std::env::var_os(knobs::ENV_ANDERSEN_EXPLAIN_NODE).is_some();
        let arg_source = if detailed {
            format!("omega:external_call_arg:{}", callsite.key)
        } else {
            "omega:external_call_arg".to_string()
        };
        for &arg in &callsite.args {
            self.seed_unknown_store_through(
                solve,
                arg,
                ExternalRegion::ClientBoundary(callsite.id.0),
                &arg_source,
            );
        }
        if let Some(result) = callsite.result {
            let result_source = if detailed {
                format!("omega:external_call_result:{}", callsite.key)
            } else {
                "omega:external_call_result".to_string()
            };
            self.seed_points_to_region(
                solve,
                result,
                ExternalRegion::ExternalReturn(callsite.id.0),
                &result_source,
            );
        }
    }

    fn apply_vararg_call_effects(&self, solve: &mut Solve, callsite: &pangs_pag::Callsite) {
        let source = if std::env::var_os(knobs::ENV_ANDERSEN_EXPLAIN_NODE).is_some() {
            format!("omega:vararg_call_arg:{}", callsite.key)
        } else {
            "omega:vararg_call_arg".to_string()
        };
        for &arg in callsite.args.iter().skip(callsite.sig.params.len()) {
            self.seed_unknown_store_through(
                solve,
                arg,
                ExternalRegion::ClientBoundary(callsite.id.0),
                &source,
            );
        }
    }

    fn seed_escaped_function_params(&self, solve: &mut Solve) {
        for node in &self.pag.nodes {
            let NodeKind::Object {
                object: ObjectKind::Function,
                key,
                ..
            } = &node.kind
            else {
                continue;
            };
            let class = self.classes.class_of(node.id);
            if !self.classes.esc[class] {
                continue;
            }
            let Some(&func_index) = self.func_index.get(key) else {
                continue;
            };
            for param_index in 0..self.pir.functions[func_index].sig.params.len() {
                if let Some(&param) = self.param_nodes.get(&(func_index, param_index)) {
                    if !self.node_may_carry_pointer(param) {
                        continue;
                    }
                    self.seed_points_to_region(
                        solve,
                        param,
                        ExternalRegion::EscapedFunctionParam(param.0),
                        "omega:escaped_function_param",
                    );
                }
            }
        }
    }

    fn seed_main_entry_params(&self, solve: &mut Solve) {
        if self.build_mode != BuildMode::Executable {
            return;
        }
        let Some(&main_index) = self.func_index.get("main") else {
            return;
        };
        for param_index in 1..self.pir.functions[main_index].sig.params.len() {
            if let Some(&param) = self.param_nodes.get(&(main_index, param_index)) {
                self.seed_points_to_region(
                    solve,
                    param,
                    ExternalRegion::EntryArguments,
                    "omega:main_entry_param",
                );
            }
        }
    }

    fn seed_points_to_region(
        &self,
        solve: &mut Solve,
        node: NodeId,
        region: ExternalRegion,
        source: &str,
    ) {
        if self.in_scope.get(node.0 as usize).copied().unwrap_or(false) {
            let region = solve.region(region);
            solve.add_pts_with_source(node.0, region, Some(source));
        }
    }

    fn seed_unknown_store_through(
        &self,
        solve: &mut Solve,
        node: NodeId,
        region: ExternalRegion,
        source: &str,
    ) {
        if self.in_scope.get(node.0 as usize).copied().unwrap_or(false) {
            let region = solve.region(region);
            solve.add_store(node.0, region, Some(source.to_string()));
        }
    }

    fn scope_profile(&self) -> ScopeProfile {
        let mut profile = ScopeProfile {
            in_scope_nodes: self.in_scope.iter().filter(|&&in_scope| in_scope).count(),
            ..ScopeProfile::default()
        };
        for edge in &self.pag.edges {
            if !self.in_scope[edge.dst.0 as usize] && !self.in_scope[edge.src.0 as usize] {
                continue;
            }
            profile.in_scope_edges += 1;
            match edge.kind {
                EdgeKind::Load => profile.in_scope_loads += 1,
                EdgeKind::Store => profile.in_scope_stores += 1,
                EdgeKind::Gep { .. } => profile.in_scope_geps += 1,
                EdgeKind::Memcpy { .. } => profile.in_scope_memcpys += 1,
                EdgeKind::AddrOf | EdgeKind::Assign => {}
            }
        }
        profile
    }

    fn exact_target_indices(&self, callsite_key: &str) -> Option<Vec<usize>> {
        let targets = self.exact_targets.get(callsite_key)?;
        Some(self.target_indices(targets.iter().map(String::as_str)))
    }

    fn non_confined_target_indices(&self, targets: &[String]) -> Vec<usize> {
        self.target_indices(
            targets
                .iter()
                .map(String::as_str)
                .filter(|target| !self.confined_targets.contains(*target)),
        )
    }

    fn target_indices<'b>(&self, targets: impl Iterator<Item = &'b str>) -> Vec<usize> {
        let mut funcs: Vec<usize> = targets
            .filter_map(|target| self.func_index.get(target).copied())
            .collect();
        funcs.sort_unstable();
        funcs.dedup();
        funcs
    }

    fn emit_indirect_calls(
        &self,
        in_scope_sites: &[usize],
        activated: &HashMap<usize, BTreeSet<usize>>,
        eager_sites: &HashSet<usize>,
        pts: &Solve,
    ) -> Vec<IndirectCallResolution> {
        let in_scope: HashSet<usize> = in_scope_sites.iter().copied().collect();
        let mut out = Vec::new();
        for (idx, cs) in self.pag.callsites.iter().enumerate() {
            if cs.kind != CallKind::Indirect {
                continue;
            }
            let steens = self
                .base
                .indirect_calls
                .iter()
                .find(|r| r.callsite_key == cs.key);
            if in_scope.contains(&idx) {
                let mut targets: Vec<String> = activated
                    .get(&idx)
                    .map(|fs| {
                        fs.iter()
                            .map(|&i| self.pir.functions[i].key.clone())
                            .collect()
                    })
                    .unwrap_or_default();
                targets.sort();
                // M2.0 subset tripwire: a more-exact tier may only narrow. Andersen's
                // per-site targets must be ⊆ the Steensgaard envelope it refined.
                if let Some(steens) = steens {
                    crate::debug_assert_narrows(
                        &cs.key,
                        "andersen",
                        &targets,
                        "steens",
                        &steens.targets,
                    );
                }
                let operand_unknown = cs
                    .operand
                    .and_then(|operand| pts.points_to(operand.0))
                    .is_some_and(|set| {
                        set.iter().any(|&cell| {
                            pts.external_region(cell)
                                .is_some_and(ExternalRegion::may_contain_function_pointer)
                        })
                    });
                let exact = self.exact_targets.contains_key(&cs.key);
                let fallback = !exact && eager_sites.contains(&idx);
                let unknown_callee =
                    steens.map(|r| r.unknown_callee).unwrap_or(false) || operand_unknown;
                out.push(IndirectCallResolution {
                    callsite_key: cs.key.clone(),
                    targets,
                    unknown_callee,
                    fallback,
                });
            } else if let Some(steens) = steens {
                // Uninteresting or oversize partition: keep Steensgaard, tag as fallback.
                out.push(IndirectCallResolution {
                    fallback: true,
                    ..steens.clone()
                });
            }
        }
        out
    }

    fn emit_node_resolutions(&self, pts: &Solve) -> Vec<RefinedNodeResolution> {
        let explain_label = std::env::var(knobs::ENV_ANDERSEN_EXPLAIN_NODE).ok();
        let address_exposed = &self.classes.global_address_exposed;
        let violation_tainted = self.classes.module_violation_tainted;
        let global_index_by_key = self
            .pir
            .globals
            .iter()
            .enumerate()
            .map(|(index, global)| (global.key.as_str(), index))
            .collect::<HashMap<_, _>>();
        let mut out = Vec::new();
        for node in &self.pag.nodes {
            if !node.kind.is_value_like_public() || !self.in_scope[node.id.0 as usize] {
                continue;
            }
            let set = pts.points_to(node.id.0);
            let external = set
                .map(|set| set.iter().any(|cell| pts.is_external(*cell)))
                .unwrap_or(false);
            let external_universal = set
                .map(|set| set.iter().any(|cell| pts.is_universal_external(*cell)))
                .unwrap_or(false);
            let reaches_function_pointer = set
                .map(|set| {
                    set.iter().any(|cell| {
                        pts.external_region(*cell)
                            .is_some_and(ExternalRegion::may_contain_function_pointer)
                            || self
                                .fn_cell_to_index
                                .contains_key(pts.field_base.get(cell).unwrap_or(cell))
                    })
                })
                .unwrap_or(false);
            let mut globals_unfiltered: Vec<String> = set
                .into_iter()
                .flat_map(|set| set.iter())
                .filter_map(|cell| {
                    let root = pts.field_base.get(cell).unwrap_or(cell);
                    self.global_of_cell.get(root)
                })
                .map(|&idx| self.pir.globals[idx].key.clone())
                .collect();
            globals_unfiltered.sort();
            globals_unfiltered.dedup();
            let mut globals = if external_universal || violation_tainted {
                globals_unfiltered.clone()
            } else {
                globals_unfiltered
                    .iter()
                    .filter(|key| {
                        global_index_by_key
                            .get(key.as_str())
                            .is_some_and(|&index| address_exposed[index])
                    })
                    .cloned()
                    .collect()
            };
            globals.sort();
            debug_assert_narrows(
                &node.label,
                "address-exposed-andersen",
                &globals,
                "andersen",
                &globals_unfiltered,
            );
            let globals_unfiltered = if globals != globals_unfiltered {
                globals_unfiltered
            } else {
                Vec::new()
            };
            let external_sources = if external {
                pts.external_sources_for(node.id.0)
                    .map(|sources| sources.iter().cloned().collect())
                    .unwrap_or_else(|| vec!["omega:unknown".to_string()])
            } else {
                Vec::new()
            };
            if explain_label.as_deref() == Some(node.label.as_str()) {
                let mut allocations = set
                    .into_iter()
                    .flat_map(|set| set.iter().copied())
                    .map(|cell| {
                        if let Some(region) = pts.external_region(cell) {
                            return format!("external:{}", region.label());
                        }
                        let root = *pts.field_base.get(&cell).unwrap_or(&cell);
                        if let Some(index) = self.fn_cell_to_index.get(&root) {
                            return format!("function:{}", self.pir.functions[*index].key);
                        }
                        if let Some(index) = self.global_of_cell.get(&root) {
                            return format!("global:{}", self.pir.globals[*index].key);
                        }
                        self.pag
                            .nodes
                            .get(root as usize)
                            .map(|node| node.label.clone())
                            .unwrap_or_else(|| format!("cell:{cell}"))
                    })
                    .collect::<Vec<_>>();
                allocations.sort();
                allocations.dedup();
                let source_count = external_sources.len();
                let source_sample = external_sources
                    .iter()
                    .take(knobs::ANDERSEN_EXTERNAL_SOURCE_LIMIT)
                    .cloned()
                    .collect::<Vec<_>>();
                eprintln!(
                    "pangs andersen explain node={} reaches_function_pointer={} external={} external_universal={} allocations={:?} omega_source_count={} omega_source_sample={:?}",
                    node.label,
                    reaches_function_pointer,
                    external,
                    external_universal,
                    allocations,
                    source_count,
                    source_sample
                );
            }
            out.push(RefinedNodeResolution {
                label: node.label.clone(),
                reaches_function_pointer,
                external,
                external_universal,
                pointee_globals: globals,
                pointee_globals_unfiltered: globals_unfiltered,
                external_sources,
            });
        }
        out
    }

    /// Refined `ptr_points_to` for every in-scope global memory object: the named allocations
    /// (function + global keys) reachable from the object cell *and all its materialized field
    /// cells*. Unioning the fields keeps this object-granular — the same shape cc2json's escape
    /// fixpoint consumes from the Steensgaard fallback — while still benefiting from Andersen's
    /// reduced cross-object over-merge. Ω is not a named allocation, so it is dropped.
    fn emit_global_points_to(&self, pts: &Solve) -> Vec<(String, BTreeSet<String>)> {
        let mut out = Vec::new();
        for node in &self.pag.nodes {
            if !matches!(
                node.kind,
                NodeKind::Object {
                    object: ObjectKind::Global,
                    ..
                }
            ) || !self.in_scope[node.id.0 as usize]
            {
                continue;
            }
            let obj = node.id.0;
            let mut content_cells = vec![obj];
            if let Some(fields) = pts.obj_fields.get(&obj) {
                content_cells.extend(fields.iter().copied());
            }
            let mut allocs = BTreeSet::new();
            for cell in content_cells {
                let Some(set) = pts.points_to(cell) else {
                    continue;
                };
                for &o in set {
                    if pts.is_external(o) {
                        continue;
                    }
                    let root = pts.field_base.get(&o).copied().unwrap_or(o);
                    if let Some(&idx) = self.fn_cell_to_index.get(&root) {
                        allocs.insert(self.pir.functions[idx].key.clone());
                    } else if let Some(&idx) = self.global_of_cell.get(&root) {
                        allocs.insert(self.pir.globals[idx].key.clone());
                    }
                }
            }
            if !allocs.is_empty() {
                out.push((node.label.clone(), allocs));
            }
        }
        out
    }
}

fn omega_seed_source(kind: OmegaSeedKind) -> &'static str {
    match kind {
        OmegaSeedKind::ExportedSymbol => "omega:exported_symbol",
        OmegaSeedKind::ImportedSymbol => "omega:imported_symbol",
        OmegaSeedKind::PtrToInt => "omega:ptrtoint_escape",
        OmegaSeedKind::IntToPtr => "omega:inttoptr",
        OmegaSeedKind::UnknownOperandEscape => "omega:unknown_operand_escape",
        OmegaSeedKind::UnknownResultExternal => "omega:unknown_result",
        OmegaSeedKind::ExternalCallBoundary => "omega:external_call",
        OmegaSeedKind::VarargCallBoundary => "omega:vararg_call",
    }
}

fn andersen_profile_enabled() -> bool {
    std::env::var_os(knobs::ENV_ANDERSEN_PROFILE).is_some()
}

fn copy_scc_min_edges() -> usize {
    std::env::var(knobs::ENV_ANDERSEN_COPY_SCC_MIN_EDGES)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|&value| value > 0)
        .unwrap_or(knobs::ANDERSEN_COPY_SCC_MIN_EDGES)
}

fn andersen_max_steps() -> Option<usize> {
    std::env::var(knobs::ENV_ANDERSEN_MAX_STEPS)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
}

fn andersen_max_resumes() -> usize {
    std::env::var(knobs::ENV_ANDERSEN_MAX_RESUMES)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|&value| value > 0)
        .unwrap_or(knobs::ANDERSEN_MAX_RESUME_ROUNDS)
}

fn partition_profile_enabled() -> bool {
    std::env::var_os(knobs::ENV_PARTITION_PROFILE).is_some()
}

fn partition_profile_top() -> usize {
    std::env::var(knobs::ENV_PARTITION_PROFILE_TOP)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|&value| value > 0)
        .unwrap_or(knobs::PARTITION_PROFILE_TOP)
}

fn admission_profile_enabled() -> bool {
    std::env::var_os(knobs::ENV_ANDERSEN_ADMISSION_PROFILE).is_some()
}

fn admission_profile_root() -> Option<usize> {
    if !admission_profile_enabled() {
        return None;
    }
    std::env::var(knobs::ENV_ANDERSEN_ADMISSION_PROFILE_ROOT)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
}

fn ap_find_const(parent: &[usize], mut x: usize) -> usize {
    while parent[x] != x {
        x = parent[x];
    }
    x
}

fn edge_family(kind: EdgeKind) -> &'static str {
    match kind {
        EdgeKind::AddrOf => "addr_of",
        EdgeKind::Assign => "assign",
        EdgeKind::Load => "load",
        EdgeKind::Store => "store",
        EdgeKind::Gep {
            byte_off: Some(_), ..
        }
        | EdgeKind::Gep { lane: Some(_), .. } => "gep_const",
        EdgeKind::Gep {
            byte_off: None,
            lane: None,
        } => "gep_unknown",
        EdgeKind::Memcpy { .. } => "memcpy",
    }
}

fn omega_seed_kind_label(kind: OmegaSeedKind) -> &'static str {
    match kind {
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

fn format_counts(counts: &BTreeMap<&'static str, usize>) -> String {
    counts
        .iter()
        .map(|(name, count)| format!("{name}={count}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn sample_strings(values: &[String], limit: usize) -> Vec<String> {
    values.iter().take(limit).cloned().collect()
}

fn push_limited_witness(
    witnesses: &mut HashMap<usize, Vec<String>>,
    root: usize,
    witness: String,
    limit: usize,
) {
    let samples = witnesses.entry(root).or_default();
    if samples.len() < limit {
        samples.push(witness);
    }
}

fn edge_witness(kind: &str, edge: &pangs_pag::Edge) -> String {
    let owner = match &edge.owner {
        pangs_pag::Owner::Module => "module".to_string(),
        pangs_pag::Owner::GlobalInit => "global_init".to_string(),
        pangs_pag::Owner::Function(func) => func.clone(),
    };
    let loc = edge
        .loc
        .as_ref()
        .map(|loc| format!("{}:{}:{}", loc.file, loc.line, loc.col))
        .unwrap_or_else(|| "noloc".to_string());
    format!("{}:{}:{}->{}", kind, owner, loc, edge.id.0)
}

/// One stateless inclusion solve over a fixed constraint set.
///
/// A memcpy constraint adds `source_object -> destination_object` copy edges for the
/// Cartesian product of its operands' points-to sets. Remember both frontiers so later
/// growth visits only pairs with at least one newly discovered endpoint.
struct MemcpyJoin {
    dst: Cell,
    src: Cell,
    seen_destinations: HashSet<Cell>,
    seen_sources: HashSet<Cell>,
}

struct MemcpyDelta {
    // These two rectangles partition the newly required pairs without overlapping:
    // `new_destinations × all_sources` and `old_destinations × new_sources`.
    new_destinations: Vec<Cell>,
    old_destinations: Vec<Cell>,
    all_sources: Vec<Cell>,
    new_sources: Vec<Cell>,
}

struct Solve {
    next_field: Cell,
    /// Constraint-graph node representative. This canonicalizes where pointer contents are
    /// stored and propagated; cells appearing *inside* points-to sets remain allocation
    /// identities and are deliberately never canonicalized.
    representative: Vec<Cell>,
    pts: HashMap<Cell, HashSet<Cell>>,
    /// Points-to facts not yet propagated over the source's established copy edges.
    pending_pts: HashMap<Cell, Vec<Cell>>,
    external_sources: HashMap<Cell, BTreeSet<String>>,
    /// External-origin facts not yet propagated over established copy edges.
    pending_external_sources: HashMap<Cell, Vec<String>>,
    regions: HashMap<ExternalRegion, Cell>,
    region_of_cell: HashMap<Cell, ExternalRegion>,
    /// Copy edges which have already received their source's complete points-to set.
    succ: HashMap<Cell, HashSet<Cell>>,
    /// Newly inserted copy edges awaiting one full-set seed. Keeping these separate from
    /// `succ` lets established edges consume only deltas without missing old source facts.
    pending_succ: HashMap<Cell, HashSet<Cell>>,
    /// Complex constraints which have already consumed their owner's complete points-to
    /// set. Established constraints consume only later points-to deltas.
    loads: HashMap<Cell, Vec<Cell>>,
    stores: HashMap<Cell, Vec<(Cell, Option<String>)>>,
    geps: HashMap<Cell, Vec<(FieldLocation, Cell)>>,
    /// Newly inserted complex constraints awaiting one join with their owner's complete
    /// points-to set. Keeping these separate makes the joins semi-naive without losing
    /// constraints registered after propagation has otherwise reached quiescence.
    pending_loads: HashMap<Cell, Vec<Cell>>,
    pending_stores: HashMap<Cell, Vec<(Cell, Option<String>)>>,
    pending_geps: HashMap<Cell, Vec<(FieldLocation, Cell)>>,
    memcpys: Vec<MemcpyJoin>,
    memcpy_by_endpoint: HashMap<Cell, Vec<usize>>,
    fields: HashMap<(Cell, FieldLocation), Cell>,
    /// field cell -> base object cell, so a refined field resolves back to its global.
    field_base: HashMap<Cell, Cell>,
    /// field cell -> normalized location from its root object.
    field_location: HashMap<Cell, FieldLocation>,
    /// Locations certified in the fixed constraint graph. Nested GEPs are canonicalized
    /// only into this finite vocabulary.
    known_locations: HashSet<FieldLocation>,
    /// base object cell -> its materialized constant-offset field cells. Needed to
    /// retroactively connect them when the base later receives a non-constant access (M2.1).
    obj_fields: HashMap<Cell, Vec<Cell>>,
    /// base object cell -> per-base unknown-offset summary cell. Dynamic GEPs over the same
    /// object all route through this cell rather than collapsing every future field to the
    /// whole-object cell.
    unknown_fields: HashMap<Cell, Cell>,
    /// unknown-offset summary cell -> base object cell.
    unknown_field_base: HashMap<Cell, Cell>,
    /// base object cells that have had a direct load/store through the whole object. If the
    /// object also has an unknown-offset summary, the direct cell aliases the summary.
    direct_accessed: HashSet<Cell>,
    worklist: Vec<Cell>,
    queued: HashSet<Cell>,
    profile: bool,
    steps: usize,
    memcpy_pairs_processed: usize,
    copy_fact_pairs_processed: usize,
    load_pairs_processed: usize,
    store_pairs_processed: usize,
    gep_pairs_processed: usize,
    points_to_facts_inserted: usize,
    copy_edges_inserted: usize,
    field_cells_allocated: usize,
    scc_nodes_scanned: usize,
    scc_edges_scanned: usize,
    new_copy_edges_since_scc: usize,
    scc_enabled: bool,
    scc_min_edges: usize,
    scc_passes: usize,
    scc_nodes_collapsed: usize,
    scc_copy_edges_removed: usize,
}

impl Solve {
    fn new(n_base: usize, profile: bool) -> Self {
        Self {
            next_field: n_base as Cell,
            representative: (0..n_base as Cell).collect(),
            pts: HashMap::new(),
            pending_pts: HashMap::new(),
            external_sources: HashMap::new(),
            pending_external_sources: HashMap::new(),
            regions: HashMap::new(),
            region_of_cell: HashMap::new(),
            succ: HashMap::new(),
            pending_succ: HashMap::new(),
            loads: HashMap::new(),
            stores: HashMap::new(),
            geps: HashMap::new(),
            pending_loads: HashMap::new(),
            pending_stores: HashMap::new(),
            pending_geps: HashMap::new(),
            memcpys: Vec::new(),
            memcpy_by_endpoint: HashMap::new(),
            fields: HashMap::new(),
            field_base: HashMap::new(),
            field_location: HashMap::new(),
            known_locations: HashSet::new(),
            obj_fields: HashMap::new(),
            unknown_fields: HashMap::new(),
            unknown_field_base: HashMap::new(),
            direct_accessed: HashSet::new(),
            worklist: Vec::new(),
            queued: HashSet::new(),
            profile,
            steps: 0,
            memcpy_pairs_processed: 0,
            copy_fact_pairs_processed: 0,
            load_pairs_processed: 0,
            store_pairs_processed: 0,
            gep_pairs_processed: 0,
            points_to_facts_inserted: 0,
            copy_edges_inserted: 0,
            field_cells_allocated: 0,
            scc_nodes_scanned: 0,
            scc_edges_scanned: 0,
            new_copy_edges_since_scc: 0,
            scc_enabled: std::env::var_os(knobs::ENV_ANDERSEN_DISABLE_COPY_SCC).is_none(),
            scc_min_edges: copy_scc_min_edges(),
            scc_passes: 0,
            scc_nodes_collapsed: 0,
            scc_copy_edges_removed: 0,
        }
    }

    fn allocate_cell(&mut self) -> Cell {
        let cell = self.next_field;
        self.next_field += 1;
        self.representative.push(cell);
        cell
    }

    fn canonical(&self, cell: Cell) -> Cell {
        self.representative[cell as usize]
    }

    fn points_to(&self, cell: Cell) -> Option<&HashSet<Cell>> {
        self.pts.get(&self.canonical(cell))
    }

    fn external_sources_for(&self, cell: Cell) -> Option<&BTreeSet<String>> {
        self.external_sources.get(&self.canonical(cell))
    }

    fn region(&mut self, region: ExternalRegion) -> Cell {
        if let Some(&cell) = self.regions.get(&region) {
            return cell;
        }
        let cell = self.allocate_cell();
        self.regions.insert(region, cell);
        self.region_of_cell.insert(cell, region);
        // Each region denotes its own foreign objects. Unlike the old absorbing Ω cell,
        // its contents may gain named objects through real store/copy constraints.
        self.add_pts(cell, cell);
        cell
    }

    fn external_region(&self, cell: Cell) -> Option<ExternalRegion> {
        self.region_of_cell.get(&cell).copied()
    }

    fn is_external(&self, cell: Cell) -> bool {
        self.region_of_cell.contains_key(&cell)
    }

    fn is_universal_external(&self, cell: Cell) -> bool {
        self.external_region(cell)
            .is_some_and(ExternalRegion::is_universal)
    }

    fn enqueue(&mut self, cell: Cell) {
        let cell = self.canonical(cell);
        if self.queued.insert(cell) {
            self.worklist.push(cell);
        }
    }

    fn add_pts(&mut self, cell: Cell, obj: Cell) {
        self.add_pts_with_source(cell, obj, None);
    }

    fn add_pts_with_source(&mut self, cell: Cell, obj: Cell, source: Option<&str>) {
        self.add_pts_batch(cell, std::slice::from_ref(&obj));
        if self.is_external(obj) {
            if let Some(source) = source {
                let source = source.to_string();
                self.add_external_sources(cell, std::slice::from_ref(&source));
                // Loads from the region must retain the region's origin even when the
                // pointer used to reach it is not copied into the loaded value.
                self.add_external_sources(obj, std::slice::from_ref(&source));
            }
        }
    }

    fn add_pts_batch(&mut self, cell: Cell, objects: &[Cell]) {
        if objects.is_empty() {
            return;
        }
        let cell = self.canonical(cell);
        let dst = self.pts.entry(cell).or_default();
        let mut added = Vec::new();
        for &object in objects {
            if dst.insert(object) {
                added.push(object);
            }
        }
        if !added.is_empty() {
            self.points_to_facts_inserted =
                self.points_to_facts_inserted.saturating_add(added.len());
            self.pending_pts.entry(cell).or_default().extend(added);
            self.enqueue(cell);
        }
    }

    fn add_external_sources(&mut self, cell: Cell, sources: &[String]) {
        if sources.is_empty() {
            return;
        }
        let cell = self.canonical(cell);
        let dst = self.external_sources.entry(cell).or_default();
        let mut added = Vec::new();
        for source in sources {
            if dst.insert(source.clone()) {
                added.push(source.clone());
            }
        }
        if !added.is_empty() {
            self.pending_external_sources
                .entry(cell)
                .or_default()
                .extend(added);
            self.enqueue(cell);
        }
    }

    fn add_copy(&mut self, from: Cell, to: Cell) {
        let from = self.canonical(from);
        let to = self.canonical(to);
        if from == to {
            return;
        }
        if self
            .succ
            .get(&from)
            .is_some_and(|successors| successors.contains(&to))
            || self
                .pending_succ
                .get(&from)
                .is_some_and(|successors| successors.contains(&to))
        {
            return;
        }
        self.pending_succ.entry(from).or_default().insert(to);
        self.copy_edges_inserted = self.copy_edges_inserted.saturating_add(1);
        self.new_copy_edges_since_scc = self.new_copy_edges_since_scc.saturating_add(1);
        // Even an empty source must run once so the edge becomes established before later
        // source facts are propagated as deltas.
        self.enqueue(from);
    }

    fn add_load(&mut self, base: Cell, destination: Cell) {
        let base = self.canonical(base);
        let established = self
            .loads
            .get(&base)
            .is_some_and(|loads| loads.contains(&destination));
        let pending = self
            .pending_loads
            .get(&base)
            .is_some_and(|loads| loads.contains(&destination));
        if !established && !pending {
            self.pending_loads
                .entry(base)
                .or_default()
                .push(destination);
            self.enqueue(base);
        }
    }

    fn add_store(&mut self, base: Cell, value: Cell, source: Option<String>) {
        let base = self.canonical(base);
        let store = (value, source);
        let established = self
            .stores
            .get(&base)
            .is_some_and(|stores| stores.contains(&store));
        let pending = self
            .pending_stores
            .get(&base)
            .is_some_and(|stores| stores.contains(&store));
        if !established && !pending {
            self.pending_stores.entry(base).or_default().push(store);
            // A late constraint must run even when the owner has no pending points-to delta.
            self.enqueue(base);
        }
    }

    fn add_gep(&mut self, base: Cell, location: FieldLocation, destination: Cell) {
        let base = self.canonical(base);
        let gep = (location, destination);
        let established = self.geps.get(&base).is_some_and(|geps| geps.contains(&gep));
        let pending = self
            .pending_geps
            .get(&base)
            .is_some_and(|geps| geps.contains(&gep));
        if !established && !pending {
            self.pending_geps.entry(base).or_default().push(gep);
            self.enqueue(base);
        }
    }

    fn add_memcpy(&mut self, dst: Cell, src: Cell) {
        let dst = self.canonical(dst);
        let src = self.canonical(src);
        if self
            .memcpys
            .iter()
            .any(|join| self.canonical(join.dst) == dst && self.canonical(join.src) == src)
        {
            return;
        }
        let index = self.memcpys.len();
        self.memcpys.push(MemcpyJoin {
            dst,
            src,
            seen_destinations: HashSet::new(),
            seen_sources: HashSet::new(),
        });
        self.memcpy_by_endpoint.entry(dst).or_default().push(index);
        if src != dst {
            self.memcpy_by_endpoint.entry(src).or_default().push(index);
        }
        self.enqueue(dst);
        self.enqueue(src);
    }

    fn memcpy_delta(&mut self, index: usize) -> MemcpyDelta {
        let join = &self.memcpys[index];
        let destination = self.canonical(join.dst);
        let source = self.canonical(join.src);
        let new_destinations = self
            .pts
            .get(&destination)
            .map(|set| {
                set.iter()
                    .copied()
                    .filter(|object| !join.seen_destinations.contains(object))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let new_sources = self
            .pts
            .get(&source)
            .map(|set| {
                set.iter()
                    .copied()
                    .filter(|object| !join.seen_sources.contains(object))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let all_sources = if new_destinations.is_empty() {
            Vec::new()
        } else {
            self.pts
                .get(&source)
                .map(|set| set.iter().copied().collect())
                .unwrap_or_default()
        };

        let join = &mut self.memcpys[index];
        let old_destinations = if new_sources.is_empty() {
            Vec::new()
        } else {
            join.seen_destinations.iter().copied().collect()
        };
        join.seen_destinations
            .extend(new_destinations.iter().copied());
        join.seen_sources.extend(new_sources.iter().copied());

        MemcpyDelta {
            new_destinations,
            old_destinations,
            all_sources,
            new_sources,
        }
    }

    /// Field/subobject identity for `base + location`.
    ///
    /// A **constant** offset gets its own subobject cell, giving field sensitivity. A
    /// **non-constant** offset (`None`) uses a per-root unknown-offset summary cell. The
    /// summary aliases every materialized constant field for that root, so a dynamic-index
    /// store is visible to constant-field loads (and vice versa), but we avoid routing all
    /// future fields through the whole-object cell. This keeps the M2.1 soundness property
    /// while reducing broad cross-field/root pollution.
    fn field_of(&mut self, base: Cell, location: FieldLocation) -> Cell {
        if self.is_external(base) {
            return base;
        }
        if self.unknown_field_base.contains_key(&base) {
            return base;
        }
        if let Some(&root) = self.field_base.get(&base) {
            // Keep nested GEPs finite by canonicalizing them back to a root-relative location
            // rather than creating field-of-field chains. We only materialize combined
            // locations that occur in the fixed graph's finite vocabulary.
            let base_location = self
                .field_location
                .get(&base)
                .copied()
                .unwrap_or(FieldLocation::Unknown);
            let combined = base_location.add(location);
            if combined == base_location {
                return base;
            }
            return if self.known_locations.contains(&combined) {
                self.field_of(root, combined)
            } else {
                self.unknown_field_of(root)
            };
        }
        if let Some(&cell) = self.fields.get(&(base, location)) {
            return cell;
        }
        let cell = self.allocate_cell();
        self.field_cells_allocated = self.field_cells_allocated.saturating_add(1);
        self.fields.insert((base, location), cell);
        self.field_base.insert(cell, base);
        self.field_location.insert(cell, location);
        let existing = self.obj_fields.entry(base).or_default().clone();
        self.obj_fields.entry(base).or_default().push(cell);
        if location == FieldLocation::Unknown {
            self.unknown_fields.insert(base, cell);
            self.unknown_field_base.insert(cell, base);
        }
        for field in existing {
            let candidate = self
                .field_location
                .get(&field)
                .copied()
                .unwrap_or(FieldLocation::Unknown);
            if location.may_alias(candidate) {
                self.add_copy(cell, field);
                self.add_copy(field, cell);
            }
        }
        if location == FieldLocation::Unknown && self.direct_accessed.contains(&base) {
            self.add_copy(base, cell);
            self.add_copy(cell, base);
        }
        cell
    }

    fn unknown_field_of(&mut self, base: Cell) -> Cell {
        if let Some(&cell) = self.unknown_fields.get(&base) {
            return cell;
        }
        self.field_of(base, FieldLocation::Unknown)
    }

    fn note_direct_access(&mut self, base: Cell) {
        if self.is_external(base)
            || self.field_base.contains_key(&base)
            || self.unknown_field_base.contains_key(&base)
        {
            return;
        }
        if !self.direct_accessed.insert(base) {
            return;
        }
        if let Some(&summary) = self.unknown_fields.get(&base) {
            self.add_copy(base, summary);
            self.add_copy(summary, base);
        }
    }

    fn should_collapse_copy_sccs(&self) -> bool {
        let edges = self.copy_edges();
        self.scc_enabled
            && edges >= self.scc_min_edges
            && self.new_copy_edges_since_scc >= self.scc_min_edges.max(edges / 2)
    }

    /// Collapse every non-trivial SCC in the current copy graph.
    ///
    /// Mutual inclusion makes the members' pointer contents equal at the least fixed point,
    /// so eagerly replacing them with one shared variable is exact. Allocation identities
    /// stored in the points-to relation are not rewritten: two globals whose *contents* are
    /// mutually included do not thereby become the same concrete object.
    fn collapse_copy_sccs(&mut self) {
        self.scc_passes = self.scc_passes.saturating_add(1);
        self.new_copy_edges_since_scc = 0;

        let cell_count = self.next_field as usize;
        let mut adjacency = vec![Vec::<Cell>::new(); cell_count];
        for (&source, successors) in self.succ.iter().chain(&self.pending_succ) {
            adjacency[source as usize].extend(successors.iter().copied());
        }
        for successors in &mut adjacency {
            successors.sort_unstable();
            successors.dedup();
        }
        let old_edge_count = adjacency.iter().map(Vec::len).sum::<usize>();
        self.scc_nodes_scanned = self.scc_nodes_scanned.saturating_add(cell_count);
        self.scc_edges_scanned = self
            .scc_edges_scanned
            .saturating_add(old_edge_count.saturating_mul(2));

        // Iterative Kosaraju keeps stack usage independent of corpus size. Cells are dense
        // integer IDs, so vector-indexed graph state is substantially cheaper than hashing.
        let mut reverse = vec![Vec::<Cell>::new(); cell_count];
        let mut active = vec![false; cell_count];
        for (source, successors) in adjacency.iter().enumerate() {
            if !successors.is_empty() {
                active[source] = true;
            }
            for &destination in successors {
                active[destination as usize] = true;
                reverse[destination as usize].push(source as Cell);
            }
        }
        let mut seen = vec![false; cell_count];
        let mut finish_order = Vec::new();
        for root in 0..cell_count {
            if !active[root] || seen[root] {
                continue;
            }
            seen[root] = true;
            let mut dfs = vec![(root as Cell, 0usize)];
            while let Some((node, next_successor)) = dfs.last_mut() {
                if *next_successor < adjacency[*node as usize].len() {
                    let successor = adjacency[*node as usize][*next_successor];
                    *next_successor += 1;
                    if !seen[successor as usize] {
                        seen[successor as usize] = true;
                        dfs.push((successor, 0));
                    }
                } else {
                    let (node, _) = dfs.pop().expect("non-empty SCC DFS stack");
                    finish_order.push(node);
                }
            }
        }

        let mut component_of = vec![usize::MAX; cell_count];
        let mut components = Vec::<Vec<Cell>>::new();
        while let Some(root) = finish_order.pop() {
            if component_of[root as usize] != usize::MAX {
                continue;
            }
            let component = components.len();
            component_of[root as usize] = component;
            let mut pending = vec![root];
            let mut members = Vec::new();
            while let Some(node) = pending.pop() {
                members.push(node);
                for &predecessor in &reverse[node as usize] {
                    if component_of[predecessor as usize] == usize::MAX {
                        component_of[predecessor as usize] = component;
                        pending.push(predecessor);
                    }
                }
            }
            components.push(members);
        }

        let mut collapsed_to: Vec<Cell> = (0..cell_count as Cell).collect();
        let mut collapsed_nodes = 0usize;
        let mut largest_scc = 0usize;
        for members in &components {
            if members.len() <= 1 {
                continue;
            }
            let representative = *members.iter().min().expect("non-empty SCC");
            for &member in members {
                collapsed_to[member as usize] = representative;
            }
            collapsed_nodes = collapsed_nodes.saturating_add(members.len() - 1);
            largest_scc = largest_scc.max(members.len());
        }
        if collapsed_nodes == 0 {
            if self.profile {
                eprintln!(
                    "pangs andersen profile: scc pass={} copy_edges={} collapsed_nodes=0",
                    self.scc_passes, old_edge_count
                );
            }
            return;
        }

        for representative in &mut self.representative {
            *representative = collapsed_to[*representative as usize];
        }
        let representatives = self.representative.clone();

        let mut merged_pts = HashMap::<Cell, HashSet<Cell>>::new();
        for (cell, objects) in std::mem::take(&mut self.pts) {
            merged_pts
                .entry(representatives[cell as usize])
                .or_default()
                .extend(objects);
        }
        self.pts = merged_pts;

        let mut merged_external = HashMap::<Cell, BTreeSet<String>>::new();
        for (cell, sources) in std::mem::take(&mut self.external_sources) {
            merged_external
                .entry(representatives[cell as usize])
                .or_default()
                .extend(sources);
        }
        self.external_sources = merged_external;

        let mut condensed_succ = HashMap::<Cell, HashSet<Cell>>::new();
        for (source, successors) in adjacency.into_iter().enumerate() {
            let source = representatives[source];
            for destination in successors {
                let destination = representatives[destination as usize];
                if source != destination {
                    condensed_succ
                        .entry(source)
                        .or_default()
                        .insert(destination);
                }
            }
        }
        let new_edge_count = condensed_succ.values().map(HashSet::len).sum::<usize>();
        self.succ = condensed_succ;
        self.pending_succ.clear();

        // Collapsing variables can combine constraints from one old member with pointees
        // from another. Treat every merged complex constraint as new so the complete
        // representative points-to set is joined once; subsequent growth returns to delta
        // propagation.
        let mut replay_loads = HashMap::<Cell, Vec<Cell>>::new();
        for (cell, loads) in std::mem::take(&mut self.loads)
            .into_iter()
            .chain(std::mem::take(&mut self.pending_loads))
        {
            replay_loads
                .entry(representatives[cell as usize])
                .or_default()
                .extend(loads);
        }
        for loads in replay_loads.values_mut() {
            loads.sort_unstable();
            loads.dedup();
        }
        self.pending_loads = replay_loads;

        let mut replay_stores = HashMap::<Cell, Vec<(Cell, Option<String>)>>::new();
        for (cell, stores) in std::mem::take(&mut self.stores)
            .into_iter()
            .chain(std::mem::take(&mut self.pending_stores))
        {
            replay_stores
                .entry(representatives[cell as usize])
                .or_default()
                .extend(stores);
        }
        for stores in replay_stores.values_mut() {
            stores.sort_unstable();
            stores.dedup();
        }
        self.pending_stores = replay_stores;

        let mut replay_geps = HashMap::<Cell, Vec<(FieldLocation, Cell)>>::new();
        for (cell, geps) in std::mem::take(&mut self.geps)
            .into_iter()
            .chain(std::mem::take(&mut self.pending_geps))
        {
            replay_geps
                .entry(representatives[cell as usize])
                .or_default()
                .extend(geps);
        }
        for geps in replay_geps.values_mut() {
            geps.sort_unstable();
            geps.dedup();
        }
        self.pending_geps = replay_geps;

        let mut merged_memcpy_endpoints = HashMap::<Cell, Vec<usize>>::new();
        for (cell, joins) in std::mem::take(&mut self.memcpy_by_endpoint) {
            merged_memcpy_endpoints
                .entry(representatives[cell as usize])
                .or_default()
                .extend(joins);
        }
        for joins in merged_memcpy_endpoints.values_mut() {
            joins.sort_unstable();
            joins.dedup();
        }
        self.memcpy_by_endpoint = merged_memcpy_endpoints;

        // Re-seed every condensed variable from its complete state. This costs one
        // propagation over the much smaller condensation graph and also re-evaluates
        // complex constraints whose members just gained facts from one another.
        self.pending_pts = self
            .pts
            .iter()
            .map(|(&cell, objects)| (cell, objects.iter().copied().collect()))
            .collect();
        self.pending_external_sources = self
            .external_sources
            .iter()
            .map(|(&cell, sources)| (cell, sources.iter().cloned().collect()))
            .collect();
        self.worklist.clear();
        self.queued.clear();
        let mut reseed = self.pending_pts.keys().copied().collect::<HashSet<_>>();
        reseed.extend(self.pending_external_sources.keys().copied());
        reseed.extend(self.pending_loads.keys().copied());
        reseed.extend(self.pending_stores.keys().copied());
        reseed.extend(self.pending_geps.keys().copied());
        for cell in reseed {
            self.enqueue(cell);
        }

        self.scc_nodes_collapsed = self.scc_nodes_collapsed.saturating_add(collapsed_nodes);
        let removed_edges = old_edge_count.saturating_sub(new_edge_count);
        self.scc_copy_edges_removed = self.scc_copy_edges_removed.saturating_add(removed_edges);
        if self.profile {
            eprintln!(
                "pangs andersen profile: scc pass={} copy_edges_before={} copy_edges_after={} collapsed_nodes={} largest_scc={} removed_edges={}",
                self.scc_passes,
                old_edge_count,
                new_edge_count,
                collapsed_nodes,
                largest_scc,
                removed_edges
            );
        }
    }

    fn pts_facts(&self) -> usize {
        self.pts.values().map(HashSet::len).sum()
    }

    fn copy_edges(&self) -> usize {
        self.succ.values().map(HashSet::len).sum::<usize>()
            + self.pending_succ.values().map(HashSet::len).sum::<usize>()
    }

    fn copy_sources(&self) -> usize {
        self.succ.len()
            + self
                .pending_succ
                .keys()
                .filter(|source| !self.succ.contains_key(source))
                .count()
    }

    fn maybe_report_progress(&self) {
        if self.profile && self.steps % knobs::ANDERSEN_PROFILE_STEP_INTERVAL == 0 {
            eprintln!(
                "pangs andersen profile: solve progress steps={} worklist={} queued={} pts_entries={} pts_facts={} copy_sources={} copy_edges={} fields={} unknown_fields={} memcpy_pairs_processed={} copy_fact_pairs_processed={} load_pairs_processed={} store_pairs_processed={} gep_pairs_processed={} scc_passes={} scc_nodes_collapsed={} scc_copy_edges_removed={} new_copy_edges_since_scc={}",
                self.steps,
                self.worklist.len(),
                self.queued.len(),
                self.pts.len(),
                self.pts_facts(),
                self.copy_sources(),
                self.copy_edges(),
                self.fields.len(),
                self.unknown_fields.len(),
                self.memcpy_pairs_processed,
                self.copy_fact_pairs_processed,
                self.load_pairs_processed,
                self.store_pairs_processed,
                self.gep_pairs_processed,
                self.scc_passes,
                self.scc_nodes_collapsed,
                self.scc_copy_edges_removed,
                self.new_copy_edges_since_scc
            );
        }
    }

    fn report_large_product(&self, kind: &str, base: Cell, lhs: usize, rhs: usize) {
        if self.profile && lhs.saturating_mul(rhs) >= knobs::ANDERSEN_PROFILE_LARGE_PRODUCT {
            eprintln!(
                "pangs andersen profile: large {} expansion base={} lhs={} rhs={} product={} steps={} pts_facts={} copy_edges={}",
                kind,
                base,
                lhs,
                rhs,
                lhs.saturating_mul(rhs),
                self.steps,
                self.pts_facts(),
                self.copy_edges()
            );
        }
    }

    fn run(&mut self) {
        assert!(self.run_with_limit(None));
    }

    /// Resume propagation. The cumulative limit is checked against `steps`, so repeated
    /// resumes share one budget rather than resetting it at each discovery boundary.
    fn run_with_limit(&mut self, max_steps: Option<usize>) -> bool {
        while let Some(n) = self.worklist.pop() {
            if max_steps.is_some_and(|limit| self.steps >= limit) {
                self.worklist.push(n);
                return false;
            }
            self.steps += 1;
            self.maybe_report_progress();
            self.queued.remove(&n);
            let pts_delta = self.pending_pts.remove(&n).unwrap_or_default();
            let external_delta = self.pending_external_sources.remove(&n).unwrap_or_default();
            let new_successors = self.pending_succ.remove(&n).unwrap_or_default();

            // Established copy edges consume only facts discovered since `n` last ran.
            if let Some(successors) = self.succ.get(&n).cloned() {
                self.copy_fact_pairs_processed = self
                    .copy_fact_pairs_processed
                    .saturating_add(pts_delta.len().saturating_mul(successors.len()));
                for successor in successors {
                    self.add_pts_batch(successor, &pts_delta);
                    self.add_external_sources(successor, &external_delta);
                }
            }

            // A new edge predates none of the source's facts, so seed it from the complete
            // set once and only then promote it to the established successor relation.
            if !new_successors.is_empty() {
                let all_pts = self
                    .pts
                    .get(&n)
                    .map(|set| set.iter().copied().collect::<Vec<_>>())
                    .unwrap_or_default();
                let all_external_sources = self
                    .external_sources
                    .get(&n)
                    .map(|set| set.iter().cloned().collect::<Vec<_>>())
                    .unwrap_or_default();
                self.copy_fact_pairs_processed = self
                    .copy_fact_pairs_processed
                    .saturating_add(all_pts.len().saturating_mul(new_successors.len()));
                for &successor in &new_successors {
                    self.add_pts_batch(successor, &all_pts);
                    self.add_external_sources(successor, &all_external_sources);
                }
                self.succ.entry(n).or_default().extend(new_successors);
            }

            // n as a load base: p = *n  ⇒  pts(o) ⊆ pts(p)  for o ∈ pts(n)
            if let Some(ps) = self.loads.get(&n).cloned() {
                self.report_large_product("load", n, ps.len(), pts_delta.len());
                self.load_pairs_processed = self
                    .load_pairs_processed
                    .saturating_add(ps.len().saturating_mul(pts_delta.len()));
                for p in ps {
                    for &o in &pts_delta {
                        self.note_direct_access(o);
                        self.add_copy(o, p);
                    }
                }
            }
            if let Some(ps) = self.pending_loads.remove(&n) {
                let all_pts = self
                    .pts
                    .get(&n)
                    .map(|set| set.iter().copied().collect::<Vec<_>>())
                    .unwrap_or_default();
                self.report_large_product("new-load", n, ps.len(), all_pts.len());
                self.load_pairs_processed = self
                    .load_pairs_processed
                    .saturating_add(ps.len().saturating_mul(all_pts.len()));
                for &p in &ps {
                    for &o in &all_pts {
                        self.note_direct_access(o);
                        self.add_copy(o, p);
                    }
                }
                self.loads.entry(n).or_default().extend(ps);
            }
            // n as a store base: *n = q  ⇒  pts(q) ⊆ pts(o)  for o ∈ pts(n)
            if let Some(qs) = self.stores.get(&n).cloned() {
                self.report_large_product("store", n, qs.len(), pts_delta.len());
                self.store_pairs_processed = self
                    .store_pairs_processed
                    .saturating_add(qs.len().saturating_mul(pts_delta.len()));
                for (q, omega_source) in qs {
                    for &o in &pts_delta {
                        self.note_direct_access(o);
                        if self.is_external(q) {
                            self.add_pts_with_source(o, q, omega_source.as_deref());
                        } else {
                            self.add_copy(q, o);
                        }
                    }
                }
            }
            if let Some(qs) = self.pending_stores.remove(&n) {
                let all_pts = self
                    .pts
                    .get(&n)
                    .map(|set| set.iter().copied().collect::<Vec<_>>())
                    .unwrap_or_default();
                self.report_large_product("new-store", n, qs.len(), all_pts.len());
                self.store_pairs_processed = self
                    .store_pairs_processed
                    .saturating_add(qs.len().saturating_mul(all_pts.len()));
                for (q, omega_source) in &qs {
                    for &o in &all_pts {
                        self.note_direct_access(o);
                        if self.is_external(*q) {
                            self.add_pts_with_source(o, *q, omega_source.as_deref());
                        } else {
                            self.add_copy(*q, o);
                        }
                    }
                }
                self.stores.entry(n).or_default().extend(qs);
            }
            // n as a gep base: p = n + off  ⇒  field(o, off) ∈ pts(p)  for o ∈ pts(n)
            if let Some(gs) = self.geps.get(&n).cloned() {
                self.report_large_product("gep", n, gs.len(), pts_delta.len());
                self.gep_pairs_processed = self
                    .gep_pairs_processed
                    .saturating_add(gs.len().saturating_mul(pts_delta.len()));
                for (off, p) in gs {
                    for &o in &pts_delta {
                        let f = self.field_of(o, off);
                        self.add_pts(p, f);
                    }
                }
            }
            if let Some(gs) = self.pending_geps.remove(&n) {
                let all_pts = self
                    .pts
                    .get(&n)
                    .map(|set| set.iter().copied().collect::<Vec<_>>())
                    .unwrap_or_default();
                self.report_large_product("new-gep", n, gs.len(), all_pts.len());
                self.gep_pairs_processed = self
                    .gep_pairs_processed
                    .saturating_add(gs.len().saturating_mul(all_pts.len()));
                for &(off, p) in &gs {
                    for &o in &all_pts {
                        let f = self.field_of(o, off);
                        self.add_pts(p, f);
                    }
                }
                self.geps.entry(n).or_default().extend(gs);
            }
            // n in a memcpy: contents-copy between pointed-to objects (field-insensitive).
            if let Some(relevant) = self.memcpy_by_endpoint.get(&n).cloned() {
                for index in relevant {
                    let delta = self.memcpy_delta(index);
                    self.report_large_product(
                        "memcpy",
                        n,
                        delta.new_destinations.len(),
                        delta.all_sources.len(),
                    );
                    self.memcpy_pairs_processed = self.memcpy_pairs_processed.saturating_add(
                        delta
                            .new_destinations
                            .len()
                            .saturating_mul(delta.all_sources.len()),
                    );
                    for &od in &delta.new_destinations {
                        self.note_direct_access(od);
                        for &os in &delta.all_sources {
                            self.note_direct_access(os);
                            self.add_copy(os, od);
                        }
                    }
                    self.report_large_product(
                        "memcpy",
                        n,
                        delta.old_destinations.len(),
                        delta.new_sources.len(),
                    );
                    self.memcpy_pairs_processed = self.memcpy_pairs_processed.saturating_add(
                        delta
                            .old_destinations
                            .len()
                            .saturating_mul(delta.new_sources.len()),
                    );
                    for &od in &delta.old_destinations {
                        self.note_direct_access(od);
                        for &os in &delta.new_sources {
                            self.note_direct_access(os);
                            self.add_copy(os, od);
                        }
                    }
                }
            }
            if self.should_collapse_copy_sccs() {
                self.collapse_copy_sccs();
            }
        }
        true
    }
}

// `NodeKind::is_value_like` is private in pangs-pag; mirror it here.
trait ValueLike {
    fn is_value_like_public(&self) -> bool;
}
impl ValueLike for NodeKind {
    fn is_value_like_public(&self) -> bool {
        matches!(
            self,
            NodeKind::Value { .. } | NodeKind::Param { .. } | NodeKind::Return { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashSet};
    use std::path::Path;

    use pangs_pag::{BuildMode, Pag, PagOpts};
    use pangs_pir::Pir;

    use super::{
        finish_andersen_controlled, solve_andersen, solve_andersen_with_overrides,
        AndersenControls, ExternalRegion, Refiner, Solve,
    };
    use crate::{solve_steensgaard, FieldLocation, PointsToMaterialization};

    fn fixture(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/synthetic/m1_4b")
            .join(name)
    }

    fn load(name: &str) -> (Pir, Pag) {
        let pir = Pir::from_path(fixture(name)).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        (pir, pag)
    }

    fn load_m1_4(name: &str) -> (Pir, Pag) {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/synthetic/m1_4")
            .join(name);
        let pir = Pir::from_path(path).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        (pir, pag)
    }

    fn load_m2_1(name: &str) -> (Pir, Pag) {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/synthetic/m2_1")
            .join(name);
        let pir = Pir::from_path(path).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        (pir, pag)
    }

    fn load_m2_3(name: &str) -> (Pir, Pag) {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/synthetic/m2_3")
            .join(name);
        let pir = Pir::from_path(path).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        (pir, pag)
    }

    fn load_m3_2(name: &str) -> (Pir, Pag) {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/synthetic/m3_2")
            .join(name);
        let pir = Pir::from_path(path).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        (pir, pag)
    }

    fn load_m5(name: &str) -> (Pir, Pag) {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/synthetic/m5")
            .join(name);
        let pir = Pir::from_path(path).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        (pir, pag)
    }

    #[test]
    fn m2_1_dynamic_store_is_seen_by_constant_load() {
        // The (o,⊤) generalization: a value written through a non-constant-offset GEP must
        // reach a constant-offset load of the same object. Before M2.1, andersen dropped it.
        let (pir, pag) = load_m2_1("dynamic_store_const_load.pir.json");
        let steens = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert_eq!(steens.indirect_calls[0].targets, vec!["alpha".to_string()]);
        let andersen = solve_andersen(&pir, &pag, BuildMode::Library, 1_000_000);
        assert_eq!(
            andersen.indirect_calls[0].targets,
            vec!["alpha".to_string()],
            "M2.1: dynamic-offset store must be visible to a constant-offset load"
        );
    }

    #[test]
    fn m2_1_constant_store_is_seen_by_dynamic_load() {
        // Reverse direction: a constant-offset store must reach a non-constant (⊤) load.
        let (pir, pag) = load_m2_1("const_store_dynamic_load.pir.json");
        let steens = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert_eq!(steens.indirect_calls[0].targets, vec!["beta".to_string()]);
        let andersen = solve_andersen(&pir, &pag, BuildMode::Library, 1_000_000);
        assert_eq!(
            andersen.indirect_calls[0].targets,
            vec!["beta".to_string()],
            "M2.1: constant-offset store must be visible to a non-constant-offset load"
        );
    }

    #[test]
    fn exact_overrides_survive_confined_subtraction_while_candidate_sites_narrow() {
        let (pir, pag) = load_m2_3("confined_subtraction.pir.json");
        let mut exact = BTreeMap::new();
        exact.insert("driver@!noloc#0".to_string(), vec!["cb".to_string()]);
        let confined = BTreeSet::from(["cb".to_string()]);

        let andersen = solve_andersen_with_overrides(
            &pir,
            &pag,
            BuildMode::Library,
            1_000_000,
            &exact,
            &confined,
        );
        let exact_site = andersen
            .indirect_calls
            .iter()
            .find(|r| r.callsite_key == "driver@!noloc#0")
            .unwrap();
        assert_eq!(exact_site.targets, vec!["cb".to_string()]);

        let candidate_site = andersen
            .indirect_calls
            .iter()
            .find(|r| r.callsite_key == "driver@!noloc#1")
            .unwrap();
        assert_eq!(candidate_site.targets, vec!["other".to_string()]);
    }

    #[test]
    fn exhaustion_at_every_joint_phase_reverts_every_output_but_exact_calls() {
        let (pir, pag) = load_m2_3("confined_subtraction.pir.json");
        let mut exact = BTreeMap::new();
        exact.insert("driver@!noloc#0".to_string(), vec!["cb".to_string()]);
        let confined = BTreeSet::from(["cb".to_string()]);
        let (base, classes) = crate::solve_steensgaard_classes_materialized(
            &pir,
            &pag,
            BuildMode::Library,
            PointsToMaterialization::GlobalObjects,
        );
        let base_nodes = format!("{:?}", base.nodes);
        let base_points_to = base.node_points_to.clone();

        for (injection, reason) in [
            ("propagation", "injected_during_propagation"),
            ("discovery", "injected_after_discovery"),
            ("activation", "injected_after_activation"),
        ] {
            let result = finish_andersen_controlled(
                &pir,
                &pag,
                &classes,
                base.clone(),
                BuildMode::Library,
                1_000_000,
                &exact,
                &confined,
                true,
                AndersenControls {
                    inject_exhaustion: Some(injection.to_string()),
                    ..AndersenControls::default()
                },
            );

            assert!(!result.metrics.andersen_complete);
            assert_eq!(
                result.metrics.andersen_exhaustion_reason.as_deref(),
                Some(reason)
            );
            assert_eq!(format!("{:?}", result.nodes), base_nodes);
            assert_eq!(result.node_points_to, base_points_to);
            let exact_site = result
                .indirect_calls
                .iter()
                .find(|row| row.callsite_key == "driver@!noloc#0")
                .unwrap();
            assert_eq!(exact_site.targets, vec!["cb".to_string()]);
            assert!(!exact_site.fallback);
            assert!(result
                .indirect_calls
                .iter()
                .filter(|row| row.callsite_key != "driver@!noloc#0")
                .all(|row| row.fallback));
        }
    }

    #[test]
    fn a_late_store_replays_the_owner_complete_points_to_set() {
        let mut solve = Solve::new(4, false);
        solve.add_pts(0, 1);
        solve.run();

        let external = solve.region(ExternalRegion::ClientBoundary(7));
        solve.add_store(0, external, Some("late-boundary".to_string()));
        solve.run();

        assert!(solve.points_to(1).unwrap().contains(&external));
        assert!(solve
            .external_sources_for(1)
            .unwrap()
            .contains("late-boundary"));
    }

    #[test]
    fn complex_constraints_join_only_new_pointees_and_replay_late_constraints() {
        let mut loads = Solve::new(12, false);
        loads.add_pts(1, 7);
        loads.add_pts(2, 8);
        loads.add_pts(3, 9);
        loads.add_pts(0, 1);
        loads.add_pts(0, 2);
        loads.add_load(0, 5);
        loads.run();
        assert_eq!(loads.load_pairs_processed, 2);
        assert_eq!(loads.points_to(5).unwrap(), &HashSet::from([7, 8]));

        loads.add_pts(0, 3);
        loads.run();
        assert_eq!(loads.load_pairs_processed, 3);
        assert_eq!(loads.points_to(5).unwrap(), &HashSet::from([7, 8, 9]));
        loads.run();
        assert_eq!(loads.load_pairs_processed, 3);

        loads.add_load(0, 6);
        loads.run();
        assert_eq!(loads.load_pairs_processed, 6);
        assert_eq!(loads.points_to(6).unwrap(), &HashSet::from([7, 8, 9]));

        let mut stores = Solve::new(12, false);
        stores.add_pts(4, 10);
        stores.add_pts(0, 1);
        stores.add_pts(0, 2);
        stores.add_store(0, 4, None);
        stores.run();
        assert_eq!(stores.store_pairs_processed, 2);
        assert!(stores.points_to(1).unwrap().contains(&10));
        assert!(stores.points_to(2).unwrap().contains(&10));

        stores.add_pts(0, 3);
        stores.run();
        assert_eq!(stores.store_pairs_processed, 3);
        assert!(stores.points_to(3).unwrap().contains(&10));
        stores.run();
        assert_eq!(stores.store_pairs_processed, 3);

        stores.add_store(0, 5, None);
        stores.run();
        assert_eq!(stores.store_pairs_processed, 6);

        let mut geps = Solve::new(12, false);
        geps.known_locations.insert(FieldLocation::Exact(4));
        geps.add_pts(0, 1);
        geps.add_pts(0, 2);
        geps.add_gep(0, FieldLocation::Exact(4), 5);
        geps.run();
        assert_eq!(geps.gep_pairs_processed, 2);
        assert_eq!(geps.points_to(5).unwrap().len(), 2);

        geps.add_pts(0, 3);
        geps.run();
        assert_eq!(geps.gep_pairs_processed, 3);
        assert_eq!(geps.points_to(5).unwrap().len(), 3);
        geps.run();
        assert_eq!(geps.gep_pairs_processed, 3);

        geps.add_gep(0, FieldLocation::Exact(4), 6);
        geps.run();
        assert_eq!(geps.gep_pairs_processed, 6);
        assert_eq!(geps.points_to(6).unwrap().len(), 3);
    }

    #[test]
    fn forged_indirect_operand_retains_unknown_fallback_provenance() {
        let (pir, pag) = load_m1_4("inttoptr_unknown_call.pir.json");
        let result = solve_andersen(&pir, &pag, BuildMode::Library, 1_000_000);
        let call = &result.indirect_calls[0];
        assert!(call.targets.is_empty());
        assert!(call.unknown_callee);
        assert!(call.fallback);
        assert!(result.metrics.andersen_complete);
    }

    #[test]
    fn propagation_step_budget_is_cumulative_across_resumes() {
        let mut solve = Solve::new(4, false);
        solve.add_pts(0, 1);
        assert!(solve.run_with_limit(Some(1)));
        assert_eq!(solve.steps, 1);

        solve.add_copy(0, 2);
        assert!(!solve.run_with_limit(Some(1)));
        assert_eq!(solve.steps, 1);
        assert!(solve.run_with_limit(Some(3)));
        assert_eq!(solve.steps, 3);
    }

    #[test]
    fn andersen_distinguishes_struct_fn_ptr_fields() {
        let (pir, pag) = load("field_sensitive_fnptr.pir.json");

        // Field-aware Steensgaard already keeps independently rooted struct fields apart.
        let steens = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert_eq!(steens.indirect_calls.len(), 1);
        assert_eq!(steens.indirect_calls[0].targets, vec!["f0".to_string()]);

        // Andersen agrees while retaining its distinct refinement provenance.
        let andersen = solve_andersen(&pir, &pag, BuildMode::Library, 1_000_000);
        assert_eq!(andersen.indirect_calls.len(), 1);
        assert_eq!(andersen.indirect_calls[0].targets, vec!["f0".to_string()]);
        assert!(!andersen.indirect_calls[0].fallback);
        // Narrowing ledger: andersen ⊆ steens.
        assert!(andersen.indirect_calls[0]
            .targets
            .iter()
            .all(|t| steens.indirect_calls[0].targets.contains(t)));
        assert!(andersen.metrics.rounds >= 1);
    }

    #[test]
    fn dynamic_array_indices_preserve_struct_field_lanes() {
        let (pir, pag) = load("array_lane_fnptr.pir.json");

        // Access widths prove that the affine callback and data lanes cannot overlap, so both
        // Steensgaard and Andersen retain the distinction.
        let steens = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert_eq!(steens.indirect_calls.len(), 1);
        assert_eq!(steens.indirect_calls[0].targets, vec!["f0".to_string()]);

        let andersen = solve_andersen(&pir, &pag, BuildMode::Library, 1_000_000);
        assert_eq!(andersen.indirect_calls.len(), 1);
        assert_eq!(andersen.indirect_calls[0].targets, vec!["f0".to_string()]);
        assert!(!andersen.indirect_calls[0].fallback);
    }

    #[test]
    fn andersen_refines_function_pointer_reachability_for_data_fields() {
        let (pir, pag) = load("field_sensitive_data_vs_fnptr.pir.json");

        // Field-aware Steensgaard keeps the aggregate's callback and data fields separate.
        let steens = solve_steensgaard(&pir, &pag, BuildMode::Library);
        let data = "val:setup:%data";
        assert!(!steens.nodes[data].reaches_function_pointer);
        assert_eq!(
            steens.nodes[data].pointee_globals,
            vec!["@Data".to_string()]
        );

        // Andersen retains the same precise allocation and function-pointer facts.
        let andersen = solve_andersen(&pir, &pag, BuildMode::Library, 1_000_000);
        assert!(!andersen.nodes[data].reaches_function_pointer);
        assert_eq!(
            andersen.nodes[data].pointee_globals,
            vec!["@Data".to_string()]
        );
    }

    #[test]
    fn andersen_refines_node_external_for_field_sensitive_store_addresses() {
        let (pir, pag) = load_m5("andersen_refines_store_external.pir.json");

        let steens = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert!(!steens.nodes["val:driver:%gp"].external);

        let andersen = solve_andersen(&pir, &pag, BuildMode::Library, 1_000_000);
        let gp = &andersen.nodes["val:driver:%gp"];
        assert!(!gp.external);
        assert_eq!(gp.pointee_globals, vec!["@Table".to_string()]);

        let unknown_ptr = &andersen.nodes["val:driver:%unknown_ptr"];
        assert!(unknown_ptr.external);
        assert_eq!(unknown_ptr.external_sources, vec!["omega:inttoptr"]);
    }

    #[test]
    fn external_origins_remain_separate_until_a_constraint_connects_them() {
        let (pir, pag) = load("external_provenance_regions.pir.json");
        let result = solve_andersen(&pir, &pag, BuildMode::Executable, 1_000_000);

        // `opaque` observes both argv and @G, but observation is not pointer flow between
        // them. Loading argv after the boundary therefore retains foreign provenance without
        // acquiring @G. This is the distinction the former single Ω object could not express.
        let path = &result.nodes["val:main:%path"];
        assert!(path.external);
        assert!(!path.external_universal);
        assert!(path.pointee_globals.is_empty());

        let external_result = &result.nodes["val:main:%external_result"];
        assert!(external_result.external);
        assert!(!external_result.external_universal);
        assert!(external_result.pointee_globals.is_empty());

        let forged = &result.nodes["val:main:%forged"];
        assert!(forged.external);
        assert!(forged.external_universal);
    }

    #[test]
    fn external_region_contents_gain_named_objects_only_from_constraints() {
        let mut solve = Solve::new(3, false);
        let entry = solve.region(ExternalRegion::EntryArguments);
        let returned = solve.region(ExternalRegion::ExternalReturn(7));
        solve.add_pts_with_source(1, entry, Some("omega:main_entry_param"));
        solve.add_pts_with_source(2, returned, Some("omega:external_call_result"));
        solve.run();
        assert!(!solve.pts[&1].contains(&0));
        assert!(!solve.pts[&2].contains(&0));

        // A real store of a pointer to base object 0 into entry-owned storage connects
        // precisely that object. A subsequent load can then recover it.
        solve.add_pts(0, 0);
        solve.add_copy(0, entry);
        solve.add_copy(entry, 1);
        solve.run();
        assert!(solve.pts[&1].contains(&0));
        assert!(!solve.pts[&2].contains(&0));
    }

    #[test]
    fn memcpy_joins_only_new_pointee_pairs() {
        let mut solve = Solve::new(10, false);
        solve.add_memcpy(0, 1);

        solve.add_pts(0, 2);
        solve.add_pts(1, 3);
        solve.add_pts(3, 6);
        solve.run();
        assert_eq!(solve.memcpy_pairs_processed, 1);
        assert!(solve.succ[&3].contains(&2));
        assert!(solve.pts[&2].contains(&6));

        // Growing both endpoints adds the three missing quadrants:
        // (new dst 4 × old/new src 3,5) plus (old dst 2 × new src 5).
        solve.add_pts(0, 4);
        solve.add_pts(1, 5);
        solve.add_pts(5, 7);
        solve.run();
        assert_eq!(solve.memcpy_pairs_processed, 4);
        for (src, dst) in [(3, 2), (3, 4), (5, 2), (5, 4)] {
            assert!(solve.succ[&src].contains(&dst), "missing {src} -> {dst}");
        }
        assert_eq!(solve.pts[&2], HashSet::from([6, 7]));
        assert_eq!(solve.pts[&4], HashSet::from([6, 7]));

        // A later payload fact follows the established copy edge. Re-running an idle solver
        // must not revisit any memcpy object pair.
        solve.add_pts(3, 8);
        solve.run();
        assert_eq!(solve.memcpy_pairs_processed, 4);
        assert!(solve.pts[&2].contains(&8));
        assert!(solve.pts[&4].contains(&8));
        solve.run();
        assert_eq!(solve.memcpy_pairs_processed, 4);
    }

    #[test]
    fn memcpy_with_same_endpoint_avoids_new_new_overlap() {
        let mut solve = Solve::new(6, false);
        solve.add_memcpy(0, 0);
        solve.add_pts(0, 1);
        solve.add_pts(0, 2);
        solve.run();
        assert_eq!(solve.memcpy_pairs_processed, 4);

        // The new object participates in five new ordered pairs, not six: the new/new
        // pair belongs only to the new-destination rectangle.
        solve.add_pts(0, 3);
        solve.run();
        assert_eq!(solve.memcpy_pairs_processed, 9);
        solve.run();
        assert_eq!(solve.memcpy_pairs_processed, 9);
    }

    #[test]
    fn copy_edges_propagate_only_new_points_to_facts() {
        let mut solve = Solve::new(8, false);
        solve.add_pts(0, 1);
        solve.add_pts(0, 2);
        solve.add_copy(0, 4);
        solve.run();
        assert_eq!(solve.pts[&4], HashSet::from([1, 2]));
        assert_eq!(solve.copy_fact_pairs_processed, 2);

        // An established edge receives only the newly discovered fact.
        solve.add_pts(0, 3);
        solve.run();
        assert_eq!(solve.pts[&4], HashSet::from([1, 2, 3]));
        assert_eq!(solve.copy_fact_pairs_processed, 3);

        // A dynamically added edge receives the complete current source set once.
        solve.add_copy(0, 5);
        solve.run();
        assert_eq!(solve.pts[&5], HashSet::from([1, 2, 3]));
        assert_eq!(solve.copy_fact_pairs_processed, 6);

        // Later facts fan out once per established edge; an idle rerun does no work.
        solve.add_pts(0, 6);
        solve.run();
        assert_eq!(solve.pts[&4], HashSet::from([1, 2, 3, 6]));
        assert_eq!(solve.pts[&5], HashSet::from([1, 2, 3, 6]));
        assert_eq!(solve.copy_fact_pairs_processed, 8);
        solve.run();
        assert_eq!(solve.copy_fact_pairs_processed, 8);
    }

    #[test]
    fn copy_scc_collapse_preserves_object_identity_and_dynamic_growth() {
        let mut solve = Solve::new(10, false);
        solve.add_pts(0, 1); // Object identity 1 must not canonicalize with variable 1.
        solve.add_pts(0, 6);
        solve.add_pts(1, 7);
        solve.add_pts(6, 8);
        solve.add_external_sources(1, &["test-origin".to_string()]);
        solve.loads.entry(1).or_default().push(5);
        solve.add_copy(0, 1);
        solve.add_copy(1, 2);
        solve.add_copy(2, 0);
        solve.add_copy(2, 3);

        solve.collapse_copy_sccs();
        let representative = solve.canonical(0);
        assert_eq!(solve.canonical(1), representative);
        assert_eq!(solve.canonical(2), representative);
        assert_eq!(solve.points_to(0).unwrap(), &HashSet::from([1, 6, 7]));
        assert!(solve.points_to(0).unwrap().contains(&1));
        assert!(solve
            .external_sources_for(2)
            .unwrap()
            .contains("test-origin"));
        assert_eq!(solve.scc_nodes_collapsed, 2);
        assert_eq!(solve.scc_copy_edges_removed, 3);

        // Re-seeding propagates the union through the condensed edge and re-evaluates the
        // load owned by member 1. The latter discovers contents of object 6 at destination 5;
        // other possible pointee objects conservatively contribute their contents as well.
        solve.run();
        assert_eq!(solve.points_to(3).unwrap(), &HashSet::from([1, 6, 7]));
        assert!(solve.points_to(5).unwrap().contains(&8));

        // Facts and edges added through an old member ID resolve through the representative.
        solve.add_pts(2, 9);
        solve.add_copy(4, 1);
        solve.add_pts(4, 8);
        solve.run();
        assert!(solve.points_to(0).unwrap().contains(&8));
        assert!(solve.points_to(0).unwrap().contains(&9));
        assert!(solve.points_to(3).unwrap().contains(&8));
        assert!(solve.points_to(3).unwrap().contains(&9));

        // A complex constraint installed through an old SCC member also resolves through
        // the representative and replays its complete pointee set.
        let external = solve.region(ExternalRegion::ClientBoundary(99));
        solve.add_store(2, external, Some("late-after-scc".to_string()));
        solve.run();
        assert!(solve.points_to(6).unwrap().contains(&external));
        assert!(solve
            .external_sources_for(6)
            .unwrap()
            .contains("late-after-scc"));
    }

    #[test]
    fn copy_scc_collapse_replays_every_complex_join_across_merged_members() {
        let mut solve = Solve::new(16, false);
        solve.known_locations.insert(FieldLocation::Exact(4));
        solve.add_pts(0, 6);
        solve.add_pts(1, 7);
        solve.add_pts(6, 8);
        solve.add_pts(7, 9);
        solve.add_pts(4, 10);
        solve.add_load(1, 11);
        solve.add_store(1, 4, None);
        solve.add_gep(1, FieldLocation::Exact(4), 12);
        solve.run();

        assert_eq!(solve.points_to(11).unwrap(), &HashSet::from([9, 10]));
        assert!(!solve.points_to(6).is_some_and(|pts| pts.contains(&10)));
        assert_eq!(solve.points_to(12).unwrap().len(), 1);
        assert_eq!(solve.load_pairs_processed, 1);
        assert_eq!(solve.store_pairs_processed, 1);
        assert_eq!(solve.gep_pairs_processed, 1);

        solve.add_copy(0, 1);
        solve.add_copy(1, 0);
        solve.collapse_copy_sccs();
        solve.run();

        // The merged representative combines object 6 from member 0 with constraints
        // formerly owned by member 1. Full replay after collapse must process that new
        // cross-product for all three complex-constraint kinds.
        assert_eq!(solve.points_to(11).unwrap(), &HashSet::from([8, 9, 10]));
        assert!(solve.points_to(6).unwrap().contains(&10));
        assert_eq!(solve.points_to(12).unwrap().len(), 2);
        assert_eq!(solve.load_pairs_processed, 3);
        assert_eq!(solve.store_pairs_processed, 3);
        assert_eq!(solve.gep_pairs_processed, 3);
    }

    #[test]
    fn andersen_collapses_nested_gep_cycles_to_finite_field_domain() {
        let (pir, pag) = load("cyclic_nested_gep.pir.json");
        let andersen = solve_andersen(&pir, &pag, BuildMode::Library, 1_000_000);
        assert_eq!(andersen.indirect_calls.len(), 1);
        assert_eq!(
            andersen.indirect_calls[0].targets,
            vec!["target".to_string()]
        );
    }

    #[test]
    fn andersen_preserves_known_nested_gep_offsets() {
        let (pir, pag) = load_m3_2("negative_offset_container.pir.json");
        let andersen = solve_andersen(&pir, &pag, BuildMode::Library, 1_000_000);
        assert_eq!(andersen.indirect_calls.len(), 1);
        assert_eq!(
            andersen.indirect_calls[0].targets,
            vec!["target".to_string()]
        );
    }

    #[test]
    fn cg_refinement_drops_an_edge_in_a_later_round() {
        let (pir, pag) = load("cg_refinement.pir.json");

        let steens = solve_steensgaard(&pir, &pag, BuildMode::Library);
        let steens_b = steens
            .indirect_calls
            .iter()
            .find(|r| r.callsite_key == "dispatchB@!noloc#0")
            .unwrap();
        // Field-aware round 0 already excludes dispatchB from the outer field load, so its
        // parameter receives no binding from that callsite.
        assert!(steens_b.targets.is_empty());

        let andersen = solve_andersen(&pir, &pag, BuildMode::Library, 1_000_000);
        // Outer site narrows to dispatchA only…
        let outer = andersen
            .indirect_calls
            .iter()
            .find(|r| r.callsite_key == "setup@!noloc#0")
            .unwrap();
        assert_eq!(outer.targets, vec!["dispatchA".to_string()]);
        // …which removes the g→dispatchB.cb binding, dropping dispatchB's inner edge.
        let andersen_b = andersen
            .indirect_calls
            .iter()
            .find(|r| r.callsite_key == "dispatchB@!noloc#0")
            .unwrap();
        assert!(
            andersen_b.targets.is_empty(),
            "expected dispatchB inner edge dropped, got {:?}",
            andersen_b.targets
        );
        // dispatchA's inner edge survives.
        let andersen_a = andersen
            .indirect_calls
            .iter()
            .find(|r| r.callsite_key == "dispatchA@!noloc#0")
            .unwrap();
        assert_eq!(andersen_a.targets, vec!["g".to_string()]);
        assert!(andersen.metrics.rounds >= 1);
    }

    #[test]
    fn prepartition_graph_keeps_disjoint_allocation_regions_separate() {
        let (pir, pag) = load("cg_refinement.pir.json");
        let labels = BTreeSet::new();
        let (base, classes) =
            crate::solve_steensgaard_classes_targeted(&pir, &pag, BuildMode::Library, &labels);
        let exact_targets = BTreeMap::new();
        let confined_targets = BTreeSet::new();
        let refiner = Refiner::new(
            &pir,
            &pag,
            &classes,
            &base,
            BuildMode::Library,
            u64::MAX,
            &exact_targets,
            &confined_targets,
            false,
        );
        let node = |label: &str| {
            pag.nodes
                .iter()
                .find(|node| node.label == label)
                .unwrap_or_else(|| panic!("missing PAG node {label}"))
                .id
        };

        // %p0 and %q0 are two GEP instructions naming the same byte interval. %p1 names
        // offset 8 of the same allocation. The former must meet; the latter must not be
        // pulled in merely because Steensgaard used one carrier/pointee class.
        assert_eq!(
            refiner.partition_of_node(node("val:setup:%p0")),
            refiner.partition_of_node(node("val:setup:%q0"))
        );
        assert_ne!(
            refiner.partition_of_node(node("val:setup:%p0")),
            refiner.partition_of_node(node("val:setup:%p1"))
        );
    }

    #[test]
    fn andersen_subset_of_steensgaard_and_terminates_on_suite() {
        // Walk every solver fixture and assert the narrowing ledger holds and the
        // CG-refinement loop converges within the round budget.
        let roots = ["m1_4", "m1_4b", "m1_5"];
        let mut checked = 0;
        for root in roots {
            let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/synthetic")
                .join(root);
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                let pir = Pir::from_path(&path).unwrap();
                let pag = Pag::from_pir(&pir, &PagOpts::default());
                let steens = solve_steensgaard(&pir, &pag, BuildMode::Library);
                let andersen = solve_andersen(&pir, &pag, BuildMode::Library, 1_000_000);

                let steens_by_key: std::collections::HashMap<_, _> = steens
                    .indirect_calls
                    .iter()
                    .map(|r| (r.callsite_key.as_str(), r))
                    .collect();
                for a in &andersen.indirect_calls {
                    let s = steens_by_key.get(a.callsite_key.as_str()).unwrap();
                    for t in &a.targets {
                        assert!(
                            s.targets.contains(t),
                            "{}: andersen target {} not in steens for {} (ledger break)",
                            path.display(),
                            t,
                            a.callsite_key
                        );
                    }
                }
                assert!(
                    andersen.metrics.rounds <= 4,
                    "{}: {} rounds exceeds budget",
                    path.display(),
                    andersen.metrics.rounds
                );
                checked += 1;
            }
        }
        assert!(
            checked >= 10,
            "expected to check ≥10 fixtures, got {checked}"
        );
    }

    #[test]
    fn two_global_fnptrs_through_memory_resolve_both_sites() {
        // Regression for the Steensgaard over-merge bug (ju_steens_overmerge_bug.md):
        // two distinct global function pointers stored and loaded through memory in the
        // same function form a cyclic pointee structure. The `join` recursion used to
        // re-parent the destination root and orphan the merged pointee link, dropping the
        // *second* icall site to empty targets with no `unknown_callee` — a silent false
        // negative. Both sites must now resolve to their single target on both stages.
        let (pir, pag) = load("two_global_fnptrs.pir.json");

        let steens = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert_eq!(steens.indirect_calls.len(), 2);
        for r in &steens.indirect_calls {
            assert_eq!(
                r.targets.len(),
                1,
                "steens dropped {}: {:?}",
                r.callsite_key,
                r.targets
            );
            // Soundness: a resolved site must never be empty-without-unknown_callee.
            assert!(!r.targets.is_empty() || r.unknown_callee);
        }
        let steens_targets: Vec<&str> = steens
            .indirect_calls
            .iter()
            .flat_map(|r| r.targets.iter().map(|t| t.as_str()))
            .collect();
        assert!(steens_targets.contains(&"alpha"));
        assert!(steens_targets.contains(&"beta"));

        let andersen = solve_andersen(&pir, &pag, BuildMode::Library, 1_000_000);
        assert_eq!(andersen.indirect_calls.len(), 2);
        for r in &andersen.indirect_calls {
            assert_eq!(
                r.targets.len(),
                1,
                "andersen dropped {}: {:?}",
                r.callsite_key,
                r.targets
            );
        }
    }

    #[test]
    fn oversize_budget_falls_back_to_steensgaard() {
        let (pir, pag) = load("field_sensitive_fnptr.pir.json");
        // A zero budget forces every partition oversize → Steensgaard answer, tagged fallback.
        let andersen = solve_andersen(&pir, &pag, BuildMode::Library, 0);
        assert_eq!(andersen.indirect_calls.len(), 1);
        assert!(andersen.indirect_calls[0].fallback);
        assert_eq!(andersen.indirect_calls[0].targets, vec!["f0".to_string()]);
        assert!(andersen.metrics.oversize_fallbacks >= 1);
        assert!(andersen.metrics.oversize_fallback_max_size >= 1);
    }
}
