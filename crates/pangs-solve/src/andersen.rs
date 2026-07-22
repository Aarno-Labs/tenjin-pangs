//! Partition-scoped, field-sensitive inclusion (Andersen) solver — the lite design's one
//! real solver (`DESIGN_lite.md` §2 D', `PLAN-M1_lite_delta.md` §M1.4b).
//!
//! It runs *on top of* Steensgaard: `solve_steensgaard_with_classes` provides the union-find
//! classes (Kahlon partitions) and the authoritative global escape facts. Andersen then
//! refines the **points-to sets** within interesting, within-budget partitions, which
//! sharpens per-node points-to-derived outputs — indirect-call concrete targets,
//! `reaches_function_pointer`, `external`, and `pointee_globals` (mod/ref) — while global
//! escape and unknown-caller verdicts stay exactly as Steensgaard computed them.
//!
//! Soundness rests on three facts:
//! * Steensgaard unification is a sound over-approximation of Andersen, so refined targets
//!   are always ⊆ the Steensgaard targets (the narrowing ledger, asserted in tests).
//! * Constraints never cross a partition: assign/load/store/gep all *join* in Steensgaard,
//!   and an `&o` object lives in the pointer's pointee class, which we fold into the same
//!   Andersen partition — so a partition is a self-contained subproblem.
//! * Anything reachable only through Ω stays Ω (absorbing), and the global escape/unknown
//!   outputs that drive component freezing are taken verbatim from Steensgaard.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use pangs_pag::{
    BuildMode, CallKind, EdgeKind, NodeId, NodeKind, ObjectKind, OmegaSeedKind, Pag, SeedTarget,
};
use pangs_pir::{fsa_compatible, Pir};

use crate::{debug_assert_narrows, IndirectCallResolution, SolveResult, SteensClasses};

/// Hard cap on CG-refinement rounds. The loop converges by monotone shrinkage in 2–3
/// rounds in practice; this only guards against a pathological input.
const MAX_ROUNDS: usize = 8;

// The quadratic partition-cost proxy predates provenance-separated external regions and
// rejects some sparse, medium-sized partitions that solve cheaply in practice.  Refine those
// partitions when they contain no integer-forged (universal) source; retain the ordinary
// fallback for larger or genuinely universal partitions.  This keeps the expensive YAPET/Vim
// cases behind the existing budget while allowing external-origin separation to survive past
// Steensgaard on cases such as JPEGOptim.
const PROVENANCE_PROMOTION_MIN_BUDGET: u64 = 100_000;
const PROVENANCE_PROMOTION_MAX_NODES: u64 = 4_096;
const PROVENANCE_PROMOTION_MAX_EDGES: u64 = 4_096;

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
    mut base: SolveResult,
    build_mode: BuildMode,
    partition_budget: u64,
    exact_targets: &BTreeMap<String, Vec<String>>,
    confined_targets: &BTreeSet<String>,
    materialize_global_points_to: bool,
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
    );
    refiner.materialize_global_points_to = materialize_global_points_to;
    let refined = refiner.run();

    // Override only the refined facts; keep global escape/unknown-caller facts from
    // Steensgaard. Unrefined/oversize node partitions retain their Steensgaard node rows.
    base.indirect_calls = refined.indirect_calls;
    for resolution in refined.nodes {
        if let Some(node) = base.nodes.get_mut(&resolution.label) {
            // Andersen runs inside a self-contained Steensgaard partition, so its points-to
            // set is a sound subset of the union-based answer. In particular, a data pointer
            // need not retain `reaches_function_pointer` merely because field-insensitive
            // Steensgaard merged a sibling callback field into the same pointee class.
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
    // Refined in-scope globals replace their Steensgaard `node_points_to` entry; oversize and
    // uninteresting globals keep the Steensgaard fallback already seeded into `base`.
    for (label, allocs) in refined.global_points_to {
        base.node_points_to.insert(label, allocs);
    }
    base.metrics.rounds = refined.rounds;
    base.metrics.oversize_fallbacks = refined.oversize_fallbacks;
    base.metrics.oversize_fallback_max_size = refined.oversize_fallback_max_size;
    base
}

struct RefinerOutput {
    indirect_calls: Vec<IndirectCallResolution>,
    nodes: Vec<RefinedNodeResolution>,
    /// Refined global-object points-to (`obj:global:<name>` label → named allocations), only
    /// populated when `Refiner::materialize_global_points_to` is set.
    global_points_to: Vec<(String, BTreeSet<String>)>,
    rounds: usize,
    oversize_fallbacks: usize,
    oversize_fallback_max_size: usize,
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

    /// Andersen partition root for each Steensgaard class root (class ∪ pointee folded).
    ap_parent: Vec<usize>,
    /// Whether a base node sits in an interesting, within-budget partition.
    in_scope: Vec<bool>,
    oversize_fallbacks: usize,
    oversize_fallback_max_size: usize,
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
            ap_parent: Vec::new(),
            in_scope: vec![false; n_base],
            oversize_fallbacks: 0,
            oversize_fallback_max_size: 0,
            materialize_global_points_to: false,
        };
        refiner.build_scope();
        refiner
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

    /// Fold Steensgaard classes into Andersen partitions (class ∪ pointee), pick the
    /// interesting ones (reachable from icall operands, globals, or escape), then drop any
    /// that blow the oversize budget back to the Steensgaard answer.
    fn build_scope(&mut self) {
        let total = self.classes.pointee.len();
        self.ap_parent = (0..total).collect();
        for root in 0..total {
            if let Some(p) = self.classes.pointee[root] {
                self.ap_union(root, p);
            }
        }

        // Seed interesting Andersen partitions.
        let mut interesting: HashSet<usize> = HashSet::new();
        for callsite in &self.pag.callsites {
            if callsite.kind == CallKind::Indirect {
                if let Some(op) = callsite.operand {
                    let ap = self.ap_find(self.classes.class_of(op));
                    interesting.insert(ap);
                }
            }
        }
        for node in &self.pag.nodes {
            let class = self.classes.class_of(node.id);
            let ap = self.ap_find(class);
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

        // Per-partition oversize estimate: nodes × (nodes + edges touching the partition),
        // a proxy for "constraints × pts bits" (`PLAN-M1_lite_delta.md` §M1.4b).
        let mut nodes_in: HashMap<usize, u64> = HashMap::new();
        for node in &self.pag.nodes {
            let ap = self.ap_find(self.classes.class_of(node.id));
            *nodes_in.entry(ap).or_insert(0) += 1;
        }
        let mut edges_in: HashMap<usize, u64> = HashMap::new();
        for edge in &self.pag.edges {
            let ap = self.ap_find(self.classes.class_of(edge.dst));
            *edges_in.entry(ap).or_insert(0) += 1;
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
            let provenance_promoted = self.budget >= PROVENANCE_PROMOTION_MIN_BUDGET
                && n <= PROVENANCE_PROMOTION_MAX_NODES
                && e <= PROVENANCE_PROMOTION_MAX_EDGES
                && !forged_partitions.contains(&ap);
            if cost > self.budget && !provenance_promoted {
                oversize.insert(ap);
            }
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
            let ap = self.ap_find(self.classes.class_of(NodeId(i as u32)));
            self.in_scope[i] = interesting.contains(&ap) && !oversize.contains(&ap);
        }
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
            let ap = ap_find_const(&self.ap_parent, class);
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
            let ap = ap_find_const(&self.ap_parent, self.classes.class_of(operand));
            profiles
                .entry(ap)
                .or_insert_with(|| PartitionProfile {
                    root: ap,
                    ..PartitionProfile::default()
                })
                .icalls += 1;
        }
        for edge in &self.pag.edges {
            let ap = ap_find_const(&self.ap_parent, self.classes.class_of(edge.dst));
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
                sample_strings(&profile.globals, 12),
                sample_strings(&profile.functions, 12)
            );
            let hubs = self.partition_hubs(profile.root, 5);
            if !hubs.is_empty() {
                eprintln!(
                    "pangs partition profile: root={} top_load_store_hubs={}",
                    profile.root,
                    hubs.join("; ")
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
                    self.partition_cut_components(profile.root, cut, 8)
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
            SeedTarget::Node(node) => {
                Some(ap_find_const(&self.ap_parent, self.classes.class_of(node)))
            }
            SeedTarget::Callsite(callsite) => self
                .pag
                .callsites
                .get(callsite.0 as usize)
                .and_then(|callsite| callsite.operand)
                .map(|node| ap_find_const(&self.ap_parent, self.classes.class_of(node))),
        }
    }

    fn diagnostic_join_edge(&self, edge: &pangs_pag::Edge) -> Option<(usize, usize, &'static str)> {
        let src = self.classes.class_of(edge.src);
        let dst = self.classes.class_of(edge.dst);
        match edge.kind {
            EdgeKind::AddrOf => Some((self.classes.pointee[dst]?, src, "addr_of")),
            EdgeKind::Assign => Some((src, dst, "assign")),
            EdgeKind::Load => Some((dst, self.classes.pointee[src]?, "load")),
            EdgeKind::Store => Some((self.classes.pointee[dst]?, src, "store")),
            EdgeKind::Gep { byte_off } => Some((
                self.classes.pointee[dst]?,
                self.classes.pointee[src]?,
                if byte_off.is_some() {
                    "gep_const"
                } else {
                    "gep_unknown"
                },
            )),
            EdgeKind::Memcpy { .. } => {
                let dst_p = self.classes.pointee[dst]?;
                let src_p = self.classes.pointee[src]?;
                Some((
                    self.classes.pointee[dst_p]?,
                    self.classes.pointee[src_p]?,
                    "memcpy",
                ))
            }
        }
    }

    fn partition_hubs(&self, ap: usize, limit: usize) -> Vec<String> {
        let mut counts: HashMap<usize, (usize, usize)> = HashMap::new();
        let mut witnesses: HashMap<usize, Vec<String>> = HashMap::new();
        for edge in &self.pag.edges {
            let Some((left, right, family)) = self.diagnostic_join_edge(edge) else {
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
                    self.class_label_sample(root, 4),
                    witnesses.remove(&root).unwrap_or_default()
                )
            })
            .collect()
    }

    fn partition_cut_components(&self, ap: usize, cut: PartitionCut, limit: usize) -> Vec<usize> {
        let mut nodes = BTreeSet::<u32>::new();
        for node in &self.pag.nodes {
            if ap_find_const(&self.ap_parent, self.classes.class_of(node.id)) == ap {
                nodes.insert(node.id.0);
            }
        }
        let mut adjacency: HashMap<u32, Vec<u32>> = HashMap::new();
        for edge in &self.pag.edges {
            let family = edge_family(edge.kind);
            if cut.removes(family) {
                continue;
            }
            let src_ap = ap_find_const(&self.ap_parent, self.classes.class_of(edge.src));
            let dst_ap = ap_find_const(&self.ap_parent, self.classes.class_of(edge.dst));
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

    fn class_label_sample(&self, class: usize, limit: usize) -> Vec<String> {
        let mut labels = self
            .pag
            .nodes
            .iter()
            .filter(|node| self.classes.class_of(node.id) == class)
            .map(|node| node.label.clone())
            .take(limit)
            .collect::<Vec<_>>();
        if labels.is_empty() && class >= self.n_base {
            labels.push(format!("synthetic:{class}"));
        }
        labels
    }

    // ----- CG-refinement outer loop -----------------------------------------------------

    fn run(mut self) -> RefinerOutput {
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

        // Round-0 seed: exact overrides for proven sites, otherwise FSA ∩ Steensgaard
        // targets with confined targets removed from candidate callsites.
        let steens_by_key: HashMap<&str, &IndirectCallResolution> = self
            .base
            .indirect_calls
            .iter()
            .map(|r| (r.callsite_key.as_str(), r))
            .collect();
        let mut target_map: HashMap<usize, Vec<usize>> = HashMap::new();
        for &site in &in_scope_sites {
            let key = self.pag.callsites[site].key.as_str();
            let funcs = if let Some(funcs) = self.exact_target_indices(key) {
                funcs
            } else {
                steens_by_key
                    .get(key)
                    .map(|r| self.non_confined_target_indices(&r.targets))
                    .unwrap_or_default()
            };
            target_map.insert(site, funcs);
        }

        let mut rounds = 0usize;
        let mut pts = self.solve_once(&target_map);
        loop {
            rounds += 1;
            let new_map = self.recompute_targets(&in_scope_sites, &pts);
            // Monotone shrinkage: round k+1 ⊆ round k. A growth is a soundness bug.
            for (&site, funcs) in &new_map {
                let prev: HashSet<usize> = target_map[&site].iter().copied().collect();
                debug_assert!(
                    funcs.iter().all(|f| prev.contains(f)),
                    "Andersen CG-refinement grew an icall target set (soundness bug)"
                );
            }
            if maps_equal(&new_map, &target_map) || rounds >= MAX_ROUNDS {
                break;
            }
            if andersen_profile_enabled() {
                eprintln!(
                    "pangs andersen profile: round {rounds} target map changed; rerunning fixed-graph solve"
                );
            }
            target_map = new_map;
            pts = self.solve_once(&target_map);
        }

        let indirect_calls = self.emit_indirect_calls(&in_scope_sites, &pts);
        let nodes = self.emit_node_resolutions(&pts);
        let global_points_to = if self.materialize_global_points_to {
            self.emit_global_points_to(&pts)
        } else {
            Vec::new()
        };
        RefinerOutput {
            indirect_calls,
            nodes,
            global_points_to,
            rounds,
            oversize_fallbacks: self.oversize_fallbacks,
            oversize_fallback_max_size: self.oversize_fallback_max_size,
        }
    }

    // ----- the inclusion solve (stateless per round) ------------------------------------

    /// Solve one fixed call graph from scratch (no caches across rounds). Returns the
    /// points-to set of every in-scope cell.
    fn solve_once(&mut self, target_map: &HashMap<usize, Vec<usize>>) -> Solve {
        let profile = andersen_profile_enabled();
        let mut solve = Solve::new(self.n_base, profile);

        // Base constraints from PAG edges (in-scope only; partitions are self-contained).
        for edge in &self.pag.edges {
            if !self.in_scope[edge.dst.0 as usize] && !self.in_scope[edge.src.0 as usize] {
                continue;
            }
            match edge.kind {
                EdgeKind::AddrOf => solve.add_pts(edge.dst.0, edge.src.0),
                EdgeKind::Assign => solve.add_copy(edge.src.0, edge.dst.0),
                EdgeKind::Load => solve.loads.entry(edge.src.0).or_default().push(edge.dst.0),
                EdgeKind::Store => solve
                    .stores
                    .entry(edge.dst.0)
                    .or_default()
                    .push((edge.src.0, None)),
                EdgeKind::Gep { byte_off } => {
                    if let Some(byte_off) = byte_off {
                        solve.known_offsets.insert(byte_off);
                    }
                    solve
                        .geps
                        .entry(edge.src.0)
                        .or_default()
                        .push((byte_off, edge.dst.0));
                }
                EdgeKind::Memcpy { .. } => solve.memcpys.push((edge.dst.0, edge.src.0)),
            }
        }

        self.apply_boundary_omega_seeds(&mut solve);

        // Indirect-call bindings for the fixed call graph (direct calls are already PAG
        // Assign edges; only icalls are bound dynamically).
        for (&site, funcs) in target_map {
            let cs = &self.pag.callsites[site];
            for &f in funcs {
                if self.pir.functions[f].external {
                    self.apply_external_call_effects(&mut solve, cs);
                }
                for (i, &arg) in cs.args.iter().enumerate() {
                    if let Some(&param) = self.param_nodes.get(&(f, i)) {
                        solve.add_copy(arg.0, param.0);
                    }
                }
                if let (Some(result), Some(&ret)) = (cs.result, self.ret_nodes.get(&f)) {
                    solve.add_copy(ret.0, result.0);
                }
            }
        }

        if profile {
            eprintln!(
                "pangs andersen profile: solve start target_sites={} target_edges={} pts_entries={} pts_facts={} copy_sources={} copy_edges={} loads={} stores={} geps={} memcpys={}",
                target_map.len(),
                target_map.values().map(Vec::len).sum::<usize>(),
                solve.pts.len(),
                solve.pts_facts(),
                solve.succ.len(),
                solve.copy_edges(),
                solve.loads.values().map(Vec::len).sum::<usize>(),
                solve.stores.values().map(Vec::len).sum::<usize>(),
                solve.geps.values().map(Vec::len).sum::<usize>(),
                solve.memcpys.len()
            );
        }
        solve.run();
        if profile {
            eprintln!(
                "pangs andersen profile: solve done steps={} pts_entries={} pts_facts={} copy_sources={} copy_edges={} fields={} unknown_fields={}",
                solve.steps,
                solve.pts.len(),
                solve.pts_facts(),
                solve.succ.len(),
                solve.copy_edges(),
                solve.fields.len(),
                solve.unknown_fields.len()
            );
        }
        solve
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
        let detailed = std::env::var_os("PANGS_ANDERSEN_EXPLAIN_NODE").is_some();
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
        let source = if std::env::var_os("PANGS_ANDERSEN_EXPLAIN_NODE").is_some() {
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
            solve
                .stores
                .entry(node.0)
                .or_default()
                .push((region, Some(source.to_string())));
        }
    }

    fn scope_profile(&self) -> ScopeProfile {
        let mut profile = ScopeProfile::default();
        profile.in_scope_nodes = self.in_scope.iter().filter(|&&in_scope| in_scope).count();
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

    /// Recompute each in-scope site's targets = FSA ∩ {address-taken functions in
    /// pts(operand)} from the solved points-to.
    fn recompute_targets(&self, sites: &[usize], pts: &Solve) -> HashMap<usize, Vec<usize>> {
        let mut map = HashMap::new();
        for &site in sites {
            let cs = &self.pag.callsites[site];
            if let Some(funcs) = self.exact_target_indices(&cs.key) {
                map.insert(site, funcs);
                continue;
            }
            let operand = cs.operand.unwrap();
            let mut funcs: Vec<usize> = Vec::new();
            if let Some(set) = pts.pts.get(&operand.0) {
                for &cell in set {
                    if let Some(&idx) = self.fn_cell_to_index.get(&cell) {
                        let f = &self.pir.functions[idx];
                        if f.address_taken
                            && !self.confined_targets.contains(&f.key)
                            && fsa_compatible(&cs.sig, &f.sig)
                        {
                            funcs.push(idx);
                        }
                    }
                }
            }
            funcs.sort_unstable();
            funcs.dedup();
            map.insert(site, funcs);
        }
        map
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
        pts: &Solve,
    ) -> Vec<IndirectCallResolution> {
        let in_scope: HashSet<usize> = in_scope_sites.iter().copied().collect();
        let final_map = self.recompute_targets(in_scope_sites, pts);
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
                let mut targets: Vec<String> = final_map
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
                out.push(IndirectCallResolution {
                    callsite_key: cs.key.clone(),
                    targets,
                    // Ω/unknown-callee is a Steensgaard escape verdict, kept verbatim.
                    unknown_callee: steens.map(|r| r.unknown_callee).unwrap_or(false),
                    fallback: false,
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
        let explain_label = std::env::var("PANGS_ANDERSEN_EXPLAIN_NODE").ok();
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
            let set = pts.pts.get(&node.id.0);
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
                pts.external_sources
                    .get(&node.id.0)
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
                const SOURCE_LIMIT: usize = 32;
                let source_count = external_sources.len();
                let source_sample = external_sources
                    .iter()
                    .take(SOURCE_LIMIT)
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
                let Some(set) = pts.pts.get(&cell) else {
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

fn maps_equal(a: &HashMap<usize, Vec<usize>>, b: &HashMap<usize, Vec<usize>>) -> bool {
    a.len() == b.len()
        && a.iter()
            .all(|(k, v)| b.get(k).map(|w| w == v).unwrap_or(false))
}

fn andersen_profile_enabled() -> bool {
    std::env::var_os("PANGS_ANDERSEN_PROFILE").is_some()
}

fn partition_profile_enabled() -> bool {
    std::env::var_os("PANGS_PARTITION_PROFILE").is_some()
}

fn partition_profile_top() -> usize {
    std::env::var("PANGS_PARTITION_PROFILE_TOP")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|&value| value > 0)
        .unwrap_or(20)
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
        EdgeKind::Gep { byte_off: Some(_) } => "gep_const",
        EdgeKind::Gep { byte_off: None } => "gep_unknown",
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
struct Solve {
    next_field: Cell,
    pts: HashMap<Cell, HashSet<Cell>>,
    external_sources: HashMap<Cell, BTreeSet<String>>,
    regions: HashMap<ExternalRegion, Cell>,
    region_of_cell: HashMap<Cell, ExternalRegion>,
    succ: HashMap<Cell, HashSet<Cell>>,
    loads: HashMap<Cell, Vec<Cell>>,
    stores: HashMap<Cell, Vec<(Cell, Option<String>)>>,
    geps: HashMap<Cell, Vec<(Option<i64>, Cell)>>,
    memcpys: Vec<(Cell, Cell)>,
    fields: HashMap<(Cell, i64), Cell>,
    /// field cell -> base object cell, so a refined field resolves back to its global.
    field_base: HashMap<Cell, Cell>,
    /// field cell -> byte offset from its root object.
    field_offset: HashMap<Cell, i64>,
    /// Constant offsets that occur in the fixed constraint graph. Nested GEPs are
    /// canonicalized only into this finite vocabulary.
    known_offsets: HashSet<i64>,
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
}

impl Solve {
    fn new(n_base: usize, profile: bool) -> Self {
        Self {
            next_field: n_base as Cell,
            pts: HashMap::new(),
            external_sources: HashMap::new(),
            regions: HashMap::new(),
            region_of_cell: HashMap::new(),
            succ: HashMap::new(),
            loads: HashMap::new(),
            stores: HashMap::new(),
            geps: HashMap::new(),
            memcpys: Vec::new(),
            fields: HashMap::new(),
            field_base: HashMap::new(),
            field_offset: HashMap::new(),
            known_offsets: HashSet::new(),
            obj_fields: HashMap::new(),
            unknown_fields: HashMap::new(),
            unknown_field_base: HashMap::new(),
            direct_accessed: HashSet::new(),
            worklist: Vec::new(),
            queued: HashSet::new(),
            profile,
            steps: 0,
        }
    }

    fn region(&mut self, region: ExternalRegion) -> Cell {
        if let Some(&cell) = self.regions.get(&region) {
            return cell;
        }
        let cell = self.next_field;
        self.next_field += 1;
        self.regions.insert(region, cell);
        self.region_of_cell.insert(cell, region);
        // Each region denotes its own foreign objects. Unlike the old absorbing Ω cell,
        // its contents may gain named objects through real store/copy constraints.
        self.pts.entry(cell).or_default().insert(cell);
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
        if self.queued.insert(cell) {
            self.worklist.push(cell);
        }
    }

    fn add_pts(&mut self, cell: Cell, obj: Cell) {
        self.add_pts_with_source(cell, obj, None);
    }

    fn add_pts_with_source(&mut self, cell: Cell, obj: Cell, source: Option<&str>) {
        let mut changed = self.pts.entry(cell).or_default().insert(obj);
        if self.is_external(obj) {
            if let Some(source) = source {
                let source = source.to_string();
                changed |= self
                    .external_sources
                    .entry(cell)
                    .or_default()
                    .insert(source.clone());
                // Loads from the region must retain the region's origin even when the
                // pointer used to reach it is not copied into the loaded value.
                self.external_sources.entry(obj).or_default().insert(source);
            }
        }
        if changed {
            self.enqueue(cell);
        }
    }

    fn add_copy(&mut self, from: Cell, to: Cell) {
        if from == to {
            return;
        }
        if self.succ.entry(from).or_default().insert(to) {
            // Push current pts(from) into pts(to) immediately.
            if let Some(src) = self.pts.get(&from).cloned() {
                let mut changed = false;
                let dst = self.pts.entry(to).or_default();
                for o in src {
                    changed |= dst.insert(o);
                }
                changed |= self.propagate_external_sources(from, to);
                if changed {
                    self.enqueue(to);
                }
            }
        }
    }

    fn propagate_external_sources(&mut self, from: Cell, to: Cell) -> bool {
        let Some(sources) = self.external_sources.get(&from).cloned() else {
            return false;
        };
        if sources.is_empty() {
            return false;
        }
        let dst = self.external_sources.entry(to).or_default();
        let mut changed = false;
        for source in sources {
            changed |= dst.insert(source);
        }
        changed
    }

    /// Field/subobject identity for `base + off` (M2.1, `PLAN-M2_lite_delta.md` §1 M2.1).
    ///
    /// A **constant** offset gets its own subobject cell, giving field sensitivity. A
    /// **non-constant** offset (`None`) uses a per-root unknown-offset summary cell. The
    /// summary aliases every materialized constant field for that root, so a dynamic-index
    /// store is visible to constant-field loads (and vice versa), but we avoid routing all
    /// future fields through the whole-object cell. This keeps the M2.1 soundness property
    /// while reducing broad cross-field/root pollution.
    fn field_of(&mut self, base: Cell, off: Option<i64>) -> Cell {
        if self.is_external(base) {
            return base;
        }
        if self.unknown_field_base.contains_key(&base) {
            return base;
        }
        if let Some(&root) = self.field_base.get(&base) {
            // Keep nested constant GEPs finite by canonicalizing them back to root+offset
            // rather than creating field-of-field chains. We only materialize combined
            // offsets that occur in the fixed graph's finite offset vocabulary; other nested
            // constants route to the root's unknown-offset summary. Unknown nested offsets
            // also route to the root summary because they may alias any root field.
            let base_off = self.field_offset.get(&base).copied().unwrap_or(0);
            return match off.and_then(|delta| base_off.checked_add(delta)) {
                Some(combined) if combined == base_off => base,
                Some(combined) if self.known_offsets.contains(&combined) => {
                    self.field_of(root, Some(combined))
                }
                Some(_) | None => self.unknown_field_of(root),
            };
        }
        match off {
            None => self.unknown_field_of(base),
            Some(off) => {
                if let Some(&cell) = self.fields.get(&(base, off)) {
                    return cell;
                }
                let cell = self.next_field;
                self.next_field += 1;
                self.fields.insert((base, off), cell);
                self.field_base.insert(cell, base);
                self.field_offset.insert(cell, off);
                self.obj_fields.entry(base).or_default().push(cell);
                if let Some(&summary) = self.unknown_fields.get(&base) {
                    self.add_copy(cell, summary);
                    self.add_copy(summary, cell);
                }
                cell
            }
        }
    }

    fn unknown_field_of(&mut self, base: Cell) -> Cell {
        if let Some(&cell) = self.unknown_fields.get(&base) {
            return cell;
        }
        let cell = self.next_field;
        self.next_field += 1;
        self.unknown_fields.insert(base, cell);
        self.unknown_field_base.insert(cell, base);
        self.field_base.insert(cell, base);
        self.obj_fields.entry(base).or_default().push(cell);
        if let Some(fields) = self.obj_fields.get(&base).cloned() {
            for field in fields {
                if field == cell {
                    continue;
                }
                self.add_copy(field, cell);
                self.add_copy(cell, field);
            }
        }
        if self.direct_accessed.contains(&base) {
            self.add_copy(base, cell);
            self.add_copy(cell, base);
        }
        cell
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

    fn pts_facts(&self) -> usize {
        self.pts.values().map(HashSet::len).sum()
    }

    fn copy_edges(&self) -> usize {
        self.succ.values().map(HashSet::len).sum()
    }

    fn maybe_report_progress(&self) {
        if self.profile && self.steps % 10_000 == 0 {
            eprintln!(
                "pangs andersen profile: solve progress steps={} worklist={} queued={} pts_entries={} pts_facts={} copy_sources={} copy_edges={} fields={} unknown_fields={}",
                self.steps,
                self.worklist.len(),
                self.queued.len(),
                self.pts.len(),
                self.pts_facts(),
                self.succ.len(),
                self.copy_edges(),
                self.fields.len(),
                self.unknown_fields.len()
            );
        }
    }

    fn report_large_product(&self, kind: &str, base: Cell, lhs: usize, rhs: usize) {
        if self.profile && lhs.saturating_mul(rhs) >= 50_000 {
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
        // Prime the worklist with every cell that already has points-to facts.
        let seeded: Vec<Cell> = self.pts.keys().copied().collect();
        for c in seeded {
            self.enqueue(c);
        }

        while let Some(n) = self.worklist.pop() {
            self.steps += 1;
            self.maybe_report_progress();
            self.queued.remove(&n);
            let objs: Vec<Cell> = self
                .pts
                .get(&n)
                .map(|s| s.iter().copied().collect())
                .unwrap_or_default();

            // n as a load base: p = *n  ⇒  pts(o) ⊆ pts(p)  for o ∈ pts(n)
            if let Some(ps) = self.loads.get(&n).cloned() {
                self.report_large_product("load", n, ps.len(), objs.len());
                for p in ps {
                    for &o in &objs {
                        self.note_direct_access(o);
                        self.add_copy(o, p);
                    }
                }
            }
            // n as a store base: *n = q  ⇒  pts(q) ⊆ pts(o)  for o ∈ pts(n)
            if let Some(qs) = self.stores.get(&n).cloned() {
                self.report_large_product("store", n, qs.len(), objs.len());
                for (q, omega_source) in qs {
                    for &o in &objs {
                        self.note_direct_access(o);
                        if self.is_external(q) {
                            self.add_pts_with_source(o, q, omega_source.as_deref());
                        } else {
                            self.add_copy(q, o);
                        }
                    }
                }
            }
            // n as a gep base: p = n + off  ⇒  field(o, off) ∈ pts(p)  for o ∈ pts(n)
            if let Some(gs) = self.geps.get(&n).cloned() {
                self.report_large_product("gep", n, gs.len(), objs.len());
                for (off, p) in gs {
                    for &o in &objs {
                        let f = self.field_of(o, off);
                        self.add_pts(p, f);
                    }
                }
            }
            // n in a memcpy: contents-copy between pointed-to objects (field-insensitive).
            if !self.memcpys.is_empty() {
                let relevant: Vec<(Cell, Cell)> = self
                    .memcpys
                    .iter()
                    .copied()
                    .filter(|&(d, s)| d == n || s == n)
                    .collect();
                for (d, s) in relevant {
                    let dobjs: Vec<Cell> = self
                        .pts
                        .get(&d)
                        .map(|s| s.iter().copied().collect())
                        .unwrap_or_default();
                    let sobjs: Vec<Cell> = self
                        .pts
                        .get(&s)
                        .map(|s| s.iter().copied().collect())
                        .unwrap_or_default();
                    self.report_large_product("memcpy", n, dobjs.len(), sobjs.len());
                    for &od in &dobjs {
                        self.note_direct_access(od);
                        for &os in &sobjs {
                            self.note_direct_access(os);
                            self.add_copy(os, od);
                        }
                    }
                }
            }
            // Propagate along copy edges.
            if let Some(succs) = self.succ.get(&n).cloned() {
                let src: HashSet<Cell> = self.pts.get(&n).cloned().unwrap_or_default();
                for s in succs {
                    let mut changed = false;
                    let dst = self.pts.entry(s).or_default();
                    for &o in &src {
                        changed |= dst.insert(o);
                    }
                    changed |= self.propagate_external_sources(n, s);
                    if changed {
                        self.enqueue(s);
                    }
                }
            }
        }
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
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;

    use pangs_pag::{BuildMode, Pag, PagOpts};
    use pangs_pir::Pir;

    use super::{solve_andersen, solve_andersen_with_overrides, ExternalRegion, Solve};
    use crate::solve_steensgaard;

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
    fn andersen_distinguishes_struct_fn_ptr_fields() {
        let (pir, pag) = load("field_sensitive_fnptr.pir.json");

        // Steensgaard conflates the two struct fields → both targets.
        let steens = solve_steensgaard(&pir, &pag, BuildMode::Library);
        assert_eq!(steens.indirect_calls.len(), 1);
        assert_eq!(
            steens.indirect_calls[0].targets,
            vec!["f0".to_string(), "f1".to_string()]
        );

        // Andersen's field sensitivity keeps only the field actually loaded.
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
    fn andersen_refines_function_pointer_reachability_for_data_fields() {
        let (pir, pag) = load("field_sensitive_data_vs_fnptr.pir.json");

        // Steensgaard merges the aggregate's callback and data fields, so the loaded data
        // pointer inherits the callback function object.
        let steens = solve_steensgaard(&pir, &pag, BuildMode::Library);
        let data = "val:setup:%data";
        assert!(steens.nodes[data].reaches_function_pointer);
        assert_eq!(
            steens.nodes[data].pointee_globals,
            vec!["@Data".to_string()]
        );

        // Andersen keeps the constant-offset fields separate. Its allocation set contains
        // only @Data, so the refined function-pointer bit must narrow with it.
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
        assert!(steens.nodes["val:driver:%gp"].external);

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
        // Round-0 (Steensgaard) call graph routes g into dispatchB's parameter.
        assert_eq!(steens_b.targets, vec!["g".to_string()]);

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
        // The drop only happens because the loop ran a second round.
        assert!(
            andersen.metrics.rounds >= 2,
            "rounds={}",
            andersen.metrics.rounds
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
            assert!(!(r.targets.is_empty() && !r.unknown_callee));
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
        assert_eq!(
            andersen.indirect_calls[0].targets,
            vec!["f0".to_string(), "f1".to_string()]
        );
        assert!(andersen.metrics.oversize_fallbacks >= 1);
        assert!(andersen.metrics.oversize_fallback_max_size >= 1);
    }
}
