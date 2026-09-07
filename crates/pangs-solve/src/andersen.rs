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
//! * Ordinary admission partitions are weak components of the inclusion constraints. An
//!   oversize component may expose a source-closed directed-SCC predecessor slice around an
//!   indirect-call operand; excluded successors retain their complete Steensgaard fallback rows.
//!   Certified memory accesses use allocation-relative byte-region vertices, while unresolved
//!   accesses retain their address carrier.
//! * Anything reachable only through Ω stays Ω (absorbing), and the global escape/unknown
//!   outputs that drive component freezing are taken verbatim from Steensgaard.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::time::Instant;

use pangs_pag::{
    BuildMode, CallKind, EdgeKind, NodeId, NodeKind, ObjectKind, OmegaSeedKind, Pag, SeedTarget,
};
use pangs_pir::Pir;

use crate::knobs;
use crate::{
    debug_assert_narrows, exact_allocation_addresses, ExactAddress, FieldLocation, FieldRegion,
    IndirectCallResolution, SharedStringList, SolveResult, SteensClasses,
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
    closed_producers: bool,
    closed_consumers: bool,
    offline_quotient: bool,
    asymmetric_field_overlap: bool,
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
            closed_producers: closed_producers_enabled(),
            closed_consumers: closed_consumers_enabled(),
            offline_quotient: std::env::var_os(knobs::ENV_ANDERSEN_OFFLINE_QUOTIENT).is_some(),
            asymmetric_field_overlap: asymmetric_field_overlap_enabled(),
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
    // `Refiner::run` owns and drops the inclusion graph before returning. Reclaim those arena
    // pages before folding its compact output into the long-lived public result.
    let allocator_trimmed = release_allocator_pages();
    print_process_memory("andersen-state-released", None, Some(allocator_trimmed));

    match outcome {
        RefinerOutcome::Complete(refined) => {
            // Override only complete refined facts; keep global escape/unknown-caller facts
            // from Steensgaard. Unrefined/oversize node partitions retain their base rows.
            base.indirect_calls = refined.indirect_calls;
            for function in &refined.closed_consumers {
                base.unknown_callers.remove(function);
            }
            patch_exact_overrides(pir, &mut base.indirect_calls, exact_targets);
            for resolution in refined.nodes {
                if let Some(node) = base.nodes.get_mut(&resolution.label) {
                    node.reaches_function_pointer = resolution.reaches_function_pointer;
                    node.external = resolution.external;
                    node.external_escaped_union = resolution.external_escaped_union;
                    node.pointee_globals = resolution.pointee_globals;
                    node.pointee_globals_unfiltered = resolution.pointee_globals_unfiltered;
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
            base.metrics.andersen_coarser_than_steens_nodes = refined.coarser_than_steens_nodes;
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
                "pangs andersen exhausted: reason={} steps={} resume_rounds={} worklist={} queued={} pending_copy_seeds={} pending_pts_deltas={} known_unbound_targets={} activated_targets={} scc_passes={} scc_nodes_collapsed={} scc_copy_edges_removed={} memcpy_pairs_processed={} memcpy_logical_pairs_covered={} memcpy_summary_edges_inserted={} memcpy_summary_sites={} memcpy_summary_cells={} copy_fact_pairs_processed={}",
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
                exhausted.memcpy_logical_pairs_covered,
                exhausted.memcpy_summary_edges_inserted,
                exhausted.memcpy_summary_sites,
                exhausted.memcpy_summary_cells,
                exhausted.copy_fact_pairs_processed,
            );
        }
    }
    base
}

/// Return allocator pages made unreachable by a completed Andersen solve to the OS before
/// downstream clients start building ModRef and disposition state. The inclusion solver uses
/// many independently allocated hash tables; glibc otherwise tends to retain those freed pages
/// in its arenas until process exit, making later phases overlap with the solver's RSS.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn release_allocator_pages() -> bool {
    extern "C" {
        fn malloc_trim(pad: usize) -> i32;
    }

    // SAFETY: malloc_trim is a process-local glibc allocator operation. Calling it after Rust
    // values have been dropped does not invalidate any live allocation; `pad = 0` requests that
    // all wholly free pages be returned.
    unsafe { malloc_trim(0) != 0 }
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn release_allocator_pages() -> bool {
    false
}

fn proc_memory_kib() -> Option<(u64, u64, u64)> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let value = |name: &str| {
        status.lines().find_map(|line| {
            let rest = line.strip_prefix(name)?.trim();
            rest.split_whitespace().next()?.parse::<u64>().ok()
        })
    };
    Some((value("VmRSS:")?, value("VmHWM:")?, value("RssAnon:")?))
}

fn print_process_memory(phase: &str, solve: Option<&Solve>, allocator_trimmed: Option<bool>) {
    if std::env::var_os(knobs::ENV_MEMORY_PROFILE).is_none() {
        return;
    }
    let (rss_kib, hwm_kib, anonymous_kib) = proc_memory_kib().unwrap_or_default();
    if let Some(solve) = solve {
        let external_source_sets = solve.external_sources.len();
        let external_source_facts = solve
            .external_sources
            .values()
            .map(BTreeSet::len)
            .sum::<usize>();
        let external_source_bytes = solve
            .external_sources
            .values()
            .flatten()
            .map(String::len)
            .sum::<usize>();
        eprintln!(
            "pangs memory profile: phase={phase} rss_kib={rss_kib} hwm_kib={hwm_kib} anonymous_kib={anonymous_kib} pts_entries={} pts_facts={} copy_sources={} copy_edges={} external_source_sets={external_source_sets} external_source_facts={external_source_facts} external_source_bytes={external_source_bytes} representative_cells={} fields={} obj_fields={} loads={} stores={} geps={} memcpys={}",
            solve.pts.len(),
            solve.pts_facts(),
            solve.copy_sources(),
            solve.copy_edges(),
            solve.representative.len(),
            solve.fields.len(),
            solve.obj_fields.values().map(Vec::len).sum::<usize>(),
            solve.loads.values().map(Vec::len).sum::<usize>(),
            solve.stores.values().map(Vec::len).sum::<usize>(),
            solve.geps.values().map(Vec::len).sum::<usize>(),
            solve.memcpys.len(),
        );
    } else {
        eprintln!(
            "pangs memory profile: phase={phase} rss_kib={rss_kib} hwm_kib={hwm_kib} anonymous_kib={anonymous_kib} allocator_trimmed={}",
            allocator_trimmed.unwrap_or(false),
        );
    }
}

enum RefinerOutcome {
    Complete(RefinerOutput),
    Exhausted(ExhaustionDiagnostic),
}

struct RefinerOutput {
    indirect_calls: Vec<IndirectCallResolution>,
    closed_consumers: BTreeSet<String>,
    nodes: Vec<RefinedNodeResolution>,
    /// Refined global-object points-to (`obj:global:<name>` label → named allocations), only
    /// populated when `Refiner::materialize_global_points_to` is set.
    global_points_to: Vec<(String, BTreeSet<String>)>,
    resume_rounds: usize,
    steps: usize,
    activated_targets: usize,
    oversize_fallbacks: usize,
    oversize_fallback_max_size: usize,
    coarser_than_steens_nodes: usize,
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
    memcpy_logical_pairs_covered: usize,
    memcpy_summary_edges_inserted: usize,
    memcpy_summary_sites: usize,
    memcpy_summary_cells: usize,
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
    external_escaped_union: bool,
    pointee_globals: SharedStringList,
    pointee_globals_unfiltered: SharedStringList,
    external_sources: Vec<String>,
}

#[derive(Default)]
struct RefinedPointeeGlobalInterner {
    by_indices: HashMap<Vec<usize>, SharedStringList>,
}

impl RefinedPointeeGlobalInterner {
    fn intern(&mut self, indices: Vec<usize>, pir: &Pir) -> SharedStringList {
        if indices.is_empty() {
            return SharedStringList::default();
        }
        if let Some(existing) = self.by_indices.get(indices.as_slice()) {
            return existing.clone();
        }
        let globals = SharedStringList::from(
            indices
                .iter()
                .map(|&index| pir.globals[index].key.clone())
                .collect::<Vec<_>>(),
        );
        self.by_indices.insert(indices, globals.clone());
        globals
    }
}

#[derive(Default)]
struct TargetDiscovery {
    targets: Vec<(usize, usize)>,
    eager_sites: Vec<usize>,
}

/// A single source-closed producer graph shared by all indirect-call queries.
///
/// The graph contains PAG values plus materialized allocation-relative field cells. Edges are
/// producer dependencies, not points-to edges: assignments/GEPs preserve their source, stores
/// feed every solved destination cell, and loads consume every solved source cell. Direct call
/// argument/return summaries need no special representation because PAG construction has already
/// flattened them into `Assign` edges. Unsupported aggregate copies fail closed.
struct ClosedProducerAnalysis {
    complete: Vec<bool>,
}

#[derive(Debug)]
struct ClosedProducerQuery {
    complete: bool,
    targets: Vec<usize>,
    external: bool,
    non_function: bool,
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
    memcpy_logical_pairs_covered: usize,
    memcpy_summary_edges_inserted: usize,
    memcpy_summary_sites: usize,
    memcpy_summary_cells: usize,
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
    ReceiverPayload(u32),
    VarargPayload(u32),
}

impl ExternalRegion {
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
            Self::ReceiverPayload(id) => format!("receiver_payload:{id}"),
            Self::VarargPayload(id) => format!("vararg_payload:{id}"),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct AllocationOrigins {
    roots: BTreeSet<NodeId>,
    complete: bool,
}

#[derive(Debug, Clone, Default)]
struct ReceiverPayloadOp {
    /// Pointer parameters (other than the receiver) whose values may be stored in receiver
    /// reachable memory, together with the allocation-relative fields they populate.
    stored_params: BTreeMap<usize, BTreeSet<FieldLocation>>,
    /// Allocation-relative receiver fields from which the function may return a pointer.
    returned_regions: BTreeSet<FieldLocation>,
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
    /// Experimental, automatically inferred receiver-relative container operations.
    receiver_payload_ops: HashMap<usize, ReceiverPayloadOp>,
    /// Bounded address-preserving allocation origins for receiver payload values.
    receiver_payload_origins: Vec<AllocationOrigins>,

    /// Union-find for the independent prepartition constraint graph. PAG nodes occupy
    /// `[0, n_base)`; allocation-relative memory regions are synthetic vertices above it.
    ap_parent: Vec<usize>,
    /// Region identity for synthetic prepartition vertices.
    prepartition_regions: Vec<Option<(NodeId, FieldRegion)>>,
    /// Constraint endpoints used by diagnostics, parallel to `pag.edges`.
    prepartition_edge_vertices: Vec<Option<(usize, usize)>>,
    /// Directed inclusion dependencies. Source-closed SCC slices use these to ensure no
    /// excluded predecessor can feed an admitted Andersen subproblem.
    prepartition_flow_edges: Vec<(usize, usize)>,
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
            exact_addresses: exact_allocation_addresses(pag, &base.storage_roots),
            receiver_payload_ops: HashMap::new(),
            receiver_payload_origins: Vec::new(),
            ap_parent: Vec::new(),
            prepartition_regions: Vec::new(),
            prepartition_edge_vertices: Vec::new(),
            prepartition_flow_edges: Vec::new(),
            in_scope: vec![false; n_base],
            oversize_fallbacks: 0,
            oversize_fallback_max_size: 0,
            admission_profile_root: admission_profile_root(),
            collect_admission_structures,
            admission_structures: Vec::new(),
            materialize_global_points_to: false,
        };
        if receiver_payloads_enabled() {
            refiner.receiver_payload_ops = refiner.infer_receiver_payload_ops();
            refiner.receiver_payload_origins =
                bounded_allocation_origins(pag, knobs::ANDERSEN_RECEIVER_PAYLOAD_ORIGIN_LIMIT);
        }
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

    fn receiver_payload_location(&self, address: NodeId) -> FieldLocation {
        self.exact_addresses[address.0 as usize]
            .map(|exact| exact.location)
            .or_else(|| {
                self.pag.edges.iter().find_map(|edge| {
                    (edge.dst == address)
                        .then(|| match edge.kind {
                            EdgeKind::Gep { byte_off, lane } => {
                                Some(FieldLocation::from_gep(byte_off, lane))
                            }
                            _ => None,
                        })
                        .flatten()
                })
            })
            .unwrap_or(FieldLocation::Unknown)
    }

    /// Infer a deliberately small container interface without relying on source names or LLVM
    /// aggregate types. The first pointer parameter is the receiver. A pointer parameter is a
    /// payload input when local value flow can carry it to a store through receiver-reachable
    /// memory; a pointer return is a payload output when a receiver-reachable load can reach the
    /// return node. Thin direct wrappers are recognized by the same graph because their
    /// actual-to-formal and return-to-result assignments are already explicit PAG edges.
    ///
    /// To avoid turning every object method into a context family, an operation is enabled only
    /// in a connected family with at least one member called on two independently certified
    /// receiver allocation roots.
    fn infer_receiver_payload_ops(&self) -> HashMap<usize, ReceiverPayloadOp> {
        let mut inferred = HashMap::<usize, ReceiverPayloadOp>::new();
        let mut local_adjacency = HashMap::<usize, Vec<Vec<usize>>>::new();
        let mut local_copy_adjacency = HashMap::<usize, Vec<Vec<usize>>>::new();
        for (function, pir_function) in self.pir.functions.iter().enumerate() {
            if pir_function.external || !self.param_nodes.contains_key(&(function, 0)) {
                continue;
            }
            let receiver = self.param_nodes[&(function, 0)];
            if !self.node_may_carry_pointer(receiver) {
                continue;
            }
            let mut adjacency = vec![Vec::new(); self.n_base];
            let mut copy_adjacency = vec![Vec::new(); self.n_base];
            for edge in &self.pag.edges {
                if !matches!(
                    &edge.owner,
                    pangs_pag::Owner::Function(owner) if owner == &pir_function.key
                ) {
                    continue;
                }
                match edge.kind {
                    EdgeKind::Assign | EdgeKind::Load | EdgeKind::Gep { .. } => {
                        if self.pointer_transfer(edge.src, edge.dst) {
                            adjacency[edge.src.0 as usize].push(edge.dst.0 as usize);
                            if edge.kind == EdgeKind::Assign {
                                copy_adjacency[edge.src.0 as usize].push(edge.dst.0 as usize);
                            }
                        }
                    }
                    _ => {}
                }
            }

            let receiver_reachable = graph_reachable(receiver.0 as usize, &adjacency);
            let mut operation = ReceiverPayloadOp::default();
            for edge in &self.pag.edges {
                if !matches!(
                    &edge.owner,
                    pangs_pag::Owner::Function(owner) if owner == &pir_function.key
                ) {
                    continue;
                }
                if edge.kind == EdgeKind::Store
                    && receiver_reachable.contains(&(edge.dst.0 as usize))
                {
                    for index in 1..pir_function.sig.params.len() {
                        let Some(&parameter) = self.param_nodes.get(&(function, index)) else {
                            continue;
                        };
                        if self.node_may_carry_pointer(parameter)
                            && graph_reachable(parameter.0 as usize, &adjacency)
                                .contains(&(edge.src.0 as usize))
                        {
                            operation
                                .stored_params
                                .entry(index)
                                .or_default()
                                .insert(self.receiver_payload_location(edge.dst));
                        }
                    }
                }
                if edge.kind == EdgeKind::Load
                    && receiver_reachable.contains(&(edge.src.0 as usize))
                {
                    if let Some(&ret) = self.ret_nodes.get(&function) {
                        if graph_reachable(edge.dst.0 as usize, &adjacency)
                            .contains(&(ret.0 as usize))
                        {
                            operation
                                .returned_regions
                                .insert(self.receiver_payload_location(edge.src));
                        }
                    }
                }
            }
            if !operation.stored_params.is_empty() || !operation.returned_regions.is_empty() {
                inferred.insert(function, operation);
            }
            local_adjacency.insert(function, adjacency);
            local_copy_adjacency.insert(function, copy_adjacency);
        }

        // Lift leaf behavior through thin wrappers. This is a small monotone summary fixpoint:
        // if caller.receiver reaches callee.receiver, translate the callee's payload positions
        // back to caller parameters and translate a payload return through the call result.
        loop {
            let mut changed = false;
            for callsite in &self.pag.callsites {
                if callsite.kind != CallKind::Direct {
                    continue;
                }
                let Some(&caller) = self.func_index.get(&callsite.caller) else {
                    continue;
                };
                let Some(callee) = callsite
                    .callee
                    .as_ref()
                    .and_then(|callee| self.func_index.get(callee))
                    .copied()
                else {
                    continue;
                };
                let Some(callee_operation) = inferred.get(&callee).cloned() else {
                    continue;
                };
                let Some(copy_adjacency) = local_copy_adjacency.get(&caller) else {
                    continue;
                };
                let Some(adjacency) = local_adjacency.get(&caller) else {
                    continue;
                };
                let Some(&caller_receiver) = self.param_nodes.get(&(caller, 0)) else {
                    continue;
                };
                let Some(&callee_receiver_actual) = callsite.args.first() else {
                    continue;
                };
                if !graph_reachable(caller_receiver.0 as usize, copy_adjacency)
                    .contains(&(callee_receiver_actual.0 as usize))
                {
                    continue;
                }

                let caller_function = &self.pir.functions[caller];
                let mut lifted = inferred.get(&caller).cloned().unwrap_or_default();
                for (callee_index, regions) in callee_operation.stored_params {
                    let Some(&actual) = callsite.args.get(callee_index) else {
                        continue;
                    };
                    for caller_index in 1..caller_function.sig.params.len() {
                        let Some(&parameter) = self.param_nodes.get(&(caller, caller_index)) else {
                            continue;
                        };
                        if self.node_may_carry_pointer(parameter)
                            && graph_reachable(parameter.0 as usize, copy_adjacency)
                                .contains(&(actual.0 as usize))
                        {
                            let target = lifted.stored_params.entry(caller_index).or_default();
                            let old_len = target.len();
                            target.extend(regions.iter().copied());
                            changed |= target.len() != old_len;
                        }
                    }
                }
                if !callee_operation.returned_regions.is_empty() {
                    if let (Some(result), Some(&ret)) =
                        (callsite.result, self.ret_nodes.get(&caller))
                    {
                        if graph_reachable(result.0 as usize, copy_adjacency)
                            .contains(&(ret.0 as usize))
                        {
                            let old_len = lifted.returned_regions.len();
                            lifted
                                .returned_regions
                                .extend(callee_operation.returned_regions.iter().copied());
                            changed |= lifted.returned_regions.len() != old_len;
                        } else {
                            // The callee may return receiver-owned storage which this wrapper
                            // dereferences before returning a nested payload (for example,
                            // get_entry(map) followed by entry->value). Infer the wrapper's own
                            // load location rather than incorrectly forwarding the callee's
                            // receiver field.
                            let derived = graph_reachable(result.0 as usize, adjacency);
                            for edge in &self.pag.edges {
                                if edge.kind != EdgeKind::Load
                                    || !matches!(
                                        &edge.owner,
                                        pangs_pag::Owner::Function(owner)
                                            if owner == &caller_function.key
                                    )
                                    || !derived.contains(&(edge.src.0 as usize))
                                    || !graph_reachable(edge.dst.0 as usize, copy_adjacency)
                                        .contains(&(ret.0 as usize))
                                {
                                    continue;
                                }
                                changed |= lifted
                                    .returned_regions
                                    .insert(self.receiver_payload_location(edge.src));
                            }
                        }
                    }
                }
                if !lifted.stored_params.is_empty() || !lifted.returned_regions.is_empty() {
                    inferred.insert(caller, lifted);
                }
            }
            if !changed {
                break;
            }
        }

        // Connect inferred operations through direct wrapper/helper calls.
        let mut family_edges = HashMap::<usize, HashSet<usize>>::new();
        for callsite in &self.pag.callsites {
            if callsite.kind != CallKind::Direct {
                continue;
            }
            let Some(&caller) = self.func_index.get(&callsite.caller) else {
                continue;
            };
            let Some(callee) = callsite
                .callee
                .as_ref()
                .and_then(|callee| self.func_index.get(callee))
                .copied()
            else {
                continue;
            };
            if inferred.contains_key(&caller) && inferred.contains_key(&callee) {
                family_edges.entry(caller).or_default().insert(callee);
                family_edges.entry(callee).or_default().insert(caller);
            }
        }

        let mut seed_functions = HashSet::new();
        for (&function, operation) in &inferred {
            let roots =
                self.pag
                    .callsites
                    .iter()
                    .filter(|callsite| {
                        callsite.kind == CallKind::Direct
                            && callsite.callee.as_deref().is_some_and(|callee| {
                                self.func_index.get(callee) == Some(&function)
                            })
                    })
                    .filter_map(|callsite| callsite.args.first())
                    .filter_map(|receiver| self.exact_addresses[receiver.0 as usize])
                    .map(|address| address.root)
                    .collect::<HashSet<_>>();
            if roots.len() >= 2
                && (!operation.stored_params.is_empty() || !operation.returned_regions.is_empty())
            {
                seed_functions.insert(function);
            }
        }

        let mut enabled = seed_functions.clone();
        let mut stack = seed_functions.into_iter().collect::<Vec<_>>();
        while let Some(function) = stack.pop() {
            for &neighbor in family_edges.get(&function).into_iter().flatten() {
                if enabled.insert(neighbor) {
                    stack.push(neighbor);
                }
            }
        }
        inferred.retain(|function, _| enabled.contains(function));

        if andersen_profile_enabled() {
            let mut descriptions = inferred
                .iter()
                .map(|(&function, operation)| {
                    format!(
                        "{}(store={:?},load={})",
                        self.pir.functions[function].key,
                        operation.stored_params,
                        !operation.returned_regions.is_empty()
                    )
                })
                .collect::<Vec<_>>();
            descriptions.sort();
            eprintln!(
                "pangs receiver payloads: inferred={} operations={descriptions:?}",
                descriptions.len()
            );
        }
        inferred
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

    /// Select the source-closed SCC predecessor slice needed by indirect-call operands in one
    /// oversize weak component. Excluded successors keep their Steensgaard rows at the merge
    /// boundary; source closure means no excluded predecessor needs to be under-approximately
    /// reconstructed inside Andersen.
    fn directional_icall_slice(&self, ap: usize) -> Option<HashSet<usize>> {
        let active = (0..self.ap_parent.len())
            .map(|vertex| ap_find_const(&self.ap_parent, vertex) == ap)
            .collect::<Vec<_>>();
        let mut seeds = BTreeMap::<usize, u8>::new();
        for vertex in self
            .pag
            .callsites
            .iter()
            .filter(|callsite| callsite.kind == CallKind::Indirect)
            .filter_map(|callsite| callsite.operand)
            .map(|node| node.0 as usize)
            .filter(|&vertex| active[vertex])
        {
            seeds.insert(vertex, 0);
        }
        if seeds.is_empty() {
            return None;
        }

        let (component_of, component_sizes) = directed_sccs(&active, &self.prepartition_flow_edges);
        let mut predecessors = vec![HashSet::new(); component_sizes.len()];
        // Attribute every edge to its destination SCC. Any admitted component set is
        // predecessor-closed, so selecting a destination SCC also selects the source SCC of
        // every edge attributed to it. The induced edge count is therefore the sum of these
        // weights, without rescanning all flow edges for every candidate closure.
        let mut component_edge_counts = vec![0u64; component_sizes.len()];
        for &(source, destination) in &self.prepartition_flow_edges {
            if !active[source] || !active[destination] {
                continue;
            }
            let source_component = component_of[source];
            let destination_component = component_of[destination];
            component_edge_counts[destination_component] += 1;
            if source_component != destination_component {
                predecessors[destination_component].insert(source_component);
            }
        }

        let seed_count = seeds.len();
        let mut candidates = seeds
            .into_iter()
            .map(|(seed, priority)| {
                let mut closure = HashSet::from([component_of[seed]]);
                let mut stack = vec![component_of[seed]];
                while let Some(component) = stack.pop() {
                    for &predecessor in &predecessors[component] {
                        if closure.insert(predecessor) {
                            stack.push(predecessor);
                        }
                    }
                }
                let nodes = closure
                    .iter()
                    .map(|&component| component_sizes[component])
                    .sum::<usize>();
                (priority, nodes, seed, closure)
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|(priority, nodes, seed, _)| (*priority, *nodes, *seed));

        let mut components = HashSet::new();
        let mut selected_nodes = 0u64;
        let mut selected_edges = 0u64;
        let mut selected_seeds = 0usize;
        for (_, _, _, closure) in candidates {
            let (added_nodes, added_edges) = closure
                .iter()
                .filter(|&&component| !components.contains(&component))
                .fold((0u64, 0u64), |(nodes, edges), &component| {
                    (
                        nodes + component_sizes[component] as u64,
                        edges + component_edge_counts[component],
                    )
                });
            let nodes = selected_nodes + added_nodes;
            let edges = selected_edges + added_edges;
            let cost = nodes.saturating_mul(nodes.saturating_add(edges));
            if cost <= self.budget {
                components.extend(closure);
                selected_nodes = nodes;
                selected_edges = edges;
                selected_seeds += 1;
            }
        }
        if components.is_empty() {
            return None;
        }
        let vertices = active
            .iter()
            .enumerate()
            .filter_map(|(vertex, &active)| {
                (active && components.contains(&component_of[vertex])).then_some(vertex)
            })
            .collect::<HashSet<_>>();
        let nodes = selected_nodes;
        let edges = selected_edges;
        debug_assert_eq!(nodes, vertices.len() as u64);
        let cost = nodes.saturating_mul(nodes.saturating_add(edges));
        if partition_profile_enabled() || admission_profile_enabled() {
            eprintln!(
                "pangs directional admission: root={} total_sccs={} largest_scc={} slice_sccs={} slice_nodes={} slice_edges={} slice_cost={} budget={} admitted={}",
                ap,
                component_sizes.len(),
                component_sizes.iter().copied().max().unwrap_or(0),
                components.len(),
                nodes,
                edges,
                cost,
                self.budget,
                cost <= self.budget
            );
            eprintln!(
                "pangs directional admission: root={} candidate_seeds={} selected_seeds={}",
                ap, seed_count, selected_seeds
            );
        }
        (cost <= self.budget).then_some(vertices)
    }

    /// Build weak components of the actual inclusion constraints, using independent
    /// allocation-relative region vertices for certified memory accesses. This graph is
    /// intentionally not derived from final Steensgaard equivalence classes: those classes
    /// remain the sound fallback and target envelope, but no longer dictate admission size.
    fn build_scope(&mut self) {
        self.ap_parent = (0..self.n_base).collect();
        self.prepartition_regions = vec![None; self.n_base];
        self.prepartition_edge_vertices = vec![None; self.pag.edges.len()];
        self.prepartition_flow_edges.clear();
        let mut regions = HashMap::new();
        let suppressed_payload_bindings = self.receiver_payload_binding_edges();
        // Storage support is directional: a possibly aliased write is a producer
        // of a read, not an equality between their value carriers. Keep certified
        // region-to-region accesses independent; bridge them only when an access
        // lacks a fixed allocation-relative certificate.
        let mut memory_support = BTreeMap::<usize, Vec<(usize, bool, bool)>>::new();

        for (edge_index, edge) in self.pag.edges.iter().enumerate() {
            if suppressed_payload_bindings.contains(&(edge.src, edge.dst)) {
                continue;
            }
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
                match edge.kind {
                    EdgeKind::AddrOf => self.prepartition_flow_edges.push((right, left)),
                    EdgeKind::Assign | EdgeKind::Load => {
                        self.prepartition_flow_edges.push((left, right));
                    }
                    EdgeKind::Store | EdgeKind::Gep { .. } | EdgeKind::Memcpy { .. } => {
                        self.prepartition_flow_edges.push((right, left));
                    }
                }
                // The concrete Andersen implementation still evaluates memory constraints
                // through their address carrier. Retain that dependency even when the
                // allocation-relative storage vertex supplies the payload dependency.
                match edge.kind {
                    EdgeKind::Load if left != src => {
                        self.prepartition_flow_edges.push((src, dst));
                    }
                    EdgeKind::Store if left != dst => {
                        self.prepartition_flow_edges.push((dst, left));
                    }
                    EdgeKind::Memcpy { .. } => {
                        self.prepartition_flow_edges.push((src, left));
                        self.prepartition_flow_edges.push((dst, left));
                        // Both endpoints above are synthetic storage regions, so unlike
                        // every other memory edge this one contributes no value node to
                        // the component. Attach the carriers explicitly, or their
                        // producers stay in an uninteresting partition and the copy is
                        // solved with empty endpoint sets.
                        self.ap_union(src, left);
                        self.ap_union(dst, left);
                    }
                    _ => {}
                }
            }
            self.prepartition_edge_vertices[edge_index] = endpoints;
            if let Some((left, right)) = endpoints {
                let accesses = match edge.kind {
                    EdgeKind::Load => vec![(edge.src, left, false)],
                    EdgeKind::Store => vec![(edge.dst, left, true)],
                    EdgeKind::Memcpy { .. } => {
                        vec![(edge.src, right, false), (edge.dst, left, true)]
                    }
                    _ => Vec::new(),
                };
                for (address, vertex, write) in accesses {
                    let class = self.classes.class_of(address);
                    if let Some(storage) = self.classes.pointee[class] {
                        memory_support.entry(storage).or_default().push((
                            vertex,
                            write,
                            self.exact_addresses[address.0 as usize].is_some(),
                        ));
                    }
                }
            }
        }

        // Two stars per storage envelope encode the producer/consumer join in
        // linear space. The first joins all writers to uncertified readers; the
        // second joins uncertified writers to certified readers. These edges
        // participate in BOTH weak-component admission and SCC predecessor closure.
        let support_start = self.prepartition_flow_edges.len();
        for accesses in memory_support.values() {
            for certified_read in [false, true] {
                let writers = accesses
                    .iter()
                    .filter_map(|&(vertex, write, certified)| {
                        (write && (!certified_read || !certified)).then_some(vertex)
                    })
                    .collect::<BTreeSet<_>>();
                let readers = accesses
                    .iter()
                    .filter_map(|&(vertex, write, certified)| {
                        (!write && certified == certified_read).then_some(vertex)
                    })
                    .collect::<BTreeSet<_>>();
                if writers.is_empty() || readers.is_empty() {
                    continue;
                }
                let hub = self.ap_parent.len();
                self.ap_parent.push(hub);
                self.prepartition_regions.push(None);
                for writer in writers {
                    self.ap_union(writer, hub);
                    self.prepartition_flow_edges.push((writer, hub));
                }
                for reader in readers {
                    self.ap_union(hub, reader);
                    self.prepartition_flow_edges.push((hub, reader));
                }
            }
        }
        let support_edges = self.prepartition_flow_edges[support_start..].to_vec();

        // Receiver-relative payload cells participate in admission, not just in the final
        // inclusion solve. Otherwise a source-closed slice could admit a get while excluding
        // the puts which populate its contextual payload.
        let selected_roots = self.receiver_payload_context_roots();
        let payload_calls = self
            .pag
            .callsites
            .iter()
            .filter_map(|callsite| {
                self.receiver_payload_summary_call(callsite, &selected_roots)
                    .map(|(operation, root)| {
                        (
                            operation.clone(),
                            root,
                            callsite.args.clone(),
                            callsite.result,
                        )
                    })
            })
            .collect::<Vec<_>>();
        let mut payload_vertices = HashMap::<(NodeId, FieldLocation), usize>::new();
        let mut receiver_support_vertices = HashSet::<usize>::new();
        for (operation, root, arguments, result) in payload_calls {
            for (&index, locations) in &operation.stored_params {
                if let Some(argument) = arguments.get(index) {
                    for &location in locations {
                        let payload = receiver_payload_vertex(
                            &mut self.ap_parent,
                            &mut self.prepartition_regions,
                            &mut payload_vertices,
                            root,
                            location,
                        );
                        let argument = argument.0 as usize;
                        // Connect the payload to its bounded allocation origins, not to the
                        // polluted carrier. For incomplete rows the final solve adds an explicit
                        // receiver-local unknown token; no excluded concrete carrier constraint
                        // is needed inside this source-closed slice.
                        let origins = self.receiver_payload_origins[argument]
                            .roots
                            .iter()
                            .copied()
                            .collect::<Vec<_>>();
                        for origin in origins {
                            let field_vertices = self
                                .prepartition_regions
                                .iter()
                                .enumerate()
                                .filter_map(|(vertex, region)| {
                                    region
                                        .is_some_and(|(root, _)| root == origin)
                                        .then_some(vertex)
                                })
                                .collect::<Vec<_>>();
                            for field in field_vertices {
                                self.prepartition_flow_edges.push((field, payload));
                                receiver_support_vertices.insert(field);
                            }
                            let object = origin.0 as usize;
                            self.prepartition_flow_edges.push((object, payload));
                            receiver_support_vertices.insert(object);
                        }
                    }
                }
            }
            for &location in &operation.returned_regions {
                if let Some(result) = result {
                    let payload = receiver_payload_vertex(
                        &mut self.ap_parent,
                        &mut self.prepartition_regions,
                        &mut payload_vertices,
                        root,
                        location,
                    );
                    let result = result.0 as usize;
                    self.ap_union(payload, result);
                    self.prepartition_flow_edges.push((payload, result));
                }
            }
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
                            self.prepartition_flow_edges
                                .push((argument.0 as usize, parameter.0 as usize));
                        }
                    }
                }
                if let (Some(result), Some(&ret)) = (callsite.result, self.ret_nodes.get(&function))
                {
                    if self.pointer_transfer(ret, result) {
                        self.ap_union(ret.0 as usize, result.0 as usize);
                        self.prepartition_flow_edges
                            .push((ret.0 as usize, result.0 as usize));
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
        // Allocation-field initializers supporting a receiver payload remain separate weak
        // components. Admit those components independently instead of merging every payload
        // object into the indirect-call megapartition.
        for vertex in receiver_support_vertices {
            interesting.insert(self.ap_find(vertex));
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
        for (source, _) in support_edges {
            let ap = self.ap_find(source);
            *edges_in.entry(ap).or_insert(0) += 1;
        }
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
        if closed_producers_enabled() || closed_consumers_enabled() {
            let call_partitions = self
                .pag
                .callsites
                .iter()
                .filter(|callsite| callsite.kind == CallKind::Indirect)
                .filter_map(|callsite| callsite.operand)
                .map(|operand| self.ap_find(operand.0 as usize))
                .collect::<HashSet<_>>();
            oversize.retain(|partition| {
                let nodes = nodes_in.get(partition).copied().unwrap_or(0);
                let edges = edges_in.get(partition).copied().unwrap_or(0);
                !call_partitions.contains(partition)
                    || forged_partitions.contains(partition)
                    || nodes > knobs::ANDERSEN_CLOSED_PRODUCER_MAX_NODES
                    || edges > knobs::ANDERSEN_CLOSED_PRODUCER_MAX_EDGES
            });
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

        let directional = oversize
            .iter()
            .filter_map(|&ap| self.directional_icall_slice(ap))
            .flatten()
            .collect::<HashSet<_>>();
        for i in 0..self.n_base {
            let ap = self.ap_find(i);
            self.in_scope[i] =
                (interesting.contains(&ap) && !oversize.contains(&ap)) || directional.contains(&i);
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
                    .map(|row| {
                        if !self.receiver_payload_ops.is_empty() && row.unknown_callee {
                            // In the call-target lattice, unknown is top: it envelopes every
                            // address-taken function, not merely the named targets Steensgaard
                            // happened to retain alongside the unknown bit.
                            self.all_address_taken_non_confined_target_indices()
                        } else {
                            self.non_confined_target_indices(&row.targets)
                        }
                    })
                    .unwrap_or_default();
                envelopes.insert(site, envelope);
                // A Steensgaard unknown-callee verdict means named address flow is not a
                // complete account of possible internal callbacks. Activate the envelope
                // eagerly and retain fallback provenance for this site.
                if !controls.disable_eager_unknown
                    && self.receiver_payload_ops.is_empty()
                    && steens_by_key.get(key).is_some_and(|row| row.unknown_callee)
                {
                    eager_sites.insert(site);
                }
            }
        }

        let mut solve = self.build_base_solve(controls.asymmetric_field_overlap);
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
        if controls.offline_quotient {
            let offline = solve.offline_quotient(&self.offline_late_generators());
            if andersen_profile_enabled() {
                eprintln!(
                    "pangs andersen offline quotient: original_nodes={} original_edges={} quotient_nodes={} quotient_edges_before_factor={} quotient_edges={} static_scc_merges={} substitutions={} value_number_merges={} factored_groups={} factored_edges_removed={} synthetic_nodes={} elapsed_us={}",
                    offline.original_nodes,
                    offline.original_edges,
                    offline.quotient_nodes,
                    offline.quotient_edges_before_factor,
                    offline.quotient_edges,
                    offline.static_scc_merges,
                    offline.substitutions,
                    offline.value_number_merges,
                    offline.factored_groups,
                    offline.factored_edges_removed,
                    offline.synthetic_nodes,
                    offline.elapsed_micros,
                );
            }
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
            let oracle = self.subtractive_oracle(
                &in_scope_sites,
                &envelopes,
                &exact_map,
                controls.offline_quotient,
                controls.asymmetric_field_overlap,
            );
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
                "pangs andersen profile: joint solve done steps={} resume_rounds={} activated_targets={} eager_sites={} pts_entries={} pts_facts={} copy_sources={} copy_edges={} fields={} unknown_fields={} overlap_reads={} overlap_pairs={} overlap_late_replays={} overlap_index_roots={} overlap_index_entries={} overlap_index_capacity_bytes={} chained_field_derivations_exact={} chained_field_derivations_lane={} chain_collapses_missing_exact={} chain_collapses_lane_cap={} chain_collapses_unknown_input={} chain_collapses_arithmetic={} derived_lanes_admitted={} max_lanes_per_root={} roots_reaching_lane_cap={} lane_cap={} memcpy_pairs_processed={} memcpy_logical_pairs_covered={} memcpy_summary_edges_inserted={} memcpy_summary_sites={} memcpy_summary_cells={} copy_fact_pairs_processed={} load_pairs_processed={} store_pairs_processed={} gep_pairs_processed={} scc_passes={} scc_nodes_collapsed={} scc_copy_edges_removed={}",
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
                solve.overlap_read_dependencies,
                solve.overlap_read_pairs,
                solve.overlap_read_late_replays,
                solve.overlap_reads.len(),
                solve.overlap_reads.values().map(Vec::len).sum::<usize>(),
                solve.overlap_read_index_bytes(),
                solve.chained_exact_field_derivations,
                solve.chained_lane_field_derivations,
                solve.chain_missing_exact_collapses,
                solve.chain_lane_cap_collapses,
                solve.chain_unknown_input_collapses,
                solve.chain_arithmetic_collapses,
                solve.derived_lanes_admitted,
                solve.max_lanes_per_root,
                solve.roots_reaching_lane_cap,
                solve.lane_cap.unwrap_or(0),
                solve.memcpy_pairs_processed,
                solve.memcpy_logical_pairs_covered,
                solve.memcpy_summary_edges_inserted,
                solve.memcpy_summary_sites,
                solve.memcpy_summary_cells_allocated,
                solve.copy_fact_pairs_processed,
                solve.load_pairs_processed,
                solve.store_pairs_processed,
                solve.gep_pairs_processed,
                solve.scc_passes,
                solve.scc_nodes_collapsed,
                solve.scc_copy_edges_removed,
            );
        }
        if std::env::var_os(knobs::ENV_ANDERSEN_HYBRID_BITSETS_PROFILE).is_some() {
            let (hash_sets, small_sets, sparse_sets, dense_sets, dense_words) =
                solve.point_set_storage();
            eprintln!(
                "pangs hybrid bitsets: hash_sets={hash_sets} small_sets={small_sets} sparse_sets={sparse_sets} dense_sets={dense_sets} dense_words={dense_words} dense_bytes={}",
                dense_words.saturating_mul(std::mem::size_of::<u64>())
            );
        }
        print_process_memory("andersen-fixed-point", Some(&solve), None);
        let indirect_calls = self.emit_indirect_calls(
            &in_scope_sites,
            &activated,
            &eager_sites,
            &solve,
            controls.closed_producers,
        );
        let closed_consumers = if controls.closed_consumers {
            self.closed_consumer_certificates(&solve)
        } else {
            BTreeSet::new()
        };
        // Call-target discovery and the optional producer/consumer certificates are the only
        // result families that inspect propagation constraints. Keep just the fixed-point query
        // tables while materializing per-node and global outputs, so those outputs do not overlap
        // with copy/load/store/GEP graphs that can be very large on linked applications.
        solve.release_propagation_state();
        print_process_memory("andersen-query-state", Some(&solve), None);
        let (nodes, coarser_than_steens_nodes) = self.emit_node_resolutions(&solve);
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
                memcpy_logical_pairs_covered: solve.memcpy_logical_pairs_covered,
                memcpy_summary_edges_inserted: solve.memcpy_summary_edges_inserted,
                memcpy_summary_sites: solve.memcpy_summary_sites,
                memcpy_summary_cells: solve.memcpy_summary_cells_allocated,
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
        let output = RefinerOutput {
            indirect_calls,
            closed_consumers,
            nodes,
            global_points_to,
            resume_rounds,
            steps: solve.steps,
            activated_targets,
            oversize_fallbacks: self.oversize_fallbacks,
            oversize_fallback_max_size: self.oversize_fallback_max_size,
            coarser_than_steens_nodes,
        };
        // `self` owns Andersen's prepartition/scope tables and `solve` owns the remaining
        // fixed-point query state. Drop both before `finish_andersen_controlled` folds `output`
        // into the public SolveResult, then make the freed pages available to downstream ModRef.
        drop(solve);
        drop(self);
        RefinerOutcome::Complete(output)
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
            pending_pts_deltas: solve.pending_pts.values().map(PointSet::len).sum(),
            known_unbound_targets,
            activated_targets,
            scc_passes: solve.scc_passes,
            scc_nodes_collapsed: solve.scc_nodes_collapsed,
            scc_copy_edges_removed: solve.scc_copy_edges_removed,
            memcpy_pairs_processed: solve.memcpy_pairs_processed,
            memcpy_logical_pairs_covered: solve.memcpy_logical_pairs_covered,
            memcpy_summary_edges_inserted: solve.memcpy_summary_edges_inserted,
            memcpy_summary_sites: solve.memcpy_summary_sites,
            memcpy_summary_cells: solve.memcpy_summary_cells_allocated,
            copy_fact_pairs_processed: solve.copy_fact_pairs_processed,
            oversize_fallbacks: self.oversize_fallbacks,
            oversize_fallback_max_size: self.oversize_fallback_max_size,
        }
    }

    // ----- the persistent inclusion solve -----------------------------------------------

    fn build_base_solve(&mut self, asymmetric_field_overlap: bool) -> Solve {
        let profile = andersen_profile_enabled();
        let mut solve = Solve::new_with_pwc_and_overlap(
            self.n_base,
            profile,
            self.pag.pwc_lanes_enabled,
            asymmetric_field_overlap,
        );
        solve.known_locations.extend(
            self.exact_addresses
                .iter()
                .flatten()
                .map(|address| address.location),
        );

        let suppressed_payload_bindings = self.receiver_payload_binding_edges();

        // Base constraints from PAG edges (in-scope only; partitions are self-contained).
        for edge in &self.pag.edges {
            if !self.in_scope[edge.dst.0 as usize] && !self.in_scope[edge.src.0 as usize] {
                continue;
            }
            if suppressed_payload_bindings.contains(&(edge.src, edge.dst)) {
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
        self.apply_receiver_payload_summaries(&mut solve);

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

    /// Actual/formal payload bindings which the experimental receiver-relative summary replaces.
    /// Receiver and key/control parameters retain their ordinary context-insensitive bindings.
    fn receiver_payload_binding_edges(&self) -> HashSet<(NodeId, NodeId)> {
        let mut suppressed = HashSet::new();
        let selected_roots = self.receiver_payload_context_roots();
        for callsite in &self.pag.callsites {
            let Some((operation, _)) =
                self.receiver_payload_summary_call(callsite, &selected_roots)
            else {
                continue;
            };
            let function = self.func_index[callsite.callee.as_ref().unwrap()];
            for &index in operation.stored_params.keys() {
                if let (Some(&argument), Some(&parameter)) = (
                    callsite.args.get(index),
                    self.param_nodes.get(&(function, index)),
                ) {
                    suppressed.insert((argument, parameter));
                }
            }
            if !operation.returned_regions.is_empty() {
                if let (Some(&ret), Some(result)) = (self.ret_nodes.get(&function), callsite.result)
                {
                    suppressed.insert((ret, result));
                }
            }
        }
        suppressed
    }

    fn receiver_payload_context_roots(&self) -> HashSet<NodeId> {
        let mut profiles = HashMap::<NodeId, (usize, usize, usize)>::new();
        for callsite in self.pag.callsites.iter().filter(|callsite| {
            callsite.kind == CallKind::Direct
                && !self
                    .func_index
                    .get(&callsite.caller)
                    .is_some_and(|caller| self.receiver_payload_ops.contains_key(caller))
        }) {
            let Some((root, operation)) = (|| {
                let function = callsite
                    .callee
                    .as_ref()
                    .and_then(|callee| self.func_index.get(callee))?;
                let operation = self.receiver_payload_ops.get(function)?;
                let receiver = *callsite.args.first()?;
                let root = self.exact_addresses[receiver.0 as usize]?.root;
                Some((root, operation))
            })() else {
                continue;
            };
            let profile = profiles.entry(root).or_default();
            profile.0 += usize::from(!operation.stored_params.is_empty());
            profile.1 += usize::from(!operation.returned_regions.is_empty());
            profile.2 += 1;
        }
        let mut roots = profiles.into_iter().collect::<Vec<_>>();
        // Prefer receiver roots observed at both updates and lookups, then hot roots. This makes
        // the bounded contexts useful without depending on allocation numbering.
        roots.sort_by_key(|(root, (stores, loads, calls))| {
            (
                std::cmp::Reverse(usize::from(*stores > 0 && *loads > 0)),
                std::cmp::Reverse(*calls),
                root.0,
            )
        });
        roots.truncate(knobs::ANDERSEN_RECEIVER_PAYLOAD_CONTEXT_LIMIT);
        roots.into_iter().map(|(root, _)| root).collect()
    }

    fn receiver_payload_summary_call<'b>(
        &'b self,
        callsite: &pangs_pag::Callsite,
        selected_roots: &HashSet<NodeId>,
    ) -> Option<(&'b ReceiverPayloadOp, NodeId)> {
        if callsite.kind != CallKind::Direct
            || self
                .func_index
                .get(&callsite.caller)
                .is_some_and(|caller| self.receiver_payload_ops.contains_key(caller))
        {
            return None;
        }
        let function = callsite
            .callee
            .as_ref()
            .and_then(|callee| self.func_index.get(callee))?;
        let operation = self.receiver_payload_ops.get(function)?;
        let receiver = *callsite.args.first()?;
        let root = self.exact_addresses[receiver.0 as usize]?.root;
        selected_roots.contains(&root).then_some((operation, root))
    }

    fn apply_receiver_payload_summaries(&self, solve: &mut Solve) {
        if self.receiver_payload_ops.is_empty() {
            return;
        }

        let selected_roots = self.receiver_payload_context_roots();
        let mut payload_cells = HashMap::<(NodeId, FieldLocation), Cell>::new();
        // Receiver payloads are synthetic allocation-relative storage.  They deliberately
        // stay out of `Solve::field_of` (receiver roots are PAG nodes, not object cells),
        // but use the identical direct-overlap read interpretation when C is enabled.
        let mut payload_reads = HashMap::<NodeId, Vec<(FieldLocation, Cell)>>::new();

        let mut summarized_calls = 0usize;
        let mut singleton_payloads = 0usize;
        let mut multi_payloads = 0usize;
        let mut incomplete_payloads = 0usize;
        let mut origin_facts = 0usize;
        let mut context_profiles =
            HashMap::<(NodeId, FieldLocation), (usize, usize, BTreeSet<NodeId>)>::new();
        for callsite in &self.pag.callsites {
            let Some((operation, root)) =
                self.receiver_payload_summary_call(callsite, &selected_roots)
            else {
                continue;
            };
            for (&index, locations) in &operation.stored_params {
                if let Some(argument) = callsite.args.get(index) {
                    if self.node_may_carry_pointer(*argument) {
                        for &location in locations {
                            let payload =
                                if let Some(&payload) = payload_cells.get(&(root, location)) {
                                    payload
                                } else {
                                    let payload = solve.allocate_cell();
                                    payload_cells.insert((root, location), payload);
                                    solve
                                        .receiver_payload_fields
                                        .entry(root.0)
                                        .or_default()
                                        .push(payload);
                                    payload
                                };
                            let origins = &self.receiver_payload_origins[argument.0 as usize];
                            for &origin in &origins.roots {
                                solve.add_pts(payload, origin.0);
                            }
                            origin_facts += origins.roots.len();
                            if origins.complete {
                                if origins.roots.len() <= 1 {
                                    singleton_payloads += 1;
                                } else {
                                    multi_payloads += 1;
                                }
                            } else {
                                incomplete_payloads += 1;
                                let unknown =
                                    solve.region(ExternalRegion::ReceiverPayload(payload));
                                solve.add_pts_with_source(
                                    payload,
                                    unknown,
                                    Some("omega:receiver_payload_origin_overflow"),
                                );
                            }
                            let profile = context_profiles.entry((root, location)).or_default();
                            profile.0 += usize::from(origins.complete);
                            profile.1 += usize::from(!origins.complete);
                            profile.2.extend(origins.roots.iter().copied());
                        }
                    }
                }
            }
            for &location in &operation.returned_regions {
                if let Some(result) = callsite.result {
                    if self.node_may_carry_pointer(result) {
                        let payload = if let Some(&payload) = payload_cells.get(&(root, location)) {
                            payload
                        } else {
                            let payload = solve.allocate_cell();
                            payload_cells.insert((root, location), payload);
                            solve
                                .receiver_payload_fields
                                .entry(root.0)
                                .or_default()
                                .push(payload);
                            payload
                        };
                        if solve.asymmetric_field_overlap {
                            let reads = payload_reads.entry(root).or_default();
                            if !reads.contains(&(location, result.0)) {
                                reads.push((location, result.0));
                            }
                        } else {
                            solve.add_copy(payload, result.0);
                        }
                    }
                }
            }
            summarized_calls += 1;
        }
        if solve.asymmetric_field_overlap {
            for (root, reads) in payload_reads {
                for (read_location, destination) in reads {
                    for (&(payload_root, payload_location), &payload) in &payload_cells {
                        if payload_root == root && read_location.may_alias(payload_location) {
                            solve.add_copy(payload, destination);
                        }
                    }
                }
            }
        }
        if andersen_profile_enabled() {
            let mut context_labels = selected_roots
                .iter()
                .map(|root| self.pag.nodes[root.0 as usize].label.clone())
                .collect::<Vec<_>>();
            context_labels.sort();
            eprintln!(
                "pangs receiver payloads: contexts={} summarized_calls={} singleton_payloads={} multi_payloads={} incomplete_payloads={} origin_facts={} roots={context_labels:?}",
                selected_roots.len(),
                summarized_calls,
                singleton_payloads,
                multi_payloads,
                incomplete_payloads,
                origin_facts
            );
            let mut profiles = context_profiles.into_iter().collect::<Vec<_>>();
            profiles.sort_by_key(|((root, location), _)| (root.0, *location));
            for ((root, location), (complete, incomplete, origins)) in profiles {
                let sample = origins
                    .iter()
                    .take(12)
                    .map(|origin| self.pag.nodes[origin.0 as usize].label.clone())
                    .collect::<Vec<_>>();
                eprintln!(
                    "pangs receiver payload origins: receiver={} location={location:?} complete_rows={} incomplete_rows={} distinct_origins={} sample={sample:?}",
                    self.pag.nodes[root.0 as usize].label,
                    complete,
                    incomplete,
                    origins.len()
                );
            }
        }
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

    /// Cells which can acquire an independent generator after base construction. Static
    /// load/GEP destinations and seeded allocation identities are added by `Solve`; this
    /// supplies the call-graph-dependent remainder.
    fn offline_late_generators(&self) -> HashSet<Cell> {
        let mut protected = self
            .pag
            .nodes
            .iter()
            .filter(|node| matches!(node.kind, NodeKind::Object { .. }))
            .map(|node| node.id.0)
            .collect::<HashSet<_>>();
        protected.extend(self.param_nodes.values().map(|node| node.0));
        protected.extend(
            self.pag
                .callsites
                .iter()
                .filter_map(|callsite| callsite.result.map(|node| node.0)),
        );
        protected
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
        offline_quotient: bool,
        asymmetric_field_overlap: bool,
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
            let mut solve = self.build_base_solve(asymmetric_field_overlap);
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
            if offline_quotient {
                solve.offline_quotient(&self.offline_late_generators());
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
                        let root = solve.field_base.get(&cell).copied().unwrap_or(cell);
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
            for cell in points_to {
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
                // The list contents are opaque, but the list address itself is not published:
                // this stores one external region *through* the address without making the
                // address a boundary root. Every external region already contains itself, so a
                // multi-level `va_arg` extraction keeps yielding the region.
                (OmegaSeedKind::VarargListPayload, SeedTarget::Node(id)) => self
                    .seed_unknown_store_through(
                        solve,
                        id,
                        ExternalRegion::VarargPayload(id.0),
                        omega_seed_source(seed.kind),
                    ),
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

    fn all_address_taken_non_confined_target_indices(&self) -> Vec<usize> {
        let mut functions = self
            .fn_cell_to_index
            .values()
            .copied()
            .filter(|function| {
                !self
                    .confined_targets
                    .contains(&self.pir.functions[*function].key)
            })
            .collect::<Vec<_>>();
        functions.sort_unstable();
        functions.dedup();
        functions
    }

    fn target_indices<'b>(&self, targets: impl Iterator<Item = &'b str>) -> Vec<usize> {
        let mut funcs: Vec<usize> = targets
            .filter_map(|target| self.func_index.get(target).copied())
            .collect();
        funcs.sort_unstable();
        funcs.dedup();
        funcs
    }

    fn closed_producer_analysis(&self, solve: &Solve) -> ClosedProducerAnalysis {
        let node_count = solve.next_field as usize;
        // Receiver payload cells are allocation-relative synthetic storage outside the
        // ordinary field inventory. Until their overlap projection is represented in this
        // certificate graph, never use the producer certificate to clear an unknown bit.
        if solve.asymmetric_field_overlap && !self.receiver_payload_ops.is_empty() {
            return ClosedProducerAnalysis {
                complete: vec![false; node_count],
            };
        }
        let mut dependencies = Vec::<(usize, usize)>::new();
        let mut terminal = vec![false; node_count];
        let mut explicit_open = vec![false; node_count];
        let mut has_producer = vec![false; node_count];

        // Propagation-only memcpy summaries are outside the producer graph's declared
        // PAG/allocation-relative domain. If SCC canonicalization makes one visible through
        // a real cell, failing that component open is conservative.
        for &summary in &solve.memcpy_summary_cells {
            explicit_open[solve.canonical(summary) as usize] = true;
        }

        let mut add_dependency = |source: Cell, destination: Cell| {
            let source = solve.canonical(source) as usize;
            let destination = solve.canonical(destination) as usize;
            if source != destination {
                dependencies.push((source, destination));
            }
        };

        for node in &self.pag.nodes {
            let index = solve.canonical(node.id.0) as usize;
            let exact_address = self.exact_addresses[node.id.0 as usize].is_some();
            if !self.in_scope[node.id.0 as usize] && !exact_address {
                explicit_open[index] = true;
            }
            if exact_address
                || matches!(
                    node.label.rsplit(':').next(),
                    Some("null") | Some("0") | Some("zeroinitializer")
                )
            {
                terminal[index] = true;
                has_producer[index] = true;
            }
        }

        // An external-region pointee is an explicit missing producer. This includes unknown
        // call results and unknown stores that the Andersen solve has propagated into a
        // concrete allocation-relative cell.
        for cell in 0..solve.next_field {
            if solve.points_to(cell).is_some_and(|points_to| {
                points_to
                    .iter()
                    .any(|pointee| solve.external_region(pointee).is_some())
            }) {
                explicit_open[solve.canonical(cell) as usize] = true;
            }
        }

        for edge in &self.pag.edges {
            match edge.kind {
                EdgeKind::AddrOf => {
                    let destination = solve.canonical(edge.dst.0) as usize;
                    terminal[destination] = true;
                    has_producer[destination] = true;
                }
                EdgeKind::Assign | EdgeKind::Gep { .. } => {
                    if self.pointer_transfer(edge.src, edge.dst) {
                        add_dependency(edge.src.0, edge.dst.0);
                    }
                }
                EdgeKind::Load => {
                    let destination = solve.canonical(edge.dst.0) as usize;
                    let Some(objects) = solve.points_to(edge.src.0) else {
                        explicit_open[destination] = true;
                        continue;
                    };
                    if objects.is_empty() {
                        explicit_open[destination] = true;
                        continue;
                    }
                    add_dependency(edge.src.0, edge.dst.0);
                    for object in objects {
                        if solve.external_region(object).is_some() {
                            explicit_open[destination] = true;
                        } else {
                            for source in solve.overlap_read_cells(object) {
                                add_dependency(source, edge.dst.0);
                            }
                        }
                    }
                }
                EdgeKind::Store => {
                    let Some(objects) = solve.points_to(edge.dst.0) else {
                        continue;
                    };
                    for object in objects {
                        if solve.external_region(object).is_some() {
                            continue;
                        }
                        // The address is a guard dependency: a missing address producer could
                        // hide another store destination even if the stored value is closed.
                        add_dependency(edge.dst.0, object);
                        add_dependency(edge.src.0, object);
                    }
                }
                EdgeKind::Memcpy { .. } => {
                    let destinations = solve
                        .memcpy_logical_endpoints(edge.dst.0, edge.src.0)
                        .map(|(destinations, _)| destinations)
                        .unwrap_or_else(|| {
                            solve
                                .points_to(edge.dst.0)
                                .map(|set| set.iter().collect())
                                .unwrap_or_default()
                        });
                    for destination in destinations {
                        // C bulk writes project an exact endpoint to the whole destination
                        // allocation. Keep the raw endpoint for the logical audit, but make
                        // every actual root/field content cell incomplete here.
                        let destination = if solve.asymmetric_field_overlap {
                            solve.allocation_root(destination)
                        } else {
                            destination
                        };
                        if solve.external_region(destination).is_some() {
                            continue;
                        }
                        explicit_open[solve.canonical(destination) as usize] = true;
                        for field in solve.content_fields(destination) {
                            explicit_open[solve.canonical(field) as usize] = true;
                        }
                    }
                }
            }
        }

        dependencies.sort_unstable();
        dependencies.dedup();
        for &(_, destination) in &dependencies {
            has_producer[destination] = true;
        }
        for index in 0..node_count {
            if !has_producer[index] && !terminal[index] {
                explicit_open[index] = true;
            }
        }

        let active = vec![true; node_count];
        let (component_of, component_sizes) = directed_sccs(&active, &dependencies);
        let mut component_open = vec![false; component_sizes.len()];
        let mut component_terminal = vec![false; component_sizes.len()];
        let mut component_has_predecessor = vec![false; component_sizes.len()];
        let mut component_successors = vec![Vec::<usize>::new(); component_sizes.len()];
        for index in 0..node_count {
            let component = component_of[index];
            component_open[component] |= explicit_open[index];
            component_terminal[component] |= terminal[index];
        }
        for &(source, destination) in &dependencies {
            let source = component_of[source];
            let destination = component_of[destination];
            if source != destination {
                component_successors[source].push(destination);
                component_has_predecessor[destination] = true;
            }
        }
        for successors in &mut component_successors {
            successors.sort_unstable();
            successors.dedup();
        }
        // A producer cycle with neither a terminal nor an incoming producer is not evidence
        // of a value. Mark it open before propagating open predecessors through the DAG.
        for component in 0..component_sizes.len() {
            if !component_terminal[component] && !component_has_predecessor[component] {
                component_open[component] = true;
            }
        }
        let mut worklist = component_open
            .iter()
            .enumerate()
            .filter_map(|(component, &open)| open.then_some(component))
            .collect::<Vec<_>>();
        while let Some(component) = worklist.pop() {
            for &successor in &component_successors[component] {
                if !component_open[successor] {
                    component_open[successor] = true;
                    worklist.push(successor);
                }
            }
        }
        let complete = component_of
            .iter()
            .map(|&component| !component_open[component])
            .collect();
        eprintln!(
            "pangs closed producer graph: nodes={} dependencies={} components={} open_components={}",
            node_count,
            dependencies.len(),
            component_sizes.len(),
            component_open.iter().filter(|&&open| open).count()
        );
        ClosedProducerAnalysis { complete }
    }

    fn query_closed_producer(
        &self,
        analysis: &ClosedProducerAnalysis,
        solve: &Solve,
        operand: NodeId,
    ) -> ClosedProducerQuery {
        let complete = analysis.complete[solve.canonical(operand.0) as usize];
        let mut targets = Vec::new();
        let mut external = false;
        let mut non_function = false;
        if let Some(points_to) = solve.points_to(operand.0) {
            for cell in points_to {
                if solve.external_region(cell).is_some() {
                    external = true;
                    continue;
                }
                let root = solve.field_base.get(&cell).copied().unwrap_or(cell);
                if let Some(&function) = self.fn_cell_to_index.get(&root) {
                    targets.push(function);
                } else {
                    non_function = true;
                }
            }
        }
        targets.sort_unstable();
        targets.dedup();
        ClosedProducerQuery {
            complete,
            targets,
            external,
            non_function,
        }
    }

    /// Prove that an address-taken internal function has no unknown incoming caller.
    ///
    /// This is the forward dual of the closed-producer query. The completed inclusion solve
    /// already materializes every admitted value and memory cell that may contain a named
    /// function object. We audit every boundary consumer and every fixed PAG transfer, rather
    /// than running one graph search per function:
    ///
    /// * an indirect-call operand is a safe terminal (it invokes the value inside the module);
    /// * internal copies, calls, loads, stores, and memcpy joins are safe only when the final
    ///   solve contains the corresponding named-function fact at every destination;
    /// * external/vararg arguments, exported or opaque storage, pointer/integer escapes, and
    ///   externally callable returns are open terminals.
    ///
    /// The result is demand-bounded by the named-function facts already present in admitted
    /// partitions. If an address seed or transfer was cut from the solve, its function fails
    /// closed instead of triggering a module-wide address solve.
    fn closed_consumer_certificates(&self, solve: &Solve) -> BTreeSet<String> {
        // See the producer-side note above.  This is deliberately a coverage loss, not an
        // unsound claim about a receiver-local payload that has not been made overlap-aware.
        if solve.asymmetric_field_overlap && !self.receiver_payload_ops.is_empty() {
            return BTreeSet::new();
        }
        let mut seeded = vec![false; self.pir.functions.len()];
        let mut open = vec![false; self.pir.functions.len()];
        let mut boundary_roots = HashSet::<Cell>::new();

        let functions_in = |cell: Cell| {
            solve
                .points_to(cell)
                .into_iter()
                .flat_map(|points_to| points_to.iter())
                .filter_map(|cell| {
                    let root = solve.field_base.get(&cell).copied().unwrap_or(cell);
                    self.fn_cell_to_index.get(&root).copied()
                })
                .collect::<BTreeSet<_>>()
        };
        let functions_read = |cell: Cell| {
            solve
                .overlap_read_cells(cell)
                .into_iter()
                .flat_map(|source| functions_in(source))
                .collect::<BTreeSet<_>>()
        };

        let mark_open = |functions: BTreeSet<usize>, open: &mut [bool]| {
            for function in functions {
                open[function] = true;
            }
        };

        // Every concrete `&function` producer must be represented in the admitted solve.
        // Otherwise the consumer inventory is incomplete for that function.
        for edge in &self.pag.edges {
            if edge.kind != EdgeKind::AddrOf {
                continue;
            }
            let Some(&function) = self.fn_cell_to_index.get(&edge.src.0) else {
                continue;
            };
            seeded[function] = true;
            if !functions_in(edge.dst.0).contains(&function) {
                open[function] = true;
            }
        }

        // Audit transfer completeness. A missing destination fact means the relevant path
        // crossed an admission boundary and cannot be certified by this bounded solve.
        for edge in &self.pag.edges {
            match edge.kind {
                EdgeKind::AddrOf => {}
                EdgeKind::Assign => {
                    let source = functions_in(edge.src.0);
                    let destination = functions_in(edge.dst.0);
                    for function in source.difference(&destination) {
                        open[*function] = true;
                    }
                }
                EdgeKind::Gep { .. } => {
                    // Arithmetic on a function address is outside the supported consumer
                    // grammar. GEPs used only to address storage do not themselves contain
                    // the function stored in that storage.
                    mark_open(functions_in(edge.src.0), &mut open);
                }
                EdgeKind::Load => {
                    // Treating a function address as the address operand is unsupported.
                    mark_open(functions_in(edge.src.0), &mut open);
                    let Some(objects) = solve.points_to(edge.src.0) else {
                        continue;
                    };
                    let destination = functions_in(edge.dst.0);
                    for object in objects {
                        if solve.is_external(object) {
                            continue;
                        }
                        for function in functions_read(object).difference(&destination) {
                            open[*function] = true;
                        }
                    }
                }
                EdgeKind::Store => {
                    // Treating a function address as the address operand is unsupported.
                    mark_open(functions_in(edge.dst.0), &mut open);
                    let source = functions_in(edge.src.0);
                    if source.is_empty() {
                        continue;
                    }
                    let Some(objects) = solve.points_to(edge.dst.0) else {
                        mark_open(source, &mut open);
                        continue;
                    };
                    if objects.is_empty() {
                        mark_open(source, &mut open);
                        continue;
                    }
                    for object in objects {
                        if solve.is_external(object) {
                            mark_open(source.clone(), &mut open);
                            continue;
                        }
                        let destination = functions_in(object);
                        for function in source.difference(&destination) {
                            open[*function] = true;
                        }
                    }
                }
                EdgeKind::Memcpy { .. } => {
                    mark_open(functions_in(edge.src.0), &mut open);
                    mark_open(functions_in(edge.dst.0), &mut open);
                    let Some((destinations, sources)) =
                        solve.memcpy_logical_endpoints(edge.dst.0, edge.src.0)
                    else {
                        // Missing join metadata makes the represented transfer inventory
                        // incomplete. Fail every function currently visible at the source
                        // storage open rather than clearing an unknown-caller bit.
                        if let Some(sources) = solve.points_to(edge.src.0) {
                            for source in sources {
                                let source = if solve.asymmetric_field_overlap {
                                    solve.allocation_root(source)
                                } else {
                                    source
                                };
                                let copied = solve
                                    .overlap_read_cells(source)
                                    .into_iter()
                                    .flat_map(|source| functions_in(source))
                                    .collect::<BTreeSet<_>>();
                                mark_open(copied, &mut open);
                            }
                        }
                        continue;
                    };
                    for source in sources {
                        // C's bulk operation projects a field endpoint to its owning
                        // allocation before reading: memcpy(base + 0, ..., 16) may carry a
                        // pointer from byte 8. The old path remains raw-endpoint based.
                        let source = if solve.asymmetric_field_overlap {
                            solve.allocation_root(source)
                        } else {
                            source
                        };
                        let copied = solve
                            .overlap_read_cells(source)
                            .into_iter()
                            .flat_map(|source| functions_in(source))
                            .collect::<BTreeSet<_>>();
                        for &destination in &destinations {
                            let destination = if solve.asymmetric_field_overlap {
                                solve.allocation_root(destination)
                            } else {
                                destination
                            };
                            if solve.is_external(destination) {
                                mark_open(copied.clone(), &mut open);
                                continue;
                            }
                            let received = functions_in(destination);
                            for function in copied.difference(&received) {
                                open[*function] = true;
                            }
                        }
                    }
                }
            }
        }

        // External regions model foreign storage. Anything recursively reachable from one
        // can be retained and invoked outside the module.
        for &region in solve.region_of_cell.keys() {
            boundary_roots.insert(region);
        }

        for seed in &self.pag.omega_seeds {
            match (seed.kind, seed.target) {
                (
                    OmegaSeedKind::ExportedSymbol
                    | OmegaSeedKind::ImportedSymbol
                    | OmegaSeedKind::PtrToInt
                    | OmegaSeedKind::UnknownOperandEscape,
                    SeedTarget::Node(node),
                ) => {
                    if let Some(&function) = self.fn_cell_to_index.get(&node.0) {
                        open[function] = true;
                    }
                    boundary_roots.insert(node.0);
                }
                (OmegaSeedKind::ExternalCallBoundary, SeedTarget::Callsite(id)) => {
                    if let Some(callsite) = self.pag.callsites.get(id.0 as usize) {
                        for &argument in &callsite.args {
                            boundary_roots.insert(argument.0);
                        }
                    }
                }
                (OmegaSeedKind::VarargCallBoundary, SeedTarget::Callsite(id)) => {
                    if let Some(callsite) = self.pag.callsites.get(id.0 as usize) {
                        for &argument in callsite.args.iter().skip(callsite.sig.params.len()) {
                            boundary_roots.insert(argument.0);
                        }
                    }
                }
                _ => {}
            }
        }

        // A pointer returned by a function which still has an unknown caller can leave the
        // module. This is deliberately not a mutual proof: recursive removal would require
        // a separate greatest-fixed-point argument.
        for node in &self.pag.nodes {
            if let NodeKind::Return { func } = &node.kind {
                if self.base.unknown_callers.contains(func) {
                    boundary_roots.insert(node.id.0);
                }
            }
        }

        // Traverse all boundary-reachable storage in one shared pass. This avoids a
        // boundary-count × graph-size cost and makes the proof linear in the retained
        // points-to graph plus its materialized field inventory.
        let mut seen = HashSet::new();
        let mut pending = boundary_roots.into_iter().collect::<Vec<_>>();
        while let Some(cell) = pending.pop() {
            // Keep the raw storage identity here. A copy SCC representative describes its
            // content variable, not which allocation's materialized fields an external
            // caller may inspect.
            if !seen.insert(cell) {
                continue;
            }
            let root = solve.allocation_root(cell);
            if !solve.is_external(cell) {
                // Do this before inspecting raw contents: a directly exported global root
                // may have no root-cell payload while a materialized field holds a callback.
                if cell == root {
                    pending.extend(solve.content_fields(root));
                }
            }
            let Some(points_to) = solve.points_to(cell) else {
                continue;
            };
            for pointee in points_to {
                let root = solve.field_base.get(&pointee).copied().unwrap_or(pointee);
                if let Some(&function) = self.fn_cell_to_index.get(&root) {
                    open[function] = true;
                } else if !solve.is_external(pointee) {
                    pending.push(pointee);
                    // A boundary receiving an allocation address may inspect any of its
                    // materialized fields. Field cells are content variables rather than
                    // ordinary points-to successors, so include them explicitly.
                    pending.extend(solve.content_fields(root));
                }
            }
        }

        let certified = self
            .pir
            .functions
            .iter()
            .enumerate()
            .filter(|(function, metadata)| {
                !metadata.external
                    && seeded[*function]
                    && !open[*function]
                    && self.base.unknown_callers.contains(&metadata.key)
            })
            .map(|(_, metadata)| metadata.key.clone())
            .collect::<BTreeSet<_>>();
        eprintln!(
            "pangs closed consumers: address_seeded={} base_unknown={} certified={}",
            seeded.iter().filter(|&&value| value).count(),
            self.base.unknown_callers.len(),
            certified.len()
        );
        certified
    }

    fn emit_indirect_calls(
        &self,
        in_scope_sites: &[usize],
        activated: &HashMap<usize, BTreeSet<usize>>,
        eager_sites: &HashSet<usize>,
        pts: &Solve,
        closed_producers_enabled: bool,
    ) -> Vec<IndirectCallResolution> {
        let in_scope: HashSet<usize> = in_scope_sites.iter().copied().collect();
        let closed_producers = closed_producers_enabled.then(|| self.closed_producer_analysis(pts));
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
                if let Some(steens) = steens.filter(|steens| !steens.unknown_callee) {
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
                        set.iter().any(|cell| {
                            pts.external_region(cell)
                                .is_some_and(ExternalRegion::may_contain_function_pointer)
                        })
                    });
                let exact = self.exact_targets.contains_key(&cs.key);
                let mut fallback = !exact && eager_sites.contains(&idx);
                let steens_unknown = steens.map(|r| r.unknown_callee).unwrap_or(false);
                let mut unknown_callee =
                    if !self.receiver_payload_ops.is_empty() && !pts.asymmetric_field_overlap {
                        operand_unknown || (targets.is_empty() && steens_unknown)
                    } else {
                        steens_unknown || operand_unknown
                    };
                if let (Some(analysis), Some(operand)) = (&closed_producers, cs.operand) {
                    let certificate = self.query_closed_producer(analysis, pts, operand);
                    let certified = certificate.complete
                        && !certificate.external
                        && !certificate.non_function
                        && !certificate.targets.is_empty();
                    if certified {
                        targets = certificate
                            .targets
                            .iter()
                            .map(|&function| self.pir.functions[function].key.clone())
                            .collect();
                        targets.sort();
                        if let Some(steens) = steens {
                            debug_assert_narrows(
                                &cs.key,
                                "closed-producer",
                                &targets,
                                "steens",
                                &steens.targets,
                            );
                        }
                        unknown_callee = false;
                        fallback = false;
                    }
                    eprintln!(
                        "pangs closed producer: callsite={} complete={} raw_targets={} external={} non_function={} certified={}",
                        cs.key,
                        certificate.complete,
                        certificate.targets.len(),
                        certificate.external,
                        certificate.non_function,
                        certified
                    );
                }
                // Diagnostic-only census of the pre-FSA pointer answer at this site: the
                // address-taken function objects Andersen actually materialized in the
                // operand's points-to set, and how many of them the signature envelope
                // would reject. Neither counter feeds `targets`.
                let mut prefsa_targets = 0usize;
                let mut fsa_rejected_targets = 0usize;
                for function in cs
                    .operand
                    .and_then(|operand| pts.points_to(operand.0))
                    .into_iter()
                    .flat_map(|points_to| points_to.iter())
                    .filter_map(|cell| {
                        let root = pts.field_base.get(&cell).copied().unwrap_or(cell);
                        self.fn_cell_to_index.get(&root).copied()
                    })
                    .collect::<BTreeSet<_>>()
                {
                    let meta = &self.pir.functions[function];
                    if !meta.address_taken {
                        continue;
                    }
                    prefsa_targets += 1;
                    if !pangs_pir::fsa_compatible(&cs.sig, &meta.sig) {
                        fsa_rejected_targets += 1;
                    }
                }
                // Preserve the target-lattice invariant at the final refinement boundary:
                // empty-without-top is analysis silence, never a conservative call answer.
                // Without an empty witness, retain the already conservative base envelope
                // and its census provenance instead of widening a finite answer to top.
                // An actual external operand must still carry unknown.
                if targets.is_empty() && !operand_unknown {
                    if let Some(base) = steens {
                        out.push(IndirectCallResolution {
                            fallback: true,
                            ..base.clone()
                        });
                        continue;
                    }
                }
                unknown_callee |= targets.is_empty();
                out.push(IndirectCallResolution {
                    callsite_key: cs.key.clone(),
                    targets,
                    unknown_callee,
                    fallback,
                    prefsa_targets,
                    fsa_rejected_targets,
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

    fn emit_node_resolutions(&self, pts: &Solve) -> (Vec<RefinedNodeResolution>, usize) {
        let explain_label = std::env::var(knobs::ENV_ANDERSEN_EXPLAIN_NODE).ok();
        let address_exposed = &self.classes.global_address_exposed;
        let violation_module_wide = matches!(
            self.classes.violation_exposure,
            crate::ViolationExposure::ModuleWide
        );
        let mut pointee_global_interner = RefinedPointeeGlobalInterner::default();
        let mut out = Vec::new();
        let mut coarser_than_steens_nodes = 0usize;
        let mut coarser_samples = Vec::new();
        for node in &self.pag.nodes {
            if !node.kind.is_value_like_public() || !self.in_scope[node.id.0 as usize] {
                continue;
            }
            let set = pts.points_to(node.id.0);
            let external = set
                .map(|set| set.iter().any(|cell| pts.is_external(cell)))
                .unwrap_or(false);
            let external_escaped_union = set
                .map(|set| {
                    set.iter().any(|cell| {
                        matches!(
                            pts.external_region(cell),
                            Some(ExternalRegion::ForgedPointer(_))
                        )
                    })
                })
                .unwrap_or(false);
            if self
                .base
                .nodes
                .get(&node.label)
                .is_some_and(|base| external && !base.external)
            {
                coarser_than_steens_nodes += 1;
                if coarser_samples.len() < 8 {
                    coarser_samples.push(node.label.clone());
                }
            }
            let reaches_function_pointer = set
                .map(|set| {
                    set.iter().any(|cell| {
                        pts.external_region(cell)
                            .is_some_and(ExternalRegion::may_contain_function_pointer)
                            || self
                                .fn_cell_to_index
                                .contains_key(&pts.field_base.get(&cell).copied().unwrap_or(cell))
                    })
                })
                .unwrap_or(false);
            let mut global_indices_unfiltered: Vec<usize> = set
                .into_iter()
                .flat_map(|set| set.iter())
                .filter_map(|cell| {
                    let root = pts.field_base.get(&cell).copied().unwrap_or(cell);
                    self.global_of_cell.get(&root).copied()
                })
                .collect();
            global_indices_unfiltered.sort_unstable_by(|&left, &right| {
                self.pir.globals[left].key.cmp(&self.pir.globals[right].key)
            });
            global_indices_unfiltered.dedup();
            let global_indices = if violation_module_wide {
                global_indices_unfiltered.clone()
            } else {
                global_indices_unfiltered
                    .iter()
                    .copied()
                    .filter(|&index| address_exposed[index])
                    .collect()
            };
            if cfg!(debug_assertions) {
                let globals = global_indices
                    .iter()
                    .map(|&index| self.pir.globals[index].key.clone())
                    .collect::<Vec<_>>();
                let globals_unfiltered = global_indices_unfiltered
                    .iter()
                    .map(|&index| self.pir.globals[index].key.clone())
                    .collect::<Vec<_>>();
                debug_assert_narrows(
                    &node.label,
                    "address-exposed-andersen",
                    &globals,
                    "andersen",
                    &globals_unfiltered,
                );
            }
            let same_pointee_globals = global_indices == global_indices_unfiltered;
            let globals = pointee_global_interner.intern(global_indices, self.pir);
            let globals_unfiltered = if same_pointee_globals {
                SharedStringList::default()
            } else {
                pointee_global_interner.intern(global_indices_unfiltered, self.pir)
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
                    .flat_map(|set| set.iter())
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
                    "pangs andersen explain node={} reaches_function_pointer={} external={} allocations={:?} omega_source_count={} omega_source_sample={:?}",
                    node.label,
                    reaches_function_pointer,
                    external,
                    allocations,
                    source_count,
                    source_sample
                );
            }
            out.push(RefinedNodeResolution {
                label: node.label.clone(),
                reaches_function_pointer,
                external,
                external_escaped_union,
                pointee_globals: globals,
                pointee_globals_unfiltered: globals_unfiltered,
                external_sources,
            });
        }
        if std::env::var_os(knobs::ENV_ANDERSEN_EXPLAIN_NODE).is_some()
            && coarser_than_steens_nodes != 0
        {
            eprintln!(
                "pangs andersen coarser than steens: nodes={coarser_than_steens_nodes} sample={coarser_samples:?}"
            );
        }
        (out, coarser_than_steens_nodes)
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
            content_cells.extend(pts.content_fields(obj));
            let mut allocs = BTreeSet::new();
            for cell in content_cells {
                let Some(set) = pts.points_to(cell) else {
                    continue;
                };
                for o in set {
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
        OmegaSeedKind::VarargListPayload => "omega:vararg_list_payload",
    }
}

fn andersen_profile_enabled() -> bool {
    std::env::var_os(knobs::ENV_ANDERSEN_PROFILE).is_some()
}

fn hybrid_points_to_enabled_for(value: Option<&str>) -> bool {
    !matches!(value, Some("0"))
}

fn hybrid_points_to_enabled() -> bool {
    let value = std::env::var(knobs::ENV_ANDERSEN_HYBRID_BITSETS).ok();
    hybrid_points_to_enabled_for(value.as_deref())
}

fn copy_scc_min_edges() -> usize {
    std::env::var(knobs::ENV_ANDERSEN_COPY_SCC_MIN_EDGES)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|&value| value > 0)
        .unwrap_or(knobs::ANDERSEN_COPY_SCC_MIN_EDGES)
}

fn lane_cap() -> usize {
    std::env::var(knobs::ENV_ANDERSEN_PWC_LANE_CAP)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(knobs::ANDERSEN_PWC_LANE_CAP)
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

fn receiver_payloads_enabled() -> bool {
    std::env::var_os(knobs::ENV_ANDERSEN_RECEIVER_PAYLOADS).is_some()
}

fn closed_producers_enabled() -> bool {
    std::env::var_os(knobs::ENV_ANDERSEN_CLOSED_PRODUCERS).is_some()
}

fn closed_consumers_enabled() -> bool {
    std::env::var_os(knobs::ENV_ANDERSEN_CLOSED_CONSUMERS).is_some()
}

fn memcpy_edge_summaries_enabled_for(value: Option<&str>) -> bool {
    !matches!(value, Some("0"))
}

fn memcpy_edge_summaries_enabled() -> bool {
    let value = std::env::var(knobs::ENV_ANDERSEN_MEMCPY_EDGE_SUMMARIES).ok();
    memcpy_edge_summaries_enabled_for(value.as_deref())
}

fn asymmetric_field_overlap_enabled() -> bool {
    matches!(
        std::env::var(knobs::ENV_ANDERSEN_ASYMMETRIC_FIELD_OVERLAP).as_deref(),
        Ok("1") | Ok("true")
    )
}

fn graph_reachable(start: usize, adjacency: &[Vec<usize>]) -> HashSet<usize> {
    let mut reachable = HashSet::from([start]);
    let mut stack = vec![start];
    while let Some(node) = stack.pop() {
        for &successor in &adjacency[node] {
            if reachable.insert(successor) {
                stack.push(successor);
            }
        }
    }
    reachable
}

/// Recover a bounded set of concrete allocation origins using only address-preserving PAG
/// operations. This is intentionally independent of Steensgaard: loads and other unsupported
/// producers make a row incomplete, while assignments (including phi/select and direct
/// actual/formal bindings) and GEPs preserve the allocation root. The retained roots are useful
/// positive facts; `complete == false` is an explicit overflow/unknown bit.
fn bounded_allocation_origins(pag: &Pag, limit: usize) -> Vec<AllocationOrigins> {
    assert!(limit > 0, "allocation-origin limit must be positive");
    let mut incoming = vec![Vec::<&pangs_pag::Edge>::new(); pag.nodes.len()];
    for edge in &pag.edges {
        if matches!(
            edge.kind,
            EdgeKind::AddrOf | EdgeKind::Assign | EdgeKind::Load | EdgeKind::Gep { .. }
        ) {
            incoming[edge.dst.0 as usize].push(edge);
        }
    }

    let mut roots = vec![BTreeSet::<NodeId>::new(); pag.nodes.len()];
    let mut overflow = vec![false; pag.nodes.len()];
    loop {
        let mut changed = false;
        for (destination, producers) in incoming.iter().enumerate() {
            for edge in producers {
                match edge.kind {
                    EdgeKind::AddrOf => {
                        if roots[destination].len() < limit {
                            changed |= roots[destination].insert(edge.src);
                        } else if !roots[destination].contains(&edge.src) && !overflow[destination]
                        {
                            overflow[destination] = true;
                            changed = true;
                        }
                    }
                    EdgeKind::Assign | EdgeKind::Gep { .. } => {
                        let source = edge.src.0 as usize;
                        if overflow[source] && !overflow[destination] {
                            overflow[destination] = true;
                            changed = true;
                        }
                        let source_roots = roots[source].iter().copied().collect::<Vec<_>>();
                        for root in source_roots {
                            if roots[destination].len() < limit {
                                changed |= roots[destination].insert(root);
                            } else if !roots[destination].contains(&root) && !overflow[destination]
                            {
                                overflow[destination] = true;
                                changed = true;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        for origin in &pag.pointer_integer_origins {
            let destination = origin.destination.0 as usize;
            for source in &origin.sources {
                let source = source.0 as usize;
                if overflow[source] && !overflow[destination] {
                    overflow[destination] = true;
                    changed = true;
                }
                let source_roots = roots[source].iter().copied().collect::<Vec<_>>();
                for root in source_roots {
                    if roots[destination].len() < limit {
                        changed |= roots[destination].insert(root);
                    } else if !roots[destination].contains(&root) && !overflow[destination] {
                        overflow[destination] = true;
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }

    let mut complete = pag
        .nodes
        .iter()
        .map(pangs_pag::is_canonical_pointer_null)
        .collect::<Vec<_>>();
    loop {
        let mut changed = false;
        for (destination, producers) in incoming.iter().enumerate() {
            if complete[destination] || producers.is_empty() || overflow[destination] {
                continue;
            }
            let all_supported_and_complete = producers.iter().all(|edge| match edge.kind {
                EdgeKind::AddrOf => true,
                EdgeKind::Assign | EdgeKind::Gep { .. } => complete[edge.src.0 as usize],
                _ => false,
            });
            if all_supported_and_complete {
                complete[destination] = true;
                changed = true;
            }
        }
        for origin in &pag.pointer_integer_origins {
            let destination = origin.destination.0 as usize;
            if complete[destination] || !origin.complete || overflow[destination] {
                continue;
            }
            if origin
                .sources
                .iter()
                .all(|source| complete[source.0 as usize])
            {
                complete[destination] = true;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    roots
        .into_iter()
        .zip(complete)
        .map(|(roots, complete)| AllocationOrigins { roots, complete })
        .collect()
}

fn receiver_payload_vertex(
    parents: &mut Vec<usize>,
    regions: &mut Vec<Option<(NodeId, FieldRegion)>>,
    vertices: &mut HashMap<(NodeId, FieldLocation), usize>,
    root: NodeId,
    location: FieldLocation,
) -> usize {
    if let Some(&vertex) = vertices.get(&(root, location)) {
        return vertex;
    }
    let vertex = parents.len();
    parents.push(vertex);
    regions.push(Some((root, FieldRegion::access(location, None))));
    vertices.insert((root, location), vertex);
    vertex
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

fn directed_sccs(active: &[bool], edges: &[(usize, usize)]) -> (Vec<usize>, Vec<usize>) {
    let mut successors = vec![Vec::new(); active.len()];
    let mut predecessors = vec![Vec::new(); active.len()];
    for &(source, destination) in edges {
        if active[source] && active[destination] {
            successors[source].push(destination);
            predecessors[destination].push(source);
        }
    }

    let mut seen = vec![false; active.len()];
    let mut order = Vec::new();
    for start in 0..active.len() {
        if !active[start] || seen[start] {
            continue;
        }
        seen[start] = true;
        let mut stack = vec![(start, 0usize)];
        while let Some((vertex, next)) = stack.pop() {
            if next < successors[vertex].len() {
                stack.push((vertex, next + 1));
                let successor = successors[vertex][next];
                if !seen[successor] {
                    seen[successor] = true;
                    stack.push((successor, 0));
                }
            } else {
                order.push(vertex);
            }
        }
    }

    let mut component_of = vec![usize::MAX; active.len()];
    let mut component_sizes = Vec::new();
    for &start in order.iter().rev() {
        if component_of[start] != usize::MAX {
            continue;
        }
        let component = component_sizes.len();
        component_of[start] = component;
        let mut size = 0usize;
        let mut stack = vec![start];
        while let Some(vertex) = stack.pop() {
            size += 1;
            for &predecessor in &predecessors[vertex] {
                if component_of[predecessor] == usize::MAX {
                    component_of[predecessor] = component;
                    stack.push(predecessor);
                }
            }
        }
        component_sizes.push(size);
    }
    (component_of, component_sizes)
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
        OmegaSeedKind::VarargListPayload => "vararg_list_payload",
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
    /// Site-local propagation cell. It is never inserted into a points-to set or any
    /// allocation/object lookup. `None` retains the direct Cartesian implementation.
    summary: Option<Cell>,
    /// A summary stays dormant until both logical endpoint sets are non-empty, preserving
    /// the direct join's guarded direct-access effects and copy-edge topology.
    summary_active: bool,
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

fn hybrid_point_set_promotion() -> usize {
    static PROMOTION: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *PROMOTION.get_or_init(|| {
        std::env::var(knobs::ENV_ANDERSEN_HYBRID_BITSET_THRESHOLD)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(64)
    })
}

fn hybrid_point_set_small_limit() -> usize {
    static LIMIT: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *LIMIT.get_or_init(|| {
        std::env::var(knobs::ENV_ANDERSEN_HYBRID_SMALL_THRESHOLD)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(8)
    })
}

fn hybrid_point_set_max_bits_per_member() -> usize {
    static BITS: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *BITS.get_or_init(|| {
        std::env::var(knobs::ENV_ANDERSEN_HYBRID_BITSET_MAX_BITS_PER_MEMBER)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(128)
    })
}

fn dense_point_set_worthwhile(len: usize, max: Cell) -> bool {
    if len <= hybrid_point_set_promotion() {
        return false;
    }
    // Dense cells are indexed by module-wide Cell IDs, not by a set-local base. Bound
    // both empty-word scanning and allocation relative to useful members. The default
    // 128 bits/member permits at most two bitmap words per fact and is comparable to a
    // conservative hash-table storage estimate.
    let bitmap_bits = (max as usize / 64 + 1).saturating_mul(64);
    bitmap_bits <= len.saturating_mul(hybrid_point_set_max_bits_per_member())
}

#[derive(Clone, Debug)]
enum HybridPointSet {
    Small(Vec<Cell>),
    Sparse {
        cells: HashSet<Cell>,
        max: Cell,
    },
    Dense {
        words: Vec<u64>,
        len: usize,
        max: Cell,
    },
}

#[derive(Clone, Debug)]
enum PointSet {
    Hash(HashSet<Cell>),
    Hybrid(HybridPointSet),
}

enum PointSetIter<'a> {
    Hash(std::iter::Copied<std::collections::hash_set::Iter<'a, Cell>>),
    Small(std::iter::Copied<std::slice::Iter<'a, Cell>>),
    Sparse(std::iter::Copied<std::collections::hash_set::Iter<'a, Cell>>),
    Dense(DensePointSetIter<'a>),
}

struct DensePointSetIter<'a> {
    words: &'a [u64],
    word_index: usize,
    remaining: u64,
}

impl Iterator for DensePointSetIter<'_> {
    type Item = Cell;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.remaining != 0 {
                let bit = self.remaining.trailing_zeros() as usize;
                self.remaining &= self.remaining - 1;
                return Some(((self.word_index - 1) * 64 + bit) as Cell);
            }
            self.remaining = *self.words.get(self.word_index)?;
            self.word_index += 1;
        }
    }
}

impl Iterator for PointSetIter<'_> {
    type Item = Cell;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Hash(iter) => iter.next(),
            Self::Small(iter) => iter.next(),
            Self::Sparse(iter) => iter.next(),
            Self::Dense(iter) => iter.next(),
        }
    }
}

impl HybridPointSet {
    fn from_dense_words(mut words: Vec<u64>, len: usize, max: Cell) -> Self {
        if len == 0 {
            return Self::Small(Vec::new());
        }
        words.truncate(max as usize / 64 + 1);
        if dense_point_set_worthwhile(len, max) {
            return Self::Dense { words, len, max };
        }

        let mut cells = Vec::with_capacity(len);
        for (word_index, mut word) in words.into_iter().enumerate() {
            while word != 0 {
                let bit = word.trailing_zeros() as usize;
                word &= word - 1;
                cells.push((word_index * 64 + bit) as Cell);
            }
        }
        if cells.len() <= hybrid_point_set_small_limit() {
            Self::Small(cells)
        } else {
            Self::Sparse {
                cells: cells.into_iter().collect(),
                max,
            }
        }
    }

    fn promote_sparse_if_dense(&mut self) {
        let should_promote = match self {
            Self::Sparse { cells, max } => dense_point_set_worthwhile(cells.len(), *max),
            _ => false,
        };
        if !should_promote {
            return;
        }
        let Self::Sparse { cells, max } = std::mem::replace(self, Self::Small(Vec::new())) else {
            unreachable!();
        };
        let mut words = vec![0u64; max as usize / 64 + 1];
        let len = cells.len();
        for member in cells {
            words[member as usize / 64] |= 1u64 << (member % 64);
        }
        *self = Self::Dense { words, len, max };
    }

    fn demote_dense_with(&mut self, cell: Cell) {
        let Self::Dense { words, len, .. } = std::mem::replace(self, Self::Small(Vec::new()))
        else {
            unreachable!();
        };
        let mut cells = HashSet::with_capacity(len.saturating_add(1));
        for (word_index, mut word) in words.into_iter().enumerate() {
            while word != 0 {
                let bit = word.trailing_zeros() as usize;
                word &= word - 1;
                cells.insert((word_index * 64 + bit) as Cell);
            }
        }
        cells.insert(cell);
        let max = cells.iter().copied().max().unwrap_or(cell);
        *self = Self::Sparse { cells, max };
    }

    fn insert(&mut self, cell: Cell) -> bool {
        match self {
            Self::Small(cells) => {
                if cells.contains(&cell) {
                    return false;
                }
                cells.push(cell);
                if cells.len() > hybrid_point_set_small_limit() {
                    let old = std::mem::take(cells);
                    let max = old.iter().copied().max().unwrap_or(cell);
                    *self = Self::Sparse {
                        cells: old.into_iter().collect(),
                        max,
                    };
                    self.promote_sparse_if_dense();
                }
                true
            }
            Self::Sparse { cells, max } => {
                if !cells.insert(cell) {
                    return false;
                }
                *max = (*max).max(cell);
                self.promote_sparse_if_dense();
                true
            }
            Self::Dense { words, len, max } => {
                let word = cell as usize / 64;
                if words
                    .get(word)
                    .is_some_and(|bits| bits & (1u64 << (cell % 64)) != 0)
                {
                    return false;
                }
                let new_len = len.saturating_add(1);
                let new_max = (*max).max(cell);
                if !dense_point_set_worthwhile(new_len, new_max) {
                    self.demote_dense_with(cell);
                    return true;
                }
                if words.len() <= word {
                    words.resize(word + 1, 0);
                }
                words[word] |= 1u64 << (cell % 64);
                *len = new_len;
                *max = new_max;
                true
            }
        }
    }

    /// Join `source` into this set and return exactly the newly inserted members.
    ///
    /// Dense-to-dense joins stay wordwise. The returned delta retains a bitmap only when
    /// the changed words are themselves dense enough; small overlap remainders return to
    /// the tiny/sparse representations used by ordinary delta consumers.
    fn union_delta(&mut self, source: &Self) -> Self {
        if self.is_empty() {
            *self = source.clone();
            return source.clone();
        }
        if let (
            Self::Dense {
                words: destination_words,
                len: destination_len,
                max: destination_max,
            },
            Self::Dense {
                words: source_words,
                ..
            },
        ) = (&mut *self, source)
        {
            if destination_words.len() < source_words.len() {
                destination_words.resize(source_words.len(), 0);
            }
            let mut changed_words = vec![0; source_words.len()];
            let mut changed_len = 0usize;
            let mut changed_max = 0;
            for (word_index, &source_word) in source_words.iter().enumerate() {
                let changed = source_word & !destination_words[word_index];
                if changed == 0 {
                    continue;
                }
                destination_words[word_index] |= source_word;
                changed_words[word_index] = changed;
                changed_len = changed_len.saturating_add(changed.count_ones() as usize);
                changed_max = (word_index * 64 + (63 - changed.leading_zeros() as usize)) as Cell;
            }
            if changed_len == 0 {
                return Self::Small(Vec::new());
            }
            *destination_len = destination_len.saturating_add(changed_len);
            *destination_max = (*destination_max).max(changed_max);
            return Self::from_dense_words(changed_words, changed_len, changed_max);
        }

        let mut added = Self::Small(Vec::new());
        for cell in source.iter() {
            if self.insert(cell) {
                added.insert(cell);
            }
        }
        added
    }

    /// Merge a delta whose members are known not to occur in this set.
    fn union_disjoint(&mut self, source: Self) {
        match (self, source) {
            (destination, source) if destination.is_empty() => *destination = source,
            (
                Self::Dense {
                    words: destination_words,
                    len: destination_len,
                    max: destination_max,
                },
                Self::Dense {
                    words: source_words,
                    len: source_len,
                    max: source_max,
                },
            ) => {
                if destination_words.len() < source_words.len() {
                    destination_words.resize(source_words.len(), 0);
                }
                for (destination, source) in destination_words.iter_mut().zip(source_words) {
                    debug_assert_eq!(*destination & source, 0);
                    *destination |= source;
                }
                *destination_len = destination_len.saturating_add(source_len);
                *destination_max = (*destination_max).max(source_max);
            }
            (destination, source) => {
                for cell in source.iter() {
                    let inserted = destination.insert(cell);
                    debug_assert!(inserted);
                }
            }
        }
    }

    fn is_empty(&self) -> bool {
        match self {
            Self::Small(cells) => cells.is_empty(),
            Self::Sparse { cells, .. } => cells.is_empty(),
            Self::Dense { len, .. } => *len == 0,
        }
    }

    fn iter(&self) -> PointSetIter<'_> {
        match self {
            Self::Small(cells) => PointSetIter::Small(cells.iter().copied()),
            Self::Sparse { cells, .. } => PointSetIter::Sparse(cells.iter().copied()),
            Self::Dense { words, .. } => PointSetIter::Dense(DensePointSetIter {
                words,
                word_index: 0,
                remaining: 0,
            }),
        }
    }
}

impl<'a> IntoIterator for &'a PointSet {
    type Item = Cell;
    type IntoIter = PointSetIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl PointSet {
    fn new(hybrid: bool) -> Self {
        if hybrid {
            Self::Hybrid(HybridPointSet::Small(Vec::new()))
        } else {
            Self::Hash(HashSet::new())
        }
    }

    fn insert(&mut self, cell: Cell) -> bool {
        match self {
            Self::Hash(set) => set.insert(cell),
            Self::Hybrid(set) => set.insert(cell),
        }
    }

    fn union_delta(&mut self, source: &Self) -> Self {
        match (&mut *self, source) {
            (Self::Hybrid(destination), Self::Hybrid(source)) => {
                Self::Hybrid(destination.union_delta(source))
            }
            (Self::Hash(destination), _) => {
                let mut added = HashSet::new();
                for cell in source.iter() {
                    if destination.insert(cell) {
                        added.insert(cell);
                    }
                }
                Self::Hash(added)
            }
            (Self::Hybrid(destination), _) => {
                let mut added = HybridPointSet::Small(Vec::new());
                for cell in source.iter() {
                    if destination.insert(cell) {
                        added.insert(cell);
                    }
                }
                Self::Hybrid(added)
            }
        }
    }

    fn union_disjoint(&mut self, source: Self) {
        match (self, source) {
            (Self::Hybrid(destination), Self::Hybrid(source)) => {
                destination.union_disjoint(source);
            }
            (Self::Hash(destination), Self::Hash(source)) => destination.extend(source),
            (destination, source) => {
                for cell in source.iter() {
                    let inserted = destination.insert(cell);
                    debug_assert!(inserted);
                }
            }
        }
    }

    #[allow(dead_code)]
    fn contains(&self, cell: &Cell) -> bool {
        match self {
            Self::Hash(set) => set.contains(cell),
            Self::Hybrid(HybridPointSet::Small(cells)) => cells.contains(cell),
            Self::Hybrid(HybridPointSet::Sparse { cells, .. }) => cells.contains(cell),
            Self::Hybrid(HybridPointSet::Dense { words, .. }) => words
                .get(*cell as usize / 64)
                .is_some_and(|word| word & (1u64 << (*cell % 64)) != 0),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Hash(set) => set.len(),
            Self::Hybrid(HybridPointSet::Small(cells)) => cells.len(),
            Self::Hybrid(HybridPointSet::Sparse { cells, .. }) => cells.len(),
            Self::Hybrid(HybridPointSet::Dense { len, .. }) => *len,
        }
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn iter(&self) -> PointSetIter<'_> {
        match self {
            Self::Hash(set) => PointSetIter::Hash(set.iter().copied()),
            Self::Hybrid(set) => set.iter(),
        }
    }
}

impl PartialEq<HashSet<Cell>> for PointSet {
    fn eq(&self, other: &HashSet<Cell>) -> bool {
        self.len() == other.len() && self.iter().all(|cell| other.contains(&cell))
    }
}

struct Solve {
    next_field: Cell,
    /// Constraint-graph node representative. This canonicalizes where pointer contents are
    /// stored and propagated; cells appearing *inside* points-to sets remain allocation
    /// identities and are deliberately never canonicalized.
    representative: Vec<Cell>,
    pts: HashMap<Cell, PointSet>,
    /// Points-to facts not yet propagated over the source's established copy edges.
    pending_pts: HashMap<Cell, PointSet>,
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
    /// Exact number of distinct edges across `succ` and `pending_succ`. Copy-edge SCC
    /// admission is checked after every worklist pop, so deriving this from the maps there
    /// turns propagation into repeated whole-graph scans.
    copy_edge_count: usize,
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
    /// Per-root count of admitted affine lane cells. Exact cells retain their fixed PAG
    /// vocabulary; only lanes are bounded by the PWC experiment's finite domain.
    lane_cells_by_root: HashMap<Cell, usize>,
    lane_cap: Option<usize>,
    /// base object cell -> its materialized constant-offset field cells. Needed to
    /// retroactively connect them when the base later receives a non-constant access (M2.1).
    obj_fields: HashMap<Cell, Vec<Cell>>,
    /// base object cell -> per-base unknown-offset summary cell. Dynamic GEPs over the same
    /// object all route through this cell rather than collapsing every future field to the
    /// whole-object cell.
    unknown_fields: HashMap<Cell, Cell>,
    /// unknown-offset summary cell -> base object cell.
    unknown_field_base: HashMap<Cell, Cell>,
    /// Persistent allocation-relative memory reads.  The key is deliberately the raw
    /// allocation root: copy representatives describe contents, never locations.
    overlap_reads: HashMap<Cell, Vec<(FieldLocation, Cell)>>,
    /// Receiver-summary raw payload cells by their receiver allocation root. Unlike ordinary
    /// field cells these are synthetic, but aggregate export and boundary traversal must still
    /// be able to inspect them after propagation-state compaction.
    receiver_payload_fields: HashMap<Cell, Vec<Cell>>,
    /// base object cells that have had a direct load/store through the whole object. If the
    /// object also has an unknown-offset summary, the direct cell aliases the summary.
    direct_accessed: HashSet<Cell>,
    /// Raw identities of propagation-only memcpy cells. Copy-SCC canonicalization may fold
    /// one into an ordinary representative, but the synthetic identity remains non-pointee.
    memcpy_summary_cells: HashSet<Cell>,
    worklist: Vec<Cell>,
    queued: HashSet<Cell>,
    profile: bool,
    steps: usize,
    memcpy_pairs_processed: usize,
    memcpy_logical_pairs_covered: usize,
    memcpy_summary_edges_inserted: usize,
    memcpy_summary_sites: usize,
    memcpy_summary_cells_allocated: usize,
    copy_fact_pairs_processed: usize,
    load_pairs_processed: usize,
    store_pairs_processed: usize,
    gep_pairs_processed: usize,
    points_to_facts_inserted: usize,
    copy_edges_inserted: usize,
    field_cells_allocated: usize,
    chained_exact_field_derivations: usize,
    chained_lane_field_derivations: usize,
    chain_missing_exact_collapses: usize,
    chain_lane_cap_collapses: usize,
    chain_unknown_input_collapses: usize,
    chain_arithmetic_collapses: usize,
    derived_lanes_admitted: usize,
    max_lanes_per_root: usize,
    roots_reaching_lane_cap: usize,
    scc_nodes_scanned: usize,
    scc_edges_scanned: usize,
    new_copy_edges_since_scc: usize,
    scc_enabled: bool,
    scc_min_edges: usize,
    scc_passes: usize,
    scc_nodes_collapsed: usize,
    scc_copy_edges_removed: usize,
    hybrid_points_to: bool,
    memcpy_edge_summaries: bool,
    asymmetric_field_overlap: bool,
    overlap_read_dependencies: usize,
    overlap_read_pairs: usize,
    overlap_read_late_replays: usize,
}

#[derive(Debug, Default)]
struct OfflineQuotientProfile {
    original_nodes: usize,
    original_edges: usize,
    quotient_nodes: usize,
    quotient_edges_before_factor: usize,
    quotient_edges: usize,
    static_scc_merges: usize,
    substitutions: usize,
    value_number_merges: usize,
    factored_groups: usize,
    factored_edges_removed: usize,
    synthetic_nodes: usize,
    elapsed_micros: u128,
}

fn offline_find(parent: &mut [Cell], cell: Cell) -> Cell {
    let mut root = cell;
    while parent[root as usize] != root {
        root = parent[root as usize];
    }
    let mut current = cell;
    while parent[current as usize] != current {
        let next = parent[current as usize];
        parent[current as usize] = root;
        current = next;
    }
    root
}

fn offline_union_into(parent: &mut [Cell], member: Cell, representative: Cell) -> bool {
    let member = offline_find(parent, member);
    let representative = offline_find(parent, representative);
    if member == representative {
        return false;
    }
    parent[member as usize] = representative;
    true
}

impl Solve {
    #[cfg(test)]
    fn new(n_base: usize, profile: bool) -> Self {
        Self::new_with_pwc_and_overlap(n_base, profile, false, false)
    }

    fn new_with_pwc_and_overlap(
        n_base: usize,
        profile: bool,
        pwc_lanes: bool,
        asymmetric_field_overlap: bool,
    ) -> Self {
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
            copy_edge_count: 0,
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
            lane_cells_by_root: HashMap::new(),
            lane_cap: pwc_lanes.then(lane_cap),
            obj_fields: HashMap::new(),
            unknown_fields: HashMap::new(),
            unknown_field_base: HashMap::new(),
            overlap_reads: HashMap::new(),
            receiver_payload_fields: HashMap::new(),
            direct_accessed: HashSet::new(),
            memcpy_summary_cells: HashSet::new(),
            worklist: Vec::new(),
            queued: HashSet::new(),
            profile,
            steps: 0,
            memcpy_pairs_processed: 0,
            memcpy_logical_pairs_covered: 0,
            memcpy_summary_edges_inserted: 0,
            memcpy_summary_sites: 0,
            memcpy_summary_cells_allocated: 0,
            copy_fact_pairs_processed: 0,
            load_pairs_processed: 0,
            store_pairs_processed: 0,
            gep_pairs_processed: 0,
            points_to_facts_inserted: 0,
            copy_edges_inserted: 0,
            field_cells_allocated: 0,
            chained_exact_field_derivations: 0,
            chained_lane_field_derivations: 0,
            chain_missing_exact_collapses: 0,
            chain_lane_cap_collapses: 0,
            chain_unknown_input_collapses: 0,
            chain_arithmetic_collapses: 0,
            derived_lanes_admitted: 0,
            max_lanes_per_root: 0,
            roots_reaching_lane_cap: 0,
            scc_nodes_scanned: 0,
            scc_edges_scanned: 0,
            new_copy_edges_since_scc: 0,
            scc_enabled: std::env::var_os(knobs::ENV_ANDERSEN_DISABLE_COPY_SCC).is_none(),
            scc_min_edges: copy_scc_min_edges(),
            scc_passes: 0,
            scc_nodes_collapsed: 0,
            scc_copy_edges_removed: 0,
            hybrid_points_to: hybrid_points_to_enabled(),
            memcpy_edge_summaries: memcpy_edge_summaries_enabled(),
            asymmetric_field_overlap,
            overlap_read_dependencies: 0,
            overlap_read_pairs: 0,
            overlap_read_late_replays: 0,
        }
    }

    /// Discard fixed-point machinery that no result query reads. The retained tables are:
    /// representatives, points-to sets, external-region/provenance facts, and the field-to-base
    /// inventory used by node/global result materialization.
    fn release_propagation_state(&mut self) {
        self.pending_pts = HashMap::new();
        self.pending_external_sources = HashMap::new();
        self.regions = HashMap::new();
        self.succ = HashMap::new();
        self.pending_succ = HashMap::new();
        self.copy_edge_count = 0;
        self.loads = HashMap::new();
        self.stores = HashMap::new();
        self.geps = HashMap::new();
        self.pending_loads = HashMap::new();
        self.pending_stores = HashMap::new();
        self.pending_geps = HashMap::new();
        self.memcpys = Vec::new();
        self.memcpy_by_endpoint = HashMap::new();
        self.fields = HashMap::new();
        self.field_location = HashMap::new();
        self.known_locations = HashSet::new();
        self.lane_cells_by_root = HashMap::new();
        self.unknown_fields = HashMap::new();
        self.unknown_field_base = HashMap::new();
        self.overlap_reads = HashMap::new();
        self.direct_accessed = HashSet::new();
        self.memcpy_summary_cells = HashSet::new();
        self.worklist = Vec::new();
        self.queued = HashSet::new();
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

    fn points_to(&self, cell: Cell) -> Option<&PointSet> {
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
        let hybrid = self.hybrid_points_to;
        let dst = self
            .pts
            .entry(cell)
            .or_insert_with(|| PointSet::new(hybrid));
        let mut added = PointSet::new(hybrid);
        for &object in objects {
            if dst.insert(object) {
                added.insert(object);
            }
        }
        if !added.is_empty() {
            self.points_to_facts_inserted =
                self.points_to_facts_inserted.saturating_add(added.len());
            match self.pending_pts.entry(cell) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(added);
                }
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    entry.get_mut().union_disjoint(added);
                }
            }
            self.enqueue(cell);
        }
    }

    fn union_pts_delta(&mut self, cell: Cell, objects: &PointSet) {
        if objects.is_empty() {
            return;
        }
        let cell = self.canonical(cell);
        let hybrid = self.hybrid_points_to;
        let added = self
            .pts
            .entry(cell)
            .or_insert_with(|| PointSet::new(hybrid))
            .union_delta(objects);
        if added.is_empty() {
            return;
        }
        self.points_to_facts_inserted = self.points_to_facts_inserted.saturating_add(added.len());
        match self.pending_pts.entry(cell) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(added);
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                entry.get_mut().union_disjoint(added);
            }
        }
        self.enqueue(cell);
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
        let inserted = self.pending_succ.entry(from).or_default().insert(to);
        debug_assert!(inserted, "duplicate copy edge passed the membership checks");
        self.copy_edge_count = self
            .copy_edge_count
            .checked_add(1)
            .expect("copy-edge count overflow");
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
        let summary = self.memcpy_edge_summaries.then(|| {
            let cell = self.allocate_cell();
            self.memcpy_summary_cells.insert(cell);
            self.memcpy_summary_cells_allocated =
                self.memcpy_summary_cells_allocated.saturating_add(1);
            cell
        });
        self.memcpys.push(MemcpyJoin {
            dst,
            src,
            summary,
            summary_active: false,
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
                    .filter(|object| !join.seen_destinations.contains(object))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let new_sources = self
            .pts
            .get(&source)
            .map(|set| {
                set.iter()
                    .filter(|object| !join.seen_sources.contains(object))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let all_sources = if new_destinations.is_empty() {
            Vec::new()
        } else {
            self.pts
                .get(&source)
                .map(|set| set.iter().collect())
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

    /// Logical memcpy endpoint relation for post-solve soundness audits. The physical copy
    /// graph may be a Cartesian biclique or two stars; certificates must not depend on it.
    fn memcpy_logical_endpoints(&self, dst: Cell, src: Cell) -> Option<(Vec<Cell>, Vec<Cell>)> {
        let dst = self.canonical(dst);
        let src = self.canonical(src);
        let matching = self
            .memcpys
            .iter()
            .filter(|join| self.canonical(join.dst) == dst && self.canonical(join.src) == src)
            .collect::<Vec<_>>();
        if matching.is_empty() {
            return None;
        }
        let mut destinations = matching
            .iter()
            .flat_map(|join| join.seen_destinations.iter().copied())
            .collect::<Vec<_>>();
        let mut sources = matching
            .iter()
            .flat_map(|join| join.seen_sources.iter().copied())
            .collect::<Vec<_>>();
        destinations.sort_unstable();
        destinations.dedup();
        sources.sort_unstable();
        sources.dedup();

        debug_assert_eq!(
            destinations.iter().copied().collect::<HashSet<_>>(),
            self.points_to(dst)
                .map(|set| set.iter().collect())
                .unwrap_or_default(),
            "quiescent memcpy destination inventory is incomplete"
        );
        debug_assert_eq!(
            sources.iter().copied().collect::<HashSet<_>>(),
            self.points_to(src)
                .map(|set| set.iter().collect())
                .unwrap_or_default(),
            "quiescent memcpy source inventory is incomplete"
        );
        Some((destinations, sources))
    }

    fn add_memcpy_summary_edge(&mut self, source: Cell, destination: Cell) {
        let before = self.copy_edges_inserted;
        self.add_copy(source, destination);
        self.memcpy_summary_edges_inserted = self
            .memcpy_summary_edges_inserted
            .saturating_add(self.copy_edges_inserted.saturating_sub(before));
    }

    fn process_memcpy_summary(&mut self, index: usize, delta: MemcpyDelta) {
        let logical_pairs = delta
            .new_destinations
            .len()
            .saturating_mul(delta.all_sources.len())
            .saturating_add(
                delta
                    .old_destinations
                    .len()
                    .saturating_mul(delta.new_sources.len()),
            );
        self.memcpy_logical_pairs_covered = self
            .memcpy_logical_pairs_covered
            .saturating_add(logical_pairs);

        // The baseline marks every newly discovered destination before entering its
        // possibly-empty source loop. Preserve that asymmetric side effect exactly.
        for &destination in &delta.new_destinations {
            self.note_direct_access(destination);
        }

        let (summary, active, all_destinations, all_sources) = {
            let join = &self.memcpys[index];
            (
                join.summary
                    .expect("summary mode memcpy has a summary cell"),
                join.summary_active,
                join.seen_destinations.iter().copied().collect::<Vec<_>>(),
                join.seen_sources.iter().copied().collect::<Vec<_>>(),
            )
        };

        if !active {
            if all_destinations.is_empty() || all_sources.is_empty() {
                return;
            }
            // Publish the active state before enqueueing copy work. All retained endpoints
            // are connected synchronously in this worklist step; solver exhaustion is only
            // observed between steps and therefore cannot expose a partial refined result.
            self.memcpys[index].summary_active = true;
            self.memcpy_summary_sites = self.memcpy_summary_sites.saturating_add(1);
            for source in all_sources {
                self.note_direct_access(source);
                if self.asymmetric_field_overlap {
                    // Bulk copies retain their whole-object interpretation even when the
                    // endpoint happened to be a field address.
                    self.read_overlap(self.allocation_root(source), summary);
                } else {
                    self.add_memcpy_summary_edge(source, summary);
                }
            }
            for destination in all_destinations {
                self.add_memcpy_summary_edge(
                    summary,
                    if self.asymmetric_field_overlap {
                        self.allocation_root(destination)
                    } else {
                        destination
                    },
                );
            }
            return;
        }

        for source in delta.new_sources {
            self.note_direct_access(source);
            if self.asymmetric_field_overlap {
                self.read_overlap(self.allocation_root(source), summary);
            } else {
                self.add_memcpy_summary_edge(source, summary);
            }
        }
        for destination in delta.new_destinations {
            self.add_memcpy_summary_edge(
                summary,
                if self.asymmetric_field_overlap {
                    self.allocation_root(destination)
                } else {
                    destination
                },
            );
        }
    }

    fn allocation_root(&self, cell: Cell) -> Cell {
        self.field_base.get(&cell).copied().unwrap_or(cell)
    }

    fn location_of(&self, cell: Cell) -> FieldLocation {
        self.field_location
            .get(&cell)
            .copied()
            .unwrap_or(FieldLocation::Unknown)
    }

    /// Raw content cells contributing to a memory read. Value queries intentionally do not
    /// use this helper: only location-aware consumers may reinterpret a cell this way.
    fn overlap_read_cells(&self, cell: Cell) -> Vec<Cell> {
        if !self.asymmetric_field_overlap || self.is_external(cell) {
            return vec![cell];
        }
        let root = self.allocation_root(cell);
        let location = self.location_of(cell);
        let mut cells = vec![root];
        if let Some(fields) = self.obj_fields.get(&root) {
            cells.extend(fields.iter().copied());
        }
        cells.retain(|candidate| location.may_alias(self.location_of(*candidate)));
        cells
    }

    /// Register an allocation-relative memory read and seed it from every currently
    /// directly-overlapping raw cell.  This is intentionally not a transitive closure.
    fn read_overlap(&mut self, cell: Cell, destination: Cell) {
        if !self.asymmetric_field_overlap || self.is_external(cell) {
            self.add_copy(cell, destination);
            return;
        }
        let root = self.allocation_root(cell);
        let location = self.location_of(cell);
        let destination = self.canonical(destination);
        let reads = self.overlap_reads.entry(root).or_default();
        if reads
            .iter()
            .any(|&(loc, dst)| loc == location && dst == destination)
        {
            return;
        }
        reads.push((location, destination));
        self.overlap_read_dependencies = self.overlap_read_dependencies.saturating_add(1);
        let mut sources = vec![root];
        if let Some(fields) = self.obj_fields.get(&root) {
            sources.extend(fields.iter().copied());
        }
        for source in sources {
            if location.may_alias(self.location_of(source)) {
                let before = self.copy_edges_inserted;
                self.add_copy(source, destination);
                self.overlap_read_pairs = self
                    .overlap_read_pairs
                    .saturating_add(self.copy_edges_inserted.saturating_sub(before));
            }
        }
    }

    fn replay_overlap_reads_for_field(&mut self, root: Cell, cell: Cell, location: FieldLocation) {
        if !self.asymmetric_field_overlap {
            return;
        }
        let reads = self.overlap_reads.get(&root).cloned().unwrap_or_default();
        for (read_location, destination) in reads {
            if read_location.may_alias(location) {
                let before = self.copy_edges_inserted;
                self.add_copy(cell, destination);
                let inserted = self.copy_edges_inserted.saturating_sub(before);
                self.overlap_read_pairs = self.overlap_read_pairs.saturating_add(inserted);
                self.overlap_read_late_replays =
                    self.overlap_read_late_replays.saturating_add(inserted);
            }
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
            match (base_location, location, combined) {
                (_, FieldLocation::Unknown, _) | (FieldLocation::Unknown, _, _) => {
                    self.chain_unknown_input_collapses =
                        self.chain_unknown_input_collapses.saturating_add(1);
                    return self.unknown_field_of(root);
                }
                (_, _, FieldLocation::Unknown) => {
                    self.chain_arithmetic_collapses =
                        self.chain_arithmetic_collapses.saturating_add(1);
                    return self.unknown_field_of(root);
                }
                (_, _, FieldLocation::Exact(_)) if self.known_locations.contains(&combined) => {
                    self.chained_exact_field_derivations =
                        self.chained_exact_field_derivations.saturating_add(1);
                    return self.field_of(root, combined);
                }
                (_, _, FieldLocation::Exact(_)) => {
                    self.chain_missing_exact_collapses =
                        self.chain_missing_exact_collapses.saturating_add(1);
                    return self.unknown_field_of(root);
                }
                (_, _, FieldLocation::Lane(_)) => {
                    self.chained_lane_field_derivations =
                        self.chained_lane_field_derivations.saturating_add(1);
                    // Outside the opt-in PWC experiment retain the historical finite fixed
                    // vocabulary rule. Dynamic LLVM lanes alone must not alter defaults.
                    if self.lane_cap.is_none() && !self.known_locations.contains(&combined) {
                        self.chain_missing_exact_collapses =
                            self.chain_missing_exact_collapses.saturating_add(1);
                        return self.unknown_field_of(root);
                    }
                    return self.field_of(root, combined);
                }
            }
        }
        if let Some(&cell) = self.fields.get(&(base, location)) {
            return cell;
        }
        if matches!(location, FieldLocation::Lane(_)) {
            if let Some(cap) = self.lane_cap {
                let count = self
                    .lane_cells_by_root
                    .get(&base)
                    .copied()
                    .unwrap_or_default();
                if count >= cap {
                    self.chain_lane_cap_collapses = self.chain_lane_cap_collapses.saturating_add(1);
                    return self.unknown_field_of(base);
                }
            }
        }
        let cell = self.allocate_cell();
        self.field_cells_allocated = self.field_cells_allocated.saturating_add(1);
        self.fields.insert((base, location), cell);
        self.field_base.insert(cell, base);
        self.field_location.insert(cell, location);
        if matches!(location, FieldLocation::Lane(_)) {
            let count = self.lane_cells_by_root.entry(base).or_default();
            *count = count.saturating_add(1);
            self.derived_lanes_admitted = self.derived_lanes_admitted.saturating_add(1);
            self.max_lanes_per_root = self.max_lanes_per_root.max(*count);
            if self.lane_cap == Some(*count) {
                self.roots_reaching_lane_cap = self.roots_reaching_lane_cap.saturating_add(1);
            }
        }
        let existing = self.obj_fields.entry(base).or_default().clone();
        self.obj_fields.entry(base).or_default().push(cell);
        if location == FieldLocation::Unknown {
            self.unknown_fields.insert(base, cell);
            self.unknown_field_base.insert(cell, base);
        }
        if self.asymmetric_field_overlap {
            self.replay_overlap_reads_for_field(base, cell, location);
        } else {
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
        }
        if !self.asymmetric_field_overlap
            && location == FieldLocation::Unknown
            && self.direct_accessed.contains(&base)
        {
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
        // Materialize the summary when absent. `field_of` aliases a newly created
        // `Unknown` location with every field of `base` that already exists. Keep the
        // explicit bridge for an already-present summary as well.
        let summary = self.unknown_field_of(base);
        if !self.asymmetric_field_overlap {
            self.add_copy(base, summary);
            self.add_copy(summary, base);
        }
    }

    fn copy_edge_pairs(&self) -> Vec<(Cell, Cell)> {
        let mut edges = self
            .succ
            .iter()
            .chain(&self.pending_succ)
            .flat_map(|(&source, destinations)| {
                destinations
                    .iter()
                    .map(move |&destination| (self.canonical(source), self.canonical(destination)))
            })
            .filter(|(source, destination)| source != destination)
            .collect::<Vec<_>>();
        edges.sort_unstable();
        edges.dedup();
        edges
    }

    /// Construct an exact quotient of the fixed inclusion system before propagation.
    ///
    /// Besides ordinary static copy SCCs, two equation identities are used:
    ///
    /// * if an unseeded variable has exactly one copy predecessor and cannot receive a late
    ///   load/GEP/call-binding fact, its least solution equals that predecessor's solution;
    /// * two such variables with the same nonempty predecessor set have identical equations.
    ///
    /// `late_generators` names base cells which later indirect-call activation may seed or
    /// target. Object identities and complex-constraint results are detected locally. The
    /// resulting equivalences are materialized as mutual copy edges and handed to the same
    /// representative remapper used by dynamic SCC collapse, so all original cell IDs remain
    /// valid query handles while pointee allocation identities are left untouched.
    fn offline_quotient(&mut self, late_generators: &HashSet<Cell>) -> OfflineQuotientProfile {
        let started = Instant::now();
        let original_nodes = self.next_field as usize;
        let original_edges = self.copy_edge_pairs();
        let mut profile = OfflineQuotientProfile {
            original_nodes,
            original_edges: original_edges.len(),
            ..OfflineQuotientProfile::default()
        };
        if original_nodes == 0 {
            profile.elapsed_micros = started.elapsed().as_micros();
            return profile;
        }

        let mut parent = (0..original_nodes as Cell).collect::<Vec<_>>();
        let active = vec![true; original_nodes];
        let usize_edges = original_edges
            .iter()
            .map(|&(source, destination)| (source as usize, destination as usize))
            .collect::<Vec<_>>();
        let (component_of, component_sizes) = directed_sccs(&active, &usize_edges);
        let mut representative_of_component = vec![None; component_sizes.len()];
        for cell in 0..original_nodes as Cell {
            let component = component_of[cell as usize];
            let representative = representative_of_component[component].get_or_insert(cell);
            if offline_union_into(&mut parent, cell, *representative) {
                profile.static_scc_merges += 1;
            }
        }

        let mut fixed_generator = vec![false; original_nodes];
        for &cell in late_generators {
            if (cell as usize) < original_nodes {
                fixed_generator[cell as usize] = true;
            }
        }
        // A seeded variable has an independent generator. Every concrete object identity is
        // protected as well because later load/store/memcpy expansion may address its contents.
        for (&cell, objects) in &self.pts {
            fixed_generator[cell as usize] = true;
            for object in objects.iter() {
                if (object as usize) < original_nodes {
                    fixed_generator[object as usize] = true;
                }
            }
        }
        for &cell in self.external_sources.keys() {
            fixed_generator[cell as usize] = true;
        }
        for destination in self
            .loads
            .values()
            .chain(self.pending_loads.values())
            .flatten()
        {
            fixed_generator[*destination as usize] = true;
        }
        // A future field may feed an overlap read.  Its destination therefore has an
        // independent generator even when no ordinary load names it.
        for reads in self.overlap_reads.values() {
            for &(_, destination) in reads {
                if (destination as usize) < original_nodes {
                    fixed_generator[destination as usize] = true;
                }
            }
        }
        for &(_, destination) in self
            .geps
            .values()
            .chain(self.pending_geps.values())
            .flatten()
        {
            fixed_generator[destination as usize] = true;
        }

        loop {
            let mut root_fixed = vec![false; original_nodes];
            for (cell, &fixed) in fixed_generator.iter().enumerate() {
                if fixed {
                    let root = offline_find(&mut parent, cell as Cell);
                    root_fixed[root as usize] = true;
                }
            }
            let mut incoming = vec![BTreeSet::<Cell>::new(); original_nodes];
            for &(source, destination) in &original_edges {
                let source = offline_find(&mut parent, source);
                let destination = offline_find(&mut parent, destination);
                if source != destination {
                    incoming[destination as usize].insert(source);
                }
            }

            let roots = (0..original_nodes as Cell)
                .filter(|&cell| offline_find(&mut parent, cell) == cell)
                .collect::<Vec<_>>();
            let substitutions = roots
                .iter()
                .filter_map(|&root| {
                    (!root_fixed[root as usize] && incoming[root as usize].len() == 1)
                        .then(|| (root, *incoming[root as usize].iter().next().unwrap()))
                })
                .collect::<Vec<_>>();
            let mut changed = false;
            for (member, predecessor) in substitutions {
                if offline_union_into(&mut parent, member, predecessor) {
                    profile.substitutions += 1;
                    changed = true;
                }
            }
            if changed {
                continue;
            }

            let mut equivalent = BTreeMap::<Vec<Cell>, Vec<Cell>>::new();
            for root in roots {
                if root_fixed[root as usize] || incoming[root as usize].is_empty() {
                    continue;
                }
                equivalent
                    .entry(incoming[root as usize].iter().copied().collect())
                    .or_default()
                    .push(root);
            }
            for members in equivalent.values().filter(|members| members.len() > 1) {
                let representative = members[0];
                for &member in &members[1..] {
                    if offline_union_into(&mut parent, member, representative) {
                        profile.value_number_merges += 1;
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }

        // Turn the proven equation equalities into SCCs. One remap then handles points-to
        // state, all complex constraints, memcpy endpoints, work queues, and original IDs.
        let roots = (0..original_nodes as Cell)
            .map(|cell| offline_find(&mut parent, cell))
            .collect::<Vec<_>>();
        if roots
            .iter()
            .enumerate()
            .any(|(cell, &root)| root != cell as Cell)
        {
            for (cell, &root) in roots.iter().enumerate() {
                let cell = cell as Cell;
                if cell != root {
                    self.add_copy(cell, root);
                    self.add_copy(root, cell);
                }
            }
            self.collapse_copy_sccs();
        }

        profile.quotient_nodes = (0..original_nodes as Cell)
            .map(|cell| self.canonical(cell))
            .collect::<HashSet<_>>()
            .len();
        profile.quotient_edges_before_factor = self.copy_edges();

        // Exact fanout factoring: S x D is replaced by S -> union -> D when every source in
        // S has precisely D as its successor set. The synthetic variable denotes only the
        // union of source contents and is never inserted as a pointee allocation identity.
        let mut fanout_by_source = BTreeMap::<Cell, BTreeSet<Cell>>::new();
        for (source, destination) in self.copy_edge_pairs() {
            fanout_by_source
                .entry(source)
                .or_default()
                .insert(destination);
        }
        let mut fanout_groups = BTreeMap::<Vec<Cell>, Vec<Cell>>::new();
        for (source, destinations) in fanout_by_source {
            if destinations.len() < 2 {
                continue;
            }
            let destinations = destinations.into_iter().collect::<Vec<_>>();
            fanout_groups.entry(destinations).or_default().push(source);
        }
        let profitable = fanout_groups
            .into_iter()
            .filter(|(destinations, sources)| {
                sources.len() >= 2
                    && sources.len().saturating_mul(destinations.len())
                        > sources.len().saturating_add(destinations.len())
            })
            .collect::<Vec<_>>();
        for (destinations, sources) in profitable {
            let old_edges = sources.len().saturating_mul(destinations.len());
            let new_edges = sources.len().saturating_add(destinations.len());
            for &source in &sources {
                let removed = self
                    .succ
                    .remove(&source)
                    .map_or(0, |successors| successors.len())
                    + self
                        .pending_succ
                        .remove(&source)
                        .map_or(0, |successors| successors.len());
                self.copy_edge_count = self
                    .copy_edge_count
                    .checked_sub(removed)
                    .expect("removed more copy edges than are tracked");
            }
            let union = self.allocate_cell();
            for source in sources {
                self.add_copy(source, union);
            }
            for destination in destinations {
                self.add_copy(union, destination);
            }
            profile.factored_groups += 1;
            profile.synthetic_nodes += 1;
            profile.factored_edges_removed += old_edges.saturating_sub(new_edges);
        }
        profile.quotient_edges = self.copy_edges();
        self.new_copy_edges_since_scc = self.pending_succ.values().map(HashSet::len).sum();
        profile.elapsed_micros = started.elapsed().as_micros();
        profile
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
        let old_edge_count = self.copy_edge_count;
        debug_assert_eq!(
            adjacency.iter().map(Vec::len).sum::<usize>(),
            old_edge_count,
            "cached copy-edge count diverged before SCC collapse"
        );
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

        let mut merged_pts = HashMap::<Cell, PointSet>::new();
        let hybrid_points_to = self.hybrid_points_to;
        for (cell, objects) in std::mem::take(&mut self.pts) {
            let destination = merged_pts
                .entry(representatives[cell as usize])
                .or_insert_with(|| PointSet::new(hybrid_points_to));
            for object in objects.iter() {
                destination.insert(object);
            }
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
        self.copy_edge_count = new_edge_count;

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

        let mut remapped_reads = HashMap::<Cell, Vec<(FieldLocation, Cell)>>::new();
        for (root, registrations) in std::mem::take(&mut self.overlap_reads) {
            let remapped = remapped_reads.entry(root).or_default();
            for (location, destination) in registrations {
                remapped.push((location, representatives[destination as usize]));
            }
            remapped.sort_unstable();
            remapped.dedup();
        }
        self.overlap_reads = remapped_reads;

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
            .map(|(&cell, objects)| (cell, objects.clone()))
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
        self.pts.values().map(PointSet::len).sum()
    }

    fn point_set_storage(&self) -> (usize, usize, usize, usize, usize) {
        self.pts.values().fold(
            (0usize, 0usize, 0usize, 0usize, 0usize),
            |(hash, small, sparse, dense, words), set| match set {
                PointSet::Hash(_) => (hash + 1, small, sparse, dense, words),
                PointSet::Hybrid(HybridPointSet::Small(_)) => {
                    (hash, small + 1, sparse, dense, words)
                }
                PointSet::Hybrid(HybridPointSet::Sparse { .. }) => {
                    (hash, small, sparse + 1, dense, words)
                }
                PointSet::Hybrid(HybridPointSet::Dense {
                    words: set_words, ..
                }) => (hash, small, sparse, dense + 1, words + set_words.len()),
            },
        )
    }

    fn copy_edges(&self) -> usize {
        self.copy_edge_count
    }

    fn copy_sources(&self) -> usize {
        self.succ.len()
            + self
                .pending_succ
                .keys()
                .filter(|source| !self.succ.contains_key(source))
                .count()
    }

    fn overlap_read_index_bytes(&self) -> usize {
        // Capacity-based lower-bound estimate for the persistent registration index; the
        // allocator/hash-table control bytes are intentionally not guessed here.
        self.overlap_reads
            .capacity()
            .saturating_mul(std::mem::size_of::<(Cell, Vec<(FieldLocation, Cell)>)>())
            .saturating_add(
                self.overlap_reads
                    .values()
                    .map(|reads| {
                        reads
                            .capacity()
                            .saturating_mul(std::mem::size_of::<(FieldLocation, Cell)>())
                    })
                    .sum::<usize>(),
            )
    }

    fn content_fields(&self, root: Cell) -> impl Iterator<Item = Cell> + '_ {
        self.obj_fields
            .get(&root)
            .into_iter()
            .flatten()
            .copied()
            .chain(
                self.receiver_payload_fields
                    .get(&root)
                    .into_iter()
                    .flatten()
                    .copied(),
            )
    }

    fn maybe_report_progress(&self) {
        if self.profile && self.steps % knobs::ANDERSEN_PROFILE_STEP_INTERVAL == 0 {
            eprintln!(
                "pangs andersen profile: solve progress steps={} worklist={} queued={} pts_entries={} pts_facts={} copy_sources={} copy_edges={} fields={} unknown_fields={} overlap_reads={} overlap_pairs={} overlap_late_replays={} overlap_index_roots={} overlap_index_entries={} overlap_index_capacity_bytes={} memcpy_pairs_processed={} memcpy_logical_pairs_covered={} memcpy_summary_edges_inserted={} memcpy_summary_sites={} memcpy_summary_cells={} copy_fact_pairs_processed={} load_pairs_processed={} store_pairs_processed={} gep_pairs_processed={} scc_passes={} scc_nodes_collapsed={} scc_copy_edges_removed={} new_copy_edges_since_scc={}",
                self.steps,
                self.worklist.len(),
                self.queued.len(),
                self.pts.len(),
                self.pts_facts(),
                self.copy_sources(),
                self.copy_edges(),
                self.fields.len(),
                self.unknown_fields.len(),
                self.overlap_read_dependencies,
                self.overlap_read_pairs,
                self.overlap_read_late_replays,
                self.overlap_reads.len(),
                self.overlap_reads.values().map(Vec::len).sum::<usize>(),
                self.overlap_read_index_bytes(),
                self.memcpy_pairs_processed,
                self.memcpy_logical_pairs_covered,
                self.memcpy_summary_edges_inserted,
                self.memcpy_summary_sites,
                self.memcpy_summary_cells_allocated,
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
            let pts_delta = self
                .pending_pts
                .remove(&n)
                .unwrap_or_else(|| PointSet::new(self.hybrid_points_to));
            let external_delta = self.pending_external_sources.remove(&n).unwrap_or_default();

            // Established copy edges consume only facts discovered since `n` last ran.
            if let Some(successors) = self.succ.get(&n).cloned() {
                self.copy_fact_pairs_processed = self
                    .copy_fact_pairs_processed
                    .saturating_add(pts_delta.len().saturating_mul(successors.len()));
                for successor in successors {
                    self.union_pts_delta(successor, &pts_delta);
                    self.add_external_sources(successor, &external_delta);
                }
            }

            // A new edge predates none of the source's facts, so seed it from the complete
            // set once and only then promote it to the established successor relation.
            let new_successors = self.pending_succ.remove(&n).unwrap_or_default();
            if !new_successors.is_empty() {
                let pending_successor_count = new_successors.len();
                self.copy_edge_count = self
                    .copy_edge_count
                    .checked_sub(pending_successor_count)
                    .expect("promoted more pending copy edges than are tracked");
                let all_pts = self
                    .pts
                    .get(&n)
                    .cloned()
                    .unwrap_or_else(|| PointSet::new(self.hybrid_points_to));
                let all_external_sources = self
                    .external_sources
                    .get(&n)
                    .map(|set| set.iter().cloned().collect::<Vec<_>>())
                    .unwrap_or_default();
                self.copy_fact_pairs_processed = self
                    .copy_fact_pairs_processed
                    .saturating_add(all_pts.len().saturating_mul(new_successors.len()));
                for &successor in &new_successors {
                    self.union_pts_delta(successor, &all_pts);
                    self.add_external_sources(successor, &all_external_sources);
                }
                let successors = self.succ.entry(n).or_default();
                let established_before = successors.len();
                successors.extend(new_successors);
                let promoted = successors.len() - established_before;
                self.copy_edge_count = self
                    .copy_edge_count
                    .checked_add(promoted)
                    .expect("copy-edge count overflow during promotion");
                debug_assert_eq!(
                    promoted, pending_successor_count,
                    "pending copy edge duplicated an established edge during promotion"
                );
            }

            // n as a load base: p = *n  ⇒  pts(o) ⊆ pts(p)  for o ∈ pts(n)
            if let Some(ps) = self.loads.get(&n).cloned() {
                self.report_large_product("load", n, ps.len(), pts_delta.len());
                self.load_pairs_processed = self
                    .load_pairs_processed
                    .saturating_add(ps.len().saturating_mul(pts_delta.len()));
                for p in ps {
                    for o in &pts_delta {
                        self.note_direct_access(o);
                        if self.asymmetric_field_overlap {
                            self.read_overlap(o, p);
                        } else {
                            self.add_copy(o, p);
                        }
                    }
                }
            }
            if let Some(ps) = self.pending_loads.remove(&n) {
                let all_pts = self
                    .pts
                    .get(&n)
                    .map(|set| set.iter().collect::<Vec<_>>())
                    .unwrap_or_default();
                self.report_large_product("new-load", n, ps.len(), all_pts.len());
                self.load_pairs_processed = self
                    .load_pairs_processed
                    .saturating_add(ps.len().saturating_mul(all_pts.len()));
                for &p in &ps {
                    for &o in &all_pts {
                        self.note_direct_access(o);
                        if self.asymmetric_field_overlap {
                            self.read_overlap(o, p);
                        } else {
                            self.add_copy(o, p);
                        }
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
                    for o in &pts_delta {
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
                    .map(|set| set.iter().collect::<Vec<_>>())
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
                    for o in &pts_delta {
                        let f = self.field_of(o, off);
                        self.add_pts(p, f);
                    }
                }
            }
            if let Some(gs) = self.pending_geps.remove(&n) {
                let all_pts = self
                    .pts
                    .get(&n)
                    .map(|set| set.iter().collect::<Vec<_>>())
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
                    if self.memcpys[index].summary.is_some() {
                        self.process_memcpy_summary(index, delta);
                        continue;
                    }
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
                    self.memcpy_logical_pairs_covered =
                        self.memcpy_logical_pairs_covered.saturating_add(
                            delta
                                .new_destinations
                                .len()
                                .saturating_mul(delta.all_sources.len()),
                        );
                    for &od in &delta.new_destinations {
                        self.note_direct_access(od);
                        for &os in &delta.all_sources {
                            self.note_direct_access(os);
                            if self.asymmetric_field_overlap {
                                self.read_overlap(
                                    self.allocation_root(os),
                                    self.allocation_root(od),
                                );
                            } else {
                                self.add_copy(os, od);
                            }
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
                    self.memcpy_logical_pairs_covered =
                        self.memcpy_logical_pairs_covered.saturating_add(
                            delta
                                .old_destinations
                                .len()
                                .saturating_mul(delta.new_sources.len()),
                        );
                    for &od in &delta.old_destinations {
                        self.note_direct_access(od);
                        for &os in &delta.new_sources {
                            self.note_direct_access(os);
                            if self.asymmetric_field_overlap {
                                self.read_overlap(
                                    self.allocation_root(os),
                                    self.allocation_root(od),
                                );
                            } else {
                                self.add_copy(os, od);
                            }
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
    use pangs_pir::{Pir, Stmt};

    use super::{
        finish_andersen_controlled, hybrid_points_to_enabled_for,
        memcpy_edge_summaries_enabled_for, solve_andersen, solve_andersen_with_overrides,
        AndersenControls, Cell, ExternalRegion, HybridPointSet, PointSet,
        RefinedPointeeGlobalInterner, Refiner, Solve,
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

    fn assert_copy_edge_count(solve: &Solve) {
        let derived = solve.succ.values().map(HashSet::len).sum::<usize>()
            + solve.pending_succ.values().map(HashSet::len).sum::<usize>();
        assert_eq!(solve.copy_edges(), derived);
    }

    #[test]
    fn refined_pointee_global_interner_shares_identical_name_lists() {
        let pir: Pir = serde_json::from_str(
            r#"{
                "module":"pointee-interner",
                "globals":[
                    {"key":"global_a","mutable":true},
                    {"key":"global_b","mutable":true},
                    {"key":"global_c","mutable":true}
                ]
            }"#,
        )
        .unwrap();
        let mut interner = RefinedPointeeGlobalInterner::default();

        let first = interner.intern(vec![0, 2], &pir);
        let duplicate = interner.intern(vec![0, 2], &pir);
        let distinct = interner.intern(vec![1, 2], &pir);

        assert_eq!(first.cache_key(), duplicate.cache_key());
        assert_ne!(first.cache_key(), distinct.cache_key());
        assert_eq!(&*first, &["global_a".to_string(), "global_c".to_string()]);
        assert_eq!(interner.by_indices.len(), 2);
    }

    #[test]
    fn hybrid_point_set_uses_sparse_middle_tier() {
        let mut set = PointSet::new(true);
        let expected = (0..20)
            .map(|cell| cell * 10_000 + 1)
            .collect::<HashSet<_>>();
        for &cell in &expected {
            assert!(set.insert(cell));
            assert!(!set.insert(cell));
        }
        assert!(matches!(
            set,
            PointSet::Hybrid(HybridPointSet::Sparse { .. })
        ));
        assert_eq!(set, expected);
    }

    #[test]
    fn hybrid_point_set_promotes_and_iterates_dense_members() {
        let mut set = PointSet::new(true);
        let expected = (0..200).collect::<HashSet<_>>();
        for &cell in &expected {
            assert!(set.insert(cell));
            assert!(!set.insert(cell));
        }
        assert!(matches!(
            set,
            PointSet::Hybrid(HybridPointSet::Dense { .. })
        ));
        assert_eq!(set, expected);
    }

    #[test]
    fn hybrid_point_set_demotes_before_sparse_high_id_growth() {
        let mut set = PointSet::new(true);
        let mut expected = (0..200).collect::<HashSet<_>>();
        for &cell in &expected {
            assert!(set.insert(cell));
        }
        assert!(matches!(
            set,
            PointSet::Hybrid(HybridPointSet::Dense { .. })
        ));

        expected.insert(Cell::MAX - 1);
        assert!(set.insert(Cell::MAX - 1));
        assert!(matches!(
            set,
            PointSet::Hybrid(HybridPointSet::Sparse { .. })
        ));
        assert_eq!(set, expected);
    }

    #[test]
    fn hybrid_point_set_union_delta_keeps_dense_changes_wordwise() {
        let mut destination = PointSet::new(true);
        let mut source = PointSet::new(true);
        for cell in 0..200 {
            destination.insert(cell);
        }
        for cell in 100..300 {
            source.insert(cell);
        }

        let delta = destination.union_delta(&source);
        assert!(matches!(
            destination,
            PointSet::Hybrid(HybridPointSet::Dense { .. })
        ));
        assert!(matches!(
            delta,
            PointSet::Hybrid(HybridPointSet::Dense { .. })
        ));
        assert_eq!(destination, (0..300).collect::<HashSet<_>>());
        assert_eq!(delta, (200..300).collect::<HashSet<_>>());
    }

    #[test]
    fn hybrid_point_set_union_delta_sparsifies_small_dense_remainder() {
        let mut destination = PointSet::new(true);
        let mut source = PointSet::new(true);
        for cell in 0..200 {
            destination.insert(cell);
            source.insert(cell);
        }
        source.insert(200);
        source.insert(201);

        let delta = destination.union_delta(&source);
        assert!(matches!(delta, PointSet::Hybrid(HybridPointSet::Small(_))));
        assert_eq!(delta, [200, 201].into_iter().collect::<HashSet<_>>());
        assert!(destination.union_delta(&source).is_empty());
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
    fn closed_producer_graph_shares_compositional_direct_call_flow() {
        let (pir, pag) = load("closed_producer_compositional.pir.json");
        let labels = BTreeSet::new();
        let (base, classes) =
            crate::solve_steensgaard_classes_targeted(&pir, &pag, BuildMode::Library, &labels);
        let exact_targets = BTreeMap::new();
        let confined_targets = BTreeSet::new();
        let mut refiner = Refiner::new(
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
        let mut solve = refiner.build_base_solve(false);
        solve.run();
        let analysis = refiner.closed_producer_analysis(&solve);
        let indirect = pag
            .callsites
            .iter()
            .filter(|callsite| callsite.kind == pangs_pag::CallKind::Indirect)
            .collect::<Vec<_>>();
        assert_eq!(indirect.len(), 3);

        for callsite in &indirect[..2] {
            let query = refiner.query_closed_producer(
                &analysis,
                &solve,
                callsite.operand.expect("indirect operand"),
            );
            assert!(query.complete);
            assert!(!query.external);
            assert!(!query.non_function);
            assert_eq!(
                query
                    .targets
                    .iter()
                    .map(|&function| pir.functions[function].key.as_str())
                    .collect::<Vec<_>>(),
                vec!["target"]
            );
        }

        let unknown = refiner.query_closed_producer(
            &analysis,
            &solve,
            indirect[2].operand.expect("indirect operand"),
        );
        assert!(!unknown.complete);
        assert!(unknown.external);
        assert!(unknown.targets.is_empty());
    }

    #[test]
    fn closed_producer_certificate_clears_only_certified_unknown_calls() {
        let (pir, pag) = load("closed_producer_compositional.pir.json");
        let labels = BTreeSet::new();
        let (mut base, classes) =
            crate::solve_steensgaard_classes_targeted(&pir, &pag, BuildMode::Library, &labels);
        let mut rows = base.indirect_calls.iter_mut();
        for row in rows.by_ref().take(2) {
            // Model a deliberately conservative base-tier unknown bit. The closed-producer
            // tier may remove it only after independently certifying the fixed PAG slice.
            row.unknown_callee = true;
            row.fallback = true;
        }
        let result = finish_andersen_controlled(
            &pir,
            &pag,
            &classes,
            base,
            BuildMode::Library,
            u64::MAX,
            &BTreeMap::new(),
            &BTreeSet::new(),
            false,
            AndersenControls {
                closed_producers: true,
                ..AndersenControls::default()
            },
        );
        assert_eq!(result.indirect_calls.len(), 3);
        for row in &result.indirect_calls[..2] {
            assert_eq!(row.targets, vec!["target".to_string()]);
            assert!(!row.unknown_callee);
            assert!(!row.fallback);
        }
        assert!(result.indirect_calls[2].unknown_callee);
        assert!(result.indirect_calls[2].fallback);
    }

    #[test]
    fn asymmetric_exact_endpoint_memcpy_keeps_closed_producer_incomplete() {
        // Rewrite the existing two-field bulk-copy fixture so the source endpoint is its
        // exact-zero field. C still treats the copy as whole-object, and the producer audit
        // must therefore fail the destination root/fields incomplete rather than certifying
        // the callback loaded from the destination's exact-zero field.
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/synthetic/m1_4b/aggregate_copy_fnptr_table.pir.json");
        let text = std::fs::read_to_string(path).unwrap();
        let text = text.replace(
            r#"{ "kind": "memcpy", "dst": "@lc", "src": "%lit", "bytes": 16 }"#,
            r#"{ "kind": "memcpy", "dst": "@lc", "src": "%lit.intro", "bytes": 16 }"#,
        );
        let pir: Pir = serde_json::from_str(&text).unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        let labels = BTreeSet::new();
        let (base, classes) =
            crate::solve_steensgaard_classes_targeted(&pir, &pag, BuildMode::Library, &labels);
        let exact = BTreeMap::new();
        let confined = BTreeSet::new();
        let mut refiner = Refiner::new(
            &pir,
            &pag,
            &classes,
            &base,
            BuildMode::Library,
            u64::MAX,
            &exact,
            &confined,
            false,
        );
        let mut solve = refiner.build_base_solve(true);
        solve.run();
        let analysis = refiner.closed_producer_analysis(&solve);
        let operand = pag
            .callsites
            .iter()
            .find(|callsite| callsite.kind == pangs_pag::CallKind::Indirect)
            .and_then(|callsite| callsite.operand)
            .expect("fixture indirect operand");
        assert!(
            !refiner
                .query_closed_producer(&analysis, &solve, operand)
                .complete,
            "whole-object exact-endpoint memcpy must not receive a closed-producer certificate"
        );
    }

    #[test]
    fn closed_consumer_certificate_clears_spurious_unknown_caller() {
        let (pir, pag) = load("closed_producer_compositional.pir.json");
        let labels = BTreeSet::new();
        let (mut base, classes) =
            crate::solve_steensgaard_classes_targeted(&pir, &pag, BuildMode::Library, &labels);
        // Model the class-level false positive this certificate is intended to override.
        base.unknown_callers.insert("target".to_string());
        for asymmetric_field_overlap in [false, true] {
            let result = finish_andersen_controlled(
                &pir,
                &pag,
                &classes,
                base.clone(),
                BuildMode::Library,
                u64::MAX,
                &BTreeMap::new(),
                &BTreeSet::new(),
                false,
                AndersenControls {
                    asymmetric_field_overlap,
                    closed_consumers: true,
                    ..AndersenControls::default()
                },
            );
            assert!(!result.unknown_callers.contains("target"));
        }
    }

    #[test]
    fn closed_consumer_certificate_retains_external_registration() {
        let (pir, pag) = load("closed_consumer_external.pir.json");
        let labels = BTreeSet::new();
        let (mut base, classes) =
            crate::solve_steensgaard_classes_targeted(&pir, &pag, BuildMode::Library, &labels);
        base.unknown_callers.insert("target".to_string());
        for asymmetric_field_overlap in [false, true] {
            let result = finish_andersen_controlled(
                &pir,
                &pag,
                &classes,
                base.clone(),
                BuildMode::Library,
                u64::MAX,
                &BTreeMap::new(),
                &BTreeSet::new(),
                false,
                AndersenControls {
                    asymmetric_field_overlap,
                    closed_consumers: true,
                    ..AndersenControls::default()
                },
            );
            assert!(result.unknown_callers.contains("target"));
        }
    }

    #[test]
    fn asymmetric_exported_field_callback_remains_an_unknown_external_consumer() {
        // The exported root cell itself has no payload: the callback exists only in a
        // materialized field. This exercises raw-root boundary traversal under C, including
        // both certificates, without relying on process-global environment mutation.
        let (pir, pag) = load_m1_4("exported_field_callback.pir.json");
        let labels = BTreeSet::new();
        let (mut base, classes) =
            crate::solve_steensgaard_classes_targeted(&pir, &pag, BuildMode::Library, &labels);
        base.unknown_callers.insert("cb".to_string());
        base.unknown_callers.insert("local_cb".to_string());
        let result = finish_andersen_controlled(
            &pir,
            &pag,
            &classes,
            base,
            BuildMode::Library,
            u64::MAX,
            &BTreeMap::new(),
            &BTreeSet::new(),
            false,
            AndersenControls {
                asymmetric_field_overlap: true,
                closed_producers: true,
                closed_consumers: true,
                ..AndersenControls::default()
            },
        );
        assert!(result.unknown_callers.contains("cb"));
        assert!(
            !result.unknown_callers.contains("local_cb"),
            "the unexported table must not inherit the exported table boundary"
        );
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

    /// A pointer `va_arg` on the SysV ABI is a two-level extraction: load an area pointer out of
    /// the list, then load the value out of that. The payload region must therefore stay opaque
    /// through any number of loads, or the extracted pointer would come back empty — a missed
    /// store destination rather than a conservative one.
    #[test]
    fn unproved_va_list_contents_stay_external_through_repeated_loads() {
        let pir: Pir = serde_json::from_str(
            r#"{
                "module":"va-list-payload",
                "globals":[{"key":"@g","mutable":true}],
                "functions":[
                    {"key":"wrapper","sig":{"ret":{"class":"void"},"params":[{"class":"integer"}],"vararg":true},
                     "param_names":["%wrapper::fmt"],
                     "body":[
                        {"kind":"alloca","dest":"%wrapper::ap","ty":"[1 x %struct.__va_list_tag]"},
                        {"kind":"gep","dest":"%wrapper::decay","base":"%wrapper::ap","byte_off":0},
                        {"kind":"va_start","list":"%wrapper::decay"},
                        {"kind":"load","dest":"%wrapper::area","address":"%wrapper::decay","access_bytes":8},
                        {"kind":"load","dest":"%wrapper::deep","address":"%wrapper::area","access_bytes":8},
                        {"kind":"load","dest":"%wrapper::deeper","address":"%wrapper::deep","access_bytes":8},
                        {"kind":"va_end","list":"%wrapper::decay"},
                        {"kind":"return","value":null}
                     ]},
                    {"key":"driver","exported":true,"sig":{"ret":{"class":"void"},"params":[]},
                     "body":[
                        {"kind":"alloca","dest":"%driver::local","ty":"i8"},
                        {"kind":"gep","dest":"%driver::addr","base":"@g","byte_off":0},
                        {"kind":"call_direct","callee":"wrapper","sig":{"ret":{"class":"void"},"params":[{"class":"integer"}],"vararg":true},"args":["%driver::fmt","%driver::addr"]},
                        {"kind":"return","value":null}
                     ]}
                ]
            }"#,
        )
        .unwrap();
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        let andersen = solve_andersen(&pir, &pag, BuildMode::Executable, 1_000_000);
        for label in [
            "val:wrapper:%wrapper::area",
            "val:wrapper:%wrapper::deep",
            "val:wrapper:%wrapper::deeper",
        ] {
            let node = &andersen.nodes[label];
            assert!(node.external, "{label} must stay opaque");
            assert!(!node.proven_empty, "{label} must not be certified empty");
        }
        // The list's own address is still an ordinary local: `va_start` does not publish it.
        let steens = solve_steensgaard(&pir, &pag, BuildMode::Executable);
        for label in ["val:wrapper:%wrapper::deep", "val:wrapper:%wrapper::deeper"] {
            assert!(steens.nodes[label].external, "{label} in steensgaard");
        }
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
        assert!(path.pointee_globals.is_empty());

        let external_result = &result.nodes["val:main:%external_result"];
        assert!(external_result.external);
        assert!(external_result.pointee_globals.is_empty());

        let forged = &result.nodes["val:main:%forged"];
        assert!(forged.external);
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
        solve.memcpy_edge_summaries = false;
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
        solve.memcpy_edge_summaries = false;
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
    fn memcpy_summary_matches_incremental_direct_join() {
        fn problem(summarized: bool) -> Solve {
            let mut solve = Solve::new(12, false);
            solve.memcpy_edge_summaries = summarized;
            solve.add_memcpy(0, 1);
            solve.add_pts(0, 2);
            solve.add_pts(1, 3);
            solve.add_pts(3, 6);
            solve.run();
            solve.add_pts(0, 4);
            solve.add_pts(1, 5);
            solve.add_pts(5, 7);
            solve.run();
            solve.add_pts(3, 8);
            solve.run();
            solve
        }

        let direct = problem(false);
        let summarized = problem(true);
        assert_eq!(
            original_points_to(&summarized, 12),
            original_points_to(&direct, 12)
        );
        assert_eq!(summarized.direct_accessed, direct.direct_accessed);
        assert_eq!(direct.memcpy_pairs_processed, 4);
        assert_eq!(summarized.memcpy_pairs_processed, 0);
        assert_eq!(summarized.memcpy_logical_pairs_covered, 4);
        assert_eq!(summarized.memcpy_summary_sites, 1);
        assert_eq!(summarized.memcpy_summary_cells_allocated, 1);
        assert_eq!(summarized.memcpy_summary_edges_inserted, 4);
        let summary = *summarized.memcpy_summary_cells.iter().next().unwrap();
        assert!(summarized
            .pts
            .values()
            .all(|points_to| !points_to.contains(&summary)));
    }

    #[test]
    fn whole_object_access_exchanges_facts_with_its_field_cells() {
        // A whole-object store writes the root cell; a constant-offset read uses a distinct
        // field cell. Without the bridge the two never exchange anything, so the field read
        // comes back empty even though the object demonstrably holds the pointer.
        let mut solve = Solve::new(6, false);
        let object = 2;
        let field = solve.field_of(object, FieldLocation::Exact(0));
        solve.note_direct_access(object);
        solve.add_pts(object, 4);
        solve.run();
        assert!(
            solve.points_to(field).is_some_and(|set| set.contains(&4)),
            "whole-object access did not reach its field cell"
        );
    }

    #[test]
    fn asymmetric_overlap_keeps_exact_siblings_isolated_but_unknown_reads_them() {
        fn problem(asymmetric: bool) -> (bool, bool) {
            let mut solve = Solve::new_with_pwc_and_overlap(10, false, false, asymmetric);
            let root = 0;
            let exact0 = solve.field_of(root, FieldLocation::Exact(0));
            let exact8 = solve.field_of(root, FieldLocation::Exact(8));
            let unknown = solve.unknown_field_of(root);
            solve.add_pts(1, exact0);
            solve.add_pts(2, unknown);
            solve.add_pts(exact8, 9);
            solve.add_load(1, 3);
            solve.add_load(2, 4);
            solve.run();
            (
                solve.points_to(3).is_some_and(|set| set.contains(&9)),
                solve.points_to(4).is_some_and(|set| set.contains(&9)),
            )
        }

        assert_eq!(
            problem(false),
            (true, true),
            "baseline retains symmetric bridges"
        );
        assert_eq!(problem(true), (false, true));
    }

    #[test]
    fn asymmetric_overlap_replays_a_late_exact_field_into_an_existing_read() {
        let mut solve = Solve::new_with_pwc_and_overlap(10, false, false, true);
        let unknown = solve.unknown_field_of(0);
        solve.add_pts(1, unknown);
        solve.add_load(1, 2);
        solve.run();

        let late = solve.field_of(0, FieldLocation::Exact(8));
        solve.add_pts(late, 9);
        solve.run();
        assert!(solve.points_to(2).is_some_and(|set| set.contains(&9)));
        assert!(solve.overlap_read_late_replays > 0);
    }

    #[test]
    fn asymmetric_overlap_remaps_read_destination_after_copy_scc() {
        let mut solve = Solve::new_with_pwc_and_overlap(12, false, false, true);
        solve.scc_min_edges = 1;
        let unknown = solve.unknown_field_of(0);
        solve.add_pts(1, unknown);
        solve.add_load(1, 3);
        solve.add_copy(3, 4);
        solve.add_copy(4, 3);
        solve.run();
        assert_eq!(solve.canonical(3), solve.canonical(4));

        let late = solve.field_of(0, FieldLocation::Exact(8));
        solve.add_pts(late, 10);
        solve.run();
        assert!(solve.points_to(3).is_some_and(|set| set.contains(&10)));
        assert!(solve.points_to(4).is_some_and(|set| set.contains(&10)));
    }

    #[test]
    fn asymmetric_memcpy_uses_whole_object_source_for_both_join_forms() {
        for summarized in [false, true] {
            let mut solve = Solve::new_with_pwc_and_overlap(16, false, false, true);
            solve.memcpy_edge_summaries = summarized;
            // Both endpoints are exact-zero fields.  A whole-object memcpy still transfers
            // the pointer stored at byte 8 without relying on an Unknown cell bridge.
            let source0 = solve.field_of(2, FieldLocation::Exact(0));
            let source8 = solve.field_of(2, FieldLocation::Exact(8));
            let destination0 = solve.field_of(3, FieldLocation::Exact(0));
            let destination8 = solve.field_of(3, FieldLocation::Exact(8));
            solve.add_pts(0, destination0);
            solve.add_pts(1, source0);
            solve.add_pts(source8, 12);
            solve.add_memcpy(0, 1);
            solve.add_pts(4, destination8);
            solve.add_load(4, 5);
            solve.run();
            assert!(
                solve.points_to(5).is_some_and(|set| set.contains(&12)),
                "whole-object field memcpy lost byte-8 payload with summaries={summarized}"
            );
        }
    }

    #[test]
    fn asymmetric_memcpy_replays_late_source_fields_for_direct_and_summary_joins() {
        for summarized in [false, true] {
            let mut solve = Solve::new_with_pwc_and_overlap(16, false, false, true);
            solve.memcpy_edge_summaries = summarized;
            solve.add_pts(0, 2);
            solve.add_pts(1, 3);
            solve.add_memcpy(0, 1);
            solve.run();

            let late_source = solve.field_of(3, FieldLocation::Exact(8));
            let destination = solve.field_of(2, FieldLocation::Exact(8));
            solve.add_pts(late_source, 12);
            solve.add_pts(4, destination);
            solve.add_load(4, 5);
            solve.run();
            assert!(
                solve.points_to(5).is_some_and(|set| set.contains(&12)),
                "late memcpy source field was not replayed with summaries={summarized}"
            );
        }
    }

    #[test]
    fn asymmetric_unknown_and_whole_object_writes_reach_each_exact_read_without_cross_root_leakage()
    {
        let mut solve = Solve::new_with_pwc_and_overlap(16, false, false, true);
        let exact_a = solve.field_of(0, FieldLocation::Exact(8));
        let exact_b = solve.field_of(1, FieldLocation::Exact(8));
        let unknown_a = solve.unknown_field_of(0);
        solve.add_pts(2, exact_a);
        solve.add_pts(3, exact_b);
        solve.add_pts(4, unknown_a);
        solve.add_pts(unknown_a, 12);
        solve.add_pts(0, 13); // raw whole-object write
        solve.add_load(2, 5);
        solve.add_load(3, 6);
        solve.add_load(4, 7);
        solve.run();
        assert!(solve
            .points_to(5)
            .is_some_and(|set| set.contains(&12) && set.contains(&13)));
        assert!(solve
            .points_to(7)
            .is_some_and(|set| set.contains(&12) && set.contains(&13)));
        assert!(solve
            .points_to(6)
            .is_none_or(|set| !set.contains(&12) && !set.contains(&13)));
    }

    #[test]
    fn asymmetric_overlap_reads_lane_and_exact_in_both_directions() {
        let lane = FieldLocation::Lane(pangs_pir::GepLane::new(16, 0).unwrap());
        for reversed in [false, true] {
            let mut solve = Solve::new_with_pwc_and_overlap(12, false, true, true);
            let exact = solve.field_of(0, FieldLocation::Exact(0));
            let lane_cell = solve.field_of(0, lane);
            let (written, addressed) = if reversed {
                (exact, lane_cell)
            } else {
                (lane_cell, exact)
            };
            solve.add_pts(1, addressed);
            solve.add_pts(written, 10);
            solve.add_load(1, 2);
            solve.run();
            assert!(solve.points_to(2).is_some_and(|set| set.contains(&10)));
        }
    }

    #[test]
    fn bulk_copied_fnptr_table_resolves_its_dispatch_site() {
        // A global callback table populated only by a compound-literal assignment. The copy
        // is field-insensitive, so the site sees both members -- but it must not come back
        // empty with an omega marker, which is what a root-to-root contents copy produced.
        let (pir, pag) = load("aggregate_copy_fnptr_table.pir.json");
        let andersen = solve_andersen(&pir, &pag, BuildMode::Library, 1_000_000);
        assert_eq!(andersen.indirect_calls.len(), 1);
        let call = &andersen.indirect_calls[0];
        assert!(
            call.targets.contains(&"intro".to_string()),
            "bulk-copied callback table did not reach the dispatch site: {call:?}"
        );
        assert!(
            !call.unknown_callee,
            "site retained its omega marker: {call:?}"
        );
    }

    #[test]
    fn hybrid_points_to_default_on_with_zero_opt_out() {
        assert!(hybrid_points_to_enabled_for(None));
        assert!(hybrid_points_to_enabled_for(Some("1")));
        assert!(hybrid_points_to_enabled_for(Some("")));
        assert!(!hybrid_points_to_enabled_for(Some("0")));
    }

    #[test]
    fn bulk_copy_carriers_admit_their_source_allocation() {
        // The copy is the only link between `producer`'s local literal and a mutable
        // global. Its address carriers must join that component, or the literal's
        // `AddrOf`/`Assign` producers are excluded from the admitted solve and the
        // source-side load resolves to nothing.
        let (pir, pag) = load("aggregate_copy_scope.pir.json");
        let andersen = solve_andersen(&pir, &pag, BuildMode::Library, 1_000_000);
        assert_eq!(andersen.indirect_calls.len(), 1);
        let call = &andersen.indirect_calls[0];
        assert_eq!(
            call.targets,
            vec!["handler".to_string()],
            "bulk copy solved with an empty source set: {call:?}"
        );
    }

    #[test]
    fn memcpy_edge_summaries_default_on_with_zero_opt_out() {
        assert!(memcpy_edge_summaries_enabled_for(None));
        assert!(memcpy_edge_summaries_enabled_for(Some("1")));
        assert!(memcpy_edge_summaries_enabled_for(Some("")));
        assert!(!memcpy_edge_summaries_enabled_for(Some("0")));
    }

    #[test]
    fn memcpy_summary_preserves_empty_side_direct_access_guards() {
        let mut empty_source = Solve::new(8, false);
        empty_source.memcpy_edge_summaries = true;
        empty_source.add_memcpy(0, 1);
        empty_source.add_pts(0, 2);
        empty_source.run();
        assert!(empty_source.direct_accessed.contains(&2));
        assert!(!empty_source.memcpys[0].summary_active);
        assert_eq!(empty_source.memcpy_summary_edges_inserted, 0);

        let mut empty_destination = Solve::new(8, false);
        empty_destination.memcpy_edge_summaries = true;
        empty_destination.add_memcpy(0, 1);
        empty_destination.add_pts(1, 3);
        empty_destination.add_pts(3, 6);
        empty_destination.run();
        assert!(!empty_destination.direct_accessed.contains(&3));
        assert!(!empty_destination.memcpys[0].summary_active);
        assert_eq!(empty_destination.memcpy_summary_edges_inserted, 0);

        // A late opposite endpoint activates the retained source and seeds its complete
        // current contents through the newly installed star.
        empty_destination.add_pts(0, 2);
        empty_destination.run();
        assert!(empty_destination.direct_accessed.contains(&2));
        assert!(empty_destination.direct_accessed.contains(&3));
        assert!(empty_destination.memcpys[0].summary_active);
        assert!(empty_destination.points_to(2).unwrap().contains(&6));
    }

    #[test]
    fn memcpy_summary_preserves_late_unknown_field_bridges() {
        fn problem(summarized: bool) -> (Solve, Cell, Cell) {
            let mut solve = Solve::new(12, false);
            solve.memcpy_edge_summaries = summarized;
            solve.known_locations.insert(FieldLocation::Exact(4));
            solve.add_memcpy(0, 1);
            solve.add_pts(0, 2);
            solve.add_pts(1, 3);
            solve.add_pts(3, 6);
            solve.run();

            let source_field = solve.field_of(3, FieldLocation::Exact(4));
            solve.add_pts(source_field, 7);
            let source_unknown = solve.unknown_field_of(3);
            let destination_field = solve.field_of(2, FieldLocation::Exact(4));
            let destination_unknown = solve.unknown_field_of(2);
            solve.run();
            assert!(solve.points_to(source_unknown).unwrap().contains(&7));
            assert!(solve.points_to(destination_unknown).unwrap().contains(&7));
            (solve, destination_field, destination_unknown)
        }

        let (direct, direct_field, direct_unknown) = problem(false);
        let (summarized, summarized_field, summarized_unknown) = problem(true);
        for fact in [6, 7] {
            assert_eq!(
                summarized.points_to(2).unwrap().contains(&fact),
                direct.points_to(2).unwrap().contains(&fact)
            );
            assert_eq!(
                summarized
                    .points_to(summarized_field)
                    .unwrap()
                    .contains(&fact),
                direct.points_to(direct_field).unwrap().contains(&fact)
            );
            assert_eq!(
                summarized
                    .points_to(summarized_unknown)
                    .unwrap()
                    .contains(&fact),
                direct.points_to(direct_unknown).unwrap().contains(&fact)
            );
        }
    }

    #[test]
    fn memcpy_summary_preserves_external_origin_labels() {
        let mut solve = Solve::new(8, false);
        solve.memcpy_edge_summaries = true;
        solve.add_memcpy(0, 1);
        let external = solve.region(ExternalRegion::ExternalReturn(7));
        solve.add_pts(0, 2);
        solve.add_pts(1, 3);
        solve.add_pts_with_source(3, external, Some("memcpy-external"));
        solve.run();

        assert!(solve.points_to(2).unwrap().contains(&external));
        assert!(solve
            .external_sources_for(2)
            .unwrap()
            .contains("memcpy-external"));
        let summary = solve.memcpys[0].summary.unwrap();
        assert!(solve
            .external_sources_for(summary)
            .unwrap()
            .contains("memcpy-external"));
    }

    #[test]
    fn memcpy_summaries_remain_site_local_after_scc_canonicalization() {
        let mut solve = Solve::new(16, false);
        solve.memcpy_edge_summaries = true;
        solve.scc_min_edges = 1;
        solve.add_memcpy(0, 1);
        solve.add_memcpy(2, 3);
        solve.add_pts(0, 4);
        solve.add_pts(1, 5);
        solve.add_pts(2, 6);
        solve.add_pts(3, 7);
        solve.add_pts(5, 10);
        solve.add_pts(7, 11);
        solve.add_copy(0, 2);
        solve.add_copy(2, 0);
        solve.add_copy(1, 3);
        solve.add_copy(3, 1);
        solve.run();

        assert_eq!(solve.memcpys.len(), 2);
        assert_eq!(solve.memcpy_summary_cells.len(), 2);
        assert_ne!(solve.memcpys[0].summary, solve.memcpys[1].summary);
        assert_eq!(solve.canonical(0), solve.canonical(2));
        assert_eq!(solve.canonical(1), solve.canonical(3));
        assert!(solve.points_to(4).unwrap().contains(&10));
        assert!(solve.points_to(6).unwrap().contains(&11));
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
    fn cached_copy_edge_count_tracks_every_graph_mutation() {
        let mut promoted = Solve::new(4, false);
        promoted.add_copy(0, 1);
        promoted.add_copy(0, 2);
        promoted.add_copy(0, 2);
        assert_eq!(promoted.copy_edges(), 2);
        assert_copy_edge_count(&promoted);
        promoted.run();
        assert!(promoted.pending_succ.is_empty());
        assert_eq!(promoted.copy_edges(), 2);
        assert_copy_edge_count(&promoted);

        let mut collapsed = Solve::new(4, false);
        collapsed.add_copy(0, 1);
        collapsed.add_copy(1, 0);
        collapsed.add_copy(1, 2);
        assert_eq!(collapsed.copy_edges(), 3);
        collapsed.collapse_copy_sccs();
        assert_eq!(collapsed.copy_edges(), 1);
        assert_copy_edge_count(&collapsed);

        let mut factored = Solve::new(5, false);
        for source in [0, 1] {
            for destination in [2, 3, 4] {
                factored.add_copy(source, destination);
            }
        }
        assert_eq!(factored.copy_edges(), 6);
        let fixed = HashSet::from([0, 1, 2, 3, 4]);
        let profile = factored.offline_quotient(&fixed);
        assert_eq!(profile.factored_groups, 1);
        assert_eq!(factored.copy_edges(), 5);
        assert_copy_edge_count(&factored);

        factored.release_propagation_state();
        assert_eq!(factored.copy_edges(), 0);
        assert_copy_edge_count(&factored);
    }

    #[test]
    fn result_compaction_releases_propagation_state_but_preserves_queries() {
        let mut solve = Solve::new(8, false);
        let external = solve.region(ExternalRegion::ExternalReturn(3));
        let field = solve.field_of(4, FieldLocation::Exact(8));
        solve.add_pts_with_source(0, external, Some("external-result"));
        solve.add_pts(0, field);
        solve.add_copy(0, 1);
        solve.add_load(1, 2);
        solve.run();

        let points_to = solve.points_to(1).unwrap().iter().collect::<HashSet<_>>();
        let sources = solve.external_sources_for(1).unwrap().clone();
        assert!(!solve.succ.is_empty());
        assert!(!solve.loads.is_empty());
        assert_eq!(solve.field_base.get(&field), Some(&4));

        solve.release_propagation_state();

        assert_eq!(
            solve.points_to(1).unwrap().iter().collect::<HashSet<_>>(),
            points_to
        );
        assert_eq!(solve.external_sources_for(1), Some(&sources));
        assert_eq!(
            solve.external_region(external),
            Some(ExternalRegion::ExternalReturn(3))
        );
        assert_eq!(solve.field_base.get(&field), Some(&4));
        assert!(solve.obj_fields.get(&4).unwrap().contains(&field));
        assert!(solve.succ.is_empty());
        assert!(solve.loads.is_empty());
        assert!(solve.fields.is_empty());
        assert!(solve.worklist.is_empty());
    }

    fn original_points_to(solve: &Solve, cells: usize) -> Vec<HashSet<Cell>> {
        (0..cells as Cell)
            .map(|cell| {
                solve
                    .points_to(cell)
                    .map(|set| set.iter().collect())
                    .unwrap_or_default()
            })
            .collect()
    }

    /// Points-to sets with synthetic field cells replaced by the `(root, location)` they
    /// denote. Raw cell ids are allocation-order artifacts: materializing one extra
    /// unknown-offset summary shifts every later id, so two runs that agree semantically can
    /// disagree numerically. Comparing identities asserts what the caller actually means.
    fn original_points_to_by_identity(
        solve: &Solve,
        cells: usize,
    ) -> Vec<HashSet<(Cell, Option<FieldLocation>)>> {
        (0..cells as Cell)
            .map(|cell| {
                solve
                    .points_to(cell)
                    .map(|set| {
                        set.iter()
                            .map(|pointee| match solve.field_base.get(&pointee) {
                                Some(&root) => (root, solve.field_location.get(&pointee).copied()),
                                None => (pointee, None),
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            })
            .collect()
    }

    #[test]
    fn offline_quotient_exactly_substitutes_chains_diamonds_and_static_cycles() {
        fn problem() -> Solve {
            let mut solve = Solve::new(16, false);
            solve.add_pts(0, 10);
            solve.add_pts(1, 11);
            solve.add_copy(0, 2);
            solve.add_copy(1, 2);
            solve.add_copy(0, 3);
            solve.add_copy(1, 3);
            solve.add_copy(2, 4);
            solve.add_copy(4, 5);
            solve.add_copy(5, 4);
            solve.add_external_sources(0, &["client-root".to_string()]);
            solve
        }

        let mut baseline = problem();
        baseline.run();
        let expected = original_points_to(&baseline, 16);

        let mut quotient = problem();
        let profile = quotient.offline_quotient(&HashSet::new());
        quotient.run();
        assert_eq!(original_points_to(&quotient, 16), expected);
        assert!(profile.static_scc_merges >= 1);
        assert!(profile.substitutions >= 1);
        assert!(profile.value_number_merges >= 1);
        // Original query IDs remain valid and retain copied provenance.
        assert!(quotient
            .external_sources_for(5)
            .unwrap()
            .contains("client-root"));
    }

    #[test]
    fn offline_quotient_preserves_load_store_gep_and_memcpy_closure() {
        fn problem() -> Solve {
            let mut solve = Solve::new(24, false);
            solve.known_locations.insert(FieldLocation::Exact(4));
            solve.add_pts(0, 8);
            solve.add_pts(1, 9);
            solve.add_pts(4, 14);
            solve.add_pts(8, 12);
            solve.add_pts(9, 13);
            solve.add_copy(0, 2);
            solve.add_load(2, 3);
            solve.add_store(2, 4, None);
            solve.add_gep(2, FieldLocation::Exact(4), 5);
            solve.add_memcpy(2, 1);
            solve
        }

        let mut baseline = problem();
        baseline.run();
        let expected = original_points_to_by_identity(&baseline, 24);

        let mut quotient = problem();
        quotient.offline_quotient(&HashSet::new());
        quotient.run();
        assert_eq!(original_points_to_by_identity(&quotient, 24), expected);
        assert_eq!(
            quotient.memcpy_pairs_processed,
            baseline.memcpy_pairs_processed
        );
    }

    #[test]
    fn offline_quotient_protects_independent_and_late_generators() {
        let mut solve = Solve::new(12, false);
        solve.add_pts(0, 8);
        solve.add_copy(0, 2);
        solve.add_copy(0, 3);
        solve.add_pts(2, 9); // Superficially similar to 3, but independently seeded.
        solve.offline_quotient(&HashSet::from([3])); // Model a late call result/formal.
        assert_ne!(solve.canonical(2), solve.canonical(3));
        assert_ne!(solve.canonical(0), solve.canonical(3));

        // A late call-binding fact must not flow backwards into its old predecessor.
        solve.add_pts(3, 10);
        solve.run();
        assert!(!solve.points_to(0).unwrap().contains(&10));
        assert!(solve.points_to(3).unwrap().contains(&10));
        assert!(solve.points_to(2).unwrap().contains(&9));
        assert!(!solve.points_to(3).unwrap().contains(&9));
    }

    #[test]
    fn offline_quotient_factors_identical_fanout_without_exposing_union_cell() {
        fn problem() -> Solve {
            let mut solve = Solve::new(16, false);
            solve.add_pts(0, 10);
            solve.add_pts(1, 11);
            solve.add_pts(2, 12);
            for source in 0..3 {
                for destination in 4..7 {
                    solve.add_copy(source, destination);
                }
            }
            solve
        }

        let mut baseline = problem();
        baseline.run();
        let expected = original_points_to(&baseline, 16);

        let mut quotient = problem();
        let profile = quotient.offline_quotient(&HashSet::from([4, 5, 6]));
        let union = 16;
        quotient.run();
        assert_eq!(original_points_to(&quotient, 16), expected);
        assert_eq!(profile.factored_groups, 1);
        assert_eq!(profile.synthetic_nodes, 1);
        assert_eq!(profile.factored_edges_removed, 3);
        assert!(quotient
            .pts
            .values()
            .all(|points_to| !points_to.contains(&union)));
    }

    #[test]
    fn offline_quotient_preserves_indirect_targets_and_client_visible_rows() {
        let (pir, pag) = load("two_global_fnptrs.pir.json");
        let (base, classes) = crate::solve_steensgaard_with_classes(&pir, &pag, BuildMode::Library);
        let exact = BTreeMap::new();
        let confined = BTreeSet::new();
        let mut baseline = finish_andersen_controlled(
            &pir,
            &pag,
            &classes,
            base.clone(),
            BuildMode::Library,
            u64::MAX,
            &exact,
            &confined,
            true,
            AndersenControls::default(),
        );
        let mut quotient = finish_andersen_controlled(
            &pir,
            &pag,
            &classes,
            base,
            BuildMode::Library,
            u64::MAX,
            &exact,
            &confined,
            true,
            AndersenControls {
                offline_quotient: true,
                ..AndersenControls::default()
            },
        );
        // Propagation work is intentionally allowed to differ; every exported fact is not.
        baseline.metrics = Default::default();
        quotient.metrics = Default::default();
        assert_eq!(
            serde_json::to_value(quotient).unwrap(),
            serde_json::to_value(baseline).unwrap()
        );
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
    fn pwc_lane_domain_admits_shifted_lanes_only_when_enabled_and_bounds_overflow() {
        let lane = pangs_pir::GepLane::new(24, 0).unwrap();
        let shifted = FieldLocation::Lane(lane.shifted(8).unwrap());

        let mut baseline = Solve::new(2, false);
        let field = baseline.field_of(0, FieldLocation::Lane(lane));
        assert_eq!(
            baseline.field_of(field, FieldLocation::Exact(8)),
            baseline.unknown_field_of(0)
        );

        let mut enabled = Solve::new_with_pwc_and_overlap(2, false, true, false);
        let field = enabled.field_of(0, FieldLocation::Lane(lane));
        let shifted_cell = enabled.field_of(field, FieldLocation::Exact(8));
        assert_eq!(enabled.field_location[&shifted_cell], shifted);
        assert_eq!(enabled.derived_lanes_admitted, 2);

        let mut capped = Solve::new_with_pwc_and_overlap(2, false, true, false);
        capped.lane_cap = Some(1);
        let field = capped.field_of(0, FieldLocation::Lane(lane));
        assert_eq!(
            capped.field_of(field, FieldLocation::Exact(8)),
            capped.unknown_field_of(0)
        );
        assert_eq!(capped.chain_lane_cap_collapses, 1);
    }

    #[test]
    fn pwc_lane_cycle_keeps_a_shifted_struct_member_without_fixed_vocabulary() {
        let lane = FieldLocation::Lane(pangs_pir::GepLane::new(24, 0).unwrap());
        let mut solve = Solve::new_with_pwc_and_overlap(10, false, true, false);
        solve.add_pts(1, 0); // base allocation
        solve.add_gep(1, lane, 2); // statically inferred pointer-walk lane
        solve.add_gep(2, lane, 2); // the PWC replay itself
        solve.add_gep(2, FieldLocation::Exact(8), 3); // member absent from PAG vocabulary
        solve.add_gep(1, lane, 6); // member 0, deliberately disjoint from member 8
        solve.add_pts(4, 9); // callback/object stored in member 8
        solve.add_store(3, 4, None);
        solve.add_load(3, 5);
        solve.add_load(6, 7);
        solve.run();
        assert!(solve.points_to(5).unwrap().contains(&9));
        assert!(!solve
            .points_to(7)
            .is_some_and(|targets| targets.contains(&9)));
        let member = solve.points_to(3).unwrap().iter().next().unwrap();
        assert_eq!(
            solve.field_location[&member],
            FieldLocation::Lane(pangs_pir::GepLane::new(24, 8).unwrap())
        );
        assert!(solve.chain_lane_cap_collapses == 0);

        let mut capped = Solve::new_with_pwc_and_overlap(10, false, true, false);
        capped.lane_cap = Some(1);
        capped.add_pts(1, 0);
        capped.add_gep(1, lane, 2);
        capped.add_gep(2, FieldLocation::Exact(8), 3);
        capped.add_pts(4, 9);
        capped.add_store(3, 4, None);
        capped.add_load(3, 5);
        capped.run();
        // Overflow widens only this root's summary; it retains the concrete payload.
        assert!(capped.points_to(5).unwrap().contains(&9));
        assert!(capped.chain_lane_cap_collapses > 0);

        // Create an independent exact cell only after the capped derived access exists. The
        // root-local Unknown fallback must retain that late payload for the earlier read.
        let late_exact = capped.field_of(0, FieldLocation::Exact(16));
        capped.add_pts(late_exact, 8);
        capped.add_load(3, 8);
        capped.run();
        assert!(capped.points_to(8).unwrap().contains(&8));
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
    fn uncertified_memory_admission_includes_initializers_and_respects_budget() {
        let (mut pir, _) = load_m1_4("internal_aggregate_callback_admission.pir.json");
        // Outgoing users make the weak component oversize without enlarging the
        // callback's producer closure. The initializer must survive SCC slicing.
        let invoke = pir
            .functions
            .iter_mut()
            .find(|f| f.key == "invoke")
            .unwrap();
        let mut source = "fp".to_string();
        for index in 0..100 {
            let dest = format!("out{index}");
            invoke.body.push(Stmt::Assign {
                dest: dest.clone(),
                sources: vec![source],
                loc: None,
            });
            source = dest;
        }
        let pag = Pag::from_pir(
            &pir,
            &PagOpts {
                build_mode: BuildMode::Executable,
                ..PagOpts::default()
            },
        );
        let (base, classes) = crate::solve_steensgaard_classes_targeted(
            &pir,
            &pag,
            BuildMode::Executable,
            &BTreeSet::new(),
        );
        for overlap in [false, true] {
            for budget in [1, 1_000, u64::MAX] {
                let result = finish_andersen_controlled(
                    &pir,
                    &pag,
                    &classes,
                    base.clone(),
                    BuildMode::Executable,
                    budget,
                    &BTreeMap::new(),
                    &BTreeSet::new(),
                    false,
                    AndersenControls {
                        asymmetric_field_overlap: overlap,
                        ..AndersenControls::default()
                    },
                );
                let site = &result.indirect_calls[0];
                assert_eq!(site.targets, vec!["cb".to_string()]);
                assert!(!site.unknown_callee);
                assert_eq!(
                    site.fallback,
                    budget == 1,
                    "overlap={overlap} budget={budget}"
                );
            }
        }
    }

    #[test]
    fn uncertified_store_supports_a_certified_load() {
        let (mut pir, _) = load_m1_4("internal_aggregate_callback_admission.pir.json");
        let store = pir
            .functions
            .iter_mut()
            .find(|f| f.key == "main")
            .unwrap()
            .body
            .remove(2);
        let invoke = pir
            .functions
            .iter_mut()
            .find(|f| f.key == "invoke")
            .unwrap();
        let load_and_call = invoke.body.split_off(1);
        invoke.body.push(store);
        pir.functions
            .iter_mut()
            .find(|f| f.key == "main")
            .unwrap()
            .body
            .extend(load_and_call);
        let pag = Pag::from_pir(
            &pir,
            &PagOpts {
                build_mode: BuildMode::Executable,
                ..PagOpts::default()
            },
        );
        let (base, classes) = crate::solve_steensgaard_classes_targeted(
            &pir,
            &pag,
            BuildMode::Executable,
            &BTreeSet::new(),
        );
        for overlap in [false, true] {
            let result = finish_andersen_controlled(
                &pir,
                &pag,
                &classes,
                base.clone(),
                BuildMode::Executable,
                u64::MAX,
                &BTreeMap::new(),
                &BTreeSet::new(),
                false,
                AndersenControls {
                    asymmetric_field_overlap: overlap,
                    ..AndersenControls::default()
                },
            );
            let site = &result.indirect_calls[0];
            assert_eq!(site.targets, vec!["cb".to_string()]);
            assert!(!site.fallback && !site.unknown_callee);
        }
    }

    #[test]
    fn null_callback_semantic_fixture_uses_finite_base_fallback() {
        let (pir, _) = load_m1_4("null_callback_empty_refinement.pir.json");
        let pag = Pag::from_pir(
            &pir,
            &PagOpts {
                build_mode: BuildMode::Executable,
                ..PagOpts::default()
            },
        );
        let (base, classes) = crate::solve_steensgaard_classes_targeted(
            &pir,
            &pag,
            BuildMode::Executable,
            &BTreeSet::new(),
        );
        for overlap in [false, true] {
            let result = finish_andersen_controlled(
                &pir,
                &pag,
                &classes,
                base.clone(),
                BuildMode::Executable,
                u64::MAX,
                &BTreeMap::new(),
                &BTreeSet::new(),
                false,
                AndersenControls {
                    asymmetric_field_overlap: overlap,
                    ..AndersenControls::default()
                },
            );
            let site = &result.indirect_calls[0];
            assert_eq!(site.targets, vec!["cb".to_string()]);
            assert!(site.fallback && !site.unknown_callee);
        }
    }

    #[test]
    fn empty_refinement_retains_base_but_external_operand_does_not_clear_unknown() {
        let (pir, pag) = load_m1_4("internal_aggregate_callback_admission.pir.json");
        let (base, classes) = crate::solve_steensgaard_classes_targeted(
            &pir,
            &pag,
            BuildMode::Executable,
            &BTreeSet::new(),
        );
        let exact = BTreeMap::new();
        let confined = BTreeSet::new();
        let refiner = Refiner::new(
            &pir,
            &pag,
            &classes,
            &base,
            BuildMode::Executable,
            u64::MAX,
            &exact,
            &confined,
            false,
        );
        let site = pag
            .callsites
            .iter()
            .position(|cs| cs.kind == pangs_pag::CallKind::Indirect)
            .unwrap();
        let mut solve = Solve::new(pag.nodes.len(), false);
        let empty = refiner.emit_indirect_calls(
            &[site],
            &Default::default(),
            &HashSet::new(),
            &solve,
            false,
        );
        assert_eq!(empty[0].targets, base.indirect_calls[0].targets);
        assert!(!empty[0].unknown_callee);
        assert!(empty[0].fallback);
        let external = solve.region(ExternalRegion::GenericStorage);
        solve.add_pts(pag.callsites[site].operand.unwrap().0, external);
        let unknown = refiner.emit_indirect_calls(
            &[site],
            &Default::default(),
            &HashSet::new(),
            &solve,
            false,
        );
        assert!(unknown[0].unknown_callee);
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
    fn receiver_payload_inference_recovers_matching_store_and_load_regions() {
        let (pir, pag) = load("receiver_payload_inference.pir.json");
        let labels = BTreeSet::new();
        let (base, classes) =
            crate::solve_steensgaard_classes_targeted(&pir, &pag, BuildMode::Library, &labels);
        let exact_targets = BTreeMap::new();
        let confined_targets = BTreeSet::new();
        let mut refiner = Refiner::new(
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
        let operations = refiner.infer_receiver_payload_ops();
        let function = |name: &str| {
            pir.functions
                .iter()
                .position(|function| function.key == name)
                .unwrap()
        };

        assert_eq!(
            operations[&function("put")].stored_params[&2],
            BTreeSet::from([FieldLocation::Exact(16)])
        );
        assert_eq!(
            operations[&function("get")].returned_regions,
            BTreeSet::from([FieldLocation::Exact(16)])
        );

        let node = |label: &str| {
            pag.nodes
                .iter()
                .find(|node| node.label == label)
                .unwrap_or_else(|| panic!("missing PAG node {label}"))
                .id
        };
        let origins = super::bounded_allocation_origins(&pag, 64);
        let mixed = &origins[node("val:driver:%mixed").0 as usize];
        assert!(mixed.complete);
        assert_eq!(mixed.roots.len(), 2);
        let loaded = &origins[node("val:driver:%loaded").0 as usize];
        assert!(!loaded.complete, "loads must retain an unknown-origin bit");

        let bounded = super::bounded_allocation_origins(&pag, 1);
        let mixed = &bounded[node("val:driver:%mixed").0 as usize];
        assert_eq!(mixed.roots.len(), 1);
        assert!(
            !mixed.complete,
            "truncating an allocation-origin set must retain overflow"
        );

        assert!(
            base.indirect_calls[0].unknown_callee,
            "the context-insensitive container should carry the forged payload to the call"
        );
        refiner.receiver_payload_ops = operations.clone();
        refiner.receiver_payload_origins = super::bounded_allocation_origins(
            &pag,
            super::knobs::ANDERSEN_RECEIVER_PAYLOAD_ORIGIN_LIMIT,
        );
        refiner.build_scope();
        let super::RefinerOutcome::Complete(output) = refiner.run(AndersenControls::default())
        else {
            panic!("receiver payload regression unexpectedly exhausted")
        };
        assert_eq!(output.indirect_calls[0].targets, vec!["target".to_string()]);
        assert!(!output.indirect_calls[0].unknown_callee);

        let mut asymmetric_refiner = Refiner::new(
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
        asymmetric_refiner.receiver_payload_ops = operations.clone();
        asymmetric_refiner.receiver_payload_origins = super::bounded_allocation_origins(
            &pag,
            super::knobs::ANDERSEN_RECEIVER_PAYLOAD_ORIGIN_LIMIT,
        );
        asymmetric_refiner.build_scope();
        let super::RefinerOutcome::Complete(output) = asymmetric_refiner.run(AndersenControls {
            asymmetric_field_overlap: true,
            closed_producers: true,
            closed_consumers: true,
            ..AndersenControls::default()
        }) else {
            panic!("receiver payload regression unexpectedly exhausted")
        };
        assert_eq!(output.indirect_calls[0].targets, vec!["target".to_string()]);
        assert!(
            output.indirect_calls[0].unknown_callee,
            "C keeps receiver-payload certificates incomplete until the synthetic producer proof is implemented"
        );

        // Aggregate global export must include the receiver-local synthetic payload cell,
        // which is not in the ordinary `field_of` inventory.
        let mut aggregate_refiner = Refiner::new(
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
        aggregate_refiner.receiver_payload_ops = operations;
        aggregate_refiner.receiver_payload_origins = super::bounded_allocation_origins(
            &pag,
            super::knobs::ANDERSEN_RECEIVER_PAYLOAD_ORIGIN_LIMIT,
        );
        aggregate_refiner.build_scope();
        let mut aggregate = aggregate_refiner.build_base_solve(true);
        aggregate.run();
        let globals = aggregate_refiner
            .emit_global_points_to(&aggregate)
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        assert!(
            globals
                .get("obj:global:map_a")
                .is_some_and(|allocs| allocs.contains("target")),
            "global aggregate export omitted receiver payload callback"
        );
        assert!(
            globals
                .get("obj:global:map_b")
                .is_none_or(|allocs| !allocs.contains("target")),
            "receiver payload roots leaked into one another"
        );
    }

    #[test]
    fn bounded_origins_retain_positive_roots_through_incomplete_integer_transforms() {
        let pir: Pir = serde_json::from_str(
            r#"{
                "module":"pointer-tag",
                "target":{"triple":"x86_64","data_layout":"e-p:64:64","supported_atomic_widths":[8,16,32,64]},
                "globals":[{"key":"g","mutable":true}],
                "functions":[{"key":"main","sig":{"ret":{"class":"void"},"params":[{"class":"integer"}]},"param_names":["c"],"body":[
                    {"kind":"ptr_to_int","dest":"bits","source":"g","integer_bits":64,"pointer_bits":64,"pointer_address_space":0},
                    {"kind":"scalar_op","dest":"tagged","op":"xor","lhs":"bits","rhs":"c"},
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
        let origins = super::bounded_allocation_origins(&pag, 64);
        let destination = &origins[node("val:main:q").0 as usize];

        assert_eq!(destination.roots, BTreeSet::from([node("obj:global:g")]));
        assert!(!destination.complete);
    }

    #[test]
    fn directional_admission_refines_a_source_closed_slice_of_an_oversize_component() {
        let (mut pir, _) = load("field_sensitive_fnptr.pir.json");
        let setup = pir
            .functions
            .iter_mut()
            .find(|function| function.key == "setup")
            .unwrap();
        let mut source = "%fp".to_string();
        for index in 0..100 {
            let destination = format!("%outgoing{index}");
            setup.body.push(Stmt::Assign {
                dest: destination.clone(),
                sources: vec![source],
                loc: None,
            });
            source = destination;
        }
        let pag = Pag::from_pir(&pir, &PagOpts::default());
        let solved = solve_andersen(&pir, &pag, BuildMode::Library, 1_000);
        let site = solved.indirect_calls.first().unwrap();

        assert_eq!(site.targets, vec!["f0".to_string()]);
        assert!(
            !site.fallback,
            "the small predecessor SCC slice should refine the callsite"
        );
        assert!(solved.metrics.oversize_fallbacks >= 1);
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
                            s.unknown_callee || s.targets.contains(t),
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
