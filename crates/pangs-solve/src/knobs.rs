//! Central policy knobs for the core points-to solvers.
//!
//! Keep tunable limits and environment-variable names here so changes to solver
//! precision, termination, and diagnostic cost are reviewable in one place.

/// Maximum number of Andersen discovery/resume phases before abandoning the
/// refinement tier. A partial ascending solve is an under-approximation, so
/// exhaustion falls back to the complete Steensgaard result.
pub(crate) const ANDERSEN_MAX_RESUME_ROUNDS: usize = 64;

/// Minimum caller-supplied partition budget that enables the sparse
/// provenance-separated partition exception. The ordinary quadratic proxy
/// overprices sparse medium-sized partitions after external regions are split
/// by provenance; this exception retains that precision without admitting the
/// large or integer-forged partitions observed in YAPET and Vim.
pub(crate) const ANDERSEN_PROVENANCE_PROMOTION_MIN_BUDGET: u64 = 100_000;

/// Largest node count admitted by the sparse provenance-separated exception.
pub(crate) const ANDERSEN_PROVENANCE_PROMOTION_MAX_NODES: u64 = 4_096;

/// Largest edge count admitted by the sparse provenance-separated exception.
pub(crate) const ANDERSEN_PROVENANCE_PROMOTION_MAX_EDGES: u64 = 4_096;

/// Minimum copy-graph size and growth used to trigger an Andersen SCC pass.
/// SCC scans are linear, so the additional growth test in the solver also
/// requires at least half of the current graph to be new.
pub(crate) const ANDERSEN_COPY_SCC_MIN_EDGES: usize = 4_096;

/// Emit an Andersen progress record every this many propagation steps when
/// profiling is enabled.
pub(crate) const ANDERSEN_PROFILE_STEP_INTERVAL: usize = 10_000;

/// Report a load/store/GEP cross product at or above this size when Andersen
/// profiling is enabled.
pub(crate) const ANDERSEN_PROFILE_LARGE_PRODUCT: usize = 50_000;

/// Default number of partitions printed by partition profiling.
pub(crate) const PARTITION_PROFILE_TOP: usize = 20;

/// Number of global/function names sampled from each profiled partition.
pub(crate) const PARTITION_PROFILE_SYMBOL_SAMPLE_LIMIT: usize = 12;

/// Number of detailed diagnostic findings emitted per profiled partition.
pub(crate) const PARTITION_PROFILE_DETAIL_LIMIT: usize = 8;

/// Number of load/store hubs emitted per profiled partition.
pub(crate) const PARTITION_PROFILE_HUB_LIMIT: usize = 5;

/// Number of node labels sampled when describing a profiled class.
pub(crate) const PARTITION_PROFILE_CLASS_LABEL_SAMPLE_LIMIT: usize = 4;

/// Number of GEP witnesses retained for each offset collision.
pub(crate) const PARTITION_PROFILE_COLLISION_WITNESS_LIMIT: usize = 3;

/// Number of distinct offsets sampled for each GEP collision.
pub(crate) const PARTITION_PROFILE_COLLISION_OFFSET_SAMPLE_LIMIT: usize = 16;

/// Number of function or data occupants sampled from a mixed class.
pub(crate) const PARTITION_PROFILE_OCCUPANT_SAMPLE_LIMIT: usize = 6;

/// Maximum number of external-source explanations retained per node.
pub(crate) const ANDERSEN_EXTERNAL_SOURCE_LIMIT: usize = 32;

/// Maximum number of certified receiver allocations materialized by the experimental
/// receiver-relative payload abstraction. Additional roots share an overflow context.
pub(crate) const ANDERSEN_RECEIVER_PAYLOAD_CONTEXT_LIMIT: usize = 16;

/// Per-query state/worklist cap for the experimental CFL query kernel.
pub(crate) const CFL_QUERY_STATE_BUDGET: usize = 25_000;

/// Hard iteration cap for the experimental field-sensitive CFL call-graph
/// fixpoint.
pub(crate) const CFL_FIXPOINT_MAX_ROUNDS: usize = 32;

/// Upper bounds for the diagnostic CFL visited-state histogram buckets.
pub(crate) const CFL_VISIT_HISTOGRAM_SMALL_MAX: usize = 10;
pub(crate) const CFL_VISIT_HISTOGRAM_MEDIUM_MAX: usize = 100;
pub(crate) const CFL_VISIT_HISTOGRAM_LARGE_MAX: usize = 1_000;

/// Candidate-pair interval between Steensgaard profiling records.
pub(crate) const STEENS_PROFILE_INTERVAL_CANDIDATE_PAIRS: u64 = 10_000_000;

/// Enables Andersen solver profiling when present.
pub(crate) const ENV_ANDERSEN_PROFILE: &str = "PANGS_ANDERSEN_PROFILE";

/// Overrides the minimum number of copy edges between SCC passes.
pub(crate) const ENV_ANDERSEN_COPY_SCC_MIN_EDGES: &str = "PANGS_ANDERSEN_COPY_SCC_MIN_EDGES";

/// Disables Andersen copy-graph SCC collapsing when present.
pub(crate) const ENV_ANDERSEN_DISABLE_COPY_SCC: &str = "PANGS_ANDERSEN_DISABLE_COPY_SCC";

/// Optional hard propagation-step limit used for diagnostics and fault tests.
pub(crate) const ENV_ANDERSEN_MAX_STEPS: &str = "PANGS_ANDERSEN_MAX_STEPS";

/// Overrides the maximum number of Andersen resume phases.
pub(crate) const ENV_ANDERSEN_MAX_RESUMES: &str = "PANGS_ANDERSEN_MAX_RESUMES";

/// Injects a named exhaustion point for fallback testing.
pub(crate) const ENV_ANDERSEN_INJECT_EXHAUSTION: &str = "PANGS_ANDERSEN_INJECT_EXHAUSTION";

/// Disables eager propagation of unknown/external facts for ablation testing.
pub(crate) const ENV_ANDERSEN_DISABLE_EAGER_UNKNOWN: &str = "PANGS_ANDERSEN_DISABLE_EAGER_UNKNOWN";

/// Selects the experimental subtractive differential propagation engine.
pub(crate) const ENV_ANDERSEN_DIFFERENTIAL_SUBTRACTIVE: &str =
    "PANGS_ANDERSEN_DIFFERENTIAL_SUBTRACTIVE";

/// Selects a node label for detailed Andersen provenance explanations.
pub(crate) const ENV_ANDERSEN_EXPLAIN_NODE: &str = "PANGS_ANDERSEN_EXPLAIN_NODE";

/// Enables the experimental receiver-allocation-relative payload summaries. The experiment
/// infers container-like first-parameter receivers and separates their pointer payload by
/// independently certified allocation root.
pub(crate) const ENV_ANDERSEN_RECEIVER_PAYLOADS: &str = "PANGS_ANDERSEN_RECEIVER_PAYLOADS";

/// Enables partition admission profiling when present.
pub(crate) const ENV_PARTITION_PROFILE: &str = "PANGS_PARTITION_PROFILE";

/// Overrides the number of partitions printed by partition profiling.
pub(crate) const ENV_PARTITION_PROFILE_TOP: &str = "PANGS_PARTITION_PROFILE_TOP";

/// Emits machine-readable structural and actual-work records used to
/// calibrate Andersen partition admission.
pub(crate) const ENV_ANDERSEN_ADMISSION_PROFILE: &str = "PANGS_ANDERSEN_ADMISSION_PROFILE";

/// Diagnostic-only partition root selector. When set together with admission
/// profiling, the selected interesting partition is forcibly admitted and all
/// other partitions retain their Steensgaard answer.
pub(crate) const ENV_ANDERSEN_ADMISSION_PROFILE_ROOT: &str =
    "PANGS_ANDERSEN_ADMISSION_PROFILE_ROOT";

/// Enables Steensgaard candidate-pair profiling when present.
pub(crate) const ENV_STEENS_PROFILE: &str = "PANGS_STEENS_PROFILE";

/// Overrides the Steensgaard candidate-pair profiling interval.
pub(crate) const ENV_STEENS_PROFILE_INTERVAL: &str = "PANGS_STEENS_PROFILE_INTERVAL";
