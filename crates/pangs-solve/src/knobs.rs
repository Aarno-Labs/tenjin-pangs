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

/// Maximum number of allocation origins retained for one receiver payload argument. Additional
/// origins set the argument's incomplete bit and are represented by a receiver-local unknown
/// region rather than structurally joining all omitted objects.
pub(crate) const ANDERSEN_RECEIVER_PAYLOAD_ORIGIN_LIMIT: usize = 64;

/// The closed-producer prototype needs concrete allocation-relative load/store destinations.
/// Permit it to promote a bounded, non-forged indirect-call partition even when the quadratic
/// admission proxy rejects it. The producer graph itself remains linear; these caps bound the
/// supporting inclusion solve used to name memory projections.
pub(crate) const ANDERSEN_CLOSED_PRODUCER_MAX_NODES: u64 = 8_192;
pub(crate) const ANDERSEN_CLOSED_PRODUCER_MAX_EDGES: u64 = 8_192;

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

/// Enables the experimental small-vector/hash-set/dense-bitset points-to representation.
pub(crate) const ENV_ANDERSEN_HYBRID_BITSETS: &str = "PANGS_ANDERSEN_HYBRID_BITSETS";

/// Overrides the minimum number of points-to facts required for dense-bitset promotion.
pub(crate) const ENV_ANDERSEN_HYBRID_BITSET_THRESHOLD: &str =
    "PANGS_ANDERSEN_HYBRID_BITSET_THRESHOLD";

/// Overrides the number of points-to facts retained in the tiny vector tier.
pub(crate) const ENV_ANDERSEN_HYBRID_SMALL_THRESHOLD: &str =
    "PANGS_ANDERSEN_HYBRID_SMALL_THRESHOLD";

/// Overrides the maximum bitmap address-space bits allowed per points-to member.
pub(crate) const ENV_ANDERSEN_HYBRID_BITSET_MAX_BITS_PER_MEMBER: &str =
    "PANGS_ANDERSEN_HYBRID_BITSET_MAX_BITS_PER_MEMBER";

/// Reports the final small/sparse/dense points-to storage mix when hybrid bitsets are enabled.
pub(crate) const ENV_ANDERSEN_HYBRID_BITSETS_PROFILE: &str =
    "PANGS_ANDERSEN_HYBRID_BITSETS_PROFILE";

/// Overrides the minimum number of copy edges between SCC passes.
pub(crate) const ENV_ANDERSEN_COPY_SCC_MIN_EDGES: &str = "PANGS_ANDERSEN_COPY_SCC_MIN_EDGES";

/// Disables Andersen copy-graph SCC collapsing when present.
pub(crate) const ENV_ANDERSEN_DISABLE_COPY_SCC: &str = "PANGS_ANDERSEN_DISABLE_COPY_SCC";

/// Enables exact offline simplification of the initial Andersen inclusion system. The
/// prototype collapses static copy SCCs, substitutes variables whose only generator is one
/// copy predecessor, value-numbers generator-free variables with identical predecessors,
/// and factors exact repeated copy fanout through synthetic union variables.
pub(crate) const ENV_ANDERSEN_OFFLINE_QUOTIENT: &str = "PANGS_ANDERSEN_OFFLINE_QUOTIENT";

/// Replaces each admitted Andersen memcpy endpoint biclique with two site-local stars
/// through a propagation-only summary cell. This changes only the internal representation
/// of the field-insensitive content-copy relation; partition admission remains unchanged.
pub(crate) const ENV_ANDERSEN_MEMCPY_EDGE_SUMMARIES: &str = "PANGS_ANDERSEN_MEMCPY_EDGE_SUMMARIES";

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

/// Enables the experimental shared closed-producer certificate for indirect-call operands.
/// A certified operand may discard a Steensgaard unknown bit when its complete Andersen
/// points-to set contains only named functions.
pub(crate) const ENV_ANDERSEN_CLOSED_PRODUCERS: &str = "PANGS_ANDERSEN_CLOSED_PRODUCERS";

/// Enables the experimental closed-consumer certificate for address-taken internal
/// functions. A certified function address reaches only internal indirect-call operands
/// and modeled internal pointer-flow/storage operations, so Steensgaard's unknown-caller
/// bit may be removed.
pub(crate) const ENV_ANDERSEN_CLOSED_CONSUMERS: &str = "PANGS_ANDERSEN_CLOSED_CONSUMERS";

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
