//! Public defaults and environment-controlled policy knobs for the analysis API.

/// API default tier. The library starts at the conservative floor unless a
/// caller explicitly requests Steensgaard or Andersen; the shipping CLI has
/// its own Andersen default.
pub const DEFAULT_STAGE: crate::Stage = crate::Stage::Conservative;

/// API default reachability model: assume a reusable library and therefore
/// consider every function reachable.
pub const DEFAULT_BUILD_MODE: crate::BuildMode = crate::BuildMode::Library;

/// Default quadratic cost budget for admitting an interesting Steensgaard
/// partition to the Andersen refinement tier.
pub const DEFAULT_PARTITION_BUDGET: u64 = 200_000;

/// Enable exact stationary-initializer indirect-call resolution by default.
pub const DEFAULT_ENABLE_B1_INITVAL: bool = true;

/// Enable bounded simple-flow indirect-call resolution by default.
pub const DEFAULT_ENABLE_B2_SIMPLE: bool = true;

/// Enable subtraction of globally confined targets by default.
pub const DEFAULT_ENABLE_B3_CONFINED: bool = true;

/// Maximum caller-context depth followed by the B2 simple indirect-call
/// resolver before it treats a path as complex.
pub const DEFAULT_B2_CONTEXT_DEPTH: usize = 8;

/// Number of attempted ModRef emissions between profiling progress records.
pub(crate) const POINTER_MODREF_PROFILE_INTERVAL_ATTEMPTS: u64 = 10_000_000;

/// Number of top ModRef emitters included in profiling summaries.
pub(crate) const POINTER_MODREF_PROFILE_TOP_EMITTERS: usize = 20;

/// Fanout at which local pointer-derived ModRef emission switches to its
/// high-fanout batching path.
pub(crate) const POINTER_MODREF_HIGH_FANOUT_LIMIT: usize = 16;

/// Fanout at which transitive ModRef closure switches to its high-fanout
/// batching path.
pub(crate) const TRANSITIVE_MODREF_HIGH_FANOUT_LIMIT: usize = 16_384;

/// Number of pointee-global names retained in each ModRef node's diagnostic
/// sample; full counts and analysis facts remain untruncated.
pub(crate) const MODREF_POINTEE_GLOBAL_SAMPLE_LIMIT: usize = 16;

/// Enables pointer-derived ModRef profiling when present.
pub(crate) const ENV_POINTER_MODREF_PROFILE: &str = "PANGS_POINTER_MODREF_PROFILE";

/// Overrides the ModRef profiling progress interval.
pub(crate) const ENV_POINTER_MODREF_PROFILE_INTERVAL: &str =
    "PANGS_POINTER_MODREF_PROFILE_INTERVAL";

/// Overrides the number of top ModRef emitters printed.
pub(crate) const ENV_POINTER_MODREF_PROFILE_TOP: &str = "PANGS_POINTER_MODREF_PROFILE_TOP";

/// Restricts detailed ModRef profiling to one global name.
pub(crate) const ENV_POINTER_MODREF_PROFILE_GLOBAL: &str = "PANGS_POINTER_MODREF_PROFILE_GLOBAL";

/// Overrides the local pointer-derived ModRef high-fanout threshold.
pub(crate) const ENV_POINTER_MODREF_HIGH_FANOUT_LIMIT: &str =
    "PANGS_POINTER_MODREF_HIGH_FANOUT_LIMIT";

/// Overrides the transitive ModRef high-fanout threshold.
pub(crate) const ENV_TRANSITIVE_MODREF_HIGH_FANOUT_LIMIT: &str =
    "PANGS_TRANSITIVE_MODREF_HIGH_FANOUT_LIMIT";
