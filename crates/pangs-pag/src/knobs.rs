//! Public defaults for pointer-assignment graph construction.

/// Default to library reachability, where every function may be entered from
/// outside the analyzed module.
pub const DEFAULT_BUILD_MODE: crate::BuildMode = crate::BuildMode::Library;

/// Enables the experimental fixed-PAG positive-weight-cycle lane rewrite.  It is opt-in until
/// corpus correctness and performance gates establish a default.
pub const ENV_PWC_LANES: &str = "PANGS_PAG_PWC_LANES";

pub(crate) fn pwc_lanes_enabled() -> bool {
    matches!(
        std::env::var(ENV_PWC_LANES).as_deref(),
        Ok("1") | Ok("true")
    )
}
