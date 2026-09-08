//! Public defaults for pointer-assignment graph construction.

/// Default to library reachability, where every function may be entered from
/// outside the analyzed module.
pub const DEFAULT_BUILD_MODE: crate::BuildMode = crate::BuildMode::Library;

/// Enable the fixed-PAG positive-weight-cycle lane rewrite by default.
pub const DEFAULT_PWC_LANES: bool = true;

/// Overrides the default/API setting for the fixed-PAG positive-weight-cycle lane rewrite.
/// Set to `0` or `false` for an ablation.
pub const ENV_PWC_LANES: &str = "PANGS_PAG_PWC_LANES";

/// Resolve the effective PWC-lane setting from an API choice and the process-wide override.
pub fn pwc_lanes_enabled(configured: bool) -> bool {
    let value = std::env::var(ENV_PWC_LANES).ok();
    pwc_lanes_enabled_for(configured, value.as_deref())
}

fn pwc_lanes_enabled_for(configured: bool, value: Option<&str>) -> bool {
    match value {
        Some("0" | "false") => false,
        Some("1" | "true") => true,
        _ => configured,
    }
}

#[cfg(test)]
mod tests {
    use super::pwc_lanes_enabled_for;

    #[test]
    fn pwc_lanes_environment_overrides_the_api_setting() {
        assert!(pwc_lanes_enabled_for(true, None));
        assert!(!pwc_lanes_enabled_for(false, None));
        assert!(!pwc_lanes_enabled_for(true, Some("0")));
        assert!(!pwc_lanes_enabled_for(true, Some("false")));
        assert!(pwc_lanes_enabled_for(false, Some("1")));
        assert!(pwc_lanes_enabled_for(false, Some("true")));
    }
}
