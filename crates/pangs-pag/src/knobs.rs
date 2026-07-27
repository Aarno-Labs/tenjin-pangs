//! Public defaults for pointer-assignment graph construction.

/// Default to library reachability, where every function may be entered from
/// outside the analyzed module.
pub const DEFAULT_BUILD_MODE: crate::BuildMode = crate::BuildMode::Library;
