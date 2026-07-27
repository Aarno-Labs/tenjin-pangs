//! Defaults for command-line choices that select core analysis behavior.

/// Shipping analysis tier used when `--stage` is omitted.
pub(crate) const DEFAULT_ANALYSIS_STAGE: &str = "andersen";

/// Whole-module reachability model used when `--build-mode` or
/// `--entrypoints` is omitted.
pub(crate) const DEFAULT_BUILD_MODE: &str = "library";

/// Default Andersen partition budget, shared with the public analysis API.
pub(crate) const DEFAULT_PARTITION_BUDGET: u64 = pangs_api::knobs::DEFAULT_PARTITION_BUDGET;

/// Experimental CFL query mode used when `query callees --mode` is omitted.
pub(crate) const DEFAULT_QUERY_MODE: &str = "field-sensitive";

/// Upper bounds for the CLI's experimental CFL visited-state histogram.
pub(crate) const QUERY_HISTOGRAM_SMALL_MAX: usize = 10;
pub(crate) const QUERY_HISTOGRAM_MEDIUM_MAX: usize = 100;
pub(crate) const QUERY_HISTOGRAM_LARGE_MAX: usize = 1_000;
