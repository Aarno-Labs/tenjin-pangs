//! Environment-controlled diagnostics shared by analysis clients.

/// Enables phase timing records for disposition-oriented analysis clients.
pub(crate) const ENV_DISPOSITION_TIMINGS: &str = "PANGS_DISPOSITION_TIMINGS";

/// Number of post-publication functions retained in phase-stationarity
/// diagnostic evidence.
pub(crate) const PHASE_FUNCTION_SAMPLE_LIMIT: usize = 16;
