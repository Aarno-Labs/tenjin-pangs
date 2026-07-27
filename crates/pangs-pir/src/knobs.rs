//! Tunable safety limits for LLVM-to-PIR lowering.

/// Maximum recursion depth while classifying nested debug-info types.
/// Malformed or exceptionally deep metadata past this point loses the optional
/// scalar classification but does not abort module lowering.
pub(crate) const DEBUG_TYPE_RECURSION_LIMIT: usize = 32;

/// Maximum recursion depth while lowering LLVM constant expressions.
/// Reaching the limit conservatively produces an unknown PIR value.
pub(crate) const CONSTANT_EXPR_RECURSION_LIMIT: usize = 4_096;
