//! Cross-stage differential ledger (`PLAN-M1.md` §M1.8, `PLAN-M1_lite_delta.md` §M1.8).
//!
//! Runs `conservative` → `steens` → `andersen` on one module and checks the relations the
//! lite design guarantees: indirect-call targets narrow monotonically
//! (`andersen ⊆ steens ⊆ conservative`), no *new* Ω/unknown facts appear as precision
//! rises, and rewritable coverage only grows. A violation is a soundness or monotonicity
//! bug, not a precision difference, so the CLI exits 3 on any.

use std::collections::{BTreeMap, BTreeSet};

use crate::{Analysis, AnalysisError, Callee, Caller, CallKind, Opts, Stage};

/// One stage's facts, keyed by stable string keys so they compare across stages.
struct StageFacts {
    /// indirect callsite key -> concrete callee function keys
    icall_targets: BTreeMap<String, BTreeSet<String>>,
    /// indirect callsite keys that carry an unknown (Ω) callee edge
    icall_unknown: BTreeSet<String>,
    /// functions reachable from an unknown (escaped) caller
    unknown_callers: BTreeSet<String>,
    /// mutable globals that live in a non-frozen (rewritable) component
    rewritable_globals: BTreeSet<String>,
    in_rewritable_components: usize,
}

impl StageFacts {
    fn extract(analysis: &Analysis) -> Self {
        let mut icall_targets: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut icall_unknown = BTreeSet::new();
        let mut unknown_callers = BTreeSet::new();

        for edge in analysis.call_edges() {
            if let (CallKind::Indirect, Some(cs)) = (edge.kind, edge.callsite) {
                let key = analysis.callsites()[cs].key.clone();
                match &edge.callee {
                    Callee::Func(id) => {
                        icall_targets
                            .entry(key)
                            .or_default()
                            .insert(analysis.functions()[*id].key.clone());
                    }
                    Callee::Unknown(_) => {
                        icall_unknown.insert(key);
                    }
                }
            }
            if let (Caller::Unknown(_), Callee::Func(id)) = (&edge.caller, &edge.callee) {
                unknown_callers.insert(analysis.functions()[*id].key.clone());
            }
        }

        let mut rewritable_globals = BTreeSet::new();
        for comp in analysis.components() {
            if comp.frozen {
                continue;
            }
            for gid in &comp.mutable_globals {
                rewritable_globals.insert(analysis.globals()[*gid].key.clone());
            }
        }

        Self {
            icall_targets,
            icall_unknown,
            unknown_callers,
            rewritable_globals,
            in_rewritable_components: analysis.metrics().in_rewritable_components,
        }
    }
}

/// The result of a differential run.
///
/// `violations` are soundness/monotonicity breaks (the CLI exits 3). `notes` are expected
/// precision differences surfaced for triage — chiefly the conservative→steens coverage
/// change, which legitimately moves in either direction because the two stages differ in
/// mod/ref *completeness* (syntactic vs pointer-aware aliased-Ω), not just call-graph
/// precision.
#[derive(Debug, Default)]
pub struct DifferentialReport {
    pub violations: Vec<String>,
    pub notes: Vec<String>,
}

impl DifferentialReport {
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Run all three stages on `module` and check the narrowing/monotonicity ledger.
pub fn run_differential(module: &pangs_pir::Pir, base: &Opts) -> Result<DifferentialReport, AnalysisError> {
    let facts = |stage: Stage| -> Result<StageFacts, AnalysisError> {
        let opts = Opts {
            stage,
            ..base.clone()
        };
        Ok(StageFacts::extract(&Analysis::run(module, &opts)?))
    };
    let cons = facts(Stage::Conservative)?;
    let steens = facts(Stage::Steens)?;
    let ander = facts(Stage::Andersen)?;

    let mut report = DifferentialReport::default();

    // Indirect-call targets narrow: andersen ⊆ steens ⊆ conservative, per callsite.
    check_targets(&mut report, "steens", &steens.icall_targets, "conservative", &cons.icall_targets);
    check_targets(&mut report, "andersen", &ander.icall_targets, "steens", &steens.icall_targets);

    // No new Ω/unknown facts as precision rises.
    check_subset(&mut report, "icall_unknown", "andersen", &ander.icall_unknown, "steens", &steens.icall_unknown);
    check_subset(&mut report, "icall_unknown", "steens", &steens.icall_unknown, "conservative", &cons.icall_unknown);
    check_subset(&mut report, "unknown_callers", "andersen", &ander.unknown_callers, "steens", &steens.unknown_callers);
    check_subset(&mut report, "unknown_callers", "steens", &steens.unknown_callers, "conservative", &cons.unknown_callers);

    // steens → andersen share the pointer-aware mod/ref machinery; Andersen only refines
    // pts, so it can never *reveal* new aliased taint — coverage must be monotone here.
    check_subset(&mut report, "rewritable_globals", "steens", &steens.rewritable_globals, "andersen", &ander.rewritable_globals);
    if steens.in_rewritable_components > ander.in_rewritable_components {
        report.violations.push(format!(
            "in_rewritable_components dropped steens→andersen: steens={}, andersen={}",
            steens.in_rewritable_components, ander.in_rewritable_components
        ));
    }

    // conservative → steens coverage can move either way (syntactic vs aliased-Ω mod/ref);
    // surface the delta for triage rather than failing on it.
    if cons.in_rewritable_components != steens.in_rewritable_components {
        report.notes.push(format!(
            "coverage moved conservative→steens: {} → {} (mod/ref completeness differs)",
            cons.in_rewritable_components, steens.in_rewritable_components
        ));
    }

    Ok(report)
}

fn check_targets(
    report: &mut DifferentialReport,
    fine: &str,
    fine_map: &BTreeMap<String, BTreeSet<String>>,
    coarse: &str,
    coarse_map: &BTreeMap<String, BTreeSet<String>>,
) {
    for (key, fine_set) in fine_map {
        let empty = BTreeSet::new();
        let coarse_set = coarse_map.get(key).unwrap_or(&empty);
        for t in fine_set {
            if !coarse_set.contains(t) {
                report.violations.push(format!(
                    "icall {key}: {fine} target {t} not present in {coarse} (narrowing ledger break)"
                ));
            }
        }
    }
}

fn check_subset(
    report: &mut DifferentialReport,
    what: &str,
    fine: &str,
    fine_set: &BTreeSet<String>,
    coarse: &str,
    coarse_set: &BTreeSet<String>,
) {
    for item in fine_set {
        if !coarse_set.contains(item) {
            report.violations.push(format!(
                "{what}: {fine} has {item} absent from {coarse} (monotonicity break)"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn checker_flags_a_target_that_grew() {
        // A fine stage that points to a target the coarse stage didn't is a ledger break.
        let mut report = DifferentialReport::default();
        let mut fine = BTreeMap::new();
        fine.insert("site@0".to_string(), set(&["a", "b"]));
        let mut coarse = BTreeMap::new();
        coarse.insert("site@0".to_string(), set(&["a"]));
        check_targets(&mut report, "andersen", &fine, "steens", &coarse);
        assert_eq!(report.violations.len(), 1);
        assert!(report.violations[0].contains("target b not present"));
    }

    #[test]
    fn checker_passes_a_proper_narrowing() {
        let mut report = DifferentialReport::default();
        let mut fine = BTreeMap::new();
        fine.insert("site@0".to_string(), set(&["a"]));
        let mut coarse = BTreeMap::new();
        coarse.insert("site@0".to_string(), set(&["a", "b"]));
        check_targets(&mut report, "andersen", &fine, "steens", &coarse);
        assert!(report.is_clean());
    }
}
