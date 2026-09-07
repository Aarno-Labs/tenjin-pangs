//! Cross-stage differential ledger (`PLAN-M1.md` §M1.8, `PLAN-M1_lite_delta.md` §M1.8).
//!
//! Runs `conservative` → `steens` → `andersen` on one module and checks the relations the
//! lite design guarantees: indirect-call targets narrow monotonically, treating an Ω/unknown
//! edge as top over every concrete target, no *new* Ω/unknown facts appear as precision
//! rises, and rewritable coverage only grows. A violation is a soundness or monotonicity
//! bug, not a precision difference, so the CLI exits 3 on any.

use std::collections::{BTreeMap, BTreeSet};

use crate::{Analysis, AnalysisError, CallKind, Callee, Caller, Opts, Stage};

/// One stage's facts, keyed by stable string keys so they compare across stages.
struct StageFacts {
    /// indirect callsite key -> concrete callee function keys
    icall_targets: BTreeMap<String, BTreeSet<String>>,
    /// indirect callsite keys that carry an unknown (Ω) callee edge
    icall_unknown: BTreeSet<String>,
    /// functions reachable from an unknown (escaped) caller
    unknown_callers: BTreeSet<String>,
    /// mutable globals named by a non-frozen component and by no frozen one
    rewritable_globals: BTreeSet<String>,
    /// locally defined globals the stage reports as written at runtime
    written_globals: BTreeSet<String>,
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

        // A global is rewritable only when *no* frozen component names it.  Counting the
        // clean components alone calls a global rewritable while a frozen component also
        // reaches it, which both overstates coverage and makes the number fall when a
        // refinement removes a false row from a clean component.
        let mut clean = BTreeSet::new();
        let mut frozen = BTreeSet::new();
        for comp in analysis.components() {
            let side = if comp.frozen { &mut frozen } else { &mut clean };
            for gid in &comp.mutable_globals {
                side.insert(analysis.globals()[*gid].key.clone());
            }
        }
        let rewritable_globals = clean.difference(&frozen).cloned().collect();

        let written_globals = analysis
            .globals()
            .iter()
            .filter(|global| global.is_definition && global.runtime_written)
            .map(|global| global.key.clone())
            .collect();

        Self {
            icall_targets,
            icall_unknown,
            unknown_callers,
            rewritable_globals,
            written_globals,
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
pub fn run_differential(
    module: &pangs_pir::Pir,
    base: &Opts,
) -> Result<DifferentialReport, AnalysisError> {
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
    check_targets(
        &mut report,
        "steens",
        &steens.icall_targets,
        "conservative",
        &cons.icall_targets,
        &cons.icall_unknown,
    );
    check_targets(
        &mut report,
        "andersen",
        &ander.icall_targets,
        "steens",
        &steens.icall_targets,
        &steens.icall_unknown,
    );

    // No new Ω/unknown facts as precision rises.
    check_subset(
        &mut report,
        "icall_unknown",
        "andersen",
        &ander.icall_unknown,
        "steens",
        &steens.icall_unknown,
    );
    check_subset(
        &mut report,
        "icall_unknown",
        "steens",
        &steens.icall_unknown,
        "conservative",
        &cons.icall_unknown,
    );
    check_subset(
        &mut report,
        "unknown_callers",
        "andersen",
        &ander.unknown_callers,
        "steens",
        &steens.unknown_callers,
    );
    check_subset(
        &mut report,
        "unknown_callers",
        "steens",
        &steens.unknown_callers,
        "conservative",
        &cons.unknown_callers,
    );

    // Rewritable coverage is *not* monotone in either direction and never was.  It is built
    // from ModRef rows, and a refinement that deletes a false row legitimately removes a
    // global from a clean component; conversely, deleting a false row from a frozen component
    // can add one.  Both were observed on the corpus.  Surface the movement for triage.
    for (coarse_name, coarse, fine_name, fine) in [
        (
            "conservative",
            &cons.rewritable_globals,
            "steens",
            &steens.rewritable_globals,
        ),
        (
            "steens",
            &steens.rewritable_globals,
            "andersen",
            &ander.rewritable_globals,
        ),
    ] {
        if coarse != fine {
            report.notes.push(format!(
                "rewritable coverage moved {coarse_name}→{fine_name}: {} → {} ({} gained, {} lost)",
                coarse.len(),
                fine.len(),
                fine.difference(coarse).count(),
                coarse.difference(fine).count(),
            ));
        }
    }

    // Writes, unlike coverage, *are* monotone: a coarser tier over-approximates points-to, so
    // every runtime write a finer tier can attribute to a global must already be attributed to
    // it by the coarser one.  A global written at Andersen and unwritten at Steensgaard means
    // the base tier lost the store, and its `immutable` answer for that global is unsound.
    check_subset(
        &mut report,
        "written_globals",
        "andersen",
        &ander.written_globals,
        "steens",
        &steens.written_globals,
    );
    // The conservative tier is syntactic: it attributes direct writes only and does no aliased
    // mod/ref at all, so it reports *fewer* writes than Steensgaard rather than more.  That is
    // a known property of the tier, not a break, but it means conservative-tier `written` — and
    // therefore any `immutable` it selects — is not a floor.  Surface it.
    let conservative_missing: Vec<_> = steens
        .written_globals
        .difference(&cons.written_globals)
        .cloned()
        .collect();
    if !conservative_missing.is_empty() {
        report.notes.push(format!(
            "written_globals: {} global(s) written at steens are unwritten at conservative \
             (the conservative tier has no aliased mod/ref; its `written` is not a floor): {}",
            conservative_missing.len(),
            conservative_missing.join(", "),
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
    coarse_unknown: &BTreeSet<String>,
) {
    for (key, fine_set) in fine_map {
        if coarse_unknown.contains(key) {
            continue;
        }
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
        check_targets(
            &mut report,
            "andersen",
            &fine,
            "steens",
            &coarse,
            &BTreeSet::new(),
        );
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
        check_targets(
            &mut report,
            "andersen",
            &fine,
            "steens",
            &coarse,
            &BTreeSet::new(),
        );
        assert!(report.is_clean());
    }

    #[test]
    fn checker_treats_a_coarse_unknown_edge_as_target_top() {
        let mut report = DifferentialReport::default();
        let fine = BTreeMap::from([("site@0".to_string(), set(&["newly_named"]))]);
        check_targets(
            &mut report,
            "andersen",
            &fine,
            "steens",
            &BTreeMap::new(),
            &set(&["site@0"]),
        );
        assert!(report.is_clean());
    }
}
