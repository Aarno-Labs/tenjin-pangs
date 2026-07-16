// O2 deliberately lands before O3/O6 wire the result into manifest assembly (ONCELOCK.md §3.2).
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use pangs_api::{Analysis, Callee, Caller, CallsiteId, FuncId, GlobalId, GlobalTarget, Via};
use pangs_manifest::Witness;
use pangs_pir::{Access, Pir, StatementCfg, Stmt};

use crate::function_witness;

const KILL_CODE_ORDER: [&str; 4] = [
    "omega-writer",
    "thread-writer",
    "violation-taint",
    "recursive-main",
];

#[derive(Clone)]
pub(crate) struct PhaseKill {
    pub(crate) code: &'static str,
    pub(crate) witness: Witness,
}

/// O4's four explicit kill rules. Unknown-call poisoning remains in O2 `gen`, as specified,
/// rather than appearing here as a second definition.
pub(crate) fn evaluate_kill_rules(
    analysis: &Analysis,
    thread_writers: &BTreeMap<GlobalId, Witness>,
) -> BTreeMap<GlobalId, Vec<PhaseKill>> {
    let mut failures = BTreeMap::<GlobalId, BTreeMap<&'static str, Witness>>::new();

    for (index, function) in analysis.functions().iter().enumerate() {
        if !function.address_escaped {
            continue;
        }
        let function_id = FuncId(index as u32);
        let witness = function_witness(
            analysis,
            function_id,
            "omega-writer",
            function.escape_witness.clone(),
        );
        for global in transitive_modified_globals(analysis, function_id) {
            failures
                .entry(global)
                .or_default()
                .entry("omega-writer")
                .or_insert_with(|| witness.clone());
        }
    }

    for (&global, witness) in thread_writers {
        failures
            .entry(global)
            .or_default()
            .entry("thread-writer")
            .or_insert_with(|| witness.clone());
    }

    for finding in analysis.audit_findings() {
        let Some(function) = finding.function else {
            continue;
        };
        let witness = function_witness(
            analysis,
            function,
            "violation-taint",
            Some(finding.kind.clone()),
        );
        for global in transitive_modified_globals(analysis, function) {
            failures
                .entry(global)
                .or_default()
                .entry("violation-taint")
                .or_insert_with(|| witness.clone());
        }
    }

    if let Some(main) = analysis.lookup_func("main") {
        if let Some(caller) = analysis.callers(main).find_map(|caller| match caller {
            Caller::Func(caller) => Some(*caller),
            Caller::Unknown(_) => None,
        }) {
            let witness = function_witness(
                analysis,
                caller,
                "recursive-main",
                Some("main has a function caller in the final call graph".into()),
            );
            for index in 0..analysis.globals().len() {
                failures
                    .entry(GlobalId(index as u32))
                    .or_default()
                    .entry("recursive-main")
                    .or_insert_with(|| witness.clone());
            }
        }
    }

    failures
        .into_iter()
        .map(|(global, by_code)| {
            let ordered = KILL_CODE_ORDER
                .iter()
                .filter_map(|&code| {
                    by_code
                        .get(code)
                        .cloned()
                        .map(|witness| PhaseKill { code, witness })
                })
                .collect();
            (global, ordered)
        })
        .collect()
}

fn transitive_modified_globals(analysis: &Analysis, function: FuncId) -> Vec<GlobalId> {
    let mut globals = Vec::new();
    for row in analysis
        .modref(function)
        .filter(|row| row.access == pangs_pir::Access::Mod)
    {
        match row.global {
            GlobalTarget::Name(global) => globals.push(global),
            GlobalTarget::Unknown(_) => {
                if let Some(pointees) = row.stationarity_pointee_globals {
                    globals.extend(pointees.iter().copied());
                } else if row.pointee_globals.is_empty() {
                    globals
                        .extend((0..analysis.globals().len()).map(|index| GlobalId(index as u32)));
                } else {
                    globals.extend(
                        row.pointee_globals
                            .iter()
                            .filter_map(|name| analysis.lookup_global(name)),
                    );
                }
            }
        }
    }
    globals.sort();
    globals.dedup();
    globals
}

/// Production O2/O3 inputs for one unspliced spine function. Direct accesses and calls are
/// attributed to their exact statement group. The pointer-modref emitter currently coalesces
/// aliased accesses by function, so those rows conservatively affect every boundary rather than
/// trusting the one preferred witness retained after deduplication.
pub(crate) struct SpineInputs {
    pub(crate) generated_writes: Vec<Vec<GlobalId>>,
    pub(crate) observations: BTreeMap<GlobalId, Vec<Observation>>,
}

pub(crate) fn assemble_spine_inputs(
    analysis: &Analysis,
    module: &Pir,
    function: FuncId,
    cfg: &StatementCfg,
    pseudo_read_callsites: &BTreeMap<GlobalId, BTreeSet<CallsiteId>>,
) -> SpineInputs {
    let global_count = analysis.globals().len();
    let all_globals = || {
        (0..global_count)
            .map(|index| GlobalId(index as u32))
            .collect::<Vec<_>>()
    };
    let mut generated = vec![BTreeSet::new(); cfg.boundaries.len()];
    let mut observations = BTreeMap::<GlobalId, BTreeSet<Observation>>::new();
    let mut statement_boundary = BTreeMap::new();
    for boundary in &cfg.boundaries {
        for &statement in &boundary.stmt_indices {
            statement_boundary.insert(statement, boundary.id);
        }
    }
    let callsites_by_statement = callsites_by_statement(module);
    let Some(body) = module
        .functions
        .get(function.0 as usize)
        .map(|function| &function.body)
    else {
        return SpineInputs {
            generated_writes: vec![Vec::new(); cfg.boundaries.len()],
            observations: BTreeMap::new(),
        };
    };

    for (&statement, &boundary) in &statement_boundary {
        let Some(stmt) = body.get(statement as usize) else {
            continue;
        };
        match stmt {
            Stmt::GlobalRef { global, access, .. } => {
                let Some(global) = analysis.lookup_global(global) else {
                    continue;
                };
                add_access(
                    &mut generated[boundary as usize],
                    &mut observations,
                    boundary,
                    global,
                    *access,
                    true,
                );
            }
            Stmt::CallDirect { .. } | Stmt::CallIndirect { .. } => {
                let Some(&callsite) = callsites_by_statement.get(&(function, statement)) else {
                    continue;
                };
                let mut has_unknown = false;
                let mut has_callee = false;
                for callee in analysis.callees(callsite) {
                    has_callee = true;
                    match callee {
                        Callee::Func(callee) => {
                            if analysis.functions()[*callee].external {
                                has_unknown = true;
                                continue;
                            }
                            for row in analysis.modref(*callee) {
                                for global in affected_globals(analysis, &row) {
                                    add_access(
                                        &mut generated[boundary as usize],
                                        &mut observations,
                                        boundary,
                                        global,
                                        row.access,
                                        true,
                                    );
                                }
                            }
                        }
                        Callee::Unknown(_) => has_unknown = true,
                    }
                }
                if has_unknown || !has_callee {
                    for global in all_globals() {
                        generated[boundary as usize].insert(global);
                        observations.entry(global).or_default().insert(Observation {
                            boundary,
                            routable_pre_p: true,
                        });
                    }
                }
            }
            _ => {}
        }
    }

    // Function-coalesced alias rows cannot safely be located from their preferred witness.
    for row in analysis
        .modrefs()
        .iter()
        .filter(|row| row.func == function && row.via != Via::Direct)
    {
        for global in affected_globals(analysis, row) {
            for boundary in &cfg.boundaries {
                add_access(
                    &mut generated[boundary.id as usize],
                    &mut observations,
                    boundary.id,
                    global,
                    row.access,
                    true,
                );
            }
        }
    }

    let boundary_by_callsite = callsites_by_statement
        .iter()
        .filter_map(|(&(owner, statement), &callsite)| {
            (owner == function)
                .then(|| {
                    statement_boundary
                        .get(&statement)
                        .map(|&boundary| (callsite, boundary))
                })
                .flatten()
        })
        .collect::<BTreeMap<_, _>>();
    for (&global, callsites) in pseudo_read_callsites {
        for callsite in callsites {
            if let Some(&boundary) = boundary_by_callsite.get(callsite) {
                observations.entry(global).or_default().insert(Observation {
                    boundary,
                    routable_pre_p: false,
                });
            }
        }
    }

    // An escaped reader is observable at each known external-call escape site. Sources that
    // cannot be placed on this spine are conservatively observable at entry.
    let callsite_by_key = analysis
        .callsites()
        .iter()
        .enumerate()
        .map(|(index, callsite)| (callsite.key.as_str(), CallsiteId(index as u32)))
        .collect::<BTreeMap<_, _>>();
    for (index, escaped) in analysis.functions().iter().enumerate() {
        if !escaped.address_escaped {
            continue;
        }
        let reader = FuncId(index as u32);
        let read_globals = transitive_accessed_globals(analysis, reader, Access::Ref);
        for global in read_globals {
            for source in &escaped.escape_sources {
                let key = source
                    .strip_prefix("external-call:")
                    .or_else(|| source.strip_prefix("vararg-call:"));
                let boundary = key
                    .and_then(|key| callsite_by_key.get(key))
                    .and_then(|callsite| boundary_by_callsite.get(callsite))
                    .copied()
                    .unwrap_or(cfg.entry);
                observations.entry(global).or_default().insert(Observation {
                    boundary,
                    routable_pre_p: false,
                });
            }
        }
    }

    SpineInputs {
        generated_writes: generated
            .into_iter()
            .map(|globals| globals.into_iter().collect())
            .collect(),
        observations: observations
            .into_iter()
            .map(|(global, sites)| (global, sites.into_iter().collect()))
            .collect(),
    }
}

fn add_access(
    writes: &mut BTreeSet<GlobalId>,
    observations: &mut BTreeMap<GlobalId, BTreeSet<Observation>>,
    boundary: u32,
    global: GlobalId,
    access: Access,
    routable_pre_p: bool,
) {
    match access {
        Access::Mod => {
            writes.insert(global);
        }
        Access::Ref => {
            observations.entry(global).or_default().insert(Observation {
                boundary,
                routable_pre_p,
            });
        }
    }
}

fn callsites_by_statement(module: &Pir) -> BTreeMap<(FuncId, u32), CallsiteId> {
    let mut result = BTreeMap::new();
    let mut next = 0_u32;
    for (function_index, function) in module.functions.iter().enumerate() {
        for (statement_index, stmt) in function.body.iter().enumerate() {
            if matches!(stmt, Stmt::CallDirect { .. } | Stmt::CallIndirect { .. }) {
                result.insert(
                    (FuncId(function_index as u32), statement_index as u32),
                    CallsiteId(next),
                );
                next += 1;
            }
        }
    }
    result
}

fn transitive_accessed_globals(
    analysis: &Analysis,
    function: FuncId,
    access: Access,
) -> Vec<GlobalId> {
    let mut result = BTreeSet::new();
    for row in analysis.modref(function).filter(|row| row.access == access) {
        result.extend(affected_globals(analysis, &row));
    }
    result.into_iter().collect()
}

fn affected_globals(analysis: &Analysis, row: &pangs_api::ModRef) -> Vec<GlobalId> {
    match &row.global {
        GlobalTarget::Name(global) => vec![*global],
        GlobalTarget::Unknown(_) => {
            if let Some(pointees) = &row.stationarity_pointee_globals {
                pointees.iter().copied().collect()
            } else if row.pointee_globals.is_empty() {
                (0..analysis.globals().len())
                    .map(|index| GlobalId(index as u32))
                    .collect()
            } else {
                row.pointee_globals
                    .iter()
                    .filter_map(|name| analysis.lookup_global(name))
                    .collect()
            }
        }
    }
}

/// O2 result at statement-boundary granularity. `writable_after[p]` includes the writes
/// generated by the statement immediately following boundary `p` and every reachable successor.
pub(crate) struct Quiescence {
    writable_after: Vec<GlobalBits>,
    reachable: Vec<bool>,
}

impl Quiescence {
    pub(crate) fn compute(
        cfg: &StatementCfg,
        global_count: usize,
        generated_writes: &[Vec<GlobalId>],
    ) -> Result<Self, &'static str> {
        if cfg.boundaries.len() != generated_writes.len() {
            return Err("statement CFG and gen vector lengths differ");
        }
        for (index, boundary) in cfg.boundaries.iter().enumerate() {
            if boundary.id as usize != index {
                return Err("statement CFG boundary ids are not dense");
            }
            if boundary
                .successors
                .iter()
                .chain(&boundary.predecessors)
                .any(|edge| *edge as usize >= cfg.boundaries.len())
            {
                return Err("statement CFG edge is out of range");
            }
        }

        let generated = generated_writes
            .iter()
            .map(|writes| GlobalBits::from_globals(global_count, writes))
            .collect::<Vec<_>>();
        let mut writable_after = generated.clone();
        let mut queued = vec![true; cfg.boundaries.len()];
        let mut worklist = (0..cfg.boundaries.len()).rev().collect::<VecDeque<_>>();
        while let Some(boundary_id) = worklist.pop_front() {
            queued[boundary_id] = false;
            let boundary = &cfg.boundaries[boundary_id];
            let mut next = generated[boundary_id].clone();
            for &successor in &boundary.successors {
                next.union_with(&writable_after[successor as usize]);
            }
            if next != writable_after[boundary_id] {
                writable_after[boundary_id] = next;
                for &predecessor in &boundary.predecessors {
                    let predecessor = predecessor as usize;
                    if !queued[predecessor] {
                        queued[predecessor] = true;
                        worklist.push_back(predecessor);
                    }
                }
            }
        }

        let mut reachable = vec![false; cfg.boundaries.len()];
        let mut pending = vec![cfg.entry as usize];
        while let Some(boundary_id) = pending.pop() {
            let Some(slot) = reachable.get_mut(boundary_id) else {
                return Err("statement CFG entry is out of range");
            };
            if *slot {
                continue;
            }
            *slot = true;
            pending.extend(
                cfg.boundaries[boundary_id]
                    .successors
                    .iter()
                    .map(|successor| *successor as usize),
            );
        }

        Ok(Self {
            writable_after,
            reachable,
        })
    }

    pub(crate) fn is_quiescent(&self, boundary: u32, global: GlobalId) -> bool {
        self.reachable
            .get(boundary as usize)
            .copied()
            .unwrap_or(false)
            && !self.writable_after[boundary as usize].contains(global)
    }

    pub(crate) fn quiescent_boundaries(&self, global: GlobalId) -> Vec<u32> {
        self.reachable
            .iter()
            .enumerate()
            .filter_map(|(boundary, reachable)| {
                (*reachable && !self.writable_after[boundary].contains(global))
                    .then_some(boundary as u32)
            })
            .collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Observation {
    pub(crate) boundary: u32,
    /// Ordinary attributed reads can be routed through the init local before P. Escape/spawn
    /// pseudo-reads cannot: publication must dominate their registration boundary.
    pub(crate) routable_pre_p: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PublicationSelection {
    pub(crate) chosen: u32,
    pub(crate) earliest: u32,
    pub(crate) latest: u32,
    pub(crate) pre_p_observations: Vec<u32>,
    pub(crate) post_p_observations: Vec<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SelectionFailure {
    NoEntrySpine,
    NeverQuiescent,
    ObservationBeforeQuiescence,
    NoSingleP,
}

/// O3 single-P selection. Candidate boundaries must be source-insertable, outside CFG cycles,
/// quiescent, and dominance-comparable with every routable observation. Pseudo-observations must
/// be dominated by P because they cannot be redirected through the init local.
pub(crate) fn select_publication(
    cfg: &StatementCfg,
    quiescence: &Quiescence,
    global: GlobalId,
    observations: &[Observation],
) -> Result<PublicationSelection, SelectionFailure> {
    if !cfg.source_mapping_available || cfg.boundaries.is_empty() {
        return Err(SelectionFailure::NoEntrySpine);
    }
    let quiescent = quiescence.quiescent_boundaries(global);
    if quiescent.is_empty() {
        return Err(SelectionFailure::NeverQuiescent);
    }

    let dominators = dominators(cfg);
    let cyclic = cyclic_boundaries(cfg);
    let mut valid = Vec::new();
    for boundary in quiescent {
        let index = boundary as usize;
        if !cfg.boundaries[index].insertable || cyclic[index] {
            continue;
        }
        let acceptable = observations.iter().all(|observation| {
            let observation_id = observation.boundary as usize;
            if observation_id >= cfg.boundaries.len() {
                return false;
            }
            let p_dominates_observation = dominators[observation_id][index];
            let observation_strictly_precedes_p = observation.boundary != boundary
                && dominators[index][observation_id]
                && observation.routable_pre_p;
            p_dominates_observation || observation_strictly_precedes_p
        });
        if acceptable {
            valid.push(boundary);
        }
    }
    if valid.is_empty() {
        let pseudo_before_quiescence = observations
            .iter()
            .filter(|observation| !observation.routable_pre_p)
            .any(|observation| {
                cfg.boundaries.get(observation.boundary as usize).is_some()
                    && cfg.boundaries.iter().any(|boundary| {
                        quiescence.is_quiescent(boundary.id, global)
                            && dominators[boundary.id as usize][observation.boundary as usize]
                    })
            });
        return Err(if pseudo_before_quiescence {
            SelectionFailure::ObservationBeforeQuiescence
        } else {
            SelectionFailure::NoSingleP
        });
    }

    valid.sort_by_key(|boundary| {
        (
            dominators[*boundary as usize]
                .iter()
                .filter(|dominates| **dominates)
                .count(),
            *boundary,
        )
    });
    // A publication interval is a dominator chain, not a set of incomparable branch points.
    if valid.windows(2).any(|pair| {
        !dominators[pair[1] as usize][pair[0] as usize]
            && !dominators[pair[0] as usize][pair[1] as usize]
    }) {
        return Err(SelectionFailure::NoSingleP);
    }
    let earliest = valid[0];
    let latest = *valid.last().unwrap();
    let chosen = earliest;
    let mut pre_p_observations = Vec::new();
    let mut post_p_observations = Vec::new();
    for observation in observations {
        if observation.boundary != chosen
            && observation.routable_pre_p
            && dominators[chosen as usize][observation.boundary as usize]
        {
            pre_p_observations.push(observation.boundary);
        } else {
            post_p_observations.push(observation.boundary);
        }
    }
    pre_p_observations.sort_unstable();
    pre_p_observations.dedup();
    post_p_observations.sort_unstable();
    post_p_observations.dedup();
    Ok(PublicationSelection {
        chosen,
        earliest,
        latest,
        pre_p_observations,
        post_p_observations,
    })
}

fn dominators(cfg: &StatementCfg) -> Vec<Vec<bool>> {
    let count = cfg.boundaries.len();
    let entry = cfg.entry as usize;
    let mut reachable = vec![false; count];
    if entry < count {
        let mut pending = vec![entry];
        while let Some(node) = pending.pop() {
            if reachable[node] {
                continue;
            }
            reachable[node] = true;
            pending.extend(
                cfg.boundaries[node]
                    .successors
                    .iter()
                    .map(|successor| *successor as usize),
            );
        }
    }
    let mut dom = vec![vec![false; count]; count];
    for node in 0..count {
        if !reachable[node] {
            continue;
        }
        if node == entry {
            dom[node][node] = true;
        } else {
            dom[node] = reachable.clone();
        }
    }
    loop {
        let mut changed = false;
        for node in 0..count {
            if node == entry || !reachable[node] {
                continue;
            }
            let predecessors = cfg.boundaries[node]
                .predecessors
                .iter()
                .map(|predecessor| *predecessor as usize)
                .filter(|predecessor| reachable[*predecessor])
                .collect::<Vec<_>>();
            let mut next = vec![true; count];
            for predecessor in predecessors {
                for (slot, incoming) in next.iter_mut().zip(&dom[predecessor]) {
                    *slot &= *incoming;
                }
            }
            next[node] = true;
            if next != dom[node] {
                dom[node] = next;
                changed = true;
            }
        }
        if !changed {
            return dom;
        }
    }
}

fn cyclic_boundaries(cfg: &StatementCfg) -> Vec<bool> {
    (0..cfg.boundaries.len())
        .map(|origin| {
            let mut seen = vec![false; cfg.boundaries.len()];
            let mut pending = cfg.boundaries[origin]
                .successors
                .iter()
                .map(|successor| *successor as usize)
                .collect::<Vec<_>>();
            while let Some(node) = pending.pop() {
                if node == origin {
                    return true;
                }
                if seen[node] {
                    continue;
                }
                seen[node] = true;
                pending.extend(
                    cfg.boundaries[node]
                        .successors
                        .iter()
                        .map(|successor| *successor as usize),
                );
            }
            false
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct GlobalBits(Vec<u64>);

impl GlobalBits {
    fn from_globals(global_count: usize, globals: &[GlobalId]) -> Self {
        let mut bits = Self(vec![0; global_count.div_ceil(64)]);
        for global in globals {
            let index = global.0 as usize;
            if index < global_count {
                bits.0[index / 64] |= 1_u64 << (index % 64);
            }
        }
        bits
    }

    fn union_with(&mut self, other: &Self) {
        for (slot, incoming) in self.0.iter_mut().zip(&other.0) {
            *slot |= incoming;
        }
    }

    fn contains(&self, global: GlobalId) -> bool {
        let index = global.0 as usize;
        self.0
            .get(index / 64)
            .is_some_and(|word| word & (1_u64 << (index % 64)) != 0)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use pangs_api::{Analysis, BuildMode, CallsiteId, Opts, Stage};
    use pangs_pir::{StatementBoundary, StatementCfg};
    use serde_json::json;

    use super::{
        assemble_spine_inputs, evaluate_kill_rules, select_publication, FuncId, GlobalId,
        Observation, Quiescence, SelectionFailure,
    };

    fn boundary(id: u32, successors: &[u32], predecessors: &[u32]) -> StatementBoundary {
        StatementBoundary {
            id,
            block: id,
            ordinal: 0,
            loc: None,
            insertable: true,
            stmt_indices: Vec::new(),
            successors: successors.to_vec(),
            predecessors: predecessors.to_vec(),
        }
    }

    #[test]
    fn loop_write_quiesces_only_at_its_exit() {
        // entry -> loop; loop -> loop or exit
        let cfg = StatementCfg {
            entry: 0,
            boundaries: vec![
                boundary(0, &[1], &[]),
                boundary(1, &[1, 2], &[0, 1]),
                boundary(2, &[], &[1]),
            ],
            source_mapping_available: true,
        };
        let writes = vec![vec![], vec![GlobalId(0)], vec![]];
        let result = Quiescence::compute(&cfg, 2, &writes).unwrap();
        assert!(!result.is_quiescent(0, GlobalId(0)));
        assert!(!result.is_quiescent(1, GlobalId(0)));
        assert!(result.is_quiescent(2, GlobalId(0)));
        assert_eq!(result.quiescent_boundaries(GlobalId(0)), vec![2]);
        assert_eq!(result.quiescent_boundaries(GlobalId(1)), vec![0, 1, 2]);
    }

    #[test]
    fn branch_writes_union_at_the_merge_predecessor() {
        // entry branches to two arms; only the left writes; both merge at node 3.
        let cfg = StatementCfg {
            entry: 0,
            boundaries: vec![
                boundary(0, &[1, 2], &[]),
                boundary(1, &[3], &[0]),
                boundary(2, &[3], &[0]),
                boundary(3, &[], &[1, 2]),
            ],
            source_mapping_available: true,
        };
        let writes = vec![vec![], vec![GlobalId(0)], vec![], vec![]];
        let result = Quiescence::compute(&cfg, 1, &writes).unwrap();
        assert!(!result.is_quiescent(0, GlobalId(0)));
        assert!(!result.is_quiescent(1, GlobalId(0)));
        assert!(result.is_quiescent(2, GlobalId(0)));
        assert!(result.is_quiescent(3, GlobalId(0)));
    }

    #[test]
    fn omega_gen_poisons_every_global_before_the_unknown_call() {
        let cfg = StatementCfg {
            entry: 0,
            boundaries: vec![boundary(0, &[1], &[]), boundary(1, &[], &[0])],
            source_mapping_available: true,
        };
        let all_globals = vec![GlobalId(0), GlobalId(1), GlobalId(2)];
        let result = Quiescence::compute(&cfg, 3, &[all_globals, vec![]]).unwrap();
        for global in 0..3 {
            assert!(!result.is_quiescent(0, GlobalId(global)));
            assert!(result.is_quiescent(1, GlobalId(global)));
        }
    }

    #[test]
    fn publication_selects_the_acyclic_loop_exit() {
        let cfg = StatementCfg {
            entry: 0,
            boundaries: vec![
                boundary(0, &[1], &[]),
                boundary(1, &[1, 2], &[0, 1]),
                boundary(2, &[], &[1]),
            ],
            source_mapping_available: true,
        };
        let quiescence =
            Quiescence::compute(&cfg, 1, &[vec![], vec![GlobalId(0)], vec![]]).unwrap();
        let selected = select_publication(
            &cfg,
            &quiescence,
            GlobalId(0),
            &[Observation {
                boundary: 2,
                routable_pre_p: true,
            }],
        )
        .unwrap();
        assert_eq!(selected.chosen, 2);
        assert_eq!(selected.earliest, 2);
        assert_eq!(selected.latest, 2);
        assert_eq!(selected.post_p_observations, vec![2]);
    }

    #[test]
    fn pseudo_observation_before_quiescence_is_not_routable() {
        let cfg = StatementCfg {
            entry: 0,
            boundaries: vec![
                boundary(0, &[1], &[]),
                boundary(1, &[2], &[0]),
                boundary(2, &[], &[1]),
            ],
            source_mapping_available: true,
        };
        let quiescence =
            Quiescence::compute(&cfg, 1, &[vec![], vec![GlobalId(0)], vec![]]).unwrap();
        assert_eq!(
            select_publication(
                &cfg,
                &quiescence,
                GlobalId(0),
                &[Observation {
                    boundary: 0,
                    routable_pre_p: false,
                }],
            ),
            Err(SelectionFailure::ObservationBeforeQuiescence)
        );
    }

    #[test]
    fn mode_split_branches_report_no_single_publication_point() {
        // Left arm writes then reads; right arm reads without passing through the left quiescent
        // point. Neither arm-local P dominates the other observation.
        let cfg = StatementCfg {
            entry: 0,
            boundaries: vec![
                boundary(0, &[1, 2], &[]),
                boundary(1, &[3], &[0]),
                boundary(2, &[], &[0]),
                boundary(3, &[], &[1]),
            ],
            source_mapping_available: true,
        };
        let quiescence =
            Quiescence::compute(&cfg, 1, &[vec![], vec![GlobalId(0)], vec![], vec![]]).unwrap();
        assert_eq!(
            select_publication(
                &cfg,
                &quiescence,
                GlobalId(0),
                &[
                    Observation {
                        boundary: 2,
                        routable_pre_p: true,
                    },
                    Observation {
                        boundary: 3,
                        routable_pre_p: true,
                    },
                ],
            ),
            Err(SelectionFailure::NoSingleP)
        );
    }

    #[test]
    fn kill_rules_report_omega_thread_taint_and_recursive_main_in_fixed_order() {
        let signature = || json!({"ret":{"class":"void"},"params":[],"cc":"ccc"});
        let callback_signature = || {
            json!({
                "ret":{"class":"integer"},
                "params":[{"class":"integer"}],
                "cc":"ccc"
            })
        };
        let pir: pangs_pir::Pir = serde_json::from_value(json!({
            "module":"phase-kills",
            "functions":[
                {
                    "key":"main", "sig":signature(),
                    "body":[
                        {"kind":"call_direct", "callee":"sink", "sig":signature(),
                         "args":["writer"]},
                        {"kind":"call_direct", "callee":"pthread_create", "sig":signature(),
                         "args":["null", "null", "worker", "null"]},
                        {"kind":"call_direct", "callee":"main", "sig":signature(), "args":[]}
                    ]
                },
                {
                    "key":"writer", "sig":signature(), "address_taken":true,
                    "body":[{"kind":"global_ref", "global":"@g_omega", "access":"mod"}]
                },
                {
                    "key":"worker", "sig":callback_signature(), "address_taken":true,
                    "body":[{"kind":"global_ref", "global":"@g_thread", "access":"mod"}]
                },
                {
                    "key":"tainted", "sig":signature(),
                    "body":[
                        {"kind":"global_ref", "global":"@g_taint", "access":"mod"},
                        {"kind":"unknown", "op":"asm", "reason":"inline_asm:test"}
                    ]
                },
                {"key":"sink", "sig":signature(), "external":true},
                {"key":"pthread_create", "sig":signature(), "external":true}
            ],
            "globals":[
                {"key":"@g_omega"}, {"key":"@g_thread"},
                {"key":"@g_taint"}, {"key":"@g_plain"}
            ]
        }))
        .unwrap();
        let opts = Opts {
            stage: Stage::Steens,
            build_mode: BuildMode::Executable,
            ..Opts::default()
        };
        let analysis = Analysis::run_with_disposition(&pir, &opts).unwrap();
        let registry = crate::registry_access_facts(&analysis, &pir);
        let kills = evaluate_kill_rules(&analysis, &registry.thread_writers);
        let codes = |name: &str| {
            let global = analysis.lookup_global(name).unwrap();
            kills[&global]
                .iter()
                .map(|failure| failure.code)
                .collect::<Vec<_>>()
        };

        assert_eq!(codes("@g_omega"), vec!["omega-writer", "recursive-main"]);
        assert_eq!(
            codes("@g_thread"),
            vec!["omega-writer", "thread-writer", "recursive-main"]
        );
        assert_eq!(codes("@g_taint"), vec!["violation-taint", "recursive-main"]);
        assert_eq!(codes("@g_plain"), vec!["recursive-main"]);
        assert!(kills.values().flatten().all(|failure| {
            !failure.witness.kind.is_empty() && failure.witness.note.is_some()
                || failure.code == "thread-writer"
        }));
    }

    #[test]
    fn production_inputs_map_direct_calls_reads_and_pseudo_reads_to_boundaries() {
        let signature = || json!({"ret":{"class":"void"},"params":[],"cc":"ccc"});
        let pir: pangs_pir::Pir = serde_json::from_value(json!({
            "module":"phase-inputs",
            "functions":[
                {
                    "key":"main", "sig":signature(),
                    "body":[
                        {"kind":"call_direct", "callee":"initialize", "sig":signature(),
                         "args":[]},
                        {"kind":"global_ref", "global":"@g", "access":"ref"}
                    ]
                },
                {
                    "key":"initialize", "sig":signature(),
                    "body":[{"kind":"global_ref", "global":"@g", "access":"mod"}]
                }
            ],
            "globals":[{"key":"@g"}]
        }))
        .unwrap();
        let opts = Opts {
            stage: Stage::Steens,
            build_mode: BuildMode::Executable,
            ..Opts::default()
        };
        let analysis = Analysis::run_with_disposition(&pir, &opts).unwrap();
        let cfg = StatementCfg {
            entry: 0,
            boundaries: vec![
                StatementBoundary {
                    stmt_indices: vec![0],
                    ..boundary(0, &[1], &[])
                },
                StatementBoundary {
                    stmt_indices: vec![1],
                    ..boundary(1, &[], &[0])
                },
            ],
            source_mapping_available: true,
        };
        let global = analysis.lookup_global("@g").unwrap();
        let inputs = assemble_spine_inputs(&analysis, &pir, FuncId(0), &cfg, &BTreeMap::new());
        assert_eq!(inputs.generated_writes, vec![vec![global], vec![]]);
        assert_eq!(
            inputs.observations[&global],
            vec![Observation {
                boundary: 1,
                routable_pre_p: true
            }]
        );

        let pseudo = BTreeMap::from([(global, BTreeSet::from([CallsiteId(0)]))]);
        let inputs = assemble_spine_inputs(&analysis, &pir, FuncId(0), &cfg, &pseudo);
        assert_eq!(
            inputs.observations[&global],
            vec![
                Observation {
                    boundary: 0,
                    routable_pre_p: false
                },
                Observation {
                    boundary: 1,
                    routable_pre_p: true
                }
            ]
        );
    }

    #[test]
    fn production_unknown_call_generates_top_and_observes_top() {
        let signature = || json!({"ret":{"class":"void"},"params":[],"cc":"ccc"});
        let pir: pangs_pir::Pir = serde_json::from_value(json!({
            "module":"phase-unknown-call",
            "functions":[
                {"key":"main", "sig":signature(), "body":[
                    {"kind":"call_direct", "callee":"external", "sig":signature(), "args":[]}
                ]},
                {"key":"external", "sig":signature(), "external":true}
            ],
            "globals":[{"key":"@a"},{"key":"@b"}]
        }))
        .unwrap();
        let analysis = Analysis::run_with_disposition(
            &pir,
            &Opts {
                stage: Stage::Steens,
                build_mode: BuildMode::Executable,
                ..Opts::default()
            },
        )
        .unwrap();
        let cfg = StatementCfg {
            entry: 0,
            boundaries: vec![StatementBoundary {
                stmt_indices: vec![0],
                ..boundary(0, &[], &[])
            }],
            source_mapping_available: true,
        };
        let inputs = assemble_spine_inputs(&analysis, &pir, FuncId(0), &cfg, &BTreeMap::new());
        assert_eq!(inputs.generated_writes[0], vec![GlobalId(0), GlobalId(1)]);
        assert_eq!(inputs.observations.len(), 2);
        assert!(inputs.observations.values().all(|observations| {
            observations
                == &[Observation {
                    boundary: 0,
                    routable_pre_p: true,
                }]
        }));
    }
}
