use std::collections::{BTreeMap, BTreeSet, VecDeque};

use pangs_api::{
    Analysis, BuildMode, Callee, Caller, CallsiteId, FuncId, GlobalId, GlobalTarget, Opts, Via,
};
use pangs_manifest::{Certificate, Extra, Site, Witness};
use pangs_pir::{Access, Pir, StatementCfg, Stmt};
use serde_json::{json, Value};

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BoundaryOrigin {
    pub(crate) function: FuncId,
    pub(crate) boundary: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DescentCandidate {
    pub(crate) callsite: CallsiteId,
    pub(crate) boundary: u32,
    pub(crate) callee: FuncId,
}

/// Applies O5's uniqueness gate to a source boundary. The call must have one internal target,
/// that function must have exactly this one incoming call site and no unknown caller, and no
/// coalesced pointer write may make removal of the parent's call summary ambiguous.
pub(crate) fn descent_candidate(
    analysis: &Analysis,
    module: &Pir,
    function: FuncId,
    cfg: &StatementCfg,
    global: GlobalId,
) -> Option<DescentCandidate> {
    if analysis
        .modrefs()
        .iter()
        .filter(|row| row.func == function && row.access == Access::Mod && row.via != Via::Direct)
        .any(|row| affected_globals(analysis, row).contains(&global))
    {
        return None;
    }
    let body = &module.functions.get(function.0 as usize)?.body;
    let callsites = callsites_by_statement(module);
    let mut candidates = Vec::new();
    for boundary in &cfg.boundaries {
        let calls = boundary
            .stmt_indices
            .iter()
            .filter_map(|statement| {
                let stmt = body.get(*statement as usize)?;
                matches!(stmt, Stmt::CallDirect { .. } | Stmt::CallIndirect { .. })
                    .then(|| callsites.get(&(function, *statement)).copied())
                    .flatten()
            })
            .collect::<Vec<_>>();
        if calls.len() != 1
            || boundary.stmt_indices.iter().any(|statement| {
                matches!(
                    body.get(*statement as usize),
                    Some(Stmt::GlobalRef {
                        global: name,
                        access: Access::Mod,
                        ..
                    }) if analysis.lookup_global(name) == Some(global)
                )
            })
        {
            continue;
        }
        let callsite = calls[0];
        let targets = analysis.callees(callsite).cloned().collect::<BTreeSet<_>>();
        let targets = targets.into_iter().collect::<Vec<_>>();
        let [Callee::Func(callee)] = targets.as_slice() else {
            continue;
        };
        if analysis.functions()[*callee].external
            || !transitive_accessed_globals(analysis, *callee, Access::Mod).contains(&global)
        {
            continue;
        }
        let incoming = analysis
            .call_edges()
            .iter()
            .filter(|edge| edge.callee == Callee::Func(*callee))
            .collect::<Vec<_>>();
        if incoming.len() != 1
            || incoming[0].caller != Caller::Func(function)
            || incoming[0].callsite != Some(callsite)
        {
            continue;
        }
        candidates.push(DescentCandidate {
            callsite,
            boundary: boundary.id,
            callee: *callee,
        });
    }
    match candidates.as_slice() {
        [candidate] => Some(*candidate),
        _ => None,
    }
}

/// One source-level spine after replacing a call boundary's outgoing edge with the uniquely
/// called child's CFG. The call boundary remains as a non-insertable gateway; child exits return
/// to its former successors. Keeping a real node for the call makes repeated descent mechanical.
pub(crate) struct SplicedSpine {
    pub(crate) cfg: StatementCfg,
    pub(crate) generated_writes: Vec<Vec<GlobalId>>,
    pub(crate) observations: Vec<Observation>,
    pub(crate) origins: Vec<BoundaryOrigin>,
}

pub(crate) struct DescentEvaluation {
    pub(crate) spine: SplicedSpine,
    pub(crate) selection: Result<PublicationSelection, SelectionFailure>,
    pub(crate) path: Vec<CallsiteId>,
    pub(crate) exhausted: bool,
}

/// Runs O2/O3 on `root`, repeatedly splicing the uniquely called current leaf up to `max_depth`.
/// `exhausted` is set only when another sound descent was available after consuming the bound;
/// callers map that case to `spine-descent-exhausted` instead of the provisional O3 failure.
pub(crate) fn evaluate_with_descent(
    analysis: &Analysis,
    module: &Pir,
    root: FuncId,
    global: GlobalId,
    pseudo_read_callsites: &BTreeMap<GlobalId, BTreeSet<CallsiteId>>,
    max_depth: usize,
) -> Option<DescentEvaluation> {
    let root_info = &analysis.functions()[root];
    let root_cfg = module.lowering.statement_cfgs.get(&root_info.key)?;
    let root_inputs =
        assemble_spine_inputs(analysis, module, root, root_cfg, pseudo_read_callsites);
    let mut spine = SplicedSpine {
        cfg: root_cfg.clone(),
        generated_writes: root_inputs.generated_writes,
        observations: root_inputs
            .observations
            .get(&global)
            .cloned()
            .unwrap_or_default(),
        origins: root_cfg
            .boundaries
            .iter()
            .map(|boundary| BoundaryOrigin {
                function: root,
                boundary: boundary.id,
            })
            .collect(),
    };
    let mut leaf = root;
    let mut path = Vec::new();
    loop {
        let selection = Quiescence::compute(
            &spine.cfg,
            analysis.globals().len(),
            &spine.generated_writes,
        )
        .map_err(|_| SelectionFailure::NoEntrySpine)
        .and_then(|quiescence| {
            select_publication(&spine.cfg, &quiescence, global, &spine.observations)
        });
        if selection.is_ok() {
            return Some(DescentEvaluation {
                spine,
                selection,
                path,
                exhausted: false,
            });
        }

        let leaf_info = &analysis.functions()[leaf];
        let Some(leaf_cfg) = module.lowering.statement_cfgs.get(&leaf_info.key) else {
            return Some(DescentEvaluation {
                spine,
                selection,
                path,
                exhausted: false,
            });
        };
        let Some(candidate) = descent_candidate(analysis, module, leaf, leaf_cfg, global) else {
            return Some(DescentEvaluation {
                spine,
                selection,
                path,
                exhausted: false,
            });
        };
        if path.len() == max_depth {
            return Some(DescentEvaluation {
                spine,
                selection,
                path,
                exhausted: true,
            });
        }
        let composite_boundary =
            spine.origins.iter().position(|origin| {
                origin.function == leaf && origin.boundary == candidate.boundary
            })? as u32;
        let child_info = &analysis.functions()[candidate.callee];
        let Some(child_cfg) = module.lowering.statement_cfgs.get(&child_info.key) else {
            return Some(DescentEvaluation {
                spine,
                selection,
                path,
                exhausted: false,
            });
        };
        let child_inputs = assemble_spine_inputs(
            analysis,
            module,
            candidate.callee,
            child_cfg,
            pseudo_read_callsites,
        );
        let Ok(next) = splice_into_spine(
            spine,
            composite_boundary,
            candidate.callee,
            child_cfg,
            &child_inputs,
            global,
        ) else {
            return None;
        };
        spine = next;
        path.push(candidate.callsite);
        leaf = candidate.callee;
    }
}

#[cfg(test)]
pub(crate) fn splice_unique_call(
    parent_function: FuncId,
    parent_cfg: &StatementCfg,
    parent_inputs: &SpineInputs,
    call_boundary: u32,
    child_function: FuncId,
    child_cfg: &StatementCfg,
    child_inputs: &SpineInputs,
    global: GlobalId,
) -> Result<SplicedSpine, &'static str> {
    if parent_cfg.boundaries.len() != parent_inputs.generated_writes.len()
        || child_cfg.boundaries.len() != child_inputs.generated_writes.len()
    {
        return Err("statement CFG and gen vector lengths differ");
    }
    let parent = SplicedSpine {
        cfg: parent_cfg.clone(),
        generated_writes: parent_inputs.generated_writes.clone(),
        observations: parent_inputs
            .observations
            .get(&global)
            .cloned()
            .unwrap_or_default(),
        origins: parent_cfg
            .boundaries
            .iter()
            .map(|boundary| BoundaryOrigin {
                function: parent_function,
                boundary: boundary.id,
            })
            .collect(),
    };
    splice_into_spine(
        parent,
        call_boundary,
        child_function,
        child_cfg,
        child_inputs,
        global,
    )
}

fn splice_into_spine(
    parent: SplicedSpine,
    call_boundary: u32,
    child_function: FuncId,
    child_cfg: &StatementCfg,
    child_inputs: &SpineInputs,
    global: GlobalId,
) -> Result<SplicedSpine, &'static str> {
    let call_index = call_boundary as usize;
    let Some(call) = parent.cfg.boundaries.get(call_index) else {
        return Err("descent call boundary is out of range");
    };
    if child_cfg.boundaries.is_empty() || child_cfg.entry as usize >= child_cfg.boundaries.len() {
        return Err("descent child has no entry spine");
    }
    let child_offset = parent.cfg.boundaries.len() as u32;
    let return_successors = call.successors.clone();
    let mut boundaries = parent.cfg.boundaries.clone();
    boundaries[call_index].successors = vec![child_offset + child_cfg.entry];
    // Publication immediately before a still-executing call is not a valid replacement for a
    // boundary after it, so the gateway itself is never source-insertable.
    boundaries[call_index].insertable = false;
    for child in &child_cfg.boundaries {
        let mut lowered = child.clone();
        lowered.id += child_offset;
        lowered.successors = if child.successors.is_empty() {
            return_successors.clone()
        } else {
            child
                .successors
                .iter()
                .map(|successor| child_offset + successor)
                .collect()
        };
        lowered.predecessors.clear();
        boundaries.push(lowered);
    }
    rebuild_predecessors(&mut boundaries)?;

    let mut generated_writes = parent.generated_writes;
    // Eligibility establishes that the global's effect at this boundary came only from the
    // descended call. Other globals remain conservative because this splice is per-global.
    generated_writes[call_index].retain(|candidate| *candidate != global);
    generated_writes.extend(child_inputs.generated_writes.iter().cloned());

    let mut observations = parent
        .observations
        .into_iter()
        // Attributed reads at the replaced call are now represented inside the child. A
        // non-routable registration observation remains attached to the call gateway.
        .filter(|observation| observation.boundary != call_boundary || !observation.routable_pre_p)
        .collect::<Vec<_>>();
    observations.extend(
        child_inputs
            .observations
            .get(&global)
            .into_iter()
            .flatten()
            .map(|observation| Observation {
                boundary: child_offset + observation.boundary,
                routable_pre_p: observation.routable_pre_p,
            }),
    );
    observations.sort();
    observations.dedup();

    let mut origins = parent.origins;
    origins.extend(child_cfg.boundaries.iter().map(|boundary| BoundaryOrigin {
        function: child_function,
        boundary: boundary.id,
    }));

    Ok(SplicedSpine {
        cfg: StatementCfg {
            entry: parent.cfg.entry,
            source_mapping_available: parent.cfg.source_mapping_available
                && child_cfg.source_mapping_available,
            boundaries,
        },
        generated_writes,
        observations,
        origins,
    })
}

fn rebuild_predecessors(
    boundaries: &mut [pangs_pir::StatementBoundary],
) -> Result<(), &'static str> {
    for boundary in boundaries.iter_mut() {
        boundary.predecessors.clear();
    }
    let edges = boundaries
        .iter()
        .flat_map(|boundary| {
            boundary
                .successors
                .iter()
                .map(move |successor| (boundary.id, *successor))
        })
        .collect::<Vec<_>>();
    for (predecessor, successor) in edges {
        let Some(boundary) = boundaries.get_mut(successor as usize) else {
            return Err("spliced statement CFG edge is out of range");
        };
        boundary.predecessors.push(predecessor);
    }
    for boundary in boundaries {
        boundary.predecessors.sort_unstable();
        boundary.predecessors.dedup();
    }
    Ok(())
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
                // A resolved spawn/signal registry call has an explicit callback model below.
                // Treating its external declaration as Ω as well would contradict that model and
                // make every reader registration look like a writer of every global.
                let modeled_registry_call = pseudo_read_callsites
                    .values()
                    .any(|callsites| callsites.contains(&callsite));
                let mut has_unknown = false;
                let mut has_callee = false;
                for callee in analysis.callees(callsite) {
                    has_callee = true;
                    match callee {
                        Callee::Func(callee) => {
                            if analysis.functions()[*callee].external {
                                has_unknown |= !modeled_registry_call;
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

    // The unaggregated site ledger is authoritative for pointer accesses. A statement index is
    // exact; otherwise every boundary at the same debug location is used. Missing/unmatched
    // locations conservatively affect the whole function.
    for site in analysis
        .access_sites()
        .iter()
        .filter(|site| site.func == function && site.via != Via::Direct)
    {
        let mut boundaries = site
            .statement_index
            .and_then(|statement| statement_boundary.get(&statement).copied())
            .into_iter()
            .collect::<Vec<_>>();
        if boundaries.is_empty() {
            if let Some(loc) = &site.loc {
                boundaries.extend(cfg.boundaries.iter().filter_map(|boundary| {
                    boundary.loc.as_ref().and_then(|candidate| {
                        (candidate.file == loc.file
                            && candidate.line == loc.line
                            && candidate.col == loc.col)
                            .then_some(boundary.id)
                    })
                }));
            }
        }
        if boundaries.is_empty() {
            boundaries.extend(cfg.boundaries.iter().map(|boundary| boundary.id));
        }
        for boundary in boundaries {
            add_access(
                &mut generated[boundary as usize],
                &mut observations,
                boundary,
                site.global,
                site.access,
                true,
            );
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

pub(crate) fn certificate_slots(
    analysis: &Analysis,
    module: &Pir,
    opts: &Opts,
    pseudo_read_callsites: &BTreeMap<GlobalId, BTreeSet<CallsiteId>>,
    spawn_read_callsites: &BTreeMap<GlobalId, BTreeSet<CallsiteId>>,
    escape_read_callsites: &BTreeMap<GlobalId, BTreeSet<CallsiteId>>,
    thread_writers: &BTreeMap<GlobalId, Witness>,
) -> (Option<Value>, BTreeMap<GlobalId, Certificate>, Value) {
    let main = (opts.build_mode == BuildMode::Executable
        && opts.stage != pangs_api::Stage::Conservative)
        .then(|| analysis.lookup_func("main"))
        .flatten();
    let entry_spine = main.map(|main| {
        json!({
            "root": analysis.functions()[main].key,
            "max_descent_depth": 4,
            "assumptions": []
        })
    });
    let kills = evaluate_kill_rules(analysis, thread_writers);
    let mut slots = BTreeMap::new();
    let mut descent_depths = BTreeMap::new();
    let mut descent_exhausted = BTreeSet::new();
    for index in 0..analysis.globals().len() {
        let global = GlobalId(index as u32);
        let Some(main) = main else {
            slots.insert(
                global,
                failed_slot(
                    "no-entry-spine",
                    run_witness("no-entry-spine", "v1 requires executable mode with main"),
                ),
            );
            continue;
        };
        let Some(evaluation) =
            evaluate_with_descent(analysis, module, main, global, pseudo_read_callsites, 4)
        else {
            slots.insert(
                global,
                failed_slot(
                    "no-entry-spine",
                    run_witness("no-entry-spine", "statement CFG metadata unavailable"),
                ),
            );
            continue;
        };
        descent_depths.insert(global, evaluation.path.len());
        if evaluation.exhausted {
            descent_exhausted.insert(global);
        }
        let mut codes = kills
            .get(&global)
            .into_iter()
            .flatten()
            .map(|kill| kill.code.to_string())
            .collect::<Vec<_>>();
        let mut witnesses = kills
            .get(&global)
            .into_iter()
            .flatten()
            .map(|kill| kill.witness.clone())
            .collect::<Vec<_>>();
        let payload = match &evaluation.selection {
            Ok(selection) => build_payload(
                analysis,
                module,
                global,
                &evaluation,
                selection,
                spawn_read_callsites,
                escape_read_callsites,
            ),
            Err(failure) => Err((selection_code(*failure), selection_witness(*failure))),
        };
        let recipe = match payload {
            Ok(payload) if codes.is_empty() => {
                slots.insert(
                    global,
                    Certificate::Certified {
                        certificate: payload,
                        extra: Extra::new(),
                    },
                );
                continue;
            }
            Ok(payload) => Some(payload),
            Err((code, witness)) => {
                codes.push(if evaluation.exhausted {
                    "spine-descent-exhausted".into()
                } else {
                    code.into()
                });
                witnesses.push(witness);
                None
            }
        };
        slots.insert(
            global,
            Certificate::Failed {
                codes,
                witnesses,
                recipe,
                diagnostics: None,
                extra: Extra::new(),
            },
        );
    }
    let report = phase_report(analysis, &slots, &descent_depths, &descent_exhausted);
    (entry_spine, slots, report)
}

fn phase_report(
    analysis: &Analysis,
    slots: &BTreeMap<GlobalId, Certificate>,
    descent_depths: &BTreeMap<GlobalId, usize>,
    descent_exhausted: &BTreeSet<GlobalId>,
) -> Value {
    let relevant = analysis
        .globals()
        .iter()
        .enumerate()
        .filter(|(_, global)| global.mutable && global.is_definition)
        .map(|(index, _)| GlobalId(index as u32))
        .collect::<Vec<_>>();
    let mut certified = 0_u64;
    let mut failure_codes = BTreeMap::<String, u64>::new();
    let mut quiescence_profile = Vec::<(String, Value)>::new();
    let mut no_single_p = Vec::new();
    let mut both_phase_histogram = BTreeMap::<usize, u64>::new();
    let mut both_phase_functions_total = 0_u64;
    let mut both_phase_globals_nonempty = 0_u64;
    let mut both_phase_not_computed = 0_u64;
    let mut depth_histogram = BTreeMap::<usize, u64>::new();
    let mut not_computed = 0_u64;

    for &global in &relevant {
        let Some(slot) = slots.get(&global) else {
            not_computed += 1;
            let name = analysis.globals()[global].key.clone();
            quiescence_profile.push((
                format!("2|{name}"),
                json!({"global": name, "status": "not-computed"}),
            ));
            continue;
        };
        let payload = match slot {
            Certificate::Certified { certificate, .. } => {
                certified += 1;
                let point = &certificate["publication"]["publication_point"];
                let name = analysis.globals()[global].key.clone();
                quiescence_profile.push((
                    format!(
                        "0|{}|{:010}|{:010}|{}",
                        point["file"].as_str().unwrap_or(""),
                        point["line"].as_u64().unwrap_or(0),
                        point["col"].as_u64().unwrap_or(0),
                        name
                    ),
                    json!({
                        "global": name,
                        "status": "certified",
                        "publication_point": point,
                        "publication_interval": certificate["publication"]["publication_interval"]
                    }),
                ));
                Some(certificate)
            }
            Certificate::Failed {
                codes,
                witnesses,
                recipe,
                ..
            } => {
                for code in codes {
                    *failure_codes.entry(code.clone()).or_default() += 1;
                }
                if codes.iter().any(|code| code == "no-single-P") {
                    no_single_p.push(json!({
                        "global": analysis.globals()[global].key,
                        "witnesses": witnesses
                    }));
                }
                let name = analysis.globals()[global].key.clone();
                quiescence_profile.push((
                    format!("1|{}|{name}", codes.first().map_or("", String::as_str)),
                    json!({"global": name, "status": "failed", "codes": codes}),
                ));
                recipe.as_ref()
            }
        };
        if let Some(payload) = payload {
            let both_size = payload["readers"]["both_phase"]
                .as_array()
                .map_or(0, Vec::len);
            *both_phase_histogram.entry(both_size).or_default() += 1;
            both_phase_functions_total += both_size as u64;
            both_phase_globals_nonempty += u64::from(both_size != 0);
        } else {
            both_phase_not_computed += 1;
        }
        if let Some(&depth) = descent_depths.get(&global) {
            *depth_histogram.entry(depth).or_default() += 1;
        } else {
            not_computed += 1;
        }
    }
    no_single_p.sort_by_key(Value::to_string);
    quiescence_profile.sort_by(|left, right| left.0.cmp(&right.0));
    let quiescence_profile = quiescence_profile
        .into_iter()
        .map(|(_, entry)| entry)
        .collect::<Vec<_>>();

    json!({
        "coverage": {
            "certified_globals": certified,
            "client_relevant_mutable_globals": relevant.len()
        },
        "quiescence_profile": quiescence_profile,
        "failure_code_counts": failure_codes,
        "no_single_p": {
            "count": no_single_p.len(),
            "witnesses": no_single_p
        },
        "both_phase_bucket_sizes": {
            "histogram": both_phase_histogram,
            "globals_nonempty": both_phase_globals_nonempty,
            "functions_total": both_phase_functions_total,
            "not_computed": both_phase_not_computed
        },
        "spine_descent_depth": {
            "max_depth": 4,
            "histogram": depth_histogram,
            "exhausted": relevant.iter().filter(|global| descent_exhausted.contains(global)).count(),
            "not_computed": not_computed
        }
    })
}

#[derive(Default)]
struct PhaseReachability {
    pre: BTreeSet<FuncId>,
    post: BTreeSet<FuncId>,
    incomparable: BTreeSet<FuncId>,
    /// Only direct targets of a pre-publication spine call carry that outer callsite. Functions
    /// reached below them remain in the init subtree with an empty `spine_call_sites` list.
    pre_entry_sites: BTreeMap<FuncId, BTreeSet<CallsiteId>>,
    internal_edges: BTreeMap<FuncId, BTreeSet<FuncId>>,
}

fn phase_reachability(
    analysis: &Analysis,
    module: &Pir,
    spine: &SplicedSpine,
    selection: &PublicationSelection,
    dom: &[Vec<bool>],
) -> PhaseReachability {
    let spine_functions = spine
        .origins
        .iter()
        .map(|origin| origin.function)
        .collect::<BTreeSet<_>>();
    let callsites = callsites_by_statement(module);
    let mut result = PhaseReachability::default();
    for edge in analysis.call_edges() {
        let (Caller::Func(caller), Callee::Func(callee)) = (&edge.caller, &edge.callee) else {
            continue;
        };
        if !analysis.functions()[*callee].external {
            result
                .internal_edges
                .entry(*caller)
                .or_default()
                .insert(*callee);
        }
    }

    for (composite, origin) in spine.origins.iter().enumerate() {
        let Some(local_cfg) = module
            .functions
            .get(origin.function.0 as usize)
            .and_then(|function| module.lowering.statement_cfgs.get(&function.key))
        else {
            continue;
        };
        let Some(boundary) = local_cfg.boundaries.get(origin.boundary as usize) else {
            continue;
        };
        let before =
            composite as u32 != selection.chosen && dom[selection.chosen as usize][composite];
        let after = dom[composite][selection.chosen as usize];
        for callsite in boundary
            .stmt_indices
            .iter()
            .filter_map(|statement| callsites.get(&(origin.function, *statement)).copied())
        {
            let roots = analysis
                .callees(callsite)
                .filter_map(|callee| match callee {
                    Callee::Func(function)
                        if !analysis.functions()[*function].external
                            && !spine_functions.contains(function) =>
                    {
                        Some(*function)
                    }
                    _ => None,
                })
                .collect::<BTreeSet<_>>();
            if before {
                for &root in &roots {
                    result
                        .pre_entry_sites
                        .entry(root)
                        .or_default()
                        .insert(callsite);
                }
                extend_reachable(
                    &mut result.pre,
                    &roots,
                    &result.internal_edges,
                    &spine_functions,
                );
            } else if after {
                extend_reachable(
                    &mut result.post,
                    &roots,
                    &result.internal_edges,
                    &spine_functions,
                );
            } else {
                extend_reachable(
                    &mut result.incomparable,
                    &roots,
                    &result.internal_edges,
                    &spine_functions,
                );
            }
        }
    }
    result
}

fn extend_reachable(
    reached: &mut BTreeSet<FuncId>,
    roots: &BTreeSet<FuncId>,
    edges: &BTreeMap<FuncId, BTreeSet<FuncId>>,
    excluded: &BTreeSet<FuncId>,
) {
    let mut pending = roots.iter().copied().collect::<Vec<_>>();
    while let Some(function) = pending.pop() {
        if excluded.contains(&function) || !reached.insert(function) {
            continue;
        }
        pending.extend(edges.get(&function).into_iter().flatten().copied());
    }
}

fn init_subtree_functions(
    reachability: &PhaseReachability,
    relevant: &BTreeSet<FuncId>,
    excluded: &BTreeSet<FuncId>,
) -> BTreeSet<FuncId> {
    let mut reverse = BTreeMap::<FuncId, BTreeSet<FuncId>>::new();
    for (&caller, callees) in &reachability.internal_edges {
        if !reachability.pre.contains(&caller) || excluded.contains(&caller) {
            continue;
        }
        for &callee in callees {
            if reachability.pre.contains(&callee) && !excluded.contains(&callee) {
                reverse.entry(callee).or_default().insert(caller);
            }
        }
    }
    let mut result = BTreeSet::new();
    let mut pending = relevant
        .iter()
        .filter(|function| reachability.pre.contains(function) && !excluded.contains(function))
        .copied()
        .collect::<Vec<_>>();
    while let Some(function) = pending.pop() {
        if result.insert(function) {
            pending.extend(reverse.get(&function).into_iter().flatten().copied());
        }
    }
    result
}

#[allow(clippy::result_large_err)]
fn build_payload(
    analysis: &Analysis,
    module: &Pir,
    global: GlobalId,
    evaluation: &DescentEvaluation,
    selection: &PublicationSelection,
    spawn_read_callsites: &BTreeMap<GlobalId, BTreeSet<CallsiteId>>,
    escape_read_callsites: &BTreeMap<GlobalId, BTreeSet<CallsiteId>>,
) -> Result<Value, (&'static str, Witness)> {
    let publication = boundary_site(analysis, &evaluation.spine, selection.chosen)?;
    let earliest = boundary_site(analysis, &evaluation.spine, selection.earliest)?;
    let latest = boundary_site(analysis, &evaluation.spine, selection.latest)?;
    let dom = dominators(&evaluation.spine.cfg);
    let reachability = phase_reachability(analysis, module, &evaluation.spine, selection, &dom);
    let spine_functions = evaluation
        .spine
        .origins
        .iter()
        .map(|origin| origin.function)
        .collect::<BTreeSet<_>>();
    let mut writers = Vec::new();
    let mut pre_readers = Vec::new();
    let mut pre_functions = BTreeSet::<FuncId>::new();
    let mut post_functions = BTreeSet::<FuncId>::new();
    for access in analysis
        .access_sites()
        .iter()
        .filter(|site| site.global == global)
    {
        let (before, after, incomparable) = if spine_functions.contains(&access.func) {
            let boundary = access_boundary(module, &evaluation.spine, access).ok_or_else(|| {
                (
                    "no-entry-spine",
                    access_witness(
                        analysis,
                        access,
                        "spine access site cannot be mapped to a statement boundary",
                    ),
                )
            })?;
            let before =
                boundary != selection.chosen && dom[selection.chosen as usize][boundary as usize];
            let after = dom[boundary as usize][selection.chosen as usize];
            (before, after, !before && !after)
        } else {
            let escaped = analysis.functions()[access.func].address_escaped;
            (
                reachability.pre.contains(&access.func),
                reachability.post.contains(&access.func) || escaped,
                reachability.incomparable.contains(&access.func),
            )
        };
        // Accesses in functions unreachable from the executable entry do not constrain its
        // publication recipe. Address-escaped functions are covered independently by O4.
        if !before && !after && !incomparable {
            continue;
        }
        let site = access_site(analysis, access).ok_or_else(|| {
            (
                "no-entry-spine",
                access_witness(analysis, access, "access site lacks source coordinates"),
            )
        })?;
        let function = analysis.functions()[access.func].key.clone();
        match access.access {
            Access::Mod => {
                if !before || after || incomparable {
                    return Err((
                        "never-quiescent",
                        access_witness(analysis, access, "writer is not provably pre-publication"),
                    ));
                }
                pre_functions.insert(access.func);
                writers.push(json!({"function": function, "site": site, "kind": if access.via == Via::Direct {"direct"} else {"via-pointer"}}));
            }
            Access::Ref if incomparable => {
                return Err((
                    "no-single-P",
                    access_witness(
                        analysis,
                        access,
                        "reader is dominance-incomparable with publication",
                    ),
                ))
            }
            Access::Ref => {
                if before {
                    pre_functions.insert(access.func);
                    pre_readers.push(json!({"function": function, "site": site}));
                }
                if after {
                    post_functions.insert(access.func);
                }
            }
        }
    }
    writers.sort_by_key(|value| value.to_string());
    pre_readers.sort_by_key(|value| value.to_string());
    let both_phase = pre_functions
        .intersection(&post_functions)
        .map(|function| analysis.functions()[*function].key.clone())
        .collect::<Vec<_>>();
    let post_sample = post_functions
        .iter()
        .take(16)
        .map(|function| analysis.functions()[*function].key.clone())
        .collect::<Vec<_>>();
    let init_functions = init_subtree_functions(&reachability, &pre_functions, &spine_functions);
    let init_subtree = init_functions
        .into_iter()
        .map(|function| {
            let sites = reachability
                .pre_entry_sites
                .get(&function)
                .into_iter()
                .flatten()
                .filter_map(|callsite| analysis.callsites()[*callsite].loc.as_ref())
                .map(|loc| json!({"file":loc.file,"line":loc.line,"col":loc.col}))
                .collect::<Vec<_>>();
            json!({"function": analysis.functions()[function].key, "spine_call_sites": sites})
        })
        .collect::<Vec<_>>();
    let path = evaluation
        .path
        .iter()
        .map(|callsite| callsite_json(analysis, *callsite))
        .collect::<Vec<_>>();
    let spawn_sites = spawn_read_callsites
        .get(&global)
        .into_iter()
        .flatten()
        .map(|callsite| callsite_json(analysis, *callsite))
        .collect::<Vec<_>>();
    let mut escape_sites = escape_read_callsites
        .get(&global)
        .into_iter()
        .flatten()
        .map(|callsite| callsite_json(analysis, *callsite))
        .collect::<Vec<_>>();
    for (index, function) in analysis.functions().iter().enumerate() {
        if !function.address_escaped
            || !transitive_accessed_globals(analysis, FuncId(index as u32), Access::Ref)
                .contains(&global)
        {
            continue;
        }
        for source in &function.escape_sources {
            let Some(key) = source
                .strip_prefix("external-call:")
                .or_else(|| source.strip_prefix("vararg-call:"))
            else {
                continue;
            };
            if let Some((index, _)) = analysis
                .callsites()
                .iter()
                .enumerate()
                .find(|(_, site)| site.key == key)
            {
                escape_sites.push(callsite_json(analysis, CallsiteId(index as u32)));
            }
        }
    }
    escape_sites.sort_by_key(Value::to_string);
    escape_sites.dedup();
    Ok(json!({
        "publication": {
            "publication_function": publication.function,
            "publication_point": publication,
            "publication_interval": {"earliest": earliest, "latest": latest},
            "spine_descent_path": path,
            "kill_rules_checked": KILL_CODE_ORDER,
            "assumptions": []
        },
        "writers": writers,
        "init_subtree": init_subtree,
        "readers": {
            "pre_p": pre_readers,
            "post_p_functions_count": post_functions.len(),
            "post_p_sample": post_sample,
            "both_phase": both_phase
        },
        "observations": {"escape_sites": escape_sites, "spawn_sites": spawn_sites}
    }))
}

#[allow(clippy::result_large_err)]
fn boundary_site(
    analysis: &Analysis,
    spine: &SplicedSpine,
    boundary: u32,
) -> Result<Site, (&'static str, Witness)> {
    let origin = spine.origins.get(boundary as usize).ok_or_else(|| {
        (
            "no-entry-spine",
            run_witness("no-entry-spine", "publication boundary origin unavailable"),
        )
    })?;
    let loc = spine
        .cfg
        .boundaries
        .get(boundary as usize)
        .and_then(|boundary| boundary.loc.as_ref())
        .ok_or_else(|| {
            (
                "no-entry-spine",
                run_witness(
                    "no-entry-spine",
                    "publication boundary lacks source coordinates",
                ),
            )
        })?;
    Ok(Site {
        file: loc.file.clone(),
        line: loc.line,
        col: Some(loc.col),
        function: Some(analysis.functions()[origin.function].key.clone()),
        extra: Extra::new(),
    })
}

fn access_boundary(
    module: &Pir,
    spine: &SplicedSpine,
    access: &pangs_api::AccessSite,
) -> Option<u32> {
    spine
        .origins
        .iter()
        .enumerate()
        .find_map(|(index, origin)| {
            if origin.function != access.func {
                return None;
            }
            let cfg = module
                .lowering
                .statement_cfgs
                .get(&module.functions[access.func.0 as usize].key)?;
            let local = cfg.boundaries.get(origin.boundary as usize)?;
            let statement_match = access
                .statement_index
                .is_some_and(|statement| local.stmt_indices.contains(&statement));
            let loc_match =
                access
                    .loc
                    .as_ref()
                    .zip(local.loc.as_ref())
                    .is_some_and(|(left, right)| {
                        left.file == right.file && left.line == right.line && left.col == right.col
                    });
            (statement_match || loc_match).then_some(index as u32)
        })
}

fn access_site(analysis: &Analysis, access: &pangs_api::AccessSite) -> Option<Site> {
    let loc = access.loc.as_ref()?;
    Some(Site {
        file: loc.file.clone(),
        line: loc.line,
        col: Some(loc.col),
        function: Some(analysis.functions()[access.func].key.clone()),
        extra: Extra::new(),
    })
}

fn access_witness(analysis: &Analysis, access: &pangs_api::AccessSite, note: &str) -> Witness {
    Witness {
        kind: "phase-access-site".into(),
        site: access_site(analysis, access),
        symbol: Some(analysis.globals()[access.global].key.clone()),
        note: Some(note.into()),
        extra: Extra::new(),
    }
}

fn callsite_json(analysis: &Analysis, callsite: CallsiteId) -> Value {
    let info = &analysis.callsites()[callsite];
    json!({"function": analysis.functions()[info.caller].key, "site": info.loc.as_ref().map(|loc| json!({"file":loc.file,"line":loc.line,"col":loc.col}))})
}

fn selection_code(failure: SelectionFailure) -> &'static str {
    match failure {
        SelectionFailure::NoEntrySpine => "no-entry-spine",
        SelectionFailure::NeverQuiescent => "never-quiescent",
        SelectionFailure::ObservationBeforeQuiescence => "observation-before-quiescence",
        SelectionFailure::NoSingleP => "no-single-P",
    }
}
fn selection_witness(failure: SelectionFailure) -> Witness {
    run_witness(
        selection_code(failure),
        "phase publication selection failed",
    )
}
fn failed_slot(code: &str, witness: Witness) -> Certificate {
    Certificate::Failed {
        codes: vec![code.into()],
        witnesses: vec![witness],
        recipe: None,
        diagnostics: None,
        extra: Extra::new(),
    }
}
fn run_witness(kind: &str, note: &str) -> Witness {
    Witness {
        kind: kind.into(),
        site: None,
        symbol: None,
        note: Some(note.into()),
        extra: Extra::new(),
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
    use pangs_manifest::Certificate;
    use pangs_pir::{StatementBoundary, StatementCfg};
    use serde_json::json;

    use super::{
        assemble_spine_inputs, certificate_slots, descent_candidate, evaluate_kill_rules,
        evaluate_with_descent, select_publication, splice_unique_call, FuncId, GlobalId,
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
    fn kill_rules_report_atexit_thread_taint_and_recursive_main_in_fixed_order() {
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
                        {"kind":"call_direct", "callee":"atexit", "sig":signature(),
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
                {"key":"atexit", "sig":signature(), "external":true},
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
        let writer = analysis.lookup_func("writer").unwrap();
        assert!(analysis.functions()[writer].address_escaped);
        assert!(analysis.functions()[writer]
            .escape_sources
            .iter()
            .any(|source| source.starts_with("external-call:main@")));
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

    #[test]
    fn pointer_site_ledger_maps_alias_and_top_writes_to_exact_boundaries() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/synthetic/m1_6/aliased_unknown_modref.pir.json");
        let pir = pangs_pir::Pir::from_path(fixture).unwrap();
        let analysis = Analysis::run_with_disposition(
            &pir,
            &Opts {
                stage: Stage::Steens,
                build_mode: BuildMode::Executable,
                ..Opts::default()
            },
        )
        .unwrap();
        let boundaries = (0..7)
            .map(|id| {
                let mut result = boundary(id, &[], &[]);
                result.loc = Some(pangs_pir::Loc {
                    file: "m1_6.c".into(),
                    line: id + 1,
                    col: 1,
                    dir: None,
                    filename: None,
                });
                result.stmt_indices = vec![id];
                result.successors = if id == 6 { vec![] } else { vec![id + 1] };
                result.predecessors = if id == 0 { vec![] } else { vec![id - 1] };
                result
            })
            .collect();
        let cfg = StatementCfg {
            entry: 0,
            boundaries,
            source_mapping_available: true,
        };
        let inputs = assemble_spine_inputs(&analysis, &pir, FuncId(0), &cfg, &BTreeMap::new());
        let direct = analysis.lookup_global("@Direct").unwrap();
        let aliased = analysis.lookup_global("@Aliased").unwrap();
        assert_eq!(inputs.generated_writes[3], vec![aliased]);
        assert_eq!(inputs.generated_writes[6], vec![direct, aliased]);
        assert!(inputs.generated_writes[..3].iter().all(Vec::is_empty));
        assert!(inputs.generated_writes[4..6].iter().all(Vec::is_empty));
    }

    #[test]
    fn unique_call_descent_splices_child_quiescence_and_origin() {
        let signature = || json!({"ret":{"class":"void"},"params":[],"cc":"ccc"});
        let pir: pangs_pir::Pir = serde_json::from_value(json!({
            "module":"phase-descent",
            "functions":[
                {"key":"main", "sig":signature(), "body":[
                    {"kind":"call_direct", "callee":"run", "sig":signature(), "args":[]}
                ]},
                {"key":"run", "sig":signature(), "body":[
                    {"kind":"global_ref", "global":"@g", "access":"mod"},
                    {"kind":"global_ref", "global":"@g", "access":"ref"}
                ]}
            ],
            "globals":[{"key":"@g"}]
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
        let parent_cfg = StatementCfg {
            entry: 0,
            boundaries: vec![StatementBoundary {
                stmt_indices: vec![0],
                ..boundary(0, &[], &[])
            }],
            source_mapping_available: true,
        };
        let child_cfg = StatementCfg {
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
        let parent_inputs =
            assemble_spine_inputs(&analysis, &pir, FuncId(0), &parent_cfg, &BTreeMap::new());
        let child_inputs =
            assemble_spine_inputs(&analysis, &pir, FuncId(1), &child_cfg, &BTreeMap::new());
        let candidate = descent_candidate(&analysis, &pir, FuncId(0), &parent_cfg, global).unwrap();
        assert_eq!(candidate.boundary, 0);
        assert_eq!(candidate.callee, FuncId(1));

        let spine = splice_unique_call(
            FuncId(0),
            &parent_cfg,
            &parent_inputs,
            candidate.boundary,
            candidate.callee,
            &child_cfg,
            &child_inputs,
            global,
        )
        .unwrap();
        assert_eq!(spine.cfg.boundaries[0].successors, vec![1]);
        assert_eq!(spine.cfg.boundaries[1].successors, vec![2]);
        assert_eq!(spine.origins[2].function, FuncId(1));
        assert_eq!(spine.origins[2].boundary, 1);
        let quiescence = Quiescence::compute(
            &spine.cfg,
            analysis.globals().len(),
            &spine.generated_writes,
        )
        .unwrap();
        let selection =
            select_publication(&spine.cfg, &quiescence, global, &spine.observations).unwrap();
        assert_eq!(selection.chosen, 2);
    }

    #[test]
    fn descent_rejects_a_child_with_a_second_live_callsite() {
        let signature = || json!({"ret":{"class":"void"},"params":[],"cc":"ccc"});
        let pir: pangs_pir::Pir = serde_json::from_value(json!({
            "module":"phase-descent-shared",
            "functions":[
                {"key":"main", "sig":signature(), "body":[
                    {"kind":"call_direct", "callee":"run", "sig":signature(), "args":[]}
                ]},
                {"key":"other", "sig":signature(), "body":[
                    {"kind":"call_direct", "callee":"run", "sig":signature(), "args":[]}
                ]},
                {"key":"run", "sig":signature(), "body":[
                    {"kind":"global_ref", "global":"@g", "access":"mod"}
                ]}
            ],
            "globals":[{"key":"@g"}]
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
        let global = analysis.lookup_global("@g").unwrap();
        assert_eq!(
            descent_candidate(&analysis, &pir, FuncId(0), &cfg, global),
            None
        );
    }

    #[test]
    fn bounded_descent_repeats_and_reports_true_exhaustion() {
        let signature = || json!({"ret":{"class":"void"},"params":[],"cc":"ccc"});
        let mut pir: pangs_pir::Pir = serde_json::from_value(json!({
            "module":"phase-deep-descent",
            "functions":[
                {"key":"main", "sig":signature(), "body":[
                    {"kind":"call_direct", "callee":"wrapper", "sig":signature(), "args":[]}
                ]},
                {"key":"wrapper", "sig":signature(), "body":[
                    {"kind":"call_direct", "callee":"run", "sig":signature(), "args":[]}
                ]},
                {"key":"run", "sig":signature(), "body":[
                    {"kind":"global_ref", "global":"@g", "access":"mod"},
                    {"kind":"global_ref", "global":"@g", "access":"ref"}
                ]}
            ],
            "globals":[{"key":"@g"}]
        }))
        .unwrap();
        let shell_cfg = || StatementCfg {
            entry: 0,
            boundaries: vec![StatementBoundary {
                stmt_indices: vec![0],
                ..boundary(0, &[], &[])
            }],
            source_mapping_available: true,
        };
        pir.lowering
            .statement_cfgs
            .insert("main".into(), shell_cfg());
        pir.lowering
            .statement_cfgs
            .insert("wrapper".into(), shell_cfg());
        pir.lowering.statement_cfgs.insert(
            "run".into(),
            StatementCfg {
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
            },
        );
        let analysis = Analysis::run_with_disposition(
            &pir,
            &Opts {
                stage: Stage::Steens,
                build_mode: BuildMode::Executable,
                ..Opts::default()
            },
        )
        .unwrap();
        let global = analysis.lookup_global("@g").unwrap();

        let exhausted =
            evaluate_with_descent(&analysis, &pir, FuncId(0), global, &BTreeMap::new(), 1).unwrap();
        assert!(exhausted.exhausted);
        assert_eq!(exhausted.path, vec![CallsiteId(0)]);
        assert!(exhausted.selection.is_err());

        let completed =
            evaluate_with_descent(&analysis, &pir, FuncId(0), global, &BTreeMap::new(), 2).unwrap();
        assert!(!completed.exhausted);
        assert_eq!(completed.path, vec![CallsiteId(0), CallsiteId(1)]);
        let selection = completed.selection.unwrap();
        assert_eq!(
            completed.spine.origins[selection.chosen as usize].function,
            FuncId(2)
        );
        assert_eq!(
            completed.spine.origins[selection.chosen as usize].boundary,
            1
        );
    }

    #[test]
    fn o6_emits_complete_certified_slot_for_source_mapped_spine_accesses() {
        let signature = || json!({"ret":{"class":"void"},"params":[],"cc":"ccc"});
        let loc = |line| json!({"file":"phase.c","line":line,"col":1});
        let mut pir: pangs_pir::Pir = serde_json::from_value(json!({
            "module":"phase-o6",
            "functions":[{"key":"main", "sig":signature(), "body":[
                {"kind":"global_ref", "global":"@g", "access":"mod", "loc":loc(1)},
                {"kind":"global_ref", "global":"@g", "access":"ref", "loc":loc(2)}
            ]}],
            "globals":[{"key":"@g"}]
        }))
        .unwrap();
        let cfg_loc = |line| pangs_pir::Loc {
            file: "phase.c".into(),
            line,
            col: 1,
            dir: None,
            filename: None,
        };
        pir.lowering.statement_cfgs.insert(
            "main".into(),
            StatementCfg {
                entry: 0,
                boundaries: vec![
                    StatementBoundary {
                        loc: Some(cfg_loc(1)),
                        stmt_indices: vec![0],
                        ..boundary(0, &[1], &[])
                    },
                    StatementBoundary {
                        loc: Some(cfg_loc(2)),
                        stmt_indices: vec![1],
                        ..boundary(1, &[], &[0])
                    },
                ],
                source_mapping_available: true,
            },
        );
        let opts = Opts {
            stage: Stage::Steens,
            build_mode: BuildMode::Executable,
            ..Opts::default()
        };
        let analysis = Analysis::run_with_disposition(&pir, &opts).unwrap();
        let global = analysis.lookup_global("@g").unwrap();
        let (entry, slots, report) = certificate_slots(
            &analysis,
            &pir,
            &opts,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
        );
        assert_eq!(entry.unwrap()["root"], "main");
        let Certificate::Certified { certificate, .. } = &slots[&global] else {
            panic!("expected certified phase slot: {:#?}", slots[&global]);
        };
        assert_eq!(certificate["publication"]["publication_function"], "main");
        assert_eq!(certificate["publication"]["publication_point"]["line"], 2);
        assert_eq!(certificate["writers"].as_array().unwrap().len(), 1);
        assert_eq!(certificate["readers"]["post_p_functions_count"], 1);
        assert_eq!(report["coverage"]["certified_globals"], 1);
        assert_eq!(report["coverage"]["client_relevant_mutable_globals"], 1);
        assert_eq!(report["spine_descent_depth"]["histogram"]["0"], 1);
    }

    #[test]
    fn o6_attributes_ordinary_pre_publication_helper_subtrees() {
        let signature = || json!({"ret":{"class":"void"},"params":[],"cc":"ccc"});
        let loc = |line| json!({"file":"helpers.c","line":line,"col":1});
        let mut pir: pangs_pir::Pir = serde_json::from_value(json!({
            "module":"phase-helper-subtree",
            "functions":[
                {"key":"main", "sig":signature(), "body":[
                    {"kind":"call_direct", "callee":"initialize", "sig":signature(),
                     "args":[], "loc":loc(1)},
                    {"kind":"global_ref", "global":"@g", "access":"ref", "loc":loc(4)}
                ]},
                {"key":"initialize", "sig":signature(), "body":[
                    {"kind":"call_direct", "callee":"register", "sig":signature(),
                     "args":[], "loc":loc(2)}
                ]},
                {"key":"register", "sig":signature(), "body":[
                    {"kind":"global_ref", "global":"@g", "access":"mod", "loc":loc(3)},
                    {"kind":"global_ref", "global":"@g", "access":"ref", "loc":loc(3)}
                ]}
            ],
            "globals":[{"key":"@g"}]
        }))
        .unwrap();
        let cfg_loc = |line| pangs_pir::Loc {
            file: "helpers.c".into(),
            line,
            col: 1,
            dir: None,
            filename: None,
        };
        pir.lowering.statement_cfgs.insert(
            "main".into(),
            StatementCfg {
                entry: 0,
                boundaries: vec![
                    StatementBoundary {
                        loc: Some(cfg_loc(1)),
                        stmt_indices: vec![0],
                        ..boundary(0, &[1], &[])
                    },
                    StatementBoundary {
                        loc: Some(cfg_loc(4)),
                        stmt_indices: vec![1],
                        ..boundary(1, &[], &[0])
                    },
                ],
                source_mapping_available: true,
            },
        );
        let opts = Opts {
            stage: Stage::Steens,
            build_mode: BuildMode::Executable,
            ..Opts::default()
        };
        let analysis = Analysis::run_with_disposition(&pir, &opts).unwrap();
        let global = analysis.lookup_global("@g").unwrap();
        let (_, slots, report) = certificate_slots(
            &analysis,
            &pir,
            &opts,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
        );
        let Certificate::Certified { certificate, .. } = &slots[&global] else {
            panic!(
                "expected certified helper-subtree slot: {:#?}",
                slots[&global]
            );
        };
        assert_eq!(certificate["writers"][0]["function"], "register");
        assert_eq!(certificate["readers"]["pre_p"][0]["function"], "register");
        assert_eq!(certificate["readers"]["post_p_functions_count"], 1);
        assert_eq!(certificate["readers"]["post_p_sample"][0], "main");
        assert_eq!(
            certificate["init_subtree"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry["function"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["initialize", "register"]
        );
        assert_eq!(
            certificate["init_subtree"][0]["spine_call_sites"][0]["line"],
            1
        );
        assert_eq!(
            certificate["init_subtree"][1]["spine_call_sites"],
            json!([])
        );
        assert_eq!(report["both_phase_bucket_sizes"]["histogram"]["0"], 1);
    }

    #[test]
    fn o6_reports_helpers_reached_from_both_phases_exhaustively() {
        let signature = || json!({"ret":{"class":"void"},"params":[],"cc":"ccc"});
        let loc = |line| json!({"file":"both.c","line":line,"col":1});
        let mut pir: pangs_pir::Pir = serde_json::from_value(json!({
            "module":"phase-both-helper",
            "functions":[
                {"key":"main", "sig":signature(), "body":[
                    {"kind":"call_direct", "callee":"initialize", "sig":signature(),
                     "args":[], "loc":loc(1)},
                    {"kind":"call_direct", "callee":"run", "sig":signature(),
                     "args":[], "loc":loc(5)}
                ]},
                {"key":"initialize", "sig":signature(), "body":[
                    {"kind":"global_ref", "global":"@g", "access":"mod", "loc":loc(2)},
                    {"kind":"call_direct", "callee":"shared", "sig":signature(),
                     "args":[], "loc":loc(3)}
                ]},
                {"key":"run", "sig":signature(), "body":[
                    {"kind":"call_direct", "callee":"shared", "sig":signature(),
                     "args":[], "loc":loc(6)}
                ]},
                {"key":"shared", "sig":signature(), "body":[
                    {"kind":"global_ref", "global":"@g", "access":"ref", "loc":loc(4)}
                ]}
            ],
            "globals":[{"key":"@g"}]
        }))
        .unwrap();
        let cfg_loc = |line| pangs_pir::Loc {
            file: "both.c".into(),
            line,
            col: 1,
            dir: None,
            filename: None,
        };
        pir.lowering.statement_cfgs.insert(
            "main".into(),
            StatementCfg {
                entry: 0,
                boundaries: vec![
                    StatementBoundary {
                        loc: Some(cfg_loc(1)),
                        stmt_indices: vec![0],
                        ..boundary(0, &[1], &[])
                    },
                    StatementBoundary {
                        loc: Some(cfg_loc(5)),
                        stmt_indices: vec![1],
                        ..boundary(1, &[], &[0])
                    },
                ],
                source_mapping_available: true,
            },
        );
        let opts = Opts {
            stage: Stage::Steens,
            build_mode: BuildMode::Executable,
            ..Opts::default()
        };
        let analysis = Analysis::run_with_disposition(&pir, &opts).unwrap();
        let global = analysis.lookup_global("@g").unwrap();
        let (_, slots, _) = certificate_slots(
            &analysis,
            &pir,
            &opts,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
        );
        let Certificate::Certified { certificate, .. } = &slots[&global] else {
            panic!("expected certified both-phase slot: {:#?}", slots[&global]);
        };
        assert_eq!(certificate["readers"]["both_phase"], json!(["shared"]));
        assert_eq!(certificate["readers"]["pre_p"][0]["function"], "shared");
        assert_eq!(certificate["readers"]["post_p_sample"], json!(["shared"]));
        assert_eq!(
            certificate["init_subtree"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry["function"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["initialize", "shared"]
        );
    }

    #[test]
    fn signal_reader_registration_constrains_publication_and_is_post_phase() {
        let signature = || json!({"ret":{"class":"void"},"params":[],"cc":"ccc"});
        let loc = |line| json!({"file":"signal.c","line":line,"col":1});
        let mut pir: pangs_pir::Pir = serde_json::from_value(json!({
            "module":"phase-signal-reader",
            "functions":[
                {"key":"main", "sig":signature(), "body":[
                    {"kind":"global_ref", "global":"@g", "access":"mod", "loc":loc(1)},
                    {"kind":"call_direct", "callee":"signal", "sig":signature(),
                     "args":["2", "handler"], "loc":loc(2)}
                ]},
                {"key":"handler", "sig":signature(), "address_taken":true, "body":[
                    {"kind":"global_ref", "global":"@g", "access":"ref", "loc":loc(3)}
                ]},
                {"key":"signal", "sig":signature(), "external":true}
            ],
            "globals":[{"key":"@g"}]
        }))
        .unwrap();
        let cfg_loc = |line| pangs_pir::Loc {
            file: "signal.c".into(),
            line,
            col: 1,
            dir: None,
            filename: None,
        };
        pir.lowering.statement_cfgs.insert(
            "main".into(),
            StatementCfg {
                entry: 0,
                boundaries: vec![
                    StatementBoundary {
                        loc: Some(cfg_loc(1)),
                        stmt_indices: vec![0],
                        ..boundary(0, &[1], &[])
                    },
                    StatementBoundary {
                        loc: Some(cfg_loc(2)),
                        stmt_indices: vec![1],
                        ..boundary(1, &[], &[0])
                    },
                ],
                source_mapping_available: true,
            },
        );
        let opts = Opts {
            stage: Stage::Steens,
            build_mode: BuildMode::Executable,
            ..Opts::default()
        };
        let analysis = Analysis::run_with_disposition(&pir, &opts).unwrap();
        let facts = crate::registry_access_facts(&analysis, &pir);
        let global = analysis.lookup_global("@g").unwrap();
        assert_eq!(
            facts.escape_read_callsites[&global],
            BTreeSet::from([CallsiteId(0)])
        );
        let (_, slots, _) = certificate_slots(
            &analysis,
            &pir,
            &opts,
            &facts.pseudo_read_callsites,
            &facts.spawn_read_callsites,
            &facts.escape_read_callsites,
            &facts.thread_writers,
        );
        let Certificate::Certified { certificate, .. } = &slots[&global] else {
            panic!(
                "expected certified signal-reader slot: {:#?}",
                slots[&global]
            );
        };
        assert_eq!(certificate["publication"]["publication_point"]["line"], 2);
        assert_eq!(certificate["readers"]["post_p_sample"], json!(["handler"]));
        assert_eq!(certificate["readers"]["pre_p"], json!([]));
        assert_eq!(
            certificate["observations"]["escape_sites"][0]["function"],
            "main"
        );
    }
}
