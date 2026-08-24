//! Read-only Phase-0 census for the proposed external-code policy.
//!
//! Nothing in this module changes a solver fact or client decision. The ordinary pipeline does
//! not populate these records; `Analysis::run_with_external_policy_census` explicitly opts into
//! targeted allocation-level points-to for opaque-call operands and arguments.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use pangs_pag::{CallKind as PagCallKind, Pag};
use pangs_pir::{Access, Pir, Stmt, ValueKind};
use pangs_solve::SolveResult;
use serde::Serialize;

use crate::{
    AffectedGlobals, Analysis, BuildMode, Callee, Caller, FuncId, GlobalCandidateSet, GlobalTarget,
    ModRef, Opts,
};

#[derive(Debug, Clone, Serialize)]
pub struct ExternalPolicyCensus {
    pub finite_effect_rows: Vec<FiniteEffectRow>,
    pub module_wide_rows: Vec<ModuleWideRow>,
    /// Every `ModuleWide` row poisons this same set. Store the identities once rather than
    /// repeating a module-sized string vector on every row.
    pub module_wide_poisoned_globals: Vec<String>,
    pub principals: Vec<PrincipalRow>,
    pub opaque_callsites: Vec<OpaqueCallsiteRow>,
    pub summary: ExternalPolicyCensusSummary,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ExternalPolicyCensusSummary {
    pub finite_external_rows: usize,
    pub finite_external_rows_single_source: usize,
    pub finite_external_rows_multiple_sources: usize,
    pub finite_rows_needing_source_candidate_correlation: usize,
    pub finite_rows_with_available_source_candidate_correlation: usize,
    pub module_wide_rows: usize,
    pub module_wide_mod_rows: usize,
    pub module_wide_ref_rows: usize,
    pub module_wide_inttoptr_rows: usize,
    pub module_wide_inline_asm_rows: usize,
    pub module_wide_mixed_rows: usize,
    pub module_wide_unattributed_rows: usize,
    pub distinct_module_wide_poisoned_globals: usize,
    pub opaque_inline_asm_exposures: usize,
    pub opaque_callsites: usize,
    pub complete_principal_identities: usize,
    pub complete_callback_inventories: usize,
    pub complete_control_closures: usize,
    pub callback_functions_held: usize,
    pub callback_transmod_globals: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct FiniteEffectRow {
    pub row_index: usize,
    pub function: String,
    pub access: Access,
    pub witness: Option<String>,
    pub address_node: Option<String>,
    pub strict_candidates: Vec<String>,
    pub external_sources: Vec<String>,
    pub principal_count: usize,
    pub source_candidate_correlation_available: bool,
    pub ideal_conventional_candidates: Option<Vec<String>>,
    pub blocker: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleWideRow {
    pub row_index: usize,
    pub function: String,
    pub access: Access,
    pub witness: Option<String>,
    pub address_node: Option<String>,
    pub seed_kinds: Vec<String>,
    pub external_sources: Vec<String>,
    pub poisoned_globals: usize,
    pub exclusively_poisoned_globals: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PrincipalRow {
    pub principal: String,
    pub identity_complete: bool,
    pub callback_inventory_complete: bool,
    pub control_closure_complete: bool,
    pub callsites: Vec<u32>,
    pub retained_callbacks: Vec<String>,
    pub reachable_internal_functions: Vec<String>,
    pub callback_transmod_globals: Vec<String>,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpaqueCallsiteRow {
    pub callsite: u32,
    pub key: String,
    pub caller: String,
    pub principal: String,
    pub principal_identity_complete: bool,
    pub callback_inventory_complete: bool,
    pub control_closure_complete: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct SolverInputs {
    callsites: Vec<SolverCallsiteInput>,
    opaque_inline_asm_exposures: usize,
    universal_sources_by_node: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone)]
struct SolverCallsiteInput {
    key: String,
    principal: String,
    identity_complete: bool,
    retained_callbacks: BTreeSet<String>,
    callback_inventory_complete: bool,
    blockers: BTreeSet<String>,
}

#[derive(Debug, Clone, Default)]
struct PrincipalInput {
    identity_complete: bool,
    callback_inventory_complete: bool,
    callsites: BTreeSet<usize>,
    retained_callbacks: BTreeSet<String>,
    blockers: BTreeSet<String>,
}

pub(crate) fn targeted_labels(pag: &Pag, callsite_filter: &BTreeSet<String>) -> BTreeSet<String> {
    pag.callsites
        .iter()
        .filter(|callsite| callsite_filter.contains(&callsite.key))
        .flat_map(|callsite| callsite.operand.iter().chain(callsite.args.iter()))
        .filter_map(|node| pag.nodes.get(node.0 as usize))
        .filter(|node| node.value_kind != ValueKind::NonPointer)
        .map(|node| node.label.clone())
        .collect()
}

pub(crate) fn collect_solver_inputs(
    pir: &Pir,
    pag: &Pag,
    solved: &SolveResult,
    targeted_points_to_labels: &BTreeSet<String>,
) -> SolverInputs {
    let internal_functions = pir
        .functions
        .iter()
        .filter(|function| !function.external)
        .map(|function| function.key.as_str())
        .collect::<BTreeSet<_>>();
    let opaque_inline_asm_exposures = pir
        .functions
        .iter()
        .flat_map(|function| &function.body)
        .chain(&pir.global_init)
        .filter(|statement| {
            matches!(statement, Stmt::Unknown { operands, results, reason, .. }
                if reason.starts_with("inline_asm")
                    && ((operands.is_empty() && results.is_empty())
                        || reason.contains("symbol_reference")))
        })
        .count();

    let callsites = pag
        .callsites
        .iter()
        .filter(|callsite| callsite.external_boundary || callsite.kind == PagCallKind::Indirect)
        .map(|callsite| {
            let (principal, identity_complete, mut blockers) =
                if let Some(callee) = &callsite.callee {
                    (
                        format!("external-symbol:{}", canonical_symbol(callee)),
                        true,
                        BTreeSet::new(),
                    )
                } else if let Some(operand) = callsite.operand {
                    let label = &pag.nodes[operand.0 as usize].label;
                    let sources = solved
                        .nodes
                        .get(label)
                        .map(|node| stable_external_sources(&node.external_sources, &callsite.key))
                        .unwrap_or_default();
                    if sources.len() == 1 && stable_principal_source(&sources[0]) {
                        (
                            format!("external-origin:{}", sources[0]),
                            true,
                            BTreeSet::new(),
                        )
                    } else {
                        let mut blockers =
                            BTreeSet::from(["principal-identity-incomplete".to_string()]);
                        if sources.is_empty() {
                            blockers.insert("callee-origin-unavailable".to_string());
                        } else if sources.len() > 1 {
                            blockers.insert("multiple-callee-origins".to_string());
                        }
                        (format!("unknown-callback:{}", label), false, blockers)
                    }
                } else {
                    (
                        format!("unknown-callsite:{}", callsite.key),
                        false,
                        BTreeSet::from(["callee-operand-unavailable".to_string()]),
                    )
                };

            let mut retained_callbacks = BTreeSet::new();
            let mut callback_inventory_complete = true;
            for argument in &callsite.args {
                let argument_node = &pag.nodes[argument.0 as usize];
                if argument_node.value_kind == ValueKind::NonPointer {
                    continue;
                }
                let label = &argument_node.label;
                let Some(node) = solved.nodes.get(label) else {
                    callback_inventory_complete = false;
                    blockers.insert(format!("argument-resolution-unavailable:{label}"));
                    continue;
                };
                let mut allocations_present = false;
                for allocations in [
                    solved.node_points_to.get(label),
                    solved.node_pointee_points_to.get(label),
                ]
                .into_iter()
                .flatten()
                {
                    allocations_present = true;
                    retained_callbacks.extend(
                        allocations
                            .iter()
                            .filter(|name| internal_functions.contains(name.as_str()))
                            .cloned(),
                    );
                }
                if node.reaches_function_pointer
                    && !allocations_present
                    && !targeted_points_to_labels.contains(label)
                {
                    callback_inventory_complete = false;
                    blockers.insert(format!("callback-targets-unavailable:{label}"));
                }
                if node.external_universal {
                    callback_inventory_complete = false;
                    blockers.insert(format!("callback-argument-forged:{label}"));
                }
                if solved
                    .node_pointee_external
                    .get(label)
                    .is_some_and(|sources| !sources.is_empty())
                    && node.reaches_function_pointer
                {
                    callback_inventory_complete = false;
                    blockers.insert(format!("callback-memory-external:{label}"));
                }
            }
            SolverCallsiteInput {
                key: callsite.key.clone(),
                principal,
                identity_complete,
                retained_callbacks,
                callback_inventory_complete,
                blockers,
            }
        })
        .collect();
    SolverInputs {
        callsites,
        opaque_inline_asm_exposures,
        universal_sources_by_node: solved
            .nodes
            .iter()
            .filter(|(_, node)| !node.universal_sources.is_empty())
            .map(|(label, node)| (label.clone(), node.universal_sources.clone()))
            .collect(),
    }
}

pub(crate) fn build(
    _pir: &Pir,
    opts: &Opts,
    analysis: &Analysis,
    inputs: SolverInputs,
) -> ExternalPolicyCensus {
    let universal_sources_by_node = inputs.universal_sources_by_node.clone();
    let callsite_by_key = analysis
        .callsites()
        .iter()
        .enumerate()
        .map(|(index, callsite)| (callsite.key.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    let opaque_callsites = analysis
        .call_edges()
        .iter()
        .filter_map(|edge| {
            let callsite = edge.callsite?;
            let opaque = match edge.callee {
                Callee::Unknown(_) => true,
                Callee::Func(function) => analysis.functions()[function].external,
            };
            opaque.then_some(callsite.0 as usize)
        })
        .collect::<BTreeSet<_>>();

    let mut principals = BTreeMap::<String, PrincipalInput>::new();
    let mut callsite_principals = BTreeMap::<usize, String>::new();
    for input in inputs.callsites {
        let Some(&callsite) = callsite_by_key.get(input.key.as_str()) else {
            continue;
        };
        if !opaque_callsites.contains(&callsite) {
            continue;
        }
        callsite_principals.insert(callsite, input.principal.clone());
        let principal = principals
            .entry(input.principal)
            .or_insert_with(|| PrincipalInput {
                identity_complete: true,
                callback_inventory_complete: true,
                ..PrincipalInput::default()
            });
        principal.identity_complete &= input.identity_complete;
        principal.callback_inventory_complete &= input.callback_inventory_complete;
        principal.callsites.insert(callsite);
        principal
            .retained_callbacks
            .extend(input.retained_callbacks);
        principal.blockers.extend(input.blockers);
    }

    let mut control_outgoing = vec![Vec::new(); analysis.functions().len()];
    for edge in analysis.call_edges() {
        let Caller::Func(caller) = edge.caller else {
            continue;
        };
        let step = match edge.callee {
            Callee::Func(callee) if !analysis.functions()[callee].external => {
                ControlStep::Function(callee)
            }
            Callee::Func(_) | Callee::Unknown(_) => {
                ControlStep::Opaque(edge.callsite.map(|callsite| callsite.0 as usize))
            }
        };
        control_outgoing[caller.0 as usize].push(step);
    }
    for outgoing in &mut control_outgoing {
        outgoing.sort();
        outgoing.dedup();
    }

    let principal_closures = principals
        .keys()
        .map(|principal| {
            (
                principal.clone(),
                control_closure(
                    analysis,
                    principal,
                    &principals,
                    &callsite_principals,
                    &control_outgoing,
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let principal_rows = principals
        .iter()
        .map(|(key, input)| {
            let closure = &principal_closures[key];
            let callback_transmod_globals = transmod_globals(analysis, &closure.functions);
            PrincipalRow {
                principal: key.clone(),
                identity_complete: input.identity_complete,
                callback_inventory_complete: input.callback_inventory_complete,
                control_closure_complete: closure.complete,
                callsites: input
                    .callsites
                    .iter()
                    .map(|callsite| *callsite as u32)
                    .collect(),
                retained_callbacks: input.retained_callbacks.iter().cloned().collect(),
                reachable_internal_functions: function_names(analysis, &closure.functions),
                callback_transmod_globals,
                blockers: closure.blockers.iter().cloned().collect(),
            }
        })
        .collect::<Vec<_>>();
    let opaque_callsite_rows = callsite_principals
        .iter()
        .map(|(&callsite, principal)| {
            let input = &principals[principal];
            let closure = &principal_closures[principal];
            OpaqueCallsiteRow {
                callsite: callsite as u32,
                key: analysis.callsites()[crate::CallsiteId(callsite as u32)]
                    .key
                    .clone(),
                caller: analysis.functions()
                    [analysis.callsites()[crate::CallsiteId(callsite as u32)].caller]
                    .key
                    .clone(),
                principal: principal.clone(),
                principal_identity_complete: input.identity_complete,
                callback_inventory_complete: input.callback_inventory_complete,
                control_closure_complete: closure.complete,
            }
        })
        .collect::<Vec<_>>();

    let poisoned_globals = analysis
        .globals()
        .iter()
        .map(|global| global.key.clone())
        .collect::<Vec<_>>();
    let module_wide_indices = analysis
        .modrefs()
        .iter()
        .enumerate()
        .filter_map(|(index, row)| {
            matches!(analysis.affected_globals(row), AffectedGlobals::ModuleWide).then_some(index)
        })
        .collect::<Vec<_>>();
    let exclusive_globals = (module_wide_indices.len() == 1)
        .then(|| {
            analysis
                .globals()
                .iter()
                .filter(|global| {
                    !global.address_escaped
                        && !(opts.build_mode == BuildMode::Library && global.exported)
                })
                .map(|global| global.key.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let mut finite_effect_rows = Vec::new();
    let mut module_wide_rows = Vec::new();
    for (row_index, row) in analysis.modrefs().iter().enumerate() {
        let GlobalTarget::Unknown(_) = row.global else {
            continue;
        };
        let external_sources = external_sources(row);
        match &row.global_candidates {
            GlobalCandidateSet::Finite(globals) if !external_sources.is_empty() => {
                let strict_candidates = globals
                    .iter()
                    .map(|global| analysis.globals()[*global].key.clone())
                    .collect::<Vec<_>>();
                let needs_correlation = external_sources.len() > 1 && !strict_candidates.is_empty();
                finite_effect_rows.push(FiniteEffectRow {
                    row_index,
                    function: analysis.functions()[row.func].key.clone(),
                    access: row.access,
                    witness: row.witness.clone(),
                    address_node: row.address_node.clone(),
                    strict_candidates: strict_candidates.clone(),
                    external_sources: external_sources.clone(),
                    principal_count: external_sources.len(),
                    source_candidate_correlation_available: !needs_correlation,
                    ideal_conventional_candidates: (!needs_correlation)
                        .then_some(strict_candidates),
                    blocker: needs_correlation
                        .then(|| "source-candidate-correlation-not-materialized".to_string()),
                });
            }
            GlobalCandidateSet::ModuleWide => {
                let universal_sources = row
                    .address_node
                    .as_ref()
                    .and_then(|node| universal_sources_by_node.get(node))
                    .cloned()
                    .unwrap_or_default();
                let mut seed_kinds = Vec::new();
                if universal_sources
                    .iter()
                    .any(|source| source.contains("inttoptr"))
                {
                    seed_kinds.push("int_to_ptr".to_string());
                }
                // Current ModRef construction does not promote inline-assembly exposure to the
                // ModuleWide lattice element. Keep that measured fact explicit rather than
                // attributing a row merely because the module also contains opaque assembly.
                module_wide_rows.push(ModuleWideRow {
                    row_index,
                    function: analysis.functions()[row.func].key.clone(),
                    access: row.access,
                    witness: row.witness.clone(),
                    address_node: row.address_node.clone(),
                    seed_kinds,
                    external_sources: if universal_sources.is_empty() {
                        external_sources
                    } else {
                        universal_sources
                    },
                    poisoned_globals: poisoned_globals.len(),
                    exclusively_poisoned_globals: if module_wide_indices == [row_index] {
                        exclusive_globals.clone()
                    } else {
                        Vec::new()
                    },
                });
            }
            GlobalCandidateSet::Finite(_) => {}
        }
    }

    let callback_functions = principal_rows
        .iter()
        .flat_map(|row| row.retained_callbacks.iter().cloned())
        .collect::<BTreeSet<_>>();
    let callback_globals = principal_rows
        .iter()
        .flat_map(|row| row.callback_transmod_globals.iter().cloned())
        .collect::<BTreeSet<_>>();
    let summary = ExternalPolicyCensusSummary {
        finite_external_rows: finite_effect_rows.len(),
        finite_external_rows_single_source: finite_effect_rows
            .iter()
            .filter(|row| row.principal_count == 1)
            .count(),
        finite_external_rows_multiple_sources: finite_effect_rows
            .iter()
            .filter(|row| row.principal_count > 1)
            .count(),
        finite_rows_needing_source_candidate_correlation: finite_effect_rows
            .iter()
            .filter(|row| row.blocker.is_some())
            .count(),
        finite_rows_with_available_source_candidate_correlation: finite_effect_rows
            .iter()
            .filter(|row| row.source_candidate_correlation_available)
            .count(),
        module_wide_rows: module_wide_rows.len(),
        module_wide_mod_rows: module_wide_rows
            .iter()
            .filter(|row| row.access == Access::Mod)
            .count(),
        module_wide_ref_rows: module_wide_rows
            .iter()
            .filter(|row| row.access == Access::Ref)
            .count(),
        module_wide_inttoptr_rows: module_wide_rows
            .iter()
            .filter(|row| row.seed_kinds == ["int_to_ptr"])
            .count(),
        module_wide_inline_asm_rows: 0,
        module_wide_mixed_rows: 0,
        module_wide_unattributed_rows: module_wide_rows
            .iter()
            .filter(|row| row.seed_kinds.is_empty())
            .count(),
        distinct_module_wide_poisoned_globals: if module_wide_rows.is_empty() {
            0
        } else {
            poisoned_globals.len()
        },
        opaque_inline_asm_exposures: inputs.opaque_inline_asm_exposures,
        opaque_callsites: opaque_callsite_rows.len(),
        complete_principal_identities: opaque_callsite_rows
            .iter()
            .filter(|row| row.principal_identity_complete)
            .count(),
        complete_callback_inventories: opaque_callsite_rows
            .iter()
            .filter(|row| row.callback_inventory_complete)
            .count(),
        complete_control_closures: opaque_callsite_rows
            .iter()
            .filter(|row| row.control_closure_complete)
            .count(),
        callback_functions_held: callback_functions.len(),
        callback_transmod_globals: callback_globals.len(),
    };

    ExternalPolicyCensus {
        finite_effect_rows,
        module_wide_rows,
        module_wide_poisoned_globals: poisoned_globals,
        principals: principal_rows,
        opaque_callsites: opaque_callsite_rows,
        summary,
    }
}

#[derive(Debug, Default)]
struct ControlClosure {
    functions: BTreeSet<FuncId>,
    complete: bool,
    blockers: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ControlStep {
    Function(FuncId),
    Opaque(Option<usize>),
}

fn control_closure(
    analysis: &Analysis,
    root: &str,
    principals: &BTreeMap<String, PrincipalInput>,
    callsite_principals: &BTreeMap<usize, String>,
    outgoing: &[Vec<ControlStep>],
) -> ControlClosure {
    enum Work {
        Principal(String),
        Function(FuncId),
    }
    let mut closure = ControlClosure {
        complete: true,
        ..ControlClosure::default()
    };
    let mut seen_principals = BTreeSet::new();
    let mut queue = VecDeque::from([Work::Principal(root.to_string())]);
    while let Some(work) = queue.pop_front() {
        match work {
            Work::Principal(principal) => {
                if !seen_principals.insert(principal.clone()) {
                    continue;
                }
                let Some(input) = principals.get(&principal) else {
                    closure.complete = false;
                    closure
                        .blockers
                        .insert(format!("principal-input-unavailable:{principal}"));
                    continue;
                };
                closure.complete &= input.identity_complete && input.callback_inventory_complete;
                closure.blockers.extend(input.blockers.iter().cloned());
                for callback in &input.retained_callbacks {
                    if let Some(function) = analysis.lookup_func(callback) {
                        queue.push_back(Work::Function(function));
                    } else {
                        closure.complete = false;
                        closure
                            .blockers
                            .insert(format!("callback-function-unavailable:{callback}"));
                    }
                }
            }
            Work::Function(function) => {
                if !closure.functions.insert(function) {
                    continue;
                }
                for step in &outgoing[function.0 as usize] {
                    match step {
                        ControlStep::Function(callee) => {
                            queue.push_back(Work::Function(*callee));
                        }
                        ControlStep::Opaque(callsite) => {
                            let Some(principal) =
                                callsite.and_then(|id| callsite_principals.get(&id))
                            else {
                                closure.complete = false;
                                closure.blockers.insert(format!(
                                    "nested-principal-unavailable:{}",
                                    callsite
                                        .map_or_else(|| "none".to_string(), |id| id.to_string())
                                ));
                                continue;
                            };
                            queue.push_back(Work::Principal(principal.clone()));
                        }
                    }
                }
            }
        }
    }
    closure
}

fn function_names(analysis: &Analysis, functions: &BTreeSet<FuncId>) -> Vec<String> {
    functions
        .iter()
        .map(|function| analysis.functions()[*function].key.clone())
        .collect()
}

fn transmod_globals(analysis: &Analysis, functions: &BTreeSet<FuncId>) -> Vec<String> {
    let mut globals = BTreeSet::new();
    for function in functions {
        for (access, affected) in analysis.transitive_accesses(*function) {
            if access != Access::Mod {
                continue;
            }
            match affected {
                AffectedGlobals::Finite(ids) => globals.extend(
                    ids.iter()
                        .map(|global| analysis.globals()[*global].key.clone()),
                ),
                AffectedGlobals::ModuleWide => {
                    globals.extend(analysis.globals().iter().map(|global| global.key.clone()))
                }
            }
        }
    }
    globals.into_iter().collect()
}

fn external_sources(row: &ModRef) -> Vec<String> {
    let mut sources = row
        .detail
        .as_deref()
        .into_iter()
        .flat_map(|detail| detail.split('|'))
        .flat_map(|part| part.split('+'))
        .filter(|part| part.starts_with("omega:") || part.starts_with("external-call:"))
        .map(str::to_string)
        .collect::<Vec<_>>();
    sources.sort();
    sources.dedup();
    sources
}

fn stable_external_sources(sources: &[String], own_callsite: &str) -> Vec<String> {
    let own_boundary = format!("external-call:{own_callsite}");
    let mut sources = sources
        .iter()
        .filter(|source| source.as_str() != own_boundary)
        .cloned()
        .collect::<Vec<_>>();
    sources.sort();
    sources.dedup();
    sources
}

fn stable_principal_source(source: &str) -> bool {
    !matches!(
        source,
        "omega:unknown" | "omega:steens_external" | "omega:inttoptr"
    )
}

fn canonical_symbol(symbol: &str) -> &str {
    symbol.strip_prefix('@').unwrap_or(symbol)
}
