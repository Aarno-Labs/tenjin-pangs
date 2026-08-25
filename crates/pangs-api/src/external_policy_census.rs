//! Read-only Phase-0 census for the proposed external-code policy.
//!
//! Nothing in this module changes a solver fact or client decision. The ordinary pipeline does
//! not populate these records; `Analysis::run_with_external_policy_census` explicitly opts into
//! targeted allocation-level points-to for opaque-call operands and arguments.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use pangs_pag::{CallKind as PagCallKind, Pag};
use pangs_pir::{Access, IntToPtrProvenanceTrace, Pir, Stmt, ValueKind};
use pangs_solve::SolveResult;
use serde::Serialize;

use crate::{
    AffectedGlobals, Analysis, BuildMode, Callee, Caller, FuncId, GlobalCandidateSet, GlobalTarget,
    ModRef, Opts,
};

#[derive(Debug, Clone, Serialize)]
pub struct ExternalPolicyCensus {
    pub build_mode: BuildMode,
    pub finite_effect_rows: Vec<FiniteEffectRow>,
    pub module_wide_rows: Vec<ModuleWideRow>,
    pub forged_pointer_seeds: Vec<ForgedPointerSeedRow>,
    pub forged_pointer_groups: Vec<ForgedPointerGroupRow>,
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
    pub forged_pointer_seeds: usize,
    pub forged_pointer_seeds_feasibly_bounded: usize,
    pub forged_pointer_seeds_bounded_constant_candidates: usize,
    pub forged_pointer_groups: usize,
    pub forged_pointer_groups_feasibly_certifiable: usize,
    pub forged_pointer_groups_bounded_constant_candidates: usize,
    pub module_wide_rows_in_feasibly_certifiable_groups: usize,
    pub module_wide_rows_in_bounded_constant_candidate_groups: usize,
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
    pub forged_pointer_group: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ForgedPointerSeedRow {
    pub source: String,
    pub function: Option<String>,
    pub destination: Option<String>,
    pub source_expression: Option<String>,
    pub classification: String,
    pub feasibly_bounded: bool,
    /// Requires an additional target/link-layout argument that the LLVM module alone does not
    /// provide: the enumerated non-zero integers must not name program storage.
    pub bounded_constant_candidate: bool,
    pub pointer_origins: Vec<String>,
    pub integer_constants: Vec<String>,
    pub operations: Vec<String>,
    pub pointer_origin_seed_dependencies: Vec<String>,
    pub finite_candidate_globals: Vec<String>,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ForgedPointerGroupRow {
    pub group: String,
    pub seed_sources: Vec<String>,
    pub modref_row_indices: Vec<usize>,
    pub classification: String,
    pub feasibly_certifiable: bool,
    pub bounded_constant_candidate: bool,
    pub finite_candidate_globals: Vec<String>,
    pub blockers: Vec<String>,
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
    forged_seed_inputs: BTreeMap<String, ForgedSeedInput>,
}

#[derive(Debug, Clone)]
struct ForgedSeedInput {
    function: String,
    destination: String,
    source_expression: String,
    trace: Option<IntToPtrProvenanceTrace>,
    finite_candidate_globals: BTreeSet<String>,
    blockers: BTreeSet<String>,
    pointer_origin_seed_dependencies: BTreeSet<String>,
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
    let forged_seed_inputs = collect_forged_seed_inputs(pir, solved);
    SolverInputs {
        callsites,
        opaque_inline_asm_exposures,
        universal_sources_by_node: solved
            .nodes
            .iter()
            .filter(|(_, node)| !node.universal_sources.is_empty())
            .map(|(label, node)| (label.clone(), node.universal_sources.clone()))
            .collect(),
        forged_seed_inputs,
    }
}

fn collect_forged_seed_inputs(
    pir: &Pir,
    solved: &SolveResult,
) -> BTreeMap<String, ForgedSeedInput> {
    let mut out = BTreeMap::new();
    for function in pir.functions.iter().filter(|function| !function.external) {
        for statement in &function.body {
            let Stmt::IntToPtr {
                dest,
                source,
                provenance_trace,
                ..
            } = statement
            else {
                continue;
            };
            let universal_source = format!("omega:inttoptr:val:{}:{}", function.key, dest);
            let mut candidates = BTreeSet::new();
            let mut blockers = BTreeSet::new();
            let mut pointer_origin_seed_dependencies = BTreeSet::new();
            if let Some(trace) = provenance_trace {
                blockers.extend(trace.blockers.iter().cloned());
                if trace
                    .integer_constants
                    .iter()
                    .any(|constant| !integer_constant_is_zero(constant))
                {
                    blockers.insert("nonzero-integer-constant".to_string());
                }
                for origin in &trace.pointer_origins {
                    let labels = pointer_origin_labels(function.key.as_str(), origin);
                    let resolution = labels.iter().find_map(|label| solved.nodes.get(label));
                    if let Some(resolution) = resolution {
                        if resolution.external_universal {
                            let dependencies = resolution
                                .universal_sources
                                .iter()
                                .filter(|source| source.starts_with("omega:inttoptr:"))
                                .cloned()
                                .collect::<Vec<_>>();
                            if dependencies.is_empty() {
                                blockers.insert(format!(
                                    "universal-pointer-origin-unattributed:{origin}"
                                ));
                            }
                            pointer_origin_seed_dependencies.extend(dependencies);
                        }
                        let globals = if resolution.pointee_globals_unfiltered.is_empty() {
                            &resolution.pointee_globals
                        } else {
                            &resolution.pointee_globals_unfiltered
                        };
                        candidates.extend(globals.iter().cloned());
                    } else if let Some(global) = pir
                        .globals
                        .iter()
                        .find(|global| canonical_symbol(&global.key) == canonical_symbol(origin))
                    {
                        candidates.insert(global.key.clone());
                    } else if origin != "null"
                        && !pir.functions.iter().any(|candidate| {
                            canonical_symbol(&candidate.key) == canonical_symbol(origin)
                        })
                    {
                        blockers.insert(format!("pointer-origin-resolution-unavailable:{origin}"));
                    }
                }
            } else {
                blockers.insert("source-provenance-unavailable".to_string());
            }
            out.insert(
                universal_source,
                ForgedSeedInput {
                    function: function.key.clone(),
                    destination: dest.clone(),
                    source_expression: source.clone(),
                    trace: provenance_trace.clone(),
                    finite_candidate_globals: candidates,
                    blockers,
                    pointer_origin_seed_dependencies,
                },
            );
        }
    }
    for statement in &pir.global_init {
        let Stmt::IntToPtr {
            dest,
            source,
            provenance_trace,
            ..
        } = statement
        else {
            continue;
        };
        let universal_source = format!("omega:inttoptr:val:global_init:{dest}");
        let mut candidates = BTreeSet::new();
        let mut blockers = BTreeSet::new();
        let mut pointer_origin_seed_dependencies = BTreeSet::new();
        if let Some(trace) = provenance_trace {
            blockers.extend(trace.blockers.iter().cloned());
            if trace
                .integer_constants
                .iter()
                .any(|constant| !integer_constant_is_zero(constant))
            {
                blockers.insert("nonzero-integer-constant".to_string());
            }
            for origin in &trace.pointer_origins {
                let labels = pointer_origin_labels("global_init", origin);
                let resolution = labels.iter().find_map(|label| solved.nodes.get(label));
                if let Some(resolution) = resolution {
                    if resolution.external_universal {
                        let dependencies = resolution
                            .universal_sources
                            .iter()
                            .filter(|source| source.starts_with("omega:inttoptr:"))
                            .cloned()
                            .collect::<Vec<_>>();
                        if dependencies.is_empty() {
                            blockers
                                .insert(format!("universal-pointer-origin-unattributed:{origin}"));
                        }
                        pointer_origin_seed_dependencies.extend(dependencies);
                    }
                    let globals = if resolution.pointee_globals_unfiltered.is_empty() {
                        &resolution.pointee_globals
                    } else {
                        &resolution.pointee_globals_unfiltered
                    };
                    candidates.extend(globals.iter().cloned());
                } else if let Some(global) = pir
                    .globals
                    .iter()
                    .find(|global| canonical_symbol(&global.key) == canonical_symbol(origin))
                {
                    candidates.insert(global.key.clone());
                } else if origin != "null"
                    && !pir.functions.iter().any(|candidate| {
                        canonical_symbol(&candidate.key) == canonical_symbol(origin)
                    })
                {
                    blockers.insert(format!("pointer-origin-resolution-unavailable:{origin}"));
                }
            }
        } else {
            blockers.insert("source-provenance-unavailable".to_string());
        }
        out.insert(
            universal_source,
            ForgedSeedInput {
                function: "global_init".to_string(),
                destination: dest.clone(),
                source_expression: source.clone(),
                trace: provenance_trace.clone(),
                finite_candidate_globals: candidates,
                blockers,
                pointer_origin_seed_dependencies,
            },
        );
    }
    out
}

fn pointer_origin_labels(function: &str, origin: &str) -> Vec<String> {
    if origin.starts_with('@') {
        vec![
            format!("sym:global:{origin}"),
            format!("sym:function:{origin}"),
        ]
    } else {
        vec![format!("val:{function}:{origin}")]
    }
}

fn integer_constant_is_zero(constant: &str) -> bool {
    constant == "0"
        || constant == "null"
        || constant
            .split_whitespace()
            .last()
            .is_some_and(|value| value == "0")
}

pub(crate) fn build(
    _pir: &Pir,
    opts: &Opts,
    analysis: &Analysis,
    inputs: SolverInputs,
) -> ExternalPolicyCensus {
    let universal_sources_by_node = inputs.universal_sources_by_node.clone();
    let forged_seed_inputs = inputs.forged_seed_inputs.clone();
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
                    forged_pointer_group: None,
                });
            }
            GlobalCandidateSet::Finite(_) => {}
        }
    }

    let (forged_pointer_seeds, forged_pointer_groups) =
        build_forged_pointer_groups(&mut module_wide_rows, &forged_seed_inputs);

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
        forged_pointer_seeds: forged_pointer_seeds.len(),
        forged_pointer_seeds_feasibly_bounded: forged_pointer_seeds
            .iter()
            .filter(|seed| seed.feasibly_bounded)
            .count(),
        forged_pointer_seeds_bounded_constant_candidates: forged_pointer_seeds
            .iter()
            .filter(|seed| seed.bounded_constant_candidate)
            .count(),
        forged_pointer_groups: forged_pointer_groups.len(),
        forged_pointer_groups_feasibly_certifiable: forged_pointer_groups
            .iter()
            .filter(|group| group.feasibly_certifiable)
            .count(),
        forged_pointer_groups_bounded_constant_candidates: forged_pointer_groups
            .iter()
            .filter(|group| group.bounded_constant_candidate)
            .count(),
        module_wide_rows_in_feasibly_certifiable_groups: forged_pointer_groups
            .iter()
            .filter(|group| group.feasibly_certifiable)
            .map(|group| group.modref_row_indices.len())
            .sum(),
        module_wide_rows_in_bounded_constant_candidate_groups: forged_pointer_groups
            .iter()
            .filter(|group| group.bounded_constant_candidate)
            .map(|group| group.modref_row_indices.len())
            .sum(),
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
        build_mode: opts.build_mode,
        finite_effect_rows,
        module_wide_rows,
        forged_pointer_seeds,
        forged_pointer_groups,
        module_wide_poisoned_globals: poisoned_globals,
        principals: principal_rows,
        opaque_callsites: opaque_callsite_rows,
        summary,
    }
}

fn build_forged_pointer_groups(
    rows: &mut [ModuleWideRow],
    inputs: &BTreeMap<String, ForgedSeedInput>,
) -> (Vec<ForgedPointerSeedRow>, Vec<ForgedPointerGroupRow>) {
    let row_seeds = rows
        .iter()
        .map(|row| {
            row.external_sources
                .iter()
                .filter(|source| source.starts_with("omega:inttoptr:"))
                .cloned()
                .collect::<BTreeSet<_>>()
        })
        .collect::<Vec<_>>();
    let mut relevant_sources = row_seeds
        .iter()
        .flat_map(|sources| sources.iter().cloned())
        .collect::<BTreeSet<_>>();
    let mut dependency_queue = relevant_sources.iter().cloned().collect::<VecDeque<_>>();
    while let Some(source) = dependency_queue.pop_front() {
        let Some(input) = inputs.get(&source) else {
            continue;
        };
        for dependency in &input.pointer_origin_seed_dependencies {
            if relevant_sources.insert(dependency.clone()) {
                dependency_queue.push_back(dependency.clone());
            }
        }
    }
    let seed_rows = relevant_sources
        .iter()
        .map(|source| forged_pointer_seed_row(source, inputs.get(source)))
        .collect::<Vec<_>>();
    let seed_by_source = seed_rows
        .iter()
        .map(|row| (row.source.as_str(), row))
        .collect::<BTreeMap<_, _>>();
    let mut rows_by_seed = BTreeMap::<String, BTreeSet<usize>>::new();
    for (row, sources) in row_seeds.iter().enumerate() {
        for source in sources {
            rows_by_seed.entry(source.clone()).or_default().insert(row);
        }
    }
    let mut adjacent = relevant_sources
        .iter()
        .map(|source| (source.clone(), BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    let mut connect = |left: &str, right: &str| {
        if left == right {
            return;
        }
        adjacent
            .entry(left.to_string())
            .or_default()
            .insert(right.to_string());
        adjacent
            .entry(right.to_string())
            .or_default()
            .insert(left.to_string());
    };
    for sources in &row_seeds {
        if let Some(first) = sources.first() {
            for source in sources.iter().skip(1) {
                connect(first, source);
            }
        }
    }
    for source in &relevant_sources {
        if let Some(input) = inputs.get(source) {
            for dependency in &input.pointer_origin_seed_dependencies {
                connect(source, dependency);
            }
        }
    }

    let mut groups = Vec::new();
    let mut visited_seeds = BTreeSet::new();
    let mut assigned_rows = BTreeSet::new();
    for initial_seed in &relevant_sources {
        if !visited_seeds.insert(initial_seed.clone()) {
            continue;
        }
        let mut group_seeds = BTreeSet::from([initial_seed.clone()]);
        let mut queue = VecDeque::from([initial_seed.clone()]);
        while let Some(source) = queue.pop_front() {
            for connected in &adjacent[&source] {
                if visited_seeds.insert(connected.clone()) {
                    group_seeds.insert(connected.clone());
                    queue.push_back(connected.clone());
                }
            }
        }
        let group_rows = group_seeds
            .iter()
            .flat_map(|source| rows_by_seed.get(source).into_iter().flatten().copied())
            .collect::<BTreeSet<_>>();
        if group_rows.is_empty() {
            continue;
        }
        assigned_rows.extend(group_rows.iter().copied());
        let group = format!("forged-group:{}", groups.len());
        for &row in &group_rows {
            rows[row].forged_pointer_group = Some(group.clone());
        }
        let seed_records = group_seeds
            .iter()
            .filter_map(|source| seed_by_source.get(source.as_str()).copied())
            .collect::<Vec<_>>();
        let feasibly_certifiable = seed_records.len() == group_seeds.len()
            && seed_records.iter().all(|seed| seed.feasibly_bounded);
        let bounded_constant_candidate = seed_records.len() == group_seeds.len()
            && seed_records
                .iter()
                .all(|seed| seed.feasibly_bounded || seed.bounded_constant_candidate)
            && seed_records
                .iter()
                .any(|seed| seed.bounded_constant_candidate);
        let mut candidates = seed_records
            .iter()
            .flat_map(|seed| seed.finite_candidate_globals.iter().cloned())
            .collect::<BTreeSet<_>>();
        let mut blockers = seed_records
            .iter()
            .flat_map(|seed| seed.blockers.iter().cloned())
            .collect::<BTreeSet<_>>();
        if seed_records.len() != group_seeds.len() {
            blockers.insert("seed-record-unavailable".to_string());
        }
        let classification = if feasibly_certifiable {
            let classes = seed_records
                .iter()
                .map(|seed| seed.classification.as_str())
                .collect::<BTreeSet<_>>();
            if classes.len() == 1 {
                classes.first().unwrap().to_string()
            } else {
                "pointer_or_null".to_string()
            }
        } else if bounded_constant_candidate {
            "bounded_constant_candidate".to_string()
        } else if seed_records.iter().any(|seed| seed.feasibly_bounded) {
            "mixed".to_string()
        } else {
            "unbounded".to_string()
        };
        groups.push(ForgedPointerGroupRow {
            group,
            seed_sources: group_seeds.into_iter().collect(),
            modref_row_indices: group_rows.iter().map(|row| rows[*row].row_index).collect(),
            classification,
            feasibly_certifiable,
            bounded_constant_candidate,
            finite_candidate_globals: candidates.iter().cloned().collect(),
            blockers: blockers.iter().cloned().collect(),
        });
        candidates.clear();
        blockers.clear();
    }
    for row in 0..rows.len() {
        if assigned_rows.contains(&row) {
            continue;
        }
        let group = format!("forged-group:{}", groups.len());
        rows[row].forged_pointer_group = Some(group.clone());
        groups.push(ForgedPointerGroupRow {
            group,
            seed_sources: Vec::new(),
            modref_row_indices: vec![rows[row].row_index],
            classification: "unbounded".to_string(),
            feasibly_certifiable: false,
            bounded_constant_candidate: false,
            finite_candidate_globals: Vec::new(),
            blockers: vec!["module-wide-row-unattributed".to_string()],
        });
    }
    (seed_rows, groups)
}

fn forged_pointer_seed_row(source: &str, input: Option<&ForgedSeedInput>) -> ForgedPointerSeedRow {
    let Some(input) = input else {
        return ForgedPointerSeedRow {
            source: source.to_string(),
            function: None,
            destination: None,
            source_expression: None,
            classification: "unbounded".to_string(),
            feasibly_bounded: false,
            bounded_constant_candidate: false,
            pointer_origins: Vec::new(),
            integer_constants: Vec::new(),
            operations: Vec::new(),
            pointer_origin_seed_dependencies: Vec::new(),
            finite_candidate_globals: Vec::new(),
            blockers: vec!["seed-provenance-unavailable".to_string()],
        };
    };
    let (pointer_origins, integer_constants, operations) = input
        .trace
        .as_ref()
        .map(|trace| {
            (
                trace.pointer_origins.clone(),
                trace.integer_constants.clone(),
                trace.operations.clone(),
            )
        })
        .unwrap_or_default();
    let all_constants_zero = integer_constants
        .iter()
        .all(|constant| integer_constant_is_zero(constant));
    let feasibly_bounded = input.blockers.is_empty()
        && all_constants_zero
        && (!pointer_origins.is_empty() || !integer_constants.is_empty());
    let bounded_constant_candidate = !feasibly_bounded
        && !integer_constants.is_empty()
        && input.blockers.iter().all(|blocker| {
            blocker == "nonzero-integer-constant"
                || blocker == "integer-width-cast:zext"
                || blocker == "integer-width-cast:sext"
        });
    let classification = if feasibly_bounded {
        match (pointer_origins.is_empty(), integer_constants.is_empty()) {
            (false, true) => "pointer_derived",
            (true, false) => "null",
            (false, false) => "pointer_or_null",
            (true, true) => unreachable!(),
        }
    } else if !all_constants_zero {
        "nonzero_integer_constant"
    } else {
        "unbounded"
    };
    ForgedPointerSeedRow {
        source: source.to_string(),
        function: Some(input.function.clone()),
        destination: Some(input.destination.clone()),
        source_expression: Some(input.source_expression.clone()),
        classification: classification.to_string(),
        feasibly_bounded,
        bounded_constant_candidate,
        pointer_origins,
        integer_constants,
        operations,
        pointer_origin_seed_dependencies: input
            .pointer_origin_seed_dependencies
            .iter()
            .cloned()
            .collect(),
        finite_candidate_globals: input.finite_candidate_globals.iter().cloned().collect(),
        blockers: input.blockers.iter().cloned().collect(),
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
