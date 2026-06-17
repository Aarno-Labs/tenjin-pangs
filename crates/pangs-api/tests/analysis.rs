use std::collections::BTreeSet;
use std::path::Path;

use pangs_api::{
    run_m2_ablation, Analysis, BuildMode, Caller, EscapeStatus, M2AblationMode, Opts, Stage,
    StationarityReason,
};
use pangs_pir::{AbiClass, Access, Func, Global, Param, Pir, Signature, Stmt};

fn sig(ret: AbiClass, params: Vec<Param>) -> Signature {
    Signature {
        ret,
        params,
        vararg: false,
        cc: "ccc".to_string(),
    }
}

fn unknown_caller(caller: &Caller) -> bool {
    matches!(caller, Caller::Unknown(reason) if reason == "address_escapes_to_external")
}

fn singleton_exports(symbol: &str) -> BTreeSet<String> {
    [symbol.to_string()].into_iter().collect()
}

fn m1_4_fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/m1_4")
        .join(name)
}

fn m1_5_fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/m1_5")
        .join(name)
}

fn m1_6_fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/m1_6")
        .join(name)
}

fn m1_7_fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/m1_7")
        .join(name)
}

fn m2_2_fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/m2_2")
        .join(name)
}

fn m2_3_fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/m2_3")
        .join(name)
}

fn m2_4_fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/m2_4")
        .join(name)
}

fn assert_single_simple_target(analysis: &Analysis, target: &str) {
    let target_id = analysis.lookup_func(target).unwrap();
    let concrete_edges = analysis
        .call_edges()
        .iter()
        .filter(|edge| edge.kind == pangs_api::CallKind::Indirect)
        .collect::<Vec<_>>();
    assert_eq!(concrete_edges.len(), 1, "{concrete_edges:#?}");
    assert_eq!(concrete_edges[0].callee, pangs_api::Callee::Func(target_id));
    assert_eq!(concrete_edges[0].tier, pangs_api::Tier::Simple);
    assert_eq!(analysis.metrics().icalls_simple, 1);
    assert_eq!(analysis.metrics().icalls_andersen, 0);
    assert_eq!(analysis.metrics().icalls_unknown, 0);
}

#[test]
fn unknown_caller_seeds_only_exported_external_and_address_taken_functions() {
    let pir = Pir {
        module: "m".to_string(),
        source: None,
        lowering: Default::default(),
        functions: vec![
            Func {
                key: "helper".to_string(),
                sig: sig(AbiClass::Void, vec![]),
                param_names: vec![],
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                body: vec![],
            },
            Func {
                key: "cb".to_string(),
                sig: sig(AbiClass::Void, vec![]),
                param_names: vec![],
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: true,
                body: vec![],
            },
            Func {
                key: "pub_fn".to_string(),
                sig: sig(AbiClass::Void, vec![]),
                param_names: vec![],
                file: None,
                line: None,
                external: false,
                exported: true,
                address_taken: false,
                body: vec![],
            },
            Func {
                key: "ext_decl".to_string(),
                sig: sig(AbiClass::Void, vec![]),
                param_names: vec![],
                file: None,
                line: None,
                external: true,
                exported: false,
                address_taken: false,
                body: vec![],
            },
        ],
        globals: vec![],
        global_init: vec![],
    };

    let analysis = Analysis::run(
        &pir,
        &Opts {
            build_mode: BuildMode::Library,
            ..Opts::default()
        },
    )
    .unwrap();

    let helper = analysis.lookup_func("helper").unwrap();
    let cb = analysis.lookup_func("cb").unwrap();
    let pub_fn = analysis.lookup_func("pub_fn").unwrap();
    let ext_decl = analysis.lookup_func("ext_decl").unwrap();

    assert!(!analysis.callers(helper).any(unknown_caller));
    assert!(analysis.callers(cb).any(unknown_caller));
    assert!(analysis.callers(pub_fn).any(unknown_caller));
    assert!(analysis.callers(ext_decl).any(unknown_caller));
}

#[test]
fn m2_2_simple_local_assign_icall_takes_exact_precedence() {
    let pir = Pir::from_path(m2_2_fixture("simple_local_assign.pir.json")).unwrap();

    let conservative = Analysis::run(&pir, &Opts::default()).unwrap();
    let conservative_targets = conservative
        .call_edges()
        .iter()
        .filter_map(|edge| match edge.callee {
            pangs_api::Callee::Func(id) if edge.kind == pangs_api::CallKind::Indirect => {
                Some(conservative.functions()[id].key.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        conservative_targets,
        ["cb".to_string(), "other".to_string()]
            .into_iter()
            .collect()
    );

    let analysis = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Andersen,
            ..Opts::default()
        },
    )
    .unwrap();

    assert_single_simple_target(&analysis, "cb");
}

#[test]
fn m2_2_simple_never_address_taken_global_slot_resolves_exactly() {
    let pir = Pir::from_path(m2_2_fixture("simple_global_slot.pir.json")).unwrap();

    let analysis = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Andersen,
            ..Opts::default()
        },
    )
    .unwrap();

    assert_single_simple_target(&analysis, "cb");
}

#[test]
fn m2_2_simple_constant_global_field_resolves_exactly() {
    let pir = Pir::from_path(m2_2_fixture("simple_global_fields.pir.json")).unwrap();

    let analysis = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Andersen,
            ..Opts::default()
        },
    )
    .unwrap();

    assert_single_simple_target(&analysis, "cb");
}

#[test]
fn m2_2_dynamic_global_field_access_is_not_marked_simple() {
    let pir = Pir::from_path(m2_2_fixture("dynamic_global_field_is_complex.pir.json")).unwrap();

    let analysis = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Andersen,
            ..Opts::default()
        },
    )
    .unwrap();

    assert_eq!(analysis.metrics().icalls_simple, 0);
    assert!(analysis.call_edges().iter().any(|edge| {
        edge.kind == pangs_api::CallKind::Indirect && edge.tier == pangs_api::Tier::Andersen
    }));
}

#[test]
fn m2_2_direct_calls_do_not_count_as_function_pointer_escape() {
    let pir = Pir::from_path(m2_2_fixture("direct_call_is_not_escape.pir.json")).unwrap();

    let analysis = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Andersen,
            ..Opts::default()
        },
    )
    .unwrap();

    assert_single_simple_target(&analysis, "cb");
}

#[test]
fn m2_2_store_through_local_memory_makes_candidate_complex() {
    let pir = Pir::from_path(m2_2_fixture("local_store_escape_is_complex.pir.json")).unwrap();

    let analysis = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Andersen,
            ..Opts::default()
        },
    )
    .unwrap();

    assert_eq!(analysis.metrics().icalls_simple, 0);
    assert!(analysis.call_edges().iter().any(|edge| {
        edge.kind == pangs_api::CallKind::Indirect && edge.tier == pangs_api::Tier::Andersen
    }));
}

#[test]
fn m2_2_simple_param_actual_resolves_through_internal_direct_call() {
    let pir = Pir::from_path(m2_2_fixture("simple_param_actual.pir.json")).unwrap();

    let analysis = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Andersen,
            ..Opts::default()
        },
    )
    .unwrap();

    assert_single_simple_target(&analysis, "cb");
}

#[test]
fn m2_2_simple_return_value_resolves_through_internal_direct_call() {
    let pir = Pir::from_path(m2_2_fixture("simple_return_value.pir.json")).unwrap();

    let analysis = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Andersen,
            ..Opts::default()
        },
    )
    .unwrap();

    assert_single_simple_target(&analysis, "cb");
}

#[test]
fn m2_3_confined_function_is_subtracted_from_complex_icall_site() {
    let pir = Pir::from_path(m2_3_fixture("confined_subtraction.pir.json")).unwrap();

    let analysis = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Andersen,
            ..Opts::default()
        },
    )
    .unwrap();

    assert_eq!(analysis.metrics().icalls_simple, 1);
    assert_eq!(analysis.metrics().icalls_andersen, 1);
    assert_eq!(analysis.metrics().confined_functions, 1);

    let cb = analysis.lookup_func("cb").unwrap();
    let other = analysis.lookup_func("other").unwrap();
    let mut simple_cb = false;
    let mut complex_other = false;
    for edge in analysis.call_edges() {
        if edge.kind != pangs_api::CallKind::Indirect {
            continue;
        }
        if edge.callsite == Some(pangs_api::CallsiteId(0))
            && edge.callee == pangs_api::Callee::Func(cb)
            && edge.tier == pangs_api::Tier::Simple
        {
            simple_cb = true;
        }
        if edge.callsite == Some(pangs_api::CallsiteId(1))
            && edge.callee == pangs_api::Callee::Func(other)
            && edge.tier == pangs_api::Tier::Andersen
        {
            complex_other = true;
        }
        assert!(
            !(edge.callsite == Some(pangs_api::CallsiteId(1))
                && edge.callee == pangs_api::Callee::Func(cb)),
            "confined cb leaked into the complex icall target set: {edge:#?}"
        );
    }
    assert!(simple_cb);
    assert!(complex_other);
}

#[test]
fn m2_4_initval_stationary_dispatch_table_resolves_exactly() {
    let pir = Pir::from_path(m2_4_fixture("initval_dispatch_table.pir.json")).unwrap();

    let analysis = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Andersen,
            ..Opts::default()
        },
    )
    .unwrap();

    assert_single_simple_target(&analysis, "other");
    assert_eq!(analysis.metrics().globals_with_complete_initval, 1);
    assert_eq!(analysis.metrics().stationary_globals, 1);
    assert_eq!(analysis.metrics().mutable_globals_total, 0);
    assert_eq!(analysis.metrics().in_rewritable_components, 0);

    let table = analysis.lookup_global("@Table").unwrap();
    assert!(analysis.globals()[table].mutable);
    assert!(analysis.globals()[table].stationary);
    let verdict = analysis
        .stationarity_verdicts()
        .iter()
        .find(|verdict| verdict.global == table)
        .unwrap();
    assert!(verdict.complete_initval);
    assert!(verdict.stationary);
    assert_eq!(verdict.reason, StationarityReason::Stationary);
    assert!(verdict.runtime_writers.is_empty());
    let driver = analysis.lookup_func("driver").unwrap();
    let component = analysis.component(analysis.component_of(driver));
    assert!(
        component.mutable_globals.is_empty(),
        "stationary table should leave localization payload: {component:#?}"
    );
}

#[test]
fn m2_4_runtime_write_blocks_initval_exact_dispatch_resolution() {
    let pir = Pir::from_path(m2_4_fixture(
        "initval_runtime_write_is_not_stationary.pir.json",
    ))
    .unwrap();

    let analysis = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Andersen,
            ..Opts::default()
        },
    )
    .unwrap();

    assert_eq!(analysis.metrics().globals_with_complete_initval, 1);
    assert_eq!(analysis.metrics().stationary_globals, 0);
    assert_eq!(analysis.metrics().icalls_simple, 0);
    assert!(analysis.call_edges().iter().any(|edge| {
        edge.kind == pangs_api::CallKind::Indirect && edge.tier == pangs_api::Tier::Andersen
    }));
}

#[test]
fn m2_4_alias_write_blocks_initval_stationarity() {
    let pir = Pir::from_path(m2_4_fixture(
        "initval_alias_write_is_not_stationary.pir.json",
    ))
    .unwrap();

    let analysis = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Andersen,
            ..Opts::default()
        },
    )
    .unwrap();

    let table = analysis.lookup_global("@Table").unwrap();
    assert!(analysis.globals()[table].mutable);
    assert!(!analysis.globals()[table].stationary);
    let verdict = analysis
        .stationarity_verdicts()
        .iter()
        .find(|verdict| verdict.global == table)
        .unwrap();
    assert!(verdict.complete_initval);
    assert!(!verdict.stationary);
    assert_eq!(verdict.reason, StationarityReason::RuntimeWriter);
    assert!(!verdict.runtime_writers.is_empty());
    assert_eq!(analysis.metrics().globals_with_complete_initval, 1);
    assert_eq!(analysis.metrics().stationary_globals, 0);
    assert_eq!(analysis.metrics().icalls_simple, 0);
    assert!(analysis.call_edges().iter().any(|edge| {
        edge.kind == pangs_api::CallKind::Indirect && edge.tier == pangs_api::Tier::Andersen
    }));
}

#[test]
fn m2_4_unknown_initializer_poisons_initval() {
    let pir = Pir::from_path(m2_4_fixture("initval_unknown_initializer_poisons.pir.json")).unwrap();

    let analysis = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Andersen,
            ..Opts::default()
        },
    )
    .unwrap();

    let table = analysis.lookup_global("@Table").unwrap();
    assert!(!analysis.globals()[table].stationary);
    let verdict = analysis
        .stationarity_verdicts()
        .iter()
        .find(|verdict| verdict.global == table)
        .unwrap();
    assert!(!verdict.complete_initval);
    assert_eq!(verdict.reason, StationarityReason::IncompleteInitval);
    assert_eq!(analysis.metrics().globals_with_complete_initval, 0);
    assert_eq!(analysis.metrics().stationary_globals, 0);
    assert_eq!(analysis.metrics().icalls_simple, 0);
}

#[test]
fn m2_4_dynamic_initializer_gep_poisons_initval() {
    let pir = Pir::from_path(m2_4_fixture(
        "initval_dynamic_initializer_gep_poisons.pir.json",
    ))
    .unwrap();

    let analysis = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Andersen,
            ..Opts::default()
        },
    )
    .unwrap();

    let table = analysis.lookup_global("@Table").unwrap();
    assert!(!analysis.globals()[table].stationary);
    assert_eq!(analysis.metrics().globals_with_complete_initval, 0);
    assert_eq!(analysis.metrics().stationary_globals, 0);
    assert_eq!(analysis.metrics().icalls_simple, 0);
}

#[test]
fn m2_4_unknown_runtime_mod_blocks_stationarity() {
    let pir = Pir::from_path(m2_4_fixture(
        "initval_unknown_runtime_mod_blocks_stationarity.pir.json",
    ))
    .unwrap();

    let analysis = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Andersen,
            ..Opts::default()
        },
    )
    .unwrap();

    let table = analysis.lookup_global("@Table").unwrap();
    assert!(analysis.globals()[table].mutable);
    assert!(!analysis.globals()[table].stationary);
    let verdict = analysis
        .stationarity_verdicts()
        .iter()
        .find(|verdict| verdict.global == table)
        .unwrap();
    assert!(verdict.complete_initval);
    assert_eq!(verdict.reason, StationarityReason::UnknownRuntimeWriter);
    assert!(verdict
        .runtime_writers
        .iter()
        .any(|writer| matches!(writer.global, pangs_api::GlobalTarget::Unknown(_))));
    assert_eq!(analysis.metrics().globals_with_complete_initval, 1);
    assert_eq!(analysis.metrics().stationary_globals, 0);
    assert_eq!(analysis.metrics().icalls_simple, 0);
    assert!(analysis.modrefs().iter().any(|mr| {
        mr.access == Access::Mod && matches!(mr.global, pangs_api::GlobalTarget::Unknown(_))
    }));
}

#[test]
fn m2_7_ablation_toggles_isolate_b2_and_b1_effects() {
    let b2_pir = Pir::from_path(m2_2_fixture("simple_local_assign.pir.json")).unwrap();
    let b2_report = run_m2_ablation(
        &b2_pir,
        &Opts {
            stage: Stage::Andersen,
            ..Opts::default()
        },
    )
    .unwrap();
    let b2_only = b2_report
        .variants
        .iter()
        .find(|variant| variant.mode == M2AblationMode::B2Only)
        .unwrap();
    let b1_only = b2_report
        .variants
        .iter()
        .find(|variant| variant.mode == M2AblationMode::B1Only)
        .unwrap();
    assert_eq!(b2_only.icalls_simple, 1);
    assert_eq!(b1_only.icalls_simple, 0);

    let b1_pir = Pir::from_path(m2_4_fixture("initval_dispatch_table.pir.json")).unwrap();
    let b1_report = run_m2_ablation(
        &b1_pir,
        &Opts {
            stage: Stage::Andersen,
            ..Opts::default()
        },
    )
    .unwrap();
    let baseline = b1_report
        .variants
        .iter()
        .find(|variant| variant.mode == M2AblationMode::M1Baseline)
        .unwrap();
    let b1_only = b1_report
        .variants
        .iter()
        .find(|variant| variant.mode == M2AblationMode::B1Only)
        .unwrap();
    assert_eq!(baseline.globals_with_complete_initval, 0);
    assert_eq!(baseline.stationary_globals, 0);
    assert_eq!(b1_only.globals_with_complete_initval, 1);
    assert_eq!(b1_only.stationary_globals, 1);
    assert_eq!(b1_only.icalls_simple, 1);
}

#[test]
fn indirect_call_component_taint_uses_callsite_witness_and_matches_external_targets() {
    let target_sig = sig(AbiClass::Void, vec![Param::Integer]);
    let pir = Pir {
        module: "m".to_string(),
        source: None,
        lowering: Default::default(),
        functions: vec![
            Func {
                key: "driver".to_string(),
                sig: sig(AbiClass::Void, vec![]),
                param_names: vec![],
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                body: vec![Stmt::CallIndirect {
                    operand: "%fp".to_string(),
                    sig: target_sig.clone(),
                    args: vec![],
                    dest: None,
                    loc: None,
                }],
            },
            Func {
                key: "ext_cb".to_string(),
                sig: target_sig,
                param_names: vec![],
                file: None,
                line: None,
                external: true,
                exported: false,
                address_taken: true,
                body: vec![],
            },
        ],
        globals: vec![Global {
            key: "@G".to_string(),
            file: None,
            line: None,
            is_const: false,
            mutable: true,
            exported: true,
        }],
        global_init: vec![],
    };

    let analysis = Analysis::run(&pir, &Opts::default()).unwrap();
    let driver = analysis.lookup_func("driver").unwrap();
    let ext_cb = analysis.lookup_func("ext_cb").unwrap();
    let gid = analysis.lookup_global("@G").unwrap();

    let callsites: Vec<_> = analysis.callsites().iter().collect();
    assert_eq!(callsites.len(), 1);
    assert_eq!(callsites[0].key, "driver@!noloc#0");

    assert!(analysis
        .call_edges()
        .iter()
        .any(|edge| edge.callsite == Some(pangs_api::CallsiteId(0))
            && edge.callee == pangs_api::Callee::Func(ext_cb)));

    let component = analysis.component(analysis.component_of(driver));
    assert!(component.taint.iter().any(|taint| {
        taint.kind == "unknown_callee" && taint.witness.as_deref() == Some("driver@!noloc#0")
    }));
    assert_eq!(analysis.escape(gid), EscapeStatus::External);
}

#[test]
fn direct_global_modref_marks_never_written_and_preserves_direct_witness() {
    let pir = Pir {
        module: "m".to_string(),
        source: None,
        lowering: Default::default(),
        functions: vec![Func {
            key: "writer".to_string(),
            sig: sig(AbiClass::Void, vec![]),
            param_names: vec![],
            file: None,
            line: None,
            external: false,
            exported: false,
            address_taken: false,
            body: vec![
                Stmt::GlobalRef {
                    global: "@G".to_string(),
                    access: Access::Mod,
                    loc: None,
                },
                Stmt::GlobalRef {
                    global: "@G".to_string(),
                    access: Access::Ref,
                    loc: None,
                },
            ],
        }],
        globals: vec![Global {
            key: "@G".to_string(),
            file: None,
            line: None,
            is_const: false,
            mutable: true,
            exported: false,
        }],
        global_init: vec![],
    };

    let analysis = Analysis::run(&pir, &Opts::default()).unwrap();
    let writer = analysis.lookup_func("writer").unwrap();
    let global = analysis.lookup_global("@G").unwrap();
    let global_info = &analysis.globals()[global];

    assert!(!global_info.never_written);
    let modrefs: Vec<_> = analysis.modref(writer).collect();
    assert_eq!(modrefs.len(), 2);
    assert!(modrefs
        .iter()
        .all(|mr| matches!(mr.global, pangs_api::GlobalTarget::Name(id) if id == global)));
    assert!(modrefs
        .iter()
        .any(|mr| mr.access == Access::Mod && mr.witness.as_deref() == Some("writer@!noloc#0")));
    assert!(modrefs
        .iter()
        .any(|mr| mr.access == Access::Ref && mr.witness.as_deref() == Some("writer@!noloc#1")));
}

#[test]
fn modref_api_closes_over_direct_calls_but_export_rows_stay_local() {
    let pir = Pir {
        module: "m".to_string(),
        source: None,
        lowering: Default::default(),
        functions: vec![
            Func {
                key: "entry".to_string(),
                sig: sig(AbiClass::Void, vec![]),
                param_names: vec![],
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                body: vec![Stmt::CallDirect {
                    callee: "leaf".to_string(),
                    sig: sig(AbiClass::Void, vec![]),
                    args: vec![],
                    dest: None,
                    loc: None,
                }],
            },
            Func {
                key: "leaf".to_string(),
                sig: sig(AbiClass::Void, vec![]),
                param_names: vec![],
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                body: vec![Stmt::GlobalRef {
                    global: "@G".to_string(),
                    access: Access::Mod,
                    loc: None,
                }],
            },
        ],
        globals: vec![Global {
            key: "@G".to_string(),
            file: None,
            line: None,
            is_const: false,
            mutable: true,
            exported: false,
        }],
        global_init: vec![],
    };

    let analysis = Analysis::run(&pir, &Opts::default()).unwrap();
    let entry = analysis.lookup_func("entry").unwrap();
    let leaf = analysis.lookup_func("leaf").unwrap();
    let global = analysis.lookup_global("@G").unwrap();

    let raw_modrefs: Vec<_> = analysis.modrefs().iter().collect();
    assert_eq!(raw_modrefs.len(), 1);
    assert_eq!(raw_modrefs[0].func, leaf);

    let entry_modrefs: Vec<_> = analysis.modref(entry).collect();
    assert_eq!(entry_modrefs.len(), 1);
    assert_eq!(entry_modrefs[0].func, entry);
    assert!(matches!(
        entry_modrefs[0].global,
        pangs_api::GlobalTarget::Name(id) if id == global
    ));
    assert_eq!(entry_modrefs[0].witness.as_deref(), Some("leaf@!noloc#0"));
}

#[test]
fn transitive_modref_api_collapses_duplicate_witnesses() {
    let pir = Pir {
        module: "m".to_string(),
        source: None,
        lowering: Default::default(),
        functions: vec![
            Func {
                key: "entry".to_string(),
                sig: sig(AbiClass::Void, vec![]),
                param_names: vec![],
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                body: vec![Stmt::CallDirect {
                    callee: "leaf".to_string(),
                    sig: sig(AbiClass::Void, vec![]),
                    args: vec![],
                    dest: None,
                    loc: None,
                }],
            },
            Func {
                key: "leaf".to_string(),
                sig: sig(AbiClass::Void, vec![]),
                param_names: vec![],
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                body: vec![
                    Stmt::GlobalRef {
                        global: "@G".to_string(),
                        access: Access::Mod,
                        loc: None,
                    },
                    Stmt::GlobalRef {
                        global: "@G".to_string(),
                        access: Access::Mod,
                        loc: None,
                    },
                ],
            },
        ],
        globals: vec![Global {
            key: "@G".to_string(),
            file: None,
            line: None,
            is_const: false,
            mutable: true,
            exported: false,
        }],
        global_init: vec![],
    };

    let analysis = Analysis::run(&pir, &Opts::default()).unwrap();
    let entry = analysis.lookup_func("entry").unwrap();

    assert_eq!(analysis.modrefs().len(), 1);
    let entry_modrefs: Vec<_> = analysis.modref(entry).collect();
    assert_eq!(entry_modrefs.len(), 1);
    assert_eq!(entry_modrefs[0].witness.as_deref(), Some("leaf@!noloc#0"));
}

#[test]
fn modref_api_closes_over_fsa_indirect_targets() {
    let target_sig = sig(AbiClass::Void, vec![Param::Integer]);
    let pir = Pir {
        module: "m".to_string(),
        source: None,
        lowering: Default::default(),
        functions: vec![
            Func {
                key: "driver".to_string(),
                sig: sig(AbiClass::Void, vec![]),
                param_names: vec![],
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                body: vec![Stmt::CallIndirect {
                    operand: "%fp".to_string(),
                    sig: target_sig.clone(),
                    args: vec![],
                    dest: None,
                    loc: None,
                }],
            },
            Func {
                key: "cb".to_string(),
                sig: target_sig,
                param_names: vec![],
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: true,
                body: vec![Stmt::GlobalRef {
                    global: "@G".to_string(),
                    access: Access::Ref,
                    loc: None,
                }],
            },
        ],
        globals: vec![Global {
            key: "@G".to_string(),
            file: None,
            line: None,
            is_const: false,
            mutable: true,
            exported: false,
        }],
        global_init: vec![],
    };

    let analysis = Analysis::run(&pir, &Opts::default()).unwrap();
    let driver = analysis.lookup_func("driver").unwrap();
    let global = analysis.lookup_global("@G").unwrap();

    let modrefs: Vec<_> = analysis.modref(driver).collect();
    assert_eq!(modrefs.len(), 1);
    assert_eq!(modrefs[0].func, driver);
    assert!(matches!(
        modrefs[0].global,
        pangs_api::GlobalTarget::Name(id) if id == global
    ));
    assert_eq!(modrefs[0].access, Access::Ref);
    assert_eq!(modrefs[0].witness.as_deref(), Some("cb@!noloc#0"));
}

#[test]
fn typed_modref_closure_preserves_split_between_local_and_transitive_rows() {
    let pir = Pir {
        module: "m".to_string(),
        source: None,
        lowering: Default::default(),
        functions: vec![
            Func {
                key: "main".to_string(),
                sig: sig(AbiClass::Integer, vec![]),
                param_names: vec![],
                file: None,
                line: None,
                external: false,
                exported: true,
                address_taken: false,
                body: vec![Stmt::CallDirect {
                    callee: "driver".to_string(),
                    sig: sig(AbiClass::Void, vec![]),
                    args: vec![],
                    dest: None,
                    loc: None,
                }],
            },
            Func {
                key: "driver".to_string(),
                sig: sig(AbiClass::Void, vec![]),
                param_names: vec![],
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                body: vec![Stmt::GlobalRef {
                    global: "@G".to_string(),
                    access: Access::Mod,
                    loc: None,
                }],
            },
        ],
        globals: vec![Global {
            key: "@G".to_string(),
            file: None,
            line: None,
            is_const: false,
            mutable: true,
            exported: false,
        }],
        global_init: vec![],
    };

    let analysis = Analysis::run(
        &pir,
        &Opts {
            build_mode: BuildMode::Executable,
            ..Opts::default()
        },
    )
    .unwrap();
    let main = analysis.lookup_func("main").unwrap();
    let driver = analysis.lookup_func("driver").unwrap();

    let raw_modrefs: Vec<_> = analysis.modrefs().iter().collect();
    assert_eq!(raw_modrefs.len(), 1);
    assert_eq!(raw_modrefs[0].func, driver);
    assert_eq!(raw_modrefs[0].witness.as_deref(), Some("driver@!noloc#0"));

    let main_modrefs: Vec<_> = analysis.modref(main).collect();
    assert_eq!(main_modrefs.len(), 1);
    assert_eq!(main_modrefs[0].func, main);
    assert_eq!(main_modrefs[0].witness.as_deref(), Some("driver@!noloc#0"));
}

#[test]
fn direct_external_call_taints_only_the_connected_component() {
    let pir = Pir {
        module: "m".to_string(),
        source: None,
        lowering: Default::default(),
        functions: vec![
            Func {
                key: "main".to_string(),
                sig: sig(AbiClass::Integer, vec![]),
                param_names: vec![],
                file: None,
                line: None,
                external: false,
                exported: true,
                address_taken: false,
                body: vec![Stmt::CallDirect {
                    callee: "driver".to_string(),
                    sig: sig(AbiClass::Void, vec![]),
                    args: vec![],
                    dest: None,
                    loc: None,
                }],
            },
            Func {
                key: "driver".to_string(),
                sig: sig(AbiClass::Void, vec![]),
                param_names: vec![],
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                body: vec![
                    Stmt::GlobalRef {
                        global: "@Gext".to_string(),
                        access: Access::Mod,
                        loc: None,
                    },
                    Stmt::CallDirect {
                        callee: "puts".to_string(),
                        sig: sig(AbiClass::Integer, vec![Param::Integer]),
                        args: vec![],
                        dest: None,
                        loc: None,
                    },
                ],
            },
            Func {
                key: "worker".to_string(),
                sig: sig(AbiClass::Void, vec![]),
                param_names: vec![],
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                body: vec![Stmt::GlobalRef {
                    global: "@Glocal".to_string(),
                    access: Access::Mod,
                    loc: None,
                }],
            },
        ],
        globals: vec![
            Global {
                key: "@Gext".to_string(),
                file: None,
                line: None,
                is_const: false,
                mutable: true,
                exported: false,
            },
            Global {
                key: "@Glocal".to_string(),
                file: None,
                line: None,
                is_const: false,
                mutable: true,
                exported: false,
            },
        ],
        global_init: vec![],
    };

    let analysis = Analysis::run(
        &pir,
        &Opts {
            build_mode: BuildMode::Executable,
            ..Opts::default()
        },
    )
    .unwrap();
    let main = analysis.lookup_func("main").unwrap();
    let driver = analysis.lookup_func("driver").unwrap();
    let worker = analysis.lookup_func("worker").unwrap();
    let gext = analysis.lookup_global("@Gext").unwrap();
    let glocal = analysis.lookup_global("@Glocal").unwrap();

    assert!(analysis.call_edges().iter().any(|edge| {
        edge.caller == pangs_api::Caller::Func(driver)
            && edge.callee == pangs_api::Callee::Unknown("external_callee".to_string())
    }));
    assert!(analysis.callers(main).any(unknown_caller));
    assert!(!analysis.callers(worker).any(unknown_caller));

    let tainted_component = analysis.component(analysis.component_of(main));
    assert_eq!(analysis.component_of(main), analysis.component_of(driver));
    assert_ne!(analysis.component_of(main), analysis.component_of(worker));
    assert_eq!(tainted_component.members, vec![driver, main]);
    assert_eq!(tainted_component.mutable_globals, vec![gext]);
    assert!(tainted_component.frozen);
    assert!(tainted_component.taint.iter().any(|taint| {
        taint.kind == "unknown_callee" && taint.witness.as_deref() == Some("driver@!noloc#0")
    }));
    assert!(tainted_component
        .taint
        .iter()
        .any(|taint| taint.kind == "unknown_caller" && taint.witness.is_none()));

    let rewritable_component = analysis.component(analysis.component_of(worker));
    assert_eq!(rewritable_component.members, vec![worker]);
    assert_eq!(rewritable_component.mutable_globals, vec![glocal]);
    assert!(!rewritable_component.frozen);
    assert!(rewritable_component.taint.is_empty());

    let metrics = analysis.metrics();
    assert_eq!(metrics.functions, 3);
    assert_eq!(metrics.globals, 2);
    assert_eq!(metrics.callsites, 2);
    assert_eq!(metrics.call_edges, 3);
    assert_eq!(metrics.mutable_globals_total, 2);
    assert_eq!(metrics.in_rewritable_components, 1);
}

#[test]
fn build_mode_changes_default_export_and_escape_behavior() {
    let pir = Pir {
        module: "m".to_string(),
        source: None,
        lowering: Default::default(),
        functions: vec![
            Func {
                key: "main".to_string(),
                sig: sig(AbiClass::Integer, vec![]),
                param_names: vec![],
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                body: vec![],
            },
            Func {
                key: "helper".to_string(),
                sig: sig(AbiClass::Void, vec![]),
                param_names: vec![],
                file: None,
                line: None,
                external: false,
                exported: true,
                address_taken: false,
                body: vec![],
            },
        ],
        globals: vec![Global {
            key: "@Pub".to_string(),
            file: None,
            line: None,
            is_const: false,
            mutable: true,
            exported: true,
        }],
        global_init: vec![],
    };

    let library = Analysis::run(
        &pir,
        &Opts {
            build_mode: BuildMode::Library,
            ..Opts::default()
        },
    )
    .unwrap();
    let executable = Analysis::run(
        &pir,
        &Opts {
            build_mode: BuildMode::Executable,
            ..Opts::default()
        },
    )
    .unwrap();

    let lib_main = library.lookup_func("main").unwrap();
    let lib_helper = library.lookup_func("helper").unwrap();
    let exe_main = executable.lookup_func("main").unwrap();
    let exe_helper = executable.lookup_func("helper").unwrap();
    let lib_global = library.lookup_global("@Pub").unwrap();
    let exe_global = executable.lookup_global("@Pub").unwrap();

    assert!(!library.functions()[lib_main].exported);
    assert!(library.functions()[lib_helper].exported);
    assert!(!library.callers(lib_main).any(unknown_caller));
    assert!(library.callers(lib_helper).any(unknown_caller));
    assert_eq!(library.escape(lib_global), EscapeStatus::External);

    assert!(executable.functions()[exe_main].exported);
    assert!(!executable.functions()[exe_helper].exported);
    assert!(executable.callers(exe_main).any(unknown_caller));
    assert!(!executable.callers(exe_helper).any(unknown_caller));
    assert_eq!(executable.escape(exe_global), EscapeStatus::Module);
}

#[test]
fn explicit_exports_override_build_mode_defaults() {
    let pir = Pir {
        module: "m".to_string(),
        source: None,
        lowering: Default::default(),
        functions: vec![Func {
            key: "helper".to_string(),
            sig: sig(AbiClass::Void, vec![]),
            param_names: vec![],
            file: None,
            line: None,
            external: false,
            exported: false,
            address_taken: false,
            body: vec![],
        }],
        globals: vec![Global {
            key: "@G".to_string(),
            file: None,
            line: None,
            is_const: false,
            mutable: true,
            exported: false,
        }],
        global_init: vec![],
    };

    let func_exported = Analysis::run(
        &pir,
        &Opts {
            build_mode: BuildMode::Executable,
            exports: singleton_exports("helper"),
            ..Opts::default()
        },
    )
    .unwrap();
    let global_exported = Analysis::run(
        &pir,
        &Opts {
            build_mode: BuildMode::Executable,
            exports: singleton_exports("@G"),
            ..Opts::default()
        },
    )
    .unwrap();

    let helper = func_exported.lookup_func("helper").unwrap();
    let global = global_exported.lookup_global("@G").unwrap();

    assert!(func_exported.functions()[helper].exported);
    assert!(func_exported.callers(helper).any(unknown_caller));
    assert_eq!(global_exported.escape(global), EscapeStatus::External);
}

#[test]
fn steens_narrows_indirect_targets_below_fsa() {
    let pir = Pir::from_path(m1_4_fixture("steens_escape_icall.pir.json")).unwrap();

    let conservative = Analysis::run(&pir, &Opts::default()).unwrap();
    let steens = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Steens,
            build_mode: BuildMode::Library,
            ..Opts::default()
        },
    )
    .unwrap();

    let conservative_targets = conservative
        .call_edges()
        .iter()
        .filter_map(|edge| match (&edge.caller, &edge.callee) {
            (pangs_api::Caller::Func(_), pangs_api::Callee::Func(id))
                if edge.kind == pangs_api::CallKind::Indirect =>
            {
                Some(conservative.functions()[*id].key.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let steens_targets = steens
        .call_edges()
        .iter()
        .filter_map(|edge| match (&edge.caller, &edge.callee) {
            (pangs_api::Caller::Func(_), pangs_api::Callee::Func(id))
                if edge.kind == pangs_api::CallKind::Indirect =>
            {
                Some(steens.functions()[*id].key.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();

    assert_eq!(
        conservative_targets,
        ["cb".to_string(), "other".to_string()]
            .into_iter()
            .collect()
    );
    assert_eq!(steens_targets, ["cb".to_string()].into_iter().collect());
    assert!(steens.call_edges().iter().any(|edge| {
        edge.kind == pangs_api::CallKind::Indirect
            && matches!(edge.callee, pangs_api::Callee::Unknown(_))
    }));
    assert!(steens.metrics().partition_count > 0);
    assert_eq!(steens.metrics().rounds, 1);
}

#[test]
fn steens_uses_escape_bits_for_unknown_callers_and_never_written() {
    let pir = Pir::from_path(m1_4_fixture("steens_escape_icall.pir.json")).unwrap();
    let analysis = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Steens,
            build_mode: BuildMode::Library,
            ..Opts::default()
        },
    )
    .unwrap();

    let cb = analysis.lookup_func("cb").unwrap();
    let other = analysis.lookup_func("other").unwrap();
    let exported_slot = analysis.lookup_global("@CB").unwrap();
    let local = analysis.lookup_global("@Local").unwrap();

    assert!(analysis.callers(cb).any(unknown_caller));
    assert!(!analysis.callers(other).any(unknown_caller));
    assert_eq!(analysis.escape(exported_slot), EscapeStatus::External);
    assert_eq!(analysis.escape(local), EscapeStatus::Module);
    assert!(!analysis.globals()[exported_slot].never_written);
    assert!(analysis.globals()[local].never_written);
}

#[test]
fn steens_ptrtoint_marks_only_the_pointee_global_as_external() {
    let pir = Pir::from_path(m1_4_fixture("ptrtoint_escape.pir.json")).unwrap();
    let analysis = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Steens,
            build_mode: BuildMode::Library,
            ..Opts::default()
        },
    )
    .unwrap();

    let global = analysis.lookup_global("@G").unwrap();
    assert_eq!(analysis.escape(global), EscapeStatus::External);
    assert!(!analysis.globals()[global].never_written);
    assert!(analysis.call_edges().is_empty());
}

#[test]
fn steens_inttoptr_keeps_unknown_indirect_callee_without_concrete_targets() {
    let pir = Pir::from_path(m1_4_fixture("inttoptr_unknown_call.pir.json")).unwrap();
    let analysis = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Steens,
            build_mode: BuildMode::Library,
            ..Opts::default()
        },
    )
    .unwrap();

    assert!(!analysis.call_edges().iter().any(|edge| {
        edge.kind == pangs_api::CallKind::Indirect
            && matches!(edge.callee, pangs_api::Callee::Func(_))
    }));
    assert!(analysis.call_edges().iter().any(|edge| {
        edge.kind == pangs_api::CallKind::Indirect
            && matches!(edge.callee, pangs_api::Callee::Unknown(_))
    }));
}

#[test]
fn steens_external_call_escapes_only_passed_pointer_targets() {
    let pir = Pir::from_path(m1_4_fixture("external_call_arg_escape.pir.json")).unwrap();
    let analysis = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Steens,
            build_mode: BuildMode::Library,
            ..Opts::default()
        },
    )
    .unwrap();

    let esc = analysis.lookup_global("@Esc").unwrap();
    let local = analysis.lookup_global("@Local").unwrap();
    let ext_decl = analysis.lookup_func("ext_decl").unwrap();

    assert!(analysis.callers(ext_decl).any(unknown_caller));
    assert_eq!(analysis.escape(esc), EscapeStatus::External);
    assert_eq!(analysis.escape(local), EscapeStatus::Module);
    assert!(!analysis.globals()[esc].never_written);
    assert!(analysis.globals()[local].never_written);
}

#[test]
fn steens_unknown_operand_and_result_seed_escape_and_unknown_icall() {
    let pir = Pir::from_path(m1_4_fixture("unknown_op_escape.pir.json")).unwrap();
    let analysis = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Steens,
            build_mode: BuildMode::Library,
            ..Opts::default()
        },
    )
    .unwrap();

    let esc = analysis.lookup_global("@Esc").unwrap();
    let local = analysis.lookup_global("@Local").unwrap();

    assert!(analysis.call_edges().iter().any(|edge| {
        edge.kind == pangs_api::CallKind::Indirect
            && matches!(edge.callee, pangs_api::Callee::Unknown(_))
    }));
    assert_eq!(analysis.escape(esc), EscapeStatus::External);
    assert_eq!(analysis.escape(local), EscapeStatus::Module);
    assert!(!analysis.globals()[esc].never_written);
    assert!(analysis.globals()[local].never_written);
}

#[test]
fn steens_escaped_function_return_marks_return_pointee_escaped() {
    let pir = Pir::from_path(m1_4_fixture("escaped_fn_return_escape.pir.json")).unwrap();
    let analysis = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Steens,
            build_mode: BuildMode::Library,
            ..Opts::default()
        },
    )
    .unwrap();

    let cb = analysis.lookup_func("cb").unwrap();
    let slot = analysis.lookup_global("@CB").unwrap();
    let ret = analysis.lookup_global("@Ret").unwrap();
    let local = analysis.lookup_global("@Local").unwrap();

    assert!(analysis.callers(cb).any(unknown_caller));
    assert_eq!(analysis.escape(slot), EscapeStatus::External);
    assert_eq!(analysis.escape(ret), EscapeStatus::External);
    assert_eq!(analysis.escape(local), EscapeStatus::Module);
    assert!(!analysis.globals()[slot].never_written);
    assert!(!analysis.globals()[ret].never_written);
    assert!(analysis.globals()[local].never_written);
}

#[test]
fn steens_store_through_unknown_pointer_escapes_the_stored_target() {
    let pir = Pir::from_path(m1_4_fixture("store_through_unknown_escape.pir.json")).unwrap();
    let analysis = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Steens,
            build_mode: BuildMode::Library,
            ..Opts::default()
        },
    )
    .unwrap();

    let esc = analysis.lookup_global("@Esc").unwrap();
    let local = analysis.lookup_global("@Local").unwrap();

    assert_eq!(analysis.escape(esc), EscapeStatus::External);
    assert_eq!(analysis.escape(local), EscapeStatus::Module);
    assert!(!analysis.globals()[esc].never_written);
    assert!(analysis.globals()[local].never_written);
}

#[test]
fn steens_escaped_function_parameter_binding_escapes_stored_targets() {
    let pir = Pir::from_path(m1_4_fixture("escaped_fn_param_escape.pir.json")).unwrap();
    let analysis = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Steens,
            build_mode: BuildMode::Library,
            ..Opts::default()
        },
    )
    .unwrap();

    let cb = analysis.lookup_func("cb").unwrap();
    let slot = analysis.lookup_global("@CB").unwrap();
    let esc = analysis.lookup_global("@Esc").unwrap();
    let local = analysis.lookup_global("@Local").unwrap();

    assert!(analysis.callers(cb).any(unknown_caller));
    assert_eq!(analysis.escape(slot), EscapeStatus::External);
    assert_eq!(analysis.escape(esc), EscapeStatus::External);
    assert_eq!(analysis.escape(local), EscapeStatus::Module);
    assert!(!analysis.globals()[slot].never_written);
    assert!(!analysis.globals()[esc].never_written);
    assert!(analysis.globals()[local].never_written);
}

#[test]
fn steens_unfreezes_address_taken_but_unescaped_components() {
    let pir = Pir::from_path(m1_4_fixture("address_taken_local_only.pir.json")).unwrap();
    let conservative = Analysis::run(&pir, &Opts::default()).unwrap();
    let steens = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Steens,
            build_mode: BuildMode::Library,
            ..Opts::default()
        },
    )
    .unwrap();

    let cb_conservative = conservative.lookup_func("cb").unwrap();
    let cb_steens = steens.lookup_func("cb").unwrap();

    assert!(conservative.callers(cb_conservative).any(unknown_caller));
    assert!(!steens.callers(cb_steens).any(unknown_caller));
    assert_eq!(conservative.metrics().mutable_globals_total, 1);
    assert_eq!(conservative.metrics().in_rewritable_components, 0);
    assert_eq!(steens.metrics().mutable_globals_total, 1);
    assert_eq!(steens.metrics().in_rewritable_components, 1);
    assert!(
        conservative
            .component(conservative.component_of(cb_conservative))
            .frozen
    );
    assert!(!steens.component(steens.component_of(cb_steens)).frozen);
}

#[test]
fn audit_inline_asm_freezes_an_otherwise_local_component() {
    let pir = Pir {
        module: "m".to_string(),
        source: None,
        lowering: Default::default(),
        functions: vec![Func {
            key: "asm_only".to_string(),
            sig: sig(AbiClass::Void, vec![]),
            param_names: vec![],
            file: None,
            line: None,
            external: false,
            exported: false,
            address_taken: false,
            body: vec![Stmt::Unknown {
                op: "call".to_string(),
                operands: vec![],
                results: vec![],
                reason: "inline_asm".to_string(),
                loc: None,
            }],
        }],
        globals: vec![],
        global_init: vec![],
    };

    let analysis = Analysis::run(&pir, &Opts::default()).unwrap();
    assert_eq!(analysis.audit_findings().len(), 1);
    assert_eq!(analysis.audit_findings()[0].kind, "inline_asm");
    assert_eq!(
        analysis.audit_findings()[0].affected,
        vec!["function:asm_only"]
    );
    assert_eq!(analysis.metrics().audit_findings, 1);
    let component =
        analysis.component(analysis.component_of(analysis.lookup_func("asm_only").unwrap()));
    assert!(component.frozen);
    assert!(component
        .taint
        .iter()
        .any(|taint| taint.kind == "inline_asm"
            && taint.witness.as_deref() == Some("asm_only@!noloc#0")));
}

#[test]
fn audit_surface_fixture_reports_varargs_and_boundary_findings() {
    let pir = Pir::from_path(m1_5_fixture("audit_surface.pir.json")).unwrap();
    let analysis = Analysis::run(&pir, &Opts::default()).unwrap();

    let kinds = analysis
        .audit_findings()
        .iter()
        .map(|finding| finding.kind.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        kinds,
        vec![
            "dlopen_dlsym",
            "dlopen_dlsym",
            "fnptr_varargs_external",
            "inline_asm",
            "setjmp_longjmp",
            "setjmp_longjmp"
        ]
    );
    assert!(analysis.audit_findings().iter().any(|finding| {
        finding.kind == "fnptr_varargs_external"
            && finding.affected == vec!["function:cb".to_string()]
    }));
    assert_eq!(analysis.metrics().audit_findings, 6);
}

#[test]
fn vararg_audit_taxonomy_splits_callsite_shape_without_changing_taint() {
    let vararg_sig = Signature {
        ret: AbiClass::Void,
        params: vec![Param::Integer],
        vararg: true,
        cc: "ccc".to_string(),
    };
    let pir = Pir {
        module: "m4_vararg_taxonomy".to_string(),
        source: None,
        lowering: Default::default(),
        functions: vec![
            Func {
                key: "external_sink".to_string(),
                sig: vararg_sig.clone(),
                param_names: vec![],
                file: None,
                line: None,
                external: true,
                exported: false,
                address_taken: false,
                body: vec![],
            },
            Func {
                key: "safe_internal_sink".to_string(),
                sig: vararg_sig.clone(),
                param_names: vec![],
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                body: vec![],
            },
            Func {
                key: "unsafe_internal_sink".to_string(),
                sig: vararg_sig.clone(),
                param_names: vec![],
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                body: vec![Stmt::Unknown {
                    op: "va_arg".to_string(),
                    operands: vec!["%ap".to_string()],
                    results: vec!["%next".to_string()],
                    reason: "va_arg".to_string(),
                    loc: None,
                }],
            },
            Func {
                key: "log_debug".to_string(),
                sig: vararg_sig.clone(),
                param_names: vec![],
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                body: vec![Stmt::Unknown {
                    op: "va_arg".to_string(),
                    operands: vec!["%ap".to_string()],
                    results: vec!["%next".to_string()],
                    reason: "va_arg".to_string(),
                    loc: None,
                }],
            },
            Func {
                key: "cb".to_string(),
                sig: sig(AbiClass::Void, vec![]),
                param_names: vec![],
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: true,
                body: vec![],
            },
            Func {
                key: "driver".to_string(),
                sig: sig(AbiClass::Void, vec![]),
                param_names: vec![],
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                body: vec![
                    Stmt::CallDirect {
                        callee: "external_sink".to_string(),
                        sig: vararg_sig.clone(),
                        args: vec!["%tag".to_string(), "cb".to_string()],
                        dest: None,
                        loc: None,
                    },
                    Stmt::CallDirect {
                        callee: "safe_internal_sink".to_string(),
                        sig: vararg_sig.clone(),
                        args: vec!["%tag".to_string(), "cb".to_string()],
                        dest: None,
                        loc: None,
                    },
                    Stmt::CallDirect {
                        callee: "unsafe_internal_sink".to_string(),
                        sig: vararg_sig.clone(),
                        args: vec!["%tag".to_string(), "cb".to_string()],
                        dest: None,
                        loc: None,
                    },
                    Stmt::CallDirect {
                        callee: "log_debug".to_string(),
                        sig: vararg_sig.clone(),
                        args: vec!["%tag".to_string(), "cb".to_string()],
                        dest: None,
                        loc: None,
                    },
                    Stmt::CallIndirect {
                        operand: "%callee".to_string(),
                        sig: vararg_sig,
                        args: vec!["%tag".to_string(), "cb".to_string()],
                        dest: None,
                        loc: None,
                    },
                ],
            },
        ],
        globals: vec![],
        global_init: vec![],
    };
    let analysis = Analysis::run(&pir, &Opts::default()).unwrap();
    let kinds = analysis
        .audit_findings()
        .iter()
        .map(|finding| finding.kind.as_str())
        .collect::<BTreeSet<_>>();

    assert!(kinds.contains("fnptr_varargs_external"));
    assert!(kinds.contains("fnptr_varargs_internal_unmodeled"));
    assert!(kinds.contains("fnptr_varargs_indirect"));
    assert_eq!(analysis.metrics().audit_findings, 3);
    let driver = analysis.lookup_func("driver").unwrap();
    let component = analysis.component(analysis.component_of(driver));
    assert!(component.frozen);
    for kind in [
        "fnptr_varargs_external",
        "fnptr_varargs_internal_unmodeled",
        "fnptr_varargs_indirect",
    ] {
        assert!(component.taint.iter().any(|taint| taint.kind == kind));
    }
    assert_eq!(
        component
            .taint
            .iter()
            .filter(|taint| taint.kind == "fnptr_varargs_internal_unmodeled")
            .count(),
        1
    );
}

#[test]
fn steens_only_audits_int_punning_when_it_reaches_function_pointers() {
    let ptr_only = Pir::from_path(m1_4_fixture("ptrtoint_escape.pir.json")).unwrap();
    let ptr_only_analysis = Analysis::run(
        &ptr_only,
        &Opts {
            stage: Stage::Steens,
            build_mode: BuildMode::Library,
            ..Opts::default()
        },
    )
    .unwrap();
    assert!(!ptr_only_analysis
        .audit_findings()
        .iter()
        .any(|finding| finding.kind == "fnptr_ptrtoint" || finding.kind == "fnptr_inttoptr"));

    let fnptr = Pir::from_path(m1_5_fixture("fnptr_int_punning.pir.json")).unwrap();
    let fnptr_analysis = Analysis::run(
        &fnptr,
        &Opts {
            stage: Stage::Steens,
            build_mode: BuildMode::Library,
            ..Opts::default()
        },
    )
    .unwrap();
    let kinds = fnptr_analysis
        .audit_findings()
        .iter()
        .map(|finding| finding.kind.as_str())
        .collect::<Vec<_>>();
    assert!(kinds.contains(&"fnptr_ptrtoint"));
    assert!(kinds.contains(&"fnptr_inttoptr"));
    assert!(fnptr_analysis.metrics().audit_findings >= 2);
    let component = fnptr_analysis
        .component(fnptr_analysis.component_of(fnptr_analysis.lookup_func("driver").unwrap()));
    assert!(component
        .taint
        .iter()
        .any(|taint| taint.kind == "fnptr_ptrtoint"
            && taint.witness.as_deref() == Some("driver@!noloc#0")));
    assert!(component
        .taint
        .iter()
        .any(|taint| taint.kind == "fnptr_inttoptr"
            && taint.witness.as_deref() == Some("driver@!noloc#0")));
}

#[test]
fn audit_memops_on_fnptr_aggregates_are_reported_but_scalar_fnptr_memops_are_not() {
    let pir = Pir::from_path(m1_5_fixture("fnptr_aggregate_memops.pir.json")).unwrap();
    let analysis = Analysis::run(&pir, &Opts::default()).unwrap();
    let kinds = analysis
        .audit_findings()
        .iter()
        .map(|finding| finding.kind.as_str())
        .collect::<Vec<_>>();
    assert!(kinds.contains(&"memcpy_fnptr_aggregate"));
    assert!(kinds.contains(&"memset_fnptr_aggregate"));
    assert!(analysis.audit_findings().iter().any(|finding| {
        finding.kind == "memcpy_fnptr_aggregate"
            && finding
                .affected
                .iter()
                .any(|value| value == "value:%agg" || value == "value:%agg_copy")
    }));
    let component =
        analysis.component(analysis.component_of(analysis.lookup_func("driver").unwrap()));
    assert!(component
        .taint
        .iter()
        .any(|taint| taint.kind == "memcpy_fnptr_aggregate"));
    assert!(component
        .taint
        .iter()
        .any(|taint| taint.kind == "memset_fnptr_aggregate"));

    let scalar = Pir {
        module: "m".to_string(),
        source: None,
        lowering: Default::default(),
        functions: vec![Func {
            key: "driver".to_string(),
            sig: sig(AbiClass::Void, vec![]),
            param_names: vec![],
            file: None,
            line: None,
            external: false,
            exported: false,
            address_taken: false,
            body: vec![
                Stmt::Alloca {
                    dest: "%slot".to_string(),
                    ty: "void ()*".to_string(),
                    loc: None,
                },
                Stmt::Memcpy {
                    dst: "%slot".to_string(),
                    src: "%slot".to_string(),
                    bytes: Some(8),
                    loc: None,
                },
                Stmt::Memset {
                    dst: "%slot".to_string(),
                    value: "%zero".to_string(),
                    bytes: Some(8),
                    loc: None,
                },
            ],
        }],
        globals: vec![],
        global_init: vec![],
    };
    let scalar_analysis = Analysis::run(&scalar, &Opts::default()).unwrap();
    assert!(!scalar_analysis
        .audit_findings()
        .iter()
        .any(|finding| finding.kind == "memcpy_fnptr_aggregate"
            || finding.kind == "memset_fnptr_aggregate"));
}

#[test]
fn steens_detects_vararg_function_pointers_through_local_values() {
    let pir = Pir::from_path(m1_5_fixture("vararg_fnptr_flow.pir.json")).unwrap();
    let analysis = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Steens,
            build_mode: BuildMode::Library,
            ..Opts::default()
        },
    )
    .unwrap();

    let cb = analysis.lookup_func("cb").unwrap();
    assert!(analysis.callers(cb).any(unknown_caller));
    assert!(analysis
        .audit_findings()
        .iter()
        .any(|finding| finding.kind == "fnptr_varargs_internal_unmodeled"
            && finding.affected == vec!["value:%fp".to_string()]));
    let driver = analysis.lookup_func("driver").unwrap();
    let component = analysis.component(analysis.component_of(driver));
    assert!(component
        .taint
        .iter()
        .any(|taint| taint.kind == "fnptr_varargs_internal_unmodeled"
            && taint.witness.as_deref() == Some("driver@!noloc#0")));
}

#[test]
fn steens_modref_is_a_superset_of_syntactic_and_exports_aliased_unknown_rows() {
    let pir = Pir::from_path(m1_6_fixture("aliased_unknown_modref.pir.json")).unwrap();
    let conservative = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Conservative,
            build_mode: BuildMode::Executable,
            ..Opts::default()
        },
    )
    .unwrap();
    let steens = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Steens,
            build_mode: BuildMode::Executable,
            ..Opts::default()
        },
    )
    .unwrap();

    let main = steens.lookup_func("main").unwrap();
    let direct = steens.lookup_global("@Direct").unwrap();
    let aliased = steens.lookup_global("@Aliased").unwrap();

    let conservative_rows: Vec<_> = conservative
        .modrefs()
        .iter()
        .map(|mr| {
            (
                conservative.functions()[mr.func].key.clone(),
                match &mr.global {
                    pangs_api::GlobalTarget::Name(id) => conservative.globals()[*id].key.clone(),
                    pangs_api::GlobalTarget::Unknown(reason) => reason.clone(),
                },
                mr.access,
                mr.via,
                mr.witness.clone(),
            )
        })
        .collect();
    let steens_rows: Vec<_> = steens
        .modrefs()
        .iter()
        .map(|mr| {
            (
                steens.functions()[mr.func].key.clone(),
                match &mr.global {
                    pangs_api::GlobalTarget::Name(id) => steens.globals()[*id].key.clone(),
                    pangs_api::GlobalTarget::Unknown(reason) => reason.clone(),
                },
                mr.access,
                mr.via,
                mr.witness.clone(),
            )
        })
        .collect();
    for row in conservative_rows {
        assert!(steens_rows.contains(&row));
    }

    let raw_modrefs: Vec<_> = steens.modrefs().iter().collect();
    assert!(raw_modrefs.iter().any(|mr| {
        mr.func == main
            && mr.global == pangs_api::GlobalTarget::Name(direct)
            && mr.access == Access::Ref
            && mr.via == pangs_api::Via::Direct
            && mr.witness.as_deref() == Some("main@m1_6.c:1:1#0")
    }));
    assert!(raw_modrefs.iter().any(|mr| {
        mr.func == main
            && mr.global == pangs_api::GlobalTarget::Name(aliased)
            && mr.access == Access::Ref
            && mr.via == pangs_api::Via::Aliased
            && mr.witness.as_deref() == Some("main@m1_6.c:3:1#0")
    }));
    assert!(raw_modrefs.iter().any(|mr| {
        mr.func == main
            && mr.global == pangs_api::GlobalTarget::Name(aliased)
            && mr.access == Access::Mod
            && mr.via == pangs_api::Via::Aliased
            && mr.witness.as_deref() == Some("main@m1_6.c:4:1#0")
    }));
    assert!(raw_modrefs.iter().any(|mr| {
        mr.func == main
            && mr.global == pangs_api::GlobalTarget::Unknown("omega_load".to_string())
            && mr.access == Access::Ref
            && mr.via == pangs_api::Via::Unknown
            && mr.witness.as_deref() == Some("main@m1_6.c:6:1#0")
    }));
    assert!(raw_modrefs.iter().any(|mr| {
        mr.func == main
            && mr.global == pangs_api::GlobalTarget::Unknown("omega_store".to_string())
            && mr.access == Access::Mod
            && mr.via == pangs_api::Via::Unknown
            && mr.witness.as_deref() == Some("main@m1_6.c:7:1#0")
    }));

    let component = steens
        .components()
        .iter()
        .find(|component| component.members == vec![main])
        .unwrap();
    assert!(component.frozen);
    assert!(component.taint.iter().any(|taint| {
        taint.kind == "unknown_global" && taint.witness.as_deref() == Some("main@m1_6.c:6:1#0")
    }));
}

#[test]
fn steens_memcpy_modref_exports_aliased_direct_symbol_and_unknown_rows() {
    let fixture = m1_6_fixture("memcpy_modref.pir.json");
    let analysis = Analysis::run(
        &Pir::from_path(&fixture).unwrap(),
        &Opts {
            stage: Stage::Steens,
            build_mode: BuildMode::Executable,
            ..Opts::default()
        },
    )
    .unwrap();

    let main = analysis.lookup_func("main").unwrap();
    let dst_aliased = analysis.lookup_global("@DstAliased").unwrap();
    let src_aliased = analysis.lookup_global("@SrcAliased").unwrap();
    let direct_dst = analysis.lookup_global("@DirectDst").unwrap();
    let direct_src = analysis.lookup_global("@DirectSrc").unwrap();
    let raw_modrefs: Vec<_> = analysis.modrefs().iter().collect();

    assert!(raw_modrefs.iter().any(|mr| {
        mr.func == main
            && mr.global == pangs_api::GlobalTarget::Name(src_aliased)
            && mr.access == Access::Ref
            && mr.via == pangs_api::Via::Aliased
            && mr.witness.as_deref() == Some("main@m1_6_memcpy.c:3:1#0")
    }));
    assert!(raw_modrefs.iter().any(|mr| {
        mr.func == main
            && mr.global == pangs_api::GlobalTarget::Name(dst_aliased)
            && mr.access == Access::Mod
            && mr.via == pangs_api::Via::Aliased
            && mr.witness.as_deref() == Some("main@m1_6_memcpy.c:3:1#0")
    }));
    assert!(raw_modrefs.iter().any(|mr| {
        mr.func == main
            && mr.global == pangs_api::GlobalTarget::Name(direct_src)
            && mr.access == Access::Ref
            && mr.via == pangs_api::Via::Aliased
            && mr.witness.as_deref() == Some("main@m1_6_memcpy.c:7:1#0")
    }));
    assert!(raw_modrefs.iter().any(|mr| {
        mr.func == main
            && mr.global == pangs_api::GlobalTarget::Name(direct_dst)
            && mr.access == Access::Mod
            && mr.via == pangs_api::Via::Aliased
            && mr.witness.as_deref() == Some("main@m1_6_memcpy.c:7:1#0")
    }));
    assert!(raw_modrefs.iter().any(|mr| {
        mr.func == main
            && mr.global == pangs_api::GlobalTarget::Unknown("omega_load".to_string())
            && mr.access == Access::Ref
            && mr.via == pangs_api::Via::Unknown
            && mr.witness.as_deref() == Some("main@m1_6_memcpy.c:6:1#0")
    }));
    assert!(raw_modrefs.iter().any(|mr| {
        mr.func == main
            && mr.global == pangs_api::GlobalTarget::Unknown("omega_store".to_string())
            && mr.access == Access::Mod
            && mr.via == pangs_api::Via::Unknown
            && mr.witness.as_deref() == Some("main@m1_6_memcpy.c:6:1#0")
    }));

    let component = analysis
        .components()
        .iter()
        .find(|component| component.members == vec![main])
        .unwrap();
    assert!(component.frozen);
    assert!(component.taint.iter().any(|taint| {
        taint.kind == "unknown_global"
            && taint.witness.as_deref() == Some("main@m1_6_memcpy.c:6:1#0")
    }));
}

#[test]
fn steens_modref_closure_carries_pointer_rows_through_direct_and_indirect_calls() {
    let fixture = m1_6_fixture("transitive_icall_modref.pir.json");
    let analysis = Analysis::run(
        &Pir::from_path(&fixture).unwrap(),
        &Opts {
            stage: Stage::Steens,
            build_mode: BuildMode::Executable,
            ..Opts::default()
        },
    )
    .unwrap();

    let main = analysis.lookup_func("main").unwrap();
    let setup = analysis.lookup_func("setup").unwrap();
    let target = analysis.lookup_func("target").unwrap();
    let other = analysis.lookup_func("other").unwrap();
    let aliased = analysis.lookup_global("@Aliased").unwrap();
    let noise = analysis.lookup_global("@Noise").unwrap();

    assert!(analysis.call_edges().iter().any(|edge| {
        edge.caller == pangs_api::Caller::Func(setup)
            && edge.callee == pangs_api::Callee::Func(target)
            && edge.tier == pangs_api::Tier::Steens
    }));
    assert!(!analysis.call_edges().iter().any(|edge| {
        edge.caller == pangs_api::Caller::Func(setup)
            && edge.callee == pangs_api::Callee::Func(other)
            && edge.tier == pangs_api::Tier::Steens
    }));

    let raw_modrefs: Vec<_> = analysis.modrefs().iter().collect();
    assert!(raw_modrefs
        .iter()
        .all(|mr| mr.func == target || mr.func == other));
    assert!(raw_modrefs.iter().any(|mr| {
        mr.func == target
            && mr.global == pangs_api::GlobalTarget::Name(aliased)
            && mr.access == Access::Ref
            && mr.via == pangs_api::Via::Aliased
            && mr.witness.as_deref() == Some("target@m1_6_icall.c:21:1#0")
    }));
    assert!(raw_modrefs.iter().any(|mr| {
        mr.func == target
            && mr.global == pangs_api::GlobalTarget::Unknown("omega_store".to_string())
            && mr.access == Access::Mod
            && mr.via == pangs_api::Via::Unknown
            && mr.witness.as_deref() == Some("target@m1_6_icall.c:23:1#0")
    }));
    assert!(raw_modrefs.iter().any(|mr| {
        mr.func == other
            && mr.global == pangs_api::GlobalTarget::Name(noise)
            && mr.access == Access::Mod
            && mr.via == pangs_api::Via::Direct
            && mr.witness.as_deref() == Some("other@m1_6_icall.c:30:1#0")
    }));

    let setup_modrefs: Vec<_> = analysis.modref(setup).collect();
    assert!(setup_modrefs.iter().any(|mr| {
        mr.func == setup
            && mr.global == pangs_api::GlobalTarget::Name(aliased)
            && mr.access == Access::Ref
            && mr.via == pangs_api::Via::Aliased
            && mr.witness.as_deref() == Some("target@m1_6_icall.c:21:1#0")
    }));
    assert!(setup_modrefs.iter().any(|mr| {
        mr.func == setup
            && mr.global == pangs_api::GlobalTarget::Unknown("omega_store".to_string())
            && mr.access == Access::Mod
            && mr.via == pangs_api::Via::Unknown
            && mr.witness.as_deref() == Some("target@m1_6_icall.c:23:1#0")
    }));
    assert!(!setup_modrefs.iter().any(|mr| {
        mr.global == pangs_api::GlobalTarget::Name(noise)
            && mr.witness.as_deref() == Some("other@m1_6_icall.c:30:1#0")
    }));

    let main_modrefs: Vec<_> = analysis.modref(main).collect();
    assert!(main_modrefs.iter().any(|mr| {
        mr.func == main
            && mr.global == pangs_api::GlobalTarget::Name(aliased)
            && mr.access == Access::Ref
            && mr.via == pangs_api::Via::Aliased
            && mr.witness.as_deref() == Some("target@m1_6_icall.c:21:1#0")
    }));
    assert!(main_modrefs.iter().any(|mr| {
        mr.func == main
            && mr.global == pangs_api::GlobalTarget::Unknown("omega_store".to_string())
            && mr.access == Access::Mod
            && mr.via == pangs_api::Via::Unknown
            && mr.witness.as_deref() == Some("target@m1_6_icall.c:23:1#0")
    }));
    assert!(!main_modrefs.iter().any(|mr| {
        mr.global == pangs_api::GlobalTarget::Name(noise)
            && mr.witness.as_deref() == Some("other@m1_6_icall.c:30:1#0")
    }));
}

#[test]
fn steens_memset_modref_exports_direct_aliased_and_unknown_store_rows() {
    let fixture = m1_6_fixture("memset_modref.pir.json");
    let analysis = Analysis::run(
        &Pir::from_path(&fixture).unwrap(),
        &Opts {
            stage: Stage::Steens,
            build_mode: BuildMode::Executable,
            ..Opts::default()
        },
    )
    .unwrap();

    let main = analysis.lookup_func("main").unwrap();
    let aliased = analysis.lookup_global("@Aliased").unwrap();
    let direct_dst = analysis.lookup_global("@DirectDst").unwrap();
    let raw_modrefs: Vec<_> = analysis.modrefs().iter().collect();

    assert!(raw_modrefs.iter().any(|mr| {
        mr.func == main
            && mr.global == pangs_api::GlobalTarget::Name(aliased)
            && mr.access == Access::Mod
            && mr.via == pangs_api::Via::Aliased
            && mr.witness.as_deref() == Some("main@m1_6_memset.c:2:1#0")
    }));
    assert!(raw_modrefs.iter().any(|mr| {
        mr.func == main
            && mr.global == pangs_api::GlobalTarget::Unknown("omega_store".to_string())
            && mr.access == Access::Mod
            && mr.via == pangs_api::Via::Unknown
            && mr.witness.as_deref() == Some("main@m1_6_memset.c:4:1#0")
    }));
    assert!(raw_modrefs.iter().any(|mr| {
        mr.func == main
            && mr.global == pangs_api::GlobalTarget::Name(direct_dst)
            && mr.access == Access::Mod
            && mr.via == pangs_api::Via::Aliased
            && mr.witness.as_deref() == Some("main@m1_6_memset.c:5:1#0")
    }));
    assert!(!raw_modrefs.iter().any(|mr| mr.access == Access::Ref));

    let component = analysis
        .components()
        .iter()
        .find(|component| component.members == vec![main])
        .unwrap();
    assert!(component.frozen);
    assert!(component.taint.iter().any(|taint| {
        taint.kind == "unknown_global"
            && taint.witness.as_deref() == Some("main@m1_6_memset.c:4:1#0")
    }));
}

#[test]
fn steens_alias_rows_increase_rewritable_coverage_over_conservative() {
    let fixture = m1_6_fixture("aliased_coverage_gain.pir.json");
    let conservative = Analysis::run(
        &Pir::from_path(&fixture).unwrap(),
        &Opts {
            stage: Stage::Conservative,
            build_mode: BuildMode::Executable,
            ..Opts::default()
        },
    )
    .unwrap();
    let steens = Analysis::run(
        &Pir::from_path(&fixture).unwrap(),
        &Opts {
            stage: Stage::Steens,
            build_mode: BuildMode::Executable,
            ..Opts::default()
        },
    )
    .unwrap();

    let worker_cons = conservative.lookup_func("worker").unwrap();
    let worker_steens = steens.lookup_func("worker").unwrap();
    let g_steens = steens.lookup_global("@G").unwrap();

    assert!(conservative.modrefs().is_empty());
    let cons_component = conservative.component(conservative.component_of(worker_cons));
    assert!(!cons_component.frozen);
    assert!(cons_component.mutable_globals.is_empty());
    assert_eq!(conservative.metrics().mutable_globals_total, 1);
    assert_eq!(conservative.metrics().in_rewritable_components, 0);

    let steens_rows: Vec<_> = steens.modrefs().iter().collect();
    assert!(steens_rows.iter().any(|mr| {
        mr.func == worker_steens
            && mr.global == pangs_api::GlobalTarget::Name(g_steens)
            && mr.access == Access::Ref
            && mr.via == pangs_api::Via::Aliased
            && mr.witness.as_deref() == Some("worker@m1_6_cover.c:2:1#0")
    }));
    let steens_component = steens.component(steens.component_of(worker_steens));
    assert!(!steens_component.frozen);
    assert_eq!(steens_component.mutable_globals, vec![g_steens]);
    assert_eq!(steens.metrics().mutable_globals_total, 1);
    assert_eq!(steens.metrics().in_rewritable_components, 1);
}

#[test]
fn steens_alias_rows_improve_split_component_coverage_over_conservative() {
    let fixture = m1_6_fixture("split_coverage_gain.pir.json");
    let conservative = Analysis::run(
        &Pir::from_path(&fixture).unwrap(),
        &Opts {
            stage: Stage::Conservative,
            build_mode: BuildMode::Executable,
            ..Opts::default()
        },
    )
    .unwrap();
    let steens = Analysis::run(
        &Pir::from_path(&fixture).unwrap(),
        &Opts {
            stage: Stage::Steens,
            build_mode: BuildMode::Executable,
            ..Opts::default()
        },
    )
    .unwrap();

    let driver_cons = conservative.lookup_func("driver").unwrap();
    let worker_cons = conservative.lookup_func("worker").unwrap();
    let driver_steens = steens.lookup_func("driver").unwrap();
    let worker_steens = steens.lookup_func("worker").unwrap();
    let rewrite_steens = steens.lookup_global("@Rewrite").unwrap();

    let cons_driver_component = conservative.component(conservative.component_of(driver_cons));
    assert!(cons_driver_component.frozen);
    let cons_worker_component = conservative.component(conservative.component_of(worker_cons));
    assert!(!cons_worker_component.frozen);
    assert!(cons_worker_component.mutable_globals.is_empty());
    assert_eq!(conservative.metrics().mutable_globals_total, 2);
    assert_eq!(conservative.metrics().in_rewritable_components, 0);

    let steens_driver_component = steens.component(steens.component_of(driver_steens));
    assert!(steens_driver_component.frozen);
    let steens_worker_component = steens.component(steens.component_of(worker_steens));
    assert!(!steens_worker_component.frozen);
    assert_eq!(
        steens_worker_component.mutable_globals,
        vec![rewrite_steens]
    );
    assert!(steens.modrefs().iter().any(|mr| {
        mr.func == worker_steens
            && mr.global == pangs_api::GlobalTarget::Name(rewrite_steens)
            && mr.access == Access::Ref
            && mr.via == pangs_api::Via::Aliased
            && mr.witness.as_deref() == Some("worker@m1_6_split.c:11:1#0")
    }));
    assert_eq!(steens.metrics().mutable_globals_total, 2);
    assert_eq!(steens.metrics().in_rewritable_components, 1);
}

#[test]
fn transitive_modrefs_preserve_recursive_call_closure() {
    let pir = Pir {
        module: "m1_7_cycle".to_string(),
        source: None,
        lowering: Default::default(),
        functions: vec![
            Func {
                key: "main".to_string(),
                sig: sig(AbiClass::Void, vec![]),
                param_names: vec![],
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                body: vec![Stmt::CallDirect {
                    callee: "a".to_string(),
                    sig: sig(AbiClass::Void, vec![]),
                    args: vec![],
                    dest: None,
                    loc: None,
                }],
            },
            Func {
                key: "a".to_string(),
                sig: sig(AbiClass::Void, vec![]),
                param_names: vec![],
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                body: vec![Stmt::CallDirect {
                    callee: "b".to_string(),
                    sig: sig(AbiClass::Void, vec![]),
                    args: vec![],
                    dest: None,
                    loc: None,
                }],
            },
            Func {
                key: "b".to_string(),
                sig: sig(AbiClass::Void, vec![]),
                param_names: vec![],
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                body: vec![
                    Stmt::CallDirect {
                        callee: "a".to_string(),
                        sig: sig(AbiClass::Void, vec![]),
                        args: vec![],
                        dest: None,
                        loc: None,
                    },
                    Stmt::GlobalRef {
                        global: "@G".to_string(),
                        access: Access::Ref,
                        loc: None,
                    },
                ],
            },
        ],
        globals: vec![Global {
            key: "@G".to_string(),
            file: None,
            line: None,
            is_const: false,
            mutable: true,
            exported: false,
        }],
        global_init: vec![],
    };

    let analysis = Analysis::run(
        &pir,
        &Opts {
            stage: Stage::Conservative,
            build_mode: BuildMode::Executable,
            ..Opts::default()
        },
    )
    .unwrap();

    let main = analysis.lookup_func("main").unwrap();
    let a = analysis.lookup_func("a").unwrap();
    let b = analysis.lookup_func("b").unwrap();
    let g = analysis.lookup_global("@G").unwrap();

    for func in [main, a, b] {
        assert!(analysis.modref(func).any(|mr| {
            mr.global == pangs_api::GlobalTarget::Name(g)
                && mr.access == Access::Ref
                && mr.via == pangs_api::Via::Direct
        }));
    }
}

#[test]
fn steens_metrics_expose_phase_timings_on_stress_fixture() {
    let fixture = m1_7_fixture("stress_chain.pir.json");
    let analysis = Analysis::run(
        &Pir::from_path(&fixture).unwrap(),
        &Opts {
            stage: Stage::Steens,
            build_mode: BuildMode::Executable,
            ..Opts::default()
        },
    )
    .unwrap();

    let metrics = analysis.metrics();
    assert!(metrics.analysis_wall_us >= metrics.pag_build_us);
    assert!(metrics.analysis_wall_us >= metrics.solve_us);
    assert!(metrics.analysis_wall_us >= metrics.transitive_modref_us);
    assert!(metrics.analysis_wall_us >= metrics.components_us);
    assert!(metrics.partition_count > 0);
}
