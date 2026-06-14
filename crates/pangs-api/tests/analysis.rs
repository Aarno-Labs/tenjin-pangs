use std::collections::BTreeSet;
use std::path::Path;

use pangs_api::{Analysis, BuildMode, Caller, EscapeStatus, Opts, Stage};
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
            "fnptr_varargs",
            "inline_asm",
            "setjmp_longjmp",
            "setjmp_longjmp"
        ]
    );
    assert!(analysis.audit_findings().iter().any(|finding| {
        finding.kind == "fnptr_varargs" && finding.affected == vec!["function:cb".to_string()]
    }));
    assert_eq!(analysis.metrics().audit_findings, 6);
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
        .any(|finding| finding.kind == "fnptr_varargs"
            && finding.affected == vec!["value:%fp".to_string()]));
    let driver = analysis.lookup_func("driver").unwrap();
    let component = analysis.component(analysis.component_of(driver));
    assert!(component
        .taint
        .iter()
        .any(|taint| taint.kind == "fnptr_varargs"
            && taint.witness.as_deref() == Some("driver@!noloc#0")));
}
