use pangs_api::{Analysis, BuildMode, Caller, EscapeStatus, Opts};
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
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                body: vec![Stmt::CallIndirect {
                    operand: "%fp".to_string(),
                    sig: target_sig.clone(),
                    loc: None,
                }],
            },
            Func {
                key: "ext_cb".to_string(),
                sig: target_sig,
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
