use std::path::Path;

use pangs_pag::{BuildMode, EdgeKind, OmegaSeedKind, Pag, PagOpts, SeedTarget, ValidationIssue};
use pangs_pir::{AbiClass, Func, Param, Pir, Signature, Stmt, VarArgPosition};

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/m1_3")
        .join(name)
}

fn m1_1_fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/m1_1")
        .join(name)
}

fn m1_4_fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/m1_4")
        .join(name)
}

fn sig(ret: AbiClass, params: Vec<Param>) -> Signature {
    Signature {
        ret,
        params,
        vararg: false,
        cc: "ccc".to_string(),
    }
}

#[test]
fn builds_core_nodes_edges_callsites_and_seeds() {
    let pir = Pir::from_path(fixture("core_edges.pir.json")).unwrap();
    let pag = Pag::from_pir(
        &pir,
        &PagOpts {
            build_mode: BuildMode::Executable,
            ..PagOpts::default()
        },
    );

    pag.validate().unwrap();
    assert_eq!(pag.metrics().nodes, pag.nodes.len());
    assert_eq!(pag.metrics().edges, pag.edges.len());
    assert_eq!(pag.metrics().callsites, pag.callsites.len());
    assert_eq!(pag.metrics().omega_seeds, pag.omega_seeds.len());
    assert_eq!(pag.metrics().direct_calls, 2);
    assert_eq!(pag.metrics().indirect_calls, 1);
    assert_eq!(pag.metrics().store_edges, 2);
    assert_eq!(pag.metrics().load_edges, 1);
    assert_eq!(pag.metrics().gep_edges, 1);
    assert_eq!(pag.metrics().object_nodes, 6);

    assert!(pag
        .nodes
        .iter()
        .any(|node| node.label == "obj:alloca:main:%slot"));
    assert!(pag
        .nodes
        .iter()
        .any(|node| node.label == "sym:function:target"));
    assert!(pag
        .nodes
        .iter()
        .any(|node| node.label == "sym:global:g_box"));
    assert!(pag.nodes.iter().any(|node| node.label == "ret:main"));
    assert!(pag.nodes.iter().any(|node| node.label == "param:id_i32:0"));
    assert!(pag.nodes.iter().any(|node| node.label == "ret:id_i32"));

    assert!(pag
        .edges
        .iter()
        .any(|edge| matches!(edge.kind, pangs_pag::EdgeKind::AddrOf)));
    assert!(pag
        .edges
        .iter()
        .any(|edge| matches!(edge.kind, pangs_pag::EdgeKind::Assign)));
    assert!(pag
        .edges
        .iter()
        .any(|edge| matches!(edge.kind, pangs_pag::EdgeKind::Load)));
    assert!(pag
        .edges
        .iter()
        .any(|edge| matches!(edge.kind, pangs_pag::EdgeKind::Store)));
    assert!(pag.edges.iter().any(|edge| matches!(
        edge.kind,
        pangs_pag::EdgeKind::Gep {
            byte_off: Some(8),
            ..
        }
    )));
    let bits = pag
        .nodes
        .iter()
        .find(|node| node.label == "val:main:%bits")
        .unwrap()
        .id;
    let rv = pag
        .nodes
        .iter()
        .find(|node| node.label == "val:main:%rv")
        .unwrap()
        .id;
    let callee_param = pag
        .nodes
        .iter()
        .find(|node| node.label == "param:id_i32:0")
        .unwrap()
        .id;
    let callee_ret = pag
        .nodes
        .iter()
        .find(|node| node.label == "ret:id_i32")
        .unwrap()
        .id;
    assert!(pag.edges.iter().any(|edge| {
        matches!(edge.kind, pangs_pag::EdgeKind::Assign)
            && edge.src == bits
            && edge.dst == callee_param
    }));
    assert!(pag.edges.iter().any(|edge| {
        matches!(edge.kind, pangs_pag::EdgeKind::Assign) && edge.src == callee_ret && edge.dst == rv
    }));

    assert_eq!(pag.callsites.len(), 3);
    assert!(pag.callsites.iter().any(|callsite| {
        callsite.callee.as_deref() == Some("id_i32")
            && callsite.args.len() == 1
            && callsite.result == Some(rv)
    }));
    assert!(pag.callsites.iter().any(
        |callsite| callsite.callee.as_deref() == Some("ext_decl") && callsite.external_boundary
    ));
    assert!(pag
        .callsites
        .iter()
        .any(|callsite| callsite.callee.is_none()
            && callsite.operand.is_some()
            && callsite.args.len() == 1
            && callsite.sig.vararg));

    assert!(pag
        .omega_seeds
        .iter()
        .any(|seed| seed.kind == OmegaSeedKind::ExportedSymbol));
    assert!(pag
        .omega_seeds
        .iter()
        .any(|seed| seed.kind == OmegaSeedKind::ImportedSymbol));
    assert!(pag
        .omega_seeds
        .iter()
        .any(|seed| seed.kind == OmegaSeedKind::ExternalCallBoundary));
    assert!(pag
        .omega_seeds
        .iter()
        .any(|seed| seed.kind == OmegaSeedKind::VarargCallBoundary));
    assert!(pag
        .omega_seeds
        .iter()
        .any(|seed| seed.kind == OmegaSeedKind::PtrToInt));
    assert!(pag
        .omega_seeds
        .iter()
        .any(|seed| seed.kind == OmegaSeedKind::IntToPtr));
    assert!(pag
        .omega_seeds
        .iter()
        .any(|seed| seed.kind == OmegaSeedKind::UnknownOperandEscape));
    assert!(pag
        .omega_seeds
        .iter()
        .any(|seed| seed.kind == OmegaSeedKind::UnknownResultExternal));
}

#[test]
fn fresh_allocator_result_is_a_bounded_heap_object() {
    let alloc_sig = sig(AbiClass::Integer, vec![Param::Integer, Param::Integer]);
    let pir = Pir {
        module: "fresh_allocator".into(),
        source: None,
        lowering: Default::default(),
        target: None,
        functions: vec![
            Func {
                key: "calloc".into(),
                sig: alloc_sig.clone(),
                param_names: Vec::new(),
                file: None,
                line: None,
                external: true,
                exported: false,
                address_taken: false,
                body: Vec::new(),
            },
            Func {
                key: "main".into(),
                sig: sig(AbiClass::Void, Vec::new()),
                param_names: Vec::new(),
                file: None,
                line: None,
                external: false,
                exported: true,
                address_taken: false,
                body: vec![
                    Stmt::CallDirect {
                        callee: "calloc".into(),
                        sig: alloc_sig,
                        args: vec!["1".into(), "4".into()],
                        dest: Some("%heap".into()),
                        loc: None,
                    },
                    Stmt::Load {
                        dest: "%value".into(),
                        address: "%heap".into(),
                        volatile: false,
                        access_bytes: Some(8),
                        loc: None,
                    },
                ],
            },
        ],
        globals: Vec::new(),
        global_init: Vec::new(),
    };
    let pag = Pag::from_pir(
        &pir,
        &PagOpts {
            build_mode: BuildMode::Executable,
            ..PagOpts::default()
        },
    );
    pag.validate().unwrap();

    let callsite = pag
        .callsites
        .iter()
        .find(|callsite| callsite.callee.as_deref() == Some("calloc"))
        .unwrap();
    assert!(!callsite.external_boundary);
    assert!(pag.nodes.iter().any(|node| node.label == "obj:heap:main:0"));
    assert!(pag
        .edges
        .iter()
        .any(|edge| edge.kind == pangs_pag::EdgeKind::Load && edge.access_bytes == Some(8)));
    assert!(!pag.omega_seeds.iter().any(|seed| {
        seed.kind == OmegaSeedKind::ExternalCallBoundary
            && seed.target == SeedTarget::Callsite(callsite.id)
    }));
}

#[test]
fn direct_internal_vararg_boundary_requires_visible_vararg_consumption() {
    let vararg_sig = Signature {
        ret: AbiClass::Void,
        params: vec![Param::Integer],
        vararg: true,
        cc: "ccc".to_string(),
    };
    let pir = Pir {
        module: "m4_vararg_boundary".to_string(),
        source: None,
        lowering: Default::default(),
        target: None,
        functions: vec![
            Func {
                key: "safe_sink".to_string(),
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
                key: "unsafe_sink".to_string(),
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
            // Proved read-only from its own body: reading through a tail pointer is the whole
            // effect, so its callers' pointer actuals need no boundary. This replaces the
            // hard-coded benign-name list that used to make this case pass.
            Func {
                key: "read_only_sink".to_string(),
                sig: vararg_sig.clone(),
                param_names: vec!["%read_only_sink::tag".to_string()],
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                body: vec![
                    Stmt::Alloca {
                        dest: "%read_only_sink::ap".to_string(),
                        ty: "[1 x %struct.__va_list_tag]".to_string(),
                        loc: None,
                    },
                    Stmt::Gep {
                        dest: "%read_only_sink::decay".to_string(),
                        base: "%read_only_sink::ap".to_string(),
                        byte_off: Some(0),
                        lane: None,
                        loc: None,
                    },
                    Stmt::VaStart {
                        list: "%read_only_sink::decay".to_string(),
                        loc: None,
                    },
                    Stmt::Load {
                        dest: "%read_only_sink::tail".to_string(),
                        address: "%read_only_sink::decay".to_string(),
                        volatile: false,
                        access_bytes: Some(8),
                        loc: None,
                    },
                    Stmt::Load {
                        dest: "%read_only_sink::byte".to_string(),
                        address: "%read_only_sink::tail".to_string(),
                        volatile: false,
                        access_bytes: Some(1),
                        loc: None,
                    },
                    Stmt::VaEnd {
                        list: "%read_only_sink::decay".to_string(),
                        loc: None,
                    },
                ],
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
                        callee: "safe_sink".to_string(),
                        sig: vararg_sig.clone(),
                        args: vec!["%tag".to_string(), "cb".to_string()],
                        dest: None,
                        loc: None,
                    },
                    Stmt::CallDirect {
                        callee: "unsafe_sink".to_string(),
                        sig: vararg_sig.clone(),
                        args: vec!["%tag".to_string(), "cb".to_string()],
                        dest: None,
                        loc: None,
                    },
                    Stmt::CallDirect {
                        callee: "read_only_sink".to_string(),
                        sig: vararg_sig.clone(),
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
    let pag = Pag::from_pir(&pir, &PagOpts::default());

    let safe = pag
        .callsites
        .iter()
        .find(|callsite| callsite.callee.as_deref() == Some("safe_sink"))
        .unwrap();
    let unsafe_site = pag
        .callsites
        .iter()
        .find(|callsite| callsite.callee.as_deref() == Some("unsafe_sink"))
        .unwrap();
    let summarized = pag
        .callsites
        .iter()
        .find(|callsite| callsite.callee.as_deref() == Some("read_only_sink"))
        .unwrap();

    assert!(!pag.omega_seeds.iter().any(|seed| {
        seed.kind == OmegaSeedKind::VarargCallBoundary
            && seed.target == SeedTarget::Callsite(safe.id)
    }));
    assert!(pag.omega_seeds.iter().any(|seed| {
        seed.kind == OmegaSeedKind::VarargCallBoundary
            && seed.target == SeedTarget::Callsite(unsafe_site.id)
    }));
    assert!(!pag.omega_seeds.iter().any(|seed| {
        seed.kind == OmegaSeedKind::VarargCallBoundary
            && seed.target == SeedTarget::Callsite(summarized.id)
    }));
    // A proof replaces the boundary with what it proved, so the read the callee performs
    // through the tail actual is still recorded. Dropping the seed without this would report
    // less than the boundary it replaced.
    assert!(pag.edges.iter().any(|edge| {
        edge.kind == EdgeKind::Load && Some(&edge.src) == summarized.args.get(1)
    }));
}

#[test]
fn positional_varargs_bind_only_the_callees_tail_actuals() {
    let vararg_sig = Signature {
        ret: AbiClass::Void,
        params: vec![Param::Integer],
        vararg: true,
        cc: "ccc".to_string(),
    };
    let positional_body = vec![Stmt::VarArg {
        dest: "%slot".to_string(),
        position: VarArgPosition::From { index: 0 },
        loc: None,
    }];
    let pir = Pir {
        module: "positional_varargs".to_string(),
        source: None,
        lowering: Default::default(),
        target: None,
        functions: vec![
            Func {
                key: "modeled_sink".to_string(),
                sig: vararg_sig.clone(),
                param_names: vec!["%tag".to_string()],
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                body: positional_body.clone(),
            },
            Func {
                key: "address_taken_sink".to_string(),
                sig: vararg_sig.clone(),
                param_names: vec!["%tag".to_string()],
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: true,
                body: positional_body,
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
                        callee: "modeled_sink".to_string(),
                        sig: vararg_sig.clone(),
                        args: vec!["%tag".to_string(), "cb".to_string(), "%data".to_string()],
                        dest: None,
                        loc: None,
                    },
                    Stmt::CallDirect {
                        callee: "address_taken_sink".to_string(),
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

    let pag = Pag::from_pir(&pir, &PagOpts::default());
    let modeled = pag
        .callsites
        .iter()
        .find(|site| site.callee.as_deref() == Some("modeled_sink"))
        .unwrap();
    let fallback = pag
        .callsites
        .iter()
        .find(|site| site.callee.as_deref() == Some("address_taken_sink"))
        .unwrap();
    assert!(!pag.omega_seeds.iter().any(|seed| {
        seed.kind == OmegaSeedKind::VarargCallBoundary
            && seed.target == SeedTarget::Callsite(modeled.id)
    }));
    assert!(pag.omega_seeds.iter().any(|seed| {
        seed.kind == OmegaSeedKind::VarargCallBoundary
            && seed.target == SeedTarget::Callsite(fallback.id)
    }));

    let destination = pag
        .nodes
        .iter()
        .find(|node| node.label == "val:modeled_sink:%slot")
        .unwrap()
        .id;
    let mut sources = pag
        .edges
        .iter()
        .filter(|edge| edge.kind == pangs_pag::EdgeKind::Assign && edge.dst == destination)
        .map(|edge| pag.nodes[edge.src.0 as usize].label.as_str())
        .collect::<Vec<_>>();
    sources.sort_unstable();
    assert_eq!(sources, ["sym:function:cb", "val:driver:%data"]);
}

#[test]
fn validate_rejects_bad_addr_of_shape() {
    let pir = Pir::from_path(fixture("core_edges.pir.json")).unwrap();
    let mut pag = Pag::from_pir(&pir, &PagOpts::default());
    let value = pag
        .nodes
        .iter()
        .find(|node| node.label == "val:main:%slot")
        .unwrap()
        .id;
    let edge = pag
        .edges
        .iter()
        .position(|edge| matches!(edge.kind, pangs_pag::EdgeKind::AddrOf))
        .unwrap();
    pag.edges[edge].src = value;

    let issues = pag.validate().unwrap_err();
    assert!(issues.iter().any(|issue| matches!(
        issue,
        ValidationIssue::EdgeKindInvariant {
            kind: "addr_of",
            ..
        }
    )));
}

#[test]
fn builds_checked_in_m1_1_fixture_suite() {
    for name in [
        "address_taken.ll",
        "aggregate_eh.ll",
        "abi_rows.ll",
        "addrspacecast.ll",
        "aliases.ll",
        "arithmetic.ll",
        "call_shapes.ll",
        "gep_offsets.ll",
        "global_init.ll",
        "global_init_select.ll",
        "ifunc.ll",
        "inline_asm.ll",
        "invoke.ll",
        "no_debug.ll",
        "resume.ll",
        "unknown_intrinsics.ll",
        "value_flow.ll",
        "volatile_atomic.ll",
    ] {
        let pir = Pir::from_path(m1_1_fixture(name)).unwrap();
        let pag = Pag::from_pir(
            &pir,
            &PagOpts {
                build_mode: BuildMode::Executable,
                ..PagOpts::default()
            },
        );
        pag.validate().unwrap();
        assert_eq!(pag.metrics().nodes, pag.nodes.len(), "{name}");
        assert_eq!(pag.metrics().edges, pag.edges.len(), "{name}");
    }
}

#[test]
fn binds_named_function_parameters_into_the_body_graph() {
    let pir = Pir::from_path(m1_4_fixture("escaped_fn_param_escape.pir.json")).unwrap();
    let pag = Pag::from_pir(&pir, &PagOpts::default());

    let param = pag
        .nodes
        .iter()
        .find(|node| node.label == "param:cb:0")
        .unwrap()
        .id;
    let value = pag
        .nodes
        .iter()
        .find(|node| node.label == "val:cb:%p")
        .unwrap()
        .id;
    assert!(pag.edges.iter().any(|edge| {
        matches!(edge.kind, pangs_pag::EdgeKind::Assign) && edge.src == param && edge.dst == value
    }));
}

#[test]
fn direct_byval_binding_uses_a_fresh_copy_object() {
    let byval_sig = sig(AbiClass::Void, vec![Param::Byval { size: 16 }]);
    let pir = Pir {
        module: "byval-copy".into(),
        source: None,
        lowering: Default::default(),
        target: None,
        functions: vec![
            Func {
                key: "callee".into(),
                sig: byval_sig.clone(),
                param_names: vec!["%callee::arg".into()],
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                body: Vec::new(),
            },
            Func {
                key: "caller".into(),
                sig: sig(AbiClass::Void, Vec::new()),
                param_names: Vec::new(),
                file: None,
                line: None,
                external: false,
                exported: false,
                address_taken: false,
                body: vec![
                    Stmt::Alloca {
                        dest: "%caller::src".into(),
                        ty: "{ i8*, i64 }".into(),
                        loc: None,
                    },
                    Stmt::CallDirect {
                        callee: "callee".into(),
                        sig: byval_sig,
                        args: vec!["%caller::src".into()],
                        dest: None,
                        loc: None,
                    },
                ],
            },
        ],
        globals: Vec::new(),
        global_init: Vec::new(),
    };
    let pag = Pag::from_pir(&pir, &PagOpts::default());
    let actual = pag
        .nodes
        .iter()
        .find(|node| node.label == "val:caller:%caller::src")
        .unwrap()
        .id;
    let param = pag
        .nodes
        .iter()
        .find(|node| node.label == "param:callee:0")
        .unwrap()
        .id;
    let copy = pag
        .nodes
        .iter()
        .find(|node| node.label == "obj:byval:caller:1:0")
        .unwrap()
        .id;

    assert!(pag.edges.iter().any(|edge| {
        edge.kind == pangs_pag::EdgeKind::AddrOf && edge.src == copy && edge.dst == param
    }));
    assert!(pag.edges.iter().any(|edge| {
        edge.kind == pangs_pag::EdgeKind::Memcpy { bytes: Some(16) }
            && edge.src == actual
            && edge.dst == param
    }));
    assert!(!pag.edges.iter().any(|edge| {
        edge.kind == pangs_pag::EdgeKind::Assign && edge.src == actual && edge.dst == param
    }));
}
