use std::path::Path;

use pangs_pag::{BuildMode, OmegaSeedKind, Pag, PagOpts, ValidationIssue};
use pangs_pir::Pir;

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
    assert!(pag
        .edges
        .iter()
        .any(|edge| matches!(edge.kind, pangs_pag::EdgeKind::Gep { byte_off: Some(8) })));
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
