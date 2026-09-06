use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use pangs_pir::{GepLane, Param, Pir, ScalarTypeClass, Stmt, ValueKind, VarArgPosition};
use tempfile::TempDir;

const CLANG_14: &str = "/home/brk/tenjin/_local/xj-llvm-14/bin/clang";

fn m1_1_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/m1_1")
        .join(name)
}

fn pir_from_llvm_sys(path: &Path) -> Pir {
    Pir::from_path(path).unwrap()
}

#[test]
fn lowers_statement_boundary_cfg_with_insertability_and_bidirectional_edges() {
    assert!(Path::new(CLANG_14).exists(), "LLVM-14 clang is required");
    let tmp = TempDir::new().unwrap();
    let bc_path = tmp.path().join("phase-cfg.bc");
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source = repo_root.join("fixtures/synthetic/disposition/phase_cfg.c");
    assert!(Command::new(CLANG_14)
        .args(["-O0", "-g", "-emit-llvm", "-c"])
        .arg(&source)
        .arg("-o")
        .arg(&bc_path)
        .status()
        .unwrap()
        .success());

    let pir = Pir::from_path_with_repo_root(&bc_path, &repo_root).unwrap();
    let main = pir
        .functions
        .iter()
        .find(|function| function.key == "main")
        .unwrap();
    let cfg = &pir.lowering.statement_cfgs["main"];
    assert!(cfg.source_mapping_available);
    assert_eq!(cfg.entry, 0);
    assert!(cfg
        .boundaries
        .iter()
        .any(|boundary| boundary.successors.len() == 2));

    let mut covered_statements = cfg
        .boundaries
        .iter()
        .flat_map(|boundary| boundary.stmt_indices.iter().copied())
        .collect::<Vec<_>>();
    covered_statements.sort_unstable();
    assert_eq!(
        covered_statements,
        (0..main.body.len() as u32).collect::<Vec<_>>()
    );
    for (expected_id, boundary) in cfg.boundaries.iter().enumerate() {
        assert_eq!(boundary.id as usize, expected_id);
        for &successor in &boundary.successors {
            assert!(cfg.boundaries[successor as usize]
                .predecessors
                .contains(&boundary.id));
        }
        for &predecessor in &boundary.predecessors {
            assert!(cfg.boundaries[predecessor as usize]
                .successors
                .contains(&boundary.id));
        }
        if let Some(location) = &boundary.loc {
            assert_eq!(location.file, "fixtures/synthetic/disposition/phase_cfg.c");
        }
    }

    // Two source statements share line 14, so neither boundary is source-insertable.
    let ambiguous = cfg
        .boundaries
        .iter()
        .filter(|boundary| boundary.loc.as_ref().is_some_and(|loc| loc.line == 14))
        .collect::<Vec<_>>();
    assert!(ambiguous.len() >= 2);
    assert!(ambiguous.iter().all(|boundary| !boundary.insertable));
}

#[test]
fn lowers_typedef_pointer_spelling_and_resolved_scalar_class() {
    assert!(Path::new(CLANG_14).exists(), "LLVM-14 clang is required");
    let tmp = TempDir::new().unwrap();
    let bc_path = tmp.path().join("typedef.bc");
    let c_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/synthetic/m1_8/icall_exec.c");
    assert!(Command::new(CLANG_14)
        .arg("-O0")
        .arg("-g")
        .arg("-emit-llvm")
        .arg("-c")
        .arg(c_path)
        .arg("-o")
        .arg(&bc_path)
        .status()
        .unwrap()
        .success());

    let pir = Pir::from_path(&bc_path).unwrap();
    let global = pir.globals.iter().find(|global| global.key == "g").unwrap();
    assert_eq!(global.type_spelling.as_deref(), Some("fn"));
    assert_eq!(global.scalar_class, Some(ScalarTypeClass::Pointer));
    assert_eq!(global.signed, None);
    assert_eq!(global.size_bits, Some(64));
}

#[test]
fn lowers_complete_qualified_scalar_type_evidence() {
    assert!(Path::new(CLANG_14).exists(), "LLVM-14 clang is required");
    let tmp = TempDir::new().unwrap();
    let c_path = tmp.path().join("qualified-scalars.c");
    let bc_path = tmp.path().join("qualified-scalars.bc");
    fs::write(
        &c_path,
        r#"
typedef int __sig_atomic_t;
typedef __sig_atomic_t sig_atomic_t;
typedef sig_atomic_t signal_alias;
typedef _Atomic int atomic_int;

volatile sig_atomic_t flag;
volatile signal_alias nested;
const volatile sig_atomic_t const_flag;
atomic_int named_atomic;
_Atomic int bare_atomic;
_Thread_local int tls_global;
int sectioned_global __attribute__((section(".pangs_test")));
"#,
    )
    .unwrap();
    assert!(Command::new(CLANG_14)
        .args(["-std=c11", "-O0", "-g", "-emit-llvm", "-c"])
        .arg(&c_path)
        .arg("-o")
        .arg(&bc_path)
        .status()
        .unwrap()
        .success());

    let pir = Pir::from_path(&bc_path).unwrap();
    let evidence = |name: &str| {
        pir.globals
            .iter()
            .find(|global| global.key == name)
            .and_then(|global| global.scalar_type_evidence.as_ref())
            .unwrap()
    };

    let flag = evidence("flag");
    assert_eq!(flag.type_spelling.as_deref(), Some("sig_atomic_t"));
    assert_eq!(flag.typedef_chain, ["sig_atomic_t", "__sig_atomic_t"]);
    assert!(flag.qualifiers.is_volatile);
    assert!(!flag.qualifiers.is_atomic);
    assert_eq!(flag.class, Some(ScalarTypeClass::Integer));
    assert_eq!(flag.signed, Some(true));

    let nested = evidence("nested");
    assert_eq!(nested.type_spelling.as_deref(), Some("signal_alias"));
    assert_eq!(
        nested.typedef_chain,
        ["signal_alias", "sig_atomic_t", "__sig_atomic_t"]
    );
    assert!(nested.qualifiers.is_volatile);

    let const_flag = evidence("const_flag");
    assert!(const_flag.qualifiers.is_const);
    assert!(const_flag.qualifiers.is_volatile);

    let named_atomic = evidence("named_atomic");
    assert_eq!(named_atomic.type_spelling.as_deref(), Some("atomic_int"));
    assert!(named_atomic.qualifiers.is_atomic);
    assert_eq!(named_atomic.class, Some(ScalarTypeClass::Integer));
    assert_eq!(named_atomic.signed, Some(true));

    let bare_atomic = evidence("bare_atomic");
    assert_eq!(bare_atomic.type_spelling.as_deref(), Some("int"));
    assert!(bare_atomic.typedef_chain.is_empty());
    assert!(bare_atomic.qualifiers.is_atomic);
    assert_eq!(bare_atomic.class, Some(ScalarTypeClass::Integer));
    assert_eq!(bare_atomic.signed, Some(true));

    let tls = pir
        .globals
        .iter()
        .find(|global| global.key == "tls_global")
        .unwrap();
    assert!(tls.thread_local);
    assert!(tls.section.is_none());
    let sectioned = pir
        .globals
        .iter()
        .find(|global| global.key == "sectioned_global")
        .unwrap();
    assert_eq!(sectioned.section.as_deref(), Some(".pangs_test"));
    assert!(!sectioned.thread_local);
}

#[test]
fn lowers_volatile_on_direct_local_gep_and_pointer_memory_operations() {
    assert!(Path::new(CLANG_14).exists(), "LLVM-14 clang is required");
    let temp = TempDir::new().unwrap();
    let source_path = temp.path().join("volatile-shapes.c");
    let bitcode_path = temp.path().join("volatile-shapes.bc");
    fs::write(
        &source_path,
        r#"
volatile int direct_global;
struct Box { volatile int field; };
int direct_read(void) { return direct_global; }
int local_read(void) { volatile int local = 1; return local; }
int field_read(struct Box *box) { return box->field; }
int pointer_read(volatile int *pointer) { return *pointer; }
int plain_read(int *pointer) { return *pointer; }
"#,
    )
    .unwrap();
    assert!(Command::new(CLANG_14)
        .args(["-std=c11", "-O0", "-g", "-emit-llvm", "-c"])
        .arg(&source_path)
        .arg("-o")
        .arg(&bitcode_path)
        .status()
        .unwrap()
        .success());
    let pir = Pir::from_path(&bitcode_path).unwrap();
    let function = |name: &str| {
        pir.functions
            .iter()
            .find(|function| function.key == name)
            .unwrap()
    };
    assert!(function("direct_read")
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::Load { volatile: true, .. })));
    assert!(function("local_read")
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::Store { volatile: true, .. })));
    assert!(function("local_read")
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::Load { volatile: true, .. })));
    assert!(function("field_read")
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::Gep { .. })));
    assert!(function("field_read")
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::Load { volatile: true, .. })));
    assert!(function("pointer_read")
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::Load { volatile: true, .. })));
    assert!(function("plain_read").body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Load {
            volatile: false,
            ..
        }
    )));
}

#[test]
fn qualified_scalar_type_walk_fails_closed_on_cycles_and_excess_depth() {
    assert!(Path::new(CLANG_14).exists(), "LLVM-14 clang is required");
    let tmp = TempDir::new().unwrap();
    let c_path = tmp.path().join("type-chain.c");
    let ll_path = tmp.path().join("type-chain.ll");
    fs::write(&c_path, "typedef int I; volatile I g;\n").unwrap();
    assert!(Command::new(CLANG_14)
        .args(["-std=c11", "-O0", "-g", "-S", "-emit-llvm"])
        .arg(&c_path)
        .arg("-o")
        .arg(&ll_path)
        .status()
        .unwrap()
        .success());
    let original = fs::read_to_string(&ll_path).unwrap();
    let outer = "!6 = !DIDerivedType(tag: DW_TAG_volatile_type, baseType: !7)";
    assert!(original.contains(outer));

    let cyclic = original.replacen(
        outer,
        "!6 = distinct !DIDerivedType(tag: DW_TAG_volatile_type, baseType: !6)",
        1,
    );
    let cyclic_path = tmp.path().join("cyclic.ll");
    fs::write(&cyclic_path, cyclic).unwrap();
    let cyclic_global = &Pir::from_path(&cyclic_path).unwrap().globals[0];
    assert!(cyclic_global.scalar_type_evidence.is_none());
    assert!(cyclic_global.type_spelling.is_none());
    assert!(cyclic_global.scalar_class.is_none());
    assert!(cyclic_global.signed.is_none());

    let mut deep = original.replacen(
        outer,
        "!6 = !DIDerivedType(tag: DW_TAG_volatile_type, baseType: !20)",
        1,
    );
    for id in 20..=51 {
        let base = if id == 51 { 8 } else { id + 1 };
        deep.push_str(&format!(
            "!{id} = !DIDerivedType(tag: DW_TAG_typedef, name: \"T{id}\", baseType: !{base})\n"
        ));
    }
    let deep_path = tmp.path().join("deep.ll");
    fs::write(&deep_path, deep).unwrap();
    let deep_global = &Pir::from_path(&deep_path).unwrap().globals[0];
    assert!(deep_global.scalar_type_evidence.is_none());
    assert!(deep_global.type_spelling.is_none());
    assert!(deep_global.scalar_class.is_none());
    assert!(deep_global.signed.is_none());
}

#[test]
fn lowers_llvm14_bitcode_function_pointer_smoke() {
    assert!(
        Path::new(CLANG_14).exists(),
        "LLVM-14 clang is required for the M1.1 lowering smoke test"
    );

    let tmp = TempDir::new().unwrap();
    let bc_path = tmp.path().join("fp.bc");
    let c_path = m1_1_fixture("fp_smoke.c");

    let status = Command::new(CLANG_14)
        .arg("-O0")
        .arg("-g")
        .arg("-emit-llvm")
        .arg("-c")
        .arg(&c_path)
        .arg("-o")
        .arg(&bc_path)
        .status()
        .unwrap();
    assert!(status.success());

    let pir = Pir::from_path(&bc_path).unwrap();
    let target = pir.functions.iter().find(|f| f.key == "target").unwrap();
    assert!(target.address_taken);
    assert!(target
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::Alloca { .. })));
    assert!(target
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::Load { .. })));
    assert!(target
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::Store { .. })));
    assert!(target.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Load {
            access_bytes: Some(8),
            ..
        }
    )));
    assert!(target.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Store {
            access_bytes: Some(4 | 8),
            ..
        }
    )));
    assert!(target
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::Return { .. })));

    let driver = pir.functions.iter().find(|f| f.key == "driver").unwrap();
    assert!(driver
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::CallIndirect { .. })));

    let counter = pir
        .globals
        .iter()
        .find(|global| global.key == "g_counter")
        .unwrap();
    assert!(counter.mutable);
    assert!(counter.is_definition);
    assert_eq!(counter.linkage, pangs_pir::SymbolLinkage::External);
    assert_eq!(counter.size_bits, Some(32));
    assert_eq!(counter.align_bits, Some(32));
    assert_eq!(counter.type_spelling.as_deref(), Some("int"));
    assert_eq!(counter.scalar_class, Some(ScalarTypeClass::Integer));
    assert_eq!(counter.signed, Some(true));
    assert_eq!(counter.initializer_ir.as_deref(), Some("i32 0"));
    assert!(counter
        .file
        .as_deref()
        .is_some_and(|file| file.ends_with("fp_smoke.c")));
    let target_info = pir.target.as_ref().unwrap();
    assert!(!target_info.triple.is_empty());
    assert!(!target_info.data_layout.is_empty());
    assert!(target_info.supported_atomic_widths.contains(&32));

    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let rooted = Pir::from_path_with_repo_root(&bc_path, &repo_root).unwrap();
    let rooted_counter = rooted
        .globals
        .iter()
        .find(|global| global.key == "g_counter")
        .unwrap();
    assert_eq!(
        rooted_counter.file.as_deref(),
        Some("fixtures/synthetic/m1_1/fp_smoke.c")
    );
    assert!(rooted_counter.path_error.is_none());
    let rooted_driver = rooted
        .functions
        .iter()
        .find(|function| function.key == "driver")
        .unwrap();
    assert_eq!(
        rooted_driver.file.as_deref(),
        Some("fixtures/synthetic/m1_1/fp_smoke.c")
    );
    assert!(pir.lowering.instruction_counts["alloca"] >= 1);
    assert!(pir.lowering.modeled_counts["load"] >= 1);
    assert!(pir.lowering.modeled_counts["store"] >= 1);
    assert_eq!(pir.lowering.globals, 2);
}

#[test]
fn llvm_sys_lowers_llvm14_bitcode_function_pointer_smoke() {
    assert!(
        Path::new(CLANG_14).exists(),
        "LLVM-14 clang is required for the M1.1 lowering smoke test"
    );

    let tmp = TempDir::new().unwrap();
    let bc_path = tmp.path().join("fp.bc");
    let c_path = m1_1_fixture("fp_smoke.c");

    let status = Command::new(CLANG_14)
        .arg("-O0")
        .arg("-g")
        .arg("-emit-llvm")
        .arg("-c")
        .arg(&c_path)
        .arg("-o")
        .arg(&bc_path)
        .status()
        .unwrap();
    assert!(status.success());

    let pir = Pir::from_path(&bc_path).unwrap();
    let target = pir.functions.iter().find(|f| f.key == "target").unwrap();
    assert!(target.address_taken);
    assert!(target
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::Alloca { .. })));
    assert!(target
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::Load { .. })));
    assert!(target
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::Store { .. })));
    assert!(target
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::Return { .. })));

    let driver = pir.functions.iter().find(|f| f.key == "driver").unwrap();
    assert!(driver
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::CallIndirect { .. })));

    assert!(pir
        .globals
        .iter()
        .any(|global| global.key == "g_counter" && global.mutable));
    assert!(pir.lowering.instruction_counts["alloca"] >= 1);
    assert!(pir.lowering.modeled_counts["load"] >= 1);
    assert!(pir.lowering.modeled_counts["store"] >= 1);
    assert_eq!(pir.lowering.globals, 2);
}

#[test]
fn lowers_call_args_and_results_from_ll() {
    let pir = Pir::from_path(m1_1_fixture("call_shapes.ll")).unwrap();
    let driver = pir.functions.iter().find(|f| f.key == "driver").unwrap();

    assert_eq!(driver.param_names, vec!["%driver::x".to_string()]);
    assert!(driver.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::CallDirect {
            callee,
            args,
            dest,
            ..
        } if callee == "id" && args.len() == 1 && dest.as_deref() == Some("%driver::direct")
    )));
    assert!(driver.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::CallIndirect {
            operand,
            args,
            dest,
            ..
        } if operand == "%driver::fp"
            && args.as_slice() == ["%driver::direct"]
            && dest.as_deref() == Some("%driver::indirect")
    )));
}

#[test]
fn lowers_address_taken_through_callbacks_varargs_and_stores() {
    let pir = Pir::from_path(m1_1_fixture("address_taken.ll")).unwrap();
    for name in ["cb_arg", "cb_vararg", "cb_store"] {
        assert!(
            pir.functions
                .iter()
                .find(|f| f.key == name)
                .unwrap()
                .address_taken
        );
    }
    let accept_vararg = pir
        .functions
        .iter()
        .find(|f| f.key == "accept_vararg")
        .unwrap();
    assert!(accept_vararg.sig.vararg);
    let driver = pir.functions.iter().find(|f| f.key == "driver").unwrap();
    assert!(driver.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::CallDirect { callee, sig, args, .. }
            if callee == "accept_vararg" && sig.vararg && args.len() == 2
    )));
}

#[test]
fn lowers_vararg_and_x87_signatures_from_ll() {
    let pir = Pir::from_path(m1_1_fixture("abi_rows.ll")).unwrap();

    let vararg_target = pir
        .functions
        .iter()
        .find(|f| f.key == "vararg_target")
        .unwrap();
    assert!(vararg_target.external);
    assert!(vararg_target.sig.vararg);
    assert_eq!(vararg_target.sig.params.as_slice(), &[Param::Integer]);
    assert_eq!(vararg_target.sig.ret, pangs_pir::AbiClass::Integer);

    let x87_id = pir.functions.iter().find(|f| f.key == "x87_id").unwrap();
    assert!(x87_id.external);
    assert_eq!(x87_id.sig.params.as_slice(), &[Param::X87]);
    assert_eq!(x87_id.sig.ret, pangs_pir::AbiClass::X87);

    let accept_short_cb = pir
        .functions
        .iter()
        .find(|f| f.key == "accept_short_cb")
        .unwrap();
    assert_eq!(accept_short_cb.sig.params.as_slice(), &[Param::Integer]);

    let short_cb = pir.functions.iter().find(|f| f.key == "short_cb").unwrap();
    assert!(short_cb.address_taken);

    let driver = pir.functions.iter().find(|f| f.key == "driver").unwrap();
    assert!(driver.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::CallDirect { callee, sig, args, .. }
            if callee == "vararg_target"
                && sig.vararg
                && args.len() == 3
                && sig.params.as_slice() == [Param::Integer]
                && sig.ret == pangs_pir::AbiClass::Integer
    )));
    assert!(driver.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::CallDirect { callee, sig, args, .. }
            if callee == "x87_id"
                && args.len() == 1
                && sig.params.as_slice() == [Param::X87]
                && sig.ret == pangs_pir::AbiClass::X87
    )));
}

#[test]
fn recognizes_closed_sysv_pointer_varargs_and_rejects_va_copy() {
    assert!(Path::new(CLANG_14).exists(), "LLVM-14 clang is required");
    let tmp = TempDir::new().unwrap();
    let bc_path = tmp.path().join("positional-varargs.bc");
    assert!(Command::new(CLANG_14)
        .args(["-O0", "-g", "-emit-llvm", "-c"])
        .arg(m1_1_fixture("positional_varargs.c"))
        .arg("-o")
        .arg(&bc_path)
        .status()
        .unwrap()
        .success());

    let pir = Pir::from_path(&bc_path).unwrap();
    let first = pir
        .functions
        .iter()
        .find(|function| function.key == "first_pointer")
        .unwrap();
    assert!(first.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::VarArg {
            position: VarArgPosition::Exact { index: 0 },
            ..
        }
    )));
    assert!(!first.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Unknown { reason, .. } if reason == "varargs_intrinsic"
    )));
    // The list operations are explicit in both paths, so the write to the list is never lost,
    // and neither intrinsic is an opaque operand escape.
    assert!(first
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::VaStart { .. })));
    assert!(first
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::VaEnd { .. })));

    let tail = pir
        .functions
        .iter()
        .find(|function| function.key == "pointer_tail")
        .unwrap();
    assert!(tail.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::VarArg {
            position: VarArgPosition::From { index: 0 },
            ..
        }
    )));

    let copied = pir
        .functions
        .iter()
        .find(|function| function.key == "copied_list")
        .unwrap();
    assert!(!copied
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::VarArg { .. })));
    // `va_copy` is explicit — it reads one list's storage and writes another's, publishing
    // neither address — but it still defeats positional recognition, which can only bind
    // actuals it can name.
    assert!(copied
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::VaCopy { .. })));
    assert!(!copied.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Unknown { reason, .. } if reason == "varargs_intrinsic"
    )));
}

#[test]
fn lowers_addrspacecast_pointer_flow_from_ll() {
    let pir = Pir::from_path(m1_1_fixture("addrspacecast.ll")).unwrap();
    let casts = pir.functions.iter().find(|f| f.key == "casts").unwrap();
    let assigns = casts
        .body
        .iter()
        .filter_map(|stmt| match stmt {
            Stmt::Assign { dest, sources, .. } => Some((dest.as_str(), sources.as_slice())),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(assigns
        .iter()
        .any(|(dest, sources)| *dest == "%casts::to_as1" && *sources == ["%casts::p"]));
    assert!(assigns
        .iter()
        .any(|(dest, sources)| *dest == "%casts::back" && *sources == ["%casts::to_as1"]));
    assert_eq!(pir.lowering.instruction_counts["addrspacecast"], 2);
    assert_eq!(pir.lowering.modeled_counts["assign"], 2);
    assert!(!pir
        .lowering
        .skipped_counts
        .contains_key("addrspacecast_non_pointer"));
}

#[test]
fn lowers_volatile_and_atomic_global_accesses_from_ll() {
    let pir = Pir::from_path(m1_1_fixture("volatile_atomic.ll")).unwrap();
    let touch = pir.functions.iter().find(|f| f.key == "touch").unwrap();
    assert_eq!(
        touch
            .body
            .iter()
            .filter(|stmt| matches!(stmt, Stmt::Store { address, .. } if address == "@GP"))
            .count(),
        2
    );
    assert_eq!(
        touch
            .body
            .iter()
            .filter(|stmt| matches!(stmt, Stmt::Load { address, .. } if address == "@GP"))
            .count(),
        2
    );
    assert_eq!(pir.lowering.modeled_counts["volatile_store"], 1);
    assert_eq!(pir.lowering.modeled_counts["volatile_load"], 1);
    assert_eq!(pir.lowering.modeled_counts["atomic_store"], 1);
    assert_eq!(pir.lowering.modeled_counts["atomic_load"], 1);
    assert_eq!(pir.lowering.modeled_counts["global_mod"], 2);
    assert_eq!(pir.lowering.modeled_counts["global_ref"], 2);
    assert_eq!(
        touch
            .body
            .iter()
            .filter(|stmt| matches!(stmt, Stmt::Store { volatile: true, .. }))
            .count(),
        1
    );
    assert_eq!(
        touch
            .body
            .iter()
            .filter(|stmt| matches!(stmt, Stmt::Load { volatile: true, .. }))
            .count(),
        1
    );
    assert_eq!(
        touch
            .body
            .iter()
            .filter(|stmt| matches!(stmt, Stmt::GlobalRef { volatile: true, .. }))
            .count(),
        2
    );
    assert_eq!(
        touch
            .body
            .iter()
            .filter(|stmt| matches!(
                stmt,
                Stmt::GlobalRef {
                    volatile: false,
                    ..
                }
            ))
            .count(),
        2
    );
}

#[test]
fn lowers_inline_asm_calls_as_unknown_and_taints_them() {
    let pir = Pir::from_path(m1_1_fixture("inline_asm.ll")).unwrap();
    let asm_call = pir.functions.iter().find(|f| f.key == "asm_call").unwrap();
    assert!(asm_call.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Unknown { op, reason, .. } if op == "call" && reason == "inline_asm"
    )));
    assert_eq!(pir.lowering.tainted_counts["inline_asm"], 1);
}

#[test]
fn classifies_operand_bounded_and_symbol_referencing_inline_asm() {
    let pir = Pir::from_path(m1_1_fixture("inline_asm_exposure.ll")).unwrap();
    let bounded = pir
        .functions
        .iter()
        .find(|func| func.key == "bounded_asm")
        .unwrap();
    assert!(bounded.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Unknown { operands, reason, .. }
            if operands == &["@bits".to_string()] && reason == "inline_asm"
    )));

    let symbol = pir
        .functions
        .iter()
        .find(|func| func.key == "symbol_asm")
        .unwrap();
    assert!(symbol.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Unknown { reason, .. } if reason == "inline_asm_symbol_reference"
    )));
}

#[test]
fn lowers_large_struct_byval_and_sret_from_bitcode() {
    assert!(
        Path::new(CLANG_14).exists(),
        "LLVM-14 clang is required for the M1.1 lowering ABI fixture"
    );

    let tmp = TempDir::new().unwrap();
    let bc_path = tmp.path().join("agg.bc");
    let c_path = m1_1_fixture("byval_sret.c");

    let status = Command::new(CLANG_14)
        .arg("-O0")
        .arg("-g0")
        .arg("-emit-llvm")
        .arg("-c")
        .arg(&c_path)
        .arg("-o")
        .arg(&bc_path)
        .status()
        .unwrap();
    assert!(status.success());

    let pir = Pir::from_path(&bc_path).unwrap();
    let ret_big = pir.functions.iter().find(|f| f.key == "ret_big").unwrap();
    assert!(matches!(
        ret_big.sig.params.first(),
        Some(Param::Sret { size: 24 })
    ));
    assert!(ret_big.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::CallDirect { callee, sig, .. }
            if callee == "sink"
                && matches!(sig.params.as_slice(), [Param::Byval { size: 24 }])
    )));
    let sink = pir.functions.iter().find(|f| f.key == "sink").unwrap();
    assert!(sink.external);
    assert!(matches!(
        sink.sig.params.as_slice(),
        [Param::Byval { size: 24 }]
    ));
}

#[test]
fn llvm_sys_lowers_large_struct_byval_and_sret_from_bitcode() {
    assert!(
        Path::new(CLANG_14).exists(),
        "LLVM-14 clang is required for the M1.1 lowering ABI fixture"
    );

    let tmp = TempDir::new().unwrap();
    let bc_path = tmp.path().join("agg.bc");
    let c_path = m1_1_fixture("byval_sret.c");

    let status = Command::new(CLANG_14)
        .arg("-O0")
        .arg("-g0")
        .arg("-emit-llvm")
        .arg("-c")
        .arg(&c_path)
        .arg("-o")
        .arg(&bc_path)
        .status()
        .unwrap();
    assert!(status.success());

    let pir = Pir::from_path(&bc_path).unwrap();
    let ret_big = pir.functions.iter().find(|f| f.key == "ret_big").unwrap();
    assert!(matches!(
        ret_big.sig.params.first(),
        Some(Param::Sret { size: 24 })
    ));
    assert!(ret_big.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::CallDirect { callee, sig, .. }
            if callee == "sink"
                && matches!(sig.params.as_slice(), [Param::Byval { size: 24 }])
    )));
    let sink = pir.functions.iter().find(|f| f.key == "sink").unwrap();
    assert!(sink.external);
    assert!(matches!(
        sink.sig.params.as_slice(),
        [Param::Byval { size: 24 }]
    ));
}

#[test]
fn lowers_value_flow_memory_intrinsics_and_atomics_from_ll() {
    let tmp = TempDir::new().unwrap();
    let ll_path = tmp.path().join("flow.ll");
    fs::write(
        &ll_path,
        r#"
@P = global i8* null
@I = global i64 0

declare void @llvm.memcpy.p0i8.p0i8.i64(i8* nocapture writeonly, i8* nocapture readonly, i64, i1 immarg)

define i8* @flow(i1 %c, i8* %a, i8* %b) {
entry:
  %slot = alloca i8*
  store i8* %a, i8** %slot
  %loaded = load i8*, i8** %slot
  %gep = getelementptr i8, i8* %loaded, i64 0
  %cast = bitcast i8* %gep to i8*
  %sel = select i1 %c, i8* %cast, i8* %b
  br i1 %c, label %left, label %right
left:
  br label %join
right:
  br label %join
join:
  %phi = phi i8* [ %sel, %left ], [ %b, %right ]
  %fr = freeze i8* %phi
  %pi = ptrtoint i8* %fr to i64
  %ip = inttoptr i64 %pi to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* %ip, i8* %b, i64 4, i1 false)
  ret i8* %ip
}

define i64 @atomic_xchg(i64 %new) {
entry:
  %old = atomicrmw xchg i64* @I, i64 %new seq_cst
  ret i64 %old
}

define i8* @atomic_cas(i8* %expected, i8* %new) {
entry:
  %res = cmpxchg i8** @P, i8* %expected, i8* %new seq_cst seq_cst
  %old = extractvalue { i8*, i1 } %res, 0
  ret i8* %old
}
"#,
    )
    .unwrap();

    let pir = Pir::from_path(&ll_path).unwrap();
    let flow = pir.functions.iter().find(|f| f.key == "flow").unwrap();
    assert!(flow.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Gep {
            byte_off: Some(0),
            ..
        }
    )));
    assert!(
        flow.body
            .iter()
            .filter(|stmt| matches!(stmt, Stmt::Assign { .. }))
            .count()
            >= 4
    );
    assert!(flow.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::PtrToInt {
            integer_bits: Some(64),
            pointer_bits: Some(64),
            pointer_address_space: Some(0),
            ..
        }
    )));
    assert!(flow.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::IntToPtr {
            integer_bits: Some(64),
            pointer_bits: Some(64),
            pointer_address_space: Some(0),
            ..
        }
    )));
    assert!(flow
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::Memcpy { bytes: Some(4), .. })));

    let atomic_xchg = pir
        .functions
        .iter()
        .find(|f| f.key == "atomic_xchg")
        .unwrap();
    assert!(atomic_xchg
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::Load { .. })));
    assert!(atomic_xchg
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::Store { .. })));

    let atomic_cas = pir
        .functions
        .iter()
        .find(|f| f.key == "atomic_cas")
        .unwrap();
    assert!(atomic_cas
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::Load { dest, .. } if dest.ends_with(".old"))));
    assert!(atomic_cas
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::Store { .. })));

    assert_eq!(pir.lowering.instruction_counts["atomicrmw"], 1);
    assert_eq!(pir.lowering.instruction_counts["cmpxchg"], 1);
    assert_eq!(pir.lowering.terminator_counts["condbr"], 1);
    assert_eq!(pir.lowering.terminator_counts["br"], 2);
    assert_eq!(pir.lowering.modeled_counts["memcpy"], 1);
    assert_eq!(pir.lowering.modeled_counts["atomicrmw"], 1);
    assert_eq!(pir.lowering.modeled_counts["cmpxchg"], 1);
    assert_eq!(pir.lowering.tainted_counts["inttoptr"], 1);
}

#[test]
fn records_fail_closed_inttoptr_integer_provenance_traces() {
    let tmp = TempDir::new().unwrap();
    let ll_path = tmp.path().join("inttoptr-provenance.ll");
    fs::write(
        &ll_path,
        r#"
@tag = global i8* inttoptr (i64 2 to i8*)

define i8* @pointer_or_null(i1 %condition, i8* %pointer) {
entry:
  %bits = ptrtoint i8* %pointer to i64
  %selected = select i1 %condition, i64 %bits, i64 0
  %result = inttoptr i64 %selected to i8*
  ret i8* %result
}

define i8* @integer_tag() {
entry:
  %result = inttoptr i64 2 to i8*
  ret i8* %result
}

define i8* @unbounded_argument(i64 %bits) {
entry:
  %result = inttoptr i64 %bits to i8*
  ret i8* %result
}
"#,
    )
    .unwrap();

    let pir = Pir::from_path(&ll_path).unwrap();
    let trace = |function: &str| {
        pir.functions
            .iter()
            .find(|candidate| candidate.key == function)
            .unwrap()
            .body
            .iter()
            .find_map(|statement| match statement {
                Stmt::IntToPtr {
                    provenance_trace, ..
                } => provenance_trace.as_ref(),
                _ => None,
            })
            .unwrap()
    };
    let pointer_or_null = trace("pointer_or_null");
    assert_eq!(pointer_or_null.operations, ["ptrtoint", "select"]);
    assert_eq!(pointer_or_null.integer_constants, ["0"]);
    assert_eq!(pointer_or_null.pointer_origins.len(), 1);
    assert!(pointer_or_null.blockers.is_empty());

    let tag = trace("integer_tag");
    assert_eq!(tag.integer_constants, ["2"]);
    assert!(tag.pointer_origins.is_empty());
    assert!(tag.blockers.is_empty());

    let argument = trace("unbounded_argument");
    assert_eq!(argument.blockers, ["function-argument"]);

    let global_tag = pir
        .global_init
        .iter()
        .find_map(|statement| match statement {
            Stmt::IntToPtr {
                provenance_trace, ..
            } => provenance_trace.as_ref(),
            _ => None,
        })
        .unwrap();
    assert_eq!(global_tag.integer_constants, ["2"]);
    assert!(global_tag.blockers.is_empty());
}

#[test]
fn lowers_pointer_integer_arithmetic_in_constant_expressions() {
    let tmp = TempDir::new().unwrap();
    let ll_path = tmp.path().join("pointer-integer-constant-expr.ll");
    fs::write(
        &ll_path,
        r#"
@storage = global i8 0
@tagged = global i8* inttoptr (i64 xor (i64 ptrtoint (i8* @storage to i64), i64 1) to i8*)
"#,
    )
    .unwrap();

    let pir = Pir::from_path(&ll_path).unwrap();
    assert!(pir
        .global_init
        .iter()
        .any(|stmt| matches!(stmt, Stmt::PtrToInt { source, .. } if source == "@storage")));
    assert!(pir.global_init.iter().any(|stmt| matches!(
        stmt,
        Stmt::ScalarOp {
            op: pangs_pir::ScalarOp::Xor,
            rhs,
            ..
        } if rhs == "1"
    )));
    assert!(pir
        .global_init
        .iter()
        .any(|stmt| matches!(stmt, Stmt::IntToPtr { .. })));
}

#[test]
fn certifies_only_exact_fully_initialized_function_pointer_aggregate_copies() {
    let tmp = TempDir::new().unwrap();
    let ll_path = tmp.path().join("fnptr-init-copy.ll");
    fs::write(
        &ll_path,
        r#"
%Callbacks = type { void ()*, void ()* }
@good_table = global %Callbacks zeroinitializer
@partial_table = global %Callbacks zeroinitializer
@unknown_table = global %Callbacks zeroinitializer

declare void @llvm.memcpy.p0i8.p0i8.i64(i8* nocapture writeonly, i8* nocapture readonly, i64, i1 immarg)
declare void @cb0()
declare void @cb1()

define void @copies(void ()* %unknown) {
entry:
  %good = alloca %Callbacks
  %good0 = getelementptr %Callbacks, %Callbacks* %good, i64 0, i32 0
  store void ()* @cb0, void ()** %good0
  %good1 = getelementptr %Callbacks, %Callbacks* %good, i64 0, i32 1
  store void ()* @cb1, void ()** %good1
  %good.src = bitcast %Callbacks* %good to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* bitcast (%Callbacks* @good_table to i8*), i8* %good.src, i64 16, i1 false)

  %partial = alloca %Callbacks
  %partial0 = getelementptr %Callbacks, %Callbacks* %partial, i64 0, i32 0
  store void ()* @cb0, void ()** %partial0
  %partial.src = bitcast %Callbacks* %partial to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* bitcast (%Callbacks* @partial_table to i8*), i8* %partial.src, i64 16, i1 false)

  %unknown.local = alloca %Callbacks
  %unknown0 = getelementptr %Callbacks, %Callbacks* %unknown.local, i64 0, i32 0
  store void ()* %unknown, void ()** %unknown0
  %unknown1 = getelementptr %Callbacks, %Callbacks* %unknown.local, i64 0, i32 1
  store void ()* @cb1, void ()** %unknown1
  %unknown.src = bitcast %Callbacks* %unknown.local to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* bitcast (%Callbacks* @unknown_table to i8*), i8* %unknown.src, i64 16, i1 false)
  ret void
}
"#,
    )
    .unwrap();

    let pir = Pir::from_path(&ll_path).unwrap();
    let copies = pir
        .functions
        .iter()
        .find(|func| func.key == "copies")
        .unwrap();
    let memcpys = copies
        .body
        .iter()
        .filter_map(|stmt| match stmt {
            Stmt::Memcpy {
                dst,
                proven_fnptr_init,
                ..
            } => Some((dst.as_str(), *proven_fnptr_init)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        memcpys,
        vec![
            ("@good_table", true),
            ("@partial_table", false),
            ("@unknown_table", false),
        ]
    );
}

#[test]
fn llvm_sys_lowers_value_flow_memory_intrinsics_and_atomics_from_ll() {
    let tmp = TempDir::new().unwrap();
    let ll_path = tmp.path().join("flow.ll");
    fs::write(
        &ll_path,
        r#"
@P = global i8* null
@I = global i64 0

declare void @llvm.memcpy.p0i8.p0i8.i64(i8* nocapture writeonly, i8* nocapture readonly, i64, i1 immarg)

define i8* @flow(i1 %c, i8* %a, i8* %b) {
entry:
  %slot = alloca i8*
  store i8* %a, i8** %slot
  %loaded = load i8*, i8** %slot
  %gep = getelementptr i8, i8* %loaded, i64 0
  %cast = bitcast i8* %gep to i8*
  %sel = select i1 %c, i8* %cast, i8* %b
  br i1 %c, label %left, label %right
left:
  br label %join
right:
  br label %join
join:
  %phi = phi i8* [ %sel, %left ], [ %b, %right ]
  %fr = freeze i8* %phi
  %pi = ptrtoint i8* %fr to i64
  %ip = inttoptr i64 %pi to i8*
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* %ip, i8* %b, i64 4, i1 false)
  ret i8* %ip
}

define i64 @atomic_xchg(i64 %new) {
entry:
  %old = atomicrmw xchg i64* @I, i64 %new seq_cst
  ret i64 %old
}

define i8* @atomic_cas(i8* %expected, i8* %new) {
entry:
  %res = cmpxchg i8** @P, i8* %expected, i8* %new seq_cst seq_cst
  %old = extractvalue { i8*, i1 } %res, 0
  ret i8* %old
}
"#,
    )
    .unwrap();

    let pir = pir_from_llvm_sys(&ll_path);
    let flow = pir.functions.iter().find(|f| f.key == "flow").unwrap();
    assert!(flow.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Gep {
            byte_off: Some(0),
            ..
        }
    )));
    assert!(
        flow.body
            .iter()
            .filter(|stmt| matches!(stmt, Stmt::Assign { .. }))
            .count()
            >= 4
    );
    assert!(flow.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::PtrToInt {
            integer_bits: Some(64),
            pointer_bits: Some(64),
            pointer_address_space: Some(0),
            ..
        }
    )));
    assert!(flow.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::IntToPtr {
            integer_bits: Some(64),
            pointer_bits: Some(64),
            pointer_address_space: Some(0),
            ..
        }
    )));
    assert!(flow
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::Memcpy { bytes: Some(4), .. })));

    let atomic_xchg = pir
        .functions
        .iter()
        .find(|f| f.key == "atomic_xchg")
        .unwrap();
    assert!(atomic_xchg
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::Load { .. })));
    assert!(atomic_xchg
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::Store { .. })));

    let atomic_cas = pir
        .functions
        .iter()
        .find(|f| f.key == "atomic_cas")
        .unwrap();
    assert!(atomic_cas
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::Load { dest, .. } if dest.ends_with(".old"))));
    assert!(atomic_cas
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::Store { .. })));

    assert_eq!(pir.lowering.instruction_counts["atomicrmw"], 1);
    assert_eq!(pir.lowering.instruction_counts["cmpxchg"], 1);
    assert_eq!(pir.lowering.terminator_counts["condbr"], 1);
    assert_eq!(pir.lowering.terminator_counts["br"], 2);
    assert_eq!(pir.lowering.modeled_counts["memcpy"], 1);
    assert_eq!(pir.lowering.modeled_counts["atomicrmw"], 1);
    assert_eq!(pir.lowering.modeled_counts["cmpxchg"], 1);
    assert_eq!(pir.lowering.tainted_counts["inttoptr"], 1);
}

#[test]
fn llvm_sys_models_supported_scalar_ops_and_names_the_rest() {
    let tmp = TempDir::new().unwrap();
    let ll_path = tmp.path().join("arith.ll");
    fs::write(
        &ll_path,
        r#"
define void @arith(i32 %a, i32 %b, float %x, float %y) {
entry:
  %sum = add i32 %a, %b
  %diff = sub i32 %a, %b
  %mask = and i32 %sum, %diff
  %wide = add i128 170141183460469231731687303715884105727, 1
  %cmp = icmp eq i32 %sum, %diff
  %fsum = fadd float %x, %y
  %neg = fneg float %x
  ret void
}
"#,
    )
    .unwrap();

    let pir = pir_from_llvm_sys(&ll_path);
    assert_eq!(pir.lowering.instruction_counts["add"], 2);
    assert_eq!(pir.lowering.instruction_counts["sub"], 1);
    assert_eq!(pir.lowering.instruction_counts["and"], 1);
    assert_eq!(pir.lowering.instruction_counts["icmp"], 1);
    assert_eq!(pir.lowering.instruction_counts["fadd"], 1);
    assert_eq!(pir.lowering.instruction_counts["fneg"], 1);
    assert_eq!(pir.lowering.modeled_counts["scalar_add"], 2);
    assert_eq!(pir.lowering.modeled_counts["scalar_sub"], 1);
    assert_eq!(pir.lowering.modeled_counts["scalar_and"], 1);
    assert_eq!(
        pir.functions[0]
            .body
            .iter()
            .filter(|stmt| matches!(stmt, Stmt::ScalarOp { .. }))
            .count(),
        4
    );
    assert!(pir.functions[0].body.iter().any(|stmt| matches!(
        stmt,
        Stmt::ScalarOp { lhs, .. } if lhs == "i128 170141183460469231731687303715884105727"
    )));
    assert_eq!(pir.lowering.skipped_counts["unmodeled_instruction:icmp"], 1);
    assert_eq!(pir.lowering.skipped_counts["unmodeled_instruction:fadd"], 1);
    assert_eq!(pir.lowering.skipped_counts["unmodeled_instruction:fneg"], 1);
    assert!(!pir
        .lowering
        .skipped_counts
        .contains_key("unmodeled_instruction:other"));
}

#[test]
fn llvm_sys_classifies_innocuous_ptrtoint_use_shapes() {
    let tmp = TempDir::new().unwrap();
    let ll_path = tmp.path().join("ptrtoint_uses.ll");
    fs::write(
        &ll_path,
        r#"
declare void @sink(i64)
declare void @sink_ptr(i8*)
declare void @llvm.memcpy.p0i8.p0i8.i64(i8*, i8*, i64, i1 immarg)
@observed_difference = global i64 0

define i1 @direct_compare(i8* %p, i8* %q) {
entry:
  %pi = ptrtoint i8* %p to i64
  %qi = ptrtoint i8* %q to i64
  %cmp = icmp ult i64 %pi, %qi
  ret i1 %cmp
}

define i1 @arithmetic_compare(i8* %p) {
entry:
  %bits = ptrtoint i8* %p to i64
  %masked = and i64 %bits, -2
  %cmp = icmp eq i64 %masked, 0
  ret i1 %cmp
}

define i1 @select_compare(i1 %condition, i8* %p) {
entry:
  %bits = ptrtoint i8* %p to i64
  %selected = select i1 %condition, i64 %bits, i64 0
  %cmp = icmp eq i64 %selected, 0
  ret i1 %cmp
}

define void @switch_compare(i8* %p) {
entry:
  %bits = ptrtoint i8* %p to i64
  switch i64 %bits, label %ordinary [
    i64 0, label %special
    i64 -1, label %special
  ]

ordinary:
  ret void

special:
  ret void
}

define i1 @unsupported_arithmetic(i8* %p) {
entry:
  %bits = ptrtoint i8* %p to i64
  %product = mul i64 %bits, 2
  %cmp = icmp eq i64 %product, 0
  ret i1 %cmp
}

define void @externally_observed(i8* %p) {
entry:
  %bits = ptrtoint i8* %p to i64
  call void @sink(i64 %bits)
  ret void
}

define i8* @reified(i8* %p) {
entry:
  %bits = ptrtoint i8* %p to i64
  %again = inttoptr i64 %bits to i8*
  ret i8* %again
}

define void @mixed_use(i8* %p) {
entry:
  %bits = ptrtoint i8* %p to i64
  %cmp = icmp eq i64 %bits, 0
  call void @sink(i64 %bits)
  ret void
}

define void @closed_pointer_difference(i8* %p, i8* %q, i8* %dst) {
entry:
  %len.addr = alloca i32
  %lhs = getelementptr i8, i8* %p, i64 7
  %rhs = getelementptr i8, i8* %p, i64 2
  %pi = ptrtoint i8* %lhs to i64
  %qi = ptrtoint i8* %rhs to i64
  %delta = sub i64 %pi, %qi
  %plus_one = add i64 %delta, 1
  %narrow = trunc i64 %plus_one to i32
  store i32 %narrow, i32* %len.addr
  %loaded = load i32, i32* %len.addr
  %wide = sext i32 %loaded to i64
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* %dst, i8* %q, i64 %wide, i1 false)
  %indexed = getelementptr i8, i8* %dst, i64 %wide
  store i8 0, i8* %indexed
  ret void
}

define void @shared_paired_pointer_differences(i8* %p, i8* %q, i8* %r) {
entry:
  %pi = ptrtoint i8* %p to i64
  %qi = ptrtoint i8* %q to i64
  %ri = ptrtoint i8* %r to i64
  %first = sub i64 %pi, %qi
  %second = sub i64 %ri, %qi
  call void @sink(i64 %first)
  call void @sink(i64 %second)
  ret void
}

define void @phi_selected_pointer_difference(i1 %choose, i8* %p, i8* %q, i8* %r) {
entry:
  %pi = ptrtoint i8* %p to i64
  br i1 %choose, label %left, label %right

left:
  %qi = ptrtoint i8* %q to i64
  br label %merge

right:
  %ri = ptrtoint i8* %r to i64
  br label %merge

merge:
  %selected = phi i64 [ %qi, %left ], [ %ri, %right ]
  %delta = sub i64 %pi, %selected
  call void @sink(i64 %delta)
  ret void
}

define void @select_pointer_difference(i1 %choose, i8* %p, i8* %q, i8* %r) {
entry:
  %pi = ptrtoint i8* %p to i64
  %qi = ptrtoint i8* %q to i64
  %ri = ptrtoint i8* %r to i64
  %selected = select i1 %choose, i64 %qi, i64 %ri
  %delta = sub i64 %pi, %selected
  call void @sink(i64 %delta)
  ret void
}

define void @mixed_phi_pointer_difference(i1 %choose, i8* %p, i8* %q) {
entry:
  %pi = ptrtoint i8* %p to i64
  %qi = ptrtoint i8* %q to i64
  br i1 %choose, label %left, label %right

left:
  br label %merge

right:
  br label %merge

merge:
  %selected = phi i64 [ %qi, %left ], [ 0, %right ]
  %delta = sub i64 %pi, %selected
  call void @sink(i64 %delta)
  ret void
}

define void @paired_and_raw_pointer_use(i8* %p, i8* %q) {
entry:
  %pi = ptrtoint i8* %p to i64
  %qi = ptrtoint i8* %q to i64
  %delta = sub i64 %pi, %qi
  call void @sink(i64 %delta)
  call void @sink(i64 %pi)
  ret void
}

define void @unpaired_pointer_integer_subtraction(i8* %p) {
entry:
  %pi = ptrtoint i8* %p to i64
  %delta = sub i64 %pi, 4
  call void @sink(i64 %delta)
  ret void
}

define void @escaping_pointer_difference(i8* %p, i8* %q) {
entry:
  %pi = ptrtoint i8* %p to i64
  %qi = ptrtoint i8* %q to i64
  %delta = sub i64 %pi, %qi
  call void @sink(i64 %delta)
  ret void
}

define i8* @reified_pointer_difference(i8* %p, i8* %q) {
entry:
  %pi = ptrtoint i8* %p to i64
  %qi = ptrtoint i8* %q to i64
  %delta = sub i64 %pi, %qi
  %again = inttoptr i64 %delta to i8*
  ret i8* %again
}

define void @stored_pointer_difference(i8* %p, i8* %q) {
entry:
  %pi = ptrtoint i8* %p to i64
  %qi = ptrtoint i8* %q to i64
  %delta = sub i64 %pi, %qi
  store i64 %delta, i64* @observed_difference
  ret void
}

define void @escaping_derived_address(i8* %p, i8* %q, i8* %base) {
entry:
  %pi = ptrtoint i8* %p to i64
  %qi = ptrtoint i8* %q to i64
  %delta = sub i64 %pi, %qi
  %derived = getelementptr i8, i8* %base, i64 %delta
  call void @sink_ptr(i8* %derived)
  ret void
}
"#,
    )
    .unwrap();

    let pir = pir_from_llvm_sys(&ll_path);
    let innocuous = |function: &str| {
        let function = pir
            .functions
            .iter()
            .find(|candidate| candidate.key == function)
            .unwrap();
        let conversions = function
            .body
            .iter()
            .filter_map(|statement| match statement {
                Stmt::PtrToInt {
                    comparison_only, ..
                } => Some(*comparison_only),
                _ => None,
            })
            .collect::<Vec<_>>();
        !conversions.is_empty() && conversions.into_iter().all(|closed| closed)
    };
    assert!(innocuous("direct_compare"));
    assert!(innocuous("arithmetic_compare"));
    assert!(innocuous("select_compare"));
    assert!(innocuous("switch_compare"));
    assert!(!innocuous("unsupported_arithmetic"));
    assert!(!innocuous("externally_observed"));
    assert!(!innocuous("reified"));
    assert!(!innocuous("mixed_use"));
    assert!(innocuous("closed_pointer_difference"));
    assert!(innocuous("shared_paired_pointer_differences"));
    assert!(innocuous("phi_selected_pointer_difference"));
    assert!(innocuous("select_pointer_difference"));
    assert!(!innocuous("mixed_phi_pointer_difference"));
    assert!(!innocuous("paired_and_raw_pointer_use"));
    assert!(!innocuous("unpaired_pointer_integer_subtraction"));
    assert!(innocuous("escaping_pointer_difference"));
    assert!(innocuous("reified_pointer_difference"));
    assert!(innocuous("stored_pointer_difference"));
    assert!(innocuous("escaping_derived_address"));
}

#[test]
fn lowers_unknown_intrinsics_with_pointer_and_non_pointer_shapes() {
    let tmp = TempDir::new().unwrap();
    let ll_path = tmp.path().join("unknown_intrinsics.ll");
    fs::write(
        &ll_path,
        r#"
declare i8* @llvm.ptrmask.p0i8.i64(i8*, i64)
declare i32 @llvm.smax.i32(i32, i32)

define i8* @probe(i8* %p, i32 %a, i32 %b) {
entry:
  %masked = call i8* @llvm.ptrmask.p0i8.i64(i8* %p, i64 255)
  %v = call i32 @llvm.smax.i32(i32 %a, i32 %b)
  ret i8* %masked
}
"#,
    )
    .unwrap();

    let pir = Pir::from_path(&ll_path).unwrap();
    let func = pir.functions.iter().find(|f| f.key == "probe").unwrap();
    assert!(func.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Unknown { op, reason, .. }
            if op == "llvm.ptrmask.p0i8.i64" && reason == "unknown_pointer_intrinsic"
    )));
    assert_eq!(
        pir.lowering.tainted_counts["unknown_pointer_intrinsic:llvm.ptrmask.p0i8.i64"],
        1
    );
    assert_eq!(
        pir.lowering.skipped_counts["unknown_non_pointer_intrinsic:llvm.smax.i32"],
        1
    );
}

#[test]
fn llvm_sys_lowers_unknown_intrinsics_with_pointer_and_non_pointer_shapes() {
    let tmp = TempDir::new().unwrap();
    let ll_path = tmp.path().join("unknown_intrinsics.ll");
    fs::write(
        &ll_path,
        r#"
declare i8* @llvm.ptrmask.p0i8.i64(i8*, i64)
declare i32 @llvm.smax.i32(i32, i32)

define i8* @probe(i8* %p, i32 %a, i32 %b) {
entry:
  %masked = call i8* @llvm.ptrmask.p0i8.i64(i8* %p, i64 255)
  %v = call i32 @llvm.smax.i32(i32 %a, i32 %b)
  ret i8* %masked
}
"#,
    )
    .unwrap();

    let pir = pir_from_llvm_sys(&ll_path);
    let func = pir.functions.iter().find(|f| f.key == "probe").unwrap();
    assert!(func.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Unknown { op, reason, .. }
            if op == "llvm.ptrmask.p0i8.i64" && reason == "unknown_pointer_intrinsic"
    )));
    assert_eq!(
        pir.lowering.tainted_counts["unknown_pointer_intrinsic:llvm.ptrmask.p0i8.i64"],
        1
    );
    assert_eq!(
        pir.lowering.skipped_counts["unknown_non_pointer_intrinsic:llvm.smax.i32"],
        1
    );
}

#[test]
fn llvm_sys_counts_resume_terminators() {
    let tmp = TempDir::new().unwrap();
    let ll_path = tmp.path().join("resume.ll");
    fs::write(
        &ll_path,
        r#"
declare i32 @__gxx_personality_v0(...)
declare i32 @may_throw()

define void @caller() personality i32 (...)* @__gxx_personality_v0 {
entry:
  invoke i32 @may_throw() to label %ok unwind label %lpad

ok:
  ret void

lpad:
  %lp = landingpad { i8*, i32 }
          cleanup
  resume { i8*, i32 } %lp
}
"#,
    )
    .unwrap();

    let pir = pir_from_llvm_sys(&ll_path);
    assert_eq!(pir.lowering.terminator_counts["invoke"], 1);
    assert_eq!(pir.lowering.terminator_counts["resume"], 1);
    assert!(!pir.lowering.terminator_counts.contains_key("other"));
    assert_eq!(pir.lowering.instruction_counts["landingpad"], 1);
}

#[test]
fn lowers_global_initializer_select_pointer_flow_from_ll() {
    let tmp = TempDir::new().unwrap();
    let ll_path = tmp.path().join("global_init_select.ll");
    fs::write(
        &ll_path,
        r#"
@A = extern_weak global i8
@B = extern_weak global i8
@Sel = global i8* select (i1 icmp eq (i8* @A, i8* @B), i8* @A, i8* @B)
"#,
    )
    .unwrap();

    let pir = Pir::from_path(&ll_path).unwrap();
    let selected = pir
        .global_init
        .iter()
        .find_map(|stmt| match stmt {
            Stmt::Assign { dest, sources, .. }
                if sources.iter().map(String::as_str).eq(["@A", "@B"]) =>
            {
                Some(dest.clone())
            }
            _ => None,
        })
        .unwrap();
    assert!(pir.global_init.iter().any(|stmt| matches!(
        stmt,
        Stmt::Store { address, value, .. } if address == "@Sel" && value == &selected
    )));
    assert_eq!(pir.lowering.modeled_counts["global_init_select"], 1);
    assert_eq!(pir.lowering.modeled_counts["global_init_store"], 1);
}

#[test]
fn llvm_sys_lowers_global_initializer_select_pointer_flow_from_ll() {
    let tmp = TempDir::new().unwrap();
    let ll_path = tmp.path().join("global_init_select.ll");
    fs::write(
        &ll_path,
        r#"
@A = extern_weak global i8
@B = extern_weak global i8
@Sel = global i8* select (i1 icmp eq (i8* @A, i8* @B), i8* @A, i8* @B)
"#,
    )
    .unwrap();

    let pir = pir_from_llvm_sys(&ll_path);
    let selected = pir
        .global_init
        .iter()
        .find_map(|stmt| match stmt {
            Stmt::Assign { dest, sources, .. }
                if sources.iter().map(String::as_str).eq(["@A", "@B"]) =>
            {
                Some(dest.clone())
            }
            _ => None,
        })
        .unwrap();
    assert!(pir.global_init.iter().any(|stmt| matches!(
        stmt,
        Stmt::Store { address, value, .. } if address == "@Sel" && value == &selected
    )));
    assert_eq!(pir.lowering.modeled_counts["global_init_select"], 1);
    assert_eq!(pir.lowering.modeled_counts["global_init_store"], 1);
}

#[test]
fn llvm_sys_lowers_blockaddress_global_initializer_without_visiting_basic_block_operands() {
    let tmp = TempDir::new().unwrap();
    let ll_path = tmp.path().join("global_init_blockaddress.ll");
    fs::write(
        &ll_path,
        r#"
@dispatch = global [2 x i8*] [
  i8* blockaddress(@match_at, %left),
  i8* blockaddress(@match_at, %right)
]

define void @match_at(i1 %condition) {
entry:
  br i1 %condition, label %left, label %right

left:
  ret void

right:
  ret void
}
"#,
    )
    .unwrap();

    let pir = pir_from_llvm_sys(&ll_path);
    let block_addresses = pir
        .global_init
        .iter()
        .filter(|stmt| {
            matches!(
                stmt,
                Stmt::Unknown {
                    op,
                    operands,
                    reason,
                    ..
                } if op == "constant_expr:constant"
                    && operands == &["@match_at"]
                    && reason == "global_initializer_pointer_constant"
            )
        })
        .count();

    assert_eq!(block_addresses, 2);
    assert_eq!(pir.lowering.modeled_counts["global_init_store"], 2);
}

fn scalar_phi_rmw_ir() -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/synthetic/disposition/scalar_phi_rmw.ll"),
    )
    .unwrap()
}

#[test]
fn llvm_sys_retains_trusted_current_global_evidence_for_narrow_scalar_phi_rmw() {
    let tmp = TempDir::new().unwrap();
    let ll_path = tmp.path().join("scalar_phi_rmw.ll");
    fs::write(&ll_path, scalar_phi_rmw_ir()).unwrap();

    let pir = pir_from_llvm_sys(&ll_path);
    let evidence = &pir.lowering.scalar_phi_rmw["%update::current"];
    assert_eq!(evidence.global, "g");
    assert_eq!(evidence.reference, "%update::pre");

    let serialized = serde_json::to_string(&pir).unwrap();
    let round_tripped: Pir = serde_json::from_str(&serialized).unwrap();
    assert!(round_tripped.lowering.scalar_phi_rmw.is_empty());
}

#[test]
fn llvm_sys_rejects_scalar_phi_rmw_with_a_stale_or_arbitrary_arm() {
    let variants = [
        scalar_phi_rmw_ir().replace(
            "  %pre = load i32, i32* @g, align 4, !dbg !10\n  br label %join",
            "  %pre = load i32, i32* @g, align 4, !dbg !10\n  store i32 7, i32* @g, align 4, !dbg !10\n  br label %join",
        ),
        scalar_phi_rmw_ir().replace(
            "[ %first, %through ]",
            "[ 7, %through ]",
        ),
        scalar_phi_rmw_ir().replace(
            "through:\n  br label %join",
            "through:\n  store i32 7, i32* @g, align 4, !dbg !11\n  br label %join",
        ),
        scalar_phi_rmw_ir().replace(
            "  %current = phi i32 [ %pre, %direct ], [ %first, %through ], !dbg !10\n  %next = add",
            "  %current = phi i32 [ %pre, %direct ], [ %first, %through ], !dbg !10\n  store i32 7, i32* @g, align 4, !dbg !10\n  %next = add",
        ),
    ];

    for (index, ir) in variants.into_iter().enumerate() {
        let tmp = TempDir::new().unwrap();
        let ll_path = tmp
            .path()
            .join(format!("scalar_phi_rmw_rejected_{index}.ll"));
        fs::write(&ll_path, ir).unwrap();
        let pir = pir_from_llvm_sys(&ll_path);
        assert!(pir.lowering.scalar_phi_rmw.is_empty(), "variant {index}");
    }
}

#[test]
fn lowers_global_initializer_pointer_flow_from_ll() {
    let tmp = TempDir::new().unwrap();
    let ll_path = tmp.path().join("global_init.ll");
    fs::write(
        &ll_path,
        r#"
@G = global i32 0
@FP = global void ()* @target
@FPCast = global i8* bitcast (void ()* @target to i8*)
@GPtr = global i32* @G
@Arr = global [4 x i8] zeroinitializer
@GepPtr = global i8* getelementptr ([4 x i8], [4 x i8]* @Arr, i64 0, i64 1)
@Table = global [2 x void ()*] [void ()* @target, void ()* @other]
%Record = type { i32, void ()* }
@Record = global %Record { i32 7, void ()* @target }

define void @target() {
entry:
  ret void
}

define void @other() {
entry:
  ret void
}
"#,
    )
    .unwrap();

    let pir = pir_from_llvm_sys(&ll_path);
    assert!(
        pir.functions
            .iter()
            .find(|f| f.key == "target")
            .unwrap()
            .address_taken
    );
    assert!(
        pir.functions
            .iter()
            .find(|f| f.key == "other")
            .unwrap()
            .address_taken
    );
    assert!(pir.global_init.iter().any(|stmt| matches!(
        stmt,
        Stmt::Store { address, value, .. } if address == "@FP" && value == "@target"
    )));
    assert!(pir.global_init.iter().any(|stmt| matches!(
        stmt,
        Stmt::Store { address, value, .. } if address == "@GPtr" && value == "@G"
    )));
    assert!(pir.global_init.iter().any(|stmt| matches!(
        stmt,
        Stmt::Assign { sources, .. } if sources.iter().map(String::as_str).eq(["@target"])
    )));
    assert!(pir.global_init.iter().any(|stmt| matches!(
        stmt,
        Stmt::Gep {
            base,
            byte_off: Some(1),
            ..
        } if base == "@Arr"
    )));
    let second_table_slot = pir
        .global_init
        .iter()
        .find_map(|stmt| match stmt {
            Stmt::Gep {
                dest,
                base,
                byte_off: Some(8),
                ..
            } if base == "@Table" => Some(dest.clone()),
            _ => None,
        })
        .unwrap();
    assert!(pir.global_init.iter().any(|stmt| matches!(
        stmt,
        Stmt::Store { address, value, .. } if address == "@Table" && value == "@target"
    )));
    assert!(pir.global_init.iter().any(|stmt| matches!(
        stmt,
        Stmt::Store { address, value, .. } if address == &second_table_slot && value == "@other"
    )));
    let record_field = pir
        .global_init
        .iter()
        .find_map(|stmt| match stmt {
            Stmt::Gep {
                dest,
                base,
                byte_off: Some(8),
                ..
            } if base == "@Record" => Some(dest.clone()),
            _ => None,
        })
        .unwrap();
    assert!(pir.global_init.iter().any(|stmt| matches!(
        stmt,
        Stmt::Store { address, value, .. } if address == &record_field && value == "@target"
    )));
    assert!(pir.lowering.modeled_counts["global_init_store"] >= 6);
    assert!(pir.lowering.modeled_counts["global_init_assign"] >= 1);
    assert_eq!(pir.lowering.modeled_counts["global_init_gep"], 1);
    assert!(pir.lowering.modeled_counts["global_init_field_gep"] >= 2);
    assert_eq!(
        pir.lowering.modeled_counts["global_init_gep_byte_offset"],
        1
    );
}

#[test]
fn llvm_sys_lowers_global_initializer_pointer_flow_from_ll() {
    let tmp = TempDir::new().unwrap();
    let ll_path = tmp.path().join("global_init.ll");
    fs::write(
        &ll_path,
        r#"
@G = global i32 0
@FP = global void ()* @target
@FPCast = global i8* bitcast (void ()* @target to i8*)
@GPtr = global i32* @G
@Arr = global [4 x i8] zeroinitializer
@GepPtr = global i8* getelementptr ([4 x i8], [4 x i8]* @Arr, i64 0, i64 1)
@Table = global [2 x void ()*] [void ()* @target, void ()* @other]
%Record = type { i32, void ()* }
@Record = global %Record { i32 7, void ()* @target }

define void @target() {
entry:
  ret void
}

define void @other() {
entry:
  ret void
}
"#,
    )
    .unwrap();

    let pir = pir_from_llvm_sys(&ll_path);
    assert!(
        pir.functions
            .iter()
            .find(|f| f.key == "target")
            .unwrap()
            .address_taken
    );
    assert!(
        pir.functions
            .iter()
            .find(|f| f.key == "other")
            .unwrap()
            .address_taken
    );
    assert!(pir.global_init.iter().any(|stmt| matches!(
        stmt,
        Stmt::Store { address, value, .. } if address == "@FP" && value == "@target"
    )));
    assert!(pir.global_init.iter().any(|stmt| matches!(
        stmt,
        Stmt::Store { address, value, .. } if address == "@GPtr" && value == "@G"
    )));
    assert!(pir.global_init.iter().any(|stmt| matches!(
        stmt,
        Stmt::Assign { sources, .. } if sources.iter().map(String::as_str).eq(["@target"])
    )));
    assert!(pir.global_init.iter().any(|stmt| matches!(
        stmt,
        Stmt::Gep {
            base,
            byte_off: Some(1),
            ..
        } if base == "@Arr"
    )));
    let second_table_slot = pir
        .global_init
        .iter()
        .find_map(|stmt| match stmt {
            Stmt::Gep {
                dest,
                base,
                byte_off: Some(8),
                ..
            } if base == "@Table" => Some(dest.clone()),
            _ => None,
        })
        .unwrap();
    assert!(pir.global_init.iter().any(|stmt| matches!(
        stmt,
        Stmt::Store { address, value, .. } if address == "@Table" && value == "@target"
    )));
    assert!(pir.global_init.iter().any(|stmt| matches!(
        stmt,
        Stmt::Store { address, value, .. } if address == &second_table_slot && value == "@other"
    )));
    let record_field = pir
        .global_init
        .iter()
        .find_map(|stmt| match stmt {
            Stmt::Gep {
                dest,
                base,
                byte_off: Some(8),
                ..
            } if base == "@Record" => Some(dest.clone()),
            _ => None,
        })
        .unwrap();
    assert!(pir.global_init.iter().any(|stmt| matches!(
        stmt,
        Stmt::Store { address, value, .. } if address == &record_field && value == "@target"
    )));
    assert!(pir.lowering.modeled_counts["global_init_store"] >= 6);
    assert!(pir.lowering.modeled_counts["global_init_assign"] >= 1);
    assert_eq!(pir.lowering.modeled_counts["global_init_gep"], 1);
    assert!(pir.lowering.modeled_counts["global_init_field_gep"] >= 2);
    assert_eq!(
        pir.lowering.modeled_counts["global_init_gep_byte_offset"],
        1
    );
}

#[test]
fn llvm_sys_resolves_internal_aliases() {
    let tmp = TempDir::new().unwrap();
    let ll_path = tmp.path().join("aliases.ll");
    fs::write(
        &ll_path,
        r#"
@G = global i32 0
@GA = internal alias i32, i32* @G
@FnAlias = internal alias void (), void ()* @target

define void @target() {
entry:
  ret void
}

define void @caller() {
entry:
  %v = load i32, i32* @GA
  call void @FnAlias()
  ret void
}
"#,
    )
    .unwrap();

    let pir = pir_from_llvm_sys(&ll_path);
    let caller = pir.functions.iter().find(|f| f.key == "caller").unwrap();
    assert!(caller.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::GlobalRef { global, access, .. } if global == "G" && access == &pangs_pir::Access::Ref
    )));
    assert!(caller.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::CallDirect { callee, .. } if callee == "target"
    )));
    assert_eq!(pir.lowering.modeled_counts["alias_global_resolved"], 1);
    assert_eq!(pir.lowering.modeled_counts["alias_function_resolved"], 1);
    assert_eq!(pir.lowering.modeled_counts["alias_call_direct"], 1);
}

#[test]
fn llvm_sys_records_runtime_global_rewrite_roots_through_constant_casts() {
    let tmp = TempDir::new().unwrap();
    let ll_path = tmp.path().join("rewrite-roots.ll");
    fs::write(
        &ll_path,
        r#"
%Map = type { i8*, i64 }
@include_guards = internal global %Map zeroinitializer

declare void @consume(i8*)

define void @include_file() {
entry:
  call void @consume(i8* bitcast (%Map* @include_guards to i8*))
  ret void
}
"#,
    )
    .unwrap();

    let pir = pir_from_llvm_sys(&ll_path);
    assert_eq!(
        pir.lowering.rewrite_global_refs["include_file"],
        vec!["include_guards"]
    );
}

#[test]
fn llvm_sys_lowers_ifunc_callee_as_unknown() {
    let tmp = TempDir::new().unwrap();
    let ll_path = tmp.path().join("ifunc.ll");
    fs::write(
        &ll_path,
        r#"
@IfuncTarget = ifunc void (), void ()* ()* @resolve

define void @target() {
entry:
  ret void
}

define void ()* @resolve() {
entry:
  ret void ()* @target
}

define void @ifunc_caller() {
entry:
  call void @IfuncTarget()
  ret void
}
"#,
    )
    .unwrap();

    let pir = pir_from_llvm_sys(&ll_path);
    let caller = pir
        .functions
        .iter()
        .find(|f| f.key == "ifunc_caller")
        .unwrap();
    assert!(caller.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Unknown { reason, op, .. } if reason == "ifunc_callee" && op == "call"
    )));
    assert_eq!(pir.lowering.ifuncs, 1);
    assert_eq!(pir.lowering.tainted_counts["ifunc:IfuncTarget"], 1);
    assert_eq!(pir.lowering.tainted_counts["ifunc_callee:IfuncTarget"], 1);
}

#[test]
fn llvm_sys_lowers_invoke_and_taints_exception_flow() {
    let tmp = TempDir::new().unwrap();
    let ll_path = tmp.path().join("invoke.ll");
    fs::write(
        &ll_path,
        r#"
declare i32 @may_throw()
declare i32 @__gxx_personality_v0(...)

define i32 @caller() personality i32 (...)* @__gxx_personality_v0 {
entry:
  %res = invoke i32 @may_throw() to label %ok unwind label %lpad

ok:
  ret i32 %res

lpad:
  %lp = landingpad { i8*, i32 }
          cleanup
  ret i32 0
}
"#,
    )
    .unwrap();

    let pir = pir_from_llvm_sys(&ll_path);
    let caller = pir.functions.iter().find(|f| f.key == "caller").unwrap();
    assert!(caller.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::CallDirect { callee, sig, .. }
            if callee == "may_throw" && sig.ret == pangs_pir::AbiClass::Integer
    )));
    assert_eq!(pir.lowering.terminator_counts["invoke"], 1);
    assert_eq!(
        pir.lowering.tainted_counts["invoke_exception_control_flow"],
        1
    );
    assert_eq!(pir.lowering.tainted_counts["personality_function"], 1);
    assert!(
        pir.functions
            .iter()
            .find(|f| f.key == "__gxx_personality_v0")
            .unwrap()
            .address_taken
    );
}

#[test]
fn llvm_sys_lowers_clang14_asm_goto_bitcode() {
    assert!(
        Path::new(CLANG_14).exists(),
        "LLVM-14 clang is required for the asm goto lowering test"
    );

    let tmp = TempDir::new().unwrap();
    let c_path = tmp.path().join("asm_goto.c");
    let bc_path = tmp.path().join("asm_goto.bc");
    fs::write(
        &c_path,
        r#"
void target(void);

void caller(void) {
  asm goto ("" :::: hit);
  target();
hit:
  return;
}
"#,
    )
    .unwrap();

    let status = Command::new(CLANG_14)
        .arg("-O0")
        .arg("-emit-llvm")
        .arg("-c")
        .arg(&c_path)
        .arg("-o")
        .arg(&bc_path)
        .status()
        .unwrap();
    assert!(status.success());

    let pir = pir_from_llvm_sys(&bc_path);
    let caller = pir.functions.iter().find(|f| f.key == "caller").unwrap();
    assert!(caller.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Unknown { op, reason, .. } if op == "callbr" && reason == "inline_asm_callbr"
    )));
    assert_eq!(pir.lowering.terminator_counts["callbr"], 1);
    assert_eq!(pir.lowering.tainted_counts["callbr"], 1);
}

#[test]
fn llvm_sys_taints_pointer_vectors_and_models_aggregate_pointer_fields() {
    let tmp = TempDir::new().unwrap();
    let ll_path = tmp.path().join("aggregate_eh.ll");
    fs::write(
        &ll_path,
        r#"
declare i32 @__gxx_personality_v0(...)
declare i32 @may_throw()

define i8* @agg_and_eh(i8* %p, i8* %q) personality i32 (...)* @__gxx_personality_v0 {
entry:
  %vec0 = insertelement <2 x i8*> poison, i8* %p, i64 0
  %vec1 = insertelement <2 x i8*> %vec0, i8* %q, i64 1
  %elt = extractelement <2 x i8*> %vec1, i64 0
  %agg0 = insertvalue { i8*, i32 } undef, i8* %p, 0
  %agg1 = insertvalue { i8*, i32 } %agg0, i32 7, 1
  %field = extractvalue { i8*, i32 } %agg1, 0
  invoke i32 @may_throw() to label %ok unwind label %lpad

ok:
  ret i8* %field

lpad:
  %lp = landingpad { i8*, i32 }
          cleanup
  %ehptr = extractvalue { i8*, i32 } %lp, 0
  ret i8* %ehptr
}
"#,
    )
    .unwrap();

    let pir = pir_from_llvm_sys(&ll_path);
    assert_eq!(
        pir.lowering.semantic_value_kinds.get("%agg_and_eh::agg0"),
        Some(&ValueKind::PointerAggregate)
    );
    assert_eq!(
        pir.lowering.semantic_value_kinds.get("%agg_and_eh::field"),
        Some(&ValueKind::Pointer)
    );
    assert!(
        pir.functions
            .iter()
            .find(|f| f.key == "__gxx_personality_v0")
            .unwrap()
            .address_taken
    );
    let func = pir
        .functions
        .iter()
        .find(|f| f.key == "agg_and_eh")
        .unwrap();
    assert!(func.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Unknown { op, reason, .. } if op == "insertelement" && reason == "pointer_vector"
    )));
    assert!(func.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Unknown { op, reason, .. } if op == "extractelement" && reason == "pointer_vector"
    )));
    assert!(func.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Assign { dest, sources, .. }
            if dest.ends_with("::agg0") && sources.contains(&"%agg_and_eh::p".to_string())
    )));
    assert!(func.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Assign { dest, sources, .. }
            if dest.ends_with("::field")
                && sources.iter().map(String::as_str).eq(["%agg_and_eh::agg1"])
    )));
    assert!(func.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Unknown {
            op,
            reason,
            results,
            ..
        } if op == "landingpad"
            && reason == "landingpad_pointer_result"
            && results.iter().map(String::as_str).eq(["%agg_and_eh::lp"])
    )));
    assert!(func.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Assign { dest, sources, .. }
            if dest.ends_with("::ehptr")
                && sources.iter().map(String::as_str).eq(["%agg_and_eh::lp"])
    )));
    assert_eq!(pir.lowering.tainted_counts["personality_function"], 1);
    assert_eq!(
        pir.lowering.tainted_counts["personality_operand:@__gxx_personality_v0"],
        1
    );
    assert_eq!(
        pir.lowering.tainted_counts["pointer_vector:insertelement"],
        2
    );
    assert_eq!(
        pir.lowering.tainted_counts["pointer_vector:extractelement"],
        1
    );
    assert_eq!(pir.lowering.tainted_counts["landingpad_pointer_result"], 1);
    assert_eq!(pir.lowering.tainted_counts["insertvalue_coarse"], 2);
    assert_eq!(pir.lowering.modeled_counts["insertvalue"], 2);
    assert_eq!(pir.lowering.modeled_counts["extractvalue"], 2);
}

#[test]
fn computes_gep_byte_offsets_from_ll() {
    let tmp = TempDir::new().unwrap();
    let ll_path = tmp.path().join("gep_offsets.ll");
    fs::write(
        &ll_path,
        r#"
%S = type { i8, i32, i8* }
%Inner = type { i16, i8* }
%Outer = type { i8, [3 x %Inner] }
@table = internal global [512 x %S] zeroinitializer

define void @gep_offsets(i32* %arr, %S* %s, %Outer* %o, i64 %idx) {
entry:
  %arr_gep = getelementptr i32, i32* %arr, i64 3
  %struct_gep = getelementptr %S, %S* %s, i64 0, i32 1
  %nested_gep = getelementptr %Outer, %Outer* %o, i64 0, i32 1, i64 2, i32 1
  %dynamic_gep = getelementptr i32, i32* %arr, i64 %idx
  %dynamic_field = getelementptr [512 x %S], [512 x %S]* @table, i64 0, i64 %idx, i32 2
  ret void
}
"#,
    )
    .unwrap();

    let pir = Pir::from_path(&ll_path).unwrap();
    let func = pir
        .functions
        .iter()
        .find(|f| f.key == "gep_offsets")
        .unwrap();
    assert!(func.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Gep {
            dest,
            byte_off: Some(12),
            ..
        } if dest.ends_with("::arr_gep")
    )));
    assert!(func.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Gep {
            dest,
            byte_off: Some(4),
            ..
        } if dest.ends_with("::struct_gep")
    )));
    assert!(func.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Gep {
            dest,
            byte_off: Some(48),
            ..
        } if dest.ends_with("::nested_gep")
    )));
    assert!(func.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Gep {
            dest,
            byte_off: None,
            lane: Some(GepLane {
                modulus: 4,
                residue: 0
            }),
            ..
        } if dest.ends_with("::dynamic_gep")
    )));
    assert!(func.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Gep {
            dest,
            byte_off: None,
            lane: Some(GepLane {
                modulus: 16,
                residue: 8
            }),
            ..
        } if dest.ends_with("::dynamic_field")
    )));
    assert_eq!(pir.lowering.modeled_counts["gep_byte_offset"], 3);
    assert_eq!(pir.lowering.modeled_counts["gep_array_lane"], 2);
    assert_eq!(
        pir.lowering
            .skipped_counts
            .get("gep_dynamic_index")
            .copied()
            .unwrap_or(0),
        0
    );
}

#[test]
fn lowers_ifunc_callee_as_unknown() {
    let tmp = TempDir::new().unwrap();
    let ll_path = tmp.path().join("ifunc.ll");
    fs::write(
        &ll_path,
        r#"
@IfuncTarget = ifunc void (), void ()* ()* @resolve

define void @target() {
entry:
  ret void
}

define void ()* @resolve() {
entry:
  ret void ()* @target
}

define void @ifunc_caller() {
entry:
  call void @IfuncTarget()
  ret void
}
"#,
    )
    .unwrap();

    let pir = Pir::from_path(&ll_path).unwrap();
    let caller = pir
        .functions
        .iter()
        .find(|f| f.key == "ifunc_caller")
        .unwrap();
    assert!(caller.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Unknown {
            reason,
            op,
            ..
        } if reason == "ifunc_callee" && op == "call"
    )));
    assert_eq!(pir.lowering.ifuncs, 1);
    assert_eq!(pir.lowering.tainted_counts["ifunc:IfuncTarget"], 1);
    assert_eq!(pir.lowering.tainted_counts["ifunc_callee:IfuncTarget"], 1);
}

#[test]
fn lowers_invoke_as_direct_call_and_taints_exception_flow() {
    let tmp = TempDir::new().unwrap();
    let ll_path = tmp.path().join("invoke.ll");
    fs::write(
        &ll_path,
        r#"
declare i32 @may_throw()
declare i32 @__gxx_personality_v0(...)

define i32 @caller() personality i32 (...)* @__gxx_personality_v0 {
entry:
  %res = invoke i32 @may_throw() to label %ok unwind label %lpad

ok:
  ret i32 %res

lpad:
  %lp = landingpad { i8*, i32 }
          cleanup
  ret i32 0
}
"#,
    )
    .unwrap();

    let pir = Pir::from_path(&ll_path).unwrap();
    let caller = pir.functions.iter().find(|f| f.key == "caller").unwrap();
    assert!(caller.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::CallDirect { callee, sig, .. }
            if callee == "may_throw" && sig.ret == pangs_pir::AbiClass::Integer
    )));
    assert_eq!(pir.lowering.terminator_counts["invoke"], 1);
    assert_eq!(
        pir.lowering.tainted_counts["invoke_exception_control_flow"],
        1
    );
    assert_eq!(pir.lowering.tainted_counts["personality_function"], 1);
}

#[test]
fn taints_pointer_vectors_and_models_aggregate_pointer_fields() {
    let tmp = TempDir::new().unwrap();
    let ll_path = tmp.path().join("aggregate_eh.ll");
    fs::write(
        &ll_path,
        r#"
declare i32 @__gxx_personality_v0(...)
declare i32 @may_throw()

define i8* @agg_and_eh(i8* %p, i8* %q) personality i32 (...)* @__gxx_personality_v0 {
entry:
  %vec0 = insertelement <2 x i8*> poison, i8* %p, i64 0
  %vec1 = insertelement <2 x i8*> %vec0, i8* %q, i64 1
  %elt = extractelement <2 x i8*> %vec1, i64 0
  %agg0 = insertvalue { i8*, i32 } undef, i8* %p, 0
  %agg1 = insertvalue { i8*, i32 } %agg0, i32 7, 1
  %field = extractvalue { i8*, i32 } %agg1, 0
  invoke i32 @may_throw() to label %ok unwind label %lpad

ok:
  ret i8* %field

lpad:
  %lp = landingpad { i8*, i32 }
          cleanup
  %ehptr = extractvalue { i8*, i32 } %lp, 0
  ret i8* %ehptr
}

"#,
    )
    .unwrap();

    let pir = Pir::from_path(&ll_path).unwrap();
    assert!(
        pir.functions
            .iter()
            .find(|f| f.key == "__gxx_personality_v0")
            .unwrap()
            .address_taken
    );
    let func = pir
        .functions
        .iter()
        .find(|f| f.key == "agg_and_eh")
        .unwrap();
    assert!(func.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Unknown { op, reason, .. } if op == "insertelement" && reason == "pointer_vector"
    )));
    assert!(func.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Unknown { op, reason, .. } if op == "extractelement" && reason == "pointer_vector"
    )));
    assert!(func.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Assign { dest, sources, .. }
            if dest.ends_with("::agg0") && sources.contains(&"%agg_and_eh::p".to_string())
    )));
    assert!(func.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Assign { dest, sources, .. }
            if dest.ends_with("::field") && sources == &vec!["%agg_and_eh::agg1".to_string()]
    )));
    assert!(func.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Unknown {
            op,
            reason,
            results,
            ..
        } if op == "landingpad"
            && reason == "landingpad_pointer_result"
            && results == &vec!["%agg_and_eh::lp".to_string()]
    )));
    assert!(func.body.iter().any(|stmt| matches!(
        stmt,
        Stmt::Assign { dest, sources, .. }
            if dest.ends_with("::ehptr") && sources == &vec!["%agg_and_eh::lp".to_string()]
    )));
    assert_eq!(pir.lowering.tainted_counts["personality_function"], 1);
    assert_eq!(
        pir.lowering.tainted_counts["personality_operand:@__gxx_personality_v0"],
        1
    );
    assert_eq!(
        pir.lowering.tainted_counts["pointer_vector:insertelement"],
        2
    );
    assert_eq!(
        pir.lowering.tainted_counts["pointer_vector:extractelement"],
        1
    );
    assert_eq!(pir.lowering.tainted_counts["landingpad_pointer_result"], 1);
    assert_eq!(pir.lowering.tainted_counts["insertvalue_coarse"], 2);
    assert_eq!(pir.lowering.modeled_counts["insertvalue"], 2);
    assert_eq!(pir.lowering.modeled_counts["extractvalue"], 2);
}
