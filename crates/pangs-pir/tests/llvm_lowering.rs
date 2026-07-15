use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use pangs_pir::{Param, Pir, ScalarTypeClass, Stmt};
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
    assert!(flow
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::PtrToInt { .. })));
    assert!(flow
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::IntToPtr { .. })));
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
    assert!(flow
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::PtrToInt { .. })));
    assert!(flow
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::IntToPtr { .. })));
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
fn llvm_sys_names_unmodeled_arithmetic_opcodes() {
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
  %cmp = icmp eq i32 %sum, %diff
  %fsum = fadd float %x, %y
  %neg = fneg float %x
  ret void
}
"#,
    )
    .unwrap();

    let pir = pir_from_llvm_sys(&ll_path);
    assert_eq!(pir.lowering.instruction_counts["add"], 1);
    assert_eq!(pir.lowering.instruction_counts["sub"], 1);
    assert_eq!(pir.lowering.instruction_counts["and"], 1);
    assert_eq!(pir.lowering.instruction_counts["icmp"], 1);
    assert_eq!(pir.lowering.instruction_counts["fadd"], 1);
    assert_eq!(pir.lowering.instruction_counts["fneg"], 1);
    assert_eq!(pir.lowering.skipped_counts["unmodeled_instruction:add"], 1);
    assert_eq!(pir.lowering.skipped_counts["unmodeled_instruction:sub"], 1);
    assert_eq!(pir.lowering.skipped_counts["unmodeled_instruction:and"], 1);
    assert_eq!(pir.lowering.skipped_counts["unmodeled_instruction:icmp"], 1);
    assert_eq!(pir.lowering.skipped_counts["unmodeled_instruction:fadd"], 1);
    assert_eq!(pir.lowering.skipped_counts["unmodeled_instruction:fneg"], 1);
    assert!(!pir
        .lowering
        .skipped_counts
        .contains_key("unmodeled_instruction:other"));
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

define void @gep_offsets(i32* %arr, %S* %s, %Outer* %o, i64 %idx) {
entry:
  %arr_gep = getelementptr i32, i32* %arr, i64 3
  %struct_gep = getelementptr %S, %S* %s, i64 0, i32 1
  %nested_gep = getelementptr %Outer, %Outer* %o, i64 0, i32 1, i64 2, i32 1
  %dynamic_gep = getelementptr i32, i32* %arr, i64 %idx
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
            ..
        } if dest.ends_with("::dynamic_gep")
    )));
    assert_eq!(pir.lowering.modeled_counts["gep_byte_offset"], 3);
    assert_eq!(pir.lowering.skipped_counts["gep_dynamic_index"], 1);
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
