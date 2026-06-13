use std::fs;
use std::path::Path;
use std::process::Command;

use pangs_pir::{Pir, Stmt};
use tempfile::TempDir;

const CLANG_14: &str = "/home/brk/tenjin/_local/xj-llvm-14/bin/clang";

#[test]
fn lowers_llvm14_bitcode_function_pointer_smoke() {
    assert!(
        Path::new(CLANG_14).exists(),
        "LLVM-14 clang is required for the M1.1 lowering smoke test"
    );

    let tmp = TempDir::new().unwrap();
    let c_path = tmp.path().join("fp.c");
    let bc_path = tmp.path().join("fp.bc");
    fs::write(
        &c_path,
        r#"
int g_counter;
void target(long value);
void (*fp)(long) = target;

void target(long value) {
  g_counter = (int)value;
}

void driver(void) {
  fp(7);
}
"#,
    )
    .unwrap();

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
    assert_eq!(pir.lowering.modeled_counts["memcpy"], 1);
    assert_eq!(pir.lowering.modeled_counts["atomicrmw"], 1);
    assert_eq!(pir.lowering.modeled_counts["cmpxchg"], 1);
    assert_eq!(pir.lowering.tainted_counts["inttoptr"], 1);
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

    let pir = Pir::from_path(&ll_path).unwrap();
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
        Stmt::Assign { sources, .. } if sources == &vec!["@target".to_string()]
    )));
    assert!(pir.global_init.iter().any(|stmt| matches!(
        stmt,
        Stmt::Gep {
            base,
            byte_off: None,
            ..
        } if base == "@Arr"
    )));
    assert_eq!(
        pir.global_init
            .iter()
            .filter(|stmt| matches!(stmt, Stmt::Store { address, value, .. } if address == "@Table" && (value == "@target" || value == "@other")))
            .count(),
        2
    );
    assert!(pir.lowering.modeled_counts["global_init_store"] >= 5);
    assert!(pir.lowering.modeled_counts["global_init_assign"] >= 1);
    assert_eq!(pir.lowering.modeled_counts["global_init_gep"], 1);
}
