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
