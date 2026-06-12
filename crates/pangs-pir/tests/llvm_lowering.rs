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

    let driver = pir.functions.iter().find(|f| f.key == "driver").unwrap();
    assert!(driver
        .body
        .iter()
        .any(|stmt| matches!(stmt, Stmt::CallIndirect { .. })));

    assert!(pir
        .globals
        .iter()
        .any(|global| global.key == "g_counter" && global.mutable));
}
