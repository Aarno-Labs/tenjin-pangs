use std::fs;
use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

#[test]
fn analyze_validate_is_deterministic() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/trivial/module.pir.json");
    let tmp = TempDir::new().unwrap();
    let out_a = tmp.path().join("a");
    let out_b = tmp.path().join("b");

    run_analyze(&fixture, &out_a);
    run_analyze(&fixture, &out_b);

    for name in [
        "functions.jsonl",
        "globals.jsonl",
        "callgraph.jsonl",
        "modref.jsonl",
        "components.json",
        "audit.jsonl",
        "metrics.json",
    ] {
        let a = fs::read(out_a.join(name)).unwrap();
        let b = fs::read(out_b.join(name)).unwrap();
        assert_eq!(a, b, "{name} should be byte-identical");
    }
}

#[test]
fn analyze_validate_llvm_noloc_is_deterministic() {
    let tmp = TempDir::new().unwrap();
    let fixture = tmp.path().join("noloc.ll");
    fs::write(
        &fixture,
        r#"
@GP = global i8* null

define void @callee(i8* %p) {
entry:
  store i8* %p, i8** @GP
  ret void
}

define void @driver(i8* %p) {
entry:
  call void @callee(i8* %p)
  store i8* %p, i8** @GP
  ret void
}
"#,
    )
    .unwrap();

    let out_a = tmp.path().join("a");
    let out_b = tmp.path().join("b");

    run_analyze(&fixture, &out_a);
    run_analyze(&fixture, &out_b);

    for name in [
        "functions.jsonl",
        "globals.jsonl",
        "callgraph.jsonl",
        "modref.jsonl",
        "components.json",
        "audit.jsonl",
        "metrics.json",
    ] {
        let a = fs::read(out_a.join(name)).unwrap();
        let b = fs::read(out_b.join(name)).unwrap();
        assert_eq!(a, b, "{name} should be byte-identical");
    }

    let callgraph = fs::read_to_string(out_a.join("callgraph.jsonl")).unwrap();
    assert!(callgraph.contains("\"callsite\":\"driver@!noloc#0\""));
    let modref = fs::read_to_string(out_a.join("modref.jsonl")).unwrap();
    assert!(modref.contains("\"witness\":\"callee@!noloc#0\""));
    assert!(modref.contains("\"witness\":\"driver@!noloc#0\""));
}

#[test]
fn analyze_validate_llvm_sys_noloc_is_deterministic() {
    let tmp = TempDir::new().unwrap();
    let fixture = tmp.path().join("noloc.ll");
    fs::write(
        &fixture,
        r#"
@GP = global i8* null

define void @callee(i8* %p) {
entry:
  store i8* %p, i8** @GP
  ret void
}

define void @driver(i8* %p) {
entry:
  call void @callee(i8* %p)
  store i8* %p, i8** @GP
  ret void
}
"#,
    )
    .unwrap();

    let out_a = tmp.path().join("a");
    let out_b = tmp.path().join("b");

    run_analyze_with_backend(&fixture, &out_a, "llvm-sys");
    run_analyze_with_backend(&fixture, &out_b, "llvm-sys");

    for name in [
        "functions.jsonl",
        "globals.jsonl",
        "callgraph.jsonl",
        "modref.jsonl",
        "components.json",
        "audit.jsonl",
        "metrics.json",
    ] {
        let a = fs::read(out_a.join(name)).unwrap();
        let b = fs::read(out_b.join(name)).unwrap();
        assert_eq!(a, b, "{name} should be byte-identical");
    }

    let callgraph = fs::read_to_string(out_a.join("callgraph.jsonl")).unwrap();
    assert!(callgraph.contains("\"callsite\":\"driver@!noloc#0\""));
    let modref = fs::read_to_string(out_a.join("modref.jsonl")).unwrap();
    assert!(modref.contains("\"witness\":\"callee@!noloc#0\""));
    assert!(modref.contains("\"witness\":\"driver@!noloc#0\""));
}

fn run_analyze(fixture: &Path, out: &Path) {
    run_analyze_with_backend(fixture, out, "llvm-ir");
}

fn run_analyze_with_backend(fixture: &Path, out: &Path, backend: &str) {
    let status = Command::new(env!("CARGO_BIN_EXE_pangs"))
        .arg("analyze")
        .arg(fixture)
        .arg("-o")
        .arg(out)
        .arg("--validate")
        .arg("--build-mode")
        .arg("executable")
        .arg("--llvm-backend")
        .arg(backend)
        .status()
        .unwrap();
    assert!(status.success());
}
