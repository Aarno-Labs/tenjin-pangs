use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

fn m1_1_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/m1_1")
        .join(name)
}

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
    let fixture = m1_1_fixture("no_debug.ll");
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
fn analyze_validate_checked_in_m1_1_fixtures() {
    let tmp = TempDir::new().unwrap();
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/synthetic/m1_1");
    assert!(
        fs::read_dir(&corpus).unwrap().count() >= 20,
        "expected at least 20 checked-in M1.1 fixtures"
    );
    let out_a = tmp.path().join("a");
    for name in [
        "address_taken.ll",
        "aggregate_eh.ll",
        "abi_rows.ll",
        "addrspacecast.ll",
        "aliases.ll",
        "arithmetic.ll",
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
        let fixture = m1_1_fixture(name);
        let out = out_a.join(name.trim_end_matches(".ll"));
        run_analyze(&fixture, &out);
        for artifact in [
            "functions.jsonl",
            "globals.jsonl",
            "callgraph.jsonl",
            "modref.jsonl",
            "components.json",
            "audit.jsonl",
            "metrics.json",
        ] {
            assert!(
                out.join(artifact).exists(),
                "{} should exist for {}",
                artifact,
                name
            );
        }
    }
}

fn run_analyze(fixture: &Path, out: &Path) {
    let status = Command::new(env!("CARGO_BIN_EXE_pangs"))
        .arg("analyze")
        .arg(fixture)
        .arg("-o")
        .arg(out)
        .arg("--validate")
        .arg("--build-mode")
        .arg("executable")
        .status()
        .unwrap();
    assert!(status.success());
}
