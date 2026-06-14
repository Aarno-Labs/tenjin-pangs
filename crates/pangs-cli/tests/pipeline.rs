use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
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

#[test]
fn analyze_trivial_fixture_exports_components_and_coverage() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/trivial/module.pir.json");
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("out");

    run_analyze(&fixture, &out);

    let callgraph: Vec<Value> = fs::read_to_string(out.join("callgraph.jsonl"))
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(callgraph.len(), 5);
    assert!(callgraph.iter().any(|row| {
        row["caller"]["func"] == "main"
            && row["callee"]["func"] == "driver"
            && row["tier"] == "direct"
    }));
    assert!(callgraph.iter().any(|row| {
        row["caller"]["func"] == "driver"
            && row["callee"]["func"] == "target"
            && row["tier"] == "fsa"
    }));
    assert!(callgraph.iter().any(|row| {
        row["caller"]["unknown"] == "address_escapes_to_external"
            && row["callee"]["func"] == "target"
    }));

    let components: Value =
        serde_json::from_str(&fs::read_to_string(out.join("components.json")).unwrap()).unwrap();
    let list = components["components"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    let component = &list[0];
    assert_eq!(component["id"], "c0001");
    assert_eq!(component["frozen"], true);
    assert_eq!(
        component["members"].as_array().unwrap(),
        &vec![
            Value::String("driver".to_string()),
            Value::String("main".to_string()),
            Value::String("target".to_string())
        ]
    );
    assert_eq!(
        component["mutable_globals"].as_array().unwrap(),
        &vec![Value::String("g_counter".to_string())]
    );
    assert!(component["taint"].as_array().unwrap().iter().any(|taint| {
        taint["kind"] == "unknown_callee"
            && taint["witness"] == "driver@fixtures/synthetic/trivial/trivial.c:9:3#0"
    }));
    assert!(component["taint"]
        .as_array()
        .unwrap()
        .iter()
        .any(|taint| { taint["kind"] == "unknown_caller" && taint["witness"].is_null() }));
    assert_eq!(components["coverage"]["mutable_globals_total"], 1);
    assert_eq!(components["coverage"]["in_rewritable_components"], 0);

    let metrics: Value =
        serde_json::from_str(&fs::read_to_string(out.join("metrics.json")).unwrap()).unwrap();
    assert_eq!(metrics["functions"], 3);
    assert_eq!(metrics["globals"], 1);
    assert_eq!(metrics["callsites"], 2);
    assert_eq!(metrics["call_edges"], 5);
    assert_eq!(metrics["mutable_globals_total"], 1);
    assert_eq!(metrics["in_rewritable_components"], 0);

    let modref: Vec<Value> = fs::read_to_string(out.join("modref.jsonl"))
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(modref.len(), 1);
    assert_eq!(modref[0]["func"], "main");
    assert_eq!(modref[0]["global"]["name"], "g_counter");
    assert_eq!(modref[0]["access"], "mod");
    assert_eq!(
        modref[0]["witness"],
        "main@fixtures/synthetic/trivial/trivial.c:4:3#0"
    );
}

#[test]
fn analyze_split_fixture_reports_rewritable_coverage() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/trivial/rewritable_split.pir.json");
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("out");

    run_analyze(&fixture, &out);

    let components: Value =
        serde_json::from_str(&fs::read_to_string(out.join("components.json")).unwrap()).unwrap();
    let list = components["components"].as_array().unwrap();
    assert_eq!(list.len(), 2);

    let frozen = &list[0];
    assert_eq!(frozen["id"], "c0001");
    assert_eq!(frozen["frozen"], true);
    assert_eq!(
        frozen["members"].as_array().unwrap(),
        &vec![
            Value::String("driver".to_string()),
            Value::String("main".to_string()),
            Value::String("target".to_string())
        ]
    );
    assert_eq!(
        frozen["mutable_globals"].as_array().unwrap(),
        &vec![Value::String("g_tainted".to_string())]
    );
    assert!(frozen["taint"].as_array().unwrap().iter().any(|taint| {
        taint["kind"] == "unknown_callee"
            && taint["witness"] == "driver@fixtures/synthetic/trivial/rewritable_split.c:9:3#0"
    }));
    assert!(frozen["taint"]
        .as_array()
        .unwrap()
        .iter()
        .any(|taint| { taint["kind"] == "unknown_caller" && taint["witness"].is_null() }));

    let rewritable = &list[1];
    assert_eq!(rewritable["id"], "c0002");
    assert_eq!(rewritable["frozen"], false);
    assert_eq!(
        rewritable["members"].as_array().unwrap(),
        &vec![Value::String("worker".to_string())]
    );
    assert_eq!(
        rewritable["mutable_globals"].as_array().unwrap(),
        &vec![Value::String("g_rewrite".to_string())]
    );
    assert_eq!(rewritable["taint"].as_array().unwrap().len(), 0);

    assert_eq!(components["coverage"]["mutable_globals_total"], 2);
    assert_eq!(components["coverage"]["in_rewritable_components"], 1);

    let metrics: Value =
        serde_json::from_str(&fs::read_to_string(out.join("metrics.json")).unwrap()).unwrap();
    assert_eq!(metrics["functions"], 4);
    assert_eq!(metrics["globals"], 2);
    assert_eq!(metrics["callsites"], 2);
    assert_eq!(metrics["call_edges"], 5);
    assert_eq!(metrics["mutable_globals_total"], 2);
    assert_eq!(metrics["in_rewritable_components"], 1);

    let modref: Vec<Value> = fs::read_to_string(out.join("modref.jsonl"))
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(modref.len(), 2);
    assert!(modref.iter().any(|row| {
        row["func"] == "target"
            && row["global"]["name"] == "g_tainted"
            && row["witness"] == "target@fixtures/synthetic/trivial/rewritable_split.c:13:3#0"
    }));
    assert!(modref.iter().any(|row| {
        row["func"] == "worker"
            && row["global"]["name"] == "g_rewrite"
            && row["witness"] == "worker@fixtures/synthetic/trivial/rewritable_split.c:18:3#0"
    }));
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
