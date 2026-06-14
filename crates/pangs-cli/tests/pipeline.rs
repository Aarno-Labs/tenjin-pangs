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

fn m1_3_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/m1_3")
        .join(name)
}

fn m1_4_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/m1_4")
        .join(name)
}

fn m1_5_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/m1_5")
        .join(name)
}

fn m1_6_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/m1_6")
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

#[test]
fn analyze_external_callee_fixture_freezes_only_the_connected_component() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/trivial/external_callee_split.pir.json");
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("out");

    run_analyze(&fixture, &out);

    let callgraph: Vec<Value> = fs::read_to_string(out.join("callgraph.jsonl"))
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(callgraph.len(), 3);
    assert!(callgraph.iter().any(|row| {
        row["caller"]["func"] == "main"
            && row["callee"]["func"] == "driver"
            && row["tier"] == "direct"
    }));
    assert!(callgraph.iter().any(|row| {
        row["caller"]["func"] == "driver"
            && row["callsite"] == "driver@fixtures/synthetic/trivial/external_callee_split.c:10:3#0"
            && row["callee"]["unknown"] == "external_callee"
            && row["tier"] == "direct"
    }));
    assert!(callgraph.iter().any(|row| {
        row["caller"]["unknown"] == "address_escapes_to_external" && row["callee"]["func"] == "main"
    }));

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
            Value::String("main".to_string())
        ]
    );
    assert_eq!(
        frozen["mutable_globals"].as_array().unwrap(),
        &vec![Value::String("g_external".to_string())]
    );
    assert!(frozen["taint"].as_array().unwrap().iter().any(|taint| {
        taint["kind"] == "unknown_callee"
            && taint["witness"]
                == "driver@fixtures/synthetic/trivial/external_callee_split.c:10:3#0"
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
        &vec![Value::String("g_local".to_string())]
    );
    assert_eq!(rewritable["taint"].as_array().unwrap().len(), 0);

    assert_eq!(components["coverage"]["mutable_globals_total"], 2);
    assert_eq!(components["coverage"]["in_rewritable_components"], 1);

    let metrics: Value =
        serde_json::from_str(&fs::read_to_string(out.join("metrics.json")).unwrap()).unwrap();
    assert_eq!(metrics["functions"], 3);
    assert_eq!(metrics["globals"], 2);
    assert_eq!(metrics["callsites"], 2);
    assert_eq!(metrics["call_edges"], 3);
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
        row["func"] == "driver"
            && row["global"]["name"] == "g_external"
            && row["witness"] == "driver@fixtures/synthetic/trivial/external_callee_split.c:9:3#0"
    }));
    assert!(modref.iter().any(|row| {
        row["func"] == "worker"
            && row["global"]["name"] == "g_local"
            && row["witness"] == "worker@fixtures/synthetic/trivial/external_callee_split.c:15:3#0"
    }));
}

#[test]
fn dump_pag_emits_core_graph_and_function_filter() {
    let fixture = m1_3_fixture("core_edges.pir.json");

    let output = Command::new(env!("CARGO_BIN_EXE_pangs"))
        .arg("dump-pag")
        .arg(&fixture)
        .arg("--build-mode")
        .arg("executable")
        .arg("--func")
        .arg("main")
        .output()
        .unwrap();
    assert!(output.status.success());

    let pag: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(pag["module"], "m1_3_core");
    assert_eq!(
        pag["metrics"]["nodes"],
        pag["nodes"].as_array().unwrap().len()
    );
    assert_eq!(
        pag["metrics"]["edges"],
        pag["edges"].as_array().unwrap().len()
    );
    assert_eq!(
        pag["metrics"]["callsites"],
        pag["callsites"].as_array().unwrap().len()
    );
    assert_eq!(pag["callsites"].as_array().unwrap().len(), 3);
    assert!(pag["callsites"].as_array().unwrap().iter().any(|callsite| {
        callsite["callee"] == "id_i32"
            && callsite["args"].as_array().unwrap().len() == 1
            && callsite["result"].is_number()
    }));
    assert!(pag["edges"]
        .as_array()
        .unwrap()
        .iter()
        .any(|edge| edge["kind"]["kind"] == "store"));
    assert!(pag["edges"]
        .as_array()
        .unwrap()
        .iter()
        .any(|edge| edge["kind"]["kind"] == "gep"));
    assert!(pag["omega_seeds"]
        .as_array()
        .unwrap()
        .iter()
        .any(|seed| seed["kind"] == "external_call_boundary"));
}

#[test]
fn check_pag_accepts_core_fixture() {
    let fixture = m1_3_fixture("core_edges.pir.json");

    let status = Command::new(env!("CARGO_BIN_EXE_pangs"))
        .arg("check-pag")
        .arg(&fixture)
        .arg("--build-mode")
        .arg("executable")
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn check_pag_accepts_checked_in_m1_1_fixtures() {
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
        let fixture = m1_1_fixture(name);
        let status = Command::new(env!("CARGO_BIN_EXE_pangs"))
            .arg("check-pag")
            .arg(&fixture)
            .arg("--build-mode")
            .arg("executable")
            .status()
            .unwrap();
        assert!(status.success(), "{name}");
    }
}

#[test]
fn analyze_steens_exports_narrowed_indirect_targets() {
    let fixture = m1_4_fixture("steens_escape_icall.pir.json");
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("out");

    let status = Command::new(env!("CARGO_BIN_EXE_pangs"))
        .arg("analyze")
        .arg(&fixture)
        .arg("-o")
        .arg(&out)
        .arg("--validate")
        .arg("--stage")
        .arg("steens")
        .status()
        .unwrap();
    assert!(status.success());

    let callgraph: Vec<Value> = fs::read_to_string(out.join("callgraph.jsonl"))
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(callgraph.iter().any(|row| {
        row["caller"]["func"] == "setup" && row["callee"]["func"] == "cb" && row["tier"] == "steens"
    }));
    assert!(!callgraph
        .iter()
        .any(|row| { row["caller"]["func"] == "setup" && row["callee"]["func"] == "other" }));
    assert!(callgraph.iter().any(|row| {
        row["caller"]["func"] == "setup" && row["callee"]["unknown"] == "omega_fnptr"
    }));

    let globals: Vec<Value> = fs::read_to_string(out.join("globals.jsonl"))
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(globals.iter().any(|row| row["key"] == "@CB"
        && row["escape"] == "external"
        && row["never_written"] == false));
    assert!(globals.iter().any(|row| row["key"] == "@Local"
        && row["escape"] == "module"
        && row["never_written"] == true));

    let metrics: Value =
        serde_json::from_str(&fs::read_to_string(out.join("metrics.json")).unwrap()).unwrap();
    assert!(metrics["partition_count"].as_u64().unwrap() > 0);
    assert_eq!(metrics["rounds"], 1);
}

#[test]
fn analyze_steens_narrows_exported_callgraph_vs_conservative() {
    let fixture = m1_4_fixture("steens_escape_icall.pir.json");
    let tmp = TempDir::new().unwrap();
    let out_conservative = tmp.path().join("conservative");
    let out_steens = tmp.path().join("steens");

    let conservative = Command::new(env!("CARGO_BIN_EXE_pangs"))
        .arg("analyze")
        .arg(&fixture)
        .arg("-o")
        .arg(&out_conservative)
        .arg("--validate")
        .arg("--stage")
        .arg("conservative")
        .status()
        .unwrap();
    assert!(conservative.success());

    let steens = Command::new(env!("CARGO_BIN_EXE_pangs"))
        .arg("analyze")
        .arg(&fixture)
        .arg("-o")
        .arg(&out_steens)
        .arg("--validate")
        .arg("--stage")
        .arg("steens")
        .status()
        .unwrap();
    assert!(steens.success());

    let conservative_callgraph: Vec<Value> =
        fs::read_to_string(out_conservative.join("callgraph.jsonl"))
            .unwrap()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
    let steens_callgraph: Vec<Value> = fs::read_to_string(out_steens.join("callgraph.jsonl"))
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();

    assert!(conservative_callgraph.iter().any(|row| {
        row["caller"]["func"] == "setup" && row["callee"]["func"] == "other" && row["tier"] == "fsa"
    }));
    assert!(!steens_callgraph
        .iter()
        .any(|row| { row["caller"]["func"] == "setup" && row["callee"]["func"] == "other" }));
    assert!(conservative_callgraph.iter().any(|row| {
        row["caller"]["func"] == "setup" && row["callee"]["func"] == "cb" && row["tier"] == "fsa"
    }));
    assert!(steens_callgraph.iter().any(|row| {
        row["caller"]["func"] == "setup" && row["callee"]["func"] == "cb" && row["tier"] == "steens"
    }));
    assert!(conservative_callgraph.iter().any(|row| {
        row["caller"]["func"] == "setup" && row["callee"]["unknown"] == "omega_fnptr"
    }));
    assert!(steens_callgraph.iter().any(|row| {
        row["caller"]["func"] == "setup" && row["callee"]["unknown"] == "omega_fnptr"
    }));
    assert!(steens_callgraph.len() < conservative_callgraph.len());
}

#[test]
fn analyze_steens_improves_rewritable_coverage_over_conservative() {
    let fixture = m1_4_fixture("address_taken_local_only.pir.json");
    let tmp = TempDir::new().unwrap();
    let out_conservative = tmp.path().join("conservative");
    let out_steens = tmp.path().join("steens");

    run_analyze_stage(&fixture, &out_conservative, "conservative");
    run_analyze_stage(&fixture, &out_steens, "steens");

    let conservative_components: Value = serde_json::from_str(
        &fs::read_to_string(out_conservative.join("components.json")).unwrap(),
    )
    .unwrap();
    let steens_components: Value =
        serde_json::from_str(&fs::read_to_string(out_steens.join("components.json")).unwrap())
            .unwrap();

    assert_eq!(
        conservative_components["coverage"]["mutable_globals_total"],
        1
    );
    assert_eq!(
        conservative_components["coverage"]["in_rewritable_components"],
        0
    );
    assert_eq!(steens_components["coverage"]["mutable_globals_total"], 1);
    assert_eq!(steens_components["coverage"]["in_rewritable_components"], 1);
    assert_eq!(
        conservative_components["components"][0]["frozen"],
        Value::Bool(true)
    );
    assert_eq!(
        steens_components["components"][0]["frozen"],
        Value::Bool(false)
    );

    let conservative_callgraph =
        fs::read_to_string(out_conservative.join("callgraph.jsonl")).unwrap();
    let steens_callgraph = fs::read_to_string(out_steens.join("callgraph.jsonl")).unwrap();
    assert!(conservative_callgraph.contains("\"unknown\":\"address_escapes_to_external\""));
    assert!(!steens_callgraph.contains("\"unknown\":\"address_escapes_to_external\""));
}

#[test]
fn analyze_inline_asm_exports_audit_and_freezes_the_component() {
    let fixture = m1_1_fixture("inline_asm.ll");
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("out");

    run_analyze(&fixture, &out);

    let audit: Vec<Value> = fs::read_to_string(out.join("audit.jsonl"))
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0]["kind"], "inline_asm");
    assert_eq!(audit[0]["effect"], "omega_taint");

    let components: Value =
        serde_json::from_str(&fs::read_to_string(out.join("components.json")).unwrap()).unwrap();
    assert_eq!(components["components"][0]["frozen"], Value::Bool(true));
    assert!(components["components"][0]["taint"]
        .as_array()
        .unwrap()
        .iter()
        .any(|taint| { taint["kind"] == "inline_asm" && taint["witness"] == "asm_call@!noloc#0" }));

    let metrics: Value =
        serde_json::from_str(&fs::read_to_string(out.join("metrics.json")).unwrap()).unwrap();
    assert_eq!(metrics["audit_findings"], 1);
}

#[test]
fn analyze_audit_surface_exports_boundary_and_vararg_findings() {
    let fixture = m1_5_fixture("audit_surface.pir.json");
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("out");

    run_analyze(&fixture, &out);

    let audit: Vec<Value> = fs::read_to_string(out.join("audit.jsonl"))
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(audit.len(), 6);
    assert!(audit.iter().any(|row| row["kind"] == "fnptr_varargs"));
    assert!(
        audit
            .iter()
            .filter(|row| row["kind"] == "dlopen_dlsym")
            .count()
            == 2
    );
    assert!(
        audit
            .iter()
            .filter(|row| row["kind"] == "setjmp_longjmp")
            .count()
            == 2
    );

    let metrics: Value =
        serde_json::from_str(&fs::read_to_string(out.join("metrics.json")).unwrap()).unwrap();
    assert_eq!(metrics["audit_findings"], 6);
}

#[test]
fn analyze_steens_exports_fnptr_int_punning_audits_but_not_non_fn_ptrtoint() {
    let tmp = TempDir::new().unwrap();

    let fnptr_fixture = m1_5_fixture("fnptr_int_punning.pir.json");
    let fnptr_out = tmp.path().join("fnptr");
    run_analyze_stage(&fnptr_fixture, &fnptr_out, "steens");

    let fnptr_audit: Vec<Value> = fs::read_to_string(fnptr_out.join("audit.jsonl"))
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(fnptr_audit
        .iter()
        .any(|row| row["kind"] == "fnptr_ptrtoint"));
    assert!(fnptr_audit
        .iter()
        .any(|row| row["kind"] == "fnptr_inttoptr"));

    let plain_fixture = m1_4_fixture("ptrtoint_escape.pir.json");
    let plain_out = tmp.path().join("plain");
    run_analyze_stage(&plain_fixture, &plain_out, "steens");

    let plain_audit = fs::read_to_string(plain_out.join("audit.jsonl")).unwrap();
    assert!(!plain_audit.contains("fnptr_ptrtoint"));
    assert!(!plain_audit.contains("fnptr_inttoptr"));
}

#[test]
fn analyze_exports_memop_findings_for_fnptr_aggregates() {
    let fixture = m1_5_fixture("fnptr_aggregate_memops.pir.json");
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("out");

    run_analyze(&fixture, &out);

    let audit: Vec<Value> = fs::read_to_string(out.join("audit.jsonl"))
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(audit
        .iter()
        .any(|row| row["kind"] == "memcpy_fnptr_aggregate"));
    assert!(audit
        .iter()
        .any(|row| row["kind"] == "memset_fnptr_aggregate"));

    let components: Value =
        serde_json::from_str(&fs::read_to_string(out.join("components.json")).unwrap()).unwrap();
    assert_eq!(components["components"][0]["frozen"], Value::Bool(true));
    assert!(components["components"][0]["taint"]
        .as_array()
        .unwrap()
        .iter()
        .any(|taint| taint["kind"] == "memcpy_fnptr_aggregate"));
    assert!(components["components"][0]["taint"]
        .as_array()
        .unwrap()
        .iter()
        .any(|taint| taint["kind"] == "memset_fnptr_aggregate"));

    let metrics: Value =
        serde_json::from_str(&fs::read_to_string(out.join("metrics.json")).unwrap()).unwrap();
    assert_eq!(metrics["audit_findings"], 2);
}

#[test]
fn analyze_steens_exports_vararg_function_pointer_audits_from_local_values() {
    let fixture = m1_5_fixture("vararg_fnptr_flow.pir.json");
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("out");

    run_analyze_stage(&fixture, &out, "steens");

    let audit: Vec<Value> = fs::read_to_string(out.join("audit.jsonl"))
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(audit.iter().any(|row| {
        row["kind"] == "fnptr_varargs" && row["affected"] == serde_json::json!(["value:%fp"])
    }));

    let callgraph = fs::read_to_string(out.join("callgraph.jsonl")).unwrap();
    assert!(callgraph.contains("\"unknown\":\"address_escapes_to_external\""));

    let components: Value =
        serde_json::from_str(&fs::read_to_string(out.join("components.json")).unwrap()).unwrap();
    assert!(components["components"]
        .as_array()
        .unwrap()
        .iter()
        .any(
            |component| component["members"] == serde_json::json!(["driver", "sink"])
                && component["taint"].as_array().unwrap().iter().any(|taint| {
                    taint["kind"] == "fnptr_varargs" && taint["witness"] == "driver@!noloc#0"
                })
        ));
}

#[test]
fn analyze_steens_exports_pointer_aware_modref_and_freezes_unknown_global_components() {
    let fixture = m1_6_fixture("aliased_unknown_modref.pir.json");
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("out");

    run_analyze_stage(&fixture, &out, "steens");

    let modref: Vec<Value> = fs::read_to_string(out.join("modref.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(modref.iter().any(|row| {
        row["func"] == "main"
            && row["global"]["name"] == "@Direct"
            && row["access"] == "ref"
            && row["via"] == "direct"
            && row["witness"] == "main@m1_6.c:1:1#0"
    }));
    assert!(modref.iter().any(|row| {
        row["func"] == "main"
            && row["global"]["name"] == "@Aliased"
            && row["access"] == "ref"
            && row["via"] == "aliased"
            && row["witness"] == "main@m1_6.c:3:1#0"
    }));
    assert!(modref.iter().any(|row| {
        row["func"] == "main"
            && row["global"]["name"] == "@Aliased"
            && row["access"] == "mod"
            && row["via"] == "aliased"
            && row["witness"] == "main@m1_6.c:4:1#0"
    }));
    assert!(modref.iter().any(|row| {
        row["func"] == "main"
            && row["global"]["unknown"] == "omega_load"
            && row["access"] == "ref"
            && row["via"] == "unknown"
            && row["witness"] == "main@m1_6.c:6:1#0"
    }));
    assert!(modref.iter().any(|row| {
        row["func"] == "main"
            && row["global"]["unknown"] == "omega_store"
            && row["access"] == "mod"
            && row["via"] == "unknown"
            && row["witness"] == "main@m1_6.c:7:1#0"
    }));

    let components: Value =
        serde_json::from_str(&fs::read_to_string(out.join("components.json")).unwrap()).unwrap();
    assert!(components["components"]
        .as_array()
        .unwrap()
        .iter()
        .any(|component| {
            component["members"] == serde_json::json!(["main"])
                && component["frozen"] == true
                && component["taint"].as_array().unwrap().iter().any(|taint| {
                    taint["kind"] == "unknown_global" && taint["witness"] == "main@m1_6.c:6:1#0"
                })
        }));
}

#[test]
fn analyze_steens_exports_memcpy_pointer_modref_rows() {
    let fixture = m1_6_fixture("memcpy_modref.pir.json");
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("out");

    run_analyze_stage(&fixture, &out, "steens");

    let modref: Vec<Value> = fs::read_to_string(out.join("modref.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(modref.iter().any(|row| {
        row["func"] == "main"
            && row["global"]["name"] == "@SrcAliased"
            && row["access"] == "ref"
            && row["via"] == "aliased"
            && row["witness"] == "main@m1_6_memcpy.c:3:1#0"
    }));
    assert!(modref.iter().any(|row| {
        row["func"] == "main"
            && row["global"]["name"] == "@DstAliased"
            && row["access"] == "mod"
            && row["via"] == "aliased"
            && row["witness"] == "main@m1_6_memcpy.c:3:1#0"
    }));
    assert!(modref.iter().any(|row| {
        row["func"] == "main"
            && row["global"]["name"] == "@DirectSrc"
            && row["access"] == "ref"
            && row["via"] == "aliased"
            && row["witness"] == "main@m1_6_memcpy.c:7:1#0"
    }));
    assert!(modref.iter().any(|row| {
        row["func"] == "main"
            && row["global"]["name"] == "@DirectDst"
            && row["access"] == "mod"
            && row["via"] == "aliased"
            && row["witness"] == "main@m1_6_memcpy.c:7:1#0"
    }));
    assert!(modref.iter().any(|row| {
        row["func"] == "main"
            && row["global"]["unknown"] == "omega_load"
            && row["access"] == "ref"
            && row["via"] == "unknown"
            && row["witness"] == "main@m1_6_memcpy.c:6:1#0"
    }));
    assert!(modref.iter().any(|row| {
        row["func"] == "main"
            && row["global"]["unknown"] == "omega_store"
            && row["access"] == "mod"
            && row["via"] == "unknown"
            && row["witness"] == "main@m1_6_memcpy.c:6:1#0"
    }));

    let components: Value =
        serde_json::from_str(&fs::read_to_string(out.join("components.json")).unwrap()).unwrap();
    assert!(components["components"]
        .as_array()
        .unwrap()
        .iter()
        .any(|component| {
            component["members"] == serde_json::json!(["main"])
                && component["frozen"] == true
                && component["taint"].as_array().unwrap().iter().any(|taint| {
                    taint["kind"] == "unknown_global"
                        && taint["witness"] == "main@m1_6_memcpy.c:6:1#0"
                })
        }));
}

#[test]
fn analyze_steens_keeps_pointer_modref_exports_local_while_callgraph_narrows_indirect_target() {
    let fixture = m1_6_fixture("transitive_icall_modref.pir.json");
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("out");

    run_analyze_stage(&fixture, &out, "steens");

    let callgraph: Vec<Value> = fs::read_to_string(out.join("callgraph.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(callgraph.iter().any(|row| {
        row["caller"]["func"] == "main"
            && row["callee"]["func"] == "setup"
            && row["tier"] == "direct"
    }));
    assert!(callgraph.iter().any(|row| {
        row["caller"]["func"] == "setup"
            && row["callee"]["func"] == "target"
            && row["tier"] == "steens"
            && row["callsite"] == "setup@m1_6_icall.c:12:1#0"
    }));
    assert!(!callgraph.iter().any(|row| {
        row["caller"]["func"] == "setup"
            && row["callee"]["func"] == "other"
            && row["tier"] == "steens"
    }));

    let modref: Vec<Value> = fs::read_to_string(out.join("modref.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(modref.iter().any(|row| {
        row["func"] == "target"
            && row["global"]["name"] == "@Aliased"
            && row["access"] == "ref"
            && row["via"] == "aliased"
            && row["witness"] == "target@m1_6_icall.c:21:1#0"
    }));
    assert!(modref.iter().any(|row| {
        row["func"] == "target"
            && row["global"]["unknown"] == "omega_store"
            && row["access"] == "mod"
            && row["via"] == "unknown"
            && row["witness"] == "target@m1_6_icall.c:23:1#0"
    }));
    assert!(modref.iter().any(|row| {
        row["func"] == "other"
            && row["global"]["name"] == "@Noise"
            && row["access"] == "mod"
            && row["via"] == "direct"
            && row["witness"] == "other@m1_6_icall.c:30:1#0"
    }));
    assert!(!modref
        .iter()
        .any(|row| row["func"] == "setup" || row["func"] == "main"));
}

#[test]
fn analyze_steens_exports_memset_pointer_modref_rows() {
    let fixture = m1_6_fixture("memset_modref.pir.json");
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("out");

    run_analyze_stage(&fixture, &out, "steens");

    let modref: Vec<Value> = fs::read_to_string(out.join("modref.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(modref.iter().any(|row| {
        row["func"] == "main"
            && row["global"]["name"] == "@Aliased"
            && row["access"] == "mod"
            && row["via"] == "aliased"
            && row["witness"] == "main@m1_6_memset.c:2:1#0"
    }));
    assert!(modref.iter().any(|row| {
        row["func"] == "main"
            && row["global"]["unknown"] == "omega_store"
            && row["access"] == "mod"
            && row["via"] == "unknown"
            && row["witness"] == "main@m1_6_memset.c:4:1#0"
    }));
    assert!(modref.iter().any(|row| {
        row["func"] == "main"
            && row["global"]["name"] == "@DirectDst"
            && row["access"] == "mod"
            && row["via"] == "aliased"
            && row["witness"] == "main@m1_6_memset.c:5:1#0"
    }));
    assert!(!modref.iter().any(|row| row["access"] == "ref"));

    let components: Value =
        serde_json::from_str(&fs::read_to_string(out.join("components.json")).unwrap()).unwrap();
    assert!(components["components"]
        .as_array()
        .unwrap()
        .iter()
        .any(|component| {
            component["members"] == serde_json::json!(["main"])
                && component["frozen"] == true
                && component["taint"].as_array().unwrap().iter().any(|taint| {
                    taint["kind"] == "unknown_global"
                        && taint["witness"] == "main@m1_6_memset.c:4:1#0"
                })
        }));
}

#[test]
fn analyze_steens_alias_rows_improve_rewritable_coverage_over_conservative() {
    let fixture = m1_6_fixture("aliased_coverage_gain.pir.json");
    let tmp = TempDir::new().unwrap();
    let out_cons = tmp.path().join("cons");
    let out_steens = tmp.path().join("steens");

    run_analyze_stage(&fixture, &out_cons, "conservative");
    run_analyze_stage(&fixture, &out_steens, "steens");

    let cons_modref = fs::read_to_string(out_cons.join("modref.jsonl")).unwrap();
    assert!(cons_modref.trim().is_empty());

    let cons_components: Value =
        serde_json::from_str(&fs::read_to_string(out_cons.join("components.json")).unwrap())
            .unwrap();
    assert!(cons_components["components"]
        .as_array()
        .unwrap()
        .iter()
        .any(|component| {
            component["members"] == serde_json::json!(["worker"])
                && component["frozen"] == false
                && component["mutable_globals"] == serde_json::json!([])
        }));
    let cons_metrics: Value =
        serde_json::from_str(&fs::read_to_string(out_cons.join("metrics.json")).unwrap()).unwrap();
    assert_eq!(cons_metrics["mutable_globals_total"], 1);
    assert_eq!(cons_metrics["in_rewritable_components"], 0);

    let steens_modref: Vec<Value> = fs::read_to_string(out_steens.join("modref.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(steens_modref.iter().any(|row| {
        row["func"] == "worker"
            && row["global"]["name"] == "@G"
            && row["access"] == "ref"
            && row["via"] == "aliased"
            && row["witness"] == "worker@m1_6_cover.c:2:1#0"
    }));

    let steens_components: Value =
        serde_json::from_str(&fs::read_to_string(out_steens.join("components.json")).unwrap())
            .unwrap();
    assert!(steens_components["components"]
        .as_array()
        .unwrap()
        .iter()
        .any(|component| {
            component["members"] == serde_json::json!(["worker"])
                && component["frozen"] == false
                && component["mutable_globals"] == serde_json::json!(["@G"])
        }));
    let steens_metrics: Value =
        serde_json::from_str(&fs::read_to_string(out_steens.join("metrics.json")).unwrap())
            .unwrap();
    assert_eq!(steens_metrics["mutable_globals_total"], 1);
    assert_eq!(steens_metrics["in_rewritable_components"], 1);
}

fn run_analyze(fixture: &Path, out: &Path) {
    run_analyze_stage(fixture, out, "conservative");
}

fn run_analyze_stage(fixture: &Path, out: &Path, stage: &str) {
    let status = Command::new(env!("CARGO_BIN_EXE_pangs"))
        .arg("analyze")
        .arg(fixture)
        .arg("-o")
        .arg(out)
        .arg("--validate")
        .arg("--stage")
        .arg(stage)
        .arg("--build-mode")
        .arg("executable")
        .status()
        .unwrap();
    assert!(status.success());
}
