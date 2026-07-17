use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use sha2::{Digest, Sha256};
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

fn m1_7_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/m1_7")
        .join(name)
}

fn m2_2_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/m2_2")
        .join(name)
}

fn m2_3_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/m2_3")
        .join(name)
}

fn m2_4_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/m2_4")
        .join(name)
}

fn m3_3_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/m3_3")
        .join(name)
}

fn m5_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/m5")
        .join(name)
}

fn scrub_timing_fields(mut metrics: Value) -> Value {
    let object = metrics.as_object_mut().unwrap();
    for key in [
        "analysis_wall_us",
        "setup_scan_us",
        "preanalysis_us",
        "pag_build_us",
        "solve_us",
        "solver_postprocess_us",
        "pointer_modref_us",
        "callgraph_dedup_us",
        "modref_dedup_us",
        "stationarity_us",
        "initval_reapply_us",
        "transitive_modref_us",
        "findings_dedup_us",
        "components_us",
        "metrics_bookkeeping_us",
    ] {
        object.remove(key);
    }
    metrics
}

/// Regression for the callsite-key ordinal mismatch (ju_steens_overmerge_bug.md).
/// A function with two indirect calls at *distinct* source locations used to lose the
/// second site's resolved targets from `callgraph.jsonl`: the solver keyed callsites with
/// a per-function ordinal (`…:7:5#0`, `…:9:5#1`) while the export layer keyed them
/// per-distinct-loc (`…:7:5#0`, `…:9:5#0`), so the export-time `callsite_by_key` lookup
/// missed the second site and silently dropped its edge — a soundness false negative.
/// Both indirect edges must now appear on both `steens` and `andersen`.
#[test]
fn two_distinct_loc_icalls_both_appear_in_callgraph() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/m1_4b/two_global_fnptrs.pir.json");

    for stage in ["steens", "andersen"] {
        let tmp = TempDir::new().unwrap();
        let out = tmp.path().join(stage);
        run_analyze_stage(&fixture, &out, stage);

        let edges: Vec<Value> = fs::read_to_string(out.join("callgraph.jsonl"))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let indirect: Vec<&Value> = edges.iter().filter(|e| e["kind"] == "indirect").collect();
        let callees: Vec<&str> = indirect
            .iter()
            .filter_map(|e| e["callee"]["func"].as_str())
            .collect();
        assert!(
            callees.contains(&"alpha"),
            "{stage}: first icall site (alpha) missing: {indirect:?}"
        );
        assert!(
            callees.contains(&"beta"),
            "{stage}: second icall site (beta) dropped — callsite-key ordinal drift: {indirect:?}"
        );
        // The two sites have distinct keys ending in #0 and #1 (per-function ordinals).
        let keys: Vec<&str> = indirect
            .iter()
            .filter_map(|e| e["callsite"].as_str())
            .collect();
        assert!(
            keys.iter().any(|k| k.ends_with("#0")),
            "missing #0: {keys:?}"
        );
        assert!(
            keys.iter().any(|k| k.ends_with("#1")),
            "missing #1: {keys:?}"
        );
    }
}

#[test]
fn analyze_exports_m2_2_simple_icall_provenance() {
    let fixture = m2_2_fixture("simple_local_assign.pir.json");
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("out");

    run_analyze_stage(&fixture, &out, "andersen");

    let callgraph: Vec<Value> = fs::read_to_string(out.join("callgraph.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let indirect = callgraph
        .iter()
        .filter(|row| row["kind"] == "indirect")
        .collect::<Vec<_>>();
    assert_eq!(indirect.len(), 1, "{indirect:#?}");
    assert_eq!(indirect[0]["callee"]["func"], "cb");
    assert_eq!(indirect[0]["tier"], "simple");

    let metrics: Value =
        serde_json::from_str(&fs::read_to_string(out.join("metrics.json")).unwrap()).unwrap();
    assert_eq!(metrics["icalls_simple"], 1);
    assert_eq!(metrics["icalls_andersen"], 0);
    assert_eq!(metrics["icalls_unknown"], 0);
}

#[test]
fn analyze_exports_m2_3_confined_subtraction() {
    let fixture = m2_3_fixture("confined_subtraction.pir.json");
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("out");

    run_analyze_stage(&fixture, &out, "andersen");

    let callgraph: Vec<Value> = fs::read_to_string(out.join("callgraph.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(callgraph.iter().any(|row| {
        row["kind"] == "indirect"
            && row["callsite"] == "driver@!noloc#0"
            && row["callee"]["func"] == "cb"
            && row["tier"] == "simple"
    }));
    assert!(callgraph.iter().any(|row| {
        row["kind"] == "indirect"
            && row["callsite"] == "driver@!noloc#1"
            && row["callee"]["func"] == "other"
            && row["tier"] == "andersen"
    }));
    assert!(!callgraph.iter().any(|row| {
        row["kind"] == "indirect"
            && row["callsite"] == "driver@!noloc#1"
            && row["callee"]["func"] == "cb"
    }));

    let metrics: Value =
        serde_json::from_str(&fs::read_to_string(out.join("metrics.json")).unwrap()).unwrap();
    assert_eq!(metrics["confined_functions"], 1);
    assert_eq!(metrics["icalls_simple"], 1);
    assert_eq!(metrics["icalls_andersen"], 1);
}

#[test]
fn analyze_exports_m2_4_initval_dispatch_table_resolution() {
    let fixture = m2_4_fixture("initval_dispatch_table.pir.json");
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("out");

    run_analyze_stage(&fixture, &out, "andersen");

    let callgraph: Vec<Value> = fs::read_to_string(out.join("callgraph.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let indirect = callgraph
        .iter()
        .filter(|row| row["kind"] == "indirect")
        .collect::<Vec<_>>();
    assert_eq!(indirect.len(), 1, "{indirect:#?}");
    assert_eq!(indirect[0]["callee"]["func"], "other");
    assert_eq!(indirect[0]["tier"], "simple");

    let metrics: Value =
        serde_json::from_str(&fs::read_to_string(out.join("metrics.json")).unwrap()).unwrap();
    assert_eq!(metrics["icalls_simple"], 1);
    assert_eq!(metrics["globals_with_complete_initval"], 1);
    assert_eq!(metrics["stationary_globals"], 1);
    assert_eq!(metrics["mutable_globals_total"], 0);
    assert_eq!(metrics["in_rewritable_components"], 0);

    let globals: Vec<Value> = fs::read_to_string(out.join("globals.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(globals.iter().any(|row| {
        row["key"] == "@Table" && row["mutable"] == true && row["stationary"] == true
    }));
    let stationarity: Vec<Value> = fs::read_to_string(out.join("stationarity.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(stationarity.len(), 1, "{stationarity:#?}");
    assert_eq!(stationarity[0]["global"], "@Table");
    assert_eq!(stationarity[0]["complete_initval"], true);
    assert_eq!(stationarity[0]["stationary"], true);
    assert_eq!(stationarity[0]["reason"], "stationary");
    assert_eq!(stationarity[0]["runtime_writers"], serde_json::json!([]));

    let components: Value =
        serde_json::from_str(&fs::read_to_string(out.join("components.json")).unwrap()).unwrap();
    assert_eq!(components["coverage"]["mutable_globals_total"], 0);
    assert_eq!(components["coverage"]["in_rewritable_components"], 0);
    assert!(components["components"]
        .as_array()
        .unwrap()
        .iter()
        .all(|component| {
            component["mutable_globals"]
                .as_array()
                .unwrap()
                .iter()
                .all(|global| global != "@Table")
        }));
}

#[test]
fn analyze_exports_m2_5_stationarity_unknown_writer_evidence() {
    let fixture = m2_4_fixture("initval_unknown_runtime_mod_blocks_stationarity.pir.json");
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("out");

    run_analyze_stage(&fixture, &out, "andersen");

    let stationarity: Vec<Value> = fs::read_to_string(out.join("stationarity.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(stationarity.len(), 1, "{stationarity:#?}");
    assert_eq!(stationarity[0]["global"], "@Table");
    assert_eq!(stationarity[0]["complete_initval"], true);
    assert_eq!(stationarity[0]["stationary"], false);
    assert_eq!(stationarity[0]["reason"], "unknown_runtime_writer");
    assert!(stationarity[0]["runtime_writers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|writer| {
            writer["func"] == "driver"
                && writer["global"]["unknown"] == "omega_store"
                && writer["access"] == "mod"
        }));

    let modref: Vec<Value> = fs::read_to_string(out.join("modref.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(modref.iter().any(|row| {
        row["func"] == "driver"
            && row["global"]["unknown"] == "omega_store"
            && row["access"] == "mod"
            && row["detail"] == "edge:store|omega:inttoptr|pointee_count=0"
    }));
}

#[test]
fn analyze_exports_scalar_pointer_initval_stationarity() {
    let fixture = m2_4_fixture("initval_scalar_pointer_global.pir.json");
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("out");

    run_analyze_stage(&fixture, &out, "andersen");

    let metrics: Value =
        serde_json::from_str(&fs::read_to_string(out.join("metrics.json")).unwrap()).unwrap();
    assert_eq!(metrics["globals_with_complete_initval"], 1);
    assert_eq!(metrics["stationary_globals"], 1);

    let stationarity: Vec<Value> = fs::read_to_string(out.join("stationarity.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let sep = stationarity
        .iter()
        .find(|row| row["global"] == "@Sep")
        .unwrap();
    assert_eq!(sep["complete_initval"], true);
    assert_eq!(sep["stationary"], true);
    assert_eq!(sep["reason"], "stationary");
    assert!(sep["initval_diagnostics"]
        .as_array()
        .is_none_or(|diagnostics| diagnostics.is_empty()));
}

#[test]
fn m2_ablation_reports_preanalysis_variants() {
    let fixture = m2_2_fixture("simple_local_assign.pir.json");
    let output = Command::new(env!("CARGO_BIN_EXE_pangs"))
        .arg("m2-ablation")
        .arg(&fixture)
        .arg("--stage")
        .arg("andersen")
        .arg("--build-mode")
        .arg("executable")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "m2-ablation failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let variants = report["variants"].as_array().unwrap();
    assert_eq!(variants.len(), 4, "{variants:#?}");
    assert!(variants
        .iter()
        .any(|variant| { variant["mode"] == "m1_baseline" && variant["icalls_simple"] == 0 }));
    assert!(variants
        .iter()
        .any(|variant| { variant["mode"] == "b2_only" && variant["icalls_simple"] == 1 }));
    assert!(variants
        .iter()
        .any(|variant| { variant["mode"] == "b1_only" && variant["icalls_simple"] == 0 }));
    assert!(variants
        .iter()
        .any(|variant| { variant["mode"] == "both" && variant["icalls_simple"] == 1 }));
}

#[test]
fn query_callees_reports_m3_1_field_insensitive_results() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/m3_1/two_level_memory.pir.json");
    let output = Command::new(env!("CARGO_BIN_EXE_pangs"))
        .arg("query")
        .arg("callees")
        .arg(&fixture)
        .arg("--build-mode")
        .arg("executable")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "query callees failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["kind"], "callees");
    assert_eq!(report["experimental"], "tier_e_prototype");
    assert_eq!(report["used_by_lite_analyze"], false);
    assert_eq!(report["mode"], "field_sensitive");
    assert_eq!(
        report["by_callsite"]["driver@!noloc#0"],
        serde_json::json!(["target"])
    );
    assert_eq!(report["queries"].as_array().unwrap().len(), 1);
    assert!(report["max_visited_states"].as_u64().unwrap() >= 6);
    let histogram_total = report["visit_histogram"]["le_10"].as_u64().unwrap()
        + report["visit_histogram"]["le_100"].as_u64().unwrap()
        + report["visit_histogram"]["le_1000"].as_u64().unwrap()
        + report["visit_histogram"]["gt_1000"].as_u64().unwrap();
    assert_eq!(histogram_total, 1);
}

#[test]
fn query_callees_mode_selects_field_sensitivity() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/synthetic/m1_4b/field_sensitive_fnptr.pir.json");
    let insensitive = Command::new(env!("CARGO_BIN_EXE_pangs"))
        .arg("query")
        .arg("callees")
        .arg(&fixture)
        .arg("--mode")
        .arg("field-insensitive")
        .output()
        .unwrap();
    assert!(
        insensitive.status.success(),
        "query callees --mode field-insensitive failed:\n{}",
        String::from_utf8_lossy(&insensitive.stderr)
    );
    let insensitive: Value = serde_json::from_slice(&insensitive.stdout).unwrap();
    assert_eq!(insensitive["mode"], "field_insensitive");
    assert_eq!(
        insensitive["by_callsite"]["setup@!noloc#0"],
        serde_json::json!(["f0", "f1"])
    );

    let sensitive = Command::new(env!("CARGO_BIN_EXE_pangs"))
        .arg("query")
        .arg("callees")
        .arg(&fixture)
        .arg("--mode")
        .arg("field-sensitive")
        .output()
        .unwrap();
    assert!(
        sensitive.status.success(),
        "query callees --mode field-sensitive failed:\n{}",
        String::from_utf8_lossy(&sensitive.stderr)
    );
    let sensitive: Value = serde_json::from_slice(&sensitive.stdout).unwrap();
    assert_eq!(sensitive["mode"], "field_sensitive");
    assert_eq!(
        sensitive["by_callsite"]["setup@!noloc#0"],
        serde_json::json!(["f0"])
    );
}

#[test]
fn query_callees_fixpoint_reports_rounds_and_indirect_bindings() {
    let fixture = m3_3_fixture("indirect_arg_fixpoint.pir.json");
    let output = Command::new(env!("CARGO_BIN_EXE_pangs"))
        .arg("query")
        .arg("callees")
        .arg(&fixture)
        .arg("--mode")
        .arg("field-sensitive-fixpoint")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "query callees --mode field-sensitive-fixpoint failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["mode"], "field_sensitive_fixpoint");
    assert_eq!(
        report["by_callsite"]["driver@!noloc#0"],
        serde_json::json!(["invoke"])
    );
    assert_eq!(
        report["by_callsite"]["invoke@!noloc#0"],
        serde_json::json!(["target"])
    );
    assert_eq!(report["rounds"].as_array().unwrap().len(), 2);
    assert_eq!(report["rounds"][0]["new_targets"], 1);
    assert_eq!(report["rounds"][1]["new_targets"], 1);
    assert_eq!(report["truncated_queries"], 0);
    assert_eq!(report["fallback_callsites"], 0);
    assert_eq!(report["fallback_targets"], 0);
    assert!(report["fallback_by_callsite"]
        .as_object()
        .unwrap()
        .is_empty());
    assert!(report["truncated_functions"].as_array().unwrap().is_empty());
    assert_eq!(report["raw_by_callsite"], report["by_callsite"]);
}

#[test]
fn query_callees_filters_abi_incompatible_targets() {
    let fixture = m3_3_fixture("incompatible_signature_filter.pir.json");
    let output = Command::new(env!("CARGO_BIN_EXE_pangs"))
        .arg("query")
        .arg("callees")
        .arg(&fixture)
        .arg("--mode")
        .arg("field-sensitive-fixpoint")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "query callees incompatible signature fixture failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["mode"], "field_sensitive_fixpoint");
    assert!(report["by_callsite"].as_object().unwrap().is_empty());
    assert_eq!(report["rounds"].as_array().unwrap().len(), 1);
    assert_eq!(report["rounds"][0]["new_targets"], 0);
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
        "stationarity.jsonl",
        "components.json",
        "audit.jsonl",
    ] {
        let a = fs::read(out_a.join(name)).unwrap();
        let b = fs::read(out_b.join(name)).unwrap();
        assert_eq!(a, b, "{name} should be byte-identical");
    }
    let a = scrub_timing_fields(
        serde_json::from_str(&fs::read_to_string(out_a.join("metrics.json")).unwrap()).unwrap(),
    );
    let b = scrub_timing_fields(
        serde_json::from_str(&fs::read_to_string(out_b.join("metrics.json")).unwrap()).unwrap(),
    );
    assert_eq!(
        a, b,
        "metrics.json should be byte-identical after scrubbing timing fields"
    );
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
        "stationarity.jsonl",
        "components.json",
        "audit.jsonl",
    ] {
        let a = fs::read(out_a.join(name)).unwrap();
        let b = fs::read(out_b.join(name)).unwrap();
        assert_eq!(a, b, "{name} should be byte-identical");
    }
    let a = scrub_timing_fields(
        serde_json::from_str(&fs::read_to_string(out_a.join("metrics.json")).unwrap()).unwrap(),
    );
    let b = scrub_timing_fields(
        serde_json::from_str(&fs::read_to_string(out_b.join("metrics.json")).unwrap()).unwrap(),
    );
    assert_eq!(
        a, b,
        "metrics.json should be byte-identical after scrubbing timing fields"
    );

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
            "stationarity.jsonl",
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
fn analyze_steens_stress_fixture_is_stable_except_for_timing_fields() {
    let fixture = m1_7_fixture("stress_chain.pir.json");
    let tmp = TempDir::new().unwrap();
    let out_a = tmp.path().join("a");
    let out_b = tmp.path().join("b");

    run_analyze_stage(&fixture, &out_a, "steens");
    run_analyze_stage(&fixture, &out_b, "steens");

    for name in [
        "functions.jsonl",
        "globals.jsonl",
        "callgraph.jsonl",
        "modref.jsonl",
        "stationarity.jsonl",
        "components.json",
        "audit.jsonl",
    ] {
        let a = fs::read(out_a.join(name)).unwrap();
        let b = fs::read(out_b.join(name)).unwrap();
        assert_eq!(a, b, "{name} should be byte-identical");
    }

    let metrics_a: Value =
        serde_json::from_str(&fs::read_to_string(out_a.join("metrics.json")).unwrap()).unwrap();
    let metrics_b: Value =
        serde_json::from_str(&fs::read_to_string(out_b.join("metrics.json")).unwrap()).unwrap();
    for key in [
        "analysis_wall_us",
        "setup_scan_us",
        "preanalysis_us",
        "pag_build_us",
        "solve_us",
        "solver_postprocess_us",
        "pointer_modref_us",
        "callgraph_dedup_us",
        "modref_dedup_us",
        "stationarity_us",
        "initval_reapply_us",
        "transitive_modref_us",
        "findings_dedup_us",
        "components_us",
        "metrics_bookkeeping_us",
    ] {
        assert!(
            metrics_a[key].as_u64().is_some(),
            "{key} missing in metrics"
        );
        assert!(
            metrics_b[key].as_u64().is_some(),
            "{key} missing in metrics"
        );
    }
    assert_eq!(
        scrub_timing_fields(metrics_a),
        scrub_timing_fields(metrics_b)
    );

    let manifest_a: Value =
        serde_json::from_str(&fs::read_to_string(out_a.join("manifest.json")).unwrap()).unwrap();
    let manifest_b: Value =
        serde_json::from_str(&fs::read_to_string(out_b.join("manifest.json")).unwrap()).unwrap();
    assert!(manifest_a["wall_ms"].as_u64().is_some());
    assert!(manifest_b["wall_ms"].as_u64().is_some());
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
    assert!(audit
        .iter()
        .any(|row| row["kind"] == "fnptr_varargs_external"));
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
        row["kind"] == "fnptr_varargs_internal_unmodeled"
            && row["affected"] == serde_json::json!(["value:%fp"])
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
                    taint["kind"] == "fnptr_varargs_internal_unmodeled"
                        && taint["witness"] == "driver@!noloc#0"
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
            && row["detail"] == "edge:load|omega:steens_external|pointee_count=0"
    }));
    assert!(modref.iter().any(|row| {
        row["func"] == "main"
            && row["global"]["unknown"] == "omega_store"
            && row["access"] == "mod"
            && row["via"] == "unknown"
            && row["witness"] == "main@m1_6.c:7:1#0"
            && row["detail"] == "edge:store|omega:steens_external|pointee_count=0"
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
            && row["global"]["name"] == "@DirectExprSrc"
            && row["access"] == "ref"
            && row["via"] == "aliased"
            && row["witness"] == "main@m1_6_memcpy.c:8:1#0"
    }));
    assert!(modref.iter().any(|row| {
        row["func"] == "main"
            && row["global"]["name"] == "@DirectExprDst"
            && row["access"] == "mod"
            && row["via"] == "aliased"
            && row["witness"] == "main@m1_6_memcpy.c:8:1#0"
    }));
    assert!(modref.iter().any(|row| {
        row["func"] == "main"
            && row["global"]["unknown"] == "omega_load"
            && row["access"] == "ref"
            && row["via"] == "unknown"
            && row["witness"] == "main@m1_6_memcpy.c:6:1#0"
            && row["detail"] == "edge:memcpy_src|omega:steens_external|pointee_count=0"
    }));
    assert!(modref.iter().any(|row| {
        row["func"] == "main"
            && row["global"]["unknown"] == "omega_store"
            && row["access"] == "mod"
            && row["via"] == "unknown"
            && row["witness"] == "main@m1_6_memcpy.c:6:1#0"
            && row["detail"] == "edge:memcpy_dst|omega:steens_external|pointee_count=0"
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
            && row["detail"] == "edge:store|omega:steens_external|pointee_count=0"
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
            && row["detail"] == "stmt:memset_dst|omega:steens_external"
    }));
    assert!(modref.iter().any(|row| {
        row["func"] == "main"
            && row["global"]["name"] == "@DirectDst"
            && row["access"] == "mod"
            && row["via"] == "aliased"
            && row["witness"] == "main@m1_6_memset.c:5:1#0"
    }));
    assert!(modref.iter().any(|row| {
        row["func"] == "main"
            && row["global"]["name"] == "@DirectExprDst"
            && row["access"] == "mod"
            && row["via"] == "aliased"
            && row["witness"] == "main@m1_6_memset.c:6:1#0"
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
fn analyze_steens_does_not_expand_precise_stack_or_global_storage_to_pointees() {
    let fixture = m1_6_fixture("precise_storage_modref.pir.json");
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
            && row["global"]["name"] == "@Cell"
            && row["access"] == "mod"
            && row["via"] == "direct"
            && row["witness"] == "main@m1_6_precise_storage.c:2:1#0"
    }));
    assert!(!modref
        .iter()
        .any(|row| row["global"]["name"] == "@Other" && row["access"] == "mod"));
    assert_eq!(
        modref
            .iter()
            .filter(|row| row["global"]["name"] == "@Cell" && row["access"] == "mod")
            .count(),
        1
    );
}

#[test]
fn analyze_steens_collapses_high_fanout_pointer_modref_to_unknown() {
    let fixture = m1_6_fixture("high_fanout_modref.pir.json");
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
            && row["global"]["unknown"] == "omega_store"
            && row["access"] == "mod"
            && row["via"] == "unknown"
            && row["witness"] == "main@m1_6_high_fanout.c:19:1#0"
            && row["detail"]
                .as_str()
                .unwrap()
                .starts_with("high_fanout_pointer_modref:source=pag_pointer")
            && row.get("pointee_globals").is_none()
            && row["candidate_scope"] == "finite-collapsed"
            && row["pointee_global_count"] == 17
            && row["pointee_global_sample"].as_array().unwrap().len() == 8
            && row["pointee_global_hash"]
                .as_str()
                .is_some_and(|hash| hash.len() == 64)
    }));
    assert!(!modref.iter().any(|row| {
        row["access"] == "mod"
            && row["global"]
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| name.starts_with("@G"))
    }));

    let metrics: Value =
        serde_json::from_str(&fs::read_to_string(out.join("metrics.json")).unwrap()).unwrap();
    assert!(
        metrics["pointer_modref_high_fanout_fallbacks"]
            .as_u64()
            .unwrap()
            >= 1
    );
}

#[test]
fn analyze_andersen_refines_spurious_external_store_address_modref() {
    let fixture = m5_fixture("andersen_refines_store_external.pir.json");
    let tmp = TempDir::new().unwrap();
    let out_steens = tmp.path().join("steens");
    let out = tmp.path().join("out");

    run_analyze_stage(&fixture, &out_steens, "steens");
    run_analyze_stage(&fixture, &out, "andersen");

    let steens_modref: Vec<Value> = fs::read_to_string(out_steens.join("modref.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(steens_modref.iter().any(|row| {
        row["func"] == "driver"
            && row["global"]["unknown"] == "omega_store"
            && row["access"] == "mod"
            && row["via"] == "unknown"
            && row["witness"] == "driver@m5_store.c:8:1#0"
            && row["detail"] == "edge:store|omega:steens_external|pointee_count=1"
            && row["address_node"] == "val:driver:%gp"
            && row["pointee_globals"] == serde_json::json!(["@Table"])
            && row["candidate_scope"] == "finite"
            && row["pointee_global_count"] == 1
    }));

    let modref: Vec<Value> = fs::read_to_string(out.join("modref.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(modref.iter().any(|row| {
        row["func"] == "driver"
            && row["global"]["name"] == "@Table"
            && row["access"] == "mod"
            && row["via"] == "aliased"
            && row["witness"] == "driver@m5_store.c:8:1#0"
    }));
    assert!(!modref.iter().any(|row| {
        row["func"] == "driver"
            && row["global"]["unknown"] == "omega_store"
            && row["witness"] == "driver@m5_store.c:8:1#0"
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
                && component["mutable_globals"] == serde_json::json!([])
        }));
    let steens_metrics: Value =
        serde_json::from_str(&fs::read_to_string(out_steens.join("metrics.json")).unwrap())
            .unwrap();
    assert_eq!(steens_metrics["mutable_globals_total"], 0);
    assert_eq!(steens_metrics["in_rewritable_components"], 0);
}

#[test]
fn analyze_steens_alias_rows_improve_split_component_coverage_over_conservative() {
    let fixture = m1_6_fixture("split_coverage_gain.pir.json");
    let tmp = TempDir::new().unwrap();
    let out_cons = tmp.path().join("cons");
    let out_steens = tmp.path().join("steens");

    run_analyze_stage(&fixture, &out_cons, "conservative");
    run_analyze_stage(&fixture, &out_steens, "steens");

    let cons_components: Value =
        serde_json::from_str(&fs::read_to_string(out_cons.join("components.json")).unwrap())
            .unwrap();
    assert!(cons_components["components"]
        .as_array()
        .unwrap()
        .iter()
        .any(|component| {
            component["members"] == serde_json::json!(["driver"])
                && component["frozen"] == true
                && component["mutable_globals"] == serde_json::json!(["@Frozen"])
        }));
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
    assert_eq!(cons_metrics["mutable_globals_total"], 2);
    assert_eq!(cons_metrics["in_rewritable_components"], 0);

    let steens_modref: Vec<Value> = fs::read_to_string(out_steens.join("modref.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(steens_modref.iter().any(|row| {
        row["func"] == "worker"
            && row["global"]["name"] == "@Rewrite"
            && row["access"] == "ref"
            && row["via"] == "aliased"
            && row["witness"] == "worker@m1_6_split.c:11:1#0"
    }));

    let steens_components: Value =
        serde_json::from_str(&fs::read_to_string(out_steens.join("components.json")).unwrap())
            .unwrap();
    assert!(steens_components["components"]
        .as_array()
        .unwrap()
        .iter()
        .any(|component| {
            component["members"] == serde_json::json!(["driver"])
                && component["frozen"] == true
                && component["mutable_globals"] == serde_json::json!(["@Frozen"])
        }));
    assert!(steens_components["components"]
        .as_array()
        .unwrap()
        .iter()
        .any(|component| {
            component["members"] == serde_json::json!(["worker"])
                && component["frozen"] == false
                && component["mutable_globals"] == serde_json::json!([])
        }));
    let steens_metrics: Value =
        serde_json::from_str(&fs::read_to_string(out_steens.join("metrics.json")).unwrap())
            .unwrap();
    assert_eq!(steens_metrics["mutable_globals_total"], 1);
    assert_eq!(steens_metrics["in_rewritable_components"], 0);
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

/// M1.8 differential ledger: every synthetic PIR fixture must satisfy the cross-stage
/// narrowing/monotonicity relations (`pangs differential` exits 0). A non-zero exit is a
/// soundness regression, not a precision difference.
#[test]
fn differential_ledger_holds_on_synthetic_suite() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/synthetic");
    let mut checked = 0;
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if !path.to_string_lossy().ends_with(".pir.json") {
                continue;
            }
            let output = Command::new(env!("CARGO_BIN_EXE_pangs"))
                .arg("differential")
                .arg(&path)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "differential failed on {}:\n{}",
                path.display(),
                String::from_utf8_lossy(&output.stderr)
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 10,
        "expected ≥10 PIR fixtures, checked {checked}"
    );
}

const CLANG_14: &str = "/home/brk/tenjin/_local/xj-llvm-14/bin/clang";

#[test]
fn analyze_dispose_emits_policy_pair_without_indexing_it() {
    assert!(Path::new(CLANG_14).exists(), "LLVM-14 clang is required");
    let tmp = TempDir::new().unwrap();
    let bc = tmp.path().join("dispose.bc");
    let out = tmp.path().join("out");
    assert!(Command::new(CLANG_14)
        .args(["-O0", "-g", "-emit-llvm", "-c"])
        .arg(m1_1_fixture("fp_smoke.c"))
        .arg("-o")
        .arg(&bc)
        .status()
        .unwrap()
        .success());
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new(env!("CARGO_BIN_EXE_pangs"))
        .arg("analyze")
        .arg(&bc)
        .arg("--out")
        .arg(&out)
        .arg("--build-mode")
        .arg("executable")
        .arg("--dispose")
        .arg("--repo-root")
        .arg(&repo_root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let disposition: Value =
        serde_json::from_slice(&fs::read(out.join("pangs-manifest.json")).unwrap()).unwrap();
    assert_eq!(disposition["schema_version"], 3);
    let counter = disposition["globals"]
        .as_array()
        .unwrap()
        .iter()
        .find(|global| global["key"] == "fixtures/synthetic/m1_1/fp_smoke.c::g_counter")
        .expect("g_counter disposition record");
    assert_eq!(counter["facts"]["word_sized_scalar"]["value"], true);
    assert_eq!(counter["facts"]["word_sized_scalar"]["class"], "integer");
    assert_eq!(counter["facts"]["word_sized_scalar"]["signed"], true);
    let phase_report = &disposition["run"]["analysis"]["phase_stationarity_report"];
    assert!(phase_report["coverage"]["client_relevant_mutable_globals"]
        .as_u64()
        .is_some());
    assert!(phase_report["quiescence_profile"].is_array());
    assert!(phase_report["failure_code_counts"].is_object());
    assert!(phase_report["no_single_p"]["witnesses"].is_array());
    assert!(phase_report["both_phase_bucket_sizes"]["histogram"].is_object());
    assert!(phase_report["spine_descent_depth"]["histogram"].is_object());
    let measurements = &disposition["run"]["dispose"]["measurement_report"];
    assert_eq!(
        measurements["disposition_distribution"]
            .as_object()
            .unwrap()
            .values()
            .map(|count| count.as_u64().unwrap())
            .sum::<u64>(),
        disposition["globals"].as_array().unwrap().len() as u64
    );
    assert!(measurements["cascade_skip_histogram"].is_object());
    assert!(measurements["would_be_eligibility"]["atomic"]["eligible"].is_u64());
    assert!(measurements["would_be_eligibility"]["mutex"]["eligible"].is_u64());
    assert!(measurements["context_struct_pressure"]["components"].is_object());
    assert_eq!(measurements["override_usage"]["honored"], 0);
    assert!(out.join("pangs-audit.json").exists());
    let export_index: Value =
        serde_json::from_slice(&fs::read(out.join("manifest.json")).unwrap()).unwrap();
    assert!(
        !export_index["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["path"] == "pangs-manifest.json"
                || entry["path"] == "pangs-audit.json")
    );
    // Full-artifact golden: normalize only machine/run identity, then hash the canonical bytes.
    // On failure the ordinary assertions above retain readable field-level diagnostics.
    let manifest_bytes = fs::read_to_string(out.join("pangs-manifest.json")).unwrap();
    let normalized = manifest_bytes
        .replace(bc.to_str().unwrap(), "<INPUT>")
        .replace(
            fs::canonicalize(&repo_root).unwrap().to_str().unwrap(),
            "<REPO_ROOT>",
        )
        .replace(
            disposition["run"]["analysis"]["input_sha256"]
                .as_str()
                .unwrap(),
            "<INPUT_SHA256>",
        )
        .replace(
            disposition["run"]["analysis"]["pangs_git"]
                .as_str()
                .unwrap(),
            "<PANGS_GIT>",
        );
    assert_eq!(
        sha256_text(&normalized),
        "ff8c1a02d04001bba6d0e459916d6dc8c8460a117a6318e7715a6b24474070a9"
    );
    let audit = fs::read_to_string(out.join("pangs-audit.json")).unwrap();
    assert_eq!(
        sha256_text(&audit),
        "e1c123f6a5ef5286e562d5790d7d38c76629cb1b70901b2d6dcd1589e2218763"
    );

    let library_out = tmp.path().join("library-out");
    let library = Command::new(env!("CARGO_BIN_EXE_pangs"))
        .arg("analyze")
        .arg(&bc)
        .arg("--out")
        .arg(&library_out)
        .arg("--build-mode")
        .arg("library")
        .arg("--dispose")
        .arg("--repo-root")
        .arg(&repo_root)
        .output()
        .unwrap();
    assert!(
        library.status.success(),
        "{}",
        String::from_utf8_lossy(&library.stderr)
    );
    let library_manifest: Value =
        serde_json::from_slice(&fs::read(library_out.join("pangs-manifest.json")).unwrap())
            .unwrap();
    let library_counter = library_manifest["globals"]
        .as_array()
        .unwrap()
        .iter()
        .find(|global| global["meta"]["llvm_name"] == "g_counter")
        .unwrap();
    assert_eq!(
        library_counter["facts"]["omega_escaped_address"]["value"],
        false
    );
    assert_eq!(
        library_counter["facts"]["access_set_complete"]["value"],
        false
    );
    assert!(
        library_counter["facts"]["access_set_complete"]["witness"]["note"]
            .as_str()
            .unwrap()
            .contains("reachable by name")
    );
}

fn sha256_text(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

#[test]
fn analyze_dispose_reports_registry_reachability_and_coupling() {
    assert!(Path::new(CLANG_14).exists(), "LLVM-14 clang is required");
    let tmp = TempDir::new().unwrap();
    let bc = tmp.path().join("registry.bc");
    let out = tmp.path().join("out");
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source = repo_root.join("fixtures/synthetic/disposition/registry_and_coupling.c");
    assert!(Command::new(CLANG_14)
        .args(["-O0", "-g", "-emit-llvm", "-c"])
        .arg(source)
        .arg("-o")
        .arg(&bc)
        .status()
        .unwrap()
        .success());
    let output = Command::new(env!("CARGO_BIN_EXE_pangs"))
        .arg("analyze")
        .arg(&bc)
        .arg("--out")
        .arg(&out)
        .arg("--build-mode")
        .arg("executable")
        .arg("--dispose")
        .arg("--repo-root")
        .arg(&repo_root)
        .arg("--registry-config")
        .arg(repo_root.join("fixtures/synthetic/disposition/registry_config.json"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let manifest: Value =
        serde_json::from_slice(&fs::read(out.join("pangs-manifest.json")).unwrap()).unwrap();
    let globals = manifest["globals"].as_array().unwrap();
    let left = globals
        .iter()
        .find(|global| global["meta"]["llvm_name"] == "left_state")
        .unwrap();
    let right = globals
        .iter()
        .find(|global| global["meta"]["llvm_name"] == "right_state")
        .unwrap();
    let handler_only = globals
        .iter()
        .find(|global| global["meta"]["llvm_name"] == "handler_only_state")
        .unwrap();
    let custom = globals
        .iter()
        .find(|global| global["meta"]["llvm_name"] == "custom_state")
        .unwrap();
    let indirect_worker = globals
        .iter()
        .find(|global| global["meta"]["llvm_name"] == "indirect_worker_state")
        .unwrap();
    let sigaction_handler = globals
        .iter()
        .find(|global| global["meta"]["llvm_name"] == "sigaction_handler_state")
        .unwrap();
    assert_eq!(left["facts"]["thread_visible"]["value"], true);
    assert_eq!(left["facts"]["signal_context_access"]["value"], false);
    assert_eq!(right["facts"]["thread_visible"]["value"], true);
    assert_eq!(right["facts"]["signal_context_access"]["value"], true);
    assert_eq!(handler_only["facts"]["thread_visible"]["value"], false);
    assert_eq!(
        handler_only["facts"]["signal_context_access"]["value"],
        true
    );
    assert_eq!(custom["facts"]["thread_visible"]["value"], true);
    assert_eq!(custom["facts"]["signal_context_access"]["value"], false);
    assert_eq!(indirect_worker["facts"]["thread_visible"]["value"], true);
    assert_eq!(
        indirect_worker["facts"]["signal_context_access"]["value"],
        false
    );
    assert_eq!(sigaction_handler["facts"]["thread_visible"]["value"], false);
    assert_eq!(
        sigaction_handler["facts"]["signal_context_access"]["value"],
        true
    );
    assert_eq!(
        manifest["run"]["analysis"]["opts"]["disposition_registries"][0]["name"],
        "register_worker"
    );
    assert!(left["facts"]["coupling_group"].is_null());
    assert!(right["facts"]["coupling_group"].is_null());
    let groups = manifest["coupling_groups"].as_array().unwrap();
    assert!(groups.is_empty());
    let candidates = manifest["coupling_candidates"].as_array().unwrap();
    assert_eq!(candidates.len(), 1);
    assert!(candidates[0]["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|edge| {
            edge["kind"] == "co-write"
                && edge["strength"] == "suspected"
                && edge["members"].as_array().unwrap().len() == 2
        }));
}

#[test]
fn analyze_dispose_certifies_a_source_mapped_once_lock_candidate() {
    assert!(Path::new(CLANG_14).exists(), "LLVM-14 clang is required");
    let tmp = TempDir::new().unwrap();
    let bc = tmp.path().join("phase-once-lock.bc");
    let out = tmp.path().join("out");
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source = repo_root.join("fixtures/synthetic/disposition/phase_once_lock.c");
    assert!(Command::new(CLANG_14)
        .args(["-O0", "-g", "-emit-llvm", "-c"])
        .arg(source)
        .arg("-o")
        .arg(&bc)
        .status()
        .unwrap()
        .success());
    let output = Command::new(env!("CARGO_BIN_EXE_pangs"))
        .arg("analyze")
        .arg(&bc)
        .arg("--out")
        .arg(&out)
        .arg("--build-mode")
        .arg("executable")
        .arg("--dispose")
        .arg("--repo-root")
        .arg(&repo_root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let manifest: Value =
        serde_json::from_slice(&fs::read(out.join("pangs-manifest.json")).unwrap()).unwrap();
    let configured = manifest["globals"]
        .as_array()
        .unwrap()
        .iter()
        .find(|global| global["meta"]["llvm_name"] == "configured")
        .expect("configured disposition record");
    assert_eq!(
        configured["facts"]["phase_stationarity"]["status"],
        "certified"
    );
    let certificate = &configured["facts"]["phase_stationarity"]["certificate"];
    assert_eq!(certificate["publication"]["publication_function"], "main");
    assert_eq!(certificate["writers"][0]["function"], "initialize");
    assert_eq!(certificate["init_subtree"][0]["function"], "initialize");
    assert_eq!(configured["disposition"]["chosen"], "once-lock");
    assert_eq!(
        manifest["run"]["analysis"]["phase_stationarity_report"]["coverage"]["certified_globals"],
        1
    );
}

#[test]
fn analyze_dispose_derives_common_once_lock_group_support() {
    assert!(Path::new(CLANG_14).exists(), "LLVM-14 clang is required");
    let tmp = TempDir::new().unwrap();
    let bc = tmp.path().join("phase-once-lock-group.bc");
    let out = tmp.path().join("out");
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source = repo_root.join("fixtures/synthetic/disposition/phase_once_lock_group.c");
    assert!(Command::new(CLANG_14)
        .args(["-O0", "-g", "-emit-llvm", "-c"])
        .arg(source)
        .arg("-o")
        .arg(&bc)
        .status()
        .unwrap()
        .success());
    let output = Command::new(env!("CARGO_BIN_EXE_pangs"))
        .arg("analyze")
        .arg(&bc)
        .arg("--out")
        .arg(&out)
        .arg("--build-mode")
        .arg("executable")
        .arg("--dispose")
        .arg("--repo-root")
        .arg(&repo_root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let manifest: Value =
        serde_json::from_slice(&fs::read(out.join("pangs-manifest.json")).unwrap()).unwrap();
    let groups = manifest["coupling_groups"].as_array().unwrap();
    assert_eq!(groups.len(), 1);
    let group = &groups[0];
    assert_eq!(group["members"].as_array().unwrap().len(), 2);
    assert_eq!(group["strategy_support"]["once_lock"]["supported"], true);
    assert!(
        group["strategy_support"]["once_lock"]["publication_function"]
            .as_str()
            .unwrap()
            .ends_with("::main")
    );
    assert_eq!(group["group_disposition"], "once-lock");
    assert!(group["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|edge| edge["kind"] == "oncelock-interval"
            && edge["strength"] == "hard"
            && edge["shared_init_functions"] == serde_json::json!(["initialize"])));
    assert!(!group["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|edge| edge["kind"] == "co-write"));
    assert!(manifest["globals"]
        .as_array()
        .unwrap()
        .iter()
        .all(|global| global["disposition"]["chosen"] == "once-lock"));
    let report = &manifest["run"]["analysis"]["phase_stationarity_report"]["coupling_groups"];
    assert_eq!(report["count"], 1);
    assert_eq!(report["once_lock_supported"], 1);
    assert_eq!(report["once_lock_evidence_edges"], 1);
    assert_eq!(report["groups"][0]["id"], group["id"]);
}

fn workspace_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

/// M1.8 dynamic icall validation, end to end: compile a synthetic executable, instrument
/// its indirect calls, link the trace runtime, run it, and assert `check-traces` confirms
/// every observed (caller, idx, target) pair is in the andersen edge set.
#[test]
fn dynamic_icall_trace_validates_against_andersen() {
    assert!(
        Path::new(CLANG_14).exists(),
        "LLVM-14 clang is required for the M1.8 dynamic trace test"
    );
    let tmp = TempDir::new().unwrap();
    let src = workspace_path("fixtures/synthetic/m1_8/icall_exec.c");
    let runtime = workspace_path("scripts/pangs_trace_runtime.c");
    let bc = tmp.path().join("exec.bc");
    let inst = tmp.path().join("exec_inst.bc");
    let exe = tmp.path().join("exec_inst");
    let out = tmp.path().join("out");
    let trace = tmp.path().join("trace.txt");

    // 1. compile to bitcode
    assert!(Command::new(CLANG_14)
        .args([
            "-O0",
            "-g",
            "-emit-llvm",
            "-Xclang",
            "-disable-O0-optnone",
            "-c"
        ])
        .arg(&src)
        .arg("-o")
        .arg(&bc)
        .status()
        .unwrap()
        .success());

    // 2. analyze (default andersen)
    assert!(Command::new(env!("CARGO_BIN_EXE_pangs"))
        .args(["analyze"])
        .arg(&bc)
        .arg("-o")
        .arg(&out)
        .args(["--build-mode", "executable"])
        .status()
        .unwrap()
        .success());

    // 3. instrument
    assert!(Command::new(env!("CARGO_BIN_EXE_pangs"))
        .arg("instrument")
        .arg(&bc)
        .arg("-o")
        .arg(&inst)
        .status()
        .unwrap()
        .success());

    // 4. link instrumented module + trace runtime
    assert!(Command::new(CLANG_14)
        .args(["-O0"])
        .arg(&inst)
        .arg(&runtime)
        .args(["-rdynamic", "-ldl", "-o"])
        .arg(&exe)
        .status()
        .unwrap()
        .success());

    // 5. run with the trace sink
    assert!(Command::new(&exe)
        .env("PANGS_TRACE", &trace)
        .status()
        .unwrap()
        .success());

    // 6. validate the trace against the analysis (exit 0 == every pair in the edge set)
    let check = Command::new(env!("CARGO_BIN_EXE_pangs"))
        .arg("check-traces")
        .arg(&out)
        .arg(&trace)
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "check-traces failed:\n{}",
        String::from_utf8_lossy(&check.stderr)
    );
}

/// M1.8 dynamic validation on a *multi-icall* executable — the end-to-end counterpart of
/// `two_distinct_loc_icalls_both_appear_in_callgraph`. Two indirect calls at distinct
/// source lines must each produce a resolved, validated (caller, idx, target) trace pair.
/// Guards the callsite-key ordinal fix (ju_steens_overmerge_bug.md) through real bitcode:
/// before the fix the second site (`beta`) was dropped from the analysis edge set, so a
/// resolved `beta` trace pair would make `check-traces` exit 3.
#[test]
fn dynamic_multi_icall_trace_validates_both_sites() {
    assert!(
        Path::new(CLANG_14).exists(),
        "LLVM-14 clang is required for the M1.8 dynamic trace test"
    );
    let tmp = TempDir::new().unwrap();
    let src = workspace_path("fixtures/synthetic/m1_8/two_icall_exec.c");
    let runtime = workspace_path("scripts/pangs_trace_runtime.c");
    let bc = tmp.path().join("exec.bc");
    let inst = tmp.path().join("exec_inst.bc");
    let exe = tmp.path().join("exec_inst");
    let out = tmp.path().join("out");
    let trace = tmp.path().join("trace.txt");

    assert!(Command::new(CLANG_14)
        .args([
            "-O0",
            "-g",
            "-emit-llvm",
            "-Xclang",
            "-disable-O0-optnone",
            "-c"
        ])
        .arg(&src)
        .arg("-o")
        .arg(&bc)
        .status()
        .unwrap()
        .success());
    assert!(Command::new(env!("CARGO_BIN_EXE_pangs"))
        .args(["analyze"])
        .arg(&bc)
        .arg("-o")
        .arg(&out)
        .args(["--build-mode", "executable"])
        .status()
        .unwrap()
        .success());

    // Both icall edges must be present in the analysis (the regression).
    let callgraph = fs::read_to_string(out.join("callgraph.jsonl")).unwrap();
    assert!(
        callgraph.contains("\"func\":\"alpha\""),
        "alpha edge missing"
    );
    assert!(callgraph.contains("\"func\":\"beta\""), "beta edge missing");

    assert!(Command::new(env!("CARGO_BIN_EXE_pangs"))
        .arg("instrument")
        .arg(&bc)
        .arg("-o")
        .arg(&inst)
        .status()
        .unwrap()
        .success());
    assert!(Command::new(CLANG_14)
        .args(["-O0"])
        .arg(&inst)
        .arg(&runtime)
        .args(["-rdynamic", "-ldl", "-o"])
        .arg(&exe)
        .status()
        .unwrap()
        .success());
    assert!(Command::new(&exe)
        .env("PANGS_TRACE", &trace)
        .status()
        .unwrap()
        .success());

    // The runtime resolves the externally-visible targets, so the trace carries the real
    // symbol names — confirming both sites were actually observed and validated.
    let trace_text = fs::read_to_string(&trace).unwrap();
    assert!(
        trace_text.contains("\talpha"),
        "alpha not observed:\n{trace_text}"
    );
    assert!(
        trace_text.contains("\tbeta"),
        "beta not observed:\n{trace_text}"
    );

    let check = Command::new(env!("CARGO_BIN_EXE_pangs"))
        .arg("check-traces")
        .arg(&out)
        .arg(&trace)
        .output()
        .unwrap();
    assert!(
        check.status.success(),
        "check-traces failed:\n{}",
        String::from_utf8_lossy(&check.stderr)
    );
}
