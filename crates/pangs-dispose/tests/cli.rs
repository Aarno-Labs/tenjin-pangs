use std::fs;
use std::process::Command;

use pangs_manifest::{
    canonicalize_audit, to_canonical_json, AnalysisRun, AuditRecord, AuditScope, AuditSource,
    EvidencedBool, Extra, Facts, GlobalRecord, Key, Linkage, Manifest, Meta, RunHeader,
    WordSizedScalar, SCHEMA_VERSION,
};
use serde_json::json;
use tempfile::tempdir;

fn bool_fact(value: bool) -> EvidencedBool {
    EvidencedBool {
        value,
        witness: None,
        extra: Extra::new(),
    }
}

fn fixture() -> (Manifest, Vec<AuditRecord>) {
    let manifest = Manifest {
        schema_version: SCHEMA_VERSION,
        run: RunHeader {
            analysis: AnalysisRun {
                pangs_git: "test".into(),
                llvm_version: "14".into(),
                input_path: "test.bc".into(),
                input_sha256: "00".into(),
                opts: json!({"build_mode": "executable"}),
                repo_root: "/repo".into(),
                target_triple: "x86_64-unknown-linux-gnu".into(),
                data_layout: "e-p:64:64".into(),
                supported_atomic_widths: vec![8, 16, 32, 64],
                entry_spine: None,
                extra: Extra::new(),
            },
            dispose: None,
            extra: Extra::new(),
        },
        globals: vec![GlobalRecord {
            key: Key::parse("src/a.c::g").unwrap(),
            meta: Meta {
                linkage: Linkage::Internal,
                type_spelling: None,
                size_bits: None,
                align_bits: None,
                llvm_name: "g".into(),
                file: Some("src/a.c".into()),
                line: Some(1),
                extra: Extra::new(),
            },
            storage_members: Vec::new(),
            facts: Facts {
                written: bool_fact(false),
                omega_escaped_address: bool_fact(false),
                violation_taint: bool_fact(false),
                thread_visible: bool_fact(false),
                signal_context_access: bool_fact(false),
                access_set_complete: bool_fact(true),
                word_sized_scalar: WordSizedScalar {
                    value: false,
                    type_spelling: None,
                    size_bits: None,
                    class: None,
                    signed: None,
                    extra: Extra::new(),
                },
                phase_stationarity: None,
                atomic_eligibility: None,
                mutex_eligibility: None,
                coupling_group: None,
                localization: None,
                violation_relevance: Vec::new(),
                extra: Extra::new(),
            },
            disposition: None,
            extra: Extra::new(),
        }],
        synthetic_globals: Vec::new(),
        unkeyed_globals: Vec::new(),
        coupling_groups: Vec::new(),
        coupling_candidates: Vec::new(),
        override_report: None,
        materialization: None,
        extra: Extra::new(),
    };
    let mut ledger = vec![AuditRecord {
        id: String::new(),
        kind: "run-assumption".into(),
        scope: AuditScope::Run {
            extra: Extra::new(),
        },
        source: AuditSource::Analysis,
        text: "fixture".into(),
        witness: None,
        failures: None,
        extra: Extra::new(),
    }];
    canonicalize_audit(&mut ledger).unwrap();
    (manifest, ledger)
}

fn write_fixture(dir: &std::path::Path) {
    let (manifest, ledger) = fixture();
    fs::write(
        dir.join("pangs-manifest.json"),
        to_canonical_json(&manifest).unwrap(),
    )
    .unwrap();
    fs::write(
        dir.join("pangs-audit.json"),
        to_canonical_json(&ledger).unwrap(),
    )
    .unwrap();
}

fn command(dir: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pangs-dispose"));
    command.arg(dir);
    command
}

#[test]
fn no_override_run_is_byte_idempotent() {
    let temp = tempdir().unwrap();
    write_fixture(temp.path());
    assert!(command(temp.path())
        .arg("--no-overrides")
        .status()
        .unwrap()
        .success());
    let first_manifest = fs::read(temp.path().join("pangs-manifest.json")).unwrap();
    let first_audit = fs::read(temp.path().join("pangs-audit.json")).unwrap();
    assert!(command(temp.path())
        .arg("--no-overrides")
        .status()
        .unwrap()
        .success());
    assert_eq!(
        fs::read(temp.path().join("pangs-manifest.json")).unwrap(),
        first_manifest
    );
    assert_eq!(
        fs::read(temp.path().join("pangs-audit.json")).unwrap(),
        first_audit
    );
}

#[test]
fn exit_codes_distinguish_override_problems_and_newer_schema() {
    let temp = tempdir().unwrap();
    write_fixture(temp.path());
    fs::write(
        temp.path().join("pangs-overrides.toml"),
        "[globals.\"src/a.c::missing\"]\ndisposition = \"immutable\"\n",
    )
    .unwrap();
    assert_eq!(command(temp.path()).status().unwrap().code(), Some(2));
    let output: serde_json::Value =
        serde_json::from_slice(&fs::read(temp.path().join("pangs-manifest.json")).unwrap())
            .unwrap();
    assert_eq!(output["override_report"]["counts"]["unmatched_key"], 1);

    let (mut manifest, _) = fixture();
    manifest.schema_version = SCHEMA_VERSION + 1;
    fs::write(
        temp.path().join("pangs-manifest.json"),
        to_canonical_json(&manifest).unwrap(),
    )
    .unwrap();
    assert_eq!(
        command(temp.path())
            .arg("--no-overrides")
            .status()
            .unwrap()
            .code(),
        Some(3)
    );
}

#[test]
fn missing_ledger_is_exit_one() {
    let temp = tempdir().unwrap();
    let (manifest, _) = fixture();
    fs::write(
        temp.path().join("pangs-manifest.json"),
        to_canonical_json(&manifest).unwrap(),
    )
    .unwrap();
    assert_eq!(
        command(temp.path())
            .arg("--no-overrides")
            .status()
            .unwrap()
            .code(),
        Some(1)
    );
}
