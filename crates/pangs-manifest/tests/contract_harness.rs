use std::collections::BTreeSet;

use pangs_manifest::{
    expected_markers, validate_marker_inventory, Demotion, DispositionProvenance, Extra, Manifest,
    MarkerInventoryEntry, Materialization, MaterializationDemotion, Site, Strategy, ToolInfo,
    Witness,
};
use serde_json::json;

fn contract_manifest() -> Manifest {
    let global = |key: &str, llvm_name: &str, chosen: &str, group: Option<&str>| {
        let atomic_eligibility = (chosen == "atomic").then(|| {
            json!({
                "status": "certified",
                "certificate": {
                    "recipe": {
                        "mode": "ordinary",
                        "ordering": "relaxed"
                    }
                }
            })
        });
        json!({
            "key": key,
            "meta": {
                "linkage": "internal",
                "type_spelling": "int",
                "size_bits": 32,
                "align_bits": 32,
                "llvm_name": llvm_name,
                "file": "src/toy.c",
                "line": 1
            },
            "facts": {
                "written": {
                    "value": true,
                    "witness": { "kind": "fixture-write" }
                },
                "omega_escaped_address": { "value": false },
                "violation_taint": { "value": false },
                "thread_visible": { "value": false },
                "signal_context_access": { "value": false },
                "access_set_complete": { "value": true },
                "word_sized_scalar": { "value": true, "type_spelling": "int",
                    "size_bits": 32, "class": "integer", "signed": true },
                "phase_stationarity": null,
                "atomic_eligibility": atomic_eligibility,
                "mutex_eligibility": null,
                "coupling_group": group,
                "localization": null
            },
            "disposition": {
                "chosen": chosen,
                "cascade_chosen": chosen,
                "provenance": "cascade",
                "cascade_trace": [],
                "override": null
            }
        })
    };
    serde_json::from_value(json!({
        "schema_version": 5,
        "run": {
            "analysis": {
                "pangs_git": "test",
                "llvm_version": "14",
                "input_path": "toy.bc",
                "input_sha256": "00",
                "opts": { "build_mode": "executable" },
                "repo_root": "/repo",
                "target_triple": "x86_64-unknown-linux-gnu",
                "data_layout": "e-p:64:64",
                "supported_atomic_widths": [8, 16, 32, 64],
                "entry_spine": null
            }
        },
        "globals": [
            global("src/toy.c::joint_a", "joint_a", "once-lock", Some("grp-joint")),
            global("src/toy.c::joint_b", "joint_b", "once-lock", Some("grp-joint")),
            global("src/toy.c::member_c", "member_c", "immutable", Some("grp-members")),
            global("src/toy.c::member_d", "member_d", "immutable", Some("grp-members")),
            global("src/toy.c::published", "published", "once-lock", None),
            global("src/toy.c::counter", "counter", "atomic", None)
        ],
        "synthetic_globals": [],
        "unkeyed_globals": [],
        "coupling_groups": [
            {
                "id": "grp-joint",
                "members": ["src/toy.c::joint_a", "src/toy.c::joint_b"],
                "evidence": [],
                "strategy_support": { "once_lock": null, "mutex": null },
                "group_disposition": "once-lock",
                "group_provenance": "cascade"
            },
            {
                "id": "grp-members",
                "members": ["src/toy.c::member_c", "src/toy.c::member_d"],
                "evidence": [],
                "strategy_support": { "once_lock": null, "mutex": null }
            }
        ]
    }))
    .unwrap()
}

fn demotion_witness(key: &str) -> Witness {
    Witness {
        kind: "mock-materialization-failure".into(),
        site: Some(Site {
            file: "src/toy.c".into(),
            line: 1,
            col: None,
            function: None,
            extra: Extra::new(),
        }),
        symbol: Some(key.into()),
        note: Some("fixture publication point is intentionally not rewritable".into()),
        extra: Extra::new(),
    }
}

fn mock_materialize(manifest: &mut Manifest, input: &str, failing_keys: &[&str]) -> String {
    let mut demote_keys = BTreeSet::new();
    for failing in failing_keys {
        let global = manifest
            .globals
            .iter()
            .find(|global| global.key.to_string() == *failing)
            .unwrap();
        let disposition = global.disposition.as_ref().unwrap();
        if matches!(disposition.chosen, Strategy::OnceLock | Strategy::Mutex) {
            if let Some(group_id) = &global.facts.coupling_group {
                let group = manifest
                    .coupling_groups
                    .iter()
                    .find(|group| &group.id == group_id)
                    .unwrap();
                if group.group_disposition == Some(disposition.chosen) {
                    demote_keys.extend(group.members.iter().map(ToString::to_string));
                    continue;
                }
            }
        }
        demote_keys.insert((*failing).to_owned());
    }

    let mut demotions = Vec::new();
    for key in demote_keys {
        let global = manifest
            .globals
            .iter_mut()
            .find(|global| global.key.to_string() == key)
            .unwrap();
        let disposition = global.disposition.as_mut().unwrap();
        let from = disposition.chosen;
        let witness = demotion_witness(&key);
        disposition.chosen = Strategy::Unhandled;
        disposition.provenance = DispositionProvenance::Demoted;
        disposition.demotion = Some(Demotion {
            from,
            witness: witness.clone(),
            extra: Extra::new(),
        });
        demotions.push(MaterializationDemotion {
            key: global.key.clone(),
            from,
            witness,
            extra: Extra::new(),
        });
    }
    for group in &mut manifest.coupling_groups {
        if group.members.iter().all(|member| {
            manifest
                .globals
                .iter()
                .find(|global| global.key == *member)
                .is_some_and(|global| {
                    global.disposition.as_ref().unwrap().chosen == Strategy::Unhandled
                })
        }) {
            group.group_disposition = Some(Strategy::Unhandled);
        }
    }

    let expected = expected_markers(manifest).unwrap();
    let inventory = expected
        .iter()
        .map(|marker| MarkerInventoryEntry {
            key: marker.key.clone(),
            kind: marker.kind.clone(),
            marker: marker.marker.clone(),
            group: marker.group.clone(),
            insertion: Site {
                file: "src/toy.c".into(),
                line: 1,
                col: None,
                function: None,
                extra: Extra::new(),
            },
            extra: Extra::new(),
        })
        .collect();
    manifest.materialization = Some(Materialization {
        tool: ToolInfo {
            name: "mock-c-materializer".into(),
            version: "test".into(),
            extra: Extra::new(),
        },
        marker_inventory: inventory,
        demotions,
        extra: Extra::new(),
    });

    let mut output = input.to_owned();
    let symbols = expected
        .iter()
        .map(|marker| marker.marker.as_str())
        .collect::<BTreeSet<_>>();
    for symbol in symbols {
        output.push_str(&format!("{symbol}();\n"));
    }
    output
}

fn fixture_rust_rewriter(manifest: &Manifest, translated: &str) -> String {
    let observed = translated
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .filter(|token| token.starts_with("pangs_"))
        .collect::<BTreeSet<_>>();
    validate_marker_inventory(manifest, observed.iter().copied()).unwrap();

    let mut output = translated
        .lines()
        .filter(|line| !line.contains("pangs_"))
        .collect::<Vec<_>>()
        .join("\n");
    for global in &manifest.globals {
        let disposition = global.disposition.as_ref().unwrap();
        let c_declaration = format!("static int {};", global.meta.llvm_name);
        let rust_declaration = match disposition.chosen {
            Strategy::OnceLock => format!(
                "static {}: OnceLock<i32> = OnceLock::new();",
                global.meta.llvm_name
            ),
            Strategy::Immutable => format!("static {}: i32 = 0;", global.meta.llvm_name),
            Strategy::Atomic => format!(
                "static {}: AtomicI32 = AtomicI32::new(0);",
                global.meta.llvm_name
            ),
            _ => format!("static mut {}: i32 = 0;", global.meta.llvm_name),
        };
        output = output.replace(&c_declaration, &rust_declaration);
    }
    output
}

#[test]
fn mock_materializer_and_fixture_rewriter_pin_the_marker_and_demotion_contract() {
    let mut manifest = contract_manifest();
    let toy = "static int joint_a;\nstatic int joint_b;\nstatic int member_c;\nstatic int member_d;\nstatic int published;\nstatic int counter;\n";
    let planted = mock_materialize(
        &mut manifest,
        toy,
        &["src/toy.c::joint_a", "src/toy.c::member_c"],
    );

    let chosen = |key: &str| {
        manifest
            .globals
            .iter()
            .find(|global| global.key.to_string() == key)
            .unwrap()
            .disposition
            .as_ref()
            .unwrap()
            .chosen
    };
    assert_eq!(chosen("src/toy.c::joint_a"), Strategy::Unhandled);
    assert_eq!(chosen("src/toy.c::joint_b"), Strategy::Unhandled);
    assert_eq!(chosen("src/toy.c::member_c"), Strategy::Unhandled);
    assert_eq!(chosen("src/toy.c::member_d"), Strategy::Immutable);
    assert_eq!(
        manifest.materialization.as_ref().unwrap().demotions.len(),
        3
    );

    let rewritten = fixture_rust_rewriter(&manifest, &planted);
    assert!(rewritten.contains("static published: OnceLock<i32> = OnceLock::new();"));
    assert!(rewritten.contains("static member_d: i32 = 0;"));
    assert!(rewritten.contains("static counter: AtomicI32 = AtomicI32::new(0);"));
    assert!(rewritten.contains("static mut joint_a: i32 = 0;"));
    assert!(!rewritten.contains("pangs_"));
}

#[test]
fn inventory_validation_rejects_an_orphan_marker_from_the_mock_boundary() {
    let mut manifest = contract_manifest();
    let planted = mock_materialize(&mut manifest, "static int published;\n", &[]);
    let mut observed = planted
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .filter(|token| token.starts_with("pangs_"))
        .collect::<BTreeSet<_>>();
    observed.insert("pangs_orphan__bad__00000000");
    assert!(validate_marker_inventory(&manifest, observed).is_err());
}

#[test]
fn inventory_validation_rejects_a_missing_translated_marker() {
    let mut manifest = contract_manifest();
    let planted = mock_materialize(&mut manifest, "static int published;\n", &[]);
    let mut observed = planted
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .filter(|token| token.starts_with("pangs_"))
        .collect::<BTreeSet<_>>();
    let missing = observed.pop_first().unwrap();
    let error = validate_marker_inventory(&manifest, observed).unwrap_err();
    assert!(error.to_string().contains(missing));
}

#[test]
fn independent_once_lock_in_a_mixed_group_uses_a_member_marker_and_demotes_alone() {
    let mut manifest = contract_manifest();
    let member = manifest
        .globals
        .iter_mut()
        .find(|global| global.key.to_string() == "src/toy.c::member_c")
        .unwrap();
    let disposition = member.disposition.as_mut().unwrap();
    disposition.chosen = Strategy::OnceLock;
    disposition.cascade_chosen = Strategy::OnceLock;

    let marker = expected_markers(&manifest)
        .unwrap()
        .into_iter()
        .find(|marker| marker.key.to_string() == "src/toy.c::member_c")
        .unwrap();
    assert_eq!(marker.group, None);

    mock_materialize(
        &mut manifest,
        "static int member_c;\nstatic int member_d;\n",
        &["src/toy.c::member_c"],
    );
    let chosen = |key: &str| {
        manifest
            .globals
            .iter()
            .find(|global| global.key.to_string() == key)
            .unwrap()
            .disposition
            .as_ref()
            .unwrap()
            .chosen
    };
    assert_eq!(chosen("src/toy.c::member_c"), Strategy::Unhandled);
    assert_eq!(chosen("src/toy.c::member_d"), Strategy::Immutable);
}

#[test]
fn failed_joint_mutex_materialization_demotes_every_group_member() {
    let mut manifest = contract_manifest();
    for global in manifest
        .globals
        .iter_mut()
        .filter(|global| global.facts.coupling_group.as_deref() == Some("grp-joint"))
    {
        let disposition = global.disposition.as_mut().unwrap();
        disposition.chosen = Strategy::Mutex;
        disposition.cascade_chosen = Strategy::Mutex;
    }
    manifest.coupling_groups[0].group_disposition = Some(Strategy::Mutex);
    mock_materialize(
        &mut manifest,
        "static int joint_a;\nstatic int joint_b;\n",
        &["src/toy.c::joint_b"],
    );
    for key in ["src/toy.c::joint_a", "src/toy.c::joint_b"] {
        let disposition = manifest
            .globals
            .iter()
            .find(|global| global.key.to_string() == key)
            .unwrap()
            .disposition
            .as_ref()
            .unwrap();
        assert_eq!(disposition.chosen, Strategy::Unhandled);
        assert_eq!(disposition.demotion.as_ref().unwrap().from, Strategy::Mutex);
    }
}
