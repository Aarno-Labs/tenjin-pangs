use pangs_manifest::{compose_source_edits, ContextRewriteField, Extra, Key};
use serde_json::json;

fn recipe(replacement: &str, start: usize, end: usize) -> ContextRewriteField {
    let mut extra = Extra::new();
    extra.insert(
        "source_edits".into(),
        json!([{
            "file":"test.i", "start":start, "end":end,
            "replacement":replacement, "kind":"signature"
        }]),
    );
    ContextRewriteField {
        global: Key::unqualified("g").unwrap(),
        llvm_name: "g".into(),
        accessors: vec![],
        functions: vec![],
        rewrite_callsites: vec![],
        blockers: vec![],
        extra,
    }
}

#[test]
fn composition_deduplicates_shared_edits_and_rejects_conflicts() {
    let a = recipe("context", 2, 2);
    assert_eq!(
        compose_source_edits(&[a.clone(), a.clone()]).unwrap().len(),
        1
    );
    assert!(compose_source_edits(&[a.clone(), recipe("other", 2, 2)]).is_err());
    assert!(compose_source_edits(&[a, recipe("overlap", 0, 4)]).is_err());
    assert_eq!(
        compose_source_edits(&[recipe("a", 0, 1), recipe("b", 2, 2)])
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn composition_rejects_reversed_ranges() {
    assert!(compose_source_edits(&[recipe("invalid", 2, 1)]).is_err());
}

#[test]
fn wrappers_are_deduplicated_combined_and_omitted_for_changed_functions() {
    let mut a = recipe("g", 1, 2);
    a.extra.insert("source_wrappers".into(), json!([
        {"function": "plain", "edits": [
            {"file":"test.i", "start":10, "end":10, "replacement":"a", "kind":"wrapper-definition"},
            {"file":"test.i", "start":4, "end":9, "replacement":"plain_xjw", "kind":"wrapper-use"}
        ]},
        {"function": "other", "edits": [
            {"file":"test.i", "start":10, "end":10, "replacement":"b", "kind":"wrapper-definition"}
        ]}
    ]));
    let composed = compose_source_edits(&[a.clone(), a.clone()]).unwrap();
    assert_eq!(composed.len(), 3);
    assert_eq!(composed[2].replacement, "ab");
    let mut b = recipe("h", 2, 3);
    b.functions.push("plain".into());
    let composed = compose_source_edits(&[a, b]).unwrap();
    assert_eq!(composed.len(), 3);
    assert_eq!(composed[2].replacement, "b");
    assert!(!composed.iter().any(|e| e.kind == "wrapper-use"));
}
