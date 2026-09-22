//! Clang source constraints, separate from LLVM runtime facts and points-to.
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::{CStr, CString};
use std::fs;
use std::os::raw::c_char;
use std::path::Path;
use std::time::Instant;

use anyhow::{bail, ensure, Context, Result};
use pangs_api::{Analysis, Callee, Caller};
use pangs_manifest::{
    ContextRewriteBlocker, ContextRewriteCallsite, ContextRewriteField, Extra, Localization,
    LocalizationBlocker, LocalizationVerdict, Manifest, Site, SourceEdit, SourceObligations,
    SourceObservation, SourceWrapper, Witness, SOURCE_EMITTER, SOURCE_PLAN_VERSION,
};
use serde::Deserialize;
use serde_json::{json, Value};

extern "C" {
    fn pangs_source_extract(database: *const c_char) -> *mut c_char;
    fn pangs_source_free(result: *mut c_char);
}

#[derive(Debug, Default, Deserialize)]
struct Node {
    function: String,
    blockers: BTreeSet<String>,
    edits: Vec<SourceEdit>,
}
#[derive(Debug, Default, Deserialize)]
struct ConditionalChange {
    dependencies: BTreeSet<String>,
    blockers: BTreeSet<String>,
    edits: Vec<SourceEdit>,
}
#[derive(Debug, Deserialize)]
struct Call {
    caller: String,
    targets: Vec<String>,
    file: String,
    line: u32,
    col: u32,
    offset: usize,
    edit: SourceEdit,
}
#[derive(Debug, Deserialize)]
struct Use {
    global: String,
    function: String,
    initializer: String,
    file: String,
    offset: usize,
    observations: Vec<SourceObservation>,
}
#[derive(Debug, Deserialize)]
struct Function {
    name: String,
    defined: bool,
    file: String,
    offset: usize,
    internal: bool,
    external_inline: bool,
}
#[derive(Debug, Deserialize)]
struct Producer {
    function: String,
    edit: SourceEdit,
}
#[derive(Debug, Deserialize)]
struct Wrapper {
    function: String,
    internal: bool,
    blockers: BTreeSet<String>,
    declaration: SourceEdit,
    definition: SourceEdit,
}
#[derive(Debug, Deserialize)]
struct Facts {
    nodes: BTreeMap<String, Node>,
    conditional_changes: BTreeMap<String, ConditionalChange>,
    edges: Vec<[String; 2]>,
    producers: BTreeMap<String, Producer>,
    wrappers: Vec<Wrapper>,
    calls: Vec<Call>,
    uses: Vec<Use>,
    functions: Vec<Function>,
    records: Vec<Value>,
    variables: Vec<Value>,
    invocations: Vec<Value>,
    pruned_declarations: Vec<Value>,
    unprunable_declarations: Vec<Value>,
    globals: BTreeSet<String>,
    no_initializer: BTreeSet<String>,
    compiler: String,
}

fn extract(database: &Path) -> Result<Facts> {
    let path = CString::new(
        database
            .to_str()
            .context("non-UTF8 compilation database path")?,
    )?;
    // One owned allocation, freed even if JSON decoding fails. No Clang pointer
    // survives this call. Each TU uses a private VFS working directory.
    let value = unsafe {
        let ptr = pangs_source_extract(path.as_ptr());
        ensure!(!ptr.is_null(), "source extraction allocation failed");
        let result = serde_json::from_slice::<Value>(CStr::from_ptr(ptr).to_bytes());
        pangs_source_free(ptr);
        result?
    };
    if let Some(error) = value.get("error") {
        bail!("Clang source extraction: {error}");
    }
    Ok(serde_json::from_value(value)?)
}

fn blocker(kind: &str, node: &str) -> ContextRewriteBlocker {
    ContextRewriteBlocker {
        kind: kind.into(),
        function: node.strip_prefix("fn:").map(str::to_owned),
        callsite: None,
        initializer: None,
        extra: BTreeMap::from([("source_node".into(), json!(node))]),
    }
}

fn check_shared_data_types(facts: &Facts) -> Result<()> {
    let mut variables: BTreeMap<&str, (&Value, String)> = BTreeMap::new();
    for variable in &facts.variables {
        let name = variable["name"].as_str().context("missing global name")?;
        let signature = variable["signature"]
            .as_str()
            .context("missing global type")?;
        let (identity, previous) = variables
            .entry(name)
            .or_insert_with(|| (&variable["id"], signature.into()));
        ensure!(
            *identity == &variable["id"],
            "ambiguous source global: {name}; uniquify statics first"
        );
        *previous = merge_variable_types(previous, signature).with_context(|| {
            format!("incompatible source declarations for {name}: {previous} vs {signature}")
        })?;
    }
    let mut records = BTreeMap::new();
    for record in &facts.records {
        let id = record["id"].as_str().context("missing record identity")?;
        if let Some(previous) = records.insert(id, record) {
            ensure!(
                previous == record,
                "cross-TU record mismatch: {id}: {previous} vs {record}"
            );
        }
    }
    Ok(())
}

// C permits an external incomplete array to be completed by a later or
// cross-TU definition. Accumulate known bounds so [] cannot hide conflicting
// [N] and [M] declarations elsewhere in the database.
fn merge_variable_types(a: &str, b: &str) -> Option<String> {
    if a == b {
        return Some(a.into());
    }
    fn split(mut t: &str) -> (&str, Vec<Option<u64>>) {
        let mut dimensions = Vec::new();
        while let Some(end) = t.strip_suffix(']') {
            let Some(begin) = end.rfind('[') else { break };
            let count = &end[begin + 1..];
            let value = if count.is_empty() {
                None
            } else if let Ok(n) = count.parse::<u64>() {
                Some(n)
            } else {
                break;
            };
            dimensions.push(value);
            t = end[..begin].trim_end();
        }
        (t, dimensions)
    }
    let (base_a, dims_a) = split(a);
    let (base_b, dims_b) = split(b);
    if base_a != base_b || dims_a.len() != dims_b.len() || dims_a.is_empty() {
        return None;
    }
    let mut result = base_a.to_owned();
    for (x, y) in dims_a.into_iter().zip(dims_b).rev() {
        if x.is_some() && y.is_some() && x != y {
            return None;
        }
        result.push('[');
        if let Some(n) = x.or(y) {
            result.push_str(&n.to_string());
        }
        result.push(']');
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::merge_variable_types;
    #[test]
    fn compatible_incomplete_arrays_accumulate_bounds() {
        let t = merge_variable_types("const unsigned int[]", "const unsigned int[256]").unwrap();
        assert_eq!(t, "const unsigned int[256]");
        assert_eq!(
            merge_variable_types(&t, "const unsigned int[]"),
            Some(t.clone())
        );
        assert_eq!(merge_variable_types(&t, "const unsigned int[100]"), None);
        assert_eq!(merge_variable_types("int[2]", "float[2]"), None);
    }
}

/// Validation only: no LLVM analysis, closure, repair, or disposition selection.
pub fn validate_sources(database: &Path, removed_globals: &[String]) -> Result<()> {
    let facts = extract(database)?;
    check_shared_data_types(&facts)?;
    for usage in &facts.uses {
        ensure!(
            !removed_globals.contains(&usage.global),
            "unmaterialized global reference {} at {}:{}",
            usage.global,
            usage.file,
            usage.offset
        );
    }
    Ok(())
}

/// Add source feasibility before disposition. Runtime facts remain unchanged.
pub fn augment_manifest(
    manifest: &mut Manifest,
    analysis: &Analysis,
    database: &Path,
    root: &Path,
) -> Result<()> {
    let started = Instant::now();
    let root = fs::canonicalize(root)?;
    let bytes = fs::read(database)?;
    let commands: Vec<Value> = serde_json::from_slice(&bytes)?;
    ensure!(!commands.is_empty(), "empty source compilation database");
    let mut files = BTreeMap::new();
    for command in &commands {
        let directory = Path::new(
            command["directory"]
                .as_str()
                .context("missing command directory")?,
        );
        ensure!(
            directory.is_absolute(),
            "source command directory must be absolute"
        );
        let file = directory.join(command["file"].as_str().context("missing command file")?);
        let file = fs::canonicalize(file)?;
        let relative = file
            .strip_prefix(&root)
            .context("source TU outside snapshot")?;
        ensure!(
            !files.contains_key(&file),
            "multiple command variants for {}",
            file.display()
        );
        files.insert(file.clone(), json!({"path": relative, "command": command}));
    }
    let mut facts = extract(database)?;
    for invocation in &facts.invocations {
        let args = invocation["cc1"]
            .as_array()
            .context("missing cc1 options")?;
        let triple = args
            .windows(2)
            .find(|pair| pair[0] == "-triple")
            .map(|pair| &pair[1]);
        ensure!(
            triple == Some(&json!(manifest.run.analysis.target_triple)),
            "source/module target mismatch for {}",
            invocation["file"]
        );
    }
    check_shared_data_types(&facts)?;
    let mut defined = BTreeSet::new();
    let mut definitions = BTreeMap::new();
    for function in &facts.functions {
        if function.defined {
            let position = (
                function.file.clone(),
                function.offset,
                function.external_inline,
            );
            if let Some(old) = definitions.insert(function.name.clone(), position.clone()) {
                ensure!(
                    old == position || (old.2 && position.2),
                    "ambiguous function identity {}; uniquify statics first",
                    function.name
                );
            }
            // Header-provided external inline bodies can occur in every TU,
            // but cannot prove the external ABI/callback boundary is ours.
            if !function.external_inline {
                defined.insert(function.name.clone());
            }
        }
        if !function.internal && manifest.run.analysis.opts["build_mode"] == "library" {
            facts
                .nodes
                .entry(format!("fn:{}", function.name))
                .or_default()
                .blockers
                .insert("source-exported-entry".into());
        }
    }
    for (name, node) in &mut facts.nodes {
        if let Some(function) = name.strip_prefix("fn:") {
            if function != "main" && !defined.contains(function) {
                node.blockers.insert("source-external-producer".into());
            }
        }
    }
    // Newly reached functions must pass unknown-entry checks too.
    for variable in &facts.variables {
        let name = variable["name"].as_str().context("missing global name")?;
        if !facts.globals.contains(name) {
            // An extern-only slot/aggregate may have producers and consumers
            // outside the source snapshot. A source-only store into it must
            // not turn those unknown alternatives into an empty flow set.
            for slot in variable["callable_nodes"]
                .as_array()
                .context("missing callable slots")?
            {
                facts
                    .nodes
                    .entry(slot.as_str().context("invalid callable slot")?.into())
                    .or_default()
                    .blockers
                    .insert("source-external-callable-storage".into());
            }
        }
    }
    for edge in analysis.call_edges() {
        if let (Caller::Unknown(_), Callee::Func(callee)) = (&edge.caller, &edge.callee) {
            let name = &analysis.functions()[*callee].key;
            if name != "main" {
                facts
                    .nodes
                    .entry(format!("fn:{name}"))
                    .or_default()
                    .blockers
                    .insert("unknown-caller-taint".into());
            }
        }
    }
    let mut adjacency: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for [a, b] in &facts.edges {
        if let Some(function) = b.strip_prefix("boundary:") {
            if !defined.contains(function) {
                facts
                    .nodes
                    .entry(a.clone())
                    .or_default()
                    .blockers
                    .insert(format!("source-external-callback:{function}"));
            }
            // Internal parameter slots do not share flow via their function.
            continue;
        }
        adjacency.entry(a.clone()).or_default().insert(b.clone());
        adjacency.entry(b.clone()).or_default().insert(a.clone());
    }
    let mut calls_by_target: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for function in &facts.functions {
        if facts
            .producers
            .values()
            .any(|p| p.function == function.name)
        {
            let prefix = format!("param:{}:", function.name);
            for (key, node) in &mut facts.nodes {
                if key.starts_with(&prefix) {
                    node.blockers
                        .insert("source-higher-order-function-value".into());
                }
            }
        }
    }
    // Changing a function changes every value of that function. Changing a
    // slot only changes its participating occurrences: other producers can be
    // adapted without changing their bodies, callers, or unrelated slots.
    for (node, producer) in &facts.producers {
        adjacency
            .entry(format!("fn:{}", producer.function))
            .or_default()
            .insert(node.clone());
    }
    for (index, call) in facts.calls.iter().enumerate() {
        for node in &call.targets {
            calls_by_target.entry(node.clone()).or_default().push(index);
        }
    }
    let old_fields = std::mem::take(&mut manifest.context_rewrite.fields)
        .into_iter()
        .map(|f| (f.global.clone(), f))
        .collect::<BTreeMap<_, _>>();
    let mut fields = Vec::new();
    let main_file = facts
        .functions
        .iter()
        .find(|f| f.name == "main" && f.defined)
        .map(|f| f.file.as_str());
    for global in &mut manifest.globals {
        let name = global
            .meta
            .llvm_name
            .rsplit('.')
            .next()
            .unwrap_or(&global.meta.llvm_name);
        let uses = facts
            .uses
            .iter()
            .filter(|u| u.global == name)
            .collect::<Vec<_>>();
        let declarations = facts
            .variables
            .iter()
            .filter(|v| v["name"] == name && v["defined"] == true)
            .collect::<Vec<_>>();
        let mut observations = uses
            .iter()
            .flat_map(|u| u.observations.iter().cloned())
            .collect::<Vec<_>>();
        let relative_site = |site: &mut Site| -> Result<()> {
            site.file = Path::new(&site.file)
                .strip_prefix(&root)
                .context("source observation outside snapshot")?
                .to_string_lossy()
                .into_owned();
            Ok(())
        };
        for observation in &mut observations {
            relative_site(&mut observation.site)?;
        }
        let mut declaration_site = declarations
            .first()
            .map(|v| serde_json::from_value::<Site>(v["site"].clone()))
            .transpose()?;
        if let Some(site) = &mut declaration_site {
            relative_site(site)?;
        }
        let source = SourceObligations {
            emitter: SOURCE_EMITTER.into(),
            declaration: declarations
                .first()
                .and_then(|v| v["declaration"].as_str())
                .map(str::to_owned),
            declaration_site,
            contains_object_pointer: declarations
                .iter()
                .any(|v| v["contains_object_pointer"] == true),
            initializer_features: declarations
                .iter()
                .flat_map(|v| v["initializer_features"].as_array().into_iter().flatten())
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            observations,
        };
        global
            .facts
            .extra
            .insert("source_obligations".into(), serde_json::to_value(source)?);
        let old = old_fields.get(&global.key);
        if old.is_none() && uses.is_empty() {
            continue;
        }
        let mut field = old.cloned().unwrap_or_else(|| ContextRewriteField {
            global: global.key.clone(),
            llvm_name: global.meta.llvm_name.clone(),
            accessors: Vec::new(),
            functions: Vec::new(),
            rewrite_callsites: Vec::new(),
            blockers: Vec::new(),
            extra: Extra::new(),
        });
        let mut seeds = field
            .accessors
            .iter()
            .map(|f| format!("fn:{f}"))
            .collect::<BTreeSet<_>>();
        // The IR-only recipe widens every target of an indirect call. Rebuild
        // that rewrite closure from actual accessors and source occurrences;
        // source adapters can keep other targets (including externs) unchanged.
        let ir_rewrite_gate = |kind: &str| {
            matches!(
                kind,
                "unknown-caller-taint" | "unknown-callee-taint" | "unlocatable-callsite"
            )
        };
        field.blockers.retain(|b| !ir_rewrite_gate(&b.kind));
        // Moving a private callback's initializer to another TU would require
        // exporting the function or an initialization recipe in its owning TU.
        // This constrains moving the storage, not changing its callback type.
        for dependency in declarations
            .iter()
            .flat_map(|v| v["initializer_functions"].as_array().into_iter().flatten())
        {
            if dependency["internal"] == true && dependency["site"]["file"].as_str() != main_file {
                let function = dependency["name"]
                    .as_str()
                    .context("initializer function name")?;
                let mut b = blocker("source-private-initializer-function", function);
                b.extra
                    .insert("source_site".into(), dependency["site"].clone());
                field.blockers.push(b);
            }
        }
        for usage in &uses {
            if !usage.initializer.is_empty() {
                let mut b = blocker("source-static-initializer-dependency", &usage.initializer);
                b.initializer = Some(usage.initializer.clone());
                b.extra.insert("source_file".into(), json!(usage.file));
                b.extra.insert("source_offset".into(), json!(usage.offset));
                field.blockers.push(b);
            } else if !usage.function.is_empty() {
                seeds.insert(format!("fn:{}", usage.function));
                field.accessors.push(usage.function.clone());
            } else {
                field
                    .blockers
                    .push(blocker("source-unscoped-global-use", name));
            }
        }
        seeds.insert(format!("global:{name}"));
        if !defined.contains("main") {
            field.blockers.push(blocker("source-missing-main", name));
        }
        if !facts.globals.contains(name) {
            field.blockers.push(blocker("source-unmapped-global", name));
        }
        if !global.storage_members.is_empty() {
            field
                .blockers
                .push(blocker("source-owned-storage-recipe-required", name));
        }
        if !global.facts.access_set_complete.value {
            field.blockers.push(blocker("access-set-complete", name));
        }
        if global.facts.omega_escaped_address.value {
            field
                .blockers
                .push(blocker("source-context-lifetime-escape", name));
        }
        if global.facts.violation_taint.value {
            field.blockers.push(blocker("violation-taint", name));
        }
        let mut queue = seeds.iter().cloned().collect::<VecDeque<_>>();
        let mut reached = seeds;
        let mut reasons = Vec::new();
        let mut calls = BTreeSet::new();
        while let Some(node) = queue.pop_front() {
            let mut next = adjacency.get(&node).cloned().unwrap_or_default();
            for &i in calls_by_target.get(&node).into_iter().flatten() {
                if calls.insert(i) {
                    let call = &facts.calls[i];
                    next.extend(call.targets.iter().cloned());
                    next.insert(format!("fn:{}", call.caller));
                }
            }
            for other in next {
                if reached.insert(other.clone()) {
                    reasons.push(json!({"from": node, "to": other}));
                    queue.push_back(other);
                }
            }
        }
        let mut active = reached.clone();
        let mut conditional = BTreeSet::new();
        loop {
            let mut additions = Vec::new();
            for (node, change) in &facts.conditional_changes {
                if active.contains(node) {
                    continue;
                }
                if let Some(dependency) = change.dependencies.iter().find(|d| active.contains(*d)) {
                    additions.push((node.clone(), dependency.clone()));
                }
            }
            if additions.is_empty() {
                break;
            }
            for (node, dependency) in additions {
                active.insert(node.clone());
                conditional.insert(node.clone());
                reasons.push(json!({"from": dependency, "to": node}));
            }
        }
        let mut edits = BTreeSet::new();
        let mut functions = BTreeSet::new();
        for node in &reached {
            if let Some(n) = facts.nodes.get(node) {
                if !n.function.is_empty() {
                    functions.insert(n.function.clone());
                }
                edits.extend(n.edits.iter().cloned());
                for kind in &n.blockers {
                    field.blockers.push(blocker(kind, node));
                }
            } else if node.starts_with("fn:") {
                field
                    .blockers
                    .push(blocker("source-unmapped-function", node));
            }
        }
        for node in conditional {
            let change = &facts.conditional_changes[&node];
            edits.extend(change.edits.iter().cloned());
            for kind in &change.blockers {
                field.blockers.push(blocker(kind, &node));
            }
        }
        let mut wrappers: BTreeMap<String, BTreeSet<SourceEdit>> = BTreeMap::new();
        for node in &reached {
            let Some(producer) = facts.producers.get(node) else {
                continue;
            };
            if functions.contains(&producer.function) {
                continue;
            }
            wrappers
                .entry(producer.function.clone())
                .or_default()
                .insert(producer.edit.clone());
        }
        for (function, wrapper_edits) in &mut wrappers {
            let declarations = facts
                .wrappers
                .iter()
                .filter(|w| &w.function == function)
                .collect::<Vec<_>>();
            if declarations.is_empty() {
                field
                    .blockers
                    .push(blocker("source-missing-wrapper-recipe", function));
            }
            for (i, wrapper) in declarations.iter().enumerate() {
                for kind in &wrapper.blockers {
                    field.blockers.push(blocker(kind, function));
                }
                wrapper_edits.insert(wrapper.declaration.clone());
                if i == 0 || wrapper.internal {
                    wrapper_edits.insert(wrapper.definition.clone());
                }
            }
        }
        field.functions = functions.into_iter().collect();
        field.rewrite_callsites.clear();
        for i in calls {
            let call = &facts.calls[i];
            if call.targets.iter().any(|n| n == "fn:main") {
                field.blockers.push(blocker("source-call-to-main", "main"));
            }
            edits.insert(call.edit.clone());
            field.rewrite_callsites.push(ContextRewriteCallsite {
                key: format!("source:{}:{}", call.file, call.offset),
                caller: call.caller.clone(),
                callees: call
                    .targets
                    .iter()
                    .filter_map(|n| n.strip_prefix("fn:").map(str::to_owned))
                    .collect(),
                unresolved: false,
                site: Some(Site {
                    file: call.file.clone(),
                    line: call.line,
                    col: Some(call.col),
                    function: Some(call.caller.clone()),
                    extra: Extra::new(),
                }),
                extra: BTreeMap::from([("source_offset".into(), json!(call.offset))]),
            });
        }
        let normalize = |mut edit: SourceEdit| -> Result<SourceEdit> {
            let file = fs::canonicalize(&edit.file)?;
            ensure!(
                files.contains_key(&file),
                "edit outside preprocessed TU snapshot"
            );
            edit.file = file
                .strip_prefix(&root)?
                .to_str()
                .context("non-UTF8 source path")?
                .into();
            Ok(edit)
        };
        let normalized = edits
            .into_iter()
            .map(&normalize)
            .collect::<Result<Vec<_>>>()?;
        let wrappers = wrappers
            .into_iter()
            .map(|(function, edits)| {
                Ok(SourceWrapper {
                    function,
                    edits: edits
                        .into_iter()
                        .map(&normalize)
                        .collect::<Result<Vec<_>>>()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        field.extra.insert("source_edits".into(), json!(normalized));
        field
            .extra
            .insert("source_wrappers".into(), json!(wrappers));
        field.extra.insert("source_reasons".into(), json!(reasons));
        if pangs_manifest::compose_source_edits(&[field.clone()]).is_err() {
            field
                .blockers
                .push(blocker("source-conflicting-edits", name));
        }
        let mut samples = global
            .facts
            .localization
            .as_ref()
            .map(|l| l.blocker_samples.clone())
            .unwrap_or_default();
        samples.retain(|b| !ir_rewrite_gate(&b.code));
        samples.extend(field.blockers.iter().map(|b| LocalizationBlocker {
            code: b.kind.clone(),
            witness: Witness {
                kind: b.kind.clone(),
                site: None,
                symbol: Some(name.into()),
                note: Some(format!("source obligation: {:?}", b.extra)),
                extra: Extra::new(),
            },
            extra: Extra::new(),
        }));
        global.facts.localization = Some(Localization {
            component: manifest.context_rewrite.id.clone(),
            verdict: if samples.is_empty() {
                LocalizationVerdict::Ok
            } else {
                LocalizationVerdict::Blocked
            },
            blocker_count: samples.len(),
            blocker_samples: samples,
            extra: Extra::new(),
        });
        fields.push(field);
    }
    manifest.context_rewrite.fields = fields;
    manifest.context_rewrite.extra.insert("source".into(), json!({
        "version": SOURCE_PLAN_VERSION, "complete": true, "compiler": facts.compiler,
        "files": files.into_values().collect::<Vec<_>>(),
        "invocations": facts.invocations,
        "construction": "automatic-context-in-main", "parse_and_plan_ms": started.elapsed().as_millis(),
        "node_count": facts.nodes.len(), "call_count": facts.calls.len(),
        "globals_without_initializers": facts.no_initializer,
        "retention": {"policy": "c2rust-declaration-dependencies", "version": 1,
                      "preserve_unused_functions": false},
        "emitter": SOURCE_EMITTER,
        "pruned_declarations": facts.pruned_declarations,
        "unprunable_declarations": facts.unprunable_declarations,
        "retained_functions": facts.functions.iter().filter(|f| f.defined)
            .map(|f| f.name.clone()).collect::<BTreeSet<_>>(),
    }));
    manifest.canonicalize();
    manifest.validate()?;
    Ok(())
}
