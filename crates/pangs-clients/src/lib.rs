use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};
use jsonschema::JSONSchema;
use pangs_api::{
    Analysis, CallEdge, Callee, Caller, ComponentInfo, FuncId, GlobalId, GlobalTarget, ModRef,
    Opts, StationarityVerdict, StationarityWriter,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub fn export_analysis(
    analysis: &Analysis,
    opts: &Opts,
    input_path: &Path,
    outdir: &Path,
    validate: bool,
    pipeline_started: Instant,
) -> Result<()> {
    fs::create_dir_all(outdir).with_context(|| format!("create {}", outdir.display()))?;

    let mut files = Vec::new();
    let mut functions: Vec<_> = analysis.functions().iter().collect();
    functions.sort_by_key(|func| func.key.clone());
    write_jsonl(
        outdir.join("functions.jsonl"),
        functions.into_iter().map(FunctionRecord::from),
        &mut files,
    )?;
    let mut globals: Vec<_> = analysis.globals().iter().collect();
    globals.sort_by_key(|global| global.key.clone());
    write_jsonl(
        outdir.join("globals.jsonl"),
        globals.into_iter().map(GlobalRecord::from),
        &mut files,
    )?;
    write_jsonl(
        outdir.join("callgraph.jsonl"),
        analysis
            .call_edges()
            .iter()
            .map(|edge| CallEdgeRecord::from_edge(edge, analysis)),
        &mut files,
    )?;
    write_jsonl(
        outdir.join("modref.jsonl"),
        analysis
            .modrefs()
            .iter()
            .map(|mr| ModRefRecord::from_modref(mr, analysis)),
        &mut files,
    )?;
    write_jsonl(
        outdir.join("stationarity.jsonl"),
        analysis
            .stationarity_verdicts()
            .iter()
            .map(|verdict| StationarityRecord::from_verdict(verdict, analysis)),
        &mut files,
    )?;
    write_jsonl(
        outdir.join("audit.jsonl"),
        analysis.audit_findings().iter(),
        &mut files,
    )?;
    write_json(
        outdir.join("components.json"),
        &ComponentsRecord::from_analysis(analysis),
        &mut files,
    )?;
    let metrics = analysis.metrics().clone();
    write_json(outdir.join("metrics.json"), &metrics, &mut files)?;

    let manifest = Manifest {
        schema_version: 1,
        pangs_git: option_env!("VERGEN_GIT_SHA")
            .unwrap_or("unknown")
            .to_string(),
        llvm_version: "llvm-14-planned".to_string(),
        input_path: input_path.display().to_string(),
        input_sha256: sha256_file(input_path)?,
        opts,
        files,
        wall_ms: pipeline_started.elapsed().as_millis() as u64,
    };
    write_json(outdir.join("manifest.json"), &manifest, &mut Vec::new())?;

    if validate {
        validate_export_dir(outdir)?;
    }
    Ok(())
}

pub fn validate_export_dir(outdir: &Path) -> Result<()> {
    let json_files = [
        "manifest.json",
        "components.json",
        "metrics.json",
        "functions.jsonl",
        "globals.jsonl",
        "callgraph.jsonl",
        "modref.jsonl",
        "stationarity.jsonl",
        "audit.jsonl",
    ];
    for name in json_files {
        let path = outdir.join(name);
        let schema_json = load_schema_for_artifact(name)?;
        let schema_json = Box::leak(Box::new(schema_json));
        let schema = JSONSchema::compile(schema_json)
            .with_context(|| format!("compile schema for {name}"))?;
        if name.ends_with(".jsonl") {
            let file = File::open(&path).with_context(|| format!("open {}", path.display()))?;
            for (line_no, line) in BufReader::new(file).lines().enumerate() {
                let line = line?;
                if !line.trim().is_empty() {
                    let value = serde_json::from_str::<Value>(&line).with_context(|| {
                        format!("parse {} line {}", path.display(), line_no + 1)
                    })?;
                    validate_value_against_schema(
                        &schema,
                        &value,
                        &format!("{} line {}", path.display(), line_no + 1),
                    )?;
                }
            }
        } else {
            let text =
                fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
            let value = serde_json::from_str::<Value>(&text)
                .with_context(|| format!("parse {}", path.display()))?;
            validate_value_against_schema(&schema, &value, &path.display().to_string())?;
        }
    }
    Ok(())
}

fn load_schema_for_artifact(name: &str) -> Result<Value> {
    let schema_name = name.replace(".jsonl", ".schema.json");
    let schema_name = if schema_name == "components.json" || schema_name == "metrics.json" {
        schema_name.replace(".json", ".schema.json")
    } else if schema_name == "manifest.json" {
        "manifest.schema.json".to_string()
    } else {
        schema_name
    };
    let path = schema_dir().join(schema_name);
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str::<Value>(&text).with_context(|| format!("parse {}", path.display()))
}

fn validate_value_against_schema(schema: &JSONSchema, value: &Value, label: &str) -> Result<()> {
    schema.validate(value).map_err(|errors| {
        let details = errors
            .map(|error| format!("{} at {}", error, error.instance_path))
            .collect::<Vec<_>>()
            .join("; ");
        anyhow::anyhow!("schema validation failed for {label}: {details}")
    })
}

fn schema_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas")
        .to_path_buf()
}

pub fn report(outdir: &Path) -> Result<String> {
    let metrics_path = outdir.join("metrics.json");
    let metrics: pangs_api::Metrics = serde_json::from_str(
        &fs::read_to_string(&metrics_path)
            .with_context(|| format!("read {}", metrics_path.display()))?,
    )?;
    let manifest_path = outdir.join("manifest.json");
    let manifest: Value = serde_json::from_str(
        &fs::read_to_string(&manifest_path)
            .with_context(|| format!("read {}", manifest_path.display()))?,
    )?;
    let wall_ms = manifest["wall_ms"].as_u64().unwrap_or(0);
    let component_summary = component_summary(outdir)?;
    let callgraph_summary = jsonl_histogram(outdir, "callgraph.jsonl", &["tier"])?;
    let stationarity_summary = jsonl_histogram(outdir, "stationarity.jsonl", &["reason"])?;
    let audit_kind_summary = jsonl_histogram(outdir, "audit.jsonl", &["kind"])?;
    let audit_effect_summary = jsonl_histogram(outdir, "audit.jsonl", &["effect"])?;
    Ok(format!(
        "functions: {}\nglobals: {}\ncall edges: {}\nicalls by tier: simple={} andersen={} steens={} fsa={} unknown={}\ncall edges by tier: {}\nconfined functions: {}\ninitval complete globals: {}\nstationary globals: {}\nstationarity reasons: {}\noversize fallbacks: {} max_size={}\naudit findings: {}\naudit kinds: {}\naudit effects: {}\nmutable globals rewritable: {}/{}\ncomponent sizes: {}\nlargest frozen components: {}\ncomponent taints: {}\ncomponent blockers: {}\npipeline wall: {} ms\nanalysis wall: {} us\nsetup scan: {} us\npreanalysis: {} us\npag build: {} us\nsolve: {} us\nsolver postprocess: {} us\npointer modref: {} us\ncallgraph dedup: {} us\nmodref dedup: {} us\nstationarity: {} us\ninitval reapply: {} us\ntransitive modref: {} us\nfindings dedup: {} us\ncomponents: {} us\nmetrics bookkeeping: {} us\n",
        metrics.functions,
        metrics.globals,
        metrics.call_edges,
        metrics.icalls_simple,
        metrics.icalls_andersen,
        metrics.icalls_steens,
        metrics.icalls_fsa,
        metrics.icalls_unknown,
        format_histogram(&callgraph_summary),
        metrics.confined_functions,
        metrics.globals_with_complete_initval,
        metrics.stationary_globals,
        format_histogram(&stationarity_summary),
        metrics.oversize_fallbacks,
        metrics.oversize_fallback_max_size,
        metrics.audit_findings,
        format_histogram(&audit_kind_summary),
        format_histogram(&audit_effect_summary),
        metrics.in_rewritable_components,
        metrics.mutable_globals_total,
        component_summary.sizes,
        component_summary.largest_frozen,
        format_histogram(&component_summary.taints),
        component_summary.blockers,
        wall_ms,
        metrics.analysis_wall_us,
        metrics.setup_scan_us,
        metrics.preanalysis_us,
        metrics.pag_build_us,
        metrics.solve_us,
        metrics.solver_postprocess_us,
        metrics.pointer_modref_us,
        metrics.callgraph_dedup_us,
        metrics.modref_dedup_us,
        metrics.stationarity_us,
        metrics.initval_reapply_us,
        metrics.transitive_modref_us,
        metrics.findings_dedup_us,
        metrics.components_us,
        metrics.metrics_bookkeeping_us,
    ))
}

#[derive(Debug, Default)]
struct ComponentSummary {
    sizes: String,
    largest_frozen: String,
    taints: BTreeMap<String, usize>,
    blockers: String,
}

fn component_summary(outdir: &Path) -> Result<ComponentSummary> {
    let path = outdir.join("components.json");
    let value: Value = serde_json::from_str(
        &fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?,
    )
    .with_context(|| format!("parse {}", path.display()))?;
    let components = value["components"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("components.json missing components array"))?;

    let mut sizes = Vec::new();
    let mut frozen = Vec::new();
    let mut taints = BTreeMap::new();
    let call_edges = read_jsonl_values(outdir, "callgraph.jsonl")?;
    let modrefs = read_jsonl_values(outdir, "modref.jsonl")?;
    let audits = read_jsonl_values(outdir, "audit.jsonl")?;

    for component in components {
        let id = component["id"].as_str().unwrap_or("<unknown>").to_string();
        let members = component["members"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|member| member.as_str().map(ToOwned::to_owned))
            .collect::<BTreeSet<_>>();
        let mutable_globals = component["mutable_globals"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|global| global.as_str().map(ToOwned::to_owned))
            .collect::<BTreeSet<_>>();
        let member_count = members.len();
        let mutable_count = mutable_globals.len();
        let taint_values = component["taint"].as_array().cloned().unwrap_or_default();
        let taint_kinds = taint_values
            .iter()
            .filter_map(|taint| taint["kind"].as_str())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();

        sizes.push(member_count);
        for kind in &taint_kinds {
            *taints.entry(kind.clone()).or_insert(0) += 1;
        }
        if component["frozen"].as_bool().unwrap_or(false) {
            frozen.push(FrozenComponent {
                member_count,
                mutable_count,
                id,
                members,
                mutable_globals,
                taint_kinds,
            });
        }
    }

    sizes.sort_unstable();
    frozen.sort_by(|left, right| {
        right
            .member_count
            .cmp(&left.member_count)
            .then_with(|| left.id.cmp(&right.id))
    });

    let sizes = if sizes.is_empty() {
        "count=0 p50=0 p95=0 max=0".to_string()
    } else {
        format!(
            "count={} p50={} p95={} max={}",
            sizes.len(),
            percentile(&sizes, 50),
            percentile(&sizes, 95),
            sizes.last().copied().unwrap_or(0)
        )
    };

    let largest_frozen = if frozen.is_empty() {
        "none".to_string()
    } else {
        frozen
            .iter()
            .take(5)
            .map(|component| {
                let taints = if component.taint_kinds.is_empty() {
                    "none".to_string()
                } else {
                    format_histogram(&histogram_from_strings(&component.taint_kinds))
                };
                format!(
                    "{}(members={}, mutable_globals={}, taints={taints})",
                    component.id, component.member_count, component.mutable_count
                )
            })
            .collect::<Vec<_>>()
            .join("; ")
    };
    let blockers = format_component_blockers(&frozen, &call_edges, &modrefs, &audits);

    Ok(ComponentSummary {
        sizes,
        largest_frozen,
        taints,
        blockers,
    })
}

#[derive(Debug)]
struct FrozenComponent {
    id: String,
    member_count: usize,
    mutable_count: usize,
    members: BTreeSet<String>,
    mutable_globals: BTreeSet<String>,
    taint_kinds: Vec<String>,
}

fn format_component_blockers(
    frozen: &[FrozenComponent],
    call_edges: &[Value],
    modrefs: &[Value],
    audits: &[Value],
) -> String {
    if frozen.is_empty() {
        return "none".to_string();
    }

    frozen
        .iter()
        .take(5)
        .map(|component| {
            let mut incoming_indirect = BTreeMap::new();
            let mut outgoing_indirect = BTreeMap::new();
            let mut unknown_callees = 0usize;
            let mut unknown_callers = 0usize;

            for edge in call_edges {
                if edge["kind"].as_str() != Some("indirect") {
                    continue;
                }
                let tier = edge["tier"].as_str().unwrap_or("<missing>");
                let caller = endpoint_func(&edge["caller"]);
                let callee = endpoint_func(&edge["callee"]);
                let caller_unknown = endpoint_unknown(&edge["caller"]).is_some();
                let callee_unknown = endpoint_unknown(&edge["callee"]).is_some();

                if caller
                    .as_deref()
                    .is_some_and(|func| component.members.contains(func))
                {
                    *outgoing_indirect.entry(tier.to_string()).or_insert(0) += 1;
                    if callee_unknown {
                        unknown_callees += 1;
                    }
                }
                if callee
                    .as_deref()
                    .is_some_and(|func| component.members.contains(func))
                {
                    *incoming_indirect.entry(tier.to_string()).or_insert(0) += 1;
                    if caller_unknown {
                        unknown_callers += 1;
                    }
                }
            }

            let mut unknown_modrefs = 0usize;
            for row in modrefs {
                let func_touches_component = row["func"]
                    .as_str()
                    .is_some_and(|func| component.members.contains(func));
                let global_touches_component = row["global"]["name"]
                    .as_str()
                    .is_some_and(|global| component.mutable_globals.contains(global));
                let unknown_global = row["global"]["unknown"].as_str().is_some();
                if (func_touches_component || global_touches_component) && unknown_global {
                    unknown_modrefs += 1;
                }
            }

            let mut audit_kinds = BTreeMap::new();
            for audit in audits {
                let Some(affected) = audit["affected"].as_array() else {
                    continue;
                };
                let touches_component = affected.iter().any(|item| {
                    let Some(affected) = item.as_str() else {
                        return false;
                    };
                    affected
                        .strip_prefix("function:")
                        .is_some_and(|func| component.members.contains(func))
                        || affected
                            .strip_prefix("global:")
                            .is_some_and(|global| component.mutable_globals.contains(global))
                });
                if touches_component {
                    let kind = audit["kind"].as_str().unwrap_or("<missing>");
                    *audit_kinds.entry(kind.to_string()).or_insert(0) += 1;
                }
            }

            format!(
                "{}(out_indirect={}, in_indirect={}, unknown_callees={}, unknown_callers={}, unknown_modrefs={}, audits={})",
                component.id,
                format_histogram(&outgoing_indirect),
                format_histogram(&incoming_indirect),
                unknown_callees,
                unknown_callers,
                unknown_modrefs,
                format_histogram(&audit_kinds)
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn endpoint_func(endpoint: &Value) -> Option<String> {
    endpoint["func"].as_str().map(ToOwned::to_owned)
}

fn endpoint_unknown(endpoint: &Value) -> Option<String> {
    endpoint["unknown"].as_str().map(ToOwned::to_owned)
}

fn jsonl_histogram(
    outdir: &Path,
    filename: &str,
    field_path: &[&str],
) -> Result<BTreeMap<String, usize>> {
    let values = read_jsonl_values(outdir, filename)?;
    let mut histogram = BTreeMap::new();
    for value in &values {
        let key = field_path
            .iter()
            .try_fold(value, |current, field| current.get(*field))
            .and_then(Value::as_str)
            .unwrap_or("<missing>");
        *histogram.entry(key.to_string()).or_insert(0) += 1;
    }
    Ok(histogram)
}

fn read_jsonl_values(outdir: &Path, filename: &str) -> Result<Vec<Value>> {
    let path = outdir.join(filename);
    let file = File::open(&path).with_context(|| format!("open {}", path.display()))?;
    let mut values = Vec::new();
    for (line_no, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let value = serde_json::from_str::<Value>(&line)
            .with_context(|| format!("parse {} line {}", path.display(), line_no + 1))?;
        values.push(value);
    }
    Ok(values)
}

fn format_histogram(histogram: &BTreeMap<String, usize>) -> String {
    if histogram.is_empty() {
        return "none".to_string();
    }
    histogram
        .iter()
        .map(|(key, count)| format!("{key}={count}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn histogram_from_strings(values: &[String]) -> BTreeMap<String, usize> {
    let mut histogram = BTreeMap::new();
    for value in values {
        *histogram.entry(value.clone()).or_insert(0) += 1;
    }
    histogram
}

fn percentile(sorted: &[usize], percentile: usize) -> usize {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((sorted.len() - 1) * percentile).div_ceil(100);
    sorted[rank]
}

#[derive(Serialize)]
struct Manifest<'a> {
    schema_version: u32,
    pangs_git: String,
    llvm_version: String,
    input_path: String,
    input_sha256: String,
    opts: &'a Opts,
    files: Vec<FileRecord>,
    wall_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
struct FileRecord {
    name: String,
    records: usize,
    sha256: String,
}

#[derive(Serialize)]
struct FunctionRecord<'a> {
    key: &'a str,
    file: &'a Option<String>,
    line: Option<u32>,
    external: bool,
    exported: bool,
    address_taken: bool,
    vararg: bool,
    sig: &'a str,
}

impl<'a> From<&'a pangs_api::FuncInfo> for FunctionRecord<'a> {
    fn from(info: &'a pangs_api::FuncInfo) -> Self {
        Self {
            key: &info.key,
            file: &info.file,
            line: info.line,
            external: info.external,
            exported: info.exported,
            address_taken: info.address_taken,
            vararg: info.vararg,
            sig: &info.sig,
        }
    }
}

#[derive(Serialize)]
struct GlobalRecord<'a> {
    key: &'a str,
    file: &'a Option<String>,
    line: Option<u32>,
    is_const: bool,
    never_written: bool,
    escape: pangs_api::EscapeStatus,
    mutable: bool,
    stationary: bool,
}

impl<'a> From<&'a pangs_api::GlobalInfo> for GlobalRecord<'a> {
    fn from(info: &'a pangs_api::GlobalInfo) -> Self {
        Self {
            key: &info.key,
            file: &info.file,
            line: info.line,
            is_const: info.is_const,
            never_written: info.never_written,
            escape: info.escape,
            mutable: info.mutable,
            stationary: info.stationary,
        }
    }
}

#[derive(Serialize)]
struct CallEdgeRecord {
    caller: Endpoint,
    callsite: Option<String>,
    callee: Endpoint,
    kind: pangs_api::CallKind,
    tier: pangs_api::Tier,
}

impl CallEdgeRecord {
    fn from_edge(edge: &CallEdge, analysis: &Analysis) -> Self {
        Self {
            caller: match &edge.caller {
                Caller::Func(id) => Endpoint::Func {
                    func: func_key(analysis, *id),
                },
                Caller::Unknown(reason) => Endpoint::Unknown {
                    unknown: reason.clone(),
                },
            },
            callsite: edge.callsite.map(|id| analysis.callsites()[id].key.clone()),
            callee: match &edge.callee {
                Callee::Func(id) => Endpoint::Func {
                    func: func_key(analysis, *id),
                },
                Callee::Unknown(reason) => Endpoint::Unknown {
                    unknown: reason.clone(),
                },
            },
            kind: edge.kind,
            tier: edge.tier,
        }
    }
}

#[derive(Serialize)]
#[serde(untagged)]
enum Endpoint {
    Func { func: String },
    Unknown { unknown: String },
}

#[derive(Serialize)]
struct ModRefRecord {
    func: String,
    global: GlobalRecordTarget,
    access: pangs_pir::Access,
    via: pangs_api::Via,
    witness: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address_node: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pointee_globals: Vec<String>,
}

impl ModRefRecord {
    fn from_modref(mr: &ModRef, analysis: &Analysis) -> Self {
        Self {
            func: func_key(analysis, mr.func),
            global: match &mr.global {
                GlobalTarget::Name(id) => GlobalRecordTarget::Name {
                    name: global_key(analysis, *id),
                },
                GlobalTarget::Unknown(reason) => GlobalRecordTarget::Unknown {
                    unknown: reason.clone(),
                },
            },
            access: mr.access,
            via: mr.via,
            witness: mr.witness.clone(),
            detail: mr.detail.clone(),
            address_node: mr.address_node.clone(),
            pointee_globals: mr.pointee_globals.clone(),
        }
    }
}

#[derive(Serialize)]
#[serde(untagged)]
enum GlobalRecordTarget {
    Name { name: String },
    Unknown { unknown: String },
}

#[derive(Serialize)]
struct StationarityRecord {
    global: String,
    complete_initval: bool,
    stationary: bool,
    reason: pangs_api::StationarityReason,
    runtime_writers: Vec<StationarityWriterRecord>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    initval_diagnostics: Vec<InitValDiagnosticRecord>,
}

impl StationarityRecord {
    fn from_verdict(verdict: &StationarityVerdict, analysis: &Analysis) -> Self {
        Self {
            global: global_key(analysis, verdict.global),
            complete_initval: verdict.complete_initval,
            stationary: verdict.stationary,
            reason: verdict.reason,
            runtime_writers: verdict
                .runtime_writers
                .iter()
                .map(|writer| StationarityWriterRecord::from_writer(writer, analysis))
                .collect(),
            initval_diagnostics: verdict
                .initval_diagnostics
                .iter()
                .map(InitValDiagnosticRecord::from_diagnostic)
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct InitValDiagnosticRecord {
    reason: String,
    witness: Option<String>,
}

impl InitValDiagnosticRecord {
    fn from_diagnostic(diagnostic: &pangs_api::InitValDiagnostic) -> Self {
        Self {
            reason: diagnostic.reason.clone(),
            witness: diagnostic.witness.clone(),
        }
    }
}

#[derive(Serialize)]
struct StationarityWriterRecord {
    func: Option<String>,
    global: GlobalRecordTarget,
    access: pangs_pir::Access,
    via: pangs_api::Via,
    witness: Option<String>,
}

impl StationarityWriterRecord {
    fn from_writer(writer: &StationarityWriter, analysis: &Analysis) -> Self {
        Self {
            func: writer.func.map(|id| func_key(analysis, id)),
            global: match &writer.global {
                GlobalTarget::Name(id) => GlobalRecordTarget::Name {
                    name: global_key(analysis, *id),
                },
                GlobalTarget::Unknown(reason) => GlobalRecordTarget::Unknown {
                    unknown: reason.clone(),
                },
            },
            access: writer.access,
            via: writer.via,
            witness: writer.witness.clone(),
        }
    }
}

#[derive(Serialize)]
struct ComponentsRecord {
    components: Vec<ComponentExport>,
    coverage: Coverage,
}

impl ComponentsRecord {
    fn from_analysis(analysis: &Analysis) -> Self {
        Self {
            components: analysis
                .components()
                .iter()
                .map(|component| ComponentExport::from_component(component, analysis))
                .collect(),
            coverage: Coverage {
                mutable_globals_total: analysis.metrics().mutable_globals_total,
                in_rewritable_components: analysis.metrics().in_rewritable_components,
            },
        }
    }
}

#[derive(Serialize)]
struct ComponentExport {
    id: String,
    frozen: bool,
    taint: Vec<pangs_api::Taint>,
    members: Vec<String>,
    mutable_globals: Vec<String>,
}

impl ComponentExport {
    fn from_component(component: &ComponentInfo, analysis: &Analysis) -> Self {
        Self {
            id: component.id.clone(),
            frozen: component.frozen,
            taint: component.taint.clone(),
            members: component
                .members
                .iter()
                .map(|id| func_key(analysis, *id))
                .collect(),
            mutable_globals: component
                .mutable_globals
                .iter()
                .map(|id| global_key(analysis, *id))
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct Coverage {
    mutable_globals_total: usize,
    in_rewritable_components: usize,
}

fn func_key(analysis: &Analysis, id: FuncId) -> String {
    analysis.functions()[id].key.clone()
}

fn global_key(analysis: &Analysis, id: GlobalId) -> String {
    analysis.globals()[id].key.clone()
}

fn write_jsonl<T, I>(path: impl AsRef<Path>, records: I, files: &mut Vec<FileRecord>) -> Result<()>
where
    T: Serialize,
    I: IntoIterator<Item = T>,
{
    let path = path.as_ref();
    let mut file = File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut count = 0;
    for record in records {
        serde_json::to_writer(&mut file, &record)?;
        file.write_all(b"\n")?;
        count += 1;
    }
    files.push(FileRecord {
        name: path.file_name().unwrap().to_string_lossy().to_string(),
        records: count,
        sha256: sha256_file(path)?,
    });
    Ok(())
}

fn write_json<T: Serialize>(
    path: impl AsRef<Path>,
    value: &T,
    files: &mut Vec<FileRecord>,
) -> Result<()> {
    let path = path.as_ref();
    let mut file = File::create(path).with_context(|| format!("create {}", path.display()))?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    if files.is_empty() && path.file_name().is_some_and(|name| name == "manifest.json") {
        return Ok(());
    }
    files.push(FileRecord {
        name: path.file_name().unwrap().to_string_lossy().to_string(),
        records: 1,
        sha256: sha256_file(path)?,
    });
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(data);
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use std::time::Instant;

    use pangs_api::{Analysis, Opts};
    use pangs_pir::Pir;
    use tempfile::TempDir;

    use super::{check_traces, export_analysis, report, validate_export_dir};

    #[test]
    fn check_traces_flags_a_target_outside_the_edge_set() {
        let dir = TempDir::new().unwrap();
        // One indirect callsite resolved to {target}; no unknown edge → not permissive.
        fs::write(
            dir.path().join("callgraph.jsonl"),
            "{\"caller\":{\"func\":\"main\"},\"callsite\":\"main@!noloc#0\",\"callee\":{\"func\":\"target\"},\"kind\":\"indirect\",\"tier\":\"andersen\"}\n",
        )
        .unwrap();
        let trace = dir.path().join("trace.txt");

        // Observed target in the set → clean.
        fs::write(&trace, "main\t0\ttarget\n").unwrap();
        assert!(check_traces(dir.path(), &trace).unwrap().is_clean());

        // Observed target NOT in the set → violation (the soundness catch).
        fs::write(&trace, "main\t0\trogue\n").unwrap();
        let report = check_traces(dir.path(), &trace).unwrap();
        assert!(!report.is_clean());
        assert!(report.violations[0].contains("rogue"));
    }

    #[test]
    fn check_traces_permits_targets_at_unknown_sites() {
        let dir = TempDir::new().unwrap();
        // Site carries an unknown (Ω) callee edge → permissive: any observed target is ok.
        fs::write(
            dir.path().join("callgraph.jsonl"),
            "{\"caller\":{\"func\":\"main\"},\"callsite\":\"main@!noloc#0\",\"callee\":{\"unknown\":\"omega_fnptr\"},\"kind\":\"indirect\",\"tier\":\"andersen\"}\n",
        )
        .unwrap();
        let trace = dir.path().join("trace.txt");
        fs::write(&trace, "main\t0\tanything\n").unwrap();
        assert!(check_traces(dir.path(), &trace).unwrap().is_clean());
    }

    #[test]
    fn validate_export_dir_rejects_schema_mismatch() {
        let fixture = workspace_root().join("fixtures/synthetic/trivial/module.pir.json");
        let pir = Pir::from_path(&fixture).unwrap();
        let analysis = Analysis::run(&pir, &Opts::default()).unwrap();
        let outdir = TempDir::new().unwrap();

        export_analysis(
            &analysis,
            &Opts::default(),
            &fixture,
            outdir.path(),
            false,
            Instant::now(),
        )
        .unwrap();
        fs::write(
            outdir.path().join("metrics.json"),
            "{\"functions\":\"bad\",\"globals\":0,\"callsites\":0,\"call_edges\":0,\"audit_findings\":0,\"mutable_globals_total\":0,\"in_rewritable_components\":0,\"partition_count\":0,\"partition_p50_size\":0,\"partition_p95_size\":0,\"partition_max_size\":0,\"oversize_fallbacks\":0,\"oversize_fallback_max_size\":0,\"rounds\":0,\"analysis_wall_us\":0,\"setup_scan_us\":0,\"preanalysis_us\":0,\"pag_build_us\":0,\"solve_us\":0,\"solver_postprocess_us\":0,\"pointer_modref_us\":0,\"callgraph_dedup_us\":0,\"modref_dedup_us\":0,\"stationarity_us\":0,\"initval_reapply_us\":0,\"transitive_modref_us\":0,\"findings_dedup_us\":0,\"components_us\":0,\"metrics_bookkeeping_us\":0}\n",
        )
        .unwrap();

        let err = validate_export_dir(outdir.path()).unwrap_err().to_string();
        assert!(err.contains("metrics.json"));
        assert!(err.contains("schema validation failed"));
    }

    #[test]
    fn report_includes_pipeline_and_phase_timings() {
        let fixture = workspace_root().join("fixtures/synthetic/trivial/module.pir.json");
        let pir = Pir::from_path(&fixture).unwrap();
        let analysis = Analysis::run(&pir, &Opts::default()).unwrap();
        let outdir = TempDir::new().unwrap();

        export_analysis(
            &analysis,
            &Opts::default(),
            &fixture,
            outdir.path(),
            false,
            Instant::now(),
        )
        .unwrap();

        let text = report(outdir.path()).unwrap();
        assert!(text.contains("pipeline wall: "));
        assert!(text.contains("analysis wall: "));
        assert!(text.contains("setup scan: "));
        assert!(text.contains("preanalysis: "));
        assert!(text.contains("pag build: "));
        assert!(text.contains("solve: "));
        assert!(text.contains("solver postprocess: "));
        assert!(text.contains("pointer modref: "));
        assert!(text.contains("callgraph dedup: "));
        assert!(text.contains("modref dedup: "));
        assert!(text.contains("stationarity: "));
        assert!(text.contains("initval reapply: "));
        assert!(text.contains("transitive modref: "));
        assert!(text.contains("findings dedup: "));
        assert!(text.contains("components: "));
        assert!(text.contains("metrics bookkeeping: "));
        assert!(text.contains("icalls by tier: "));
        assert!(text.contains("call edges by tier: "));
        assert!(text.contains("confined functions: "));
        assert!(text.contains("initval complete globals: "));
        assert!(text.contains("stationary globals: "));
        assert!(text.contains("stationarity reasons: "));
        assert!(text.contains("oversize fallbacks: "));
        assert!(text.contains("audit kinds: "));
        assert!(text.contains("audit effects: "));
        assert!(text.contains("component sizes: "));
        assert!(text.contains("largest frozen components: "));
        assert!(text.contains("component taints: "));
        assert!(text.contains("component blockers: "));
    }

    fn workspace_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }
}

/// Result of validating a dynamic icall trace against an export directory.
#[derive(Debug, Default)]
pub struct TraceReport {
    /// (caller, idx, target) pairs that are not in the analysis's edge set.
    pub violations: Vec<String>,
    pub checked: usize,
    /// Trace rows whose target could not be resolved to a symbol (dladdr "?").
    pub unresolved: usize,
}

impl TraceReport {
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }
}

/// M1.8 dynamic icall validation: assert every observed `(caller, idx, target)` in a trace
/// file is permitted by the analysis's indirect-call edge set in `dir/callgraph.jsonl`.
///
/// `idx` is the static index of an indirect call among its function's indirect calls (in
/// instruction order). The analysis's indirect callsites for a caller, ordered by their
/// key ordinal, are in the same order — so trace `idx` selects the matching callsite. A
/// callsite that already carries an unknown (Ω) callee edge is permissive (the analysis
/// conceded it cannot bound that site, so no observed target there is a violation).
pub fn check_traces(dir: &Path, trace: &Path) -> Result<TraceReport> {
    let callgraph = dir.join("callgraph.jsonl");
    let file = File::open(&callgraph).with_context(|| format!("open {}", callgraph.display()))?;

    // caller -> callsite_key -> (allowed targets, permissive?)
    use std::collections::{BTreeMap, BTreeSet};
    let mut sites: BTreeMap<String, BTreeMap<String, (BTreeSet<String>, bool)>> = BTreeMap::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let row: Value = serde_json::from_str(&line)?;
        if row.get("kind").and_then(Value::as_str) != Some("indirect") {
            continue;
        }
        let Some(caller) = row["caller"].get("func").and_then(Value::as_str) else {
            continue;
        };
        let Some(callsite) = row.get("callsite").and_then(Value::as_str) else {
            continue;
        };
        let entry = sites
            .entry(caller.to_string())
            .or_default()
            .entry(callsite.to_string())
            .or_insert_with(|| (BTreeSet::new(), false));
        match (&row["callee"]).get("func").and_then(Value::as_str) {
            Some(func) => {
                entry.0.insert(func.to_string());
            }
            None => {
                // unknown/Ω callee → permissive site
                entry.1 = true;
            }
        }
    }

    // For each caller, order its indirect callsite keys by their ordinal (the trailing
    // `#<n>` segment), giving the same index the runtime counts.
    let ordered: BTreeMap<String, Vec<String>> = sites
        .iter()
        .map(|(caller, by_key)| {
            let mut keys: Vec<String> = by_key.keys().cloned().collect();
            keys.sort_by_key(|k| key_ordinal(k));
            (caller.clone(), keys)
        })
        .collect();

    let trace_file = File::open(trace).with_context(|| format!("open {}", trace.display()))?;
    let mut report = TraceReport::default();
    for line in BufReader::new(trace_file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let mut cols = line.split('\t');
        let caller = cols.next().unwrap_or("").to_string();
        let idx: usize = cols.next().unwrap_or("").parse().unwrap_or(usize::MAX);
        let target = cols.next().unwrap_or("").to_string();
        report.checked += 1;
        if target == "?" {
            report.unresolved += 1;
            continue;
        }
        let Some(keys) = ordered.get(&caller) else {
            report.violations.push(format!(
                "{caller}#{idx}: caller has no indirect callsites in the analysis, observed target {target}"
            ));
            continue;
        };
        let Some(key) = keys.get(idx) else {
            report.violations.push(format!(
                "{caller}#{idx}: observed indirect call index out of range (analysis has {} sites), target {target}",
                keys.len()
            ));
            continue;
        };
        let (allowed, permissive) = &sites[&caller][key];
        if *permissive || allowed.contains(&target) {
            continue;
        }
        report.violations.push(format!(
            "{key}: observed target {target} not in analysis edge set {{{}}}",
            allowed.iter().cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    Ok(report)
}

/// Parse the trailing `#<n>` ordinal of a callsite key; keys without one sort last.
fn key_ordinal(key: &str) -> u64 {
    key.rsplit_once('#')
        .and_then(|(_, n)| n.parse().ok())
        .unwrap_or(u64::MAX)
}
