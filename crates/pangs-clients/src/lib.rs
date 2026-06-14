use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};
use jsonschema::JSONSchema;
use pangs_api::{
    Analysis, CallEdge, Callee, Caller, ComponentInfo, FuncId, GlobalId, GlobalTarget, ModRef, Opts,
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
    Ok(format!(
        "functions: {}\nglobals: {}\ncall edges: {}\naudit findings: {}\nmutable globals rewritable: {}/{}\n",
        metrics.functions,
        metrics.globals,
        metrics.call_edges,
        metrics.audit_findings,
        metrics.in_rewritable_components,
        metrics.mutable_globals_total,
    ))
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

    use super::{export_analysis, validate_export_dir};

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
            "{\"functions\":\"bad\",\"globals\":0,\"callsites\":0,\"call_edges\":0,\"audit_findings\":0,\"mutable_globals_total\":0,\"in_rewritable_components\":0,\"partition_count\":0,\"partition_p50_size\":0,\"partition_p95_size\":0,\"partition_max_size\":0,\"oversize_fallbacks\":0,\"rounds\":0,\"analysis_wall_us\":0,\"pag_build_us\":0,\"solve_us\":0,\"transitive_modref_us\":0,\"components_us\":0}\n",
        )
        .unwrap();

        let err = validate_export_dir(outdir.path()).unwrap_err().to_string();
        assert!(err.contains("metrics.json"));
        assert!(err.contains("schema validation failed"));
    }

    fn workspace_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }
}
