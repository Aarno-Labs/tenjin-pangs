use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use pangs_api::{AffectedGlobals, Analysis, BuildMode, GlobalTarget, Opts, RegistryApi, Stage};
use pangs_dispose::{apply_policy, config_with_overrides, parse_overrides, write_artifact_pair};
use pangs_manifest::{write_canonical_json, DisposeMode};
use pangs_pag::{BuildMode as PagBuildMode, Pag, PagOpts};
use pangs_pir::Pir;
use sha2::{Digest, Sha256};

mod knobs;

#[derive(Debug, Parser)]
#[command(name = "pangs")]
#[command(about = "PANGS analysis CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Analyze {
        module: PathBuf,
        #[arg(short, long)]
        out: PathBuf,
        // Andersen is the M1 shipping answer (M1.4b); `conservative` and `steens` remain
        // runnable regression floors.
        #[arg(long, default_value = knobs::DEFAULT_ANALYSIS_STAGE)]
        stage: StageArg,
        #[arg(long, default_value = knobs::DEFAULT_BUILD_MODE)]
        build_mode: BuildModeArg,
        #[arg(long)]
        exports: Option<PathBuf>,
        #[arg(long, default_value_t = knobs::DEFAULT_PARTITION_BUDGET, hide = true)]
        partition_budget: u64,
        #[arg(long)]
        validate: bool,
        #[arg(long)]
        dispose: bool,
        /// Emit only the disposition manifest, audit ledger, and analysis metrics.
        #[arg(long, requires = "dispose")]
        manifest_only: bool,
        #[arg(long, requires = "dispose")]
        repo_root: Option<PathBuf>,
        #[arg(long, requires = "dispose")]
        mode: Option<DisposeModeArg>,
        #[arg(long, requires = "dispose", conflicts_with = "no_overrides")]
        overrides: Option<PathBuf>,
        #[arg(long, requires = "dispose")]
        no_overrides: bool,
        /// JSON array of additional or replacement spawn/signal registry entries.
        #[arg(long, requires = "dispose")]
        registry_config: Option<PathBuf>,
    },
    Stats {
        module: PathBuf,
    },
    /// Run analysis and print mod/ref row counts without writing exports.
    ModrefSummary {
        module: PathBuf,
        #[arg(long, default_value = knobs::DEFAULT_ANALYSIS_STAGE)]
        stage: StageArg,
        #[arg(long, default_value = knobs::DEFAULT_BUILD_MODE)]
        build_mode: BuildModeArg,
        #[arg(long)]
        exports: Option<PathBuf>,
        #[arg(long, default_value_t = knobs::DEFAULT_PARTITION_BUDGET, hide = true)]
        partition_budget: u64,
    },
    /// Emit the diagnostic-only Phase-0 external-policy opportunity census as JSON.
    ExternalPolicyCensus {
        module: PathBuf,
        #[arg(short, long)]
        out: Option<PathBuf>,
        #[arg(long, default_value = knobs::DEFAULT_ANALYSIS_STAGE)]
        stage: StageArg,
        #[arg(long, default_value = knobs::DEFAULT_BUILD_MODE)]
        build_mode: BuildModeArg,
        #[arg(long)]
        exports: Option<PathBuf>,
        #[arg(long, default_value_t = knobs::DEFAULT_PARTITION_BUDGET, hide = true)]
        partition_budget: u64,
        /// Repository root used by disposition fact assembly.
        #[arg(long, default_value = ".")]
        repo_root: PathBuf,
        /// Retain targeted allocation-level points-to for callback-capable opaque-call
        /// arguments. Expensive; use after the core census identifies a D4 opportunity.
        #[arg(long)]
        callback_closure: bool,
    },
    DumpPir {
        module: PathBuf,
        #[arg(long)]
        func: Option<String>,
    },
    DumpPag {
        module: PathBuf,
        #[arg(long)]
        func: Option<String>,
        #[arg(long, default_value = knobs::DEFAULT_BUILD_MODE)]
        build_mode: BuildModeArg,
        #[arg(long)]
        exports: Option<PathBuf>,
    },
    CheckPag {
        module: PathBuf,
        #[arg(long, default_value = knobs::DEFAULT_BUILD_MODE)]
        build_mode: BuildModeArg,
        #[arg(long)]
        exports: Option<PathBuf>,
    },
    /// Emit the cheap Steensgaard-derived Andersen admission census as JSONL.
    AndersenAdmissionCensus {
        module: PathBuf,
        #[arg(long, default_value = knobs::DEFAULT_BUILD_MODE)]
        build_mode: BuildModeArg,
        #[arg(long)]
        exports: Option<PathBuf>,
    },
    Report {
        dir: PathBuf,
    },
    /// Run experimental tier-E query prototypes over the frozen PAG.
    ///
    /// These diagnostics are not used by the PANGS-lite `analyze` pipeline.
    Query {
        #[command(subcommand)]
        query: QueryCommand,
    },
    /// Run conservative→steens→andersen and check the narrowing/monotonicity ledger.
    Differential {
        module: PathBuf,
        #[arg(long, default_value = knobs::DEFAULT_BUILD_MODE)]
        build_mode: BuildModeArg,
        #[arg(long)]
        exports: Option<PathBuf>,
        #[arg(long, default_value_t = knobs::DEFAULT_PARTITION_BUDGET, hide = true)]
        partition_budget: u64,
    },
    /// Emit the diagnostic indirect-call provenance + FSA-intersection census as JSONL.
    ///
    /// One row per indirect callsite: how its function-pointer operand is produced, the size
    /// of its FSA signature envelope, and how the pointer answer relates to that envelope.
    /// Purely observational — no analysis fact depends on it.
    IcallCensus {
        module: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        /// Also write a module-level summary JSON (row counts plus the analysis metrics that
        /// bear on this census), so a corpus sweep needs only this one run per module.
        #[arg(long)]
        summary: Option<PathBuf>,
        #[arg(long, default_value = knobs::DEFAULT_ANALYSIS_STAGE)]
        stage: StageArg,
        #[arg(long, default_value = knobs::DEFAULT_BUILD_MODE)]
        build_mode: BuildModeArg,
        #[arg(long)]
        exports: Option<PathBuf>,
        #[arg(long, default_value_t = knobs::DEFAULT_PARTITION_BUDGET, hide = true)]
        partition_budget: u64,
    },
    /// Run the M2.7 pre-analysis ablation: M1 baseline, B2 only, B1 only, and both.
    M2Ablation {
        module: PathBuf,
        #[arg(long, default_value = knobs::DEFAULT_ANALYSIS_STAGE)]
        stage: StageArg,
        #[arg(long, default_value = knobs::DEFAULT_BUILD_MODE)]
        build_mode: BuildModeArg,
        #[arg(long)]
        exports: Option<PathBuf>,
        #[arg(long, default_value_t = knobs::DEFAULT_PARTITION_BUDGET, hide = true)]
        partition_budget: u64,
    },
    /// Instrument every indirect call in a module, writing an instrumented `.bc`.
    Instrument {
        module: PathBuf,
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Validate a dynamic icall trace against an analysis export directory.
    CheckTraces {
        dir: PathBuf,
        trace: PathBuf,
    },
    /// Emit a `cc2json`-compatible JSON summary (mutated/escaped globals, bipartite call-graph
    /// components, mutable-global tissue, global initializer references) for a bitcode module.
    Cc2json {
        module: PathBuf,
        #[arg(long)]
        json_out: PathBuf,
        #[arg(long, default_value = knobs::DEFAULT_ANALYSIS_STAGE)]
        stage: StageArg,
        /// pangs reachability mode: `library` (all functions reachable) or `executable`
        /// (reachable from `main`). Mirrors cc2json's `--entrypoints`.
        #[arg(long, default_value = knobs::DEFAULT_BUILD_MODE)]
        entrypoints: BuildModeArg,
        /// Treat all globals as module-internal for escape analysis (cclyzer's
        /// `--internalize-globals`). Off by default, matching how the goldens were produced.
        #[arg(long)]
        internalize_globals: bool,
        #[arg(long, default_value_t = knobs::DEFAULT_PARTITION_BUDGET, hide = true)]
        partition_budget: u64,
    },
}

#[derive(Debug, Subcommand)]
enum QueryCommand {
    /// Run the experimental tier-E M3 callee query prototype.
    Callees {
        module: PathBuf,
        #[arg(long, default_value = knobs::DEFAULT_BUILD_MODE)]
        build_mode: BuildModeArg,
        #[arg(long)]
        exports: Option<PathBuf>,
        #[arg(long, default_value = knobs::DEFAULT_QUERY_MODE)]
        mode: QueryModeArg,
    },
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, ValueEnum)]
enum QueryModeArg {
    FieldInsensitive,
    FieldSensitive,
    FieldSensitiveFixpoint,
}

impl QueryModeArg {
    fn label(self) -> &'static str {
        match self {
            QueryModeArg::FieldInsensitive => "field_insensitive",
            QueryModeArg::FieldSensitive => "field_sensitive",
            QueryModeArg::FieldSensitiveFixpoint => "field_sensitive_fixpoint",
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum StageArg {
    Conservative,
    Steens,
    Andersen,
}

impl From<StageArg> for Stage {
    fn from(value: StageArg) -> Self {
        match value {
            StageArg::Conservative => Stage::Conservative,
            StageArg::Steens => Stage::Steens,
            StageArg::Andersen => Stage::Andersen,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BuildModeArg {
    Library,
    Executable,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DisposeModeArg {
    Application,
    Library,
}

impl From<DisposeModeArg> for DisposeMode {
    fn from(value: DisposeModeArg) -> Self {
        match value {
            DisposeModeArg::Application => Self::Application,
            DisposeModeArg::Library => Self::Library,
        }
    }
}

impl From<BuildModeArg> for BuildMode {
    fn from(value: BuildModeArg) -> Self {
        match value {
            BuildModeArg::Library => BuildMode::Library,
            BuildModeArg::Executable => BuildMode::Executable,
        }
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err:#}");
        std::process::exit(2);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Analyze {
            module,
            out,
            stage,
            build_mode,
            exports,
            partition_budget,
            validate,
            dispose,
            manifest_only,
            repo_root,
            mode,
            overrides,
            no_overrides,
            registry_config,
        } => {
            let pipeline_started = Instant::now();
            let pir = if dispose {
                let repo_root = repo_root
                    .as_ref()
                    .context("--dispose requires --repo-root")?;
                Pir::from_path_with_repo_root(&module, repo_root)?
            } else {
                Pir::from_path(&module)?
            };
            let opts = Opts {
                stage: stage.into(),
                build_mode: build_mode.into(),
                exports: read_exports(exports)?,
                partition_budget,
                disposition_registries: read_registry_config(registry_config.as_deref())?,
                ..Opts::default()
            };
            eprintln!(
                "pangs analyze stage={:?} build_mode={:?}",
                opts.stage, opts.build_mode
            );
            let analysis = if dispose {
                Analysis::run_with_disposition(&pir, &opts)?
            } else {
                Analysis::run(&pir, &opts)?
            };
            if !manifest_only {
                pangs_clients::export_analysis(
                    &analysis,
                    &opts,
                    &module,
                    &out,
                    validate,
                    pipeline_started,
                )?;
            }
            if dispose {
                let repo_root = repo_root.as_ref().expect("checked above");
                let target = pir
                    .target
                    .as_ref()
                    .context("--dispose requires LLVM target metadata")?;
                let (mut disposition_manifest, mut ledger) =
                    pangs_clients::assemble_disposition_artifacts(
                        &analysis, &pir, &opts, &module, repo_root, target,
                    )?;
                let analysis_mode = match opts.build_mode {
                    BuildMode::Executable => DisposeMode::Application,
                    BuildMode::Library => DisposeMode::Library,
                };
                let disposition_mode = match mode.map(DisposeMode::from) {
                    None => analysis_mode,
                    Some(DisposeMode::Library) => DisposeMode::Library,
                    Some(DisposeMode::Application) if analysis_mode == DisposeMode::Application => {
                        DisposeMode::Application
                    }
                    Some(DisposeMode::Application) => {
                        anyhow::bail!("cannot widen a library analysis to application mode")
                    }
                };
                let discovered = out.join("pangs-overrides.toml");
                let overrides_path = if no_overrides {
                    None
                } else if let Some(path) = overrides {
                    if !path.exists() {
                        anyhow::bail!("explicit override file does not exist: {}", path.display());
                    }
                    Some(fs::canonicalize(path)?)
                } else {
                    discovered
                        .exists()
                        .then(|| fs::canonicalize(discovered))
                        .transpose()?
                };
                let (override_config, overrides_sha256) =
                    load_disposition_overrides(overrides_path.as_deref())?;
                let config = config_with_overrides(disposition_mode, override_config.as_ref())?;
                let outcome = apply_policy(
                    &mut disposition_manifest,
                    &mut ledger,
                    &config,
                    override_config.as_ref(),
                    overrides_path.map(|path| path.display().to_string()),
                    overrides_sha256,
                )?;
                write_artifact_pair(&out, &disposition_manifest, &ledger)?;
                if manifest_only {
                    write_canonical_json(&out.join("metrics.json"), analysis.metrics())?;
                }
                if outcome.override_problems {
                    anyhow::bail!(
                        "one or more disposition overrides were rejected or unmatched; artifacts were written"
                    );
                }
            }
        }
        Command::Stats { module } => {
            let pir = Pir::from_path(&module)?;
            let opts = Opts::default();
            let analysis = Analysis::run(&pir, &opts)?;
            println!("{}", serde_json::to_string_pretty(analysis.metrics())?);
        }
        Command::ModrefSummary {
            module,
            stage,
            build_mode,
            exports,
            partition_budget,
        } => {
            let pir = Pir::from_path(&module)?;
            let opts = Opts {
                stage: stage.into(),
                build_mode: build_mode.into(),
                exports: read_exports(exports)?,
                partition_budget,
                ..Opts::default()
            };
            let analysis = Analysis::run(&pir, &opts)?;
            let transitive_rows = analysis.transitive_modref_count();
            let mut unknown_rows = 0usize;
            let mut module_wide_rows = 0usize;
            let mut module_wide_rows_with_universal_sources = 0usize;
            let mut universal_source_rows = BTreeMap::<String, usize>::new();
            for row in analysis.modrefs() {
                if !matches!(&row.global, GlobalTarget::Unknown(_)) {
                    continue;
                }
                unknown_rows += 1;
                if !matches!(analysis.affected_globals(row), AffectedGlobals::ModuleWide) {
                    continue;
                }
                module_wide_rows += 1;
                let Some((_, sources)) = row
                    .detail
                    .as_deref()
                    .and_then(|detail| detail.split_once(":universal_sources="))
                else {
                    continue;
                };
                module_wide_rows_with_universal_sources += 1;
                for source in sources.split(',').filter(|source| !source.is_empty()) {
                    *universal_source_rows.entry(source.to_string()).or_default() += 1;
                }
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "functions": analysis.functions().len(),
                    "local_modref_rows": analysis.modrefs().len(),
                    "unknown_modref_rows": unknown_rows,
                    "module_wide_modref_rows": module_wide_rows,
                    "module_wide_rows_with_universal_sources": module_wide_rows_with_universal_sources,
                    "universal_source_rows": universal_source_rows,
                    "transitive_modref_rows": transitive_rows,
                    "metrics": analysis.metrics(),
                }))?
            );
        }
        Command::ExternalPolicyCensus {
            module,
            out,
            stage,
            build_mode,
            exports,
            partition_budget,
            repo_root,
            callback_closure,
        } => {
            if matches!(stage, StageArg::Conservative) {
                anyhow::bail!("external-policy-census requires --stage steens or andersen");
            }
            let pir = Pir::from_path_with_repo_root(&module, &repo_root)?;
            let opts = Opts {
                stage: stage.into(),
                build_mode: build_mode.into(),
                exports: read_exports(exports)?,
                partition_budget,
                ..Opts::default()
            };
            let mut analysis = Analysis::run_with_external_policy_census(&pir, &opts, None)?;
            let target = pir
                .target
                .as_ref()
                .context("external-policy-census requires LLVM target metadata")?;
            let (mut manifest, _) = pangs_clients::assemble_disposition_artifacts(
                &analysis, &pir, &opts, &module, &repo_root, target,
            )?;
            let mut d4 = pangs_clients::external_policy_d4_census(&analysis, &manifest);
            let mut callback_target_callsites = BTreeSet::new();
            if callback_closure {
                let core = analysis
                    .external_policy_census()
                    .context("external-policy core census inputs were not produced")?;
                let selected_callsites = d4
                    .globals
                    .iter()
                    .filter(|global| {
                        global
                            .strict_mutex_codes
                            .iter()
                            .any(|code| code == "unknown-callee-reentrancy")
                    })
                    .flat_map(|global| &global.unknown_calls)
                    .filter_map(|call| call.callsite)
                    .collect::<BTreeSet<_>>();
                let selected_principals = core
                    .opaque_callsites
                    .iter()
                    .filter(|callsite| selected_callsites.contains(&callsite.callsite))
                    .map(|callsite| callsite.principal.as_str())
                    .collect::<BTreeSet<_>>();
                callback_target_callsites.extend(
                    core.opaque_callsites
                        .iter()
                        .filter(|callsite| {
                            selected_principals.contains(callsite.principal.as_str())
                        })
                        .map(|callsite| callsite.key.clone()),
                );
                eprintln!(
                    "external-policy callback enrichment: d4_callsites={} principals={} targeted_callsites={}",
                    selected_callsites.len(),
                    selected_principals.len(),
                    callback_target_callsites.len(),
                );
                if !callback_target_callsites.is_empty() {
                    analysis = Analysis::run_with_external_policy_census(
                        &pir,
                        &opts,
                        Some(&callback_target_callsites),
                    )?;
                    (manifest, _) = pangs_clients::assemble_disposition_artifacts(
                        &analysis, &pir, &opts, &module, &repo_root, target,
                    )?;
                    d4 = pangs_clients::external_policy_d4_census(&analysis, &manifest);
                }
            }
            let effect_control = analysis
                .external_policy_census()
                .context("external-policy census inputs were not produced")?;
            let report = serde_json::json!({
                "module": module,
                "stage": opts.stage,
                "build_mode": opts.build_mode,
                "callback_closure_enrichment": callback_closure,
                "callback_target_callsites": callback_target_callsites.len(),
                "analysis_metrics": analysis.metrics(),
                "effect_control": effect_control,
                "d4": d4,
            });
            let rendered = serde_json::to_string_pretty(&report)?;
            if let Some(path) = out {
                fs::write(&path, format!("{rendered}\n"))
                    .with_context(|| format!("write {}", path.display()))?;
                eprintln!("external-policy census -> {}", path.display());
            } else {
                println!("{rendered}");
            }
        }
        Command::DumpPir { module, func } => {
            let mut pir = Pir::from_path(&module)?;
            if let Some(func_key) = func {
                pir.functions.retain(|f| f.key == func_key);
            }
            println!("{}", serde_json::to_string_pretty(&pir)?);
        }
        Command::DumpPag {
            module,
            func,
            build_mode,
            exports,
        } => {
            let pir = Pir::from_path(&module)?;
            let opts = PagOpts {
                build_mode: build_mode.into(),
                exports: read_exports(exports)?,
                ..PagOpts::default()
            };
            let pag = Pag::from_pir(&pir, &opts);
            let pag = if let Some(func_key) = func {
                pag.for_function(&func_key)
            } else {
                pag
            };
            println!("{}", serde_json::to_string_pretty(&pag)?);
        }
        Command::CheckPag {
            module,
            build_mode,
            exports,
        } => {
            let pir = Pir::from_path(&module)?;
            let opts = PagOpts {
                build_mode: build_mode.into(),
                exports: read_exports(exports)?,
                ..PagOpts::default()
            };
            let pag = Pag::from_pir(&pir, &opts);
            if let Err(issues) = pag.validate() {
                for issue in issues {
                    eprintln!("{issue}");
                }
                std::process::exit(3);
            }
            eprintln!(
                "check-pag: ok (nodes={}, edges={}, callsites={}, omega_seeds={})",
                pag.nodes.len(),
                pag.edges.len(),
                pag.callsites.len(),
                pag.omega_seeds.len()
            );
        }
        Command::AndersenAdmissionCensus {
            module,
            build_mode,
            exports,
        } => {
            let pir = Pir::from_path(&module)?;
            let build_mode = build_mode.into();
            let pag = Pag::from_pir(
                &pir,
                &PagOpts {
                    build_mode,
                    exports: read_exports(exports)?,
                    ..PagOpts::default()
                },
            );
            for record in pangs_solve::andersen_admission_census(&pir, &pag, build_mode) {
                println!("{}", serde_json::to_string(&record)?);
            }
        }
        Command::Report { dir } => {
            print!("{}", pangs_clients::report(&dir)?);
        }
        Command::Query { query } => match query {
            QueryCommand::Callees {
                module,
                build_mode,
                exports,
                mode,
            } => {
                let pir = Pir::from_path(&module)?;
                let pag_build_mode: PagBuildMode = build_mode.into();
                let opts = PagOpts {
                    build_mode: pag_build_mode,
                    exports: read_exports(exports)?,
                    ..PagOpts::default()
                };
                let pag = Pag::from_pir(&pir, &opts);
                let signatures = function_signatures(&pir);
                let run = match mode {
                    QueryModeArg::FieldInsensitive => {
                        let report =
                            pangs_solve::query_all_callees_field_insensitive_report_with_signatures(
                                &pag,
                                &signatures,
                            );
                        CalleeQueryRun {
                            by_callsite: report.by_callsite,
                            queries: report.queries,
                            ..CalleeQueryRun::default()
                        }
                    }
                    QueryModeArg::FieldSensitive => {
                        let report =
                            pangs_solve::query_all_callees_field_sensitive_report_with_signatures(
                                &pag,
                                &signatures,
                            );
                        CalleeQueryRun {
                            by_callsite: report.by_callsite,
                            queries: report.queries,
                            ..CalleeQueryRun::default()
                        }
                    }
                    QueryModeArg::FieldSensitiveFixpoint => {
                        let report = pangs_solve::query_all_callees_field_sensitive_fixpoint_report_with_signatures(
                            &pag,
                            &signatures,
                        );
                        let envelope = steens_targets_by_callsite(&pir, &pag, pag_build_mode);
                        let fallback = report.fallback_for_truncated_queries(&envelope);
                        let fallback_callsites = fallback.fallback_callsite_count();
                        let fallback_targets = fallback.fallback_target_count();
                        CalleeQueryRun {
                            by_callsite: fallback.by_callsite,
                            raw_by_callsite: Some(report.by_callsite),
                            fallback_by_callsite: fallback.fallback_by_callsite,
                            fallback_callsites,
                            fallback_targets,
                            truncated_functions: fallback.truncated_functions,
                            queries: report.queries,
                            rounds: Some(report.rounds),
                        }
                    }
                };
                let rounds_json = run.rounds.as_ref().map(|rounds| {
                    rounds
                        .iter()
                        .map(|round| {
                            serde_json::json!({
                                "round": round.round,
                                "queries_run": round.queries_run,
                                "new_targets": round.new_targets,
                                "new_interproc_edges": round.new_interproc_edges,
                                "dependency_records": round.dependency_records,
                            })
                        })
                        .collect::<Vec<_>>()
                });
                let queries_json = run
                    .queries
                    .iter()
                    .map(|query| {
                        serde_json::json!({
                            "function": query.function,
                            "source": query.source.map(|id| id.0),
                            "callsites": query.callsites,
                            "dependencies": query.dependencies,
                            "return_dependencies": query.return_dependencies,
                            "visited_states": query.metrics.visited_states,
                            "max_worklist": query.metrics.max_worklist,
                            "truncated": query.metrics.truncated,
                        })
                    })
                    .collect::<Vec<_>>();
                let mut histogram = [0usize; 4];
                for query in &run.queries {
                    match query.metrics.visited_states {
                        value if value <= knobs::QUERY_HISTOGRAM_SMALL_MAX => histogram[0] += 1,
                        value if value <= knobs::QUERY_HISTOGRAM_MEDIUM_MAX => histogram[1] += 1,
                        value if value <= knobs::QUERY_HISTOGRAM_LARGE_MAX => histogram[2] += 1,
                        _ => histogram[3] += 1,
                    }
                }
                let max_visited_states = run
                    .queries
                    .iter()
                    .map(|query| query.metrics.visited_states)
                    .max()
                    .unwrap_or(0);
                let truncated_queries = run
                    .queries
                    .iter()
                    .filter(|query| query.metrics.truncated)
                    .count();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "kind": "callees",
                        "experimental": "tier_e_prototype",
                        "used_by_lite_analyze": false,
                        "mode": mode.label(),
                        "by_callsite": run.by_callsite,
                        "raw_by_callsite": run.raw_by_callsite,
                        "fallback_by_callsite": run.fallback_by_callsite,
                        "fallback_callsites": run.fallback_callsites,
                        "fallback_targets": run.fallback_targets,
                        "truncated_functions": run.truncated_functions,
                        "queries": queries_json,
                        "rounds": rounds_json,
                        "visit_histogram": {
                            "le_10": histogram[0],
                            "le_100": histogram[1],
                            "le_1000": histogram[2],
                            "gt_1000": histogram[3],
                        },
                        "max_visited_states": max_visited_states,
                        "truncated_queries": truncated_queries,
                    }))?
                );
            }
        },
        Command::IcallCensus {
            module,
            out,
            summary,
            stage,
            build_mode,
            exports,
            partition_budget,
        } => {
            let pir = Pir::from_path(&module)?;
            let opts = Opts {
                stage: stage.into(),
                build_mode: build_mode.into(),
                exports: read_exports(exports)?,
                partition_budget,
                ..Opts::default()
            };
            let provenance = pangs_api::icall_census::classify_icalls(&pir);
            let analysis = Analysis::run(&pir, &opts)?;

            // Rows join positionally with the indirect entries of the callsite table; both
            // are built in module-function order then body order. Verify rather than trust:
            // a mismatch means one of the two walks changed and every row after it is
            // attributed to the wrong callsite.
            let indirect: Vec<_> = analysis
                .callsites()
                .iter()
                .enumerate()
                .filter(|(_, cs)| cs.kind == pangs_api::CallKind::Indirect)
                .collect();
            anyhow::ensure!(
                indirect.len() == provenance.len(),
                "icall census: {} classified operands vs {} indirect callsites — the PIR walk \
                 and the callsite table have diverged",
                provenance.len(),
                indirect.len()
            );

            let census = analysis.icall_fsa_census();
            let mut lines = Vec::new();
            for ((index, callsite), row) in indirect.iter().zip(&provenance) {
                let caller = &analysis.functions()[callsite.caller].key;
                anyhow::ensure!(
                    caller == &row.caller,
                    "icall census: callsite {} is in {caller} but the classified operand is in \
                     {} — positional join is invalid",
                    callsite.key,
                    row.caller
                );
                let fsa = census
                    .get(&pangs_api::CallsiteId(*index as u32))
                    .copied()
                    .unwrap_or_default();
                lines.push(serde_json::json!({
                    "module": module.file_name().and_then(|n| n.to_str()).unwrap_or_default(),
                    "callsite": callsite.key,
                    "caller": row.caller,
                    "bucket": row.bucket,
                    "labels": row.labels.iter().map(|l| l.name()).collect::<Vec<_>>(),
                    "truncated": row.truncated,
                    "fsa_envelope": row.fsa_envelope,
                    "pointer_targets_prefsa": fsa.prefsa_targets,
                    "fsa_rejected_targets": fsa.fsa_rejected_targets,
                    "targets": fsa.kept_targets,
                    "unknown_callee": fsa.unknown_callee,
                    "fallback": fsa.fallback,
                }));
            }
            // Newline-terminated JSONL, and genuinely empty for a module with no indirect
            // calls — a lone "\n" would be an unparseable record, not an empty file.
            let body = lines
                .iter()
                .map(|line| format!("{line}\n"))
                .collect::<String>();
            match out {
                Some(path) => {
                    fs::write(&path, &body)
                        .with_context(|| format!("writing {}", path.display()))?;
                    eprintln!("icall census: {} rows -> {}", lines.len(), path.display());
                }
                None => print!("{body}"),
            }
            if let Some(path) = summary {
                let metrics = analysis.metrics();
                let report = serde_json::json!({
                    "module": module.file_name().and_then(|n| n.to_str()).unwrap_or_default(),
                    "stage": format!("{:?}", opts.stage),
                    "build_mode": format!("{:?}", opts.build_mode),
                    "functions": analysis.functions().len(),
                    "callsites": analysis.callsites().len(),
                    "indirect_callsites": lines.len(),
                    "address_taken": analysis
                        .functions()
                        .iter()
                        .filter(|func| func.address_taken)
                        .count(),
                    "icalls_simple": metrics.icalls_simple,
                    "icalls_b1_initval": metrics.icalls_b1_initval,
                    "icalls_b2_simple": metrics.icalls_b2_simple,
                    "icalls_andersen": metrics.icalls_andersen,
                    "icalls_steens": metrics.icalls_steens,
                    "icalls_fsa": metrics.icalls_fsa,
                    "icalls_unknown": metrics.icalls_unknown,
                    "confined_functions": metrics.confined_functions,
                    "steens_fsa_compatible_pairs": metrics.steens_fsa_compatible_pairs,
                    "steens_fsa_rejected_pairs": metrics.steens_fsa_rejected_pairs,
                    "oversize_fallbacks": metrics.oversize_fallbacks,
                    "analysis_wall_us": metrics.analysis_wall_us,
                });
                fs::write(&path, format!("{report}\n"))
                    .with_context(|| format!("writing {}", path.display()))?;
            }
        }
        Command::Differential {
            module,
            build_mode,
            exports,
            partition_budget,
        } => {
            let pir = Pir::from_path(&module)?;
            let opts = Opts {
                build_mode: build_mode.into(),
                exports: read_exports(exports)?,
                partition_budget,
                ..Opts::default()
            };
            let report = pangs_api::run_differential(&pir, &opts)?;
            for note in &report.notes {
                eprintln!("differential note: {note}");
            }
            if report.is_clean() {
                eprintln!("differential: ok (andersen ⊆ steens ⊆ conservative; coverage sound)");
            } else {
                for violation in &report.violations {
                    eprintln!("differential: {violation}");
                }
                std::process::exit(3);
            }
        }
        Command::M2Ablation {
            module,
            stage,
            build_mode,
            exports,
            partition_budget,
        } => {
            let pir = Pir::from_path(&module)?;
            let opts = Opts {
                stage: stage.into(),
                build_mode: build_mode.into(),
                exports: read_exports(exports)?,
                partition_budget,
                ..Opts::default()
            };
            let report = pangs_api::run_m2_ablation(&pir, &opts)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Instrument { module, out } => {
            let count = pangs_pir::instrument_icalls(&module, &out)?;
            eprintln!("instrument: {count} indirect call(s) → {}", out.display());
        }
        Command::CheckTraces { dir, trace } => {
            let report = pangs_clients::check_traces(&dir, &trace)?;
            eprintln!(
                "check-traces: {} checked, {} unresolved",
                report.checked, report.unresolved
            );
            if !report.is_clean() {
                for violation in &report.violations {
                    eprintln!("check-traces: {violation}");
                }
                std::process::exit(3);
            }
            eprintln!("check-traces: ok (all observed pairs in analysis edge set)");
        }
        Command::Cc2json {
            module,
            json_out,
            stage,
            entrypoints,
            internalize_globals,
            partition_budget,
        } => {
            let pir = Pir::from_path(&module)?;
            let opts = pangs_clients::Cc2jsonOpts {
                stage: stage.into(),
                build_mode: entrypoints.into(),
                internalize_globals,
                partition_budget,
            };
            let json = pangs_clients::run_cc2json(&pir, &module, &opts)?;
            fs::write(&json_out, &json).with_context(|| format!("write {}", json_out.display()))?;
            eprintln!("cc2json: wrote {}", json_out.display());
        }
    }
    Ok(())
}

impl From<BuildModeArg> for PagBuildMode {
    fn from(value: BuildModeArg) -> Self {
        match value {
            BuildModeArg::Library => PagBuildMode::Library,
            BuildModeArg::Executable => PagBuildMode::Executable,
        }
    }
}

#[derive(Debug, Default)]
struct CalleeQueryRun {
    by_callsite: BTreeMap<String, BTreeSet<String>>,
    raw_by_callsite: Option<BTreeMap<String, BTreeSet<String>>>,
    fallback_by_callsite: BTreeMap<String, BTreeSet<String>>,
    fallback_callsites: usize,
    fallback_targets: usize,
    truncated_functions: BTreeSet<String>,
    queries: Vec<pangs_solve::CflCalleeQuery>,
    rounds: Option<Vec<pangs_solve::CflFixpointRound>>,
}

fn read_exports(path: Option<PathBuf>) -> Result<BTreeSet<String>> {
    let Some(path) = path else {
        return Ok(BTreeSet::new());
    };
    let data = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    Ok(data
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect())
}

fn read_registry_config(path: Option<&std::path::Path>) -> Result<Vec<RegistryApi>> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let bytes =
        fs::read(path).with_context(|| format!("read registry config {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parse registry config {} as a JSON array", path.display()))
}

fn load_disposition_overrides(
    path: Option<&std::path::Path>,
) -> Result<(Option<pangs_dispose::Overrides>, Option<String>)> {
    let Some(path) = path else {
        return Ok((None, None));
    };
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let text = std::str::from_utf8(&bytes).context("override file is not UTF-8")?;
    let overrides = parse_overrides(text)?;
    let sha = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok((Some(overrides), Some(sha)))
}

fn function_signatures(pir: &Pir) -> BTreeMap<String, pangs_pir::Signature> {
    pir.functions
        .iter()
        .map(|func| (func.key.clone(), func.sig.clone()))
        .collect()
}

fn steens_targets_by_callsite(
    pir: &Pir,
    pag: &Pag,
    build_mode: PagBuildMode,
) -> BTreeMap<String, BTreeSet<String>> {
    pangs_solve::solve_steensgaard(pir, pag, build_mode)
        .indirect_calls
        .into_iter()
        .map(|resolution| {
            (
                resolution.callsite_key,
                resolution.targets.into_iter().collect(),
            )
        })
        .collect()
}
