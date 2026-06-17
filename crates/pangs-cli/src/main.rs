use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use pangs_api::{Analysis, BuildMode, FuncId, Opts, Stage};
use pangs_pag::{BuildMode as PagBuildMode, Pag, PagOpts};
use pangs_pir::Pir;

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
        #[arg(long, default_value = "andersen")]
        stage: StageArg,
        #[arg(long, default_value = "library")]
        build_mode: BuildModeArg,
        #[arg(long)]
        exports: Option<PathBuf>,
        #[arg(long, default_value_t = 1_000, hide = true)]
        partition_budget: u64,
        #[arg(long)]
        validate: bool,
    },
    Stats {
        module: PathBuf,
    },
    /// Run analysis and print mod/ref row counts without writing exports.
    ModrefSummary {
        module: PathBuf,
        #[arg(long, default_value = "andersen")]
        stage: StageArg,
        #[arg(long, default_value = "library")]
        build_mode: BuildModeArg,
        #[arg(long)]
        exports: Option<PathBuf>,
        #[arg(long, default_value_t = 1_000, hide = true)]
        partition_budget: u64,
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
        #[arg(long, default_value = "library")]
        build_mode: BuildModeArg,
        #[arg(long)]
        exports: Option<PathBuf>,
    },
    CheckPag {
        module: PathBuf,
        #[arg(long, default_value = "library")]
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
        #[arg(long, default_value = "library")]
        build_mode: BuildModeArg,
        #[arg(long)]
        exports: Option<PathBuf>,
        #[arg(long, default_value_t = 1_000, hide = true)]
        partition_budget: u64,
    },
    /// Run the M2.7 pre-analysis ablation: M1 baseline, B2 only, B1 only, and both.
    M2Ablation {
        module: PathBuf,
        #[arg(long, default_value = "andersen")]
        stage: StageArg,
        #[arg(long, default_value = "library")]
        build_mode: BuildModeArg,
        #[arg(long)]
        exports: Option<PathBuf>,
        #[arg(long, default_value_t = 1_000, hide = true)]
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
}

#[derive(Debug, Subcommand)]
enum QueryCommand {
    /// Run the experimental tier-E M3 callee query prototype.
    Callees {
        module: PathBuf,
        #[arg(long, default_value = "library")]
        build_mode: BuildModeArg,
        #[arg(long)]
        exports: Option<PathBuf>,
        #[arg(long, default_value = "field-sensitive")]
        mode: QueryModeArg,
    },
}

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
        } => {
            let pipeline_started = Instant::now();
            let pir = Pir::from_path(&module)?;
            let opts = Opts {
                stage: stage.into(),
                build_mode: build_mode.into(),
                exports: read_exports(exports)?,
                partition_budget,
                ..Opts::default()
            };
            eprintln!(
                "pangs analyze stage={:?} build_mode={:?}",
                opts.stage, opts.build_mode
            );
            let analysis = Analysis::run(&pir, &opts)?;
            pangs_clients::export_analysis(
                &analysis,
                &opts,
                &module,
                &out,
                validate,
                pipeline_started,
            )?;
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
            let transitive_rows: usize = (0..analysis.functions().len())
                .map(|idx| analysis.modref(FuncId(idx as u32)).count())
                .sum();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "functions": analysis.functions().len(),
                    "local_modref_rows": analysis.modrefs().len(),
                    "transitive_modref_rows": transitive_rows,
                    "metrics": analysis.metrics(),
                }))?
            );
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
                        0..=10 => histogram[0] += 1,
                        11..=100 => histogram[1] += 1,
                        101..=1_000 => histogram[2] += 1,
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
