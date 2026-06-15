use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use pangs_api::{Analysis, BuildMode, Opts, Stage};
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
        #[arg(long)]
        validate: bool,
    },
    Stats {
        module: PathBuf,
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
    /// Run conservative→steens→andersen and check the narrowing/monotonicity ledger.
    Differential {
        module: PathBuf,
        #[arg(long, default_value = "library")]
        build_mode: BuildModeArg,
        #[arg(long)]
        exports: Option<PathBuf>,
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
            validate,
        } => {
            let pipeline_started = Instant::now();
            let pir = Pir::from_path(&module)?;
            let opts = Opts {
                stage: stage.into(),
                build_mode: build_mode.into(),
                exports: read_exports(exports)?,
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
        Command::Differential {
            module,
            build_mode,
            exports,
        } => {
            let pir = Pir::from_path(&module)?;
            let opts = Opts {
                build_mode: build_mode.into(),
                exports: read_exports(exports)?,
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
