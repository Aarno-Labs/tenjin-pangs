use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use pangs_api::{Analysis, BuildMode, Opts, Stage};
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
        #[arg(long, default_value = "conservative")]
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
    },
    CheckPag {
        module: PathBuf,
    },
    Report {
        dir: PathBuf,
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
            pangs_clients::export_analysis(&analysis, &opts, &module, &out, validate)?;
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
        Command::DumpPag { module, func } => {
            let _pir = Pir::from_path(&module)?;
            println!(
                "{}",
                serde_json::json!({
                    "status": "pag construction starts in M1.3",
                    "func": func
                })
            );
        }
        Command::CheckPag { module } => {
            let _pir = Pir::from_path(&module)?;
            eprintln!("check-pag: no PAG invariants enabled before M1.3");
        }
        Command::Report { dir } => {
            print!("{}", pangs_clients::report(&dir)?);
        }
    }
    Ok(())
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
