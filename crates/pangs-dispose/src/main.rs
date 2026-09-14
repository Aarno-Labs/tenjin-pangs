use std::path::{Path, PathBuf};

use clap::{Parser, ValueEnum};
use pangs_dispose::{
    apply_policy, config_with_overrides, parse_overrides, read_ledger, write_artifact_pair,
    write_artifact_pair_to, DisposeError, Overrides,
};
use pangs_manifest::{marker_artifacts, read_manifest, DisposeMode, Error as ManifestError};
use sha2::{Digest, Sha256};

#[derive(Debug, Parser)]
#[command(name = "pangs-dispose", about = "Assign per-global PANGS dispositions")]
struct Cli {
    /// Analysis export directory or pangs-manifest.json path.
    input: PathBuf,
    /// Override the sibling pangs-audit.json path.
    #[arg(long)]
    audit: Option<PathBuf>,
    /// Write the pair elsewhere instead of replacing it in place.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Narrow an executable analysis to library policy.
    #[arg(long)]
    mode: Option<ModeArg>,
    /// Suppress sibling pangs-overrides.toml discovery.
    #[arg(long)]
    no_overrides: bool,
    /// Use this override file instead of sibling auto-discovery.
    #[arg(long, conflicts_with = "no_overrides")]
    overrides: Option<PathBuf>,
    /// Emit pangs_markers.h and pangs_markers.c for the resulting dispositions.
    #[arg(long)]
    emit_markers: Option<PathBuf>,
}

fn main() {
    let code = match run(Cli::parse()) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{error}");
            if matches!(error, DisposeError::OverrideProblems) {
                2
            } else if matches!(
                error,
                DisposeError::Manifest(ManifestError::UnsupportedSchema { .. })
            ) {
                3
            } else {
                1
            }
        }
    };
    std::process::exit(code);
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ModeArg {
    Application,
    Library,
}

impl From<ModeArg> for DisposeMode {
    fn from(value: ModeArg) -> Self {
        match value {
            ModeArg::Application => Self::Application,
            ModeArg::Library => Self::Library,
        }
    }
}

fn run(cli: Cli) -> Result<(), DisposeError> {
    let manifest_path = if cli.input.is_dir() {
        cli.input.join("pangs-manifest.json")
    } else {
        cli.input.clone()
    };
    let input_dir = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let discovered_overrides = input_dir.join("pangs-overrides.toml");
    let overrides_path = if cli.no_overrides {
        None
    } else if let Some(path) = cli.overrides {
        if !path.exists() {
            return Err(DisposeError::InvalidOverrides(format!(
                "explicit override file does not exist: {}",
                path.display()
            )));
        }
        Some(path)
    } else {
        discovered_overrides
            .exists()
            .then_some(discovered_overrides)
    }
    .map(std::fs::canonicalize)
    .transpose()?;
    let (overrides, overrides_sha256) = read_overrides(overrides_path.as_deref())?;
    let audit_path = cli
        .audit
        .unwrap_or_else(|| input_dir.join("pangs-audit.json"));
    let mut manifest = read_manifest(&manifest_path)?;
    let mut ledger = read_ledger(&audit_path)?;
    let analysis_mode = analysis_mode(&manifest.run.analysis.opts)?;
    let mode = match cli.mode.map(DisposeMode::from) {
        None => analysis_mode,
        Some(DisposeMode::Library) => DisposeMode::Library,
        Some(DisposeMode::Application) if analysis_mode == DisposeMode::Application => {
            DisposeMode::Application
        }
        Some(DisposeMode::Application) => {
            return Err(DisposeError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cannot widen a library analysis to application disposition mode",
            )))
        }
    };
    let config = config_with_overrides(mode, overrides.as_ref())?;
    let outcome = apply_policy(
        &mut manifest,
        &mut ledger,
        &config,
        overrides.as_ref(),
        overrides_path.map(|path| path.display().to_string()),
        overrides_sha256,
    )?;
    manifest.validate()?;
    if let Some(output_dir) = cli.out.as_deref() {
        write_artifact_pair(output_dir, &manifest, &ledger)?;
    } else {
        write_artifact_pair_to(&manifest_path, &audit_path, &manifest, &ledger)?;
    }
    if let Some(marker_dir) = cli.emit_markers {
        std::fs::create_dir_all(&marker_dir)?;
        let (header, source) = marker_artifacts(&manifest)?;
        std::fs::write(marker_dir.join("pangs_markers.h"), header)?;
        std::fs::write(marker_dir.join("pangs_markers.c"), source)?;
    }
    if outcome.override_problems {
        return Err(DisposeError::OverrideProblems);
    }
    Ok(())
}

fn read_overrides(
    path: Option<&Path>,
) -> Result<(Option<Overrides>, Option<String>), DisposeError> {
    let Some(path) = path else {
        return Ok((None, None));
    };
    let bytes = std::fs::read(path)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| DisposeError::InvalidOverrides(error.to_string()))?;
    let overrides = parse_overrides(text)?;
    let sha = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok((Some(overrides), Some(sha)))
}

fn analysis_mode(opts: &serde_json::Value) -> Result<DisposeMode, DisposeError> {
    match opts.get("build_mode").and_then(serde_json::Value::as_str) {
        Some("executable") => Ok(DisposeMode::Application),
        Some("library") => Ok(DisposeMode::Library),
        other => Err(DisposeError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("run.analysis.opts.build_mode is missing or invalid: {other:?}"),
        ))),
    }
}
