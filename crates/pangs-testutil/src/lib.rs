use anyhow::Result;
use pangs_api::{Analysis, Opts};
use pangs_pir::Pir;

pub fn analyze_fixture(path: &str) -> Result<Analysis> {
    let pir = Pir::from_path(path)?;
    Ok(Analysis::run(&pir, &Opts::default())?)
}
