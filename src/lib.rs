//! Compare baseline and candidate sandbox side-effect traces under explicit budgets.

mod compare;
mod input;
mod model;
mod policy;

use std::io;
use std::path::{Path, PathBuf};

pub use compare::{BucketReport, Delta, Finding, Metrics, Report, Verdict};
pub use model::{EffectEvent, Outcome};
pub use policy::{Limits, Policy, Rule};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CompareError {
    #[error("baseline and candidate cannot both use stdin")]
    BothTracesUseStdin,
    #[error("failed to read {kind} trace {path}: {source}")]
    ReadTrace {
        kind: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    #[error("{kind} trace {path} exceeds the 64 MiB input limit")]
    TraceTooLarge { kind: &'static str, path: PathBuf },
    #[error("invalid {kind} trace {path} at line {line}: {message}")]
    InvalidTrace {
        kind: &'static str,
        path: PathBuf,
        line: usize,
        message: String,
    },
    #[error("{kind} trace {path} exceeds the 1,000,000-record limit")]
    TooManyRecords { kind: &'static str, path: PathBuf },
    #[error("failed to read policy {path}: {source}")]
    ReadPolicy { path: PathBuf, source: io::Error },
    #[error("invalid policy {path}: {message}")]
    InvalidPolicy { path: PathBuf, message: String },
    #[error("failed to serialize report: {source}")]
    SerializeReport { source: serde_json::Error },
    #[error("failed to write report {path}: {source}")]
    WriteReport { path: PathBuf, source: io::Error },
}

pub fn compare_paths(
    baseline_path: &Path,
    candidate_path: &Path,
    policy_path: &Path,
) -> Result<Report, CompareError> {
    let policy = policy::load(policy_path)?;
    let baseline = input::load_trace(baseline_path, "baseline")?;
    let candidate = input::load_trace(candidate_path, "candidate")?;
    Ok(compare::compare(&baseline, &candidate, &policy))
}
