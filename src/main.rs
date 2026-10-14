use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use effect_pair::{CompareError, compare_paths};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// Baseline JSONL trace path, or - for stdin.
    #[arg(long)]
    baseline: PathBuf,
    /// Candidate JSONL trace path, or - for stdin.
    #[arg(long)]
    candidate: PathBuf,
    /// TOML comparison policy.
    #[arg(long)]
    policy: PathBuf,
    /// Report format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
    /// Write the report to a file instead of stdout.
    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("effect-pair: {error}");
            ExitCode::from(1)
        }
    }
}

fn run(args: Args) -> Result<ExitCode, CompareError> {
    if args.baseline.as_os_str() == "-" && args.candidate.as_os_str() == "-" {
        return Err(CompareError::BothTracesUseStdin);
    }
    let report = compare_paths(&args.baseline, &args.candidate, &args.policy)?;
    let rendered = match args.format {
        OutputFormat::Text => report.render_text(),
        OutputFormat::Json => serde_json::to_string_pretty(&report)
            .map_err(|source| CompareError::SerializeReport { source })?,
    };
    if let Some(path) = args.output {
        fs::write(&path, format!("{rendered}\n"))
            .map_err(|source| CompareError::WriteReport { path, source })?;
    } else {
        println!("{rendered}");
    }
    Ok(if report.is_compatible() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}
