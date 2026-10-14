use std::fs;

use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use tempfile::tempdir;

#[test]
fn compatible_trace_exits_zero() {
    cargo_bin_cmd!("effect-pair")
        .args([
            "--baseline",
            "examples/baseline.jsonl",
            "--candidate",
            "examples/candidate-ok.jsonl",
            "--policy",
            "examples/policy.toml",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("verdict: compatible"));
}

#[test]
fn drift_exits_two_and_emits_json_findings() {
    cargo_bin_cmd!("effect-pair")
        .args([
            "--baseline",
            "examples/baseline.jsonl",
            "--candidate",
            "examples/candidate-drift.jsonl",
            "--policy",
            "examples/policy.toml",
            "--format",
            "json",
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("EP003_ALLOWED_INCREASE"))
        .stdout(predicate::str::contains("process_start"));
}

#[test]
fn malformed_trace_is_an_operational_error() {
    let directory = tempdir().unwrap();
    let trace = directory.path().join("broken.jsonl");
    fs::write(&trace, "{}\n").unwrap();
    cargo_bin_cmd!("effect-pair")
        .args([
            "--baseline",
            trace.to_str().unwrap(),
            "--candidate",
            "examples/candidate-ok.jsonl",
            "--policy",
            "examples/policy.toml",
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("invalid baseline trace"));
}

#[test]
fn report_can_be_written_to_a_file() {
    let directory = tempdir().unwrap();
    let output = directory.path().join("report.json");
    cargo_bin_cmd!("effect-pair")
        .args([
            "--baseline",
            "examples/baseline.jsonl",
            "--candidate",
            "examples/candidate-ok.jsonl",
            "--policy",
            "examples/policy.toml",
            "--format",
            "json",
            "--output",
            output.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
    assert_eq!(report["verdict"], "compatible");
}
