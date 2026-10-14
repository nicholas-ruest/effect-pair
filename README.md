# effect-pair

`effect-pair` is a fail-closed Rust CLI for comparing two sandbox side-effect traces. It turns paired baseline/candidate runs into a deterministic CI decision: newly allowed effects, missing effects, failures, byte growth, and latency growth must stay inside explicit TOML budgets.

It is useful when a runtime, policy, dependency, model, or sandbox changes and “the command still exits zero” is not enough evidence that behavior stayed inside its envelope.

## What works

- Strict, versioned JSONL events for filesystem, process, network, environment, or custom effect kinds.
- Multiset comparison by `kind + target + operation + stable attributes`.
- Volatile attribute removal (for example `pid` or a trace ID).
- Fail-closed default budgets plus ordered glob rules with aggregate budgets.
- Detection of new, missing, newly allowed, newly failed, larger, and slower effects.
- Deterministic text and JSON reports with SHA-256 input receipts and stable finding codes.
- CI exit codes: `0` compatible, `2` policy difference, `1` invalid input or operational error.
- Bounded input: 64 MiB, 1,000,000 records per trace, and `10^12` per numeric record field.

`effect-pair` never executes the workload and does not grant permissions. It compares declared observations produced by a tracer or sandbox.

## Install

Rust 1.85 or newer is required.

```bash
cargo install --git https://github.com/nicholas-ruest/effect-pair
```

Or build from a clone:

```bash
cargo build --release
```

## Quick start

Compare the included baseline with an acceptable candidate:

```bash
cargo run -- \
  --baseline examples/baseline.jsonl \
  --candidate examples/candidate-ok.jsonl \
  --policy examples/policy.toml
```

Compare a candidate that newly allows metadata access and spawns `curl`:

```bash
cargo run -- \
  --baseline examples/baseline.jsonl \
  --candidate examples/candidate-drift.jsonl \
  --policy examples/policy.toml \
  --format json
echo $? # 2
```

Either trace can be read from stdin with `-`, but not both. Use `--output report.json` to write the report without mixing it with stdout.

## Trace format

Each non-blank JSONL line is one event or an already aggregated group:

```json
{"schema_version":1,"kind":"network_connect","target":"api.example.com:443","operation":"connect","outcome":"allowed","count":1,"bytes":0,"duration_ms":12,"attributes":{"pid":"4101","protocol":"tcp"}}
```

Required fields are `schema_version`, `kind`, `target`, `operation`, and `outcome`. Outcomes are `allowed`, `blocked`, or `failed`. `count` defaults to 1; byte and duration totals default to 0. Unknown fields and blank JSONL records are rejected.

`bytes` and `duration_ms` are aggregate values for the record, not per-event averages. `count`, `bytes`, and `duration_ms` are capped at `10^12` per record so aggregate arithmetic cannot overflow within the record limit.

## Policy format

The default bucket is strict. Rules are checked in file order; the first match owns an identity. A rule budget is aggregated across every changed identity it owns, preventing many individually small changes from bypassing the limit.

```toml
schema_version = 1
ignore_attributes = ["pid", "trace_id"]

[defaults]
max_new_events = 0
max_missing_events = 0
max_allowed_increase = 0
max_failed_increase = 0
max_bytes_increase = 0
max_duration_increase_ms = 0

[[rules]]
name = "approved-api-latency"
kind = "network_connect"
target_glob = "api.example.com:443"
operation = "connect"

[rules.limits]
max_duration_increase_ms = 10
```

Positive deltas are summed per identity before they are summed into a bucket. This means a missing effect cannot cancel a new effect elsewhere, and a faster call cannot hide a slower call.

## Verification

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

## Limitations

- The quality and completeness of the comparison depend on the upstream tracer.
- Targets and stable attributes must already be normalized; only exact attribute keys can be ignored.
- Rules use first-match ordering, so broad rules should follow narrow ones.
- Budgets compare positive aggregate deltas; they do not model event ordering, causality, concurrency, or statistical variance.
- SHA-256 receipts identify the exact trace bytes, but reports are not signed.

## License

MIT. See [LICENSE](LICENSE).
