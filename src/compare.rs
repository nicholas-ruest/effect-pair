use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::input::Trace;
use crate::model::Outcome;
use crate::policy::{CompiledPolicy, Limits};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct Identity {
    pub kind: String,
    pub target: String,
    pub operation: String,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, Default)]
struct Stats {
    total: u64,
    allowed: u64,
    failed: u64,
    bytes: u64,
    duration_ms: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Metrics {
    pub new_events: u64,
    pub missing_events: u64,
    pub allowed_increase: u64,
    pub failed_increase: u64,
    pub bytes_increase: u64,
    pub duration_increase_ms: u64,
}

impl Metrics {
    fn add(&mut self, other: Self) {
        self.new_events = self.new_events.saturating_add(other.new_events);
        self.missing_events = self.missing_events.saturating_add(other.missing_events);
        self.allowed_increase = self.allowed_increase.saturating_add(other.allowed_increase);
        self.failed_increase = self.failed_increase.saturating_add(other.failed_increase);
        self.bytes_increase = self.bytes_increase.saturating_add(other.bytes_increase);
        self.duration_increase_ms = self
            .duration_increase_ms
            .saturating_add(other.duration_increase_ms);
    }

    fn is_zero(self) -> bool {
        self == Self::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Delta {
    pub bucket: String,
    pub kind: String,
    pub target: String,
    pub operation: String,
    pub attributes: BTreeMap<String, String>,
    pub metrics: Metrics,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BucketReport {
    pub name: String,
    pub metrics: Metrics,
    pub limits: Limits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub code: String,
    pub bucket: String,
    pub actual: u64,
    pub limit: u64,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Compatible,
    Different,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub verdict: Verdict,
    pub baseline_sha256: String,
    pub candidate_sha256: String,
    pub baseline_records: usize,
    pub candidate_records: usize,
    pub buckets: Vec<BucketReport>,
    pub deltas: Vec<Delta>,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn is_compatible(&self) -> bool {
        self.verdict == Verdict::Compatible
    }

    pub fn render_text(&self) -> String {
        let mut lines = vec![
            format!("verdict: {:?}", self.verdict).to_ascii_lowercase(),
            format!("baseline sha256: {}", self.baseline_sha256),
            format!("candidate sha256: {}", self.candidate_sha256),
            format!(
                "records: baseline={} candidate={}",
                self.baseline_records, self.candidate_records
            ),
            format!(
                "changed identities: {} | findings: {}",
                self.deltas.len(),
                self.findings.len()
            ),
        ];
        for finding in &self.findings {
            lines.push(format!(
                "{} [{}] actual={} limit={} — {}",
                finding.code, finding.bucket, finding.actual, finding.limit, finding.message
            ));
        }
        lines.join("\n")
    }
}

pub(crate) fn compare(baseline: &Trace, candidate: &Trace, policy: &CompiledPolicy) -> Report {
    let baseline_stats = aggregate(baseline, policy);
    let candidate_stats = aggregate(candidate, policy);
    let identities: BTreeSet<_> = baseline_stats
        .keys()
        .chain(candidate_stats.keys())
        .cloned()
        .collect();

    let mut bucket_metrics: BTreeMap<String, (Metrics, Limits)> = BTreeMap::new();
    let mut deltas = Vec::new();
    for identity in identities {
        let baseline_value = baseline_stats.get(&identity).copied().unwrap_or_default();
        let candidate_value = candidate_stats.get(&identity).copied().unwrap_or_default();
        let metrics = calculate_metrics(baseline_value, candidate_value);
        if metrics.is_zero() {
            continue;
        }
        let (bucket_name, limits) = policy.bucket(&identity);
        bucket_metrics
            .entry(bucket_name.to_owned())
            .and_modify(|(total, _)| total.add(metrics))
            .or_insert((metrics, limits));
        deltas.push(Delta {
            bucket: bucket_name.to_owned(),
            kind: identity.kind,
            target: identity.target,
            operation: identity.operation,
            attributes: identity.attributes,
            metrics,
        });
    }

    let buckets: Vec<_> = bucket_metrics
        .into_iter()
        .map(|(name, (metrics, limits))| BucketReport {
            name,
            metrics,
            limits,
        })
        .collect();
    let findings = build_findings(&buckets);
    let verdict = if findings.is_empty() {
        Verdict::Compatible
    } else {
        Verdict::Different
    };

    Report {
        schema_version: 1,
        verdict,
        baseline_sha256: baseline.digest.clone(),
        candidate_sha256: candidate.digest.clone(),
        baseline_records: baseline.events.len(),
        candidate_records: candidate.events.len(),
        buckets,
        deltas,
        findings,
    }
}

fn aggregate(trace: &Trace, policy: &CompiledPolicy) -> BTreeMap<Identity, Stats> {
    let mut result: BTreeMap<Identity, Stats> = BTreeMap::new();
    for event in &trace.events {
        let attributes = event
            .attributes
            .iter()
            .filter(|(key, _)| !policy.policy.ignore_attributes.contains(*key))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let identity = Identity {
            kind: event.kind.clone(),
            target: event.target.clone(),
            operation: event.operation.clone(),
            attributes,
        };
        let stats = result.entry(identity).or_default();
        stats.total = stats.total.saturating_add(event.count);
        match event.outcome {
            Outcome::Allowed => stats.allowed = stats.allowed.saturating_add(event.count),
            Outcome::Failed => stats.failed = stats.failed.saturating_add(event.count),
            Outcome::Blocked => {}
        }
        stats.bytes = stats.bytes.saturating_add(event.bytes);
        stats.duration_ms = stats.duration_ms.saturating_add(event.duration_ms);
    }
    result
}

fn calculate_metrics(baseline: Stats, candidate: Stats) -> Metrics {
    Metrics {
        new_events: candidate.total.saturating_sub(baseline.total),
        missing_events: baseline.total.saturating_sub(candidate.total),
        allowed_increase: candidate.allowed.saturating_sub(baseline.allowed),
        failed_increase: candidate.failed.saturating_sub(baseline.failed),
        bytes_increase: candidate.bytes.saturating_sub(baseline.bytes),
        duration_increase_ms: candidate.duration_ms.saturating_sub(baseline.duration_ms),
    }
}

type Check = (
    &'static str,
    fn(Metrics) -> u64,
    fn(Limits) -> u64,
    &'static str,
);

fn build_findings(buckets: &[BucketReport]) -> Vec<Finding> {
    let checks: [Check; 6] = [
        (
            "EP001_NEW_EVENTS",
            |v| v.new_events,
            |v| v.max_new_events,
            "candidate introduced events",
        ),
        (
            "EP002_MISSING_EVENTS",
            |v| v.missing_events,
            |v| v.max_missing_events,
            "candidate omitted baseline events",
        ),
        (
            "EP003_ALLOWED_INCREASE",
            |v| v.allowed_increase,
            |v| v.max_allowed_increase,
            "candidate increased allowed effects",
        ),
        (
            "EP004_FAILED_INCREASE",
            |v| v.failed_increase,
            |v| v.max_failed_increase,
            "candidate increased failed effects",
        ),
        (
            "EP005_BYTES_INCREASE",
            |v| v.bytes_increase,
            |v| v.max_bytes_increase,
            "candidate increased transferred bytes",
        ),
        (
            "EP006_DURATION_INCREASE",
            |v| v.duration_increase_ms,
            |v| v.max_duration_increase_ms,
            "candidate increased cumulative duration",
        ),
    ];
    let mut result = Vec::new();
    for bucket in buckets {
        for (code, actual_fn, limit_fn, message) in checks {
            let actual = actual_fn(bucket.metrics);
            let limit = limit_fn(bucket.limits);
            if actual > limit {
                result.push(Finding {
                    code: code.to_owned(),
                    bucket: bucket.name.clone(),
                    actual,
                    limit,
                    message: message.to_owned(),
                });
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use crate::model::EffectEvent;
    use crate::policy::{Policy, Rule, compile};

    use super::*;

    fn trace(events: Vec<EffectEvent>) -> Trace {
        Trace {
            events,
            digest: "digest".to_owned(),
        }
    }

    fn event(target: &str, outcome: Outcome, count: u64) -> EffectEvent {
        EffectEvent {
            schema_version: 1,
            kind: "network_connect".to_owned(),
            target: target.to_owned(),
            operation: "connect".to_owned(),
            outcome,
            count,
            bytes: 0,
            duration_ms: 0,
            attributes: BTreeMap::new(),
        }
    }

    fn strict_policy() -> CompiledPolicy {
        compile(Policy {
            schema_version: 1,
            ignore_attributes: BTreeSet::new(),
            defaults: Limits::default(),
            rules: Vec::new(),
        })
        .unwrap()
    }

    #[test]
    fn identical_traces_are_compatible() {
        let baseline = trace(vec![event("api.example:443", Outcome::Allowed, 1)]);
        let candidate = trace(vec![event("api.example:443", Outcome::Allowed, 1)]);
        assert!(compare(&baseline, &candidate, &strict_policy()).is_compatible());
    }

    #[test]
    fn newly_allowed_effect_is_reported() {
        let baseline = trace(vec![event("api.example:443", Outcome::Blocked, 1)]);
        let candidate = trace(vec![event("api.example:443", Outcome::Allowed, 1)]);
        let report = compare(&baseline, &candidate, &strict_policy());
        assert_eq!(report.verdict, Verdict::Different);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "EP003_ALLOWED_INCREASE")
        );
    }

    #[test]
    fn ignored_attributes_do_not_split_identity() {
        let mut baseline_event = event("api.example:443", Outcome::Allowed, 1);
        baseline_event
            .attributes
            .insert("pid".to_owned(), "10".to_owned());
        let mut candidate_event = baseline_event.clone();
        candidate_event
            .attributes
            .insert("pid".to_owned(), "11".to_owned());
        let policy = compile(Policy {
            schema_version: 1,
            ignore_attributes: BTreeSet::from(["pid".to_owned()]),
            defaults: Limits::default(),
            rules: Vec::new(),
        })
        .unwrap();
        assert!(
            compare(
                &trace(vec![baseline_event]),
                &trace(vec![candidate_event]),
                &policy
            )
            .is_compatible()
        );
    }

    #[test]
    fn matching_rule_applies_an_aggregate_budget() {
        let candidate = trace(vec![
            event("cache.example:443", Outcome::Blocked, 1),
            event("mirror.example:443", Outcome::Blocked, 1),
        ]);
        let policy = compile(Policy {
            schema_version: 1,
            ignore_attributes: BTreeSet::new(),
            defaults: Limits::default(),
            rules: vec![Rule {
                name: "blocked-network".to_owned(),
                kind: Some("network_connect".to_owned()),
                target_glob: "*.example:443".to_owned(),
                operation: Some("connect".to_owned()),
                limits: Limits {
                    max_new_events: 2,
                    ..Limits::default()
                },
            }],
        })
        .unwrap();
        assert!(compare(&trace(Vec::new()), &candidate, &policy).is_compatible());
    }

    #[test]
    fn report_text_contains_stable_finding_code() {
        let report = compare(
            &trace(Vec::new()),
            &trace(vec![event("new.example:443", Outcome::Allowed, 1)]),
            &strict_policy(),
        );
        assert!(report.render_text().contains("EP001_NEW_EVENTS"));
    }
}
