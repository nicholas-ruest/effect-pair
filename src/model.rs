use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

const MAX_RECORD_VALUE: u64 = 1_000_000_000_000;

fn one() -> u64 {
    1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Allowed,
    Blocked,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectEvent {
    pub schema_version: u32,
    pub kind: String,
    pub target: String,
    pub operation: String,
    pub outcome: Outcome,
    #[serde(default = "one")]
    pub count: u64,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

impl EffectEvent {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 {
            return Err(format!(
                "unsupported schema_version {}; expected 1",
                self.schema_version
            ));
        }
        if !valid_token(&self.kind) {
            return Err("kind must match [a-z0-9][a-z0-9_.-]*".to_owned());
        }
        if self.target.trim().is_empty() {
            return Err("target must not be empty".to_owned());
        }
        if !valid_token(&self.operation) {
            return Err("operation must match [a-z0-9][a-z0-9_.-]*".to_owned());
        }
        if self.count == 0 {
            return Err("count must be greater than zero".to_owned());
        }
        for (name, value) in [
            ("count", self.count),
            ("bytes", self.bytes),
            ("duration_ms", self.duration_ms),
        ] {
            if value > MAX_RECORD_VALUE {
                return Err(format!(
                    "{name} exceeds the per-record limit of {MAX_RECORD_VALUE}"
                ));
            }
        }
        if let Some(key) = self.attributes.keys().find(|key| key.trim().is_empty()) {
            return Err(format!("attribute key {key:?} must not be empty"));
        }
        Ok(())
    }
}

pub(crate) fn valid_token(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_lowercase() || first.is_ascii_digit())
        && chars.all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '_' | '.' | '-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> EffectEvent {
        EffectEvent {
            schema_version: 1,
            kind: "file_write".to_owned(),
            target: "/workspace/result".to_owned(),
            operation: "modify".to_owned(),
            outcome: Outcome::Allowed,
            count: 1,
            bytes: 0,
            duration_ms: 0,
            attributes: BTreeMap::new(),
        }
    }

    #[test]
    fn accepts_a_valid_event() {
        assert!(event().validate().is_ok());
    }

    #[test]
    fn rejects_zero_count() {
        let mut candidate = event();
        candidate.count = 0;
        assert_eq!(
            candidate.validate().unwrap_err(),
            "count must be greater than zero"
        );
    }

    #[test]
    fn rejects_uppercase_kind() {
        let mut candidate = event();
        candidate.kind = "FileWrite".to_owned();
        assert!(candidate.validate().is_err());
    }

    #[test]
    fn rejects_values_that_could_overflow_aggregates() {
        let mut candidate = event();
        candidate.bytes = MAX_RECORD_VALUE + 1;
        assert!(
            candidate
                .validate()
                .unwrap_err()
                .contains("per-record limit")
        );
    }
}
