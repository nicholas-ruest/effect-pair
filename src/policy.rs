use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use globset::{Glob, GlobMatcher};
use serde::{Deserialize, Serialize};

use crate::model::valid_token;
use crate::{CompareError, compare::Identity};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub max_new_events: u64,
    pub max_missing_events: u64,
    pub max_allowed_increase: u64,
    pub max_failed_increase: u64,
    pub max_bytes_increase: u64,
    pub max_duration_increase_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    #[serde(default)]
    pub kind: Option<String>,
    pub target_glob: String,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub limits: Limits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema_version: u32,
    #[serde(default)]
    pub ignore_attributes: BTreeSet<String>,
    #[serde(default)]
    pub defaults: Limits,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug)]
pub(crate) struct CompiledRule {
    pub rule: Rule,
    matcher: GlobMatcher,
}

#[derive(Debug)]
pub(crate) struct CompiledPolicy {
    pub policy: Policy,
    rules: Vec<CompiledRule>,
}

impl CompiledPolicy {
    pub fn bucket<'a>(&'a self, identity: &Identity) -> (&'a str, Limits) {
        self.rules
            .iter()
            .find(|compiled| compiled.matches(identity))
            .map_or(("default", self.policy.defaults), |compiled| {
                (compiled.rule.name.as_str(), compiled.rule.limits)
            })
    }
}

impl CompiledRule {
    fn matches(&self, identity: &Identity) -> bool {
        self.rule
            .kind
            .as_ref()
            .is_none_or(|kind| kind == &identity.kind)
            && self.matcher.is_match(&identity.target)
            && self
                .rule
                .operation
                .as_ref()
                .is_none_or(|operation| operation == &identity.operation)
    }
}

pub(crate) fn load(path: &Path) -> Result<CompiledPolicy, CompareError> {
    let text = fs::read_to_string(path).map_err(|source| CompareError::ReadPolicy {
        path: path.to_path_buf(),
        source,
    })?;
    let policy: Policy = toml::from_str(&text).map_err(|error| CompareError::InvalidPolicy {
        path: path.to_path_buf(),
        message: error.to_string(),
    })?;
    compile(policy).map_err(|message| CompareError::InvalidPolicy {
        path: path.to_path_buf(),
        message,
    })
}

pub(crate) fn compile(policy: Policy) -> Result<CompiledPolicy, String> {
    if policy.schema_version != 1 {
        return Err(format!(
            "unsupported schema_version {}; expected 1",
            policy.schema_version
        ));
    }
    if let Some(attribute) = policy
        .ignore_attributes
        .iter()
        .find(|attribute| attribute.trim().is_empty())
    {
        return Err(format!("ignored attribute {attribute:?} must not be empty"));
    }
    let mut names = BTreeSet::new();
    let mut rules = Vec::with_capacity(policy.rules.len());
    for rule in &policy.rules {
        if rule.name.trim().is_empty() {
            return Err("rule names must not be empty".to_owned());
        }
        if !names.insert(rule.name.clone()) {
            return Err(format!("duplicate rule name {:?}", rule.name));
        }
        if rule.kind.as_ref().is_some_and(|kind| !valid_token(kind)) {
            return Err(format!("rule {:?} has an invalid kind", rule.name));
        }
        if rule
            .operation
            .as_ref()
            .is_some_and(|operation| !valid_token(operation))
        {
            return Err(format!("rule {:?} has an invalid operation", rule.name));
        }
        let matcher = Glob::new(&rule.target_glob)
            .map_err(|error| format!("rule {:?} has an invalid target_glob: {error}", rule.name))?
            .compile_matcher();
        rules.push(CompiledRule {
            rule: rule.clone(),
            matcher,
        });
    }
    Ok(CompiledPolicy { policy, rules })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            schema_version: 1,
            ignore_attributes: BTreeSet::new(),
            defaults: Limits::default(),
            rules: Vec::new(),
        }
    }

    #[test]
    fn rejects_duplicate_rule_names() {
        let mut candidate = policy();
        let rule = Rule {
            name: "same".to_owned(),
            kind: None,
            target_glob: "**".to_owned(),
            operation: None,
            limits: Limits::default(),
        };
        candidate.rules = vec![rule.clone(), rule];
        assert!(compile(candidate).unwrap_err().contains("duplicate"));
    }

    #[test]
    fn rejects_invalid_glob() {
        let mut candidate = policy();
        candidate.rules.push(Rule {
            name: "broken".to_owned(),
            kind: None,
            target_glob: "[".to_owned(),
            operation: None,
            limits: Limits::default(),
        });
        assert!(compile(candidate).unwrap_err().contains("target_glob"));
    }
}
