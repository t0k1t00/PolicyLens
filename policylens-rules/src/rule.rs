//! Stage 2: the PolicyLens rule DSL schema.
//!
//! # Why YAML, why this shape
//!
//! Rules describe **linear graph-path patterns**: an alternating sequence of
//! node-matchers and edge-matchers, e.g. "a public S3 bucket -[IamGrants
//! write]-> a role -[IamTrust wildcard]-> anything". We confirmed with the
//! user that none of the five built-in rules need branching subgraph
//! matching (no rule needs "resource A connects to both B and C
//! simultaneously"), so the DSL intentionally only expresses **paths**, not
//! general subgraphs. That constraint is what keeps the matcher a simple,
//! boundedly-terminating path walk instead of a general (and potentially
//! expensive) subgraph-isomorphism search.
//!
//! YAML was chosen over a hand-rolled custom syntax because:
//! - The pattern shape (list of alternating typed steps, each with a small
//!   predicate string) maps directly onto YAML lists/maps with no impedance
//!   mismatch -- a custom grammar would just be reinventing YAML's list/map
//!   syntax with extra parsing code to maintain.
//! - `serde_yaml` + `serde::Deserialize` gets us parsing, error messages,
//!   and schema validation (via Rust's type system) for free.
//! - Only the `where:` predicate itself needs a genuinely new mini-grammar
//!   (see `predicate.rs`) -- and keeping *that* small and hand-parsed, while
//!   using YAML for structure, is what stops the DSL from creeping into "a
//!   full programming language" territory the brief explicitly ruled out.
//!
//! # Path shape
//!
//! A `path` is `[node, edge, node, edge, node, ...]` -- it must start and
//! end with a `node` step, and `node`/`edge` steps must strictly alternate.
//! This is validated at load time (`RuleSet::load`), not at match time.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    /// Baseline severity before Stage 4's chain-length/sensitivity scoring
    /// adjustments. One of "critical" | "high" | "medium" | "low".
    pub severity_base: Severity,
    /// Hard cap on total edges traversed for one match of this rule,
    /// summed across all edge steps (each of which may itself repeat up to
    /// its own `max_hops`, see `EdgeStep`). This bounds worst-case
    /// traversal cost independent of how the path is written -- required
    /// even though today's built-in rules are all short, so a future rule
    /// with a wide `max_hops` on one edge step can't blow up runtime on a
    /// large graph.
    pub max_total_hops: usize,
    pub path: Vec<PathStep>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum PathStep {
    Node(NodeStep),
    Edge(EdgeStep),
}

#[derive(Debug, Clone, Deserialize)]
pub struct NodeStep {
    pub node: NodeMatcher,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NodeMatcher {
    /// Resource kind name matching `types::ResourceKind`'s variant names
    /// (e.g. `"S3Bucket"`, `"IamRole"`). Omit to match any kind.
    #[serde(default)]
    pub kind: Option<String>,
    /// A predicate string in the where-clause mini-grammar (see
    /// `predicate.rs`), evaluated against the node's `attrs` (raw parsed
    /// HCL) merged with `_derived` (facts computed by the classification
    /// pass -- e.g. `_derived.public`, `_derived.sensitive`). Omit to match
    /// unconditionally (kind filter only).
    #[serde(default)]
    pub r#where: Option<String>,
    /// A short label referencing this step's matched node in evidence
    /// output, e.g. `"public_bucket"`. Optional; defaults to the step's
    /// position (e.g. `"node_0"`).
    #[serde(default)]
    pub bind: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EdgeStep {
    pub edge: EdgeMatcher,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EdgeMatcher {
    /// Edge kind name matching `types::EdgeKind`'s variant names (e.g.
    /// `"IamGrants"`, `"NetworkReachable"`, `"References"`).
    pub kind: String,
    #[serde(default)]
    pub r#where: Option<String>,
    /// Minimum consecutive hops of this edge kind/predicate to traverse
    /// (default 1). Set > 1 with `max_hops` to express a bounded "chain of
    /// N-to-M same-kind edges" without needing subgraph matching -- e.g. "1
    /// to 3 References hops" for indirect wiring through an intermediate
    /// resource. Still linear: at every hop the *same* matcher is applied,
    /// there's no branching.
    #[serde(default = "one")]
    pub min_hops: usize,
    /// Maximum consecutive hops of this edge kind/predicate (default 1).
    /// This is the per-step bound; `Rule::max_total_hops` is the
    /// rule-wide bound the engine enforces on top of it.
    #[serde(default = "one")]
    pub max_hops: usize,
}

fn one() -> usize {
    1
}

#[derive(Debug, thiserror::Error)]
pub enum RuleLoadError {
    #[error("failed to parse rule YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("rule `{id}`: path must start and end with a `node` step")]
    PathMustStartAndEndWithNode { id: String },
    #[error("rule `{id}`: path steps must strictly alternate node/edge/node/edge/...")]
    PathMustAlternate { id: String },
    #[error("rule `{id}`: path must contain at least one node step")]
    PathEmpty { id: String },
    #[error("rule `{id}`: edge step has min_hops ({min}) > max_hops ({max})")]
    InvalidHopRange { id: String, min: usize, max: usize },
    #[error("rule `{id}`: max_total_hops ({total}) is smaller than the path's own minimum hop count ({min_required}) -- this rule could never match")]
    MaxTotalHopsTooSmall {
        id: String,
        total: usize,
        min_required: usize,
    },
}

pub struct RuleSet {
    pub rules: Vec<Rule>,
}

impl RuleSet {
    /// Load and validate every `.yaml`/`.yml` file directly inside `dir`.
    pub fn load_dir(dir: &std::path::Path) -> Result<RuleSet, RuleLoadError> {
        let mut rules = Vec::new();
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .expect("rules directory should exist")
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                matches!(
                    p.extension().and_then(|e| e.to_str()),
                    Some("yaml") | Some("yml")
                )
            })
            .collect();
        entries.sort();
        for path in entries {
            let src = std::fs::read_to_string(&path).expect("rule file should be readable");
            let rule = Self::parse_one(&src)?;
            rules.push(rule);
        }
        Ok(RuleSet { rules })
    }

    pub fn parse_one(yaml: &str) -> Result<Rule, RuleLoadError> {
        let rule: Rule = serde_yaml::from_str(yaml)?;
        validate(&rule)?;
        Ok(rule)
    }
}

fn validate(rule: &Rule) -> Result<(), RuleLoadError> {
    let id = rule.id.clone();
    if rule.path.is_empty() {
        return Err(RuleLoadError::PathEmpty { id });
    }
    match rule.path.first() {
        Some(PathStep::Node(_)) => {}
        _ => return Err(RuleLoadError::PathMustStartAndEndWithNode { id }),
    }
    match rule.path.last() {
        Some(PathStep::Node(_)) => {}
        _ => return Err(RuleLoadError::PathMustStartAndEndWithNode { id }),
    }
    for w in rule.path.windows(2) {
        let alternates = matches!(
            (&w[0], &w[1]),
            (PathStep::Node(_), PathStep::Edge(_)) | (PathStep::Edge(_), PathStep::Node(_))
        );
        if !alternates {
            return Err(RuleLoadError::PathMustAlternate { id });
        }
    }

    let mut min_required = 0usize;
    for step in &rule.path {
        if let PathStep::Edge(e) = step {
            if e.edge.min_hops > e.edge.max_hops {
                return Err(RuleLoadError::InvalidHopRange {
                    id,
                    min: e.edge.min_hops,
                    max: e.edge.max_hops,
                });
            }
            min_required += e.edge.min_hops;
        }
    }
    if min_required > rule.max_total_hops {
        return Err(RuleLoadError::MaxTotalHopsTooSmall {
            id,
            total: rule.max_total_hops,
            min_required,
        });
    }

    Ok(())
}

#[cfg(test)]
mod rule_tests {
    use super::*;

    #[test]
    fn load_and_validate_example_rules() {
        let dir = std::path::Path::new("../rules");
        let set = RuleSet::load_dir(dir).expect("rules dir should load and validate");
        assert_eq!(set.rules.len(), 5, "expected all 5 built-in rules");
        let ids: Vec<_> = set.rules.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"public-storage-writable-by-untrusted-role"));
        assert!(ids.contains(&"iam-role-self-privilege-escalation"));
        assert!(ids.contains(&"overly-permissive-role-sensitive-access"));
        assert!(ids.contains(&"unauthenticated-compute-secret-access"));
        assert!(ids.contains(&"open-security-group-to-data-store"));
    }

    #[test]
    fn rejects_path_not_starting_with_node() {
        let yaml = r#"
id: bad
title: bad
severity_base: low
max_total_hops: 1
path:
  - edge: { kind: References }
  - node: { kind: S3Bucket }
"#;
        let err = RuleSet::parse_one(yaml).unwrap_err();
        assert!(matches!(
            err,
            RuleLoadError::PathMustStartAndEndWithNode { .. }
        ));
    }

    #[test]
    fn rejects_non_alternating_path() {
        let yaml = r#"
id: bad
title: bad
severity_base: low
max_total_hops: 1
path:
  - node: { kind: S3Bucket }
  - node: { kind: IamRole }
"#;
        let err = RuleSet::parse_one(yaml).unwrap_err();
        assert!(matches!(err, RuleLoadError::PathMustAlternate { .. }));
    }

    #[test]
    fn rejects_max_total_hops_too_small() {
        let yaml = r#"
id: bad
title: bad
severity_base: low
max_total_hops: 1
path:
  - node: { kind: S3Bucket }
  - edge: { kind: References, min_hops: 2, max_hops: 3 }
  - node: { kind: IamRole }
"#;
        let err = RuleSet::parse_one(yaml).unwrap_err();
        assert!(matches!(err, RuleLoadError::MaxTotalHopsTooSmall { .. }));
    }
}
