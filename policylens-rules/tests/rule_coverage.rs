//! Two things not covered by `corpus.rs`:
//!
//! 1. True-positive detection for rules 2 and 4, which the main test
//!    corpus doesn't dedicate a top-level vulnerable module to (the brief
//!    asks for "at least 3" vulnerable modules and "each rule's true
//!    positive detection" as a separate test-suite requirement -- these
//!    small fixtures satisfy the latter without inflating the corpus
//!    beyond what it needs to demonstrate for a human reader).
//! 2. Evidence-path reconstruction accuracy: given a known finding, do the
//!    reported file/resource/attribute values actually match what's in
//!    the source? This is what makes a finding auditable rather than just
//!    asserted.

use policylens_graph::build_graph_from_dir;
use policylens_rules::classify::classify;
use policylens_rules::matcher::run_rules;
use policylens_rules::report::build_report;
use policylens_rules::rule::RuleSet;
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

fn rules_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../rules")
}

#[test]
fn rule2_true_positive_wildcard_grant_to_sensitive_bucket() {
    let mut g = build_graph_from_dir(&fixture("rule2-tp")).unwrap();
    classify(&mut g);
    let rule_set = RuleSet::load_dir(&rules_dir()).unwrap();
    let findings = run_rules(&g, &rule_set.rules);

    let matches: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "overly-permissive-role-sensitive-access")
        .collect();
    assert_eq!(matches.len(), 1, "expected rule 2 to fire exactly once");
    assert_eq!(
        matches[0].node_ids,
        vec![
            "aws_iam_role.broad_access".to_string(),
            "aws_s3_bucket.sensitive_data".to_string()
        ]
    );
}

#[test]
fn rule4_true_positive_open_sg_to_sensitive_data_via_instance_role() {
    let mut g = build_graph_from_dir(&fixture("rule4-tp")).unwrap();
    classify(&mut g);
    let rule_set = RuleSet::load_dir(&rules_dir()).unwrap();
    let findings = run_rules(&g, &rule_set.rules);

    let matches: Vec<_> = findings
        .iter()
        .filter(|f| f.rule_id == "open-security-group-to-data-store")
        .collect();
    assert_eq!(matches.len(), 1, "expected rule 4 to fire exactly once");
    assert_eq!(
        matches[0].node_ids,
        vec![
            "aws_security_group.open".to_string(),
            "aws_instance.exposed".to_string(),
            "aws_iam_role.instance_role".to_string(),
            "aws_s3_bucket.sensitive_data".to_string(),
        ],
        "expected the full 4-hop chain: SG -> Instance -> Role -> Bucket"
    );
}

#[test]
fn evidence_path_reconstructs_correct_file_and_attribute() {
    let mut g = build_graph_from_dir(&fixture("rule2-tp")).unwrap();
    classify(&mut g);
    let rule_set = RuleSet::load_dir(&rules_dir()).unwrap();
    let findings = run_rules(&g, &rule_set.rules);
    let report = build_report("tests/fixtures/rule2-tp", &g, &rule_set.rules, &findings);

    assert_eq!(report.findings.len(), 1);
    let f = &report.findings[0];

    // The chain has exactly one edge (role -> bucket).
    assert_eq!(f.edges.len(), 1);
    let edge = &f.edges[0];
    assert_eq!(edge.from, "aws_iam_role.broad_access");
    assert_eq!(edge.to, "aws_s3_bucket.sensitive_data");
    assert_eq!(edge.kind, "IamGrants");
    // The evidence must point at the *policy holder* resource
    // (aws_iam_role_policy.broad_access_policy), the statement that
    // actually grants the access -- not just "somewhere in this file".
    assert!(
        edge.evidence_file.ends_with("rule2-tp/main.tf"),
        "evidence file should point at the actual source file, got {}",
        edge.evidence_file
    );
    assert_eq!(edge.evidence_attr_path, "policy.Statement[0]");
    assert!(
        edge.description.contains("aws_iam_role_policy.broad_access_policy"),
        "evidence description should name the resource that actually declared the grant, got: {}",
        edge.description
    );
    assert!(
        edge.description.contains("s3:*"),
        "evidence description should include the actual over-broad action, got: {}",
        edge.description
    );
}

#[test]
fn severity_score_and_explanation_are_internally_consistent() {
    let mut g = build_graph_from_dir(&fixture("rule2-tp")).unwrap();
    classify(&mut g);
    let rule_set = RuleSet::load_dir(&rules_dir()).unwrap();
    let findings = run_rules(&g, &rule_set.rules);
    let report = build_report("tests/fixtures/rule2-tp", &g, &rule_set.rules, &findings);

    let f = &report.findings[0];
    // rule2's severity_base is "medium" (50); target bucket is sensitive
    // (+10); no publicly-reachable node in this fixture (+0); single hop
    // (no hop penalty) -> 60.
    assert_eq!(f.severity.score, 60, "score should match the documented formula exactly");
    assert_eq!(f.severity.label, "MEDIUM");
    assert!(f.severity.explanation.contains("base 50"));
    assert!(f.severity.explanation.contains("sensitivity bonus 10"));
    assert!(f.severity.explanation.contains("exposure bonus 0"));
}
