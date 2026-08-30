//! Runs the full pipeline (parse -> build graph -> classify -> match
//! rules) against every module in `test-corpus/` and asserts the expected
//! outcome for each: vulnerable modules must trigger their specific rule
//! (and no other), "looks suspicious but safe" modules must trigger
//! nothing, and zero-issue modules must trigger nothing. This is the
//! concrete enforcement of the corpus design: every module's *comment*
//! makes a claim about what should happen, and every claim here is
//! actually checked in CI rather than just asserted in prose.

use policylens_graph::build_graph_from_dir;
use policylens_rules::classify::classify;
use policylens_rules::matcher::run_rules;
use policylens_rules::rule::RuleSet;
use std::path::{Path, PathBuf};

fn corpus_dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../test-corpus").join(name)
}

fn rules_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../rules")
}

fn scan(module: &str) -> Vec<String> {
    let mut g = build_graph_from_dir(&corpus_dir(module)).expect("module should parse and build");
    classify(&mut g);
    let rule_set = RuleSet::load_dir(&rules_dir()).expect("rules should load");
    let findings = run_rules(&g, &rule_set.rules);
    findings.into_iter().map(|f| f.rule_id).collect()
}

#[test]
fn all_five_built_in_rules_are_present() {
    let rule_set = RuleSet::load_dir(&rules_dir()).expect("rules should load");
    assert_eq!(rule_set.rules.len(), 5);
}

// --- Vulnerable modules: each must trigger its specific rule ---

#[test]
fn vuln_01_triggers_public_storage_writable_by_untrusted_role() {
    let rule_ids = scan("vuln-01-public-bucket-untrusted-role");
    assert_eq!(
        rule_ids,
        vec!["public-storage-writable-by-untrusted-role".to_string()],
        "expected exactly one finding, from rule 1"
    );
}

#[test]
fn vuln_02_triggers_iam_self_privilege_escalation() {
    let rule_ids = scan("vuln-02-privilege-escalation");
    assert_eq!(
        rule_ids,
        vec!["iam-role-self-privilege-escalation".to_string()],
        "expected exactly one finding, from rule 5"
    );
}

#[test]
fn vuln_03_triggers_unauthenticated_compute_secret_access() {
    let rule_ids = scan("vuln-03-unauthenticated-lambda-secret-access");
    assert_eq!(
        rule_ids,
        vec!["unauthenticated-compute-secret-access".to_string()],
        "expected exactly one finding, from rule 3"
    );
}

// --- "Looks suspicious per-resource but is safe end-to-end" modules:
//     each must trigger NOTHING despite containing an ingredient that
//     would make a naive single-resource scanner flag something. ---

#[test]
fn safe_01_locked_down_bucket_with_wildcard_trust_role_triggers_nothing() {
    let rule_ids = scan("safe-01-public-bucket-but-locked-down-role");
    assert!(
        rule_ids.is_empty(),
        "expected no findings (PAB blocks all public access, wildcard-trust role has no grant to \
         the locked-down bucket), got: {rule_ids:?}"
    );
}

#[test]
fn safe_02_wildcard_grant_on_nonsensitive_bucket_triggers_nothing() {
    let rule_ids = scan("safe-02-wildcard-role-on-nonsensitive-bucket");
    assert!(
        rule_ids.is_empty(),
        "expected no findings (wildcard s3:* grant exists, but target bucket isn't tagged \
         sensitive), got: {rule_ids:?}"
    );
}

#[test]
fn safe_03_open_sg_instance_with_no_sensitive_access_triggers_nothing() {
    let rule_ids = scan("safe-03-open-sg-instance-no-sensitive-access");
    assert!(
        rule_ids.is_empty(),
        "expected no findings (SG is genuinely open to 0.0.0.0/0, but the instance's role only \
         reaches a non-sensitive bucket), got: {rule_ids:?}"
    );
}

// --- Zero-issue modules: nothing to find, full stop. ---

#[test]
fn zero_01_single_private_bucket_triggers_nothing() {
    let rule_ids = scan("zero-01-single-private-bucket");
    assert!(rule_ids.is_empty(), "expected no findings, got: {rule_ids:?}");
}

#[test]
fn zero_02_least_privilege_role_triggers_nothing() {
    let rule_ids = scan("zero-02-least-privilege-role");
    assert!(
        rule_ids.is_empty(),
        "expected no findings (properly-scoped trust + properly-scoped grant to a sensitive \
         bucket is not, on its own, a chain), got: {rule_ids:?}"
    );
}
