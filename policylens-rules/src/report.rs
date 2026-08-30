//! Stage 4, part B: turn `matcher::Finding`s into a fully evidence-grounded
//! report -- structured JSON (for CI) and a human-readable rendering (for
//! the terminal). Every finding traces back to concrete source: which
//! file, which resource, which attribute, for every hop in the chain. A
//! human should be able to open the listed files at the listed attributes
//! and independently verify the claim without trusting PolicyLens's word
//! for it.

use crate::matcher::Finding;
use crate::rule::Rule;
use crate::scoring::{score_finding, ScoreBreakdown};
use policylens_graph::graph::IacGraph;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ChainNode {
    pub id: String,
    pub kind: String,
    pub file: String,
}

#[derive(Debug, Serialize)]
pub struct ChainEdge {
    pub from: String,
    pub to: String,
    pub kind: String,
    pub details: serde_json::Value,
    pub description: String,
    pub evidence_file: String,
    pub evidence_attr_path: String,
}

#[derive(Debug, Serialize)]
pub struct SeverityReport {
    pub label: String,
    pub score: i64,
    pub explanation: String,
}

#[derive(Debug, Serialize)]
pub struct FindingReport {
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub severity: SeverityReport,
    pub chain_length_hops: usize,
    pub nodes: Vec<ChainNode>,
    pub edges: Vec<ChainEdge>,
}

#[derive(Debug, Serialize)]
pub struct Summary {
    pub total_findings: usize,
    pub by_severity: std::collections::BTreeMap<String, usize>,
    pub node_count: usize,
    pub edge_count: usize,
    pub unresolved_node_count: usize,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub directory: String,
    pub summary: Summary,
    pub findings: Vec<FindingReport>,
}

pub fn build_report(
    directory: &str,
    graph: &IacGraph,
    rules: &[Rule],
    findings: &[Finding],
) -> Report {
    let mut reports: Vec<FindingReport> = findings
        .iter()
        .map(|f| build_finding_report(graph, rules, f))
        .collect();

    // Highest severity first, so the report reads worst-first -- the
    // whole point of scoring is to triage attention, so the report itself
    // should reflect that ordering rather than making the reader re-sort.
    reports.sort_by_key(|r| std::cmp::Reverse(r.severity.score));

    let mut by_severity: std::collections::BTreeMap<String, usize> = Default::default();
    for r in &reports {
        *by_severity.entry(r.severity.label.clone()).or_insert(0) += 1;
    }

    Report {
        directory: directory.to_string(),
        summary: Summary {
            total_findings: reports.len(),
            by_severity,
            node_count: graph.node_count(),
            edge_count: graph.edge_count(),
            unresolved_node_count: graph.unresolved_node_count,
        },
        findings: reports,
    }
}

fn build_finding_report(graph: &IacGraph, rules: &[Rule], finding: &Finding) -> FindingReport {
    let rule = rules
        .iter()
        .find(|r| r.id == finding.rule_id)
        .expect("finding references a rule that was loaded");

    let node_ixs: Vec<_> = finding
        .node_ids
        .iter()
        .map(|id| {
            *graph
                .index_of
                .get(id)
                .expect("finding node id exists in graph")
        })
        .collect();

    let breakdown: ScoreBreakdown =
        score_finding(graph, rule.severity_base, &node_ixs, finding.edges.len());

    let nodes = node_ixs
        .iter()
        .map(|&ix| {
            let n = &graph.graph[ix];
            ChainNode {
                id: n.id.clone(),
                kind: format!("{:?}", n.kind),
                file: n.file.display().to_string(),
            }
        })
        .collect();

    let edges = finding
        .edges
        .iter()
        .map(|&eix| {
            let (from_ix, to_ix) = graph.graph.edge_endpoints(eix).unwrap();
            let e = &graph.graph[eix];
            ChainEdge {
                from: graph.graph[from_ix].id.clone(),
                to: graph.graph[to_ix].id.clone(),
                kind: edge_kind_name(&e.kind).to_string(),
                details: edge_kind_details(&e.kind),
                description: e.description.clone(),
                evidence_file: e.evidence.file.display().to_string(),
                evidence_attr_path: e.evidence.attr_path.clone(),
            }
        })
        .collect();

    FindingReport {
        rule_id: rule.id.clone(),
        title: rule.title.clone(),
        description: rule.description.clone(),
        severity: SeverityReport {
            label: breakdown.label.to_string(),
            score: breakdown.total,
            explanation: breakdown.explanation,
        },
        chain_length_hops: finding.edges.len(),
        nodes,
        edges,
    }
}

fn edge_kind_name(kind: &policylens_graph::types::EdgeKind) -> &'static str {
    use policylens_graph::types::EdgeKind;
    match kind {
        EdgeKind::References => "References",
        EdgeKind::IamTrust { .. } => "IamTrust",
        EdgeKind::IamGrants { .. } => "IamGrants",
        EdgeKind::Attached => "Attached",
        EdgeKind::NetworkReachable { .. } => "NetworkReachable",
    }
}

/// Structured (non-Debug-formatted) payload for an edge kind, for the JSON
/// report -- keeps machine consumers from having to parse Rust's `Debug`
/// output.
fn edge_kind_details(kind: &policylens_graph::types::EdgeKind) -> serde_json::Value {
    use policylens_graph::types::EdgeKind;
    match kind {
        EdgeKind::IamGrants {
            actions,
            effect,
            resource_match,
        } => {
            serde_json::json!({ "actions": actions, "effect": effect, "resource_match": resource_match })
        }
        EdgeKind::NetworkReachable {
            protocol,
            from_port,
            to_port,
            cidr,
        } => {
            serde_json::json!({ "protocol": protocol, "from_port": from_port, "to_port": to_port, "cidr": cidr })
        }
        EdgeKind::IamTrust { principal } => serde_json::json!({ "principal": principal }),
        EdgeKind::References | EdgeKind::Attached => serde_json::json!({}),
    }
}

/// Human-readable CLI rendering. Deliberately plain text (no color codes)
/// so it's identical whether piped to a file, a CI log, or a terminal.
pub fn render_human(report: &Report) -> String {
    let mut out = String::new();
    out.push_str(&format!("PolicyLens scan: {}\n", report.directory));
    out.push_str(&format!(
        "  {} resource(s), {} edge(s), {} unresolved attribute(s)\n",
        report.summary.node_count, report.summary.edge_count, report.summary.unresolved_node_count
    ));
    if report.summary.total_findings == 0 {
        out.push_str("\nNo cross-resource attack chains found.\n");
        return out;
    }

    out.push_str(&format!(
        "\n{} finding(s):\n",
        report.summary.total_findings
    ));
    for (label, count) in &report.summary.by_severity {
        out.push_str(&format!("  {label}: {count}\n"));
    }

    for (i, f) in report.findings.iter().enumerate() {
        out.push_str(&format!(
            "\n[{}] {} -- {} (score {})\n",
            i + 1,
            f.severity.label,
            f.title,
            f.severity.score
        ));
        out.push_str(&format!("  rule: {}\n", f.rule_id));
        out.push_str(&format!(
            "  why this severity: {}\n",
            f.severity.explanation
        ));
        out.push_str(&format!("  chain ({} hop(s)):\n", f.chain_length_hops));
        out.push_str(&format!("    {}", f.nodes[0].id));
        for (edge, node) in f.edges.iter().zip(f.nodes.iter().skip(1)) {
            out.push_str(&format!("\n      --[{}]--> {}", edge.kind, node.id));
            out.push_str(&format!(
                "\n          evidence: {} ({}, attribute `{}`)",
                edge.description, edge.evidence_file, edge.evidence_attr_path
            ));
        }
        out.push('\n');
    }
    out
}
