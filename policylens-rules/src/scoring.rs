//! Stage 4, part A: severity scoring.
//!
//! # The formula, and why
//!
//! Score = `base(rule.severity_base)` − `hop_penalty(chain length)` +
//! `sensitivity_bonus` + `exposure_bonus`, clamped to `0..=100`, then mapped
//! back to a display label. Every term exists for a specific, statable
//! reason -- there is no free-floating constant in this file that isn't
//! explained here:
//!
//! - **`base`**: `critical=90, high=70, medium=50, low=30`. This is the
//!   rule author's own judgment of how dangerous *this class* of chain is
//!   in the abstract (declared per-rule in the YAML, not computed) --
//!   everything else in the formula is a per-instance adjustment on top of
//!   that baseline.
//! - **`hop_penalty`**: `5 points per edge beyond the first, capped at 20`.
//!   The brief's own requirement: "shorter chains to sensitive data score
//!   higher than long/improbable ones." A longer chain requires more
//!   independent conditions to hold simultaneously (more assumptions about
//!   what an attacker can actually reach and do), so it's statistically
//!   less likely to be exploitable *as found* even when every edge is
//!   real. The cap at 20 exists so a long-but-certain chain doesn't get
//!   scored as trivial -- length matters, but shouldn't be able to
//!   completely override the base severity of the rule that matched.
//! - **`sensitivity_bonus` (+10)**: applied if *any* node in the chain
//!   carries `_derived.sensitive == true`. A chain that reaches data the
//!   organization itself has flagged as sensitive is worse than a
//!   structurally identical chain that doesn't, independent of which rule
//!   matched.
//! - **`exposure_bonus` (+8)**: applied if *any* node in the chain is
//!   directly internet-reachable (`_derived.public`,
//!   `_derived.publicly_invokable`, or `_derived.open_ingress`). A chain
//!   with a public entry point requires no prior foothold to exploit;
//!   one that's only reachable from inside the account already assumes a
//!   compromised principal, which is a meaningfully higher bar.
//!
//! These bonuses are small and additive (not multiplicative) deliberately:
//! they nudge the rule's own baseline judgment, they don't get to invert
//! it -- a `low`-severity rule with both bonuses (30 + 10 + 8 = 48) still
//! scores below a `high`-severity rule with neither (70), which matches the
//! intent that `severity_base` is the primary signal and these are
//! secondary refinements.

use crate::rule::Severity;
use petgraph::graph::NodeIndex;
use policylens_graph::graph::IacGraph;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeverityLabel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for SeverityLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SeverityLabel::Low => "LOW",
            SeverityLabel::Medium => "MEDIUM",
            SeverityLabel::High => "HIGH",
            SeverityLabel::Critical => "CRITICAL",
        };
        write!(f, "{s}")
    }
}

pub struct ScoreBreakdown {
    pub base: i64,
    pub hop_penalty: i64,
    pub sensitivity_bonus: i64,
    pub exposure_bonus: i64,
    pub total: i64,
    pub label: SeverityLabel,
    /// One-line human explanation of how `total` was derived, for direct
    /// inclusion in the report -- so "why is this a 78" is always
    /// answerable without reading this file.
    pub explanation: String,
}

fn base_score(sev: Severity) -> i64 {
    match sev {
        Severity::Critical => 90,
        Severity::High => 70,
        Severity::Medium => 50,
        Severity::Low => 30,
    }
}

fn label_for(score: i64) -> SeverityLabel {
    if score >= 85 {
        SeverityLabel::Critical
    } else if score >= 65 {
        SeverityLabel::High
    } else if score >= 40 {
        SeverityLabel::Medium
    } else {
        SeverityLabel::Low
    }
}

pub fn score_finding(
    graph: &IacGraph,
    severity_base: Severity,
    node_ixs: &[NodeIndex],
    edge_count: usize,
) -> ScoreBreakdown {
    let base = base_score(severity_base);

    let extra_hops = edge_count.saturating_sub(1);
    let hop_penalty = (extra_hops as i64 * 5).min(20);

    let sensitive = node_ixs
        .iter()
        .any(|&ix| derived_bool(graph, ix, "sensitive"));
    let sensitivity_bonus = if sensitive { 10 } else { 0 };

    let exposed = node_ixs.iter().any(|&ix| {
        derived_bool(graph, ix, "public")
            || derived_bool(graph, ix, "publicly_invokable")
            || derived_bool(graph, ix, "open_ingress")
    });
    let exposure_bonus = if exposed { 8 } else { 0 };

    let total = (base - hop_penalty + sensitivity_bonus + exposure_bonus).clamp(0, 100);
    let label = label_for(total);

    let explanation = format!(
        "base {base} ({severity_base:?}) − hop penalty {hop_penalty} ({extra_hops} extra hop(s) beyond the first, capped at 20) \
         + sensitivity bonus {sensitivity_bonus} ({}) + exposure bonus {exposure_bonus} ({}) = {total} -> {label}",
        if sensitive { "chain reaches a resource tagged sensitive" } else { "no sensitive-tagged resource in chain" },
        if exposed { "chain includes a publicly-reachable entry point" } else { "no publicly-reachable entry point in chain" },
    );

    ScoreBreakdown {
        base,
        hop_penalty,
        sensitivity_bonus,
        exposure_bonus,
        total,
        label,
        explanation,
    }
}

fn derived_bool(graph: &IacGraph, ix: NodeIndex, key: &str) -> bool {
    graph.graph[ix]
        .attrs
        .get("_derived")
        .and_then(|d| d.get(key))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}
