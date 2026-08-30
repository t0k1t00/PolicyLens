//! Stage 3, part B: the rule matcher.
//!
//! Walks each rule's `path` (alternating `NodeStep`/`EdgeStep`) against the
//! classified graph. Because the DSL is restricted to linear path patterns
//! (see `rule.rs`'s design note), this is a straightforward bounded
//! breadth-first expansion, not general subgraph isomorphism: at each step
//! we hold a frontier of "partial matches so far" and extend it by one
//! (possibly-repeated) edge hop plus one node check at a time. Every
//! partial match's total edge count is checked against `rule.max_total_hops`
//! before being extended further, so a pathological graph can't cause
//! unbounded work -- the cap is enforced by the engine, not just documented
//! as a convention rule authors are trusted to respect.

use crate::classify::edge_derived_facts;
use crate::predicate::{self, Predicate};
use crate::rule::{EdgeMatcher, NodeMatcher, PathStep, Rule};
use policylens_graph::graph::IacGraph;
use policylens_graph::types::{Edge, EdgeKind, ResourceKind};
use petgraph::graph::{EdgeIndex, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use serde_json::{json, Value};

/// One completed match of a rule's path against the graph: the sequence of
/// node ids visited and the edges (with full evidence) connecting them, in
/// order. This is Stage 3's output and Stage 4's input -- everything Stage
/// 4 needs to render an evidence trail is already here.
#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: String,
    pub node_ids: Vec<String>,
    pub edges: Vec<EdgeIndex>,
}

pub fn run_rules(graph: &IacGraph, rules: &[Rule]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for rule in rules {
        findings.extend(run_rule(graph, rule));
    }
    findings
}

fn run_rule(graph: &IacGraph, rule: &Rule) -> Vec<Finding> {
    let PathStep::Node(first) = &rule.path[0] else {
        unreachable!("validated at load time: path starts with a node step");
    };
    let first_pred = compile_where(&first.node.r#where);

    // Frontier entries: (current node, node_ids visited so far, edges taken
    // so far, total hop count so far).
    let mut frontier: Vec<(NodeIndex, Vec<NodeIndex>, Vec<EdgeIndex>, usize)> = graph
        .graph
        .node_indices()
        .filter(|&ix| node_matches(graph, ix, &first.node, first_pred.as_ref()))
        .map(|ix| (ix, vec![ix], Vec::new(), 0))
        .collect();

    // Walk (edge_step, node_step) pairs in order.
    let mut steps = rule.path[1..].chunks(2);
    while let Some(pair) = steps.next() {
        let (PathStep::Edge(edge_step), Some(PathStep::Node(node_step))) =
            (&pair[0], pair.get(1))
        else {
            unreachable!("validated at load time: strictly alternating, ends on a node");
        };
        let edge_pred = compile_where(&edge_step.edge.r#where);
        let node_pred = compile_where(&node_step.node.r#where);

        let mut next_frontier = Vec::new();
        for (from_ix, node_ids, edges_so_far, hops_so_far) in &frontier {
            for (reached, edge_trail) in walk_bounded_hops(
                graph,
                *from_ix,
                &edge_step.edge,
                edge_pred.as_ref(),
                *hops_so_far,
                rule.max_total_hops,
            ) {
                if node_matches(graph, reached, &node_step.node, node_pred.as_ref()) {
                    let mut ids = node_ids.clone();
                    ids.push(reached);
                    let mut edges = edges_so_far.clone();
                    edges.extend(&edge_trail);
                    next_frontier.push((reached, ids, edges, hops_so_far + edge_trail.len()));
                }
            }
        }
        frontier = next_frontier;
        if frontier.is_empty() {
            break;
        }
    }

    frontier
        .into_iter()
        .map(|(_, node_ixs, edges, _)| Finding {
            rule_id: rule.id.clone(),
            node_ids: node_ixs.iter().map(|&ix| graph.graph[ix].id.clone()).collect(),
            edges,
        })
        .collect()
}

/// From `from_ix`, find every node reachable by 1..=`edge_step.max_hops`
/// consecutive edges matching `edge_step`'s kind/predicate, respecting
/// `edge_step.min_hops` as the minimum chain length and `rule_max_total_hops`
/// (minus hops already spent) as a hard ceiling. Returns `(reached_node,
/// edge_trail)` pairs. Bounded DFS -- `max_hops` is a small integer by
/// construction (validated at rule-load time against `max_total_hops`), so
/// this can't run away.
fn walk_bounded_hops(
    graph: &IacGraph,
    from_ix: NodeIndex,
    edge_step: &EdgeMatcher,
    edge_pred: Option<&Predicate>,
    hops_so_far: usize,
    rule_max_total_hops: usize,
) -> Vec<(NodeIndex, Vec<EdgeIndex>)> {
    let mut results = Vec::new();
    let remaining_budget = rule_max_total_hops.saturating_sub(hops_so_far);
    let effective_max = edge_step.max_hops.min(remaining_budget);
    if effective_max == 0 {
        return results;
    }

    fn dfs(
        graph: &IacGraph,
        cur: NodeIndex,
        edge_step: &EdgeMatcher,
        edge_pred: Option<&Predicate>,
        depth: usize,
        effective_max: usize,
        min_hops: usize,
        trail: &mut Vec<EdgeIndex>,
        out: &mut Vec<(NodeIndex, Vec<EdgeIndex>)>,
    ) {
        if depth >= min_hops {
            out.push((cur, trail.clone()));
        }
        if depth >= effective_max {
            return;
        }
        for edge_ref in graph.graph.edges_directed(cur, Direction::Outgoing) {
            if !edge_matches(edge_ref.weight(), edge_step, edge_pred) {
                continue;
            }
            trail.push(edge_ref.id());
            dfs(
                graph,
                edge_ref.target(),
                edge_step,
                edge_pred,
                depth + 1,
                effective_max,
                min_hops,
                trail,
                out,
            );
            trail.pop();
        }
    }

    let mut trail = Vec::new();
    dfs(
        graph,
        from_ix,
        edge_step,
        edge_pred,
        0,
        effective_max,
        edge_step.min_hops,
        &mut trail,
        &mut results,
    );
    // depth==0 (the "reached == from_ix, zero hops taken" case) only
    // happens if min_hops == 0, which the DSL doesn't currently allow
    // (min_hops defaults to 1); filtering here keeps the function correct
    // even if that changes later.
    results.retain(|(_, trail)| !trail.is_empty());
    results
}

fn compile_where(where_clause: &Option<String>) -> Option<Predicate> {
    where_clause.as_ref().map(|s| {
        predicate::parse(s).unwrap_or_else(|e| {
            panic!("invalid where-clause `{s}`: {e} (should have been caught at rule load time)")
        })
    })
}

fn node_matches(
    graph: &IacGraph,
    ix: NodeIndex,
    matcher: &NodeMatcher,
    pred: Option<&Predicate>,
) -> bool {
    let node = &graph.graph[ix];
    if let Some(kind_name) = &matcher.kind {
        if !kind_matches(&node.kind, kind_name) {
            return false;
        }
    }
    match pred {
        Some(p) => predicate::evaluate(p, &node.attrs),
        None => true,
    }
}

fn kind_matches(kind: &ResourceKind, name: &str) -> bool {
    match kind {
        ResourceKind::Other(tf_type) => tf_type == name,
        other => resource_kind_name(other) == name,
    }
}

fn resource_kind_name(kind: &ResourceKind) -> &'static str {
    match kind {
        ResourceKind::S3Bucket => "S3Bucket",
        ResourceKind::S3BucketPolicy => "S3BucketPolicy",
        ResourceKind::S3BucketPublicAccessBlock => "S3BucketPublicAccessBlock",
        ResourceKind::S3BucketAcl => "S3BucketAcl",
        ResourceKind::IamRole => "IamRole",
        ResourceKind::IamPolicy => "IamPolicy",
        ResourceKind::IamRolePolicy => "IamRolePolicy",
        ResourceKind::IamRolePolicyAttachment => "IamRolePolicyAttachment",
        ResourceKind::IamInstanceProfile => "IamInstanceProfile",
        ResourceKind::LambdaFunction => "LambdaFunction",
        ResourceKind::LambdaPermission => "LambdaPermission",
        ResourceKind::SecurityGroup => "SecurityGroup",
        ResourceKind::SecurityGroupRule => "SecurityGroupRule",
        ResourceKind::Instance => "Instance",
        ResourceKind::SecretsManagerSecret => "SecretsManagerSecret",
        ResourceKind::Other(_) => "Other",
    }
}

fn edge_matches(edge: &Edge, matcher: &EdgeMatcher, pred: Option<&Predicate>) -> bool {
    if edge_kind_name(&edge.kind) != matcher.kind {
        return false;
    }
    match pred {
        Some(p) => predicate::evaluate(p, &edge_json(edge)),
        None => true,
    }
}

fn edge_kind_name(kind: &EdgeKind) -> &'static str {
    match kind {
        EdgeKind::References => "References",
        EdgeKind::IamTrust { .. } => "IamTrust",
        EdgeKind::IamGrants { .. } => "IamGrants",
        EdgeKind::Attached => "Attached",
        EdgeKind::NetworkReachable { .. } => "NetworkReachable",
    }
}

/// Build the JSON value a `where:` predicate on an edge is evaluated
/// against: kind-specific raw fields plus `_derived` facts (see
/// `classify::edge_derived_facts`), mirroring the `_derived.*` convention
/// node predicates use. `attr_path` (the attribute that produced this edge,
/// e.g. `"role"` or `"environment.variables.BUCKET_ARN"`) is exposed on
/// every edge kind so rules can disambiguate which attribute a generic
/// `References` edge came from without needing a new edge kind per
/// attribute.
fn edge_json(edge: &Edge) -> Value {
    let derived = edge_derived_facts(&edge.kind);
    let attr_path = &edge.evidence.attr_path;
    match &edge.kind {
        EdgeKind::IamGrants {
            actions,
            effect,
            resource_match,
        } => json!({
            "actions": actions,
            "effect": effect,
            "resource_match": resource_match,
            "attr_path": attr_path,
            "_derived": derived,
        }),
        EdgeKind::NetworkReachable {
            protocol,
            from_port,
            to_port,
            cidr,
        } => json!({
            "protocol": protocol,
            "from_port": from_port,
            "to_port": to_port,
            "cidr": cidr,
            "attr_path": attr_path,
            "_derived": derived,
        }),
        EdgeKind::IamTrust { principal } => json!({
            "principal": principal,
            "attr_path": attr_path,
            "_derived": derived,
        }),
        EdgeKind::References | EdgeKind::Attached => json!({
            "attr_path": attr_path,
            "_derived": derived,
        }),
    }
}
