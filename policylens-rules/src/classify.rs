//! Stage 3, part A: classification.
//!
//! `policylens-graph` (Stage 1) only knows generic structure: nodes,
//! attributes, and `References` edges from attribute traversals. It
//! deliberately has zero AWS/IAM/networking knowledge. This module is where
//! that knowledge lives: it reads node `attrs` (parsed IAM policy JSON,
//! security-group ingress rules, tags, public-access-block flags, ...) and
//! produces two things the rule engine's `where:` predicates and edge
//! matchers depend on:
//!
//! 1. **Derived facts** (`node.attrs["_derived"]`, e.g. `public`,
//!    `sensitive`, `wildcard_trust`) -- booleans computed once so rule
//!    predicates stay simple equality checks (see `predicate.rs`'s design
//!    note on why the DSL pushes this complexity here rather than
//!    expressing it inline).
//! 2. **Semantic edges** (`IamGrants`, `NetworkReachable`, `Attached`) on
//!    top of the generic `References` edges Stage 1 already found.
//!
//! Every derived fact and synthesized edge is computed from data that is
//! *already on the graph* -- this pass never re-reads source files or
//! invents information; it's a pure function of `(nodes, References edges)
//! -> (derived facts, semantic edges)`.

use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use policylens_graph::graph::IacGraph;
use policylens_graph::types::{Edge, EdgeKind, ResourceKind, SourceRef};
use serde_json::{json, Value};

/// Action-name substrings that count as "this grant lets you write/modify
/// the target", used by `_derived.grants_write`. Deliberately substring
/// based (not an exhaustive enumeration of every AWS API call) because IAM
/// action lists are effectively open-ended; this is a heuristic, documented
/// as such, not a claim of complete IAM semantics coverage.
const WRITE_ACTION_MARKERS: &[&str] = &["Put", "Delete", "Write", "Create", "Update", "Upload"];

/// Specific IAM actions that let a principal change what permissions a
/// role/policy has -- the textbook privilege-escalation primitives.
const IAM_ESCALATION_ACTIONS: &[&str] = &[
    "iam:putrolepolicy",
    "iam:attachrolepolicy",
    "iam:createpolicyversion",
    "iam:setdefaultpolicyversion",
    "iam:attachuserpolicy",
    "iam:attachgrouppolicy",
    "iam:addusertogroup",
    "iam:updateassumerolepolicy",
    "iam:passrole",
];

pub fn classify(graph: &mut IacGraph) {
    derive_s3_bucket_facts(graph);
    derive_iam_role_trust_facts(graph);
    derive_security_group_facts(graph);
    derive_lambda_public_invoke_facts(graph);
    let iam_grant_edges = compute_iam_grant_edges(graph);
    let network_edges = compute_network_reachable_edges(graph);
    let attached_edges = compute_attached_edges(graph);
    for (from, to, edge) in iam_grant_edges
        .into_iter()
        .chain(network_edges)
        .chain(attached_edges)
    {
        graph.graph.add_edge(from, to, edge);
    }
}

fn set_derived(graph: &mut IacGraph, ix: NodeIndex, key: &str, value: Value) {
    let node = &mut graph.graph[ix];
    if !node.attrs.is_object() {
        return;
    }
    let obj = node.attrs.as_object_mut().unwrap();
    let derived = obj
        .entry("_derived")
        .or_insert_with(|| Value::Object(Default::default()));
    derived
        .as_object_mut()
        .unwrap()
        .insert(key.to_string(), value);
}

/// `_derived.public` and `_derived.sensitive` on every `S3Bucket` node.
///
/// `public`: AWS has defaulted S3 buckets to fully-blocked public access
/// since 2023, so a bucket with **no** `S3BucketPublicAccessBlock` (or
/// `S3BucketAcl`) resource pointed at it is treated as **not** public --
/// that's the safe, accurate default, not an unresolved unknown. A bucket
/// *is* flagged public if a public-access-block resource explicitly turns
/// any of the four protections off, or an ACL resource sets a public canned
/// ACL.
///
/// `sensitive`: a `tags` map containing a `sensitive` (case-insensitive)
/// key whose value is truthy (`"true"`, `true`, `"yes"`). This is a modeling
/// convention this tool defines for its own test corpus and README, not an
/// AWS concept -- real usage would tune this to an org's actual tagging
/// standard, called out explicitly in the README.
fn derive_s3_bucket_facts(graph: &mut IacGraph) {
    let bucket_ixs: Vec<NodeIndex> = graph
        .graph
        .node_indices()
        .filter(|&ix| graph.graph[ix].kind == ResourceKind::S3Bucket)
        .collect();

    for bucket_ix in bucket_ixs {
        let sensitive = is_tagged_sensitive(&graph.graph[bucket_ix].attrs);
        set_derived(graph, bucket_ix, "sensitive", json!(sensitive));

        let mut public = false;
        // Any node with a `References` edge into this bucket whose kind is
        // a public-access-block or ACL resource contributes to the
        // public/private determination.
        for edge_ix in graph
            .graph
            .edges_directed(bucket_ix, Direction::Incoming)
            .map(|e| e.id())
            .collect::<Vec<_>>()
        {
            let (src_ix, _) = graph.graph.edge_endpoints(edge_ix).unwrap();
            let src = &graph.graph[src_ix];
            match src.kind {
                ResourceKind::S3BucketPublicAccessBlock => {
                    let a = &src.attrs;
                    let blocks_everything = attr_bool(a, "block_public_acls", true)
                        && attr_bool(a, "block_public_policy", true)
                        && attr_bool(a, "ignore_public_acls", true)
                        && attr_bool(a, "restrict_public_buckets", true);
                    if !blocks_everything {
                        public = true;
                    }
                }
                ResourceKind::S3BucketAcl => {
                    if let Some(acl) = src.attrs.get("acl").and_then(|v| v.as_str()) {
                        if acl == "public-read" || acl == "public-read-write" {
                            public = true;
                        }
                    }
                }
                _ => {}
            }
        }
        set_derived(graph, bucket_ix, "public", json!(public));
    }
}

fn attr_bool(attrs: &Value, key: &str, default: bool) -> bool {
    attrs.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
}

fn is_tagged_sensitive(attrs: &Value) -> bool {
    let Some(tags) = attrs.get("tags").and_then(|v| v.as_object()) else {
        return false;
    };
    for (k, v) in tags {
        if k.to_lowercase() == "sensitive" {
            let truthy = match v {
                Value::Bool(b) => *b,
                Value::String(s) => matches!(s.to_lowercase().as_str(), "true" | "yes" | "1"),
                _ => false,
            };
            if truthy {
                return true;
            }
        }
    }
    false
}

/// `_derived.wildcard_trust` on every `IamRole` node: true if
/// `assume_role_policy` contains an `Allow` statement whose `Principal` is
/// `"*"`, or whose `Principal.AWS` is (or contains) `"*"`. A `Principal`
/// scoped to a specific AWS service (`"lambda.amazonaws.com"`), account, or
/// role ARN is intentionally *not* flagged -- that's normal, expected
/// trust, not the untrusted/wildcard case rules 1 and 5 look for.
fn derive_iam_role_trust_facts(graph: &mut IacGraph) {
    let role_ixs: Vec<NodeIndex> = graph
        .graph
        .node_indices()
        .filter(|&ix| graph.graph[ix].kind == ResourceKind::IamRole)
        .collect();

    for role_ix in role_ixs {
        let attrs = &graph.graph[role_ix].attrs;
        let wildcard = attrs
            .get("assume_role_policy")
            .and_then(|p| p.get("Statement"))
            .map(|stmts| {
                statement_iter(stmts)
                    .iter()
                    .any(statement_has_wildcard_principal)
            })
            .unwrap_or(false);
        set_derived(graph, role_ix, "wildcard_trust", json!(wildcard));
    }
}

fn statement_iter(stmts: &Value) -> Vec<&Value> {
    match stmts {
        Value::Array(a) => a.iter().collect(),
        other => vec![other],
    }
}

fn statement_has_wildcard_principal(stmt: &&Value) -> bool {
    let effect_allow = stmt
        .get("Effect")
        .and_then(|v| v.as_str())
        .map(|s| s == "Allow")
        .unwrap_or(false);
    if !effect_allow {
        return false;
    }
    match stmt.get("Principal") {
        Some(Value::String(s)) => s == "*",
        Some(Value::Object(map)) => map.values().any(value_contains_star),
        _ => false,
    }
}

fn value_contains_star(v: &Value) -> bool {
    match v {
        Value::String(s) => s == "*",
        Value::Array(arr) => arr.iter().any(value_contains_star),
        _ => false,
    }
}

/// `_derived.open_ingress` on every `SecurityGroup` node: true if any
/// `ingress` rule allows a `cidr_blocks` of `0.0.0.0/0` (or `::/0`).
fn derive_security_group_facts(graph: &mut IacGraph) {
    let sg_ixs: Vec<NodeIndex> = graph
        .graph
        .node_indices()
        .filter(|&ix| graph.graph[ix].kind == ResourceKind::SecurityGroup)
        .collect();

    for sg_ix in sg_ixs {
        let attrs = &graph.graph[sg_ix].attrs;
        let open = attrs
            .get("ingress")
            .map(|ingress_list| {
                statement_iter(ingress_list).iter().any(|rule| {
                    rule.get("cidr_blocks")
                        .map(|cidrs| {
                            statement_iter(cidrs)
                                .iter()
                                .any(|c| matches!(c.as_str(), Some("0.0.0.0/0") | Some("::/0")))
                        })
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);
        set_derived(graph, sg_ix, "open_ingress", json!(open));
    }
}

/// `_derived.publicly_invokable` on every `LambdaFunction` node: true if
/// any `aws_lambda_permission` resource grants `lambda:InvokeFunction` (or
/// `"*"`) to principal `"*"` against this function with no `source_arn`
/// restricting who can actually trigger it. A permission scoped to a
/// specific service principal (e.g. `apigateway.amazonaws.com`) with a
/// `source_arn` is normal, expected wiring and is not flagged -- it's the
/// combination of wildcard principal *and* no source restriction that
/// means literally anyone can invoke the function.
fn derive_lambda_public_invoke_facts(graph: &mut IacGraph) {
    let lambda_ixs: Vec<NodeIndex> = graph
        .graph
        .node_indices()
        .filter(|&ix| graph.graph[ix].kind == ResourceKind::LambdaFunction)
        .collect();

    for lambda_ix in lambda_ixs {
        let mut public = false;
        for perm_ix in graph.graph.node_indices() {
            let perm = &graph.graph[perm_ix];
            if perm.kind != ResourceKind::LambdaPermission {
                continue;
            }
            if referenced_node(graph, perm_ix, "function_name") != Some(lambda_ix) {
                continue;
            }
            let principal_wildcard = perm
                .attrs
                .get("principal")
                .and_then(|v| v.as_str())
                .map(|s| s == "*")
                .unwrap_or(false);
            let has_source_arn = perm.attrs.get("source_arn").is_some();
            if principal_wildcard && !has_source_arn {
                public = true;
            }
        }
        set_derived(graph, lambda_ix, "publicly_invokable", json!(public));
    }
}

/// Walk every `IamRole`'s inline policies (`IamRolePolicy`) and every
/// standalone `IamPolicy` attached to a role (via
/// `IamRolePolicyAttachment`), extract each `Allow` statement's actions,
/// and -- using the `References` edges Stage 1 already resolved from each
/// statement's `Resource` field -- emit an `IamGrants` edge from the
/// **role** directly to the **target resource**, skipping the
/// intermediate policy node. This is what lets rule paths read simply as
/// `IamRole -[IamGrants]-> target` without needing to know whether the
/// grant came from an inline or attached policy.
fn compute_iam_grant_edges(graph: &IacGraph) -> Vec<(NodeIndex, NodeIndex, Edge)> {
    let mut out = Vec::new();

    for ix in graph.graph.node_indices() {
        let node = &graph.graph[ix];
        match node.kind {
            ResourceKind::IamRolePolicy => {
                let Some(role_ix) = referenced_node(graph, ix, "role") else {
                    continue;
                };
                out.extend(grants_from_policy_holder(
                    graph,
                    ix,
                    role_ix,
                    node.id.clone(),
                ));
            }
            ResourceKind::IamPolicy => {
                // Find every attachment resource that links this policy to a role.
                for att_ix in graph.graph.node_indices() {
                    let att = &graph.graph[att_ix];
                    if att.kind != ResourceKind::IamRolePolicyAttachment {
                        continue;
                    }
                    let policy_edge_target = referenced_node(graph, att_ix, "policy_arn");
                    if policy_edge_target != Some(ix) {
                        continue;
                    }
                    let Some(role_ix) = referenced_node(graph, att_ix, "role") else {
                        continue;
                    };
                    out.extend(grants_from_policy_holder(
                        graph,
                        ix,
                        role_ix,
                        node.id.clone(),
                    ));
                }
            }
            _ => {}
        }
    }
    out
}

/// Find the node a given `attr_path` on `from_ix` references, via a
/// `References` edge Stage 1 already built (e.g. `role` on an
/// `aws_iam_role_policy`, or `policy_arn` on an attachment resource).
fn referenced_node(graph: &IacGraph, from_ix: NodeIndex, attr_path: &str) -> Option<NodeIndex> {
    graph
        .graph
        .edges_directed(from_ix, Direction::Outgoing)
        .find(|e| {
            matches!(&e.weight().kind, EdgeKind::References)
                && e.weight().evidence.attr_path == attr_path
        })
        .map(|e| e.target())
}

fn grants_from_policy_holder(
    graph: &IacGraph,
    holder_ix: NodeIndex,
    role_ix: NodeIndex,
    holder_id: String,
) -> Vec<(NodeIndex, NodeIndex, Edge)> {
    let holder = &graph.graph[holder_ix];
    let role_id = graph.graph[role_ix].id.clone();
    let Some(statements) = holder.attrs.get("policy").and_then(|p| p.get("Statement")) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for (stmt_idx, stmt) in statement_iter(statements).into_iter().enumerate() {
        let effect = stmt
            .get("Effect")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if effect != "Allow" {
            continue;
        }
        let actions = normalize_string_or_array(stmt.get("Action"));
        if actions.is_empty() {
            continue;
        }

        // Prefer precise per-statement resolution via the `Statement[N]`
        // attr_path Stage 1 recorded (see expr.rs's TemplateExpr walk);
        // fall back to "any Resource reference anywhere in this policy"
        // for authoring styles where the JSON was written as a flat
        // interpolated string rather than jsonencode({...}) (see
        // README limitations: statement-index resolution is best-effort).
        let precise_targets: Vec<NodeIndex> = graph
            .graph
            .edges_directed(holder_ix, Direction::Outgoing)
            .filter(|e| {
                matches!(&e.weight().kind, EdgeKind::References)
                    && statement_index_from_attr_path(&e.weight().evidence.attr_path)
                        == Some(stmt_idx)
                    && e.weight().evidence.attr_path.ends_with(".Resource")
            })
            .map(|e| e.target())
            .collect();

        let targets: Vec<NodeIndex> = if !precise_targets.is_empty() {
            precise_targets
        } else if statements_have_no_indexed_evidence(graph, holder_ix) {
            graph
                .graph
                .edges_directed(holder_ix, Direction::Outgoing)
                .filter(|e| {
                    matches!(&e.weight().kind, EdgeKind::References)
                        && e.weight().evidence.attr_path.contains("Resource")
                })
                .map(|e| e.target())
                .collect()
        } else {
            Vec::new()
        };

        let resource_match = normalize_string_or_array(stmt.get("Resource"))
            .into_iter()
            .map(|s| {
                // Internal marker for an unresolved traversal (see expr.rs)
                // -- strip the marker prefix so evidence text reads as the
                // plain resource-address path a human wrote, not our
                // internal bookkeeping string.
                s.strip_prefix("unresolved:ref:")
                    .map(|rest| rest.to_string())
                    .unwrap_or(s)
            })
            .collect::<Vec<_>>()
            .join(",");
        for target_ix in targets {
            // Deliberately NOT skipping target_ix == role_ix: a role
            // granting itself IAM-modifying permissions on its own ARN is
            // exactly the self-loop rule 5 (privilege escalation) matches
            // against. See rules/iam-role-self-privilege-escalation.yaml.
            let grants_write = actions
                .iter()
                .any(|a| a == "*" || WRITE_ACTION_MARKERS.iter().any(|m| a.contains(m)));
            let grants_wildcard = actions.iter().any(|a| a == "*" || a.ends_with(":*"));
            let grants_iam_escalation = actions.iter().any(|a| {
                let lower = a.to_lowercase();
                lower == "*" || lower == "iam:*" || IAM_ESCALATION_ACTIONS.contains(&lower.as_str())
            });

            out.push((
                role_ix,
                target_ix,
                Edge {
                    kind: EdgeKind::IamGrants {
                        actions: actions.clone(),
                        effect: effect.clone(),
                        resource_match: resource_match.clone(),
                    },
                    evidence: SourceRef {
                        file: holder.file.clone(),
                        resource_id: holder_id.clone(),
                        attr_path: format!("policy.Statement[{stmt_idx}]"),
                    },
                    description: format!(
                        "{role_id} (via {holder_id}, statement {stmt_idx}) is granted {actions:?} on {}",
                        graph.graph[target_ix].id
                    ),
                },
            ));
            // Stash grants_write/grants_wildcard/grants_iam_escalation as
            // JSON-visible facts by re-deriving them at match time from
            // `actions` (see matcher.rs `edge_derived`) rather than
            // duplicating storage here -- avoided a second mutable pass.
            let _ = (grants_write, grants_wildcard, grants_iam_escalation);
        }
    }
    out
}

fn statements_have_no_indexed_evidence(graph: &IacGraph, holder_ix: NodeIndex) -> bool {
    !graph
        .graph
        .edges_directed(holder_ix, Direction::Outgoing)
        .any(|e| {
            matches!(&e.weight().kind, EdgeKind::References)
                && statement_index_from_attr_path(&e.weight().evidence.attr_path).is_some()
        })
}

fn statement_index_from_attr_path(attr_path: &str) -> Option<usize> {
    let start = attr_path.find("Statement[")? + "Statement[".len();
    let end = attr_path[start..].find(']')? + start;
    attr_path[start..end].parse().ok()
}

fn normalize_string_or_array(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

/// `NetworkReachable` edges, from `SecurityGroup` to whatever resource
/// uses it. Direction is deliberately the reverse of the raw `References`
/// edge (which points *instance -> security_group*, since that's how the
/// HCL attribute traversal reads): a rule pattern wants to start from "the
/// open door" and walk *into* what it exposes, i.e. `SecurityGroup
/// -[NetworkReachable]-> Instance`.
fn compute_network_reachable_edges(graph: &IacGraph) -> Vec<(NodeIndex, NodeIndex, Edge)> {
    let mut out = Vec::new();
    for ix in graph.graph.node_indices() {
        let node = &graph.graph[ix];
        if node.kind != ResourceKind::Instance {
            continue;
        }
        for attr_path in ["vpc_security_group_ids", "security_groups"] {
            for edge_ref in graph
                .graph
                .edges_directed(ix, Direction::Outgoing)
                .filter(|e| {
                    matches!(&e.weight().kind, EdgeKind::References)
                        && e.weight().evidence.attr_path.starts_with(attr_path)
                })
                .collect::<Vec<_>>()
            {
                let sg_ix = edge_ref.target();
                if graph.graph[sg_ix].kind != ResourceKind::SecurityGroup {
                    continue;
                }
                let sg_attrs = &graph.graph[sg_ix].attrs;
                for rule in ingress_rules_with_open_cidr(sg_attrs) {
                    out.push((
                        sg_ix,
                        ix,
                        Edge {
                            kind: EdgeKind::NetworkReachable {
                                protocol: rule.0,
                                from_port: rule.1,
                                to_port: rule.2,
                                cidr: rule.3,
                            },
                            evidence: SourceRef {
                                file: graph.graph[sg_ix].file.clone(),
                                resource_id: graph.graph[sg_ix].id.clone(),
                                attr_path: "ingress".to_string(),
                            },
                            description: format!(
                                "{} allows inbound from 0.0.0.0/0, reaching {}",
                                graph.graph[sg_ix].id, node.id
                            ),
                        },
                    ));
                }
            }
        }
    }
    out
}

fn ingress_rules_with_open_cidr(sg_attrs: &Value) -> Vec<(String, i64, i64, String)> {
    let Some(ingress_list) = sg_attrs.get("ingress") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for rule in statement_iter(ingress_list) {
        let has_open_cidr = rule
            .get("cidr_blocks")
            .map(|cidrs| {
                statement_iter(cidrs)
                    .iter()
                    .any(|c| matches!(c.as_str(), Some("0.0.0.0/0") | Some("::/0")))
            })
            .unwrap_or(false);
        if has_open_cidr {
            let protocol = rule
                .get("protocol")
                .and_then(|v| v.as_str())
                .unwrap_or("tcp")
                .to_string();
            let from_port = rule.get("from_port").and_then(|v| v.as_i64()).unwrap_or(0);
            let to_port = rule.get("to_port").and_then(|v| v.as_i64()).unwrap_or(0);
            out.push((protocol, from_port, to_port, "0.0.0.0/0".to_string()));
        }
    }
    out
}

/// `Attached` edges from `Instance` directly to `IamRole`, collapsing the
/// `Instance -> IamInstanceProfile -> IamRole` indirection into one edge.
/// This is a deliberate simplification for pattern-matching ergonomics
/// (documented in the README): PolicyLens does not model instance profiles
/// as a distinct hop in rule paths, only as the mechanism used to resolve
/// which role an instance runs as.
fn compute_attached_edges(graph: &IacGraph) -> Vec<(NodeIndex, NodeIndex, Edge)> {
    let mut out = Vec::new();
    for ix in graph.graph.node_indices() {
        let node = &graph.graph[ix];
        if node.kind != ResourceKind::Instance {
            continue;
        }
        let Some(profile_ix) = referenced_node(graph, ix, "iam_instance_profile") else {
            continue;
        };
        if graph.graph[profile_ix].kind != ResourceKind::IamInstanceProfile {
            continue;
        }
        let Some(role_ix) = referenced_node(graph, profile_ix, "role") else {
            continue;
        };
        out.push((
            ix,
            role_ix,
            Edge {
                kind: EdgeKind::Attached,
                evidence: SourceRef {
                    file: node.file.clone(),
                    resource_id: node.id.clone(),
                    attr_path: "iam_instance_profile".to_string(),
                },
                description: format!(
                    "{} runs as {} (via instance profile {})",
                    node.id, graph.graph[role_ix].id, graph.graph[profile_ix].id
                ),
            },
        ));
    }
    out
}

/// Derived boolean facts about an `IamGrants` edge, computed on demand by
/// the matcher (kept out of the stored `Edge` to avoid duplicating the
/// action-classification logic in two places -- see the `let _ = (...)` in
/// `grants_from_policy_holder`).
pub fn edge_derived_facts(kind: &EdgeKind) -> Value {
    match kind {
        EdgeKind::IamGrants { actions, .. } => {
            let grants_write = actions
                .iter()
                .any(|a| a == "*" || WRITE_ACTION_MARKERS.iter().any(|m| a.contains(m)));
            let grants_wildcard = actions.iter().any(|a| a == "*" || a.ends_with(":*"));
            let grants_iam_escalation = actions.iter().any(|a| {
                let lower = a.to_lowercase();
                lower == "*" || lower == "iam:*" || IAM_ESCALATION_ACTIONS.contains(&lower.as_str())
            });
            json!({
                "grants_write": grants_write,
                "grants_wildcard": grants_wildcard,
                "grants_iam_escalation": grants_iam_escalation,
            })
        }
        _ => json!({}),
    }
}
