//! Stage 1b: turn parsed HCL bodies into the resource-dependency graph.
//!
//! Two passes, deliberately:
//! 1. **Node pass** -- every `resource "<type>" "<name>" { ... }` block
//!    becomes a `Node`. Terraform allows forward references (a resource
//!    can reference another resource declared later in the file, or in a
//!    different file), so all nodes must exist before edge resolution can
//!    run.
//! 2. **Edge pass** -- walk each node's attribute expressions for
//!    traversals into other resource ids (`expr::collect_traversals`) and
//!    emit `References` edges. Semantic edge classification (IAM trust,
//!    grants, network reachability) is layered on top of node attrs by the
//!    rule engine / a thin classification pass -- see `classify.rs`.

use crate::expr::{self, RESERVED_ROOTS};
use crate::parser::ParsedFile;
use crate::types::{Edge, EdgeKind, Node, ResourceKind, SourceRef};
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GraphBuildError {
    #[error(
        "duplicate resource address `{id}` (first seen in {first_file}, again in {second_file}) -- \
         PolicyLens requires unique resource addresses within the scanned directory and refuses to \
         silently overwrite one definition with another"
    )]
    DuplicateResource {
        id: String,
        first_file: String,
        second_file: String,
    },
}

/// The resource-dependency graph. Wraps `petgraph::DiGraph` and adds an
/// id -> NodeIndex lookup, since rules address nodes by Terraform address
/// (`"aws_s3_bucket.data"`), not by petgraph's internal index.
pub struct IacGraph {
    pub graph: DiGraph<Node, Edge>,
    pub index_of: HashMap<String, NodeIndex>,
    /// Count of attributes across all nodes that contained an unresolved
    /// interpolation, surfaced in reports per the "N resources skipped due
    /// to unresolved interpolation" requirement.
    pub unresolved_node_count: usize,
}

impl IacGraph {
    pub fn node(&self, id: &str) -> Option<&Node> {
        self.index_of.get(id).map(|&ix| &self.graph[ix])
    }

    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }
}

pub fn build_graph(files: &[ParsedFile]) -> Result<IacGraph, GraphBuildError> {
    let mut graph: DiGraph<Node, Edge> = DiGraph::new();
    let mut index_of: HashMap<String, NodeIndex> = HashMap::new();
    let mut first_seen_file: HashMap<String, String> = HashMap::new();

    // --- Pass 1: nodes ---
    for file in files {
        for structure in file.body.iter() {
            let Some(block) = structure.as_block() else {
                continue;
            };
            if block.identifier() != "resource" {
                continue;
            }
            let labels: Vec<&str> = block.labels().iter().map(|l| l.as_str()).collect();
            let (Some(tf_type), Some(tf_name)) = (labels.first(), labels.get(1)) else {
                continue; // malformed `resource` block without two labels; skip rather than panic
            };
            let id = format!("{tf_type}.{tf_name}");

            if let Some(existing_file) = first_seen_file.get(&id) {
                return Err(GraphBuildError::DuplicateResource {
                    id,
                    first_file: existing_file.clone(),
                    second_file: file.path.display().to_string(),
                });
            }
            first_seen_file.insert(id.clone(), file.path.display().to_string());

            let (attrs, has_unresolved) = body_to_json(block.body());
            let attrs = promote_embedded_json(attrs);

            let node = Node {
                id: id.clone(),
                tf_type: tf_type.to_string(),
                tf_name: tf_name.to_string(),
                kind: ResourceKind::classify(tf_type),
                file: file.path.clone(),
                attrs,
                has_unresolved_attrs: has_unresolved,
            };
            let ix = graph.add_node(node);
            index_of.insert(id, ix);
        }
    }

    let unresolved_node_count = graph
        .node_indices()
        .filter(|&ix| graph[ix].has_unresolved_attrs)
        .count();

    // --- Pass 2: edges (generic References edges from attribute traversals) ---
    for file in files {
        for structure in file.body.iter() {
            let Some(block) = structure.as_block() else {
                continue;
            };
            if block.identifier() != "resource" {
                continue;
            }
            let labels: Vec<&str> = block.labels().iter().map(|l| l.as_str()).collect();
            let (Some(tf_type), Some(tf_name)) = (labels.first(), labels.get(1)) else {
                continue;
            };
            let from_id = format!("{tf_type}.{tf_name}");
            let Some(&from_ix) = index_of.get(&from_id) else {
                continue;
            };

            let mut refs = Vec::new();
            for attr in block.body().attributes() {
                expr::collect_traversals(attr.expr(), attr.key(), &mut refs);
            }
            // Also walk nested blocks (e.g. `environment { variables = {...} }`)
            for nested in block.body().blocks() {
                walk_nested_block(nested, nested.identifier(), &mut refs);
            }

            for r in refs {
                // Skip self-references and reserved roots already filtered
                // in collect_traversals; here we additionally require the
                // target to be a *known* node -- an unresolved forward
                // reference to a resource type PolicyLens doesn't parse
                // (or a typo) is dropped rather than fabricated.
                if r.target_id == from_id {
                    continue;
                }
                let Some(&to_ix) = index_of.get(&r.target_id) else {
                    continue;
                };
                let edge = Edge {
                    kind: EdgeKind::References,
                    evidence: SourceRef {
                        file: file.path.clone(),
                        resource_id: from_id.clone(),
                        attr_path: r.attr_path.clone(),
                    },
                    description: format!(
                        "{from_id}.{} references {} ({})",
                        r.attr_path, r.target_id, r.full_path
                    ),
                };
                graph.add_edge(from_ix, to_ix, edge);
            }
        }
    }

    Ok(IacGraph {
        graph,
        index_of,
        unresolved_node_count,
    })
}

fn walk_nested_block(block: &hcl::Block, path_prefix: &str, out: &mut Vec<expr::TraversalRef>) {
    for attr in block.body().attributes() {
        let path = format!("{path_prefix}.{}", attr.key());
        expr::collect_traversals(attr.expr(), &path, out);
    }
    for nested in block.body().blocks() {
        let path = format!("{path_prefix}.{}", nested.identifier());
        walk_nested_block(nested, &path, out);
    }
}

fn body_to_json(body: &hcl::Body) -> (serde_json::Value, bool) {
    let mut map = serde_json::Map::new();
    let mut unresolved = false;
    for attr in body.attributes() {
        let (v, u) = expr::expr_to_json(attr.expr());
        unresolved |= u;
        map.insert(attr.key().to_string(), v);
    }
    for block in body.blocks() {
        let (v, u) = body_to_json(block.body());
        unresolved |= u;
        // Repeated nested block labels (e.g. multiple `ingress { }` blocks)
        // become a JSON array under that key so nothing is silently
        // overwritten -- this matters a lot for security_group ingress/egress.
        match map.get_mut(block.identifier()) {
            Some(serde_json::Value::Array(arr)) => arr.push(v),
            Some(existing) => {
                let prev = existing.take();
                map.insert(
                    block.identifier().to_string(),
                    serde_json::Value::Array(vec![prev, v]),
                );
            }
            None => {
                map.insert(block.identifier().to_string(), serde_json::Value::Array(vec![v]));
            }
        }
    }
    (serde_json::Value::Object(map), unresolved)
}

/// Walk a JSON value replacing any string that parses cleanly as a JSON
/// object/array with the parsed structure. This is what lets
/// `assume_role_policy = <<POLICY ... POLICY` (raw heredoc JSON) and
/// `assume_role_policy = jsonencode({...})` (already unwrapped in
/// `expr_to_json`) end up as the *same* structured shape for rules to query.
fn promote_embedded_json(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::String(s) => {
            let trimmed = s.trim();
            if (trimmed.starts_with('{') && trimmed.ends_with('}'))
                || (trimmed.starts_with('[') && trimmed.ends_with(']'))
            {
                match serde_json::from_str::<serde_json::Value>(trimmed) {
                    Ok(parsed) => promote_embedded_json(parsed),
                    Err(_) => serde_json::Value::String(s),
                }
            } else {
                serde_json::Value::String(s)
            }
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(promote_embedded_json).collect())
        }
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.into_iter()
                .map(|(k, v)| (k, promote_embedded_json(v)))
                .collect(),
        ),
        other => other,
    }
}

// Re-export for callers that only need the reserved-roots list (e.g. rule
// engine diagnostics that explain why a traversal wasn't treated as a ref).
pub fn reserved_roots() -> &'static [&'static str] {
    RESERVED_ROOTS
}
