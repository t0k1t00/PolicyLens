//! `policylens-graph`: Stage 1 of PolicyLens.
//!
//! Parses a flat directory of `.tf` files (AWS provider resources only) and
//! builds a directed resource graph: nodes are individual resources, edges
//! are relationships discovered between them. This crate deliberately knows
//! nothing about *rules* or *severity* -- see `policylens-rules` for that.
//! Its only job is: turn Terraform source into a queryable, evidence-linked
//! graph.

pub mod expr;
pub mod graph;
pub mod parser;
pub mod types;

use anyhow::Result;
use std::path::Path;

/// Convenience entry point: parse `dir` and build the graph in one call.
pub fn build_graph_from_dir(dir: &Path) -> Result<graph::IacGraph> {
    let files = parser::parse_directory(dir)?;
    let g = graph::build_graph(&files)?;
    Ok(g)
}
