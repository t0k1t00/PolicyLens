//! Stage 1a: read every `.tf` file in a (flat) directory and parse it into
//! an `hcl::Body`. No `module` block traversal, no remote state, no
//! variable evaluation -- see README "Limitations". This module's only job
//! is turning bytes on disk into HCL ASTs; graph construction happens in
//! `graph.rs`.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// A parsed `.tf` file: its path (for evidence grounding) and HCL body.
pub struct ParsedFile {
    pub path: PathBuf,
    pub body: hcl::Body,
}

/// Parse every `*.tf` file directly inside `dir` (non-recursive by design --
/// Terraform root modules conventionally keep resources flat, and
/// recursing would silently start pulling in child module source, which
/// contradicts the "no module traversal" scope decision).
pub fn parse_directory(dir: &Path) -> Result<Vec<ParsedFile>> {
    if !dir.is_dir() {
        anyhow::bail!("{} is not a directory", dir.display());
    }

    let mut files = Vec::new();
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .with_context(|| format!("reading directory {}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|ext| ext == "tf").unwrap_or(false))
        .collect();
    entries.sort(); // deterministic ordering -> deterministic node/edge iteration -> stable reports

    if entries.is_empty() {
        anyhow::bail!("no .tf files found directly in {}", dir.display());
    }

    for path in entries {
        let src =
            fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        let body: hcl::Body =
            hcl::from_str(&src).with_context(|| format!("parsing HCL in {}", path.display()))?;
        files.push(ParsedFile { path, body });
    }

    Ok(files)
}
