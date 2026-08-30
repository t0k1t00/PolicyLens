use anyhow::Result;
use std::path::PathBuf;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_default();

    match cmd.as_str() {
        "scan" => {
            let dir = args.next().expect("usage: policylens scan <path>");
            run_scan(PathBuf::from(dir))
        }
        "debug-graph" => {
            let dir = args.next().expect("usage: policylens debug-graph <path>");
            let classified = args.next().as_deref() == Some("--classified");
            debug_graph(PathBuf::from(dir), classified)
        }
        _ => {
            eprintln!("usage: policylens <scan|debug-graph> <path-to-terraform-dir>");
            std::process::exit(2);
        }
    }
}

/// Stage-1 checkpoint helper: build the graph and dump it as JSON
/// (nodes + edges) so it can be inspected directly. This is not the final
/// `scan` report format -- that comes in Stage 4 (evidence + severity).
fn debug_graph(dir: PathBuf, classified: bool) -> Result<()> {
    let mut g = policylens_graph::build_graph_from_dir(&dir)?;
    if classified {
        policylens_rules::classify::classify(&mut g);
    }

    let nodes: Vec<_> = g.graph.node_indices().map(|ix| &g.graph[ix]).collect();
    let edges: Vec<serde_json::Value> = g
        .graph
        .edge_indices()
        .map(|eix| {
            let (from_ix, to_ix) = g.graph.edge_endpoints(eix).unwrap();
            let edge = &g.graph[eix];
            serde_json::json!({
                "from": g.graph[from_ix].id,
                "to": g.graph[to_ix].id,
                "kind": edge.kind,
                "evidence": edge.evidence,
                "description": edge.description,
            })
        })
        .collect();

    let out = serde_json::json!({
        "node_count": g.node_count(),
        "edge_count": g.edge_count(),
        "unresolved_node_count": g.unresolved_node_count,
        "nodes": nodes,
        "edges": edges,
    });

    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn run_scan(dir: PathBuf) -> Result<()> {
    let mut g = policylens_graph::build_graph_from_dir(&dir)?;
    policylens_rules::classify::classify(&mut g);

    let rules_dir = find_rules_dir()?;
    let rule_set = policylens_rules::rule::RuleSet::load_dir(&rules_dir)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let findings = policylens_rules::matcher::run_rules(&g, &rule_set.rules);
    let report = policylens_rules::report::build_report(
        &dir.display().to_string(),
        &g,
        &rule_set.rules,
        &findings,
    );

    println!("{}", policylens_rules::report::render_human(&report));

    let json = serde_json::to_string_pretty(&report)?;
    std::fs::write("policylens-report.json", json)?;
    println!("(also wrote policylens-report.json)");

    Ok(())
}

fn find_rules_dir() -> Result<PathBuf> {
    // Look for a `rules/` dir starting from cwd and walking up -- keeps
    // `cargo run` and the built binary both working without hardcoding an
    // absolute path. Stage 4/5 will formalize this (bundled rules vs.
    // user-supplied rules dir via a flag).
    let mut dir = std::env::current_dir()?;
    loop {
        let candidate = dir.join("rules");
        if candidate.is_dir() {
            return Ok(candidate);
        }
        if !dir.pop() {
            anyhow::bail!("could not find a `rules/` directory searching upward from cwd");
        }
    }
}
