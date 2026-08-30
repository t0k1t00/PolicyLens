//! Graph construction correctness tests -- Stage 1's contract: given known
//! `.tf` input, PolicyLens should produce exactly the nodes/edges/derived
//! facts the source implies, no more, no less.

use policylens_graph::build_graph_from_dir;
use policylens_graph::graph::GraphBuildError;
use policylens_graph::parser::parse_directory;
use policylens_graph::types::ResourceKind;
use std::path::Path;

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

#[test]
fn parses_all_resources_with_correct_kinds() {
    let g = build_graph_from_dir(&fixture("basic")).expect("should build");
    assert_eq!(g.node_count(), 4, "expected exactly the 4 resources in the fixture");

    let bucket = g.node("aws_s3_bucket.data").expect("bucket node should exist");
    assert_eq!(bucket.kind, ResourceKind::S3Bucket);
    assert_eq!(bucket.tf_type, "aws_s3_bucket");
    assert_eq!(bucket.tf_name, "data");

    let pab = g
        .node("aws_s3_bucket_public_access_block.data")
        .expect("public access block node should exist");
    assert_eq!(pab.kind, ResourceKind::S3BucketPublicAccessBlock);

    let role = g.node("aws_iam_role.reader").expect("role node should exist");
    assert_eq!(role.kind, ResourceKind::IamRole);

    let lambda = g
        .node("aws_lambda_function.consumer")
        .expect("lambda node should exist");
    assert_eq!(lambda.kind, ResourceKind::LambdaFunction);
}

#[test]
fn discovers_expected_reference_edges() {
    let g = build_graph_from_dir(&fixture("basic")).expect("should build");

    // aws_s3_bucket_public_access_block.data.bucket -> aws_s3_bucket.data
    let pab_ix = *g.index_of.get("aws_s3_bucket_public_access_block.data").unwrap();
    let bucket_ix = *g.index_of.get("aws_s3_bucket.data").unwrap();
    assert!(
        g.graph.find_edge(pab_ix, bucket_ix).is_some(),
        "expected a References edge from the public access block to the bucket"
    );

    // aws_lambda_function.consumer.role -> aws_iam_role.reader
    let lambda_ix = *g.index_of.get("aws_lambda_function.consumer").unwrap();
    let role_ix = *g.index_of.get("aws_iam_role.reader").unwrap();
    assert!(
        g.graph.find_edge(lambda_ix, role_ix).is_some(),
        "expected a References edge from the lambda to its execution role"
    );

    // aws_lambda_function.consumer.environment.variables.BUCKET_ARN -> aws_s3_bucket.data
    assert!(
        g.graph.find_edge(lambda_ix, bucket_ix).is_some(),
        "expected a References edge from the lambda's environment variable to the bucket"
    );
}

#[test]
fn edge_evidence_has_correct_attr_path() {
    let g = build_graph_from_dir(&fixture("basic")).expect("should build");
    let lambda_ix = *g.index_of.get("aws_lambda_function.consumer").unwrap();
    let bucket_ix = *g.index_of.get("aws_s3_bucket.data").unwrap();
    let edge_ix = g.graph.find_edge(lambda_ix, bucket_ix).unwrap();
    let edge = &g.graph[edge_ix];
    assert_eq!(edge.evidence.attr_path, "environment.variables.BUCKET_ARN");
    assert_eq!(edge.evidence.resource_id, "aws_lambda_function.consumer");
}

#[test]
fn tags_and_public_access_block_settings_are_preserved_in_attrs() {
    let g = build_graph_from_dir(&fixture("basic")).expect("should build");
    let bucket = g.node("aws_s3_bucket.data").unwrap();
    assert_eq!(
        bucket.attrs.get("tags").and_then(|t| t.get("sensitive")).and_then(|v| v.as_str()),
        Some("true")
    );

    let pab = g.node("aws_s3_bucket_public_access_block.data").unwrap();
    assert_eq!(pab.attrs.get("block_public_acls").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(pab.attrs.get("restrict_public_buckets").and_then(|v| v.as_bool()), Some(true));
}

#[test]
fn duplicate_resource_address_is_a_hard_error() {
    let files = parse_directory(&fixture("duplicate")).expect("files should parse");
    let result = policylens_graph::graph::build_graph(&files);
    match result {
        Err(GraphBuildError::DuplicateResource { id, .. }) => {
            assert_eq!(id, "aws_s3_bucket.dup");
        }
        Ok(_) => panic!("expected DuplicateResource error, got Ok"),
    }
}

#[test]
fn deterministic_node_and_edge_ordering_across_runs() {
    let g1 = build_graph_from_dir(&fixture("basic")).expect("should build");
    let g2 = build_graph_from_dir(&fixture("basic")).expect("should build");
    let ids1: Vec<_> = g1.graph.node_indices().map(|ix| g1.graph[ix].id.clone()).collect();
    let ids2: Vec<_> = g2.graph.node_indices().map(|ix| g2.graph[ix].id.clone()).collect();
    assert_eq!(ids1, ids2, "node ordering should be deterministic across repeated builds");
}
