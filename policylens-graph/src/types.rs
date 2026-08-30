//! Core data types for the PolicyLens resource graph.
//!
//! A `Node` is one Terraform `resource` block (e.g. `aws_s3_bucket.data`).
//! An `Edge` is a directed relationship discovered between two resources
//! (an attribute reference, an IAM trust relationship, a policy grant, or a
//! network-reachability link). Every edge carries `evidence`: the concrete
//! attribute path and rendered value that caused PolicyLens to draw it, so a
//! human can go verify the claim against the original `.tf` source.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The narrow set of AWS resource kinds PolicyLens understands structurally.
/// Anything else is still parsed into a generic `Node` (kind = `Other`), so
/// unsupported resource types don't break graph construction -- they just
/// don't participate in the specialized edge-classification passes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum ResourceKind {
    S3Bucket,
    S3BucketPolicy,
    S3BucketPublicAccessBlock,
    S3BucketAcl,
    IamRole,
    IamPolicy,
    IamRolePolicy,
    IamRolePolicyAttachment,
    IamInstanceProfile,
    LambdaFunction,
    LambdaPermission,
    SecurityGroup,
    SecurityGroupRule,
    Instance,
    SecretsManagerSecret,
    /// Any other `resource "<type>" "<name>"` block. `String` holds the
    /// literal Terraform type (e.g. `aws_dynamodb_table`) so rules can still
    /// pattern-match on it even without first-class support.
    Other(String),
}

impl ResourceKind {
    /// Classify a Terraform resource type string (e.g. `"aws_s3_bucket"`)
    /// into a `ResourceKind`. This is the single place new AWS resource
    /// types get "onboarded" into structural understanding.
    pub fn classify(tf_type: &str) -> ResourceKind {
        match tf_type {
            "aws_s3_bucket" => ResourceKind::S3Bucket,
            "aws_s3_bucket_policy" => ResourceKind::S3BucketPolicy,
            "aws_s3_bucket_public_access_block" => ResourceKind::S3BucketPublicAccessBlock,
            "aws_s3_bucket_acl" => ResourceKind::S3BucketAcl,
            "aws_iam_role" => ResourceKind::IamRole,
            "aws_iam_policy" => ResourceKind::IamPolicy,
            "aws_iam_role_policy" => ResourceKind::IamRolePolicy,
            "aws_iam_role_policy_attachment" => ResourceKind::IamRolePolicyAttachment,
            "aws_iam_instance_profile" => ResourceKind::IamInstanceProfile,
            "aws_lambda_function" => ResourceKind::LambdaFunction,
            "aws_lambda_permission" => ResourceKind::LambdaPermission,
            "aws_security_group" => ResourceKind::SecurityGroup,
            "aws_security_group_rule" => ResourceKind::SecurityGroupRule,
            "aws_instance" => ResourceKind::Instance,
            "aws_secretsmanager_secret" => ResourceKind::SecretsManagerSecret,
            other => ResourceKind::Other(other.to_string()),
        }
    }
}

/// Where in the source a fact came from. Note: because PolicyLens is pinned
/// to hcl-rs 0.14 (see README -- forced by the rustc 1.75 toolchain
/// available in this environment), the underlying parser does not expose
/// byte/line spans. Evidence is therefore grounded at
/// `(file, resource_id, attribute_path)` granularity, not exact line
/// numbers. This is a real, documented limitation, not a silent gap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRef {
    pub file: PathBuf,
    pub resource_id: String,
    /// Dotted/bracket attribute path within the resource block, e.g.
    /// `"environment.variables.BUCKET_ARN"` or `"ingress[0].cidr_blocks[0]"`.
    /// Empty string means "the resource block as a whole".
    pub attr_path: String,
}

/// A single Terraform resource, plus everything PolicyLens was able to
/// determine about it structurally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    /// Terraform address: `"<type>.<name>"`, globally unique within the
    /// scanned directory (duplicates are a hard parse error -- see
    /// `GraphBuildError::DuplicateResource`).
    pub id: String,
    pub tf_type: String,
    pub tf_name: String,
    pub kind: ResourceKind,
    pub file: PathBuf,
    /// The resource body, converted to JSON. Every HCL expression PolicyLens
    /// could not statically resolve (a `var.x`, an unresolved `for_each`,
    /// etc.) is rendered as a JSON string with an `"unresolved:"` prefix
    /// rather than silently dropped or guessed at -- see `expr_to_json`.
    pub attrs: serde_json::Value,
    /// True if any attribute on this node contains an unresolved
    /// interpolation. Rules and reports surface this explicitly so a
    /// "no chain found" result can be distinguished from "couldn't tell".
    pub has_unresolved_attrs: bool,
}

/// The kind of relationship an edge represents, plus enough payload for a
/// rule to pattern-match on it (e.g. "only IamGrants edges whose actions
/// contain a wildcard").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeKind {
    /// `from`'s HCL body contains an attribute expression that traverses
    /// into `to` (e.g. a Lambda's `environment.variables` referencing an S3
    /// bucket ARN). This is the generic, provider-agnostic "data flow /
    /// wiring" edge -- everything else is built on top of it or alongside
    /// it as a semantic classification.
    References,
    /// `from` (an IAM role) has an `assume_role_policy` that trusts a
    /// principal capable of assuming it. `to` is the resource that *is*
    /// or *represents* that principal when it can be resolved to a node in
    /// this graph (e.g. an `aws_lambda_function` that uses this role); for
    /// trust in an AWS service principal with no corresponding resource
    /// node, this edge is not emitted -- the trust fact instead lives on
    /// the role node's attrs for rules to read directly.
    IamTrust { principal: String },
    /// `from` (an IAM role/policy) can perform `actions` against `to`.
    IamGrants {
        actions: Vec<String>,
        effect: String,
        resource_match: String,
    },
    /// `from` is attached to / assumed by `to` (role <-> policy attachment,
    /// role <-> compute resource via instance profile or Lambda `role`).
    Attached,
    /// `from` (a security group or a resource associated with one) allows
    /// inbound network reachability to `to`.
    NetworkReachable {
        protocol: String,
        from_port: i64,
        to_port: i64,
        cidr: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub kind: EdgeKind,
    pub evidence: SourceRef,
    /// Human-readable one-liner describing exactly what triggered this
    /// edge, e.g. `"aws_lambda_function.ingest.environment.variables.BUCKET
    /// references aws_s3_bucket.data.arn"`. Rendered once at edge-creation
    /// time so Stage 3 reporting never has to re-derive it.
    pub description: String,
}
