//! Turns hcl-rs `Expression` trees into two things every downstream stage
//! needs:
//!
//! 1. A `serde_json::Value` snapshot of the resource's attributes, for the
//!    rule engine's `where:` predicates to query (see `expr_to_json`).
//! 2. A flat list of "this attribute path traverses into resource
//!    `<type>.<name>`" facts, which is how Stage 1 discovers `References`
//!    edges without knowing anything about IAM/S3/networking semantics
//!    (see `collect_traversals`).
//!
//! Terraform identifiers that are never resource references -- `var`,
//! `local`, `data`, `each`, `count`, `self`, `path`, `terraform`, `module` --
//! are filtered out of (2) by `RESERVED_ROOTS`.

use hcl::expr::{Expression, ObjectKey, Traversal, TraversalOperator};
use serde_json::{Map, Value};

/// Identifiers that begin a traversal but are never a `<resource_type>.
/// <resource_name>` reference. Anything else is treated as a candidate
/// resource reference and resolved against the graph's known node ids;
/// traversals that don't resolve to a real node are simply dropped (with a
/// debug-log style note) rather than fabricating a dangling edge.
pub const RESERVED_ROOTS: &[&str] = &[
    "var", "local", "data", "each", "count", "self", "path", "terraform", "module",
];

/// One discovered "attribute at `attr_path` traverses into `target_id`"
/// fact, target_id being a candidate `"<type>.<name>"` string that the
/// caller still needs to check against the actual node table.
#[derive(Debug, Clone)]
pub struct TraversalRef {
    pub attr_path: String,
    pub target_id: String,
    /// The full dotted path as written, e.g. `"aws_s3_bucket.data.arn"` --
    /// kept for evidence text even though only the first two segments
    /// (`target_id`) matter for edge resolution.
    pub full_path: String,
}

/// Recursively walk `expr` collecting every `Traversal` whose root variable
/// looks like a resource reference. `attr_path` is the dotted path of the
/// attribute currently being visited (for evidence).
pub fn collect_traversals(expr: &Expression, attr_path: &str, out: &mut Vec<TraversalRef>) {
    match expr {
        Expression::Traversal(t) => {
            if let Some(full_path) = traversal_root_and_path(t) {
                let mut segments = full_path.split('.');
                if let (Some(root), Some(name)) = (segments.next(), segments.next()) {
                    if !RESERVED_ROOTS.contains(&root) {
                        out.push(TraversalRef {
                            attr_path: attr_path.to_string(),
                            target_id: format!("{root}.{name}"),
                            full_path: full_path.clone(),
                        });
                    }
                }
            }
            // A traversal's base expression can itself contain nested
            // traversals/func calls (rare in Terraform, but be safe).
            collect_traversals(&t.expr, attr_path, out);
        }
        Expression::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                collect_traversals(item, &format!("{attr_path}[{i}]"), out);
            }
        }
        Expression::Object(obj) => {
            for (k, v) in obj.iter() {
                let key = object_key_to_string(k);
                let child_path = if attr_path.is_empty() {
                    key
                } else {
                    format!("{attr_path}.{key}")
                };
                collect_traversals(v, &child_path, out);
            }
        }
        Expression::FuncCall(call) => {
            for (i, arg) in call.args.iter().enumerate() {
                collect_traversals(arg, &format!("{attr_path}/arg{i}"), out);
            }
        }
        Expression::Parenthesis(inner) => collect_traversals(inner, attr_path, out),
        Expression::TemplateExpr(t) => {
            // Interpolations like `"${aws_s3_bucket.data.arn}/*"` embed a
            // full sub-expression inside a string literal. Parse the
            // template into its literal/interpolation/directive elements
            // and walk each interpolated expression the same way we'd walk
            // any other attribute value. A malformed/unparseable template
            // (rare) is skipped rather than treated as an error, since
            // template parsing failures here shouldn't abort graph
            // construction for the whole file.
            if let Ok(template) = hcl::template::Template::from_expr(t) {
                for element in template.elements() {
                    collect_template_element(element, attr_path, out);
                }
            }
        }
        Expression::Conditional(cond) => {
            collect_traversals(&cond.true_expr, attr_path, out);
            collect_traversals(&cond.false_expr, attr_path, out);
        }
        Expression::Operation(_) => {
            // Unary/binary operations (e.g. `!local.flag`) essentially never
            // carry resource traversals in practice; not walked in v1.
        }
        Expression::ForExpr(_) => {
            // `for` expressions over resource collections are rare in flat
            // (non-module) root configs; not walked in v1 (see README limitations).
        }
        _ => {}
    }
}

/// Render a `Traversal`'s root + `GetAttr` operators as a dotted string,
/// e.g. `aws_s3_bucket.foo.arn`. Returns `None` if any operator is an
/// index/splat we can't render as a clean dotted path (index expressions
/// like `foo[count.index]` still count as a reference to `foo`, so we
/// truncate at the first non-GetAttr operator rather than discarding the
/// whole traversal).
fn traversal_root_and_path(t: &Traversal) -> Option<String> {
    let root = match &t.expr {
        Expression::Variable(v) => v.as_str().to_string(),
        _ => return None,
    };
    let mut parts = vec![root];
    for op in &t.operators {
        match op {
            TraversalOperator::GetAttr(id) => parts.push(id.to_string()),
            _ => break, // stop at first index/splat; keep what we have so far
        }
    }
    if parts.len() < 2 {
        return None;
    }
    Some(parts.join("."))
}

/// Walk one `Element` of a parsed `Template` (see `TemplateExpr` handling in
/// `collect_traversals`). Directives (`%{ for ... }`, `%{ if ... }`) are
/// walked recursively into their nested templates so a traversal inside a
/// `for`/`if` body inside a heredoc is still found.
fn collect_template_element(
    element: &hcl::template::Element,
    attr_path: &str,
    out: &mut Vec<TraversalRef>,
) {
    use hcl::template::{Directive, Element};
    match element {
        Element::Literal(_) => {}
        Element::Interpolation(interp) => collect_traversals(&interp.expr, attr_path, out),
        Element::Directive(Directive::If(if_dir)) => {
            collect_traversals(&if_dir.cond_expr, attr_path, out);
            for e in if_dir.true_template.elements() {
                collect_template_element(e, attr_path, out);
            }
            if let Some(false_template) = &if_dir.false_template {
                for e in false_template.elements() {
                    collect_template_element(e, attr_path, out);
                }
            }
        }
        Element::Directive(Directive::For(for_dir)) => {
            collect_traversals(&for_dir.collection_expr, attr_path, out);
            for e in for_dir.template.elements() {
                collect_template_element(e, attr_path, out);
            }
        }
    }
}

fn object_key_to_string(k: &ObjectKey) -> String {
    match k {
        ObjectKey::Identifier(id) => id.to_string(),
        ObjectKey::Expression(e) => e.to_string(),
        _ => "<unknown-key>".to_string(),
    }
}

/// Convert an `Expression` into a `serde_json::Value`, returning also
/// whether the conversion had to fall back to rendering an unresolved
/// interpolation as an opaque string (a `var.x`, a traversal, a function
/// call PolicyLens doesn't special-case, etc.).
///
/// Design note: `jsonencode(...)` is special-cased because it is the
/// idiomatic way to write IAM policy documents in Terraform, and rules need
/// the *structured* policy (statements, actions, principals), not an opaque
/// string -- unwrapping it here means the rule engine never has to know
/// jsonencode exists.
pub fn expr_to_json(expr: &Expression) -> (Value, bool) {
    match expr {
        Expression::Null => (Value::Null, false),
        Expression::Bool(b) => (Value::Bool(*b), false),
        Expression::Number(n) => {
            let v = if let Some(i) = n.as_i64() {
                Value::from(i)
            } else if let Some(f) = n.as_f64() {
                Value::from(f)
            } else {
                Value::from(n.to_string())
            };
            (v, false)
        }
        Expression::String(s) => (Value::String(maybe_parse_embedded_json(s)), false),
        Expression::Array(items) => {
            let mut unresolved = false;
            let arr = items
                .iter()
                .map(|i| {
                    let (v, u) = expr_to_json(i);
                    unresolved |= u;
                    v
                })
                .collect();
            (Value::Array(arr), unresolved)
        }
        Expression::Object(obj) => {
            let mut unresolved = false;
            let mut map = Map::new();
            for (k, v) in obj.iter() {
                let (jv, u) = expr_to_json(v);
                unresolved |= u;
                map.insert(object_key_to_string(k), jv);
            }
            (Value::Object(map), unresolved)
        }
        Expression::TemplateExpr(t) => {
            let rendered = t.to_string();
            // A template with no interpolation renders back to plain text;
            // one that still contains `${` means we couldn't resolve an
            // embedded reference (e.g. a heredoc bucket policy that embeds
            // `${aws_s3_bucket.data.arn}`).
            let unresolved = rendered.contains("${");
            (Value::String(maybe_parse_embedded_json(&rendered)), unresolved)
        }
        Expression::FuncCall(call) if call.name.as_str() == "jsonencode" && call.args.len() == 1 => {
            // Unwrap jsonencode(...) to its structured argument directly.
            expr_to_json(&call.args[0])
        }
        Expression::FuncCall(call) => (
            Value::String(format!("unresolved:call:{}", call.to_string_lossy_stub())),
            true,
        ),
        Expression::Variable(v) => (Value::String(format!("unresolved:var:{}", v.as_str())), true),
        Expression::Traversal(_) => (
            Value::String(format!("unresolved:ref:{expr}")),
            true,
        ),
        Expression::Parenthesis(inner) => expr_to_json(inner),
        Expression::Conditional(_)
        | Expression::Operation(_)
        | Expression::ForExpr(_)
        | Expression::Raw(_) => (Value::String(format!("unresolved:expr:{expr}")), true),
        _ => (Value::String(format!("unresolved:expr:{expr}")), true),
    }
}

/// If `s` looks like a JSON object/array (common for `assume_role_policy`,
/// `policy`, etc. written as raw/heredoc JSON strings rather than
/// `jsonencode(...)`), parse it and re-embed it as structured JSON so rules
/// can query it uniformly regardless of which style the author used.
/// Falls back to returning the original string unchanged if it doesn't
/// parse -- this is a best-effort convenience, never a hard requirement.
fn maybe_parse_embedded_json(s: &str) -> String {
    // We keep the return type String here and let the caller decide; actual
    // structured embedding happens in a post-pass (see graph.rs
    // `promote_embedded_json`) because changing this function's return type
    // to Value would complicate every call site above for the common case.
    s.to_string()
}

trait FuncCallStub {
    fn to_string_lossy_stub(&self) -> String;
}
impl FuncCallStub for hcl::expr::FuncCall {
    fn to_string_lossy_stub(&self) -> String {
        self.name.to_string()
    }
}
