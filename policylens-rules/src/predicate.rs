//! The `where:` predicate mini-grammar used inside rule DSL node/edge
//! matchers.
//!
//! # Grammar
//!
//! ```text
//! predicate := clause (' && ' clause)*
//! clause    := path op literal
//!            | path 'exists'
//!            | path 'not' 'exists'
//!            | path 'contains' literal
//! path      := ident ('.' ident | '[' int ']')*
//! op        := '==' | '!=' | '>' | '>=' | '<' | '<='
//! literal   := 'true' | 'false' | number | '"' ... '"'
//! ```
//!
//! Deliberately **AND-only, no OR, no parentheses, no negation beyond
//! `not exists`**. Every one of PolicyLens's five built-in rules is
//! expressible with a conjunction of simple comparisons once the
//! classification pass (Stage 3) has computed derived boolean facts like
//! `_derived.public` or `_derived.wildcard_trust` -- the *complexity* of
//! "is this bucket public" lives in Rust code that computes that fact once,
//! not in a DSL expression that would need OR/precedence to ask the
//! question inline. If a future rule genuinely needs OR-of-clauses, the
//! honest options are (a) split it into two rules, or (b) extend this
//! grammar deliberately -- not backing into a general expression language
//! by accretion.
//!
//! `path` is resolved against a `serde_json::Value` (a node's `attrs`
//! merged with `_derived`, or an edge's own derived-fact object).

use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    Bool(bool),
    Number(f64),
    String(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    Contains,
    Exists,
    NotExists,
}

#[derive(Debug, Clone)]
pub struct Clause {
    pub path: Vec<PathSeg>,
    pub op: Op,
    pub literal: Option<Literal>,
}

#[derive(Debug, Clone)]
pub enum PathSeg {
    Field(String),
    Index(usize),
}

#[derive(Debug, Clone)]
pub struct Predicate {
    pub clauses: Vec<Clause>,
    pub source: String,
}

#[derive(Debug, Error)]
pub enum PredicateParseError {
    #[error("empty predicate")]
    Empty,
    #[error("could not parse clause `{0}`")]
    BadClause(String),
    #[error("unterminated string literal in clause `{0}`")]
    UnterminatedString(String),
    #[error("empty path in clause `{0}`")]
    EmptyPath(String),
}

pub fn parse(source: &str) -> Result<Predicate, PredicateParseError> {
    let trimmed = source.trim();
    if trimmed.is_empty() {
        return Err(PredicateParseError::Empty);
    }
    let mut clauses = Vec::new();
    for raw_clause in split_top_level_and(trimmed) {
        clauses.push(parse_clause(raw_clause.trim())?);
    }
    Ok(Predicate {
        clauses,
        source: source.to_string(),
    })
}

/// Split on `&&`, respecting quoted strings (so a literal containing `&&`
/// inside quotes, however unlikely, isn't mis-split).
fn split_top_level_and(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut in_string = false;
    let bytes = s.as_bytes();
    let mut last = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => in_string = !in_string,
            b'&' if !in_string && i + 1 < bytes.len() && bytes[i + 1] == b'&' => {
                parts.push(&s[last..i]);
                i += 1;
                last = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    parts.push(&s[last..]);
    parts
}

fn parse_clause(clause: &str) -> Result<Clause, PredicateParseError> {
    let err = || PredicateParseError::BadClause(clause.to_string());

    // `not exists` / `exists` (no literal / operator on the right).
    if let Some(path_str) = clause.strip_suffix("not exists") {
        let path = parse_path(path_str.trim()).ok_or_else(err)?;
        return Ok(Clause {
            path,
            op: Op::NotExists,
            literal: None,
        });
    }
    if let Some(path_str) = clause.strip_suffix("exists") {
        let path = parse_path(path_str.trim()).ok_or_else(err)?;
        return Ok(Clause {
            path,
            op: Op::Exists,
            literal: None,
        });
    }

    // Binary operators, longest-first so `==` isn't mis-split on a lone `=`.
    const OPS: &[(&str, Op)] = &[
        ("==", Op::Eq),
        ("!=", Op::Ne),
        (">=", Op::Ge),
        ("<=", Op::Le),
        (">", Op::Gt),
        ("<", Op::Lt),
        (" contains ", Op::Contains),
    ];
    for (token, op) in OPS {
        if let Some(idx) = clause.find(token) {
            let path_str = clause[..idx].trim();
            let lit_str = clause[idx + token.len()..].trim();
            let path = parse_path(path_str).ok_or_else(err)?;
            let literal = parse_literal(lit_str)
                .ok_or_else(|| PredicateParseError::BadClause(clause.to_string()))?;
            return Ok(Clause {
                path,
                op: op.clone(),
                literal: Some(literal),
            });
        }
    }

    Err(err())
}

fn parse_path(s: &str) -> Option<Vec<PathSeg>> {
    if s.is_empty() {
        return None;
    }
    let mut segs = Vec::new();
    for raw in s.split('.') {
        if let Some(idx_part) = raw.strip_suffix(']') {
            let (field, idx) = idx_part.split_once('[')?;
            if !field.is_empty() {
                segs.push(PathSeg::Field(field.to_string()));
            }
            segs.push(PathSeg::Index(idx.parse().ok()?));
        } else {
            segs.push(PathSeg::Field(raw.to_string()));
        }
    }
    if segs.is_empty() {
        None
    } else {
        Some(segs)
    }
}

fn parse_literal(s: &str) -> Option<Literal> {
    if s == "true" {
        return Some(Literal::Bool(true));
    }
    if s == "false" {
        return Some(Literal::Bool(false));
    }
    if let Some(inner) = s.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
        return Some(Literal::String(inner.to_string()));
    }
    if let Ok(n) = s.parse::<f64>() {
        return Some(Literal::Number(n));
    }
    None
}

/// Resolve a `path` against `root`, returning `None` if any segment is
/// missing (a missing path is not an error -- `exists`/`not exists` rely on
/// this, and a comparison against a missing path simply evaluates to
/// `false` rather than aborting the whole rule).
fn resolve<'a>(root: &'a Value, path: &[PathSeg]) -> Option<&'a Value> {
    let mut cur = root;
    for seg in path {
        cur = match seg {
            PathSeg::Field(f) => cur.get(f)?,
            PathSeg::Index(i) => cur.get(i)?,
        };
    }
    Some(cur)
}

pub fn evaluate(predicate: &Predicate, root: &Value) -> bool {
    predicate.clauses.iter().all(|c| evaluate_clause(c, root))
}

fn evaluate_clause(clause: &Clause, root: &Value) -> bool {
    let found = resolve(root, &clause.path);
    match clause.op {
        Op::Exists => found.is_some(),
        Op::NotExists => found.is_none(),
        Op::Contains => match (found, &clause.literal) {
            (Some(Value::Array(arr)), Some(lit)) => arr.iter().any(|v| value_eq_literal(v, lit)),
            (Some(Value::String(s)), Some(Literal::String(needle))) => s.contains(needle.as_str()),
            _ => false,
        },
        Op::Eq | Op::Ne | Op::Gt | Op::Ge | Op::Lt | Op::Le => {
            let (Some(v), Some(lit)) = (found, &clause.literal) else {
                return false;
            };
            match clause.op {
                Op::Eq => value_eq_literal(v, lit),
                Op::Ne => !value_eq_literal(v, lit),
                Op::Gt | Op::Ge | Op::Lt | Op::Le => {
                    let (Some(a), Literal::Number(b)) = (v.as_f64(), lit) else {
                        return false;
                    };
                    match clause.op {
                        Op::Gt => a > *b,
                        Op::Ge => a >= *b,
                        Op::Lt => a < *b,
                        Op::Le => a <= *b,
                        _ => unreachable!(),
                    }
                }
                _ => unreachable!(),
            }
        }
    }
}

fn value_eq_literal(v: &Value, lit: &Literal) -> bool {
    match (v, lit) {
        (Value::Bool(b), Literal::Bool(l)) => b == l,
        (Value::String(s), Literal::String(l)) => s == l,
        (Value::Number(n), Literal::Number(l)) => n.as_f64().map(|f| f == *l).unwrap_or(false),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn eq_bool() {
        let p = parse("_derived.public == true").unwrap();
        assert!(evaluate(&p, &json!({"_derived": {"public": true}})));
        assert!(!evaluate(&p, &json!({"_derived": {"public": false}})));
    }

    #[test]
    fn exists() {
        let p = parse("tags.sensitive exists").unwrap();
        assert!(evaluate(&p, &json!({"tags": {"sensitive": "true"}})));
        assert!(!evaluate(&p, &json!({"tags": {}})));
    }

    #[test]
    fn not_exists() {
        let p = parse("tags.sensitive not exists").unwrap();
        assert!(evaluate(&p, &json!({"tags": {}})));
        assert!(!evaluate(&p, &json!({"tags": {"sensitive": "true"}})));
    }

    #[test]
    fn contains_array() {
        let p = parse(r#"actions contains "s3:*""#).unwrap();
        assert!(evaluate(&p, &json!({"actions": ["s3:GetObject", "s3:*"]})));
        assert!(!evaluate(&p, &json!({"actions": ["s3:GetObject"]})));
    }

    #[test]
    fn and_conjunction() {
        let p = parse(r#"_derived.public == true && tags.sensitive == "true""#).unwrap();
        assert!(evaluate(
            &p,
            &json!({"_derived": {"public": true}, "tags": {"sensitive": "true"}})
        ));
        assert!(!evaluate(
            &p,
            &json!({"_derived": {"public": false}, "tags": {"sensitive": "true"}})
        ));
    }

    #[test]
    fn missing_path_is_false_not_error() {
        let p = parse("_derived.public == true").unwrap();
        assert!(!evaluate(&p, &json!({})));
    }
}
