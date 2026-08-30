# PolicyLens

A taint-aware Infrastructure-as-Code misconfiguration scanner for Terraform
that detects **cross-resource attack chains**, not just isolated
single-resource misconfigurations.

Architecturally, this is my Rust static-analysis pipeline (custom pattern
DSL, structural matchers, evidence grounding, 3-stage design) retargeted
from smart-contract analysis to Terraform IaC.

---

## The problem this exists to solve

Tools like Checkov, tfsec, and friends evaluate each resource in isolation:
*"this S3 bucket allows public access"* and *"this IAM role has a wildcard
principal in its trust policy"* are each reported as independent findings,
each with their own severity, each easy to triage (or dismiss) on its own.

Real breaches usually don't come from one bad resource. They come from
**chains**: a public bucket, plus a role that can write to it, plus a
trust policy that lets more than the intended principal assume that role —
each individually defensible, together a full compromise path.

Concretely, from this project's own test corpus
(`test-corpus/vuln-01-public-bucket-untrusted-role`):

```hcl
resource "aws_s3_bucket_public_access_block" "exports" {
  bucket = aws_s3_bucket.exports.id
  block_public_acls   = false   # <- a per-resource scanner flags this
  block_public_policy = false
  ...
}

resource "aws_iam_role" "cross_account_writer" {
  assume_role_policy = jsonencode({
    Statement = [{ Effect = "Allow", Principal = { AWS = "*" }, ... }]
    # <- and a per-resource scanner flags THIS, separately
  })
}

resource "aws_iam_role_policy" "writer_access" {
  role   = aws_iam_role.cross_account_writer.id
  policy = jsonencode({
    Statement = [{ Action = ["s3:PutObject", "s3:GetObject"], Resource = "${aws_s3_bucket.exports.arn}/*" }]
  })
}
```

A single-resource scanner emits two disconnected medium-priority findings.
PolicyLens emits one HIGH-severity finding: *anyone in any AWS account can
assume `cross_account_writer` and write into the publicly-exposed
`exports` bucket* — with the full evidence path connecting the three
resources.

Just as importantly: PolicyLens is built to be **quiet** when the
combination isn't actually dangerous. `test-corpus/safe-01-*` has a bucket
with a `public_access_block` resource present (which some scanners flag on
sight) and a role with the exact same `Principal.AWS = "*"` trust policy as
the vulnerable example above — but the access block actually blocks
everything, and the wildcard-trust role has no grant reaching that bucket
at all. No chain exists, so PolicyLens reports nothing. Getting this
right — not just finding real chains, but not inventing fake ones — is
treated as equally important throughout this project (see
[Test corpus](#test-corpus) and [Design decisions](#design-decisions-worth-knowing-about)).

---

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │           STAGE 1: policylens-graph       │
                    │                                           │
  .tf files  ─────► │  parser.rs   -> hcl-rs AST per file       │
                    │  expr.rs     -> Expression -> JSON,       │
                    │                 traversal extraction      │
                    │  graph.rs    -> two-pass graph builder:   │
                    │                 1) nodes (resources)      │
                    │                 2) References edges       │
                    │                    (attribute traversals) │
                    │  types.rs    -> Node / Edge / SourceRef   │
                    └───────────────────┬───────────────────────┘
                                         │  IacGraph
                                         ▼
                    ┌─────────────────────────────────────────┐
                    │           STAGE 2/3: policylens-rules      │
                    │                                           │
  rules/*.yaml ───► │  rule.rs      -> DSL schema + validation  │
                    │  predicate.rs -> where-clause mini-grammar│
                    │  classify.rs  -> AWS semantics: derived   │
                    │                  facts (_derived.public,  │
                    │                  .sensitive, .wildcard_   │
                    │                  trust, ...) + semantic   │
                    │                  edges (IamGrants,        │
                    │                  NetworkReachable,        │
                    │                  Attached) layered onto   │
                    │                  the graph                │
                    │  matcher.rs   -> bounded linear path walk │
                    │                  over the classified graph│
                    └───────────────────┬───────────────────────┘
                                         │  Vec<Finding>
                                         ▼
                    ┌─────────────────────────────────────────┐
                    │       STAGE 4: policylens-rules::report    │
                    │                                           │
                    │  scoring.rs -> severity = f(rule base,    │
                    │                chain length, sensitivity, │
                    │                exposure), fully explained │
                    │  report.rs  -> evidence-grounded JSON +   │
                    │                human-readable rendering   │
                    └───────────────────┬───────────────────────┘
                                         │
                                         ▼
                    ┌─────────────────────────────────────────┐
                    │              policylens-cli                │
                    │  `policylens scan <dir>` -> stdout report │
                    │                           + report.json   │
                    └─────────────────────────────────────────┘
```

Three crates, deliberately separated so each stage is independently
testable and independently explainable:

- **`policylens-graph`** knows nothing about AWS semantics — it turns HCL
  into a generic node/edge graph. This is the only crate that touches
  `hcl-rs`.
- **`policylens-rules`** owns the DSL, the AWS-specific classification
  logic, the matcher, and the report/scoring. This is where "what counts
  as public / sensitive / over-permissive" actually lives.
- **`policylens-cli`** is a thin binary wiring the two together.

---

## Running it

```bash
# From the workspace root:
cargo run -p policylens-cli -- scan test-corpus/vuln-01-public-bucket-untrusted-role
```

This prints a human-readable report to stdout and writes
`policylens-report.json` (structured, for CI) to the current directory.

```
PolicyLens scan: test-corpus/vuln-01-public-bucket-untrusted-role
  4 resource(s), 4 edge(s), 2 unresolved attribute(s)

1 finding(s):
  HIGH: 1

[1] HIGH -- Publicly accessible storage is writable by a role with untrusted trust policy (score 78)
  rule: public-storage-writable-by-untrusted-role
  why this severity: base 70 (High) − hop penalty 0 (0 extra hop(s) beyond the first, capped at 20)
    + sensitivity bonus 0 (no sensitive-tagged resource in chain) + exposure bonus 8
    (chain includes a publicly-reachable entry point) = 78 -> HIGH
  chain (1 hop(s)):
    aws_iam_role.cross_account_writer
      --[IamGrants]--> aws_s3_bucket.exports
          evidence: aws_iam_role.cross_account_writer (via aws_iam_role_policy.writer_access,
            statement 0) is granted ["s3:PutObject", "s3:GetObject"] on aws_s3_bucket.exports
            (test-corpus/.../main.tf, attribute `policy.Statement[0]`)
```

Run the full test suite:

```bash
cargo test --workspace
```

Inspect the raw graph for any directory (debugging aid, not part of the
public CLI contract):

```bash
cargo run -p policylens-cli -- debug-graph <dir> [--classified]
```

---

## The rule DSL

Rules live in `rules/*.yaml` as **linear graph-path patterns**: alternating
node-matchers and edge-matchers. No branching, no general subgraph
matching — every one of the five built-in rules is expressible as a
straight-line path, and keeping the DSL to that shape is what keeps the
matcher a simple bounded walk instead of a general (and potentially
expensive) isomorphism search.

```yaml
id: overly-permissive-role-sensitive-access
title: "IAM role has wildcard-scoped access to a sensitive resource"
severity_base: medium        # critical | high | medium | low
max_total_hops: 1             # hard cap the engine enforces regardless of path length
path:
  - node:
      kind: IamRole            # matches types::ResourceKind variant name,
      bind: role                # or the raw tf_type string for unmodeled kinds
  - edge:
      kind: IamGrants           # References | IamTrust | IamGrants | Attached | NetworkReachable
      where: "_derived.grants_wildcard == true"
  - node:
      kind: S3Bucket
      where: "_derived.sensitive == true"
      bind: sensitive_bucket
```

### The `where:` mini-grammar

```
predicate := clause (' && ' clause)*
clause    := path op literal | path 'exists' | path 'not exists' | path 'contains' literal
path      := ident ('.' ident | '[' int ']')*
op        := '==' | '!=' | '>' | '>=' | '<' | '<='
literal   := 'true' | 'false' | number | '"quoted string"'
```

Deliberately AND-only, no OR, no parentheses. Every rule so far is
expressible as a conjunction of simple comparisons — the actual complexity
of deciding "is this bucket public" lives in `classify.rs` as a computed
`_derived.public` boolean, not inline in the DSL. If a future rule needs
OR-of-clauses, the honest options are (a) split it into two rules, or (b)
extend the grammar deliberately, not backing into a general expression
language by accretion (explicitly out of scope per this project's brief).

### Adding a new rule

1. If your rule needs a fact that isn't already computed (say,
   `_derived.encrypted` on an S3 bucket), add it in
   `policylens-rules/src/classify.rs` — follow the pattern of
   `derive_s3_bucket_facts` / `derive_iam_role_trust_facts`: read raw
   `node.attrs`, write a boolean under `node.attrs["_derived"]`, document
   *why* the fact means what you say it means.
2. If your rule needs a new *edge* kind, add a variant to `EdgeKind` in
   `policylens-graph/src/types.rs` and a classification function in
   `classify.rs` that emits it (see `compute_iam_grant_edges` /
   `compute_network_reachable_edges` for the pattern: read existing
   `References` edges + node attrs, emit new semantic edges).
3. Write the rule YAML in `rules/`. It's validated at load time — path
   must start/end on a node step, must strictly alternate, hop budgets
   must be satisfiable — so a malformed rule fails fast with a specific
   error rather than silently matching nothing.
4. Add at least one vulnerable fixture and one "looks-suspicious-but-safe"
   fixture (see `policylens-rules/tests/rule_coverage.rs` for the pattern
   used for rules 2 and 4, which don't have a dedicated top-level
   `test-corpus/` module) and assert the exact expected `rule_id` set.

---

## Severity scoring

```
score = base(severity_base) − hop_penalty + sensitivity_bonus + exposure_bonus
```

clamped to `0..=100`, then mapped to a label (`>=85` Critical, `>=65`
High, `>=40` Medium, else Low). Full rationale for every term lives in
`policylens-rules/src/scoring.rs`; summary:

- **`base`**: `critical=90, high=70, medium=50, low=30` — the rule
  author's own judgment of how dangerous this *class* of chain is,
  declared per-rule.
- **`hop_penalty`**: `5 per edge beyond the first, capped at 20`. Directly
  implements "shorter chains to sensitive data score higher than
  long/improbable ones": a longer chain needs more independent conditions
  to hold simultaneously, so it's less certain to be exploitable exactly
  as found, even when every edge is real. Capped so a long-but-certain
  chain can't be scored as trivial.
- **`sensitivity_bonus` (+10)**: any node in the chain tagged
  `sensitive = true`.
- **`exposure_bonus` (+8)**: any node in the chain is directly
  internet-reachable (`_derived.public`, `.publicly_invokable`, or
  `.open_ingress`) — a chain with a public entry point needs no prior
  foothold, unlike one only reachable from inside the account.

Every finding's report includes the fully-expanded explanation string
(see the CLI output example above), so "why is this a 78" is always
answerable from the report itself.

---

## Test corpus

`test-corpus/` — 8 modules, each with a comment explaining exactly what
it's testing and why:

| Module | Category | Verifies |
|---|---|---|
| `vuln-01-public-bucket-untrusted-role` | vulnerable | rule 1 true positive |
| `vuln-02-privilege-escalation` | vulnerable | rule 5 true positive (self-loop pattern) |
| `vuln-03-unauthenticated-lambda-secret-access` | vulnerable | rule 3 true positive |
| `safe-01-public-bucket-but-locked-down-role` | looks-suspicious-but-safe | rule 1 FP resistance (PAB present but blocks everything; wildcard-trust role has no grant to the bucket) |
| `safe-02-wildcard-role-on-nonsensitive-bucket` | looks-suspicious-but-safe | rule 2 FP resistance (wildcard grant exists, target isn't sensitive) |
| `safe-03-open-sg-instance-no-sensitive-access` | looks-suspicious-but-safe | rule 4 FP resistance (SG genuinely open, instance role reaches nothing sensitive) |
| `zero-01-single-private-bucket` | zero-issue | no findings out of nothing |
| `zero-02-least-privilege-role` | zero-issue | properly-scoped trust + properly-scoped grant to sensitive data is not, alone, a chain |

Rules 2 and 4 additionally have dedicated true-positive fixtures under
`policylens-rules/tests/fixtures/` (`rule2-tp`, `rule4-tp`), since the
top-level corpus only needed "at least 3" vulnerable modules but the test
*suite* needs true-positive coverage for all 5 rules.

All 8 corpus modules, both extra TP fixtures, and every graph-construction
and evidence-accuracy claim in this README are enforced by
`cargo test --workspace` (29 tests total, see
`policylens-rules/tests/corpus.rs` and `rule_coverage.rs`) — nothing here
is just asserted in prose.

---

## Design decisions worth knowing about

- **YAML for rule structure, a small hand-parsed grammar for `where:`
  predicates only.** YAML's list/map syntax maps directly onto "alternating
  typed steps," so a custom grammar there would just be reinventing YAML
  with extra parsing code. The one genuinely new piece of syntax
  (predicates) is kept deliberately minimal.
- **Edge direction is actor → target**, not "left-to-right as read in the
  rule file." `IamGrants` edges point from the role that *has* the grant to
  the resource it can act on. This bit me once during development (see the
  Stage 3 notes in project history): rule 1 was originally written
  bucket-first and silently matched nothing until the path was reordered
  to match the actual edge direction. Worth knowing if you're writing a new
  rule and it isn't matching.
- **`Instance -> IamInstanceProfile -> IamRole` is collapsed into one
  synthetic `Attached` edge** (`classify.rs::compute_attached_edges`)
  rather than making rule paths spell out the profile hop. This is a
  deliberate ergonomic simplification, not a claim that PolicyLens models
  instance profiles as a first-class concept.
- **A missing `where:` path evaluates to `false`, not an error.** Combined
  with unresolved-interpolation tracking (below), "checked and it's fine"
  and "couldn't tell" stay distinguishable throughout the pipeline rather
  than collapsing into a single "no finding" bucket.
- **`hcl-rs` is pinned to `0.14.3`** (with `pest`/`pest_meta`/`pest_derive`
  further pinned to `2.7.15`), forced by this environment only having
  rustc 1.75 available with no network path to a newer toolchain. This
  version predates hcl-rs's source-span support, which is *why* evidence
  grounding is `(file, resource_id, attribute_path)` rather than exact
  line numbers — see Limitations. If you have a modern toolchain, bumping
  `hcl-rs` and re-adding span-based evidence would be a natural
  improvement, not a redesign.

---

## Limitations (honest, not aspirational)

- **AWS only** — S3, IAM, Lambda, EC2 security groups/instances. No
  GCP/Azure, no RDS, no VPC-level networking beyond security group
  ingress. This is a deliberate scope decision (per the project brief),
  not a partial implementation of something broader.
- **No Terraform module traversal.** Only root-level `resource` blocks in
  a flat, non-recursive directory listing are parsed. `module "x" {
  source = ... }` blocks are not followed. No remote state, no
  `terraform.tfstate` reconciliation — this is pure static source
  analysis.
- **No variable/expression evaluation.** `var.x`, unresolved `for_each`,
  function calls other than `jsonencode(...)`, and generally anything that
  isn't a literal or a direct resource-to-resource traversal is recorded
  as an explicit `"unresolved:..."` marker rather than guessed at. The CLI
  reports a count of resources with at least one unresolved attribute so
  this is visible, not silent. This is the single biggest source of
  potential false negatives: a chain that only exists once a variable is
  substituted with its real value won't be found.
- **No exact source line numbers.** Evidence is grounded at
  `(file, resource_id, attribute_path)` granularity — see the `hcl-rs`
  pinning note above.
- **IAM policy statement matching is best-effort for non-`jsonencode`
  authoring styles.** Policies written via `jsonencode({...})` (or plain
  HCL objects) get precise per-statement resource resolution. Policies
  written as a single interpolated string
  (`policy = "{\"Statement\":[...${ref}...]}"`) without `jsonencode` fall
  back to "any Resource reference anywhere in this policy," which can
  attribute a grant's actions to the wrong statement if a policy holder
  has multiple statements written that way. `jsonencode(...)` is by far
  the more common idiom, so this is a narrow gap, but it's a real one.
- **`sensitive` and "public" are conventions this tool defines, not AWS
  concepts.** `sensitive` keys off a `tags.sensitive` (case-insensitive)
  truthy value; a real deployment would want this tuned to an
  organization's actual tagging standard. "Public" for S3 buckets uses
  AWS's own since-2023 default-private behavior (no
  `public_access_block`/ACL resource pointed at a bucket ⇒ not public);
  this is accurate for current AWS defaults but would be wrong for very
  old accounts/buckets that predate that default and never had a block
  applied.
- **Action-based heuristics, not full IAM semantics.** `grants_write`,
  `grants_wildcard`, and `grants_iam_escalation` are substring/set-based
  heuristics over action names (see `classify.rs`'s documented marker
  lists), not a complete model of AWS's IAM action namespace or of
  resource-based policy evaluation (deny-overrides-allow across multiple
  policies, permission boundaries, SCPs, etc. are not modeled).
- **Duplicate resource addresses are a hard parse error** by design (see
  Stage 1 discussion) — this means PolicyLens cannot currently scan a
  directory containing multiple independent Terraform root modules that
  happen to reuse the same resource names; point it at one root module at
  a time.
- **CI's lint step is unverified in this delivery.** The sandbox this was
  built in has no network path to install `rustup`/`clippy`/`rustfmt`
  (only a small domain allowlist, sufficient for crates.io but not
  `static.rust-lang.org`), so while `cargo build --workspace --all-targets`
  produces zero warnings, the `cargo clippy -- -D warnings` and
  `cargo fmt --check` steps in `.github/workflows/ci.yml` have not
  actually been run end-to-end — only written and reasoned about. First
  real CI run may surface formatting or clippy issues that need a
  follow-up commit.
