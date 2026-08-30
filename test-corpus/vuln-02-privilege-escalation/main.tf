# VULNERABLE (should trigger: iam-role-self-privilege-escalation).
#
# A role trusts any principal within the same wildcard-scoped condition
# (modeled here the same way as module 1: Principal.AWS = "*", the
# simplest concrete case our wildcard_trust detection covers) and ALSO
# has a grant permitting iam:PutRolePolicy on itself. Whoever can assume
# this role can grant themselves arbitrary additional permissions
# afterwards -- the role's *declared* permissions (just IAM self-management)
# look unremarkable on their own, which is exactly why this needs
# cross-resource reasoning: the trust policy and the grant have to be read
# together to see the escalation path.

resource "aws_iam_role" "automation" {
  name = "automation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "*" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "self_manage" {
  name = "self-manage-permissions"
  role = aws_iam_role.automation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iam:PutRolePolicy", "iam:AttachRolePolicy"]
        Resource = aws_iam_role.automation.arn
      }
    ]
  })
}
