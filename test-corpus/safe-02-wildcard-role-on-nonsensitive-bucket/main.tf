# SAFE (should NOT trigger any rule) -- false-positive resistance test for
# `overly-permissive-role-sensitive-access` (rule 2).
#
# This module has the "overly permissive" half of rule 2's pattern --a role
# with a wildcard-scoped `s3:*` grant -- which a naive single-resource IAM
# scanner would likely flag on its own ("this role has s3:* -- too broad!").
# But the target bucket is a public asset bucket with no sensitivity tag at
# all: static website assets meant to be world-readable. Rule 2 requires
# BOTH the wildcard grant AND `_derived.sensitive == true` on the target;
# since this bucket was never tagged sensitive, the chain correctly does
# not fire. (Whether "wildcard grant to a non-sensitive public-assets
# bucket" is itself worth flagging as a lesser issue is a reasonable
# design question -- PolicyLens's answer, consistent with its whole
# premise, is that it should stay silent unless the *combination* with
# something sensitive is present; least-privilege-in-isolation is
# Checkov's job, not this tool's.)

resource "aws_s3_bucket" "static_assets" {
  bucket = "acme-public-website-assets"

  tags = {
    purpose = "static-website-hosting"
  }
}

resource "aws_iam_role" "asset_publisher" {
  name = "asset-publisher-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "codebuild.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "publisher_wildcard" {
  name = "publisher-wildcard-s3"
  role = aws_iam_role.asset_publisher.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:*"]
        Resource = "${aws_s3_bucket.static_assets.arn}/*"
      }
    ]
  })
}
