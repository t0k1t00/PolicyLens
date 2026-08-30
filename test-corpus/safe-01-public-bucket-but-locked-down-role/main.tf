# SAFE (should NOT trigger any rule) -- false-positive resistance test.
#
# This module is deliberately built to look suspicious to a naive,
# per-resource scanner: there's a public_access_block resource present at
# all (some simplistic scanners flag "has a PAB resource" as noteworthy
# regardless of its settings), and there's a role whose trust policy uses
# `Principal.AWS = "*"` (same shape as the vulnerable module 1). But:
#   1. The public access block explicitly BLOCKS all four public-access
#      vectors (all flags true) -- the bucket is not actually public.
#   2. The wildcard-trust role's only grant is read-only access to a
#      DIFFERENT, non-sensitive bucket -- there is no IamGrants edge at all
#      from this role to the "exports" bucket, so no chain exists even
#      though both individual ingredients (a PAB resource, a wildcard-trust
#      role) are present in the file.
# A scanner that pattern-matches on isolated facts ("there's a
# public-access-block resource" or "there's a role trusting *") without
# actually resolving the *combination* would risk a false positive here.

resource "aws_s3_bucket" "exports" {
  bucket = "acme-locked-down-exports"
}

resource "aws_s3_bucket_public_access_block" "exports" {
  bucket = aws_s3_bucket.exports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "public_docs" {
  bucket = "acme-public-docs"
  # No public_access_block resource at all -- but per classify.rs's
  # documented default (AWS blocks public access by default since 2023),
  # the *absence* of a PAB resource means `_derived.public` is `false`,
  # not "unknown". This exercises that default explicitly.
}

resource "aws_iam_role" "federated_reader" {
  name = "federated-reader"

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

resource "aws_iam_role_policy" "reader_access" {
  name = "reader-docs-access"
  role = aws_iam_role.federated_reader.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.public_docs.arn}/*"
      }
    ]
  })
}
