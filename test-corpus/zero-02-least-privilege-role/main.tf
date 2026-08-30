# ZERO ISSUES EXPECTED.
#
# A role trusted only by a specific AWS service principal (not a wildcard),
# with a narrowly-scoped read-only grant (a single named action, not `*` or
# `service:*`) to a bucket that IS tagged sensitive. This is deliberately
# the "everything done right" case: a sensitive resource exists and is
# accessed by a role, but every individual link in what could have been a
# chain is properly scoped. If PolicyLens flagged this, that would mean its
# rules are keying off "a role touches a sensitive bucket at all" rather
# than the actual dangerous combinations (wildcard trust, wildcard grants,
# public exposure) -- this module exists specifically to catch that class
# of over-eager false positive.

resource "aws_s3_bucket" "customer_pii" {
  bucket = "acme-customer-pii"

  tags = {
    sensitive = "true"
  }
}

resource "aws_s3_bucket_public_access_block" "customer_pii" {
  bucket = aws_s3_bucket.customer_pii.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_iam_role" "pii_reader" {
  name = "pii-reader-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "pii_read_only" {
  name = "pii-read-only"
  role = aws_iam_role.pii_reader.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.customer_pii.arn}/*"
      }
    ]
  })
}
