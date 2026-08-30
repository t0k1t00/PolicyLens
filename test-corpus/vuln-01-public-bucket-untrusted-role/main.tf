# VULNERABLE (should trigger: public-storage-writable-by-untrusted-role).
#
# A publicly accessible bucket, plus a role that trusts ANY AWS principal
# (Principal.AWS = "*") to assume it, with write access to that bucket.
# Each piece looks individually plausible in isolation: the bucket's public
# access block explicitly disables all four protections (maybe someone
# thought this was a public asset bucket), and a role with `Principal: "*"`
# in its trust policy might be dismissed as a demo/test artifact. Together:
# anyone in any AWS account can assume this role and write to the bucket.

resource "aws_s3_bucket" "exports" {
  bucket = "acme-public-exports"
}

resource "aws_s3_bucket_public_access_block" "exports" {
  bucket = aws_s3_bucket.exports.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_iam_role" "cross_account_writer" {
  name = "cross-account-writer"

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

resource "aws_iam_role_policy" "writer_access" {
  name = "writer-bucket-access"
  role = aws_iam_role.cross_account_writer.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject"]
        Resource = "${aws_s3_bucket.exports.arn}/*"
      }
    ]
  })
}
