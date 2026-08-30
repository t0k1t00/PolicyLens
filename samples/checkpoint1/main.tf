# Intentionally vulnerable sample: a public S3 bucket, an over-permissive
# IAM role trusted by Lambda, and a Lambda function that references the
# bucket in its environment variables. Individually each resource looks
# plausible; together they form a public-read/write path into a bucket
# tagged as holding sensitive data. Used only to exercise Stage 1 graph
# construction end-to-end (checkpoint), not as a rule-matching test case yet.

resource "aws_s3_bucket" "data" {
  bucket = "acme-customer-exports"

  tags = {
    sensitive = "true"
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_iam_role" "ingest_lambda" {
  name = "ingest-lambda-role"

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

resource "aws_iam_role_policy" "ingest_lambda_s3" {
  name = "ingest-lambda-s3-access"
  role = aws_iam_role.ingest_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:*"]
        Resource = "${aws_s3_bucket.data.arn}/*"
      }
    ]
  })
}

resource "aws_lambda_function" "ingest" {
  function_name = "ingest-handler"
  role          = aws_iam_role.ingest_lambda.arn
  handler       = "index.handler"
  runtime       = "python3.12"

  environment {
    variables = {
      BUCKET_NAME = aws_s3_bucket.data.bucket
      BUCKET_ARN  = aws_s3_bucket.data.arn
    }
  }
}
