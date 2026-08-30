resource "aws_s3_bucket" "data" {
  bucket = "fixture-bucket"

  tags = {
    sensitive = "true"
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = false
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_iam_role" "reader" {
  name = "fixture-reader"

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

resource "aws_lambda_function" "consumer" {
  function_name = "fixture-consumer"
  role          = aws_iam_role.reader.arn
  handler       = "index.handler"
  runtime       = "python3.12"

  environment {
    variables = {
      BUCKET_ARN = aws_s3_bucket.data.arn
    }
  }
}
