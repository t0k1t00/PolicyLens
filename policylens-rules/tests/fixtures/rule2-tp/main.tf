resource "aws_s3_bucket" "sensitive_data" {
  bucket = "fixture-sensitive-data"

  tags = {
    sensitive = "true"
  }
}

resource "aws_iam_role" "broad_access" {
  name = "fixture-broad-access-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "broad_access_policy" {
  name = "fixture-broad-access-policy"
  role = aws_iam_role.broad_access.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:*"]
        Resource = "${aws_s3_bucket.sensitive_data.arn}/*"
      }
    ]
  })
}
