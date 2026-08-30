# VULNERABLE (should trigger: unauthenticated-compute-secret-access).
#
# A Lambda permission grants invocation to `principal = "*"` with no
# `source_arn` restriction -- meaning literally anyone can invoke the
# function without authentication. Its execution role has a grant reaching
# a Secrets Manager secret. A scanner checking IAM grants in isolation
# would see "role can read a secret" and might not even flag it (reading a
# secret is often the role's legitimate job); a scanner checking Lambda
# permissions in isolation would see "public function" and flag it as a
# generic "publicly accessible compute" finding without knowing what's
# reachable behind it. Together: anyone on the internet can trigger code
# that has a path to your database credential.

resource "aws_secretsmanager_secret" "db_credentials" {
  name = "prod/db-credentials"
}

resource "aws_iam_role" "handler_role" {
  name = "public-handler-role"

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

resource "aws_iam_role_policy" "handler_secrets_access" {
  name = "handler-secrets-access"
  role = aws_iam_role.handler_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = aws_secretsmanager_secret.db_credentials.arn
      }
    ]
  })
}

resource "aws_lambda_function" "public_handler" {
  function_name = "public-webhook-handler"
  role          = aws_iam_role.handler_role.arn
  handler       = "index.handler"
  runtime       = "python3.12"
}

resource "aws_lambda_permission" "allow_anyone" {
  statement_id  = "AllowAnyoneInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.public_handler.function_name
  principal     = "*"
  # No source_arn -- nothing restricts who can call this.
}
