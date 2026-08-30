# SAFE (should NOT trigger any rule) -- false-positive resistance test for
# `open-security-group-to-data-store` (rule 4).
#
# The security group genuinely is open to the internet on port 443 -- a
# per-resource network scanner would correctly flag "0.0.0.0/0 ingress" on
# its own. The instance behind it runs with a role that can only read a
# public, non-sensitive documentation bucket. Rule 4 requires the chain to
# terminate at a resource with `_derived.sensitive == true`; since nothing
# sensitive is reachable from this instance's role, the chain correctly
# does not fire even though "public-facing web server" is a completely
# real (if different) finding a network-focused scanner might still want to
# raise on its own -- that's out of PolicyLens's scope (see README), not a
# false negative of the rule this test targets.

resource "aws_security_group" "web" {
  name        = "public-web-sg"
  description = "Public HTTPS web tier"

  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "public_docs" {
  bucket = "acme-public-help-docs"

  tags = {
    purpose = "public-documentation"
  }
}

resource "aws_iam_role" "web_server_role" {
  name = "web-server-role"

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

resource "aws_iam_role_policy" "web_server_docs_read" {
  name = "web-server-docs-read"
  role = aws_iam_role.web_server_role.id

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

resource "aws_iam_instance_profile" "web_server" {
  name = "web-server-instance-profile"
  role = aws_iam_role.web_server_role.name
}

resource "aws_instance" "web" {
  ami                    = "ami-0123456789abcdef0"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.web.id]
  iam_instance_profile   = aws_iam_instance_profile.web_server.name
}
