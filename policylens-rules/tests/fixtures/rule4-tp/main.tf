resource "aws_security_group" "open" {
  name = "fixture-open-sg"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "sensitive_data" {
  bucket = "fixture-sensitive-data-r4"

  tags = {
    sensitive = "true"
  }
}

resource "aws_iam_role" "instance_role" {
  name = "fixture-instance-role"

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

resource "aws_iam_role_policy" "instance_role_access" {
  name = "fixture-instance-role-access"
  role = aws_iam_role.instance_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "${aws_s3_bucket.sensitive_data.arn}/*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "instance_profile" {
  name = "fixture-instance-profile"
  role = aws_iam_role.instance_role.name
}

resource "aws_instance" "exposed" {
  ami                    = "ami-0123456789abcdef0"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.open.id]
  iam_instance_profile   = aws_iam_instance_profile.instance_profile.name
}
