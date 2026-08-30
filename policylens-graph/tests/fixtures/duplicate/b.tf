resource "aws_s3_bucket" "dup" {
  bucket = "second-definition-should-error"
}
