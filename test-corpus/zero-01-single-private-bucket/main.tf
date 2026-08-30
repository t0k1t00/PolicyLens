# ZERO ISSUES EXPECTED.
#
# The simplest possible case: one S3 bucket, no public access configured
# (and per classify.rs's documented default, no public_access_block
# resource means "not public," matching AWS's own default-private
# behavior), no tags at all so nothing is sensitive, and no IAM anywhere
# in the file for a chain to even start from. This confirms PolicyLens
# doesn't manufacture findings out of nothing.

resource "aws_s3_bucket" "logs" {
  bucket = "acme-internal-logs"
}
