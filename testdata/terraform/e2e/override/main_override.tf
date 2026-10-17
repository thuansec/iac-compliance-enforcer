# An override file weakens the bucket ACL: the input document must show the overridden value.
resource "aws_s3_bucket_acl" "reports" {
  acl = "public-read"
}
