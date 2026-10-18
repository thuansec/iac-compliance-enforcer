terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

variable "block_acls" {
  type = bool
}

# block_public_acls comes from a variable with no value: unknown, neither a pass nor a violation.
resource "aws_s3_bucket_public_access_block" "reports" {
  bucket = "example-reports"

  block_public_acls       = var.block_acls
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
