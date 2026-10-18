terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

# No public access block declared: AWS blocks public access on new buckets by default.
resource "aws_s3_bucket" "reports" {
  bucket = "example-reports"
}
