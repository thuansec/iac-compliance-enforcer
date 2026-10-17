terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

resource "aws_s3_bucket" "reports" {
  bucket = "example-reports"
}

resource "aws_s3_bucket_acl" "reports" {
  bucket = aws_s3_bucket.reports.id
  acl    = "private"
}
