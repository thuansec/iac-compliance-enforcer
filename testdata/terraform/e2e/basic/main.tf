terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = "eu-west-1"
}

variable "env" {
  type    = string
  default = "prod"
}

resource "aws_s3_bucket" "data" {
  bucket = "example-${var.env}-data"

  tags = {
    Environment = var.env
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

module "logs" {
  source = "./modules/logs"
  prefix = var.env
}

output "data_bucket" {
  value = aws_s3_bucket.data.bucket
}
