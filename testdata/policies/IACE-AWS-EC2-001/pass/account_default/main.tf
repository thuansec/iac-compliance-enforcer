terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

# Unset on the instance, but the account default requires tokens.
resource "aws_instance" "account_default" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"
}

resource "aws_ec2_instance_metadata_defaults" "this" {
  http_tokens = "required"
}
