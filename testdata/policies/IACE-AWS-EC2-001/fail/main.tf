terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

# IMDSv1 allowed explicitly.
resource "aws_instance" "optional" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"

  metadata_options {
    http_tokens = "optional"
  }
}

# Unset, and no account default requires tokens.
resource "aws_instance" "unset" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"
}
