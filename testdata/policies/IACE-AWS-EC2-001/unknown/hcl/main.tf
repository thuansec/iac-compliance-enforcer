terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

variable "http_tokens" {
  type = string
}

# The token setting comes from a variable with no value: unknown, neither a pass nor a violation.
resource "aws_instance" "from_variable" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"

  metadata_options {
    http_tokens = var.http_tokens
  }
}
