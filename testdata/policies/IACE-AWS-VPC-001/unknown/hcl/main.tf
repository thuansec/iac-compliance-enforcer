terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

variable "admin_cidrs" {
  type = list(string)
}

# The source comes from a variable with no value: unknown, neither a pass nor a violation.
resource "aws_security_group" "bastion" {
  name   = "bastion"
  vpc_id = "vpc-0123456789abcdef0"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.admin_cidrs
  }
}
