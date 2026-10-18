terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

resource "aws_security_group" "bastion" {
  name   = "bastion"
  vpc_id = "vpc-0123456789abcdef0"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group_rule" "ssh_v6" {
  type              = "ingress"
  security_group_id = "sg-0123456789abcdef0"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  ipv6_cidr_blocks  = ["::/0"]
}

# Quoted ports: Terraform converts them to numbers.
resource "aws_vpc_security_group_ingress_rule" "quoted" {
  security_group_id = "sg-0123456789abcdef0"
  from_port         = "22"
  to_port           = "22"
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}

# A port range that contains RDP.
resource "aws_vpc_security_group_ingress_rule" "range" {
  security_group_id = "sg-0123456789abcdef0"
  from_port         = 3000
  to_port           = 4000
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}
