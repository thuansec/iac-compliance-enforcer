variable "name" {}
variable "cidr" {}
variable "az" {}
variable "tier" {}
variable "tags" {}

locals {
  ports = [22, 80, 443, 5432, 6379, 8080, 8443, 9090, 9100, 3000]
  peers = [for i in range(10) : cidrsubnet("10.100.0.0/16", 8, i)]
  rules = flatten([
    for p in local.ports : [
      for c in local.peers : {
        port = p
        cidr = c
        name = "${var.name}-${p}-${replace(c, "/", "_")}"
      }
    ]
  ])
}

resource "aws_subnet" "this" {
  cidr_block        = var.cidr
  availability_zone = var.az
  tags              = merge(var.tags, { Name = var.name, Tier = var.tier })
}

resource "aws_security_group" "this" {
  name = "${var.name}-sg"
  dynamic "ingress" {
    for_each = { for r in local.rules : r.name => r }
    content {
      from_port   = ingress.value.port
      to_port     = ingress.value.port
      protocol    = "tcp"
      cidr_blocks = [ingress.value.cidr]
    }
  }
}
