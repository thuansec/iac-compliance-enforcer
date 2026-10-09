# A VPC fanned out over 150 subnets, each a module instance with security-group rules built
# from nested for expressions over ports and CIDR blocks.
locals {
  azs = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]
  subnets = {
    for i in range(150) : "subnet-${i}" => {
      cidr = cidrsubnet("10.0.0.0/8", 8, i)
      az   = local.azs[i % length(local.azs)]
      tier = i % 4 == 0 ? "public" : "private"
    }
  }
  common_tags = {
    owner       = "platform-team"
    cost_center = "cc-1234"
    environment = "example"
  }
}

module "subnet" {
  source   = "./modules/subnet"
  for_each = local.subnets
  name     = each.key
  cidr     = each.value.cidr
  az       = each.value.az
  tier     = each.value.tier
  tags     = local.common_tags
}
