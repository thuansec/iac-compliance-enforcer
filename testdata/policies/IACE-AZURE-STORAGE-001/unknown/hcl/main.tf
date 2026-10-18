terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

variable "min_tls" {
  type = string
}

# The minimum version comes from a variable with no value: unknown, neither a pass nor a violation.
resource "azurerm_storage_account" "data" {
  name                     = "exampledata"
  resource_group_name      = "example-rg"
  location                 = "westeurope"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = var.min_tls
}
