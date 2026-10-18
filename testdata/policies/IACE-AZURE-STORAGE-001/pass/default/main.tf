terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

# min_tls_version unset: TLS1_2 is the default on azurerm 4.x and 5.x.
resource "azurerm_storage_account" "data" {
  name                     = "exampledata"
  resource_group_name      = "example-rg"
  location                 = "westeurope"
  account_tier             = "Standard"
  account_replication_type = "LRS"
}
