terraform {
  backend "azurerm" {
    resource_group_name  = "tfstate-rg"
    storage_account_name = "tfstatevignesh001"
    container_name       = "tfstate"
    key                  = "3tier.terraform.tfstate"
  }
}
