output "resource_group" {
  description = "Name of the resource group"
  value       = azurerm_resource_group.main.name
}

output "web_app_url" {
  description = "Public URL of the web tier"
  value       = "https://${azurerm_linux_web_app.web.default_hostname}"
}

output "web_app_name" {
  description = "Name of the App Service"
  value       = azurerm_linux_web_app.web.name
}

output "sql_server_fqdn" {
  description = "Fully qualified domain name of the SQL server"
  value       = azurerm_mssql_server.main.fully_qualified_domain_name
}

output "sql_database_name" {
  description = "Name of the SQL database"
  value       = azurerm_mssql_database.main.name
}

output "storage_account_name" {
  description = "Name of the storage account"
  value       = azurerm_storage_account.main.name
}

output "key_vault_name" {
  description = "Name of the Key Vault"
  value       = azurerm_key_vault.main.name
}

output "vnet_id" {
  description = "Resource ID of the virtual network"
  value       = azurerm_virtual_network.main.id
}
