resource "azurerm_service_plan" "web" {
  name                = "${local.name}-asp"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  os_type             = "Linux"
  sku_name            = "B1"
  tags                = local.tags
}

resource "azurerm_linux_web_app" "web" {
  name                = "${local.name}-app-${random_string.suffix.result}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  service_plan_id     = azurerm_service_plan.web.id
  https_only          = true
  tags                = local.tags

  site_config {
    always_on              = false
    minimum_tls_version    = "1.2"
    ftps_state             = "Disabled"
    vnet_route_all_enabled = true

    application_stack {
      docker_image_name   = "nginxdemos/hello:latest"
      docker_registry_url = "https://index.docker.io"
    }
  }

  app_settings = {
    WEBSITES_PORT       = "80"
    SQL_SERVER_FQDN     = azurerm_mssql_server.main.fully_qualified_domain_name
    SQL_DATABASE_NAME   = azurerm_mssql_database.main.name
    STORAGE_ACCOUNT_URL = azurerm_storage_account.main.primary_blob_endpoint
    KEY_VAULT_URI       = azurerm_key_vault.main.vault_uri
    SQL_PASSWORD_SECRET = "@Microsoft.KeyVault(SecretUri=${azurerm_key_vault_secret.sql_password.id})"
  }

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_app_service_virtual_network_swift_connection" "web" {
  app_service_id = azurerm_linux_web_app.web.id
  subnet_id      = azurerm_subnet.web_integration.id
}
