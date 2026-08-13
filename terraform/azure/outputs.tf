output "resource_group_name" {
  description = "Lab resource group name — pass to the Security Monkey as SECLAB_AZURE_RESOURCE_GROUP."
  value       = azurerm_resource_group.lab.name
}

output "location" {
  value = azurerm_resource_group.lab.location
}

output "nsg_name" {
  description = "NSG the network-exposure injector targets."
  value       = azurerm_network_security_group.lab.name
}

output "storage_account_name" {
  description = "Storage account the public-data injector targets."
  value       = azurerm_storage_account.lab.name
}

output "storage_container_name" {
  value = azurerm_storage_container.lab.name
}

output "monkey_env" {
  description = "Copy these into your .env for the Security Monkey."
  value       = <<-EOT
    SECLAB_AZURE_SUBSCRIPTION_ID=${var.subscription_id}
    SECLAB_AZURE_RESOURCE_GROUP=${azurerm_resource_group.lab.name}
    SECLAB_AZURE_NSG=${azurerm_network_security_group.lab.name}
    SECLAB_AZURE_STORAGE_ACCOUNT=${azurerm_storage_account.lab.name}
    SECLAB_PREFIX=${var.prefix}
  EOT
}
