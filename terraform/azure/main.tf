#############################################
# Lab resource group — the safety boundary.
# The Security Monkey ONLY ever touches resources in this RG (scoped by name/tag).
#############################################
resource "azurerm_resource_group" "lab" {
  name     = "${var.prefix}-rg"
  location = var.location
  tags     = var.tags
}

resource "random_string" "suffix" {
  length  = 6
  upper   = false
  special = false
}

#############################################
# Network — secure baseline.
# The NSG starts LOCKED DOWN. The "network exposure" injector adds an
# inbound rule to 0.0.0.0/0; teardown removes it again.
#############################################
resource "azurerm_virtual_network" "lab" {
  name                = "${var.prefix}-vnet"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  address_space       = var.vnet_address_space
  tags                = var.tags
}

resource "azurerm_subnet" "lab" {
  name                 = "${var.prefix}-subnet"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = [var.subnet_prefix]
}

resource "azurerm_network_security_group" "lab" {
  name                = "${var.prefix}-nsg"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  tags                = var.tags

  # Deny-all inbound baseline (explicit; complements Azure's default rules).
  # NOTE: injectors will add a higher-priority ALLOW rule to simulate exposure.
  security_rule {
    name                       = "deny-all-inbound"
    priority                   = 4000
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "lab" {
  subnet_id                 = azurerm_subnet.lab.id
  network_security_group_id = azurerm_network_security_group.lab.id
}

#############################################
# Storage — secure baseline.
# Public access is DISABLED here. The "public data" injector flips
# allow_blob_public_access / creates a public container; teardown reverts.
#############################################
resource "azurerm_storage_account" "lab" {
  name                     = "${var.prefix}${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.lab.name
  location                 = azurerm_resource_group.lab.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  account_kind             = "StorageV2"
  min_tls_version          = "TLS1_2"

  # Secure baseline — the whole point is that the injector has to WEAKEN this.
  allow_nested_items_to_be_public = false
  public_network_access_enabled   = true # network reachable, but blob public access off
  shared_access_key_enabled       = true

  tags = var.tags
}

resource "azurerm_storage_container" "lab" {
  name                  = "labdata"
  storage_account_name  = azurerm_storage_account.lab.name
  container_access_type = "private"
}
