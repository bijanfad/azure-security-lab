terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "azurerm" {
  # Auth comes from `az login` / env vars — never hard-code credentials.
  subscription_id = var.subscription_id

  features {
    resource_group {
      # Safety: refuse to delete an RG that still contains resources not managed here.
      prevent_deletion_if_contains_resources = true
    }
  }
}

provider "random" {}
