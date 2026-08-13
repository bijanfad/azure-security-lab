variable "subscription_id" {
  description = "Azure subscription ID for the LAB subscription. Do not point this at a shared/prod subscription."
  type        = string
}

variable "location" {
  description = "Azure region for lab resources. Pick one close to you with cheap SKUs."
  type        = string
  default     = "westeurope"
}

variable "prefix" {
  description = "Name prefix for all lab resources. Also used by the Security Monkey to scope what it touches."
  type        = string
  default     = "seclab"

  validation {
    condition     = can(regex("^[a-z][a-z0-9]{2,10}$", var.prefix))
    error_message = "prefix must be 3-11 chars, lowercase alphanumeric, starting with a letter (storage-account friendly)."
  }
}

variable "tags" {
  description = "Tags applied to every resource. The `project` tag is the primary safety scope for the injectors."
  type        = map(string)
  default = {
    project     = "security-lab"
    environment = "lab"
    managed_by  = "terraform"
  }
}

variable "vnet_address_space" {
  description = "Address space for the lab VNet."
  type        = list(string)
  default     = ["10.42.0.0/24"]
}

variable "subnet_prefix" {
  description = "Subnet prefix inside the lab VNet."
  type        = string
  default     = "10.42.0.0/26"
}
