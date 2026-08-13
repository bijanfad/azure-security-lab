# Copy to terraform.tfvars and fill in. terraform.tfvars is gitignored.
subscription_id = "00000000-0000-0000-0000-000000000000" # your LAB subscription
location        = "westeurope"
prefix          = "seclab"

tags = {
  project     = "security-lab"
  environment = "lab"
  managed_by  = "terraform"
  owner       = "bijan"
}
