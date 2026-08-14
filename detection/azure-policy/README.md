# Azure Policy — detect & auto-remediate storage public access

Policy-as-code for the **public-data** scenario: a built-in **Modify** policy that flags a storage
account with `allowBlobPublicAccess = true` as non-compliant **and** auto-remediates it back to
`false`. This is the project's "one automated remediation" deliverable.

- **Policy (built-in):** `Configure your Storage account public access to be disallowed`
  (`13502221-8df0-4414-9937-de9c5c4e396b`), effect **Modify**.
- **Operation:** `addOrReplace Microsoft.Storage/storageAccounts/allowBlobPublicAccess = false`.
- **Identity role required:** `Storage Account Contributor` (`17d1049b-9a84-46fb-8f53-869881c3d3ab`).

## Reproduce

```bash
RG=seclab-rg
SUB=$(az account show --query id -o tsv)
SCOPE="/subscriptions/$SUB/resourceGroups/$RG"

# 1. Assign the Modify policy with a system-assigned managed identity
az policy assignment create \
  --name seclab-disallow-storage-public \
  --display-name "Seclab: disallow storage public access (Modify)" \
  --policy 13502221-8df0-4414-9937-de9c5c4e396b \
  --scope "$SCOPE" \
  --params '{"effect":{"value":"Modify"}}' \
  --mi-system-assigned --location westeurope

# 2. Grant the identity the role the Modify effect needs
PID=$(az policy assignment show --name seclab-disallow-storage-public --scope "$SCOPE" --query identity.principalId -o tsv)
az role assignment create --assignee-object-id "$PID" --assignee-principal-type ServicePrincipal \
  --role "Storage Account Contributor" --scope "$SCOPE"

# 3. Evaluate compliance on demand (unattended cadence is up to ~24h)
az policy state trigger-scan -g $RG
az policy state list -g $RG \
  --filter "policyAssignmentName eq 'seclab-disallow-storage-public'" \
  --query "[].{resource:resourceId, state:complianceState}" -o table   # -> NonCompliant

# 4. Auto-remediate existing non-compliant resources
az policy remediation create --name seclab-remediate-storage \
  --resource-group $RG --policy-assignment seclab-disallow-storage-public
az storage account show -g $RG -n <account> --query allowBlobPublicAccess -o tsv   # -> false
```

## Cleanup (these live outside Terraform/the Security Monkey)

```bash
az policy remediation delete --name seclab-remediate-storage -g $RG
az policy assignment delete --name seclab-disallow-storage-public --scope "$SCOPE"
# role assignment for the (now-deleted) identity is removed with the RG on `terraform destroy`
```

> Findings & timeline recorded in `../../results/detection-coverage-matrix.md` (note 3).
