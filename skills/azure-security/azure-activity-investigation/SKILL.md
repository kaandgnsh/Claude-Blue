---
name: azure-activity-investigation
description: Investigate Azure control-plane and resource activity — Activity Log (AzureActivity), resource diagnostic logs (Key Vault, Storage, VM run-command), Defender for Cloud alerts — for privilege escalation, persistence, data access and defense evasion in subscriptions. Use when an Azure subscription or resource may be compromised, or a Defender for Cloud alert needs investigation.
license: MIT
metadata:
  category: azure-security
  version: "2.0.0"
  verification: documented
---

# Azure Activity Investigation

## Key operations (`AzureActivity.OperationNameValue`)

| Tactic | Operation |
|---|---|
| Privilege escalation | `MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE`, `Microsoft.Authorization/elevateAccess/action` |
| Execution on VMs | `MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION`, `.../EXTENSIONS/WRITE` (CustomScriptExtension) |
| Credential access | `MICROSOFT.KEYVAULT/VAULTS/WRITE` (access policy changes), Key Vault data plane `SecretGet` (in `AzureDiagnostics`/`KeyVault` logs), `MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION` |
| Defense evasion | `MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE`, `MICROSOFT.SECURITY/PRICINGS/WRITE` (Defender plan disabled), NSG rule changes |
| Exfiltration | `MICROSOFT.COMPUTE/DISKS/BEGINGETACCESS/ACTION` (disk SAS export), `MICROSOFT.COMPUTE/SNAPSHOTS/WRITE`, storage SAS generation |
| Impact | Mass `DELETE` operations, resource locks removed (`MICROSOFT.AUTHORIZATION/LOCKS/DELETE`) |

## KQL

```kusto
AzureActivity
| where TimeGenerated > ago(14d)
| where OperationNameValue has_any ("ROLEASSIGNMENTS/WRITE", "RUNCOMMAND/ACTION", "LISTKEYS/ACTION", "DIAGNOSTICSETTINGS/DELETE",
                                    "BEGINGETACCESS/ACTION", "elevateAccess", "LOCKS/DELETE", "EXTENSIONS/WRITE")
| where ActivityStatusValue in ("Success", "Succeeded")
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ResourceGroup, _ResourceId, Properties_d
| order by TimeGenerated asc
```
Key Vault data plane:
```kusto
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT" and OperationName in ("SecretGet", "KeyDecrypt", "SecretList")
| summarize count(), secrets=make_set(id_s, 50) by CallerIPAddress, identity_claim_upn_s, bin(TimeGenerated, 1h)
```
(Column names depend on whether resource-specific tables are used — e.g. `AZKVAuditLogs`.)

## Workflow

1. Identify the caller (user, service principal, managed identity) and correlate with Entra sign-ins (`entra-signin-investigation`, `AADServicePrincipalSignInLogs`).
2. Build the change list; check Run Command/extension contents (`az vm run-command list`, extension settings) for executed scripts.
3. Check data access: storage account keys listed → assume data access possible (storage logs only if diagnostics enabled), Key Vault secret reads.
4. Review Defender for Cloud alerts (`SecurityAlert | where ProductName has "Defender"`) for correlated detections.

## Related skills

`entra-audit-investigation`, `azure-rbac-review`, `cloud-incident-response`, `sentinel-kql-investigation`

## References

- Azure Activity Log schema: https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log-schema
- Azure resource provider operations: https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations
- Key Vault logging: https://learn.microsoft.com/en-us/azure/key-vault/general/logging
- Microsoft Azure Threat Research Matrix: https://microsoft.github.io/Azure-Threat-Research-Matrix/
