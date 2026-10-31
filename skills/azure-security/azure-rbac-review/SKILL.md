---
name: azure-rbac-review
description: Review Azure RBAC and Entra directory roles — Owner/Contributor/User Access Administrator assignments at management group, subscription and resource scopes, Global Administrator and privileged directory roles, PIM eligibility vs. standing access, guest and service principal privileges, custom roles with wildcards. Use for Azure access reviews, tenant security assessments, or after suspected privilege escalation.
license: MIT
metadata:
  category: azure-security
  version: "2.0.0"
  verification: documented
---

# Azure RBAC and Entra Role Review

## Two separate planes

- **Entra directory roles** (tenant): Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator, Application Administrator, Cloud Application Administrator, Exchange/SharePoint Admin, Conditional Access Administrator, Hybrid Identity Administrator.
- **Azure RBAC** (resources): Owner, Contributor, User Access Administrator, Role Based Access Control Administrator, plus data roles (Storage Blob Data Owner, Key Vault Administrator).
- Global Admins can **elevate** to User Access Administrator at root (`/`) — check `Microsoft.Authorization/elevateAccess/action` in Activity Log.

## Collect

```sh
az role assignment list --all --include-inherited --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='User Access Administrator' || roleDefinitionName=='Contributor'].{principal:principalName,type:principalType,role:roleDefinitionName,scope:scope}" -o table
az role assignment list --scope / --query "[].{p:principalName,r:roleDefinitionName}"    # root scope (needs elevation to view)
az role definition list --custom-role-only true --query "[].{name:roleName,actions:permissions[0].actions}"
```
```powershell
Connect-MgGraph -Scopes "RoleManagement.Read.Directory"
Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal | Select-Object RoleDefinitionId, @{n='Principal';e={$_.Principal.AdditionalProperties.userPrincipalName ?? $_.Principal.AdditionalProperties.displayName}}
Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All      # PIM eligible assignments
```

## Findings

| Finding | Target state |
|---|---|
| > 5 Global Administrators, or GA used daily | 2–4 GA, cloud-only accounts, PIM-eligible, phishing-resistant MFA, plus 2 break-glass accounts (monitored) |
| Standing Owner/UAA at subscription or MG | PIM eligible with approval |
| Service principals with Owner / directory roles | Least privilege; review app credentials (`entra-audit-investigation`) |
| Guests with privileged roles | Remove |
| Custom roles with `*` actions or `Microsoft.Authorization/*/write` | Scope down |
| Synced (on-prem) accounts in privileged roles | Cloud-only admins (on-prem compromise ≠ cloud compromise) |
| Classic administrators (co-admin) | Removed (retired) |

## Output

`Principal | Type | Role | Scope | Standing/eligible | Last used | Justification | Decision`

## Related skills

`privileged-access-review`, `entra-audit-investigation`, `conditional-access-review`, `access-certification`

## References

- Azure RBAC best practices: https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices
- Entra built-in roles: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
- Securing privileged access for hybrid and cloud deployments: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-planning
- Elevate access for a Global Administrator: https://learn.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin
