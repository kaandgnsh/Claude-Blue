---
name: asset-criticality-tiering
description: Assign criticality tiers to assets and identities based on business service impact, data sensitivity, privilege (Tier 0 control-plane systems) and exposure, and propagate tiers into SIEM, vulnerability prioritization, alert severity and access controls. Use when prioritizing security work by asset importance, building asset context for SOC, or defining crown jewels.
license: MIT
metadata:
  category: asset-attack-surface
  version: "2.0.0"
  verification: documented
---

# Asset Criticality Tiering

## Tier model (example)

| Tier | Criteria | Examples |
|---|---|---|
| 0 — Control plane | Compromise gives control of most of the environment | Domain controllers, IdP (Entra Connect, AD FS, Okta admin), PKI/ADCS, PAM vault, backup servers, hypervisor management, EDR/SIEM/SOAR consoles, CI/CD with prod deploy rights, cloud org admin accounts |
| 1 — Crown jewels | Critical business services or highly sensitive data | Payment systems, core ERP, customer databases, source code for flagship products, OT supervisory systems |
| 2 — Business important | Supports operations; moderate data | Departmental apps, file servers |
| 3 — Standard | User endpoints, low-impact services | Workstations, kiosks |

Factors: business impact from `critical-service-mapping`, data classification (`data-classification`), privilege/blast radius, internet exposure, regulatory scope.

## Propagate

- **SIEM/SOAR**: asset lookup with `tier`; alert severity modifier (Tier 0 ×2).
- **Vulnerability management**: SLA by tier × exposure (`vuln-prioritization`).
- **Access**: Tier 0 administered only from PAWs; separate admin accounts per tier.
- **Monitoring**: Tier 0/1 require full logging, EDR in prevention mode, file integrity monitoring.
- **Change management**: stricter approvals.

## Maintenance

Tier stored as an attribute in CMDB/cloud tags (`criticality=tier0`); reviewed when services change; automatic tiering rules for known roles (all DCs = Tier 0) plus owner attestation.

## Output

`Asset/identity | Tier | Rationale | Owner | Data | Exposure | Controls required | Gaps`

## Related skills

`critical-service-mapping`, `asset-inventory-reconciliation`, `ad-privileged-access-review`, `vuln-prioritization`

## References

- Microsoft enterprise access model (tiering): https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model
- NIST CSF 2.0 ID.AM (Asset Management): https://www.nist.gov/cyberframework
