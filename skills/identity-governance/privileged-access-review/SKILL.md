---
name: privileged-access-review
description: Review privileged access across platforms — who holds admin in IdP, AD, cloud, databases, network devices, hypervisors, backup and security tools; standing vs. just-in-time (PIM/PAM) access; vaulting and session recording; break-glass accounts — and drive reduction. Use for privileged access audits, PAM program design, or after an incident involving admin credentials.
license: MIT
metadata:
  category: identity-governance
  version: "2.0.0"
  verification: documented
---

# Privileged Access Review

## Inventory privileged access everywhere

| Platform | Privileged roles to enumerate |
|---|---|
| Identity | Entra Global/Privileged Role/Auth Admin, Okta Super Admin, Google Super Admin |
| AD | Tier 0 groups (`ad-privileged-access-review`) |
| Cloud | AWS AdministratorAccess / IAM full, Azure Owner/UAA at MG/subscription, GCP Owner/Org Admin |
| Servers | Local Administrators, sudoers with ALL |
| Databases | `sysadmin`, `db_owner`, `SUPERUSER`, `DBA` |
| Infrastructure | Hypervisor (vCenter, ESXi root), network devices, storage, **backup consoles** |
| Security tools | EDR/SIEM/SOAR admins (can disable detection) |
| DevOps | GitHub org owners, CI admins, Kubernetes cluster-admin |

## Assessment questions

1. **Standing vs. JIT**: is access permanently assigned, or eligible and activated with approval/MFA/time limit (Entra PIM, AWS IAM Identity Center + temporary elevation, CyberArk/Delinea/BeyondTrust, Teleport)?
2. **Separate admin accounts**: admins use dedicated accounts not used for email/browsing; from PAWs for Tier 0.
3. **MFA**: phishing-resistant for all privileged access.
4. **Vaulting**: shared/root/break-glass credentials vaulted, checked out with reason, rotated after use; session recording for critical systems.
5. **Count and justification**: number of holders per role vs. need; each has an owner-approved justification.
6. **Monitoring**: alerts on role activation outside process, break-glass use, new privileged assignment.
7. **Backup & hypervisor isolation**: separate identity domain/MFA for backup and virtualization admin (ransomware targets).

## Metrics

Standing privileged accounts (trend down), % privileged access via JIT, % with phishing-resistant MFA, break-glass tests performed, mean time privileged assignment remains after role change.

## Output

`Platform | Role | Holder | Standing/JIT | MFA type | Last used | Justification | Decision`

## Related skills

`ad-privileged-access-review`, `azure-rbac-review`, `aws-iam-review`, `access-certification`

## References

- Microsoft privileged access strategy: https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-strategy
- NIST SP 800-53 Rev. 5 AC-6 Least Privilege: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- CISA/NSA "Identity and Access Management Recommended Best Practices for Administrators": https://media.defense.gov/2023/Mar/14/2003178390/-1/-1/0/ESF%20ID%20AND%20ACCESS%20MGMT%20RECOMMENDED%20BEST%20PRACTICES%20FOR%20ADMINISTRATORS%20PP-23-0248_508C.PDF
