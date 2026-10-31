---
name: adcs-security-review
description: Review Active Directory Certificate Services for ESC1–ESC16 style misconfigurations — enrollee-supplied SAN templates, dangerous EKUs, weak template/CA ACLs, EDITF_ATTRIBUTESUBJECTALTNAME2, web enrollment NTLM relay — using Certify/Certipy output, PSPKIAudit or Locksmith, and monitor certificate issuance. Use when assessing AD CS, after an AD compromise, or investigating suspicious certificate requests.
license: MIT
metadata:
  category: active-directory-security
  version: "2.0.0"
  verification: documented
---

# AD CS Security Review

AD CS misconfigurations frequently give any domain user a path to Domain Admin via certificate-based authentication (PKINIT), and certificates survive password resets.

## Core misconfigurations (SpecterOps "Certified Pre-Owned" naming)

| ID | Condition | Fix |
|---|---|---|
| ESC1 | Template: low-priv enroll + `ENROLLEE_SUPPLIES_SUBJECT` + client-auth EKU + no manager approval | Remove enrollee-supplied subject or restrict enrollment; require approval |
| ESC2 | Any Purpose EKU or no EKU, low-priv enroll | Restrict EKU/enrollment |
| ESC3 | Certificate Request Agent EKU enrollable by low-priv | Restrict; enrollment agent restrictions on CA |
| ESC4 | Low-priv has write/owner rights on a template | Fix template ACL |
| ESC6 | CA flag `EDITF_ATTRIBUTESUBJECTALTNAME2` | `certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2`, restart CertSvc |
| ESC7 | Low-priv ManageCA/ManageCertificates on CA | Fix CA ACL |
| ESC8 | HTTP web enrollment (`/certsrv`) allowing NTLM relay | Disable or require HTTPS + EPA, disable NTLM |
| ESC9/10 | Weak certificate mapping (`StrongCertificateBindingEnforcement`) | Enforce strong mapping (KB5014754) |
| ESC11 | RPC enrollment without packet privacy (`IF_ENFORCEENCRYPTICERTREQUEST` off) | Enable |
| ESC13+ | Issuance policy linked to groups (OID group link), others | Review per current research |

## Assessment commands (read-only)

```powershell
certutil -v -dstemplate > templates.txt              # template details
certutil -getreg policy\EditFlags                    # ESC6 check on the CA
Invoke-Locksmith -Mode 0                             # Locksmith (TrimarcJake) report
```
Certipy (Linux, authorized): `certipy find -u user@corp.local -p '...' -dc-ip 10.0.0.1 -vulnerable -stdout`. Treat output as sensitive.

## Monitoring

Enable CA auditing (`certutil -setreg CA\AuditFilter 127`) and object access on the CA:
- 4886 request received, 4887 certificate issued, 4888 denied, 4899/4900 template changes.
- Alert when the **requester ≠ subject/SAN**, when a SAN UPN names a privileged user, or a certificate is issued from a template rarely used.
- 4768 with `PreAuthType=16/17` (PKINIT) from unexpected hosts for privileged accounts.

## Incident note

If a malicious certificate was issued, **revoke it and publish the CRL** — resetting the user's password does not invalidate certificate auth. Consider whether the CA private key itself was exposed (then the CA must be rebuilt and its certs distrusted from NTAuth).

## Related skills

`ad-attack-path-analysis`, `ad-privileged-access-review`, `certificate-lifecycle`

## References

- SpecterOps "Certified Pre-Owned": https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf
- Locksmith: https://github.com/jakehildreth/Locksmith
- Microsoft KB5014754 certificate-based authentication changes: https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
