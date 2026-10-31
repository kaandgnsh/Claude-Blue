---
name: containment-plan
description: Plan and execute coordinated containment for a security incident — host isolation, account disablement, token revocation, network blocks, cloud key deactivation — with impact analysis, approvals, sequencing and verification. Use when scoping is sufficient to act, or when ongoing damage forces immediate containment.
license: MIT
metadata:
  category: incident-response
  version: "2.0.0"
  verification: documented
---

# Containment Plan

Containment is a coordinated cut-over, ideally executed in one window so the attacker cannot react and re-enter through a foothold you missed.

## Decide the strategy

| Situation | Strategy |
|---|---|
| Active destruction/exfiltration/ransomware spread | **Immediate** containment of affected segment; scope in parallel |
| Stealthy intrusion, scope incomplete | **Delayed/coordinated** containment after scoping; monitor meanwhile |
| Critical system can't go offline | **Compensating** containment (network ACL, block egress, revoke creds) |

## Containment action catalogue

| Target | Action | Verify |
|---|---|---|
| Endpoint | EDR network isolation (keeps EDR channel) | Host shows isolated; no new outbound in netflow |
| AD user | Disable account (`Disable-ADAccount`), reset password, remove from privileged groups; purge Kerberos tickets on affected hosts (`klist purge`) | 4725/4724 events; logon attempts fail |
| Entra ID user | `Revoke-MgUserSignInSession -UserId <id>`; disable; remove attacker MFA methods; check CA | Sign-in logs show failures |
| AWS key | `aws iam update-access-key --user-name U --access-key-id AKIA... --status Inactive`; attach deny-all inline policy to role sessions (`aws:TokenIssueTime` condition) | CloudTrail shows AccessDenied |
| OAuth app | Revoke consent / disable service principal | No new token issuance |
| Network | Block C2 IP/domain at egress proxy/DNS/firewall | No hits after block, monitor for fallback C2 |
| Mail | Remove malicious inbox rules/forwarding, block sender, purge messages | Rule absent, purge report |
| krbtgt (Golden ticket) | Reset krbtgt **twice**, ≥ replication interval (and > max ticket lifetime, typically 10h) apart | New tickets issued; old TGTs fail |

## Workflow

1. List every action, target, owner, expected business impact, rollback, verification.
2. Sequence: revoke credentials/tokens and block C2 **at the same time** as host isolation; remove persistence after isolation.
3. Get approvals per the IR plan's decision authority; record in decision log.
4. Execute in the agreed window; owners confirm completion in channel with timestamp.
5. Verify each action independently (don't trust the console's "success").
6. Heightened monitoring for re-entry: same TTPs, new infrastructure, previously unknown accounts.

## Output template

```
Containment plan <incident> — window <UTC>
# | Target | Action | Owner | Impact | Approval | Rollback | Verification | Status
Re-entry monitoring: <detections, duration>
```

## Safety

Never shut down/reboot hosts before memory capture unless safety requires it — volatile evidence is lost. Do not delete attacker files during containment; preserve them for analysis.

## Related skills

`incident-scoping`, `host-isolation`, `eradication-recovery`, `aws-credential-compromise`, `token-theft-investigation`

## References

- NIST SP 800-61r3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
- Microsoft: Revoke user access in Entra ID: https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access
- AWS Security Incident Response Guide: https://docs.aws.amazon.com/security-ir/latest/userguide/
- Microsoft krbtgt reset guidance: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password
