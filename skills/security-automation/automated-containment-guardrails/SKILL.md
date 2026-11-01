---
name: automated-containment-guardrails
description: Define when containment may run without a human (auto-isolate a host, disable or revoke sessions for an account, block an IOC) using confidence thresholds, asset and identity tiers, exclusion lists, rate caps, circuit breakers, release paths and after-action review. Use when proposing or reviewing automatic response in EDR, identity protection or SOAR, or when an automatic action hit the wrong target.
license: MIT
metadata:
  category: security-automation
  version: "2.2.0"
  verification: documented
---

# Automated Containment Guardrails

Automatic containment buys minutes against ransomware and token theft. It also lets an attacker, a bad rule or a bad feed take your own business offline. Write the guardrails as policy first, then encode them in the playbook.

## 1. Pre-approval matrix

Decide per action and per target tier, and get it signed by the incident response owner and the asset/business owners.

| Action | Tier 0 (DCs, IdP, PKI, hypervisors) | Tier 1 (servers, prod workloads) | Tier 2 (user endpoints) | Standard users | Privileged/VIP/break-glass |
|---|---|---|---|---|---|
| EDR network isolation | Never automatic | Human approval | **Auto** at high confidence | n/a | n/a |
| Kill process / quarantine file | Human | Auto for known-bad hash | Auto | n/a | n/a |
| Revoke sessions / refresh tokens | n/a | n/a | n/a | **Auto** at high confidence | Human |
| Disable account | n/a | n/a | n/a | Human (auto only with step-up) | Never automatic |
| Block IP/domain at edge | Human | Human | Auto with TTL for high-confidence IOC | n/a | n/a |

"High confidence" must be defined concretely, e.g. vendor severity High **and** one of: known-bad hash prevalence < 5 hosts, ransomware behaviour detection (mass file rename/encrypt), impossible travel plus token anomaly on the same session.

## 2. Exclusions (never-act lists)

Maintain these as data the playbook reads (watchlist, config table, CMDB tag), owned by named teams and reviewed quarterly:

- Domain controllers, IdP/federation servers, PKI, backup servers, hypervisor hosts, jump hosts, SOC tooling hosts.
- Break-glass accounts, service accounts with dependent production workloads, executive accounts (route to human).
- Critical IPs/domains: IdP endpoints, DNS resolvers, update and certificate revocation services, your own egress IPs.

Exclusion hit → playbook stops the automatic path and opens a P1 task for a human, with the evidence attached.

## 3. Rate caps and circuit breaker

- Per-run cap: one playbook run acts on at most N entities (typical: 1 host, 1 user).
- Per-window cap: at most M automatic actions per hour across all runs (typical: 5 isolations/hour, 20 session revocations/hour).
- When a cap trips: stop automatic actions, page the on-call lead, keep enrichment running. A burst of high-confidence detections is itself an incident, not a reason to isolate 300 hosts unattended.

## 4. Release and rollback

Every automatic action declares:

| Item | Example |
|---|---|
| Rollback | EDR "release from isolation"; re-enable account; remove block entry |
| Who may roll back | SOC L2 on shift, without further approval |
| Auto-expiry | Edge blocks expire after 24 h unless renewed by an analyst |
| User communication | Template to the device owner and service desk: what happened, ticket number, how to reach SOC |
| Verification | Confirm action took effect (device shows isolated; sign-in logs show revoked tokens) |

## 5. Encode in the playbook

```json
"isolate": {"type": "action", "action": "edr_isolate_host", "destructive": true,
            "auto_approved_by": "IR-policy-2026-07 section 3.1",
            "exclusions": "watchlist:never_isolate", "idempotency_key": "{{device_id}}",
            "rollback": "release_host", "timeout_s": 120, "on_error": "page_oncall", "next": "notify_owner"}
```

Lint with the checker in `soar-playbook-design`: `auto_approved_by` without `exclusions` is reported as high.

## 6. Measure and review

- Every automatic action gets an after-action label within 1 business day: correct / correct-but-unnecessary / wrong target.
- Wrong target > 0 in a month → review the threshold; > 2 → suspend the automatic path until fixed.
- Track mean time from detection to containment for automatic vs. human paths to show the value (see `automation-metrics`).

## Example detections that commonly justify automatic action

- Ransomware behaviour (T1486) on a Tier 2 endpoint → auto-isolate.
- LSASS credential dumping (T1003.001) by an unsigned binary on a workstation → auto-isolate, human review for servers.
- Token theft indicators on a standard user (anomalous token, session from known-bad infrastructure) → auto-revoke sessions.

## Related skills

`host-isolation`, `containment-plan`, `soar-playbook-design`, `automation-risk-review`, `automation-metrics`, `token-theft-investigation`

## References

- Microsoft Defender for Endpoint automated investigation and response levels: https://learn.microsoft.com/en-us/defender-endpoint/automation-levels
- Microsoft Entra ID Protection risk policies: https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-policies
- CrowdStrike Falcon prevention policy (vendor overview): https://www.crowdstrike.com/en-us/platform/endpoint-security/
- NIST SP 800-61r3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
