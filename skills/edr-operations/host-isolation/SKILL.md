---
name: host-isolation
description: Decide on, approve, execute and verify endpoint network isolation through EDR (and fallback network controls), including impact analysis for servers and release criteria. Use when a host is confirmed or strongly suspected compromised and containment is being considered.
license: MIT
metadata:
  category: edr-operations
  version: "2.0.0"
  verification: documented
---

# Host Isolation

## Decision criteria

Isolate when the host shows **any** of: active C2, hands-on-keyboard activity, credential dumping, ransomware precursors, spreading behaviour, or confirmed malware with network capability — and the business impact of isolation is lower than the risk of continued access.

For critical servers (DCs, databases, production apps, OT gateways) consider alternatives first: restrict at the firewall to required flows only, block C2 egress, disable the compromised account, fail over to a clean replica.

## Before isolating

- [ ] Memory captured or explicitly waived (isolation keeps processes running; reboot/power off destroys memory).
- [ ] Business owner informed (or emergency authority invoked per IR plan).
- [ ] Coordinated with containment plan (simultaneous credential resets / C2 blocks).
- [ ] Out-of-band contact for the user (phone) — isolated laptops lose VPN/chat.

## Execute

| Product | Action |
|---|---|
| Microsoft Defender for Endpoint | Device page → *Isolate device* (Full or Selective); API `POST /api/machines/{id}/isolate` with `IsolationType` |
| CrowdStrike Falcon | Host → *Network contain* |
| SentinelOne | Endpoint → *Disconnect from network* |
| Fallback | Switch port shutdown / NAC quarantine VLAN / cloud security group replacement |

## Verify

- Console shows isolated state **and** telemetry continues (EDR channel intact).
- Network logs show no new connections from the host except EDR cloud.
- Re-check after reboot that isolation persists.

## Release criteria

Eradication complete or host rebuilt; credentials exposed on host rotated; detections for the TTPs in place; IC approval recorded.

## Output

`Host | Reason | Approver | Isolated at (UTC) | Method | Verification | Released at | Release approver`

## Related skills

`containment-plan`, `edr-alert-investigation`, `live-response`

## References

- Microsoft: Take response actions on a device: https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts
- NIST SP 800-61r3: https://csrc.nist.gov/pubs/sp/800/61/r3/final
