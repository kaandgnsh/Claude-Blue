---
name: honeypot-deployment
description: Deploy internal honeypots and decoy services for detection — low-interaction decoys mimicking file servers, RDP/SSH, databases, web admin panels and OT devices (OpenCanary, T-Pot, commercial deception) — with safe network placement, logging to SIEM and maintenance. Use when adding lateral-movement and reconnaissance detection inside networks, or evaluating deception platforms.
license: MIT
metadata:
  category: deception
  version: "2.0.0"
  verification: documented
---

# Honeypot Deployment

## Internal vs. internet honeypots

**Internal** decoys detect attackers already inside (high fidelity: no one should touch them). **Internet-facing** honeypots collect noisy opportunistic scanning — useful for research/threat intel, not for detecting compromise of your environment. Prioritize internal.

## OpenCanary example (low-interaction)

```sh
pip install opencanary
opencanaryd --copyconfig         # writes /etc/opencanaryd/opencanary.conf (or ~/.opencanary.conf)
# enable modules in the JSON config, e.g.:
#   "smb.enabled": true, "rdp.enabled": true, "ssh.enabled": true, "http.enabled": true, "mysql.enabled": true
#   "logger": {"class": "PyLogger", "kwargs": {"handlers": {"syslog-unix": {"class": "logging.handlers.SysLogHandler", "address": ["siem.example", 514]}}}}
opencanaryd --start
```
Check module names and the logging configuration format in the OpenCanary docs for your version.

## Placement

- One or more decoys per important segment (server VLANs, management networks, near Tier 0, OT DMZ).
- Plausible hostnames (`fs-finance-02`, `sql-hr`), realistic banners, registered in DNS (attackers enumerate DNS/AD).
- Isolated host with no real data or credentials; hardened; cannot be used as a pivot (egress restricted).
- Exclude from vulnerability scanners and asset discovery jobs **or** whitelist those scanner IPs in alerting.

## Alerting

Any connection → SOC alert with source IP/host, service, credentials attempted (if captured) → `deception-alert-triage`. Correlate source host with EDR immediately.

## Maintenance

Periodic test connections (scheduled, from a known test host, suppressed by rule), patching, and refreshing decoy content so it stays believable.

## Related skills

`honeytoken-deployment`, `deception-alert-triage`, `lateral-movement-detection`, `network-segmentation-review`

## References

- OpenCanary: https://github.com/thinkst/opencanary
- T-Pot honeypot platform: https://github.com/telekom-security/tpotce
- MITRE Engage: https://engage.mitre.org/
