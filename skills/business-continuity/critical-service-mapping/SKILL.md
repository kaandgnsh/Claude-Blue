---
name: critical-service-mapping
description: Map critical business services to their technical dependencies — applications, data stores, identity, network, cloud services, third parties, people — with impact tolerances (RTO/RPO, maximum tolerable downtime) to drive recovery order, security priorities and asset criticality. Use for business impact analysis, ransomware recovery planning, DORA/operational resilience work, or prioritizing protection of crown jewels.
license: MIT
metadata:
  category: business-continuity
  version: "2.0.0"
  verification: documented
---

# Critical Service Mapping

## Steps

1. **Identify important business services** (customer-facing outcomes: "take card payments", "ship orders", "pay employees"), not systems.
2. **Impact tolerances** per service from business owners: maximum tolerable downtime, RTO, RPO, peak periods, regulatory/contractual obligations.
3. **Map dependencies** (use CMDB, cloud resource graphs, APM/service maps, interviews):
   - Applications and their components
   - Data stores and integrations (queues, APIs, file transfers)
   - Identity (AD, IdP, PKI) — almost everything depends on it
   - Infrastructure (DNS, network, hypervisors, cloud regions/accounts)
   - Third parties (payment gateways, SaaS, MSPs)
   - Key people/roles and manual workarounds
4. **Find single points of failure and shared dependencies** (one AD forest, one region, one vendor).
5. **Assign criticality tiers** and feed: recovery order (`ransomware-recovery`), backup requirements (`backup-assurance`), asset criticality (`asset-criticality-tiering`), monitoring priorities.
6. **Review** annually and on major change.

## Record

```
Service: <name>   Owner: <>   MTD: <h>   RTO: <h>   RPO: <min>
Dependencies:
  App: <> (tier) | Data: <> | Identity: AD/Entra | Infra: <region/cluster> | Third parties: <> | People: <>
Manual workaround: <> (max duration)
SPOFs: <>
Recovery order position: <n>
```

## Dependency discovery tips

- **Identity is a hidden dependency** of nearly every service: if AD/Entra/Okta is down or untrusted, list which services still work (local accounts, break-glass) and which do not.
- **Time, DNS and certificates**: NTP, internal DNS and PKI outages break authentication and TLS across services.
- **Licensing and SaaS back-ends**: on-prem applications that phone home for licences fail in isolated recovery.
- **Data flows**: nightly file transfers or message queues that, if missing, silently corrupt downstream processes.
- Validate maps in exercises (`recovery-exercise`): turn off a dependency in a test environment and observe what breaks.

## Related skills

`asset-criticality-tiering`, `backup-assurance`, `ransomware-recovery`, `recovery-exercise`

## References

- NIST SP 800-34 Rev. 1 Contingency Planning Guide: https://csrc.nist.gov/pubs/sp/800/34/r1/upd1/final
- ISO 22301 Business continuity management (standard; purchase required)
- EU DORA (Regulation (EU) 2022/2554): https://eur-lex.europa.eu/eli/reg/2022/2554/oj
