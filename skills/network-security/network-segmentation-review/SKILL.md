---
name: network-segmentation-review
description: Assess network segmentation and microsegmentation — zone model, Tier 0 isolation, user-to-server and workstation-to-workstation controls, management plane separation, flow evidence and reachability testing. Use when validating segmentation (PCI scope, ransomware blast radius), designing zones, or reviewing a flat network after an incident.
license: MIT
metadata:
  category: network-security
  version: "2.0.0"
  verification: documented
---

# Network Segmentation Review

## Target model (typical)

| Zone | Allowed inbound | Notes |
|---|---|---|
| Internet / DMZ | Published services only | WAF/reverse proxy |
| User workstations | Management tools only | **Deny workstation↔workstation** SMB/RDP/WinRM |
| Servers (by app tier) | From app front-ends / users per app | Default deny between apps |
| Tier 0 (DCs, PKI, IdP, PAM) | Authentication protocols from clients; admin only from PAWs | Strictest |
| Management (iDRAC/iLO, hypervisors, network gear, backups) | Only from admin jump hosts | Frequent ransomware target |
| OT | Via DMZ/conduits only | See `ot-segmentation-review` |
| Cardholder data (PCI) | Documented flows only | Segmentation testing required |

## Assessment workflow

1. Obtain zone/VLAN/VRF/VNet diagrams and the intended flow matrix.
2. Collect **actual flows** (NetFlow/IPFIX, VPC/NSG flow logs, Zeek conn) for 30 days; build a zone-to-zone matrix.
3. Compare intended vs. actual; flag flows that violate policy (e.g., workstation → workstation 445).
4. **Reachability testing** from each zone (authorized): `nmap -Pn -sT -p 22,135,139,445,3389,5985,5986 <target-range>` from a test host in the source zone; or analyze configs with Batfish.
5. Check management plane exposure (BMC, hypervisor, backup consoles) from user zones.
6. Rate blast radius: from a compromised workstation, which zones/services are reachable?

## Quick flow query (Zeek)

```sh
# Workstation-to-workstation SMB (assumes 10.10.0.0/16 = workstations)
jq -r 'select(."id.resp_p"==445 and (."id.orig_h"|startswith("10.10.")) and (."id.resp_h"|startswith("10.10.")) and .conn_state=="SF") | [."id.orig_h", ."id.resp_h"] | @tsv' conn.log | sort -u | wc -l
```

## Output

`Source zone | Dest zone | Port/app | Intended? | Observed flows | Reachable in test | Risk | Fix`

## Safety

Reachability scans need written authorization and timing coordination; scan rates should be low in production and OT networks must not be actively scanned without OT owner approval.

## Related skills

`firewall-rule-review`, `zero-trust-assessment`, `ot-segmentation-review`, `netflow-analysis`

## References

- NIST SP 800-207 Zero Trust Architecture: https://csrc.nist.gov/pubs/sp/800/207/final
- PCI SSC Guidance for PCI DSS Scoping and Network Segmentation: https://www.pcisecuritystandards.org/document_library/
- CISA microsegmentation guidance (2025): https://www.cisa.gov/resources-tools/resources/microsegmentation-zero-trust-part-one-introduction-and-planning
