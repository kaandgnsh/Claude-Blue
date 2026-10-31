---
name: firewall-rule-review
description: Review firewall and cloud security-group rule bases for overly permissive, shadowed, redundant, unused and undocumented rules, risky services exposed to the internet, and missing egress control, using hit counts and change history. Use for periodic firewall audits (PCI DSS 1.x), cleanup projects, or after an incident involving network exposure.
license: MIT
metadata:
  category: network-security
  version: "2.0.0"
  verification: documented
---

# Firewall Rule Review

## Data to collect

- Rule base export with order, source/destination objects (expanded), services/applications, action, logging, comments/ticket IDs, created/modified dates.
- **Hit counts** over ≥ 90 days (Palo Alto rule usage, Fortinet policy hit count, Check Point hit count, AWS VPC Flow Logs/Network Firewall logs, Azure NSG flow logs).
- Network zone definitions and asset criticality.

## Findings to flag

| Finding | Test |
|---|---|
| Any/any or broad allow | Source or destination `any` with action allow; service `any` |
| Internet-exposed admin services | Inbound from `0.0.0.0/0` to 22, 3389, 445, 5985/5986, 23, 1433, 3306, 5432, 6379, 9200, 27017, management GUIs |
| Shadowed rules | A later rule never matches because an earlier rule covers it |
| Redundant | Duplicate coverage by another rule with the same action |
| Unused | Zero hits for 90+ days (validate seasonal/DR flows before removal) |
| No logging on allow/deny of sensitive zones | Logging disabled |
| No egress filtering | Servers allowed outbound any; should allow only required destinations/proxy |
| Undocumented | No owner/ticket/justification; expired temporary rules |
| Cloud SGs | `0.0.0.0/0` ingress, `::/0` ingress, SGs attached to many resources |

AWS quick check:
```sh
aws ec2 describe-security-groups --query "SecurityGroups[?IpPermissions[?IpRanges[?CidrIp=='0.0.0.0/0']]].[GroupId,GroupName]" --output table
```
Azure: `az network nsg list --query "[].securityRules[?sourceAddressPrefix=='*' && access=='Allow' && direction=='Inbound']"`.

Tools: vendor policy optimizers, Capirca/aerleon for policy-as-code, Batfish for reachability analysis.

## Output

`Rule ID | Finding | Evidence (hits/date) | Risk | Recommendation | Owner | Decision`

## Safety

Never delete rules directly from a review; propose changes through change management with rollback (disable first, monitor, then delete).

## Related skills

`network-segmentation-review`, `external-attack-surface-review`, `cloud-exposure-review`

## References

- NIST SP 800-41 Rev. 1, Guidelines on Firewalls and Firewall Policy: https://csrc.nist.gov/pubs/sp/800/41/r1/final
- PCI DSS v4.0.1 Requirement 1: https://www.pcisecuritystandards.org/document_library/
- Batfish: https://batfish.org/
