---
name: netflow-analysis
description: Analyze NetFlow/IPFIX/sFlow and cloud flow logs (AWS VPC Flow Logs, Azure VNet/NSG flow logs, GCP VPC Flow Logs) to find exfiltration, scanning, lateral movement, C2 and policy violations when no packet capture exists. Use when investigating network activity with flow data or hunting volume and connectivity anomalies.
license: MIT
metadata:
  category: network-security
  version: "2.0.0"
  verification: documented
---

# Flow Log Analysis

## Fields

Flows give 5-tuple, bytes/packets, start/end, TCP flags, and (cloud) action ACCEPT/REJECT, interface/instance IDs. No payload — infer from volume, timing, peers and ports.

AWS VPC Flow Log v2 default format: `version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status`. Custom formats can add `pkt-srcaddr`, `tcp-flags`, `flow-direction`, `vpc-id`, `instance-id`.

## Analyses

| Question | Approach |
|---|---|
| Exfiltration | Sum bytes out per internal host → external destination per day; compare to 30-day baseline; destinations in cloud storage/VPS ASNs |
| Scanning | One source, many destinations or ports, many REJECT / short flows, low bytes |
| Lateral movement | Internal → internal on 445/135/3389/5985/22 from hosts that don't normally initiate them |
| C2 | Long-lived or periodic flows to rare external IPs (`beaconing-hunt`) |
| Policy | Flows violating intended segmentation (`network-segmentation-review`) |

## Athena (AWS VPC Flow Logs) example

```sql
SELECT srcaddr, dstaddr, SUM(bytes) AS bytes_out
FROM vpc_flow_logs
WHERE day = '2025/03/01' AND action = 'ACCEPT'
  AND srcaddr LIKE '10.%' AND NOT (dstaddr LIKE '10.%' OR dstaddr LIKE '172.%' OR dstaddr LIKE '192.168.%')
GROUP BY srcaddr, dstaddr
ORDER BY bytes_out DESC
LIMIT 50;
```
(Table/partition names depend on how the flow log table was created; use Athena partition projection for performance.)

nfdump (on-prem collectors): `nfdump -R /var/cache/nfdump -s srcip/bytes -n 20 'dst net not 10.0.0.0/8'`.

## Caveats

- NAT hides internal sources — correlate with NAT/firewall translation logs.
- Sampled flows (sFlow, sampled NetFlow) undercount; don't use for exact byte totals.
- Flow records are split by timeouts; aggregate by 5-tuple and time window.

## Related skills

`beaconing-hunt`, `network-segmentation-review`, `cloud-incident-response`, `data-exposure-investigation`

## References

- AWS VPC Flow Logs: https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html
- Azure virtual network flow logs: https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview
- GCP VPC Flow Logs: https://cloud.google.com/vpc/docs/flow-logs
- nfdump: https://github.com/phaag/nfdump
