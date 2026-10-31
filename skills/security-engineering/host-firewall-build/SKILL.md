---
name: host-firewall-build
description: Design, generate, test and safely deploy a Linux host firewall with nftables — default-deny inbound, source allowlists, per-source SSH rate limiting, required ICMP/ICMPv6, optional egress control and logging — from a validated JSON policy, with real-traffic tests in isolated network namespaces and an auto-rollback apply script that prevents lockout. Use when building or replacing a server firewall, converting iptables/ufw rules to nftables, or locking down a host's exposed services.
license: MIT
metadata:
  category: security-engineering
  version: "2.1.0"
  verification: tested
---

# Host Firewall Build (nftables)

Follows `secure-build-workflow`: requirements → policy → generate → test → staged apply → persist → document.

## 1. Requirements (ask before writing rules)

- Host role and every service that must be reachable: port, protocol, **who** needs it (CIDRs, not "everyone" by default).
- Management path: SSH/admin source networks or bastion. If this is unknown, stop: a wrong guess locks people out.
- IPv6 in use? Container runtimes (Docker/Podman/Kubernetes) on the host? Docker manages its own tables, and published container ports bypass `input`; restrict them in the `DOCKER-USER` chain or bind them to `127.0.0.1`.
- Egress control wanted? If so, list the required destinations: DNS, NTP, package mirrors, log/SIEM collector, EDR cloud, backup.

## 2. Write the policy

```sh
python3 scripts/nft_policy.py --example > policy.json     # starter; edit it
python3 scripts/nft_policy.py policy.json --explain       # review in plain language
```
```json
{
  "name": "web-server",
  "inbound": [
    {"name": "ssh", "proto": "tcp", "ports": [22], "sources": ["10.20.0.0/24"], "rate_limit": "10/minute", "management": true},
    {"name": "web", "proto": "tcp", "ports": [80, 443], "sources": ["any"]},
    {"name": "node_exporter", "proto": "tcp", "ports": [9100], "sources": ["10.20.5.10"]}
  ],
  "default_output": "accept"
}
```
The generator refuses unsafe or ambiguous policies:
- invalid CIDRs or ports, or unknown keys (typos);
- duplicate rule names;
- no rule marked `"management": true`, which would lock out administration.

It also warns about sensitive ports such as 22, 3389, 3306, 6379 or 9200 opened to `any`, and about egress-drop policies with no outbound rules. Use `--strict` in CI to turn warnings into failures.

## 3. Generate

```sh
python3 scripts/nft_policy.py policy.json -o firewall.nft
```
The output does the following:
- manages **only** `table inet cb_filter`, replacing it atomically (`table …; delete table …; table … { }`), so it never runs `flush ruleset` and never touches Docker, libvirt or firewalld tables;
- uses `policy drop` on input and forward;
- drops `ct state invalid` and accepts established/related traffic and loopback;
- drops spoofed loopback source addresses;
- allows the ICMPv6 needed for neighbour discovery and PMTU, and the ICMPv4 error types;
- matches allowlists through interval sets;
- applies per-source rate limits with dynamic sets (`add @set { ip saddr limit rate over … }`);
- adds counters and comments on every rule, plus rate-limited drop logging.

## 4. Test before touching a real host

```sh
python3 scripts/netns_test.py policy.json firewall.nft
python3 scripts/netns_test.py policy.json firewall.nft --source 10.20.0.9 --source 198.51.100.4
```
The harness needs **no root and never touches the host network**. It re-executes under `unshare -rn`, then:
1. creates one client namespace per probe source, connected by a veth pair;
2. starts TCP/UDP listeners on every policy port;
3. loads the ruleset;
4. checks with real connections that each source reaches exactly the ports the policy allows (and port 9 is always blocked).

Exit code 0 means every probe matched the policy.

## 5. Apply safely (lockout prevention)

```sh
sudo ./scripts/safe_apply.sh firewall.nft 120
```
The script:
1. syntax-checks the file (`nft -c`);
2. backs up the current `cb_filter` table only;
3. applies the new ruleset;
4. starts a **detached rollback timer** that still fires if your SSH session dies;
5. keeps the change only if you type `yes` within the timeout.

Confirm from a **second, new** SSH session: an existing session survives on established/related state even when new connections are blocked. Have console/out-of-band access available for the first rollout. Change windows apply to production hosts.

## 6. Persist and operate

- Debian/Ubuntu/RHEL/Arch: put the file at `/etc/nftables.d/50-cb-filter.nft` and include it from `/etc/nftables.conf`, then run `systemctl enable --now nftables`. Disable conflicting managers (`ufw`, `firewalld`) or translate the policy into them instead. Never run two managers on the same hooks unknowingly.
- Commit `policy.json` and `firewall.nft` to Git. Changes go through review, and CI runs `nft_policy.py --strict` plus `netns_test.py`.
- Monitoring: `nft list ruleset -a` shows counters. Drops are logged with the prefix `cb_filter-in-drop:`, read them with `journalctl -k | grep cb_filter`. Ship them to the SIEM and alert on repeated drops from internal hosts (possible lateral movement).

## Deliverables

`policy.json` · generated `firewall.nft` · `netns_test.py` output (all probes ok) · apply record (time, operator, confirmation, rollback plan) · persistence location · monitoring query.

## Related skills

`secure-build-workflow`, `firewall-rule-review`, `network-segmentation-review`, `cloud-firewall-build`, `linux-hardening`

## References

- nftables wiki (quick reference, sets, meters): https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
- nft(8) man page: https://www.netfilter.org/projects/nftables/manpage.html
- RFC 4890 ICMPv6 filtering recommendations: https://www.rfc-editor.org/rfc/rfc4890
- Docker and nftables/iptables (DOCKER-USER): https://docs.docker.com/engine/network/packet-filtering-firewalls/
