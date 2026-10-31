---
name: secure-build-workflow
description: Engineering standard for building defensive security artifacts — firewalls, hardening configs, detection pipelines, IDS/log shipping deployments, security tools and IaC — from requirements and threat model through generation, automated validation, isolated testing, staged rollout with rollback, monitoring and documentation. Use whenever you are asked to write, configure, deploy or automate a blue-team control rather than just review one; every other security-engineering skill follows it.
license: MIT
metadata:
  category: security-engineering
  version: "2.1.0"
  verification: documented
---

# Secure Build Workflow

When asked to *build* a defensive control, the deliverable is a working, tested, reversible change. A snippet is not enough. Work through these stages and show the evidence for each.

## 1. Requirements

Write down (and confirm with the requester when unknown):
- **Purpose:** the threat or risk the control addresses, and the success criterion.
- **Environment:** OS/distribution and version, cloud, network layout, existing controls and managers (ufw/firewalld, config management, GitOps).
- **Inventory:** every legitimate flow, user and service that must keep working.
- **Management and recovery path:** console, bastion, break-glass.
- **Constraints:** change windows, compliance requirements, performance.

**Never guess** values whose wrong guess causes an outage or lockout: admin source IPs, required ports, certificates, DNS names. Ask.

## 2. Design

- Default deny / least privilege, explicit allowlists, secure defaults (TLS 1.2+, no passwords where keys or certs work, no debug interfaces).
- Fail safe: decide what happens if the control fails open or closed, and document it.
- Separate **policy** (human-reviewable data: JSON/YAML) from **generated artifact** (config/code). Generators validate input and reject unknown keys.
- Idempotent and atomic changes; manage only the objects you own (your own nft table, a drop-in config file, a dedicated systemd unit).

## 3. Build

- Generate or write the artifact with comments that name the policy source.
- No secrets in files or Git: reference a secret store or environment, with file permissions 0600 where secrets must live on disk.
- Pin versions (packages, container images by digest, actions by SHA).

## 4. Validate (automated)

| Artifact | Validators |
|---|---|
| nftables | `nft -c -f`, `netns_test.py` (`host-firewall-build`) |
| sshd | `sshd -t -f`, `sshd -T` assertions (`ssh-hardening-build`) |
| nginx | `nginx -t`, `testssl.sh` against staging |
| Suricata | `suricata -T -c`, run against PCAPs |
| Vector / Fluent Bit | `vector validate`, `fluent-bit --dry-run` |
| Ansible | `ansible-lint`, `--check --diff`, Molecule |
| Terraform | `terraform fmt -check`, `validate`, `plan`, Checkov/Trivy config, OPA/conftest |
| Shell | `shellcheck`, `set -euo pipefail`, `LC_ALL=C` for regex/ranges |
| Python | unit tests, `ruff`/`bandit`, type hints at boundaries |

## 5. Test in isolation

Use network namespaces, containers, VMs or a staging account. Include a **positive test** (legitimate use still works) and a **negative test** (the attack or unauthorized flow fails). Record the commands and outputs.

## 6. Roll out safely

Use a canary or one host first. Arrange an automatic rollback (timer, health check, previous config kept) and an out-of-band access path. Get change approval for production. Verify from a fresh session or client after applying.

## 7. Operate

Persist the change across reboots, monitor it (counters, logs to SIEM, health alerts), document ownership, and keep the policy in version control with review.

## Deliverable checklist

- [ ] Requirements and assumptions stated
- [ ] Policy/source file + generated artifact
- [ ] Validation output (all passing)
- [ ] Isolated test evidence (positive + negative)
- [ ] Rollout and rollback procedure
- [ ] Monitoring and ownership notes

## Related skills

`host-firewall-build`, `ssh-hardening-build`, `security-tool-development`, `tls-reverse-proxy-build`, `threat-modeling`

## References

- NIST SP 800-160 Vol. 1 Rev. 1 Engineering Trustworthy Secure Systems: https://csrc.nist.gov/pubs/sp/800/160/v1/r1/final
- NIST SP 800-218 Secure Software Development Framework: https://csrc.nist.gov/pubs/sp/800/218/final
- CISA Secure by Design: https://www.cisa.gov/securebydesign
