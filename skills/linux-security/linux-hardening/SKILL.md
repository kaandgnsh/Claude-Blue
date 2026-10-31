---
name: linux-hardening
description: Assess and harden Linux servers against CIS Benchmarks — SSH configuration, accounts and sudo, patching, filesystem mount options, kernel sysctls, service minimization, MAC (SELinux/AppArmor), logging — using Lynis, OpenSCAP and manual checks. Use when building a server baseline, reviewing a hardening report, or remediating Linux findings.
license: MIT
metadata:
  category: linux-security
  version: "2.0.0"
  verification: documented
---

# Linux Hardening

## Assessment tools

```sh
lynis audit system --quick                                   # findings + hardening index
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis \
  --results results.xml --report report.html /usr/share/xml/scap/ssg/content/ssg-<distro>-ds.xml
```
OpenSCAP profile IDs and datastream file names vary by distribution — list with `oscap info <ds.xml>`.

## Priority controls

| Area | Control | Check |
|---|---|---|
| SSH | `PermitRootLogin no`, `PasswordAuthentication no` (keys/certs), `MaxAuthTries 3`, `LoginGraceTime 30`, `AllowGroups`, `LogLevel VERBOSE` | `sshd -T \| grep -Ei 'permitrootlogin|passwordauthentication|maxauthtries'` |
| Patching | Automatic security updates or tracked patch SLA | `unattended-upgrades` / `dnf-automatic`; `needrestart` for running old libs |
| Accounts | No UID 0 except root, no empty passwords, locked system accounts | `awk -F: '($3==0)' /etc/passwd`; `awk -F: '($2=="")' /etc/shadow` |
| sudo | No `NOPASSWD: ALL` for humans, `Defaults use_pty`, `logfile` | `sudo -l -U <user>`; review `/etc/sudoers.d` |
| Filesystems | `/tmp`, `/dev/shm`, `/var/tmp` with `nodev,nosuid,noexec` | `findmnt -no OPTIONS /tmp` |
| Kernel | `kernel.kptr_restrict=2`, `kernel.dmesg_restrict=1`, `kernel.yama.ptrace_scope=1+`, `net.ipv4.conf.all.rp_filter=1`, `net.ipv4.conf.all.accept_redirects=0`, `fs.suid_dumpable=0` | `sysctl -a \| grep -E '...'` |
| Services | Disable unneeded listeners | `ss -tulpn` |
| MAC | SELinux enforcing / AppArmor enabled | `getenforce`, `aa-status` |
| Logging | auditd running with rules; remote log forwarding | `systemctl is-active auditd`; `auditctl -l` |
| Integrity | AIDE or package verification | `aide --check`; `rpm -Va` |

## Workflow

1. Classify server role; pick CIS Level 1 (default) or Level 2 (high security) profile.
2. Scan, export results, and triage: break-fix risk vs. security gain.
3. Apply via configuration management (Ansible role, e.g. `ansible-lockdown`, or `oscap --remediate` in test first).
4. Re-scan; document accepted exceptions with expiry (`security-exception-management`).

## Safety

Test SSH changes with a second open session before restarting `sshd` to avoid lockout; validate `sshd -t` first. Apply mount option changes during maintenance windows.

## Related skills

`auditd-rules`, `endpoint-hardening`, `vuln-prioritization`, `security-exception-management`, `ssh-hardening-build`

## References

- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
- Lynis: https://cisofy.com/lynis/
- OpenSCAP / SCAP Security Guide: https://www.open-scap.org/ , https://github.com/ComplianceAsCode/content
