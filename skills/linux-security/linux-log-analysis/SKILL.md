---
name: linux-log-analysis
description: Analyze Linux authentication and system logs — auth.log/secure, journald, sudo, sshd, wtmp/btmp/lastlog, package and kernel logs — to find brute force, successful intrusions, privilege escalation and tampering. Use when investigating SSH logins, sudo abuse or suspicious activity on Linux from logs.
license: MIT
metadata:
  category: linux-security
  version: "2.0.0"
  verification: documented
---

# Linux Log Analysis

## Where logs are

| Data | Debian/Ubuntu | RHEL/Fedora | journald |
|---|---|---|---|
| Auth/SSH/sudo | `/var/log/auth.log` | `/var/log/secure` | `journalctl _COMM=sshd`, `_COMM=sudo` |
| System | `/var/log/syslog` | `/var/log/messages` | `journalctl` |
| Logins | `/var/log/wtmp` (`last`), `/var/log/btmp` (`lastb`), `/var/log/lastlog` (`lastlog`) | same | |
| Packages | `/var/log/dpkg.log`, `/var/log/apt/history.log` | `/var/log/dnf.log`, `yum.log` | |
| Kernel | `/var/log/kern.log` | `dmesg`, `messages` | `journalctl -k` |
| Audit | `/var/log/audit/audit.log` | same | see `auditd-rules` |

Note: some minimal distros only keep journald (possibly volatile — check `Storage=` in `/etc/systemd/journald.conf`).

## Useful extractions

```sh
# Successful SSH logins (method, user, source)
grep -E 'sshd\[[0-9]+\]: Accepted' /var/log/auth.log* | awk '{print $1,$2,$3,$9,$11,$7}'
journalctl _COMM=sshd --since "2025-03-01" -o short-iso | grep Accepted
# Failed passwords by source IP
grep -h 'Failed password' /var/log/auth.log* | grep -oE 'from [0-9a-f.:]+' | sort | uniq -c | sort -rn | head
# Invalid users tried
grep -h 'Invalid user' /var/log/auth.log* | awk '{print $8}' | sort | uniq -c | sort -rn | head
# Successful login from an IP that also brute forced
comm -12 <(grep -h 'Failed password' /var/log/auth.log* | grep -oE 'from [0-9.]+' | sort -u) \
         <(grep -h 'Accepted' /var/log/auth.log* | grep -oE 'from [0-9.]+' | sort -u)
# sudo usage
grep -h 'sudo:' /var/log/auth.log* | grep -E 'COMMAND=' 
# wtmp from an image
last -Faiwx -f /mnt/img/var/log/wtmp
```

## Tampering indicators

- Gaps in timestamps, truncated files (size 0 with recent mtime), `wtmp`/`lastlog` inconsistencies with auth.log, `history -c`, `unset HISTFILE`, `HISTSIZE=0` in shell rc, `/dev/null` symlinked `.bash_history`.
- `rsyslog`/`journald` stopped or config changed; compare with central log copies — attackers can't edit what's already forwarded.

## Interpretation

- `Accepted publickey` vs `Accepted password` — key-based login from new IP with new key fingerprint (logged as `SHA256:...`) means check `authorized_keys`.
- `session opened for user root by (uid=0)` from cron is normal; from `sshd` for `root` may violate policy.

## Related skills

`linux-incident-triage`, `auditd-rules`, `password-spray-detection`, `timeline-analysis`

## References

- journalctl man page: https://man7.org/linux/man-pages/man1/journalctl.1.html
- OpenSSH sshd logging (LogLevel VERBOSE logs key fingerprints): https://man.openbsd.org/sshd_config
