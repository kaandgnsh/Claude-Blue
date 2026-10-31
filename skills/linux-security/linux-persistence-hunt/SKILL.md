---
name: linux-persistence-hunt
description: Hunt Linux persistence — cron/anacron/at, systemd services/timers/generators, shell rc files, SSH authorized_keys, ld.so.preload, PAM modules, udev rules, kernel modules, MOTD scripts and web shells. Use when sweeping Linux servers after compromise, verifying eradication, or building persistence detections.
license: MIT
metadata:
  category: linux-security
  version: "2.0.0"
  verification: documented
---

# Linux Persistence Hunt

## Locations and checks

| Mechanism | ATT&CK | Check |
|---|---|---|
| Cron / at | T1053.003 | `/etc/crontab`, `/etc/cron.d/*`, `/etc/cron.{hourly,daily,weekly,monthly}`, `/var/spool/cron/{crontabs/,}*`, `atq` |
| systemd | T1543.002 | `systemctl list-unit-files --state=enabled`; unit files in `/etc/systemd/system`, `/lib/systemd/system`, `~/.config/systemd/user/`; generators `/etc/systemd/system-generators/`; timers |
| Shell init | T1546.004 | `/etc/profile`, `/etc/profile.d/*`, `/etc/bash.bashrc`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zshrc` |
| SSH keys | T1098.004 | `~/.ssh/authorized_keys` (incl. `command=` options), `AuthorizedKeysFile` overrides in `sshd_config` |
| Preload | T1574.006 | `/etc/ld.so.preload` (normally absent), `LD_PRELOAD` in environment files |
| PAM | T1556.003 | Unexpected modules in `/etc/pam.d/*`, non-package `.so` in `/lib*/security/` |
| Kernel modules | T1547.006 | `/etc/modules`, `/etc/modules-load.d/`, out-of-tree modules |
| udev | T1546 | `/etc/udev/rules.d/*` with `RUN+=` |
| MOTD / update-motd | T1546 | `/etc/update-motd.d/*` (run as root at SSH login) |
| Init scripts | T1037 | `/etc/rc.local`, `/etc/init.d/` |
| Accounts | T1136 | New users, UID 0 duplicates, sudoers changes (`/etc/sudoers`, `/etc/sudoers.d/`) |
| Web shells | T1505.003 | See `web-shell-detection` |

## Sweep commands

```sh
# Files in persistence locations changed in the last 30 days
find /etc/cron* /var/spool/cron /etc/systemd /lib/systemd/system /etc/profile* /etc/pam.d /etc/ld.so.preload \
     /etc/update-motd.d /etc/udev/rules.d /etc/sudoers* /root /home/*/.ssh /home/*/.bashrc \
     -xdev -type f -mtime -30 -printf '%TY-%Tm-%Td %TH:%TM %u %p\n' 2>/dev/null | sort
# Files not owned by any package (Debian / RHEL)
dpkg -S /etc/systemd/system/*.service 2>&1 | grep 'no path found'
rpm -qf /etc/systemd/system/*.service | grep 'not owned'
# Unit files executing from suspicious paths
grep -rEn 'Exec(Start|StartPre|StartPost)=.*(/tmp|/dev/shm|/var/tmp|curl|wget|base64|bash -c)' /etc/systemd /lib/systemd /usr/lib/systemd 2>/dev/null
```
Fleet: osquery tables `crontab`, `systemd_units`, `authorized_keys`, `startup_items`, `kernel_modules`; Velociraptor `Linux.Sys.Crontab`, `Linux.Ssh.AuthorizedKeys`.

## Detection (auditd)

Watch persistence paths with `-w` rules (`auditd-rules`) and alert on writes by non-package-manager processes.

## Output

`Host | Mechanism | Path | Content/Command | Owner | mtime/ctime UTC | Package-owned? | Verdict`

## Related skills

`linux-incident-triage`, `auditd-rules`, `osquery-investigation`, `eradication-recovery`

## References

- MITRE ATT&CK Linux matrix: https://attack.mitre.org/matrices/enterprise/linux/
- osquery schema: https://github.com/osquery/osquery/tree/master/specs
