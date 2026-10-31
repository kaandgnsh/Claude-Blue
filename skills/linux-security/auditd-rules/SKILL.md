---
name: auditd-rules
description: Design, deploy and tune Linux auditd rules for security monitoring — execve logging, identity/sudoers/SSH file watches, privilege escalation, kernel module loading, time changes — and query them with ausearch/aureport. Use when building Linux detection telemetry, meeting audit requirements, or investigating with audit.log.
license: MIT
metadata:
  category: linux-security
  version: "2.0.0"
  verification: documented
---

# auditd Rules

## Baseline rule set (`/etc/audit/rules.d/50-security.rules`)

```
## Buffer and failure mode
-b 8192
-f 1

## Identity and authentication files
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /root/.ssh/ -p wa -k root_ssh

## Persistence locations
-w /etc/cron.d/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /etc/systemd/system/ -p wa -k systemd
-w /etc/ld.so.preload -p wa -k preload

## Kernel modules
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
-w /usr/sbin/insmod -p x -k modules
-w /usr/sbin/modprobe -p x -k modules

## Time changes
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time_change

## Command execution (high volume: consider limiting to euid=0 or interactive auid)
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k root_cmd
-a always,exit -F arch=b32 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k root_cmd

## Make configuration immutable until reboot (last line)
-e 2
```
Load: `augenrules --load`; verify: `auditctl -l`, `auditctl -s` (check `lost` counter). On 64-bit systems add matching `arch=b32` syscall rules to avoid 32-bit bypass. Prefer the community baselines (Neo23x0/auditd, Florian Roth) as a starting point.

## Querying

```sh
ausearch -k identity -ts today -i                 # interpreted
ausearch -k root_cmd -ts recent -i | grep -E 'proctitle|exe='
ausearch -m USER_LOGIN,USER_AUTH --success no -ts this-week -i
aureport --summary; aureport -x --summary         # executables
aureport -au --failed                             # failed authentications
```
`auid` (login UID) survives `sudo`/`su` — use it to attribute root actions to the original user.

## Tuning

- `execve` for all users is very noisy; scope by `auid`/`euid`, and exclude known noisy daemons with `-a never,exit -F exe=/path/to/daemon` rules placed *before* the logging rules (first match wins).
- Watch `lost`/`backlog` in `auditctl -s`; raise `-b` and use `--backlog_wait_time`.
- Forward via audisp plugins/`laurel` (JSON enrichment) or the SIEM agent (Elastic Auditbeat, Splunk TA for Linux).

## Related skills

`linux-persistence-hunt`, `linux-log-analysis`, `log-source-onboarding`

## References

- auditd rules man page: https://man7.org/linux/man-pages/man7/audit.rules.7.html
- Neo23x0 auditd baseline: https://github.com/Neo23x0/auditd
- Laurel (auditd log transformer): https://github.com/threathunters-io/laurel
