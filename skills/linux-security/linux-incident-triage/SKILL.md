---
name: linux-incident-triage
description: Perform live triage of a potentially compromised Linux server — processes, network connections, users, recent files, deleted-but-running binaries, kernel modules, containers — with built-in commands while preserving evidence. Use when a Linux host shows suspicious activity (cryptominer, web shell, unknown SSH logins, outbound C2) and you need answers before imaging.
license: MIT
metadata:
  category: linux-security
  version: "2.0.0"
  verification: documented
---

# Linux Incident Triage

Run from trusted binaries if possible (statically linked busybox on read-only media) — a rootkit can lie to the host's `ps`/`ls`. Write output off-host. Capture memory first if feasible (`forensic-imaging`, AVML).

## Collection (read-only, in this order)

```sh
OUT=/mnt/usb/triage-$(hostname)-$(date -u +%Y%m%dT%H%M%SZ); mkdir -p "$OUT"
date -u > "$OUT/time.txt"; uptime >> "$OUT/time.txt"; timedatectl >> "$OUT/time.txt" 2>&1
ps -eo pid,ppid,user,lstart,etimes,cmd --sort=start_time > "$OUT/ps.txt"
ss -tunap > "$OUT/ss.txt"                       # sockets with owning process
ls -l /proc/*/exe 2>/dev/null | grep -E '\(deleted\)' > "$OUT/deleted_exe.txt"   # running deleted binaries
for p in /proc/[0-9]*; do printf '%s %s\n' "${p#/proc/}" "$(tr '\0' ' ' < $p/cmdline)"; done > "$OUT/cmdline.txt"
who -a > "$OUT/who.txt"; last -Faiw > "$OUT/last.txt"; lastb -Faiw > "$OUT/lastb.txt" 2>/dev/null
cat /etc/passwd /etc/group > "$OUT/accounts.txt"; awk -F: '$3==0' /etc/passwd > "$OUT/uid0.txt"
lsmod > "$OUT/lsmod.txt"; cat /proc/modules > "$OUT/proc_modules.txt"
find / -xdev \( -path /proc -o -path /sys \) -prune -o -type f -mtime -3 -printf '%T@ %p\n' 2>/dev/null | sort -n > "$OUT/recent_files.txt"
find / -xdev -perm -4000 -type f 2>/dev/null > "$OUT/suid.txt"
crontab -l -u root > "$OUT/root_cron.txt" 2>&1; ls -la /etc/cron* /var/spool/cron* > "$OUT/cron_ls.txt" 2>&1
systemctl list-units --type=service --all > "$OUT/services.txt"; systemctl list-timers --all > "$OUT/timers.txt"
cat /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys > "$OUT/authorized_keys.txt" 2>/dev/null
cp -a /var/log "$OUT/varlog" 2>/dev/null; journalctl --since "-7 days" -o short-iso-precise > "$OUT/journal.txt"
docker ps -a > "$OUT/docker.txt" 2>/dev/null; crictl ps -a >> "$OUT/docker.txt" 2>/dev/null
sha256sum "$OUT"/* > "$OUT/SHA256SUMS" 2>/dev/null
```

## Red flags

- Process with `(deleted)` exe, or running from `/tmp`, `/dev/shm`, `/var/tmp`, hidden dirs (`/.x`, `/usr/lib/.cache`).
- Process name mismatching `/proc/PID/exe` (e.g. `[kworker]` with a userspace exe — kernel threads have no exe link).
- High CPU + outbound to mining pools (ports 3333/4444/5555/14444, stratum) — cryptominers.
- Web server user (`www-data`, `nginx`, `apache`) spawning `sh`, `bash`, `curl`, `wget`, `python`, `nc`.
- New UID 0 accounts, unknown SSH keys, `PermitRootLogin yes` changes, modified `/etc/ld.so.preload` (userland rootkit).
- Kernel modules not from distro packages (`modinfo <mod>` path/signature), `taint` in `/proc/sys/kernel/tainted`.
- Package integrity failures: `rpm -Va` / `debsums -c` / `dpkg --verify` on `/bin`, `/usr/bin`, `/sbin`.

## Preserve a suspicious running binary

`cp /proc/<PID>/exe "$OUT/pid<PID>.bin"; cat /proc/<PID>/maps > "$OUT/pid<PID>.maps"` — recovers deleted binaries.

## Related skills

`linux-persistence-hunt`, `linux-log-analysis`, `forensic-imaging`, `memory-forensics`, `web-shell-detection`

## References

- SANS Linux forensics / "Hunt Evil Linux": https://www.sans.org/posters/
- Sandfly Security Linux compromise detection blog: https://sandflysecurity.com/blog/
- AVML: https://github.com/microsoft/avml
