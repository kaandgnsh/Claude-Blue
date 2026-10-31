---
name: osquery-investigation
description: Investigate and sweep endpoints with osquery SQL (osqueryi, Fleet, Kolide) — processes without binaries on disk, listening ports, persistence, users, kernel modules, file hashes — across Windows, macOS and Linux. Use when you need fast cross-platform endpoint answers, fleet-wide IOC sweeps, or scheduled detection queries.
license: MIT
metadata:
  category: endpoint-security
  version: "2.0.0"
  verification: documented
---

# osquery Investigation

## Query library

```sql
-- Processes whose binary was deleted from disk (Linux/macOS: on_disk = 0)
SELECT pid, name, path, cmdline, parent FROM processes WHERE on_disk = 0;

-- Processes running from temp/user-writable paths
SELECT pid, name, path, cmdline FROM processes
WHERE path LIKE '/tmp/%' OR path LIKE '/dev/shm/%' OR path LIKE '%\AppData\%' OR path LIKE '%\Temp\%';

-- Listening ports with owning process
SELECT lp.port, lp.address, lp.protocol, p.name, p.path FROM listening_ports lp
JOIN processes p USING (pid) WHERE lp.address NOT IN ('127.0.0.1', '::1');

-- Outbound connections per process
SELECT p.name, p.path, s.remote_address, s.remote_port FROM process_open_sockets s
JOIN processes p USING (pid) WHERE s.remote_address NOT IN ('', '0.0.0.0', '127.0.0.1', '::', '::1');

-- SSH authorized keys for all users (Linux/macOS)
SELECT u.username, ak.key, ak.key_file FROM users u CROSS JOIN authorized_keys ak USING (uid);

-- Persistence: Windows autoruns / macOS launchd / Linux cron & systemd
SELECT name, path, source, status FROM startup_items;
SELECT label, program, program_arguments, path FROM launchd WHERE run_at_load = '1';
SELECT command, path FROM crontab;
SELECT id, fragment_path, active_state FROM systemd_units WHERE active_state = 'active';

-- IOC sweep: hash a specific path
SELECT path, sha256 FROM hash WHERE path = '/usr/local/bin/suspicious';
-- IOC sweep: find by file name under a directory (bounded!)
SELECT path, size, mtime FROM file WHERE path LIKE '/var/www/%%' AND filename LIKE '%.php' AND mtime > (strftime('%s','now') - 86400*7);
```
Table availability differs per OS — check https://github.com/osquery/osquery/tree/master/specs for the deployed version.

## Fleet sweeps

- Use live queries (Fleet/Kolide/osctrl) for incident sweeps; scheduled `packs` for continuous detection with `differential` results to the SIEM.
- Bound `file`/`hash` queries with specific paths: recursive `%%` over `/` or `C:\` is expensive.
- Record query text, target labels, time, and responded/total host counts — non-responding hosts are unknowns, not negatives.

## Detection ideas for scheduled queries

`processes WHERE on_disk = 0`, new `listening_ports`, changes to `authorized_keys`, `kernel_modules` not in baseline, `startup_items` diffs, `chrome_extensions`/`firefox_addons` with broad permissions.

## Related skills

`velociraptor-collection`, `linux-persistence-hunt`, `macos-persistence-review`, `stack-counting-hunt`

## References

- osquery documentation: https://osquery.readthedocs.io/
- osquery schema: https://github.com/osquery/osquery/tree/master/specs
- Fleet: https://fleetdm.com/docs
