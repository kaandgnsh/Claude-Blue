---
name: db-exfiltration-investigation
description: Investigate suspected database data theft — anomalous query volume, bulk SELECT/export commands, new logins from unusual hosts, SQL injection traces in web logs, backup/snapshot exports, dump tool usage — using database audit logs, application logs, network and cloud control-plane logs to scope records taken. Use when a database may have been dumped, SQL injection was exploited, or stolen data appears externally.
license: MIT
metadata:
  category: database-security
  version: "2.0.0"
  verification: documented
---

# Database Exfiltration Investigation

## Exfil paths and evidence

| Path | Evidence |
|---|---|
| SQL injection via web app | Web/WAF logs with injection payloads (`UNION SELECT`, `information_schema`, `sleep(`, `WAITFOR DELAY`, `xp_cmdshell`), large response sizes, sqlmap user agents; DB logs of unusual queries from the app account (`web-server-log-analysis`) |
| Stolen DB credentials | Logins from new client hosts/IPs/apps (`application_name`, `client_addr`, SQL Server `client_net_address`/`program_name`) |
| Dump tools | `pg_dump`, `mysqldump`, `bcp`, `sqlcmd -Q "SELECT..." -o`, `mongodump`, `expdp` on servers or jump hosts (EDR process events) |
| Bulk export features | `COPY ... TO`, `SELECT ... INTO OUTFILE`, SSIS/BACPAC exports, BigQuery `EXPORT DATA` |
| Backups/snapshots | Cloud: `ModifyDBSnapshotAttribute`/`CopyDBSnapshot` to another account, `StartExportTask` (RDS export to S3), Azure SQL `Export`, GCS exports; backup files copied off-host |
| Replication | New replica/subscription to external host |

## Queries

PostgreSQL current/recent activity (live): `SELECT usename, client_addr, application_name, backend_start, query FROM pg_stat_activity WHERE state <> 'idle';`
SQL Server audit file: `SELECT event_time, server_principal_name, client_ip, application_name, statement FROM sys.fn_get_audit_file('D:\Audit\*.sqlaudit', DEFAULT, DEFAULT) WHERE statement LIKE '%SELECT%customers%';`
AWS: CloudTrail for `rds:` snapshot/export events (`cloudtrail-investigation`); Performance Insights / Database Activity Streams for query history.

## Scoping records

1. Identify the queries/exports and their time window.
2. Determine row counts returned (audit logs with row counts, app logs with response sizes, re-run the query read-only on a restored snapshot from that time to count rows).
3. Map columns to data categories for `privacy-incident-assessment`.

## Contain

Rotate compromised DB and application credentials, block attacker IPs, patch the injection flaw (and add WAF virtual patch), revoke snapshot sharing, review new users/grants created during the window.

## Related skills

`db-audit-logging`, `web-server-log-analysis`, `data-exposure-investigation`, `privacy-incident-assessment`

## References

- MITRE ATT&CK T1213 Data from Information Repositories: https://attack.mitre.org/techniques/T1213/
- OWASP SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- PostgreSQL monitoring stats (pg_stat_activity): https://www.postgresql.org/docs/current/monitoring-stats.html
