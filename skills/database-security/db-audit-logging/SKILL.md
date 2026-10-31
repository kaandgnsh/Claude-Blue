---
name: db-audit-logging
description: Configure and use database audit logging for security — PostgreSQL pgaudit, MySQL/MariaDB audit plugins, SQL Server Audit, Oracle Unified Auditing, cloud database audit (RDS, Azure SQL, Cloud SQL), MongoDB auditing — capturing logins, privilege changes, schema changes and sensitive-table access without crippling performance. Use when enabling database monitoring, meeting audit requirements, or preparing to investigate database access.
license: MIT
metadata:
  category: database-security
  version: "2.0.0"
  verification: documented
---

# Database Audit Logging

## What to capture

Successful and failed logins (with client host/app), privilege and role changes (GRANT/REVOKE/CREATE USER), schema changes (DDL), configuration changes, access to sensitive tables (SELECT on PII/financial tables), bulk exports (`COPY TO`, `bcp`, `SELECT INTO OUTFILE`), admin/superuser sessions. Avoid logging full statement text for high-volume app queries unless needed (cost, and statements can contain PII).

## Engines

PostgreSQL (pgaudit):
```sql
-- postgresql.conf: shared_preload_libraries = 'pgaudit'
ALTER SYSTEM SET pgaudit.log = 'role, ddl, write';    -- session-level classes
ALTER SYSTEM SET log_connections = on; ALTER SYSTEM SET log_disconnections = on;
-- object-level auditing for a sensitive table via an audit role
CREATE ROLE auditor NOLOGIN; ALTER SYSTEM SET pgaudit.role = 'auditor';
GRANT SELECT ON customers TO auditor;                   -- SELECTs on customers now audited
SELECT pg_reload_conf();
```
SQL Server:
```sql
CREATE SERVER AUDIT SecAudit TO FILE (FILEPATH = 'D:\Audit\'); ALTER SERVER AUDIT SecAudit WITH (STATE = ON);
CREATE SERVER AUDIT SPECIFICATION SecSpec FOR SERVER AUDIT SecAudit
  ADD (FAILED_LOGIN_GROUP), ADD (SUCCESSFUL_LOGIN_GROUP), ADD (SERVER_ROLE_MEMBER_CHANGE_GROUP), ADD (DATABASE_PERMISSION_CHANGE_GROUP)
  WITH (STATE = ON);
```
MySQL: Enterprise Audit, Percona Audit Log plugin, or MariaDB `server_audit` (`server_audit_events='CONNECT,QUERY_DDL,QUERY_DCL'`). Oracle: Unified Auditing policies (`CREATE AUDIT POLICY ... ; AUDIT POLICY ...`). MongoDB Enterprise/Atlas: `auditLog` with filters.

Cloud: RDS/Aurora parameter groups (pgaudit / MariaDB audit plugin) + export to CloudWatch; Azure SQL Auditing to Log Analytics; Cloud SQL `cloudsql.enable_pgaudit` + Data Access logs; Database Activity Streams (Aurora) for tamper-resistant streams.

## Integrity

Send to SIEM promptly; DBAs should not be able to alter audit trails without detection (separate storage, alert on audit disable events — e.g., SQL Server `AUDIT_CHANGE_GROUP`, PostgreSQL config changes).

## Related skills

`db-exfiltration-investigation`, `db-privilege-review`, `log-source-onboarding`

## References

- pgaudit: https://github.com/pgaudit/pgaudit
- SQL Server Audit: https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine
- Oracle Unified Auditing: https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/introduction-to-auditing.html
- MariaDB Audit Plugin: https://mariadb.com/kb/en/mariadb-audit-plugin/
