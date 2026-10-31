---
name: db-privilege-review
description: Review database privileges — superuser/sysadmin holders, application accounts with DDL or excessive rights, PUBLIC grants, shared DBA accounts, cross-database access, password vs. IAM/Kerberos authentication — for PostgreSQL, SQL Server, MySQL, Oracle and cloud databases. Use for database access audits, least-privilege remediation, or after suspected database compromise.
license: MIT
metadata:
  category: database-security
  version: "2.0.0"
  verification: documented
---

# Database Privilege Review

## Queries

PostgreSQL:
```sql
SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin, rolbypassrls, rolvaliduntil FROM pg_roles ORDER BY rolsuper DESC;
SELECT grantee, table_schema, table_name, privilege_type FROM information_schema.role_table_grants
 WHERE grantee NOT IN ('postgres') AND table_schema NOT IN ('pg_catalog','information_schema') ORDER BY grantee;
SELECT r.rolname, m.rolname AS member_of FROM pg_auth_members am JOIN pg_roles r ON r.oid = am.member JOIN pg_roles m ON m.oid = am.roleid;
```
SQL Server:
```sql
SELECT p.name, p.type_desc, r.name AS server_role FROM sys.server_role_members rm
 JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id JOIN sys.server_principals p ON rm.member_principal_id = p.principal_id;
SELECT dp.name, dp.type_desc, rp.name AS db_role FROM sys.database_role_members drm
 JOIN sys.database_principals rp ON drm.role_principal_id = rp.principal_id JOIN sys.database_principals dp ON drm.member_principal_id = dp.principal_id;
SELECT * FROM sys.database_permissions WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID('public') AND state_desc = 'GRANT';
```
MySQL:
```sql
SELECT user, host, Super_priv, Grant_priv, File_priv, Process_priv FROM mysql.user;
SHOW GRANTS FOR 'app'@'%';
```

## Findings

| Finding | Risk |
|---|---|
| App account with superuser/sysadmin/`db_owner`/DDL | SQL injection → full DB/host compromise (e.g. `xp_cmdshell`, `COPY ... PROGRAM`) |
| Accounts with host `%` (MySQL) or `0.0.0.0/0` in pg_hba | Login from anywhere |
| `FILE`/`pg_read_server_files`/`pg_execute_server_program` grants | Server file access / command execution |
| Shared DBA logins | No accountability |
| PUBLIC grants on sensitive objects | Everyone can read |
| Password auth for humans instead of IAM/Kerberos/SSO | Credential sprawl |
| Default/sample accounts (`sa` enabled, `scott`) | Easy targets |

## Fix

Per-application least-privilege roles (DML on specific schemas only), separate migration role for DDL used only by CI, named DBA accounts via PAM/JIT, IAM database authentication (RDS IAM auth, Entra auth for Azure SQL, Cloud SQL IAM), revoke PUBLIC, row-level security for multi-tenant data.

## Related skills

`db-hardening`, `db-audit-logging`, `privileged-access-review`, `access-certification`

## References

- PostgreSQL privileges: https://www.postgresql.org/docs/current/ddl-priv.html
- PostgreSQL predefined roles: https://www.postgresql.org/docs/current/predefined-roles.html
- SQL Server security best practices: https://learn.microsoft.com/en-us/sql/relational-databases/security/sql-server-security-best-practices
- CIS Benchmarks (databases): https://www.cisecurity.org/cis-benchmarks
