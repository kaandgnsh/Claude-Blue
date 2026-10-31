---
name: db-hardening
description: Harden database servers and managed databases — network exposure, TLS, authentication methods (pg_hba, SQL auth vs. Windows/Entra), dangerous features (xp_cmdshell, COPY PROGRAM, LOAD DATA LOCAL), encryption at rest/TDE, patching, backups encryption — against CIS benchmarks. Use when deploying or reviewing a database, after finding an internet-exposed database, or remediating database benchmark findings.
license: MIT
metadata:
  category: database-security
  version: "2.0.0"
  verification: documented
---

# Database Hardening

## Exposure and network

- Not internet-reachable; private subnets/endpoints only (`cloud-exposure-review`: `PubliclyAccessible`, public IP on Azure SQL/Cloud SQL, open 1433/3306/5432/27017/6379/9200).
- Host firewall / security groups restrict to app tiers and admin jump hosts.
- NoSQL/search engines: authentication **enabled** (MongoDB `security.authorization: enabled`, Redis `requirepass`/ACLs + `protected-mode yes`, Elasticsearch security features on) — unauthenticated instances are mass-scanned and ransomed within hours.

## Authentication & transport

- PostgreSQL `pg_hba.conf`: `hostssl` + `scram-sha-256`, no `trust`, no `0.0.0.0/0` for admin roles; `ssl = on`; `password_encryption = scram-sha-256`.
- SQL Server: Windows/Entra authentication preferred; if SQL auth, enforce policy; disable `sa` or rename + strong secret; force encryption.
- MySQL: `require_secure_transport=ON`, `caching_sha2_password`, no anonymous users.

## Dangerous features

| Engine | Disable/restrict |
|---|---|
| SQL Server | `xp_cmdshell`, `Ole Automation Procedures`, CLR (`clr enabled`/`clr strict security`), `Ad Hoc Distributed Queries`, cross-db ownership chaining — check with `SELECT name, value_in_use FROM sys.configurations WHERE name IN ('xp_cmdshell','clr enabled','Ole Automation Procedures','Ad Hoc Distributed Queries');` |
| PostgreSQL | `pg_execute_server_program`/`pg_read_server_files` grants, untrusted languages (`plpython3u`) for non-admins, `COPY ... PROGRAM` |
| MySQL | `local_infile=OFF`, `secure_file_priv` set to a dedicated dir or NULL, `FILE` privilege |
| Oracle | Default accounts locked, `UTL_*` package grants to PUBLIC revoked |

## Data protection

Encryption at rest (TDE / managed storage encryption with KMS keys), encrypted backups with restricted access, masking in non-prod copies, audit logging (`db-audit-logging`).

## Patch & version

Supported major versions only; track CVEs for the engine; managed services' maintenance windows enabled.

## Related skills

`db-privilege-review`, `db-audit-logging`, `cloud-exposure-review`, `linux-hardening`

## References

- CIS Benchmarks for PostgreSQL, MySQL, SQL Server, Oracle, MongoDB: https://www.cisecurity.org/cis-benchmarks
- PostgreSQL client authentication (pg_hba.conf): https://www.postgresql.org/docs/current/auth-pg-hba-conf.html
- MongoDB security checklist: https://www.mongodb.com/docs/manual/administration/security-checklist/
- Redis security: https://redis.io/docs/latest/operate/oss_and_stack/management/security/
