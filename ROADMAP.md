# Roadmap

## Done in 2.2.0
- `security-automation` and `security-testing` categories (12 skills, two with tested scripts).
- Six more `tested` skills: Zeek, Okta and Entra export analysis, osquery query library in a container, playbook linting, detection coverage scoring.
- `references/` files for Windows event IDs, AADSTS codes and OWASP mappings.
- Skill-trigger evals for `claude plugin eval`, generated from `evals/cases.json`.
- Weekly link check and ATT&CK snapshot comparison in CI (non-blocking).

## Next
1. Run documented KQL with the Kusto emulator (Kustainer) and `datatable()` fixtures, and SPL in a Splunk container; promote the skills that pass.
2. More eval cases per profile (at least 3 should-trigger, 2 should-not-trigger), full 3-run passes, results recorded in BUILD_STATUS.
3. More fixtures: Velociraptor collections, Suricata EVE JSON, M365 unified audit log, Google Workspace and GitHub audit logs.
4. Reference files for other long tables (Kerberos error codes, M365 audit operations, CloudTrail high-risk events).

## Later
- Product-specific query packs (Sentinel ASIM, Splunk CIM, Elastic ECS) generated from Sigma with tested pipelines.
- Optional read-only MCP integrations (e.g., KEV/EPSS lookup) with documented scopes.
- Translations and localized regulatory notes (NIS2, DORA, LGPD, APPI).
- Re-introduce `poc-safety-review` (reviewing public exploit code safely before validation in labs).
