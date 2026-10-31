# Roadmap

## Next
1. **security-automation** and **security-testing** categories (SOAR playbook design/testing, automation risk, purple teaming, control validation, test planning). Planned, not yet included.
2. More `tested` skills: run KQL with Kusto emulation or `datatable()` fixtures, and SPL in a Splunk container. Add fixtures for Zeek logs, Velociraptor/osquery output and Okta/Entra exports.
3. Per-skill `references/` files for the largest tables (Windows event IDs, Entra error codes, OWASP mappings), to shrink SKILL.md bodies further.
4. Skill-trigger evals (`claude plugin eval`) with should/should-not-trigger prompts per profile.
5. Scheduled link checking and ATT&CK snapshot refresh in CI (network jobs, non-blocking).

## Later
- Product-specific query packs (Sentinel ASIM, Splunk CIM, Elastic ECS) generated from Sigma with tested pipelines.
- Optional read-only MCP integrations (e.g., KEV/EPSS lookup) with documented scopes.
- Translations and localized regulatory notes (NIS2, DORA, LGPD, APPI).
- Re-introduce `poc-safety-review` (reviewing public exploit code safely before validation in labs).
