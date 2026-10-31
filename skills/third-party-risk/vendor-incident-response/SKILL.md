---
name: vendor-incident-response
description: Respond when a vendor, SaaS provider, MSP or software supplier is breached — determine exposure of your data and access, contain integrations (tokens, VPN, accounts, API keys), hunt for downstream compromise, manage contractual and regulatory notifications, and track vendor remediation. Use when a supplier announces or is reported to have a security incident affecting customers.
license: MIT
metadata:
  category: third-party-risk
  version: "2.0.0"
  verification: documented
---

# Vendor Incident Response

## First 24 hours

1. **Gather facts** from the vendor (advisory, customer notice), CISA/threat intel, and public reporting: what was compromised (customer data, support systems, source code, signing keys, update channel, admin consoles), time window, IOCs, recommended customer actions.
2. **Map your exposure**:
   - Data shared with the vendor (data inventory/contract).
   - Integrations: SSO apps, OAuth tokens (`oauth-app-review`), API keys you issued to them, keys they issued to you, service accounts, VPN/remote access for vendor staff, installed agents/software (supply-chain risk), MSP/RMM tools with admin access.
3. **Contain proactively**: rotate credentials the vendor held or that transited their systems (API keys, OAuth client secrets, SAML certs), disable vendor remote access temporarily, revoke and re-establish integrations, block IOCs.
4. **Hunt**: activity from vendor accounts/IPs/integrations in your logs during the window; for software supply chain incidents, inventory affected versions and look for the published malicious behaviour (`malicious-package-response`).

## Ongoing

- Request vendor's investigation report, RCA, and evidence that keys/credentials were rotated on their side.
- Track contractual obligations: their notification timing, cooperation, audit rights.
- Assess your own notification duties if personal data was affected (`privacy-incident-assessment`) — you may be the controller even though the vendor was breached.
- Decide on relationship actions (enhanced monitoring, compensating controls, termination).

## Tracker

`Vendor | Incident | Our data exposed | Integrations | Credentials rotated | Hunt result | Vendor RCA received | Notifications | Status`

## Related skills

`vendor-security-assessment`, `third-party-access-review`, `oauth-app-review`, `incident-scoping`

## References

- CISA: Defending against software supply chain attacks: https://www.cisa.gov/resources-tools/resources/defending-against-software-supply-chain-attacks
- NIST SP 800-161 Rev. 1: https://csrc.nist.gov/pubs/sp/800/161/r1/upd1/final
- CISA advisory on Snowflake customer compromises (2024) as example of SaaS credential abuse: https://www.cisa.gov/news-events/alerts/2024/06/03/snowflake-recommends-customers-take-steps-prevent-unauthorized-access
