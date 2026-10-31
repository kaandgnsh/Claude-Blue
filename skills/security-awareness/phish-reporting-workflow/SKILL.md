---
name: phish-reporting-workflow
description: Operate the user phish-reporting pipeline — report button configuration (Microsoft Report Message/Report Phishing, Gmail reporting, third-party add-ins), reported-mailbox routing, automated triage and clustering, feedback to reporters, purge of related messages and metrics. Use when setting up or fixing how users report suspicious email, or when the reported-phish queue is overwhelming the SOC.
license: MIT
metadata:
  category: security-awareness
  version: "2.0.0"
  verification: documented
---

# Phish Reporting Workflow

## Pipeline

1. **Report button** in all mail clients (Outlook desktop/web/mobile, Gmail). Microsoft 365: user reported settings route reports to a **reporting mailbox** and/or Microsoft; reported messages appear in Defender "User reported" submissions.
2. **Ingestion**: SOAR/SIEM reads the reporting mailbox or submissions API; preserve original as attachment (`.eml`) with headers.
3. **Automatic triage**: parse (`email-header-analysis`), detect simulation (campaign headers) → thank-you and close, cluster duplicates by sender/URL/attachment hash so one analysis covers many reports, enrich URLs/hashes (lookups only).
4. **Analyst review** for unclustered or suspicious items (`phishing-triage`).
5. **Action**: purge all copies of confirmed phish across mailboxes, block indicators, check clickers (`phishing-campaign-scope`).
6. **Feedback to reporter**: "confirmed phishing — thank you", "safe — legitimate newsletter", or "simulation — well done". Feedback sustains reporting.

## Microsoft 365 notes

Defender for Office 365: Submissions page (user reported tab), automated investigation and response (AIR) can cluster and remediate; "Mark and notify" sends result templates to users. Configure in *Settings → Email & collaboration → User reported settings*.

## Metrics

Reports/day, % true phish, median time to verdict, median time from first report to purge, reporters per campaign before first click, % auto-closed (simulations, duplicates).

## Related skills

`phishing-triage`, `phishing-campaign-scope`, `phishing-simulation-program`, `email-header-analysis`

## References

- Microsoft user reported settings: https://learn.microsoft.com/en-us/defender-office-365/submissions-user-reported-messages-custom-mailbox
- Microsoft AIR in Defender for Office 365: https://learn.microsoft.com/en-us/defender-office-365/air-about
- Google Workspace phishing reporting: https://support.google.com/a/answer/9223479
