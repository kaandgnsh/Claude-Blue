---
name: phishing-simulation-program
description: Run an ethical, effective phishing simulation program — goals beyond click rate (report rate, time to report, repeat behaviour), realistic but fair scenarios, targeting and frequency, just-in-time training, HR/works-council agreement, allow-listing in mail security, and metrics. Use when designing or reviewing phishing simulations or interpreting their results.
license: MIT
metadata:
  category: security-awareness
  version: "2.0.0"
  verification: documented
---

# Phishing Simulation Program

## Principles

- **Primary metric is reporting**, not clicking: report rate and median time-to-first-report (a fast report lets the SOC purge a real campaign).
- **No punishment-first culture**: shaming reduces reporting. Use coaching; escalate only for repeated risky behaviour per agreed policy.
- **Fair lures**: realistic, but avoid exploiting sensitive topics (bonuses, layoffs, health emergencies) that damage trust — agree boundaries with HR/legal/works council.
- **Coverage**: everyone including executives and IT admins; vary difficulty; include QR codes, callback/vishing-style, and credential-harvest landing pages.

## Operations

1. Agreement: scope, data handling (who sees individual results), cadence (monthly/quarterly), approvals.
2. Mail security: allow-list simulation infrastructure via the vendor's documented method (e.g., Microsoft Defender "advanced delivery" for third-party phishing simulations) — don't weaken real filtering.
3. Exclude or coordinate during real incidents.
4. Landing page: immediate, short teachable moment pointing out the cues.
5. Ensure the **report button** works for simulations and real mail alike; acknowledge reporters.

## Metrics

| Metric | Target trend |
|---|---|
| Report rate | Up |
| Median time to first report | Down (minutes) |
| Click / credential-submit rate | Down, interpreted by difficulty level |
| Repeat clickers | Down; targeted coaching |
| Real phish reports (`phish-reporting-workflow`) | Up, with true-positive share |

## Related skills

`security-awareness-program`, `phish-reporting-workflow`, `phishing-triage`

## References

- NIST "Phish Scale" for rating simulation difficulty: https://www.nist.gov/news-events/news/2020/09/phish-scale-nist-developed-method-helps-it-staff-see-why-users-click
- Microsoft: Configure advanced delivery for third-party phishing simulations: https://learn.microsoft.com/en-us/defender-office-365/advanced-delivery-policy-configure
- CISA phishing guidance: https://www.cisa.gov/resources-tools/resources/phishing-guidance-stopping-attack-cycle-phase-one
