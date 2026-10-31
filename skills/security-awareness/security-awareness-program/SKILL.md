---
name: security-awareness-program
description: Design a risk-based security awareness and behaviour program — target behaviours tied to real incidents (reporting, MFA approval hygiene, payment verification, data handling, AI tool use), role-based content for high-risk groups (finance, help desk, admins, executives, developers), delivery formats, and outcome measurement. Use when building or refreshing awareness training, or when incidents show recurring human-factor causes.
license: MIT
metadata:
  category: security-awareness
  version: "2.0.0"
  verification: documented
---

# Security Awareness Program

## Start from behaviours, not topics

| Risk (from incidents/threat profile) | Target behaviour | Audience |
|---|---|---|
| Credential phishing / AiTM | Report suspicious messages; never approve unexpected MFA prompts | All |
| BEC / payment fraud | Verify bank-detail changes by calling a known number | Finance, procurement, executive assistants |
| Help-desk social engineering | Follow identity verification procedure for resets, no exceptions under pressure | Service desk |
| Admin credential theft | Use separate admin accounts/PAWs; never admin from email workstation | IT admins |
| Secrets in code | Use secret manager; respond to push-protection blocks correctly | Developers |
| Data leakage via AI tools | Use approved AI tools; no confidential data in public tools | All |
| Lost devices / physical | Report loss immediately | All |

## Delivery

Short, frequent, contextual: onboarding module, 5–10 minute monthly micro-learning, just-in-time prompts (e.g., banner on external email, DLP policy tips), role-based workshops for high-risk groups, exercises (`phishing-simulation-program`, tabletops). Accessibility and localization matter.

## Measure outcomes

Behavioural metrics (report rate and speed, verified-callback compliance in finance audits, help-desk procedure adherence in QA calls, push-protection bypass rate), incident root causes trending down — completion rates are compliance evidence, not effectiveness.

## Governance

Annual plan approved by security leadership, content reviewed against current threats quarterly, mapping to compliance requirements (ISO/IEC 27001 A.6.3, PCI DSS 12.6, HIPAA).

## Related skills

`phishing-simulation-program`, `phish-reporting-workflow`, `bec-investigation`, `policy-review`

## References

- NIST SP 800-50 Rev. 1 Building a Cybersecurity and Privacy Learning Program: https://csrc.nist.gov/pubs/sp/800/50/r1/final
- SANS Security Awareness Maturity Model: https://www.sans.org/security-awareness-training/resources/maturity-model/
