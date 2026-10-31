---
name: policy-review
description: Draft or review information security policies, standards and procedures — hierarchy, mandatory statements, scope, roles, exceptions, measurable requirements, mapping to frameworks (ISO 27001, NIST CSF 2.0, SOC 2, CIS Controls), and alignment with actual practice. Use when writing or refreshing security policies, preparing for certification audits, or checking whether policies are enforceable.
license: MIT
metadata:
  category: security-governance
  version: "2.0.0"
  verification: documented
---

# Security Policy Review

## Document hierarchy

| Level | Purpose | Example |
|---|---|---|
| Policy | Management intent, short, stable, approved by leadership | "All access to company systems requires authentication proportionate to risk." |
| Standard | Measurable mandatory requirements | "Phishing-resistant MFA is required for all administrator accounts." |
| Procedure/runbook | How to do it | "How to register a FIDO2 key" |
| Guideline | Recommended practice | "Use a password manager" |

## Review checklist

- [ ] Scope (entities, systems, people incl. contractors) and applicability clear.
- [ ] Requirements use **shall/must** and are testable (who, what, how often, what threshold).
- [ ] Roles and accountability (owner, approver, enforcer) named by role.
- [ ] Exception process referenced (`security-exception-management`).
- [ ] Mapped to framework controls (ISO/IEC 27001:2022 Annex A, NIST CSF 2.0 subcategories, SOC 2 TSC, CIS Controls v8.1) — keep the mapping in a control matrix, not in the policy text.
- [ ] Consistent with technical reality: if the standard says "patch critical vulns in 14 days" but median is 45 days, either fix practice or document a plan — auditors test practice.
- [ ] No conflicts with other policies (HR, privacy, procurement).
- [ ] Review date, version, approver recorded; reviewed at least annually.
- [ ] Readable: plain language, short; users can find what applies to them.

## Common gaps

Policies copied from templates naming tools/teams that don't exist, missing standards for cloud/SaaS/AI use, no requirement owners, outdated password rules (forced rotation, complexity) contradicting NIST SP 800-63B, no acceptable-use rules for generative AI.

## Output

`Document | Section | Issue | Framework impact | Proposed text | Owner`

## Related skills

`control-mapping`, `security-exception-management`, `maturity-assessment`, `security-awareness-program`

## References

- NIST CSF 2.0 (Govern function): https://www.nist.gov/cyberframework
- CIS Controls v8.1: https://www.cisecurity.org/controls
- SANS security policy templates: https://www.sans.org/information-security-policy/
