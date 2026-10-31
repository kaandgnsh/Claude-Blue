---
name: authentication-policy-review
description: Review authentication policy and MFA posture across IdPs — MFA coverage and method strength (phishing-resistant vs. SMS/push), legacy protocol exposure, password policy (NIST SP 800-63B), session lifetimes, self-service recovery and help-desk reset procedures, break-glass accounts. Use when assessing identity security, planning passwordless/passkey rollout, or after MFA-bypass incidents.
license: MIT
metadata:
  category: identity-security
  version: "2.0.0"
  verification: documented
---

# Authentication Policy Review

## Method strength ladder

| Strength | Methods |
|---|---|
| Phishing-resistant | FIDO2 security keys / passkeys (device-bound or synced with origin binding), Windows Hello for Business, certificate-based auth / PIV smart cards |
| Strong but phishable | Authenticator push with number matching, TOTP apps |
| Weak | SMS, voice, email OTP, push without number matching |
| None | Password only, legacy protocols (IMAP/POP/SMTP AUTH basic, NTLM to internet services) |

## Review areas

1. **Coverage**: % users with MFA registered; % sign-ins MFA-enforced (from logs, not policy intent). Find single-factor successes (`conditional-access-review` query).
2. **Admins**: phishing-resistant required for all privileged roles.
3. **Registration security**: who can register MFA and from where (require compliant device / trusted location / Temporary Access Pass for bootstrap).
4. **Recovery & help desk**: identity verification before MFA/password reset; alert on admin MFA resets; high-risk users require in-person/video verification.
5. **Passwords**: NIST SP 800-63B rev. 4 — length ≥ 15 (single-factor) / ≥ 8 (with MFA), no composition rules, no periodic forced rotation without cause, blocklists of breached/common passwords, allow paste/password managers.
6. **Sessions**: sign-in frequency for admins and unmanaged devices; Continuous Access Evaluation; token protection.
7. **Legacy**: block legacy auth; disable NTLM where possible; LDAP signing/channel binding.
8. **Break-glass**: 2 cloud-only emergency accounts, phishing-resistant (FIDO2), excluded from CA carefully, monitored with alerts on any use.

## Output

`Area | Current state | Evidence | Gap | Risk | Recommendation | Priority`

## Related skills

`conditional-access-review`, `mfa-fatigue-detection`, `privileged-access-review`, `ad-privileged-access-review`

## References

- NIST SP 800-63B (Digital Identity Guidelines, Authentication): https://pages.nist.gov/800-63-4/sp800-63b.html
- CISA phishing-resistant MFA fact sheet: https://www.cisa.gov/resources-tools/resources/implementing-phishing-resistant-mfa
- FIDO Alliance passkeys: https://fidoalliance.org/passkeys/
- Microsoft emergency access accounts: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access
