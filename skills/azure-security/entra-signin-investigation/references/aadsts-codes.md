# Entra ID sign-in result codes (AADSTS)

Loaded on demand by `entra-signin-investigation`. `ResultType` in `SigninLogs` is the numeric part of the AADSTS code (`50126` = `AADSTS50126`). Codes are grouped by what they tell an investigator. Microsoft adds and renames codes; confirm unknown ones with the error lookup at https://login.microsoftonline.com/error?code=NNNNN.

## Success and interrupts (not failures)

| Code | Meaning | Investigation note |
|---|---|---|
| 0 | Success | Check `AuthenticationRequirement` and `MfaDetail`: single-factor success from an unusual location is the key signal |
| 50055 | Password expired | User then changes password; check whether the change came from the same IP |
| 50058 | Silent sign-in failed, no session | Normal for SSO probes; high volume from one IP may be token tooling |
| 50072 | User must enroll for MFA | **Attacker with a password and no MFA registered can register their own method**: check AuditLogs for method registration right after |
| 50074 | Strong authentication required | Interrupt; a following success shows which MFA method satisfied it |
| 50076 | MFA required (location/policy) | As above |
| 50079 | MFA registration required | As 50072 |
| 50097 | Device authentication required | Device-based CA policy |
| 50125 | Sign-in interrupted (password reset or registration) | |
| 50140 | "Keep me signed in" interrupt | Normal interactive flow |
| 50199 | Redirect confirmation (CmsiInterrupt) | Seen with device code and some native clients |
| 81010 / 81012 | Seamless SSO failures | Often benign; Kerberos ticket issues |

## Credential failures

| Code | Meaning | Investigation note |
|---|---|---|
| 50126 | Invalid username or password | Spraying (many users, one IP) or brute force (one user, many attempts) |
| 50034 | User does not exist in tenant | Username enumeration / spraying with a guessed list |
| 50053 | Account locked (smart lockout) or sign-in from malicious IP blocked | Smart lockout counts failures per familiar/unfamiliar location |
| 50056 | No password stored (federated or passwordless user) | Attempts against accounts without passwords suggest a generic list |
| 50057 | Account disabled | Attempts on disabled accounts after offboarding: leaked credentials |
| 50064 | Credential validation failed (on-premises) | PTA agent / federation failure |
| 50144 | Active Directory password expired | |
| 80012 | Sign-in outside allowed hours (PTA) | |

## MFA outcomes

| Code | Meaning | Investigation note |
|---|---|---|
| 500121 | Strong authentication failed (denied, timed out, wrong code) | Bursts = MFA fatigue / push bombing |
| 50158 | External security challenge not satisfied | Third-party MFA or Duo |
| 500133 | Token not in validity window (MFA claim stale) | Can follow token replay attempts |
| 50088 | Limit on telecom MFA calls reached | SMS/voice abuse |
| 50089 | Flow token expired | User did not complete MFA in time |

## Policy and access control

| Code | Meaning | Investigation note |
|---|---|---|
| 53000 | Device not compliant / not managed | |
| 53001 | Device not domain joined | |
| 53003 | Blocked by Conditional Access | Check `ConditionalAccessPolicies` for which policy blocked; attackers probe for gaps (other apps, legacy clients) |
| 53004 | Proof-up blocked (risky user must register MFA) | |
| 53011 | User blocked due to risk on home tenant | |
| 530032 | Blocked by security policy (security defaults) | |
| 530034 | Federation blocked by tenant restrictions or policy | |
| 50105 | User not assigned to the application | Attempts against apps the user never uses |
| 65001 | Consent required, user or admin has not consented | Illicit consent attempts precede `Consent to application` audit events |
| 90095 | Admin consent required | |
| 7000218 | Request body must contain client_assertion or client_secret | Public client misuse; common with ROPC tooling |
| 700016 | Application not found in tenant | Wrong tenant or deleted app; scanning for apps |

## Token and session

| Code | Meaning | Investigation note |
|---|---|---|
| 70043 | Refresh token expired or invalid due to sign-in frequency | |
| 70044 | Session expired or invalid due to CA sign-in frequency | |
| 70008 | Authorization code or refresh token expired | |
| 50173 | Grant expired because of password change / revocation | Expected after `Revoke-MgUserSignInSession`; bursts from an unfamiliar IP mean the attacker's stolen refresh token stopped working, so scope where else it was used |
| 50133 | Session invalid due to password change | As above |
| 50132 | Session revoked (password change or user action) | |
| 70016 / 70019 | Device code flow pending / expired | Device code phishing leaves long pending chains |

## Sources

- AADSTS error code reference: https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes
- Sign-in log schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
- Smart lockout: https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout
