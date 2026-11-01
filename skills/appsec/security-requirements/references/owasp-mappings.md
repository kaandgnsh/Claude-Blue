# OWASP mappings for security requirements

Loaded on demand by `security-requirements`. Use it to pick ASVS 5.0 chapters for a feature, phrase acceptance criteria, and show which risk lists a requirement answers. ASVS requirement IDs changed between 4.0.3 and 5.0: always cite `v5.0.0-<chapter>.<section>.<n>` and check the exact text in the standard before copying an ID into a contract or audit report.

## ASVS 5.0 chapters

| Chapter | Topic | Typical acceptance criterion | Best verification | Related risk lists |
|---|---|---|---|---|
| V1 | Encoding and Sanitization | Output to HTML, SQL, OS commands and LDAP is encoded or parameterized by the framework, never concatenated | SAST rule + code review | Top 10 2025 A05 Injection; API8 2023 |
| V2 | Validation and Business Logic | Server rejects quantities, prices and state transitions that the business flow does not allow, even if the UI hides them | Integration tests with tampered requests | API6 2023 Unrestricted Access to Sensitive Business Flows |
| V3 | Web Frontend Security | CSP without `unsafe-inline` for scripts; cookies `Secure`, `HttpOnly`, `SameSite`; framing restricted | DAST + header test | A02 Security Misconfiguration |
| V4 | API and Web Service | Every endpoint documented in the API spec; unknown fields rejected; methods limited | Contract tests, API inventory diff | API9 2023 Improper Inventory Management |
| V5 | File Handling | Uploads limited by type (content-checked), size and count; stored outside web root; served with `Content-Disposition: attachment` | Integration tests with crafted files | A05 Injection, A06 Insecure Design |
| V6 | Authentication | MFA available (required at L2+ for privileged functions); breached-password check; lockout/throttling | Integration tests + manual review | A07 Authentication Failures; API2 2023 |
| V7 | Session Management | Session invalidated on logout and password change; absolute and idle timeouts; token rotated after login | Integration tests | A07 Authentication Failures |
| V8 | Authorization | Object-level check on every request using server-side identity; deny by default | Per-endpoint authz test matrix (two users, two tenants) | A01 Broken Access Control; API1, API3, API5 2023 |
| V9 | Self-contained Tokens | JWT signature verified with a pinned algorithm list; `aud`, `iss`, `exp` validated; no `none` | Unit tests with forged tokens | A07; API2 2023 |
| V10 | OAuth and OIDC | PKCE for public clients; exact redirect URI match; `state`/`nonce` validated; refresh tokens sender-constrained or rotated | Config review + flow tests | A07; A01 |
| V11 | Cryptography | Approved algorithms only, keys from a KMS/HSM, no custom crypto, crypto inventory maintained | Code review + dependency scan | A04 Cryptographic Failures |
| V12 | Secure Communication | TLS 1.2+ everywhere incl. internal service calls; certificate validation not disabled | Config scan (testssl.sh), code search for `verify=False` | A04 Cryptographic Failures |
| V13 | Configuration | Debug off, default credentials removed, secrets from a vault, dependencies pinned | IaC scan + build checks | A02 Security Misconfiguration; A03 Software Supply Chain Failures |
| V14 | Data Protection | Sensitive fields classified; not cached by clients; not logged; retention enforced | Review + log sampling | A04; API3 2023 (excessive data exposure) |
| V15 | Secure Coding and Architecture | Dependencies tracked in an SBOM and patched within SLA; dangerous functions banned; safe concurrency | SCA in CI, SAST | A03 Software Supply Chain Failures; A08 Software or Data Integrity Failures |
| V16 | Security Logging and Error Handling | Auth, authz failures and admin actions logged with user, time, source; no secrets in logs; errors fail closed | Log review + tests | A09 Logging and Alerting Failures; A10 Mishandling of Exceptional Conditions |
| V17 | WebRTC | TURN/STUN servers authenticated; media encrypted (DTLS-SRTP) | Config review | — |

## OWASP Top 10:2025 → where to look

| Top 10:2025 | ASVS 5.0 chapters | Claude-Blue skills |
|---|---|---|
| A01 Broken Access Control | V8, V10 | `api-authorization-testing`, `secure-code-review` |
| A02 Security Misconfiguration | V3, V13 | `dast-baseline`, `iac-scanning` |
| A03 Software Supply Chain Failures | V13, V15 | `sca-dependency-risk`, `sbom-vulnerability-analysis` |
| A04 Cryptographic Failures | V11, V12, V14 | `secure-code-review`, `tls-reverse-proxy-build` |
| A05 Injection | V1, V5 | `sast-triage`, `secure-code-review` |
| A06 Insecure Design | V2, V5, threat model | `threat-modeling` |
| A07 Authentication Failures | V6, V7, V9, V10 | `authentication-policy-review` |
| A08 Software or Data Integrity Failures | V15, V13 | `github-actions-hardening`, `sca-dependency-risk` |
| A09 Logging and Alerting Failures | V16 | `logging-architecture` |
| A10 Mishandling of Exceptional Conditions | V16, V2 | `secure-code-review` |

## OWASP API Security Top 10 2023 → ASVS 5.0

| API risk | ASVS 5.0 |
|---|---|
| API1 Broken Object Level Authorization | V8 |
| API2 Broken Authentication | V6, V9, V10 |
| API3 Broken Object Property Level Authorization | V8, V14 |
| API4 Unrestricted Resource Consumption | V2 (anti-automation, limits), V4 |
| API5 Broken Function Level Authorization | V8 |
| API6 Unrestricted Access to Sensitive Business Flows | V2 |
| API7 Server Side Request Forgery | V1, V12 (outbound allow-lists) |
| API8 Security Misconfiguration | V13, V3 |
| API9 Improper Inventory Management | V4, V15 |
| API10 Unsafe Consumption of APIs | V1, V12 |

## OWASP Top 10 for LLM Applications 2025 (when the app embeds an LLM)

ASVS does not cover model-specific risks. Add requirements for LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM05 Improper Output Handling (treat model output as untrusted input → V1), LLM06 Excessive Agency (least-privilege tools → V8) and LLM10 Unbounded Consumption (limits → V2). See `prompt-injection-review` and `llm-gateway-controls`.

## Sources

- OWASP ASVS 5.0: https://owasp.org/www-project-application-security-verification-standard/
- OWASP Top 10:2025: https://owasp.org/Top10/
- OWASP API Security Top 10 2023: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/llm-top-10/
