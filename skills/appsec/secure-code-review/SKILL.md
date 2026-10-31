---
name: secure-code-review
description: Perform a security-focused code review of a change or codebase — authentication, authorization (object/function level), input handling and injection, output encoding, cryptography, secrets, deserialization, SSRF, file handling, logging — with language-specific sinks and a findings format developers can act on. Use when reviewing a pull request for security, auditing a service before release, or verifying a reported vulnerability in source.
license: MIT
metadata:
  category: appsec
  version: "2.0.0"
  verification: documented
---

# Secure Code Review

## Approach

1. Understand the feature and trust boundaries (what input is attacker-controlled? who is the caller?).
2. Trace **sources → sinks**: request params/headers/body, files, queue messages, webhooks, DB content written by users → dangerous operations.
3. Check **authorization on every handler** that touches an object by ID (BOLA/IDOR), not only authentication.
4. Review security-sensitive diffs line by line; for large codebases combine with SAST (`sast-triage`) and grep for sinks.

## Sink cheat sheet

| Class | Sinks / patterns to inspect |
|---|---|
| SQL/NoSQL injection | String-built queries: `cursor.execute(f"...{x}")`, `"SELECT ..." + x`, `$where`, `db.collection.find(JSON.parse(input))`, ORM `raw()`/`extra()` |
| Command injection | `subprocess` with `shell=True`, `os.system`, `Runtime.exec` with concatenated string, `child_process.exec`, backticks |
| Code injection / deserialization | `eval`, `exec`, `pickle.loads`, `yaml.load` (unsafe loader), Java `ObjectInputStream`, .NET `BinaryFormatter`, PHP `unserialize`, template rendering of user input (SSTI: `render_template_string`) |
| XSS | `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `|safe`, `Html.Raw`, unescaped template output, URL `javascript:` in href |
| SSRF | Server fetches user-supplied URL (`requests.get(url)`, `HttpClient`, image/PDF renderers, webhooks); check allow-list, DNS rebinding, redirects, cloud metadata (169.254.169.254) |
| Path traversal | `open(base + user_path)`, `send_file`, zip extraction without path checks (Zip Slip) |
| AuthN | Custom JWT parsing (`alg=none`, missing `exp`/`aud` checks), password hashing not bcrypt/scrypt/Argon2, session fixation, MFA bypass paths |
| AuthZ | Missing ownership check (`Order.get(id)` without `user_id`), role checks only in UI, mass assignment (binding all request fields to model) |
| Crypto | ECB mode, static IV/nonce, `Math.random()`/`random` for tokens, MD5/SHA1 for passwords, disabled TLS verification (`verify=False`, `InsecureSkipVerify`) |
| Secrets | Hard-coded keys, tokens in logs, secrets in client bundles |
| Logging | Missing audit of security events; logging PII/secrets; log injection (CRLF) |

## Findings format

```
[Severity] <Title> — <file>:<line>
Issue: <what and why exploitable>, attacker-controlled input: <source>
Impact: <data/privilege affected>
Fix: <specific code-level fix, e.g. use parameterized query / check order.owner_id == current_user.id>
Reference: <CWE-xxx, OWASP ASVS x.y.z>
```

Rate with exploitability + impact; avoid flagging theoretical issues without a reachable source.

## Related skills

`sast-triage`, `threat-modeling`, `security-requirements`, `api-authorization-testing`

## References

- OWASP Code Review Guide: https://owasp.org/www-project-code-review-guide/
- OWASP ASVS 5.0: https://owasp.org/www-project-application-security-verification-standard/
- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/
- CWE Top 25: https://cwe.mitre.org/top25/
