---
name: mobile-app-security-review
description: Review iOS and Android application security against OWASP MASVS/MASTG — static analysis (MobSF, jadx, apktool), data storage, network security (ATS, network security config, certificate pinning), authentication and token handling, platform interaction (intents, deep links, WebViews), secrets in binaries — in authorized test builds. Use when assessing a mobile app before release, reviewing a third-party app, or verifying mobile findings.
license: MIT
metadata:
  category: mobile-security
  version: "2.0.0"
  verification: documented
---

# Mobile App Security Review

## Static analysis

```sh
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest   # MobSF web UI; upload APK/IPA
apktool d app.apk -o app_src                         # resources, AndroidManifest.xml, smali
jadx -d app_java app.apk                             # decompile to Java
grep -rEn "(api[_-]?key|secret|token|password)\s*[:=]" app_java | head
```
Android manifest checks: `android:debuggable`, `android:allowBackup`, exported components (`android:exported="true"` activities/services/receivers/providers without permissions), `android:usesCleartextTraffic`, network security config (`res/xml/network_security_config.xml`: cleartext, user CAs trusted, pinning). iOS: `Info.plist` App Transport Security exceptions (`NSAllowsArbitraryLoads`), URL schemes/universal links, entitlements, keychain accessibility classes.

## MASVS areas

| MASVS | Focus |
|---|---|
| STORAGE | No sensitive data in plaintext prefs/SQLite/logs/backups; Keychain/Keystore use |
| CRYPTO | Platform crypto APIs, no hard-coded keys |
| AUTH | Server-side auth enforcement, secure token storage, biometric binding to keystore keys |
| NETWORK | TLS everywhere, certificate validation, pinning where justified |
| PLATFORM | Safe IPC, deep link validation, WebView hardening (no `setJavaScriptEnabled` + `addJavascriptInterface` on untrusted content) |
| CODE | Up-to-date dependencies, no debug code, input validation |
| RESILIENCE | Root/jailbreak detection, anti-tamper (for high-risk apps; defense-in-depth only) |
| PRIVACY | Minimal permissions and data collection, transparency |

## Dynamic testing (test devices, authorized builds)

Proxy traffic (Burp/ZAP with test CA), Frida/objection for runtime inspection (`objection -g com.example.app explore`), check API authorization separately (`api-authorization-testing`) — the backend is where most real vulnerabilities are.

## Output

`Finding | MASVS control | Platform | Evidence | Severity | Fix`

## Related skills

`api-authorization-testing`, `security-requirements`, `mdm-compliance-review`, `secret-scanning`

## References

- OWASP MASVS: https://mas.owasp.org/MASVS/
- OWASP MASTG: https://mas.owasp.org/MASTG/
- MobSF: https://github.com/MobSF/Mobile-Security-Framework-MobSF
- Android network security configuration: https://developer.android.com/privacy-and-security/security-config
