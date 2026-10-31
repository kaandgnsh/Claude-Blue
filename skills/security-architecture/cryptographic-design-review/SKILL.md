---
name: cryptographic-design-review
description: Review cryptographic design and usage — algorithm and mode choices (AEAD, KDFs, password hashing), randomness, key management and rotation, TLS configuration, token signing (JWT/JWS), envelope encryption, crypto-agility and post-quantum migration planning (ML-KEM, ML-DSA). Use when designing encryption features, reviewing code or architecture that uses crypto, or building a PQC migration inventory.
license: MIT
metadata:
  category: security-architecture
  version: "2.0.0"
  verification: documented
---

# Cryptographic Design Review

## Recommended defaults

| Need | Use | Avoid |
|---|---|---|
| Symmetric encryption | AES-256-GCM or ChaCha20-Poly1305 (AEAD) via high-level libraries (libsodium, Tink, AWS Encryption SDK) | ECB, CBC without MAC, homemade constructions, static/reused nonces |
| Password storage | Argon2id (or scrypt, bcrypt; PBKDF2 with high iterations if FIPS required) | MD5/SHA-1/SHA-256 unsalted or single-iteration |
| Key derivation | HKDF for key material; Argon2/scrypt for passwords | Truncated hashes as keys |
| Integrity/MAC | HMAC-SHA-256 | Plain hashes for authentication |
| Signatures | Ed25519, ECDSA P-256, RSA-PSS ≥ 3072 (PQC: ML-DSA planning) | RSA PKCS#1 v1.5 for new designs, DSA |
| Key exchange | X25519/ECDHE; hybrid X25519MLKEM768 in TLS 1.3 where supported | Static RSA key exchange |
| Randomness | OS CSPRNG (`secrets`, `crypto.randomBytes`, `SecureRandom`) | `random`, `Math.random()`, time-seeded PRNGs |
| Tokens | JWS with explicit algorithm allow-list, `exp`/`aud`/`iss` validation, short lifetimes; opaque tokens when possible | `alg: none`, accepting algorithm from the token header, HS256 with public keys |

## Key management questions

Who generates keys, where are they stored (KMS/HSM vs. app config), who can use vs. manage them, rotation and re-encryption plan, envelope encryption (data keys wrapped by KMS key), backup/escrow, destruction, separation between environments and tenants (`kms-key-review`).

## Post-quantum readiness

NIST finalized FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) in August 2024. Build a **cryptographic inventory** (protocols, libraries, certificates, long-lived data needing confidentiality for 10+ years — "harvest now, decrypt later"), prioritize key exchange for long-lived secrets, ensure crypto-agility (configurable algorithms, no hard-coded key sizes).

## Output

`Component | Crypto use | Algorithm/mode/library | Key storage | Issue | Risk | Recommendation`

## Related skills

`kms-key-review`, `certificate-lifecycle`, `secure-code-review`, `architecture-review`

## References

- OWASP Cryptographic Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
- OWASP Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- NIST post-quantum cryptography standards (FIPS 203/204/205): https://csrc.nist.gov/projects/post-quantum-cryptography
- NIST SP 800-57 Part 1 Rev. 5: https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
