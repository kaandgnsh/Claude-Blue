---
name: kms-key-review
description: Review cloud KMS and HSM key management — AWS KMS key policies and grants, Azure Key Vault keys/Managed HSM, GCP Cloud KMS IAM — for who can use/manage/delete keys, rotation, separation of duties, cross-account access, and detect key abuse (unexpected Decrypt, ScheduleKeyDeletion, disabled keys in ransom scenarios). Use when auditing encryption key governance or investigating suspicious key operations.
license: MIT
metadata:
  category: secrets-management
  version: "2.0.0"
  verification: documented
---

# KMS Key Review

## AWS KMS

```sh
aws kms list-keys --query 'Keys[].KeyId' --output text | tr '\t' '\n' | while read k; do
  aws kms describe-key --key-id "$k" --query 'KeyMetadata.{id:KeyId,mgr:KeyManager,state:KeyState,spec:KeySpec,origin:Origin}' --output text
  aws kms get-key-rotation-status --key-id "$k" --query KeyRotationEnabled 2>/dev/null
done
aws kms get-key-policy --key-id <id> --policy-name default --output text | jq .
aws kms list-grants --key-id <id>
```
Policy review: who has `kms:Decrypt`/`kms:GenerateDataKey` (use) vs. `kms:PutKeyPolicy`/`kms:ScheduleKeyDeletion`/`kms:DisableKey` (manage) — separate them; `"Principal": {"AWS": "arn:aws:iam::<acct>:root"}` delegates to IAM (normal, but then IAM must be tight); cross-account principals; `kms:ViaService` / `kms:EncryptionContext` conditions to bind usage to services.

## Azure / GCP

- Azure Key Vault keys: RBAC roles `Key Vault Crypto User` (use) vs. `Key Vault Crypto Officer`/`Administrator` (manage); purge protection on; rotation policies (`az keyvault key rotation-policy show`).
- GCP Cloud KMS: `roles/cloudkms.cryptoKeyEncrypterDecrypter` per key, not project-wide; rotation period on symmetric keys (`gcloud kms keys describe KEY --keyring R --location L --format='value(rotationPeriod)'`); destruction scheduled duration.

## Detection

| Event | Concern |
|---|---|
| `ScheduleKeyDeletion`, `DisableKey` (AWS), key delete/purge (Azure), `DestroyCryptoKeyVersion` (GCP) | Ransom/sabotage (data becomes unrecoverable) |
| `PutKeyPolicy` adding external account | Exfiltration path |
| Spike in `Decrypt` by a principal / from new IPs | Bulk data decryption |
| `CreateGrant` to unexpected principals | Hidden access |

AWS KMS deletion has a 7–30 day waiting period — `aws kms cancel-key-deletion` during incidents.

## Related skills

`vault-policy-review`, `cryptographic-design-review`, `cloudtrail-investigation`

## References

- AWS KMS key policies: https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html
- AWS KMS best practices: https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html
- GCP Cloud KMS IAM: https://cloud.google.com/kms/docs/reference/permissions-and-roles
- NIST SP 800-57 Part 1 Rev. 5 key management: https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
