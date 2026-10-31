---
name: vault-policy-review
description: Review secrets manager configuration and access — HashiCorp Vault/OpenBao policies and auth methods, AWS Secrets Manager and Parameter Store, Azure Key Vault, GCP Secret Manager — for over-broad read paths, weak auth bindings, root token use, audit devices, rotation and dynamic secrets. Use when auditing a secrets manager, onboarding applications, or after suspected secret store abuse.
license: MIT
metadata:
  category: secrets-management
  version: "2.0.0"
  verification: documented
---

# Secrets Manager Policy Review

## HashiCorp Vault / OpenBao

```sh
vault policy list ; vault policy read app-payments
vault auth list -detailed ; vault read auth/kubernetes/role/payments
vault audit list -detailed                   # must have at least one (ideally two) audit devices
vault token lookup                            # never operate with a root token; revoke after break-glass: vault token revoke <root>
```
Red flags in policies:
```hcl
path "secret/*"            { capabilities = ["read", "list"] }          # app can read every secret
path "sys/*"               { capabilities = ["sudo", "update"] }       # administrative
path "auth/token/create"   { capabilities = ["update"] }               # can mint tokens (with policies it holds)
path "*"                   { capabilities = ["create","read","update","delete","list","sudo"] }
```
Prefer per-app paths (`secret/data/payments/*`), templated policies (`{{identity.entity.aliases.<accessor>.name}}`), auth roles bound to specific Kubernetes namespaces/service accounts or cloud IAM roles, short token TTLs, **dynamic secrets** (database, AWS) instead of static ones.

## Cloud secret stores

| Store | Check |
|---|---|
| AWS Secrets Manager | Resource policies (no `*` principals), IAM `secretsmanager:GetSecretValue` scope by ARN/tag, rotation enabled (`aws secretsmanager list-secrets --query 'SecretList[].{n:Name,r:RotationEnabled}'`), KMS key policy |
| SSM Parameter Store | SecureString with CMK; `ssm:GetParameter*` scope |
| Azure Key Vault | RBAC mode over access policies; `Key Vault Secrets User` scoped per vault; soft-delete + purge protection; private endpoint; diagnostic logs |
| GCP Secret Manager | `roles/secretmanager.secretAccessor` granted per secret, not project-wide; CMEK if required |

## Audit & detection

Audit logs to SIEM; alert on bulk secret reads, reads by unusual identities, policy changes, root token generation (`sys/generate-root`), Key Vault access policy changes.

## Related skills

`kms-key-review`, `secret-leak-response`, `k8s-secrets-review`, `ci-secret-review`

## References

- Vault policies: https://developer.hashicorp.com/vault/docs/concepts/policies
- Vault production hardening: https://developer.hashicorp.com/vault/docs/concepts/production-hardening
- AWS Secrets Manager best practices: https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html
- Azure Key Vault security: https://learn.microsoft.com/en-us/azure/key-vault/general/secure-key-vault
