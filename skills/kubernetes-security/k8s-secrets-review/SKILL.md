---
name: k8s-secrets-review
description: Review Kubernetes secret handling — etcd encryption at rest (KMS v2), RBAC on secrets, external secret stores (External Secrets Operator, Secrets Store CSI, Vault), service account token projection, secrets in env vars/ConfigMaps/images/Git — and plan rotation after exposure. Use when auditing cluster secrets management or after secrets may have leaked from a cluster.
license: MIT
metadata:
  category: kubernetes-security
  version: "2.0.0"
  verification: documented
---

# Kubernetes Secrets Review

## Checks

| Area | Check | How |
|---|---|---|
| Encryption at rest | `EncryptionConfiguration` with `kms` (v2) provider first; managed: EKS envelope encryption with KMS, AKS KMS etcd encryption, GKE application-layer secrets encryption | API server flags / cloud console; `aws eks describe-cluster --query cluster.encryptionConfig` |
| Access | Who can `get/list/watch secrets` | `k8s-rbac-review` analyzer, `kubectl auth can-i list secrets -A --as=...` |
| Placement | Secrets in ConfigMaps or plain env in manifests | `kubectl get cm -A -o json | jq` + grep for key patterns; `secret-scanning` on Git manifests/Helm values |
| Exposure via env | `env.valueFrom.secretKeyRef` leaks to process listings/crash dumps; prefer mounted files | Review pod specs |
| Tokens | Legacy long-lived SA token Secrets (`kubernetes.io/service-account-token`) | `kubectl get secrets -A --field-selector type=kubernetes.io/service-account-token` |
| Automount | `automountServiceAccountToken: false` where API access isn't needed | Pod/SA specs |
| External stores | ESO/CSI driver with least-privilege cloud IAM per namespace | Review SecretStore/ClusterSecretStore scopes |
| GitOps | Sealed Secrets/SOPS for secrets in Git; no plaintext | Repo scan |

## Exposure response

If a secret leaked (repo, logs, compromised pod with secret access):
1. Identify the secret's consumers and what it grants (DB, cloud API, third-party).
2. Rotate at the **source** (the database/user/API key), then update the Kubernetes secret (or external store) and restart consumers.
3. Review audit logs for who read it (`k8s-audit-log-analysis`) and provider logs for its use.
4. Revoke legacy SA tokens; rotate SA signing keys only if the key itself was exposed (cluster-wide impact).

## Related skills

`k8s-rbac-review`, `secret-leak-response`, `vault-policy-review`, `k8s-audit-log-analysis`

## References

- Kubernetes Secrets good practices: https://kubernetes.io/docs/concepts/security/secrets-good-practices/
- Encrypting confidential data at rest: https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/
- External Secrets Operator: https://external-secrets.io/
- Secrets Store CSI Driver: https://secrets-store-csi-driver.sigs.k8s.io/
