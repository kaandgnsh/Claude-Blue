---
name: k8s-rbac-review
description: Review Kubernetes RBAC for privilege-escalation paths — cluster-admin bindings, wildcard roles, secrets read, pods/exec, pod creation, escalate/bind/impersonate, nodes/proxy, token creation, grants to system:authenticated — with a bundled tested analyzer plus kubectl auth can-i, rbac-tool or KubiScan. Use when auditing cluster access, after a cluster compromise, or before granting a team or service account new permissions.
license: MIT
metadata:
  category: kubernetes-security
  version: "2.0.0"
  verification: tested
---

# Kubernetes RBAC Review

## Collect and analyze

```sh
kubectl get roles,clusterroles,rolebindings,clusterrolebindings -A -o json > rbac.json
python3 scripts/rbac_audit.py rbac.json --min-severity high      # bundled analyzer: findings per subject/binding
kubectl auth can-i --list --as=system:serviceaccount:build:ci     # effective permissions of one identity
kubectl auth can-i get secrets -A --as=alice
kubectl rbac-tool who-can get secrets                             # (rbac-tool plugin) reverse lookup
```

## Dangerous permissions (why they matter)

| Permission | Escalation |
|---|---|
| `*` on `*` / cluster-admin | Full control |
| `get/list/watch secrets` | Read service-account tokens & app credentials → become other identities |
| `create pods` (any namespace with privileged SA) | Mount any secret/SA in that namespace; hostPath/privileged if admission doesn't block |
| `create pods/exec`, `pods/attach` | Run commands in other workloads (inherit their identity) |
| `escalate`, `bind` on roles | Grant themselves more |
| `impersonate` users/groups/SAs | Act as anyone, e.g. `system:masters` |
| `nodes/proxy` | Kubelet API → exec in any pod on the node |
| `create serviceaccounts/token` | Mint tokens for privileged SAs |
| `approve CSRs`, webhook config write | Mint client certs; intercept/mutate all objects |
| Grants to `system:authenticated`/`system:anonymous` | Everyone (including any cloud-IAM-authenticated principal on some managed clusters) gets it |

## Review steps

1. List all cluster-admin / `system:masters` holders (including cloud IAM mappings: EKS access entries / `aws-auth` ConfigMap, AKS Entra ID group bindings, GKE IAM `container.admin`).
2. Run the analyzer; for each critical/high finding confirm business need and owner.
3. Check default service accounts: `automountServiceAccountToken: false` where not needed; no roles bound to `default` SAs.
4. Prefer namespace-scoped Roles, aggregated read-only roles, and groups from the IdP over individual users.
5. Recheck after changes; schedule quarterly reviews.

## Output

`Subject | Via binding/role | Scope | Risky permission | Justification | Decision | Owner`

## Related skills

`k8s-audit-log-analysis`, `k8s-cluster-hardening`, `k8s-incident-response`, `privileged-access-review`

## References

- Kubernetes RBAC good practices: https://kubernetes.io/docs/concepts/security/rbac-good-practices/
- Kubernetes RBAC authorization: https://kubernetes.io/docs/reference/access-authn-authz/rbac/
- rbac-tool: https://github.com/alcideio/rbac-tool
