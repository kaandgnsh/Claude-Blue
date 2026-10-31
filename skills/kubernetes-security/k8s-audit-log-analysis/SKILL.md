---
name: k8s-audit-log-analysis
description: Investigate and hunt in Kubernetes API server audit logs (self-managed, EKS, AKS, GKE) — exec into pods, secret reads, RBAC changes, privileged pod creation, anonymous access, token creation, unusual user agents and source IPs. Use when investigating cluster compromise, building Kubernetes detections, or verifying audit policy coverage.
license: MIT
metadata:
  category: kubernetes-security
  version: "2.0.0"
  verification: documented
---

# Kubernetes Audit Log Analysis

## Where the logs are

| Platform | Location |
|---|---|
| Self-managed | `--audit-log-path` / webhook backend; policy via `--audit-policy-file` |
| EKS | CloudWatch Logs `/aws/eks/<cluster>/cluster`, stream `kube-apiserver-audit-*` (enable `audit` control-plane logging) |
| AKS | Diagnostic setting category `kube-audit` / `kube-audit-admin` → Log Analytics (`AKSAudit`/`AzureDiagnostics`) |
| GKE | Cloud Audit Logs: Admin Activity (on) + Data Access (enable) with `protoPayload.serviceName="k8s.io"` |

## Key fields (audit.k8s.io/v1 Event)

`verb`, `user.username`, `user.groups`, `impersonatedUser`, `sourceIPs`, `userAgent`, `objectRef.{resource,subresource,namespace,name}`, `responseStatus.code`, `requestObject` (at RequestResponse level), `annotations["authorization.k8s.io/decision"]`.

## Hunts (jq over JSON-lines audit logs)

```sh
# Exec/attach into pods
jq -c 'select(.objectRef.subresource=="exec" or .objectRef.subresource=="attach") | {t:.requestReceivedTimestamp,u:.user.username,ns:.objectRef.namespace,pod:.objectRef.name,ip:.sourceIPs[0],code:.responseStatus.code}' audit.log
# Secret reads by non-system identities
jq -c 'select(.objectRef.resource=="secrets" and (.verb=="get" or .verb=="list") and (.user.username|startswith("system:")|not)) | {u:.user.username,ns:.objectRef.namespace,name:.objectRef.name,verb}' audit.log
# RBAC changes
jq -c 'select(.objectRef.resource|test("rolebindings|clusterroles|roles")) | select(.verb|test("create|update|patch|delete")) | {t:.requestReceivedTimestamp,u:.user.username,verb,res:.objectRef.resource,name:.objectRef.name}' audit.log
# Privileged pods created
jq -c 'select(.verb=="create" and .objectRef.resource=="pods") | select([.requestObject.spec.containers[]?.securityContext.privileged]|any) | {u:.user.username,ns:.objectRef.namespace,pod:.objectRef.name}' audit.log
# Anonymous / forbidden probing
jq -c 'select(.user.username=="system:anonymous" or .responseStatus.code==403) | {u:.user.username,ip:.sourceIPs[0],uri:.requestURI,code:.responseStatus.code}' audit.log
# Token creation for service accounts
jq -c 'select(.objectRef.resource=="serviceaccounts" and .objectRef.subresource=="token") | {u:.user.username,sa:.objectRef.name,ns:.objectRef.namespace}' audit.log
```
Sentinel (AKS): `AKSAudit | where ObjectRef.subresource == "exec" | project TimeGenerated, User.username, ObjectRef.namespace, ObjectRef.name, SourceIps` (column names per table version).

## Red flags

kubectl from unusual IPs/user agents (`kubectl/v1.x (linux/amd64)` from a pod IP = in-cluster attacker), service accounts doing `list secrets` cluster-wide, new ClusterRoleBinding to cluster-admin, `create pods` with `hostPID`/`hostPath: /`, DaemonSets in `kube-system` created by humans, `system:anonymous` successes.

## Audit policy

Log `secrets`, `configmaps`, `tokenreviews` at Metadata (never RequestResponse for secrets); `pods/exec`, RBAC and workload writes at RequestResponse; drop noisy read-only system traffic.

## Related skills

`k8s-incident-response`, `k8s-rbac-review`, `runtime-detection-falco`, `cloud-logging-baseline`

## References

- Kubernetes auditing: https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
- EKS control plane logging: https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html
- GKE audit logging: https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging
- Microsoft Threat Matrix for Kubernetes: https://microsoft.github.io/Threat-Matrix-for-Kubernetes/
