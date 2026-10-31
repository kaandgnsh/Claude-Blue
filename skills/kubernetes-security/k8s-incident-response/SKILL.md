---
name: k8s-incident-response
description: Respond to a Kubernetes cluster compromise — scope via audit logs and runtime alerts, identify abused identities (service accounts, cloud IAM, kubeconfigs), find attacker workloads and persistence (DaemonSets, CronJobs, webhooks, RBAC), contain, and rebuild trust. Use when a cluster shows malicious workloads, unexpected RBAC changes, cryptomining, or stolen kubeconfig/cloud credentials.
license: MIT
metadata:
  category: kubernetes-security
  version: "2.0.0"
  verification: documented
---

# Kubernetes Incident Response

## Scope

1. **Entry point**: exposed dashboard/API, vulnerable app → pod → SA token, leaked kubeconfig/cloud credentials, compromised CI deploy credentials, vulnerable ingress controller.
2. **Identities used**: from audit logs (`k8s-audit-log-analysis`): usernames, SA names, source IPs, user agents; cloud audit logs for the cluster's IAM (CloudTrail `eks:*`/`sts:AssumeRoleWithWebIdentity`, Azure Activity, GCP audit).
3. **Attacker objects** — look for recently created/changed:
   ```sh
   kubectl get pods,deploy,ds,sts,cronjobs,jobs -A --sort-by=.metadata.creationTimestamp -o wide | tail -40
   kubectl get clusterrolebindings,rolebindings -A --sort-by=.metadata.creationTimestamp | tail -20
   kubectl get mutatingwebhookconfigurations,validatingwebhookconfigurations
   kubectl get secrets -A --field-selector type=kubernetes.io/service-account-token
   kubectl get pods -A -o json | jq -r '.items[] | select(.spec.hostPID or .spec.hostNetwork or ([.spec.containers[].securityContext.privileged]|any)) | "\(.metadata.namespace)/\(.metadata.name)"'
   ```
   Typical persistence: privileged DaemonSet, CronJob pulling a miner, new ClusterRoleBinding, malicious admission webhook, static pod manifests on nodes (`/etc/kubernetes/manifests`), backdoored images.
4. **Node impact**: any privileged/hostPath workload → treat node as compromised (`linux-incident-triage`).

## Contain

- Preserve evidence first (`container-incident`), export manifests of attacker objects (`kubectl get <obj> -o yaml`).
- NetworkPolicy quarantine; scale attacker workloads to 0 after capture; cordon/drain compromised nodes.
- Revoke credentials: delete attacker RBAC, rotate SA tokens (delete legacy token secrets; restart pods for projected tokens), revoke cloud IAM sessions, rotate kubeconfig client certs (or the cluster CA in severe cases — cluster-wide disruption), restrict API endpoint access.

## Recover

Rebuild compromised nodes from clean images; redeploy workloads from Git by signed digest; rotate all secrets the compromised identities could read; consider new cluster if control plane trust is lost (cluster-admin + unknown persistence).

## Output

Incident timeline + `Object | Namespace | Created by | Time | Purpose | Action` + credential rotation list.

## Related skills

`k8s-audit-log-analysis`, `container-incident`, `k8s-rbac-review`, `cloud-incident-response`

## References

- Microsoft Threat Matrix for Kubernetes: https://microsoft.github.io/Threat-Matrix-for-Kubernetes/
- MITRE ATT&CK Containers matrix: https://attack.mitre.org/matrices/enterprise/containers/
- AWS EKS Best Practices — incident response: https://docs.aws.amazon.com/eks/latest/best-practices/incident-response-and-forensics.html
