---
name: k8s-cluster-hardening
description: Assess and harden Kubernetes clusters against CIS Kubernetes Benchmark and NSA/CISA guidance — API server exposure and authentication, kubelet authn/authz, etcd, control-plane logging, node hardening, managed-service settings (EKS/AKS/GKE) — using kube-bench, kubescape and managed-cluster checks. Use for cluster security assessments, new cluster baselines, or remediation of benchmark findings.
license: MIT
metadata:
  category: kubernetes-security
  version: "2.0.0"
  verification: documented
---

# Kubernetes Cluster Hardening

## Assessment tools

```sh
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml && kubectl logs job/kube-bench   # CIS checks on nodes
kube-bench run --targets node                     # on a node; managed control planes can't be fully checked
kubescape scan framework nsa                      # NSA/CISA hardening framework; also 'cis-v1.10.0', 'mitre'
trivy k8s --report summary cluster                # misconfig + vulns across workloads
```
Managed services publish their own benchmark variants (CIS EKS, AKS, GKE benchmarks).

## Priority controls

| Area | Control |
|---|---|
| API server | Private endpoint or authorized IP ranges; no anonymous auth (`--anonymous-auth=false` or restricted); OIDC/cloud IAM auth; audit logging on |
| Kubelet | `--anonymous-auth=false`, `--authorization-mode=Webhook`, read-only port 10255 disabled |
| etcd | TLS client auth, not reachable from pod network, encryption at rest |
| Nodes | Minimal OS (Bottlerocket, COS, Flatcar), auto-upgrades, no SSH or SSH via SSM/bastion only, IMDSv2 with hop limit 1 |
| Identity | Workload identity (IRSA/EKS Pod Identity, AKS Workload Identity, GKE Workload Identity) instead of node credentials |
| Workloads | PSA restricted / admission policies (`k8s-admission-control`), NetworkPolicies (`k8s-network-policy`) |
| Add-ons | Dashboards not exposed; ingress controllers patched (e.g., ingress-nginx CVE-2025-1974 "IngressNightmare" — admission webhook exposure) |
| Upgrades | Supported Kubernetes minor version; documented upgrade cadence |

Managed checks:
```sh
aws eks describe-cluster --name C --query 'cluster.{endpointPublic:resourcesVpcConfig.endpointPublicAccess,publicCidrs:resourcesVpcConfig.publicAccessCidrs,logging:logging.clusterLogging}'
az aks show -g RG -n C --query '{private:apiServerAccessProfile.enablePrivateCluster,authorizedIps:apiServerAccessProfile.authorizedIpRanges,aad:aadProfile}'
gcloud container clusters describe C --zone Z --format='yaml(privateClusterConfig,masterAuthorizedNetworksConfig,workloadIdentityConfig,legacyAbac)'
```

## Output

`Control | Benchmark ID | Status | Evidence | Risk | Remediation | Owner`

## Related skills

`k8s-admission-control`, `k8s-rbac-review`, `k8s-network-policy`, `cloud-posture-assessment`

## References

- CIS Kubernetes Benchmark: https://www.cisecurity.org/benchmark/kubernetes
- NSA/CISA Kubernetes Hardening Guide: https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF
- kube-bench: https://github.com/aquasecurity/kube-bench
- Kubescape: https://kubescape.io/docs/
