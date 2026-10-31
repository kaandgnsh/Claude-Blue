---
name: k8s-network-policy
description: Design, review and test Kubernetes NetworkPolicies (and Cilium/Calico policies) — default-deny ingress/egress, namespace isolation, DNS egress, blocking cloud metadata, egress to the API server — and verify enforcement. Use when isolating workloads, containing a compromised pod, or reviewing whether a cluster network is flat.
license: MIT
metadata:
  category: kubernetes-security
  version: "2.0.0"
  verification: documented
---

# Kubernetes Network Policy

NetworkPolicies only work if the CNI enforces them (Calico, Cilium, Antrea, managed equivalents). Verify enforcement — on some clusters policies are silently ignored.

## Baseline per namespace

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: payments
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: payments
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```
Then add explicit allows (frontend → api on 8080, api → database).

## Block cloud metadata

```yaml
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except: [169.254.169.254/32]
```
(Also enforce IMDSv2 hop limit 1 on EKS nodes; GKE Workload Identity / metadata concealment.)

## Review checklist

- [ ] Every namespace has default-deny ingress **and** egress.
- [ ] No `podSelector: {}` + `ingress: [{}]` (allow-all) policies.
- [ ] Egress to the internet only from workloads that need it (via egress gateway/proxy).
- [ ] Pods can't reach the API server unless they need to.
- [ ] Monitoring/ingress controller namespaces explicitly allowed.

## Test

```sh
kubectl run np-test --rm -it -n payments --image=busybox:1.36 --restart=Never -- wget -qO- -T 3 http://api.other-ns.svc:8080 || echo blocked
```
Cilium: `cilium connectivity test`; Hubble flow logs show policy verdicts (`hubble observe --verdict DROPPED`).

## Containment use

Isolate a compromised pod: label it `quarantine=true` and apply a deny-all policy selecting that label (keeps it running for forensics — `container-incident`).

## Related skills

`container-incident`, `network-segmentation-review`, `k8s-cluster-hardening`

## References

- Kubernetes Network Policies: https://kubernetes.io/docs/concepts/services-networking/network-policies/
- Network policy recipes: https://github.com/ahmetb/kubernetes-network-policy-recipes
- Cilium network policy: https://docs.cilium.io/en/stable/security/policy/
