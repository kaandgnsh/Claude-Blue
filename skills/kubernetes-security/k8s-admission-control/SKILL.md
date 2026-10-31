---
name: k8s-admission-control
description: Enforce workload security with Kubernetes admission control — Pod Security Admission (baseline/restricted), ValidatingAdmissionPolicy (CEL), Kyverno or OPA Gatekeeper policies for privileged pods, host namespaces, image registries/signatures, resource limits — with audit-first rollout. Use when hardening clusters against risky workloads, writing admission policies, or reviewing policy exceptions.
license: MIT
metadata:
  category: kubernetes-security
  version: "2.0.0"
  verification: documented
---

# Kubernetes Admission Control

## Pod Security Admission (built-in)

```sh
kubectl label ns payments pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest \
  pod-security.kubernetes.io/warn=restricted pod-security.kubernetes.io/audit=restricted
kubectl label --dry-run=server --overwrite ns --all pod-security.kubernetes.io/enforce=baseline   # preview violations
```
`restricted` requires: non-root, no privilege escalation, drop ALL capabilities, seccomp RuntimeDefault, no host namespaces/hostPath, restricted volume types.

## ValidatingAdmissionPolicy (CEL, GA in 1.30)

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: images-from-approved-registry
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
  validations:
    - expression: "object.spec.containers.all(c, c.image.startsWith('registry.corp.example/'))"
      message: "Images must come from registry.corp.example"
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: images-from-approved-registry
spec:
  policyName: images-from-approved-registry
  validationActions: ["Audit", "Warn"]   # switch to ["Deny"] after review
  matchResources:
    namespaceSelector:
      matchLabels:
        env: production
```
Extend the expression to `initContainers` and `ephemeralContainers` for completeness.

## Kyverno example (disallow privileged, audit first)

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged
spec:
  validationFailureAction: Audit
  background: true
  rules:
    - name: no-privileged
      match:
        any:
          - resources:
              kinds: [Pod]
      validate:
        message: "Privileged containers are not allowed."
        pattern:
          spec:
            =(initContainers):
              - =(securityContext):
                  =(privileged): "false"
            containers:
              - =(securityContext):
                  =(privileged): "false"
```
Kyverno also verifies image signatures (`verifyImages`, see `artifact-signing`).

## Rollout

Audit/warn → review PolicyReports (`kubectl get policyreport -A`) or audit annotations → fix workloads → enforce per namespace → handle exceptions with scoped exemptions (namespace + workload, expiry, owner). Exempt `kube-system` carefully; attackers target exempt namespaces.

## Related skills

`k8s-cluster-hardening`, `artifact-signing`, `dockerfile-hardening`, `iac-scanning`

## References

- Pod Security Standards: https://kubernetes.io/docs/concepts/security/pod-security-standards/
- ValidatingAdmissionPolicy: https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/
- Kyverno: https://kyverno.io/docs/
- OPA Gatekeeper: https://open-policy-agent.github.io/gatekeeper/website/docs/
