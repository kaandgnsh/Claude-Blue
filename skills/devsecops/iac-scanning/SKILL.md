---
name: iac-scanning
description: Scan and review infrastructure-as-code (Terraform, CloudFormation, Bicep/ARM, Kubernetes manifests, Helm, Dockerfiles) for security misconfigurations with Checkov, Trivy config, KICS or tfsec-equivalents, triage findings, write custom policies, and gate pipelines. Use when reviewing IaC pull requests, adding IaC scanning to CI, or preventing cloud misconfigurations before deployment.
license: MIT
metadata:
  category: devsecops
  version: "2.0.0"
  verification: documented
---

# IaC Scanning

## Tools

```sh
checkov -d . --framework terraform,kubernetes,dockerfile --output sarif --output-file-path results/
checkov -f plan.json --framework terraform_plan             # scan rendered plan (resolves variables/modules)
trivy config --severity HIGH,CRITICAL .                     # Trivy misconfiguration scanning (tfsec engine merged into Trivy)
kics scan -p . -o results/ --report-formats sarif
```
For Terraform, scanning the **plan JSON** (`terraform plan -out tf.plan && terraform show -json tf.plan > plan.json`) catches values hidden behind variables and modules.

## High-value checks

Public storage (S3 `block_public_acls`, Azure `allow_blob_public_access`, GCS `uniform_bucket_level_access` + no `allUsers`), security groups/NSGs open to `0.0.0.0/0` on admin ports, encryption at rest/in transit disabled, logging disabled (CloudTrail, flow logs, diagnostic settings), IAM wildcards (`"Action": "*"`, `"Resource": "*"`), public database endpoints, IMDSv1 allowed (`http_tokens = "optional"`), Kubernetes privileged pods/hostPath/root users, secrets in plain text variables.

## Triage & suppression

- Validate context: a public bucket for a static website may be intended — suppress inline with justification:
  - Checkov: `#checkov:skip=CKV_AWS_20:Public website bucket, approved RISK-123`
  - Trivy: `#trivy:ignore:AVD-AWS-0086` (with comment)
- Fail CI on new HIGH/CRITICAL; report MEDIUM.
- Custom policies for org rules (Checkov YAML/Python policies, OPA/Rego with conftest: `conftest test plan.json -p policy/`).

## Related skills

`cloud-posture-assessment`, `release-gate`, `k8s-admission-control`, `dockerfile-hardening`, `cloud-firewall-build`

## References

- Checkov: https://www.checkov.io/
- Trivy misconfiguration scanning: https://trivy.dev/latest/docs/scanner/misconfiguration/
- KICS: https://docs.kics.io/
- Conftest: https://www.conftest.dev/
