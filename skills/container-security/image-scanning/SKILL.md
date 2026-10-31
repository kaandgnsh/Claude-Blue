---
name: image-scanning
description: Scan container images for vulnerabilities, secrets, misconfigurations and malware with Trivy, Grype or registry-native scanners; choose minimal base images; gate builds; and continuously rescan registries and running workloads. Use when building or approving container images, triaging image CVE reports, or setting registry admission policy.
license: MIT
metadata:
  category: container-security
  version: "2.0.0"
  verification: documented
---

# Container Image Scanning

## Scan

```sh
trivy image --severity HIGH,CRITICAL --ignore-unfixed ghcr.io/org/app@sha256:<digest>
trivy image --scanners vuln,secret,misconfig --format sarif -o trivy.sarif ghcr.io/org/app:1.4.2
grype ghcr.io/org/app@sha256:<digest> --only-fixed --fail-on high
trivy k8s --report summary cluster          # scan workloads running in a cluster (Trivy k8s mode)
```
Registry-native: ECR enhanced scanning (Inspector), Azure Defender for Containers, GCP Artifact Analysis, Harbor (Trivy).

## Triage

1. **Base image vs. app layer**: `trivy image --format json` shows the layer/package; most OS CVEs are fixed by rebuilding on an updated base.
2. **Fixable?** `--ignore-unfixed` to focus effort; track unfixed criticals with exceptions.
3. **Reachability/runtime relevance**: package present but binary never executed (e.g., `perl` in a Go service image) → remove it with a smaller base rather than debating.
4. **KEV/EPSS** prioritization (`vuln-prioritization`).

## Base image strategy

Prefer minimal images: distroless, Chainguard/Wolfi, Alpine (musl caveats), `scratch` for static binaries; pin by digest; rebuild on a schedule (weekly) and on critical base CVEs; maintain an approved base-image list.

## Gates

CI: fail on fixable critical (and KEV) in new images. Registry: block pulls of images with critical findings or no signature (`artifact-signing`). Runtime: rescan running images daily — new CVEs appear for old images.

## Output

`Image@digest | Base | Critical/High (fixable) | KEV | Secrets | Misconfig | Decision | Owner`

## Related skills

`dockerfile-hardening`, `sbom-vulnerability-analysis`, `artifact-signing`, `release-gate`

## References

- Trivy: https://trivy.dev/
- Grype: https://github.com/anchore/grype
- NIST SP 800-190 Application Container Security Guide: https://csrc.nist.gov/pubs/sp/800/190/final
