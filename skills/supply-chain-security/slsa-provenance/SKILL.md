---
name: slsa-provenance
description: Assess and implement SLSA build provenance — SLSA v1.0 build track levels, in-toto provenance attestations, hosted isolated builders, slsa-github-generator and slsa-verifier — and verify provenance (source repo, ref, builder) before deployment. Use when evaluating build integrity, raising a project's SLSA level, or verifying third-party artifacts' provenance.
license: MIT
metadata:
  category: supply-chain-security
  version: "2.0.0"
  verification: documented
---

# SLSA Provenance

## SLSA v1.0 build track

| Level | Requirement (summary) | Defends against |
|---|---|---|
| Build L1 | Provenance exists describing how the artifact was built | Mistakes, lack of visibility |
| Build L2 | Hosted build platform generates and **signs** provenance | Tampering after the build |
| Build L3 | Hardened builder: isolated builds, provenance unforgeable by tenant/user build steps, secrets not accessible to user-defined steps that could forge provenance | Tampering during the build by compromised build steps or insiders |

(SLSA source track requirements are evolving separately — check current spec.)

## Generate

- GitHub: `slsa-framework/slsa-github-generator` reusable workflows (generic, container, Go) produce L3 provenance; or GitHub artifact attestations (`actions/attest-build-provenance`) for L2-style signed provenance.
- GitLab: SLSA provenance via `RUNNER_GENERATE_ARTIFACTS_METADATA`.
- Tekton Chains / Google Cloud Build produce provenance for those platforms.

## Verify

```sh
slsa-verifier verify-artifact app-linux-amd64 \
  --provenance-path app-linux-amd64.intoto.jsonl \
  --source-uri github.com/org/app --source-tag v1.4.2
slsa-verifier verify-image ghcr.io/org/app@sha256:<digest> --source-uri github.com/org/app --source-branch main
gh attestation verify oci://ghcr.io/org/app@sha256:<digest> -o org   # GitHub attestations
```
Policy: deploy only artifacts whose provenance shows the expected **source repo**, **ref** (protected branch/tag), and **builder ID**.

## Review questions

- Can a developer produce an artifact accepted by deploy without CI? (bypass)
- Are build steps able to read signing material? (forgery)
- Are builds ephemeral and isolated from each other (cache poisoning)?
- Are dependencies pinned and fetched from trusted sources?

## Related skills

`artifact-signing`, `pipeline-threat-model`, `github-actions-hardening`, `sbom-generation`

## References

- SLSA specification v1.0: https://slsa.dev/spec/v1.0/
- in-toto attestation framework: https://github.com/in-toto/attestation
- slsa-github-generator: https://github.com/slsa-framework/slsa-github-generator
- slsa-verifier: https://github.com/slsa-framework/slsa-verifier
