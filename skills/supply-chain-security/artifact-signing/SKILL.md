---
name: artifact-signing
description: Sign and verify software artifacts and container images with Sigstore cosign (keyless OIDC or KMS keys), GitHub artifact attestations, npm provenance and Notation; enforce verification at deploy with admission policies. Use when implementing artifact integrity, verifying third-party images, or investigating whether a deployed artifact is the one CI built.
license: MIT
metadata:
  category: supply-chain-security
  version: "2.0.0"
  verification: documented
---

# Artifact Signing and Verification

## Cosign (Sigstore)

```sh
# Keyless signing in CI (OIDC identity → Fulcio cert, logged in Rekor transparency log)
cosign sign --yes ghcr.io/org/app@sha256:<digest>
# Verify: pin the expected signer identity and issuer — never verify "any signature"
cosign verify ghcr.io/org/app@sha256:<digest> \
  --certificate-identity "https://github.com/org/app/.github/workflows/release.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
# Key-based with cloud KMS
cosign sign --key awskms:///alias/cosign-signing ghcr.io/org/app@sha256:<digest>
cosign verify --key awskms:///alias/cosign-signing ghcr.io/org/app@sha256:<digest>
# Blobs (release tarballs)
cosign sign-blob --yes --bundle app.tgz.sigstore.json app.tgz
cosign verify-blob --bundle app.tgz.sigstore.json --certificate-identity-regexp '^https://github.com/org/app/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com app.tgz
```
Always sign and deploy by **digest**, not tag.

## GitHub artifact attestations

Workflow step `actions/attest-build-provenance` (needs `id-token: write`, `attestations: write`); verify: `gh attestation verify ./app.tgz -R org/app` or `gh attestation verify oci://ghcr.io/org/app@sha256:<digest> -o org`.

## npm

`npm publish --provenance` from CI; consumers: `npm audit signatures` checks registry signatures and provenance attestations.

## Enforce at deploy

Kubernetes admission: Sigstore **policy-controller** (`ClusterImagePolicy` with keyless identities), **Kyverno** `verifyImages` rules, or Ratify with Gatekeeper. Start in audit mode, then enforce for production namespaces.

## Investigation: "is this the artifact we built?"

Compare running image digest (`kubectl get pod -o jsonpath='{..imageID}'`) to the signed digest; check Rekor entry (`rekor-cli search --sha <digest>`) and provenance (`slsa-provenance`) for the source commit and workflow.

## Related skills

`slsa-provenance`, `sbom-generation`, `k8s-admission-control`, `release-gate`

## References

- Sigstore cosign docs: https://docs.sigstore.dev/cosign/signing/overview/
- GitHub artifact attestations: https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations
- npm provenance: https://docs.npmjs.com/generating-provenance-statements
- Sigstore policy-controller: https://docs.sigstore.dev/policy-controller/overview/
- Kyverno verifyImages: https://kyverno.io/docs/policy-types/cluster-policy/verify-images/
