---
name: sbom-generation
description: Generate accurate SBOMs (CycloneDX, SPDX) for source, containers and binaries with Syft, cdxgen, Trivy or build plugins; meet NTIA minimum elements; attach SBOMs to releases as signed attestations; and manage SBOM quality. Use when producing SBOMs for customers/regulators (EO 14028, EU CRA), building an SBOM pipeline, or checking an SBOM's completeness.
license: MIT
metadata:
  category: supply-chain-security
  version: "2.0.0"
  verification: documented
---

# SBOM Generation

## Generate

```sh
syft dir:. -o cyclonedx-json=sbom.cdx.json                 # source tree (lockfiles)
syft registry:ghcr.io/org/app@sha256:<digest> -o spdx-json=sbom.spdx.json   # container image by digest
cdxgen -r -o bom.json .                                     # CycloneDX generator, deep language support (-r recursive)
trivy image --format cyclonedx --output sbom.cdx.json ghcr.io/org/app:1.4.2
```
Build-time plugins (CycloneDX Maven/Gradle/npm, `cyclonedx-py`) give more accurate dependency graphs than post-hoc scanning. Generate from the **built artifact** (image digest), not only the repo.

## Quality checklist (NTIA minimum elements + practice)

- [ ] Supplier, component name, version, unique identifier (**purl**, CPE), dependency relationships, author of SBOM data, timestamp.
- [ ] Transitive dependencies included (lockfiles present at scan time).
- [ ] OS packages included for images.
- [ ] Hashes for components where available.
- [ ] SBOM references the exact artifact (image digest / file hash) it describes.
- [ ] Format validated: `cyclonedx validate --input-file sbom.cdx.json` (CycloneDX CLI) or SPDX tools.

## Distribution

Attach as a signed attestation to the image (`cosign attest --predicate sbom.cdx.json --type cyclonedx ghcr.io/org/app@sha256:<digest>`) or GitHub attestation (`actions/attest-sbom`), and store with the release. Keep SBOMs per version to answer "were we affected?" retroactively (`emergency-vulnerability-response`).

## Related skills

`sbom-vulnerability-analysis`, `artifact-signing`, `slsa-provenance`, `image-scanning`

## References

- NTIA Minimum Elements for an SBOM: https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom
- CISA SBOM resources: https://www.cisa.gov/sbom
- CycloneDX: https://cyclonedx.org/ ; SPDX: https://spdx.dev/
- Syft: https://github.com/anchore/syft ; cdxgen: https://github.com/CycloneDX/cdxgen
