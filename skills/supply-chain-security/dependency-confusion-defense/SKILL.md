---
name: dependency-confusion-defense
description: Prevent and detect dependency confusion, typosquatting and namespace hijacking across npm, PyPI, Maven, NuGet, Go and container registries — scoped/namespaced internal packages, registry routing (no extra-index-url mixing), package source mapping, name reservation and install-time monitoring. Use when designing internal package management, reviewing build configs, or investigating an unexpected public package in a build.
license: MIT
metadata:
  category: supply-chain-security
  version: "2.0.0"
  verification: documented
---

# Dependency Confusion Defense

Dependency confusion: a build resolves an internal package name from a **public** registry where an attacker published a higher version.

## Controls by ecosystem

| Ecosystem | Control |
|---|---|
| npm | Use **scopes** for internal packages (`@corp/pkg`) and map the scope to the internal registry in `.npmrc`: `@corp:registry=https://npm.corp.example/`; register the scope on npmjs.com; commit lockfiles and use `npm ci` |
| PyPI | Never mix `--extra-index-url` with internal names (pip picks highest version across indexes). Use a single proxy index (Artifactory/Nexus/devpi) that **blocks** public packages matching internal names; pin hashes (`--require-hashes`); consider PEP 708 tracking metadata |
| Maven/Gradle | Internal groupIds you own (reverse DNS); repository ordering + content filtering (`exclusiveContent` in Gradle) |
| NuGet | **Package Source Mapping** in `nuget.config` (`<packageSourceMapping>`) and reserved ID prefixes on nuget.org |
| Go | `GOPRIVATE=corp.example/*`, `GONOSUMDB`, `GOPROXY` pointing to internal proxy |
| Containers | Pull internal images by full registry path + digest; disable implicit Docker Hub fallback |

Registry managers (Artifactory/Nexus): use virtual repos with priority resolution / exclude patterns so internal names never resolve externally.

## Detection

- Monitor builds for packages resolved from public registries whose names match internal naming patterns.
- Alert on install scripts executing network calls (`preinstall`/`postinstall` with `curl`, DNS exfil patterns).
- Periodically query public registries for your internal package names (`npm view <name>`, `pip index versions <name>`) and reserve them.

## Typosquatting

Review new dependencies in PRs (diff of lockfile), flag names within edit distance 1–2 of popular packages, prefer allow-listed packages for production, and use tooling that checks malicious-package databases (OSV `MAL-` advisories, Socket, Phylum, GuardDog).

## Related skills

`malicious-package-response`, `sca-dependency-risk`, `pipeline-threat-model`

## References

- Alex Birsan, "Dependency Confusion" (2021): https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
- Microsoft "3 ways to mitigate risk when using private package feeds": https://azure.microsoft.com/en-us/resources/3-ways-to-mitigate-risk-using-private-package-feeds/
- NuGet Package Source Mapping: https://learn.microsoft.com/en-us/nuget/consume-packages/package-source-mapping
- OpenSSF malicious packages repository: https://github.com/ossf/malicious-packages
