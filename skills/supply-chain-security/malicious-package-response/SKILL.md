---
name: malicious-package-response
description: Respond to a malicious or compromised open-source package or build dependency (e.g. hijacked npm maintainer accounts, self-propagating token-stealing worms, backdoored releases like xz-utils) — find every consumer, determine whether the malicious version executed, rotate exposed secrets, and block recurrence. Use when an advisory reports a malicious package version or a dependency shows unexpected install-time behaviour.
license: MIT
metadata:
  category: supply-chain-security
  version: "2.0.0"
  verification: documented
---

# Malicious Package Response

## 1. Establish facts

Package name(s), ecosystem, malicious versions and publish window, payload behaviour (install script, runtime backdoor, credential theft targets — npm tokens, GitHub tokens, cloud keys, SSH keys, crypto wallets), IOCs (domains, webhook URLs, created repos/workflows), and whether it self-propagates by republishing packages with stolen tokens.

## 2. Find consumers

```sh
# Lockfiles across repos (example: npm)
gh search code '"<pkg>": {' --owner my-org --filename package-lock.json
grep -R --include=package-lock.json -n '"node_modules/<pkg>"' -A2 . | grep '"version"'
# SBOM portfolio
for f in sboms/*.json; do jq -r --arg f "$f" '.components[]? | select(.name=="<pkg>") | [$f,.version] | @tsv' "$f"; done
# Developer machines / CI caches via EDR file search or osquery (npm_packages table on some platforms)
```
Also check artifact registries/proxies for cached malicious versions and purge them.

## 3. Did it execute?

- CI logs in the window: installs of the bad version (`npm ci` output, resolved versions), outbound network from runners to IOCs.
- Developer endpoints: EDR process events for `node`/`python` spawning `curl`, credential tool binaries (e.g. trufflehog downloaded by payload), access to `~/.npmrc`, `~/.aws/credentials`, `~/.ssh`.
- GitHub: unexpected new repos/branches/workflows created by your users' tokens (audit log `repo.create`, `workflows` changes).

## 4. Contain and recover

- Remove/pin to a known-good version; regenerate lockfiles; purge caches.
- **Rotate every secret reachable** from affected runners/machines (npm/PyPI tokens, GitHub PATs, cloud keys, SSH keys), and revoke sessions.
- Review packages you publish for unauthorized releases if maintainer tokens were exposed; enable npm trusted publishing/2FA for publish.
- Add the package/version to blocklists in the proxy registry and SCA policy.

## 5. Prevent

Lockfiles + `npm ci`, delay adoption of brand-new versions (cool-down policies in proxies/Renovate `minimumReleaseAge`), disable install scripts where possible (`npm config set ignore-scripts true` for CI jobs that don't need them), least-privilege CI tokens, malicious-package feeds in SCA.

## Related skills

`dependency-confusion-defense`, `secret-leak-response`, `github-audit-investigation`, `incident-scoping`

## References

- OpenSSF malicious packages (OSV MAL- entries): https://github.com/ossf/malicious-packages
- CISA alert on xz-utils backdoor (CVE-2024-3094): https://www.cisa.gov/news-events/alerts/2024/03/29/reported-supply-chain-compromise-affecting-xz-utils-data-compression-library-cve-2024-3094
- CISA alert: widespread npm supply chain compromise (Sept 2025): https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem
- npm trusted publishing: https://docs.npmjs.com/trusted-publishers
