---
name: hunt-to-detection
description: Convert hunt findings into durable, tested detections — decide alert vs. dashboard vs. scheduled hunt, generalize from IOCs to behaviour, estimate volume, write Sigma/SIEM rules, and hand off with documentation. Use at the end of a hunt, or when a manual query keeps being re-run and should become automated.
license: MIT
metadata:
  category: threat-hunting
  version: "2.0.0"
  verification: documented
---

# Hunt to Detection

## Decide the output type

| Signal characteristics | Output |
|---|---|
| High fidelity, low volume (< ~1/day), clear response | **Alert** (detection rule) |
| Useful context, too noisy alone | **Risk-based score / correlation input** (`correlation-rule-design`) |
| Requires human pattern recognition | **Scheduled hunt / dashboard** with owner and cadence |
| Single IOC with short lifetime | **IOC watchlist** with expiry (`intel-to-detection`) |

## Workflow

1. **Generalize**: replace the specific hash/IP/filename with the behaviour (e.g., "msbuild.exe compiling a project from a user-writable path" rather than "msbuild.exe C:\Users\bob\x.csproj").
2. **Back-test** the logic over 30–90 days: count hits, inspect a sample, compute expected daily volume and benign sources.
3. **Write the rule** in Sigma first (`sigma-authoring`) then convert/deploy (`sigma-conversion`, `detection-as-code`).
4. **Document** with the ADS template (`alerting-detection-strategy`): goal, ATT&CK, blind spots, false positives, validation, response.
5. **Validate** with a true-positive test (`detection-testing`) and a known benign case.
6. **Hand off**: SOC runbook (`runbook-authoring`), severity, owner, review date.

## Quality gate

- [ ] Fires on the original hunt finding (or its lab reproduction).
- [ ] Expected volume known and acceptable to the SOC.
- [ ] Exclusions are narrow (`alert-tuning` checklist).
- [ ] Blind spots documented (e.g., renamed binaries, missing telemetry on Linux).
- [ ] Runbook exists.

## Related skills

`hypothesis-hunt`, `sigma-authoring`, `detection-testing`, `alerting-detection-strategy`, `detection-lifecycle`

## References

- Palantir ADS framework: https://github.com/palantir/alerting-detection-strategy-framework
- SigmaHQ: https://github.com/SigmaHQ/sigma
