---
name: alerting-detection-strategy
description: Document a detection with the Alerting and Detection Strategy (ADS) framework — goal, categorization, strategy abstract, technical context, blind spots and assumptions, false positives, validation, priority and response. Use when proposing a new detection, reviewing a rule for production readiness, or onboarding analysts to an alert.
license: MIT
metadata:
  category: detection-engineering
  version: "2.0.0"
  verification: documented
---

# Alerting and Detection Strategy (ADS)

An ADS forces the author to state what the detection *cannot* see. Write it before (or alongside) the rule.

## Template

```markdown
# ADS: <Detection name>   Rule ID: <>   Owner: <>   Status: <draft/prod>

## Goal
What adversary behaviour this detects and why it matters (one paragraph).

## Categorization
MITRE ATT&CK: <tactic> / <technique ID and name>

## Strategy Abstract
High-level how: data sources, the key logic, enrichment, thresholds.

## Technical Context
Background an analyst needs: how the technique works, what normal looks like,
relevant event/field documentation.

## Blind Spots and Assumptions
- Assumes <telemetry X> is collected on <population>.
- Does not detect <variation: renamed binary / alternate API / Linux>.
- Attacker could evade by <...>.

## False Positives
Known benign sources and how they are handled (exclusion lookup reference).

## Validation
Exact steps to generate a true positive (e.g. Atomic test GUID / command) and expected alert.

## Priority
Severity mapping and rationale (e.g. high if target is Tier 0).

## Response
Link to runbook; first three triage steps.

## Additional Resources
References.
```

## Worked example (abbreviated)

- **Goal**: detect LSASS memory dumping via `comsvcs.dll` MiniDump on Windows endpoints.
- **Categorization**: Credential Access / T1003.001 OS Credential Dumping: LSASS Memory.
- **Strategy abstract**: process-creation telemetry (Sysmon 1 / MDE `DeviceProcessEvents`) where the command line contains both `comsvcs` and `MiniDump`; enriched with host tier.
- **Blind spots**: renamed `rundll32` copies are caught only via `OriginalFileName`; dumping via direct API calls or other tools (procdump, custom loaders) needs the ProcessAccess-based companion rule; hosts without command-line logging are blind.
- **False positives**: none expected; vendor support tooling must be documented in the allow-list lookup with owner/expiry.
- **Validation**: Atomic Red Team T1003.001 test "Dump LSASS.exe Memory using comsvcs.dll" on a lab host; alert expected within 5 minutes.
- **Priority**: high; critical when host is Tier 0.
- **Response**: `credential-theft-detection` runbook — isolate, scope sessions on host, reset exposed credentials.

## Review criteria

- Blind spots are specific, not "attacker may evade".
- Validation steps are reproducible by someone else.
- False-positive handling references a maintained, owned allow-list.
- Response section enables a tier-1 analyst to act.

## Related skills

`sigma-authoring`, `detection-testing`, `runbook-authoring`, `hunt-to-detection`

## References

- Palantir ADS framework: https://github.com/palantir/alerting-detection-strategy-framework
