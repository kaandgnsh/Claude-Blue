---
name: control-testing-sampling
description: Test security controls for design and operating effectiveness — test of design vs. operating effectiveness, attribute sampling with sample sizes by control frequency, random selection, exception evaluation and deficiency classification — for internal audit, SOX ITGC, SOC 2 readiness or second-line assurance. Use when planning control tests, choosing sample sizes, or evaluating exceptions found in testing.
license: MIT
metadata:
  category: compliance-audit
  version: "2.0.0"
  verification: documented
---

# Control Testing and Sampling

## Design vs. operation

- **Test of design (TOD)**: walkthrough of one instance — if performed as described, would the control prevent/detect the risk?
- **Test of operating effectiveness (TOE)**: did it operate consistently over the period? Requires sampling.

## Common sample size guidance (attribute testing, low expected deviation)

| Control frequency | Population/period | Typical sample |
|---|---|---|
| Annual | 1 | 1 |
| Quarterly | 4 | 2 |
| Monthly | 12 | 2–5 |
| Weekly | 52 | 5–15 |
| Daily | ~250–365 | 20–40 |
| Multiple times per day / transactional | > 365 | 25–60 |
| Automated (system-enforced) | — | 1 per configuration + change management test |

Firms use different tables — follow your audit methodology; these ranges reflect widely used practice.

## Random selection (reproducible)

```python
import csv, random
rows = list(csv.DictReader(open("population.csv")))
random.seed(20261031)                    # record the seed in workpapers
sample = random.sample(rows, k=25)
```
Document population source, count, selection method and seed.

## Evaluate exceptions

1. Confirm it's a true exception (not a misunderstanding of the control).
2. Root cause and whether it's isolated or systemic; consider expanding sample.
3. Compensating controls?
4. Classify: control deficiency / significant deficiency / material weakness (SOX), or nonconformity minor/major (ISO).
5. Remediation plan and retest.

## Workpaper fields

`Control | Risk | Test procedure | Population (source, count) | Sample (method, size) | Attributes tested | Results | Exceptions | Conclusion | Tester/reviewer/date`

## Related skills

`audit-evidence-package`, `control-mapping`, `segregation-of-duties`

## References

- AICPA Audit Guide: Audit Sampling: https://www.aicpa-cima.com/
- IIA International Professional Practices Framework (Global Internal Audit Standards): https://www.theiia.org/en/standards/
- PCAOB AS 2315 Audit Sampling: https://pcaobus.org/oversight/standards/auditing-standards/details/AS2315
