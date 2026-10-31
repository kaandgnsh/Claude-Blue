---
name: risk-quantification-fair
description: Quantify cyber risk in financial terms with the FAIR model — loss event frequency (threat event frequency × vulnerability) and loss magnitude (primary and secondary losses) as calibrated ranges, Monte Carlo simulation, and comparison of control investments. Use when executives need risk in dollars/euros, comparing security investments, setting insurance limits, or prioritizing top risks.
license: MIT
metadata:
  category: security-metrics
  version: "2.0.0"
  verification: documented
---

# Risk Quantification (FAIR)

## Model

Risk = **Loss Event Frequency** (LEF) × **Loss Magnitude** (LM)
- LEF = Threat Event Frequency (how often attackers try) × Vulnerability (probability an attempt succeeds given controls).
- LM = Primary loss (response, productivity, replacement) + Secondary loss (fines, legal, notification, reputation/customer churn) × probability of secondary effects.

## Workflow

1. **Scope the scenario** precisely: asset, threat community, effect. "Ransomware affiliate encrypts ERP causing outage" — not "cyber risk".
2. **Estimate ranges** (min / most likely / max) with calibrated estimators and data: internal incidents, industry reports (Verizon DBIR, IBM/Ponemon cost data — note biases), insurance claims data, downtime cost per hour from finance.
3. **Simulate** (Monte Carlo, e.g. 10,000 iterations with PERT distributions).
4. **Report** annualized loss exposure distribution: median, 90th percentile, probability of exceeding a threshold.
5. **Compare controls**: rerun with the control's effect on vulnerability/frequency/magnitude → risk reduction vs. cost.

## Minimal Monte Carlo (Python, stdlib)

```python
import random, statistics
def pert(lo, ml, hi, lamb=4):
    a = 1 + lamb * (ml - lo) / (hi - lo); b = 1 + lamb * (hi - ml) / (hi - lo)
    return lo + random.betavariate(a, b) * (hi - lo)
random.seed(1)
annual = []
for _ in range(10000):
    events = sum(1 for _ in range(100) if random.random() < pert(0.05, 0.2, 0.6) / 100)  # LEF per year ≈ 0.05–0.6
    annual.append(sum(pert(250_000, 1_200_000, 8_000_000) for _ in range(events)))
annual.sort()
print("median", statistics.median(annual), "p90", annual[int(0.9 * len(annual))])
```
(The Bernoulli loop approximates a Poisson count of loss events; replace with your own frequency model.)

## Pitfalls

False precision (present ranges), anchoring on vendor breach-cost averages, double counting, ignoring correlation between scenarios. Document assumptions so others can challenge them.

## Related skills

`risk-register`, `security-metric-definition`, `critical-service-mapping`

## References

- FAIR Institute: https://www.fairinstitute.org/
- The Open Group Risk Taxonomy (O-RT) and Risk Analysis (O-RA) standards: https://www.opengroup.org/certifications/openfair
- NIST IR 8286A (risk register and quantification guidance): https://csrc.nist.gov/pubs/ir/8286/a/final
