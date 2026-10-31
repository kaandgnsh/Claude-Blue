---
name: segregation-of-duties
description: Define and detect segregation-of-duties (SoD) conflicts and toxic access combinations — finance (create vendor + approve payment), IT (develop + deploy to prod, admin + audit log control), security (grant access + approve access) — build a conflict matrix, find violations from entitlement data and manage mitigating controls. Use for SOX/financial controls, IAM role design, or when auditors report SoD violations.
license: MIT
metadata:
  category: identity-governance
  version: "2.0.0"
  verification: documented
---

# Segregation of Duties

## Conflict matrix (examples)

| Function A | Function B | Risk |
|---|---|---|
| Create/modify vendor master | Approve/release payments | Fictitious vendor fraud |
| Create purchase order | Approve PO / receive goods | Procurement fraud |
| Payroll data maintenance | Payroll run approval | Ghost employees |
| Develop code | Deploy to production without review | Unauthorized changes |
| Administer system | Modify/delete its audit logs | Covering tracks |
| Request access | Approve own access | Self-provisioning |
| Manage security tooling (EDR/SIEM) | Day-to-day privileged admin | Disable detection before misuse |
| Grant cloud IAM | Approve change tickets | Unchecked privilege |

## Detection workflow

1. Map business functions to technical entitlements per system (SAP roles/transactions, Oracle responsibilities, Workday security groups, cloud IAM roles, CI/CD permissions). This mapping is the hard, valuable part — keep it versioned.
2. Extract user → entitlement data from each system; normalize identities (employee ID).
3. Evaluate rules (including cross-system: e.g., ERP vendor creation + banking portal payment release).
4. For each violation: remove access, or document a **mitigating control** (e.g., monthly review of vendor-master changes by finance controller, with evidence), approver and expiry.
5. Prevent: check SoD rules at access-request time (IGA preventive SoD).

Simple evaluation sketch:
```python
conflicts = [({"ERP:VendorMaintain"}, {"ERP:PaymentRelease"}), ({"GH:repo-admin"}, {"PROD:deploy"})]
for user, ents in user_entitlements.items():
    for a, b in conflicts:
        if ents & a and ents & b:
            print(user, sorted(ents & a), sorted(ents & b))
```

## Output

`User | Conflict rule | Entitlements | Systems | Mitigating control | Owner | Decision | Expiry`

## Related skills

`access-certification`, `privileged-access-review`, `control-testing-sampling`

## References

- ISACA, "A Step-by-Step SoD Implementation Guide" (ISACA Journal): https://www.isaca.org/resources/isaca-journal
- NIST SP 800-53 Rev. 5 AC-5 Separation of Duties: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- COSO Internal Control framework: https://www.coso.org/
