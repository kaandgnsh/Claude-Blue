---
name: ad-attack-path-analysis
description: Use BloodHound (Community Edition) and SharpHound/AzureHound data defensively to find and remove attack paths to Tier 0 — ACL abuse (GenericAll, WriteDacl, AddMember), sessions, delegation, ADCS and hybrid paths. Use when prioritizing AD remediation, validating tiering, or explaining how an attacker reached Domain Admin.
license: MIT
metadata:
  category: active-directory-security
  version: "2.0.0"
  verification: documented
---

# AD Attack Path Analysis (Defensive BloodHound)

## Collection (authorized, coordinated with the SOC)

```powershell
SharpHound.exe -c All,GPOLocalGroup --outputdirectory C:\bh --zipfilename collection.zip
```
SharpHound/AzureHound activity resembles attacker reconnaissance — notify the SOC, run from an approved host, and store output as sensitive (it is a map to your crown jewels). BloodHound Enterprise / CE ingest via the UI.

## Edges that matter most

| Edge | Meaning | Typical fix |
|---|---|---|
| MemberOf → Tier 0 | Direct privilege | Remove; use JIT/PIM |
| GenericAll / GenericWrite / WriteDacl / WriteOwner / Owns | Full or ACL control over object | Remove ACE; review delegated admin model |
| AddMember / AddSelf | Can add to group | Remove ACE |
| ForceChangePassword | Reset another user's password | Restrict to helpdesk tier for non-admin users only |
| HasSession / AdminTo | Credential exposure from privileged logons on lower-tier hosts | Enforce tiering, PAWs, logon restrictions |
| AllowedToDelegate / AllowedToAct / unconstrained | Delegation abuse | Remove delegation, mark admins sensitive |
| GetChanges + GetChangesAll | DCSync | Only DCs/Entra Connect (scoped) |
| ADCSESC1…ESC13 | Certificate template/CA abuse | See `adcs-security-review` |
| GPLink / GenericWrite on GPO | Code execution on linked OUs | Restrict GPO edit rights |

## Cypher examples (BloodHound CE)

```cypher
// Shortest paths from any enabled user to Domain Admins
MATCH p=shortestPath((u:User {enabled:true})-[*1..]->(g:Group))
WHERE g.objectid ENDS WITH '-512'
RETURN p LIMIT 50

// Non-admin principals with DCSync rights on the domain
MATCH (n)-[:GetChanges|GetChangesAll|DCSync]->(d:Domain)
WHERE NOT (n)-[:MemberOf*1..]->(:Group {highvalue:true})
RETURN n.name, labels(n)
```
Property names (`highvalue`, tier tags) differ between legacy BloodHound and CE — adapt to your version.

## Prioritization

1. Count how many principals reach Tier 0 through each edge ("choke points"): fixing one ACE that cuts thousands of paths beats fixing many leaf issues.
2. Prefer structural fixes (tiering, delegated admin redesign) over one-off ACE removals that regrow.
3. Re-collect after remediation and compare path counts.

## Output

```
Attack path review <domain> <date>  Collection: <tool/version/time>
Principals with path to Tier 0: <n> (before) → <n> (after)
Top choke points: <edge> <source> → <target> <paths cut> <fix> <owner>
```

## Related skills

`ad-privileged-access-review`, `adcs-security-review`, `gpo-security-review`, `dcsync-detection`

## References

- BloodHound CE docs: https://bloodhound.specterops.io/
- Microsoft Enterprise access model: https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model
