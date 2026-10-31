---
name: endpoint-hardening
description: Assess and improve Windows and macOS workstation/server hardening — Microsoft/CIS baselines, Defender ASR rules, Credential Guard, LSA protection, SMB signing, local admin removal, BitLocker/FileVault, macro and script controls — and measure coverage. Use when building endpoint baselines, reviewing Intune/GPO security settings, or reducing ransomware attack surface.
license: MIT
metadata:
  category: endpoint-security
  version: "2.0.0"
  verification: documented
---

# Endpoint Hardening

## High-impact controls (Windows)

| Control | How | Verify |
|---|---|---|
| Remove standing local admin | Intune/GPO Restricted Groups; Windows LAPS for break-glass | `net localgroup administrators` |
| Defender ASR rules (block mode after audit) | Intune Endpoint security → ASR; key rules: block Office child processes, credential stealing from LSASS, executable content from email, obfuscated scripts, WMI persistence, PSExec/WMI process creation | `Get-MpPreference | Select AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions` |
| Tamper protection | Defender for Endpoint | `Get-MpComputerStatus | Select IsTamperProtected` |
| Credential Guard + LSA PPL | VBS policy, `RunAsPPL` | `msinfo32` (VBS services running); registry `Lsa\RunAsPPL` |
| Macros from internet blocked | Office policy "Block macros from running in Office files from the Internet" (default in M365 Apps) | Policy report |
| SMB signing / disable SMBv1 | GPO; `Set-SmbServerConfiguration -RequireSecuritySignature $true` | `Get-SmbServerConfiguration` |
| NTLM restrictions / LLMNR & NBT-NS off | GPO "Turn off multicast name resolution", NetBIOS over TCP/IP disabled | Responder-style poisoning risk |
| BitLocker | Intune disk encryption, keys escrowed | `manage-bde -status` |
| PowerShell | Script block logging, Constrained Language Mode with app control, remove v2 | `powershell-logging` |
| Application control | WDAC/AppLocker | `application-control` |

## macOS

FileVault on with escrowed keys, Gatekeeper/SIP enabled, automatic updates enforced via MDM (DDM software update), firewall + stealth mode, no admin rights for daily users, managed login items (BTM) via profiles.

## Workflow

1. Choose baseline (Microsoft Security Baselines for Windows/Edge/M365, CIS Level 1, Intune security baselines).
2. Export current configuration (Intune reports, `gpresult /h`, Policy Analyzer) and measure coverage per control across device groups.
3. Pilot changes in audit mode (ASR audit, WDAC audit) for 2–4 weeks; review events (ASR: Defender Operational 1121 block / 1122 audit).
4. Roll out in rings; track exceptions with expiry.
5. Report coverage % by control and residual risk.

## Output

`Control | Target | Coverage % | Gap devices | Exceptions | Plan | Owner`

## Related skills

`application-control`, `credential-theft-detection`, `gpo-security-review`, `mdm-compliance-review`

## References

- Microsoft Security Baselines: https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines
- ASR rules reference: https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference
- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks
- Australian ASD Essential Eight: https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight
