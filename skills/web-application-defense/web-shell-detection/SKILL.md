---
name: web-shell-detection
description: Detect and remove web shells on IIS, Apache, Nginx/PHP-FPM, Tomcat and Exchange/SharePoint servers — file-based indicators (new script files in web roots, obfuscation), process indicators (web server spawning shells), network/log indicators — with YARA, file integrity baselines and EDR queries. Use after web application exploitation, when hunting on internet-facing servers, or following edge-application vulnerability advisories.
license: MIT
metadata:
  category: web-application-defense
  version: "2.0.0"
  verification: documented
---

# Web Shell Detection

## File-based hunting

```sh
# Recently modified script files in web roots (Linux)
find /var/www /usr/share/nginx /opt/tomcat/webapps -type f \( -name '*.php' -o -name '*.jsp' -o -name '*.jspx' -o -name '*.phtml' \) -mtime -14 -printf '%TY-%Tm-%Td %TH:%TM %u %p\n' | sort
# Suspicious functions in PHP files
grep -RIlE "(eval\(|assert\(|base64_decode\(|gzinflate\(|str_rot13\(|shell_exec\(|passthru\(|system\(|proc_open\(|preg_replace\(.*/e)" /var/www | head
```
```powershell
# IIS / Exchange: new .aspx/.ashx in the last 14 days
Get-ChildItem -Path C:\inetpub\wwwroot, "C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy" -Recurse -Include *.aspx,*.ashx,*.asmx -ErrorAction SilentlyContinue |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-14) } | Select-Object FullName, LastWriteTime, Length
```
Compare against deployment artefacts or a known-good baseline (hash list from the build); any file not from deployment is suspect. Scan web roots with YARA web-shell rules (e.g., Neo23x0 signature-base) — `yara -r rules/gen_webshells.yar /var/www`.

## Process and network indicators

- Web server process (`w3wp.exe`, `httpd`, `apache2`, `nginx`/`php-fpm`, `java` for Tomcat) spawning `cmd.exe`, `powershell.exe`, `sh`, `bash`, `whoami`, `net.exe`, `certutil`.
  ```kusto
  DeviceProcessEvents
  | where InitiatingProcessFileName in~ ("w3wp.exe", "httpd.exe", "tomcat9.exe", "php-cgi.exe", "java.exe")
  | where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "whoami.exe", "net.exe", "certutil.exe", "rundll32.exe")
  | project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
  ```
- Logs: POST requests to rarely-accessed script files, single-client access patterns, odd user agents (`web-server-log-analysis`).

## Response

Preserve the file (hash, copy, timestamps) and logs; identify the entry vulnerability (upload flaw, unpatched CVE); search all servers in the farm; remove shells, patch, rotate credentials accessible from the server (app pool identities, config connection strings, machine keys for ASP.NET ViewState); monitor for re-entry.

## Related skills

`web-server-log-analysis`, `yara-authoring`, `process-tree-analysis`, `linux-incident-triage`

## References

- NSA/ASD "Detect and Prevent Web Shell Malware": https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF
- MITRE ATT&CK T1505.003 Web Shell: https://attack.mitre.org/techniques/T1505/003/
- Neo23x0 signature-base: https://github.com/Neo23x0/signature-base
