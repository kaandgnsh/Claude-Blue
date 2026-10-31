---
name: pcap-analysis
description: Analyze packet captures with tshark/Wireshark — conversation and protocol summaries, DNS/HTTP/TLS extraction (SNI, JA3/JA4), object export, stream reconstruction and time slicing — to identify C2, exfiltration, exploitation and malware downloads. Use when a PCAP is available from an incident, sandbox, IDS or network tap.
license: MIT
metadata:
  category: network-security
  version: "2.0.0"
  verification: tested
---

# PCAP Analysis (tshark)

Commands below were verified against TShark 4.7 with the repository fixture `tests/fixtures/http_dns.pcap`.

## First look

```sh
capinfos capture.pcap                                  # duration, packets, time range
tshark -r capture.pcap -q -z io,phs                    # protocol hierarchy
tshark -r capture.pcap -q -z conv,tcp                  # TCP conversations (bytes, duration)
tshark -r capture.pcap -q -z endpoints,ip              # top talkers
```

## Extract indicators

```sh
# DNS queries with time and client
tshark -r capture.pcap -Y dns.flags.response==0 -T fields -e frame.time_epoch -e ip.src -e dns.qry.name -e dns.qry.type
# HTTP requests
tshark -r capture.pcap -Y http.request -T fields -e ip.src -e http.host -e http.request.method -e http.request.uri -e http.user_agent
# TLS Client Hello: SNI and fingerprints
tshark -r capture.pcap -Y 'tls.handshake.type == 1' -T fields -e ip.src -e ip.dst -e tls.handshake.extensions_server_name -e tls.handshake.ja3 -e tls.handshake.ja4
# Certificates presented by servers
tshark -r capture.pcap -Y 'tls.handshake.type == 11' -T fields -e ip.src -e x509sat.printableString -e x509ce.dNSName
# Export transferred files
mkdir -p objects && tshark -r capture.pcap -q --export-objects http,objects   # also smb, tftp, imf, dicom
# Follow a TCP stream as ASCII
tshark -r capture.pcap -q -z follow,tcp,ascii,0
```
Slice large captures: `editcap -A "2025-03-01 10:00:00" -B "2025-03-01 11:00:00" big.pcap slice.pcap`; filter to a host: `tshark -r big.pcap -Y 'ip.addr==10.0.0.5' -w host.pcap`.

## What to look for

| Pattern | Indicator |
|---|---|
| Malware download | HTTP GET of `.exe/.dll/.ps1/.hta/.zip` from raw IP or new domain; `Content-Type` mismatching file magic |
| C2 | Regular intervals (`beaconing-hunt`), odd/outdated user agents, POSTs to `.php` gates, self-signed certs, JA3/JA4 matching known tooling |
| DNS tunnelling | Long, high-entropy subdomains, many TXT/NULL queries, high query volume to one domain |
| Exfiltration | Large outbound uploads, sessions to cloud storage/paste sites, FTP/SMTP from servers |
| Exploitation | Payloads in URIs/headers (`${jndi:`, `../`, `' OR 1=1`), followed by callbacks from the target |
| Cleartext credentials | HTTP Basic, FTP, Telnet, SMTP AUTH, LDAP simple binds |

## Safety

Exported objects may be live malware: hash them (`sha256sum objects/*`), store in a password-protected archive, never open on the analysis host. PCAPs often contain personal data and credentials — handle per data policy.

## Related skills

`zeek-log-analysis`, `suricata-alert-triage`, `beaconing-hunt`, `dns-threat-analysis`, `sample-intake`

## References

- TShark manual: https://www.wireshark.org/docs/man-pages/tshark.html
- Wireshark display filter reference: https://www.wireshark.org/docs/dfref/
- JA4+ fingerprints: https://github.com/FoxIO-LLC/ja4
- Malware-Traffic-Analysis.net exercises: https://www.malware-traffic-analysis.net/
