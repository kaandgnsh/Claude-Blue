---
name: zeek-log-analysis
description: Investigate and hunt with Zeek logs — conn, dns, http, ssl, x509, files, notice, smb, dce_rpc, kerberos — using zeek-cut, jq (JSON logs) or SIEM queries to find C2, lateral movement, exfiltration and anomalies. Use when Zeek/Corelight data is available or when processing a PCAP with Zeek.
license: MIT
metadata:
  category: network-security
  version: "2.0.0"
  verification: documented
---

# Zeek Log Analysis

## Generate logs from a PCAP

```sh
zeek -C -r capture.pcap LogAscii::use_json=T local   # -C ignores checksum errors; JSON output
```

## Key logs

| Log | Use |
|---|---|
| `conn.log` | Every connection: `uid`, `id.orig_h/p`, `id.resp_h/p`, `proto`, `service`, `duration`, `orig_bytes`, `resp_bytes`, `conn_state`, `history` |
| `dns.log` | `query`, `qtype_name`, `rcode_name`, `answers` |
| `http.log` | `host`, `uri`, `method`, `user_agent`, `status_code`, `resp_mime_types` |
| `ssl.log` / `x509.log` | `server_name` (SNI), `version`, `cipher`, `validation_status`, cert subject/issuer, `ja3` (with package) |
| `files.log` | Transferred files: `mime_type`, `md5/sha1/sha256`, `tx_hosts/rx_hosts` |
| `smb_files.log`, `smb_mapping.log`, `dce_rpc.log` | Lateral movement (ADMIN$/C$ mapping, `svcctl` CreateService, `drsuapi` DRSGetNCChanges) |
| `kerberos.log` | `request_type`, `client`, `service`, `cipher` (RC4 = `rc4-hmac`) |
| `notice.log`, `weird.log` | Zeek scripts' findings, protocol anomalies |

## Queries (TSV with zeek-cut, JSON with jq)

```sh
# Top talkers by bytes out
zeek-cut id.orig_h id.resp_h orig_bytes < conn.log | awk '{b[$1" "$2]+=$3} END{for(k in b) print b[k],k}' | sort -rn | head
# Long connections (> 1h)
zeek-cut uid id.orig_h id.resp_h id.resp_p duration < conn.log | awk '$5 > 3600' | sort -k5 -rn
# Rare user agents
zeek-cut user_agent < http.log | sort | uniq -c | sort -n | head -20
# Self-signed / invalid certs (JSON logs)
jq -r 'select(.validation_status != null and .validation_status != "ok") | [.ts, ."id.orig_h", .server_name, .validation_status] | @tsv' ssl.log
# Executables transferred
jq -r 'select(.mime_type == "application/x-dosexec") | [.ts, .tx_hosts[0], .rx_hosts[0], .sha256] | @tsv' files.log
# Service creation over RPC (PsExec-like)
jq -r 'select(.endpoint == "svcctl" and (.operation | test("Create"))) | [.ts, ."id.orig_h", ."id.resp_h", .operation] | @tsv' dce_rpc.log
# DCSync
jq -r 'select(.endpoint == "drsuapi" and .operation == "DRSGetNCChanges") | [.ts, ."id.orig_h", ."id.resp_h"] | @tsv' dce_rpc.log
```
Pivot across logs with `uid` (conn ↔ http/ssl/files) and `fuid` (files).

## Interpretation tips

- `conn_state`: `S0` (no reply — scanning), `REJ` (rejected), `SF` (normal), `RSTO/RSTR`; `history` letters show handshake details.
- Internal-to-internal SMB/RPC from workstations to many hosts = lateral movement candidate.
- `orig_bytes` ≫ `resp_bytes` on long sessions to external hosts = possible exfiltration.

## Related skills

`pcap-analysis`, `beaconing-hunt`, `dcsync-detection`, `lateral-movement-detection`, `netflow-analysis`

## References

- Zeek log documentation: https://docs.zeek.org/en/master/logs/index.html
- Zeek scripting reference: https://docs.zeek.org/en/master/script-reference/index.html
- Corelight Zeek cheatsheets: https://github.com/corelight/bro-cheatsheets
