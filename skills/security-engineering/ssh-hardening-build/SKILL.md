---
name: ssh-hardening-build
description: Build and deploy a hardened OpenSSH server configuration — key/certificate-only authentication, AllowGroups, no root login, forwarding disabled, modern and post-quantum hybrid KEX (mlkem768x25519) intersected with the local OpenSSH version — as a drop-in generated from a JSON policy, verified with sshd -t/-T and a live client test that proves weak methods are refused. Use when hardening SSH on Linux servers, fixing SSH audit/CIS findings, or rolling out SSH certificates.
license: MIT
metadata:
  category: security-engineering
  version: "2.1.0"
  verification: tested
---

# SSH Hardening Build

Follows `secure-build-workflow`.

## 1. Requirements

- Who must log in: which **groups**, from where, and how (keys, FIDO2 `sk-` keys, SSH certificates from a CA)? Every allowed user must have a working key **before** passwords are disabled.
- Is forwarding or agent forwarding needed (jump hosts, Git over SSH)? Default is no.
- OpenSSH version on targets (`ssh -V`), automation accounts (Ansible, backup), and console/break-glass access.
- Firewall: restrict the SSH port to admin networks as well (`host-firewall-build`).

## 2. Generate

```sh
python3 scripts/sshd_harden.py --example > ssh-policy.json        # edit allow_groups etc.
python3 scripts/sshd_harden.py ssh-policy.json -o 00-cb-hardening.conf
```
- The generator refuses an empty or invalid `allow_groups` (lockout protection), unknown keys, relative paths and invalid ports.
- Crypto lists are intersected with `ssh -Q kex|cipher|mac|key-sig` on the machine running the generator. Run it on (or for) the target's OpenSSH version, or pass `--no-detect` to get the full preferred list.
- Settings produced:
  - **Authentication:** `PermitRootLogin no`, `AuthenticationMethods publickey`, password and keyboard-interactive auth off, `MaxAuthTries 3`, `LoginGraceTime 30`, `MaxStartups 10:30:60`, `AllowGroups`, optional `TrustedUserCAKeys`.
  - **Pivot features:** TCP, agent and stream-local forwarding off; X11, tunnels and `GatewayPorts` off; `PermitUserEnvironment no`.
  - **Logging and sessions:** `LogLevel VERBOSE` (logs key fingerprints), client alive timeouts.
  - **Crypto:** the ML-KEM/sntrup hybrid post-quantum KEX first, then curve25519; ChaCha20/AES-GCM/AES-CTR; ETM MACs only; Ed25519 and RSA-SHA2 signatures only.
- sshd keeps the **first** value it reads for most keywords. Install the file as `/etc/ssh/sshd_config.d/00-cb-hardening.conf` and confirm the main `sshd_config` includes `sshd_config.d/*.conf` **at its top** (the default on current Debian, Ubuntu, Fedora and Arch). Then check the main file for conflicting earlier lines.

## 3. Validate and test

```sh
sudo sshd -t                                                         # syntax with the real config
sudo sshd -T -C user=alice,host=admin-pc,addr=10.20.0.5 | grep -E '^(passwordauthentication|permitrootlogin|authenticationmethods|allowgroups|kexalgorithms) '
./scripts/live_test.sh 00-cb-hardening.conf                          # unprivileged throwaway sshd on 127.0.0.1
```
`live_test.sh` starts a temporary sshd as your user, with no root and no change to the system sshd. It passes only if:
- key login works for an allowed user;
- the server offers **only** publickey (read from the offered methods, not inferred from a failed login);
- `aes128-cbc`, `diffie-hellman-group14-sha1` and `hmac-sha1` are refused;
- remote forwarding is refused when disabled.

It also prints the negotiated KEX. A deliberately weak config fails it, as tested in the repository's test suite.

## 4. Roll out

1. Keep an existing root/admin session open; have console access.
2. Distribute keys (or the CA) first; verify `ssh -o PreferredAuthentications=publickey user@host` works for each group.
3. Install the drop-in, run `sshd -t`, then `systemctl reload sshd` (reload keeps current sessions).
4. Test from a **new** session. Roll back by removing the drop-in and reloading.
5. Fleet: deploy with configuration management (`hardening-automation-build`) to a canary host first.

## 5. Operate

Alert on `Accepted publickey` from new source networks, on `Failed`/`Invalid user` bursts (`linux-log-analysis`) and on changes to `sshd_config*` (`auditd-rules`). Consider SSH certificates with short validity to replace sprawling `authorized_keys`. OpenSSH 9.8+ also applies `PerSourcePenalties` by default against repeated failures.

## Related skills

`secure-build-workflow`, `host-firewall-build`, `linux-hardening`, `linux-log-analysis`, `hardening-automation-build`

## References

- sshd_config(5): https://man.openbsd.org/sshd_config
- OpenSSH release notes (ML-KEM default in 10.0, PerSourcePenalties in 9.8): https://www.openssh.com/releasenotes.html
- Mozilla OpenSSH guidelines: https://infosec.mozilla.org/guidelines/openssh
- ssh-audit (external verification): https://github.com/jtesta/ssh-audit
