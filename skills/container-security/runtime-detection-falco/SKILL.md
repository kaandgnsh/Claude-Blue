---
name: runtime-detection-falco
description: Detect malicious behaviour in running containers and Kubernetes nodes with Falco (or Tetragon/Tracee) — shells in containers, unexpected processes, sensitive file reads, crypto-miner activity, container escape attempts — write and tune Falco rules, and route alerts. Use when deploying container runtime security, writing runtime detections, or triaging Falco alerts.
license: MIT
metadata:
  category: container-security
  version: "2.0.0"
  verification: documented
---

# Container Runtime Detection (Falco)

## Deploy

Helm: `helm install falco falcosecurity/falco -n falco --create-namespace --set driver.kind=modern_ebpf --set falcosidekick.enabled=true` (falcosidekick forwards to Slack/SIEM/webhooks). Confirm the driver loaded and events flow (`kubectl logs -n falco ds/falco`).

## Custom rule example

```yaml
- list: web_server_procs
  items: [nginx, httpd, apache2, node, java, php-fpm, gunicorn, uwsgi]

- rule: Shell Spawned by Web Server in Container
  desc: A web server process inside a container spawned an interactive shell or downloader (possible RCE / web shell).
  condition: >
    spawned_process and container and
    proc.pname in (web_server_procs) and
    proc.name in (sh, bash, dash, ash, zsh, curl, wget, nc, ncat, python, python3, perl)
  output: >
    Web server spawned %proc.name in container (cmd=%proc.cmdline parent=%proc.pname user=%user.name
    container=%container.name image=%container.image.repository:%container.image.tag k8s.ns=%k8s.ns.name k8s.pod=%k8s.pod.name)
  priority: WARNING
  tags: [container, mitre_execution, T1059]
```
Load as an additional rules file (`customRules` in Helm values); override default rules with `append`/`override` keys rather than editing upstream files.

## High-value default rules

Terminal shell in container, read sensitive file untrusted (`/etc/shadow`), write below binary dir, contact K8s API server from container, launch privileged container, mount of host filesystem, unexpected outbound connection to mining pools, `ptrace` attach, kernel module load from container, drift detection (executing binaries not in the image — `Drop and execute new binary in container`).

## Tuning

Exceptions by **image repository + process + args** (rule `exceptions:` field), not by namespace wholesale; separate CI/build namespaces (shells are normal) from production.

## Triage

Map alert → pod/image/deployment owner; check image provenance (`artifact-signing`); inspect process tree and network; if malicious, follow `container-incident`.

## Related skills

`container-incident`, `k8s-audit-log-analysis`, `k8s-incident-response`, `image-scanning`

## References

- Falco documentation: https://falco.org/docs/
- Falco rules reference (fields, macros): https://falco.org/docs/reference/rules/
- Cilium Tetragon: https://tetragon.io/docs/
