---
name: container-incident
description: Investigate and contain a compromised container — preserve the container filesystem and metadata (docker/crictl inspect, diff, export, checkpoint), analyze processes and network from the node, determine escape to host or cluster, and redeploy cleanly. Use when a running container is suspected compromised (web shell, miner, reverse shell) on Docker, containerd or Kubernetes nodes.
license: MIT
metadata:
  category: container-security
  version: "2.0.0"
  verification: documented
---

# Container Incident Response

Containers are ephemeral: if the pod restarts or scales down, evidence disappears. Preserve before you kill.

## Preserve (from the node)

```sh
# Docker
docker inspect <cid> > inspect.json
docker diff <cid> > diff.txt                       # A/C/D changes vs. image — fast IOC source
docker export <cid> -o container-fs.tar            # filesystem snapshot
docker logs --timestamps <cid> > logs.txt
docker top <cid> -eo pid,ppid,user,args
# containerd / CRI-O (Kubernetes nodes)
crictl inspect <cid> > inspect.json ; crictl logs <cid> > logs.txt
PID=$(crictl inspect --output go-template --template '{{.info.pid}}' <cid>)
nsenter -t $PID -n ss -tupan                       # network namespace sockets
ls -l /proc/$PID/root/tmp /proc/$PID/root/dev/shm  # container FS via host /proc
# Kubernetes: checkpoint (where kubelet checkpoint API is enabled) or snapshot the node volume
```
Also capture: pod spec (`kubectl get pod <p> -o yaml`), service account and its RBAC, node name, image digest, events.

## Contain

- Kubernetes: isolate with a deny-all NetworkPolicy selecting the pod label (`k8s-network-policy`); cordon the node if escape suspected; remove the pod from Service endpoints by relabeling instead of deleting (keeps it running for analysis).
- Revoke the pod's service account token and any cloud credentials (IRSA/Workload Identity) it could use.

## Escape assessment

Privileged container, `hostPID`/`hostNetwork`, hostPath mounts (`/`, `/var/run/docker.sock`, `/var/lib/kubelet`), capabilities (`SYS_ADMIN`, `SYS_PTRACE`), kernel exploits — if any were present, treat the **node** as compromised and pivot to `k8s-incident-response` and node forensics.

## Eradicate

Fix the entry point (vulnerable app, exposed dashboard, leaked credentials), rebuild image from clean source, redeploy by digest, rotate secrets mounted in the pod, and replace (not clean) compromised nodes.

## Related skills

`runtime-detection-falco`, `k8s-incident-response`, `k8s-network-policy`, `linux-incident-triage`

## References

- Kubernetes forensic container checkpointing: https://kubernetes.io/blog/2022/12/05/forensic-container-checkpointing-alpha/
- crictl: https://github.com/kubernetes-sigs/cri-tools/blob/master/docs/crictl.md
- NIST SP 800-190: https://csrc.nist.gov/pubs/sp/800/190/final
