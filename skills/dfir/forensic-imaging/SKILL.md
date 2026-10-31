---
name: forensic-imaging
description: Acquire forensically sound disk, memory and cloud-volume images using order of volatility — WinPmem/AVML/LiME for RAM, ewfacquire/dc3dd/FTK Imager for disks, provider snapshots for cloud. Use when evidence must be collected from a live or powered-off system, VM or cloud instance.
license: MIT
metadata:
  category: dfir
  version: "2.0.0"
  verification: documented
---

# Forensic Imaging

## Order of volatility (RFC 3227)

CPU/cache → **memory** → network state/process table → temp files → **disk** → remote logs → backups/archives. Capture memory before anything that changes state (reboot, isolation that drops connections is acceptable — EDR isolation preserves the process state).

## Memory acquisition

| Platform | Tool | Example |
|---|---|---|
| Windows | WinPmem | `winpmem_mini_x64.exe C:\out\host.raw` (write to external/remote storage, not the suspect disk) |
| Windows | Magnet DumpIt / RAM Capture | GUI/CLI per vendor docs |
| Linux | AVML (Microsoft) | `sudo ./avml /mnt/usb/host.lime` |
| Linux | LiME | `sudo insmod lime-$(uname -r).ko "path=/mnt/usb/host.lime format=lime"` (module must match kernel) |
| macOS | Requires commercial tools on Apple silicon; collect unified logs and artefacts instead if not available |
| VMs | Hypervisor snapshot with memory (VMware `.vmem`/`.vmsn`, Hyper-V `.bin/.vsv`) — least intrusive |

Record tool hash, host time vs. reference time (clock skew), and the output hash.

## Disk acquisition

- Physical, powered-off: hardware write blocker, then `ewfacquire /dev/sdX` (E01 with embedded hashes) or `dc3dd if=/dev/sdX of=disk.dd hash=sha256 log=disk.log`.
- Plain dd fallback: `dd if=/dev/sdX of=disk.dd bs=4M conv=noerror,sync status=progress` then hash both source and image.
- Live system (encrypted disk, cannot power off): logical acquisition of the unlocked volume (FTK Imager, or a triage collection with KAPE/Velociraptor) — document that it is live and why.
- BitLocker: record recovery key retrieval path (AD/Entra/Intune escrow) before powering off.

## Cloud volumes

- AWS: `aws ec2 create-snapshot --volume-id vol-... --description "CASE-001 evidence" --tag-specifications 'ResourceType=snapshot,Tags=[{Key=case,Value=CASE-001}]'`; share/copy to an isolated forensic account; create volume and attach read-only to a forensic instance.
- Azure: create snapshot of managed disk (`az snapshot create -g RG -n snap --source <diskId>`); grant SAS access for copy to forensic storage.
- GCP: `gcloud compute snapshots create snap --source-disk DISK --source-disk-zone ZONE`.
- Also capture instance metadata, security groups, attached roles, and console output.

## Verification

Hash the image after acquisition and again after transfer; record both in `evidence-intake`.

## Safety

Collection on production systems requires incident authorization. Never install tools onto the suspect disk if avoidable (run from external media/network share). Kernel modules (LiME) can crash a host — prefer AVML on modern kernels.

## Related skills

`evidence-intake`, `memory-forensics`, `velociraptor-collection`, `cloud-incident-response`

## References

- RFC 3227: https://www.rfc-editor.org/rfc/rfc3227
- AVML: https://github.com/microsoft/avml
- LiME: https://github.com/504ensicsLabs/LiME
- WinPmem: https://github.com/Velocidex/WinPmem
- libewf (ewfacquire/ewfverify): https://github.com/libyal/libewf
- AWS forensic snapshot guidance: https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/automate-incident-response-and-forensics.html
