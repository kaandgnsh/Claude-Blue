---
name: dockerfile-hardening
description: Review and harden Dockerfiles and container build practice — minimal pinned base images, multi-stage builds, non-root USER, no secrets in layers (BuildKit secret mounts), least packages, HEALTHCHECK, read-only filesystems — with hadolint and image scanners. Use when writing or reviewing a Dockerfile, or when image scans show secrets, root users or bloated images.
license: MIT
metadata:
  category: container-security
  version: "2.0.0"
  verification: documented
---

# Dockerfile Hardening

## Example

```dockerfile
# syntax=docker/dockerfile:1
FROM golang:1.23@sha256:<digest> AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN --mount=type=secret,id=netrc,target=/root/.netrc CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app ./cmd/app

FROM gcr.io/distroless/static-debian12:nonroot@sha256:<digest>
COPY --from=build /out/app /app
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app"]
```
Build with the secret: `docker build --secret id=netrc,src=$HOME/.netrc -t app .` — the secret never lands in a layer.

## Checklist

- [ ] Base image minimal and pinned by digest; from an approved registry.
- [ ] Multi-stage: compilers/package managers not in the final image.
- [ ] `USER` non-root (numeric UID helps with `runAsNonRoot` policies).
- [ ] No secrets in `ENV`, `ARG`, `COPY`ed files, or earlier layers (deleting in a later layer doesn't remove them) — check with `docker history --no-trunc` and `trivy image --scanners secret`.
- [ ] `COPY` specific paths (with `.dockerignore` excluding `.git`, `.env`, keys) rather than `COPY . .` into the final stage.
- [ ] Package installs pinned/minimal with `--no-install-recommends`, caches cleaned in the same layer.
- [ ] No `curl | sh` from the internet without checksum verification.
- [ ] `HEALTHCHECK` (or orchestrator probes) defined.
- [ ] Runtime settings documented: read-only root FS, drop all capabilities, no privilege escalation (enforced in Kubernetes securityContext — `k8s-admission-control`).

## Lint

`hadolint Dockerfile` (rules like DL3006 tag the image, DL3008 pin apt versions, DL3002 last USER should not be root); `trivy config Dockerfile`; `checkov -f Dockerfile`.

## Related skills

`image-scanning`, `k8s-admission-control`, `secret-scanning`, `iac-scanning`

## References

- Docker build best practices: https://docs.docker.com/build/building/best-practices/
- BuildKit secret mounts: https://docs.docker.com/build/building/secrets/
- hadolint: https://github.com/hadolint/hadolint
- CIS Docker Benchmark: https://www.cisecurity.org/benchmark/docker
