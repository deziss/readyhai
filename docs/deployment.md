# Deployment

## What runs where

ReadyHai does not host scanners. It runs as one small service (or as a CLI) and starts short-lived scanner containers through the Docker CLI. Anything with a Docker daemon (local, rootless, remote through `DOCKER_HOST`) works.

## Docker compose

`docker-compose.yml` defines two services and one volume.

| Service | Image | Notes |
|---|---|---|
| `readyhai` | `ghcr.io/deziss/readyhai:latest` (override with `READYHAI_IMAGE`); `build: .` kept for local dev | Runs `readyhai serve --bind 0.0.0.0:8080` as uid 10001. Read-only rootfs, `/tmp` tmpfs, `cap_drop: ALL`, `no-new-privileges`, `mem_limit: 1g`. Published on `127.0.0.1:${READYHAI_PORT:-8080}` only. Healthcheck `readyhai ping`. `env_file: .env`. |
| `frontend` | `ghcr.io/deziss/readyhai-frontend:latest` (override with `READYHAI_FRONTEND_IMAGE`); `build: ./frontend` kept for local dev | Production Next.js Agent Studio UI on port 3000. Multi-stage minimal standalone build, non-root user `readyhai` (UID 10001). Published on `127.0.0.1:${FRONTEND_PORT:-3000}`. Connects internally to `http://readyhai:8080`. |
| `socket-proxy` | `tecnativa/docker-socket-proxy:v0.3.0` | Mounts `/var/run/docker.sock` read-only; enables `CONTAINERS IMAGES POST VOLUMES INFO VERSION PING ALLOW_START ALLOW_STOP`; disables `EXEC BUILD SWARM SECRETS`. `mem_limit: 64m`. |

Environment set by compose: `DOCKER_HOST=tcp://readyhai-socket-proxy:2375`, `READYHAI_DATA=/data`, `READYHAI_DATA_VOLUME=readyhai_data`, `READYHAI_ALLOWED_ROOTS=/targets`. Volumes: named volume `readyhai_data` at `/data`; `${TARGETS_DIR:-./targets}` at `/targets` read-only.

```bash
cp .env.example .env            # set READYHAI_TOKEN (16+ chars); never commit .env
docker compose pull                                   # published images from GHCR
# local dev instead: docker compose build   (heavy; not done on the author's laptop)
docker compose up -d
curl http://127.0.0.1:8080/health
```

Compose does not pass `READYHAI_SCOPE` or `READYHAI_PLUGINS`; add them to `.env` (and mount the files) to scan web targets through the API. Without a scope file, public web targets still work read-only and internal hosts are refused; list a host with `env = "nonprod"` for intrusive actions.

### Volume-subpath trick

The readyhai container and the scanner containers must share files, but the scanners are started by the *host* daemon, which cannot see paths inside the readyhai container. So the run directory lives in a named volume (`readyhai_data`) and each scanner mounts only its slice of it:

```
--mount type=volume,src=readyhai_data,dst=/src,volume-subpath=runs/<id>/src,readonly
--mount type=volume,src=readyhai_data,dst=/out,volume-subpath=runs/<id>/out
--mount type=volume,src=readyhai_data,dst=/cache,volume-subpath=cache[,readonly]
```

`volume-subpath` needs Docker 26 or newer (the author's host has 29.x; the image copies the `docker:29-cli` client). `READYHAI_DATA_VOLUME` must equal the volume's real name (`readyhai_data`; compose pins `name: readyhai_data`). Paths outside the data root are rejected. Without `READYHAI_DATA_VOLUME` the CLI uses plain bind mounts of the host paths.

### Socket-proxy caveat

The proxy filters Docker API paths, not request bodies. A caller that can reach it can create a privileged container mounting `/`. It is **not a security boundary**: whoever controls the readyhai API token or the network around the proxy effectively has root on the host. Recommended instead:

- Rootless Docker or Podman for the daemon ReadyHai talks to (set `DOCKER_HOST` to its socket and drop the proxy), or
- run the CLI directly on a build agent under a dedicated user and skip the server.

### Image limitations to know

The runtime image (`debian:bookworm-slim` + `ca-certificates` + `git` + `docker` CLI) does **not** contain `openssh-client` or `adb`. In the container, `ssh://` host scans and `android.runtime` fail or skip. Use the CLI on a workstation for those, or extend the image. MobSF, Grype, Semgrep etc. are not in the image; they are separate containers pulled on demand.

## Published images

Tagged releases (`v*`) publish multi-arch (amd64, arm64) images via `.github/workflows/image.yml`, each with an SBOM and SLSA build provenance attestation:

| Image | Source |
|---|---|
| `ghcr.io/deziss/readyhai` | root `Dockerfile` |
| `ghcr.io/deziss/readyhai-frontend` | `frontend/Dockerfile` |
| `ghcr.io/deziss/readyhai-playwright-runner` | `runners/playwright` |

Tags: `X.Y.Z`, `X.Y`, and `sha-<commit>`. Pin a version or digest in production. Verify an image before running it:

```bash
gh attestation verify oci://ghcr.io/deziss/readyhai:X.Y.Z --repo deziss/readyhai
```

## Images you can build locally

| Image | Build | Why |
|---|---|---|
| `readyhai:local` | `docker build -t readyhai:local .` (multi-stage: `rust:1-slim-bookworm` build with `--locked`, then runtime image) | The service |
| `readyhai/playwright-runner:local` | `docker build -t readyhai/playwright-runner:local runners/playwright` (base `mcr.microsoft.com/playwright:v1.56.0-noble`, runs as `pwuser`) | `tool.playwright`. Not in any registry; until built the check is `skipped` with a build hint. The base is not digest-pinned yet (TODO in the Dockerfile). |

The published runner image is `ghcr.io/deziss/readyhai-playwright-runner`; the check looks for the local tag above, so `docker tag` the pulled image to that name. Both local builds are left to the user: heavy builds are not run on the author's laptop (the Playwright image was never built).

## tools pull and update

```bash
readyhai tools pull --lock tools.lock.toml   # docker pull each scanner image, write sha256 digests
export READYHAI_TOOLS_LOCK=$PWD/tools.lock.toml
readyhai tools update                         # grype DB, semgrep rules, Lynis tarball into <data>/cache
```

In compose, run them inside the service: `docker compose exec readyhai readyhai tools update` (needs the network from that container). `tools update` runs grype in a network-enabled container with the cache mounted read-write; it is the only networked step. Re-run `update` regularly: a grype DB older than 7 days makes `tool.sbom_cve` `partial`.

## Offline / air-gapped

1. On a connected machine: `readyhai tools pull --lock tools.lock.toml`, `readyhai tools update`.
2. Move images: `docker save $(images from the lock) | gzip > images.tgz`; move `<data>/cache/` (grype DB, `semgrep/default.yml`, `lynis/lynis.tar.gz`).
3. On the offline host: `docker load < images.tgz`, copy the cache into `<data>/cache/`, set `READYHAI_TOOLS_LOCK`.
4. Scans never need the network except web targets, `tool.playwright`, ZAP and Schemathesis (which talk to the target), and `git:` clones. Static scans run with `--network none`.

## Resource sizing

| Resource | Guideline |
|---|---|
| readyhai service | 1 GB RAM limit is enough (it only orchestrates) |
| Per scanner | default 2 GB RAM, 2 CPUs, 512 pids; semgrep 3 GB; MobSF 2 GB |
| Concurrency | One scan at a time per process (CLI is sequential; the server has one worker) |
| Disk | Scanner images about 8 to 10 GB; grype DB about 1 GB in cache; each run keeps its snapshot, `image.tar` (image scans) and outputs under `runs/<id>/` until deleted |
| Time limits | Per check: scanners 300 to 900 s, own tests 900 s (configurable), ZAP 900 s, Playwright 600 s, SSH probe 120 s, Lynis 600 s |

There is no automatic cleanup of `runs/`; prune old directories yourself.
