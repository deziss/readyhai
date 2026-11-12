# Deployment

## What runs where

ReadyHai does not host scanners. It runs as one small service (or as a CLI) and starts short-lived scanner containers through the Docker CLI. Anything with a Docker daemon (local, rootless, remote through `DOCKER_HOST`) works.

## Docker compose

`docker-compose.yml` defines three services, two networks and one volume. First run on a fresh clone: `cp .env.example .env` **and** `cp scope.example.toml scope.toml` (compose bind-mounts `scope.toml`; if it does not exist when you run `docker compose up`, Docker creates an empty directory of that name and `readyhai serve` refuses to start with a message that says how to fix it).

| Service | Image | Notes |
|---|---|---|
| `readyhai` | `ghcr.io/deziss/readyhai:latest` (override with `READYHAI_IMAGE`); `build: .` kept for local dev | Runs `readyhai serve --bind 0.0.0.0:8080` as uid 10001. Read-only rootfs, `/tmp` tmpfs, `cap_drop: ALL`, `no-new-privileges`, `mem_limit: 1g`, `init: true`, `stop_grace_period: 20s`. Published on `${READYHAI_PORT:-8080}:8080` (dual-stack host binding). Healthcheck `readyhai ping`; starts only once `socket-proxy` is healthy. `env_file: .env`. Networks `socket` and `edge`. |
| `frontend` | `ghcr.io/deziss/readyhai-frontend:latest` (override with `READYHAI_FRONTEND_IMAGE`); `build: ./frontend` kept for local dev | Production Next.js Agent Studio UI on port 3000. Multi-stage minimal standalone build, non-root user `readyhai` (UID 10001). Published on `${FRONTEND_PORT:-3000}:3000` (dual-stack host binding). Connects internally to `http://readyhai:8080` (`READYHAI_BACKEND_URL`); compose also passes it `READYHAI_TOKEN`, which its `/api/*` proxy attaches server-side, so the browser needs no pasted token (and anyone who reaches port 3000 gets the API: it is published on loopback only). Starts only once `readyhai` is healthy. Network `edge` only, so it cannot reach `socket-proxy`. `init: true`, `stop_grace_period: 10s`, `mem_limit: 512m`. |
| `socket-proxy` | `tecnativa/docker-socket-proxy:v0.5.0` (pinned; the docs used to say `v0.3.0`, which is published as `0.3.0`) | Mounts `/var/run/docker.sock` read-only; enables `CONTAINERS IMAGES POST VOLUMES INFO VERSION PING ALLOW_START ALLOW_STOP`; disables `EXEC BUILD SWARM SECRETS`. `mem_limit: 64m`. Healthcheck on `/_ping`. Network `socket` only. |

Networks: `socket` is `internal: true` (no route out) and holds only `readyhai` and `socket-proxy`; `edge` holds `readyhai` and `frontend` and carries the published host ports and readyhai's outbound traffic (scan targets, git clones). The frontend is on `edge` only, so a compromised UI container has no path to the Docker API.

Environment set by compose: `DOCKER_HOST=tcp://readyhai-socket-proxy:2375`, `READYHAI_DATA=/data`, `READYHAI_DATA_VOLUME=readyhai_data`, `READYHAI_ALLOWED_ROOTS=/targets`, `READYHAI_SCOPE=/config/scope.toml`; everything else (`READYHAI_TOKEN`, `READYHAI_PRINCIPAL`, `READYHAI_LLM_URL` (the old `READYHAI_VLLM_URL` still works), `READYHAI_LLM_*` including `READYHAI_LLM_API_KEY`, the `READYHAI_AGENT_*` budget, `READYHAI_VERIFY_K`, `READYHAI_AGENT_WORKERS`, `READYHAI_MCP_*`) comes from `.env` through `env_file`. Agent runs, memory and baselines live in the `readyhai_data` volume. To test an app on the same machine, list `host.docker.internal` in `scope.toml` (the shipped template does) and point the agent at `http://host.docker.internal:<port>`. Volumes: named volume `readyhai_data` at `/data`; `${TARGETS_DIR:-./targets}` at `/targets` read-only; `${SCOPE_FILE:-./scope.toml}` at `/config/scope.toml` read-only.

Shutdown: `docker stop` sends SIGTERM; readyhai drains connections for at most 8 s, removes the scanner containers of the run in flight and exits. The 20 s `stop_grace_period` leaves room for that (the Docker default of 10 s would not); `init: true` gives it a real PID 1. With plain `docker run` use `--init` and `docker stop -t 20`.

```bash
cp .env.example .env            # set READYHAI_TOKEN (16+ chars); never commit .env
cp scope.example.toml scope.toml  # rules of engagement; must exist BEFORE `up` (it is bind-mounted)
docker compose pull                                   # published images from GHCR
# local dev instead: docker compose build   (heavy; not done on the author's laptop)
docker compose up -d
curl http://127.0.0.1:8080/health
```

Compose passes `READYHAI_SCOPE=/config/scope.toml` and mounts your `./scope.toml` there (override the source with `SCOPE_FILE`). It does not pass `READYHAI_PLUGINS`; add it to `.env` (and mount the directory) to use plugins. `readyhai serve` validates the scope file at startup: a missing file, a directory or invalid TOML stops the server with a message instead of running unscoped. The policy: a public host needs no entry and gets full testing; an internal host (loopback, RFC1918, metadata, `host.docker.internal`) must be listed or matched by the `*` entry shipped in `scope.example.toml`; mark a host `env = "prod"` to keep it read-only. See [configuration.md](configuration.md#scopetoml).

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

The runtime image (`debian:bookworm-slim` + `ca-certificates` + `git` + `openssh-client` + `curl` + the `docker` CLI) contains `ssh`, so `ssh://` host scans work from the container when a key or agent is available; it does **not** contain `adb`, so `android.runtime` is skipped there. Use the CLI on a workstation for Android runtime checks, or extend the image. The `eval` command needs `python3`, which the image does not have: run it from a checkout or in CI. MobSF, Grype, Semgrep etc. are not in the image; they are separate containers pulled on demand.

## Published images

Tagged releases (`v*`) publish multi-arch (amd64, arm64) images via `.github/workflows/image.yml`, each with an SBOM and SLSA build provenance attestation. Publishing happens only when the tag equals `v<VERSION>` (the `VERSION` file) **and** the full CI workflow (fmt, clippy, tests, frontend, Python) has passed in the same run. Pull requests build all three images without pushing (`ci.yml`, job `docker`). The image workflow calls the same `ci.yml` (`workflow_call`) and `needs` it, so nothing is published unless fmt, clippy, tests, eval, frontend and Python jobs passed.

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
| `readyhai/playwright-runner:local` | `docker build -t readyhai/playwright-runner:local runners/playwright` (base `mcr.microsoft.com/playwright:v1.56.0-noble` pinned by digest, UID 1000) | `qa.ui`, `tool.playwright`, PDF. If neither this nor `READYHAI_PLAYWRIGHT_IMAGE` is present the published `ghcr.io/deziss/readyhai-playwright-runner:latest` is used; without Docker the check is `skipped` with a hint. |

The runner image resolves in this order: `READYHAI_PLAYWRIGHT_IMAGE`, the local tag above, then `ghcr.io/deziss/readyhai-playwright-runner:latest`. Local image builds are left to the user: heavy builds are not run on the author's laptop.

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
