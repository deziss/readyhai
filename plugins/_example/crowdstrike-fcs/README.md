# CrowdStrike Falcon (commercial integration template)

CrowdStrike offers **no OSS/community scanner image**; everything is tenant-gated.
Supported surfaces you can wire into ReadyHai today:

| Product | CLI / API | Output glue |
|---|---|---|
| Falcon Container Security (image scan) | `falcon-provision-tool container_scan_run` | JSON -> readyhai-json via `falcon2readyhai.sh` (included) |
| Falcon Next-Gen SAST (repo) | `falcon-sast` | JSON findings -> jq -> readyhai-json |
| Horizon CSPm (cloud posture) | Falcon Discover/KSPM API | nightly export -> readyhai-json |
| Falcon Sensor posture on SSH hosts | `psf`/API sensor status | add as `host.*` evidence in a wrapper script |

Setup:

1. Download the CLI from Falcon console → Support → Tools & Downloads (needs an
   API client with `container-scan:read` scope).
2. Build a private plugin image (never commit it to the repo):
   ```dockerfile
   FROM alpine:3.21
   RUN apk add --no-cache jq curl ca-certificates
   COPY falcon-provision-tool falcon2readyhai.sh /opt/falcon/
   ```
3. `cp -r crowdstrike-fcs ../crowdstrike-fcs`, set `image =` to your private image
   (digest-pinned), and pass credentials via a secrets file the wrapper reads —
   the plugin format has no env passthrough yet (plugins/README.md upgrade #2).
4. Keep it `profile = "deep"`: vendor scans are slow and billed per scan.

The Falcon **Prevent/Sensor agent itself** is not a scanner ReadyHai should
duplicate — instead a cheap `readyhai-json` wrapper that reports sensor presence
+ version (`psf version`) is a good `host.*`-style evidence check once env/host
plugins land.
