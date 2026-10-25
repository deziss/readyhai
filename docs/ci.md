# CI integration

Recipes live in `ci/`. All run `readyhai scan` and gate on its exit code: `0` PASS, `1` WARN, `2` FAIL, `3` tool error. In every recipe the readyhai binary (and Docker, for container scanners) must be available on the runner; see the placeholders called out below.

## Common pattern

```bash
readyhai tools update                                   # vuln DB + rules (networked, once per runner or cached)
readyhai scan . --profile quick --format html,sarif,junit --out readyhai-report \
  --baseline .readyhai/baseline.json
echo $?                                                  # 0/1/2/3
```

Policy for each pipeline decides what WARN means: Jenkins marks the build unstable, GitHub Actions treats it as non-blocking, GitLab allows exit code 1.

## Jenkins (`ci/Jenkinsfile.stage`)

A declarative stage to paste into a pipeline. It replaces steps like `if command -v trivy; then trivy ... || true; fi`, which the `readiness.ci.scanner_optional` and `scanner_never_fails` rules flag.

- Runs `readyhai scan . --profile quick --format html,sarif,junit --out readyhai-report` with `returnStatus: true`.
- Exit 1: `unstable('ReadyHai: WARN findings')`. Exit 2 or 3: `error(...)` fails the build.
- `post { always }` archives `readyhai-report/**` and publishes `readyhai-report.junit.xml` through the JUnit plugin.
- Requires `readyhai` on the agent PATH. Add `--baseline .readyhai/baseline.json` to gate only on new findings. Because the stage text contains "readyhai", it also satisfies the `readiness.ci.no_sast/no_secret_scan/no_dep_scan` rules for itself.

## GitHub Actions (`ci/github-action.yml`)

Workflow `readyhai` on push and pull request, `permissions: contents read, security-events write`.

1. `actions/checkout@v4`.
2. Install: `curl -sSfL <release-url> | sudo tar xz -C /usr/local/bin`. **`<release-url>` is a TODO**: no release is published yet. Replace it with your tarball, or build from source.
3. `readyhai tools update` (needs Docker, which hosted runners have).
4. Scan with `set +e`, capture the exit code into `steps.scan.outputs.code`.
5. `github/codeql-action/upload-sarif@v3` with `readyhai-report/readyhai-report.sarif` (`if: always()`); results appear under Code scanning, with `partialFingerprints["readyhai/v1"]` for dedup.
6. `actions/upload-artifact@v4` for the HTML report.
7. Gate step: fails if the code is empty (scan never ran) or `>= 2`. WARN (1) passes.

Note: SARIF upload to private repos requires GitHub code scanning (Advanced Security) to be enabled. Pull requests from forks get a read-only token and cannot upload SARIF. Tool images are pulled by tag unless you commit a lock file and set `READYHAI_TOOLS_LOCK`.

## GitLab CI (`ci/gitlab-ci.yml`)

Job `readyhai` in stage `test`, image `readyhai:local` with `entrypoint: [""]` (the image's entrypoint is `readyhai`). **The image path is a TODO** until you publish the image to a registry. Artifacts always include `readyhai-report/` and the JUnit report (`reports: junit`). `allow_failure: exit_codes: [1]` makes WARN non-blocking.

Caveats: the job needs Docker to run scanners (docker-in-docker or a runner with the host socket) and `ssh`/`adb` are not in the image. Without Docker only native rules run: every container check is `skipped("docker not available")`, which is visible but not failing.

## ArgoCD PostSync hook (`ci/argocd-postsync-job.yaml`)

A `ConfigMap` (`readyhai-scope`, holding `scope.toml` and the target host) plus a `Job` with annotations `argocd.argoproj.io/hook: PostSync` and `hook-delete-policy: HookSucceeded`. It runs `readyhai scan https://$(TARGET_HOST) --profile standard --scope /config/scope.toml --format json,html --out /tmp/report` as uid 10001 with a read-only root filesystem, dropped capabilities, 900 s deadline and no retries (`backoffLimit: 0`).

What it can do in-cluster: there is no Docker, so only `web.smoke` runs; Schemathesis, ZAP and Playwright are `skipped`. A failing verdict fails the Job, which marks the sync failed.

Known problems (the manifest has not been run on a cluster):
- The image sets `READYHAI_DATA=/data` but the Job mounts only `/tmp` as writable and `/data` is not mounted, so with `readOnlyRootFilesystem: true` the run directory cannot be created. Add `READYHAI_DATA: /tmp/data` (or mount an `emptyDir` at `/data`).
- `image: readyhai:local` is a placeholder for a registry image.
- The HTML/JSON report is written to the pod's `/tmp` and deleted with the pod (`HookSucceeded`); on failure the pod remains for `kubectl cp`/logs only.
- Hook policy: use `HookFailed` retention or ship the report elsewhere if you need it after success.

## SARIF upload

`--format sarif` writes `readyhai-report.sarif` (SARIF 2.1.0). Levels: critical/high `error`, medium `warning`, low/info `note`. `partialFingerprints.readyhai/v1` carries the finding fingerprint. Suppressed findings include `suppressions: [{kind: external, justification}]`. Locations are repo-relative paths with line when known; URLs for web findings.

## Carrying the baseline

CI agents lose local state, so keep the baseline in the repo:

```bash
readyhai scan .                                              # on a clean main branch
readyhai baseline accept <run-id> --out .readyhai/baseline.json
git add .readyhai/baseline.json && git commit -m "readyhai baseline"
# pipelines:
readyhai scan . --baseline .readyhai/baseline.json
```

- Refresh the baseline deliberately (a human accepting debt), not automatically; a baseline that auto-updates hides regressions.
- `.readyhai/` is excluded from the snapshot, so the file is not scanned.
- If the file does not exist, ReadyHai prints a note and treats everything as new.
- Suppressions with expiry go in `readyhai.toml`, not in the baseline.

## Exit codes in pipelines

| Code | Meaning | Typical handling |
|---|---|---|
| 0 | PASS | continue |
| 1 | WARN | mark unstable / non-blocking |
| 2 | FAIL | block |
| 3 | Tool error (not a verdict) | block and investigate; for an `errored` check the run still exits 1 or 2 |
