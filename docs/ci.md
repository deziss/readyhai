# CI integration

Recipes live in `ci/`. All run `readyhai scan` and gate on its exit code: `0` PASS, `1` WARN, `2` FAIL, `3` tool error. To gate a deployment on the agent instead, run `readyhai agent <url> --spec <spec-url> [--repo . --diff-base origin/main]`: `0` GO, `1` CONDITIONAL_GO, `2` NO_GO or not evaluated, `3` error; the target must be reachable from the runner and any internal host listed in `scope.toml`. In every recipe the readyhai binary (and Docker, for container scanners) must be available on the runner; see the placeholders called out below.

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
- Requires `readyhai` on the agent PATH. Add `--baseline .readyhai/baseline.json` to gate only on new findings. A `readyhai scan` step (without `--no-tools`) also satisfies the `readiness.ci.no_sast/no_secret_scan/no_dep_scan` rules; the bare word "readyhai" alone does not.

## Pull-request bot

`--format pr` writes `readyhai-pr-comment.md`: a compact Markdown summary (verdict, reasons, per-category counts, top 15 open findings) that starts with the hidden marker `<!-- readyhai-pr-comment -->`. The GitHub Action and the GitLab recipe use that marker to keep **one** comment per PR/MR and edit it on every push instead of adding a new one. All finding text is escaped, so nothing from the scanned code becomes links, markup or @mentions. Nothing needs to be installed on developer machines: the gate runs in CI and reports back on the PR.

## GitHub Actions (`action.yml`, `ci/github-action.yml`)

The repo root is a composite action, so a workflow only needs:

```yaml
permissions: { contents: read, pull-requests: write, security-events: write }
steps:
  - uses: actions/checkout@v4
  - uses: deziss/readyhai@v0.6.0
    with:
      profile: quick      # quick | standard | deep
      fail-on: fail       # fail | warn | never
      # no-tools: "true"  # native checks only, no Docker
```

Inputs: `target` (default `.`), `profile`, `version` (release tag or `latest`), `no-tools`, `comment` (default `true`), `fail-on`, `out` (default `readyhai-report`), `github-token`. Outputs: `verdict`, `exit-code`, `report-dir`.

What it does:
1. Downloads `readyhai-linux-x86_64.tar.gz` from the release and checks it against the published `.sha256`.
2. `readyhai tools update` unless `no-tools` (hosted runners have Docker).
3. `readyhai scan --format sarif,html,json,junit,pr`; the summary is also appended to the job summary page.
4. On pull requests, creates or updates the single ReadyHai comment through `gh api`. Fork PRs get a read-only token, so the comment step is `continue-on-error`.
5. Gate: fails on exit `>= 2` (or no exit code); with `fail-on: warn` also on `1`; `never` only reports.

`ci/github-action.yml` is a complete workflow using the action plus SARIF upload (`github/codeql-action/upload-sarif@v3`, needs code scanning on private repos) and the report artifact.

## GitLab CI (`ci/gitlab-ci.yml`)

Job `readyhai` in stage `test`, image `ghcr.io/deziss/readyhai:latest` (pin a version tag or digest in production) with `entrypoint: [""]` (the image's entrypoint is `readyhai`). Artifacts always include `readyhai-report/` and the JUnit report (`reports: junit`). `allow_failure: exit_codes: [1]` makes WARN non-blocking.

On merge requests the job also writes `--format pr` and posts or updates one MR note (found by the `<!-- readyhai-pr-comment -->` marker) through the GitLab API. Set a masked CI/CD variable `READYHAI_GITLAB_TOKEN` (project access token, scope `api`, Reporter or higher); without it the note is skipped and the job still gates. The image ships `curl` and `jq` for this.

Caveats: the job needs Docker to run scanners (docker-in-docker or a runner with the host socket) and `adb` is not in the image. Without Docker only native rules run: every container check is `skipped("docker not available")`, which is visible but not failing.

## ArgoCD PostSync hook (`ci/argocd-postsync-job.yaml`)

A `ConfigMap` (`readyhai-scope`, holding `scope.toml` and the target host) plus a `Job` with annotations `argocd.argoproj.io/hook: PostSync` and `hook-delete-policy: HookSucceeded`. It runs `readyhai scan https://$(TARGET_HOST) --profile standard --scope /config/scope.toml --format json,html --out /tmp/report` as uid 10001 with a read-only root filesystem, dropped capabilities, 900 s deadline and no retries (`backoffLimit: 0`).

What it can do in-cluster: there is no Docker, so only `web.smoke` runs; Schemathesis, ZAP and Playwright are `skipped`. A failing verdict fails the Job, which marks the sync failed.

Known problems (the manifest has not been run on a cluster):
- `/data` (the image's `READYHAI_DATA`) is mounted as an `emptyDir`, so the run directory can be created under `readOnlyRootFilesystem: true`; nothing persists after the Job.
- `image: ghcr.io/deziss/readyhai:latest`: pin a release tag or digest instead of `latest`.
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

## Verifying release artifacts

Release tarballs and published images carry SLSA build provenance attestations. Verify before use:

```bash
# tarball (download it and its .sha256 from the GitHub release)
sha256sum -c readyhai-linux-x86_64.tar.gz.sha256
gh attestation verify readyhai-linux-x86_64.tar.gz --repo deziss/readyhai

# container image
gh attestation verify oci://ghcr.io/deziss/readyhai:X.Y.Z --repo deziss/readyhai
```

## ReadyHai's own workflows (`.github/workflows/`)

| Workflow | Runs | What |
|---|---|---|
| `ci.yml` | push and pull request to `main`/`master`; callable (`workflow_call`) | `test`: version sync (`scripts/version.sh check`), `cargo fmt -- --check`, `cargo clippy -- -D warnings`, `cargo test --verbose`, release build. `eval` (needs `test`, 20 min): `cargo run -- eval --suite all --k 2`, summary appended to the job summary, `eval-report` artifact. `frontend` (node 24): `npm ci`, lint, `tsc --noEmit`, `npm test`. `python`: context-retriever unit tests. `docker` (pull requests only): no-push builds of the backend, frontend and runner images |
| `image.yml` | `v*` tags | `verify` (the tag must equal `v<VERSION>`), `ci` (the whole `ci.yml`), then multi-arch GHCR images with SBOM and SLSA provenance; `needs: [verify, ci]` |
| `release.yml` | `v*` tags | tag must match `VERSION`; release tarball and `.sha256` with build provenance attestation; GitHub release |
| `scorecard.yml` | weekly | OpenSSF Scorecard with SARIF upload |

All actions are pinned by commit SHA. The `eval` job is the regression gate for detection quality: it fails when a threshold in `tests/eval/*.toml` is missed ([eval.md](eval.md)).
