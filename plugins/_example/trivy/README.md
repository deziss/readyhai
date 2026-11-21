# trivy (example plugin)

Wraps Aqua Security's [Trivy](https://github.com/aquasecurity/trivy) (Apache-2.0).

```bash
cp -r ../_example/trivy ../trivy
# pin the digest of the tag you actually use:
docker pull aquasec/trivy:0.69.1
docker inspect --format='{{index .RepoDigests 0}}' aquasec/trivy:0.69.1
# -> aquasec/trivy@sha256:<digest>   (paste into image = "aquasec/trivy:0.69.1@sha256:<digest>")
readyhai --plugins plugins scan myimage:1.2.3
```

Two caveats vs the built-in `tool.sbom_cve` (syft+grype):

1. `docker-archive:/src/image.tar` only exists for **image** targets. For `repo`
   targets change `args` to `["fs", "--scanners", "vuln,secret", ..., "{src}"]`
   and keep the rest identical.
2. Trivy's SARIF includes licenses and misconfig; if that doubles up with Checkov,
   narrow `--scanners vuln` or add a `[[suppress]] rule = "plugin.trivy"` entry for
   the overlapping paths in `readyhai.toml`.
