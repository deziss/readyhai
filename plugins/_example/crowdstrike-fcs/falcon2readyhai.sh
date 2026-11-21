#!/bin/sh
# Convert Falcon Container Security scan JSON to ReadyHai readyhai-json findings.
# Usage inside the plugin image: falcon2readyhai.sh <image-ref> > /out/falcon.json
# Requires: falcon-provision-tool (container_scan_run --json), jq.
# Field names may differ per FCS release: adjust .detections[] paths to your CLI
# version after a manual run. Schema: src/model.rs Finding (fingerprint, check*,
# rule, category, severity, title, detail, location, package, version, fix_version,
# remediation). *check is overwritten by the runner with plugin.<id>.
set -eu
REF="$1"
KEYID="${FALCON_API_KEYID:?}"
SECRET="${FALCON_API_KEYSECRET:?}"
falcon-provision-tool container_scan_run \
    --client-id "$KEYID" --client-secret "$SECRET" \
    --image "$REF" --json --quiet \
| jq '[.detections[]? | select(.severity_label | test("High|Critical|Medium"; "i"))
      | {fingerprint: ("fcs-" + (.sha256 // .rule_id // "x") + "-" + (.package // "")),
         check: "plugin.crowdstrike-fcs",
         rule: ("fcs." + (.rule_id // "detection")),
         category: "security",
         severity: (.severity_label | ascii_downcase),
         title: (.description // .rule_id // "CrowdStrike detection"),
         detail: (.remediation // .cve_id // .description // ""),
         location: (.package // .file_path // "'"$REF"'"),
         package: (.package // null),
         version: (.package_version // null),
         fix_version: (.fixed_version // null),
         remediation: (.remediation // ""),
         }]'
