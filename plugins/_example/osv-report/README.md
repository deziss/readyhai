# osv-report (placeholder — not enabled)

`osv-scanner --report` emits HTML, and the plugin runner only parses SARIF/JUnit/
readyhai-json. The native `tool.osv_reachability` check already uses osv-scanner
`--json` with a proper parser, so this wrapper would be a downgrade.

If you want OSV *rollup* output as an artifact (not findings), add `text`/`html`
passthrough to the runner (plugins/README.md "Core upgrades") or convert with
`osv-scanner scan --format json --output /out/osv.json` plus a jq wrapper that
emits readyhai-json with one Finding per vulnerable package.
