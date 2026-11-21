`readyhai-json` = an array of `Finding` objects (schema: `src/model.rs`):
`fingerprint`, `check`, `rule`, `category` (lowercase snake_case, e.g.
`supply_chain`), `severity` (lowercase), `title`, `location` are required;
`detail`, `package`, `version`, `fix_version`, `remediation` optional.

The plugin above mounts only `/src` + `/out`, so `rh.jq` isn't present in the
node image — for a working setup either bake a tiny derived image:

    FROM node:22-slim
    RUN apt-get update && apt-get install -y --no-install-recommends jq && rm -rf /var/lib/apt/lists/*
    COPY rh.jq /tmp/rh.jq

with `rh.jq`:

    [.vulnerabilities | to_entries[]
     | select(.value.severity=="high" or .value.severity=="critical")
     | { fingerprint: ("npm-" + .key + "-" + (.value.range // "x")),
         check: "plugin.npm-audit",
         rule: ("npm." + (.value.via[0].title // .value.via // "vuln") | tostring),
         category: "supply_chain",
         severity: .value.severity,
         title: ("Vulnerable dependency " + .key),
         detail: (.value.via | if type=="array" then map(.title) | join("; ") else tostring end),
         location: "package-lock.json",
         package: .key,
         remediation: ("npm audit fix (range " + (.value.range // "?") + ")") }]

or replace the plugin with a native check: npm/pip/cargo/bun audits all speak the
same shape ("known-vuln for my lockfile") and deserve one first-class
`tool.lockfile_audit` in `src/tools/checks.rs` using `run_capped` (host binaries,
like the `tests.own` check) instead of three container plugins.
