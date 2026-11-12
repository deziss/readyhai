# Security Policy

## Supported Versions

Security fixes and container image updates are published for the current minor release line:

| Version | Supported |
|---|---|
| `0.7.x` | Yes |
| `< 0.7.0` | No (upgrade to latest release) |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities in ReadyHai itself (such as sandbox escapes, SSRF/egress-guard bypasses, token handling bugs, or command injection).

Report vulnerabilities privately via one of:

1. **GitHub Security Advisories:** [Report a vulnerability on `deziss/readyhai`](https://github.com/deziss/readyhai/security/advisories/new)
2. **Email:** [kushwahaanshu8858@gmail.com](mailto:kushwahaanshu8858@gmail.com)

Please include:

- Affected component (`readyhai` CLI/server, `frontend` Studio UI, Playwright runner, or action/workflow)
- Version or commit SHA (`readyhai --version`)
- Reproduction steps or proof-of-concept
- Potential impact and suggested remediation (if known)

## Responsible Usage & Target Authorization

ReadyHai includes active security probing capabilities (`readyhai agent`, `tool.nuclei`, `tool.zap_active`, `qa.resilience`). Always follow [`docs/security-model.md`](docs/security-model.md) and [`scope.example.toml`](scope.example.toml):

- Run intrusive or write-capable probes only against systems you own or have explicit authorization to test (`nonprod`).
- Never bypass [`scope.toml`](scope.example.toml) nonprod gates against third-party or production targets.
