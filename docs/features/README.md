# ReadyHai feature guides

Comprehensive, per-feature documentation: what each feature does, why it matters, how to use
it, and how to configure it. These guides explain behaviour and intent; the reference pages
([usage](../usage.md), [checks](../checks.md), [configuration](../configuration.md),
[api](../api.md)) remain the exhaustive lists of flags, rule ids, keys and endpoints.

| Guide | Covers |
|---|---|
| [scanning-and-targets.md](scanning-and-targets.md) | The verdict model and `readyhai scan`: repository, container image, web/API, SSH host and Android APK targets; baselines and noise control; reports (HTML/JSON/SARIF); the tool orchestrator and plugged OSS scanner packs; offline feeds |
| [agent-qa-security.md](agent-qa-security.md) | `readyhai qa` (senior-QA engine), the Super Agent pipeline incl. the v3.8.0 Intel stage, exploitation verification (`readyhai exploits`), the vulnerability database, the network lab and WireGuard audit, the eval harnesses, `eval-ai`, `fix`, `mutate`, the MCP server, and the settings/RBAC system |

There is also a rendered, in-app version of the feature catalog in the frontend at the
**Docs** route (`/docs`) — same content shape, browsable beside the Agent Studio.

Rules for these pages:

- Describe the shipped code (current `VERSION`); where prose and code disagree, the code wins.
- Every command, flag and settings key shown here must exist in
  `src/main.rs` / `settings.example.toml` — no aspirational documentation.
- Link out to reference pages for exhaustive lists instead of duplicating them here.
