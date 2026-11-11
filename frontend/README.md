# ReadyHai Agent Studio

The web UI for ReadyHai's autonomous QA agent, scans and network lab. Built with **Next.js 16**, **React 19**, **Tailwind CSS v4** and **Lucide icons**. It is a separate app from the Rust backend (`../src`): it talks to the backend's REST API through its own `/api/*` proxy.

> Next.js 16 has breaking changes from the versions most tools know. `AGENTS.md` points at the docs shipped in `node_modules/next/dist/docs/`; read the relevant guide there before changing routing, fonts or config.

## What it does

The header has three views: **Agent studio**, **Scans** and **Network lab**. Runs history is part of the studio's workspace.

1. **Agent studio**
   - **Command center** (left column). The header and the mode switch (Autonomous QA, Adversarial and auth, Contract and spec) are pinned at the top and the **Run agent** button is pinned at the bottom; only the controls in between scroll (target, OpenAPI spec, directives, profile, steps, model tier and reasoning budget, discovery and crawl). Nothing can be pushed out of reach.
   - **Pipeline stepper.** Six stages: Recon, Discovery, Plan, Execute, Verify, Gate. Every stage has a fixed size and border in every state; stage details open on click or keyboard into a fixed-height area, nothing reacts to hover except colour, so the layout never shifts. The Gate stage shows the verdict exactly as the backend reported it (`GO`, `CONDITIONAL_GO`, `NO_GO`) or "No verdict reported".
   - **Workspace** (right column). Tabs stay pinned above their scrolling panels: Scenarios and inspector (reproduction cURL, response, latency, in-place retest), Discovered routes, Evidence ledger (four pillars, exit checklist), Threat triage, Runs history. The **Release gate** card (sign-off) lives here, not in the command center, so it can never push the run controls away; it collapses to a one-line header.
   - **Runs history.** Every stored run with a lifecycle chip (running, cancelled, failed; completed runs show only their verdict), a **Cancel** button for a running run (`POST /api/agent/runs/{id}/cancel`, 202, the run stops at its next step and keeps its partial results), report downloads, delete, and "load into studio".
2. **Scans**: master-detail archive of static scans with verdict, kind and severity filters, a check grid, and report downloads.
3. **Network lab**: regressive testing with separate private sessions and throttling presets, root-cause diagnosis, the six-pillar deep audit and a cURL runner. Its audit is cached per target with a timestamp; only the current target's audit is shown, and the PR comment is built only from an audit under 30 minutes old.

The UI shows only values the backend reported. A missing verdict, score, pillar, requester IP or latency is rendered as "not evaluated" / "unknown" in a neutral style; a green GO appears only when the backend returned a `GO` verdict. Sign-off ("Approve for deployment" is offered only for `GO` / `CONDITIONAL_GO`; a `NO_GO` run can only be blocked) changes the UI only after the backend confirmed it, using the `approval_status` it echoes back, and only for the run the request was sent for. A cancelled run shows its partial results and never a gate decision.

## Design system

Defined once in `src/app/globals.css` (Tailwind v4 `@theme static`, so every variable stays in `:root`); components use the generated utilities (`bg-rh-surface`, `text-rh-muted`, `border-rh-line`, ...) and never hard-coded colours.

| Token | Value | Use |
|---|---|---|
| `rh-bg` | `#0e1320` | page background |
| `rh-surface` | `#151b2b` | panels |
| `rh-raised` | `#1c2436` | raised surfaces, chips, hover |
| `rh-line` | `#2a3348` | 1px borders (panels use borders, not shadows) |
| `rh-text` / `rh-muted` | `#e6eaf2` / `#8b95ab` | text |
| `rh-primary` / `rh-primary-hover` | `#5b7cfa` / `#7390fb` | actions, focus ring, active stage |
| `rh-go` / `rh-cond` / `rh-nogo` | `#3fb68b` / `#e0a43a` / `#e5484d` | GO, CONDITIONAL_GO, NO_GO and pass / warn / fail |
| `rh-info` | `#4fa3d9` | running and informational chips |

- **Type.** IBM Plex Sans (400, 500, 600) for the UI and IBM Plex Mono (400, 500) only for real code (URLs, curl commands, ids), loaded with `next/font/google` in `src/app/layout.tsx` and folded into `--font-sans` / `--font-mono`. Scale: 12 / 13 (`text-ui`, dense controls) / 14 / 16 / 20 / 24 px.
- **Shape.** Radius `sm` 6 px (inputs, chips), `md` 10 px (panels). The only shadow is `--shadow-popover` for menus, popovers and dialogs.
- **Accessibility.** A global, unlayered `:focus-visible` ring (2px `rh-primary`; `--rh-focus-offset` pulls it inward on clipped edges), `prefers-reduced-motion` disables animation, tabs and steppers are keyboard operable.
- Dark only (`<html class="dark">`, `color-scheme: dark`).

## Development

Node 24 is required for the lint and test tools (CI uses node 24). On a machine whose default `node` is older (v18, for example), vitest and eslint fail with misleading errors such as `File is not defined`: put node 24 first on `PATH` before running them, for example `nvm use 24`.

```bash
npm ci                    # install exactly what package-lock.json says
npm run dev               # Next.js dev server on http://localhost:3000
npm run build             # production standalone bundle
npm start                 # serve the production build
npm run lint              # eslint (eslint-config-next)
npx tsc --noEmit          # type check (CI runs it)
npm test                  # vitest run: jsdom, Testing Library, src/**/*.test.{ts,tsx}
```

CI (`.github/workflows/ci.yml`, job `frontend`) runs `npm ci`, `npm run lint`, `npx tsc --noEmit` and `npm test` on node 24. The tests (127 cases) cover the API helpers (`src/lib/api.ts`, `runs.ts`, `clipboard.ts`, `deepAuditCache.ts`) and the components with logic worth pinning: run status chips, cancel flow, composer, pipeline stepper, floating task widget, approval card and verdict badge.

The dev server proxies `/api/*` to the ReadyHai backend (`http://127.0.0.1:8080` by default); start the backend first (`READYHAI_TOKEN=... readyhai serve`).

## API authentication

Every backend `/api/*` route (everything except `/health`) requires `Authorization: Bearer <token>`.

1. Open the UI and click **Set API token** (key icon in the header).
2. Paste the backend bearer token and save. It is stored in this browser's `localStorage` (key `readyhai_api_token`) and attached to every request by `src/lib/api.ts`; if storage is blocked it is kept in memory for the session.
3. After any `401`, a banner asks you to set (or replace) the token; the failing view recovers once a valid token is saved.

Notes:

- **Server-side token.** The `/api/*` proxy (`src/app/api/[...path]/route.ts`) forwards the browser's `Authorization` header unchanged. When the UI container itself has `READYHAI_TOKEN` (the compose file passes it), the proxy attaches it to requests that carry no `Authorization` header, so nothing has to be pasted into the browser. That also means anyone who can reach the UI port can use the API: compose publishes it on `127.0.0.1` only; do not expose the UI beyond loopback without authentication in front of it. A token set in the dialog takes precedence.
- **Reports.** Links cannot send headers from a plain `<a>` or `<iframe>`, so reports (HTML, Markdown, SARIF, JSON, JUnit) are fetched with the token and opened or downloaded as blobs. HTML reports are shown in an iframe sandboxed without `allow-scripts` and `allow-same-origin` (also when opened in a new tab, via a script-free wrapper page), and the backend serves them with a CSP that has no `script-src`; non-HTML files are downloaded.
- Copy buttons go through `src/lib/clipboard.ts`: Clipboard API, then an `execCommand` fallback (plain http), then a notice; "Copied" is shown only when the copy really worked.

## Environment configuration

| Variable | Default | Purpose |
|---|---|---|
| `READYHAI_BACKEND_URL` | `http://127.0.0.1:8080` | URL of the ReadyHai REST API backend (compose: `http://readyhai:8080`) |
| `READYHAI_TOKEN` | unset | Optional server-side bearer token the proxy attaches (see above) |
| `PORT` | `3000` | Port for the Next.js server |

## Docker

The frontend image is a multi-stage standalone build (`Dockerfile`: `node:20-slim`, non-root user `readyhai`, UID 10001, `HOSTNAME=0.0.0.0`). Published as `ghcr.io/deziss/readyhai-frontend`.

```bash
docker build -t readyhai-frontend:local .
docker run -d --rm -p 3000:3000 -e READYHAI_BACKEND_URL=http://host.docker.internal:8080 readyhai-frontend:local
```

In the ReadyHai full-stack compose setup (from the project root, after `cp .env.example .env` and `cp scope.example.toml scope.toml`):

```bash
docker compose up -d      # backend on 127.0.0.1:8080, this UI on 127.0.0.1:3000
```

The frontend sits on the `edge` network only, so it cannot reach the Docker socket proxy.

## License

Distributed under the [GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE).
See [`LICENSE`](LICENSE) for complete terms.
