# Agent Discover Module (`src/agent/discover`)

## Responsibility
Discovers target attack surface, technology profile, SPA manifests, OpenAPI operations, and harvests live identifiers within strict run budgets.

## Architecture & Submodules
- `tech.rs`: Technology profile detection (PHP, Django, Spring, React, Next.js, Nuxt, Angular, SvelteKit, REST API) and OpenAPI `SpecDoc`.
- `surface.rs`: Internal link parsing, HTTP redirect chain tracking (`Fetched`, `fetch`), login wall classification (`is_login_location`), and `route_from`.
- `spec.rs`: OpenAPI specification loading from URL, disk paths, or standard locations with size caps.
- `harvest.rs`: Read-only harvesting of existing record identifiers from GET collection endpoints (`harvest_ids`).
- `crawler.rs`: Crawler context `Cx`, JavaScript chunk ranking, build manifest parsing, and sitemap/robots.txt extraction (`spa_extras`).
- `soft404.rs`: Target soft-404 fingerprint calibration and catch-all response detection.
- `spa.rs`: Single Page App asset parser (Next.js manifests, JS chunks, sitemap.xml, robots.txt).
- `xhr.rs`: Headless Playwright runner integration for live fetch/XHR discovery.
- `mod.rs`: Top-level facade and orchestrator (`discover`, `discover_routes`, `crawl_and_discover_routes`).
- `tests.rs`: Comprehensive unit and site integration tests.

## Security & Architectural Constraints
1. **Budget Enforcement**: Every single probe and HTTP hop decrements the run budget (`RunBudget`).
2. **Same-Origin Constraint**: Requests never follow redirects off-origin or probe out-of-scope hosts.
3. **Destructive Action Avoidance**: Speculative probing drops dangerous paths (`logout`, `delete`, `reset`, etc.).
4. **Single Responsibility**: Every file is bounded (<450 lines) with isolated logic.

## Test Commands
```bash
cargo test --bin readyhai -- agent::discover::tests
```
