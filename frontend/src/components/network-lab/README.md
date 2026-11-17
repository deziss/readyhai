# Network Lab Modular Architecture

## Responsibility
The `network-lab` module encapsulates all networking diagnostics, latency benchmarking, and protocol analysis tools for ReadyHai. It enables AI coding agents and developers to inspect, modify, and test network UI views in isolation.

## Component Slices
| File | Lines | Responsibility |
|---|---|---|
| `types.ts` | 33 | Shared design tokens, button styles, focus rings, and sentence-case formatters |
| `harExport.ts` | 76 | Standard HTTP Archive (HAR 1.2) serialization and client-side browser download |
| `LabHeader.tsx` | 163 | Tab navigation bar, active target display, requester egress IP chip, and HAR export trigger |
| `RegressConfigPanel.tsx` | 326 | Regressive testing sidebar (methods, iterations, throttling, headers, timeouts) |
| `RegressResultsView.tsx` | 359 | Availability KPIs, automated root-cause diagnosis, latency waterfall bar chart, and iteration rows |
| `DeepAuditView.tsx` | 454 | 6-pillar protocol audit view (IPv4/v6 Happy Eyeballs, Subresources, Protocol Matrix, TLS chain, CORS, MTU) |
| `MultiRegionView.tsx` | 232 | Distributed 4-region edge mesh probe, regional disparity metrics, and edge POP routing insights |
| `PrGateView.tsx` | 343 | PR status gate, embeddable SVG badges, PR comment generator, and GitHub Action workflow snippet |
| `CurlProbeCard.tsx` | 118 | Real-time cURL diagnostic probe, timing chips (DNS, TCP, TLS, TTFB), and stdout drawer |
| `index.ts` | 9 | Barrel export for consumer components |
| `../NetworkLabView.tsx` | 491 | Top-level coordinator managing lab state, API lifecycle, and subtab switching |

## Public Interfaces
- `<NetworkLabView initialTarget="..." onRunningChange={...} ledgerScore={...} />`
- All sub-views exported via `./network-lab/index.ts`

## Invariants & Rules
1. **Isolated Views**: Each tab (Regress, Deep Audit, Multi-Region, PR Gate) is rendered in its own dedicated slice.
2. **Measurement Integrity**: Badges, HAR export, and PR comments only activate on measured backend data—never stubbed or fabricated values.
3. **UI Selector Stability**: Critical button IDs (`#btn-run-regress`, `#btn-run-deep-audit`, `#btn-run-multi-region`, `#btn-export-har`) must be preserved for automated testing.

## Verification
- Unit & Component tests:
  ```bash
  cd frontend && npm test -- --run
  ```
- Typecheck & Production Build:
  ```bash
  cd frontend && npx tsc --noEmit && npm run build
  ```
