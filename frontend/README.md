# ReadyHai Agent Studio · Autonomous QA Gate Frontend

A high-performance, cyber-dark UI for ReadyHai's autonomous multi-agent QA engine, built with **Next.js 16**, **React 19**, **Tailwind CSS v4**, and **Lucide Icons**.

## Core Capabilities

1. **Attack Surface Discovery & URL Reconnaissance**: Probes endpoints, inspects OpenAPI/Swagger contracts, detects SPA shells vs JSON APIs, and records scans to the persistent history ledger.
2. **Autonomous Multi-Agent Swarm Orchestration**: Synthesizes adversarial test scenarios (Boundary, Authz/BOLA, Prompt Injection, Negative cases) grounded in discovered attack surfaces.
3. **Deep Payload Inspector & Interactive Retests**: Inspects complete cURL reproductions, HTTP response bodies, and latency traces with in-place one-click re-execution.
4. **4-Pillar Evidence Ledger & Human-in-the-Loop Governance Gate**: Evaluates `Value`, `Authority`, `Safety`, and `Evidence` with cryptographic signature generation and operator sign-off (`Approved` / `Rejected`).
5. **Global Persistent History Archive**: Visualizes both URL reconnaissance scans and comprehensive test runs with complete state restoration and one-click run deletion.

## Development

```bash
# Install dependencies
npm install

# Start Next.js development server on port 3000
npm run dev

# Build production standalone bundle
npm run build
```

The frontend runs at `http://localhost:3000` and automatically proxies `/api/*` to the ReadyHai backend running on `http://127.0.0.1:8080`.

## Environment Configuration

| Variable | Default | Purpose |
|---|---|---|
| `READYHAI_BACKEND_URL` | `http://127.0.0.1:8080` | URL of the ReadyHai REST API backend |
| `PORT` | `3000` | Port for the Next.js server |

## Docker Containerization

The frontend is containerized using a hardened multi-stage build:

```bash
# Build standalone Docker image
docker build -t readyhai-frontend:local .

# Run container
docker run -d --rm -p 3000:3000 -e READYHAI_BACKEND_URL=http://host.docker.internal:8080 readyhai-frontend:local
```

In the ReadyHai full-stack Compose setup:
```bash
# From project root:
docker compose up --build -d
```
