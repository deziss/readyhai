# Deep Agentic Software Factory Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform ReadyHai from a 2-call deterministic runner into a deep, multi-call LLM-driven autonomous security software factory spanning 6 discrete stations: Recon, Discovery, Plan, Execute (Adaptive ReAct Loop), Verify (Contextual Taint Juror), and Gate (Factory Attestation), with dynamic LLM-synthesized agent directives eliminating manual input from the frontend command center.

**Architecture:** Implement a formal StateGraph / Software Factory pipeline where each station runs deep LLM reasoning with deterministic guardrails. Station 1 (Recon) fingerprints targets and synthesizes autonomous rules of engagement; Station 2 (Discovery) predicts shadow routes and schema shapes; Station 3 (Plan) builds multi-step Attack DAGs; Station 4 (Execute) drives an adaptive OODA/ReAct loop; Station 5 (Verify) executes Contextual Taint Tracing via an LLM Juror to eliminate false positives; Station 6 (Gate) generates signed Software Factory Attestations. The frontend replaces manual directives text areas with a live autonomous directives preview and badge system.

**Tech Stack:** Rust 2024 edition, Axum, Tokio, Reqwest, Serde JSON, React 19, TypeScript, Tailwind CSS, Lucide icons, Vitest.

---

## File Structure & Decomposition

```
readyhai/
├── src/
│   ├── agent/
│   │   ├── recon/                       # [NEW] Reconnaissance & Directives Engine
│   │   │   ├── mod.rs                   # Recon module exports & TargetRecon
│   │   │   ├── directives.rs            # Dynamic Directives LLM prompt & synthesis
│   │   │   └── tests.rs                 # Unit tests for recon & directive synthesis
│   │   ├── discover/
│   │   │   ├── mod.rs                   # Re-export semantic discovery
│   │   │   ├── semantic.rs              # [NEW] LLM-assisted shadow route & param expansion
│   │   │   └── tests.rs                 # Discovery tests
│   │   ├── plan/
│   │   │   ├── mod.rs                   # Plan orchestration
│   │   │   ├── dag.rs                   # [NEW] Attack DAG & dependency graph models
│   │   │   ├── directives.rs            # Directive-driven case expansion
│   │   │   ├── llm.rs                   # LLM planning prompts
│   │   │   └── tests.rs                 # Plan tests
│   │   ├── react.rs                     # Multi-wave adaptive ReAct execution loop
│   │   ├── verify/
│   │   │   ├── mod.rs                   # Verification exports
│   │   │   ├── juror.rs                 # [NEW] Contextual Taint Tracing Juror & remediation diffs
│   │   │   └── tests.rs                 # Juror tests
│   │   ├── pipeline/
│   │   │   ├── mod.rs                   # Pipeline exports
│   │   │   ├── graph.rs                 # [NEW] StateGraph & Software Factory station state machine
│   │   │   ├── gate.rs                  # Factory Attestation & release directive generation
│   │   │   ├── stages.rs                # 6-station orchestrator
│   │   │   └── tests.rs                 # Pipeline integration tests
│   │   └── types/
│   │       └── reports.rs               # SynthesizedDirectives, AttackDag, Attestation types
│   └── serve/
│       ├── agent_api.rs                 # Directives synthesis endpoint
│       ├── router.rs                    # Route wiring
│       └── tests.rs                     # API tests
└── frontend/
    └── src/
        ├── components/
        │   ├── Composer.tsx             # Autonomous Directives UI (no manual typing)
        │   └── __tests__/Composer.test.tsx
        └── types/
            └── agent.ts                 # Directives & Factory types
```

---

### Task 1: Target Reconnaissance & Dynamic Directives Engine

**Files:**
- Create: `readyhai/src/agent/recon/mod.rs`
- Create: `readyhai/src/agent/recon/directives.rs`
- Create: `readyhai/src/agent/recon/tests.rs`
- Modify: `readyhai/src/agent/mod.rs`
- Modify: `readyhai/src/agent/types/reports.rs`

- [ ] **Step 1: Write failing test for Dynamic Directives Synthesis**

```rust
// In readyhai/src/agent/recon/tests.rs
#[test]
fn test_parse_synthesized_directives_json() {
    let raw = r#"{
        "focus_areas": ["BOLA/IDOR on /api/v1/tenant", "JWT algorithm confusion", "Prompt injection canary"],
        "boundary_rules": ["Stay within /api paths", "Do not fuzz destructive deletion"],
        "rules_of_engagement": "Adversarial assessment targeting authorization boundaries and input sanitization",
        "canary_token": "CANARY_RECON_7A3B"
    }"#;
    let res = super::directives::parse_directives_response(raw).expect("parse failed");
    assert_eq!(res.focus_areas.len(), 3);
    assert_eq!(res.canary_token, "CANARY_RECON_7A3B");
    assert!(res.as_custom_instructions().contains("BOLA/IDOR"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin readyhai agent::recon::tests::test_parse_synthesized_directives_json`
Expected: FAIL with "module `recon` not found"

- [ ] **Step 3: Implement Recon models & Dynamic Directives Synthesizer**

Implement `readyhai/src/agent/recon/directives.rs` with `SynthesizedDirectives` struct, prompt engineering, and parsing logic. Expose `probe_target_recon` to inspect headers/security cookies and `synthesize_directives` using `LlmConfig`.
Expose `pub mod recon;` in `readyhai/src/agent/mod.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin readyhai agent::recon::tests::test_parse_synthesized_directives_json`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add readyhai/src/agent/recon readyhai/src/agent/mod.rs readyhai/src/agent/types/reports.rs
git commit -m "feat(agent): add reconnaissance and dynamic directives synthesis engine"
```

---

### Task 2: Backend Directives Synthesis API Endpoint

**Files:**
- Modify: `readyhai/src/serve/agent_api.rs:1-120`
- Modify: `readyhai/src/serve/router.rs:130-170`
- Modify: `readyhai/src/serve/tests.rs`

- [ ] **Step 1: Write failing test for `/api/agent/directives/synthesize`**

```rust
// In readyhai/src/serve/tests.rs
#[tokio::test]
async fn test_agent_directives_synthesize_endpoint() {
    let app = test_app().await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/agent/directives/synthesize")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"target":"https://example.com"}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin readyhai serve::tests::test_agent_directives_synthesize_endpoint`
Expected: FAIL with 404 Not Found

- [ ] **Step 3: Implement `agent_directives_post` handler and route**

Implement `agent_directives_post` in `src/serve/agent_api.rs` that accepts `{ target: String, spec_url?: Option<String> }` and runs fast recon + directive synthesis, returning JSON. Register route in `src/serve/router.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin readyhai serve::tests::test_agent_directives_synthesize_endpoint`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add readyhai/src/serve/agent_api.rs readyhai/src/serve/router.rs readyhai/src/serve/tests.rs
git commit -m "feat(serve): expose POST /api/agent/directives/synthesize endpoint"
```

---

### Task 3: Discovery Stage Deep LLM Semantic Route & Parameter Expansion

**Files:**
- Create: `readyhai/src/agent/discover/semantic.rs`
- Modify: `readyhai/src/agent/discover/mod.rs`
- Modify: `readyhai/src/agent/discover/tests.rs`

- [ ] **Step 1: Write failing test for Semantic Route Prediction**

```rust
// In readyhai/src/agent/discover/tests.rs
#[test]
fn test_parse_semantic_discovered_routes() {
    let raw = r#"[
        {"path": "/api/v1/internal/health", "method": "GET", "reasoning": "Standard Spring/Actuator monitor path"},
        {"path": "/api/v1/users/{id}/permissions", "method": "GET", "reasoning": "Inferred RBAC boundary from auth endpoints"}
    ]"#;
    let routes = super::semantic::parse_semantic_routes(raw).expect("parse semantic routes");
    assert_eq!(routes.len(), 2);
    assert_eq!(routes[0].path, "/api/v1/internal/health");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin readyhai agent::discover::tests::test_parse_semantic_discovered_routes`
Expected: FAIL with "module `semantic` not found"

- [ ] **Step 3: Implement Semantic Route & Parameter Expander**

Implement `readyhai/src/agent/discover/semantic.rs` with `discover_semantic_routes(llm, target, tech, known_routes, directives)` injecting high-confidence predicted shadow endpoints and parameter schemas. Connect in `src/agent/discover/mod.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin readyhai agent::discover::tests::test_parse_semantic_discovered_routes`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add readyhai/src/agent/discover/semantic.rs readyhai/src/agent/discover/mod.rs readyhai/src/agent/discover/tests.rs
git commit -m "feat(agent): implement semantic shadow route and parameter discovery"
```

---

### Task 4: Plan Stage Attack DAG & Stateful Workflow Synthesis

**Files:**
- Create: `readyhai/src/agent/plan/dag.rs`
- Modify: `readyhai/src/agent/plan/mod.rs`
- Modify: `readyhai/src/agent/plan/llm.rs`
- Modify: `readyhai/src/agent/plan/directives.rs`
- Modify: `readyhai/src/agent/plan/tests.rs`

- [ ] **Step 1: Write failing test for Attack DAG validation and topological sort**

```rust
// In readyhai/src/agent/plan/tests.rs
#[test]
fn test_attack_dag_resolution() {
    use super::dag::{AttackDag, AttackDagNode};
    let mut dag = AttackDag::new();
    dag.add_node(AttackDagNode::new("setup_user", vec![]));
    dag.add_node(AttackDagNode::new("escalate_role", vec!["setup_user".into()]));
    dag.add_node(AttackDagNode::new("exfiltrate_tenant", vec!["escalate_role".into()]));
    let sorted = dag.topological_order().expect("cycle detected");
    assert_eq!(sorted, vec!["setup_user", "escalate_role", "exfiltrate_tenant"]);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin readyhai agent::plan::tests::test_attack_dag_resolution`
Expected: FAIL with "module `dag` not found"

- [ ] **Step 3: Implement `AttackDag` and dynamic prompt synthesis**

Implement `readyhai/src/agent/plan/dag.rs` and update `llm.rs` to generate structured multi-step attack graphs from the dynamic directives. Update `plan_directives` to parse synthesized directives.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin readyhai agent::plan::tests::test_attack_dag_resolution`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add readyhai/src/agent/plan/dag.rs readyhai/src/agent/plan/mod.rs readyhai/src/agent/plan/llm.rs readyhai/src/agent/plan/directives.rs readyhai/src/agent/plan/tests.rs
git commit -m "feat(agent): implement Attack DAG and dynamic directive planning"
```

---

### Task 5: Execute Stage Adaptive ReAct Loop with Dynamic Branching

**Files:**
- Modify: `readyhai/src/agent/react.rs:1-250`
- Modify: `readyhai/src/agent/pipeline/stages.rs:410-466`

- [ ] **Step 1: Write failing test for anomaly observation in ReAct loop**

```rust
// In readyhai/src/agent/react.rs tests
#[test]
fn test_react_anomaly_detector() {
    let mut result = CaseExecutionResult::default();
    result.status = "FAIL".into();
    result.response_status = Some(500);
    result.response_body = Some(r#"{"error":"InternalServerError: NullPointer at AuthService.java:42"}"#.into());
    assert!(is_anomaly_candidate(&result));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin readyhai agent::react::tests::test_react_anomaly_detector`
Expected: FAIL with "function `is_anomaly_candidate` not found"

- [ ] **Step 3: Enhance ReAct Loop with LLM hypothesis & dynamic probe branching**

Implement `is_anomaly_candidate` and LLM mutation hypothesis trigger in `src/agent/react.rs`. When a response leaks stack traces, error messages, or 403 reflection, the ReAct loop queries LLM to synthesize targeted probes and execute immediate follow-up waves.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin readyhai agent::react::tests::test_react_anomaly_detector`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add readyhai/src/agent/react.rs readyhai/src/agent/pipeline/stages.rs
git commit -m "feat(agent): enhance ReAct loop with anomaly detection and adaptive branching"
```

---

### Task 6: Verify Stage Contextual Taint Tracing Juror & Remediation Diffs

**Files:**
- Create: `readyhai/src/agent/verify/juror.rs`
- Modify: `readyhai/src/agent/verify/mod.rs`
- Modify: `readyhai/src/agent/verify/tests.rs`
- Modify: `readyhai/src/agent/triage/mod.rs`

- [ ] **Step 1: Write failing test for Contextual Taint Juror evaluation**

```rust
// In readyhai/src/agent/verify/tests.rs
#[test]
fn test_juror_verdict_parsing() {
    let raw = r#"{
        "is_true_positive": true,
        "confidence": 95,
        "taint_path": "request body 'user_id' -> SQL error in response body",
        "remediation_diff": "--- a/app.py\n+++ b/app.py\n- query = f'SELECT * FROM users WHERE id={id}'\n+ cursor.execute('SELECT * FROM users WHERE id=%s', (id,))",
        "explanation": "Unsanitized user_id parameter allows SQL syntax injection"
    }"#;
    let verdict = super::juror::parse_juror_verdict(raw).expect("parse juror verdict");
    assert!(verdict.is_true_positive);
    assert_eq!(verdict.confidence, 95);
    assert!(verdict.remediation_diff.unwrap().contains("cursor.execute"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin readyhai agent::verify::tests::test_juror_verdict_parsing`
Expected: FAIL with "module `juror` not found"

- [ ] **Step 3: Implement Contextual Taint Tracing Juror & Diff Generator**

Implement `readyhai/src/agent/verify/juror.rs` with `evaluate_with_juror` executing Source-to-Sink taint inspection for candidate failures. Filter false positives out and attach generated patch diffs to `TriagedDefect`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin readyhai agent::verify::tests::test_juror_verdict_parsing`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add readyhai/src/agent/verify/juror.rs readyhai/src/agent/verify/mod.rs readyhai/src/agent/verify/tests.rs readyhai/src/agent/triage/
git commit -m "feat(agent): implement Contextual Taint Tracing Juror and remediation diff generation"
```

---

### Task 7: Gate Stage Software Factory Attestation & StateGraph Pipeline

**Files:**
- Create: `readyhai/src/agent/pipeline/graph.rs`
- Modify: `readyhai/src/agent/pipeline/gate.rs`
- Modify: `readyhai/src/agent/pipeline/stages.rs`
- Modify: `readyhai/src/agent/pipeline/tests.rs`

- [ ] **Step 1: Write failing test for Pipeline StateGraph transitions**

```rust
// In readyhai/src/agent/pipeline/tests.rs
#[test]
fn test_pipeline_graph_state_transitions() {
    use super::graph::{PipelineState, StationNode};
    let mut station = StationNode::new(PipelineState::Recon);
    assert_eq!(station.current_state(), PipelineState::Recon);
    station.transition_to(PipelineState::Discovery).expect("valid transition");
    assert_eq!(station.current_state(), PipelineState::Discovery);
    station.transition_to(PipelineState::Plan).expect("valid transition");
    assert_eq!(station.current_state(), PipelineState::Plan);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin readyhai agent::pipeline::tests::test_pipeline_graph_state_transitions`
Expected: FAIL with "module `graph` not found"

- [ ] **Step 3: Implement Pipeline StateGraph and Software Factory Attestation**

Implement `readyhai/src/agent/pipeline/graph.rs` defining formal station transitions (Recon -> Discovery -> Plan -> Execute [Loop] -> Verify -> Gate). Enhance `gate.rs` with Software Factory release attestation scoring and signed release directives. Wire into `stages.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin readyhai agent::pipeline::tests::test_pipeline_graph_state_transitions`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add readyhai/src/agent/pipeline/graph.rs readyhai/src/agent/pipeline/gate.rs readyhai/src/agent/pipeline/stages.rs readyhai/src/agent/pipeline/tests.rs
git commit -m "feat(agent): implement StateGraph factory orchestration and release attestation"
```

---

### Task 8: Frontend Command Center - Autonomous Directives UI

**Files:**
- Modify: `readyhai/frontend/src/components/Composer.tsx`
- Modify: `readyhai/frontend/src/types/agent.ts`
- Modify: `readyhai/frontend/src/components/__tests__/Composer.test.tsx`

- [ ] **Step 1: Write failing test for Autonomous Directives in Composer**

```tsx
// In readyhai/frontend/src/components/__tests__/Composer.test.tsx
it("renders autonomous dynamic directives without requiring manual textarea input", () => {
  render(<Composer {...defaultProps} />);
  expect(screen.getByText(/Autonomous Directives/i)).toBeInTheDocument();
  expect(screen.queryByPlaceholderText(/e\.g\. Focus on unauthenticated/i)).not.toBeInTheDocument();
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm test Composer.test.tsx`
Expected: FAIL

- [ ] **Step 3: Replace manual directives textarea with Dynamic Directives Engine**

Update `Composer.tsx`:
- Remove manual `<textarea>` input for directives.
- Display an Autonomous Directives status panel with:
  - Dynamic threat focus tags (BOLA, IDOR, Canary Injections, Auth Boundaries)
  - One-click "Synthesize Directives" button to preview / trigger synthesis via `/api/agent/directives/synthesize`
  - Auto-synthesized Rules of Engagement display.

- [ ] **Step 4: Run test to verify it passes**

Run: `npm test Composer.test.tsx`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add readyhai/frontend/src/components/Composer.tsx readyhai/frontend/src/types/agent.ts readyhai/frontend/src/components/__tests__/Composer.test.tsx
git commit -m "feat(frontend): replace manual directives input with autonomous dynamic directives engine"
```

---

### Task 9: Full Regression, End-to-End Suite & Clippy Verification

**Files:**
- None (system-wide test & clippy pass)

- [ ] **Step 1: Run full Rust test suite**
Run: `cargo test --bin readyhai`
Expected: All tests pass (845+ tests, 0 failures)

- [ ] **Step 2: Run Clippy with strict flags**
Run: `cargo clippy -- -D warnings`
Expected: Zero warnings, clean build

- [ ] **Step 3: Run full Frontend test suite**
Run: `npm test` in `readyhai/frontend/`
Expected: All 141+ tests pass

- [ ] **Step 4: CLI Smoke Test**
Run: `cargo run --bin readyhai -- agent --target https://myvapi.com --dry-run`
Expected: Clean execution demonstrating multi-station progress through Recon, Discovery, Plan, Execute, Verify, and Gate.

- [ ] **Step 5: Final Local Commit**
```bash
git add .
git commit -m "chore(agent): complete deep agentic software factory pipeline integration"
```
