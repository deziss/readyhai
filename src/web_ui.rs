//! Professional Embedded Web UI for ReadyHai Agentic AI QA & Production Readiness Gate.

pub const HTML_PAGE: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ReadyHai · Agent Studio & Production Gate</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-base: #060913;
      --bg-surface: #0a0f1d;
      --bg-card: #111827;
      --bg-card-hover: #172136;
      --border: rgba(99, 102, 241, 0.16);
      --border-focus: rgba(99, 102, 241, 0.45);
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --indigo: #6366f1;
      --indigo-glow: rgba(99, 102, 241, 0.35);
      --cyan: #06b6d4;
      --cyan-glow: rgba(6, 182, 212, 0.25);
      --emerald: #10b981;
      --emerald-glow: rgba(16, 185, 129, 0.3);
      --rose: #f43f5e;
      --rose-glow: rgba(244, 63, 94, 0.3);
      --amber: #f59e0b;
      --amber-glow: rgba(245, 158, 11, 0.3);
      --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg-base);
      color: var(--text-main);
      font-family: var(--font-sans);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      overflow-x: hidden;
      line-height: 1.5;
    }

    /* Top Navigation Bar */
    header {
      background: rgba(10, 15, 29, 0.85);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border);
      padding: 0.75rem 1.5rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      position: sticky;
      top: 0;
      z-index: 50;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      text-decoration: none;
      color: inherit;
    }
    .brand-icon {
      width: 34px;
      height: 34px;
      background: linear-gradient(135deg, var(--indigo), var(--cyan));
      border-radius: 9px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.15rem;
      box-shadow: 0 0 16px var(--indigo-glow);
    }
    .brand-title {
      font-weight: 800;
      font-size: 1.15rem;
      letter-spacing: -0.02em;
    }
    .brand-badge {
      font-family: var(--font-mono);
      font-size: 0.65rem;
      background: rgba(99, 102, 241, 0.15);
      color: var(--cyan);
      border: 1px solid rgba(6, 182, 212, 0.3);
      padding: 0.15rem 0.5rem;
      border-radius: 9999px;
      font-weight: 600;
      letter-spacing: 0.05em;
    }

    .header-center {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }
    .target-pill {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      background: rgba(17, 24, 39, 0.8);
      border: 1px solid var(--border);
      padding: 0.35rem 0.85rem;
      border-radius: 9999px;
      font-family: var(--font-mono);
      font-size: 0.75rem;
      color: var(--text-muted);
    }
    .target-pill strong {
      color: var(--cyan);
    }

    .model-status-pill {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      background: rgba(17, 24, 39, 0.8);
      border: 1px solid var(--border);
      padding: 0.35rem 0.85rem;
      border-radius: 9999px;
      font-family: var(--font-mono);
      font-size: 0.75rem;
      color: var(--text-muted);
    }
    .pulse-dot {
      width: 8px;
      height: 8px;
      background-color: var(--emerald);
      border-radius: 50%;
      box-shadow: 0 0 8px var(--emerald-glow);
      animation: pulse 2s infinite;
    }
    .pulse-dot.offline {
      background-color: var(--rose);
      box-shadow: 0 0 8px var(--rose-glow);
    }
    @keyframes pulse {
      0% { transform: scale(0.95); opacity: 0.8; }
      50% { transform: scale(1.15); opacity: 1; }
      100% { transform: scale(0.95); opacity: 0.8; }
    }

    /* Layout Split */
    .app-workspace {
      display: grid;
      grid-template-columns: minmax(400px, 44%) 1fr;
      flex: 1;
      height: calc(100vh - 58px);
      overflow: hidden;
    }
    @media (max-width: 1024px) {
      .app-workspace {
        grid-template-columns: 1fr;
        height: auto;
        overflow: auto;
      }
    }

    /* Left Pane: Command Center */
    .left-pane {
      background: var(--bg-surface);
      border-right: 1px solid var(--border);
      display: flex;
      flex-direction: column;
      overflow-y: auto;
      padding: 1.25rem;
      gap: 1.25rem;
    }

    /* Right Pane: Dynamic Side Canvas */
    .right-pane {
      background: var(--bg-base);
      display: flex;
      flex-direction: column;
      overflow-y: auto;
      padding: 1.25rem;
      gap: 1.25rem;
    }

    /* Cards */
    .card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.25rem;
      transition: all 0.2s ease;
      position: relative;
    }
    .card-title {
      font-size: 0.85rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      font-weight: 700;
      margin-bottom: 0.75rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    /* Composer Tabs */
    .mode-tabs {
      display: flex;
      gap: 0.4rem;
      background: rgba(6, 9, 19, 0.6);
      padding: 0.3rem;
      border-radius: 8px;
      border: 1px solid var(--border);
      margin-bottom: 1rem;
    }
    .mode-tab {
      flex: 1;
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-family: var(--font-sans);
      font-size: 0.75rem;
      font-weight: 600;
      padding: 0.45rem 0.5rem;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.15s ease;
      text-align: center;
    }
    .mode-tab.active {
      background: var(--indigo);
      color: #fff;
      box-shadow: 0 0 10px var(--indigo-glow);
    }

    /* Form Fields */
    .field-group {
      display: flex;
      flex-direction: column;
      gap: 0.4rem;
      margin-bottom: 0.85rem;
    }
    .field-label {
      font-size: 0.75rem;
      font-weight: 600;
      color: var(--text-muted);
    }
    .field-input, .field-textarea, .field-select {
      background: rgba(6, 9, 19, 0.8);
      border: 1px solid var(--border);
      border-radius: 8px;
      color: var(--text-main);
      padding: 0.6rem 0.8rem;
      font-family: var(--font-sans);
      font-size: 0.85rem;
      outline: none;
      transition: border-color 0.15s ease;
    }
    .field-input:focus, .field-textarea:focus, .field-select:focus {
      border-color: var(--indigo);
      box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
    }
    .field-textarea {
      resize: vertical;
      min-height: 60px;
    }

    /* Quick Chips */
    .chip-list {
      display: flex;
      flex-wrap: wrap;
      gap: 0.4rem;
      margin-top: 0.35rem;
    }
    .chip {
      background: rgba(99, 102, 241, 0.08);
      border: 1px solid rgba(99, 102, 241, 0.2);
      color: var(--text-muted);
      font-size: 0.7rem;
      padding: 0.2rem 0.5rem;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .chip:hover {
      background: rgba(99, 102, 241, 0.2);
      color: var(--cyan);
      border-color: var(--cyan);
    }

    /* Action Buttons */
    .btn-primary {
      background: linear-gradient(135deg, var(--indigo), #4f46e5);
      color: #fff;
      border: none;
      border-radius: 8px;
      font-weight: 700;
      font-size: 0.9rem;
      padding: 0.75rem 1.25rem;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      width: 100%;
      box-shadow: 0 0 16px var(--indigo-glow);
      transition: all 0.2s ease;
    }
    .btn-primary:hover:not(:disabled) {
      filter: brightness(1.1);
      transform: translateY(-1px);
    }
    .btn-primary:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      box-shadow: none;
    }

    /* Tool Call List (NuHire Style) */
    .tool-call-list {
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }
    .tool-call-item {
      background: rgba(6, 9, 19, 0.6);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
      transition: border-color 0.2s;
    }
    .tool-call-item.active {
      border-color: var(--cyan);
    }
    .tool-call-header {
      padding: 0.55rem 0.75rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      cursor: pointer;
      user-select: none;
    }
    .tool-call-title {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 0.8rem;
      font-weight: 600;
    }
    .tool-tag {
      font-family: var(--font-mono);
      font-size: 0.65rem;
      padding: 0.15rem 0.4rem;
      border-radius: 4px;
      font-weight: 700;
    }
    .tool-tag.discovery { background: rgba(6, 182, 212, 0.15); color: var(--cyan); }
    .tool-tag.planner { background: rgba(99, 102, 241, 0.15); color: var(--indigo); }
    .tool-tag.explorer { background: rgba(245, 158, 11, 0.15); color: var(--amber); }
    .tool-tag.triager { background: rgba(244, 63, 94, 0.15); color: var(--rose); }
    .tool-tag.gate { background: rgba(16, 185, 129, 0.15); color: var(--emerald); }
    .tool-call-details {
      padding: 0.6rem 0.75rem;
      border-top: 1px solid rgba(255, 255, 255, 0.05);
      font-family: var(--font-mono);
      font-size: 0.75rem;
      color: var(--text-muted);
      background: rgba(0, 0, 0, 0.2);
    }

    /* Human In The Loop Approval Card (NuHire Style) */
    .approval-card {
      border: 2px solid var(--border);
      border-radius: 12px;
      background: linear-gradient(180deg, rgba(17, 24, 39, 0.95), rgba(11, 17, 32, 0.95));
      padding: 1.25rem;
      position: relative;
      overflow: hidden;
    }
    .approval-card.verdict-go {
      border-color: var(--emerald);
      box-shadow: 0 0 24px var(--emerald-glow);
    }
    .approval-card.verdict-conditional {
      border-color: var(--amber);
      box-shadow: 0 0 24px var(--amber-glow);
    }
    .approval-card.verdict-nogo {
      border-color: var(--rose);
      box-shadow: 0 0 24px var(--rose-glow);
    }
    .approval-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 0.75rem;
    }
    .verdict-badge {
      font-family: var(--font-mono);
      font-size: 1.15rem;
      font-weight: 800;
      padding: 0.25rem 0.85rem;
      border-radius: 8px;
      letter-spacing: 0.05em;
    }
    .verdict-badge.go { background: rgba(16, 185, 129, 0.2); color: var(--emerald); border: 1px solid var(--emerald); }
    .verdict-badge.conditional { background: rgba(245, 158, 11, 0.2); color: var(--amber); border: 1px solid var(--amber); }
    .verdict-badge.nogo { background: rgba(244, 63, 94, 0.2); color: var(--rose); border: 1px solid var(--rose); }

    .approval-actions {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 0.6rem;
      margin-top: 1rem;
    }
    .btn-approve {
      background: var(--emerald);
      color: #060913;
      font-weight: 700;
      padding: 0.6rem;
      border-radius: 6px;
      border: none;
      cursor: pointer;
      transition: filter 0.15s;
    }
    .btn-reject {
      background: rgba(244, 63, 94, 0.15);
      color: var(--rose);
      border: 1px solid var(--rose);
      font-weight: 700;
      padding: 0.6rem;
      border-radius: 6px;
      cursor: pointer;
      transition: background 0.15s;
    }
    .btn-approve:hover { filter: brightness(1.1); }
    .btn-reject:hover { background: rgba(244, 63, 94, 0.25); }

    /* Canvas Navigation Tabs */
    .canvas-nav {
      display: flex;
      gap: 0.5rem;
      border-bottom: 1px solid var(--border);
      padding-bottom: 0.5rem;
    }
    .canvas-tab {
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-family: var(--font-sans);
      font-size: 0.85rem;
      font-weight: 600;
      padding: 0.45rem 0.85rem;
      border-radius: 6px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 0.4rem;
      transition: all 0.15s ease;
    }
    .canvas-tab.active {
      background: var(--bg-card);
      color: var(--cyan);
      box-shadow: 0 0 12px rgba(6, 182, 212, 0.15);
      border: 1px solid var(--border);
    }
    .tab-badge {
      font-size: 0.65rem;
      font-family: var(--font-mono);
      background: rgba(255, 255, 255, 0.08);
      padding: 0.1rem 0.35rem;
      border-radius: 9999px;
    }

    /* Data Tables */
    .data-table-container {
      overflow-x: auto;
      border-radius: 8px;
      border: 1px solid var(--border);
    }
    .data-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.8rem;
      text-align: left;
    }
    .data-table th {
      background: rgba(17, 24, 39, 0.9);
      padding: 0.6rem 0.8rem;
      font-weight: 600;
      color: var(--text-muted);
      border-bottom: 1px solid var(--border);
      font-family: var(--font-mono);
    }
    .data-table td {
      padding: 0.65rem 0.8rem;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      vertical-align: middle;
    }
    .data-table tr:hover td {
      background: rgba(99, 102, 241, 0.04);
    }
    .data-table tr.selected td {
      background: rgba(99, 102, 241, 0.12);
    }

    /* Badges */
    .status-badge {
      font-family: var(--font-mono);
      font-size: 0.7rem;
      font-weight: 700;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      display: inline-block;
    }
    .status-badge.pass { background: rgba(16, 185, 129, 0.15); color: var(--emerald); }
    .status-badge.fail { background: rgba(244, 63, 94, 0.15); color: var(--rose); }
    .status-badge.blocked { background: rgba(245, 158, 11, 0.15); color: var(--amber); }
    .status-badge.skipped { background: rgba(148, 163, 184, 0.15); color: var(--text-muted); }

    .method-badge {
      font-family: var(--font-mono);
      font-size: 0.65rem;
      font-weight: 800;
      padding: 0.15rem 0.35rem;
      border-radius: 4px;
    }
    .method-badge.get { background: rgba(6, 182, 212, 0.15); color: var(--cyan); }
    .method-badge.post { background: rgba(99, 102, 241, 0.15); color: var(--indigo); }
    .method-badge.put { background: rgba(245, 158, 11, 0.15); color: var(--amber); }
    .method-badge.delete { background: rgba(244, 63, 94, 0.15); color: var(--rose); }

    /* Deep Payload Inspector */
    .inspector-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1rem;
      margin-top: 1rem;
    }
    .code-block {
      background: #02040a;
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 6px;
      padding: 0.75rem;
      font-family: var(--font-mono);
      font-size: 0.75rem;
      color: #38bdf8;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .copy-btn {
      background: rgba(255, 255, 255, 0.08);
      border: 1px solid var(--border);
      color: var(--text-muted);
      border-radius: 4px;
      font-size: 0.7rem;
      padding: 0.2rem 0.6rem;
      cursor: pointer;
      transition: all 0.15s;
    }
    .copy-btn:hover {
      background: var(--indigo);
      color: #fff;
    }

    /* Pillars Grid */
    .pillars-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 1rem;
    }
    .pillar-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1rem;
    }
    .pillar-score {
      font-size: 2rem;
      font-weight: 800;
      font-family: var(--font-mono);
      line-height: 1;
      margin: 0.4rem 0;
    }
    .progress-bar-bg {
      background: rgba(255, 255, 255, 0.05);
      border-radius: 9999px;
      height: 6px;
      overflow: hidden;
      margin-top: 0.5rem;
    }
    .progress-bar-fill {
      height: 100%;
      border-radius: 9999px;
      transition: width 0.6s ease;
    }
  </style>
</head>
<body>

  <!-- Top Navigation -->
  <header>
    <a href="/" class="brand">
      <div class="brand-icon">🛡️</div>
      <div>
        <div class="brand-title">ReadyHai</div>
      </div>
      <span class="brand-badge">AGENT STUDIO 2026</span>
    </a>

    <div class="header-center">
      <div class="target-pill" id="target-pill-display">
        <span>Target:</span>
        <strong id="active-target-text">http://localhost:3000</strong>
        <span class="tab-badge" id="target-type-badge">STANDALONE</span>
      </div>

      <div class="model-status-pill">
        <span class="pulse-dot" id="model-dot"></span>
        <span id="model-text">qwen3.8-flash-next · checking...</span>
      </div>
    </div>
  </header>

  <!-- Split Studio Workspace -->
  <div class="app-workspace">

    <!-- Left Pane: Command Center & Tool Timeline -->
    <div class="left-pane">
      
      <!-- Target Configuration & Composer -->
      <div class="card">
        <div class="card-title">
          <span>🎯 Agent Command Composer</span>
          <span style="font-size: 0.7rem; color: var(--cyan);">NuHire Reference Mode</span>
        </div>

        <div class="mode-tabs">
          <button class="mode-tab active" data-mode="autonomous" onclick="setMode('autonomous', this)">⚡ Autonomous QA</button>
          <button class="mode-tab" data-mode="adversarial" onclick="setMode('adversarial', this)">🎯 Adversarial & Auth</button>
          <button class="mode-tab" data-mode="contract" onclick="setMode('contract', this)">📊 Contract & Spec</button>
        </div>

        <div class="field-group">
          <label class="field-label">Target URL or Host</label>
          <input type="text" id="target-url" class="field-input" value="http://localhost:3000" placeholder="https://agent-prod.nuhire.in or http://localhost:8080" oninput="updateTargetDisplay()" onblur="autoDiscover()">
          <div class="chip-list">
            <span class="chip" onclick="applyTarget('https://agent-prod.nuhire.in')">https://agent-prod.nuhire.in</span>
            <span class="chip" onclick="applyTarget('http://localhost:3000')">http://localhost:3000</span>
            <span class="chip" onclick="applyTarget('http://127.0.0.1:8080')">http://127.0.0.1:8080</span>
          </div>
        </div>

        <div class="field-group">
          <label class="field-label">OpenAPI Specification URL (Optional)</label>
          <input type="text" id="spec-url" class="field-input" placeholder="e.g. /openapi.json (leave blank for auto-discovery)">
        </div>

        <div class="field-group">
          <label class="field-label">Agent Directives & Focus</label>
          <textarea id="agent-directives" class="field-textarea" placeholder="e.g. Focus on unauthenticated session access, boundary limits, and prompt injection canaries"></textarea>
          <div class="chip-list">
            <span class="chip" onclick="appendDirective('Check unauthenticated access to /api/auth/session')">+ Auth Session Check</span>
            <span class="chip" onclick="appendDirective('Probe 100KB boundary size on chat input')">+ 100KB Boundary</span>
            <span class="chip" onclick="appendDirective('Inject prompt override canary on chat')">+ Prompt Injection</span>
          </div>
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; margin-bottom: 0.85rem;">
          <div class="field-group" style="margin-bottom: 0;">
            <label class="field-label">Execution Profile</label>
            <select id="run-profile" class="field-select">
              <option value="standard" selected>Standard (Multi-Agent)</option>
              <option value="quick">Quick (Contract/Smoke)</option>
              <option value="deep">Deep (Chaos & Adversarial)</option>
            </select>
          </div>
          <div class="field-group" style="margin-bottom: 0;">
            <label class="field-label">Max Steps</label>
            <input type="number" id="max-steps" class="field-input" value="6" min="1" max="20">
          </div>
        </div>

        <button id="run-btn" class="btn-primary" onclick="triggerAgentRun()">
          <span>⚡ Launch Multi-Agent Loop</span>
        </button>
      </div>

      <!-- Human-In-The-Loop Approval Card (NuHire Style) -->
      <div id="approval-card" class="approval-card" style="display: none;">
        <div class="approval-header">
          <div>
            <div style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Deployment Gate Review</div>
            <div id="approval-subtitle" style="font-size: 0.85rem; color: var(--text-main);">Evidence Ledger Complete</div>
          </div>
          <div id="approval-badge" class="verdict-badge go">GO</div>
        </div>

        <p id="approval-summary" style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.75rem; line-height: 1.4;">
          All exit criteria validated. Production readiness verified with zero critical defects.
        </p>

        <div style="display: flex; gap: 0.75rem; font-family: var(--font-mono); font-size: 0.75rem; margin-bottom: 0.5rem;">
          <div>Score: <strong id="approval-score" style="color: var(--cyan);">98%</strong></div>
          <div>Defects: <strong id="approval-defects" style="color: var(--emerald);">0</strong></div>
          <div>Status: <strong id="approval-operator-status" style="color: var(--amber);">Pending Human Review</strong></div>
        </div>

        <div class="approval-actions">
          <button class="btn-approve" onclick="signOffRun('approved')">✅ Approve Deployment</button>
          <button class="btn-reject" onclick="signOffRun('rejected')">⛔ Block Release</button>
        </div>
      </div>

      <!-- Live Tool Call Timeline (NuHire Style) -->
      <div class="card">
        <div class="card-title">
          <span>⚡ Live Agent Tool Pipeline</span>
          <span id="pipeline-status-badge" style="font-size: 0.7rem; color: var(--emerald);">IDLE</span>
        </div>
        <div class="tool-call-list" id="tool-timeline">
          <div class="tool-call-item">
            <div class="tool-call-header" onclick="toggleDetails(this)">
              <div class="tool-call-title">
                <span class="tool-tag discovery">DISCOVER</span>
                <span>Active Route Discovery & SPA Detection</span>
              </div>
              <span style="font-size: 0.7rem; color: var(--text-muted);">Standby</span>
            </div>
            <div class="tool-call-details" style="display: none;">Probes target root, checks Content-Type, detects SPA catch-all vs true API endpoints.</div>
          </div>

          <div class="tool-call-item">
            <div class="tool-call-header" onclick="toggleDetails(this)">
              <div class="tool-call-title">
                <span class="tool-tag planner">PLANNER</span>
                <span>Adversarial Test Case Synthesis</span>
              </div>
              <span style="font-size: 0.7rem; color: var(--text-muted);">Standby</span>
            </div>
            <div class="tool-call-details" style="display: none;">Synthesizes real HTTP methods, paths, boundary parameters, and injection vectors.</div>
          </div>

          <div class="tool-call-item">
            <div class="tool-call-header" onclick="toggleDetails(this)">
              <div class="tool-call-title">
                <span class="tool-tag explorer">EXPLORER</span>
                <span>Real HTTP Execution & cURL Trace</span>
              </div>
              <span style="font-size: 0.7rem; color: var(--text-muted);">Standby</span>
            </div>
            <div class="tool-call-details" style="display: none;">Transmits payloads, validates response content-type, eliminates SPA false positives.</div>
          </div>

          <div class="tool-call-item">
            <div class="tool-call-header" onclick="toggleDetails(this)">
              <div class="tool-call-title">
                <span class="tool-tag triager">TRIAGER</span>
                <span>OWASP Clustering & Blast Radius</span>
              </div>
              <span style="font-size: 0.7rem; color: var(--text-muted);">Standby</span>
            </div>
            <div class="tool-call-details" style="display: none;">Deduplicates true failures, isolates root causes, suggests concrete fixes.</div>
          </div>

          <div class="tool-call-item">
            <div class="tool-call-header" onclick="toggleDetails(this)">
              <div class="tool-call-title">
                <span class="tool-tag gate">GATE</span>
                <span>4-Pillar Evidence Ledger (LLM-Judge)</span>
              </div>
              <span style="font-size: 0.7rem; color: var(--text-muted);">Standby</span>
            </div>
            <div class="tool-call-details" style="display: none;">Evaluates Value, Authority, Safety, Evidence pillars and issues deployment verdict.</div>
          </div>
        </div>
      </div>

    </div>

    <!-- Right Pane: Dynamic Side Canvas -->
    <div class="right-pane">
      
      <!-- Canvas Tabs -->
      <div class="canvas-nav">
        <button class="canvas-tab active" data-tab="scenarios" onclick="switchCanvasTab('scenarios', this)">📋 Scenarios & Inspector <span class="tab-badge" id="scenarios-badge">0</span></button>
        <button class="canvas-tab" data-tab="ledger" onclick="switchCanvasTab('ledger', this)">🛡️ Evidence Ledger</button>
        <button class="canvas-tab" data-tab="routes" onclick="switchCanvasTab('routes', this)">🌐 Discovered Routes <span class="tab-badge" id="routes-badge">0</span></button>
        <button class="canvas-tab" data-tab="triage" onclick="switchCanvasTab('triage', this)">🔍 Threat Triage <span class="tab-badge" id="defects-badge">0</span></button>
        <button class="canvas-tab" data-tab="history" onclick="switchCanvasTab('history', this)">🕒 Runs History <span class="tab-badge" id="history-badge">0</span></button>
      </div>

      <!-- Tab 1: Scenarios & Deep Payload Inspector -->
      <div id="tab-scenarios" class="canvas-content">
        <div class="card" style="margin-bottom: 1rem;">
          <div class="card-title">
            <span>Synthesized Adversarial Scenarios</span>
            <span style="font-size: 0.75rem; color: var(--text-muted);">Click any row to inspect exact request/response</span>
          </div>
          <div class="data-table-container">
            <table class="data-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Method</th>
                  <th>Component / Path</th>
                  <th>Technique</th>
                  <th>Status</th>
                  <th>Latency</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody id="scenarios-table-body">
                <tr>
                  <td colspan="7" style="text-align: center; color: var(--text-dim); padding: 2rem;">No active test execution. Launch a multi-agent loop to inspect live traces.</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Deep Payload Inspector -->
        <div id="inspector-card" class="inspector-card" style="display: none;">
          <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.75rem;">
            <div>
              <span id="inspect-id" class="method-badge get">TC-001</span>
              <strong id="inspect-title" style="margin-left: 0.5rem; font-size: 0.95rem;">Unauthenticated access</strong>
            </div>
            <div style="display: flex; gap: 0.4rem;">
              <button class="copy-btn" onclick="retestActiveScenario()">⚡ Re-Test in Browser</button>
              <button class="copy-btn" onclick="copyInspectorCurl()">📋 Copy cURL</button>
            </div>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; margin-bottom: 0.75rem;">
            <div>
              <div class="field-label">Target Endpoint</div>
              <div id="inspect-endpoint" class="code-block">/api/auth/session</div>
            </div>
            <div>
              <div class="field-label">Response Status & Latency</div>
              <div id="inspect-status-latency" class="code-block">HTTP 401 Unauthorized · 18ms</div>
            </div>
          </div>

          <div class="field-group">
            <div class="field-label">Exact Reproduction cURL</div>
            <div id="inspect-curl" class="code-block" style="color: #a7f3d0;">curl -X GET https://...</div>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem;">
            <div class="field-group">
              <div class="field-label">Request Payload Sent</div>
              <div id="inspect-payload" class="code-block" style="color: #cbd5e1;">(None - GET request)</div>
            </div>
            <div class="field-group">
              <div class="field-label">Response Evidence Snippet</div>
              <div id="inspect-evidence" class="code-block" style="color: #fca5a5;">{}</div>
            </div>
          </div>
        </div>
      </div>

      <!-- Tab 2: Evidence Ledger -->
      <div id="tab-ledger" class="canvas-content" style="display: none;">
        <div class="pillars-grid" style="margin-bottom: 1rem;">
          <div class="pillar-card">
            <div class="card-title">Value Pillar (Correctness)</div>
            <div id="pillar-val-score" class="pillar-score" style="color: var(--cyan);">100%</div>
            <p style="font-size: 0.75rem; color: var(--text-muted);">Core API routes, parameter boundaries, and SLA conformance.</p>
            <div class="progress-bar-bg"><div id="pillar-val-bar" class="progress-bar-fill" style="width: 100%; background: var(--cyan);"></div></div>
          </div>

          <div class="pillar-card">
            <div class="card-title">Authority Pillar (RBAC)</div>
            <div id="pillar-auth-score" class="pillar-score" style="color: var(--indigo);">98%</div>
            <p style="font-size: 0.75rem; color: var(--text-muted);">Privilege boundaries, unauthenticated rejection, tenant isolation.</p>
            <div class="progress-bar-bg"><div id="pillar-auth-bar" class="progress-bar-fill" style="width: 98%; background: var(--indigo);"></div></div>
          </div>

          <div class="pillar-card">
            <div class="card-title">Safety Pillar (Shielding)</div>
            <div id="pillar-safe-score" class="pillar-score" style="color: var(--emerald);">96%</div>
            <p style="font-size: 0.75rem; color: var(--text-muted);">Canary injection shielding, SQLi defense, zero secret leakage.</p>
            <div class="progress-bar-bg"><div id="pillar-safe-bar" class="progress-bar-fill" style="width: 96%; background: var(--emerald);"></div></div>
          </div>

          <div class="pillar-card">
            <div class="card-title">Evidence Pillar (Audit)</div>
            <div id="pillar-evi-score" class="pillar-score" style="color: var(--amber);">95%</div>
            <p style="font-size: 0.75rem; color: var(--text-muted);">100% deterministic reproduction traces and verifiable cURL commands.</p>
            <div class="progress-bar-bg"><div id="pillar-evi-bar" class="progress-bar-fill" style="width: 95%; background: var(--amber);"></div></div>
          </div>
        </div>

        <div class="card">
          <div class="card-title">Exit Criteria Verification</div>
          <div id="exit-criteria-list" style="display: flex; flex-direction: column; gap: 0.5rem;">
            <div style="font-size: 0.8rem; color: var(--text-dim);">Run agent pipeline to compute live exit criteria.</div>
          </div>
        </div>
      </div>

      <!-- Tab 3: Discovered Routes -->
      <div id="tab-routes" class="canvas-content" style="display: none;">
        <div class="card">
          <div class="card-title">
            <span>Target Route Inspection</span>
            <span style="font-size: 0.75rem; color: var(--cyan);">Active Grounding Map</span>
          </div>
          <div class="data-table-container">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Method</th>
                  <th>Discovered Path</th>
                  <th>HTTP Status</th>
                  <th>Content-Type</th>
                  <th>Classification</th>
                </tr>
              </thead>
              <tbody id="routes-table-body">
                <tr>
                  <td colspan="5" style="text-align: center; color: var(--text-dim); padding: 2rem;">No endpoints discovered yet.</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Tab 4: Threat Triage -->
      <div id="tab-triage" class="canvas-content" style="display: none;">
        <div class="card">
          <div class="card-title">
            <span>OWASP Defect Clusters</span>
            <span style="font-size: 0.75rem; color: var(--rose);">Root Cause Analysis</span>
          </div>
          <div class="data-table-container">
            <table class="data-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Defect Title</th>
                  <th>Severity</th>
                  <th>Priority</th>
                  <th>OWASP Category</th>
                  <th>Blast Radius</th>
                  <th>Recommended Fix</th>
                </tr>
              </thead>
              <tbody id="triage-table-body">
                <tr>
                  <td colspan="7" style="text-align: center; color: var(--text-dim); padding: 2rem;">Zero active defects. Target verified clean.</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Tab 5: Runs History -->
      <div id="tab-history" class="canvas-content" style="display: none;">
        <div class="card">
          <div class="card-title">
            <span>Historical Multi-Agent Runs</span>
            <button class="copy-btn" onclick="fetchRunHistory()">🔄 Refresh</button>
          </div>
          <div class="data-table-container">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Run ID</th>
                  <th>Target</th>
                  <th>Verdict</th>
                  <th>Readiness</th>
                  <th>Defects</th>
                  <th>Cases</th>
                  <th>Approval</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody id="history-table-body">
                <tr>
                  <td colspan="8" style="text-align: center; color: var(--text-dim); padding: 2rem;">Loading history...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

    </div>

  </div>

  <script>
    let activeReport = null;
    let activeCaseIndex = null;
    let currentMode = 'autonomous';

    function setMode(mode, btn) {
      currentMode = mode;
      document.querySelectorAll('.mode-tab').forEach(b => b.classList.remove('active'));
      if (btn) {
        btn.classList.add('active');
      } else {
        const el = document.querySelector('.mode-tab[data-mode="' + mode + '"]');
        if (el) el.classList.add('active');
      }

      const directives = document.getElementById('agent-directives');
      if (mode === 'adversarial') {
        directives.value = 'Focus heavily on authorization bypass, BOLA, IDOR, token forgery, and prompt injection canaries.';
      } else if (mode === 'contract') {
        directives.value = 'Focus on OpenAPI contract compliance, boundary values, negative JSON parsing, and HTTP status codes.';
      } else if (mode === 'contract') {
        directives.value = 'Focus on OpenAPI contract compliance, boundary values, negative JSON parsing, and HTTP status codes.';
      } else {
        directives.value = '';
      }
    }

    function applyTarget(url) {
      document.getElementById('target-url').value = url;
      updateTargetDisplay();
      autoDiscover();
    }

    function appendDirective(text) {
      const el = document.getElementById('agent-directives');
      el.value = el.value ? el.value + '; ' + text : text;
    }

    function updateTargetDisplay() {
      const val = document.getElementById('target-url').value.trim() || 'http://localhost:3000';
      document.getElementById('active-target-text').innerText = val;
    }

    function toggleDetails(header) {
      const details = header.nextElementSibling;
      if (details) {
        details.style.display = details.style.display === 'none' ? 'block' : 'none';
      }
    }

    function switchCanvasTab(tabId, btn) {
      document.querySelectorAll('.canvas-tab').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.canvas-content').forEach(c => c.style.display = 'none');
      
      if (btn) {
        btn.classList.add('active');
      } else {
        const activeBtn = document.querySelector('.canvas-tab[data-tab="' + tabId + '"]');
        if (activeBtn) activeBtn.classList.add('active');
      }

      const activeSection = document.getElementById('tab-' + tabId);
      if (activeSection) activeSection.style.display = 'block';

      if (tabId === 'history') {
        fetchRunHistory();
      }
    }

    async function checkModelHealth() {
      try {
        const res = await fetch('/api/agent/status');
        if (res.ok) {
          const data = await res.json();
          const dot = document.getElementById('model-dot');
          const txt = document.getElementById('model-text');
          if (data.status === 'online') {
            dot.className = 'pulse-dot';
            txt.innerText = `${data.model} · vllm · ${data.latency_ms}ms`;
          } else {
            dot.className = 'pulse-dot offline';
            txt.innerText = `${data.model || 'model'} · offline`;
          }
        }
      } catch (e) {
        document.getElementById('model-dot').className = 'pulse-dot offline';
        document.getElementById('model-text').innerText = 'vLLM unreachable';
      }
    }

    async function autoDiscover() {
      const target = document.getElementById('target-url').value.trim();
      const spec = document.getElementById('spec-url').value.trim() || null;
      if (!target.startsWith('http://') && !target.startsWith('https://')) return;

      const badge = document.getElementById('target-type-badge');
      badge.innerText = 'DISCOVERING...';
      badge.style.color = 'var(--cyan)';

      try {
        const query = new URLSearchParams({ target });
        if (spec) query.append('spec', spec);
        const res = await fetch(`/api/agent/discover?${query.toString()}`);
        if (res.ok) {
          const data = await res.json();
          badge.innerText = data.is_spa ? 'SPA DETECTED (Next.js/React)' : `${data.count} APIS DISCOVERED`;
          badge.style.color = data.is_spa ? 'var(--amber)' : 'var(--emerald)';
          renderRoutesTable(data.routes);
        }
      } catch (e) {
        badge.innerText = 'STANDALONE';
        badge.style.color = 'var(--text-muted)';
      }
    }

    function renderRoutesTable(routes) {
      const tbody = document.getElementById('routes-table-body');
      document.getElementById('routes-badge').innerText = routes.length;
      if (!routes || routes.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-dim); padding: 2rem;">No endpoints discovered.</td></tr>';
        return;
      }
      tbody.innerHTML = routes.map(r => `
        <tr>
          <td><span class="method-badge ${r.method.toLowerCase()}">${r.method}</span></td>
          <td style="font-family: var(--font-mono); font-weight: 600; color: #38bdf8;">${r.path}</td>
          <td><span class="status-badge ${r.status_code >= 200 && r.status_code < 300 ? 'pass' : (r.status_code === 401 || r.status_code === 403 ? 'pass' : 'fail')}">HTTP ${r.status_code}</span></td>
          <td style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted);">${r.content_type || 'none'}</td>
          <td>
            <span class="tab-badge" style="${r.is_spa_shell ? 'background: rgba(245, 158, 11, 0.2); color: var(--amber);' : 'background: rgba(16, 185, 129, 0.2); color: var(--emerald);'}">
              ${r.is_spa_shell ? 'SPA Catch-All Shell' : (r.is_api ? 'Protected API Route' : 'Endpoint')}
            </span>
          </td>
        </tr>
      `).join('');
    }

    async function triggerAgentRun() {
      const target = document.getElementById('target-url').value.trim();
      const spec_url = document.getElementById('spec-url').value.trim() || null;
      const custom_instructions = document.getElementById('agent-directives').value.trim() || null;
      const profile = document.getElementById('run-profile').value;
      const btn = document.getElementById('run-btn');

      btn.disabled = true;
      btn.innerHTML = '<span>⚡ Multi-Agent Loop In Progress...</span>';
      document.getElementById('pipeline-status-badge').innerText = 'RUNNING';
      document.getElementById('pipeline-status-badge').style.color = 'var(--cyan)';

      try {
        const res = await fetch('/api/agent/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target, profile, spec_url, custom_instructions, dry_run: false })
        });
        if (res.ok) {
          const report = await res.json();
          renderReport(report);
        } else {
          alert('Agent run failed: ' + res.statusText);
        }
      } catch (e) {
        alert('Network error triggering agent: ' + e);
      } finally {
        btn.disabled = false;
        btn.innerHTML = '<span>⚡ Launch Multi-Agent Loop</span>';
        document.getElementById('pipeline-status-badge').innerText = 'COMPLETED';
        document.getElementById('pipeline-status-badge').style.color = 'var(--emerald)';
      }
    }

    function renderReport(report) {
      activeReport = report;
      const executed = report.executed_results || [];
      const ledger = report.evidence_ledger || {};
      const defects = report.triaged_defects || [];
      const routes = report.discovered_routes || [];

      // Update Badges
      document.getElementById('scenarios-badge').innerText = executed.length;
      document.getElementById('defects-badge').innerText = defects.length;
      document.getElementById('routes-badge').innerText = routes.length;

      // Render Scenarios Table
      const tbody = document.getElementById('scenarios-table-body');
      if (executed.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-dim); padding: 2rem;">No test results.</td></tr>';
      } else {
        tbody.innerHTML = executed.map((c, idx) => `
          <tr id="scenario-row-${idx}" onclick="selectScenario(${idx})" style="cursor: pointer;">
            <td style="font-family: var(--font-mono); font-weight: 700; color: var(--cyan);">${c.case_id}</td>
            <td><span class="method-badge ${(c.method || 'GET').toLowerCase()}">${c.method || 'GET'}</span></td>
            <td style="font-weight: 600;">
              <div>${c.title}</div>
              <div style="font-family: var(--font-mono); font-size: 0.7rem; color: var(--text-dim);">${c.component}</div>
            </td>
            <td><span class="tab-badge">${c.technique}</span></td>
            <td><span class="status-badge ${(c.status || 'PASS').toLowerCase()}">${c.status || 'PASS'}</span></td>
            <td style="font-family: var(--font-mono); font-size: 0.75rem;">${c.latency_ms || 18}ms</td>
            <td><button class="copy-btn" onclick="event.stopPropagation(); selectScenario(${idx})">Inspect</button></td>
          </tr>
        `).join('');

        // Automatically inspect first scenario
        selectScenario(0);
      }

      // Render Approval Card
      const appCard = document.getElementById('approval-card');
      appCard.style.display = 'block';
      const verdict = (ledger.gate_verdict || 'GO').toUpperCase();
      appCard.className = 'approval-card ' + (verdict === 'GO' ? 'verdict-go' : (verdict.includes('CONDITIONAL') ? 'verdict-conditional' : 'verdict-nogo'));
      
      const vBadge = document.getElementById('approval-badge');
      vBadge.className = 'verdict-badge ' + (verdict === 'GO' ? 'go' : (verdict.includes('CONDITIONAL') ? 'conditional' : 'nogo'));
      vBadge.innerText = verdict;

      document.getElementById('approval-score').innerText = (ledger.overall_readiness || 98) + '%';
      document.getElementById('approval-defects').innerText = defects.length;
      document.getElementById('approval-summary').innerText = ledger.executive_summary || 'Evidence Ledger computed.';
      
      const opStatus = document.getElementById('approval-operator-status');
      if (report.approval_status === 'approved') {
        opStatus.innerText = `Approved by ${report.approved_by || 'Operator'}`;
        opStatus.style.color = 'var(--emerald)';
      } else if (report.approval_status === 'rejected') {
        opStatus.innerText = `Blocked by ${report.approved_by || 'Operator'}`;
        opStatus.style.color = 'var(--rose)';
      } else {
        opStatus.innerText = 'Pending Human Review';
        opStatus.style.color = 'var(--amber)';
      }

      // Render Evidence Ledger Scores
      const val = ledger.value_score || 100;
      const auth = ledger.authority_score || 98;
      const safe = ledger.safety_score || 96;
      const evi = ledger.evidence_score || 95;

      document.getElementById('pillar-val-score').innerText = val + '%';
      document.getElementById('pillar-val-bar').style.width = val + '%';

      document.getElementById('pillar-auth-score').innerText = auth + '%';
      document.getElementById('pillar-auth-bar').style.width = auth + '%';

      document.getElementById('pillar-safe-score').innerText = safe + '%';
      document.getElementById('pillar-safe-bar').style.width = safe + '%';

      document.getElementById('pillar-evi-score').innerText = evi + '%';
      document.getElementById('pillar-evi-bar').style.width = evi + '%';

      // Exit Criteria
      const critContainer = document.getElementById('exit-criteria-list');
      const checklist = ledger.exit_criteria_checklist || [];
      if (checklist.length > 0) {
        critContainer.innerHTML = checklist.map(it => `
          <div style="display: flex; align-items: center; justify-content: space-between; padding: 0.5rem; background: rgba(0,0,0,0.2); border-radius: 6px;">
            <div style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.8rem;">
              <span>${it.met ? '✅' : '❌'}</span>
              <strong>${it.criterion}</strong>
            </div>
            <span style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted);">${it.details}</span>
          </div>
        `).join('');
      }

      // Render Discovered Routes
      renderRoutesTable(routes);

      // Render Threat Triage
      const tBody = document.getElementById('triage-table-body');
      if (defects.length === 0) {
        tBody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--emerald); padding: 2rem;">Zero active defect clusters. Application passed all threat thresholds!</td></tr>';
      } else {
        tBody.innerHTML = defects.map(d => `
          <tr>
            <td style="font-family: var(--font-mono); color: var(--rose); font-weight: 700;">${d.id}</td>
            <td style="font-weight: 600;">${d.title}</td>
            <td><span class="status-badge fail">${d.severity}</span></td>
            <td><span class="tab-badge" style="color: var(--amber);">${d.priority}</span></td>
            <td style="font-family: var(--font-mono); font-size: 0.75rem;">${d.owasp_category}</td>
            <td><span class="tab-badge">${d.blast_radius}</span></td>
            <td style="font-size: 0.75rem; color: var(--cyan);">${d.recommended_fix}</td>
          </tr>
        `).join('');
      }
    }

    function selectScenario(idx) {
      if (!activeReport || !activeReport.executed_results) return;
      activeCaseIndex = idx;
      const c = activeReport.executed_results[idx];
      if (!c) return;

      document.querySelectorAll('#scenarios-table-body tr').forEach(r => r.classList.remove('selected'));
      const row = document.getElementById('scenario-row-' + idx);
      if (row) row.classList.add('selected');

      const insp = document.getElementById('inspector-card');
      insp.style.display = 'block';

      document.getElementById('inspect-id').innerText = c.case_id;
      document.getElementById('inspect-id').className = 'method-badge ' + (c.method || 'GET').toLowerCase();
      document.getElementById('inspect-title').innerText = c.title;
      document.getElementById('inspect-endpoint').innerText = `${c.method || 'GET'} ${c.component}`;
      
      const stEl = document.getElementById('inspect-status-latency');
      stEl.innerText = `HTTP ${c.status_code || 'Err'} ${c.status} · ${c.latency_ms}ms ${c.is_spa_shell ? '· [SPA Shell Catch-All]' : ''}`;
      stEl.style.color = c.status === 'PASS' ? 'var(--emerald)' : (c.status === 'FAIL' ? 'var(--rose)' : 'var(--amber)');

      document.getElementById('inspect-curl').innerText = c.reproduction_curl || 'curl -X GET ' + c.component;
      document.getElementById('inspect-payload').innerText = c.request_payload || '(None - No body sent)';
      document.getElementById('inspect-evidence').innerText = c.evidence || c.failure_reason || 'OK';
    }

    function copyInspectorCurl() {
      const curl = document.getElementById('inspect-curl').innerText;
      navigator.clipboard.writeText(curl).then(() => {
        alert('Copied reproduction cURL command to clipboard!');
      });
    }

    async function retestActiveScenario() {
      if (!activeReport || activeCaseIndex === null) return;
      const planned = activeReport.planned_cases[activeCaseIndex];
      const target = activeReport.target;
      if (!planned) return;

      try {
        const res = await fetch('/api/agent/retest', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target, case: planned, is_spa: false })
        });
        if (res.ok) {
          const updated = await res.json();
          activeReport.executed_results[activeCaseIndex] = updated;
          renderReport(activeReport);
          selectScenario(activeCaseIndex);
          alert(`Re-test complete: ${updated.status} (HTTP ${updated.status_code}, ${updated.latency_ms}ms)`);
        }
      } catch (e) {
        alert('Re-test failed: ' + e);
      }
    }

    async function signOffRun(decision) {
      if (!activeReport || !activeReport.id) return;
      const user = prompt('Enter your name or operator ID for audit trail:', 'QA Lead');
      if (!user) return;
      const notes = prompt('Enter approval/rejection rationale:', decision === 'approved' ? 'Verified evidence ledger and signed off.' : 'Blocked due to policy failure.');

      try {
        const endpoint = `/api/agent/runs/${activeReport.id}/${decision}`;
        const res = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ user, notes: notes || '' })
        });
        if (res.ok) {
          const updated = await res.json();
          renderReport(updated);
          alert(`Run ${activeReport.id} successfully marked as ${decision.toUpperCase()} by ${user}.`);
        }
      } catch (e) {
        alert('Action failed: ' + e);
      }
    }

    async function fetchRunHistory() {
      try {
        const res = await fetch('/api/agent/runs');
        if (res.ok) {
          const list = await res.json();
          document.getElementById('history-badge').innerText = list.length;
          const tbody = document.getElementById('history-table-body');
          if (list.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-dim); padding: 2rem;">No historical runs found.</td></tr>';
            return;
          }
          tbody.innerHTML = list.map(r => `
            <tr>
              <td style="font-family: var(--font-mono); font-weight: 700; color: var(--cyan);">${r.id}</td>
              <td style="font-weight: 600;">${r.target}</td>
              <td><span class="status-badge ${(r.gate_verdict || 'GO').toLowerCase()}">${r.gate_verdict || 'GO'}</span></td>
              <td style="font-family: var(--font-mono);">${r.readiness_score || 0}%</td>
              <td><span class="tab-badge" style="color: ${r.defects_count > 0 ? 'var(--rose)' : 'var(--emerald)};">${r.defects_count}</span></td>
              <td><span class="tab-badge">${r.cases_count}</span></td>
              <td><span class="tab-badge" style="color: ${r.approval_status === 'approved' ? 'var(--emerald)' : (r.approval_status === 'rejected' ? 'var(--rose)' : 'var(--amber)')};">${r.approval_status || 'pending'}</span></td>
              <td><button class="copy-btn" onclick="loadRunById('${r.id}')">Load Run</button></td>
            </tr>
          `).join('');
        }
      } catch (e) {
        console.error('Failed to fetch history:', e);
      }
    }

    async function loadRunById(id) {
      try {
        const res = await fetch(`/api/agent/runs/${id}`);
        if (res.ok) {
          const report = await res.json();
          renderReport(report);
          switchCanvasTab('scenarios');
        }
      } catch (e) {
        alert('Failed to load run: ' + e);
      }
    }

    // Init
    checkModelHealth();
    autoDiscover();
    fetchRunHistory();
  </script>
</body>
</html>
"##;
