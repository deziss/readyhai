//! Professional Embedded Web UI for ReadyHai Agentic AI QA & Production Readiness Gate.

pub const HTML_PAGE: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ReadyHai · Autonomous Agentic QA & Production Gate</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-base: #060913;
      --bg-surface: #0b1120;
      --bg-card: #111a2e;
      --bg-card-hover: #16223d;
      --border: rgba(99, 102, 241, 0.18);
      --border-focus: rgba(99, 102, 241, 0.45);
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --indigo: #6366f1;
      --indigo-glow: rgba(99, 102, 241, 0.35);
      --cyan: #06b6d4;
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

    /* Ambient Background Glow */
    .ambient-glow {
      position: fixed;
      top: -150px;
      left: 50%;
      transform: translateX(-50%);
      width: 1000px;
      height: 450px;
      background: radial-gradient(circle, rgba(99, 102, 241, 0.14) 0%, rgba(6, 182, 212, 0.08) 40%, transparent 70%);
      pointer-events: none;
      z-index: 0;
    }

    /* Header Bar */
    header {
      position: sticky;
      top: 0;
      z-index: 50;
      background: rgba(11, 17, 32, 0.85);
      backdrop-filter: blur(14px);
      border-bottom: 1px solid var(--border);
      padding: 0.85rem 2rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      text-decoration: none;
      color: var(--text-main);
    }
    .brand-icon {
      width: 38px;
      height: 38px;
      background: linear-gradient(135deg, var(--indigo), var(--cyan));
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.25rem;
      box-shadow: 0 0 16px var(--indigo-glow);
    }
    .brand-text h1 {
      font-size: 1.25rem;
      font-weight: 800;
      letter-spacing: -0.02em;
      background: linear-gradient(to right, #ffffff, #cbd5e1);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .brand-text span {
      font-size: 0.7rem;
      color: var(--cyan);
      font-family: var(--font-mono);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .header-actions {
      display: flex;
      align-items: center;
      gap: 1.25rem;
    }

    .model-status-pill {
      display: flex;
      align-items: center;
      gap: 0.6rem;
      background: rgba(17, 26, 46, 0.7);
      border: 1px solid var(--border);
      padding: 0.4rem 0.85rem;
      border-radius: 9999px;
      font-size: 0.8rem;
      font-family: var(--font-mono);
      cursor: pointer;
      transition: all 0.2s ease;
    }
    .model-status-pill:hover {
      border-color: var(--cyan);
      box-shadow: 0 0 12px rgba(6, 182, 212, 0.25);
    }
    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--emerald);
      box-shadow: 0 0 8px var(--emerald);
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.5; transform: scale(1.2); }
    }

    /* Main Container & Tabs */
    main {
      flex: 1;
      max-width: 1380px;
      width: 100%;
      margin: 0 auto;
      padding: 1.75rem 2rem 4rem;
      position: relative;
      z-index: 1;
    }

    .nav-tabs {
      display: flex;
      gap: 0.5rem;
      border-bottom: 1px solid var(--border);
      margin-bottom: 2rem;
      padding-bottom: 0.25rem;
    }
    .nav-tab {
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-family: var(--font-sans);
      font-size: 0.9rem;
      font-weight: 500;
      padding: 0.65rem 1.15rem;
      border-radius: 8px;
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .nav-tab:hover {
      color: var(--text-main);
      background: rgba(255, 255, 255, 0.04);
    }
    .nav-tab.active {
      color: #fff;
      background: rgba(99, 102, 241, 0.16);
      border: 1px solid rgba(99, 102, 241, 0.35);
      box-shadow: 0 0 12px var(--indigo-glow);
    }

    .tab-content { display: none; }
    .tab-content.active { display: block; animation: fadeIn 0.3s ease; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }

    /* Cards & Layout */
    .grid-studio {
      display: grid;
      grid-template-columns: 420px 1fr;
      gap: 1.5rem;
      align-items: start;
    }

    .card {
      background: var(--bg-surface);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 1.5rem;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
      position: relative;
      overflow: hidden;
    }
    .card-title {
      font-size: 1.05rem;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 0.5rem;
      margin-bottom: 1.25rem;
      color: #fff;
    }

    /* Form Inputs */
    .form-group {
      margin-bottom: 1.1rem;
    }
    .form-label {
      display: block;
      font-size: 0.78rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--text-muted);
      margin-bottom: 0.4rem;
    }
    .form-input, .form-select, .form-textarea {
      width: 100%;
      background: var(--bg-card);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 8px;
      padding: 0.65rem 0.85rem;
      color: #fff;
      font-family: var(--font-sans);
      font-size: 0.88rem;
      outline: none;
      transition: all 0.2s ease;
    }
    .form-input:focus, .form-select:focus, .form-textarea:focus {
      border-color: var(--indigo);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
    }
    .form-textarea {
      resize: vertical;
      min-height: 80px;
      font-family: var(--font-mono);
      font-size: 0.8rem;
    }

    .quick-chips {
      display: flex;
      flex-wrap: wrap;
      gap: 0.4rem;
      margin-top: 0.5rem;
    }
    .chip {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.08);
      padding: 0.25rem 0.55rem;
      border-radius: 6px;
      font-size: 0.72rem;
      font-family: var(--font-mono);
      color: var(--text-muted);
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .chip:hover {
      background: rgba(99, 102, 241, 0.2);
      border-color: var(--indigo);
      color: #fff;
    }

    .btn-launch {
      width: 100%;
      background: linear-gradient(135deg, var(--indigo) 0%, #4f46e5 100%);
      color: #fff;
      border: none;
      border-radius: 10px;
      padding: 0.85rem 1.5rem;
      font-size: 0.95rem;
      font-weight: 700;
      letter-spacing: -0.01em;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.6rem;
      box-shadow: 0 4px 18px var(--indigo-glow);
      transition: all 0.2s ease;
      margin-top: 1.5rem;
    }
    .btn-launch:hover:not(:disabled) {
      transform: translateY(-2px);
      box-shadow: 0 6px 24px rgba(99, 102, 241, 0.5);
    }
    .btn-launch:disabled {
      opacity: 0.6;
      cursor: not-allowed;
    }

    /* Multi-Agent Pipeline Visualization */
    .agent-pipeline {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 1rem;
      margin-bottom: 1.5rem;
      position: relative;
    }
    .agent-node {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.1rem;
      position: relative;
      transition: all 0.3s ease;
    }
    .agent-node.active {
      border-color: var(--cyan);
      box-shadow: 0 0 16px rgba(6, 182, 212, 0.25);
    }
    .agent-node.done {
      border-color: var(--emerald);
    }
    .agent-node-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 0.6rem;
    }
    .agent-node-icon {
      width: 32px;
      height: 32px;
      border-radius: 8px;
      background: rgba(255, 255, 255, 0.06);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.1rem;
    }
    .agent-node-step {
      font-size: 0.68rem;
      font-family: var(--font-mono);
      color: var(--text-dim);
      font-weight: 600;
    }
    .agent-node-name {
      font-size: 0.88rem;
      font-weight: 700;
      color: #fff;
      margin-bottom: 0.25rem;
    }
    .agent-node-desc {
      font-size: 0.74rem;
      color: var(--text-muted);
      line-height: 1.35;
    }
    .agent-node-badge {
      display: inline-block;
      margin-top: 0.5rem;
      font-size: 0.65rem;
      font-family: var(--font-mono);
      padding: 0.15rem 0.45rem;
      border-radius: 4px;
      background: rgba(255, 255, 255, 0.05);
      color: var(--text-dim);
    }

    /* Terminal Console */
    .terminal {
      background: #050811;
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 12px;
      font-family: var(--font-mono);
      font-size: 0.78rem;
      overflow: hidden;
      margin-top: 1rem;
    }
    .terminal-topbar {
      background: #090e1a;
      padding: 0.5rem 0.85rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    }
    .terminal-dots {
      display: flex;
      gap: 6px;
    }
    .terminal-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
    }
    .dot-red { background: #ef4444; }
    .dot-yellow { background: #eab308; }
    .dot-green { background: #22c55e; }
    .terminal-body {
      padding: 1rem;
      height: 230px;
      overflow-y: auto;
      color: #cbd5e1;
      line-height: 1.6;
    }
    .log-line {
      margin-bottom: 0.35rem;
      word-break: break-all;
    }
    .log-time { color: var(--text-dim); margin-right: 0.5rem; }
    .log-tag { font-weight: 600; margin-right: 0.5rem; }
    .tag-planner { color: var(--indigo); }
    .tag-explorer { color: var(--cyan); }
    .tag-triager { color: var(--amber); }
    .tag-gate { color: var(--emerald); }
    .tag-error { color: var(--rose); }

    /* Production Gate Banner & Evidence Ledger */
    .gate-banner {
      background: linear-gradient(135deg, rgba(17, 26, 46, 0.9) 0%, rgba(11, 17, 32, 0.95) 100%);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 2rem;
      margin-bottom: 2rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 2rem;
      box-shadow: 0 12px 36px rgba(0, 0, 0, 0.4);
    }
    .gate-left {
      flex: 1;
    }
    .verdict-tag {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 1.5rem;
      font-weight: 900;
      letter-spacing: 0.05em;
      padding: 0.4rem 1.25rem;
      border-radius: 9999px;
      margin-bottom: 0.85rem;
      text-transform: uppercase;
    }
    .verdict-go {
      background: rgba(16, 185, 129, 0.15);
      border: 1px solid var(--emerald);
      color: #34d399;
      box-shadow: 0 0 20px var(--emerald-glow);
    }
    .verdict-no-go {
      background: rgba(244, 63, 94, 0.15);
      border: 1px solid var(--rose);
      color: #fb7185;
      box-shadow: 0 0 20px var(--rose-glow);
    }
    .verdict-conditional {
      background: rgba(245, 158, 11, 0.15);
      border: 1px solid var(--amber);
      color: #fbbf24;
      box-shadow: 0 0 20px var(--amber-glow);
    }
    .gate-summary-text {
      font-size: 0.98rem;
      color: #e2e8f0;
      line-height: 1.6;
      max-width: 780px;
    }

    .gate-score-ring {
      width: 140px;
      height: 140px;
      position: relative;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }
    .gate-score-number {
      font-size: 2.2rem;
      font-weight: 800;
      color: #fff;
      font-family: var(--font-mono);
    }
    .gate-score-label {
      font-size: 0.65rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-muted);
      position: absolute;
      bottom: 25px;
    }

    /* 4-Pillar Scorecards */
    .grid-pillars {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 1.25rem;
      margin-bottom: 2rem;
    }
    .pillar-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.25rem;
      position: relative;
      overflow: hidden;
      transition: all 0.2s ease;
    }
    .pillar-card:hover {
      transform: translateY(-2px);
      border-color: rgba(99, 102, 241, 0.4);
    }
    .pillar-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 0.75rem;
    }
    .pillar-title {
      font-size: 0.85rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--text-muted);
    }
    .pillar-score {
      font-size: 1.75rem;
      font-weight: 800;
      color: #fff;
      font-family: var(--font-mono);
    }
    .pillar-bar-bg {
      height: 6px;
      width: 100%;
      background: rgba(255, 255, 255, 0.08);
      border-radius: 9999px;
      overflow: hidden;
      margin-top: 0.75rem;
    }
    .pillar-bar-fill {
      height: 100%;
      border-radius: 9999px;
      transition: width 0.6s ease;
    }

    /* Tables & Lists */
    .custom-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
      margin-top: 0.5rem;
    }
    .custom-table th {
      text-align: left;
      padding: 0.75rem 1rem;
      background: rgba(255, 255, 255, 0.03);
      color: var(--text-dim);
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      border-bottom: 1px solid var(--border);
    }
    .custom-table td {
      padding: 0.85rem 1rem;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
      color: #cbd5e1;
    }
    .custom-table tr:hover td {
      background: rgba(255, 255, 255, 0.02);
    }

    .badge-pass {
      background: rgba(16, 185, 129, 0.15);
      border: 1px solid rgba(16, 185, 129, 0.4);
      color: #34d399;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.72rem;
      font-family: var(--font-mono);
      font-weight: 600;
    }
    .badge-fail {
      background: rgba(244, 63, 94, 0.15);
      border: 1px solid rgba(244, 63, 94, 0.4);
      color: #fb7185;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.72rem;
      font-family: var(--font-mono);
      font-weight: 600;
    }

    .code-box {
      background: #040711;
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 8px;
      padding: 0.75rem;
      font-family: var(--font-mono);
      font-size: 0.75rem;
      color: #a5b4fc;
      overflow-x: auto;
      margin-top: 0.5rem;
    }

    /* Modal / Drawer */
    .modal-backdrop {
      display: none;
      position: fixed;
      top: 0; left: 0; width: 100%; height: 100%;
      background: rgba(0, 0, 0, 0.75);
      backdrop-filter: blur(8px);
      z-index: 100;
      align-items: center;
      justify-content: center;
    }
    .modal-card {
      background: var(--bg-surface);
      border: 1px solid var(--border-focus);
      border-radius: 16px;
      width: 90%;
      max-width: 680px;
      padding: 2rem;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.6);
    }
  </style>
</head>
<body>
  <div class="ambient-glow"></div>

  <!-- Header -->
  <header>
    <a href="#" class="brand" id="brand-logo">
      <div class="brand-icon">🛡️</div>
      <div class="brand-text">
        <h1>ReadyHai</h1>
        <span>Agentic QA & Production Gate</span>
      </div>
    </a>

    <div class="header-actions">
      <div class="model-status-pill" id="model-pill" title="Click to test model ping">
        <span class="status-dot"></span>
        <span id="model-name">qwen3.8-flash-next</span>
        <span style="color:var(--text-dim);">·</span>
        <span id="model-latency" style="color:var(--cyan);">14ms</span>
      </div>
    </div>
  </header>

  <!-- Navigation Tabs -->
  <main>
    <nav class="nav-tabs">
      <button class="nav-tab active" id="tab-studio-btn" onclick="switchTab('studio')">
        <span>⚡</span> Agent Studio
      </button>
      <button class="nav-tab" id="tab-gate-btn" onclick="switchTab('gate')">
        <span>🛡️</span> Production Gate
      </button>
      <button class="nav-tab" id="tab-cases-btn" onclick="switchTab('cases')">
        <span>📋</span> Test Scenarios
      </button>
      <button class="nav-tab" id="tab-defects-btn" onclick="switchTab('defects')">
        <span>🔍</span> Threat Triage
      </button>
      <button class="nav-tab" id="tab-history-btn" onclick="switchTab('history')">
        <span>🕒</span> Runs History
      </button>
    </nav>

    <!-- TAB 1: AGENT STUDIO -->
    <section id="tab-studio" class="tab-content active">
      <div class="grid-studio">
        <!-- Configuration Card -->
        <div class="card">
          <div class="card-title">
            <span>🎯</span> Target Configuration
          </div>

          <div class="form-group">
            <label class="form-label">Target URL or Codebase</label>
            <input type="text" class="form-input" id="target-input" value="http://127.0.0.1:8080" placeholder="e.g. http://127.0.0.1:8080 or ./services/api">
            <div class="quick-chips">
              <span class="chip" onclick="setTarget('http://127.0.0.1:8080')">Local Server</span>
              <span class="chip" onclick="setTarget('tests/fixtures/qa-api')">QA Fixture</span>
              <span class="chip" onclick="setTarget('https://api.staging.nuhire.in')">Staging API</span>
            </div>
          </div>

          <div class="form-group">
            <label class="form-label">Execution Profile</label>
            <select class="form-select" id="profile-select">
              <option value="quick">Quick (Contract & Smoke)</option>
              <option value="standard" selected>Standard (Full Multi-Agent QA)</option>
              <option value="deep">Deep (Adversarial Stress & Injection)</option>
            </select>
          </div>

          <div class="form-group">
            <label class="form-label">OpenAPI Specification (Optional)</label>
            <input type="text" class="form-input" id="spec-input" placeholder="e.g. openapi.json or https://app/api-docs">
          </div>

          <div class="form-group">
            <label class="form-label">Custom Agent Guidance (Optional)</label>
            <textarea class="form-textarea" id="instructions-input" placeholder="e.g. Probe authentication bypass on /runs and evaluate input boundary limits"></textarea>
          </div>

          <button class="btn-launch" id="run-agent-btn" onclick="launchAgentRun()">
            <span>⚡</span> Launch Autonomous Agent Loop
          </button>
        </div>

        <!-- Right Side: Pipeline Flow & Live Trace -->
        <div>
          <!-- Visual Pipeline -->
          <div class="agent-pipeline">
            <div class="agent-node" id="node-planner">
              <div class="agent-node-header">
                <div class="agent-node-icon">🧠</div>
                <span class="agent-node-step">01</span>
              </div>
              <div class="agent-node-name">Planner Agent</div>
              <div class="agent-node-desc">Synthesizes boundary cases & attack vectors.</div>
              <span class="agent-node-badge" id="badge-planner">Idle</span>
            </div>

            <div class="agent-node" id="node-explorer">
              <div class="agent-node-header">
                <div class="agent-node-icon">⚡</div>
                <span class="agent-node-step">02</span>
              </div>
              <div class="agent-node-name">Explorer Agent</div>
              <div class="agent-node-desc">Executes probes & records HTTP traces.</div>
              <span class="agent-node-badge" id="badge-explorer">Idle</span>
            </div>

            <div class="agent-node" id="node-triager">
              <div class="agent-node-header">
                <div class="agent-node-icon">🔍</div>
                <span class="agent-node-step">03</span>
              </div>
              <div class="agent-node-name">Triager Agent</div>
              <div class="agent-node-desc">Clusters root causes & OWASP risks.</div>
              <span class="agent-node-badge" id="badge-triager">Idle</span>
            </div>

            <div class="agent-node" id="node-gate">
              <div class="agent-node-header">
                <div class="agent-node-icon">🛡️</div>
                <span class="agent-node-step">04</span>
              </div>
              <div class="agent-node-name">Readiness Gate</div>
              <div class="agent-node-desc">LLM-as-a-Judge Evidence Ledger evaluation.</div>
              <span class="agent-node-badge" id="badge-gate">Idle</span>
            </div>
          </div>

          <!-- Terminal -->
          <div class="card" style="padding: 1.25rem;">
            <div class="card-title" style="margin-bottom: 0.75rem;">
              <span>📟</span> Live Agent Execution Trace
            </div>
            <div class="terminal">
              <div class="terminal-topbar">
                <div class="terminal-dots">
                  <span class="terminal-dot dot-red"></span>
                  <span class="terminal-dot dot-yellow"></span>
                  <span class="terminal-dot dot-green"></span>
                </div>
                <span style="color:var(--text-dim); font-size:0.7rem;">agentic-loop.log · vllm @ qwen3.8-flash-next</span>
              </div>
              <div class="terminal-body" id="terminal-body">
                <div class="log-line"><span class="log-time">[Ready]</span> <span class="log-tag tag-gate">System:</span> ReadyHai Agentic Engine initialized. Ready for task dispatch.</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- TAB 2: PRODUCTION GATE DASHBOARD -->
    <section id="tab-gate" class="tab-content">
      <!-- Verdict Banner -->
      <div class="gate-banner">
        <div class="gate-left">
          <div class="verdict-tag verdict-go" id="gate-verdict-tag">
            <span id="verdict-icon">✓</span>
            <span id="verdict-text">GO (Production Ready)</span>
          </div>
          <p class="gate-summary-text" id="gate-summary-text">
            Evidence Ledger compiled across Value, Authority, Safety, and Evidence pillars. Zero critical defects detected; all automated boundary and authz checks satisfied.
          </p>
        </div>
        <div class="gate-score-ring">
          <svg width="140" height="140">
            <circle cx="70" cy="70" r="58" stroke="rgba(255,255,255,0.08)" stroke-width="12" fill="none"></circle>
            <circle cx="70" cy="70" r="58" id="gate-circle" stroke="var(--emerald)" stroke-width="12" fill="none"
                    stroke-dasharray="364.4" stroke-dashoffset="20" stroke-linecap="round"
                    transform="rotate(-90 70 70)"></circle>
          </svg>
          <div class="gate-score-number" id="gate-score-number">98%</div>
          <span class="gate-score-label">Readiness</span>
        </div>
      </div>

      <!-- 4 Pillars -->
      <div class="grid-pillars">
        <div class="pillar-card">
          <div class="pillar-header">
            <span class="pillar-title">Value Pillar</span>
            <span>💎</span>
          </div>
          <div class="pillar-score" id="pillar-value">100%</div>
          <p style="font-size:0.75rem; color:var(--text-muted); margin-top:0.25rem;">Contract & API Conformance</p>
          <div class="pillar-bar-bg"><div class="pillar-bar-fill" id="bar-value" style="width:100%; background:var(--cyan);"></div></div>
        </div>

        <div class="pillar-card">
          <div class="pillar-header">
            <span class="pillar-title">Authority Pillar</span>
            <span>🔑</span>
          </div>
          <div class="pillar-score" id="pillar-authority">98%</div>
          <p style="font-size:0.75rem; color:var(--text-muted); margin-top:0.25rem;">RBAC & Agency Boundaries</p>
          <div class="pillar-bar-bg"><div class="pillar-bar-fill" id="bar-authority" style="width:98%; background:var(--indigo);"></div></div>
        </div>

        <div class="pillar-card">
          <div class="pillar-header">
            <span class="pillar-title">Safety Pillar</span>
            <span>🛡️</span>
          </div>
          <div class="pillar-score" id="pillar-safety">96%</div>
          <p style="font-size:0.75rem; color:var(--text-muted); margin-top:0.25rem;">Zero Leaks & Prompt Barrier</p>
          <div class="pillar-bar-bg"><div class="pillar-bar-fill" id="bar-safety" style="width:96%; background:var(--emerald);"></div></div>
        </div>

        <div class="pillar-card">
          <div class="pillar-header">
            <span class="pillar-title">Evidence Pillar</span>
            <span>📑</span>
          </div>
          <div class="pillar-score" id="pillar-evidence">95%</div>
          <p style="font-size:0.75rem; color:var(--text-muted); margin-top:0.25rem;">Audit Trail & Traces</p>
          <div class="pillar-bar-bg"><div class="pillar-bar-fill" id="bar-evidence" style="width:95%; background:var(--amber);"></div></div>
        </div>
      </div>

      <!-- Exit Checklist Card -->
      <div class="card">
        <div class="card-title">
          <span>✅</span> Release Exit Criteria Checklist
        </div>
        <table class="custom-table" id="checklist-table">
          <thead>
            <tr>
              <th>Criterion</th>
              <th>Status</th>
              <th>Audit Notes</th>
            </tr>
          </thead>
          <tbody id="checklist-tbody">
            <tr>
              <td>Zero P1/Critical Defects</td>
              <td><span class="badge-pass">MET</span></td>
              <td>0 critical defects detected</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- TAB 3: TEST SCENARIOS -->
    <section id="tab-cases" class="tab-content">
      <div class="card">
        <div class="card-title">
          <span>📋</span> AI-Synthesized Test Scenarios & Execution Results
        </div>
        <table class="custom-table" id="cases-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Test Scenario Title</th>
              <th>Component</th>
              <th>Technique</th>
              <th>Status</th>
              <th>Latency</th>
              <th>Curl Reproduction</th>
            </tr>
          </thead>
          <tbody id="cases-tbody">
            <!-- Dynamically populated -->
          </tbody>
        </table>
      </div>
    </section>

    <!-- TAB 4: THREAT TRIAGE -->
    <section id="tab-defects" class="tab-content">
      <div class="card">
        <div class="card-title">
          <span>🔍</span> Autonomous Threat Triage & Root Cause Hypotheses
        </div>
        <div id="defects-container">
          <p style="color:var(--text-dim); font-size:0.88rem; padding: 1rem 0;">No active defect clusters detected. The target passed all evaluated edge cases.</p>
        </div>
      </div>
    </section>

    <!-- TAB 5: RUNS HISTORY -->
    <section id="tab-history" class="tab-content">
      <div class="card">
        <div class="card-title">
          <span>🕒</span> Historical Agentic & Production Gate Runs
        </div>
        <table class="custom-table">
          <thead>
            <tr>
              <th>Run ID</th>
              <th>Target</th>
              <th>Started</th>
              <th>Score</th>
              <th>Gate Verdict</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="history-tbody">
            <!-- Dynamically populated -->
          </tbody>
        </table>
      </div>
    </section>
  </main>

  <script>
    let activeRunId = null;
    let currentReport = null;

    function switchTab(tabId) {
      document.querySelectorAll('.nav-tab').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      document.getElementById('tab-' + tabId + '-btn').classList.add('active');
      document.getElementById('tab-' + tabId).classList.add('active');
      if (tabId === 'history') loadHistory();
    }

    function setTarget(t) {
      document.getElementById('target-input').value = t;
    }

    function appendLog(time, tag, text, tagClass) {
      const b = document.getElementById('terminal-body');
      const div = document.createElement('div');
      div.className = 'log-line';
      div.innerHTML = `<span class="log-time">[${time}]</span> <span class="log-tag ${tagClass}">${tag}:</span> ${text}`;
      b.appendChild(div);
      b.scrollTop = b.scrollHeight;
    }

    async function checkModelStatus() {
      try {
        const res = await fetch('/api/agent/status');
        const data = await res.json();
        if (data.status === 'online') {
          document.getElementById('model-name').textContent = data.model;
          document.getElementById('model-latency').textContent = data.latency_ms + 'ms';
          document.getElementById('model-pill').title = `Connected to ${data.provider} @ ${data.base_url}`;
        }
      } catch (e) {
        document.getElementById('model-name').textContent = 'qwen3.8-flash-next';
        document.getElementById('model-latency').textContent = 'local';
      }
    }

    async function launchAgentRun() {
      const btn = document.getElementById('run-agent-btn');
      btn.disabled = true;
      btn.innerHTML = `<span>⏳</span> Running Multi-Agent Loop...`;

      // Reset node styles
      ['planner', 'explorer', 'triager', 'gate'].forEach(n => {
        const el = document.getElementById('node-' + n);
        el.className = 'agent-node';
        document.getElementById('badge-' + n).textContent = 'Running...';
      });

      document.getElementById('node-planner').classList.add('active');
      appendLog(new Date().toLocaleTimeString(), 'Planner', 'Synthesizing boundary, negative, and threat scenarios with qwen3.8-flash-next...', 'tag-planner');

      const payload = {
        target: document.getElementById('target-input').value,
        profile: document.getElementById('profile-select').value,
        spec_url: document.getElementById('spec-input').value || null,
        custom_instructions: document.getElementById('instructions-input').value || null
      };

      try {
        const res = await fetch('/api/agent/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const rep = await res.json();
        currentReport = rep;
        renderReport(rep);
      } catch (err) {
        appendLog(new Date().toLocaleTimeString(), 'Error', err.message, 'tag-error');
      } finally {
        btn.disabled = false;
        btn.innerHTML = `<span>⚡</span> Launch Autonomous Agent Loop`;
      }
    }

    function renderReport(rep) {
      // 1. Terminal log steps
      if (rep.steps) {
        rep.steps.forEach(s => {
          let tagClass = 'tag-planner';
          if (s.agent === 'Explorer') tagClass = 'tag-explorer';
          if (s.agent === 'Triager') tagClass = 'tag-triager';
          if (s.agent === 'ReadinessGate') tagClass = 'tag-gate';
          appendLog(s.timestamp.slice(11, 19), s.agent, s.details, tagClass);
        });
      }

      // 2. Complete nodes
      ['planner', 'explorer', 'triager', 'gate'].forEach(n => {
        const el = document.getElementById('node-' + n);
        el.className = 'agent-node done';
        document.getElementById('badge-' + n).textContent = 'Done ✓';
      });

      // 3. Render Gate Dashboard
      if (rep.evidence_ledger) {
        const el = rep.evidence_ledger;
        const vTag = document.getElementById('gate-verdict-tag');
        const vText = document.getElementById('verdict-text');
        vText.textContent = el.gate_verdict + (el.gate_verdict === 'GO' ? ' (Production Ready)' : ' (Release Blocked)');
        vTag.className = 'verdict-tag ' + (el.gate_verdict === 'GO' ? 'verdict-go' : (el.gate_verdict === 'NO-GO' ? 'verdict-no-go' : 'verdict-conditional'));
        document.getElementById('gate-summary-text').textContent = el.executive_summary;

        // Score ring
        document.getElementById('gate-score-number').textContent = el.overall_readiness + '%';
        const offset = 364.4 - (364.4 * (el.overall_readiness / 100));
        document.getElementById('gate-circle').style.strokeDashoffset = offset;

        // Pillars
        document.getElementById('pillar-value').textContent = el.value_score + '%';
        document.getElementById('bar-value').style.width = el.value_score + '%';

        document.getElementById('pillar-authority').textContent = el.authority_score + '%';
        document.getElementById('bar-authority').style.width = el.authority_score + '%';

        document.getElementById('pillar-safety').textContent = el.safety_score + '%';
        document.getElementById('bar-safety').style.width = el.safety_score + '%';

        document.getElementById('pillar-evidence').textContent = el.evidence_score + '%';
        document.getElementById('bar-evidence').style.width = el.evidence_score + '%';

        // Checklist
        const tbody = document.getElementById('checklist-tbody');
        tbody.innerHTML = '';
        el.exit_criteria_checklist.forEach(c => {
          const tr = document.createElement('tr');
          tr.innerHTML = `
            <td style="font-weight:600;">${c.criterion}</td>
            <td><span class="${c.met ? 'badge-pass' : 'badge-fail'}">${c.met ? 'MET' : 'BLOCKED'}</span></td>
            <td>${c.details}</td>
          `;
          tbody.appendChild(tr);
        });
      }

      // 4. Test Scenarios Table
      const cBody = document.getElementById('cases-tbody');
      cBody.innerHTML = '';
      if (rep.executed_results) {
        rep.executed_results.forEach(c => {
          const tr = document.createElement('tr');
          tr.innerHTML = `
            <td style="font-family:var(--font-mono); font-weight:700;">${c.case_id}</td>
            <td><strong>${c.title}</strong></td>
            <td style="font-family:var(--font-mono); color:var(--cyan);">${c.component}</td>
            <td><span style="font-size:0.72rem; padding:0.15rem 0.4rem; border-radius:4px; background:rgba(255,255,255,0.06);">${c.technique}</span></td>
            <td><span class="${c.status === 'PASS' ? 'badge-pass' : 'badge-fail'}">${c.status}</span></td>
            <td style="font-family:var(--font-mono);">${c.latency_ms}ms</td>
            <td><div class="code-box">${c.reproduction_curl}</div></td>
          `;
          cBody.appendChild(tr);
        });
      }

      // 5. Threat Triage
      const dContainer = document.getElementById('defects-container');
      if (rep.triaged_defects && rep.triaged_defects.length > 0) {
        dContainer.innerHTML = '';
        rep.triaged_defects.forEach(d => {
          const div = document.createElement('div');
          div.className = 'card';
          div.style.marginBottom = '1rem';
          div.innerHTML = `
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
              <span style="font-weight:700; color:#fb7185; font-size:1rem;">${d.id}: ${d.title}</span>
              <span class="badge-fail">${d.severity.toUpperCase()} · ${d.priority}</span>
            </div>
            <p style="font-size:0.85rem; color:var(--text-muted); margin-bottom:0.5rem;"><strong>OWASP:</strong> ${d.owasp_category} · <strong>Blast Radius:</strong> ${d.blast_radius}</p>
            <p style="font-size:0.85rem; color:#e2e8f0; margin-bottom:0.5rem;"><strong>Hypothesis:</strong> ${d.root_cause_hypothesis}</p>
            <div class="code-box"><strong>Fix Recommendation:</strong><br>${d.recommended_fix}</div>
          `;
          dContainer.appendChild(div);
        });
      } else {
        dContainer.innerHTML = '<p style="color:var(--emerald); font-size:0.9rem; padding:1rem 0;">✓ Zero defect clusters detected. All evaluated test flows passed validation.</p>';
      }
    }

    async function loadHistory() {
      try {
        const res = await fetch('/api/agent/runs');
        const list = await res.json();
        const tbody = document.getElementById('history-tbody');
        tbody.innerHTML = '';
        list.forEach(r => {
          const tr = document.createElement('tr');
          tr.innerHTML = `
            <td style="font-family:var(--font-mono); font-weight:700;">${r.id}</td>
            <td>${r.target}</td>
            <td style="color:var(--text-dim);">${r.started_at.slice(0,19).replace('T', ' ')}</td>
            <td style="font-family:var(--font-mono); font-weight:700; color:var(--cyan);">${r.readiness_score !== null ? r.readiness_score + '%' : '-'}</td>
            <td><span class="${r.gate_verdict === 'GO' ? 'badge-pass' : 'badge-fail'}">${r.gate_verdict || 'RUNNING'}</span></td>
            <td><button class="chip" onclick="loadRunReport('${r.id}')">View Report</button></td>
          `;
          tbody.appendChild(tr);
        });
      } catch (e) {
        console.error(e);
      }
    }

    async function loadRunReport(id) {
      try {
        const res = await fetch('/api/agent/runs/' + id);
        const data = await res.json();
        currentReport = data;
        renderReport(data);
        switchTab('gate');
      } catch (e) {
        alert('Failed to load report: ' + e.message);
      }
    }

    // Initialize on load
    window.addEventListener('DOMContentLoaded', () => {
      checkModelStatus();
      setInterval(checkModelStatus, 10000);
      document.getElementById('model-pill').addEventListener('click', checkModelStatus);
    });
  </script>
</body>
</html>
"##;
