// Senior-QA UI exploratory runner. usage: node qa.mjs [/out/qa-ui-input.json]
// Input : {base_url,max_pages,modes[],viewports[],nonprod,roles[],journeys[],visual_baseline_dir,axe}
// Output: /out/qa-ui.json (+ /out/shots, /out/traces). Forms are only exercised when nonprod=true.
// Mode `discover` (exclusive; used by the agent's discovery): navigate the start URL and up to
// max_pages same-origin links (GET only, no clicks, no form submits) and record every fetch/XHR
// request the app makes: method, URL template, status, content type, JSON top-level key NAMES of
// request and response. Values, cookies and Authorization are never recorded.
// Input : {base_url,modes:["discover"],max_pages,max_requests,deadline_ms,writes,allowed_hosts[]}
// Output: /out/xhr.json
import { chromium } from 'playwright';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';

const OUT = process.env.QA_OUT || '/out';
const inputPath = process.argv[2] || `${OUT}/qa-ui-input.json`;
const input = JSON.parse(readFileSync(inputPath, 'utf8'));
const deadline = Date.now() + (input.deadline_ms || 10 * 60 * 1000);
const expired = () => Date.now() > deadline;
const modes = new Set(input.modes || ['crawl']);
const base = new URL(input.base_url);
const origin = base.origin;
const maxPages = Math.max(1, input.max_pages || 20);
const nonprod = input.nonprod === true;
const NAV_TIMEOUT = 20000;
const trunc = (s, n = 300) => String(s ?? '').slice(0, n);
const norm = (u) => { try { const x = new URL(u); x.hash = ''; return x.href; } catch { return null; } };
const VIEWPORTS = (input.viewports?.length ? input.viewports : [[375, 812], [768, 1024], [1366, 768]]).map((v) =>
  Array.isArray(v) ? { width: v[0], height: v[1] } : { width: v.width ?? v.w, height: v.height ?? v.h });
const DANGER = /logout|log-out|signout|delete|remove|destroy|\bpay\b|payment|checkout|purchase|unsubscribe/i;

// ---------------------------------------------------------------- discover mode (XHR capture)
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const ASSET_EXT = /\.(?:png|jpe?g|gif|svg|ico|webp|avif|css|js|mjs|map|woff2?|ttf|eot|mp4|mp3|pdf|zip|gz)(?:$|\?)/i;
const UUID_SEG = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// numeric ids, uuids and long hex/base64-ish tokens are templated so one endpoint is one entry
function templatePath(pathname) {
  return pathname.split('/').map((seg) => {
    if (!seg) return seg;
    if (/^\d+$/.test(seg)) return '{id}';
    if (UUID_SEG.test(seg)) return '{uuid}';
    if (/^[0-9a-f]{16,}$/i.test(seg)) return '{hash}';
    if (seg.length >= 20 && /^[A-Za-z0-9_-]+$/.test(seg) && /\d/.test(seg)) return '{token}';
    return seg;
  }).join('/');
}
// top-level key names of a JSON text (object keys, or the keys of the first element of an array); never values
function jsonKeys(text) {
  try {
    let v = JSON.parse(text);
    if (Array.isArray(v)) v = v.find((x) => x && typeof x === 'object' && !Array.isArray(x));
    return v && typeof v === 'object' ? Object.keys(v).slice(0, 30).map((k) => trunc(k, 60)) : [];
  } catch { return []; }
}

async function discoverMode() {
  const maxLinks = Math.min(Math.max(1, input.max_pages || 8), 20);
  const maxReq = Math.min(Math.max(1, input.max_requests || 200), 200);
  const allowWrites = input.writes === true;
  const allowedHosts = new Set((input.allowed_hosts || []).map((h) => String(h).toLowerCase()));
  const dl = Date.now() + Math.min(input.deadline_ms || 60000, 120000);
  const left = () => dl - Date.now();
  const rep = { base_url: input.base_url, mode: 'discover', pages: [], requests: [], other_hosts: [], notes: [] };
  const entries = new Map(); // "METHOD templated-path" -> entry
  const others = new Map(); // host -> count
  let total = 0;

  const flush = () => {
    rep.requests = [...entries.values()];
    rep.other_hosts = [...others.entries()].map(([host, count]) => ({ host, count }));
    writeFileSync(`${OUT}/xhr.json`, JSON.stringify(rep, null, 2));
  };
  // a hung page must not lose what was seen: write the partial report and leave
  const watchdog = setTimeout(() => { rep.notes.push('watchdog: deadline exceeded, report is partial'); flush(); process.exit(0); }, left() + 20000);
  const browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu'] });
  const c = await browser.newContext({ viewport: { width: 1280, height: 800 }, ignoreHTTPSErrors: true });
  c.setDefaultNavigationTimeout(15000);
  c.setDefaultTimeout(15000);

  const keyOf = (req) => `${req.method().toUpperCase()} ${templatePath(new URL(req.url()).pathname)}`;
  const entryFor = (req) => {
    const u = new URL(req.url());
    const method = req.method().toUpperCase();
    const tpl = templatePath(u.pathname);
    const key = keyOf(req);
    let e = entries.get(key);
    if (!e) {
      if (entries.size >= 200) return null;
      e = { method, path: tpl, sample_path: u.pathname.slice(0, 300), query_keys: [], status: 0, content_type: '',
            req_keys: [], res_keys: [], has_auth: false, blocked: false, count: 0 };
      entries.set(key, e);
    }
    e.count++;
    for (const k of u.searchParams.keys()) if (e.query_keys.length < 20 && !e.query_keys.includes(k)) e.query_keys.push(trunc(k, 60));
    const h = req.headers();
    if (h.authorization) e.has_auth = true; // the value is never read into the report
    const body = req.postData();
    if (body && /json/i.test(h['content-type'] || '')) for (const k of jsonKeys(body)) if (e.req_keys.length < 30 && !e.req_keys.includes(k)) e.req_keys.push(k);
    return e;
  };

  // The safety net: only the target origin (and hosts scope.toml lists) are ever contacted; other hosts
  // are recorded by name and aborted. A non-GET request is let through only on a nonprod, non-dry run.
  await c.route('**/*', async (route) => {
    const req = route.request();
    const url = req.url();
    if (url.startsWith('data:') || url.startsWith('blob:')) return route.continue();
    let u;
    try { u = new URL(url); } catch { return route.abort(); }
    const type = req.resourceType();
    const isApiCall = type === 'fetch' || type === 'xhr';
    const sameOrigin = u.origin === origin;
    if (!sameOrigin && !allowedHosts.has(u.hostname.toLowerCase())) {
      if (isApiCall) others.set(u.hostname.toLowerCase(), (others.get(u.hostname.toLowerCase()) || 0) + 1);
      return route.abort();
    }
    if (isApiCall) {
      if (total >= maxReq) return route.abort();
      if (sameOrigin) {
        const e = entryFor(req);
        if (e && !SAFE_METHODS.has(req.method().toUpperCase()) && !allowWrites) { e.blocked = true; return route.abort(); }
      }
    } else if (!SAFE_METHODS.has(req.method().toUpperCase()) && !allowWrites) {
      return route.abort(); // a page form post or beacon: navigation only
    }
    total++;
    return route.continue();
  });

  const onResponse = async (resp) => {
    try {
      const req = resp.request();
      const type = req.resourceType();
      if ((type !== 'fetch' && type !== 'xhr') || new URL(req.url()).origin !== origin) return;
      const e = entries.get(keyOf(req));
      if (!e) return;
      e.status = resp.status();
      const ct = resp.headers()['content-type'] || '';
      e.content_type = trunc(ct.split(';')[0].trim(), 80);
      if (/json/i.test(ct) && resp.status() !== 204 && !(resp.status() >= 300 && resp.status() < 400)) {
        const len = Number(resp.headers()['content-length'] || 0);
        if (!len || len < 512 * 1024) {
          const text = await resp.text().catch(() => '');
          for (const k of jsonKeys(text)) if (e.res_keys.length < 30 && !e.res_keys.includes(k)) e.res_keys.push(k);
        }
      }
    } catch { /* a response that cannot be read is simply not described */ }
  };

  const queue = [norm(input.base_url)];
  const seen = new Set(queue);
  while (queue.length && rep.pages.length < maxLinks && left() > 3000) {
    const url = queue.shift();
    const page = await c.newPage();
    page.on('response', onResponse);
    const rec = { url: trunc(url, 300), path: new URL(url).pathname + new URL(url).search, status: 0 };
    try {
      const resp = await page.goto(url, { waitUntil: 'load', timeout: Math.min(15000, left()) });
      rec.status = resp ? resp.status() : 0;
      await page.waitForLoadState('networkidle', { timeout: Math.min(4000, Math.max(500, left())) }).catch(() => {});
      await page.waitForTimeout(500);
      for (const h of await page.$$eval('a[href]', (as) => as.map((a) => a.href)).catch(() => [])) {
        const n = norm(h);
        if (!n || !/^https?:/.test(n)) continue;
        const x = new URL(n);
        if (x.origin !== origin || ASSET_EXT.test(x.pathname) || DANGER.test(x.pathname) || seen.has(n) || seen.size >= maxLinks * 5) continue;
        seen.add(n);
        queue.push(n);
      }
    } catch (e) {
      rec.error = trunc(`navigation failed: ${String(e?.message ?? e).split('\n')[0]}`, 160);
    }
    rep.pages.push(rec);
    await page.close();
  }
  if (left() <= 3000 && queue.length) rep.notes.push('deadline reached; pages left unvisited');
  await c.close();
  await browser.close();
  clearTimeout(watchdog);
  flush();
}

if (modes.has('discover')) {
  await discoverMode();
  process.exit(0);
}

mkdirSync(`${OUT}/shots`, { recursive: true });
mkdirSync(`${OUT}/traces`, { recursive: true });

const result = { base_url: input.base_url, modes: [...modes], pages: [], forms: [], journeys: [], notes: [] };
const note = (s) => result.notes.push(s);

const slug = (u) => {
  const x = new URL(u);
  let s = (x.pathname + x.search).replace(/^\/+/, '').replace(/[^A-Za-z0-9]+/g, '_').replace(/^_|_$/g, '') || 'index';
  if (s.length > 60 || x.search) s = s.slice(0, 50) + '-' + createHash('sha1').update(x.pathname + x.search).digest('hex').slice(0, 6);
  return s;
};

const browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu'] });
const INIT = () => {
  window.__rh = { lcp: 0, cls: 0, longtask: 0 };
  try {
    new PerformanceObserver((l) => { for (const e of l.getEntries()) window.__rh.lcp = e.startTime; }).observe({ type: 'largest-contentful-paint', buffered: true });
    new PerformanceObserver((l) => { for (const e of l.getEntries()) if (!e.hadRecentInput) window.__rh.cls += e.value; }).observe({ type: 'layout-shift', buffered: true });
    new PerformanceObserver((l) => { for (const e of l.getEntries()) window.__rh.longtask += e.duration; }).observe({ type: 'longtask', buffered: true });
  } catch {}
};
async function newCtx(extra = {}) {
  const c = await browser.newContext({ viewport: { width: 1280, height: 800 }, ...extra });
  c.setDefaultNavigationTimeout(NAV_TIMEOUT);
  c.setDefaultTimeout(NAV_TIMEOUT);
  await c.addInitScript(INIT);
  return c;
}

// ---------------------------------------------------------------- crawl + per-page modes
let axeSource = null;
if (modes.has('a11y') || input.axe) {
  try { axeSource = readFileSync(createRequire(import.meta.url).resolve('axe-core/axe.min.js'), 'utf8'); }
  catch (e) { note(`axe-core not installed: ${trunc(e.message, 100)}`); }
}

async function responsive(page, rec) {
  rec.viewports = {};
  for (const vp of VIEWPORTS) {
    await page.setViewportSize(vp);
    await page.waitForTimeout(150);
    rec.viewports[vp.width] = await page.evaluate((narrow) => {
      const se = document.scrollingElement || document.documentElement;
      const iw = window.innerWidth;
      const clipped = [];
      for (const el of document.body.querySelectorAll('*')) {
        if (clipped.length >= 20) break;
        const cs = getComputedStyle(el);
        if (cs.display === 'none' || cs.visibility === 'hidden' || cs.position === 'fixed') continue;
        const r = el.getBoundingClientRect();
        if (r.width < 2 || r.height < 2) continue;
        if (r.right > iw + 1 || r.left < -1) {
          const id = el.id ? '#' + el.id : '';
          clipped.push({ el: el.tagName.toLowerCase() + id + (el.className && typeof el.className === 'string' ? '.' + el.className.trim().split(/\s+/)[0] : ''), left: Math.round(r.left), right: Math.round(r.right) });
        }
      }
      let small = 0;
      if (narrow) for (const el of document.querySelectorAll('a[href],button')) {
        const r = el.getBoundingClientRect();
        if (r.width > 0 && r.height > 0 && (r.width < 24 || r.height < 24)) small++;
      }
      return { scroll_width: se.scrollWidth, inner_width: iw, overflow: se.scrollWidth > iw + 1, clipped, small_targets: small };
    }, vp.width <= 400);
  }
  await page.setViewportSize({ width: 1280, height: 800 });
}

async function visual(page, rec) {
  rec.shots = [];
  for (const vp of VIEWPORTS) {
    await page.setViewportSize(vp);
    await page.waitForTimeout(200);
    const name = `${slug(rec.url)}-${vp.width}.png`;
    const s = { viewport: vp.width, file: `shots/${name}`, baseline: false };
    try {
      const buf = await page.screenshot({ path: `${OUT}/shots/${name}`, fullPage: true, timeout: 15000 });
      const bp = input.visual_baseline_dir ? `${input.visual_baseline_dir}/${name}` : null;
      if (bp && existsSync(bp)) {
        s.baseline = true;
        const { PNG } = await import('pngjs');
        const pixelmatch = (await import('pixelmatch')).default;
        const a = PNG.sync.read(readFileSync(bp)), b = PNG.sync.read(buf);
        if (a.width !== b.width || a.height !== b.height) {
          s.diff_ratio = 1; s.size_changed = `${a.width}x${a.height} -> ${b.width}x${b.height}`;
        } else {
          const diff = new PNG({ width: a.width, height: a.height });
          const n = pixelmatch(a.data, b.data, diff.data, a.width, a.height, { threshold: 0.1 });
          s.diff_ratio = n / (a.width * a.height);
          if (s.diff_ratio > 0.005) {
            const dn = name.replace(/\.png$/, '.diff.png');
            writeFileSync(`${OUT}/shots/${dn}`, PNG.sync.write(diff));
            s.diff_file = `shots/${dn}`;
          }
        }
      }
    } catch (e) { s.error = trunc(e.message, 120); }
    rec.shots.push(s);
  }
  await page.setViewportSize({ width: 1280, height: 800 });
}

const ctx = await newCtx();
const queue = [norm(input.base_url)];
const seen = new Set(queue);
const wantResp = modes.has('responsive'), wantA11y = modes.has('a11y') && axeSource, wantVitals = modes.has('vitals'), wantVisual = modes.has('visual');

while (queue.length && result.pages.length < maxPages && !expired()) {
  const url = queue.shift();
  const page = await ctx.newPage();
  const rec = { url, path: new URL(url).pathname + new URL(url).search, status: 0, console_errors: [], page_errors: [], failed_requests: [] };
  page.on('console', (m) => { if (m.type() === 'error' && rec.console_errors.length < 30) rec.console_errors.push(trunc(m.text())); });
  page.on('pageerror', (e) => { if (rec.page_errors.length < 30) rec.page_errors.push(trunc(e?.message ?? e)); });
  page.on('response', (r) => { if (r.status() >= 400 && rec.failed_requests.length < 50) rec.failed_requests.push({ url: trunc(r.url(), 300), status: r.status() }); });
  try {
    const resp = await page.goto(url, { waitUntil: 'load' });
    rec.status = resp ? resp.status() : 0;
    await page.waitForTimeout(500);
    for (const h of await page.$$eval('a[href]', (as) => as.map((a) => a.href))) {
      const n = norm(h);
      if (n && /^https?:/.test(n) && new URL(n).origin === origin && !seen.has(n) && seen.size < maxPages * 5) { seen.add(n); queue.push(n); }
    }
    if (wantVitals) {
      rec.vitals = await page.evaluate(() => {
        const rs = performance.getEntriesByType('resource');
        const nav = performance.getEntriesByType('navigation')[0];
        const size = rs.reduce((t, e) => t + (e.transferSize || 0), 0) + (nav?.transferSize || 0);
        return { lcp_ms: Math.round(window.__rh?.lcp || 0), cls: +(window.__rh?.cls || 0).toFixed(4), longtask_ms: Math.round(window.__rh?.longtask || 0), transfer_bytes: size, requests: rs.length + 1 };
      });
    }
    if (wantA11y) {
      try {
        await page.addScriptTag({ content: axeSource });
        rec.axe = await page.evaluate(async () => {
          const r = await window.axe.run(document);
          return r.violations.map((v) => ({ id: v.id, impact: v.impact || 'minor', help: v.help, nodes: v.nodes.length, target: (v.nodes[0]?.target || []).join(' ').slice(0, 200) }));
        });
      } catch (e) { rec.axe_error = trunc(e.message, 120); }
    }
    if (wantResp) await responsive(page, rec);
    if (wantVisual) await visual(page, rec);
  } catch (e) {
    rec.page_errors.push(trunc(`navigation failed: ${String(e?.message ?? e).split('\n')[0]}`));
  }
  result.pages.push(rec);
  await page.close();
}
await ctx.close();
if (expired()) note('global deadline reached; results partial');

// ---------------------------------------------------------------- forms (nonprod only)
const validFor = (f) => {
  if (f.type === 'email') return 'qa@example.com';
  if (f.type === 'number' || f.type === 'range') return String(f.min !== '' ? Number(f.min) : 1);
  if (f.type === 'url') return 'https://example.com';
  if (f.type === 'tel') return '5551234567';
  if (f.type === 'date') return '2020-01-01';
  if (f.type === 'checkbox' || f.type === 'radio') return null;
  return 'qa test';
};
function badValues(f) {
  const v = [];
  if (f.required) v.push(['empty_required', '']);
  if (f.type === 'email') v.push(['invalid_email', 'not-an-email']);
  if (f.type === 'number') {
    if (f.min !== '') v.push(['below_min', String(Number(f.min) - 1)]);
    if (f.max !== '') v.push(['above_max', String(Number(f.max) + 1)]);
    if (f.min === '' && f.max === '') v.push(['huge_number', '99999999999']);
  }
  if (f.type === 'url') v.push(['invalid_url', 'not a url']);
  if (f.type === 'tel') v.push(['invalid_tel', 'abc']);
  if (f.type === 'date') { if (f.min) v.push(['below_min', '0001-01-01']); if (f.max) v.push(['above_max', '9999-12-31']); }
  if (f.type === 'text' || f.type === 'search' || f.type === 'password' || f.type === 'textarea') {
    if (f.maxlength > 0) v.push(['over_maxlength', 'x'.repeat(f.maxlength + 1)]);
    v.push(['markup_probe', '<rh-probe>']);
  }
  return v;
}

async function formsMode() {
  if (!nonprod) { note('forms skipped: target is not tagged nonprod'); return; }
  const c = await newCtx();
  // Safety net: never talk to another origin while submitting forms.
  await c.route('**/*', (r) => {
    const u = r.request().url();
    if (u.startsWith('data:') || u.startsWith('blob:') || new URL(u).origin === origin) return r.continue();
    return r.abort();
  });
  let tests = 0;
  for (const pr of result.pages) {
    if (expired() || tests > 150) break;
    const page = await c.newPage();
    try {
      await page.goto(pr.url, { waitUntil: 'load' });
      const forms = await page.evaluate(() => [...document.forms].map((f, i) => ({
        i, action: f.action, method: (f.method || 'get').toLowerCase(), id: f.id, text: (f.innerText || '').slice(0, 200),
        submit: [...f.querySelectorAll('button,input[type=submit]')].map((b) => (b.innerText || b.value || '')).join(' '),
        fields: [...f.elements].filter((e) => e.name && !['hidden', 'submit', 'button', 'reset', 'file', 'image'].includes(e.type)).map((e, k) => ({
          name: e.name, type: e.tagName === 'TEXTAREA' ? 'textarea' : (e.type || 'text'), required: e.required,
          min: e.getAttribute('min') ?? '', max: e.getAttribute('max') ?? '', maxlength: e.maxLength > 0 ? e.maxLength : 0 })),
      })));
      for (const f of forms) {
        if (expired()) break;
        const fsel = f.id ? `form#${f.id}` : `form:nth-of-type(${f.i + 1})`;
        let act; try { act = new URL(f.action); } catch { continue; }
        if (act.origin !== origin) { note(`form ${fsel} on ${pr.path} skipped: cross-origin action`); continue; }
        if (DANGER.test(act.pathname + ' ' + f.submit) || DANGER.test(pr.url)) { note(`form ${fsel} on ${pr.path} skipped: destructive-looking action`); continue; }
        let n = 0;
        for (const field of f.fields) {
          for (const [kind, val] of badValues(field)) {
            if (n++ >= 25 || expired()) break;
            tests++;
            const rec = { page: pr.url, form: fsel, field: field.name, value_kind: kind, value: kind === 'over_maxlength' ? `${val.length} chars` : val, client_blocked: false, server_status: null, error_shown: false, gap: false };
            try {
              await page.goto(pr.url, { waitUntil: 'load' });
              const form = page.locator('form').nth(f.i);
              for (const o of f.fields) {
                const loc = form.locator(`[name="${o.name}"]`).first();
                const v = o.name === field.name ? val : validFor(o);
                if (v === null) continue;
                if (o.name !== field.name && o.type === 'select-one') continue;
                await loc.fill(v, { timeout: 3000 }).catch(() => {});
              }
              const valid = await form.locator(`[name="${field.name}"]`).first().evaluate((e) => e.validity.valid).catch(() => true);
              const formValid = await form.evaluate((e) => e.checkValidity()).catch(() => true);
              rec.client_blocked = !valid || !formValid;
              const before = await page.evaluate(() => document.body.innerText);
              let status = null;
              const onResp = (r) => {
                const req = r.request();
                if (req.isNavigationRequest() || (['fetch', 'xhr'].includes(req.resourceType()) && req.method() !== 'GET')) status = r.status();
              };
              page.on('response', onResp);
              if (!rec.client_blocked) {
                await form.evaluate((e) => e.requestSubmit()).catch(() => {});
                await page.waitForTimeout(1200);
              }
              page.off('response', onResp);
              rec.server_status = rec.client_blocked ? null : status;
              rec.error_shown = await page.evaluate((b) => {
                const vis = (e) => { const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 && getComputedStyle(e).visibility !== 'hidden'; };
                const sel = '[role=alert],.error,.errors,.invalid-feedback,.field-error,.help-block,.text-danger,[aria-invalid=true],[class*=error i]';
                if ([...document.querySelectorAll(sel)].some((e) => vis(e) && (e.innerText || '').trim() || e.getAttribute('aria-invalid') === 'true')) return true;
                const add = document.body.innerText.replace(b, '');
                return /invalid|error|required|must be|not valid|too long|too short|please enter/i.test(add);
              }, before).catch(() => false);
              rec.gap = !rec.client_blocked && rec.server_status !== null && rec.server_status >= 200 && rec.server_status < 400 && !rec.error_shown;
            } catch (e) { rec.error = trunc(e.message, 120); }
            result.forms.push(rec);
          }
        }
      }
    } catch (e) { note(`forms on ${pr.path}: ${trunc(e.message, 100)}`); }
    await page.close();
  }
  await c.close();
}

// ---------------------------------------------------------------- journeys & self-healing locators
const READONLY = new Set(['goto', 'expect_text', 'expect_url', 'wait']);

async function resolveResilient(page, targetSelector, actionKind, healedLog) {
  if (!targetSelector) return null;
  // 1. Direct primary attempt with short timeout
  try {
    const loc = page.locator(targetSelector).first();
    await loc.waitFor({ state: 'attached', timeout: 2500 });
    return loc;
  } catch {
    // Primary selector missed or timed out. Begin resilient self-healing fallback tree.
  }

  const cleanToken = targetSelector
    .replace(/^[#.]/, '')
    .replace(/\[.*?\]/g, '')
    .replace(/[_-]/g, ' ')
    .trim();

  const candidates = [];

  // Strategy A: data-testid / data-qa / data-cy / data-test
  if (cleanToken) {
    const idToken = targetSelector.replace(/^[#.]/, '').replace(/\[.*?\]/g, '').trim();
    candidates.push({
      desc: 'test-id attribute',
      loc: page.locator(`[data-testid="${idToken}"], [data-qa="${idToken}"], [data-cy="${idToken}"], [data-test="${idToken}"]`).first(),
    });
  }

  // Strategy B: Accessibility role + name
  if (cleanToken && cleanToken.length >= 2) {
    const rx = new RegExp(cleanToken.split(/\s+/)[0], 'i');
    if (actionKind === 'click') {
      candidates.push({ desc: 'role button', loc: page.getByRole('button', { name: rx }).first() });
      candidates.push({ desc: 'role link', loc: page.getByRole('link', { name: rx }).first() });
    } else if (actionKind === 'fill') {
      candidates.push({ desc: 'role textbox', loc: page.getByRole('textbox', { name: rx }).first() });
      candidates.push({ desc: 'placeholder', loc: page.getByPlaceholder(rx).first() });
      candidates.push({ desc: 'label', loc: page.getByLabel(rx).first() });
    }
  }

  // Strategy C: Exact or substring text content
  if (cleanToken && cleanToken.length >= 2) {
    candidates.push({ desc: 'text content', loc: page.locator(`text="${cleanToken}"`).first() });
    candidates.push({ desc: 'aria-label', loc: page.locator(`[aria-label*="${cleanToken}" i]`).first() });
  }

  // Strategy D: name attribute
  if (cleanToken) {
    const nameToken = targetSelector.replace(/^[#.]/, '').trim();
    candidates.push({ desc: 'name attribute', loc: page.locator(`[name="${nameToken}"]`).first() });
  }

  for (const cand of candidates) {
    try {
      await cand.loc.waitFor({ state: 'attached', timeout: 1200 });
      if (healedLog) {
        healedLog.push({
          original: targetSelector,
          healed_by: cand.desc,
          healed_selector: cand.loc.toString(),
        });
      }
      return cand.loc;
    } catch {
      // try next candidate
    }
  }

  // Fallback to original locator to let standard Playwright assertion or error handle it
  return page.locator(targetSelector).first();
}

async function runStep(page, s, healedLog = []) {
  const key = Object.keys(s).find((k) => ['goto', 'click', 'fill', 'select', 'press', 'expect_text', 'expect_url', 'wait'].includes(k));
  const val = s.value ?? '';
  switch (key) {
    case 'goto': {
      const u = new URL(s.goto, origin);
      if (u.origin !== origin) throw new Error(`cross-origin goto refused: ${u.origin}`);
      await page.goto(u.href, { waitUntil: 'load' }); break;
    }
    case 'click': {
      const sel = s.selector || s.click;
      const loc = await resolveResilient(page, sel, 'click', healedLog);
      await loc.click();
      break;
    }
    case 'fill': {
      const sel = s.selector || s.fill;
      const loc = await resolveResilient(page, sel, 'fill', healedLog);
      await loc.fill(String(val));
      break;
    }
    case 'select': {
      const sel = s.selector || s.select;
      const loc = await resolveResilient(page, sel, 'select', healedLog);
      await loc.selectOption(String(val));
      break;
    }
    case 'press': await page.keyboard.press(s.press || String(val)); break;
    case 'expect_text': {
      const t = s.expect_text || val;
      const sel = s.selector || 'body';
      const loc = await resolveResilient(page, sel, 'text', healedLog);
      await loc.waitFor({ state: 'visible', timeout: 5000 });
      const txt = await loc.innerText();
      if (!txt.includes(t)) throw new Error(`expected text "${trunc(t, 60)}" not found`);
      break;
    }
    case 'expect_url': {
      const want = s.expect_url || val;
      await page.waitForURL((u) => u.href.includes(want) || new RegExp(want).test(u.href), { timeout: 5000 });
      break;
    }
    case 'wait': if (typeof s.wait === 'number') await page.waitForTimeout(Math.min(s.wait, 10000)); else await page.locator(s.selector || s.wait).first().waitFor({ state: 'visible' }); break;
    default: throw new Error(`unknown step ${JSON.stringify(Object.keys(s))}`);
  }
}

async function journeysMode() {
  const roles = input.roles?.length ? input.roles : [{ name: 'anon' }];
  for (const j of input.journeys || []) {
    const jname = j.name || 'journey';
    const only = Array.isArray(j.roles) ? j.roles : null;
    for (const role of roles) {
      if (expired()) return;
      if (only && !only.includes(role.name)) continue;
      const rec = { name: jname, role: role.name, status: 'pass', steps: (j.steps || []).length, healed_locators: [] };
      const ro = (j.steps || []).every((s) => READONLY.has(Object.keys(s).find((k) => READONLY.has(k) || ['click', 'fill', 'select', 'press'].includes(k))));
      if (!ro && !nonprod) { rec.status = 'skipped'; rec.message = 'journey mutates UI state; target is not tagged nonprod'; result.journeys.push(rec); continue; }
      const opts = {};
      if (role.storage_state_path && existsSync(role.storage_state_path)) opts.storageState = role.storage_state_path;
      else if (role.storage_state_path) { rec.status = 'blocked'; rec.message = 'storageState missing for role'; result.journeys.push(rec); continue; }
      const c = await newCtx(opts);
      await c.tracing.start({ screenshots: true, snapshots: true });
      const page = await c.newPage();
      let idx = 0;
      try {
        for (; idx < (j.steps || []).length; idx++) await runStep(page, j.steps[idx], rec.healed_locators);
      } catch (e) {
        rec.status = 'fail'; rec.failed_step = idx; rec.message = trunc(String(e?.message ?? e).split('\n')[0], 300);
        const base_ = `${jname}-${role.name}`.replace(/[^A-Za-z0-9_-]+/g, '_');
        try { await page.screenshot({ path: `${OUT}/traces/${base_}.png`, timeout: 8000 }); rec.screenshot = `traces/${base_}.png`; } catch {}
        try { await c.tracing.stop({ path: `${OUT}/traces/${base_}.zip` }); rec.trace = `traces/${base_}.zip`; } catch {}
      }
      if (rec.status !== 'fail') await c.tracing.stop().catch(() => {});
      await c.close();
      result.journeys.push(rec);
    }
  }
}

if (modes.has('forms')) await formsMode();
if (modes.has('journeys')) await journeysMode();
await browser.close();
writeFileSync(`${OUT}/qa-ui.json`, JSON.stringify(result, null, 2));
