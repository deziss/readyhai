// Senior-QA UI exploratory runner. usage: node qa.mjs [/out/qa-ui-input.json]
// Input : {base_url,max_pages,modes[],viewports[],nonprod,roles[],journeys[],visual_baseline_dir,axe}
// Output: /out/qa-ui.json (+ /out/shots, /out/traces). Forms are only exercised when nonprod=true.
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

// ---------------------------------------------------------------- journeys
const READONLY = new Set(['goto', 'expect_text', 'expect_url', 'wait']);
async function runStep(page, s) {
  const key = Object.keys(s).find((k) => ['goto', 'click', 'fill', 'select', 'press', 'expect_text', 'expect_url', 'wait'].includes(k));
  const val = s.value ?? '';
  switch (key) {
    case 'goto': {
      const u = new URL(s.goto, origin);
      if (u.origin !== origin) throw new Error(`cross-origin goto refused: ${u.origin}`);
      await page.goto(u.href, { waitUntil: 'load' }); break;
    }
    case 'click': await page.locator(s.selector || s.click).first().click(); break;
    case 'fill': await page.locator(s.selector || s.fill).first().fill(String(val)); break;
    case 'select': await page.locator(s.selector || s.select).first().selectOption(String(val)); break;
    case 'press': await page.keyboard.press(s.press || String(val)); break;
    case 'expect_text': {
      const t = s.expect_text || val;
      await page.locator(s.selector || 'body').first().waitFor({ state: 'visible' });
      const txt = await page.locator(s.selector || 'body').first().innerText();
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
      const rec = { name: jname, role: role.name, status: 'pass', steps: (j.steps || []).length };
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
        for (; idx < (j.steps || []).length; idx++) await runStep(page, j.steps[idx]);
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
