// Non-intrusive same-origin crawl: no form submission, GET/HEAD only.
// usage: node crawl.mjs <url> [--max-pages N] [--out DIR]
import { chromium } from 'playwright';
import { writeFileSync } from 'node:fs';

const argv = process.argv.slice(2);
const start = argv[0];
const opt = (name, def) => { const i = argv.indexOf(name); return i >= 0 && argv[i + 1] ? argv[i + 1] : def; };
const maxPages = Math.max(1, parseInt(opt('--max-pages', '20'), 10) || 20);
const outDir = opt('--out', '/out');
if (!start) { console.error('usage: crawl.mjs <url>'); process.exit(2); }

const origin = new URL(start).origin;
const norm = (u) => { try { const x = new URL(u); x.hash = ''; return x.href; } catch { return null; } };
const trunc = (s, n = 300) => String(s ?? '').slice(0, n);

const browser = await chromium.launch({
  headless: true,
  args: ['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
});
const context = await browser.newContext({ ignoreHTTPSErrors: false, viewport: { width: 1280, height: 800 } });
await context.addInitScript(() => {
  window.__rh_pm = [];
  const origAdd = window.addEventListener.bind(window);
  window.addEventListener = function (type, listener, opts) {
    if (type === 'message' && typeof listener === 'function') {
      try {
        const src = listener.toString();
        if (!/\b(?:origin|trusted)\b/i.test(src) && window.__rh_pm.length < 15) {
          window.__rh_pm.push(src.slice(0, 140));
        }
      } catch {}
    }
    return origAdd(type, listener, opts);
  };
});

const queue = [norm(start)];
const seen = new Set(queue);
const pages = [];
const linkCache = new Map();
const seenMaps = new Set();
let linkChecks = 0;

async function checkLink(url) {
  if (linkCache.has(url)) return linkCache.get(url);
  if (linkChecks >= 100) return null;
  linkChecks++;
  let status = 0;
  try {
    let r = await context.request.fetch(url, { method: 'HEAD', timeout: 10000, maxRedirects: 5 });
    status = r.status();
    if (status === 405 || status === 501) {
      r = await context.request.get(url, { timeout: 10000, maxRedirects: 5 });
      status = r.status();
    }
  } catch { status = 0; }
  linkCache.set(url, status);
  return status;
}

while (queue.length && pages.length < maxPages) {
  const url = queue.shift();
  const page = await context.newPage();
  const rec = { url, status: 0, console_errors: [], page_errors: [], failed_requests: [], broken_links: [], storage_leaks: [], cookie_issues: [], sourcemaps: [], postmessage_issues: [], screenshot: null };
  page.on('console', (m) => { if (m.type() === 'error' && rec.console_errors.length < 50) rec.console_errors.push(trunc(m.text())); });
  page.on('pageerror', (e) => { if (rec.page_errors.length < 50) rec.page_errors.push(trunc(e && e.message ? e.message : e)); });
  page.on('requestfailed', (r) => {
    if (rec.failed_requests.length < 100) rec.failed_requests.push({ url: trunc(r.url(), 500), status: 0, failure: trunc(r.failure()?.errorText || 'failed') });
  });
  page.on('response', (r) => {
    if (r.status() >= 400 && rec.failed_requests.length < 100) rec.failed_requests.push({ url: trunc(r.url(), 500), status: r.status(), failure: '' });
  });
  try {
    const resp = await page.goto(url, { timeout: 15000, waitUntil: 'load' });
    rec.status = resp ? resp.status() : 0;
    await page.waitForTimeout(500);
    const hrefs = await page.$$eval('a[href]', (as) => as.map((a) => a.href));
    const uniq = [...new Set(hrefs.map(norm).filter((h) => h && /^https?:/.test(h)))];
    for (const h of uniq) {
      if (new URL(h).origin !== origin) continue;
      if (!seen.has(h) && seen.size < maxPages * 5) { seen.add(h); queue.push(h); }
      const st = await checkLink(h);
      if (st !== null && (st === 0 || st >= 400)) rec.broken_links.push({ url: trunc(h, 500), status: st });
    }
    if (pages.length === 0) {
      try { await page.screenshot({ path: `${outDir}/page-0.png`, fullPage: true, timeout: 15000 }); rec.screenshot = 'page-0.png'; } catch {}
    }
    const secSnap = await page.evaluate(() => {
      const leaks = [];
      const keySensitive = /(?:token|secret|api[_-]?key|password|private[_-]?key|jwt|session|auth)/i;
      const isJwt = (v) => /^eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/.test(String(v ?? ''));
      for (const [storeName, store] of [['localStorage', localStorage], ['sessionStorage', sessionStorage]]) {
        try {
          for (let i = 0; i < store.length; i++) {
            const k = store.key(i);
            const v = store.getItem(k);
            if (isJwt(v) || (keySensitive.test(k) && v && v.length >= 6)) {
              leaks.push({ store: storeName, key: String(k).slice(0, 80), kind: isJwt(v) ? 'jwt' : 'sensitive_key' });
            }
          }
        } catch {}
      }
      const scripts = [...document.querySelectorAll('script[src]')].map((s) => s.src).filter(Boolean).slice(0, 10);
      return { leaks, scripts, pm: window.__rh_pm || [] };
    }).catch(() => ({ leaks: [], scripts: [], pm: [] }));
    rec.storage_leaks = secSnap.leaks;
    rec.postmessage_issues = secSnap.pm;
    const cookies = await context.cookies(url).catch(() => []);
    for (const ck of cookies) {
      if (/(?:session|sid|jwt|auth|token|connect\.sid)/i.test(ck.name) && (!ck.httpOnly || (url.startsWith('https://') && !ck.secure))) {
        rec.cookie_issues.push({ name: trunc(ck.name, 64), httpOnly: !!ck.httpOnly, secure: !!ck.secure });
      }
    }
    for (const sUrl of secSnap.scripts) {
      if (seenMaps.size >= 10) break;
      try {
        if (new URL(sUrl).origin !== origin) continue;
        const mapUrl = sUrl.split('#')[0].split('?')[0] + '.map';
        if (seenMaps.has(mapUrl)) continue;
        seenMaps.add(mapUrl);
        const mr = await context.request.get(mapUrl, { timeout: 4000 });
        if (mr.status() === 200 && (await mr.text()).includes('"mappings"')) {
          rec.sourcemaps.push(trunc(mapUrl, 300));
        }
      } catch {}
    }
  } catch (e) {
    rec.page_errors.push(trunc(`navigation failed: ${e && e.message ? e.message.split('\n')[0] : e}`));
  }
  rec.broken_links = rec.broken_links.map((b) => `${b.url} (${b.status || 'unreachable'})`);
  pages.push(rec);
  await page.close();
}

await browser.close();
writeFileSync(`${outDir}/playwright.json`, JSON.stringify({ start, pages }, null, 2));
