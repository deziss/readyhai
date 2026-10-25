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

const queue = [norm(start)];
const seen = new Set(queue);
const pages = [];
const linkCache = new Map();
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
  const rec = { url, status: 0, console_errors: [], page_errors: [], failed_requests: [], broken_links: [], screenshot: null };
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
  } catch (e) {
    rec.page_errors.push(trunc(`navigation failed: ${e && e.message ? e.message.split('\n')[0] : e}`));
  }
  rec.broken_links = rec.broken_links.map((b) => `${b.url} (${b.status || 'unreachable'})`);
  pages.push(rec);
  await page.close();
}

await browser.close();
writeFileSync(`${outDir}/playwright.json`, JSON.stringify({ start, pages }, null, 2));
