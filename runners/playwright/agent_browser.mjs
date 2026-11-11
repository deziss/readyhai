// Interactive Playwright browser security runner for ReadyHai Agent (Area: browser/ui).
// usage: node agent_browser.mjs <input.json>
// Writes /out/browser-sec.json (never records raw secrets, tokens, or cookie values).
import { chromium } from 'playwright';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

const inputPath = process.argv[2] || '/out/browser-sec-input.json';
const input = JSON.parse(readFileSync(inputPath, 'utf8'));
const OUT = input.out_dir || dirname(inputPath);
const baseOrigin = new URL(input.base_url).origin;
const allowedHosts = new Set([
  new URL(input.base_url).hostname.toLowerCase(),
  ...(input.allowed_hosts || []).map((h) => String(h).toLowerCase()),
]);
const nonprod = !!input.nonprod;
const maxPages = Math.max(1, Math.min(20, input.max_pages || 8));
const deadline = Date.now() + Math.min(120000, Math.max(5000, input.deadline_ms || 45000));
const NAV_TIMEOUT = 10000;
const DANGER = /\/(delete|remove|destroy|drop|reset|purge|truncate|logout|signout)\b/i;

const expired = () => Date.now() >= deadline;
const trunc = (s, n = 200) => String(s ?? '').slice(0, n);
const normUrl = (u) => {
  try {
    const x = new URL(u, baseOrigin);
    x.hash = '';
    return x.href;
  } catch {
    return null;
  }
};
const inScope = (raw) => {
  try {
    const u = new URL(raw, baseOrigin);
    return /^https?:$/.test(u.protocol) && allowedHosts.has(u.hostname.toLowerCase());
  } catch {
    return false;
  }
};

const result = {
  base_url: input.base_url,
  pages: [],
  xss_hits: [],
  dom_sinks: [],
  storage_leaks: [],
  cookie_issues: [],
  sourcemaps: [],
  clickjacking: [],
  postmessage_issues: [],
  notes: [],
};
const note = (s) => result.notes.push(trunc(s, 240));

// Injected before page scripts execute: wraps DOM sinks, eval/Function, postMessage, and provides canary callback.
const SECURITY_INIT = () => {
  window.__rh_sec = {
    xss_hits: [],
    sink_events: [],
    postmessage_handlers: [],
  };
  window.__rh_xss_hit = (id, detail) => {
    try {
      window.__rh_sec.xss_hits.push({
        id: String(id || 'canary'),
        url: String(location.href || '').slice(0, 300),
        detail: String(detail || '').slice(0, 120),
      });
    } catch {}
  };
  const logSink = (sink, val) => {
    try {
      if (window.__rh_sec.sink_events.length >= 60) return;
      const sample = String(val ?? '');
      if (
        sample.includes('__rh_xss_hit') ||
        /<img|<script|onerror=|onload=|javascript:/i.test(sample) ||
        sink === 'eval' ||
        sink === 'Function'
      ) {
        window.__rh_sec.sink_events.push({
          sink,
          url: String(location.href || '').slice(0, 300),
          sample: sample.slice(0, 140),
        });
      }
    } catch {}
  };
  try {
    const origEval = window.eval;
    window.eval = function (code) {
      logSink('eval', code);
      return origEval.apply(this, arguments);
    };
  } catch {}
  try {
    const OrigFn = window.Function;
    window.Function = function (...args) {
      logSink('Function', args[args.length - 1]);
      return OrigFn.apply(this, args);
    };
  } catch {}
  for (const prop of ['innerHTML', 'outerHTML']) {
    try {
      const desc = Object.getOwnPropertyDescriptor(Element.prototype, prop);
      if (desc && desc.set) {
        Object.defineProperty(Element.prototype, prop, {
          configurable: true,
          enumerable: desc.enumerable,
          get: desc.get,
          set(v) {
            logSink(`Element.${prop}`, v);
            return desc.set.call(this, v);
          },
        });
      }
    } catch {}
  }
  for (const m of ['write', 'writeln']) {
    try {
      const orig = Document.prototype[m];
      Document.prototype[m] = function (...args) {
        logSink(`document.${m}`, args.join(''));
        return orig.apply(this, args);
      };
    } catch {}
  }
  try {
    const origAdd = window.addEventListener.bind(window);
    window.addEventListener = function (type, listener, opts) {
      if (type === 'message' && typeof listener === 'function') {
        try {
          const src = listener.toString();
          const hasOriginCheck = /\b(?:origin|trusted)\b/i.test(src);
          if (!hasOriginCheck && window.__rh_sec.postmessage_handlers.length < 20) {
            window.__rh_sec.postmessage_handlers.push({
              url: String(location.href || '').slice(0, 300),
              snippet: src.slice(0, 160),
            });
          }
        } catch {}
      }
      return origAdd(type, listener, opts);
    };
  } catch {}
};

const browser = await chromium.launch({
  headless: true,
  args: ['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
});

async function newSecCtx(role = {}) {
  const opts = { ignoreHTTPSErrors: false, viewport: { width: 1280, height: 800 } };
  if (role.storage_state_path && existsSync(role.storage_state_path)) {
    opts.storageState = role.storage_state_path;
  }
  const c = await browser.newContext(opts);
  c.setDefaultNavigationTimeout(NAV_TIMEOUT);
  c.setDefaultTimeout(NAV_TIMEOUT);
  await c.addInitScript(SECURITY_INIT);
  await c.route('**/*', (route) => {
    const req = route.request();
    const u = req.url();
    if (u.startsWith('data:') || u.startsWith('blob:') || u === 'about:blank') {
      return route.continue();
    }
    if (!inScope(u)) {
      return route.abort();
    }
    if (!nonprod && !['GET', 'HEAD', 'OPTIONS'].includes(req.method())) {
      return route.abort();
    }
    const headers = { ...req.headers() };
    if (role.bearer_token && new URL(u).origin === baseOrigin && !headers.authorization) {
      headers.authorization = `Bearer ${role.bearer_token}`;
    }
    return route.continue({ headers });
  });
  return c;
}

const roles = Array.isArray(input.roles) && input.roles.length ? input.roles : [{ name: 'anon' }];
const primaryRole = roles[0];
const queue = [normUrl(input.base_url)].filter(Boolean);
const seenPages = new Set(queue);
const seenMaps = new Set();
const seenXss = new Set();

const ctx = await newSecCtx(primaryRole);

while (queue.length && result.pages.length < maxPages && !expired()) {
  const url = queue.shift();
  const page = await ctx.newPage();
  let mainHeaders = {};
  let status = 0;
  try {
    const resp = await page.goto(url, { waitUntil: 'load' });
    status = resp ? resp.status() : 0;
    mainHeaders = resp ? await resp.allHeaders() : {};
    await page.waitForTimeout(350);

    // Collect links for bounded crawl
    const links = await page.$$eval('a[href]', (as) => as.map((a) => a.href)).catch(() => []);
    for (const h of links) {
      const n = normUrl(h);
      if (n && inScope(n) && !seenPages.has(n) && seenPages.size < maxPages * 3) {
        seenPages.add(n);
        queue.push(n);
      }
    }

    // 1. Collect browser storage & __NEXT_DATA__ leaks (values redacted!)
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
              leaks.push({ store: storeName, key: k, kind: isJwt(v) ? 'jwt' : 'sensitive_key', raw_len: v.length, prefix: isJwt(v) ? String(v).slice(0, 8) : '' });
            }
          }
        } catch {}
      }
      try {
        const nd = document.getElementById('__NEXT_DATA__')?.textContent;
        if (nd && /(?:secret|private[_-]?key|api[_-]?key|password_hash|jwt)/i.test(nd)) {
          leaks.push({ store: '__NEXT_DATA__', key: 'serialized_props', kind: 'sensitive_ssr_state', raw_len: nd.length, prefix: '' });
        }
      } catch {}
      const scripts = [...document.querySelectorAll('script[src]')].map((s) => s.src).filter(Boolean).slice(0, 15);
      return {
        leaks,
        scripts,
        sinks: window.__rh_sec?.sink_events || [],
        pm: window.__rh_sec?.postmessage_handlers || [],
        title: document.title || '',
        has_form: document.forms.length > 0,
      };
    }).catch(() => ({ leaks: [], scripts: [], sinks: [], pm: [], title: '', has_form: false }));

    for (const lk of secSnap.leaks) {
      result.storage_leaks.push({
        url,
        store: lk.store,
        key: trunc(lk.key, 80),
        kind: lk.kind,
        preview: lk.prefix ? `jwt(${lk.prefix}...redacted, len=${lk.raw_len})` : `<redacted len=${lk.raw_len}>`,
      });
    }
    for (const sk of secSnap.sinks) result.dom_sinks.push(sk);
    for (const pm of secSnap.pm) result.postmessage_issues.push(pm);

    // 2. Cookie hygiene check (auth/session cookies lacking HttpOnly/Secure)
    const cookies = await ctx.cookies(url).catch(() => []);
    for (const ck of cookies) {
      if (/(?:session|sid|jwt|auth|token|connect\.sid)/i.test(ck.name)) {
        const missing = [];
        if (!ck.httpOnly) missing.push('HttpOnly');
        if (url.startsWith('https://') && !ck.secure) missing.push('Secure');
        if (ck.sameSite === 'None' && !ck.secure) missing.push('SameSite=None without Secure');
        if (missing.length) {
          result.cookie_issues.push({
            url,
            name: trunc(ck.name, 64),
            missing,
          });
        }
      }
    }

    // 3. Source-map exposure check (same-origin script + .map, capped)
    if (input.probe_sourcemaps !== false) {
      for (const sUrl of secSnap.scripts) {
        if (seenMaps.size >= 15 || expired() || !inScope(sUrl)) break;
        const mapUrl = sUrl.split('#')[0].split('?')[0] + '.map';
        if (seenMaps.has(mapUrl)) continue;
        seenMaps.add(mapUrl);
        try {
          const mr = await ctx.request.get(mapUrl, { timeout: 5000 });
          if (mr.status() === 200) {
            const txt = await mr.text();
            if (txt.includes('"mappings"') && txt.includes('"sources"')) {
              result.sourcemaps.push({ url: trunc(mapUrl, 300), size_bytes: txt.length });
            }
          }
        } catch {}
      }
    }

    // 4. Clickjacking frameability check (headers + real iframe harness)
    if (input.probe_clickjacking !== false && status >= 200 && status < 400 && !DANGER.test(url)) {
      const xfo = (mainHeaders['x-frame-options'] || '').toUpperCase();
      const csp = (mainHeaders['content-security-policy'] || '').toLowerCase();
      const hasXfo = xfo === 'DENY' || xfo === 'SAMEORIGIN';
      const hasFa = /frame-ancestors\s+([^;]+)/.test(csp) && !/frame-ancestors\s+\*/.test(csp);
      if (!hasXfo && !hasFa) {
        const fpage = await ctx.newPage();
        try {
          await fpage.setContent(`<!doctype html><html><body><iframe id="rhf" src="${url.replace(/"/g, '&quot;')}"></iframe></body></html>`);
          await fpage.waitForTimeout(350);
          const frameLoaded = await fpage.evaluate(() => {
            const f = document.getElementById('rhf');
            return !!f && f.contentWindow !== null;
          }).catch(() => false);
          if (frameLoaded) {
            result.clickjacking.push({
              url,
              reason: 'Page loaded inside <iframe> without X-Frame-Options or CSP frame-ancestors',
            });
          }
        } catch {}
        await fpage.close();
      }
    }

    // 5. DOM XSS canary probes (#hash + ?q=) proving real window.__rh_xss_hit execution
    if (input.probe_dom_xss !== false && !expired() && status >= 200 && status < 400) {
      const probes = [
        { kind: 'dom_hash', id: `dom-hash-${result.pages.length}`, probeUrl: `${url}#<img src=x onerror="window.__rh_xss_hit('dom-hash-${result.pages.length}','hash')">` },
        { kind: 'dom_query', id: `dom-query-${result.pages.length}`, probeUrl: `${url}${url.includes('?') ? '&' : '?'}q=${encodeURIComponent(`<img src=x onerror="window.__rh_xss_hit('dom-query-${result.pages.length}','query')">`)}` },
      ];
      for (const p of probes) {
        if (expired()) break;
        const xpage = await ctx.newPage();
        try {
          await xpage.goto(p.probeUrl, { waitUntil: 'load' });
          await xpage.waitForTimeout(350);
          const hits = await xpage.evaluate(() => window.__rh_sec?.xss_hits || []).catch(() => []);
          for (const hit of hits) {
            const key = `${p.kind}:${url}`;
            if (!seenXss.has(key)) {
              seenXss.add(key);
              result.xss_hits.push({
                kind: p.kind,
                id: hit.id || p.id,
                url: trunc(url, 300),
                probe_url: trunc(p.probeUrl, 340),
                detail: trunc(hit.detail || 'Chromium executed window.__rh_xss_hit canary', 180),
              });
            }
          }
        } catch {}
        await xpage.close();
      }
    }

    // 6. Stored XSS form canary (nonprod only, skipping login/password/destructive forms)
    if (nonprod && input.probe_stored_xss !== false && secSnap.has_form && !/login|signin|auth/i.test(url) && !DANGER.test(url) && !expired()) {
      const fpage = await ctx.newPage();
      try {
        await fpage.goto(url, { waitUntil: 'load' });
        const formCount = await fpage.locator('form').count();
        for (let fi = 0; fi < Math.min(2, formCount); fi++) {
          const form = fpage.locator('form').nth(fi);
          const isPwd = (await form.locator('input[type="password"]').count()) > 0;
          if (isPwd) continue;
          const act = (await form.getAttribute('action')) || url;
          if (DANGER.test(act)) continue;
          const canaryId = `stored-form-${result.pages.length}-${fi}`;
          const canary = `<img src=x onerror="window.__rh_xss_hit('${canaryId}','stored')">`;
          const inputs = form.locator('input[type="text"],input:not([type]),textarea');
          const nInputs = await inputs.count();
          if (nInputs === 0) continue;
          for (let ii = 0; ii < nInputs; ii++) {
            await inputs.nth(ii).fill(canary, { timeout: 2000 }).catch(() => {});
          }
          await form.evaluate((f) => f.requestSubmit()).catch(() => {});
          await fpage.waitForTimeout(600);

          // Verify execution under viewer role (second role if present, else same role fresh page)
          const viewRole = roles.length > 1 ? roles[1] : primaryRole;
          const vctx = await newSecCtx(viewRole);
          const vpage = await vctx.newPage();
          try {
            await vpage.goto(url, { waitUntil: 'load' });
            await vpage.waitForTimeout(350);
            const hits = await vpage.evaluate(() => window.__rh_sec?.xss_hits || []).catch(() => []);
            for (const hit of hits) {
              const key = `stored_xss:${url}`;
              if (!seenXss.has(key)) {
                seenXss.add(key);
                result.xss_hits.push({
                  kind: 'stored_xss',
                  id: hit.id || canaryId,
                  url: trunc(url, 300),
                  probe_url: trunc(url, 340),
                  detail: `Stored XSS canary executed for role '${viewRole.name || 'viewer'}'`,
                });
              }
            }
          } catch {}
          await vpage.close();
          await vctx.close();
        }
      } catch (e) {
        note(`stored xss check on ${url}: ${trunc(e.message, 120)}`);
      }
      await fpage.close();
    }

    result.pages.push({ url: trunc(url, 300), status });
  } catch (e) {
    note(`navigation on ${url} failed: ${trunc(e.message, 120)}`);
  }
  await page.close();
}

await ctx.close();
await browser.close();
writeFileSync(`${OUT}/browser-sec.json`, JSON.stringify(result, null, 2));
