// node pdf.mjs in.html out.pdf — render a local HTML report to A4 PDF (offline, JS disabled).
import { chromium } from 'playwright';
const [inp, out] = process.argv.slice(2);
if (!inp || !out) { console.error('usage: node pdf.mjs in.html out.pdf'); process.exit(2); }
const browser = await chromium.launch({ args: ['--no-sandbox', '--disable-dev-shm-usage'] });
try {
  const ctx = await browser.newContext({ javaScriptEnabled: false, offline: true });
  const page = await ctx.newPage();
  await page.goto('file://' + inp, { waitUntil: 'load' });
  await page.pdf({ path: out, format: 'A4', printBackground: true, margin: { top: '12mm', right: '12mm', bottom: '12mm', left: '12mm' } });
} finally {
  await browser.close();
}
