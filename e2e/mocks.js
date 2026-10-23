// Replaces every third-party endpoint with fixtures, so the suite is
// deterministic and makes no real network requests. Each handler can be
// overridden per test; every intercepted URL is recorded in `requests`.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const fixture = (name) => readFileSync(join(fileURLToPath(import.meta.url), '..', '..', 'tests', 'fixtures', name), 'utf8');
const json = (body, status = 200) => ({ status, contentType: 'application/json', body: typeof body === 'string' ? body : JSON.stringify(body) });

const doh = (url) => {
  const type = new URL(url).searchParams.get('type');
  const q = { type: { A: 1, AAAA: 28, PTR: 12 }[type] };
  if (type === 'PTR') return json({ Status: 0, Question: [q], Answer: [{ type: 12, data: 'dns.example.net.' }] });
  return json({ Status: 0, Question: [q], Answer: [] });
};

export const defaults = {
  rdap: () => json(fixture('rdap-arin.json')),
  ipinfo: () => json(fixture('geo-ipinfo.json')),
  ipwhois: () => json(fixture('geo-ipwhois.json')),
  ipapi: () => json(fixture('geo-ipapi.json')),
  doh,
};

export async function installMocks(page, overrides = {}) {
  const h = { ...defaults, ...overrides };
  const requests = [];
  const route = (pattern, handler) => page.route(pattern, async (r) => {
    requests.push(r.request().url());
    await r.fulfill(await handler(r.request().url()));
  });
  await route(/^https:\/\/rdap-bootstrap\.arin\.net\//, h.rdap);
  await route(/^https:\/\/ipinfo\.io\//, h.ipinfo);
  await route(/^https:\/\/ipwho\.is\//, h.ipwhois);
  await route(/^https:\/\/ipapi\.co\//, h.ipapi);
  await route(/^https:\/\/(cloudflare-dns\.com|dns\.google)\//, h.doh);
  // Cosmetic third parties: never let a test depend on them.
  await page.route(/^https:\/\/(fonts\.googleapis\.com|fonts\.gstatic\.com|[a-c]\.tile\.openstreetmap\.org)\//, (r) => r.abort());
  return { requests, json };
}

// Records page errors and CSP violations; tests assert this stays empty.
export function watchErrors(page) {
  const errors = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error' && /Content Security Policy|Refused to/i.test(m.text())) errors.push(m.text());
  });
  return errors;
}
