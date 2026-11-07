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

// Real GeoIP providers echo the address they were asked about, and the app
// rejects an answer for a different address. Mirror that: the fixture's `ip`
// becomes the address in the request path (the self-lookup has none, so it
// keeps the fixture's own address).
const echoIp = (name) => (url) => {
  const body = JSON.parse(fixture(name));
  const requested = new URL(url).pathname.split('/').filter((p) => p && p !== 'json')[0];
  if (requested) body.ip = decodeURIComponent(requested);
  return json(body);
};

export const defaults = {
  rdap: () => json(fixture('rdap-arin.json')),
  ipinfo: echoIp('geo-ipinfo.json'),
  ipwhois: echoIp('geo-ipwhois.json'),
  ipapi: echoIp('geo-ipapi.json'),
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
