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

// A well-formed /api/tls success payload, as the server would produce it.
export const tlsOk = (over = {}) => ({
  status: 'ok', hostname: 'example.com', connected_ip: '93.184.216.34', port: 443, observed_at: '2026-10-23T08:00:00.000Z',
  certificate: {
    subject: 'O=Example Org, CN=example.com', issuer: 'O=Example CA, CN=Example Issuing CA 1',
    sans: ['example.com', 'www.example.com'], serial_number: '0A1B2C', valid_from: '2026-01-01T00:00:00.000Z',
    valid_to: '2027-01-01T00:00:00.000Z', days_remaining: 69, date_status: 'valid', expiring_soon: false,
    fingerprint_sha256: 'AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89',
    public_key: { algorithm: 'RSA', size: 2048, curve: null },
  },
  connection: { protocol: 'TLSv1.3', cipher: 'TLS_AES_256_GCM_SHA384', hostname_match: true, trust_status: 'valid', trust_detail: null },
  validation: { overall: 'valid', problems: [] },
  chain: [
    { position: 0, role: 'leaf', subject: 'CN=example.com', issuer: 'CN=Example Issuing CA 1', valid_from: '2026-01-01T00:00:00.000Z', valid_to: '2027-01-01T00:00:00.000Z', fingerprint_sha256: 'AA:AA', self_issued: false, presented: true },
    { position: 1, role: 'intermediate', subject: 'CN=Example Issuing CA 1', issuer: 'CN=Example Root', valid_from: null, valid_to: null, fingerprint_sha256: 'BB:BB', self_issued: false, presented: true },
    { position: 2, role: 'root', subject: 'CN=Example Root', issuer: 'CN=Example Root', valid_from: null, valid_to: null, fingerprint_sha256: 'CC:CC', self_issued: true, presented: null },
  ],
  chain_summary: { count: 3, truncated: false, validated: true },
  error_code: null, error_message: null,
  ...over,
});

// DoH answers for the given name → addresses (A records); everything else empty.
export const dohFor = (table) => (url) => {
  const u = new URL(url);
  const type = u.searchParams.get('type');
  const name = u.searchParams.get('name');
  const q = { type: { A: 1, AAAA: 28, PTR: 12 }[type] };
  if (type === 'PTR') return json({ Status: 0, Question: [q], Answer: [{ type: 12, data: 'dns.example.net.' }] });
  const addrs = type === 'A' ? table[name] || [] : [];
  return json({ Status: 0, Question: [q], Answer: addrs.map((data) => ({ type: 1, data })) });
};

export const defaults = {
  tls: () => json(tlsOk()),
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
  await page.route('**/api/tls', async (r) => {
    const body = r.request().postDataJSON();
    requests.push(`${r.request().url()} ${JSON.stringify(body)}`);
    await r.fulfill(await h.tls(body));
  });
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
