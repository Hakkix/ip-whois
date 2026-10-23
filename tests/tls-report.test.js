import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { createFakeDocument, walk } from './fixtures/dom-shim.js';
import { buildReport, withTls, reportToJSON, reportToMarkdown, reportToText } from '../js/report.js';
import { normalizeTlsResponse, fetchTls, tlsPending, tlsTone, tlsVerdict } from '../js/tls.js';

const apiOk = () => ({
  status: 'ok', hostname: 'example.com', connected_ip: '93.184.216.34', port: 443, observed_at: '2026-10-23T08:00:00.000Z',
  certificate: {
    subject: 'O=Example, CN=example.com', issuer: 'CN=Example CA', sans: ['example.com', 'www.example.com'],
    serial_number: 'ABCDEF', valid_from: '2026-01-01T00:00:00.000Z', valid_to: '2027-01-01T00:00:00.000Z',
    days_remaining: 69, date_status: 'valid', expiring_soon: false,
    fingerprint_sha256: 'AA:BB:CC', public_key: { algorithm: 'RSA', size: 2048, curve: null },
  },
  connection: { protocol: 'TLSv1.3', cipher: 'TLS_AES_256_GCM_SHA384', hostname_match: true, trust_status: 'valid', trust_detail: null },
  validation: { overall: 'valid', problems: [] },
  chain: [
    { position: 0, role: 'leaf', subject: 'CN=example.com', issuer: 'CN=Example CA', valid_from: null, valid_to: null, fingerprint_sha256: 'AA', self_issued: false, presented: true },
    { position: 1, role: 'root', subject: 'CN=Example Root', issuer: 'CN=Example Root', valid_from: null, valid_to: null, fingerprint_sha256: 'BB', self_issued: true, presented: null },
  ],
  chain_summary: { count: 2, truncated: false, validated: true },
  error_code: null, error_message: null,
});
const ctx = { hostname: 'example.com', ip: '93.184.216.34' };

function report(tls) {
  return buildReport({
    input: 'example.com', queryType: 'hostname', hostname: 'example.com', forwardAddresses: ['93.184.216.34'],
    ip: '93.184.216.34', version: 4, tls,
  });
}

describe('normalizeTlsResponse', () => {
  test('passes a fully valid response through', () => {
    const t = normalizeTlsResponse(apiOk(), ctx);
    assert.equal(t.status, 'ok');
    assert.equal(tlsTone(t), 'valid');
    assert.equal(tlsVerdict(t), 'Valid');
  });
  test('never shows ok when the individual checks do not all pass', () => {
    for (const mutate of [
      (r) => { r.connection.hostname_match = false; },
      (r) => { r.connection.trust_status = 'untrusted'; },
      (r) => { r.certificate.date_status = 'expired'; },
      (r) => { r.connection.hostname_match = null; },
    ]) {
      const raw = apiOk(); mutate(raw);
      const t = normalizeTlsResponse(raw, ctx);
      assert.equal(t.status, 'invalid');
      assert.notEqual(tlsTone(t), 'valid');
      assert.equal(t.validation.overall, raw.connection.hostname_match === null ? 'unknown' : 'invalid');
      assert.ok(t.error_code);
    }
  });
  test('expiring soon is still valid but flagged', () => {
    const raw = apiOk(); raw.certificate.days_remaining = 12; raw.certificate.expiring_soon = true;
    const t = normalizeTlsResponse(raw, ctx);
    assert.equal(t.status, 'ok');
    assert.equal(tlsTone(t), 'warning');
    assert.equal(tlsVerdict(t), 'Valid — expires in 12 days');
  });
  test('failure statuses become structured results', () => {
    const t = normalizeTlsResponse({ status: 'unavailable', error_code: 'connection_refused', error_message: 'The server refused the connection on port 443.' }, ctx);
    assert.equal(t.status, 'unavailable');
    assert.equal(t.error_code, 'connection_refused');
    assert.equal(t.certificate, null);
    assert.equal(t.hostname, 'example.com');
    assert.equal(normalizeTlsResponse({ status: 'blocked', error_code: 'destination_not_public' }, ctx).status, 'blocked');
  });
  test('garbage becomes a bad_response failure, not a throw', () => {
    for (const bad of [null, undefined, 'x', 5, {}, { status: 'lol' }, { status: 'ok' }]) {
      const t = normalizeTlsResponse(bad, ctx);
      assert.equal(t.status, 'unavailable');
      assert.equal(t.error_code, 'bad_response');
    }
  });
  test('bounds sizes and strips unknown fields', () => {
    const raw = apiOk();
    raw.certificate.sans = Array.from({ length: 500 }, (_, i) => `h${i}.com`);
    raw.certificate.subject = 'x'.repeat(5000);
    raw.chain = Array.from({ length: 50 }, () => raw.chain[0]);
    raw.secret = 'nope';
    const t = normalizeTlsResponse(raw, ctx);
    assert.equal(t.certificate.sans.length, 100);
    assert.equal(t.certificate.subject.length, 300);
    assert.equal(t.chain.length, 8);
    assert.equal('secret' in t, false);
  });
});

describe('fetchTls', () => {
  const resp = (status, body) => ({ status, json: async () => { if (body === undefined) throw new Error('no json'); return body; } });
  test('POSTs only hostname and ip to the same-origin endpoint', async () => {
    let seen;
    const t = await fetchTls('example.com', '93.184.216.34', { fetchImpl: async (url, init) => { seen = { url, init }; return resp(200, apiOk()); } });
    assert.equal(seen.url, '/api/tls');
    assert.equal(seen.init.method, 'POST');
    assert.deepEqual(JSON.parse(seen.init.body), { hostname: 'example.com', ip: '93.184.216.34' });
    assert.equal(seen.init.credentials, 'omit');
    assert.equal(t.status, 'ok');
  });
  test('network error, 404, bad JSON and timeouts all settle as structured failures', async () => {
    assert.equal((await fetchTls('a.com', '8.8.8.8', { fetchImpl: async () => { throw new TypeError('x'); } })).error_code, 'client_network');
    assert.equal((await fetchTls('a.com', '8.8.8.8', { fetchImpl: async () => resp(404, undefined) })).error_code, 'not_found');
    assert.equal((await fetchTls('a.com', '8.8.8.8', { fetchImpl: async () => resp(200, undefined) })).error_code, 'bad_response');
    const hang = (_u, init) => new Promise((_r, rej) => init.signal.addEventListener('abort', () => rej(new Error('aborted'))));
    const t = await fetchTls('a.com', '8.8.8.8', { fetchImpl: hang, timeoutMs: 50 });
    assert.equal(t.status, 'unavailable');
    assert.equal(t.error_code, 'client_timeout');
  });
  test('an external abort settles as a failure too', async () => {
    const ac = new AbortController();
    const hang = (_u, init) => new Promise((_r, rej) => init.signal.addEventListener('abort', () => rej(new Error('aborted'))));
    const p = fetchTls('a.com', '8.8.8.8', { fetchImpl: hang, signal: ac.signal });
    ac.abort();
    assert.equal((await p).error_code, 'client_network');
  });
  test('server 4xx/5xx JSON bodies are normalized, not thrown', async () => {
    const t = await fetchTls('a.com', '8.8.8.8', { fetchImpl: async () => resp(403, { status: 'blocked', error_code: 'destination_not_public', error_message: 'm' }) });
    assert.equal(t.status, 'blocked');
  });
});

describe('report model', () => {
  test('tls is null when not applicable (IP-only)', () => {
    const r = buildReport({ input: '8.8.8.8', queryType: 'ipv4', hostname: null, ip: '8.8.8.8', version: 4 });
    assert.equal(r.tls, null);
    assert.equal(r.sources.tls, null);
    assert.ok(!reportToMarkdown(r).includes('TLS Certificate'));
    assert.ok(!reportToText(r).includes('TLS CERTIFICATE'));
    assert.match(reportToJSON(r), /"tls": null/);
  });
  test('withTls applies a late result and its source without mutating the original', () => {
    const before = report(tlsPending('example.com', '93.184.216.34'));
    const after = withTls(before, normalizeTlsResponse(apiOk(), ctx));
    assert.equal(before.tls.status, 'pending');
    assert.equal(after.tls.status, 'ok');
    assert.equal(after.sources.tls.retrieved_at, '2026-10-23T08:00:00.000Z');
    assert.equal(after.generated_at, before.generated_at);
  });
});

describe('export consistency', () => {
  const cases = {
    ok: () => normalizeTlsResponse(apiOk(), ctx),
    invalid: () => { const r = apiOk(); r.connection.hostname_match = false; r.validation = { overall: 'invalid', problems: ['hostname_mismatch'] }; r.status = 'invalid'; r.error_code = 'hostname_mismatch'; r.error_message = 'The certificate is not valid for this hostname.'; return normalizeTlsResponse(r, ctx); },
    unavailable: () => normalizeTlsResponse({ status: 'unavailable', error_code: 'connection_timeout', error_message: 'The connection to port 443 timed out.' }, ctx),
    pending: () => tlsPending('example.com', '93.184.216.34'),
  };
  for (const [name, make] of Object.entries(cases)) {
    test(`JSON, Markdown and text agree for status ${name}`, () => {
      const r = report(make());
      const json = JSON.parse(reportToJSON(r));
      assert.deepEqual(json.tls, r.tls);
      assert.equal(json.schema_version, '2.2');
      const md = reportToMarkdown(r);
      const txt = reportToText(r);
      assert.match(md, /## TLS Certificate/);
      assert.match(txt, /TLS CERTIFICATE/);
      const verdict = tlsVerdict(r.tls);
      assert.ok(md.includes(verdict), `markdown has "${verdict}"`);
      assert.ok(txt.includes(verdict), `text has "${verdict}"`);
      assert.match(md, /TLS certificate \| ip-whois \/api\/tls/);
      assert.match(txt, /TLS certificate\s+ip-whois \/api\/tls/);
      if (r.tls.error_code) {
        assert.ok(md.includes(r.tls.error_code) && txt.includes(r.tls.error_code));
      }
      if (r.tls.certificate) {
        for (const v of [r.tls.certificate.subject, r.tls.certificate.issuer, r.tls.certificate.fingerprint_sha256,
          r.tls.certificate.sans.join(', '), r.tls.connection.protocol, r.tls.connection.cipher, r.tls.connected_ip, r.tls.hostname]) {
          assert.ok(md.includes(v) && txt.includes(v), `both exports include ${v}`);
        }
        assert.ok(md.includes('Root (trust anchor)') && txt.includes('not confirmed as sent by the server'));
      }
    });
  }
  test('invalid certificate is never described as valid in any export', () => {
    const r = report(cases.invalid());
    for (const out of [reportToMarkdown(r), reportToText(r)]) {
      assert.ok(!/Status\s*\|?\s+Valid\b/.test(out));
      assert.match(out, /Does not match certificate names/);
    }
  });
});

describe('TLS card rendering', () => {
  let renderReport;
  before(async () => {
    globalThis.document = createFakeDocument();
    ({ renderReport } = await import('../js/render.js'));
  });
  const textOf = (c) => walk(c).map((n) => n._text || '').join('\n');
  test('IP-only report explains SNI instead of calling TLS', () => {
    const c = document.createElement('div');
    renderReport(c, buildReport({ input: '8.8.8.8', queryType: 'ipv4', hostname: null, ip: '8.8.8.8', version: 4 }));
    assert.match(textOf(c), /SNI/);
  });
  test('hostile certificate strings stay inert text', () => {
    const raw = apiOk();
    raw.certificate.subject = '<img src=x onerror=alert(1)>';
    raw.certificate.sans = ['<script>alert(1)</script>'];
    raw.chain[0].subject = '<img src=x onerror=alert(1)>';
    const c = document.createElement('div');
    renderReport(c, report(normalizeTlsResponse(raw, ctx)));
    const nodes = walk(c);
    assert.equal(nodes.filter((n) => n.tagName === 'IMG' || n.tagName === 'SCRIPT').length, 0);
    assert.match(textOf(c), /alert\(1\)/);
  });
  test('an invalid result never gets the valid tone class', () => {
    const raw = apiOk(); raw.connection.hostname_match = false;
    const c = document.createElement('div');
    renderReport(c, report(normalizeTlsResponse(raw, ctx)));
    const classes = walk(c).map((n) => n.className || '').join(' ');
    assert.ok(!/tls-valid/.test(classes));
    assert.ok(/tls-(unknown|invalid)/.test(classes));
  });
});
