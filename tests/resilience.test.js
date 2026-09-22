// Exercises the provider-failure paths from the spec (RDAP down, first/all
// geolocation providers down, PTR NXDOMAIN, partial DNS resolution) using a
// mocked global fetch — no live network access is used or required.
import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { fetchGeo } from '../js/geo.js';
import { fetchRdap } from '../js/rdap.js';
import { resolveHostname, reversePTR } from '../js/dns.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name) => JSON.parse(readFileSync(join(here, 'fixtures', name), 'utf8'));

const okJson = (data, url = 'https://example.invalid/') => ({ ok: true, status: 200, url, json: async () => data });
const failHttp = (status = 500) => ({ ok: false, status, json: async () => ({}) });

let originalFetch;
beforeEach(() => { originalFetch = globalThis.fetch; });
afterEach(() => { globalThis.fetch = originalFetch; });

function mockFetch(handlers) {
  globalThis.fetch = async (url) => {
    for (const [matcher, respond] of handlers) {
      if (typeof matcher === 'string' ? url.includes(matcher) : matcher.test(url)) {
        return respond(url);
      }
    }
    throw new Error(`unhandled fetch in test: ${url}`);
  };
}

describe('geolocation provider cascade', () => {
  test('falls through to the second provider when the first fails', async () => {
    mockFetch([
      ['ipinfo.io', () => { throw new Error('network error'); }],
      ['ipwho.is', () => okJson(fixture('geo-ipwhois.json'))],
      ['ipapi.co', () => { throw new Error('should not be reached'); }],
    ]);
    const result = await fetchGeo('93.184.216.34');
    assert.equal(result.provider, 'ipwho.is');
  });

  test('falls through past a provider that responds 200 but reports failure in its body', async () => {
    mockFetch([
      ['ipinfo.io', () => failHttp(429)],
      ['ipwho.is', () => okJson(fixture('geo-failure.json'))],
      ['ipapi.co', () => okJson(fixture('geo-ipapi.json'))],
    ]);
    const result = await fetchGeo('93.184.216.34');
    assert.equal(result.provider, 'ipapi.co');
  });

  test('returns null (not a throw) when every provider fails', async () => {
    mockFetch([
      ['ipinfo.io', () => failHttp(500)],
      ['ipwho.is', () => okJson(fixture('geo-failure.json'))],
      ['ipapi.co', () => { throw new Error('timeout'); }],
    ]);
    const result = await fetchGeo('93.184.216.34');
    assert.equal(result, null);
  });
});

describe('RDAP failure', () => {
  test('a non-OK RDAP response raises a clear, catchable error', async () => {
    mockFetch([[/rdap-bootstrap/, () => failHttp(404)]]);
    await assert.rejects(() => fetchRdap('93.184.216.34'), /RDAP lookup failed/);
  });
});

describe('DNS resolution', () => {
  test('resolves successfully when only AAAA records exist (IPv6-only host)', async () => {
    mockFetch([
      [/type=A(?!AAA)/, () => okJson({ Status: 0, Question: [{ type: 1 }], Answer: [] })],
      [/type=AAAA/, () => okJson({
        Status: 0,
        Question: [{ type: 28 }],
        Answer: [{ type: 28, data: '2606:2800:220:1:248:1893:25c8:1946' }],
      })],
    ]);
    const result = await resolveHostname('ipv6-only.example');
    assert.deepEqual(result.addresses, ['2606:2800:220:1:248:1893:25c8:1946']);
  });

  test('resolves nothing (empty addresses) when neither A nor AAAA exist — not a thrown error', async () => {
    mockFetch([
      [/type=A(?!AAA)/, () => okJson({ Status: 0, Question: [{ type: 1 }], Answer: [] })],
      [/type=AAAA/, () => okJson({ Status: 0, Question: [{ type: 28 }], Answer: [] })],
    ]);
    const result = await resolveHostname('nonexistent.example');
    assert.deepEqual(result.addresses, []);
  });
});

describe('reverse DNS (PTR)', () => {
  test('NXDOMAIN (Status 3) resolves to { hostname: null }, not an error', async () => {
    mockFetch([[/type=PTR/, () => okJson({ Status: 3, Question: [{ type: 12 }] })]]);
    const result = await reversePTR('203.0.113.5', 4);
    assert.deepEqual(result, { hostname: null });
  });

  test('a PTR record is parsed and its trailing dot stripped', async () => {
    mockFetch([[/type=PTR/, () => okJson({
      Status: 0,
      Question: [{ type: 12 }],
      Answer: [{ type: 12, data: 'dns.google.' }],
    })]]);
    const result = await reversePTR('8.8.8.8', 4);
    assert.deepEqual(result, { hostname: 'dns.google' });
  });

  test('every DoH provider being unreachable resolves to { hostname: null }, never throws', async () => {
    mockFetch([[/./, () => { throw new Error('network down'); }]]);
    const result = await reversePTR('8.8.8.8', 4);
    assert.deepEqual(result, { hostname: null });
  });
});
