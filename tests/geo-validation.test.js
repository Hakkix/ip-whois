// GeoIP response validation: mocked providers only, no live network.
import { test, describe, beforeEach, afterEach, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { fetchGeo, fetchSelfGeo, normalizeGeoResponse, normalizeAsn, hasLocationData } from '../js/geo.js';
import { buildReport, reportToMarkdown, reportToText } from '../js/report.js';
import { createFakeDocument, walk } from './fixtures/dom-shim.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name) => JSON.parse(readFileSync(join(here, 'fixtures', name), 'utf8'));
const IP = '93.184.216.34';

const okJson = (data) => ({ ok: true, status: 200, json: async () => data });
const httpErr = (status) => ({ ok: false, status, json: async () => ({}) });
const badJson = () => ({ ok: true, status: 200, json: async () => { throw new SyntaxError('Unexpected token <'); } });

let originalFetch;
beforeEach(() => { originalFetch = globalThis.fetch; });
afterEach(() => { globalThis.fetch = originalFetch; });

// handlers: { 'ipinfo.io': () => resp, ... }; unlisted providers must not be hit.
function mock(handlers) {
  const hits = [];
  globalThis.fetch = async (url) => {
    const id = Object.keys(handlers).find((k) => url.includes(k));
    hits.push(id ?? url);
    if (!id) throw new Error(`unexpected fetch ${url}`);
    return handlers[id]();
  };
  return hits;
}
const good = { 'ipwho.is': () => okJson(fixture('geo-ipwhois.json')) };

describe('unusable provider responses fall through to the next provider', () => {
  const unusable = {
    'HTTP 200 with {}': () => okJson({}),
    'HTTP 200 with an array': () => okJson([fixture('geo-ipwhois.json')]),
    'HTTP 200 with null': () => okJson(null),
    'invalid JSON': badJson,
    'rate limited (HTTP 429)': () => httpErr(429),
    'ipinfo error payload': () => okJson({ error: { title: 'Rate limit exceeded' } }),
    'ipinfo bogon': () => okJson({ ip: IP, bogon: true }),
    'object with only an ip': () => okJson({ ip: IP }),
    'object with only unusable types': () => okJson({ ip: IP, city: 42, country: {}, loc: 7, org: ['AS1'] }),
    'response for a different address': () => okJson({ ...fixture('geo-ipinfo.json'), ip: '8.8.8.8' }),
    'non-string ip field': () => okJson({ ...fixture('geo-ipinfo.json'), ip: 1234 }),
  };
  for (const [name, respond] of Object.entries(unusable)) {
    test(name, async () => {
      mock({ 'ipinfo.io': respond, ...good });
      const r = await fetchGeo(IP);
      assert.equal(r.provider, 'ipwho.is');
    });
  }

  test('ipapi.co rate-limit body (HTTP 200, error:true) is skipped', async () => {
    mock({
      'ipinfo.io': () => httpErr(500),
      'ipwho.is': () => httpErr(500),
      'ipapi.co': () => okJson({ error: true, reason: 'RateLimited' }),
    });
    assert.equal(await fetchGeo(IP), null);
  });

  test('ipwho.is {success:false} is skipped', async () => {
    mock({ 'ipinfo.io': () => okJson({}), 'ipwho.is': () => okJson({ success: false, message: 'invalid IP address' }), 'ipapi.co': () => okJson(fixture('geo-ipapi.json')) });
    assert.equal((await fetchGeo(IP)).provider, 'ipapi.co');
  });

  test('all providers failing returns null without throwing', async () => {
    mock({ 'ipinfo.io': () => okJson({}), 'ipwho.is': badJson, 'ipapi.co': () => httpErr(503) });
    assert.equal(await fetchGeo(IP), null);
  });

  test('a matching IPv6 address in a different notation is accepted', async () => {
    mock({ 'ipinfo.io': () => okJson({ ...fixture('geo-ipinfo.json'), ip: '2001:0db8:0:0:0:0:0:1' }) });
    assert.equal((await fetchGeo('2001:db8::1')).provider, 'ipinfo.io');
  });

  test('provider provenance is preserved on the fallback result', async () => {
    mock({ 'ipinfo.io': () => okJson({}), ...good });
    const r = await fetchGeo(IP);
    assert.equal(normalizeGeoResponse(r.raw, r.provider).source, 'ipwho.is');
  });

  test('self lookup needs a valid ip in the answer, else cascades on', async () => {
    mock({ 'ipinfo.io': () => okJson({ city: 'Helsinki', country: 'FI' }), ...good });
    const r = await fetchSelfGeo();
    assert.equal(r.provider, 'ipwho.is');
    assert.equal(r.ip, IP);
  });
});

describe('partial responses are kept', () => {
  test('ASN and organisation without coordinates are accepted', async () => {
    mock({ 'ipinfo.io': () => okJson({ ip: IP, org: 'AS15133 Edgecast Inc.' }) });
    const r = await fetchGeo(IP);
    assert.equal(r.provider, 'ipinfo.io');
    assert.equal(normalizeAsn(r.raw, r.provider).number, 15133);
    const loc = normalizeGeoResponse(r.raw, r.provider);
    assert.equal(loc.latitude, null);
    assert.equal(hasLocationData(loc), false);
  });

  test('country-only location is accepted', async () => {
    mock({ 'ipinfo.io': () => okJson({ ip: IP, country: 'FI' }) });
    const r = await fetchGeo(IP);
    assert.equal(normalizeGeoResponse(r.raw, r.provider).country, 'Finland');
  });
});

describe('coordinate validation', () => {
  const badPairs = {
    NaN: [NaN, 10], Infinity: [Infinity, 10], '-Infinity': [10, -Infinity],
    'latitude > 90': [90.0001, 10], 'latitude < -90': [-91, 10],
    'longitude > 180': [10, 181], 'longitude < -180': [10, -180.5],
    'numeric strings': ['60.1', '24.9'], null: [null, null], 'one missing': [60.1, undefined],
  };
  for (const [name, [lat, lon]] of Object.entries(badPairs)) {
    test(`ipwho.is and ipapi.co drop ${name}`, () => {
      for (const [id, base] of [['ipwho.is', fixture('geo-ipwhois.json')], ['ipapi.co', fixture('geo-ipapi.json')]]) {
        const loc = normalizeGeoResponse({ ...base, latitude: lat, longitude: lon }, id);
        assert.equal(loc.latitude, null, id);
        assert.equal(loc.longitude, null, id);
        assert.equal(loc.city, 'Helsinki', 'the rest of the location is kept');
      }
    });
  }

  for (const loc of ['91,10', '10,181', 'abc,def', 'NaN,NaN', 'Infinity,5', ',', '60.1', 7, '10,']) {
    test(`ipinfo.io drops loc=${JSON.stringify(loc)}`, () => {
      const out = normalizeGeoResponse({ ...fixture('geo-ipinfo.json'), loc }, 'ipinfo.io');
      assert.equal(out.latitude, null);
      assert.equal(out.longitude, null);
    });
  }

  test('boundary values are valid', () => {
    const out = normalizeGeoResponse({ ...fixture('geo-ipwhois.json'), latitude: -90, longitude: 180 }, 'ipwho.is');
    assert.equal(out.latitude, -90);
    assert.equal(out.longitude, 180);
  });

  test('wrong field types are not carried into the model', () => {
    const out = normalizeGeoResponse({ ...fixture('geo-ipwhois.json'), city: { a: 1 }, region: 5, country_code: 'Finland', timezone: 7 }, 'ipwho.is');
    assert.equal(out.city, null);
    assert.equal(out.region, null);
    assert.equal(out.country_code, null);
    assert.equal(out.timezone, null);
  });

  test('wrong ASN field types yield no ASN instead of throwing', () => {
    assert.equal(normalizeAsn({ org: 5 }, 'ipinfo.io'), null);
    assert.equal(normalizeAsn({ connection: 'x' }, 'ipwho.is'), null);
    assert.equal(normalizeAsn({ asn: 15133 }, 'ipapi.co'), null);
    assert.equal(normalizeAsn({ connection: { asn: NaN } }, 'ipwho.is'), null);
    assert.equal(normalizeAsn({ connection: { asn: -4 } }, 'ipwho.is'), null);
  });
});

describe('invalid coordinates never reach exports or the map', () => {
  let renderReport;
  let mapCalls;
  before(async () => {
    globalThis.document = createFakeDocument();
    ({ renderReport } = await import('../js/render.js'));
  });
  beforeEach(() => {
    mapCalls = 0;
    globalThis.window = { L: { map() { mapCalls++; throw new Error('map must not be created'); } } };
  });
  afterEach(() => { delete globalThis.window; });

  // A location built by hand, bypassing normalisation, to test the second line of defence.
  const report = (latitude, longitude) => buildReport({
    input: IP, queryType: 'ipv4', hostname: null, forwardAddresses: [], ip: IP, version: 4,
    location: { country: 'Finland', country_code: 'FI', region: null, city: 'Helsinki', postal_code: null, timezone: null, latitude, longitude, source: 'ipwho.is', precision: 'approximate' },
  });

  for (const [lat, lon] of [[NaN, 1], [Infinity, 1], [95, 1], [1, 200], ['1', '2']]) {
    test(`(${String(lat)}, ${String(lon)}) is not mapped, shown, or exported`, () => {
      const r = report(lat, lon);
      const container = document.createElement('div');
      assert.doesNotThrow(() => renderReport(container, r));
      assert.equal(mapCalls, 0);
      assert.equal(walk(container).some((n) => /geo-map/.test(n.className)), false);
      assert.doesNotMatch(reportToMarkdown(r), /OpenStreetMap|Coordinates/);
      assert.doesNotMatch(reportToText(r), /Coordinates/);
    });
  }

  test('valid coordinates still reach the map', () => {
    renderReport(document.createElement('div'), report(60.17, 24.94));
    assert.equal(mapCalls, 1);
  });
});
