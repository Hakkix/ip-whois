import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { buildReport, reportToJSON, reportToMarkdown, reportToText } from '../js/report.js';
import { normalizeRdap } from '../js/rdap.js';
import { normalizeGeoResponse, normalizeAsn } from '../js/geo.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name) => JSON.parse(readFileSync(join(here, 'fixtures', name), 'utf8'));

function fullReport() {
  const rdap = normalizeRdap(fixture('rdap-arin.json'), 'https://rdap.arin.net/registry/ip/93.184.216.34', 4);
  const geoRaw = fixture('geo-ipwhois.json');
  const location = normalizeGeoResponse(geoRaw, 'ipwho.is');
  const asn = normalizeAsn(geoRaw, 'ipwho.is');
  return buildReport({
    input: 'example.com',
    queryType: 'hostname',
    hostname: 'example.com',
    forwardAddresses: ['93.184.216.34'],
    ip: '93.184.216.34',
    version: 4,
    rdap,
    location,
    asn,
    reverse: { hostname: 'example.ptr.provider.net' },
    warnings: [],
  });
}

describe('buildReport', () => {
  test('produces a schema_version 2.0 report', () => {
    const r = fullReport();
    assert.equal(r.schema_version, '2.0');
    assert.ok(r.generated_at);
  });

  test('missing optional fields (no RDAP, no geo, no PTR) still produce a valid, minimal report', () => {
    const r = buildReport({
      input: '8.8.8.8', queryType: 'ipv4', hostname: null, forwardAddresses: [],
      ip: '8.8.8.8', version: 4, rdap: null, location: null, asn: null, reverse: null,
      warnings: [{ component: 'rdap', message: 'Registration data unavailable.' }],
    });
    assert.equal(r.ip.address, '8.8.8.8');
    assert.equal(r.network.name, null);
    assert.equal(r.location, null);
    assert.equal(r.asn, null);
    assert.deepEqual(r.dns.reverse, { hostname: null });
    assert.equal(r.warnings.length, 1);
    // never "N/A" / "unknown" / "-" placeholders inside the model
    const json = reportToJSON(r);
    assert.doesNotMatch(json, /"N\/A"|"unknown"|"-"/);
  });

  test('ASN prefix defaults to the network CIDR when the provider gave none', () => {
    const r = fullReport();
    assert.equal(r.asn.prefix, r.network.cidrs[0]);
  });

  test('PTR absence (null hostname) is not treated as an error', () => {
    const r = buildReport({
      input: '8.8.8.8', queryType: 'ipv4', hostname: null, forwardAddresses: [],
      ip: '8.8.8.8', version: 4, rdap: null, location: null, asn: null,
      reverse: { hostname: null }, warnings: [],
    });
    assert.equal(r.dns.reverse.hostname, null);
    assert.equal(r.warnings.length, 0);
  });
});

describe('report exporters', () => {
  test('JSON export is valid, parseable JSON containing the core fields', () => {
    const r = fullReport();
    const parsed = JSON.parse(reportToJSON(r));
    assert.equal(parsed.ip.address, '93.184.216.34');
    assert.equal(parsed.network.name, 'EXAMPLE-NET');
    assert.equal(parsed.asn.number, 15133);
    assert.equal(parsed.location.city, 'Helsinki');
    assert.equal(parsed.dns.reverse.hostname, 'example.ptr.provider.net');
    assert.ok(parsed.sources.rdap);
  });

  test('Markdown export contains geolocation, reverse DNS, and sources', () => {
    const md = reportToMarkdown(fullReport());
    assert.match(md, /## Geolocation/);
    assert.match(md, /Helsinki/);
    assert.match(md, /## DNS/);
    assert.match(md, /example\.ptr\.provider\.net/);
    assert.match(md, /## Data Sources/);
    assert.match(md, /approximate and represents network location/);
  });

  test('Text export contains geolocation, reverse DNS, and sources', () => {
    const txt = reportToText(fullReport());
    assert.match(txt, /GEOLOCATION/);
    assert.match(txt, /Helsinki/);
    assert.match(txt, /example\.ptr\.provider\.net/);
    assert.match(txt, /DATA SOURCES/);
  });

  test('a report with only IP + RDAP (no geo, no PTR) still exports cleanly in all formats', () => {
    const rdap = normalizeRdap(fixture('rdap-arin.json'), 'https://rdap.arin.net/registry/ip/93.184.216.34', 4);
    const r = buildReport({
      input: '93.184.216.34', queryType: 'ipv4', hostname: null, forwardAddresses: [],
      ip: '93.184.216.34', version: 4, rdap, location: null, asn: null, reverse: { hostname: null },
      warnings: [{ component: 'geolocation', message: 'Geolocation data unavailable.' }],
    });
    assert.doesNotThrow(() => JSON.parse(reportToJSON(r)));
    const md = reportToMarkdown(r);
    const txt = reportToText(r);
    assert.doesNotMatch(md, /## Geolocation/);
    assert.doesNotMatch(txt, /GEOLOCATION/);
    assert.match(md, /## Network/);
    assert.match(txt, /NETWORK/);
  });
});

describe('report consistency across representations', () => {
  test('a value present in the model appears in JSON, Markdown, and Text alike', () => {
    const r = fullReport();
    r.location.city = 'Helsinki';
    const json = reportToJSON(r);
    const md = reportToMarkdown(r);
    const txt = reportToText(r);
    for (const rendering of [json, md, txt]) {
      assert.match(rendering, /Helsinki/, 'Helsinki must appear in every export format');
    }
  });
});
