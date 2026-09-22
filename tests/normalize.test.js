import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  classifyInput, ptrNameForIPv4, ptrNameForIPv6, expandIPv6, rangeToCidrs, isReservedIP,
} from '../js/utils.js';
import { normalizeGeoResponse, normalizeAsn } from '../js/geo.js';
import { normalizeRdap, detectRir } from '../js/rdap.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name) => JSON.parse(readFileSync(join(here, 'fixtures', name), 'utf8'));

describe('input parsing', () => {
  test('valid IPv4', () => {
    assert.deepEqual(classifyInput('8.8.8.8'), { type: 'ipv4', value: '8.8.8.8' });
  });

  test('valid IPv6', () => {
    assert.deepEqual(classifyInput('2001:4860:4860::8888'), { type: 'ipv6', value: '2001:4860:4860::8888' });
  });

  test('compressed IPv6', () => {
    const r = classifyInput('::1');
    assert.equal(r.type, 'ipv6');
  });

  test('valid hostname', () => {
    assert.deepEqual(classifyInput('example.com'), { type: 'hostname', value: 'example.com' });
  });

  test('uppercase hostname is lowercased', () => {
    assert.deepEqual(classifyInput('Example.COM'), { type: 'hostname', value: 'example.com' });
  });

  test('whitespace is trimmed', () => {
    assert.deepEqual(classifyInput('  example.com  '), { type: 'hostname', value: 'example.com' });
  });

  test('invalid IPv4 is rejected', () => {
    assert.equal(classifyInput('999.999.999.999'), null);
  });

  test('invalid IPv6 is rejected', () => {
    assert.equal(classifyInput('2001::db8::1'), null);
  });

  test('invalid hostname is rejected', () => {
    assert.equal(classifyInput('not a hostname'), null);
  });

  test('empty input is rejected', () => {
    assert.equal(classifyInput(''), null);
    assert.equal(classifyInput('   '), null);
  });

  test('malicious HTML input is rejected as a query', () => {
    assert.equal(classifyInput('<script>alert(1)</script>'), null);
  });

  test('a full URL is rejected, not silently reduced to a hostname', () => {
    assert.equal(classifyInput('https://example.com/foo'), null);
  });

  test('reserved / private IPv4 ranges are flagged', () => {
    assert.equal(isReservedIP(4, '10.0.0.1'), true);
    assert.equal(isReservedIP(4, '192.168.1.1'), true);
    assert.equal(isReservedIP(4, '127.0.0.1'), true);
    assert.equal(isReservedIP(4, '8.8.8.8'), false);
  });

  test('reserved IPv6 ranges are flagged', () => {
    assert.equal(isReservedIP(6, '::1'), true);
    assert.equal(isReservedIP(6, 'fe80::1'), true);
    assert.equal(isReservedIP(6, '2001:4860:4860::8888'), false);
  });
});

describe('PTR name generation', () => {
  test('IPv4 reverses octets under in-addr.arpa', () => {
    assert.equal(ptrNameForIPv4('1.2.3.4'), '4.3.2.1.in-addr.arpa');
    assert.equal(ptrNameForIPv4('8.8.8.8'), '8.8.8.8.in-addr.arpa');
  });

  test('IPv6 fully expands and nibble-reverses under ip6.arpa', () => {
    const name = ptrNameForIPv6('2001:db8::1');
    assert.equal(name, '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa');
    assert.equal(name.endsWith('.ip6.arpa'), true);
    assert.equal(name.replace('.ip6.arpa', '').split('.').length, 32);
  });

  test('IPv6 expansion fills the compressed run with zero groups', () => {
    assert.deepEqual(expandIPv6('2001:db8::1'), ['2001', '0db8', '0000', '0000', '0000', '0000', '0000', '0001']);
  });

  test('IPv6 expansion handles an embedded IPv4 tail', () => {
    assert.deepEqual(expandIPv6('::ffff:1.2.3.4'), ['0000', '0000', '0000', '0000', '0000', 'ffff', '0102', '0304']);
  });
});

describe('CIDR range fallback', () => {
  test('a single aligned IPv4 /24 collapses to one block', () => {
    assert.deepEqual(rangeToCidrs('93.184.216.0', '93.184.216.255', 4), ['93.184.216.0/24']);
  });

  test('an unaligned IPv4 range is covered by multiple blocks', () => {
    const cidrs = rangeToCidrs('93.184.216.10', '93.184.216.20', 4);
    assert.ok(cidrs.length > 1);
  });

  test('an aligned IPv6 /32 collapses to one block', () => {
    assert.deepEqual(
      rangeToCidrs('2800:3f0::', '2800:3f0:ffff:ffff:ffff:ffff:ffff:ffff', 6),
      ['2800:3f0::/32'],
    );
  });
});

describe('geolocation normalization', () => {
  const expectedBase = {
    country: 'Finland', country_code: 'FI', region: 'Uusimaa', city: 'Helsinki',
    postal_code: '00100', timezone: 'Europe/Helsinki', latitude: 60.1699, longitude: 24.9384,
    precision: 'approximate',
  };

  test('ipinfo.io normalizes to the shared schema', () => {
    const raw = fixture('geo-ipinfo.json');
    assert.deepEqual(normalizeGeoResponse(raw, 'ipinfo.io'), { ...expectedBase, source: 'ipinfo.io' });
  });

  test('ipwho.is normalizes to the shared schema', () => {
    const raw = fixture('geo-ipwhois.json');
    assert.deepEqual(normalizeGeoResponse(raw, 'ipwho.is'), { ...expectedBase, source: 'ipwho.is' });
  });

  test('ipapi.co normalizes to the shared schema', () => {
    const raw = fixture('geo-ipapi.json');
    assert.deepEqual(normalizeGeoResponse(raw, 'ipapi.co'), { ...expectedBase, source: 'ipapi.co' });
  });

  test('region/postal field-name variants all land on the same stable field', () => {
    const providers = ['ipinfo.io', 'ipwho.is', 'ipapi.co'];
    for (const p of providers) {
      const norm = normalizeGeoResponse(fixture(
        p === 'ipinfo.io' ? 'geo-ipinfo.json' : p === 'ipwho.is' ? 'geo-ipwhois.json' : 'geo-ipapi.json',
      ), p);
      assert.equal(norm.region, 'Uusimaa');
      assert.equal(norm.postal_code, '00100');
    }
  });
});

describe('ASN extraction', () => {
  test('ipinfo.io org string is parsed into number + organization', () => {
    const asn = normalizeAsn(fixture('geo-ipinfo.json'), 'ipinfo.io');
    assert.equal(asn.number, 15133);
    assert.equal(asn.display, 'AS15133');
    assert.equal(asn.organization, 'Edgecast Inc.');
  });

  test('ipwho.is connection object is parsed', () => {
    const asn = normalizeAsn(fixture('geo-ipwhois.json'), 'ipwho.is');
    assert.equal(asn.number, 15133);
    assert.equal(asn.organization, 'Edgecast Inc.');
  });

  test('ipapi.co asn/org fields are parsed', () => {
    const asn = normalizeAsn(fixture('geo-ipapi.json'), 'ipapi.co');
    assert.equal(asn.number, 15133);
    assert.equal(asn.organization, 'EDGECAST');
  });

  test('missing ASN data normalizes to null, never an invented value', () => {
    assert.equal(normalizeAsn({}, 'ipinfo.io'), null);
  });
});

describe('RDAP normalization across RIRs', () => {
  const cases = [
    ['ARIN', 'rdap-arin.json', 'https://rdap.arin.net/registry/ip/93.184.216.34', 4],
    ['RIPE NCC', 'rdap-ripe.json', 'https://rdap.db.ripe.net/ip/193.0.0.5', 4],
    ['APNIC', 'rdap-apnic.json', 'https://rdap.apnic.net/ip/203.0.0.5', 4],
    ['LACNIC', 'rdap-lacnic.json', 'https://rdap.lacnic.net/rdap/ip/2800:3f0::1', 6],
    ['AFRINIC', 'rdap-afrinic.json', 'https://rdap.afrinic.net/rdap/ip/196.11.240.5', 4],
  ];

  for (const [rirName, file, finalUrl, version] of cases) {
    test(`${rirName} fixture normalizes without structural differences leaking through`, () => {
      const raw = fixture(file);
      const rir = detectRir(finalUrl, raw);
      assert.equal(rir.name, rirName);

      const normalized = normalizeRdap(raw, finalUrl, version);
      assert.equal(normalized.rir.name, rirName);
      assert.ok(normalized.network.name);
      assert.ok(normalized.network.handle);
      assert.ok(normalized.network.cidrs.length > 0, 'a CIDR is present, from cidr0 or the range fallback');
      assert.ok(normalized.registration.registered_at);
      assert.equal(typeof normalized.registrant, 'object');
      assert.equal(typeof normalized.contacts, 'object');
      assert.ok(Array.isArray(normalized.remarks));
    });
  }

  test('CIDR falls back to range computation when cidr0 is absent (ARIN fixture)', () => {
    const raw = fixture('rdap-arin.json');
    const normalized = normalizeRdap(raw, 'https://rdap.arin.net/registry/ip/93.184.216.34', 4);
    assert.deepEqual(normalized.network.cidrs, ['93.184.216.0/24']);
  });

  test('cidr0 extension is used directly when present (RIPE fixture)', () => {
    const raw = fixture('rdap-ripe.json');
    const normalized = normalizeRdap(raw, 'https://rdap.db.ripe.net/ip/193.0.0.5', 4);
    assert.deepEqual(normalized.network.cidrs, ['193.0.0.0/21']);
  });

  test('contacts are grouped by role, not dumped raw', () => {
    const raw = fixture('rdap-arin.json');
    const normalized = normalizeRdap(raw, 'https://rdap.arin.net/registry/ip/93.184.216.34', 4);
    assert.equal(normalized.contacts.abuse.length, 1);
    assert.equal(normalized.contacts.abuse[0].email, 'abuse@example.net');
    assert.equal(normalized.contacts.registrant.length, 1);
  });

  test('registration events are normalized with ISO timestamps', () => {
    const raw = fixture('rdap-arin.json');
    const normalized = normalizeRdap(raw, 'https://rdap.arin.net/registry/ip/93.184.216.34', 4);
    assert.equal(normalized.registration.registered_at, '2010-01-01T00:00:00.000Z');
    assert.equal(normalized.registration.last_changed_at, '2024-01-01T00:00:00.000Z');
  });
});
