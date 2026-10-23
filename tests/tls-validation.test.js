import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  validateHostname, isPublicIp, normalizeIp, resolvePublicAddresses, selectValidatedAddress,
} from '../api/_lib/tls-validation.js';

describe('validateHostname', () => {
  test('accepts and normalizes public hostnames', () => {
    assert.deepEqual(validateHostname('Example.COM'), { ok: true, hostname: 'example.com' });
    assert.deepEqual(validateHostname('example.com.'), { ok: true, hostname: 'example.com' });
    assert.deepEqual(validateHostname('sub-1.example.co.uk'), { ok: true, hostname: 'sub-1.example.co.uk' });
  });
  test('converts internationalized names to punycode', () => {
    assert.deepEqual(validateHostname('bücher.example.com'), { ok: true, hostname: 'xn--bcher-kva.example.com' });
  });
  test('rejects URLs, credentials, paths, queries, ports and whitespace', () => {
    for (const bad of ['https://example.com', 'user:pw@example.com', 'user@example.com', 'example.com/path',
      'example.com?x=1', 'example.com#f', 'example.com:8443', 'exa mple.com', 'example.com\n', '[::1]', 'a..b.com', '.example.com', 'ex%41mple.com']) {
      assert.equal(validateHostname(bad).ok, false, bad);
    }
  });
  test('rejects IP literals in every spelling', () => {
    for (const bad of ['127.0.0.1', '8.8.8.8', '2130706433', '0x7f.1', '0x7f.0.0.1', '127.1', '1.2.3.4.', '::1', '2001:db8::1', '010.0.0.1']) {
      assert.equal(validateHostname(bad).ok, false, bad);
    }
  });
  test('rejects localhost, single labels and local/internal names', () => {
    for (const bad of ['localhost', 'foo.localhost', 'intranet', 'printer.local', 'db.internal', 'x.lan', 'host.home.arpa', '1.0.0.127.in-addr.arpa', 'a.test', 'a.example', 'abcdefghijklmnop.onion']) {
      assert.equal(validateHostname(bad).ok, false, bad);
    }
  });
  test('enforces length limits and non-strings', () => {
    assert.equal(validateHostname(`${'a'.repeat(64)}.com`).ok, false);
    assert.equal(validateHostname(`${'a.'.repeat(130)}com`).ok, false);
    assert.equal(validateHostname('-bad.example.com').ok, false);
    assert.equal(validateHostname('a'.repeat(5000)).ok, false);
    for (const v of [null, undefined, 5, {}, [], true]) assert.equal(validateHostname(v).ok, false);
  });
  test('rejects numeric or malformed TLDs', () => {
    assert.equal(validateHostname('example.123').ok, false);
    assert.equal(validateHostname('example.-com').ok, false);
  });
});

describe('isPublicIp', () => {
  test('accepts globally routable IPv4/IPv6', () => {
    for (const ip of ['8.8.8.8', '93.184.216.34', '1.1.1.1', '172.32.0.1', '100.63.255.255', '2606:2800:220:1:248:1893:25c8:1946', '2001:4860:4860::8888', '2a00:1450:4001::200e']) {
      assert.equal(isPublicIp(ip), true, ip);
    }
  });
  test('rejects private, loopback, link-local, multicast, documentation, CGNAT and reserved IPv4', () => {
    for (const ip of ['0.0.0.0', '10.1.2.3', '100.64.0.1', '100.127.255.255', '127.0.0.1', '127.255.255.254', '169.254.169.254',
      '172.16.0.1', '172.31.255.255', '192.0.0.1', '192.0.2.1', '192.168.1.1', '198.18.0.1', '198.19.255.255', '198.51.100.9',
      '203.0.113.9', '224.0.0.1', '239.255.255.255', '240.0.0.1', '255.255.255.255']) {
      assert.equal(isPublicIp(ip), false, ip);
    }
  });
  test('rejects non-global IPv6 and embedding edge cases', () => {
    for (const ip of ['::', '::1', 'fe80::1', 'fc00::1', 'fd12:3456::1', 'ff02::1', '2001:db8::1', '2001::1', '2002:7f00:1::1',
      '2002:c0a8:101::', '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:8.8.8.8', '0:0:0:0:0:ffff:a00:1', '64:ff9b::7f00:1', '::127.0.0.1',
      '3fff::1', 'fe80::1%eth0']) {
      assert.equal(isPublicIp(ip), false, ip);
    }
  });
  test('rejects malformed addresses and non-strings', () => {
    for (const ip of ['1.2.3', '1.2.3.256', '01.2.3.4', '1.2.3.4.5', 'abc', '', ' 8.8.8.8', '8.8.8.8 ', '0x08080808', '134744072', null, undefined, 8]) {
      assert.equal(isPublicIp(ip), false, String(ip));
    }
  });
});

describe('normalizeIp', () => {
  test('equivalent IPv6 spellings compare equal', () => {
    assert.equal(normalizeIp('2001:4860:4860::8888'), normalizeIp('2001:4860:4860:0:0:0:0:8888'));
    assert.equal(normalizeIp('2001:4860:4860::8888'), normalizeIp('2001:4860:4860::8888'.toUpperCase()));
    assert.equal(normalizeIp('nope'), null);
  });
});

const resolverOf = (a, aaaa) => ({
  resolve4: async () => { if (a instanceof Error) throw a; return a; },
  resolve6: async () => { if (aaaa instanceof Error) throw aaaa; return aaaa; },
});

describe('resolvePublicAddresses (DNS rebinding / mixed answers)', () => {
  test('returns the normalized public answer set', async () => {
    const r = await resolvePublicAddresses('example.com', resolverOf(['93.184.216.34'], ['2606:2800:220:1::1']));
    assert.equal(r.ok, true);
    assert.equal(r.addresses.length, 2);
  });
  test('tolerates one family failing', async () => {
    const r = await resolvePublicAddresses('example.com', resolverOf(['8.8.8.8'], Object.assign(new Error('x'), { code: 'ENODATA' })));
    assert.deepEqual(r, { ok: true, addresses: ['8.8.8.8'] });
  });
  test('fails closed when any answer is unsafe (mixed safe/unsafe)', async () => {
    assert.deepEqual(await resolvePublicAddresses('e.com', resolverOf(['8.8.8.8', '127.0.0.1'], [])), { ok: false, code: 'destination_not_public' });
    assert.deepEqual(await resolvePublicAddresses('e.com', resolverOf(['8.8.8.8'], ['::ffff:10.0.0.1'])), { ok: false, code: 'destination_not_public' });
    assert.deepEqual(await resolvePublicAddresses('e.com', resolverOf(['169.254.169.254'], [])), { ok: false, code: 'destination_not_public' });
  });
  test('fails closed on malformed answers', async () => {
    assert.equal((await resolvePublicAddresses('e.com', resolverOf(['not-an-ip'], []))).ok, false);
  });
  test('reports dns_failure when nothing resolves', async () => {
    const err = Object.assign(new Error('x'), { code: 'ENOTFOUND' });
    assert.deepEqual(await resolvePublicAddresses('e.com', resolverOf(err, err)), { ok: false, code: 'dns_failure' });
    assert.deepEqual(await resolvePublicAddresses('e.com', resolverOf([], [])), { ok: false, code: 'dns_failure' });
  });
});

describe('selectValidatedAddress', () => {
  test('only addresses from the validated set are selectable', () => {
    const set = ['93.184.216.34', normalizeIp('2606:2800:220:1::1')];
    assert.equal(selectValidatedAddress('93.184.216.34', set), '93.184.216.34');
    assert.equal(selectValidatedAddress('2606:2800:220:1:0:0:0:1', set), set[1]);
    assert.equal(selectValidatedAddress('93.184.216.35', set), null);
    assert.equal(selectValidatedAddress('127.0.0.1', set), null);
    assert.equal(selectValidatedAddress(undefined, set), null);
  });
});
