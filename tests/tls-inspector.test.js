import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import tls from 'node:tls';
import net from 'node:net';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  inspectCertificate, evaluateDates, checkHostname, mapTrust, overallValidity, parseSans, collectChain, clean,
  MAX_CHAIN_DEPTH, EXPIRING_SOON_DAYS,
} from '../api/_lib/tls-inspector.js';

const dir = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'tls');
const f = (n) => readFileSync(join(dir, n));
const ca = f('ca.pem');
const HOST = 'valid.test-host.com';

const servers = [];
function listen(server) {
  return new Promise((res) => server.listen(0, '127.0.0.1', () => { servers.push(server); res(server.address().port); }));
}
const tlsServer = (certName, { chain = true, onSni } = {}) => listen(tls.createServer({
  key: f(`${certName}.key.pem`),
  cert: certName === 'selfsigned' || !chain ? f(`${certName}.pem`) : Buffer.concat([f(`${certName}.pem`), f('intermediate.pem')]),
  SNICallback: onSni ? (name, cb) => { onSni(name); cb(null); } : undefined,
}, (s) => s.end()));

after(() => servers.forEach((s) => s.close()));
const inspect = (port, extra = {}, host = HOST) => inspectCertificate({ hostname: host, ip: '127.0.0.1' }, { port, ca, ...extra });

describe('inspectCertificate (local TLS fixtures)', () => {
  test('valid certificate: status ok, every check separately positive', async () => {
    const seen = [];
    const port = await tlsServer('valid', { onSni: (n) => seen.push(n) });
    const r = await inspect(port);
    assert.equal(r.status, 'ok');
    assert.equal(r.error_code, null);
    assert.deepEqual(seen, [HOST], 'original hostname is sent as SNI');
    assert.equal(r.connected_ip, '127.0.0.1');
    assert.equal(r.connection.hostname_match, true);
    assert.equal(r.connection.trust_status, 'valid');
    assert.equal(r.certificate.date_status, 'valid');
    assert.deepEqual(r.validation, { overall: 'valid', problems: [] });
    assert.match(r.connection.protocol, /^TLSv1\.[23]$/);
    assert.ok(r.connection.cipher);
    assert.match(r.certificate.fingerprint_sha256, /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
    assert.deepEqual(r.certificate.public_key, { algorithm: 'RSA', size: 2048, curve: null });
    assert.ok(r.certificate.sans.includes(HOST));
    assert.equal(r.certificate.expiring_soon, false);
    assert.ok(r.certificate.days_remaining > 1000);
    assert.match(r.certificate.subject, /CN=valid\.test-host\.com/);
    assert.match(r.certificate.issuer, /Test Intermediate CA/);
  });

  test('chain: leaf, intermediate, and a trust-store root whose presence is not claimed', async () => {
    const r = await inspect(await tlsServer('valid'));
    assert.deepEqual(r.chain.map((c) => c.role), ['leaf', 'intermediate', 'root']);
    assert.equal(r.chain[0].presented, true);
    assert.equal(r.chain[1].presented, true);
    assert.equal(r.chain[2].presented, null);
    assert.equal(r.chain_summary.validated, true);
    assert.equal(r.chain_summary.count, 3);
  });

  test('ECDSA key reported with curve and size', async () => {
    const r = await inspect(await tlsServer('ecdsa'));
    assert.deepEqual(r.certificate.public_key, { algorithm: 'EC', size: 384, curve: 'secp384r1' });
  });

  test('expired certificate: invalid, dates failed, trust not claimed valid', async () => {
    const r = await inspect(await tlsServer('expired'));
    assert.equal(r.status, 'invalid');
    assert.equal(r.certificate.date_status, 'expired');
    assert.ok(r.certificate.days_remaining < 0);
    assert.equal(r.connection.hostname_match, true);
    assert.equal(r.connection.trust_status, 'unknown');
    assert.equal(r.validation.overall, 'invalid');
    assert.equal(r.error_code, 'certificate_expired');
  });

  test('self-signed certificate', async () => {
    const r = await inspect(await tlsServer('selfsigned'));
    assert.equal(r.status, 'invalid');
    assert.equal(r.connection.trust_status, 'self_signed');
    assert.equal(r.connection.hostname_match, true);
    assert.equal(r.certificate.date_status, 'valid');
    assert.equal(r.error_code, 'self_signed_certificate');
    assert.equal(r.chain_summary.validated, false);
  });

  test('untrusted: valid chain but CA not in the trust store (production default roots)', async () => {
    const r = await inspectCertificate({ hostname: HOST, ip: '127.0.0.1' }, { port: await tlsServer('valid') });
    assert.equal(r.status, 'invalid');
    assert.notEqual(r.connection.trust_status, 'valid');
    assert.notEqual(r.error_code, null);
  });

  test('wrong hostname: identity fails while trust and dates pass', async () => {
    const r = await inspect(await tlsServer('wronghost'));
    assert.equal(r.status, 'invalid');
    assert.equal(r.connection.hostname_match, false);
    assert.equal(r.connection.trust_status, 'valid');
    assert.equal(r.certificate.date_status, 'valid');
    assert.equal(r.error_code, 'hostname_mismatch');
  });

  test('incomplete chain: server omits the intermediate', async () => {
    const r = await inspect(await tlsServer('valid', { chain: false }));
    assert.equal(r.status, 'invalid');
    assert.equal(r.connection.trust_status, 'incomplete_chain');
    assert.equal(r.error_code, 'incomplete_chain');
    assert.equal(r.chain.length, 1);
    assert.equal(r.chain_summary.validated, false);
  });

  test('wildcard SAN matches one label only', async () => {
    const port = await tlsServer('valid');
    assert.equal((await inspect(port, {}, 'a.wild.test-host.com')).connection.hostname_match, true);
    assert.equal((await inspect(port, {}, 'a.b.wild.test-host.com')).connection.hostname_match, false);
  });

  test('connection refused', async () => {
    const s = net.createServer();
    const port = await listen(s);
    await new Promise((r) => s.close(r));
    const r = await inspect(port);
    assert.deepEqual(r, { status: 'unavailable', error_code: 'connection_refused' });
  });

  test('TLS handshake timeout: TCP accepted, server silent', async () => {
    const port = await listen(net.createServer(() => {}));
    const t = Date.now();
    const r = await inspect(port, { totalTimeoutMs: 300, connectTimeoutMs: 200 });
    assert.deepEqual(r, { status: 'unavailable', error_code: 'tls_handshake_timeout' });
    assert.ok(Date.now() - t < 2000);
  });

  test('connection timeout: connect never completes', async () => {
    const fake = () => new net.Socket(); // never connects
    const r = await inspect(1, { connect: fake, connectTimeoutMs: 100, totalTimeoutMs: 300 });
    assert.equal(r.error_code, 'connection_timeout');
  });

  test('non-TLS service on the port', async () => {
    const port = await listen(net.createServer((s) => s.end('HTTP/1.1 400 Bad Request\r\n\r\n')));
    const r = await inspect(port);
    assert.deepEqual(r, { status: 'unavailable', error_code: 'not_tls_service' });
  });

  test('server closing immediately is a handshake failure, never a crash', async () => {
    const port = await listen(net.createServer((s) => s.destroy()));
    const r = await inspect(port);
    assert.equal(r.status, 'unavailable');
    assert.ok(['tls_handshake_failed', 'connection_reset'].includes(r.error_code));
  });

  test('IPv6 unreachable maps to network_unreachable', async () => {
    const connect = () => { const s = new net.Socket(); setImmediate(() => s.emit('error', Object.assign(new Error('x'), { code: 'ENETUNREACH' }))); return s; };
    const r = await inspectCertificate({ hostname: HOST, ip: '2606:2800:220:1::1' }, { connect });
    assert.deepEqual(r, { status: 'unavailable', error_code: 'network_unreachable' });
  });

  test('connects to the supplied IP literal with a lookup that cannot resolve anything else', async () => {
    let opts;
    const connect = (o) => { opts = o; const s = new net.Socket(); setImmediate(() => s.emit('error', Object.assign(new Error('x'), { code: 'ECONNREFUSED' }))); return s; };
    await inspectCertificate({ hostname: HOST, ip: '93.184.216.34' }, { connect });
    assert.equal(opts.host, '93.184.216.34');
    assert.equal(opts.port, 443);
    assert.equal(opts.servername, HOST);
    await new Promise((res, rej) => opts.lookup('evil.example', {}, (e, a) => (e ? rej(e) : (assert.equal(a, '93.184.216.34'), res()))));
    await new Promise((res) => opts.lookup('evil.example', { all: true }, (e, a) => { assert.deepEqual(a, [{ address: '93.184.216.34', family: 4 }]); res(); }));
  });

  test('error text never leaks into the result', async () => {
    const connect = () => { const s = new net.Socket(); setImmediate(() => s.emit('error', Object.assign(new Error('secret-internal-host:5432 stack'), { code: 'EWEIRD' }))); return s; };
    const r = await inspectCertificate({ hostname: HOST, ip: '8.8.8.8' }, { connect });
    assert.deepEqual(r, { status: 'unavailable', error_code: 'inspection_failed' });
  });
});

describe('certificate helpers', () => {
  const now = new Date('2026-10-23T08:00:00Z');
  test('date calculations: valid, expiring soon, expired, not yet valid', () => {
    const d = (from, to) => evaluateDates(from, to, now);
    assert.deepEqual(d('2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z'), { valid_from: '2026-01-01T00:00:00.000Z', valid_to: '2027-01-01T00:00:00.000Z', days_remaining: 69, date_status: 'valid', expiring_soon: false });
    const soon = d('2026-01-01T00:00:00Z', '2026-11-10T00:00:00Z');
    assert.equal(soon.days_remaining, 17);
    assert.equal(soon.expiring_soon, true);
    assert.equal(soon.date_status, 'valid');
    assert.equal(d('2026-01-01T00:00:00Z', `2026-11-22T08:00:00Z`).expiring_soon, false); // exactly 30 days
    assert.equal(d('2026-01-01T00:00:00Z', `2026-11-22T07:59:59Z`).expiring_soon, true);
    const exp = d('2025-01-01T00:00:00Z', '2026-10-20T00:00:00Z');
    assert.equal(exp.date_status, 'expired');
    assert.ok(exp.days_remaining < 0);
    assert.equal(exp.expiring_soon, false);
    assert.equal(d('2027-01-01T00:00:00Z', '2028-01-01T00:00:00Z').date_status, 'not_yet_valid');
    assert.equal(d('garbage', 'garbage').date_status, 'unknown');
    assert.equal(EXPIRING_SOON_DAYS, 30);
  });

  test('openssl date strings parse', () => {
    assert.equal(evaluateDates('Jan  1 00:00:00 2026 GMT', 'Jan  1 00:00:00 2027 GMT', now).date_status, 'valid');
  });

  test('SAN parsing: types, quoting, bounds', () => {
    assert.deepEqual(parseSans('DNS:a.com, DNS:*.b.com, IP Address:1.2.3.4, email:x@y.z'), ['a.com', '*.b.com', 'IP:1.2.3.4', 'email:x@y.z']);
    assert.deepEqual(parseSans('DNS:"we, ird.com"'), ['we, ird.com']);
    assert.deepEqual(parseSans(undefined), []);
    const many = Array.from({ length: 500 }, (_, i) => `DNS:h${i}.com`).join(', ');
    assert.equal(parseSans(many).length, 100);
  });

  test('hostname matching via checkServerIdentity; no DNS SAN is not a match', () => {
    const cert = { subject: { CN: 'a.com' }, subjectaltname: 'DNS:a.com, DNS:*.b.com' };
    assert.equal(checkHostname('a.com', cert), true);
    assert.equal(checkHostname('x.b.com', cert), true);
    assert.equal(checkHostname('b.com', cert), false);
    assert.equal(checkHostname('evil.com', cert), false);
    assert.equal(checkHostname('a.com', { subject: { CN: 'a.com' } }), false);
    assert.equal(checkHostname('1.2.3.4', { subject: {}, subjectaltname: 'IP Address:1.2.3.4' }), false);
  });

  test('trust-status mapping', () => {
    assert.equal(mapTrust(true, null).trust_status, 'valid');
    assert.equal(mapTrust(false, { code: 'DEPTH_ZERO_SELF_SIGNED_CERT' }).trust_status, 'self_signed');
    assert.equal(mapTrust(false, { code: 'SELF_SIGNED_CERT_IN_CHAIN' }).trust_status, 'self_signed');
    assert.equal(mapTrust(false, { code: 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY' }).trust_status, 'incomplete_chain');
    assert.equal(mapTrust(false, { code: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' }).trust_status, 'incomplete_chain');
    assert.equal(mapTrust(false, { code: 'CERT_HAS_EXPIRED' }).trust_status, 'unknown');
    assert.equal(mapTrust(false, { code: 'CERT_REVOKED' }).trust_status, 'untrusted');
    assert.equal(mapTrust(false, undefined).trust_status, 'unknown');
    assert.equal(mapTrust(false, { code: 'SOMETHING_NEW' }).trust_status, 'untrusted');
  });

  test('overall validity: ok only when every check positively succeeded; unknown is never valid', () => {
    assert.equal(overallValidity({ dates: 'valid', trust: 'valid', hostname: true }).overall, 'valid');
    for (const bad of [
      { dates: 'valid', trust: 'valid', hostname: false },
      { dates: 'expired', trust: 'valid', hostname: true },
      { dates: 'valid', trust: 'untrusted', hostname: true },
    ]) assert.equal(overallValidity(bad).overall, 'invalid');
    for (const unknown of [
      { dates: 'unknown', trust: 'valid', hostname: true },
      { dates: 'valid', trust: 'unknown', hostname: true },
      { dates: 'valid', trust: 'valid', hostname: null },
    ]) assert.deepEqual(overallValidity(unknown), { overall: 'unknown', problems: ['validation_inconclusive'] });
    assert.deepEqual(overallValidity({ dates: 'expired', trust: 'self_signed', hostname: false }).problems,
      ['certificate_expired', 'self_signed_certificate', 'hostname_mismatch']);
  });

  test('chain depth is bounded and loops terminate', async () => {
    const { X509Certificate } = await import('node:crypto');
    const [leaf, inter, root] = ['valid.pem', 'intermediate.pem', 'ca.pem'].map((n) => ({ raw: new X509Certificate(f(n)).raw }));
    leaf.issuerCertificate = inter;
    inter.issuerCertificate = root;
    root.issuerCertificate = root;
    const full = collectChain(leaf);
    assert.equal(full.entries.length, 3);
    assert.equal(full.truncated, false);
    const cut = collectChain(leaf, 2);
    assert.equal(cut.entries.length, 2);
    assert.equal(cut.truncated, true);
    assert.equal(MAX_CHAIN_DEPTH, 8);
    root.issuerCertificate = leaf; // cycle without a self-issued terminator
    assert.equal(collectChain(leaf).entries.length, 3);
  });

  test('clean() strips control characters and bounds length', () => {
    assert.equal(clean('a\u0000b\nc'), 'a b c');
    assert.equal(clean('x'.repeat(1000)).length, 256);
    assert.equal(clean(5), null);
  });
});
