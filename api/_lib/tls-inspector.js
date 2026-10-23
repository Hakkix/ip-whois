// One TLS handshake against a pre-validated IP, with the original hostname as
// SNI. Certificate problems are *reported*, never silently accepted: the
// handshake uses rejectUnauthorized:false only so an invalid certificate can
// be inspected; trust and identity are then evaluated explicitly.
import tls from 'node:tls';
import { X509Certificate } from 'node:crypto';
import { normalizeIp } from './tls-validation.js';

export const PORT = 443;
export const MAX_CHAIN_DEPTH = 8;
export const MAX_SANS = 100;
export const MAX_STRING = 256;
export const EXPIRING_SOON_DAYS = 30;
const DAY_MS = 86_400_000;

// Fixed, user-readable explanations. Never built from error text, so no
// stack traces or infrastructure details can leak through them.
export const ERROR_MESSAGES = {
  invalid_request: 'The request was malformed.',
  invalid_hostname: 'Only public DNS hostnames can be inspected.',
  hostname_not_public: 'This hostname is local or reserved and cannot be inspected.',
  invalid_ip: 'The selected IP address is not valid.',
  dns_failure: 'The server could not resolve this hostname.',
  destination_not_public: 'The hostname resolves to a non-public address, so no connection was made.',
  dns_mismatch: 'The server’s DNS answer does not include the selected IP address (DNS answers can differ between resolvers), so no connection was made.',
  connection_refused: 'The server refused the connection on port 443.',
  connection_timeout: 'The connection to port 443 timed out.',
  connection_reset: 'The connection was reset during the TLS handshake.',
  network_unreachable: 'The address could not be reached from the inspection server (IPv6 outbound connectivity is not always available).',
  tls_handshake_timeout: 'The TLS handshake did not complete in time.',
  tls_handshake_failed: 'The TLS handshake failed.',
  tls_version_unsupported: 'The server does not support a TLS version this inspector allows (TLS 1.2 or newer).',
  not_tls_service: 'Port 443 does not appear to speak TLS.',
  no_certificate: 'The server did not present a certificate.',
  inspection_failed: 'The certificate could not be inspected.',
  certificate_expired: 'The certificate has expired.',
  certificate_not_yet_valid: 'The certificate is not yet valid.',
  self_signed_certificate: 'The certificate is self-signed and not trusted.',
  untrusted_certificate: 'The certificate chain does not lead to a trusted root.',
  incomplete_chain: 'The server did not provide enough certificates to build a trusted chain.',
  hostname_mismatch: 'The certificate is not valid for this hostname.',
  validation_inconclusive: 'The certificate could not be fully validated.',
  rate_limited: 'Too many requests. Please try again shortly.',
  busy: 'The inspection service is busy. Please try again shortly.',
  disabled: 'TLS inspection is not enabled on this deployment.',
  method_not_allowed: 'Only POST is supported.',
  forbidden_origin: 'Cross-origin requests are not allowed.',
};

export const clean = (v, max = MAX_STRING) => {
  if (typeof v !== 'string') return null;
  // eslint-disable-next-line no-control-regex
  const s = v.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, ' ').trim();
  return s ? s.slice(0, max) : null;
};

// Node renders names as newline-separated "K=V" lines.
const dn = (s) => clean(typeof s === 'string' ? s.split('\n').join(', ') : '');

export function parseSans(raw) {
  if (typeof raw !== 'string') return [];
  const out = [];
  const re = /(DNS|IP Address|email|URI):(?:"((?:[^"\\]|\\.)*)"|([^,]*))(?:,\s*|$)/g;
  let m;
  while ((m = re.exec(raw)) && out.length < MAX_SANS) {
    const value = clean(m[2] !== undefined ? m[2].replace(/\\(.)/g, '$1') : m[3]);
    if (!value) continue;
    out.push(m[1] === 'DNS' ? value : `${m[1] === 'IP Address' ? 'IP' : m[1]}:${value}`);
  }
  return out;
}

const iso = (d) => (d instanceof Date && !Number.isNaN(d.getTime()) ? d.toISOString() : null);

// Date evaluation is independent of trust and identity.
export function evaluateDates(validFrom, validTo, now = new Date()) {
  const from = new Date(validFrom);
  const to = new Date(validTo);
  if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime())) {
    return { valid_from: null, valid_to: null, days_remaining: null, date_status: 'unknown', expiring_soon: false };
  }
  const daysRemaining = Math.floor((to.getTime() - now.getTime()) / DAY_MS);
  const status = now < from ? 'not_yet_valid' : now > to ? 'expired' : 'valid';
  return {
    valid_from: iso(from), valid_to: iso(to), days_remaining: daysRemaining, date_status: status,
    expiring_soon: status === 'valid' && daysRemaining < EXPIRING_SOON_DAYS,
  };
}

const CURVE_BITS = { prime256v1: 256, secp256r1: 256, secp384r1: 384, secp521r1: 521, secp256k1: 256 };

export function describePublicKey(x509) {
  try {
    const key = x509.publicKey;
    const type = key.asymmetricKeyType;
    const d = key.asymmetricKeyDetails || {};
    if (type === 'rsa' || type === 'rsa-pss') return { algorithm: 'RSA', size: d.modulusLength ?? null, curve: null };
    if (type === 'ec') return { algorithm: 'EC', size: CURVE_BITS[d.namedCurve] ?? null, curve: clean(d.namedCurve, 32) };
    if (type === 'ed25519') return { algorithm: 'Ed25519', size: 256, curve: null };
    if (type === 'ed448') return { algorithm: 'Ed448', size: 456, curve: null };
    return { algorithm: clean(type, 32), size: d.modulusLength ?? null, curve: null };
  } catch {
    return { algorithm: null, size: null, curve: null };
  }
}

// Identity check via tls.checkServerIdentity, plus a requirement that the
// certificate carries a DNS SAN (modern clients ignore the CN).
export function checkHostname(hostname, peerCert) {
  if (!parseSans(peerCert?.subjectaltname).some((s) => !/^(IP|email|URI):/.test(s))) return false;
  return tls.checkServerIdentity(hostname, peerCert) === undefined;
}

// Maps OpenSSL verification errors to a trust verdict. Certificate-date
// errors stop chain building, so they leave trust genuinely unknown.
export function mapTrust(authorized, authorizationError) {
  if (authorized) return { trust_status: 'valid', trust_detail: null };
  const code = typeof authorizationError === 'string' ? authorizationError : authorizationError?.code;
  const detail = clean(code, 64);
  switch (code) {
    case 'DEPTH_ZERO_SELF_SIGNED_CERT':
    case 'SELF_SIGNED_CERT_IN_CHAIN':
      return { trust_status: 'self_signed', trust_detail: detail };
    case 'UNABLE_TO_GET_ISSUER_CERT':
    case 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY':
    case 'UNABLE_TO_VERIFY_LEAF_SIGNATURE':
      return { trust_status: 'incomplete_chain', trust_detail: detail };
    case 'CERT_HAS_EXPIRED':
    case 'CERT_NOT_YET_VALID':
    case undefined:
    case null:
      return { trust_status: 'unknown', trust_detail: detail };
    default:
      return { trust_status: 'untrusted', trust_detail: detail };
  }
}

const PROBLEM_ORDER = [
  ['certificate_expired', (v) => v.dates === 'expired'],
  ['certificate_not_yet_valid', (v) => v.dates === 'not_yet_valid'],
  ['self_signed_certificate', (v) => v.trust === 'self_signed'],
  ['incomplete_chain', (v) => v.trust === 'incomplete_chain'],
  ['untrusted_certificate', (v) => v.trust === 'untrusted'],
  ['hostname_mismatch', (v) => v.hostname === false],
];

// Combines the independent checks. 'valid' requires every check to have
// positively succeeded; any definite failure is 'invalid'; otherwise 'unknown'.
export function overallValidity({ dates, trust, hostname }) {
  const v = { dates, trust, hostname };
  const problems = PROBLEM_ORDER.filter(([, test]) => test(v)).map(([code]) => code);
  if (problems.length) return { overall: 'invalid', problems };
  if (dates === 'valid' && trust === 'valid' && hostname === true) return { overall: 'valid', problems: [] };
  return { overall: 'unknown', problems: ['validation_inconclusive'] };
}

function certEntry(x509, position, isLast) {
  const selfIssued = x509.subject === x509.issuer;
  const role = position === 0 ? 'leaf' : (isLast && selfIssued ? 'root' : 'intermediate');
  const dates = evaluateDates(x509.validFrom, x509.validTo);
  return {
    position, role,
    subject: dn(x509.subject), issuer: dn(x509.issuer),
    valid_from: dates.valid_from, valid_to: dates.valid_to,
    fingerprint_sha256: clean(x509.fingerprint256, 95),
    self_issued: selfIssued,
    // Node appends the trust-store root to the peer chain, so whether a root
    // was actually sent by the server cannot be determined.
    presented: role === 'root' && position > 0 ? null : true,
  };
}

// Walks the issuer links Node exposes, bounded in depth.
export function collectChain(detailed, maxDepth = MAX_CHAIN_DEPTH) {
  const raws = [];
  const seen = new Set();
  let truncated = false;
  let cur = detailed;
  while (cur && cur.raw) {
    const key = cur.raw.toString('base64');
    if (seen.has(key)) break;
    if (raws.length >= maxDepth) { truncated = true; break; }
    seen.add(key);
    raws.push(cur.raw);
    if (cur.issuerCertificate === cur) break;
    cur = cur.issuerCertificate;
  }
  const certs = raws.map((r) => new X509Certificate(r));
  return { certs, truncated, entries: certs.map((c, i) => certEntry(c, i, i === certs.length - 1)) };
}

function mapError(err, phase) {
  const code = err?.code;
  if (code === 'ECONNREFUSED') return 'connection_refused';
  if (code === 'ETIMEDOUT') return phase === 'connect' ? 'connection_timeout' : 'tls_handshake_timeout';
  if (code === 'ECONNRESET' || code === 'EPIPE') return phase === 'connect' ? 'connection_reset' : 'tls_handshake_failed';
  if (['ENETUNREACH', 'EHOSTUNREACH', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'ENETDOWN'].includes(code)) return 'network_unreachable';
  if (typeof code === 'string' && /WRONG_VERSION_NUMBER|PACKET_LENGTH_TOO_LONG|HTTP_REQUEST|HTTPS_PROXY_REQUEST|RECORD_LENGTH|BAD_PACKET_LENGTH/.test(code)) return 'not_tls_service';
  if (typeof code === 'string' && /UNSUPPORTED_PROTOCOL|NO_PROTOCOLS_AVAILABLE|PROTOCOL_VERSION/.test(code)) return 'tls_version_unsupported';
  if (typeof code === 'string' && (code.startsWith('ERR_SSL') || code.startsWith('ERR_TLS') || code.startsWith('ERR_OSSL'))) return 'tls_handshake_failed';
  return 'inspection_failed';
}

const failure = (error_code, status = 'unavailable') => ({ status, error_code });

// deps: { connect, ca, now, connectTimeoutMs, totalTimeoutMs, port }.
// `ca`/`port` exist solely so tests can use a private CA and a local server;
// the HTTP handler never forwards request data into deps.
export function inspectCertificate({ hostname, ip }, deps = {}) {
  const {
    connect = tls.connect, ca, now = () => new Date(), port = PORT,
    connectTimeoutMs = 4000, totalTimeoutMs = 8000,
  } = deps;
  return new Promise((resolve) => {
    let settled = false;
    let phase = 'connect';
    let socket;
    const timers = [];
    const done = (result) => {
      if (settled) return;
      settled = true;
      timers.forEach(clearTimeout);
      try { socket?.destroy(); } catch { /* already closed */ }
      resolve(result);
    };
    try {
      const opts = {
        host: ip, port, servername: hostname,
        // Inspection only: trust is computed below from socket.authorized.
        rejectUnauthorized: false,
        checkServerIdentity: () => undefined,
        // Defence in depth: never resolve anything, always the validated IP.
        lookup: (_h, o, cb) => (o && o.all ? cb(null, [{ address: ip, family: ip.includes(':') ? 6 : 4 }]) : cb(null, ip, ip.includes(':') ? 6 : 4)),
        minVersion: 'TLSv1.2',
      };
      if (ca) opts.ca = ca;
      socket = connect(opts);
    } catch {
      resolve(failure('inspection_failed'));
      return;
    }
    timers.push(setTimeout(() => done(failure(phase === 'connect' ? 'connection_timeout' : 'tls_handshake_timeout')), connectTimeoutMs));
    timers.push(setTimeout(() => done(failure(phase === 'connect' ? 'connection_timeout' : 'tls_handshake_timeout')), totalTimeoutMs));
    socket.once('connect', () => { phase = 'handshake'; clearTimeout(timers[0]); });
    socket.once('error', (err) => done(failure(mapError(err, phase))));
    socket.once('close', () => done(failure(phase === 'connect' ? 'connection_reset' : 'tls_handshake_failed')));
    socket.once('secureConnect', () => {
      try {
        if (normalizeIp(socket.remoteAddress || '') !== normalizeIp(ip)) { done(failure('inspection_failed')); return; }
        const detailed = socket.getPeerCertificate(true);
        if (!detailed || !detailed.raw) { done(failure('no_certificate')); return; }
        const observedAt = now();
        const { certs, truncated, entries } = collectChain(detailed);
        const leaf = certs[0];
        const dates = evaluateDates(leaf.validFrom, leaf.validTo, observedAt);
        const hostnameMatch = checkHostname(hostname, detailed);
        const trust = mapTrust(socket.authorized, socket.authorizationError);
        const verdict = overallValidity({ dates: dates.date_status, trust: trust.trust_status, hostname: hostnameMatch });
        const cipher = socket.getCipher() || {};
        done({
          status: verdict.overall === 'valid' ? 'ok' : 'invalid',
          hostname, connected_ip: ip, port,
          observed_at: observedAt.toISOString(),
          certificate: {
            subject: dn(leaf.subject), issuer: dn(leaf.issuer), sans: parseSans(leaf.subjectAltName),
            serial_number: clean(leaf.serialNumber, 128), ...dates,
            fingerprint_sha256: clean(leaf.fingerprint256, 95), public_key: describePublicKey(leaf),
          },
          connection: {
            protocol: clean(socket.getProtocol() || '', 16), cipher: clean(cipher.name, 64),
            hostname_match: hostnameMatch, ...trust,
          },
          validation: verdict,
          chain: entries,
          chain_summary: { count: entries.length, truncated, validated: trust.trust_status === 'valid' ? true : trust.trust_status === 'unknown' ? null : false },
          error_code: verdict.overall === 'valid' ? null : verdict.problems[0],
        });
      } catch {
        done(failure('inspection_failed'));
      }
    });
  });
}
