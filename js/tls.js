// Browser-side client for POST /api/tls plus normalization of its response.
// The server is the only place a TLS handshake can happen; this module treats
// its response as untrusted input: whitelist fields, bound sizes, and never
// let an inconsistent payload read as "valid".
import { isoNow } from './utils.js';

const STATUSES = ['ok', 'invalid', 'unavailable', 'blocked'];
const TRUST = ['valid', 'untrusted', 'self_signed', 'incomplete_chain', 'unknown'];
const DATES = ['valid', 'expired', 'not_yet_valid', 'unknown'];
const OVERALL = ['valid', 'invalid', 'unknown'];
const ROLES = ['leaf', 'intermediate', 'root'];

const CLIENT_MESSAGES = {
  client_timeout: 'The TLS inspection request timed out.',
  client_network: 'The TLS inspection service could not be reached.',
  bad_response: 'The TLS inspection service returned an unexpected response.',
  not_found: 'TLS inspection is not available on this deployment.',
};

const str = (v, max = 300) => (typeof v === 'string' && v ? v.slice(0, max) : null);
const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const oneOf = (v, list, fallback = null) => (list.includes(v) ? v : fallback);
const bool = (v) => (typeof v === 'boolean' ? v : null);

function failure({ status = 'unavailable', code, message, hostname = null, ip = null, observedAt = null, port = null }) {
  return {
    status, hostname, connected_ip: ip, port, observed_at: observedAt ?? isoNow(),
    certificate: null, connection: null, validation: null, chain: [], chain_summary: null,
    error_code: code, error_message: message ?? CLIENT_MESSAGES[code] ?? null,
  };
}

// Transient UI state while the request is in flight. Never produced by the API.
export function tlsPending(hostname, ip) {
  return { ...failure({ status: 'pending', code: null, hostname, ip, port: 443 }), observed_at: null };
}

export function normalizeTlsResponse(raw, { hostname = null, ip = null } = {}) {
  if (!raw || typeof raw !== 'object') return failure({ code: 'bad_response', hostname, ip });
  const status = oneOf(raw.status, STATUSES);
  if (!status) return failure({ code: 'bad_response', hostname, ip });
  const base = {
    hostname: str(raw.hostname, 253) ?? hostname,
    ip: str(raw.connected_ip, 64) ?? ip,
    observedAt: str(raw.observed_at, 40),
    port: num(raw.port),
  };
  if (status === 'blocked' || status === 'unavailable') {
    return failure({ status, code: str(raw.error_code, 64) ?? 'inspection_failed', message: str(raw.error_message, 300), ...base });
  }

  const c = raw.certificate && typeof raw.certificate === 'object' ? raw.certificate : null;
  const k = raw.connection && typeof raw.connection === 'object' ? raw.connection : null;
  if (!c || !k) return failure({ code: 'bad_response', ...base });

  const pk = c.public_key && typeof c.public_key === 'object' ? c.public_key : {};
  const certificate = {
    subject: str(c.subject), issuer: str(c.issuer),
    sans: Array.isArray(c.sans) ? c.sans.slice(0, 100).map((s) => str(s)).filter(Boolean) : [],
    serial_number: str(c.serial_number, 128),
    valid_from: str(c.valid_from, 40), valid_to: str(c.valid_to, 40),
    days_remaining: num(c.days_remaining),
    date_status: oneOf(c.date_status, DATES, 'unknown'),
    expiring_soon: c.expiring_soon === true,
    fingerprint_sha256: str(c.fingerprint_sha256, 95),
    public_key: { algorithm: str(pk.algorithm, 32), size: num(pk.size), curve: str(pk.curve, 32) },
  };
  const connection = {
    protocol: str(k.protocol, 16), cipher: str(k.cipher, 64),
    hostname_match: bool(k.hostname_match),
    trust_status: oneOf(k.trust_status, TRUST, 'unknown'),
    trust_detail: str(k.trust_detail, 64),
  };
  const v = raw.validation && typeof raw.validation === 'object' ? raw.validation : {};
  const problems = Array.isArray(v.problems) ? v.problems.slice(0, 10).map((p) => str(p, 64)).filter(Boolean) : [];
  let overall = oneOf(v.overall, OVERALL, 'unknown');
  // Recompute: "valid" must be backed by every individual check.
  const allPass = certificate.date_status === 'valid' && connection.hostname_match === true && connection.trust_status === 'valid';
  const definiteFail = ['expired', 'not_yet_valid'].includes(certificate.date_status) || connection.hostname_match === false
    || ['untrusted', 'self_signed', 'incomplete_chain'].includes(connection.trust_status);
  if (overall === 'valid' && !allPass) overall = definiteFail ? 'invalid' : 'unknown';
  const chain = (Array.isArray(raw.chain) ? raw.chain : []).slice(0, 8).filter((e) => e && typeof e === 'object').map((e, i) => ({
    position: i, role: oneOf(e.role, ROLES, 'intermediate'),
    subject: str(e.subject), issuer: str(e.issuer), valid_from: str(e.valid_from, 40), valid_to: str(e.valid_to, 40),
    fingerprint_sha256: str(e.fingerprint_sha256, 95), self_issued: bool(e.self_issued),
    presented: bool(e.presented),
  }));
  const cs = raw.chain_summary && typeof raw.chain_summary === 'object' ? raw.chain_summary : {};
  const finalStatus = status === 'ok' && overall !== 'valid' ? 'invalid' : status;
  return {
    status: finalStatus, hostname: base.hostname, connected_ip: base.ip, port: base.port ?? 443,
    observed_at: base.observedAt ?? isoNow(),
    certificate, connection,
    validation: { overall, problems },
    chain,
    chain_summary: { count: chain.length, truncated: cs.truncated === true, validated: bool(cs.validated) },
    error_code: finalStatus === 'ok' ? null : str(raw.error_code, 64) ?? problems[0] ?? 'validation_inconclusive',
    error_message: finalStatus === 'ok' ? null : str(raw.error_message, 300),
  };
}

// Always resolves; a failed request becomes a structured result, not a throw.
export async function fetchTls(hostname, ip, { signal, timeoutMs = 12000, fetchImpl = fetch } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort('timeout'), timeoutMs);
  const onAbort = () => controller.abort('cancelled');
  signal?.addEventListener('abort', onAbort, { once: true });
  const ctx = { hostname, ip };
  try {
    const resp = await fetchImpl('/api/tls', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ hostname, ip }),
      cache: 'no-store', credentials: 'omit', redirect: 'error',
      signal: controller.signal,
    });
    if (resp.status === 404) return failure({ code: 'not_found', ...ctx });
    let json;
    try { json = await resp.json(); } catch { return failure({ code: 'bad_response', ...ctx }); }
    return normalizeTlsResponse(json, ctx);
  } catch {
    return failure({ code: controller.signal.reason === 'timeout' ? 'client_timeout' : 'client_network', ...ctx });
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', onAbort);
  }
}

// ---- shared display labels (UI and every export use the same wording) ----

export const TRUST_LABELS = {
  valid: 'Trusted chain', untrusted: 'Untrusted', self_signed: 'Self-signed',
  incomplete_chain: 'Incomplete chain (issuer not found)', unknown: 'Unknown',
};
export const DATE_LABELS = { valid: 'Within validity period', expired: 'Expired', not_yet_valid: 'Not yet valid', unknown: 'Unknown' };
export const ROLE_LABELS = { leaf: 'Leaf', intermediate: 'Intermediate', root: 'Root (trust anchor)' };

export const hostnameMatchLabel = (m) => (m === true ? 'Matches certificate names' : m === false ? 'Does not match certificate names' : 'Unknown');

// 'valid' | 'warning' | 'invalid' | 'unknown' | 'unavailable' | 'pending' — drives indicators.
export function tlsTone(t) {
  if (t.status === 'pending') return 'pending';
  if (t.status === 'unavailable' || t.status === 'blocked') return 'unavailable';
  if (t.status === 'ok') return t.certificate?.expiring_soon ? 'warning' : 'valid';
  return t.validation?.overall === 'invalid' ? 'invalid' : 'unknown';
}

export function tlsVerdict(t) {
  switch (tlsTone(t)) {
    case 'pending': return 'Inspection in progress';
    case 'valid': return 'Valid';
    case 'warning': return `Valid — expires in ${t.certificate.days_remaining} day${t.certificate.days_remaining === 1 ? '' : 's'}`;
    case 'invalid': return 'Invalid';
    case 'unknown': return 'Could not be verified';
    default: return t.status === 'blocked' ? 'Blocked' : 'Unavailable';
  }
}

export const publicKeyLabel = (pk) => (pk && pk.algorithm
  ? [pk.algorithm, pk.size ? `${pk.size}-bit` : null, pk.curve].filter(Boolean).join(' ') : null);
