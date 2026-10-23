// POST /api/tls — inspects the certificate a public hostname presents on
// TCP 443. Security model: see README "SSRF and abuse controls".
import { Resolver } from 'node:dns/promises';
import { validateHostname, normalizeIp, isPublicIp, resolvePublicAddresses, selectValidatedAddress, MAX_BODY_BYTES } from './_lib/tls-validation.js';
import { inspectCertificate, ERROR_MESSAGES } from './_lib/tls-inspector.js';

const HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
};

function respond(httpStatus, body, extra = {}) {
  const error_code = body.error_code ?? null;
  const payload = {
    ...body, error_code,
    error_message: error_code ? ERROR_MESSAGES[error_code] ?? ERROR_MESSAGES.inspection_failed : null,
  };
  return new Response(JSON.stringify(payload), { status: httpStatus, headers: { ...HEADERS, ...extra } });
}

const blocked = (code, httpStatus = 400, extra) => respond(httpStatus, { status: 'blocked', error_code: code }, extra);

async function readBody(request) {
  const declared = Number(request.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) return null;
  if (!request.body) return '';
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) { await reader.cancel().catch(() => {}); return null; }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function sameOrigin(request) {
  const site = request.headers.get('sec-fetch-site');
  if (site && site !== 'same-origin' && site !== 'none') return false;
  const origin = request.headers.get('origin');
  if (!origin) return true;
  const host = request.headers.get('x-forwarded-host') || request.headers.get('host');
  try { return Boolean(host) && new URL(origin).host === host; } catch { return false; }
}

export function createHandler({
  resolver = new Resolver({ timeout: 2500, tries: 2 }),
  inspect = inspectCertificate,
  inspectDeps = {},
  env = process.env,
  maxConcurrent = 4,
  log = (entry) => console.log(JSON.stringify(entry)),
} = {}) {
  let active = 0;

  return async function handle(request) {
    const started = Date.now();
    const finish = (res, body) => {
      // Minimal, anonymous operational log: no hostnames, IPs or client data.
      log({ event: 'tls_inspect', status: body.status, error_code: body.error_code ?? null, ms: Date.now() - started });
      return res;
    };

    if (request.method !== 'POST') return blocked('method_not_allowed', 405, { allow: 'POST' });
    // Fail closed: the deployment must attest that its edge rate-limit rule is configured.
    if (env.TLS_INSPECTION_ENABLED !== '1') return blocked('disabled', 503);
    if (!sameOrigin(request)) return blocked('forbidden_origin', 403);
    if (!/^application\/json\b/i.test(request.headers.get('content-type') || '')) return blocked('invalid_request');

    const text = await readBody(request);
    if (text === null) return blocked('invalid_request', 413);
    let body;
    try { body = JSON.parse(text); } catch { return blocked('invalid_request'); }
    if (!body || typeof body !== 'object' || Array.isArray(body)) return blocked('invalid_request');
    // Only hostname and ip are accepted; in particular no port.
    if (Object.keys(body).some((k) => k !== 'hostname' && k !== 'ip')) return blocked('invalid_request');

    const host = validateHostname(body.hostname);
    if (!host.ok) return blocked(host.code);
    if (typeof body.ip !== 'string' || !normalizeIp(body.ip)) return blocked('invalid_ip');
    // A non-public selected IP is rejected before any DNS or network work.
    if (!isPublicIp(body.ip)) return blocked('destination_not_public');

    if (active >= maxConcurrent) return blocked('busy', 429, { 'retry-after': '5' });
    active++;
    try {
      const dns = await resolvePublicAddresses(host.hostname, resolver);
      if (!dns.ok) {
        const out = { status: dns.code === 'destination_not_public' ? 'blocked' : 'unavailable', hostname: host.hostname, error_code: dns.code };
        return finish(respond(dns.code === 'destination_not_public' ? 403 : 200, out), out);
      }
      const target = selectValidatedAddress(body.ip, dns.addresses);
      if (!target) {
        const out = { status: 'unavailable', hostname: host.hostname, error_code: 'dns_mismatch' };
        return finish(respond(200, out), out);
      }
      // Connect to the validated address only; the inspector never resolves names.
      const result = await inspect({ hostname: host.hostname, ip: target }, inspectDeps);
      const out = result.certificate
        ? result
        : { status: result.status, hostname: host.hostname, connected_ip: target, port: 443, observed_at: new Date().toISOString(), error_code: result.error_code };
      return finish(respond(200, out), out);
    } catch {
      const out = { status: 'unavailable', error_code: 'inspection_failed' };
      return finish(respond(200, out), out);
    } finally {
      active--;
    }
  };
}

const handler = createHandler();
export const POST = handler;
export const GET = handler;
export const PUT = handler;
export const DELETE = handler;
export const PATCH = handler;
export const OPTIONS = handler;
export const HEAD = handler;
