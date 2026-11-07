// DNS-over-HTTPS resolution: forward A/AAAA lookups and reverse PTR lookups.
import { fetchWithTimeout, ptrNameFor, isoNow } from './utils.js';

export const DOH_PROVIDERS = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'];
export const RECORD_TYPE = { A: 1, AAAA: 28, PTR: 12 };

// Resolves to { json, provider } where provider is the DoH host that actually
// answered, or null when every provider failed.
async function dohQuery(name, type, timeoutMs = 6000) {
  for (const base of DOH_PROVIDERS) {
    try {
      const resp = await fetchWithTimeout(
        `${base}?name=${encodeURIComponent(name)}&type=${type}`,
        { headers: { accept: 'application/dns-json' } },
        timeoutMs,
      );
      if (!resp.ok) continue;
      const json = await resp.json();
      // NXDOMAIN (3) is a definitive answer, not a provider failure
      if (json.Status === 0 || json.Status === 3) return { json, provider: new URL(base).hostname };
    } catch {
      // try next provider
    }
  }
  return null;
}

// Outcome of a DNS operation, carried as `status` on every result:
//   'ok'        — the resolver answered and returned at least one record
//   'no_record' — the resolver answered definitively: nothing matches (NXDOMAIN
//                 or an empty answer). Not an operational failure.
//   'error'     — no provider gave a usable answer (network failure, timeout,
//                 HTTP error, SERVFAIL, malformed response)
// ('not_applicable' is assigned by the report builder for lookups never run.)
//
// Resolves a hostname to its A and AAAA addresses.
// Returns { hostname, addresses: string[], source, status } — addresses is []
// if none resolve; source names the DoH host(s) that answered (null if none).
export async function resolveHostname(hostname) {
  const [aResult, aaaaResult] = await Promise.allSettled([
    dohQuery(hostname, 'A'),
    dohQuery(hostname, 'AAAA'),
  ]);
  const addresses = [];
  const providers = [];
  let failed = 0;
  for (const result of [aResult, aaaaResult]) {
    if (result.status !== 'fulfilled' || !result.value) {
      failed++;
      continue;
    }
    const { json, provider } = result.value;
    if (!providers.includes(provider)) providers.push(provider);
    for (const rec of Array.isArray(json.Answer) ? json.Answer : []) {
      if (typeof rec?.data !== 'string') continue;
      const addr = rec.data.toLowerCase();
      if ((rec.type === RECORD_TYPE.A || rec.type === RECORD_TYPE.AAAA) && !addresses.includes(addr)) {
        addresses.push(addr);
      }
    }
  }
  const source = providers.length ? { provider: providers.join(', '), retrieved_at: isoNow() } : null;
  // One family failing while the other answers empty cannot prove "no record".
  const status = addresses.length ? 'ok' : failed ? 'error' : 'no_record';
  return { hostname, addresses, source, status };
}

// Reverse (PTR) lookup for an IP address. Absence of a PTR record is not an
// error: it resolves to { hostname: null, status: 'no_record' }. A resolver
// failure resolves to { hostname: null, status: 'error' } and never throws.
export async function reversePTR(ip, version, timeoutMs = 6000) {
  const name = ptrNameFor(ip, version);
  const answer = await dohQuery(name, 'PTR', timeoutMs);
  if (!answer) return { hostname: null, source: null, status: 'error' };
  const source = { provider: answer.provider, retrieved_at: isoNow() };
  const answers = Array.isArray(answer.json.Answer) ? answer.json.Answer : [];
  const rec = answers.find((r) => r?.type === RECORD_TYPE.PTR && typeof r.data === 'string');
  if (!rec) return { hostname: null, source, status: 'no_record' };
  return { hostname: rec.data.replace(/\.$/, ''), source, status: 'ok' };
}
