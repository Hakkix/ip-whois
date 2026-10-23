// DNS-over-HTTPS resolution: forward A/AAAA lookups and reverse PTR lookups.
import { fetchWithTimeout, ptrNameFor, isoNow } from './utils.js';

const DOH_PROVIDERS = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'];
const RECORD_TYPE = { A: 1, AAAA: 28, PTR: 12 };

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

// Resolves a hostname to its A and AAAA addresses.
// Returns { hostname, addresses: string[], source } — addresses is [] if none
// resolve; source names the DoH host(s) that answered (null if none did).
export async function resolveHostname(hostname) {
  const [aResult, aaaaResult] = await Promise.allSettled([
    dohQuery(hostname, 'A'),
    dohQuery(hostname, 'AAAA'),
  ]);
  const addresses = [];
  const providers = [];
  for (const result of [aResult, aaaaResult]) {
    if (result.status !== 'fulfilled' || !result.value) continue;
    const { json, provider } = result.value;
    if (!providers.includes(provider)) providers.push(provider);
    const type = json.Question?.[0]?.type;
    const wanted = type === RECORD_TYPE.A ? RECORD_TYPE.A : RECORD_TYPE.AAAA;
    for (const rec of json.Answer || []) {
      if (rec.type === RECORD_TYPE.A && !addresses.includes(rec.data)) addresses.push(rec.data);
      if (rec.type === RECORD_TYPE.AAAA && !addresses.includes(rec.data.toLowerCase())) {
        addresses.push(rec.data.toLowerCase());
      }
    }
  }
  const source = providers.length ? { provider: providers.join(', '), retrieved_at: isoNow() } : null;
  return { hostname, addresses, source };
}

// Reverse (PTR) lookup for an IP address. Absence of a PTR record is not an
// error: it resolves to { hostname: null }.
export async function reversePTR(ip, version, timeoutMs = 6000) {
  const name = ptrNameFor(ip, version);
  const answer = await dohQuery(name, 'PTR', timeoutMs);
  if (!answer) return { hostname: null, source: null };
  const source = { provider: answer.provider, retrieved_at: isoNow() };
  const rec = (answer.json.Answer || []).find((r) => r.type === RECORD_TYPE.PTR);
  if (!rec) return { hostname: null, source };
  return { hostname: rec.data.replace(/\.$/, ''), source };
}
