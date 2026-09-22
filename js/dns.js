// DNS-over-HTTPS resolution: forward A/AAAA lookups and reverse PTR lookups.
import { fetchWithTimeout, ptrNameFor } from './utils.js';

const DOH_PROVIDERS = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'];
const RECORD_TYPE = { A: 1, AAAA: 28, PTR: 12 };

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
      if (json.Status === 0) return json;
      if (json.Status === 3) return json; // NXDOMAIN is a definitive answer, not a provider failure
    } catch {
      // try next provider
    }
  }
  return null;
}

// Resolves a hostname to its A and AAAA addresses.
// Returns { hostname, addresses: string[] } — addresses is [] if none resolve.
export async function resolveHostname(hostname) {
  const [aResult, aaaaResult] = await Promise.allSettled([
    dohQuery(hostname, 'A'),
    dohQuery(hostname, 'AAAA'),
  ]);
  const addresses = [];
  for (const result of [aResult, aaaaResult]) {
    if (result.status !== 'fulfilled' || !result.value) continue;
    const json = result.value;
    const type = json.Question?.[0]?.type;
    const wanted = type === RECORD_TYPE.A ? RECORD_TYPE.A : RECORD_TYPE.AAAA;
    for (const rec of json.Answer || []) {
      if (rec.type === RECORD_TYPE.A && !addresses.includes(rec.data)) addresses.push(rec.data);
      if (rec.type === RECORD_TYPE.AAAA && !addresses.includes(rec.data.toLowerCase())) {
        addresses.push(rec.data.toLowerCase());
      }
    }
  }
  return { hostname, addresses };
}

// Reverse (PTR) lookup for an IP address. Absence of a PTR record is not an
// error: it resolves to { hostname: null }.
export async function reversePTR(ip, version, timeoutMs = 6000) {
  const name = ptrNameFor(ip, version);
  const json = await dohQuery(name, 'PTR', timeoutMs);
  if (!json) return { hostname: null };
  const rec = (json.Answer || []).find((r) => r.type === RECORD_TYPE.PTR);
  if (!rec) return { hostname: null };
  return { hostname: rec.data.replace(/\.$/, '') };
}
