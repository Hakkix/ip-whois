// Live-provider smoke test. NOT part of `npm test` or the pull-request
// workflow: it talks to the real RDAP, DNS-over-HTTPS and GeoIP services and
// is run by .github/workflows/live-smoke.yml (scheduled / manual) or with
// `npm run test:live`.
//
// It checks response *shape*, never exact values: addresses, ASNs, cities and
// coordinates legitimately change. Each provider is probed on its own, so an
// outage of one is distinguishable from a format change in another; see
// live/probe.mjs for the failure policy.
import { appendFileSync } from 'node:fs';
import { probe, evaluate, formatSummary, getJson, FormatError } from './probe.mjs';
import { geoUrl, isUsableGeo, GEO_PROVIDERS, normalizeGeoResponse, normalizeAsn } from '../js/geo.js';
import { DOH_PROVIDERS } from '../js/dns.js';
import { fetchRdap } from '../js/rdap.js';
import { normalizeRdap } from '../js/rdap.js';
import { validIPv4 } from '../js/utils.js';

// Well-known, long-lived public addresses and name.
const IPV4 = '8.8.8.8';
const IPV6 = '2001:4860:4860::8888';
const HOST = 'example.com';

const need = (cond, msg) => { if (!cond) throw new FormatError(msg); };

const groups = { rdap: [], dns: [], geo: [] };

for (const [ip, version] of [[IPV4, 4], [IPV6, 6]]) {
  groups.rdap.push(await probe(`RDAP bootstrap ${ip}`, async () => {
    const { rdap, finalUrl } = await fetchRdap(ip, 10000).catch((e) => {
      if (e instanceof SyntaxError) throw new FormatError('RDAP body is not valid JSON');
      throw e;
    });
    need(rdap && typeof rdap === 'object', 'RDAP answer is not an object');
    need(typeof rdap.startAddress === 'string' && typeof rdap.endAddress === 'string', 'RDAP lacks startAddress/endAddress');
    const n = normalizeRdap(rdap, finalUrl, version);
    need(n.rir && n.rir.name, 'could not identify the RIR from the RDAP answer');
    need(n.network.name || n.network.handle, 'normalized RDAP has neither network name nor handle');
    need(n.network.cidrs.length > 0, 'normalized RDAP has no CIDR');
  }));
}

for (const base of DOH_PROVIDERS) {
  const host = new URL(base).hostname;
  const doh = (name, type) => getJson(`${base}?name=${encodeURIComponent(name)}&type=${type}`, { headers: { accept: 'application/dns-json' } });
  groups.dns.push(await probe(`DoH A ${host}`, async () => {
    const j = await doh(HOST, 'A');
    need(j && j.Status === 0, `unexpected Status ${j?.Status}`);
    need(Array.isArray(j.Answer) && j.Answer.some((r) => r.type === 1 && validIPv4(r.data)), 'no valid A record in Answer');
  }));
  groups.dns.push(await probe(`DoH PTR ${host}`, async () => {
    const j = await doh('8.8.8.8.in-addr.arpa', 'PTR');
    need(j && (j.Status === 0 || j.Status === 3), `unexpected Status ${j?.Status}`);
    if (j.Status === 0) need(Array.isArray(j.Answer) && j.Answer.every((r) => typeof r.data === 'string'), 'malformed PTR Answer');
  }));
}

for (const id of GEO_PROVIDERS) {
  groups.geo.push(await probe(`GeoIP ${id}`, async () => {
    const raw = await getJson(geoUrl(id, IPV4));
    need(isUsableGeo(raw, id, IPV4), 'answer is not usable (error payload, wrong address or no data)');
    const asn = normalizeAsn(raw, id);
    const loc = normalizeGeoResponse(raw, id);
    need(asn || loc.country_code || loc.city, 'no ASN and no location fields could be extracted');
    // Coordinates are optional but, when present, were already range-checked by the normalizer.
  }));
}

const result = evaluate(groups);
const text = formatSummary(result);
console.log(text);
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `## Live provider smoke test\n\n\`\`\`\n${text}\n\`\`\`\n`);
for (const l of result.lines) {
  if (l.status === 'outage' && process.env.GITHUB_ACTIONS) console.log(`::warning title=Provider outage::${l.name}: ${l.detail}`);
  if (l.status === 'format' && process.env.GITHUB_ACTIONS) console.log(`::error title=Response format changed::${l.name}: ${l.detail}`);
}
process.exit(result.failed ? 1 : 0);
