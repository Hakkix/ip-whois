// RDAP lookup and normalization. Provider-specific (per-RIR) structural
// differences are absorbed here; nothing downstream should special-case a RIR.
import { fetchWithTimeout, rangeToCidrs, toIsoOrNull } from './utils.js';

const RDAP_BOOTSTRAP = 'https://rdap-bootstrap.arin.net/bootstrap/ip/';

export const RIR_MAP = [
  { key: 'arin.net', name: 'ARIN', region: 'North America', website: 'https://www.arin.net', color: '#4a9fff' },
  { key: 'ripe.net', name: 'RIPE NCC', region: 'Europe, Middle East, Central Asia', website: 'https://www.ripe.net', color: '#ff6577' },
  { key: 'apnic.net', name: 'APNIC', region: 'Asia Pacific', website: 'https://www.apnic.net', color: '#2bd4a3' },
  { key: 'lacnic.net', name: 'LACNIC', region: 'Latin America & Caribbean', website: 'https://www.lacnic.net', color: '#ffa451' },
  { key: 'afrinic.net', name: 'AFRINIC', region: 'Africa', website: 'https://afrinic.net', color: '#b88dff' },
];

export async function fetchRdap(ip, timeoutMs = 8000) {
  const resp = await fetchWithTimeout(`${RDAP_BOOTSTRAP}${ip}`, {}, timeoutMs);
  if (!resp.ok) throw new Error(`RDAP lookup failed (HTTP ${resp.status})`);
  const rdap = await resp.json();
  return { rdap, finalUrl: resp.url };
}

export function detectRir(finalUrl, rdap) {
  const haystack = `${finalUrl} ${JSON.stringify(rdap.links || [])} ${rdap.port43 || ''}`.toLowerCase();
  return RIR_MAP.find((r) => haystack.includes(r.key)) || null;
}

function vcardGet(vcard, prop) {
  return vcard.filter((entry) => entry[0] === prop).map((entry) => entry[3]);
}

export function normalizeContacts(entities = []) {
  const groups = { abuse: [], technical: [], administrative: [], registrant: [] };
  for (const entity of entities) {
    const vcard = entity.vcardArray?.[1] || [];
    const name = vcardGet(vcard, 'fn')[0] || null;
    const org = vcardGet(vcard, 'org')[0] || null;
    const emails = vcardGet(vcard, 'email');
    const phones = vcard.filter((e) => e[0] === 'tel').map((e) => e[3]);
    const contact = {
      name: name || org || null,
      organization: org || null,
      email: emails[0] || null,
      phone: phones[0] || null,
    };
    for (const role of entity.roles || []) {
      if (groups[role]) groups[role].push(contact);
    }
  }
  return groups;
}

export function normalizeEvents(events = []) {
  const normalized = events
    .map((e) => ({ action: e.eventAction, timestamp: toIsoOrNull(e.eventDate) }))
    .filter((e) => e.timestamp);
  const registered = normalized.find((e) => e.action === 'registration');
  const lastChanged = normalized.reduce((latest, e) => {
    if (e.action !== 'last changed' && e.action !== 'registration') return latest;
    if (!latest) return e;
    return e.timestamp > latest.timestamp ? e : latest;
  }, null);
  return {
    registered_at: registered ? registered.timestamp : null,
    last_changed_at: lastChanged ? lastChanged.timestamp : null,
    events: normalized,
  };
}

function networkCidrs(rdap, version) {
  const cidr0 = rdap.cidr0_cidrs || [];
  if (cidr0.length) {
    return cidr0.map((c) => `${c.v4prefix || c.v6prefix}/${c.length}`);
  }
  if (rdap.startAddress && rdap.endAddress) {
    try {
      return rangeToCidrs(rdap.startAddress, rdap.endAddress, version);
    } catch {
      return [];
    }
  }
  return [];
}

export function normalizeRdap(rdap, finalUrl, version) {
  const rir = detectRir(finalUrl, rdap);
  const contacts = normalizeContacts(rdap.entities);
  const registration = normalizeEvents(rdap.events);
  const registrantEntity = (rdap.entities || []).find((e) => (e.roles || []).includes('registrant'));
  const registrantVcard = registrantEntity?.vcardArray?.[1] || [];
  const registrantName = vcardGet(registrantVcard, 'fn')[0] || vcardGet(registrantVcard, 'org')[0] || rdap.name || null;

  return {
    network: {
      name: rdap.name || null,
      handle: rdap.handle || null,
      type: rdap.type || null,
      start_address: rdap.startAddress || null,
      end_address: rdap.endAddress || null,
      cidrs: networkCidrs(rdap, version),
      parent_handle: rdap.parentHandle || null,
      status: rdap.status || [],
    },
    rir: rir
      ? { name: rir.name, region: rir.region, website: rir.website, rdap_url: finalUrl, color: rir.color }
      : { name: null, region: null, website: null, rdap_url: finalUrl, color: null },
    registration,
    registrant: {
      name: registrantName,
      country_code: rdap.country || null,
    },
    contacts,
    remarks: (rdap.remarks || [])
      .map((r) => ({ title: r.title || null, description: r.description || [] }))
      .filter((r) => r.description.length),
  };
}
