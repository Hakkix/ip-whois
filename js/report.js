// Builds the normalized v2 report model and renders it to JSON, Markdown,
// and plain text. Every exporter reads only from the normalized model —
// none of them know about RDAP, DNS, or geolocation provider shapes.
import { isoNow, has } from './utils.js';

const SCHEMA_VERSION = '2.0';

const emptyNetwork = () => ({
  name: null, handle: null, type: null, start_address: null, end_address: null,
  cidrs: [], parent_handle: null, status: [],
});
const emptyRegistration = () => ({ registered_at: null, last_changed_at: null, events: [] });
const emptyContacts = () => ({ abuse: [], technical: [], administrative: [], registrant: [] });

export function buildReport({
  input, queryType, hostname, forwardAddresses = [],
  ip, version, rdap = null, location = null, asn = null, reverse = null,
  warnings = [],
}) {
  const network = rdap ? rdap.network : emptyNetwork();
  let asnFinal = asn;
  if (asnFinal && network.cidrs.length && !asnFinal.prefix) {
    asnFinal = { ...asnFinal, prefix: network.cidrs[0] };
  }

  return {
    schema_version: SCHEMA_VERSION,
    generated_at: isoNow(),
    query: {
      input,
      type: queryType,
      hostname: queryType === 'hostname' ? hostname : null,
      resolved_ip: queryType === 'hostname' ? ip : null,
    },
    ip: { address: ip, version },
    dns: {
      forward: queryType === 'hostname' ? { hostname, addresses: forwardAddresses } : { hostname: null, addresses: [] },
      reverse: { hostname: reverse ? reverse.hostname : null },
    },
    network,
    asn: asnFinal || null,
    rir: rdap ? { name: rdap.rir.name, rdap_url: rdap.rir.rdap_url } : { name: null, rdap_url: null },
    registration: rdap ? rdap.registration : emptyRegistration(),
    registrant: rdap ? rdap.registrant : { name: null, country_code: null },
    contacts: rdap ? rdap.contacts : emptyContacts(),
    location,
    remarks: rdap ? rdap.remarks : [],
    sources: {
      rdap: rdap ? { provider: rdap.rir.name, url: rdap.rir.rdap_url } : null,
      dns: { provider: 'Cloudflare / Google DNS-over-HTTPS' },
      geolocation: location ? { provider: location.source } : null,
    },
    warnings,
  };
}

export function reportToJSON(report) {
  return JSON.stringify(report, null, 2);
}

// ---- shared formatting helpers ----

const dateOnly = (iso) => (has(iso) ? iso.slice(0, 10) : null);
const coords = (loc) => `${loc.latitude.toFixed(6)}, ${loc.longitude.toFixed(6)}`;
const osmUrl = (loc) => `https://www.openstreetmap.org/?mlat=${loc.latitude}&mlon=${loc.longitude}#map=12/${loc.latitude}/${loc.longitude}`;

function mdTable(rows) {
  const present = rows.filter(([, v]) => has(v));
  if (!present.length) return [];
  return ['| Field | Value |', '|---|---|', ...present.map(([k, v]) => `| ${k} | ${v} |`)];
}

function txtRows(rows) {
  const present = rows.filter(([, v]) => has(v));
  const width = present.reduce((w, [k]) => Math.max(w, k.length), 0);
  return present.map(([k, v]) => `  ${k.padEnd(width)}   ${v}`);
}

function summaryRows(r) {
  const rows = [['IP address', r.ip.address], ['IP version', r.ip.version === 4 ? 'IPv4' : 'IPv6']];
  if (r.query.type === 'hostname') rows.push(['Queried hostname', r.query.hostname]);
  rows.push(
    ['Network', r.network.name],
    ['ASN', r.asn ? `${r.asn.display}${r.asn.organization ? ` (${r.asn.organization})` : ''}` : null],
    ['RIR', r.rir.name],
    ['Reverse DNS', r.dns.reverse.hostname],
    ['Location', r.location ? [r.location.city, r.location.region, r.location.country].filter(has).join(', ') : null],
  );
  return rows;
}

function networkRows(r) {
  return [
    ['Name', r.network.name], ['Handle', r.network.handle], ['Type', r.network.type],
    ['Start address', r.network.start_address], ['End address', r.network.end_address],
    ['CIDR', r.network.cidrs.join(', ') || null], ['Parent network', r.network.parent_handle],
    ['Status', r.network.status.join(', ') || null], ['RIR', r.rir.name],
  ];
}

function asnRows(r) {
  return [
    ['ASN', r.asn.display], ['Organization', r.asn.organization], ['Prefix', r.asn.prefix],
    ['Country', r.asn.country_code],
  ];
}

function geoRows(r) {
  const l = r.location;
  return [
    ['Country', l.country_code ? `${l.country} (${l.country_code})` : l.country],
    ['Region', l.region], ['City', l.city], ['Postal code', l.postal_code], ['Timezone', l.timezone],
    ['Coordinates', has(l.latitude) && has(l.longitude) ? coords(l) : null], ['Provider', l.source],
  ];
}

function dnsRows(r) {
  return [
    ['Query hostname', r.query.hostname], ['Resolved addresses', r.dns.forward.addresses.join(', ') || null],
    ['Reverse DNS (PTR)', r.dns.reverse.hostname],
  ];
}

function registrationRows(r) {
  return [
    ['Registered', dateOnly(r.registration.registered_at)], ['Last changed', dateOnly(r.registration.last_changed_at)],
    ['Status', r.network.status.join(', ') || null], ['Parent network', r.network.parent_handle],
  ];
}

function contactLines(contacts, formatOne) {
  const groups = [['Abuse', contacts.abuse], ['Technical', contacts.technical],
    ['Administrative', contacts.administrative], ['Registrant', contacts.registrant]];
  const lines = [];
  for (const [label, list] of groups) {
    if (!list.length) continue;
    lines.push(`**${label}**`);
    for (const c of list) lines.push(formatOne(c));
  }
  return lines;
}

function sourcesRows(r) {
  return [
    ['RDAP', r.sources.rdap ? `${r.sources.rdap.provider} — ${r.sources.rdap.url}` : null],
    ['DNS', r.sources.dns.provider],
    ['Geolocation', r.sources.geolocation ? r.sources.geolocation.provider : null],
    ['Generated', r.generated_at],
  ];
}

export function reportToMarkdown(r) {
  const out = [`# IP Intelligence Report`, ''];
  out.push('## Summary', ...mdTable(summaryRows(r)), '');
  if (mdTable(networkRows(r)).length) out.push('## Network', ...mdTable(networkRows(r)), '');
  if (r.asn) out.push('## Autonomous System', ...mdTable(asnRows(r)), '');
  if (r.location) {
    out.push('## Geolocation', ...mdTable(geoRows(r)));
    out.push('> IP geolocation is approximate and represents network location,');
    out.push('> not the physical location of a person or device.');
    if (has(r.location.latitude) && has(r.location.longitude)) out.push('', `[Open in OpenStreetMap](${osmUrl(r.location)})`);
    out.push('');
  }
  out.push('## DNS', ...mdTable(dnsRows(r)), '');
  if (mdTable(registrationRows(r)).length) out.push('## Registration', ...mdTable(registrationRows(r)), '');
  const contactsMd = contactLines(r.contacts, (c) => `- ${[c.name, c.organization, c.email, c.phone].filter(has).join(' · ')}`);
  if (contactsMd.length) out.push('## Contacts', ...contactsMd, '');
  if (r.remarks.length) {
    out.push('## Remarks');
    for (const rem of r.remarks) out.push(`**${rem.title || 'Remark'}**`, ...rem.description.map((d) => `> ${d}`), '');
  }
  out.push('## Data Sources', ...mdTable(sourcesRows(r)));
  if (r.warnings.length) out.push('', ...r.warnings.map((w) => `⚠ ${w.component}: ${w.message}`));
  return out.join('\n');
}

function textHeader(title) {
  return [title, '-'.repeat(title.length)];
}

export function reportToText(r) {
  const out = ['IP INTELLIGENCE REPORT', '='.repeat(22), ''];
  out.push(...textHeader('SUMMARY'), ...txtRows(summaryRows(r)), '');
  if (txtRows(networkRows(r)).length) out.push(...textHeader('NETWORK'), ...txtRows(networkRows(r)), '');
  if (r.asn) out.push(...textHeader('AUTONOMOUS SYSTEM'), ...txtRows(asnRows(r)), '');
  if (r.location) {
    out.push(...textHeader('GEOLOCATION'), ...txtRows(geoRows(r)));
    out.push('  IP geolocation is approximate and represents network location,');
    out.push('  not the physical location of a person or device.', '');
  }
  out.push(...textHeader('DNS'), ...txtRows(dnsRows(r)), '');
  if (txtRows(registrationRows(r)).length) out.push(...textHeader('REGISTRATION'), ...txtRows(registrationRows(r)), '');
  const contactsTxt = contactLines(r.contacts, (c) => `    ${[c.name, c.organization, c.email, c.phone].filter(has).join(' | ')}`);
  if (contactsTxt.length) out.push(...textHeader('CONTACTS'), ...contactsTxt, '');
  out.push(...textHeader('DATA SOURCES'), ...txtRows(sourcesRows(r)));
  if (r.warnings.length) out.push('', ...r.warnings.map((w) => `  WARNING (${w.component}): ${w.message}`));
  return out.join('\n');
}
