// All DOM construction for the investigation report. Every value that can
// originate from an external provider (RDAP, DNS, geolocation) is written
// through `textContent` — never `innerHTML` — so a malicious value can
// never become markup or execute script. Links are only ever built from
// URLs this app constructs itself or that pass `safeUrl()`.
import { el, icon, ICONS, copyButton, safeLink, has } from './domkit.js';

function kvRows(rows) {
  const wrap = el('div', { className: 'kv' });
  let any = false;
  for (const [label, value] of rows) {
    if (!has(value)) continue;
    any = true;
    wrap.appendChild(el('div', { className: 'k', text: label }));
    wrap.appendChild(el('div', { className: 'v mono', text: String(value) }));
  }
  return any ? wrap : null;
}

function sectionCard(id, title, iconSvg, rows, extra = []) {
  const kv = kvRows(rows);
  if (!kv && !extra.length) return null;
  const heading = el('h3', { className: 'section-title' }, [icon(iconSvg, 16), el('span', { text: title })]);
  const c = el('article', { className: 'card', attrs: { id: `section-${id}` } }, [heading]);
  if (kv) c.appendChild(kv);
  for (const e of extra) if (e) c.appendChild(e);
  return c;
}

function coords(loc) {
  return `${loc.latitude.toFixed(6)}, ${loc.longitude.toFixed(6)}`;
}

function osmUrl(loc) {
  return `https://www.openstreetmap.org/?mlat=${loc.latitude}&mlon=${loc.longitude}#map=12/${loc.latitude}/${loc.longitude}`;
}

function formatGeneratedAt(iso) {
  try {
    const d = new Date(iso);
    const datePart = new Intl.DateTimeFormat('en-CA', { year: 'numeric', month: '2-digit', day: '2-digit' }).format(d);
    const timePart = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false }).format(d);
    const parts = new Intl.DateTimeFormat('en-US', { timeZoneName: 'short' }).formatToParts(d);
    const tz = parts.find((p) => p.type === 'timeZoneName')?.value || '';
    return `Generated ${datePart} ${timePart}${tz ? ` ${tz}` : ''}`;
  } catch {
    return `Generated ${iso}`;
  }
}

function summaryCard(r) {
  const versionLabel = r.ip.version === 4 ? 'IPv4' : 'IPv6';
  const heading = el('div', { className: 'v mono summary-ip' });
  if (r.query.type === 'hostname') {
    heading.appendChild(document.createTextNode(`${r.query.hostname} → ${r.ip.address}`));
  } else {
    heading.appendChild(document.createTextNode(r.ip.address));
  }
  heading.appendChild(copyButton(r.ip.address, '', `Copy IP address ${r.ip.address}`));

  const subLine = el('p', { className: 'summary-org', text: has(r.network.name) ? r.network.name : null });

  const metaBits = [];
  if (r.asn) metaBits.push(`${r.asn.display}${has(r.asn.prefix) ? ` · ${r.asn.prefix}` : ''}`);
  const metaLine = el('p', { className: 'summary-meta mono', text: metaBits.join(' ') || null });

  const locBits = r.location ? [r.location.city, r.location.region, r.location.country].filter(has) : [];
  const locLine = el('p', { className: 'summary-loc', text: locBits.length ? locBits.join(', ') : null });

  const ptrLine = el('p', { className: 'summary-ptr mono', text: has(r.dns.reverse.hostname) ? `Reverse DNS: ${r.dns.reverse.hostname}` : null });
  const genLine = el('p', { className: 'summary-generated', text: formatGeneratedAt(r.generated_at) });

  const main = el('div', { className: 'summary-main' }, [
    el('div', { className: 'k', text: versionLabel }),
    heading,
    subLine,
    metaBits.length ? metaLine : null,
    locBits.length ? locLine : null,
    has(r.dns.reverse.hostname) ? ptrLine : null,
    genLine,
  ]);

  const badge = el('span', { className: 'badge', text: r.rir.name || 'RIR unknown' });
  const side = el('div', { className: 'summary-side' }, [badge]);

  return el('article', { className: 'result-summary', attrs: { id: 'section-summary' } }, [main, side]);
}

function sourceAvailabilityRow(r) {
  const entries = [
    ['RDAP', has(r.network.name) || has(r.rir.name)],
    ['DNS', true],
    ['GeoIP', Boolean(r.location)],
    ['ASN', Boolean(r.asn)],
  ];
  const row = el('div', { className: 'source-row', attrs: { role: 'status' } });
  for (const [label, ok] of entries) {
    const item = el('span', { className: `source-item ${ok ? 'is-ok' : 'is-missing'}` }, [
      el('span', { text: label }),
      icon(ok ? ICONS.check : '<path d="M18 6 6 18M6 6l12 12"/>', 12),
    ]);
    if (!ok) item.appendChild(el('span', { className: 'sr-only', text: 'unavailable' }));
    row.appendChild(item);
  }
  return row;
}

function sectionNav(sectionIds) {
  const nav = el('nav', { className: 'section-nav', attrs: { 'aria-label': 'Report sections' } });
  const labels = { summary: 'Summary', network: 'Network', asn: 'ASN', geo: 'Geo', dns: 'DNS', registration: 'Registration', sources: 'Sources' };
  for (const id of sectionIds) {
    nav.appendChild(el('button', { className: 'section-nav-item', text: labels[id] || id, attrs: { type: 'button', 'data-nav-target': id } }));
  }
  return nav;
}

function networkCard(r) {
  return sectionCard('network', 'Network', ICONS_NETWORK, [
    ['Name', r.network.name], ['Handle', r.network.handle], ['Type', r.network.type],
    ['Start address', r.network.start_address], ['End address', r.network.end_address],
    ['CIDR', r.network.cidrs.join(', ') || null], ['Parent network', r.network.parent_handle],
    ['Status', r.network.status.join(', ') || null], ['RIR', r.rir.name],
  ]);
}

function asnCard(r) {
  if (!r.asn) return null;
  return sectionCard('asn', 'Autonomous system', ICONS_ASN, [
    ['ASN', r.asn.display], ['Organization', r.asn.organization], ['Prefix', r.asn.prefix],
    ['Country', r.asn.country_code],
  ]);
}

function dnsCard(r) {
  return sectionCard('dns', 'DNS', ICONS_DNS, [
    ['Query hostname', r.query.hostname || null],
    ['Resolved addresses', r.dns.forward.addresses.join(', ') || null],
    ['Reverse DNS (PTR)', r.dns.reverse.hostname],
  ]);
}

function registrationCard(r) {
  return sectionCard('registration', 'Registration', ICONS_REG, [
    ['Registered', has(r.registration.registered_at) ? r.registration.registered_at.slice(0, 10) : null],
    ['Last changed', has(r.registration.last_changed_at) ? r.registration.last_changed_at.slice(0, 10) : null],
    ['Status', r.network.status.join(', ') || null],
    ['Parent network', r.network.parent_handle],
  ]);
}

function requestMapRender(container, lat, lon) {
  if (typeof window === 'undefined' || !window.L) return;
  try {
    const map = window.L.map(container, { attributionControl: true, zoomControl: true }).setView([lat, lon], 10);
    window.L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      maxZoom: 18,
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">OpenStreetMap</a> contributors',
    }).addTo(map);
    window.L.marker([lat, lon]).addTo(map);
  } catch {
    // Leaflet failed to initialize (e.g. CDN blocked) — the textual
    // geolocation data above still stands on its own.
  }
}

function geoCard(r) {
  const loc = r.location;
  if (!loc) return null;
  const rows = [
    ['Country', loc.country_code ? `${loc.country || ''} (${loc.country_code})` : loc.country],
    ['Region', loc.region], ['City', loc.city], ['Postal code', loc.postal_code], ['Timezone', loc.timezone],
    ['Provider', loc.source],
  ];
  const kv = kvRows(rows);
  const heading = el('h3', { className: 'section-title' }, [icon(ICONS_GEO, 16), el('span', { text: 'Geolocation' })]);
  const c = el('article', { className: 'card', attrs: { id: 'section-geo' } }, [heading]);
  if (kv) c.appendChild(kv);

  if (has(loc.latitude) && has(loc.longitude)) {
    const coordRow = el('div', { className: 'kv-coords' }, [
      el('span', { className: 'mono', text: coords(loc) }),
      copyButton(coords(loc), '', `Copy coordinates ${coords(loc)}`),
      safeLink(osmUrl(loc), 'Open in OpenStreetMap'),
    ]);
    c.appendChild(coordRow);
    const mapEl = el('div', { className: 'geo-map', attrs: { role: 'img', 'aria-label': `Map showing approximate location near ${[loc.city, loc.country].filter(has).join(', ') || 'the queried IP'}` } });
    c.appendChild(mapEl);
    requestMapRender(mapEl, loc.latitude, loc.longitude);
  }

  c.appendChild(el('p', { className: 'disclaimer', text: 'IP geolocation is approximate and represents network location, not the physical location of a person or device.' }));
  return c;
}

function contactGroup(label, contacts) {
  if (!contacts.length) return null;
  const group = el('div', { className: 'contact-group' }, [el('h5', { text: label })]);
  for (const c of contacts) {
    const line = [c.name, c.organization, c.email, c.phone].filter(has).join(' · ');
    if (line) group.appendChild(el('p', { className: 'mono', text: line }));
  }
  return group;
}

function contactsSection(r) {
  const groups = [
    contactGroup('Abuse', r.contacts.abuse),
    contactGroup('Technical', r.contacts.technical),
    contactGroup('Administrative', r.contacts.administrative),
    contactGroup('Registrant', r.contacts.registrant),
  ].filter(Boolean);
  if (!groups.length) return null;
  const details = el('details', { className: 'card collapsible' });
  details.appendChild(el('summary', { text: 'Contacts' }));
  for (const g of groups) details.appendChild(g);
  return details;
}

function eventsSection(r) {
  if (!r.registration.events.length) return null;
  const details = el('details', { className: 'card collapsible' });
  details.appendChild(el('summary', { text: 'Events' }));
  const list = el('div', { className: 'kv' });
  for (const e of r.registration.events) {
    list.appendChild(el('div', { className: 'k', text: e.action }));
    list.appendChild(el('div', { className: 'v mono', text: e.timestamp ? e.timestamp.slice(0, 10) : null }));
  }
  details.appendChild(list);
  return details;
}

function remarksSection(r) {
  if (!r.remarks.length) return null;
  const details = el('details', { className: 'card collapsible' });
  details.appendChild(el('summary', { text: 'Remarks' }));
  for (const rem of r.remarks) {
    if (rem.title) details.appendChild(el('h5', { text: rem.title }));
    for (const line of rem.description) details.appendChild(el('p', { text: line }));
  }
  return details;
}

function sourcesCard(r) {
  const kv = kvRows([
    ['RDAP', r.sources.rdap ? r.sources.rdap.provider : null],
    ['DNS', r.sources.dns.provider],
    ['Geolocation', r.sources.geolocation ? r.sources.geolocation.provider : null],
    ['Generated', r.generated_at],
  ]);
  const heading = el('h3', { className: 'section-title' }, [icon(ICONS_SOURCES, 16), el('span', { text: 'Data sources' })]);
  const c = el('article', { className: 'card', attrs: { id: 'section-sources' } }, [heading]);
  if (kv) c.appendChild(kv);
  if (r.sources.rdap && has(r.sources.rdap.url)) {
    c.appendChild(el('p', { className: 'mono' }, [safeLink(r.sources.rdap.url, r.sources.rdap.url)]));
  }
  return kv || (r.sources.rdap && has(r.sources.rdap.url)) ? c : null;
}

function warningsBanner(r) {
  if (!r.warnings.length) return null;
  const banner = el('div', { className: 'warnings-banner', attrs: { role: 'status', 'aria-live': 'polite' } });
  for (const w of r.warnings) banner.appendChild(el('p', { text: w.message }));
  return banner;
}

// Restrained, hard-coded icon paths (never built from external data).
const ICONS_NETWORK = '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/>';
const ICONS_ASN = '<path d="M4 19h16"/><path d="M6 19V9l6-5 6 5v10"/><path d="M10 19v-6h4v6"/>';
const ICONS_GEO = '<circle cx="12" cy="10" r="3"/><path d="M12 21s7-6.5 7-11a7 7 0 0 0-14 0c0 4.5 7 11 7 11Z"/>';
const ICONS_DNS = '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>';
const ICONS_REG = '<rect x="3" y="4" width="18" height="17" rx="2"/><path d="M3 9h18M8 2v4M16 2v4"/>';
const ICONS_SOURCES = '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>';

export function renderReport(container, report) {
  container.replaceChildren();

  const cards = {
    network: networkCard(report),
    asn: asnCard(report),
    geo: geoCard(report),
    dns: dnsCard(report),
    registration: registrationCard(report),
  };
  const sources = sourcesCard(report);
  const order = ['summary', 'network', 'asn', 'geo', 'dns', 'registration'];
  const sectionIds = ['summary', ...order.filter((id) => id !== 'summary' && cards[id])];
  if (sources) sectionIds.push('sources');

  container.appendChild(summaryCard(report));
  container.appendChild(sourceAvailabilityRow(report));
  container.appendChild(sectionNav(sectionIds));

  const banner = warningsBanner(report);
  if (banner) container.appendChild(banner);

  const grid = el('div', { className: 'result-grid' });
  for (const id of order) if (cards[id]) grid.appendChild(cards[id]);
  container.appendChild(grid);

  const secondary = el('div', { className: 'result-secondary' });
  for (const s of [contactsSection(report), eventsSection(report), remarksSection(report)]) {
    if (s) secondary.appendChild(s);
  }
  if (secondary.children.length) container.appendChild(secondary);

  if (sources) container.appendChild(sources);
}

export function renderLoading(container, text) {
  const article = el('article', { className: 'result-summary result-loading', attrs: { role: 'status', 'aria-live': 'polite' } });
  article.appendChild(el('div', { className: 'summary-main' }, [el('p', { className: 'mono', text })]));
  container.replaceChildren(article);
}

export function renderError(container, message, query) {
  const article = el('article', { className: 'result-error', attrs: { role: 'alert' } }, [
    el('h3', { text: 'Lookup failed' }),
    el('p', { text: message }),
    query ? el('p', {}, [el('strong', { text: 'Query: ' }), document.createTextNode(query)]) : null,
    el('button', { className: 'btn btn-ghost', text: 'Try another address', attrs: { type: 'button', 'data-reset': '1' } }),
  ]);
  container.replaceChildren(article);
}
