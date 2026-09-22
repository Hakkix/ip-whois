// All DOM construction for lookup results. Every value that can originate
// from an external provider (RDAP, DNS, geolocation) is written through
// `textContent` — never `innerHTML` — so a malicious value can never become
// markup or execute script. Links are only ever built from URLs this app
// constructs itself or that pass `safeUrl()`.
import { has, safeUrl } from './utils.js';

function el(tag, opts = {}, children = []) {
  const e = document.createElement(tag);
  if (opts.className) e.className = opts.className;
  if (opts.text !== undefined && opts.text !== null) e.textContent = opts.text;
  if (opts.attrs) for (const [k, v] of Object.entries(opts.attrs)) e.setAttribute(k, v);
  for (const child of children) if (child) e.appendChild(child);
  return e;
}

// Static, hard-coded SVG — never built from external data.
function copyIcon() {
  const span = el('span', { attrs: { 'aria-hidden': 'true' } });
  span.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" width="14" height="14"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
  return span;
}

function copyButton(value, label, ariaLabel) {
  const attrs = { type: 'button', 'data-copy': value };
  if (ariaLabel) attrs['aria-label'] = ariaLabel;
  const btn = el('button', { className: 'export-btn', attrs });
  btn.appendChild(copyIcon());
  btn.appendChild(el('span', { text: label }));
  return btn;
}

function exportButton(format, label) {
  const btn = el('button', { className: 'export-btn', attrs: { type: 'button', 'data-export': format, 'aria-label': `Copy report as ${label}` } });
  btn.appendChild(copyIcon());
  btn.appendChild(el('span', { text: label }));
  return btn;
}

function kvRows(rows) {
  const wrap = el('div', { className: 'kv' });
  let any = false;
  for (const [label, value] of rows) {
    if (!has(value)) continue;
    any = true;
    wrap.appendChild(el('div', { className: 'k', text: label }));
    wrap.appendChild(el('div', { className: 'v', text: String(value) }));
  }
  return any ? wrap : null;
}

function card(title, rows, extra = []) {
  const kv = kvRows(rows);
  if (!kv && !extra.length) return null;
  const c = el('article', { className: 'card' }, [el('h4', { text: title }), kv]);
  for (const e of extra) if (e) c.appendChild(e);
  return c;
}

function safeLink(url, text) {
  const safe = safeUrl(url, ['https:', 'http:']);
  if (!safe) return el('span', { text });
  return el('a', { text, attrs: { href: safe, target: '_blank', rel: 'noopener noreferrer' } });
}

function coords(loc) {
  return `${loc.latitude.toFixed(6)}, ${loc.longitude.toFixed(6)}`;
}

function osmUrl(loc) {
  return `https://www.openstreetmap.org/?mlat=${loc.latitude}&mlon=${loc.longitude}#map=12/${loc.latitude}/${loc.longitude}`;
}

function summaryCard(r) {
  const versionLabel = r.ip.version === 4 ? 'IPv4' : 'IPv6';
  const heading = el('div', { className: 'v mono summary-ip' });
  if (r.query.type === 'hostname') {
    heading.appendChild(document.createTextNode(`${r.query.hostname} → ${r.ip.address}`));
  } else {
    heading.appendChild(document.createTextNode(r.ip.address));
  }
  heading.appendChild(copyButton(r.ip.address, 'copy', `Copy IP address ${r.ip.address}`));

  const sub = [];
  if (has(r.network.name)) sub.push(r.network.name);
  const subLine = el('p', { className: 'summary-org' });
  if (sub.length) subLine.appendChild(document.createTextNode(sub.join(' ')));

  const metaBits = [];
  if (r.asn) metaBits.push(`${r.asn.display}${has(r.asn.prefix) ? ` · ${r.asn.prefix}` : ''}`);
  const metaLine = el('p', { className: 'summary-meta mono', text: metaBits.join(' ') || null });

  const locBits = r.location ? [r.location.city, r.location.region, r.location.country].filter(has) : [];
  const locLine = el('p', { className: 'summary-loc', text: locBits.length ? locBits.join(', ') : null });

  const ptrLine = el('p', { className: 'summary-ptr mono', text: has(r.dns.reverse.hostname) ? `Reverse DNS: ${r.dns.reverse.hostname}` : null });

  const main = el('div', { className: 'summary-main' }, [
    el('div', { className: 'k', text: `${versionLabel} ADDRESS` }),
    heading,
    sub.length ? subLine : null,
    metaBits.length ? metaLine : null,
    locBits.length ? locLine : null,
    has(r.dns.reverse.hostname) ? ptrLine : null,
  ]);

  const badge = el('span', { className: 'badge', text: r.rir.name || 'RIR unknown' });

  const exportBar = el('div', { className: 'export-bar' }, [
    el('span', { className: 'export-label', text: 'COPY REPORT' }),
    exportButton('markdown', 'Markdown'),
    exportButton('text', 'Text'),
    exportButton('json', 'JSON'),
  ]);

  const side = el('div', { className: 'summary-side' }, [badge, exportBar]);

  return el('article', { className: 'result-summary' }, [main, side]);
}

function networkCard(r) {
  return card('Network allocation', [
    ['Name', r.network.name], ['Handle', r.network.handle], ['Type', r.network.type],
    ['Start address', r.network.start_address], ['End address', r.network.end_address],
    ['CIDR', r.network.cidrs.join(', ') || null], ['Parent network', r.network.parent_handle],
    ['Status', r.network.status.join(', ') || null], ['RIR', r.rir.name],
  ]);
}

function asnCard(r) {
  if (!r.asn) return null;
  return card('Autonomous system', [
    ['ASN', r.asn.display], ['Organization', r.asn.organization], ['Prefix', r.asn.prefix],
    ['Country', r.asn.country_code],
  ]);
}

function dnsCard(r) {
  return card('DNS', [
    ['Query hostname', r.query.hostname || '—'],
    ['Resolved addresses', r.dns.forward.addresses.join(', ') || null],
    ['Reverse DNS (PTR)', r.dns.reverse.hostname],
  ]);
}

function registrationCard(r) {
  return card('Registration', [
    ['Registered', has(r.registration.registered_at) ? r.registration.registered_at.slice(0, 10) : null],
    ['Last changed', has(r.registration.last_changed_at) ? r.registration.last_changed_at.slice(0, 10) : null],
    ['Status', r.network.status.join(', ') || null],
    ['Parent network', r.network.parent_handle],
  ]);
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
  const c = el('article', { className: 'card' }, [el('h4', { text: 'Geolocation' })]);
  if (kv) c.appendChild(kv);

  if (has(loc.latitude) && has(loc.longitude)) {
    const coordRow = el('div', { className: 'kv-coords' }, [
      el('span', { className: 'mono', text: coords(loc) }),
      copyButton(coords(loc), 'copy', `Copy coordinates ${coords(loc)}`),
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
    list.appendChild(el('div', { className: 'v', text: e.timestamp ? e.timestamp.slice(0, 10) : null }));
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
  if (!kv) return null;
  const c = el('article', { className: 'card' }, [el('h4', { text: 'Data sources' }), kv]);
  if (r.sources.rdap && has(r.sources.rdap.url)) {
    c.appendChild(el('p', { className: 'mono' }, [safeLink(r.sources.rdap.url, r.sources.rdap.url)]));
  }
  return c;
}

function warningsBanner(r) {
  if (!r.warnings.length) return null;
  const banner = el('div', { className: 'warnings-banner', attrs: { role: 'status', 'aria-live': 'polite' } });
  for (const w of r.warnings) banner.appendChild(el('p', { text: w.message }));
  return banner;
}

export function renderReport(container, report) {
  container.replaceChildren();
  container.appendChild(summaryCard(report));
  const banner = warningsBanner(report);
  if (banner) container.appendChild(banner);

  const grid = el('div', { className: 'result-grid' });
  for (const c of [networkCard(report), asnCard(report), dnsCard(report), registrationCard(report), geoCard(report)]) {
    if (c) grid.appendChild(c);
  }
  container.appendChild(grid);

  const secondary = el('div', { className: 'result-secondary' });
  for (const s of [contactsSection(report), eventsSection(report), remarksSection(report)]) {
    if (s) secondary.appendChild(s);
  }
  if (secondary.children.length) container.appendChild(secondary);

  const src = sourcesCard(report);
  if (src) container.appendChild(src);
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
    el('button', { className: 'chip', text: 'Try another address', attrs: { type: 'button', 'data-reset': '1' } }),
  ]);
  container.replaceChildren(article);
}
