// Multi-address chooser shown when a hostname resolves to more than one IP.
// Only IP, IP version, ASN, and organization are fetched per candidate —
// never a full RDAP/geo/report enrichment just to populate the list.
import { el } from './domkit.js';

export function renderChooser(container, addresses, onSelect) {
  container.replaceChildren();
  const refs = {};
  const list = el('div', { className: 'chooser-list', attrs: { role: 'radiogroup', 'aria-label': 'Select an address to investigate' } });
  for (const ip of addresses) {
    const version = ip.includes(':') ? 6 : 4;
    const meta = el('span', { className: 'chooser-meta mono', text: `${version === 4 ? 'IPv4' : 'IPv6'} · Loading…` });
    const item = el('button', { className: 'chooser-item', attrs: { type: 'button', role: 'radio', 'aria-checked': 'false' } }, [
      el('span', { className: 'chooser-ip mono', text: ip }),
      meta,
    ]);
    item.addEventListener('click', () => onSelect(ip));
    refs[ip] = meta;
    list.appendChild(item);
  }
  container.appendChild(el('h2', { className: 'chooser-heading', text: 'Select an address to investigate' }));
  container.appendChild(list);
  return refs;
}

export function updateChooserCandidate(refs, ip, asn) {
  const meta = refs[ip];
  if (!meta) return;
  const version = ip.includes(':') ? 6 : 4;
  const bits = [version === 4 ? 'IPv4' : 'IPv6'];
  if (asn) {
    bits.push(asn.display);
    if (asn.organization) bits.push(asn.organization);
  } else {
    bits.push('ASN unavailable');
  }
  meta.textContent = bits.join(' · ');
}
