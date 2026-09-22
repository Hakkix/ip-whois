// Landing-page self-IP hero, supporting intelligence tiles, and the compact
// source-status strip. Every provider-sourced value is written via
// `textContent` (through the shared `el()` helper) — never `innerHTML`.
import { el, copyButton, has } from './domkit.js';

const STATUS_LABEL = { available: 'Available', loading: 'Loading…', unavailable: 'Unavailable' };

function statusDot(state) {
  return el('span', { className: `status-dot status-dot--${state}`, attrs: { 'aria-hidden': 'true' } });
}

export function createSelfIpView({ heroEl, tilesEl, statusStripEl }) {
  const refs = {};

  function buildHero() {
    heroEl.replaceChildren();
    const head = el('div', { className: 'self-ip-head' }, [
      el('span', { className: 'eyebrow', text: 'Your public IP' }),
    ]);
    refs.badge = el('span', { className: 'badge mono', text: '—' });
    refs.copyBtn = copyButton('', '', 'Copy public IP address');
    refs.copyBtn.disabled = true;
    const badges = el('div', { className: 'self-ip-badges' }, [refs.badge, refs.copyBtn]);
    head.appendChild(badges);

    refs.address = el('div', { className: 'self-ip-address mono', text: 'Detecting your public IP…', attrs: { 'aria-live': 'polite' } });
    refs.org = el('p', { className: 'self-ip-org' });
    refs.asn = el('p', { className: 'self-ip-asn mono' });

    refs.investigateBtn = el('button', { className: 'btn btn-primary', text: 'Investigate my IP', attrs: { type: 'button', disabled: 'disabled' } });
    refs.refreshBtn = el('button', { className: 'btn btn-ghost', text: 'Refresh', attrs: { type: 'button' } });
    const actions = el('div', { className: 'self-ip-actions' }, [refs.investigateBtn, refs.refreshBtn]);

    const card = el('article', { className: 'self-ip-card' }, [head, refs.address, refs.org, refs.asn, actions]);
    heroEl.appendChild(card);
  }

  function buildTile(key, title) {
    const body = el('div', { className: 'tile-body mono', text: `Looking up ${title.toLowerCase()}…` });
    const tile = el('article', { className: 'tile', attrs: { 'data-tile': key } }, [
      el('h3', { className: 'tile-title', text: title.toUpperCase() }),
      body,
    ]);
    refs[`tile_${key}`] = body;
    return tile;
  }

  function buildTiles() {
    tilesEl.replaceChildren(
      buildTile('asn', 'ASN / Network'),
      buildTile('location', 'Approx. location'),
      buildTile('ptr', 'Reverse DNS'),
    );
    refs.tile_asn.textContent = 'Resolving ASN…';
    refs.tile_location.textContent = 'Looking up location…';
    refs.tile_ptr.textContent = 'Looking up PTR…';
  }

  function buildStrip() {
    statusStripEl.replaceChildren();
    refs.status = {};
    for (const [key, label] of [['dns', 'DNS'], ['geoip', 'GeoIP']]) {
      const dot = statusDot('loading');
      const item = el('span', { className: 'status-item', attrs: { title: STATUS_LABEL.loading } }, [
        dot, el('span', { text: label }),
      ]);
      refs.status[key] = { item, dot };
      statusStripEl.appendChild(item);
    }
  }

  buildHero();
  buildTiles();
  buildStrip();

  return {
    refs,
    showDetecting() {
      refs.address.textContent = 'Detecting your public IP…';
      refs.investigateBtn.disabled = true;
    },
    setIp(ip, version) {
      refs.address.textContent = ip;
      refs.badge.textContent = version === 4 ? 'IPv4' : 'IPv6';
      refs.copyBtn.disabled = false;
      refs.copyBtn.dataset.copy = ip;
      refs.copyBtn.setAttribute('aria-label', `Copy public IP address ${ip}`);
      refs.investigateBtn.disabled = false;
    },
    setDetectionFailed() {
      refs.address.textContent = 'Could not detect your public IP';
      refs.investigateBtn.disabled = true;
    },
    setOrgAsn(asn) {
      if (asn && has(asn.organization)) {
        refs.org.textContent = asn.organization;
      } else {
        refs.org.textContent = '';
      }
      refs.asn.textContent = asn ? asn.display : '';
      refs.tile_asn.replaceChildren();
      if (asn) {
        refs.tile_asn.appendChild(el('p', { className: 'tile-primary mono', text: asn.display }));
        if (has(asn.organization)) refs.tile_asn.appendChild(el('p', { className: 'tile-secondary', text: asn.organization }));
      } else {
        refs.tile_asn.textContent = 'ASN unavailable';
      }
    },
    setAsnError() {
      refs.asn.textContent = '';
      refs.tile_asn.textContent = 'ASN unavailable';
    },
    setPtrUnavailable() {
      refs.tile_ptr.textContent = 'Reverse DNS unavailable';
    },
    setLocation(loc) {
      refs.tile_location.replaceChildren();
      if (!loc) {
        refs.tile_location.textContent = 'Location unavailable';
        return;
      }
      const lines = [loc.city, [loc.region, loc.country].filter(has).join(', ')].filter(has);
      if (!lines.length && has(loc.country)) lines.push(loc.country);
      if (!lines.length) {
        refs.tile_location.textContent = 'Location unavailable';
        return;
      }
      for (const line of lines) refs.tile_location.appendChild(el('p', { text: line }));
    },
    setLocationError() {
      refs.tile_location.textContent = 'Location unavailable';
    },
    setPtr(hostname, fullValue) {
      refs.tile_ptr.replaceChildren();
      if (!hostname) {
        refs.tile_ptr.textContent = 'No PTR record';
        return;
      }
      const truncated = hostname.length > 28 ? `${hostname.slice(0, 26)}…` : hostname;
      const span = el('span', { text: truncated, attrs: { tabindex: '0', title: `Source: DNS over HTTPS · ${fullValue || hostname}` } });
      refs.tile_ptr.appendChild(span);
      refs.tile_ptr.appendChild(copyButton(hostname, '', `Copy reverse DNS hostname ${hostname}`, 'icon-btn--sm'));
    },
    setStatus(key, state) {
      const entry = refs.status[key];
      if (!entry) return;
      entry.dot.className = `status-dot status-dot--${state}`;
      entry.item.setAttribute('title', STATUS_LABEL[state] || state);
    },
  };
}

export function renderRecentLookups(listEl, detailsEl, entries, onSelect) {
  listEl.replaceChildren();
  if (!entries.length) {
    detailsEl.hidden = true;
    return;
  }
  detailsEl.hidden = false;
  for (const entry of entries) {
    const btn = el('button', { className: 'recent-lookup-item mono', text: entry.query, attrs: { type: 'button' } });
    btn.addEventListener('click', () => onSelect(entry.query));
    const li = el('li', {}, [btn]);
    listEl.appendChild(li);
  }
}
