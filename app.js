import { classifyInput, isReservedIP } from './js/utils.js';
import { resolveHostname, reversePTR } from './js/dns.js';
import { fetchRdap, normalizeRdap } from './js/rdap.js';
import { fetchGeo, fetchSelfGeo, normalizeGeoResponse, normalizeAsn } from './js/geo.js';
import { buildReport, reportToJSON, reportToMarkdown, reportToText } from './js/report.js';
import { renderReport, renderLoading, renderError } from './js/render.js';
import { createSelfIpView, renderRecentLookups } from './js/landing.js';
import { renderChooser, updateChooserCandidate } from './js/chooser.js';
import { addRecentLookup, getRecentLookups } from './js/history.js';
import { initAboutModal } from './js/about.js';
import { initToasts, showToast, showIpChangeToast } from './js/toast.js';

const els = {
  header: document.querySelector('#app-header'),
  brand: document.querySelector('#brand-home'),
  myIpBtn: document.querySelector('#my-ip-btn'),
  exportBtn: document.querySelector('#export-btn'),
  exportMenu: document.querySelector('#export-menu'),
  aboutBtn: document.querySelector('#about-btn'),
  footerPrivacy: document.querySelector('#footer-privacy'),
  footerSources: document.querySelector('#footer-sources'),
  form: document.querySelector('#lookup-form'),
  input: document.querySelector('#ip-input'),
  msg: document.querySelector('#validation-message'),
  landingView: document.querySelector('#landing-view'),
  chooserView: document.querySelector('#chooser-view'),
  investigationView: document.querySelector('#investigation-view'),
  investigationContainer: document.querySelector('#investigation-container'),
  selfIpHero: document.querySelector('#self-ip-hero'),
  intelligenceTiles: document.querySelector('#intelligence-tiles'),
  sourceStatusStrip: document.querySelector('#source-status-strip'),
  recentDetails: document.querySelector('#recent-lookups'),
  recentList: document.querySelector('#recent-lookups-list'),
  toastRegion: document.querySelector('#toast-region'),
  aboutModal: document.querySelector('#about-modal'),
};

const state = { selfIp: null };
let lastReport = null;
let investigationToken = 0;

initToasts(els.toastRegion);
const about = initAboutModal(els.aboutModal);
const selfView = createSelfIpView({
  heroEl: els.selfIpHero,
  tilesEl: els.intelligenceTiles,
  statusStripEl: els.sourceStatusStrip,
});

// ---- view switching ----

function updateHeaderCompact() {
  const shouldCompact = !els.investigationView.hidden && window.scrollY > 72;
  els.header.classList.toggle('is-compact', shouldCompact);
  document.documentElement.style.setProperty('--sticky-offset', `${els.header.offsetHeight + 16}px`);
}

function showLanding() {
  els.landingView.hidden = false;
  els.chooserView.hidden = true;
  els.investigationView.hidden = true;
  els.myIpBtn.hidden = true;
  els.exportBtn.hidden = true;
  closeExportMenu();
  updateHeaderCompact();
}

function showChooser() {
  els.landingView.hidden = true;
  els.chooserView.hidden = false;
  els.investigationView.hidden = true;
  els.myIpBtn.hidden = false;
  els.exportBtn.hidden = true;
  updateHeaderCompact();
}

function showInvestigation() {
  els.landingView.hidden = true;
  els.chooserView.hidden = true;
  els.investigationView.hidden = false;
  els.myIpBtn.hidden = false;
  updateHeaderCompact();
}

function goHome() {
  investigationToken++;
  lastReport = null;
  showLanding();
  history.pushState({}, '', location.pathname);
}

// ---- clipboard + feedback ----

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      ta.remove();
      return ok;
    } catch {
      return false;
    }
  }
}

function flashIconButton(btn, ok) {
  btn.classList.toggle('is-copied', ok);
  btn.classList.toggle('is-error', !ok);
  setTimeout(() => btn.classList.remove('is-copied', 'is-error'), 1200);
}

async function handleCopyClick(e) {
  const btn = e.target.closest('[data-copy]');
  if (!btn || !btn.dataset.copy) return;
  const ok = await copyToClipboard(btn.dataset.copy);
  flashIconButton(btn, ok);
}

els.selfIpHero.addEventListener('click', handleCopyClick);
els.intelligenceTiles.addEventListener('click', handleCopyClick);

// ---- investigation report interactions ----

function scrollToSection(id) {
  const target = document.getElementById(`section-${id}`);
  if (!target) return;
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  target.scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'start' });
}

els.investigationContainer.addEventListener('click', async (e) => {
  const copyBtn = e.target.closest('[data-copy]');
  if (copyBtn) {
    const ok = await copyToClipboard(copyBtn.dataset.copy);
    flashIconButton(copyBtn, ok);
    return;
  }
  const navBtn = e.target.closest('[data-nav-target]');
  if (navBtn) {
    scrollToSection(navBtn.dataset.navTarget);
    return;
  }
  if (e.target.closest('[data-reset]')) {
    showLanding();
    els.input.focus();
  }
});

// ---- export menu ----

function closeExportMenu() {
  els.exportMenu.hidden = true;
  els.exportBtn.setAttribute('aria-expanded', 'false');
}

function toggleExportMenu() {
  const willOpen = els.exportMenu.hidden;
  els.exportMenu.hidden = !willOpen;
  els.exportBtn.setAttribute('aria-expanded', String(willOpen));
}

els.exportBtn.addEventListener('click', () => toggleExportMenu());
document.addEventListener('click', (e) => {
  if (!els.exportMenu.hidden && !e.target.closest('.export-menu-wrap')) closeExportMenu();
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !els.exportMenu.hidden) {
    closeExportMenu();
    els.exportBtn.focus();
  }
});
els.exportMenu.addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-export]');
  if (!btn || !lastReport) return;
  const format = btn.dataset.export;
  const text = format === 'json' ? reportToJSON(lastReport)
    : format === 'markdown' ? reportToMarkdown(lastReport)
      : reportToText(lastReport);
  const ok = await copyToClipboard(text);
  const label = format === 'json' ? 'JSON' : format === 'markdown' ? 'Markdown' : 'text';
  showToast(ok ? `Copied report as ${label}` : 'Copy to clipboard failed', { tone: ok ? 'info' : 'error' });
  closeExportMenu();
});

// ---- about modal + footer ----

els.aboutBtn.addEventListener('click', (e) => about.open(null, e.currentTarget));
els.footerPrivacy.addEventListener('click', (e) => about.open('privacy', e.currentTarget));
els.footerSources.addEventListener('click', (e) => about.open('sources', e.currentTarget));

// ---- brand / My IP ----

els.brand.addEventListener('click', goHome);
els.myIpBtn.addEventListener('click', goHome);

// ---- URL state ----

function pushUrlState(query) {
  const url = new URL(location.href);
  url.searchParams.set('q', query);
  history.pushState({ q: query }, '', url);
}

window.addEventListener('popstate', () => {
  const q = new URLSearchParams(location.search).get('q');
  if (q) runInvestigationFromRaw(q, { pushUrl: false });
  else goHome();
});

// ---- recent lookups ----

function refreshRecentLookupsUI() {
  renderRecentLookups(els.recentList, els.recentDetails, getRecentLookups(), (query) => {
    els.input.value = query;
    runInvestigationFromRaw(query);
  });
}

// ---- core investigation pipeline ----

async function runIpInvestigation({ ip, version, queryType, hostname, forwardAddresses, displayQuery, pushUrl }) {
  const token = ++investigationToken;
  showInvestigation();
  renderLoading(els.investigationContainer, `Looking up registration, network location, and reverse DNS for ${ip}…`);

  const [rdapSettled, geoSettled, ptrSettled] = await Promise.allSettled([
    fetchRdap(ip).then(({ rdap, finalUrl }) => normalizeRdap(rdap, finalUrl, version)),
    fetchGeo(ip),
    reversePTR(ip, version),
  ]);
  if (token !== investigationToken) return;

  const warnings = [];
  const rdapNormalized = rdapSettled.status === 'fulfilled' ? rdapSettled.value : null;
  if (rdapSettled.status !== 'fulfilled') {
    warnings.push({ component: 'rdap', message: 'Registration (RDAP) data is currently unavailable.' });
  }

  let location = null;
  let asn = null;
  if (geoSettled.status === 'fulfilled' && geoSettled.value) {
    location = normalizeGeoResponse(geoSettled.value.raw, geoSettled.value.provider);
    asn = normalizeAsn(geoSettled.value.raw, geoSettled.value.provider);
  } else {
    warnings.push({ component: 'geolocation', message: 'Geolocation data is currently unavailable.' });
  }

  const reverse = ptrSettled.status === 'fulfilled' ? ptrSettled.value : { hostname: null };

  const report = buildReport({
    input: displayQuery, queryType, hostname, forwardAddresses,
    ip, version, rdap: rdapNormalized, location, asn, reverse, warnings,
  });

  lastReport = report;
  renderReport(els.investigationContainer, report);
  els.exportBtn.hidden = false;
  updateHeaderCompact();
  addRecentLookup({ query: displayQuery });
  refreshRecentLookupsUI();
  if (pushUrl) pushUrlState(displayQuery);
}

function showChooserView(hostname, addresses, displayQuery, pushUrl) {
  const token = ++investigationToken;
  showChooser();
  const refs = renderChooser(els.chooserView, addresses, (ip) => {
    if (token !== investigationToken) return;
    const version = ip.includes(':') ? 6 : 4;
    runIpInvestigation({
      ip, version, queryType: 'hostname', hostname, forwardAddresses: addresses, displayQuery, pushUrl,
    });
  });
  for (const ip of addresses) {
    fetchGeo(ip).then((result) => {
      if (token !== investigationToken) return;
      const asn = result ? normalizeAsn(result.raw, result.provider) : null;
      updateChooserCandidate(refs, ip, asn);
    }).catch(() => updateChooserCandidate(refs, ip, null));
  }
}

async function runInvestigationFromRaw(rawInput, opts = {}) {
  const { pushUrl = true } = opts;
  const classified = classifyInput(rawInput);
  if (!classified) {
    els.msg.textContent = 'Enter a valid IPv4 address, IPv6 address, or DNS hostname.';
    return;
  }
  els.msg.textContent = '';
  const displayQuery = rawInput.trim();

  if (classified.type === 'hostname') {
    const token = ++investigationToken;
    showInvestigation();
    renderLoading(els.investigationContainer, `Resolving ${classified.value}…`);
    let resolved;
    try {
      resolved = await resolveHostname(classified.value);
    } catch {
      if (token !== investigationToken) return;
      renderError(els.investigationContainer, 'DNS resolution failed. Please try again.', classified.value);
      return;
    }
    if (token !== investigationToken) return;
    if (!resolved.addresses.length) {
      renderError(els.investigationContainer, 'Could not resolve this hostname to an IP address.', classified.value);
      return;
    }
    if (resolved.addresses.length === 1) {
      const ip = resolved.addresses[0];
      await runIpInvestigation({
        ip, version: ip.includes(':') ? 6 : 4, queryType: 'hostname', hostname: classified.value,
        forwardAddresses: resolved.addresses, displayQuery, pushUrl,
      });
      return;
    }
    showChooserView(classified.value, resolved.addresses, displayQuery, pushUrl);
    return;
  }

  const ip = classified.value;
  const version = classified.type === 'ipv4' ? 4 : 6;
  if (isReservedIP(version, ip)) {
    els.msg.textContent = 'That address is reserved/private and cannot be looked up publicly.';
    return;
  }
  await runIpInvestigation({ ip, version, queryType: classified.type, hostname: null, forwardAddresses: [], displayQuery, pushUrl });
}

els.form.addEventListener('submit', (e) => {
  e.preventDefault();
  runInvestigationFromRaw(els.input.value);
});

// ---- self-IP landing pipeline ----

async function runSelfIpDetection(isRefresh = false) {
  const previousIp = state.selfIp?.ip || null;
  if (!isRefresh) selfView.showDetecting();
  selfView.setStatus('geoip', 'loading');
  selfView.setStatus('dns', 'loading');

  let result = null;
  try {
    result = await fetchSelfGeo();
  } catch {
    result = null;
  }

  if (!result) {
    selfView.setStatus('geoip', 'unavailable');
    selfView.setStatus('dns', 'unavailable');
    if (isRefresh && previousIp) {
      showToast('Refresh failed', { tone: 'error' });
    } else {
      selfView.setDetectionFailed();
      selfView.setAsnError();
      selfView.setLocationError();
      selfView.setPtrUnavailable();
    }
    return;
  }

  const { ip, raw, provider } = result;
  const version = ip.includes(':') ? 6 : 4;
  const location = normalizeGeoResponse(raw, provider);
  const asn = normalizeAsn(raw, provider);

  selfView.setIp(ip, version);
  selfView.setOrgAsn(asn);
  selfView.setLocation(location);
  selfView.setStatus('geoip', 'available');

  state.selfIp = { ip, version, asn, location, ptr: null };

  const reverse = await reversePTR(ip, version);
  selfView.setPtr(reverse.hostname, reverse.hostname);
  selfView.setStatus('dns', 'available');
  state.selfIp.ptr = reverse.hostname;

  if (isRefresh && previousIp && previousIp !== ip) {
    showIpChangeToast(previousIp, ip);
  }
}

selfView.refs.investigateBtn.addEventListener('click', () => {
  if (!state.selfIp?.ip) return;
  runInvestigationFromRaw(state.selfIp.ip);
});
selfView.refs.refreshBtn.addEventListener('click', () => runSelfIpDetection(true));

// ---- header compact-on-scroll ----

let scrollTicking = false;
window.addEventListener('scroll', () => {
  if (scrollTicking) return;
  scrollTicking = true;
  requestAnimationFrame(() => {
    updateHeaderCompact();
    scrollTicking = false;
  });
}, { passive: true });
window.addEventListener('resize', updateHeaderCompact);

// ---- boot ----

(function init() {
  const isCoarsePointer = window.matchMedia('(pointer: coarse)').matches;
  if (!isCoarsePointer) els.input.focus();

  refreshRecentLookupsUI();
  runSelfIpDetection(false);

  const initialQuery = new URLSearchParams(location.search).get('q');
  if (initialQuery) {
    els.input.value = initialQuery;
    runInvestigationFromRaw(initialQuery, { pushUrl: false });
  } else {
    showLanding();
  }
}());
