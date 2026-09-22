import { classifyInput, isReservedIP } from './js/utils.js';
import { resolveHostname, reversePTR } from './js/dns.js';
import { fetchRdap, normalizeRdap } from './js/rdap.js';
import { fetchGeo, normalizeGeoResponse, normalizeAsn } from './js/geo.js';
import { buildReport, reportToJSON, reportToMarkdown, reportToText } from './js/report.js';
import { renderReport, renderLoading, renderError } from './js/render.js';

const els = {
  form: document.querySelector('#lookup-form'),
  input: document.querySelector('#ip-input'),
  msg: document.querySelector('#validation-message'),
  results: document.querySelector('#results-container'),
  chips: document.querySelectorAll('[data-example]'),
  how: document.querySelector('#how-it-works'),
  themeBtn: document.querySelector('#theme-toggle'),
};

let lastReport = null;

function primaryAddress(addresses) {
  const v4 = addresses.find((a) => a.includes('.'));
  return v4 || addresses[0];
}

async function runLookup(rawInput) {
  const classified = classifyInput(rawInput);
  if (!classified) {
    els.msg.textContent = 'Enter a valid IPv4 address, IPv6 address, or DNS hostname.';
    return;
  }
  els.msg.textContent = '';
  els.how.hidden = true;

  let ip;
  let version;
  let hostname = null;
  let forwardAddresses = [];

  if (classified.type === 'hostname') {
    hostname = classified.value;
    renderLoading(els.results, `Resolving ${hostname}…`);
    let resolved;
    try {
      resolved = await resolveHostname(hostname);
    } catch {
      renderError(els.results, 'DNS resolution failed. Please try again.', hostname);
      return;
    }
    if (!resolved.addresses.length) {
      renderError(els.results, 'Could not resolve this hostname to an IP address.', hostname);
      return;
    }
    forwardAddresses = resolved.addresses;
    ip = primaryAddress(forwardAddresses);
    version = ip.includes(':') ? 6 : 4;
  } else {
    ip = classified.value;
    version = classified.type === 'ipv4' ? 4 : 6;
  }

  if (isReservedIP(version, ip)) {
    els.msg.textContent = 'That address is reserved/private and cannot be looked up publicly.';
    els.results.replaceChildren();
    return;
  }

  renderLoading(els.results, `Looking up registration, network location, and reverse DNS for ${ip}…`);

  const [rdapSettled, geoSettled, ptrSettled] = await Promise.allSettled([
    fetchRdap(ip).then(({ rdap, finalUrl }) => normalizeRdap(rdap, finalUrl, version)),
    fetchGeo(ip),
    reversePTR(ip, version),
  ]);

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
    input: rawInput.trim(),
    queryType: classified.type,
    hostname,
    forwardAddresses,
    ip,
    version,
    rdap: rdapNormalized,
    location,
    asn,
    reverse,
    warnings,
  });

  lastReport = report;
  renderReport(els.results, report);
}

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

function flashButton(btn, msg, isError = false) {
  const span = btn.querySelector('span:last-child') || btn;
  const original = span.textContent;
  span.textContent = msg;
  btn.classList.toggle('is-copied', !isError);
  btn.classList.toggle('is-error', isError);
  setTimeout(() => {
    span.textContent = original;
    btn.classList.remove('is-copied', 'is-error');
  }, 1500);
}

els.form.addEventListener('submit', (e) => {
  e.preventDefault();
  runLookup(els.input.value);
});

els.chips.forEach((c) => c.addEventListener('click', () => {
  els.input.value = c.dataset.example;
  els.input.focus();
}));

els.results.addEventListener('click', async (e) => {
  const exportBtn = e.target.closest('[data-export]');
  if (exportBtn && lastReport) {
    const format = exportBtn.dataset.export;
    const text = format === 'json' ? reportToJSON(lastReport)
      : format === 'markdown' ? reportToMarkdown(lastReport)
        : reportToText(lastReport);
    const success = await copyToClipboard(text);
    flashButton(exportBtn, success ? 'copied' : 'failed', !success);
    return;
  }
  const copyBtn = e.target.closest('[data-copy]');
  if (copyBtn) {
    const success = await copyToClipboard(copyBtn.dataset.copy);
    flashButton(copyBtn, success ? 'copied' : 'failed', !success);
    return;
  }
  if (e.target.closest('[data-reset]')) {
    els.input.focus();
  }
});

(function initTheme() {
  const t = localStorage.getItem('theme') || 'dark';
  document.documentElement.classList.toggle('light', t === 'light');
  els.themeBtn.textContent = t === 'light' ? '☾' : '☼';
}());

els.themeBtn.addEventListener('click', () => {
  const light = document.documentElement.classList.toggle('light');
  localStorage.setItem('theme', light ? 'light' : 'dark');
  els.themeBtn.textContent = light ? '☾' : '☼';
});
