// Shared, safe DOM-construction helpers. Every value that can originate from
// an external provider or the user is written through `textContent`, never
// `innerHTML` — so untrusted data can never become markup or execute script.
import { safeUrl } from './utils.js';

export function el(tag, opts = {}, children = []) {
  const e = document.createElement(tag);
  if (opts.className) e.className = opts.className;
  if (opts.text !== undefined && opts.text !== null) e.textContent = opts.text;
  if (opts.attrs) for (const [k, v] of Object.entries(opts.attrs)) e.setAttribute(k, v);
  for (const child of children) if (child) e.appendChild(child);
  return e;
}

// Static, hard-coded SVG markup only — never built from external data.
export function icon(svgInner, size = 14) {
  const span = el('span', { className: 'icon', attrs: { 'aria-hidden': 'true' } });
  span.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" width="${size}" height="${size}">${svgInner}</svg>`;
  return span;
}

export const ICONS = {
  copy: '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
  refresh: '<path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
  check: '<path d="M20 6 9 17l-5-5"/>',
  chevron: '<path d="m6 9 6 6 6-6"/>',
};

export function copyButton(value, label, ariaLabel, extraClass = '') {
  const attrs = { type: 'button', 'data-copy': value };
  if (ariaLabel) attrs['aria-label'] = ariaLabel;
  const btn = el('button', { className: `icon-btn ${extraClass}`.trim(), attrs });
  btn.appendChild(icon(ICONS.copy, 13));
  if (label) btn.appendChild(el('span', { text: label }));
  return btn;
}

export function safeLink(url, text, allowed = ['https:']) {
  const safe = safeUrl(url, allowed);
  if (!safe) return el('span', { text });
  return el('a', { text, attrs: { href: safe, target: '_blank', rel: 'noopener noreferrer' } });
}

export const has = (v) => v !== null && v !== undefined && v !== '';
