// Lightweight, non-blocking toast/status feedback. Never uses alert().
import { el } from './domkit.js';

let region = null;

export function initToasts(container) {
  region = container;
}

export function showToast(message, { tone = 'info', timeout = 4000 } = {}) {
  if (!region) return;
  const toast = el('div', { className: `toast toast--${tone}`, attrs: { role: 'status' } }, [
    el('p', { text: message }),
  ]);
  region.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add('is-visible'));
  const remove = () => {
    toast.classList.remove('is-visible');
    setTimeout(() => toast.remove(), 250);
  };
  setTimeout(remove, timeout);
  return remove;
}

// Shows the two-line "Public IP changed" notice with both values visible.
export function showIpChangeToast(oldIp, newIp) {
  if (!region) return;
  const toast = el('div', { className: 'toast toast--info toast--ip-change', attrs: { role: 'status' } }, [
    el('p', { className: 'toast-title', text: 'Public IP changed' }),
    el('p', { className: 'mono toast-detail' }, [
      el('span', { text: oldIp }),
      el('span', { text: ' → ', attrs: { 'aria-hidden': 'true' } }),
      el('span', { text: newIp }),
    ]),
  ]);
  region.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add('is-visible'));
  const remove = () => {
    toast.classList.remove('is-visible');
    setTimeout(() => toast.remove(), 250);
  };
  setTimeout(remove, 6000);
}
