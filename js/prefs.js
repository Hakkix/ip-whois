// User preferences. Unlike lookup history (sessionStorage), a preference has
// to outlive the tab to be useful, so it uses localStorage. It holds only
// this flag, never a query. Storage may be unavailable; the default is off.
const KEEP_URL_CLEAN = 'ip-intelligence:keep-queries-out-of-url';

export function getKeepQueryOutOfUrl() {
  try {
    return localStorage.getItem(KEEP_URL_CLEAN) === '1';
  } catch {
    return false;
  }
}

export function setKeepQueryOutOfUrl(on) {
  try {
    if (on) localStorage.setItem(KEEP_URL_CLEAN, '1');
    else localStorage.removeItem(KEEP_URL_CLEAN);
  } catch {
    // best-effort: the choice still applies until the page is reloaded
  }
}
