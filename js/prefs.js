// User preferences. Unlike lookup history (sessionStorage), a preference has
// to outlive the tab to be useful, so it uses localStorage. It holds only
// this flag, never a query. Storage may be unavailable or throw; the default
// is privacy-first: searches stay out of the URL unless the user opts in.
//
// Legacy flag: earlier versions stored '1' under LEGACY_KEEP_URL_CLEAN to
// *hide* queries (the default then was to show them). Hiding is now the
// default, so that stored intent needs no migration. A user who had
// explicitly turned hiding off left no trace (the key was removed), so that
// choice cannot be recovered and they get the new default.
const SHARE_QUERY_IN_URL = 'ip-intelligence:share-queries-in-url';
const LEGACY_KEEP_URL_CLEAN = 'ip-intelligence:keep-queries-out-of-url';

// Holds the choice for this page load when storage is blocked, so the
// checkbox still behaves as expected until reload.
let memoryChoice = null;

export function getShareQueryInUrl() {
  if (memoryChoice !== null) return memoryChoice;
  try {
    return localStorage.getItem(SHARE_QUERY_IN_URL) === '1';
  } catch {
    return false;
  }
}

export function setShareQueryInUrl(on) {
  memoryChoice = Boolean(on);
  try {
    if (on) {
      localStorage.setItem(SHARE_QUERY_IN_URL, '1');
      localStorage.removeItem(LEGACY_KEEP_URL_CLEAN);
    } else {
      localStorage.removeItem(SHARE_QUERY_IN_URL);
    }
  } catch {
    // best-effort: the choice still applies until the page is reloaded
  }
}
