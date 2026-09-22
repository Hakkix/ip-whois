// Session-only recent-lookup history. Uses sessionStorage (never
// localStorage), so it disappears when the browser tab/session ends and is
// never shared across sessions or devices.
const KEY = 'ip-intelligence:recent-lookups';
const MAX_ENTRIES = 10;

function readAll() {
  try {
    const raw = sessionStorage.getItem(KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeAll(list) {
  try {
    sessionStorage.setItem(KEY, JSON.stringify(list.slice(0, MAX_ENTRIES)));
  } catch {
    // sessionStorage unavailable (private mode, quota) — history is best-effort.
  }
}

export function getRecentLookups() {
  return readAll();
}

// entry: { query, ip, version }. Avoids duplicate consecutive entries.
export function addRecentLookup(entry) {
  if (!entry || !entry.query) return getRecentLookups();
  const list = readAll();
  if (list.length && list[0].query === entry.query) return list;
  const next = [entry, ...list.filter((e) => e.query !== entry.query)].slice(0, MAX_ENTRIES);
  writeAll(next);
  return next;
}

export function clearRecentLookups() {
  writeAll([]);
}
