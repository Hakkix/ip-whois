// Classification and bounded retry for the live-provider smoke test.
// A probe ends in one of three states:
//   ok      — the provider answered and the answer has the shape we rely on
//   outage  — we could not get an answer: network error, timeout, HTTP 4xx/5xx
//             (including rate limiting). Retried, then reported as an outage.
//   format  — HTTP 200 but the body no longer has the expected shape. Not
//             retried (it will not fix itself) and always treated as a failure.
export class FormatError extends Error {}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Fetches JSON with a hard timeout; any HTTP error status becomes a plain
// Error (an outage), an unparseable 200 body becomes a FormatError.
export async function getJson(url, { timeoutMs = 10000, headers } = {}) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const resp = await fetch(url, { headers, signal: ctl.signal });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    try {
      return await resp.json();
    } catch {
      throw new FormatError('response body is not valid JSON');
    }
  } finally {
    clearTimeout(timer);
  }
}

export async function probe(name, fn, { attempts = 3, delayMs = 1500, wait = sleep } = {}) {
  let last;
  for (let i = 1; i <= attempts; i++) {
    try {
      await fn();
      return { name, status: 'ok', attempts: i };
    } catch (e) {
      if (e instanceof FormatError) return { name, status: 'format', attempts: i, detail: e.message };
      last = e;
      if (i < attempts) await wait(delayMs * i);
    }
  }
  const reason = last?.name === 'AbortError' ? 'timeout' : String(last?.message ?? last);
  return { name, status: 'outage', attempts, detail: reason };
}

// Policy: a format change is always a failure; an outage only fails when no
// provider in the group is left to fall back to (the app's cascade is broken).
export function evaluate(groups) {
  const lines = [];
  let failed = false;
  for (const [group, results] of Object.entries(groups)) {
    const ok = results.filter((r) => r.status === 'ok').length;
    for (const r of results) {
      lines.push({ group, ...r });
      if (r.status === 'format') failed = true;
    }
    if (ok === 0) failed = true;
  }
  return { failed, lines };
}

export function formatSummary({ failed, lines }) {
  const icon = { ok: 'OK    ', outage: 'OUTAGE', format: 'FORMAT' };
  const rows = lines.map((l) => `${icon[l.status]}  ${l.group.padEnd(5)} ${l.name}${l.detail ? ` — ${l.detail}` : ''}${l.attempts > 1 ? ` (after ${l.attempts} attempts)` : ''}`);
  return [...rows, '', failed ? 'RESULT: FAILED' : 'RESULT: PASSED'].join('\n');
}
