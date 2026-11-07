// Deterministic tests for the live-smoke classification logic (no network).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { probe, evaluate, formatSummary, FormatError, getJson } from '../live/probe.mjs';

const noWait = async () => {};

describe('probe', () => {
  test('ok on first success', async () => {
    assert.deepEqual(await probe('p', async () => {}, { wait: noWait }), { name: 'p', status: 'ok', attempts: 1 });
  });
  test('retries an outage, then succeeds', async () => {
    let n = 0;
    const r = await probe('p', async () => { if (++n < 3) throw new Error('HTTP 503'); }, { wait: noWait });
    assert.equal(r.status, 'ok');
    assert.equal(r.attempts, 3);
  });
  test('retries are bounded and the result is an outage', async () => {
    let n = 0;
    const r = await probe('p', async () => { n++; throw new Error('HTTP 429'); }, { attempts: 3, wait: noWait });
    assert.equal(n, 3);
    assert.deepEqual([r.status, r.detail], ['outage', 'HTTP 429']);
  });
  test('a timeout is reported as an outage', async () => {
    const r = await probe('p', async () => { throw Object.assign(new Error('aborted'), { name: 'AbortError' }); }, { attempts: 1, wait: noWait });
    assert.deepEqual([r.status, r.detail], ['outage', 'timeout']);
  });
  test('a format change is not retried', async () => {
    let n = 0;
    const r = await probe('p', async () => { n++; throw new FormatError('no Answer'); }, { wait: noWait });
    assert.equal(n, 1);
    assert.deepEqual([r.status, r.detail], ['format', 'no Answer']);
  });
});

describe('getJson', () => {
  const orig = globalThis.fetch;
  test('HTTP error is an outage-type Error; invalid JSON is a FormatError', async () => {
    globalThis.fetch = async () => ({ ok: false, status: 502 });
    await assert.rejects(getJson('https://x.invalid/'), (e) => !(e instanceof FormatError) && /HTTP 502/.test(e.message));
    globalThis.fetch = async () => ({ ok: true, json: async () => { throw new SyntaxError('x'); } });
    await assert.rejects(getJson('https://x.invalid/'), FormatError);
    globalThis.fetch = orig;
  });
  test('aborts a hung request at the timeout', async () => {
    globalThis.fetch = (url, { signal }) => new Promise((_, reject) => signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' }))));
    await assert.rejects(getJson('https://x.invalid/', { timeoutMs: 20 }), { name: 'AbortError' });
    globalThis.fetch = orig;
  });
});

describe('evaluate (failure policy)', () => {
  const ok = (name) => ({ name, status: 'ok', attempts: 1 });
  const out = (name) => ({ name, status: 'outage', attempts: 3, detail: 'HTTP 503' });
  const fmt = (name) => ({ name, status: 'format', attempts: 1, detail: 'changed' });

  test('all healthy passes', () => assert.equal(evaluate({ geo: [ok('a'), ok('b')] }).failed, false));
  test('one provider outage with a healthy fallback passes', () => assert.equal(evaluate({ geo: [out('a'), ok('b')] }).failed, false));
  test('every provider in a group down fails', () => assert.equal(evaluate({ geo: [out('a'), out('b')], dns: [ok('c')] }).failed, true));
  test('a format change fails even when others are healthy', () => assert.equal(evaluate({ geo: [fmt('a'), ok('b')] }).failed, true));
  test('summary distinguishes outage from format change', () => {
    const text = formatSummary(evaluate({ geo: [out('a'), fmt('b'), ok('c')] }));
    assert.match(text, /OUTAGE\s+geo\s+a — HTTP 503 \(after 3 attempts\)/);
    assert.match(text, /FORMAT\s+geo\s+b — changed/);
    assert.match(text, /RESULT: FAILED/);
  });
});
