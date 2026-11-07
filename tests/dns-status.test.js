// DNS outcome modelling: resolver results must flow into the report and the
// source indicators without a hardcoded "success".
import { test, describe, beforeEach, afterEach, before } from 'node:test';
import assert from 'node:assert/strict';

import { resolveHostname, reversePTR } from '../js/dns.js';
import { buildReport, reportToMarkdown, reportToText } from '../js/report.js';
import { dnsSourceOk } from '../js/utils.js';
import { createFakeDocument, walk } from './fixtures/dom-shim.js';

const okJson = (data) => ({ ok: true, status: 200, json: async () => data });
let originalFetch;
beforeEach(() => { originalFetch = globalThis.fetch; });
afterEach(() => { globalThis.fetch = originalFetch; });
const mockAll = (respond) => { globalThis.fetch = async (url) => respond(url); };

describe('reversePTR status', () => {
  test('record present -> ok', async () => {
    mockAll(() => okJson({ Status: 0, Answer: [{ type: 12, data: 'dns.google.' }] }));
    assert.equal((await reversePTR('8.8.8.8', 4)).status, 'ok');
  });
  test('NXDOMAIN -> no_record, not error', async () => {
    mockAll(() => okJson({ Status: 3 }));
    assert.equal((await reversePTR('203.0.113.5', 4)).status, 'no_record');
  });
  test('NOERROR with empty answer -> no_record', async () => {
    mockAll(() => okJson({ Status: 0, Answer: [] }));
    assert.equal((await reversePTR('203.0.113.5', 4)).status, 'no_record');
  });
  test('network failure -> error', async () => {
    mockAll(() => { throw new Error('down'); });
    assert.equal((await reversePTR('8.8.8.8', 4)).status, 'error');
  });
  test('SERVFAIL on every provider -> error', async () => {
    mockAll(() => okJson({ Status: 2 }));
    assert.equal((await reversePTR('8.8.8.8', 4)).status, 'error');
  });
  test('HTTP error and invalid JSON -> error', async () => {
    mockAll(() => ({ ok: false, status: 502, json: async () => ({}) }));
    assert.equal((await reversePTR('8.8.8.8', 4)).status, 'error');
    mockAll(() => ({ ok: true, status: 200, json: async () => { throw new SyntaxError('bad json'); } }));
    assert.equal((await reversePTR('8.8.8.8', 4)).status, 'error');
  });
  test('a malformed answer record does not throw', async () => {
    mockAll(() => okJson({ Status: 0, Answer: [{ type: 12, data: 42 }, null] }));
    assert.equal((await reversePTR('8.8.8.8', 4)).status, 'no_record');
  });
});

describe('resolveHostname status', () => {
  const byType = (a, aaaa) => (url) => (/type=AAAA/.test(url) ? aaaa(url) : a(url));
  test('addresses -> ok', async () => {
    mockAll(byType(() => okJson({ Status: 0, Answer: [{ type: 1, data: '93.184.216.34' }] }), () => okJson({ Status: 0 })));
    const r = await resolveHostname('example.com');
    assert.equal(r.status, 'ok');
    assert.deepEqual(r.addresses, ['93.184.216.34']);
  });
  test('NXDOMAIN -> no_record', async () => {
    mockAll(() => okJson({ Status: 3 }));
    assert.equal((await resolveHostname('nope.example')).status, 'no_record');
  });
  test('total failure -> error', async () => {
    mockAll(() => { throw new Error('down'); });
    const r = await resolveHostname('example.com');
    assert.equal(r.status, 'error');
    assert.equal(r.source, null);
  });
  test('one family fails and the other is empty -> error, not "no record"', async () => {
    mockAll(byType(() => { throw new Error('down'); }, () => okJson({ Status: 0, Answer: [] })));
    assert.equal((await resolveHostname('example.com')).status, 'error');
  });
  test('one family fails but the other has addresses -> ok', async () => {
    mockAll(byType(() => { throw new Error('down'); }, () => okJson({ Status: 0, Answer: [{ type: 28, data: '2606:4700::1111' }] })));
    assert.equal((await resolveHostname('example.com')).status, 'ok');
  });
});

describe('report model and exports', () => {
  const base = { input: '8.8.8.8', queryType: 'ipv4', hostname: null, forwardAddresses: [], ip: '8.8.8.8', version: 4 };
  test('statuses propagate to dns.forward / dns.reverse', () => {
    const r = buildReport({ ...base, input: 'a.example', queryType: 'hostname', hostname: 'a.example', forwardAddresses: ['8.8.8.8'], forwardStatus: 'ok', reverse: { hostname: null, status: 'no_record' } });
    assert.equal(r.dns.forward.status, 'ok');
    assert.equal(r.dns.reverse.status, 'no_record');
  });
  test('forward lookup is not_applicable for IP queries', () => {
    assert.equal(buildReport({ ...base, reverse: { hostname: null, status: 'ok' } }).dns.forward.status, 'not_applicable');
  });
  test('a missing result is never reported as success', () => {
    assert.equal(buildReport({ ...base, reverse: null }).dns.reverse.status, 'not_applicable');
    assert.equal(buildReport({ ...base, reverse: { hostname: null } }).dns.reverse.status, 'not_applicable');
  });
  test('Markdown and text exports name the lookup outcome', () => {
    const failed = buildReport({ ...base, reverse: { hostname: null, status: 'error' } });
    assert.match(reportToMarkdown(failed), /Reverse lookup \| Lookup failed/);
    assert.match(reportToText(failed), /Reverse lookup\s+Lookup failed/);
    const none = buildReport({ ...base, reverse: { hostname: null, status: 'no_record' } });
    assert.match(reportToMarkdown(none), /Reverse lookup \| No record/);
  });
  test('dnsSourceOk: failure is never ok; no-record is ok; nothing attempted is not ok', () => {
    const d = (forward, reverse) => ({ forward: { status: forward }, reverse: { status: reverse } });
    assert.equal(dnsSourceOk(d('not_applicable', 'ok')), true);
    assert.equal(dnsSourceOk(d('not_applicable', 'no_record')), true);
    assert.equal(dnsSourceOk(d('ok', 'error')), false);
    assert.equal(dnsSourceOk(d('error', 'ok')), false);
    assert.equal(dnsSourceOk(d('not_applicable', 'not_applicable')), false);
  });
});

describe('rendered source indicator', () => {
  let renderReport;
  before(async () => {
    globalThis.document = createFakeDocument();
    ({ renderReport } = await import('../js/render.js'));
  });
  const dnsItem = (reverse) => {
    const container = document.createElement('div');
    renderReport(container, buildReport({ input: '8.8.8.8', queryType: 'ipv4', hostname: null, forwardAddresses: [], ip: '8.8.8.8', version: 4, reverse }));
    return walk(container).find((n) => /source-item/.test(n.className) && n.textContent.startsWith('DNS'));
  };
  test('DNS failure renders as missing, never ok', () => {
    assert.match(dnsItem({ hostname: null, status: 'error' }).className, /is-missing/);
  });
  test('a clean "no PTR" renders as ok', () => {
    assert.match(dnsItem({ hostname: null, status: 'no_record' }).className, /is-ok/);
  });
  test('a resolved PTR renders as ok', () => {
    assert.match(dnsItem({ hostname: 'dns.google', status: 'ok' }).className, /is-ok/);
  });
});
