import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';

import { createFakeDocument, walk } from './fixtures/dom-shim.js';
import { buildReport } from '../js/report.js';

let renderReport;
let renderError;

before(async () => {
  globalThis.document = createFakeDocument();
  // window stays undefined in this Node environment, so render.js's map
  // integration takes its "no Leaflet available" branch and skips cleanly.
  ({ renderReport, renderError } = await import('../js/render.js'));
});

const XSS_PAYLOADS = [
  '<script>alert(1)</script>',
  '<img src=x onerror=alert(1)>',
  '<a href="javascript:alert(1)">x</a>',
];

function maliciousReport(payload) {
  const rdap = {
    network: {
      name: payload, handle: 'NET-1', type: 'DIRECT ALLOCATION',
      start_address: '1.2.3.0', end_address: '1.2.3.255', cidrs: ['1.2.3.0/24'],
      parent_handle: null, status: ['active'],
    },
    rir: { name: 'ARIN', region: 'North America', website: 'https://www.arin.net', rdap_url: 'javascript:alert(1)', color: '#4a9fff' },
    registration: { registered_at: '2020-01-01T00:00:00Z', last_changed_at: null, events: [] },
    registrant: { name: payload, country_code: 'US' },
    contacts: {
      abuse: [{ name: payload, organization: payload, email: 'abuse@example.net', phone: null }],
      technical: [], administrative: [], registrant: [],
    },
    remarks: [{ title: payload, description: [payload] }],
  };
  return buildReport({
    input: '1.2.3.4', queryType: 'ipv4', hostname: null, forwardAddresses: [],
    ip: '1.2.3.4', version: 4, rdap,
    location: {
      country: payload, country_code: 'US', region: payload, city: payload,
      postal_code: null, timezone: null, latitude: 10, longitude: 20, source: 'ipwho.is', precision: 'approximate',
    },
    asn: { number: 1, display: 'AS1', name: null, organization: payload, country_code: null, prefix: null },
    reverse: { hostname: payload },
    warnings: [],
  });
}

describe('XSS resistance of rendered reports', () => {
  for (const payload of XSS_PAYLOADS) {
    test(`payload is rendered as literal text, never as markup: ${payload}`, () => {
      const container = document.createElement('div');
      renderReport(container, maliciousReport(payload));

      const nodes = walk(container);

      // The payload must never have been used to construct new elements
      // (no <img>, <script>, or attacker-controlled <a> should exist).
      const forbiddenTags = nodes.filter((n) => n.tagName === 'IMG' || n.tagName === 'SCRIPT');
      assert.equal(forbiddenTags.length, 0, 'no IMG/SCRIPT element was created from external data');

      // No attribute anywhere should carry the raw payload as markup —
      // if it appears at all, it must be inert (never as an href/src).
      for (const n of nodes) {
        if (n.attributes) {
          for (const [attr, value] of Object.entries(n.attributes)) {
            if (attr === 'href' || attr === 'src') {
              assert.doesNotMatch(String(value), /^javascript:/i, `${attr} must never use the javascript: scheme`);
            }
          }
        }
      }

      // The payload text must still be present somewhere, verbatim, as
      // literal text content — proving it was preserved, not stripped,
      // just neutralized.
      const allText = nodes.map((n) => n._text || '').join('\n');
      assert.match(allText, /alert\(1\)/, 'the payload text survives as inert text content');
    });
  }

  test('a javascript: RDAP source URL is never rendered as a clickable link', () => {
    const container = document.createElement('div');
    renderReport(container, maliciousReport('<img src=x onerror=alert(1)>'));
    const nodes = walk(container);
    const anchors = nodes.filter((n) => n.tagName === 'A');
    for (const a of anchors) {
      const href = a.getAttribute('href');
      assert.ok(!href || /^https?:/i.test(href), `anchor href "${href}" must use http(s)`);
    }
  });

  test('renderError treats the query string as text, not markup', () => {
    const container = document.createElement('div');
    renderError(container, 'Lookup failed', '<img src=x onerror=alert(1)>');
    const nodes = walk(container);
    assert.equal(nodes.filter((n) => n.tagName === 'IMG').length, 0);
    const allText = nodes.map((n) => n._text || n.textContent || '').join('\n');
    assert.match(allText, /<img src=x onerror=alert\(1\)>/);
  });

  test('a safe https RDAP source URL is rendered as a real link', () => {
    const container = document.createElement('div');
    const report = maliciousReport('normal org name');
    report.sources.rdap.url = 'https://rdap.arin.net/registry/ip/1.2.3.4';
    renderReport(container, report);
    const nodes = walk(container);
    const anchors = nodes.filter((n) => n.tagName === 'A');
    assert.ok(anchors.some((a) => a.getAttribute('href') === 'https://rdap.arin.net/registry/ip/1.2.3.4'));
  });
});
