import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';

import { createFakeDocument, walk } from './fixtures/dom-shim.js';
import { buildReport, reportToMarkdown, reportToText, reportToJSON, escapeMarkdown } from '../js/report.js';

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

// ---- Markdown export: untrusted values must stay data ----

describe('Markdown export escaping', () => {
  const HOSTILE = [
    'evil | injected | cells |',
    'row\n| fake | row |\n|---|---|',
    '# Heading\n## Another',
    '<script>alert(1)</script><img src=x onerror=alert(1)>',
    '[click me](https://evil.example/phish)',
    '![tracker](https://evil.example/pixel.png)',
    'https://evil.example/ www.evil.example',
    '- list item\n+ plus\n1. ordered\n> quote\n---\n===',
    '```\nfenced\n```',
    'back\\slash \\| already-escaped \\\\',
    '**bold** _it_ ~~del~~ `code` ***nested _mix_ ***',
    '@octocat #123',
  ];

  const build = (payload, remark = [payload]) => buildReport({
    input: '1.2.3.4', queryType: 'ipv4', hostname: null, forwardAddresses: [],
    ip: '1.2.3.4', version: 4,
    rdap: {
      network: { name: payload, handle: payload, type: payload, start_address: '1.2.3.0', end_address: '1.2.3.255', cidrs: ['1.2.3.0/24'], parent_handle: payload, status: [payload] },
      rir: { name: payload, region: 'x', website: null, rdap_url: 'https://rdap.example/ip/1.2.3.4', color: '#000' },
      registration: { registered_at: '2020-01-01T00:00:00Z', last_changed_at: null, events: [] },
      registrant: { name: payload, country_code: 'US' },
      contacts: {
        abuse: [{ name: payload, organization: payload, email: payload, phone: payload }],
        technical: [{ name: payload, organization: null, email: null, phone: null }],
        administrative: [], registrant: [],
      },
      remarks: [{ title: payload, description: remark }],
    },
    location: { country: payload, country_code: 'FI', region: payload, city: payload, postal_code: payload, timezone: payload, latitude: 1, longitude: 2, source: payload, precision: 'approximate' },
    asn: { number: 1, display: 'AS1', name: null, organization: payload, country_code: null, prefix: null, source: payload },
    reverse: { hostname: payload, status: 'ok' },
    warnings: [{ component: 'rdap', message: payload }],
  });

  const baseline = reportToMarkdown(build('benign'));
  const baselineLines = new Set(baseline.split('\n'));
  const lines = (md) => md.split('\n');
  const startingWith = (md, ch) => lines(md).filter((l) => l.startsWith(ch));
  const ROW = /^\| [^|\\]+ \| ((?:[^|\\]|\\[\s\S])*) \|$/;

  // Peels the trusted structural wrapper off a payload-bearing line and
  // returns the untrusted content, or null if the line has no valid shape.
  function content(line) {
    let m = line.match(ROW);
    if (m) return m[1];
    m = line.match(/^(?:- |> |⚠ \w+: )([\s\S]*)$/) || line.match(/^\*\*([\s\S]*)\*\*$/);
    return m ? m[1] : null;
  }

  for (const payload of HOSTILE) {
    const label = JSON.stringify(payload).slice(0, 48);
    const md = reportToMarkdown(build(payload, [payload.replace(/\n/g, ' ')]));
    const carrying = lines(md).filter((l) => l !== '' && !baselineLines.has(l));

    test(`document structure is unchanged by ${label}`, () => {
      assert.deepEqual(startingWith(md, '#'), startingWith(baseline, '#'), 'headings unchanged');
      assert.equal(startingWith(md, '|').length, startingWith(baseline, '|').length, 'table rows unchanged');
      assert.equal(lines(md).length, lines(baseline).length, 'no lines added or removed');
      for (const l of carrying) assert.notEqual(content(l), null, `payload line has an unexpected shape: ${l}`);
    });

    test(`payload stays inert text: no HTML, link, image, block or emphasis from ${label}`, () => {
      for (const l of carrying) {
        const c = content(l);
        assert.doesNotMatch(c, /^(?:[#>`~=+-]|\d+[.)](?:\s|$)|!?\[)/, `block/link start must be escaped: ${l}`);
        const inert = c.replace(/\\[\s\S]/g, ''); // drop backslash-escaped pairs
        assert.doesNotMatch(inert, /[<>`[\]*_~@|&]/, `unescaped special in: ${l}`);
        assert.doesNotMatch(inert, /:\/\/|www\./i, `autolinkable text in: ${l}`);
      }
    });
  }

  test('multi-line remarks stay inside the blockquote, one quoted line each', () => {
    const md = reportToMarkdown(build('x', ['first\n# not a heading\n- not a list', 'second\r\n===']));
    const rem = lines(md).slice(lines(md).indexOf('## Remarks'));
    const quoted = rem.filter((l) => l.startsWith('> '));
    assert.deepEqual(quoted, ['> first', '> \\# not a heading', '> \\- not a list', '> second', '> \\===']);
    assert.equal(startingWith(md, '#').filter((l) => /not a heading/.test(l)).length, 0);
  });

  test('pipes, backslashes and newlines are escaped inside a table cell exactly once', () => {
    assert.equal(escapeMarkdown('a|b'), 'a\\|b');
    assert.equal(escapeMarkdown('a\\b'), 'a\\\\b');
    assert.equal(escapeMarkdown('a\\|b'), 'a\\\\\\|b');
    assert.equal(escapeMarkdown('a\nb\r\nc'), 'a b c');
    const md = reportToMarkdown(build('x|y\\z\nw'));
    assert.match(md, /\| Name \| x\\\|y\\\\z w \|/);
  });

  test('trusted values are not mangled: IPs, timestamps, CIDRs, ASNs and hostnames', () => {
    for (const v of ['93.184.216.34', '2001:db8::1', '1.2.3.0/24', 'AS15133', '2026-10-23T00:00:00.000Z', 'example.com', 'ARIN-NET-1', 'Edgecast Inc.']) {
      assert.equal(escapeMarkdown(v), v);
    }
    assert.match(baseline, /\| IP address \| 1\.2\.3\.4 \|/);
    assert.match(baseline, /\| CIDR \| 1\.2\.3\.0\/24 \|/);
    assert.match(baseline, /\[Open in OpenStreetMap\]\(https:\/\/www\.openstreetmap\.org\//);
  });

  test('JSON and plain-text exports carry the raw value unchanged', () => {
    const payload = 'a | b\n# h <b>x</b> [l](u)';
    const r = build(payload);
    assert.equal(JSON.parse(reportToJSON(r)).network.name, payload);
    assert.match(reportToText(r), /Network\s+a \| b\n# h <b>x<\/b> \[l\]\(u\)/);
    assert.doesNotMatch(reportToText(r), /\\\|/);
  });
});
