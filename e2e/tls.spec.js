import { test, expect } from '@playwright/test';
import { installMocks, watchErrors, dohFor, tlsOk } from './mocks.js';

const doh = dohFor({ 'example.com': ['93.184.216.34'], 'other.org': ['8.8.4.4'] });
const lookup = async (page, query) => {
  await page.locator('#ip-input').fill(query);
  await page.locator('#lookup-form button[type=submit]').click();
};
const tlsCalls = (requests) => requests.filter((u) => u.includes('/api/tls'));
const gate = () => { let release; const p = new Promise((r) => { release = r; }); return { p, release }; };

test.describe('TLS certificate section', () => {
  test('hostname lookup shows the certificate with the selected IP and SNI hostname, no CSP violations', async ({ page }) => {
    const errors = watchErrors(page);
    const { requests } = await installMocks(page, { doh });
    await page.goto('/');
    await lookup(page, 'example.com');
    const card = page.locator('#section-tls');
    await expect(card).toContainText('Valid');
    await expect(card).toContainText('CN=example.com');
    await expect(card).toContainText('Example Issuing CA 1');
    await expect(card).toContainText('www.example.com');
    await expect(card).toContainText('69');
    await expect(card).toContainText('TLSv1.3');
    await expect(card).toContainText('TLS_AES_256_GCM_SHA384');
    await expect(card).toContainText('93.184.216.34:443');
    await expect(card.locator('.tls-valid')).toBeVisible();
    expect(tlsCalls(requests)).toHaveLength(1);
    expect(tlsCalls(requests)[0]).toContain('{"hostname":"example.com","ip":"93.184.216.34"}');
    expect(errors).toEqual([]);
  });

  test('fingerprint copy button copies the SHA-256 value', async ({ page }) => {
    await installMocks(page, { doh });
    await page.goto('/?q=example.com');
    const copy = page.locator('#section-tls button[aria-label="Copy SHA-256 fingerprint"]');
    await copy.focus();
    await page.keyboard.press('Enter');
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(tlsOk().certificate.fingerprint_sha256);
  });

  test('chain is a keyboard-operable disclosure and does not call the root "presented"', async ({ page }) => {
    await installMocks(page, { doh });
    await page.goto('/?q=example.com');
    const summary = page.locator('#tls-chain > summary');
    await summary.focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('#tls-chain')).toHaveAttribute('open', '');
    await expect(page.locator('#tls-chain')).toContainText('Intermediate');
    await expect(page.locator('#tls-chain')).toContainText('not confirmed as sent by the server');
  });

  test('TLS does not block RDAP/GeoIP: report renders while TLS is pending, then updates in place', async ({ page }) => {
    const g = gate();
    await installMocks(page, { doh, tls: async () => { await g.p; return { status: 200, contentType: 'application/json', body: JSON.stringify(tlsOk()) }; } });
    await page.goto('/');
    await lookup(page, 'example.com');
    for (const id of ['network', 'asn', 'geo', 'dns', 'sources']) await expect(page.locator(`#section-${id}`)).toBeVisible();
    await expect(page.locator('#section-tls')).toContainText('Inspection in progress');
    await expect(page.locator('#section-tls')).toHaveAttribute('aria-busy', 'true');

    // Expand a panel and mark a DOM node: neither may be reset by the late TLS update.
    const details = page.locator('.result-secondary details').first();
    if (await details.count()) await details.locator('summary').click();
    await page.evaluate(() => { document.querySelector('#section-geo').dataset.marker = 'kept'; });

    // Export while pending reflects the partial state honestly.
    await page.locator('#export-btn').click();
    await page.locator('[data-export=json]').click();
    expect(JSON.parse(await page.evaluate(() => navigator.clipboard.readText())).tls.status).toBe('pending');

    g.release();
    await expect(page.locator('#section-tls')).toContainText('CN=example.com');
    await expect(page.locator('#section-tls')).toHaveAttribute('aria-busy', 'false');
    await expect(page.locator('#section-geo')).toHaveAttribute('data-marker', 'kept');
    if (await details.count()) await expect(details).toHaveAttribute('open', '');
  });

  test('IP-only lookup never calls the TLS API and explains why', async ({ page }) => {
    const { requests } = await installMocks(page);
    await page.goto('/');
    await lookup(page, '8.8.8.8');
    await expect(page.locator('#section-tls')).toContainText('SNI');
    await expect(page.locator('#section-tls .tls-status')).toHaveCount(0);
    await page.waitForTimeout(300);
    expect(tlsCalls(requests)).toHaveLength(0);
    await page.locator('#export-btn').click();
    await page.locator('[data-export=json]').click();
    expect(JSON.parse(await page.evaluate(() => navigator.clipboard.readText())).tls).toBeNull();
  });

  test('a stale TLS response from a previous search never overwrites the newer report', async ({ page }) => {
    const g = gate();
    await installMocks(page, {
      doh,
      tls: async (body) => {
        if (body.hostname === 'example.com') {
          await g.p;
          return { status: 200, contentType: 'application/json', body: JSON.stringify(tlsOk({ certificate: { ...tlsOk().certificate, subject: 'CN=stale.invalid-marker' } })) };
        }
        return { status: 200, contentType: 'application/json', body: JSON.stringify(tlsOk({ hostname: 'other.org', connected_ip: '8.8.4.4', certificate: { ...tlsOk().certificate, subject: 'CN=other.org' } })) };
      },
    });
    await page.goto('/');
    await lookup(page, 'example.com');
    await expect(page.locator('#section-tls')).toContainText('Inspection in progress');
    await lookup(page, 'other.org');
    await expect(page.locator('#section-tls')).toContainText('CN=other.org');
    g.release();
    await page.waitForTimeout(300);
    await expect(page.locator('#section-tls')).toContainText('CN=other.org');
    await expect(page.locator('#section-tls')).not.toContainText('stale.invalid-marker');
    await expect(page.locator('#section-summary .summary-ip')).toContainText('other.org');
    await page.locator('#export-btn').click();
    await page.locator('[data-export=json]').click();
    const exported = JSON.parse(await page.evaluate(() => navigator.clipboard.readText()));
    expect(exported.tls.hostname).toBe('other.org');
  });

  test('a stale response is also ignored when navigating back to the landing page', async ({ page }) => {
    const g = gate();
    await installMocks(page, { doh, tls: async () => { await g.p; return { status: 200, contentType: 'application/json', body: JSON.stringify(tlsOk()) }; } });
    await page.goto('/');
    await lookup(page, 'example.com');
    await expect(page.locator('#section-tls')).toContainText('Inspection in progress');
    await page.locator('#brand-home').click();
    g.release();
    await page.waitForTimeout(200);
    await expect(page.locator('#landing-view')).toBeVisible();
    await expect(page.locator('#section-tls')).not.toContainText('CN=example.com');
    await expect(page.locator('#section-tls')).toContainText('Inspection in progress');
  });

  test('an invalid certificate is shown as a problem, never as valid', async ({ page }) => {
    await installMocks(page, {
      doh,
      tls: () => ({ status: 200, contentType: 'application/json', body: JSON.stringify(tlsOk({
        status: 'invalid', error_code: 'hostname_mismatch', error_message: 'The certificate is not valid for this hostname.',
        connection: { ...tlsOk().connection, hostname_match: false },
        validation: { overall: 'invalid', problems: ['hostname_mismatch'] },
      })) }),
    });
    await page.goto('/?q=example.com');
    const card = page.locator('#section-tls');
    await expect(card.locator('.tls-invalid')).toBeVisible();
    await expect(card).toContainText('Invalid');
    await expect(card).toContainText('not valid for this hostname');
    await expect(card).toContainText('Does not match certificate names');
    await expect(card.locator('.tls-valid')).toHaveCount(0);
  });

  test('an untrusted server response claiming "ok" is not shown as valid', async ({ page }) => {
    await installMocks(page, {
      doh,
      tls: () => ({ status: 200, contentType: 'application/json', body: JSON.stringify(tlsOk({ connection: { ...tlsOk().connection, trust_status: 'self_signed' } })) }),
    });
    await page.goto('/?q=example.com');
    await expect(page.locator('#section-tls .tls-invalid')).toBeVisible();
    await expect(page.locator('#section-tls .tls-valid')).toHaveCount(0);
  });

  test('expiring soon is flagged as a warning but still valid', async ({ page }) => {
    await installMocks(page, {
      doh,
      tls: () => ({ status: 200, contentType: 'application/json', body: JSON.stringify(tlsOk({ certificate: { ...tlsOk().certificate, days_remaining: 12, expiring_soon: true } })) }),
    });
    await page.goto('/?q=example.com');
    const card = page.locator('#section-tls');
    await expect(card.locator('.tls-warning')).toContainText('Valid — expires in 12 days');
  });

  for (const [name, handler] of Object.entries({
    'structured unavailable': () => ({ status: 200, contentType: 'application/json', body: JSON.stringify({ status: 'unavailable', error_code: 'connection_timeout', error_message: 'The connection to port 443 timed out.' }) }),
    'HTTP 500 with HTML': () => ({ status: 500, contentType: 'text/html', body: '<h1>boom</h1>' }),
    'blocked': () => ({ status: 403, contentType: 'application/json', body: JSON.stringify({ status: 'blocked', error_code: 'destination_not_public', error_message: 'The hostname resolves to a non-public address, so no connection was made.' }) }),
    'endpoint missing (404)': () => ({ status: 404, body: 'not found' }),
  })) {
    test(`TLS failure (${name}) leaves the rest of the report usable`, async ({ page }) => {
      const errors = watchErrors(page);
      await installMocks(page, { doh, tls: handler });
      await page.goto('/?q=example.com');
      await expect(page.locator('#section-tls .tls-unavailable')).toBeVisible();
      for (const id of ['network', 'asn', 'geo', 'dns', 'sources']) await expect(page.locator(`#section-${id}`)).toBeVisible();
      await expect(page.locator('.warnings-banner')).toHaveCount(0);
      await page.locator('#export-btn').click();
      await page.locator('[data-export=markdown]').click();
      const md = await page.evaluate(() => navigator.clipboard.readText());
      expect(md).toContain('## TLS Certificate');
      expect(md).toContain('## Network');
      expect(errors).toEqual([]);
    });
  }

  test('JSON, Markdown and text exports include the TLS data', async ({ page }) => {
    await installMocks(page, { doh });
    await page.goto('/?q=example.com');
    await expect(page.locator('#section-tls')).toContainText('CN=example.com');
    const read = async (fmt) => {
      await page.locator('#export-btn').click();
      await page.locator(`[data-export=${fmt}]`).click();
      return page.evaluate(() => navigator.clipboard.readText());
    };
    const json = JSON.parse(await read('json'));
    expect(json.schema_version).toBe('2.2');
    expect(json.tls.status).toBe('ok');
    expect(json.tls.connected_ip).toBe('93.184.216.34');
    expect(json.tls.certificate.fingerprint_sha256).toBe(tlsOk().certificate.fingerprint_sha256);
    expect(json.sources.tls.retrieved_at).toBe('2026-10-23T08:00:00.000Z');
    const md = await read('markdown');
    const txt = await read('text');
    for (const out of [md, txt]) {
      for (const v of ['CN=example.com', 'Example Issuing CA 1', 'www.example.com', 'TLSv1.3', 'TLS_AES_256_GCM_SHA384', tlsOk().certificate.fingerprint_sha256, '93.184.216.34', 'Trusted chain', 'Matches certificate names']) {
        expect(out).toContain(v);
      }
    }
    expect(md).toContain('## TLS Certificate');
    expect(txt).toContain('TLS CERTIFICATE');
  });

  test('a multi-address hostname inspects only the address the user picked', async ({ page }) => {
    const { requests } = await installMocks(page, { doh: dohFor({ 'example.com': ['93.184.216.34', '93.184.216.35'] }) });
    await page.goto('/');
    await lookup(page, 'example.com');
    await expect(page.locator('#chooser-view')).toBeVisible();
    expect(tlsCalls(requests)).toHaveLength(0);
    await page.locator('.chooser-item', { hasText: '93.184.216.35' }).click();
    await expect(page.locator('#section-tls')).toContainText('Valid');
    expect(tlsCalls(requests)).toHaveLength(1);
    expect(tlsCalls(requests)[0]).toContain('93.184.216.35');
  });

  test('layout works on a narrow mobile viewport without horizontal scroll', async ({ page }) => {
    await page.setViewportSize({ width: 360, height: 740 });
    await installMocks(page, { doh });
    await page.goto('/?q=example.com');
    await expect(page.locator('#section-tls')).toContainText('CN=example.com');
    // The card itself must fit the viewport and not scroll internally.
    const fit = await page.evaluate(() => {
      const card = document.querySelector('#section-tls');
      const r = card.getBoundingClientRect();
      return { right: r.right, vw: document.documentElement.clientWidth, inner: card.scrollWidth - card.clientWidth };
    });
    expect(fit.right).toBeLessThanOrEqual(fit.vw);
    expect(fit.inner).toBeLessThanOrEqual(0);
  });
});
