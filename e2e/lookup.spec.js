import { test, expect } from '@playwright/test';
import { installMocks, watchErrors } from './mocks.js';

const lookup = async (page, query) => {
  await page.locator('#ip-input').fill(query);
  await page.locator('#lookup-form button[type=submit]').click();
};

test.describe('landing page', () => {
  test('detects and shows the visitor IP with no CSP violations', async ({ page }) => {
    const errors = watchErrors(page);
    await installMocks(page);
    await page.goto('/');
    await expect(page.locator('.self-ip-address')).toHaveText('93.184.216.34');
    await expect(page.locator('#landing-view')).toBeVisible();
    expect(errors).toEqual([]);
  });
});

test.describe('IP lookup', () => {
  test('renders the full report for a public IPv4 address', async ({ page }) => {
    const errors = watchErrors(page);
    await installMocks(page);
    await page.goto('/');
    await lookup(page, '8.8.8.8');
    await expect(page.locator('#section-summary .summary-ip')).toContainText('8.8.8.8');
    for (const id of ['network', 'asn', 'geo', 'dns', 'sources']) await expect(page.locator(`#section-${id}`)).toBeVisible();
    await expect(page.locator('#section-summary .summary-ptr')).toContainText('dns.example.net');
    await expect(page.locator('.warnings-banner')).toHaveCount(0);
    expect(new URL(page.url()).searchParams.has('q')).toBe(false);
    expect(errors).toEqual([]);
  });

  test('a deep link with ?q= starts the lookup on load', async ({ page }) => {
    await installMocks(page);
    await page.goto('/?q=8.8.8.8');
    await expect(page.locator('#section-summary .summary-ip')).toContainText('8.8.8.8');
  });

  test('rejects invalid input without any network request', async ({ page }) => {
    const { requests } = await installMocks(page);
    await page.goto('/');
    await expect(page.locator('.self-ip-address')).toHaveText('93.184.216.34');
    const before = requests.length;
    await lookup(page, 'not an address!');
    await expect(page.locator('#validation-message')).toContainText('valid IPv4 address');
    expect(requests.length).toBe(before);
  });

  test('refuses a private address without querying providers', async ({ page }) => {
    const { requests } = await installMocks(page);
    await page.goto('/');
    await expect(page.locator('.self-ip-address')).toHaveText('93.184.216.34');
    const before = requests.length;
    await lookup(page, '10.0.0.1');
    await expect(page.locator('#validation-message')).toContainText('reserved/private');
    expect(requests.length).toBe(before);
  });
});

test.describe('partial failures', () => {
  test('RDAP down: the rest of the report still renders and the gap is shown', async ({ page }) => {
    const { json } = await installMocks(page, { rdap: () => ({ status: 500, body: '' }) });
    await page.goto('/');
    await lookup(page, '8.8.8.8');
    await expect(page.locator('#section-summary')).toBeVisible();
    await expect(page.locator('.warnings-banner')).toContainText('RDAP');
    await expect(page.locator('.source-item.is-missing', { hasText: 'RDAP' })).toBeVisible();
    await expect(page.locator('#section-geo')).toBeVisible();
  });

  test('first GeoIP provider down: the fallback answers and is named in Data sources', async ({ page }) => {
    await installMocks(page, { ipinfo: () => ({ status: 503, body: '' }) });
    await page.goto('/?q=8.8.8.8');
    await expect(page.locator('#section-sources')).toContainText('ipwho.is');
  });

  test('every GeoIP provider down: report renders with a warning, not an error page', async ({ page }) => {
    const down = () => ({ status: 503, body: '' });
    await installMocks(page, { ipinfo: down, ipwhois: down, ipapi: down });
    await page.goto('/?q=8.8.8.8');
    await expect(page.locator('#section-summary')).toBeVisible();
    await expect(page.locator('.warnings-banner')).toContainText('Geolocation');
    await expect(page.locator('.source-item.is-missing', { hasText: 'GeoIP' })).toBeVisible();
  });
});

test.describe('DNS source status', () => {
  const dohDown = () => ({ status: 503, body: '' });

  test('DNS down: the report marks DNS unavailable instead of OK', async ({ page }) => {
    await installMocks(page, { doh: dohDown });
    await page.goto('/');
    await lookup(page, '8.8.8.8');
    await expect(page.locator('#section-summary')).toBeVisible();
    await expect(page.locator('.source-item.is-missing', { hasText: 'DNS' })).toBeVisible();
    await expect(page.locator('.warnings-banner')).toContainText('Reverse DNS');
  });

  test('a clean NXDOMAIN for the PTR is not a DNS failure', async ({ page }) => {
    await installMocks(page, { doh: () => ({ status: 200, contentType: 'application/json', body: JSON.stringify({ Status: 3, Question: [{ type: 12 }] }) }) });
    await page.goto('/');
    await lookup(page, '8.8.8.8');
    await expect(page.locator('#section-summary')).toBeVisible();
    await expect(page.locator('.source-item.is-ok', { hasText: 'DNS' })).toBeVisible();
    await expect(page.locator('.warnings-banner')).toHaveCount(0);
  });

  test('landing page: DNS dot turns unavailable when the PTR lookup fails', async ({ page }) => {
    await installMocks(page, { doh: dohDown });
    await page.goto('/');
    await expect(page.locator('.self-ip-address')).toHaveText('93.184.216.34');
    await expect(page.locator('#source-status-strip .status-item', { hasText: 'DNS' }).locator('.status-dot--unavailable')).toBeVisible();
    await expect(page.locator('[data-tile=ptr]')).toContainText('unavailable');
  });

  test('landing page: DNS dot is available when the PTR lookup succeeds', async ({ page }) => {
    await installMocks(page);
    await page.goto('/');
    await expect(page.locator('#source-status-strip .status-item', { hasText: 'DNS' }).locator('.status-dot--available')).toBeVisible();
  });
});

test.describe('hostname lookup', () => {
  const twoAddresses = (url) => {
    const type = new URL(url).searchParams.get('type');
    const answer = type === 'A' ? [{ type: 1, data: '93.184.216.34' }, { type: 1, data: '93.184.216.35' }] : [];
    return { status: 200, contentType: 'application/json', body: JSON.stringify({ Status: 0, Question: [{ type: type === 'A' ? 1 : 28 }], Answer: answer }) };
  };

  test('a hostname with several addresses offers a chooser, then investigates the pick', async ({ page }) => {
    await installMocks(page, { doh: twoAddresses });
    await page.goto('/');
    await lookup(page, 'example.com');
    await expect(page.locator('#chooser-view')).toBeVisible();
    await page.locator('.chooser-item', { hasText: '93.184.216.35' }).click();
    await expect(page.locator('#section-summary .summary-ip')).toContainText('example.com → 93.184.216.35');
  });
});

test.describe('export and dialogs', () => {
  test('Copy JSON puts a parseable schema-versioned report on the clipboard', async ({ page }) => {
    await installMocks(page);
    await page.goto('/?q=8.8.8.8');
    await expect(page.locator('#section-summary')).toBeVisible();
    await page.locator('#export-btn').click();
    await page.locator('[data-export=json]').click();
    const copied = JSON.parse(await page.evaluate(() => navigator.clipboard.readText()));
    expect(copied.schema_version).toMatch(/^2\./);
    expect(copied.ip.address).toBe('8.8.8.8');
  });

  test('About dialog opens from the footer link, closes on Escape and returns focus', async ({ page }) => {
    await installMocks(page);
    await page.goto('/');
    await page.locator('#about-btn').click();
    await expect(page.locator('#about-modal')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.locator('#about-modal')).toBeHidden();
    await expect(page.locator('#about-btn')).toBeFocused();
  });
});

test.describe('privacy: searches stay out of the URL by default', () => {
  test('a fresh user searching does not generate ?q=', async ({ page }) => {
    await installMocks(page);
    await page.goto('/');
    await expect(page.locator('#share-url')).not.toBeChecked();
    await lookup(page, '8.8.8.8');
    await expect(page.locator('#section-summary .summary-ip')).toContainText('8.8.8.8');
    expect(new URL(page.url()).search).toBe('');
  });

  test('an explicit ?q= link still runs, then is removed from the address bar', async ({ page }) => {
    await installMocks(page);
    await page.goto('/?q=8.8.8.8');
    await expect(page.locator('#section-summary .summary-ip')).toContainText('8.8.8.8');
    expect(new URL(page.url()).search).toBe('');
  });

  test('a new search from a shared link does not leave the old ?q= behind', async ({ page }) => {
    await installMocks(page);
    await page.goto('/?q=8.8.8.8');
    await expect(page.locator('#section-summary .summary-ip')).toContainText('8.8.8.8');
    await page.evaluate(() => history.replaceState({}, '', '/?q=8.8.8.8'));
    await lookup(page, '1.1.1.1');
    await expect(page.locator('#section-summary .summary-ip')).toContainText('1.1.1.1');
    expect(new URL(page.url()).search).toBe('');
  });

  test('opting in writes ?q=, keeps a shared link, and persists across reloads', async ({ page }) => {
    await installMocks(page);
    await page.goto('/');
    await page.locator('#share-url').check();
    await lookup(page, '8.8.8.8');
    await expect(page).toHaveURL(/[?&]q=8\.8\.8\.8/);
    await page.reload();
    await expect(page.locator('#section-summary .summary-ip')).toContainText('8.8.8.8');
    await expect(page.locator('#share-url')).toBeChecked();
    await expect(page).toHaveURL(/[?&]q=8\.8\.8\.8/);
  });

  test('unticking the option removes ?q= from the current URL', async ({ page }) => {
    await installMocks(page);
    await page.goto('/');
    await page.locator('#share-url').check();
    await lookup(page, '8.8.8.8');
    await expect(page).toHaveURL(/[?&]q=/);
    await page.locator('#share-url').uncheck();
    expect(new URL(page.url()).search).toBe('');
  });

  test('blocked localStorage does not break searching or the toggle', async ({ page }) => {
    const errors = watchErrors(page);
    await page.addInitScript(() => {
      Object.defineProperty(window, 'localStorage', { get() { throw new DOMException('denied', 'SecurityError'); } });
    });
    await installMocks(page);
    await page.goto('/');
    await lookup(page, '8.8.8.8');
    await expect(page.locator('#section-summary .summary-ip')).toContainText('8.8.8.8');
    expect(new URL(page.url()).search).toBe('');
    await page.locator('#share-url').check();
    await lookup(page, '1.1.1.1');
    await expect(page).toHaveURL(/[?&]q=1\.1\.1\.1/);
    expect(errors).toEqual([]);
  });
});
