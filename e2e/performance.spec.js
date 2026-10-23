import { test, expect } from '@playwright/test';
import { installMocks } from './mocks.js';

const delayed = (ms, handler) => async (url) => {
  await new Promise((r) => setTimeout(r, ms));
  return handler(url);
};

test.describe('response time', () => {
  test('RDAP, GeoIP and PTR run in parallel: total time tracks the slowest, not the sum', async ({ page }) => {
    const { defaults } = await import('./mocks.js');
    const ms = 600;
    await installMocks(page, {
      rdap: delayed(ms, defaults.rdap),
      ipinfo: delayed(ms, defaults.ipinfo),
      doh: delayed(ms, defaults.doh),
    });
    await page.goto('/');
    await page.locator('.self-ip-address').waitFor();
    await page.locator('#ip-input').fill('8.8.8.8');
    const start = Date.now();
    await page.locator('#lookup-form button[type=submit]').click();
    await expect(page.locator('#section-summary')).toBeVisible();
    const elapsed = Date.now() - start;
    // Sequential would take >= 3 * ms. Generous headroom for CI jitter.
    expect(elapsed).toBeLessThan(ms * 2.5);
  });

  test('with instant providers the report renders within 2 s', async ({ page }) => {
    await installMocks(page);
    await page.goto('/');
    await page.locator('.self-ip-address').waitFor();
    await page.locator('#ip-input').fill('8.8.8.8');
    const start = Date.now();
    await page.locator('#lookup-form button[type=submit]').click();
    await expect(page.locator('#section-summary')).toBeVisible();
    expect(Date.now() - start).toBeLessThan(2000);
  });
});
