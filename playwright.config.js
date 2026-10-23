import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: 'e2e',
  testMatch: '*.spec.js',
  fullyParallel: true,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: 'http://localhost:4173',
    permissions: ['clipboard-read', 'clipboard-write'],
  },
  webServer: { command: 'node e2e/serve.mjs', url: 'http://localhost:4173', reuseExistingServer: !process.env.CI },
});
