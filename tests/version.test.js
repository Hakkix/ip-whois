// The footer version is written by hand in index.html (there is no build
// step), so this fails CI when it drifts from package.json.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const root = join(fileURLToPath(import.meta.url), '..', '..');

test('footer version in index.html matches package.json', () => {
  const { version } = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  const html = readFileSync(join(root, 'index.html'), 'utf8');
  const shown = html.match(/<a id="footer-version"[^>]*>v([^<]+)<\/a>/)?.[1];
  assert.equal(shown, version);
});
