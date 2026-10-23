import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createHandler } from '../api/tls.js';

const ENABLED = { TLS_INSPECTION_ENABLED: '1' };
const okResolver = (a = ['93.184.216.34'], aaaa = []) => ({ resolve4: async () => a, resolve6: async () => aaaa });
const okResult = (hostname, ip) => ({
  status: 'ok', hostname, connected_ip: ip, port: 443, observed_at: '2026-10-23T08:00:00.000Z',
  certificate: { subject: 'CN=x' }, connection: {}, chain: [], error_code: null,
});

function setup(over = {}) {
  const calls = [];
  const logs = [];
  const handler = createHandler({
    resolver: okResolver(), env: ENABLED, log: (l) => logs.push(l),
    inspect: async (t) => { calls.push(t); return okResult(t.hostname, t.ip); },
    ...over,
  });
  return { handler, calls, logs };
}
const post = (body, headers = {}, method = 'POST') => new Request('https://ip-whois.vercel.app/api/tls', {
  method, headers: { 'content-type': 'application/json', host: 'ip-whois.vercel.app', ...headers },
  body: method === 'GET' ? undefined : (typeof body === 'string' ? body : JSON.stringify(body)),
});
const json = async (res) => res.json();

describe('POST /api/tls', () => {
  test('happy path connects to the validated IP with the original hostname', async () => {
    const { handler, calls, logs } = setup();
    const res = await handler(post({ hostname: 'Example.com', ip: '93.184.216.34' }));
    const body = await json(res);
    assert.equal(res.status, 200);
    assert.equal(body.status, 'ok');
    assert.deepEqual(calls, [{ hostname: 'example.com', ip: '93.184.216.34' }]);
    assert.equal(res.headers.get('cache-control'), 'no-store');
    assert.equal(res.headers.get('access-control-allow-origin'), null);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.deepEqual(Object.keys(logs[0]).sort(), ['error_code', 'event', 'ms', 'status']);
  });

  test('is disabled (fail closed) unless the deployment attests its rate limit', async () => {
    const { handler, calls } = setup({ env: {} });
    const res = await handler(post({ hostname: 'example.com', ip: '93.184.216.34' }));
    assert.equal(res.status, 503);
    assert.equal((await json(res)).error_code, 'disabled');
    assert.equal(calls.length, 0);
    const res2 = await setup({ env: { TLS_INSPECTION_ENABLED: 'true' } }).handler(post({ hostname: 'example.com', ip: '93.184.216.34' }));
    assert.equal(res2.status, 503);
  });

  test('only POST', async () => {
    const { handler } = setup();
    for (const m of ['GET', 'PUT', 'DELETE', 'OPTIONS']) {
      const res = await handler(post({}, {}, m));
      assert.equal(res.status, 405, m);
      assert.equal(res.headers.get('access-control-allow-origin'), null);
    }
  });

  test('rejects cross-origin callers and sends no CORS headers', async () => {
    const { handler, calls } = setup();
    const evil = await handler(post({ hostname: 'example.com', ip: '93.184.216.34' }, { origin: 'https://evil.example' }));
    assert.equal(evil.status, 403);
    const site = await handler(post({ hostname: 'example.com', ip: '93.184.216.34' }, { 'sec-fetch-site': 'cross-site' }));
    assert.equal(site.status, 403);
    const same = await handler(post({ hostname: 'example.com', ip: '93.184.216.34' }, { origin: 'https://ip-whois.vercel.app', 'sec-fetch-site': 'same-origin' }));
    assert.equal(same.status, 200);
    assert.equal(calls.length, 1);
  });

  test('requires JSON content type, valid JSON object, bounded size', async () => {
    const { handler, calls } = setup();
    assert.equal((await handler(post('x', { 'content-type': 'text/plain' }))).status, 400);
    assert.equal((await handler(post('{not json'))).status, 400);
    assert.equal((await handler(post('[]'))).status, 400);
    assert.equal((await handler(post('null'))).status, 400);
    const big = JSON.stringify({ hostname: 'example.com', ip: '93.184.216.34', pad: 'x'.repeat(5000) });
    assert.equal((await handler(post(big))).status, 413);
    assert.equal(calls.length, 0);
  });

  test('rejects unknown fields, in particular any port', async () => {
    const { handler, calls } = setup();
    for (const extra of [{ port: 8443 }, { port: 443 }, { url: 'https://example.com' }]) {
      const res = await handler(post({ hostname: 'example.com', ip: '93.184.216.34', ...extra }));
      assert.equal(res.status, 400);
      assert.equal((await json(res)).error_code, 'invalid_request');
    }
    assert.equal(calls.length, 0);
  });

  test('rejects bad hostnames before any DNS or network work', async () => {
    let dnsCalls = 0;
    const resolver = { resolve4: async () => { dnsCalls++; return []; }, resolve6: async () => { dnsCalls++; return []; } };
    const { handler, calls } = setup({ resolver });
    for (const hostname of ['https://example.com', 'example.com:8443', 'user@example.com', '127.0.0.1', 'localhost', 'a.internal', 'example.com/x', 5, null, '']) {
      const res = await handler(post({ hostname, ip: '93.184.216.34' }));
      assert.equal(res.status, 400, String(hostname));
      assert.equal((await json(res)).status, 'blocked');
    }
    assert.equal(dnsCalls, 0);
    assert.equal(calls.length, 0);
  });

  test('blocks non-public or malformed selected IPs without resolving', async () => {
    let dnsCalls = 0;
    const resolver = { resolve4: async () => { dnsCalls++; return ['127.0.0.1']; }, resolve6: async () => [] };
    const { handler, calls } = setup({ resolver });
    for (const ip of ['127.0.0.1', '10.0.0.1', '169.254.169.254', '::1', '::ffff:127.0.0.1', 'fe80::1']) {
      const res = await handler(post({ hostname: 'example.com', ip }));
      assert.equal(res.status, 400, ip);
      assert.equal((await json(res)).error_code, 'destination_not_public');
    }
    for (const ip of ['nope', '', 5, undefined]) {
      assert.equal((await json(await handler(post({ hostname: 'example.com', ip })))).error_code, 'invalid_ip');
    }
    assert.equal(dnsCalls, 0);
    assert.equal(calls.length, 0);
  });

  test('DNS rebinding: a name that now resolves privately is blocked even if the browser sent a public IP', async () => {
    const { handler, calls } = setup({ resolver: okResolver(['93.184.216.34', '127.0.0.1']) });
    const res = await handler(post({ hostname: 'example.com', ip: '93.184.216.34' }));
    const body = await json(res);
    assert.equal(res.status, 403);
    assert.equal(body.status, 'blocked');
    assert.equal(body.error_code, 'destination_not_public');
    assert.equal(calls.length, 0);
  });

  test('IPv4-mapped IPv6 answers are blocked', async () => {
    const { handler, calls } = setup({ resolver: okResolver([], ['::ffff:10.0.0.5']) });
    const res = await handler(post({ hostname: 'example.com', ip: '93.184.216.34' }));
    assert.equal((await json(res)).error_code, 'destination_not_public');
    assert.equal(calls.length, 0);
  });

  test('hostname/IP mismatch: selected IP not in the server DNS answer → no connection', async () => {
    const { handler, calls } = setup();
    const res = await handler(post({ hostname: 'example.com', ip: '8.8.8.8' }));
    const body = await json(res);
    assert.equal(body.status, 'unavailable');
    assert.equal(body.error_code, 'dns_mismatch');
    assert.match(body.error_message, /DNS answer/);
    assert.equal(calls.length, 0);
  });

  test('IPv6 selected address matches across spellings and is passed through canonically', async () => {
    const { handler, calls } = setup({ resolver: okResolver([], ['2606:2800:220:1:248:1893:25c8:1946']) });
    const res = await handler(post({ hostname: 'example.com', ip: '2606:2800:220:1:248:1893:25C8:1946' }));
    assert.equal((await json(res)).status, 'ok');
    assert.equal(calls[0].ip, '2606:2800:220:1:248:1893:25c8:1946');
  });

  test('DNS failure is unavailable with a bounded code', async () => {
    const err = Object.assign(new Error('boom internal-resolver.corp'), { code: 'ESERVFAIL' });
    const { handler } = setup({ resolver: { resolve4: async () => { throw err; }, resolve6: async () => { throw err; } } });
    const res = await handler(post({ hostname: 'example.com', ip: '93.184.216.34' }));
    const body = await json(res);
    assert.equal(body.status, 'unavailable');
    assert.equal(body.error_code, 'dns_failure');
    assert.ok(!JSON.stringify(body).includes('internal-resolver'));
  });

  test('inspector failures surface as structured unavailable results', async () => {
    const { handler } = setup({ inspect: async () => ({ status: 'unavailable', error_code: 'connection_refused' }) });
    const body = await json(await handler(post({ hostname: 'example.com', ip: '93.184.216.34' })));
    assert.equal(body.status, 'unavailable');
    assert.equal(body.error_code, 'connection_refused');
    assert.equal(body.connected_ip, '93.184.216.34');
    assert.equal(body.port, 443);
    assert.ok(body.observed_at);
    assert.ok(body.error_message);
  });

  test('unexpected exceptions never leak details', async () => {
    const { handler } = setup({ inspect: async () => { throw new Error('/var/task/secret stack trace'); } });
    const res = await handler(post({ hostname: 'example.com', ip: '93.184.216.34' }));
    const text = await res.text();
    assert.equal(res.status, 200);
    assert.ok(!text.includes('secret'));
    assert.ok(text.includes('inspection_failed'));
  });

  test('logs contain no hostnames or IPs', async () => {
    const { handler, logs } = setup();
    await handler(post({ hostname: 'example.com', ip: '93.184.216.34' }));
    await handler(post({ hostname: 'example.com', ip: '8.8.8.8' }));
    const all = JSON.stringify(logs);
    assert.ok(!all.includes('example.com') && !all.includes('93.184') && !all.includes('8.8.8.8'));
  });

  test('concurrency cap rejects excess in-flight inspections', async () => {
    let release;
    const gate = new Promise((r) => { release = r; });
    const { handler } = setup({ maxConcurrent: 2, inspect: async (t) => { await gate; return okResult(t.hostname, t.ip); } });
    const req = () => handler(post({ hostname: 'example.com', ip: '93.184.216.34' }));
    const a = req(); const b = req();
    await new Promise((r) => setTimeout(r, 20));
    const c = await req();
    assert.equal(c.status, 429);
    assert.equal((await json(c)).error_code, 'busy');
    release();
    assert.equal((await a).status, 200);
    assert.equal((await b).status, 200);
    assert.equal((await req()).status, 200);
  });
});

describe('production wiring', () => {
  test('the default export cannot be configured from a request', async () => {
    const mod = await import('../api/tls.js');
    assert.equal(typeof mod.POST, 'function');
    // Without the env attestation the default handler refuses.
    const saved = process.env.TLS_INSPECTION_ENABLED;
    delete process.env.TLS_INSPECTION_ENABLED;
    const res = await mod.POST(post({ hostname: 'example.com', ip: '93.184.216.34' }));
    if (saved !== undefined) process.env.TLS_INSPECTION_ENABLED = saved;
    assert.equal(res.status, 503);
  });
});
