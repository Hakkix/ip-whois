// Destination and input validation for the TLS inspection endpoint.
// Everything here is server-side policy: the browser's own address
// classification is never trusted.
import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';

export const MAX_HOSTNAME_LENGTH = 253;
export const MAX_BODY_BYTES = 1024;

const LABEL_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
// Characters allowed in the raw input before IDN conversion. Anything else
// (/, :, @, ?, #, %, whitespace, brackets, ...) means it is not a bare hostname.
const RAW_RE = /^[\p{L}\p{N}.-]+$/u;
const BLOCKED_TLDS = new Set([
  'localhost', 'local', 'localdomain', 'internal', 'intranet', 'lan', 'home', 'corp', 'private',
  'invalid', 'test', 'example', 'onion', 'arpa', 'alt',
]);

// Returns { ok: true, hostname } (lowercase ASCII/punycode) or { ok: false, code }.
export function validateHostname(raw) {
  if (typeof raw !== 'string') return { ok: false, code: 'invalid_hostname' };
  let s = raw.replace(/\.$/, '');
  if (!s || s.length > MAX_HOSTNAME_LENGTH * 2) return { ok: false, code: 'invalid_hostname' };
  if (!RAW_RE.test(s)) return { ok: false, code: 'invalid_hostname' };
  if (/\.\./.test(s) || s.startsWith('.')) return { ok: false, code: 'invalid_hostname' };
  s = domainToASCII(s.toLowerCase());
  if (!s || s.length > MAX_HOSTNAME_LENGTH) return { ok: false, code: 'invalid_hostname' };
  const labels = s.split('.');
  if (labels.length < 2 || !labels.every((l) => LABEL_RE.test(l))) return { ok: false, code: 'invalid_hostname' };
  const tld = labels.at(-1);
  // Numeric/hex-looking last labels are IPv4 spellings (127.1, 0x7f.1, 2130706433).
  if (!/^(xn--[a-z0-9-]+|[a-z][a-z0-9-]*)$/.test(tld) || /^0x/.test(tld)) return { ok: false, code: 'invalid_hostname' };
  if (isIP(s)) return { ok: false, code: 'invalid_hostname' };
  if (BLOCKED_TLDS.has(tld)) return { ok: false, code: 'hostname_not_public' };
  return { ok: true, hostname: s };
}

// ---- IP classification ----

export function parseIPv4(s) {
  if (typeof s !== 'string' || !/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return null;
  const parts = s.split('.');
  if (parts.some((p) => (p.length > 1 && p[0] === '0') || Number(p) > 255)) return null;
  return parts.reduce((acc, p) => (acc << 8n) | BigInt(p), 0n);
}

export function parseIPv6(s) {
  if (typeof s !== 'string' || s.includes('%') || isIP(s) !== 6) return null;
  let head = s;
  let tailV4 = [];
  const lastColon = s.lastIndexOf(':');
  const tail = s.slice(lastColon + 1);
  if (tail.includes('.')) {
    const v4 = parseIPv4(tail);
    if (v4 === null) return null;
    tailV4 = [Number(v4 >> 16n), Number(v4 & 0xffffn)].map((n) => n.toString(16));
    head = s.slice(0, lastColon + 1) + '0:0';
  }
  const [left, right, extra] = head.split('::');
  if (extra !== undefined) return null;
  const l = left ? left.split(':') : [];
  const r = right !== undefined && right ? right.split(':') : [];
  let groups;
  if (right === undefined) groups = l;
  else groups = [...l, ...Array(8 - l.length - r.length).fill('0'), ...r];
  if (groups.length !== 8) return null;
  if (tailV4.length) groups.splice(6, 2, ...tailV4);
  let n = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
    n = (n << 16n) | BigInt(parseInt(g, 16));
  }
  return n;
}

const v4 = (cidr) => { const [a, p] = cidr.split('/'); return [parseIPv4(a), Number(p)]; };
const v6 = (cidr) => { const [a, p] = cidr.split('/'); return [parseIPv6(a), Number(p)]; };

const IPV4_BLOCKED = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
  '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15',
  '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
].map(v4);

// IPv6 is allow-listed: only global unicast 2000::/3 is considered, minus the
// special-purpose blocks inside it. Mapped (::ffff:0:0/96), NAT64, ULA,
// link-local, multicast, loopback and unspecified therefore all fail closed.
const IPV6_ALLOWED = v6('2000::/3');
const IPV6_BLOCKED = [
  '2001::/23', '2001:db8::/32', '2002::/16', '3fff::/20',
].map(v6);

const inNet = (n, bits, [base, prefix]) => (n >> BigInt(bits - prefix)) === (base >> BigInt(bits - prefix));

export function isPublicIPv4(s) {
  const n = parseIPv4(s);
  return n !== null && !IPV4_BLOCKED.some((net) => inNet(n, 32, net));
}

export function isPublicIPv6(s) {
  const n = parseIPv6(s);
  if (n === null || !inNet(n, 128, IPV6_ALLOWED)) return false;
  return !IPV6_BLOCKED.some((net) => inNet(n, 128, net));
}

export function isPublicIp(s) {
  const fam = isIP(s);
  if (fam === 4) return isPublicIPv4(s);
  if (fam === 6) return isPublicIPv6(s);
  return false;
}

// Canonical form for comparing addresses from different sources.
export function normalizeIp(s) {
  const fam = isIP(s);
  if (fam === 4) return parseIPv4(s) === null ? null : s;
  if (fam === 6) {
    const n = parseIPv6(s);
    if (n === null) return null;
    return Array.from({ length: 8 }, (_, i) => ((n >> BigInt(112 - 16 * i)) & 0xffffn).toString(16)).join(':');
  }
  return null;
}

// Resolves A and AAAA on the server and validates the whole answer set.
// `resolver` needs resolve4/resolve6 (dns.promises-compatible).
// Result: { ok, addresses } | { ok:false, code }.
export async function resolvePublicAddresses(hostname, resolver) {
  const [a, aaaa] = await Promise.allSettled([resolver.resolve4(hostname), resolver.resolve6(hostname)]);
  const answers = [];
  for (const r of [a, aaaa]) if (r.status === 'fulfilled' && Array.isArray(r.value)) answers.push(...r.value);
  if (!answers.length) return { ok: false, code: 'dns_failure' };
  const seen = new Set();
  for (const addr of answers) {
    const norm = typeof addr === 'string' ? normalizeIp(addr) : null;
    // Fail closed: one unsafe or malformed answer poisons the whole set.
    if (!norm || !isPublicIp(addr)) return { ok: false, code: 'destination_not_public' };
    seen.add(norm);
  }
  return { ok: true, addresses: [...seen] };
}

// The browser-selected IP must be a member of the freshly validated answer set.
// Returns the address to connect to (the validated, canonical-from-DNS string).
export function selectValidatedAddress(ip, addresses) {
  const want = typeof ip === 'string' ? normalizeIp(ip) : null;
  if (!want) return null;
  return addresses.includes(want) ? want : null;
}
