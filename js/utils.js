// Input validation, IP/hostname parsing, PTR name generation, and small
// helpers shared across modules. No provider-specific logic lives here.

export const validIPv4 = (s) => {
  const p = s.split('.');
  return p.length === 4 && p.every((x) => /^\d{1,3}$/.test(x) && Number(x) <= 255 && String(Number(x)) === x);
};

function ipv4ToHexGroups(v4) {
  const o = v4.split('.').map(Number);
  const g1 = ((o[0] << 8) | o[1]).toString(16).padStart(4, '0');
  const g2 = ((o[2] << 8) | o[3]).toString(16).padStart(4, '0');
  return [g1, g2];
}

export function validIPv6(raw) {
  let s = raw.trim();
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  const zoneIdx = s.indexOf('%');
  if (zoneIdx > -1) s = s.slice(0, zoneIdx);
  if ((s.match(/::/g) || []).length > 1) return false;
  const hasDoubleColon = s.includes('::');
  const parts = s.split(':');
  if (!hasDoubleColon && parts.length !== 8 && !s.includes('.')) return false;
  let count = 0;
  for (const part of parts) {
    if (part === '') continue;
    if (part.includes('.')) {
      if (!validIPv4(part)) return false;
      count += 2;
      continue;
    }
    if (!/^[0-9a-fA-F]{1,4}$/.test(part)) return false;
    count++;
  }
  return hasDoubleColon ? count < 8 : count === 8;
}

// Fully expands an IPv6 address into eight 4-hex-digit groups.
export function expandIPv6(raw) {
  let ip = raw.trim().toLowerCase();
  if (ip.startsWith('[') && ip.endsWith(']')) ip = ip.slice(1, -1);
  const zoneIdx = ip.indexOf('%');
  if (zoneIdx > -1) ip = ip.slice(0, zoneIdx);

  let head = [];
  let tail = [];
  if (ip.includes('::')) {
    const [h, t] = ip.split('::');
    head = h ? h.split(':') : [];
    tail = t ? t.split(':') : [];
  } else {
    head = ip.split(':');
  }

  const target = tail.length ? tail : head;
  if (target.length && target[target.length - 1].includes('.')) {
    const v4 = target.pop();
    target.push(...ipv4ToHexGroups(v4));
  }

  let groups;
  if (ip.includes('::')) {
    const missing = 8 - (head.length + tail.length);
    groups = [...head, ...Array(Math.max(missing, 0)).fill('0'), ...tail];
  } else {
    groups = head;
  }
  return groups.map((g) => g.padStart(4, '0'));
}

export function compressIPv6(groups) {
  const ints = groups.map((g) => parseInt(g, 16));
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (ints[i] === 0) {
      if (curStart === -1) curStart = i;
      curLen++;
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  if (bestLen < 2) return ints.map((x) => x.toString(16)).join(':');
  const head = ints.slice(0, bestStart).map((x) => x.toString(16));
  const tail = ints.slice(bestStart + bestLen).map((x) => x.toString(16));
  return `${head.join(':')}::${tail.join(':')}`;
}

export function isValidHostname(raw) {
  const s = raw.trim().toLowerCase().replace(/\.$/, '');
  if (!s || s.length > 253) return false;
  const labels = s.split('.');
  if (labels.length < 2) return false;
  const labelRe = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
  if (!labels.every((l) => labelRe.test(l))) return false;
  return /^[a-z]{2,}$/.test(labels.at(-1));
}

// Classifies raw user input. Returns { type: 'ipv4'|'ipv6'|'hostname', value }
// or null when the input is not an acceptable query.
export function classifyInput(raw) {
  if (typeof raw !== 'string') return null;
  let s = raw.trim();
  if (!s) return null;
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  if (validIPv4(s)) return { type: 'ipv4', value: s };
  if (validIPv6(s)) return { type: 'ipv6', value: s.toLowerCase() };
  const hostCandidate = s.toLowerCase().replace(/\.$/, '');
  if (isValidHostname(hostCandidate)) return { type: 'hostname', value: hostCandidate };
  return null;
}

export function ptrNameForIPv4(ip) {
  return `${ip.split('.').reverse().join('.')}.in-addr.arpa`;
}

export function ptrNameForIPv6(ip) {
  const nibbles = expandIPv6(ip).join('').split('').reverse().join('.');
  return `${nibbles}.ip6.arpa`;
}

export function ptrNameFor(ip, version) {
  return version === 4 ? ptrNameForIPv4(ip) : ptrNameForIPv6(ip);
}

export function isReservedIP(version, ip) {
  if (version === 4) {
    const octets = ip.split('.').map(Number);
    const x = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
    const ranges = [
      ['0.0.0.0', 0xff000000], ['10.0.0.0', 0xff000000], ['127.0.0.0', 0xff000000],
      ['169.254.0.0', 0xffff0000], ['172.16.0.0', 0xfff00000], ['192.0.0.0', 0xffffff00],
      ['192.0.2.0', 0xffffff00], ['192.168.0.0', 0xffff0000], ['198.18.0.0', 0xfffe0000],
      ['198.51.100.0', 0xffffff00], ['203.0.113.0', 0xffffff00], ['224.0.0.0', 0xf0000000],
      ['240.0.0.0', 0xf0000000],
    ].map(([a, m]) => [a.split('.').map(Number).reduce((t, v) => ((t << 8) | v) >>> 0, 0), m]);
    return ranges.some(([base, mask]) => (x & mask) >>> 0 === base);
  }
  const l = ip.toLowerCase();
  return (
    ['::', '::1'].includes(l) ||
    l.startsWith('fc') || l.startsWith('fd') ||
    l.startsWith('fe8') || l.startsWith('fe9') || l.startsWith('fea') || l.startsWith('feb') ||
    l.startsWith('2001:db8') || l.startsWith('ff')
  );
}

function ipv4ToBigInt(ip) {
  return ip.split('.').map(Number).reduce((acc, o) => (acc << 8n) | BigInt(o), 0n);
}

function bigIntToIpv4(n) {
  const b = [24n, 16n, 8n, 0n].map((sh) => Number((n >> sh) & 0xffn));
  return b.join('.');
}

function ipv6ToBigInt(ip) {
  return expandIPv6(ip).reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g, 16)), 0n);
}

function bigIntToIpv6(n) {
  const groups = [];
  for (let i = 7; i >= 0; i--) {
    groups.push(((n >> BigInt(i * 16)) & 0xffffn).toString(16));
  }
  return compressIPv6(groups.map((g) => g.padStart(4, '0')));
}

function trailingZeroBits(x, maxBits) {
  if (x === 0n) return maxBits;
  let tz = 0;
  let v = x;
  while ((v & 1n) === 0n && tz < maxBits) {
    v >>= 1n;
    tz++;
  }
  return tz;
}

// Converts an address range (inclusive) into the minimal list of CIDR blocks
// that exactly cover it. Used as a fallback when RDAP responses omit an
// explicit cidr0 extension.
export function rangeToCidrs(startAddr, endAddr, version) {
  const bits = version === 4 ? 32 : 128;
  const toBig = version === 4 ? ipv4ToBigInt : ipv6ToBigInt;
  const toAddr = version === 4 ? bigIntToIpv4 : bigIntToIpv6;
  let start = toBig(startAddr);
  const end = toBig(endAddr);
  const max = (1n << BigInt(bits)) - 1n;
  const cidrs = [];
  let guard = 0;
  while (start <= end && guard < 4096) {
    guard++;
    let tz = trailingZeroBits(start, bits);
    let blockBits = bits - tz;
    while (blockBits < bits) {
      const blockSize = 1n << BigInt(bits - blockBits);
      if (start + blockSize - 1n <= end) break;
      blockBits++;
    }
    const blockSize = 1n << BigInt(bits - blockBits);
    cidrs.push(`${toAddr(start)}/${blockBits}`);
    start += blockSize;
    if (start > max) break;
  }
  return cidrs;
}

export function fetchWithTimeout(url, options = {}, timeoutMs = 7000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return fetch(url, { ...options, signal: controller.signal }).finally(() => clearTimeout(timer));
}

// Only known-safe protocols are ever rendered as clickable links.
export function safeUrl(candidate, allowedProtocols = ['https:']) {
  if (!candidate || typeof candidate !== 'string') return null;
  try {
    const u = new URL(candidate);
    if (!allowedProtocols.includes(u.protocol)) return null;
    return u.toString();
  } catch {
    return null;
  }
}

export const has = (v) => v !== null && v !== undefined && v !== '';

export function isoNow() {
  return new Date().toISOString();
}

export function toIsoOrNull(value) {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}
