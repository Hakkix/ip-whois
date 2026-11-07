// Geolocation provider cascade and normalization, plus best-effort ASN
// extraction (the free geolocation providers are the only source of ASN
// data this app uses — there is no dedicated BGP/ASN lookup).
import { fetchWithTimeout, classifyInput, expandIPv6, validCoords } from './utils.js';

export const GEO_PROVIDERS = ['ipinfo.io', 'ipwho.is', 'ipapi.co'];

export function geoUrl(providerId, ip) {
  // Omitting the IP asks the provider to resolve the caller's own address —
  // used for the landing-page self-IP panel.
  switch (providerId) {
    case 'ipinfo.io':
      return ip ? `https://ipinfo.io/${ip}/json` : 'https://ipinfo.io/json';
    case 'ipwho.is':
      return ip ? `https://ipwho.is/${ip}` : 'https://ipwho.is/';
    case 'ipapi.co':
      // Literal colons in the path — URL-encoding an IPv6 address here
      // trips ipapi.co's WAF and returns 403.
      return ip ? `https://ipapi.co/${ip}/json/` : 'https://ipapi.co/json/';
    default:
      return null;
  }
}

// Known provider error payloads: HTTP 200 with an error body (rate limit,
// invalid IP, bogon, quota). Anything that is not a plain JSON object fails.
function isFailedResponse(raw, providerId) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return true;
  if (providerId === 'ipwho.is') return raw.success === false;
  if (providerId === 'ipapi.co') return raw.error === true || Boolean(raw.error);
  if (providerId === 'ipinfo.io') return Boolean(raw.error) || Boolean(raw.bogon);
  return false;
}

const str = (v) => (typeof v === 'string' && v.trim() ? v.trim() : null);
const countryCode = (v) => (typeof v === 'string' && /^[A-Za-z]{2}$/.test(v.trim()) ? v.trim() : null);
// A coordinate pair is kept only if both halves are valid; half a position is
// worse than none.
const coordPair = (lat, lon) => (validCoords(lat, lon) ? [lat, lon] : [null, null]);

function countryName(code) {
  if (!code || typeof code !== 'string') return null;
  try {
    return new Intl.DisplayNames(['en'], { type: 'region' }).of(code.toUpperCase()) || null;
  } catch {
    return null;
  }
}

function sameAddress(a, b) {
  const ca = classifyInput(a);
  const cb = classifyInput(b);
  if (!ca || !cb || ca.type !== cb.type || ca.type === 'hostname') return false;
  return ca.type === 'ipv6' ? expandIPv6(ca.value).join(':') === expandIPv6(cb.value).join(':') : ca.value === cb.value;
}

export function hasLocationData(loc) {
  return Boolean(loc) && Boolean(loc.country || loc.country_code || loc.region || loc.city || loc.postal_code
    || (loc.latitude !== null && loc.longitude !== null));
}

// A provider answer is accepted only if its shape is sound, it describes the
// address we asked about, and it carries something useful: an ASN or at least
// one real location field. A partial answer (ASN but no coordinates) is kept.
export function isUsableGeo(raw, providerId, ip) {
  if (isFailedResponse(raw, providerId)) return false;
  if (raw.ip !== undefined && raw.ip !== null) {
    if (typeof raw.ip !== 'string') return false;
    if (ip ? !sameAddress(raw.ip, ip) : !classifyInput(raw.ip) || classifyInput(raw.ip).type === 'hostname') return false;
  } else if (!ip) {
    return false; // a self-lookup is only useful if it tells us the address
  }
  const loc = normalizeGeoResponse(raw, providerId);
  return Boolean(normalizeAsn(raw, providerId) || (loc && hasLocationData(loc)));
}

// Fetches from the provider cascade, returning the first usable response.
// Returns { raw, provider } or null if every provider failed, timed out or
// returned an unusable answer.
export async function fetchGeo(ip, timeoutMs = 6000) {
  for (const providerId of GEO_PROVIDERS) {
    const url = geoUrl(providerId, ip);
    try {
      const resp = await fetchWithTimeout(url, {}, timeoutMs);
      if (!resp.ok) continue;
      const raw = await resp.json();
      if (!isUsableGeo(raw, providerId, ip)) continue;
      return { raw, provider: providerId };
    } catch {
      // try next provider
    }
  }
  return null;
}

export function normalizeGeoResponse(raw, providerId) {
  if (!raw || typeof raw !== 'object') return null;
  switch (providerId) {
    case 'ipinfo.io': {
      const [latStr, lonStr] = (typeof raw.loc === 'string' ? raw.loc : '').split(',');
      const parse = (t) => (t && t.trim() !== '' ? Number(t) : null);
      const [latitude, longitude] = coordPair(parse(latStr), parse(lonStr));
      const code = countryCode(raw.country);
      return {
        country: countryName(code),
        country_code: code,
        region: str(raw.region),
        city: str(raw.city),
        postal_code: str(raw.postal),
        timezone: str(raw.timezone),
        latitude,
        longitude,
        source: 'ipinfo.io',
        precision: 'approximate',
      };
    }
    case 'ipwho.is': {
      const tz = raw.timezone && typeof raw.timezone === 'object' ? raw.timezone.id : raw.timezone;
      const code = countryCode(raw.country_code);
      const [latitude, longitude] = coordPair(raw.latitude, raw.longitude);
      return {
        country: str(raw.country) || countryName(code),
        country_code: code,
        region: str(raw.region),
        city: str(raw.city),
        postal_code: str(raw.postal),
        timezone: str(tz),
        latitude,
        longitude,
        source: 'ipwho.is',
        precision: 'approximate',
      };
    }
    case 'ipapi.co': {
      const code = countryCode(raw.country);
      const [latitude, longitude] = coordPair(raw.latitude, raw.longitude);
      return {
        country: str(raw.country_name) || countryName(code),
        country_code: code,
        region: str(raw.region),
        city: str(raw.city),
        postal_code: str(raw.postal),
        timezone: str(raw.timezone),
        latitude,
        longitude,
        source: 'ipapi.co',
        precision: 'approximate',
      };
    }
    default:
      return null;
  }
}

export function normalizeAsn(raw, providerId) {
  if (!raw || typeof raw !== 'object') return null;
  let number = null;
  let organization = null;

  if (providerId === 'ipinfo.io' && typeof raw.org === 'string') {
    const m = raw.org.match(/^AS(\d+)\s*(.*)$/i);
    if (m) {
      number = Number(m[1]);
      organization = m[2] || null;
    }
  } else if (providerId === 'ipwho.is' && raw.connection && typeof raw.connection === 'object') {
    if (typeof raw.connection.asn === 'number') number = raw.connection.asn;
    organization = str(raw.connection.org) || str(raw.connection.isp);
  } else if (providerId === 'ipapi.co' && typeof raw.asn === 'string') {
    const m = raw.asn.match(/AS(\d+)/i);
    if (m) number = Number(m[1]);
    organization = str(raw.org);
  }

  if (!Number.isSafeInteger(number) || number <= 0) return null;
  return {
    number,
    display: `AS${number}`,
    name: null,
    organization: organization || null,
    country_code: null,
    prefix: null,
    source: providerId,
  };
}

// The self-lookup ('no ip' cascade) response also reports the caller's own
// address — every one of the three providers exposes it under `ip`.
export function selfIpFromRaw(raw) {
  const ip = raw && typeof raw.ip === 'string' ? raw.ip.trim() : null;
  return ip || null;
}

// Fetches the caller's own IP + ASN + geolocation in one cascaded call.
// Returns { ip, raw, provider } or null if every provider failed/timed out.
export async function fetchSelfGeo(timeoutMs = 6000) {
  const result = await fetchGeo(null, timeoutMs);
  if (!result) return null;
  const ip = selfIpFromRaw(result.raw);
  if (!ip) return null;
  return { ip, raw: result.raw, provider: result.provider };
}
