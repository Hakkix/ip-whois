// Geolocation provider cascade and normalization, plus best-effort ASN
// extraction (the free geolocation providers are the only source of ASN
// data this app uses — there is no dedicated BGP/ASN lookup).
import { fetchWithTimeout } from './utils.js';

export const GEO_PROVIDERS = ['ipinfo.io', 'ipwho.is', 'ipapi.co'];

function geoUrl(providerId, ip) {
  switch (providerId) {
    case 'ipinfo.io':
      return `https://ipinfo.io/${ip}/json`;
    case 'ipwho.is':
      return `https://ipwho.is/${ip}`;
    case 'ipapi.co':
      // Literal colons in the path — URL-encoding an IPv6 address here
      // trips ipapi.co's WAF and returns 403.
      return `https://ipapi.co/${ip}/json/`;
    default:
      return null;
  }
}

function isFailedResponse(raw, providerId) {
  if (!raw || typeof raw !== 'object') return true;
  if (providerId === 'ipwho.is') return raw.success === false;
  if (providerId === 'ipapi.co') return raw.error === true;
  if (providerId === 'ipinfo.io') return Boolean(raw.error) || Boolean(raw.bogon);
  return false;
}

function countryName(code) {
  if (!code) return null;
  try {
    return new Intl.DisplayNames(['en'], { type: 'region' }).of(code.toUpperCase()) || null;
  } catch {
    return null;
  }
}

// Fetches from the provider cascade, returning the first usable response.
// Returns { raw, provider } or null if every provider failed/timed out.
export async function fetchGeo(ip, timeoutMs = 6000) {
  for (const providerId of GEO_PROVIDERS) {
    const url = geoUrl(providerId, ip);
    try {
      const resp = await fetchWithTimeout(url, {}, timeoutMs);
      if (!resp.ok) continue;
      const raw = await resp.json();
      if (isFailedResponse(raw, providerId)) continue;
      return { raw, provider: providerId };
    } catch {
      // try next provider
    }
  }
  return null;
}

export function normalizeGeoResponse(raw, providerId) {
  switch (providerId) {
    case 'ipinfo.io': {
      const [latStr, lonStr] = (raw.loc || '').split(',');
      return {
        country: countryName(raw.country),
        country_code: raw.country || null,
        region: raw.region || null,
        city: raw.city || null,
        postal_code: raw.postal || null,
        timezone: raw.timezone || null,
        latitude: latStr ? Number(latStr) : null,
        longitude: lonStr ? Number(lonStr) : null,
        source: 'ipinfo.io',
        precision: 'approximate',
      };
    }
    case 'ipwho.is': {
      const tz = typeof raw.timezone === 'object' && raw.timezone ? raw.timezone.id : raw.timezone;
      return {
        country: raw.country || countryName(raw.country_code) || null,
        country_code: raw.country_code || null,
        region: raw.region || null,
        city: raw.city || null,
        postal_code: raw.postal || null,
        timezone: tz || null,
        latitude: typeof raw.latitude === 'number' ? raw.latitude : null,
        longitude: typeof raw.longitude === 'number' ? raw.longitude : null,
        source: 'ipwho.is',
        precision: 'approximate',
      };
    }
    case 'ipapi.co': {
      return {
        country: raw.country_name || countryName(raw.country) || null,
        country_code: raw.country || null,
        region: raw.region || null,
        city: raw.city || null,
        postal_code: raw.postal || null,
        timezone: raw.timezone || null,
        latitude: typeof raw.latitude === 'number' ? raw.latitude : null,
        longitude: typeof raw.longitude === 'number' ? raw.longitude : null,
        source: 'ipapi.co',
        precision: 'approximate',
      };
    }
    default:
      return null;
  }
}

export function normalizeAsn(raw, providerId) {
  let number = null;
  let organization = null;

  if (providerId === 'ipinfo.io' && raw.org) {
    const m = raw.org.match(/^AS(\d+)\s*(.*)$/i);
    if (m) {
      number = Number(m[1]);
      organization = m[2] || null;
    }
  } else if (providerId === 'ipwho.is' && raw.connection) {
    if (typeof raw.connection.asn === 'number') number = raw.connection.asn;
    organization = raw.connection.org || raw.connection.isp || null;
  } else if (providerId === 'ipapi.co' && raw.asn) {
    const m = String(raw.asn).match(/AS(\d+)/i);
    if (m) number = Number(m[1]);
    organization = raw.org || null;
  }

  if (number === null) return null;
  return {
    number,
    display: `AS${number}`,
    name: null,
    organization: organization || null,
    country_code: null,
    prefix: null,
  };
}
