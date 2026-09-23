# IP Intelligence

**Live application:** https://ip-whois.vercel.app

A lightweight, browser-based IP intelligence tool. The landing page auto-detects and displays your own public IP (org, ASN, approximate location, reverse DNS), and doubles as an investigation console: given an IPv4 address, an IPv6 address, or a hostname, it combines authoritative RDAP registration data, DNS (forward and reverse), ASN information, and approximate geolocation into a single source-attributed report — viewable in the browser, or exported as JSON, Markdown, or plain text.

It is a static site with no backend, no build step, and no accounts: everything runs client-side and nothing about your query is stored server-side. Recent lookups are kept only in `sessionStorage` for the current browser session.

## What it does

For a given IP address or hostname, the report answers:

- What IP address is this, and is it IPv4 or IPv6?
- Which network owns or operates it (RDAP)?
- Which ASN announces it, and who operates that ASN?
- Which address range/prefix does it belong to?
- Which Regional Internet Registry (RIR) is authoritative?
- Where is the IP approximately located?
- What reverse DNS (PTR) hostname does it have?
- When was the allocation registered or last modified?
- Which abuse/technical/administrative contacts are on file?
- Where did each piece of data come from?

## Supported input types

- IPv4 address (e.g. `8.8.8.8`)
- IPv6 address, compressed or expanded (e.g. `2001:4860:4860::8888`)
- DNS hostname (e.g. `example.com`) — resolved to an IP (A/AAAA) before lookup

Reserved/private ranges (RFC 1918, loopback, link-local, documentation ranges, etc.) are rejected locally, since they cannot be looked up publicly. Full URLs, and anything that isn't a plain address or hostname, are rejected rather than silently reduced.

## Information sources

| Data | Source |
|---|---|
| Registration / network (RDAP) | RDAP bootstrap via `rdap-bootstrap.arin.net`, redirecting to the authoritative RIR (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC) |
| Forward DNS (A/AAAA) and reverse DNS (PTR) | DNS-over-HTTPS, tried in order: Cloudflare (`cloudflare-dns.com`), then Google (`dns.google`) |
| Geolocation and ASN | A provider cascade, tried in order: `ipinfo.io`, `ipwho.is`, `ipapi.co` — the first provider to respond successfully is used, and the report records which one |

Every report includes a **Data Sources** section naming exactly which provider supplied its RDAP, DNS, and geolocation data.

RDAP is used in preference to legacy WHOIS wherever available, per current registry practice.

## Geolocation accuracy

**IP geolocation is approximate and represents the network's location, not the physical location of a person or device.** Free geolocation providers typically resolve to the city or region level, sometimes to the ISP's routing hub rather than the end user. The report always states this alongside any coordinates, and a map (via [Leaflet](https://leafletjs.com/) and OpenStreetMap tiles) is only shown when coordinates are actually available — never a default or guessed location.

## Report formats

Every format is generated from the same normalized internal report model (schema v2), so nothing shown in the UI is missing from an export and vice versa.

- **JSON** — the normalized report object, 2-space indented, ISO 8601 timestamps, `null`/`[]` for missing data (never `"N/A"` or `"unknown"` placeholders).
- **Markdown** — headed sections with tables, suitable for pasting into documentation or a ticket.
- **Plain text** — fixed-width sections, readable in a terminal, email, or ticketing system.

## Privacy

- No browser/device geolocation is requested or used. All geolocation concerns the **queried IP address**, resolved via third-party geolocation APIs.
- No accounts, no server-side lookup history, no database.
- Queries call the RDAP/DNS/geolocation providers listed above directly from your browser, so those providers see your IP address. Reports with a map also load tiles from OpenStreetMap.
- The landing page detects your own IP by calling a third-party GeoIP provider (ipinfo.io, falling back to ipwho.is and ipapi.co). This is skipped when the page is opened with a `?q=` report link.
- Fonts (Inter, JetBrains Mono) are self-hosted under `vendor/fonts/`; no request goes to Google Fonts.

## Architecture

Static site, no build step, no frontend framework:

```
/
├── index.html        entry point
├── app.js             orchestration: view state, self-IP pipeline, investigation pipeline, DOM event wiring
├── style.css / base.css
├── js/
│   ├── utils.js        input validation, PTR generation, CIDR math
│   ├── dns.js           DNS-over-HTTPS forward + reverse (PTR) lookups
│   ├── rdap.js           RDAP fetch + per-RIR normalization
│   ├── geo.js             geolocation provider cascade (per-IP and self) + ASN extraction
│   ├── report.js           normalized report model + JSON/Markdown/Text export
│   ├── render.js            investigation report DOM (no innerHTML with external data)
│   ├── landing.js           self-IP hero, intelligence tiles, source-status strip
│   ├── chooser.js            multi-address hostname chooser
│   ├── history.js             session-only recent-lookup history (sessionStorage)
│   ├── about.js                About modal (focus trap, section targeting)
│   ├── toast.js                 non-blocking toast/status feedback
│   └── domkit.js                 shared safe DOM-construction helpers
├── vendor/leaflet/    vendored Leaflet (map tiles rendering), no CDN dependency
├── tests/
│   ├── normalize.test.js  input parsing, PTR, CIDR, RDAP/geo normalization
│   ├── report.test.js      report model + export consistency
│   ├── security.test.js     XSS-safety of the DOM renderer
│   ├── resilience.test.js    provider-failure paths
│   └── fixtures/            recorded provider responses, no live API calls in tests
└── vercel.json
```

Landing state: the visitor's public IP is detected via the geolocation provider cascade (self-lookup) and rendered as soon as it's known, then org/ASN/location/reverse-DNS enrich progressively. Investigation state: input is normalized and classified (IP vs. hostname) → a hostname is resolved to an IP (multiple results show an address chooser) → RDAP, geolocation, and reverse DNS are looked up **in parallel** (a failure in one does not block the others) → all results are normalized into one report object → the UI and every export format render from that same object.

## Security

- External data (RDAP, DNS, geolocation responses, and the query itself) is never written into the DOM via `innerHTML`. The renderer (`js/render.js`) builds elements with `document.createElement` and sets `textContent`, so a value like `<img src=x onerror=alert(1)>` in a network name or remark is always displayed as literal text, never executed.
- Links are only ever rendered for URLs the app constructs itself (e.g. the OpenStreetMap link) or that pass a protocol allowlist (`https:`/`http:` only) — `javascript:` and `data:` URLs are never linkified.
- A `Content-Security-Policy` header (see `vercel.json`) restricts script/style/connect/img sources to what the app actually needs.

## Development setup

No build step and no dependencies to install — open `index.html` directly, or serve the directory statically:

```sh
python3 -m http.server 8080
# then open http://localhost:8080
```

## Testing

Tests use Node's built-in test runner and have no dependencies to install:

```sh
npm test
# or: node --test
```

All unit and normalization tests run against recorded fixtures in `tests/fixtures/` — no live network access or external API is required for a deterministic run.

## Known limitations

- Geolocation and ASN data come from free, no-auth third-party APIs; accuracy and rate limits are outside this app's control, and a provider cascade is used to mitigate (not eliminate) outages.
- ASN data is derived from the geolocation providers' own ASN fields, not a dedicated BGP/RPKI source — the announced prefix shown is a best-effort value (falling back to the RDAP-registered CIDR when the provider doesn't supply one), not verified routing data.
- Reverse DNS (PTR) absence is common and expected; it is treated as a normal "not set" result, not an error.
- No user accounts, no persisted history, no threat/reputation scoring — by design (see the implementation spec for out-of-scope items reserved for a possible v3).
