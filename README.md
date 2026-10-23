# IP Intelligence

**Live application:** https://ip-whois.vercel.app

A lightweight, browser-based IP intelligence tool. The landing page auto-detects and displays your own public IP (org, ASN, approximate location, reverse DNS), and doubles as an investigation console: given an IPv4 address, an IPv6 address, or a hostname, it combines authoritative RDAP registration data, DNS (forward and reverse), ASN information, and approximate geolocation into a single source-attributed report — viewable in the browser, or exported as JSON, Markdown, or plain text.

It is a static site plus **one small Vercel Node.js Function** (`/api/tls`, used only for hostname lookups to read TLS certificates). There is no build step, no database and no accounts; nothing about your query is stored permanently. Apart from the TLS function, queries run directly from your browser. Recent lookups are kept only in `sessionStorage` for the current browser session.

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
- What TLS certificate does the hostname's HTTPS server present, and is it valid? (hostname lookups only)
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
| TLS certificate (hostname lookups only) | `POST /api/tls` — a server-side TLS handshake to the selected IP on port 443 (see below) |
| Geolocation and ASN | A provider cascade, tried in order: `ipinfo.io`, `ipwho.is`, `ipapi.co` — the first provider to respond successfully is used, and the report records which one |

Every report includes a **Data Sources** section naming exactly which provider supplied its RDAP, DNS, and geolocation data.

RDAP is used in preference to legacy WHOIS wherever available, per current registry practice.

## Geolocation accuracy

**IP geolocation is approximate and represents the network's location, not the physical location of a person or device.** Free geolocation providers typically resolve to the city or region level, sometimes to the ISP's routing hub rather than the end user. The report always states this alongside any coordinates, and a map (via [Leaflet](https://leafletjs.com/) and OpenStreetMap tiles) is only shown when coordinates are actually available — never a default or guessed location.

## Report formats

Every format is generated from the same normalized internal report model (schema v2.2; 2.2 added the nullable `tls` object and `sources.tls`), so nothing shown in the UI is missing from an export and vice versa.

- **JSON** — the normalized report object, 2-space indented, ISO 8601 timestamps, `null`/`[]` for missing data (never `"N/A"` or `"unknown"` placeholders).
- **Markdown** — headed sections with tables, suitable for pasting into documentation or a ticket.
- **Plain text** — fixed-width sections, readable in a terminal, email, or ticketing system.

## Privacy

- No browser/device geolocation is requested or used. All geolocation concerns the **queried IP address**, resolved via third-party geolocation APIs.
- No accounts, no server-side lookup history, no database.
- RDAP, DNS-over-HTTPS and geolocation queries go directly from your browser to the providers listed above. Those providers see your IP address and the queried IP or hostname, and may log it under their own policies.
- **Hostname lookups also send the queried hostname and the selected IP to this site's `/api/tls` function**, which resolves the hostname via the server's DNS resolver and opens an outbound TLS connection to the target on port 443. The function keeps no query history and its application log lines contain only status, error code and duration (no hostname, IP or client identifier). The hosting platform (Vercel) still sees the request and may record connection metadata such as your IP address under its own policies, and the target server sees a connection from Vercel's network. IP-only lookups never call the function.
- By default the queried address is written to the page URL (`?q=`), so it can remain in browser history and in shared links. The "Keep searches out of the URL" option under the search box turns this off (the flag is remembered in `localStorage`; queries never are).

## End-to-end tests

Playwright drives the real page against a local static server that sends the same headers as `vercel.json` (so CSP violations fail the suite). All third-party endpoints are mocked with the fixtures in `tests/fixtures`; no real network access is used.

```
npm install
npx playwright install chromium   # once
npm run test:e2e
```

`npm test` still runs only the Node unit tests.

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
│   ├── tls.js               /api/tls client, response normalization, shared TLS labels
│   ├── report.js           normalized report model + JSON/Markdown/Text export
│   ├── render.js            investigation report DOM (no innerHTML with external data)
│   ├── landing.js           self-IP hero, intelligence tiles, source-status strip
│   ├── chooser.js            multi-address hostname chooser
│   ├── history.js             session-only recent-lookup history (sessionStorage)
│   ├── about.js                About modal (focus trap, section targeting)
│   ├── toast.js                 non-blocking toast/status feedback
│   └── domkit.js                 shared safe DOM-construction helpers
├── api/
│   ├── tls.js              POST /api/tls — HTTP endpoint, request validation, orchestration
│   └── _lib/               (underscore prefix: not deployed as routes)
│       ├── tls-validation.js  hostname, public-IP and DNS-answer validation (SSRF controls)
│       └── tls-inspector.js    single TLS handshake, certificate/chain extraction, validation verdicts
├── vendor/leaflet/    vendored Leaflet (map tiles rendering), no CDN dependency
├── tests/
│   ├── normalize.test.js  input parsing, PTR, CIDR, RDAP/geo normalization
│   ├── report.test.js      report model + export consistency
│   ├── security.test.js     XSS-safety of the DOM renderer
│   ├── resilience.test.js    provider-failure paths
│   ├── tls-validation.test.js  hostname / public-IP / rebinding checks
│   ├── tls-inspector.test.js   handshakes against local TLS fixtures (valid, expired, self-signed, wrong host, incomplete chain, timeouts, non-TLS)
│   ├── tls-handler.test.js     HTTP endpoint behaviour with injected DNS and inspector
│   ├── tls-report.test.js      client normalization, report model, export consistency
│   └── fixtures/            recorded provider responses, no live API calls in tests
└── vercel.json
```

Landing state: the visitor's public IP is detected via the geolocation provider cascade (self-lookup) and rendered as soon as it's known, then org/ASN/location/reverse-DNS enrich progressively. Investigation state: input is normalized and classified (IP vs. hostname) → a hostname is resolved to an IP (multiple results show an address chooser) → RDAP, geolocation, reverse DNS and (hostname lookups only) the TLS certificate are looked up **in parallel** (a failure in one does not block the others; the TLS card shows its own loading state and updates in place when it settles) → all results are normalized into one report object → the UI and every export format render from that same object.

## Security

- External data (RDAP, DNS, geolocation responses, and the query itself) is never written into the DOM via `innerHTML`. The renderer (`js/render.js`) builds elements with `document.createElement` and sets `textContent`, so a value like `<img src=x onerror=alert(1)>` in a network name or remark is always displayed as literal text, never executed.
- Links are only ever rendered for URLs the app constructs itself (e.g. the OpenStreetMap link) or that pass a protocol allowlist (`https:`/`http:` only) — `javascript:` and `data:` URLs are never linkified.
- A `Content-Security-Policy` header (see `vercel.json`) restricts script/style/connect/img sources to what the app actually needs.

## Development setup

No build step. The static UI works from any static server; `/api/tls` additionally needs the Vercel runtime:

```sh
python3 -m http.server 8080          # UI only: the TLS card will show "not available"
npx vercel dev                        # UI + /api/tls (set TLS_INSPECTION_ENABLED=1 in .env.local)
```

## Testing

Tests use Node's built-in test runner and have no dependencies to install:

```sh
npm test
# or: node --test
```

All unit and normalization tests run against recorded fixtures in `tests/fixtures/` — no live network access or external API is required for a deterministic run. The TLS tests start local TLS servers on `127.0.0.1` using the test-only private CA and certificates in `tests/fixtures/tls/` (regenerate with `python3 tests/fixtures/tls/generate.py`; needs the Python `cryptography` package). The fixture trust anchor and the inspector's `port` override exist only as injected test dependencies; the HTTP handler never forwards request data into them.

```sh
npm test            # unit + integration (node --test)
npm run test:e2e    # Playwright; /api/tls is mocked, no live scanning
```

## TLS Certificate Intelligence

For a hostname lookup the app inspects the certificate currently presented by the HTTPS server at the **IP the investigation selected**, using the original hostname as SNI. It runs in parallel with RDAP/GeoIP/PTR and never blocks them. If a hostname has several addresses, only the address you pick is inspected. IP-only lookups perform no TLS inspection (certificates belong to server names; without a name there is no SNI to ask with).

**Shown:** subject, issuer, SANs, serial, validity dates and days remaining (with an "expiring soon" warning under 30 days — still valid), SHA-256 fingerprint (copyable), public-key algorithm/size, negotiated TLS version and cipher suite, connected IP/port/SNI, observation time, and the chain Node builds.

### Validation semantics

Four things are evaluated **separately** and never merged silently:

| Check | Values |
|---|---|
| Dates (`certificate.date_status`) | `valid`, `expired`, `not_yet_valid`, `unknown` |
| Hostname (`connection.hostname_match`) | `true`, `false`, `null` (unknown). Uses `tls.checkServerIdentity()` and additionally requires a DNS SAN (the CN is not trusted on its own) |
| Trust (`connection.trust_status`) | `valid`, `untrusted`, `self_signed`, `incomplete_chain`, `unknown` — from OpenSSL chain verification against Node's bundled root store |
| Handshake | success is implied by a certificate being returned; failures are `unavailable` with an error code |

The inspection handshake uses `rejectUnauthorized: false` **only so an invalid certificate can be read**; trust is then taken from the socket's verification result, never assumed. `validation.overall` is `valid` only if dates are `valid`, hostname is `true` and trust is `valid`; any definite failure is `invalid`; anything else is `unknown`. Unknown is never reported as valid. An expired certificate leaves trust `unknown` because OpenSSL stops verification at the date error; the expiry is reported on its own. The UI shows a green indicator only for `status: "ok"`; a successful handshake with a failed validation is shown as invalid.

**Chain caveats.** The chain lists what Node's TLS stack exposes. Node appends the matching trust-store root even when the server did not send it, so root entries are marked `presented: null` ("not confirmed as sent by the server"); an incomplete chain (missing intermediate) is reported as `incomplete_chain`. The number of certificates is never treated as proof of completeness. The certificate signature algorithm is not exposed by Node and is not reported; the cipher suite is the negotiated TLS cipher, not a certificate property.

### API

`POST /api/tls` with `Content-Type: application/json` and exactly `{"hostname": "example.com", "ip": "<selected IP>"}` (any other field, including `port`, is rejected; body ≤ 1 KiB).

```jsonc
{
  "status": "ok",                       // ok | invalid | unavailable | blocked
  "hostname": "example.com", "connected_ip": "…", "port": 443, "observed_at": "…",
  "certificate": { "subject", "issuer", "sans": [], "serial_number", "valid_from", "valid_to",
                   "days_remaining", "date_status", "expiring_soon", "fingerprint_sha256",
                   "public_key": { "algorithm", "size", "curve" } },
  "connection":  { "protocol", "cipher", "hostname_match", "trust_status", "trust_detail" },
  "validation":  { "overall": "valid|invalid|unknown", "problems": [] },
  "chain": [ { "position", "role": "leaf|intermediate|root", "subject", "issuer", "valid_from", "valid_to",
               "fingerprint_sha256", "self_issued", "presented": true|null } ],
  "chain_summary": { "count", "truncated", "validated": true|false|null },
  "error_code": null, "error_message": null
}
```

`ok` = retrieved and every check succeeded. `invalid` = a certificate was retrieved but a check failed or was inconclusive (`error_code` is the first problem). `unavailable` = no certificate could be retrieved (DNS failure, DNS mismatch, refused, timeout, handshake failure, non-TLS service, unreachable IPv6, …). `blocked` = refused by policy (bad input, non-public destination, disabled). Error codes come from a fixed set with fixed messages; no internal text is returned. The report's `tls` field is `null` when not applicable, otherwise this object (`status: "pending"` can appear in an export taken while the request is still in flight).

### SSRF and abuse controls

- Input: DNS hostnames only; URLs, credentials, paths, queries, ports, IP literals (including decimal/hex forms), `localhost`, single labels and local/internal TLDs are rejected; IDNs are converted to punycode; hostname ≤ 253 chars, body ≤ 1 KiB; only `hostname` and `ip` accepted; port is fixed at 443.
- Destination: the server resolves A and AAAA itself and requires **every** answer to be globally routable (private, loopback, link-local, CGNAT, multicast, documentation, reserved, IPv4-mapped/embedded IPv6, 6to4, Teredo, NAT64, ULA are refused; IPv6 is allow-listed to `2000::/3` minus special blocks). One unsafe answer fails the whole lookup. The browser's address filtering is not relied on.
- Rebinding: the browser-selected IP must be in that fresh answer set (else `dns_mismatch`); the socket connects directly to the validated IP literal with the hostname only as SNI, with a `lookup` that cannot resolve anything else, and the peer address is re-checked after connect. There is no fallback to any other address.
- Limits: one handshake per request, TCP connect timeout 4 s, total inspection 8 s, DNS ≤ ~5 s, function `maxDuration` 15 s, ≤ 4 concurrent inspections per instance (429 beyond), chain ≤ 8, SANs ≤ 100, strings ≤ 256 chars with control characters stripped, no redirects, no protocol other than TLS ≥ 1.2.
- HTTP: POST only, JSON only, `Cache-Control: no-store`, no CORS headers, cross-origin `Origin` / `Sec-Fetch-Site` rejected, no hostnames/IPs/client data in logs.
- **Rate limiting (deployment-level, required).** An in-memory counter in a serverless function is not a distributed limiter, so none is relied on. The endpoint is **disabled (503 `disabled`) until `TLS_INSPECTION_ENABLED=1` is set**, which the operator must set only after creating an edge rate-limit rule: Vercel Dashboard → Firewall → Rules → *Rate Limit*, condition *Request Path equals `/api/tls`*, key *IP address*, e.g. 10 requests / 60 s, action *Deny* (adjust to plan limits). This rule lives in project settings, not in the repository, and could not be verified from this repository. Do not set the variable without it.

### Deployment requirements

1. Deploy on Vercel with Node.js 22 (the repo's `vercel.json` sets `maxDuration`/`memory` for `api/tls.js`; the CSP `connect-src 'self'` already allows the call).
2. Create the Firewall rate-limit rule above.
3. Set `TLS_INSPECTION_ENABLED=1` (Production, and Preview if wanted).
4. Verify after deploy: a hostname lookup shows the card; `curl -X POST …/api/tls -d '{"hostname":"localhost","ip":"127.0.0.1"}' -H 'content-type: application/json'` returns `blocked`; repeated rapid requests are throttled at the edge.

## Known limitations

- TLS: the server's DNS answer must contain the IP the browser selected. Hostnames with large rotating or geo-DNS pools can legitimately return `dns_mismatch`. Vercel Functions often lack outbound IPv6, so IPv6 targets may report `network_unreachable`. Only TLS 1.2+ servers can be inspected. The result is what the inspection server sees on port 443 for that name and IP at that moment (SNI, geography and load balancing can change it). Revocation (OCSP/CRL) and Certificate Transparency are not checked, and trust uses Node's bundled roots, which can differ from a given browser or OS store.

- Geolocation and ASN data come from free, no-auth third-party APIs; accuracy and rate limits are outside this app's control, and a provider cascade is used to mitigate (not eliminate) outages.
- ASN data is derived from the geolocation providers' own ASN fields, not a dedicated BGP/RPKI source — the announced prefix shown is a best-effort value (falling back to the RDAP-registered CIDR when the provider doesn't supply one), not verified routing data.
- Reverse DNS (PTR) absence is common and expected; it is treated as a normal "not set" result, not an error.
- No user accounts, no persisted history, no threat/reputation scoring — by design (see the implementation spec for out-of-scope items reserved for a possible v3).
