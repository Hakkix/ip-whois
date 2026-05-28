# ip-whois

A static, client-side IP address intelligence tool that combines RDAP (Registration Data Access Protocol) records with geolocation data for comprehensive IP lookups.

**Live:** https://ip-whois.vercel.app

---

## Features

- **RDAP lookup** — queries ARIN's bootstrap service to find the authoritative RIR and retrieves full registration data
- **Geolocation** — cascades across ipinfo.io → ipwho.is → ipapi.co until a result is returned
- **IPv4 and IPv6 support** — including special handling to avoid WAF rejections on IPv6 lookups
- **Reserved/private IP detection** — blocks lookups for RFC1918, loopback, link-local, and similar ranges
- **RIR identification** — ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC
- **Report export** — download results as JSON, Markdown, or plain text; copy to clipboard
- **Dark / light theme** — persisted in localStorage
- **Zero dependencies** — no build step, no npm, no backend

---

## Data returned

| Category | Fields |
|---|---|
| Network | name, handle, type, status, IP version |
| Range | start address, end address, CIDR blocks |
| Registration | country, parent network, RIR |
| Contacts | registrant, technical, administrative, abuse |
| Events | created, last modified, revocation dates |
| Geolocation | city, region, country, timezone, coordinates |
| ASN | autonomous system number |
| Remarks | notes from the RIR |

---

## Running locally

This is a plain static site. No install step is needed.

```bash
# Simplest: open directly in a browser
open index.html

# Or serve over HTTP (avoids any file:// restrictions)
python3 -m http.server 8000
# visit http://localhost:8000
```

Any modern browser with ES6+ support works (Chrome, Firefox, Safari, Edge 2015+).

---

## Example queries

- `8.8.8.8` — Google DNS, registered with ARIN (North America)
- `2a00:1450:4001:81f::200e` — Google IPv6, registered with RIPE NCC (Europe)

---

## Project structure

```
ip-whois/
├── index.html      # Page structure and markup
├── app.js          # All application logic
├── base.css        # CSS custom properties, theming, typography
├── style.css       # Component styles
├── vercel.json     # Deployment config and security headers
└── LICENSE         # Apache 2.0
```

---

## External APIs

The app is fully client-side and queries these public APIs at runtime:

| API | Purpose |
|---|---|
| `rdap-bootstrap.arin.net/bootstrap/ip/{ip}` | Finds the authoritative RIR and returns RDAP data |
| `ipinfo.io/{ip}/json` | Geolocation (primary) |
| `ipwho.is/{ip}` | Geolocation (fallback 1) |
| `ipapi.co/{ip}/json/` | Geolocation (fallback 2) |

No API keys or authentication are required.

> **IPv6 note:** When querying `ipapi.co` for an IPv6 address, literal colons must be sent in the path — URL-encoding them (`%3A`) triggers a 403 from their WAF.

---

## Deployment

The project deploys to Vercel as a static site. `vercel.json` configures:

- `cleanUrls: true` — serves pages without the `.html` extension
- `trailingSlash: false`
- Security headers: `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options`

---

## License

[Apache 2.0](LICENSE)
