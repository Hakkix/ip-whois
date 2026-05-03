# IP WHOIS

**Live application:** https://ip-whois.vercel.app

Static single-page IP WHOIS/RDAP lookup tool for IPv4 and IPv6.

## User guide
1. Open the app: https://ip-whois.vercel.app
2. Enter an IPv4 or IPv6 address in the input field.
3. Click **Lookup** (or press Enter) to fetch WHOIS/RDAP and geolocation data.
4. Review the result sections for network, registration, ASN, and location details.
5. Use the export bar to download reports in **JSON**, **Text**, or **Markdown** format.

## Example queries
- `8.8.8.8` (ARIN)
- `2a00:1450:4001:81f::200e` (RIPE NCC)

## Data sources
- RDAP bootstrap: `https://rdap-bootstrap.arin.net/bootstrap/ip/{ip}`
- Geolocation cascade:
  1. `https://ipinfo.io/{ip}/json`
  2. `https://ipwho.is/{ip}`
  3. `https://ipapi.co/{ip}/json/`

## IPv6 note
When requesting IPv6 from `ipapi.co`, send literal colons (`::`) in the path. URL-encoding can trigger their WAF (`403`).
