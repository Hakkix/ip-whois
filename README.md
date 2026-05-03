# IP WHOIS

Static single-page IP WHOIS/RDAP lookup tool for IPv4 and IPv6.

## Data sources
- RDAP bootstrap: `https://rdap-bootstrap.arin.net/bootstrap/ip/{ip}`
- Geolocation cascade:
  1. `https://ipinfo.io/{ip}/json`
  2. `https://ipwho.is/{ip}`
  3. `https://ipapi.co/{ip}/json/`

## Quirk
When requesting IPv6 from `ipapi.co`, send literal colons (`::`) in the path. URL-encoding can trigger their WAF (`403`).

## Run
Open directly:
- `index.html`

Or serve locally:
```bash
python3 -m http.server
```

## Export formats
The app supports JSON, Text, and Markdown report exports from the result summary export bar.
Validated target queries:
- `8.8.8.8` (ARIN)
- `2a00:1450:4001:81f::200e` (RIPE NCC)


## Deploy to Vercel
This is a static app, so Vercel can deploy it with zero build step.

### Option 1: Vercel dashboard (fastest)
1. Push this repo to GitHub/GitLab/Bitbucket.
2. In Vercel, click **Add New → Project** and import the repo.
3. Framework preset: **Other**.
4. Build command: *(leave empty)*.
5. Output directory: *(leave empty)*.
6. Click **Deploy**.

### Option 2: Vercel CLI
```bash
npm i -g vercel
vercel
vercel --prod
```

The included `vercel.json` adds clean URLs and baseline security headers for static hosting.
