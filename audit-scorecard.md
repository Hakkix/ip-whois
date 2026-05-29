# Scorecard: hakkix/ip-whois

**Repo:** https://github.com/hakkix/ip-whois
**Commit:** `3996156` · **Päivämäärä:** 2026-05-29

| Alue | Pisteet | Arvosana | Paino | Painotettu |
|---|---|---|---|---|
| Tietoturva | 50 / 100 | D | 35 % | 17.5 |
| Koodin laatu | 55 / 100 | D | 30 % | 16.5 |
| Riippuvuudet & lisenssit | 82 / 100 | B | 20 % | 16.4 |
| Dokumentaatio | 50 / 100 | D | 15 % | 7.5 |
| **Kokonaispiste** | **58 / 100** | **D** | | |

---

## Löydösten yhteenveto

| Vakavuus | Lukumäärä |
|---|---|
| Critical | 0 |
| High | 2 |
| Medium | 2 |
| Low | 3 |
| Info | 2 |

## Tärkeimmät havainnot

| # | Vakavuus | Havainto | Tiedosto |
|---|---|---|---|
| 1 | HIGH | XSS: API-data suoraan innerHTML:ään sanitoimatta | app.js:51-55 |
| 2 | HIGH | Content-Security-Policy puuttuu | vercel.json |
| 3 | MEDIUM | copyToClipboard kutsutaan kahdesti per klikki | app.js:61 |
| 4 | MEDIUM | Tyhjä if-lohko (kuollut koodi) | app.js:17 |
| 5 | LOW | Deprecated execCommand fallback | app.js:47 |
| 6 | LOW | SECURITY.md puuttuu | — |
| 7 | LOW | Ei testejä eikä CI/CD | — |

## Plussat

- Ei npm-riippuvuuksia → nolla toimitusketjuriskiä
- Apache 2.0 lisenssi, ei ristiriitoja
- RDAP-bootstrap + geo-API-fallback-cascade toimii hyvin
- Vercel-otsakkeissa X-Frame-Options ja Referrer-Policy valmiina
- Ei kovakoodattuja salaisuuksia tai API-avaimia
